#requires -Version 5.1
<#
.SYNOPSIS
    On-demand Windows diagnostic data collector. Read-only by default.
.EXAMPLE
    .\WinTriage.ps1 -Mode Quick
.EXAMPLE
    .\WinTriage.ps1 -Mode Monitor -Samples 12 -IntervalSeconds 10
.EXAMPLE
    .\WinTriage.ps1 -Mode Security -RunClamAV -ScanPath "$env:USERPROFILE\Downloads"
.EXAMPLE
    .\WinTriage.ps1 -Mode Security -RunDefenderQuickScan
#>
[CmdletBinding()]
param(
    [ValidateSet('Quick','Processes','Monitor','Events','Security','Hardware','Integrity','Full')]
    [string]$Mode = 'Quick',
    [string]$OutputDir = (Join-Path $env:LOCALAPPDATA 'WinTriage\reports'),
    [ValidateRange(1,720)][int]$EventHours = 48,
    [ValidateRange(1,1000)][int]$MaxEventsPerLog = 250,
    [ValidateRange(1,50)][int]$Top = 15,
    [ValidateRange(2,300)][int]$Samples = 6,
    [ValidateRange(1,3600)][int]$IntervalSeconds = 10,
    [switch]$RunClamAV,
    [string]$ScanPath,
    [string]$ClamAVExe = 'clamscan.exe',
    [switch]$RunDefenderQuickScan,
    [switch]$RunSfcVerifyOnly,
    [switch]$RunDismScanHealth
)

# Native scanners use exit code 1 to mean detection; do not promote it to a PowerShell exception.
$PSNativeCommandUseErrorActionPreference = $false
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows에서만 실행할 수 있습니다.' }
Import-Module (Join-Path $PSScriptRoot 'src\WinTriage.Core.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'src\WinTriage.ProcessCollector.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'src\WinTriage.EventCollector.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'src\WinTriage.HardwareCollector.psm1') -Force
if (($RunClamAV -or $RunDefenderQuickScan) -and $Mode -notin @('Security','Full')) {
    throw '백신 검사는 -Mode Security 또는 -Mode Full과 함께 실행하세요.'
}
if (($RunSfcVerifyOnly -or $RunDismScanHealth) -and $Mode -notin @('Integrity','Full')) {
    throw '시스템 무결성 검사는 -Mode Integrity 또는 -Mode Full과 함께 실행하세요.'
}
if ($RunClamAV -and [string]::IsNullOrWhiteSpace($ScanPath)) {
    throw '-RunClamAV 사용 시 -ScanPath로 검사 대상을 명시해야 합니다.'
}
if ($RunClamAV -and -not (Test-Path -LiteralPath $ScanPath)) {
    throw "검사 대상이 존재하지 않습니다: $ScanPath"
}

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$runId = [datetime]::UtcNow.ToString('yyyyMMdd_HHmmss') + '_' + ([guid]::NewGuid().ToString('N').Substring(0,6))
$runDir = Join-Path $OutputDir $runId
New-Item -ItemType Directory -Path $runDir -Force | Out-Null
$warnings = New-Object 'System.Collections.Generic.List[string]'
$processReadWarnings = @{}
$report = [ordered]@{ ToolVersion='0.3.1'; ReportSchemaVersion=1; RunId = $runId; StartedUtc = [datetime]::UtcNow.ToString('o'); Mode = $Mode; Computer = $env:COMPUTERNAME; EventHours=$EventHours; MaxEventsPerLog=$MaxEventsPerLog; Files = @(); Warnings = @(); Scan = @{} }

function Save-WtJson {
    param([string]$Name, [object]$Data)
    $p = Join-Path $runDir $Name
    ConvertTo-Json -InputObject $Data -Depth 8 | Out-File -FilePath $p -Encoding utf8
    $script:report['Files'] += $Name
    return $p
}
function Save-WtCsv {
    param([string]$Name, [object[]]$Rows, [string[]]$Columns)
    $path=Join-Path $runDir $Name
    if ($Rows.Count -gt 0) {
        $Rows | Select-Object -Property $Columns | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    } else {
        # A valid header-only CSV still exists when no eligible process could be sampled.
        Set-Content -LiteralPath $path -Value ('"' + ($Columns -join '","') + '"') -Encoding UTF8
    }
    $script:report['Files'] += $Name
}
function Test-WtAdministrator {
    try {
        $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
        $principal=New-Object -TypeName System.Security.Principal.WindowsPrincipal -ArgumentList $identity
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}
function Get-WtIntegrity {
    # No native executable is launched in default/passive mode.
    $status=[ordered]@{
        Administrator=(Test-WtAdministrator)
        SfcVerifyOnly='not-requested'; DismScanHealth='not-requested'
        Notes=@('No repair option is used: /verifyonly and /ScanHealth only.',
                'Native scan exit code alone is not proof that Windows is fully healthy.',
                'Windows may create its own maintenance/diagnostic logs.')
    }
    $requested = @(
        [pscustomobject]@{ Flag=[bool]$RunSfcVerifyOnly; Key='SfcVerifyOnly'; Executable='sfc.exe'; Arguments=@('/verifyonly'); Filename='sfc-verifyonly.txt' },
        [pscustomobject]@{ Flag=[bool]$RunDismScanHealth; Key='DismScanHealth'; Executable='dism.exe'; Arguments=@('/Online','/Cleanup-Image','/ScanHealth'); Filename='dism-scanhealth.txt' }
    )
    foreach ($item in $requested) {
        if (-not $item.Flag) { continue }
        if (-not $status.Administrator) {
            $status[$item.Key]='skipped-requires-admin'
            $script:warnings.Add("$($item.Executable) 검사를 실행하려면 관리자 PowerShell이 필요합니다. 실행하지 않았습니다.")
            continue
        }
        $cmd=Get-Command $item.Executable -CommandType Application -ErrorAction SilentlyContinue
        if (-not $cmd) {
            $status[$item.Key]='unavailable'
            $script:warnings.Add("시스템 도구를 찾지 못했습니다: $($item.Executable)")
            continue
        }
        try {
            $outputPath=Join-Path $runDir $item.Filename
            # Fixed, verify-only arguments. No repair commands are called.
            $arguments = @($item.Arguments)
            & $cmd.Source @arguments 2>&1 | Out-File -LiteralPath $outputPath -Encoding utf8
            $exitCode=$LASTEXITCODE
            if ($null -eq $exitCode) { $status[$item.Key]='indeterminate' }
            elseif ([int]$exitCode -eq 0) { $status[$item.Key]='completed-review-output' }
            else { $status[$item.Key]="failed-exit-$exitCode" }
            $status["$($item.Key)ExitCode"]=$exitCode
            $status["$($item.Key)Log"]=$item.Filename
            $script:report['Files'] += $item.Filename
            if ($status[$item.Key] -ne 'completed-review-output') {
                $script:warnings.Add("무결성 검사 결과 [$($item.Key)]: $($status[$item.Key]). 로그를 확인하세요.")
            }
        } catch {
            $status[$item.Key]='execution-error'
            $script:warnings.Add("무결성 검사 실행 실패 [$($item.Key)]: $($_.Exception.Message)")
        }
    }
    return [pscustomobject]$status
}
function Get-WtSecurity {
    $s = [ordered]@{ Defender = $null; RecentDetections=@(); RequestedScan='none'; DefenderScanResult='not-requested'; ClamAVResult='not-requested' }
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        try {
            $s.Defender = Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureAge,AntivirusSignatureVersion,QuickScanEndTime,FullScanEndTime
        } catch { $script:warnings.Add("Defender 상태 조회 실패: $($_.Exception.Message)") }
        if (Get-Command Get-MpThreatDetection -ErrorAction SilentlyContinue) {
            try { $s.RecentDetections = @(Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 20 ThreatID,InitialDetectionTime,LastThreatStatusChangeTime,ActionSuccess) }
            catch { $script:warnings.Add("Defender 위협 기록 조회 실패: $($_.Exception.Message)") }
        }
    } else { $script:warnings.Add('Defender PowerShell 명령을 사용할 수 없습니다. 다른 백신 또는 시스템 구성을 확인하세요.') }
    if ($RunDefenderQuickScan) {
        $s.RequestedScan = 'Defender QuickScan'
        if (-not (Get-Command Start-MpScan -ErrorAction SilentlyContinue)) {
            $s.DefenderScanResult = 'unavailable'; $script:warnings.Add('Start-MpScan 명령을 사용할 수 없습니다.')
        } else {
            try { Start-MpScan -ScanType QuickScan -ErrorAction Stop; $s.DefenderScanResult = 'scan-request-submitted' }
            catch { $s.DefenderScanResult = 'failed'; $script:warnings.Add("Defender 빠른 검사 실패: $($_.Exception.Message)") }
        }
    }
    if ($RunClamAV) {
        $s.RequestedScan = if ($RunDefenderQuickScan) { 'Defender QuickScan + ClamAV' } else { 'ClamAV' }
        $cmd = Get-Command $ClamAVExe -CommandType Application -ErrorAction SilentlyContinue
        if (-not $cmd) {
            $s.ClamAVResult = 'not-installed'
            $script:warnings.Add("ClamAV를 찾지 못했습니다: $ClamAVExe (공식 ClamAV 설치 후 경로를 지정하세요.)")
        } else {
            $logFile = Join-Path $runDir 'clamav-output.txt'
            try {
                # No --remove/--move; do not alter scan targets.
                & $cmd.Source '--recursive=yes' '--infected' $ScanPath 2>&1 | Out-File -FilePath $logFile -Encoding utf8
                $exitCode = $LASTEXITCODE
                $s.ClamAVResult = switch ($exitCode) { 0 {'no-detection'} 1 {'detection-review-required'} default {'scan-error'} }
                $s.ClamAVExitCode = $exitCode
                $s.ClamAVOutput = 'clamav-output.txt'
                $script:report['Files'] += 'clamav-output.txt'
                if ($exitCode -eq 1) { $script:warnings.Add('ClamAV 탐지 결과가 있습니다. 출력 파일 확인 후 백업, 격리, 전문가 검토를 수행하세요. 자동 삭제하지 않았습니다.') }
                if ($exitCode -gt 1) { $script:warnings.Add("ClamAV 검사 오류 (exit=$exitCode). 로그를 확인하세요.") }
            } catch { $s.ClamAVResult='failed'; $script:warnings.Add("ClamAV 실행 실패: $($_.Exception.Message)") }
        }
    }
    return [pscustomobject]$s
}

try {
    $sys = Get-WtSystemSnapshot -Warnings $warnings
    [void](Save-WtJson -Name 'system.json' -Data $sys)

    $collectProcesses = $Mode -in @('Quick','Processes','Monitor','Full')
    $collectEvents = $Mode -in @('Quick','Events','Full')
    $collectSecurity = $Mode -in @('Quick','Security','Full')
    $collectHardware = $Mode -in @('Quick','Hardware','Full')
    $collectIntegrity = $Mode -in @('Integrity','Full')

    $topProcess = @()
    if ($collectProcesses) {
        $allSamples = New-Object 'System.Collections.Generic.List[object]'
        $n = if ($Mode -eq 'Monitor') { $Samples } else { 1 }
        for ($i=0; $i -lt $n; $i++) {
            if ($i -gt 0) { Start-Sleep -Seconds $IntervalSeconds }
            foreach ($p in @(Get-WtProcesses -Warnings $warnings -ReadFailures $processReadWarnings)) { $allSamples.Add($p) }
            if ($Mode -eq 'Monitor') { Write-Host ("메모리 샘플 {0}/{1} 수집" -f ($i+1),$n) }
        }
        $records = @($allSamples.ToArray())
        $latestTime = if ($records.Count -gt 0) { ($records | Sort-Object SampleTimeUtc -Descending | Select-Object -First 1).SampleTimeUtc } else { $null }
        $topProcess = @($records | Where-Object { $_.SampleTimeUtc -eq $latestTime } |
            Sort-Object PrivateMiB -Descending | Select-Object -First $Top)
        [void](Save-WtJson -Name 'processes.json' -Data $records)
        if ($Mode -eq 'Monitor') {
            Save-WtCsv -Name 'memory-samples.csv' -Rows $records -Columns @('SampleTimeUtc','InstanceKey','IdentityReliable','Name','Pid','StartedUtc','WorkingSetMiB','PrivateMiB','CpuSeconds','Handles')
            $growth = @(Get-WtProcessGrowth -Samples $records)
            $report['SkippedUnreliableIdentitySamples'] = @($records | Where-Object { -not $_.IdentityReliable }).Count
            Save-WtCsv -Name 'memory-growth.csv' -Rows $growth -Columns @('Name','Pid','Samples','FirstUtc','LastUtc','FirstPrivateMiB','LastPrivateMiB','PrivateGrowthMiB','FirstWorkingSetMiB','LastWorkingSetMiB','WorkingSetGrowthMiB')
            $report['MemoryGrowthTop'] = @($growth | Select-Object -First $Top)
        }
    }

    $events = @()
    if ($collectEvents) {
        $eventSampling=@{}
        $events = @(Get-WtEvents -Warnings $warnings -EventHours $EventHours -MaxEventsPerLog $MaxEventsPerLog -SamplingInfo $eventSampling)
        $report['EventSampling'] = $eventSampling
        [void](Save-WtJson -Name 'events.json' -Data $events)
        $eventSummary = @(Get-WtEventSummary -Events $events)
        [void](Save-WtJson -Name 'event-summary.json' -Data $eventSummary)
        $report['EventSummaryTop'] = @($eventSummary | Select-Object -First 20)
        $advice = @(Get-WtTriageAdvice -Events $events)
        [void](Save-WtJson -Name 'triage-advice.json' -Data $advice)
    }
    if ($collectSecurity) {
        $security = Get-WtSecurity
        [void](Save-WtJson -Name 'security.json' -Data $security)
        $report['Scan'] = @{ Defender = $security.DefenderScanResult; ClamAV = $security.ClamAVResult }
    }
    if ($collectHardware) {
        $hardware = Get-WtHardware -Warnings $warnings
        [void](Save-WtJson -Name 'hardware.json' -Data $hardware)
    }
    if ($collectIntegrity) {
        $integrity = Get-WtIntegrity
        [void](Save-WtJson -Name 'integrity.json' -Data $integrity)
        $report['Integrity'] = @{ SfcVerifyOnly=$integrity.SfcVerifyOnly; DismScanHealth=$integrity.DismScanHealth }
    }
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add('# Windows Health Triage - local report')
    $lines.Add('')
    $lines.Add("- Run: $runId")
    $lines.Add("- Mode: $Mode")
    $lines.Add("- OS: $($sys.OS) ($($sys.Version))")
    $lines.Add("- RAM: $($sys.FreePhysicalRamGiB) GiB available / $($sys.TotalRamGiB) GiB installed")
    $lines.Add('')
    if ($collectProcesses) {
        $lines.Add('## Top private memory processes (snapshot)')
        foreach ($p in $topProcess) { $lines.Add("- $($p.Name) (PID $($p.Pid)): $($p.PrivateMiB) MiB private / $($p.WorkingSetMiB) MiB working set") }
        $lines.Add('')
    }
    if ($Mode -eq 'Monitor') {
        $lines.Add('## Private memory growth (not proof of a leak)')
        $lines.Add("- Samples skipped due to unknown process start time: $($report['SkippedUnreliableIdentitySamples'])")
        foreach ($g in $report['MemoryGrowthTop']) { $lines.Add("- $($g.Name) (PID $($g.Pid)): $($g.PrivateGrowthMiB) MiB across $($g.Samples) samples") }
        $lines.Add('')
    }
    if ($collectEvents) {
        $lines.Add("## Event signals (last $EventHours hours, max $MaxEventsPerLog per log)")
        foreach ($group in @($events | Group-Object Category | Sort-Object Count -Descending)) { $lines.Add("- $($group.Name): $($group.Count)") }
        $lines.Add('')
        $lines.Add('### Suggested next checks (hypotheses; no automatic repairs)')
        foreach ($a in @($advice | Select-Object -First 8)) {
            $lines.Add("- [$($a.Priority)] $($a.Category) ($($a.EventCount) sampled): $($a.Action)")
        }
        $lines.Add('')
        $lines.Add('### Repeated provider / event ID pairs (sampled, not full-log counts)')
        foreach ($e in @($report['EventSummaryTop'] | Select-Object -First 10)) {
            $lines.Add("- $($e.Provider) / $($e.EventId): $($e.Count) ($($e.Category), $($e.Severity))")
        }
        $lines.Add('')
    }
    if ($collectSecurity) {
        $lines.Add('## Security')
        $lines.Add("- Defender requested quick scan: $($security.DefenderScanResult)")
        if ($RunClamAV) { $lines.Add("- ClamAV: $($security.ClamAVResult)") }
        $lines.Add('')
    }
    if ($collectHardware) {
        $lines.Add('## Storage (signals only; not a definitive SMART health test)')
        if (@($hardware.StorageAssessments).Count -eq 0) { $lines.Add('- Physical disk assessment unavailable; not evidence of a healthy drive.') }
        foreach ($d in @($hardware.StorageAssessments)) {
            $lines.Add("- $($d.FriendlyName) [device $($d.DeviceId)]: $($d.Assessment); counters available: $($d.CountersAvailable)")
            foreach ($e in @($d.Evidence)) { $lines.Add("  - $e") }
        }
        $lines.Add('')
    }
    if ($collectIntegrity) {
        $lines.Add('## Windows system integrity (read-only verification only)')
        $lines.Add("- Admin: $($integrity.Administrator)")
        $lines.Add("- SFC /verifyonly: $($integrity.SfcVerifyOnly)")
        $lines.Add("- DISM /ScanHealth: $($integrity.DismScanHealth)")
        $lines.Add('- Review raw output to determine detected corruption; exit 0 is not a full system health guarantee.')
        $lines.Add('')
    }
    $lines.Add('## Warnings / caveats')
    if ($warnings.Count -eq 0) { $lines.Add('- No collection warnings.') }
    foreach ($w in $warnings) { $lines.Add("- $($w.Replace([char]13,' ').Replace([char]10,' '))") }
    $lines.Add('- Event collection is capped; absence of an event does not prove a clean system.')
    $lines.Add('- For Windows system-file verification (no repair), an administrator can separately run: sfc /verifyonly')
    $lines.Add('- For component store verification (no repair), an administrator can separately run: DISM /Online /Cleanup-Image /ScanHealth')
    $lines.Add('- Classification is heuristic; do not assume malware, memory leak or hardware failure from a single event.')
    $lines.Add('- This tool itself does not delete files, kill processes, or change drivers/registry. If explicitly invoked, Defender may independently quarantine detected files.')
    $lines.Add('- Optional SFC/DISM verification can generate native Windows diagnostic logs and considerable CPU/disk I/O, but does not request a repair.')
    $lines | Out-File -FilePath (Join-Path $runDir 'SUMMARY.md') -Encoding UTF8
    $report['Warnings'] = @($warnings.ToArray())
    $report['Files'] += @('SUMMARY.md','manifest.json')
    $report['CompletedUtc'] = [datetime]::UtcNow.ToString('o')
    ConvertTo-Json -InputObject $report -Depth 8 | Out-File -FilePath (Join-Path $runDir 'manifest.json') -Encoding UTF8
    Write-Host "완료: $runDir"
    Write-Host '요약: SUMMARY.md / 상세: *.json, memory-*.csv (Monitor)'
} catch {
    Write-Warning "실행 실패: $($_.Exception.Message)"
    throw
}
