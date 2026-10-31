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
Import-Module (Join-Path $PSScriptRoot 'src\WinTriage.SecurityCollector.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'src\WinTriage.IntegrityCollector.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'src\WinTriage.ScanExecutor.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'src\WinTriage.ReportSecurity.psm1') -Force
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

# Protect this NEW per-run folder before any private OS/process/event data is collected.
# Do not alter ACLs or delete content in older reports.
$runId = [datetime]::UtcNow.ToString('yyyyMMdd_HHmmss') + '_' + ([guid]::NewGuid().ToString('N').Substring(0,6))
$runDir = New-WtPrivateReportDirectory -ParentDirectory $OutputDir -RunId $runId
# Pin root-to-run directory handles for the ENTIRE evidence-writing lifetime.
# No evidence is collected if this lease cannot be safely acquired.
$reportPathLease = Enter-WtReportPathLease -Directory $runDir
# The optional native tool only receives a TextWriter backed by the pinned
# report-directory handle. There is deliberately no path-based log fallback.
$nativeLeaseForLogs=$reportPathLease
$nativeLogBom=($PSVersionTable.PSEdition -eq 'Desktop')
$nativeLogWriterFactory={
    param([string]$name)
    $nativeLeaseForLogs.OpenNewUtf8Writer($name,$nativeLogBom)
}.GetNewClosure()
$warnings = New-Object 'System.Collections.Generic.List[string]'
$processReadWarnings = @{}
$report = [ordered]@{ ToolVersion='0.3.1'; ReportSchemaVersion=1; RunId = $runId; StartedUtc = [datetime]::UtcNow.ToString('o'); Mode = $Mode; Computer = $env:COMPUTERNAME; EventHours=$EventHours; MaxEventsPerLog=$MaxEventsPerLog; Files = @(); Warnings = @(); Scan = @{} }

function Save-WtJson {
    param([string]$Name, [object]$Data)
    $content = (ConvertTo-Json -InputObject $Data -Depth 8) + [Environment]::NewLine
    $script:reportPathLease.WriteNewUtf8($Name,$content,($PSVersionTable.PSEdition -eq 'Desktop'))
    $p = Join-Path $runDir $Name
    $script:report['Files'] += $Name
    return $p
}
function Save-WtCsv {
    param([string]$Name, [object[]]$Rows, [string[]]$Columns)
    if ($Rows.Count -gt 0) {
        $csvLines=@($Rows | Select-Object -Property $Columns | ConvertTo-Csv -NoTypeInformation)
        $csvContent=($csvLines -join [Environment]::NewLine) + [Environment]::NewLine
    } else {
        # A valid header-only CSV still exists when no eligible process could be sampled.
        $csvContent= ('"' + ($Columns -join '","') + '"') + [Environment]::NewLine
    }
    $script:reportPathLease.WriteNewUtf8($Name,$csvContent,($PSVersionTable.PSEdition -eq 'Desktop'))
    $script:report['Files'] += $Name
}
function Get-WtSecurity {
    $script:reportPathLease.AssertStable()
    # Default passive collection never requests a native scan.
    $s=Get-WtSecurityEvidence -Warnings $warnings
    $scanFiles=New-Object 'System.Collections.Generic.List[string]'
    $s=Invoke-WtRequestedScans -SecurityEvidence $s -Warnings $warnings -RecordedFiles $scanFiles -RunDefenderQuickScan:$RunDefenderQuickScan -RunClamAV:$RunClamAV -ScanPath $ScanPath -ClamAVExe $ClamAVExe -OutputDirectory $runDir -LogWriterFactory $nativeLogWriterFactory
    $script:report['Files'] += @($scanFiles.ToArray())
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
        if ($Mode -eq 'Monitor') {
            # Non-identifying aggregate counts only, never process names or IDs.
            $report['MonitorSampling'] = [ordered]@{
                RequestedAttempts=$n; AttemptedAttempts=0
                NonEmptyAttempts=0; ComparableProcesses=0; RejectedGrowthGroups=0
                SingletonGroups=0; InvalidSingletonGroups=0; UnkeyedSamples=0
            }
        }
        for ($i=0; $i -lt $n; $i++) {
            if ($i -gt 0) { Start-Sleep -Seconds $IntervalSeconds }
            $batch=@(Get-WtProcesses -Warnings $warnings -ReadFailures $processReadWarnings)
            foreach ($p in $batch) { $allSamples.Add($p) }
            if ($Mode -eq 'Monitor') {
                $report['MonitorSampling']['AttemptedAttempts']++
                if ($batch.Count -gt 0) { $report['MonitorSampling']['NonEmptyAttempts']++ }
                Write-Host ("메모리 샘플 {0}/{1} 수집" -f ($i+1),$n)
            }
        }
        $records = @($allSamples.ToArray())
        $latestTime = if ($records.Count -gt 0) { ($records | Sort-Object SampleTimeUtc -Descending | Select-Object -First 1).SampleTimeUtc } else { $null }
        $topProcess = @($records | Where-Object { $_.SampleTimeUtc -eq $latestTime } |
            Sort-Object PrivateMiB -Descending | Select-Object -First $Top)
        [void](Save-WtJson -Name 'processes.json' -Data $records)
        if ($Mode -eq 'Monitor') {
            Save-WtCsv -Name 'memory-samples.csv' -Rows $records -Columns @('SampleTimeUtc','InstanceKey','IdentityReliable','Name','Pid','StartedUtc','WorkingSetMiB','PrivateMiB','CpuSeconds','Handles')
            $growthQuality=@{}
            $growth = @(Get-WtProcessGrowth -Samples $records -QualityInfo $growthQuality)
            $report['MonitorSampling']['ComparableProcesses'] = $growth.Count
            $report['MonitorSampling']['RejectedGrowthGroups'] = [int]$growthQuality['RejectedGrowthGroups']
            $report['MonitorSampling']['SingletonGroups'] = [int]$growthQuality['SingletonGroups']
            $report['MonitorSampling']['InvalidSingletonGroups'] = [int]$growthQuality['InvalidSingletonGroups']
            $report['MonitorSampling']['UnkeyedSamples'] = [int]$growthQuality['UnkeyedSamples']
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
        $nativeFiles = New-Object 'System.Collections.Generic.List[string]'
        $reportPathLease.AssertStable()
        $integrity = Get-WtIntegrity -Warnings $warnings -RecordedFiles $nativeFiles -OutputDirectory $runDir -RunSfcVerifyOnly:$RunSfcVerifyOnly -RunDismScanHealth:$RunDismScanHealth -LogWriterFactory $nativeLogWriterFactory
        $report['Files'] += @($nativeFiles.ToArray())
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
    $reportPathLease.WriteNewUtf8('SUMMARY.md',(($lines.ToArray() -join [Environment]::NewLine) + [Environment]::NewLine),($PSVersionTable.PSEdition -eq 'Desktop'))
    $report['Warnings'] = @($warnings.ToArray())
    $report['Files'] += @('SUMMARY.md','manifest.json')
    $report['CompletedUtc'] = [datetime]::UtcNow.ToString('o')
    $manifestContent=(ConvertTo-Json -InputObject $report -Depth 8) + [Environment]::NewLine
    $reportPathLease.WriteNewUtf8('manifest.json',$manifestContent,($PSVersionTable.PSEdition -eq 'Desktop'))
    Write-Host "완료: $runDir"
    Write-Host '요약: SUMMARY.md / 상세: *.json, memory-*.csv (Monitor)'
} catch {
    Write-Warning "실행 실패: $($_.Exception.Message)"
    throw
}
finally {
    # Release the no-share-delete ancestor handles even on collector failures.
    if ($null -ne $reportPathLease) { $reportPathLease.Dispose() }
}
