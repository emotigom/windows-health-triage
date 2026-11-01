#requires -Version 5.1
# ADR-047 deterministic invented rows only; no OS process query or native scans.
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $PSScriptRoot 'ReportContract.psm1') -Force
Import-Module (Join-Path $root 'src\WinTriage.Core.psm1') -Force
Import-Module (Join-Path $root 'src\WinTriage.FieldValidation.psm1') -Force
$dir=Join-Path ([IO.Path]::GetTempPath()) ('wt-monitor-content-' + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $dir)
$sampleCols=@('SampleTimeUtc','InstanceKey','IdentityReliable','Name','Pid','StartedUtc','WorkingSetMiB','PrivateMiB','CpuSeconds','Handles')
$growthCols=@('Name','Pid','Samples','FirstUtc','LastUtc','FirstPrivateMiB','LastPrivateMiB','PrivateGrowthMiB','FirstWorkingSetMiB','LastWorkingSetMiB','WorkingSetGrowthMiB')
function Write-Json { param([string]$File,[object]$Value)
    (ConvertTo-Json -InputObject $Value -Depth 8) | Out-File -LiteralPath (Join-Path $dir $File) -Encoding UTF8
}
function Write-Csv { param([string]$File,[object[]]$Value,[string[]]$Columns)
    if ($Value.Count -gt 0) {
        $text=@($Value | Select-Object -Property $Columns | ConvertTo-Csv -NoTypeInformation) -join [Environment]::NewLine
    } else { $text='"' + ($Columns -join '","') + '"' }
    [IO.File]::WriteAllText((Join-Path $dir $File),$text+[Environment]::NewLine,
        (New-Object System.Text.UTF8Encoding -ArgumentList $false))
}
function Row { param([int]$ProcId,[string]$At,[double]$MiB,[bool]$Reliable=$true,[string]$Start='2026-10-31T00:00:00.0000000Z')
    [pscustomobject][ordered]@{
        SampleTimeUtc=$At
        InstanceKey=if($Reliable){"$ProcId|$Start"}else{$null}
        IdentityReliable=$Reliable
        Name='SYNTHETIC_PRIVATE_CANARY'
        Pid=$ProcId
        StartedUtc=if($Reliable){$Start}else{$null}
        WorkingSetMiB=$MiB;PrivateMiB=$MiB;CpuSeconds=0;Handles=1
    }
}
$at1='2026-10-31T01:00:00.0000000Z'
$at2='2026-10-31T01:00:01.0000000Z'
$rows=@((Row 4242 $at1 100),(Row 4242 $at2 125))
$manifest=[ordered]@{
    ReportSchemaVersion=1;ToolVersion='0.3.1';RunId='SYNTHETIC-RUN'
    StartedUtc=$at1;CompletedUtc=$at2;Mode='Monitor';Computer='SYNTHETIC-HOST'
    Files=@('system.json','processes.json','memory-samples.csv','memory-growth.csv','SUMMARY.md','manifest.json')
    Warnings=@();Scan=@{};SkippedUnreliableIdentitySamples=0;MemoryGrowthTop=@()
    MonitorSampling=[ordered]@{RequestedAttempts=2;AttemptedAttempts=2;NonEmptyAttempts=2
        ComparableProcesses=0;RejectedGrowthGroups=0;SingletonGroups=0
        InvalidSingletonGroups=0;UnkeyedSamples=0}
}
function Write-Consistent { param([object[]]$Records)
    # Match the production collector's contiguous time-ordered batches.
    $Records=@($Records | Sort-Object SampleTimeUtc)
    $quality=@{}
    $growth=@(Get-WtProcessGrowth -Samples $Records -QualityInfo $quality)
    $manifest.MonitorSampling.ComparableProcesses=$growth.Count
    foreach($name in @('RejectedGrowthGroups','SingletonGroups','InvalidSingletonGroups','UnkeyedSamples')) {
        $manifest.MonitorSampling[$name]=[int]$quality[$name]
    }
    $manifest.SkippedUnreliableIdentitySamples=@($Records | Where-Object {-not $_.IdentityReliable}).Count
    $groups=@($Records | Group-Object SampleTimeUtc)
    $manifest.MonitorSampling.NonEmptyAttempts=$groups.Count
    $manifest.MonitorSampling.AttemptSampleCounts=@($groups | ForEach-Object { [int]$_.Count })
    $manifest.MemoryGrowthTop=@($growth)
    Write-Json 'processes.json' $Records
    Write-Csv 'memory-samples.csv' $Records $sampleCols
    Write-Csv 'memory-growth.csv' $growth $growthCols
    Write-Json 'manifest.json' $manifest
}
function Assert-Pass { param([string]$Reason)
    if (-not (Assert-WtReportContract -RunDirectory $dir)) { throw "Expected contract pass: $Reason" }
}
function Assert-Fail { param([string]$Reason)
    $caught=$false
    try { [void](Assert-WtReportContract -RunDirectory $dir) } catch {
        $caught=$true
        if ($_.Exception.Message.Contains('SYNTHETIC_PRIVATE_CANARY')) {
            throw 'Private identifier escaped through validator error'
        }
    }
    if (-not $caught) { throw "Expected contract rejection: $Reason" }
}
try {
    Write-Json 'system.json' ([ordered]@{OS='unknown';Version='unknown';LastBootUtc=$null;TotalRamGiB=$null;FreePhysicalRamGiB=$null;ReportedFreeVirtualMemoryGiB=$null})
    Set-Content -LiteralPath (Join-Path $dir 'SUMMARY.md') -Value '# Synthetic' -Encoding UTF8
    Write-Consistent $rows
    Assert-Pass 'valid growth'

    # Bound real capture UTCs by the claimed run window, not by the rows alone.
    $manifest.StartedUtc=$at2
    Write-Json 'manifest.json' $manifest
    Assert-Fail 'sample precedes forged run start'
    $manifest.StartedUtc=$at1
    $manifest.CompletedUtc=$at1
    Write-Json 'manifest.json' $manifest
    Assert-Fail 'sample follows forged completion'
    $manifest.StartedUtc=$at2
    $manifest.CompletedUtc=$at1
    Write-Json 'manifest.json' $manifest
    Assert-Fail 'reversed run time range'
    $manifest.StartedUtc=$at1
    $manifest.CompletedUtc='2026-10-31T01:00:01+02:00'
    Write-Json 'manifest.json' $manifest
    Assert-Fail 'offset-shifted completion outside run window'
    $manifest.CompletedUtc='2026-10-31T25:00:01.0000000Z'
    Write-Json 'manifest.json' $manifest
    Assert-Fail 'impossible completion hour'
    $manifest.CompletedUtc=$at2
    Write-Consistent $rows
    Assert-Pass 'run-window restored'

    # Different singletons with reversed batches keep their numeric aggregates,
    # growth CSV and manifest internally plausible; ordered UTC still fails.
    $orderedSingles=@((Row 8000 $at1 50),(Row 9000 $at2 60))
    Write-Consistent $orderedSingles
    Assert-Pass 'invented singleton capture order'
    $reversed=@($orderedSingles[1],$orderedSingles[0])
    Write-Json 'processes.json' $reversed
    Write-Csv 'memory-samples.csv' $reversed $sampleCols
    Assert-Fail 'reversed capture batches with unchanged totals'

    # A complete coherent rewrite can pass arithmetic and UTC checks.
    # This is intentional: consistency cannot authenticate a source.
    $fullyRewritten=@((Row 4242 $at1 300),(Row 4242 $at2 375))
    Write-Consistent $fullyRewritten
    Assert-Pass 'self-consistent alternate data is NOT authenticity proof'
    Write-Consistent $rows
    Assert-Pass 'original invented data restored'
    $manifest.MonitorSampling.AttemptSampleCounts=@(2,0)
    Write-Json 'manifest.json' $manifest
    Assert-Fail 'attempt ledger cannot conceal a second nonempty batch'
    Write-Consistent $rows
    $manifest.MonitorSampling.AttemptSampleCounts=@(1,$true)
    Write-Json 'manifest.json' $manifest
    Assert-Fail 'boolean attempt ledger entry'
    Write-Consistent $rows
    $manifest.MonitorSampling.AttemptSampleCounts=@(1,-1)
    Write-Json 'manifest.json' $manifest
    Assert-Fail 'negative attempt ledger entry'
    Write-Consistent $rows
    $manifest.MonitorSampling.AttemptSampleCounts=@(1,1,0)
    Write-Json 'manifest.json' $manifest
    Assert-Fail 'extra attempt ledger slot'
    Write-Consistent $rows
    $batchRows=@((Row 4242 $at1 100),(Row 8000 $at1 50),(Row 4242 $at2 125))
    Write-Consistent $batchRows
    Assert-Pass 'multiple rows per invented attempt'
    $manifest.MonitorSampling.AttemptSampleCounts=@(1,2)
    Write-Json 'manifest.json' $manifest
    Assert-Fail 'shifted batch boundaries despite equal grand total'
    Write-Consistent $rows
    $manifest.MonitorSampling.RequestedAttempts=3
    $manifest.MonitorSampling.AttemptedAttempts=3
    $manifest.MonitorSampling.AttemptSampleCounts=@(1,0,1)
    Write-Json 'manifest.json' $manifest
    Assert-Pass 'one explicit empty attempt has consistent row coverage'
    $emptyManifest=ConvertFrom-Json -InputObject (Get-Content -LiteralPath (Join-Path $dir 'manifest.json') -Raw)
    $emptyStatus=Get-WtFieldValidationAssessment -Mode Monitor -ContractPassed:$true -AclPassed:$true -Manifest $emptyManifest
    if ($emptyStatus.Validation -ne 'review') { throw 'An empty attempt can never be structural PASS' }
    # The location of a zero slot cannot be proven from retained nonempty rows.
    $manifest.MonitorSampling.AttemptSampleCounts=@(0,1,1)
    Write-Json 'manifest.json' $manifest
    Assert-Pass 'zero slot position remains an unverifiable report claim'
    $manifest.MonitorSampling.RequestedAttempts=2
    $manifest.MonitorSampling.AttemptedAttempts=2
    Write-Consistent $rows
    $manifest.MonitorSampling.Remove('AttemptSampleCounts')
    Write-Json 'manifest.json' $manifest
    Assert-Pass 'older schema-v1 attempt ledger absence remains readable'
    $legacyLedger=ConvertFrom-Json -InputObject (Get-Content -LiteralPath (Join-Path $dir 'manifest.json') -Raw)
    $legacyLedgerState=Get-WtFieldValidationAssessment -Mode Monitor -ContractPassed:$true -AclPassed:$true -Manifest $legacyLedger
    if ($legacyLedgerState.Validation -ne 'review') { throw 'Missing attempt ledger cannot be structural PASS' }
    $manifest.MonitorSampling.AttemptSampleCounts=@(1,1)
    Write-Consistent $rows
    Assert-Pass 'modern ledger remains valid after legacy case'
    $manifest.MonitorSampling.ComparableProcesses=0;Write-Json 'manifest.json' $manifest
    Assert-Fail 'forged comparable'
    Write-Consistent $rows
    $manifest.MonitorSampling.NonEmptyAttempts=1;Write-Json 'manifest.json' $manifest
    Assert-Fail 'forged nonempty attempts'
    Write-Consistent $rows
    $manifest.MonitorSampling.SingletonGroups=1;Write-Json 'manifest.json' $manifest
    Assert-Fail 'forged singleton'
    Write-Consistent $rows
    $manifest.MonitorSampling.UnkeyedSamples=1;Write-Json 'manifest.json' $manifest
    Assert-Fail 'forged unkeyed'
    Write-Consistent $rows
    $manifest.SkippedUnreliableIdentitySamples=1;Write-Json 'manifest.json' $manifest
    Assert-Fail 'forged unreliable'
    Write-Consistent $rows
    $manifest.MemoryGrowthTop=@();Write-Json 'manifest.json' $manifest
    Assert-Pass 'empty top prefix allowed'
    $manifest.MemoryGrowthTop=@([pscustomobject]@{Name='SYNTHETIC_PRIVATE_CANARY'})
    Write-Json 'manifest.json' $manifest
    Assert-Fail 'forged growth top'
    Write-Consistent $rows
    Write-Json 'processes.json' @($rows[0],(Row 4242 $at2 900))
    Assert-Fail 'JSON differs from samples CSV'
    Write-Consistent $rows
    Write-Csv 'memory-samples.csv' @($rows[0]) $sampleCols
    Assert-Fail 'truncated samples CSV'
    Write-Consistent $rows
    Write-Csv 'memory-growth.csv' @() $growthCols
    Assert-Fail 'truncated growth CSV'
    Write-Consistent $rows
    Set-Content -LiteralPath (Join-Path $dir 'memory-growth.csv') -Value 'Name,PrivateGrowthMiB' -Encoding UTF8
    Assert-Fail 'altered growth headers'
    $mixed=@($rows[0],(Row 4242 $at2 125),(Row 8000 $at1 50),(Row 8000 $at2 70))
    $mixed[1].Pid=9999
    Write-Consistent $mixed
    Assert-Pass 'mixed rejected group counted'
    $manifest.MonitorSampling.RejectedGrowthGroups=0;Write-Json 'manifest.json' $manifest
    Assert-Fail 'rejection concealed'
    $single=@((Row 4242 $at1 100),(Row 9000 $at2 88))
    $single[1].InstanceKey='wrong|identity'
    Write-Consistent $single
    Assert-Pass 'invalid singleton counted'
    $manifest.MonitorSampling.InvalidSingletonGroups=0;Write-Json 'manifest.json' $manifest
    Assert-Fail 'invalid singleton concealed'
    $unkeyed=@((Row 4242 $at1 100),(Row 4242 $at2 125),(Row 9000 $at1 12 $false))
    Write-Consistent $unkeyed
    Assert-Pass 'unkeyed and unreliable recorded'
    $manifest.MonitorSampling.UnkeyedSamples=0;Write-Json 'manifest.json' $manifest
    Assert-Fail 'unkeyed concealed'
    Write-Consistent $rows
    $manifest.MonitorSampling.Remove('UnkeyedSamples')
    Write-Json 'manifest.json' $manifest
    Assert-Pass 'legacy schema-v1 readable'
    $legacy=ConvertFrom-Json -InputObject (Get-Content -LiteralPath (Join-Path $dir 'manifest.json') -Raw)
    $status=Get-WtFieldValidationAssessment -Mode Monitor -ContractPassed:$true -AclPassed:$true -Manifest $legacy
    if ($status.Validation -ne 'review') { throw 'Legacy report cannot be structural PASS' }
    Write-Host 'PASS: invented Monitor report content reconciliation and legacy review'
} finally {
    if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
}
