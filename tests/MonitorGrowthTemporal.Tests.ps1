#requires -Version 5.1
# ADR-044: fully synthetic growth identity and UTC ordering counterexamples.
# No live processes, process names from real workstations or native scanning.
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repo 'src\WinTriage.Core.psm1') -Force
Import-Module (Join-Path $repo 'src\WinTriage.FieldValidation.psm1') -Force
function Assert-Temporal {
    param([bool]$Condition,[string]$Label)
    if (-not $Condition) { throw ('Synthetic temporal growth failure: ' + $Label) }
}
function New-InventedRow {
    param(
        [int]$Pid=4242,
        [string]$Start='2026-10-31T00:00:00Z',
        [string]$At='2026-10-31T01:00:00Z',
        [int]$MiB=100,
        [bool]$Reliable=$true
    )
    [pscustomobject]@{
        InstanceKey=('{0}|{1}' -f $Pid,$Start)
        IdentityReliable=$Reliable
        StartedUtc=$Start;Pid=$Pid;Name='SYNTHETIC_PRIVATE_CANARY'
        SampleTimeUtc=$At;PrivateMiB=$MiB;WorkingSetMiB=$MiB
    }
}
function Assert-NoGrowth {
    param([object[]]$Rows,[string]$Label)
    $result=@(Get-WtProcessGrowth -Samples $Rows)
    Assert-Temporal ($result.Count -eq 0) $Label
    $manifest=[pscustomobject]@{
        Mode='Monitor';Warnings=@()
        MonitorSampling=[pscustomobject]@{
            RequestedAttempts=2;AttemptedAttempts=2
            NonEmptyAttempts=2;ComparableProcesses=$result.Count
        }
    }
    $assessment=Get-WtFieldValidationAssessment -Mode Monitor -ContractPassed:$true -AclPassed:$true -Manifest $manifest
    Assert-Temporal ($assessment.Validation -eq 'review') ($Label + ' must produce review, never pass')
    Assert-Temporal (-not (ConvertTo-Json -InputObject $assessment -Depth 4).Contains('SYNTHETIC_PRIVATE_CANARY')) ($Label + ' private canary leaked')
}

$a=New-InventedRow -At '2026-10-31T01:00:00Z' -MiB 100
$b=New-InventedRow -At '2026-10-31T01:00:10Z' -MiB 140
$good=@(Get-WtProcessGrowth -Samples @($a,$b))
Assert-Temporal ($good.Count -eq 1 -and $good[0].PrivateGrowthMiB -eq 40) 'increasing stable process is comparable'
Assert-Temporal ($good[0].Samples -eq 2) 'two distinct invented sample instants'

# PID reuse must not join different process start epochs.
$reused=New-InventedRow -Start '2026-10-31T00:30:00Z' -At '2026-10-31T01:00:10Z' -MiB 500
Assert-NoGrowth @($a,$reused) 'PID recycled with a different start'
$reused.IdentityReliable=$false
Assert-NoGrowth @($a,$reused) 'unreliable replacement identity'
$reused.IdentityReliable=$true

# A tampered record cannot join a trusted interval even if the group key matches.
$forged=New-InventedRow -At '2026-10-31T01:00:10Z' -MiB 500
$forged.Pid=9999
Assert-NoGrowth @($a,$forged) 'PID/key disagreement'
$forged.Pid=4242
$forged.StartedUtc='2026-10-31T00:15:00Z'
Assert-NoGrowth @($a,$forged) 'start/key disagreement'

# Do not sort away clock rollback, duplicate instants or parse invalid/offset time.
$reverse=New-InventedRow -At '2026-10-31T00:59:59Z' -MiB 500
Assert-NoGrowth @($a,$reverse) 'backward sample timestamp'
$same=New-InventedRow -At '2026-10-31T01:00:00Z' -MiB 500
Assert-NoGrowth @($a,$same) 'duplicate sample timestamp'
$badTime=New-InventedRow -At 'SYNTHETIC_PRIVATE_CANARY' -MiB 500
Assert-NoGrowth @($a,$badTime) 'unparseable time'
$offset=New-InventedRow -At '2026-10-31T02:00:10+01:00' -MiB 500
Assert-NoGrowth @($a,$offset) 'noncanonical timezone'
$future=New-InventedRow -Start '2026-10-31T02:00:00Z' -At '2026-10-31T01:00:10Z'
Assert-NoGrowth @($future,(New-InventedRow -Start $future.StartedUtc -At '2026-10-31T01:00:20Z')) 'start time after sample'
$untrusted=New-InventedRow -At '2026-10-31T01:00:10Z' -Reliable:$false
Assert-NoGrowth @($a,$untrusted) 'single unreliable row poisons matching group'
$missing=New-InventedRow -At '2026-10-31T01:00:10Z'
$missing.PSObject.Properties.Remove('IdentityReliable')
Assert-NoGrowth @($a,$missing) 'missing identity marker'

# A bad group must not corrupt a separate good group; the caller still must
# not treat partial coverage as physical machine validation.
$isolatedA=New-InventedRow -Pid 8000 -At '2026-10-31T01:00:00Z'
$isolatedB=New-InventedRow -Pid 8000 -At '2026-10-31T01:00:10Z'
$separate=@(Get-WtProcessGrowth -Samples @($a,$reverse,$isolatedA,$isolatedB))
Assert-Temporal ($separate.Count -eq 1 -and $separate[0].Pid -eq 8000) 'bad group must not produce growth while unrelated good group remains'
Write-Host 'PASS: invented UTC ordering, start-key consistency, PID reuse and no-false-growth review cases'
