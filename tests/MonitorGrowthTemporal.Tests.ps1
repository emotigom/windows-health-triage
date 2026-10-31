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
        [int]$ProcessId=4242,
        [string]$Start='2026-10-31T00:00:00Z',
        [string]$At='2026-10-31T01:00:00Z',
        [int]$MiB=100,
        [bool]$Reliable=$true
    )
    [pscustomobject]@{
        InstanceKey=('{0}|{1}' -f $ProcessId,$Start)
        IdentityReliable=$Reliable
        StartedUtc=$Start;Pid=$ProcessId;Name='SYNTHETIC_PRIVATE_CANARY'
        SampleTimeUtc=$At;PrivateMiB=$MiB;WorkingSetMiB=$MiB
    }
}
function Assert-NoGrowth {
    param([object[]]$Rows,[string]$Label)
    $quality=@{}
    $result=@(Get-WtProcessGrowth -Samples $Rows -QualityInfo $quality)
    Assert-Temporal ($result.Count -eq 0) $Label
    $manifest=[pscustomobject]@{
        Mode='Monitor';Warnings=@()
        SkippedUnreliableIdentitySamples=@($Rows | Where-Object { -not $_.IdentityReliable }).Count
        MonitorSampling=[pscustomobject]@{
            RequestedAttempts=2;AttemptedAttempts=2
            NonEmptyAttempts=2;ComparableProcesses=$result.Count
            RejectedGrowthGroups=$quality['RejectedGrowthGroups']
            SingletonGroups=$quality['SingletonGroups']
            InvalidSingletonGroups=$quality['InvalidSingletonGroups']
            UnkeyedSamples=$quality['UnkeyedSamples']
        }
    }
    $assessment=Get-WtFieldValidationAssessment -Mode Monitor -ContractPassed:$true -AclPassed:$true -Manifest $manifest
    Assert-Temporal ($assessment.Validation -eq 'review') ($Label + ' must produce review, never pass')
    Assert-Temporal (-not (ConvertTo-Json -InputObject $assessment -Depth 4).Contains('SYNTHETIC_PRIVATE_CANARY')) ($Label + ' private canary leaked')
}

$a=New-InventedRow -At '2026-10-31T01:00:00Z' -MiB 100
$b=New-InventedRow -At '2026-10-31T01:00:10Z' -MiB 140
$goodQuality=@{}
$good=@(Get-WtProcessGrowth -Samples @($a,$b) -QualityInfo $goodQuality)
Assert-Temporal ($good.Count -eq 1 -and $good[0].PrivateGrowthMiB -eq 40) 'increasing stable process is comparable'
Assert-Temporal ($goodQuality['RejectedGrowthGroups'] -eq 0) 'fully valid invented pair has zero rejected growth groups'
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
$isolatedA=New-InventedRow -ProcessId 8000 -At '2026-10-31T01:00:00Z'
$isolatedB=New-InventedRow -ProcessId 8000 -At '2026-10-31T01:00:10Z'
$mixedQuality=@{}
$separate=@(Get-WtProcessGrowth -Samples @($a,$reverse,$isolatedA,$isolatedB) -QualityInfo $mixedQuality)
Assert-Temporal ($separate.Count -eq 1 -and $separate[0].Pid -eq 8000) 'bad group must not produce growth while unrelated good group remains'
Assert-Temporal ($mixedQuality['RejectedGrowthGroups'] -eq 1) 'one invalid comparable group is counted without identifiers'
$mixedManifest=[pscustomobject]@{
    Mode='Monitor';Warnings=@();SkippedUnreliableIdentitySamples=0
    MonitorSampling=[pscustomobject]@{
        RequestedAttempts=2;AttemptedAttempts=2;NonEmptyAttempts=2
        ComparableProcesses=$separate.Count;RejectedGrowthGroups=$mixedQuality['RejectedGrowthGroups']
        SingletonGroups=$mixedQuality['SingletonGroups']
        InvalidSingletonGroups=$mixedQuality['InvalidSingletonGroups']
        UnkeyedSamples=$mixedQuality['UnkeyedSamples']
    }
}
$mixedAssessment=Get-WtFieldValidationAssessment -Mode Monitor -ContractPassed:$true -AclPassed:$true -Manifest $mixedManifest
Assert-Temporal ($mixedAssessment.Validation -eq 'review') 'one good and one rejected group must review, never pass'
Assert-Temporal ($mixedAssessment.Warnings -eq 'none') 'group rejection does not invent collector warnings'
Assert-Temporal (-not (ConvertTo-Json -InputObject $mixedAssessment -Depth 4).Contains('SYNTHETIC_PRIVATE_CANARY')) 'mixed group must not echo invented identifiers'
$mixedManifest.MonitorSampling.RejectedGrowthGroups=0
$completeAssessment=Get-WtFieldValidationAssessment -Mode Monitor -ContractPassed:$true -AclPassed:$true -Manifest $mixedManifest
Assert-Temporal ($completeAssessment.Validation -eq 'pass') 'no rejected groups can pass synthetic structure only'
$mixedManifest.SkippedUnreliableIdentitySamples=1
$unreliableAssessment=Get-WtFieldValidationAssessment -Mode Monitor -ContractPassed:$true -AclPassed:$true -Manifest $mixedManifest
Assert-Temporal ($unreliableAssessment.Validation -eq 'review') 'valid growth plus one unreliable identity must review'
Write-Host 'PASS: invented mixed valid/rejected process groups and unreliable identity yield review-only status'
Write-Host 'PASS: invented UTC ordering, start-key consistency, PID reuse and no-false-growth review cases'
