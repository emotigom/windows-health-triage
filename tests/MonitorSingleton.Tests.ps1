#requires -Version 5.1
# ADR-046: invented only. No live process reads, native scans or private reports.
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'src\WinTriage.Core.psm1') -Force
Import-Module (Join-Path $root 'src\WinTriage.FieldValidation.psm1') -Force
function Assert-Singleton {
    param([bool]$Condition,[string]$Label)
    if (-not $Condition) { throw ('Invented singleton coverage assertion: ' + $Label) }
}
function New-Row {
    param([int]$ProcessId=1234,[string]$At='2026-10-31T01:00:00Z')
    $start='2026-10-31T00:00:00Z'
    [pscustomobject]@{
        InstanceKey=('{0}|{1}' -f $ProcessId,$start)
        Pid=$ProcessId;StartedUtc=$start;IdentityReliable=$true
        SampleTimeUtc=$At;Name='SYNTHETIC_SINGLETON_PRIVATE_CANARY'
        PrivateMiB=100;WorkingSetMiB=150
    }
}
function Assess {
    param([hashtable]$Quality,[int]$Comparable)
    $manifest=[pscustomobject]@{
        Mode='Monitor';Warnings=@();SkippedUnreliableIdentitySamples=0
        MonitorSampling=[pscustomobject]@{
            RequestedAttempts=2;AttemptedAttempts=2;NonEmptyAttempts=2
            ComparableProcesses=$Comparable
            RejectedGrowthGroups=$Quality['RejectedGrowthGroups']
            SingletonGroups=$Quality['SingletonGroups']
            InvalidSingletonGroups=$Quality['InvalidSingletonGroups']
            UnkeyedSamples=$Quality['UnkeyedSamples']
        }
    }
    $result=Get-WtFieldValidationAssessment -Mode Monitor -ContractPassed:$true -AclPassed:$true -Manifest $manifest
    $serialized=ConvertTo-Json -InputObject $result -Depth 4
    Assert-Singleton (-not $serialized.Contains('SYNTHETIC_SINGLETON_PRIVATE_CANARY')) 'private marker not allowed in status'
    return $result
}
$goodA=New-Row -ProcessId 1234 -At '2026-10-31T01:00:00Z'
$goodB=New-Row -ProcessId 1234 -At '2026-10-31T01:00:10Z'
$normal=New-Row -ProcessId 9001 -At '2026-10-31T01:00:05Z'
$q=@{}
$growth=@(Get-WtProcessGrowth -Samples @($goodA,$goodB,$normal) -QualityInfo $q)
Assert-Singleton ($growth.Count -eq 1) 'valid comparison alongside process churn'
Assert-Singleton ($q['SingletonGroups'] -eq 1 -and $q['InvalidSingletonGroups'] -eq 0 -and
    $q['UnkeyedSamples'] -eq 0 -and $q['RejectedGrowthGroups'] -eq 0) 'legitimate singleton tracked without false rejection'
Assert-Singleton ((Assess -Quality $q -Comparable $growth.Count).Validation -eq 'pass') 'legitimate process churn is structural only'

$invalid=New-Row -ProcessId 9002 -At '2026-10-31T01:00:05Z'
$invalid.Pid=9003
$q=@{}
$growth=@(Get-WtProcessGrowth -Samples @($goodA,$goodB,$invalid) -QualityInfo $q)
Assert-Singleton ($growth.Count -eq 1 -and $q['InvalidSingletonGroups'] -eq 1) 'invalid one-off PID/key evidence tracked'
Assert-Singleton ((Assess -Quality $q -Comparable $growth.Count).Validation -eq 'review') 'malformed singleton alongside valid growth requires review'

$noKey=New-Row -ProcessId 9004 -At '2026-10-31T01:00:05Z'
$noKey.InstanceKey=$null
$q=@{}
$growth=@(Get-WtProcessGrowth -Samples @($goodA,$goodB,$noKey) -QualityInfo $q)
Assert-Singleton ($growth.Count -eq 1 -and $q['UnkeyedSamples'] -eq 1) 'missing identity key tracked without exposure'
Assert-Singleton ((Assess -Quality $q -Comparable $growth.Count).Validation -eq 'review') 'unkeyed row alongside valid growth requires review'

$invalidTime=New-Row -ProcessId 9005 -At 'SYNTHETIC_SINGLETON_PRIVATE_CANARY'
$q=@{}
$growth=@(Get-WtProcessGrowth -Samples @($goodA,$goodB,$invalidTime) -QualityInfo $q)
Assert-Singleton ($growth.Count -eq 1 -and $q['InvalidSingletonGroups'] -eq 1) 'invalid one-off timestamp independently counted'
Assert-Singleton ((Assess -Quality $q -Comparable $growth.Count).Validation -eq 'review') 'invalid-time singleton requires review'

$unreliable=New-Row -ProcessId 9006 -At '2026-10-31T01:00:05Z'
$unreliable.IdentityReliable=$false
$q=@{}
$growth=@(Get-WtProcessGrowth -Samples @($goodA,$goodB,$unreliable) -QualityInfo $q)
Assert-Singleton ($q['InvalidSingletonGroups'] -eq 1) 'unreliable singleton separately counted'
Assert-Singleton ((Assess -Quality $q -Comparable $growth.Count).Validation -eq 'review') 'unreliable singleton requires review'

$q=@{ SingletonGroups=444;InvalidSingletonGroups=444;UnkeyedSamples=444;RejectedGrowthGroups=444 }
$growth=@(Get-WtProcessGrowth -Samples @($goodA,$goodB) -QualityInfo $q)
Assert-Singleton ($growth.Count -eq 1 -and $q['SingletonGroups'] -eq 0 -and
    $q['InvalidSingletonGroups'] -eq 0 -and $q['UnkeyedSamples'] -eq 0 -and
    $q['RejectedGrowthGroups'] -eq 0) 'caller-owned counters reset without cross-run leaks'
Assert-Singleton ((Assess -Quality $q -Comparable $growth.Count).Validation -eq 'pass') 'complete invented comparison remains structure-only pass'
Write-Host 'PASS: invented singleton churn distinguished from missing-key, malformed and unreliable one-off observations'
