#requires -Version 5.1
# Completely fabricated reports: no live data, no native security or system scans.
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'src\WinTriage.FieldValidation.psm1') -Force
function Assert-V {
    param($Actual,$Expected,[string]$Label)
    if ($Actual -ne $Expected) { throw ("{0}: expected [{1}], got [{2}]" -f $Label,$Expected,$Actual) }
}
$sampling=[pscustomobject]@{
    System=[pscustomobject]@{Incomplete=$false;AnyQueryReachedLimit=$false;QueryFailures=0;ProjectionFailures=0}
}
$manifest=[pscustomobject]@{
    Mode='Events';Warnings=@();EventSampling=$sampling
    Scan=[pscustomobject]@{Defender='not-requested';ClamAV='not-requested'}
    Computer='SYNTHETIC_SECRET_HOST';Other='C:\FICTIONAL\PRIVATE'
}
$options=@{Mode='Events';ContractPassed=$true;AclPassed=$true;Manifest=$manifest}
$pass=Get-WtFieldValidationAssessment @options
Assert-V $pass.Validation 'pass' 'complete synthetic report structure'
Assert-V $pass.PrivateAcl 'pass' 'restricted ACL contract'
Assert-V $pass.Interpretation 'review-not-health-proof' 'never claim healthy'
Assert-V $pass.OriginVerification 'not-authenticated' 'structural pass does not prove report origin'
Assert-V $pass.ReleaseDecision 'NO_GO' 'structural pass cannot authorize release'

$noAcl=Get-WtFieldValidationAssessment -Mode Events -ContractPassed:$true -AclPassed:$false -Manifest $manifest
Assert-V $noAcl.Validation 'fail' 'no ACL is fatal'
$noSchema=Get-WtFieldValidationAssessment -Mode Events -ContractPassed:$false -AclPassed:$true -Manifest $manifest
Assert-V $noSchema.Validation 'fail' 'no schema is fatal'
$manifest.Warnings=@('SYNTHETIC-SECRET-PATH: C:\PRIVATE\SECRET')
$warn=Get-WtFieldValidationAssessment @options
Assert-V $warn.Validation 'review' 'warnings require review'
Assert-V $warn.Warnings 'present' 'warnings only reported as presence'
$manifest.Warnings=@()
$sampling.System.Incomplete=$true
$incomplete=Get-WtFieldValidationAssessment @options
Assert-V $incomplete.Validation 'review' 'incomplete event sampling'
$sampling.System.Incomplete=$false
$sampling.System.AnyQueryReachedLimit=$true
$bounded=Get-WtFieldValidationAssessment @options
Assert-V $bounded.Validation 'review' 'reached event cap'
$sampling.System.AnyQueryReachedLimit=$false
$manifest.Mode='Quick'
$security=[pscustomobject]@{RequestedScan='none';DefenderScanResult='not-requested';ClamAVResult='not-requested'}
$hardware=[pscustomobject]@{StorageAssessments=@([pscustomobject]@{Assessment='inconclusive'})}
$opts=@{Mode='Quick';ContractPassed=$true;AclPassed=$true;Manifest=$manifest;Security=$security;Hardware=$hardware}
$quick=Get-WtFieldValidationAssessment @opts
Assert-V $quick.PassiveNativeScans 'not-requested' 'Quick default passive'
Assert-V $quick.Validation 'review' 'storage cannot be pronounced healthy'
$security.RequestedScan='Defender QuickScan'
$bad=Get-WtFieldValidationAssessment @opts
Assert-V $bad.Validation 'fail' 'unexpected active scan fails'
Assert-V $bad.PassiveNativeScans 'unexpected' 'unsafe scanner request marked'
$security.RequestedScan='none'
$manifest.Mode='Integrity'
$integrity=[pscustomobject]@{Administrator=$false;SfcVerifyOnly='not-requested';DismScanHealth='not-requested'}
$opts=@{Mode='Integrity';ContractPassed=$true;AclPassed=$true;Manifest=$manifest;Integrity=$integrity}
$passive=Get-WtFieldValidationAssessment @opts
Assert-V $passive.Validation 'pass' 'passive Integrity structural status'
Assert-V $passive.PassiveNativeScans 'not-requested' 'SFC/DISM not invoked'
$integrity.SfcVerifyOnly='completed-review-output'
$unsafe=Get-WtFieldValidationAssessment @opts
Assert-V $unsafe.Validation 'fail' 'unexpected SFC invocation fails validation'
$manifest.Mode='Hardware'
$opts=@{Mode='Hardware';ContractPassed=$true;AclPassed=$true;Manifest=$manifest;Hardware=[pscustomobject]@{StorageAssessments=@()}}
$unknown=Get-WtFieldValidationAssessment @opts
Assert-V $unknown.Validation 'review' 'unavailable storage evidence is never clean'
$manifest.Mode='Monitor'
$manifest | Add-Member -NotePropertyName MonitorSampling -NotePropertyValue ([pscustomobject]@{
    RequestedAttempts=2;AttemptedAttempts=2;NonEmptyAttempts=2;ComparableProcesses=1;RejectedGrowthGroups=0
    SingletonGroups=0;InvalidSingletonGroups=0;UnkeyedSamples=0;AttemptSampleCounts=@(1,1)
})
$manifest | Add-Member -NotePropertyName SkippedUnreliableIdentitySamples -NotePropertyValue 0
$opts=@{Mode='Monitor';ContractPassed=$true;AclPassed=$true;Manifest=$manifest}
$monitor=Get-WtFieldValidationAssessment @opts
Assert-V $monitor.Validation 'pass' 'complete invented Monitor metadata, structural only'
$manifest.MonitorSampling.SingletonGroups=4
$monitorNormalSingleton=Get-WtFieldValidationAssessment @opts
Assert-V $monitorNormalSingleton.Validation 'pass' 'valid singleton churn alone must not force review'
$manifest.MonitorSampling.SingletonGroups=0
$manifest.MonitorSampling.InvalidSingletonGroups=1
$monitorBadSingleton=Get-WtFieldValidationAssessment @opts
Assert-V $monitorBadSingleton.Validation 'review' 'invalid singleton with valid growth must review'
$manifest.MonitorSampling.InvalidSingletonGroups=0
$manifest.MonitorSampling.UnkeyedSamples=1
$monitorUnkeyed=Get-WtFieldValidationAssessment @opts
Assert-V $monitorUnkeyed.Validation 'review' 'missing key with valid growth must review'
$manifest.MonitorSampling.UnkeyedSamples=0
$manifest.MonitorSampling.PSObject.Properties.Remove('SingletonGroups')
$monitorOldSingleton=Get-WtFieldValidationAssessment @opts
Assert-V $monitorOldSingleton.Validation 'review' 'older quality metadata lacks singleton visibility'
$manifest.MonitorSampling | Add-Member -NotePropertyName SingletonGroups -NotePropertyValue 0
$manifest.MonitorSampling.InvalidSingletonGroups=$true
$monitorInvalidSingletonCount=Get-WtFieldValidationAssessment @opts
Assert-V $monitorInvalidSingletonCount.Validation 'fail' 'boolean invalid singleton counter is rejected'
$manifest.MonitorSampling.InvalidSingletonGroups=0
$manifest.MonitorSampling.UnkeyedSamples=-1
$monitorInvalidUnkeyedCount=Get-WtFieldValidationAssessment @opts
Assert-V $monitorInvalidUnkeyedCount.Validation 'fail' 'negative unkeyed count is rejected'
$manifest.MonitorSampling.UnkeyedSamples=0
$manifest.MonitorSampling.RejectedGrowthGroups=1
$monitorRejected=Get-WtFieldValidationAssessment @opts
Assert-V $monitorRejected.Validation 'review' 'one rejected group despite valid growth must review'
$manifest.MonitorSampling.RejectedGrowthGroups=0
$manifest.SkippedUnreliableIdentitySamples=1
$monitorUnreliable=Get-WtFieldValidationAssessment @opts
Assert-V $monitorUnreliable.Validation 'review' 'one unreliable identity despite valid growth must review'
$manifest.SkippedUnreliableIdentitySamples=0
$manifest.MonitorSampling.PSObject.Properties.Remove('RejectedGrowthGroups')
$monitorLegacyQuality=Get-WtFieldValidationAssessment @opts
Assert-V $monitorLegacyQuality.Validation 'review' 'legacy v1 Monitor without quality telemetry must review'
$manifest.MonitorSampling | Add-Member -NotePropertyName RejectedGrowthGroups -NotePropertyValue 0
$manifest.MonitorSampling.RejectedGrowthGroups=$true
$monitorBadQuality=Get-WtFieldValidationAssessment @opts
Assert-V $monitorBadQuality.Validation 'fail' 'boolean rejected count is invalid'
$manifest.MonitorSampling.RejectedGrowthGroups=-1
$monitorNegativeQuality=Get-WtFieldValidationAssessment @opts
Assert-V $monitorNegativeQuality.Validation 'fail' 'negative rejected count is invalid'
$manifest.MonitorSampling.RejectedGrowthGroups=0
$manifest.MonitorSampling.NonEmptyAttempts=1
$manifest.MonitorSampling.AttemptSampleCounts=@(1,0)
$manifest.MonitorSampling.ComparableProcesses=0
$monitorEmpty=Get-WtFieldValidationAssessment @opts
Assert-V $monitorEmpty.Validation 'review' 'silent empty Monitor attempt is inconclusive'
$manifest.MonitorSampling.NonEmptyAttempts=2
$manifest.MonitorSampling.AttemptSampleCounts=@(1,1)
$manifest.MonitorSampling.ComparableProcesses=0
$monitorNoMatch=Get-WtFieldValidationAssessment @opts
Assert-V $monitorNoMatch.Validation 'review' 'no comparable process identities is inconclusive'
$manifest.MonitorSampling.ComparableProcesses=0
$manifest.MonitorSampling.NonEmptyAttempts=1
$manifest.MonitorSampling.AttemptedAttempts=1
$manifest.MonitorSampling.AttemptSampleCounts=@(1)
$monitorShort=Get-WtFieldValidationAssessment @opts
Assert-V $monitorShort.Validation 'review' 'short sampling run is inconclusive'
$manifest.MonitorSampling.AttemptedAttempts=2
$manifest.MonitorSampling.AttemptSampleCounts=@(1,1)
$manifest.MonitorSampling.NonEmptyAttempts=2
$manifest.MonitorSampling.ComparableProcesses=1
$manifest.MonitorSampling.AttemptSampleCounts=@($true,1)
$ledgerBad=Get-WtFieldValidationAssessment @opts
Assert-V $ledgerBad.Validation 'fail' 'boolean attempt ledger entry rejected'
$manifest.MonitorSampling.AttemptSampleCounts=@(1,1)
$manifest.MonitorSampling.PSObject.Properties.Remove('AttemptSampleCounts')
$ledgerOld=Get-WtFieldValidationAssessment @opts
Assert-V $ledgerOld.Validation 'review' 'old report without attempt ledger cannot pass'
$manifest.MonitorSampling | Add-Member -NotePropertyName AttemptSampleCounts -NotePropertyValue @(1,1)
$manifest.MonitorSampling.RequestedAttempts=$true
$monitorInvalid=Get-WtFieldValidationAssessment @opts
Assert-V $monitorInvalid.Validation 'fail' 'boolean count is invalid'
$manifest.MonitorSampling.RequestedAttempts=2
$manifest.MonitorSampling=$null
$monitorOld=Get-WtFieldValidationAssessment @opts
Assert-V $monitorOld.Validation 'review' 'legacy Monitor without attempt counts is inconclusive'
# Self-asserted metadata, even an invented signature and approval, cannot
# promote report origin or release. The assessment owns these fixed labels.
$manifest.MonitorSampling=[pscustomobject]@{
    RequestedAttempts=2;AttemptedAttempts=2;NonEmptyAttempts=2;ComparableProcesses=1
    RejectedGrowthGroups=0;SingletonGroups=0;InvalidSingletonGroups=0
    UnkeyedSamples=0;AttemptSampleCounts=@(1,1)
}
$manifest | Add-Member -NotePropertyName OriginVerified -NotePropertyValue $true
$manifest | Add-Member -NotePropertyName ReleaseApproved -NotePropertyValue $true
$manifest | Add-Member -NotePropertyName SignedBy -NotePropertyValue 'SYNTHETIC_SECRET_HOST'
$spoof=Get-WtFieldValidationAssessment @opts
Assert-V $spoof.Validation 'pass' 'synthetic completeness stays structural only'
Assert-V $spoof.OriginVerification 'not-authenticated' 'self-attestation is not independent authentication'
Assert-V $spoof.ReleaseDecision 'NO_GO' 'self-approval does not grant release'
$manifest.PSObject.Properties.Remove('OriginVerified')
$manifest.PSObject.Properties.Remove('ReleaseApproved')
$manifest.PSObject.Properties.Remove('SignedBy')
foreach ($assessment in @($pass,$monitor,$noAcl,$noSchema,$spoof)) {
    Assert-V $assessment.OriginVerification 'not-authenticated' 'all origins unverified'
    Assert-V $assessment.ReleaseDecision 'NO_GO' 'all release decisions NO_GO'
}

# Output is an allowlist; every string above is a synthetic canary that must not escape.
$aggregate=@($pass,$noAcl,$noSchema,$warn,$incomplete,$bounded,$quick,$bad,$passive,$unsafe,$unknown,$monitor,$monitorNormalSingleton,$monitorBadSingleton,$monitorUnkeyed,$monitorOldSingleton,$monitorInvalidSingletonCount,$monitorInvalidUnkeyedCount,$monitorRejected,$monitorUnreliable,$monitorLegacyQuality,$monitorBadQuality,$monitorNegativeQuality,$monitorEmpty,$monitorNoMatch,$monitorShort,$monitorInvalid,$monitorOld,$spoof) | ConvertTo-Json -Depth 7
foreach ($secret in @('SYNTHETIC_SECRET_HOST','FICTIONAL','SECRET-PATH','PRIVATE')) {
    if ($aggregate.Contains($secret)) { throw 'Sensitive free-form data leaked into field statuses' }
}
Write-Host 'PASS: synthetic field statuses, fail-closed permissions, passive-only boundary and no private text passthrough'
