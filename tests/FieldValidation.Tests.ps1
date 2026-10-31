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
    RequestedAttempts=2;AttemptedAttempts=2;NonEmptyAttempts=2;ComparableProcesses=1
})
$opts=@{Mode='Monitor';ContractPassed=$true;AclPassed=$true;Manifest=$manifest}
$monitor=Get-WtFieldValidationAssessment @opts
Assert-V $monitor.Validation 'pass' 'complete invented Monitor metadata, structural only'
$manifest.MonitorSampling.NonEmptyAttempts=1
$monitorEmpty=Get-WtFieldValidationAssessment @opts
Assert-V $monitorEmpty.Validation 'review' 'silent empty Monitor attempt is inconclusive'
$manifest.MonitorSampling.NonEmptyAttempts=2
$manifest.MonitorSampling.ComparableProcesses=0
$monitorNoMatch=Get-WtFieldValidationAssessment @opts
Assert-V $monitorNoMatch.Validation 'review' 'no comparable process identities is inconclusive'
$manifest.MonitorSampling.ComparableProcesses=0
$manifest.MonitorSampling.NonEmptyAttempts=1
$manifest.MonitorSampling.AttemptedAttempts=1
$monitorShort=Get-WtFieldValidationAssessment @opts
Assert-V $monitorShort.Validation 'review' 'short sampling run is inconclusive'
$manifest.MonitorSampling.AttemptedAttempts=2
$manifest.MonitorSampling.NonEmptyAttempts=2
$manifest.MonitorSampling.ComparableProcesses=1
$manifest.MonitorSampling.RequestedAttempts=$true
$monitorInvalid=Get-WtFieldValidationAssessment @opts
Assert-V $monitorInvalid.Validation 'fail' 'boolean count is invalid'
$manifest.MonitorSampling.RequestedAttempts=2
$manifest.MonitorSampling=$null
$monitorOld=Get-WtFieldValidationAssessment @opts
Assert-V $monitorOld.Validation 'review' 'legacy Monitor without attempt counts is inconclusive'
# Output is an allowlist; every string above is a synthetic canary that must not escape.
$aggregate=@($pass,$noAcl,$noSchema,$warn,$incomplete,$bounded,$quick,$bad,$passive,$unsafe,$unknown,$monitor,$monitorEmpty,$monitorNoMatch,$monitorShort,$monitorInvalid,$monitorOld) | ConvertTo-Json -Depth 7
foreach ($secret in @('SYNTHETIC_SECRET_HOST','FICTIONAL','SECRET-PATH','PRIVATE')) {
    if ($aggregate.Contains($secret)) { throw 'Sensitive free-form data leaked into field statuses' }
}
Write-Host 'PASS: synthetic field statuses, fail-closed permissions, passive-only boundary and no private text passthrough'
