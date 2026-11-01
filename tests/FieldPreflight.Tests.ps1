#requires -Version 5.1
# ADR-062: synthetic environment/path decisions; never collects user reports.
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'tools\WinTriage.FieldPreflight.psm1') -Force
function Assert-Preflight {
    param([bool]$Condition,[string]$Label)
    if (-not $Condition) { throw ('Synthetic preflight regression: '+$Label) }
}
$input=@{Build=19045;ProductType=1;PSMajor=5;PSMinor=1;Privilege='standard';PathState='REVIEW_REQUIRED'}
$w10=Get-WtFieldPreflightAssessment @input
Assert-Preflight ($w10.CandidateCell -eq 'WINDOWS10_POWERSHELL51_STANDARD') 'Windows 10 PS5.1 standard candidate'
Assert-Preflight ($w10.Decision -eq 'NO_GO') 'no automatic GO'
Assert-Preflight ($w10.NextAction -eq 'INDEPENDENT_APPROVAL_REQUIRED') 'all apparent preflight checks still need approval'
$input.Build=22631;$input.PSMajor=7;$input.PSMinor=5;$input.Privilege='elevated'
$w11=Get-WtFieldPreflightAssessment @input
Assert-Preflight ($w11.CandidateCell -eq 'WINDOWS11_POWERSHELL7_ELEVATED') 'elevated is NOT an authorization'
Assert-Preflight ($w11.OperatorAuthorization -eq 'NOT_VERIFIED') 'unverified elevation authorization'
$input.ProductType=3
$server=Get-WtFieldPreflightAssessment @input
Assert-Preflight ($server.OperatingSystem -eq 'UNSUPPORTED') 'server cannot become Windows 11'
Assert-Preflight ($server.CandidateCell -eq 'UNVERIFIED') 'server no candidate'
$input.ProductType=1;$input.PSMajor=6
$unsupportedShell=Get-WtFieldPreflightAssessment @input
Assert-Preflight ($unsupportedShell.PowerShell -eq 'UNSUPPORTED') 'PowerShell 6 unsupported'
$input.PSMajor=7;$input.PathState='REJECTED'
$blockedPath=Get-WtFieldPreflightAssessment @input
Assert-Preflight ($blockedPath.NextAction -eq 'SELECT_LOCAL_PRIVATE_PATH') 'known path issue fails closed'
$input.PathState='UNKNOWN';$input.Privilege='unknown'
$unknown=Get-WtFieldPreflightAssessment @input
Assert-Preflight ($unknown.NextAction -eq 'VERIFY_ENVIRONMENT_PRIVATELY') 'unknown is not success'
foreach ($case in @($w10,$w11,$server,$unsupportedShell,$blockedPath,$unknown)) {
    Assert-Preflight ($case.Decision -eq 'NO_GO' -and $case.ReleaseDecision -eq 'NO_GO') 'unconditional no go'
    Assert-Preflight ($case.RootAuthority -eq 'NOT_VERIFIED') 'initial root is independent'
    Assert-Preflight ($case.StorageSyncBackup -eq 'NOT_VERIFIED') 'sync risk remains externally reviewed'
    Assert-Preflight ($case.IndependentReview -eq 'NOT_AUTHENTICATED') 'approval cannot be inferred'
}
foreach ($bad in @('relative\output','C:relative','\\SYNTHETIC_SERVER\share','')) {
    Assert-Preflight ((Get-WtFieldPreflightPathState -Directory $bad) -eq 'REJECTED') 'relative/UNC path must reject'
}
# Launch the *separate* preflight in a new PowerShell process, never a field run.
# Only a deliberately invalid relative path is supplied; no real data is opened.
$exe=if ($PSVersionTable.PSEdition -eq 'Desktop') {
    Join-Path $PSHOME 'powershell.exe'
} else {
    Join-Path $PSHOME 'pwsh.exe'
}
$preflightScript=Join-Path $root 'Test-WtFieldPreflight.ps1'
$PSNativeCommandUseErrorActionPreference=$false
$lines=@(& $exe -NoProfile -NonInteractive -File $preflightScript -OutputDir 'relative\synthetic' 2>&1)
$exitCode=$LASTEXITCODE
Assert-Preflight ($exitCode -eq 2) 'CLI always returns exit 2'
Assert-Preflight ($lines.Count -eq 17) 'fixed output contract count'
Assert-Preflight ($lines[0] -eq 'Decision: NO_GO') 'CLI fixed decision'
Assert-Preflight ($lines[1] -eq 'Preflight: NO_AUTOMATIC_FIELD_RUN') 'CLI cannot launch collector'
Assert-Preflight ($lines[6] -eq 'OutputPath: REJECTED') 'CLI refuses relative output path'
Assert-Preflight ($lines[7] -eq 'NextAction: SELECT_LOCAL_PRIVATE_PATH') 'CLI fixed next action'
Assert-Preflight ($lines[12] -eq 'ReleaseDecision: NO_GO') 'CLI fixed release decision'
Assert-Preflight ($lines[16] -eq 'ReleaseBlocker: EXTERNAL_RELEASE_AUTHORITY') 'last release blocker'
foreach ($line in $lines) {
    Assert-Preflight ([string]$line -notmatch 'synthetic|relative|\\|C:|SYNTHETIC') 'no caller path on stdout'
}
# The child deliberately exits 2; after asserting that outcome, clear the
# test host's native exit status so the Actions step reflects test success.
$global:LASTEXITCODE=0
Write-Host 'PASS: synthetic field preflight OS/shell/path/privilege classification, read-only CLI and NO_GO privacy'
