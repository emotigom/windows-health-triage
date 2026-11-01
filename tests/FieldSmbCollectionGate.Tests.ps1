#requires -Version 5.1
# ADR-065: invented SMB states and a deliberately invalid path; no real share enumeration.
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'tools\WinTriage.FieldSmbPreflight.psm1') -Force
function Assert-GateFixture([bool]$Condition,[string]$Label) {
    if (-not $Condition) { throw ('Synthetic SMB field guard regression: '+$Label) }
}
$fixed='SMB field collection guard blocked or inconclusive; review storage privately.'
foreach ($state in @('BROAD_ACCESS_REVIEW','SHARED_REVIEW','UNKNOWN','NOT_CHECKED')) {
    $blocked=$false
    try {
        Assert-WtFieldSmbCollectionGate -PathState 'REVIEW_REQUIRED' -SmbExposure $state
    } catch {
        $blocked=($_.Exception.Message -eq $fixed)
    }
    Assert-GateFixture $blocked ('unsafe SMB state must block: '+$state)
}
foreach ($pathState in @('REJECTED','UNKNOWN')) {
    $blocked=$false
    try {
        Assert-WtFieldSmbCollectionGate -PathState $pathState -SmbExposure 'NO_NON_SPECIAL_SHARE_OBSERVED'
    } catch { $blocked=($_.Exception.Message -eq $fixed) }
    Assert-GateFixture $blocked ('bad path cannot be cleared by empty ordinary share set: '+$pathState)
}
# Invented providers, including an unavailable SMB service and administrative share.
$fictionalPath='C:\FICTIVE_COLLECTION\REPORTS'
$empty=Get-WtFieldSmbExposure -Directory $fictionalPath -PathState 'REVIEW_REQUIRED' -ShareProvider { @() } -AccessProvider { throw 'MUST_NOT_ENUMERATE_ACCESS' }
Assert-GateFixture ($empty -eq 'NO_NON_SPECIAL_SHARE_OBSERVED') 'empty ordinary share inventory is a narrow observation'
Assert-GateFixture ($null -eq (Assert-WtFieldSmbCollectionGate -PathState 'REVIEW_REQUIRED' -SmbExposure $empty)) 'narrow no-extra-SMB-block result is silent, not approval'
$unavailable=Get-WtFieldSmbExposure -Directory $fictionalPath -PathState 'REVIEW_REQUIRED' -ShareProvider { throw 'FICTIVE_UNAVAILABLE_PROVIDER_PRIVATE_CANARY' } -AccessProvider { throw 'MUST_NOT_ACCESS' }
Assert-GateFixture ($unavailable -eq 'UNKNOWN') 'service absent or access denied is unknown'
$blocked=$false
try { Assert-WtFieldSmbCollectionGate -PathState 'REVIEW_REQUIRED' -SmbExposure $unavailable } catch { $blocked=($_.Exception.Message -eq $fixed) }
Assert-GateFixture $blocked 'unavailable provider must block'
$special=Get-WtFieldSmbExposure -Directory $fictionalPath -PathState 'REVIEW_REQUIRED' -ShareProvider {
    [pscustomobject]@{Path='C:\';Name='FICTIVE_ADMIN$';Special=$true}
} -AccessProvider {
    param($share)
    [pscustomobject]@{AccountName='S-1-5-32-544';AccessControlType='Allow';AccessRight='Full'}
}
Assert-GateFixture ($special -eq 'SHARED_REVIEW') 'if special share leaks through provider it cannot be cleared'
# The opt-in command must refuse an invented relative path before any collection.
# No SMB provider is called for a rejected path; no output directory is created.
$exe=if ($PSVersionTable.PSEdition -eq 'Desktop') { Join-Path $PSHOME 'powershell.exe' } else { Join-Path $PSHOME 'pwsh.exe' }
$PSNativeCommandUseErrorActionPreference=$false
$previousPreference=$ErrorActionPreference
try {
    # A failing child emits PowerShell error-stream objects on Windows PS 5.1;
    # capture them without allowing the parent test's Stop policy to terminate.
    $ErrorActionPreference='Continue'
    $lines=@(& $exe -NoProfile -NonInteractive -File (Join-Path $root 'Invoke-WtFieldValidation.ps1') -OutputDir 'relative\FICTIONAL_PRIVATE_CANARY' -RequireSmbPreflight 2>&1 | Out-String)
    $code=$LASTEXITCODE
} finally {
    $ErrorActionPreference=$previousPreference
}
Assert-GateFixture ($code -eq 2) 'invalid opt-in collection must return fixed exit 2'
$output=($lines -join [Environment]::NewLine)
Assert-GateFixture ($output.Trim() -eq 'SmbCollectionGate: BLOCKED_OR_UNKNOWN') 'early rejection emits exactly one fixed line and no environment banner'
Assert-GateFixture (-not $output.Contains($fixed)) 'internal exception message must not escape top-level guard'
Assert-GateFixture (-not $output.Contains('relative\FICTIONAL_PRIVATE_CANARY')) 'caller path must not be echoed'
Assert-GateFixture (-not $output.Contains('.psm1:')) 'PowerShell module path and stack must not appear'
Assert-GateFixture (-not $output.Contains('At ')) 'unhandled exception source line must not appear'
# Test a missing optional SMB module from a disposable SYNTHETIC clone.
# Copy only script/module sources, never reports, logs, SMB state or system ACL.
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('WtGuardSynthetic_'+[guid]::NewGuid().ToString('N'))
try {
    [void][IO.Directory]::CreateDirectory((Join-Path $fixture 'src'))
    [void][IO.Directory]::CreateDirectory((Join-Path $fixture 'tests'))
    [void][IO.Directory]::CreateDirectory((Join-Path $fixture 'tools'))
    Copy-Item -LiteralPath (Join-Path $root 'Invoke-WtFieldValidation.ps1') -Destination $fixture
    foreach ($module in @('WinTriage.ReportSecurity.psm1','WinTriage.IntegrityCollector.psm1','WinTriage.FieldValidation.psm1')) {
        Copy-Item -LiteralPath (Join-Path $root ('src\'+$module)) -Destination (Join-Path $fixture 'src')
    }
    foreach ($module in @('ReportContract.psm1','MonitorContentContract.psm1')) {
        Copy-Item -LiteralPath (Join-Path $root ('tests\'+$module)) -Destination (Join-Path $fixture 'tests')
    }
    Copy-Item -LiteralPath (Join-Path $root 'tools\WinTriage.FieldPreflight.psm1') -Destination (Join-Path $fixture 'tools')
    # Intentionally do NOT copy WinTriage.FieldSmbPreflight.psm1.
    $previousPreference=$ErrorActionPreference
    try {
        $ErrorActionPreference='Continue'
        $loaderLines=@(& $exe -NoProfile -NonInteractive -File (Join-Path $fixture 'Invoke-WtFieldValidation.ps1') -OutputDir 'relative\FICTIONAL_IMPORT_CANARY' -RequireSmbPreflight 2>&1 | Out-String)
        $loaderExit=$LASTEXITCODE
    } finally {
        $ErrorActionPreference=$previousPreference
    }
    Assert-GateFixture ($loaderExit -eq 2) 'missing optional module exits 2'
    Assert-GateFixture ((($loaderLines -join [Environment]::NewLine).Trim()) -eq 'SmbCollectionGate: BLOCKED_OR_UNKNOWN') 'missing optional module has no PowerShell loader path or exception text'
} finally {
    # Only the disposable, test-created synthetic checkout is removed.
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force }
}
$global:LASTEXITCODE=0
Write-Host 'PASS: invented SMB fail-closed gate; first rejection and optional module failure are fixed-only'
