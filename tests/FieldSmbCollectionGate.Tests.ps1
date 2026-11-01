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
$lines=@(& $exe -NoProfile -NonInteractive -File (Join-Path $root 'Invoke-WtFieldValidation.ps1') -OutputDir 'relative\FICTIONAL_PRIVATE_CANARY' -RequireSmbPreflight 2>&1 | Out-String)
$code=$LASTEXITCODE
Assert-GateFixture ($code -ne 0) 'invalid opt-in collection must fail'
$output=($lines -join [Environment]::NewLine)
Assert-GateFixture ($output.Contains($fixed)) 'blocked run must contain only fixed guard error'
Assert-GateFixture (-not $output.Contains('relative\FICTIONAL_PRIVATE_CANARY')) 'caller path must not be echoed'
$global:LASTEXITCODE=0
Write-Host 'PASS: invented pre-collection SMB fail-closed guard and rejected-path no-collection CLI'
