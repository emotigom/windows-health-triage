#requires -Version 5.1
# ADR-064: fictional SMB share/ACL providers, no actual Windows share reads.
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'tools\WinTriage.FieldSmbPreflight.psm1') -Force

function Assert-SmbFixture {
    param([bool]$Condition,[string]$Label)
    if (-not $Condition) { throw ('Synthetic SMB preflight regression: '+$Label) }
}
$path='C:\FICTIVE_PARENT\PRIVATE_REPORTS'
$fakeAncestor={ [pscustomobject]@{Path='C:\FICTIVE_PARENT';Name='FictionalShare'} }
$fakeDirect={ [pscustomobject]@{Path='C:\FICTIVE_PARENT\PRIVATE_REPORTS';Name='FictionalExactShare'} }
$broadFull={
    param($share)
    [pscustomobject]@{AccountName='S-1-1-0';AccessControlType='Allow';AccessRight='Full'}
}
$broadRead={
    param($share)
    [pscustomobject]@{AccountName='S-1-5-11';AccessControlType='Allow';AccessRight='Read'}
}
$broadChange={
    param($share)
    [pscustomobject]@{AccountName='S-1-5-32-545';AccessControlType='Allow';AccessRight='Change'}
}
$onlyAdmins={
    param($share)
    [pscustomobject]@{AccountName='S-1-5-32-544';AccessControlType='Allow';AccessRight='Full'}
}
$failCanary={
    param($share)
    throw 'SYNTHETIC_PRIVATE_PATH_AND_ACCOUNT_CANARY'
}
function Evaluate-Smb([string]$Directory,[string]$PathState,[scriptblock]$Shares,[scriptblock]$Access) {
    Get-WtFieldSmbExposure -Directory $Directory -PathState $PathState -ShareProvider $Shares -AccessProvider $Access
}
Assert-SmbFixture ((Evaluate-Smb $path 'REVIEW_REQUIRED' { @() } $failCanary) -eq
    'NO_NON_SPECIAL_SHARE_OBSERVED') 'empty non-special share listing is not a privacy guarantee'
Assert-SmbFixture ((Evaluate-Smb $path 'REVIEW_REQUIRED' $fakeAncestor $broadFull) -eq
    'BROAD_ACCESS_REVIEW') 'ancestor Everyone Full must be reported'
Assert-SmbFixture ((Evaluate-Smb $path 'REVIEW_REQUIRED' $fakeDirect $broadRead) -eq
    'BROAD_ACCESS_REVIEW') 'exact match Authenticated Users Read must be reported'
Assert-SmbFixture ((Evaluate-Smb $path 'REVIEW_REQUIRED' $fakeAncestor $broadChange) -eq
    'BROAD_ACCESS_REVIEW') 'Users Change must be reported'
Assert-SmbFixture ((Evaluate-Smb $path 'REVIEW_REQUIRED' $fakeAncestor $onlyAdmins) -eq
    'SHARED_REVIEW') 'administrator-only share is not a privacy approval'
Assert-SmbFixture ((Evaluate-Smb $path 'REVIEW_REQUIRED' $fakeAncestor $failCanary) -eq
    'UNKNOWN') 'share ACL access failure cannot clear risk'
Assert-SmbFixture ((Evaluate-Smb $path 'REVIEW_REQUIRED' { throw 'PRIVATE_PROVIDER_CANARY' } $onlyAdmins) -eq
    'UNKNOWN') 'share enumeration failure cannot clear risk'
Assert-SmbFixture ((Evaluate-Smb $path 'REVIEW_REQUIRED' {
    [pscustomobject]@{Path='C:\FICTIVE_PARENT_2';Name='AdjacentNotAncestor'}
} $broadFull) -eq 'NO_NON_SPECIAL_SHARE_OBSERVED') 'prefix sibling is not ancestor'
Assert-SmbFixture ((Evaluate-Smb $path 'REVIEW_REQUIRED' {
    [pscustomobject]@{Path='C:\';Name='FictionalRoot'}
} $broadFull) -eq 'BROAD_ACCESS_REVIEW') 'drive root is an ancestor'
Assert-SmbFixture ((Evaluate-Smb $path 'REVIEW_REQUIRED' $fakeAncestor {
    param($share)
    [pscustomobject]@{AccountName='S-1-5-32-544';AccessControlType='Deny';AccessRight='Full'}
}) -eq 'SHARED_REVIEW') 'deny-only does not certify access'
Assert-SmbFixture ((Evaluate-Smb $path 'REVIEW_REQUIRED' $fakeAncestor {
    param($share)
    [pscustomobject]@{AccountName='FICTIONAL\NONEXISTENT_PRIVATE_CANARY';AccessControlType='Allow';AccessRight='Full'}
}) -eq 'UNKNOWN') 'unresolved ACL principal remains unknown'
Assert-SmbFixture ((Evaluate-Smb $path 'REVIEW_REQUIRED' {
    [pscustomobject]@{Path='C:\FICTIVE_PARENT';Name='KnownBroad'}
    [pscustomobject]@{Path='C:\FICTIVE_PARENT';Name='Unresolved'}
} {
    param($share)
    if ($share.Name -eq 'KnownBroad') {
        [pscustomobject]@{AccountName='S-1-1-0';AccessControlType='Allow';AccessRight='Full'}
    } else {
        throw 'SYNTHETIC_PRIVATE_CANARY'
    }
}) -eq 'BROAD_ACCESS_REVIEW') 'positive broad evidence survives another unknown ACL'
Assert-SmbFixture ((Evaluate-Smb $path 'REVIEW_REQUIRED' {
    [pscustomobject]@{Path='\\FICTIONAL_SERVER\SHARE';Name='Unsupported'}
} $broadFull) -eq 'UNKNOWN') 'unverifiable share target is not safe'
foreach ($state in @('REJECTED','UNKNOWN')) {
    Assert-SmbFixture ((Evaluate-Smb $path $state { throw 'MUST_NOT_ENUMERATE' } $failCanary) -eq
        'NOT_CHECKED') 'invalid path cannot start share enumeration'
}
Assert-SmbFixture ((Evaluate-Smb 'relative\FICTIONAL' 'REVIEW_REQUIRED' {
    throw 'MUST_NOT_ENUMERATE'
} $failCanary) -eq 'NOT_CHECKED') 'relative directory spelling cannot trigger SMB query'

Write-Host 'PASS: fictional SMB ancestor/broad ACL classification, unresolved and no-echo fail-closed'
