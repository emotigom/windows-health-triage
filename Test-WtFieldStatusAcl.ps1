#requires -Version 5.1
<#
.SYNOPSIS
    Explicit, read-only ACL and local-path observation for one field-status file.
.DESCRIPTION
    Does not parse the JSON, inspect reports, change permissions or upload.
    MetadataAcl=restricted is an ACL observation only, never privacy certification.
    Sync/backup and trusted initial path cannot be established by this command.
    Always reports NO_GO and exits 2 (not a release gate).
#>
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$MetadataPath)
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows required for field status ACL review.' }
try {
    Import-Module (Join-Path $PSScriptRoot 'tools\WinTriage.FieldStatusAclReview.psm1') -Force -ErrorAction Stop
    $result=Get-WtFieldStatusOutputAssessment -MetadataPath $MetadataPath
    # Fixed labels; no echoes of paths, SIDs, exception messages or JSON.
    Write-Output ('MetadataAcl={0}; PathObservation={1}; SyncAndBackup={2}; Decision={3}' -f
        $result.MetadataAcl,$result.PathObservation,$result.SyncAndBackup,$result.Decision)
} catch {
    Write-Output 'MetadataAcl=review; PathObservation=review; SyncAndBackup=unknown; Decision=NO_GO'
}
exit 2
