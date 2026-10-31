#requires -Version 5.1
<#
.SYNOPSIS
    Inspect local raw report retention metadata, without modifying any data.
.DESCRIPTION
    Explicit opt-in. Counts only direct run folders with expected names.
    Does not read report content, print names/paths, upload or delete anything.
.EXAMPLE
    .\Get-WtReportRetention.ps1
.EXAMPLE
    .\Get-WtReportRetention.ps1 -ReportRoot "$env:LOCALAPPDATA\WinTriage\field-validation" -OlderThanDays 14
#>
[CmdletBinding()]
param(
    [string]$ReportRoot=(Join-Path $env:LOCALAPPDATA 'WinTriage\reports'),
    [ValidateRange(1,3650)][int]$OlderThanDays=30
)
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows-only local report inspection.' }
Import-Module (Join-Path $PSScriptRoot 'src\WinTriage.ReportRetention.psm1') -Force
try {
    $summary=Get-WtReportRetentionSummary -ReportRoot $ReportRoot -OlderThanDays $OlderThanDays
} catch {
    # Do not repeat raw PowerShell exceptions, paths, identities or file names.
    throw 'Local report metadata audit failed; no files were modified.'
}
# Fixed enumeration, numbers and fields only. Never echo a supplied path.
Write-Output ('Audit={0}; Status={1}; OlderThanDays={2}; RunFolders={3}; PrivateFolders={4}; PermissionReview={5}; OlderFolders={6}; RecentFolders={7}; AgeUnknown={8}; FileCount={9}; SizeMiB={10}; IgnoredFolders={11}; Incomplete={12}; Action={13}' -f $summary.Audit,$summary.Status,$summary.OlderThanDays,$summary.RunFolders,$summary.PrivateFolders,$summary.PermissionReview,$summary.OlderFolders,$summary.RecentFolders,$summary.AgeUnknown,$summary.FileCount,$summary.SizeMiB,$summary.IgnoredFolders,$summary.Incomplete,$summary.Action)
Write-Output 'Metadata-only estimate; older means review for possible manual retention, not permission to delete.'
Write-Output 'No files were read, deleted, repaired, moved or uploaded. Private reports remain on this PC.'
