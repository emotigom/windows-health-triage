#requires -Version 5.1
# Synthetic metadata-only retention coverage. Only test-created temp folders removed.
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows required for ACL test' }
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'src\WinTriage.ReportSecurity.psm1') -Force
Import-Module (Join-Path $root 'src\WinTriage.ReportRetention.psm1') -Force
function Assert-WtRetention { param($Actual,$Expected,[string]$Label)
    if ($Actual -ne $Expected) { throw ('{0}: expected [{1}], got [{2}]' -f $Label,$Expected,$Actual) }
}
$parent=Join-Path ([System.IO.Path]::GetTempPath()) ('wt-retention-' + [guid]::NewGuid().ToString('N'))
$reports=Join-Path $parent 'reports'
$absent=Join-Path $parent 'absent'
try {
    $missing=Get-WtReportRetentionSummary -ReportRoot $absent
    Assert-WtRetention $missing.Status 'not-found' 'absent root'
    Assert-WtRetention (Test-Path -LiteralPath $absent) $false 'no directory created'
    $old=New-WtPrivateReportDirectory -ParentDirectory $reports -RunId '20260101_120000_aaa111'
    $new=New-WtPrivateReportDirectory -ParentDirectory $reports -RunId '20261031_120000_bbb222'
    $secret='SYNTHETIC_SECRET_HOST_AND_USER_C:\FICTIONAL_PRIVATE'
    $oldFile=Join-Path $old 'events.json'
    Set-Content -LiteralPath $oldFile -Value $secret -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $new 'manifest.json') -Value '{"Synthetic":true}' -Encoding UTF8
    $now=[datetime]::UtcNow
    [System.IO.Directory]::SetCreationTimeUtc($old,$now.AddDays(-46))
    [System.IO.Directory]::SetCreationTimeUtc($new,$now.AddDays(-1))
    $bad=Join-Path $reports '20261031_120000_ccc333'
    New-Item -ItemType Directory -Path $bad | Out-Null
    Set-Content -LiteralPath (Join-Path $bad 'security.json') -Value $secret -Encoding UTF8
    New-Item -ItemType Directory -Path (Join-Path $reports 'unrelated-folder') | Out-Null

    $audit=Get-WtReportRetentionSummary -ReportRoot $reports -NowUtc $now -OlderThanDays 30
    Assert-WtRetention $audit.Status 'review' 'insecure folder demands review'
    Assert-WtRetention $audit.RunFolders 3 'report folder count'
    Assert-WtRetention $audit.PrivateFolders 2 'verified private reports'
    Assert-WtRetention $audit.PermissionReview 1 'unprotected folder flagged'
    Assert-WtRetention $audit.OlderFolders 1 'old report counted'
    Assert-WtRetention $audit.RecentFolders 1 'recent report counted'
    Assert-WtRetention $audit.AgeUnknown 1 'untrusted folder age unknown'
    Assert-WtRetention $audit.FileCount 2 'insecure folder contents never enumerated'
    Assert-WtRetention $audit.IgnoredFolders 1 'unrelated folder ignored'
    Assert-WtRetention $audit.Action 'none' 'no delete instruction'
    Assert-WtRetention $audit.Incomplete $true 'incomplete flag on unsafe ACL'
    $visible=(@($audit | ConvertTo-Json -Depth 4) -join [string][char]10)
    if ($visible.Contains('FICTIONAL') -or $visible.Contains('aaa111') -or $visible.Contains($reports)) {
        throw 'Raw report information leaked into retention summary'
    }
    Assert-WtRetention (Get-Content -LiteralPath $oldFile -Raw).Contains($secret) $true 'raw report unchanged'
    $lines=@(& (Join-Path $root 'Get-WtReportRetention.ps1') -ReportRoot $reports)
    Assert-WtRetention $lines.Count 3 'CLI fixed status line count'
    if ([string]$lines[0] -cnotmatch '^Audit=metadata-only; Status=review; OlderThanDays=30; RunFolders=3; PrivateFolders=2; PermissionReview=1; OlderFolders=1; RecentFolders=1; AgeUnknown=1; FileCount=2; SizeMiB=[0-9]+(\.[0-9]+)?; IgnoredFolders=1; Incomplete=True; Action=none$') {
        throw 'CLI output drift, potential private data leak'
    }
    foreach ($line in $lines) {
        if ([string]$line -match 'SYNTHETIC_SECRET|FICTIONAL|wt-retention-|aaa111') {
            throw 'Private path or content leaked into console'
        }
    }
    # An explicitly bounded scan never pretends to have an exhaustive total.
    $limited=Get-WtReportRetentionSummary -ReportRoot $reports -MaxRuns 1
    Assert-WtRetention $limited.Incomplete $true 'root cap marks incomplete'
    Assert-WtRetention $limited.Status 'review' 'root cap cannot claim complete'
    # Child-file count cap also marks incomplete, with no file content read.
    $only=Join-Path $parent 'only'
    $run=New-WtPrivateReportDirectory -ParentDirectory $only -RunId '20261031_130000_ddd444'
    Set-Content -LiteralPath (Join-Path $run 'one.json') -Value 'synthetic' -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $run 'two.json') -Value 'synthetic' -Encoding UTF8
    $capped=Get-WtReportRetentionSummary -ReportRoot $only -MaxEntriesPerRun 1
    Assert-WtRetention $capped.Status 'review' 'file count capped'
    Assert-WtRetention $capped.Incomplete $true 'file count incomplete'
    Write-Host 'PASS: synthetic retention age, private ACL, bounded metadata, no content/paths, no modification'
} finally {
    # Explicit test-owned temp directory only, never a user's report directory.
    if (Test-Path -LiteralPath $parent) { Remove-Item -LiteralPath $parent -Recurse -Force }
}
