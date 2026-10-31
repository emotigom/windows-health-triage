#requires -Version 5.1
# Synthetic temporary directories only; never touches existing diagnostic reports.
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows ACL checks require Windows.' }
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'src\WinTriage.ReportSecurity.psm1') -Force
function Assert-WtValue { param($Actual,$Expected,[string]$Label)
    if ($Actual -ne $Expected) { throw ("{0}: expected {1}, got {2}" -f $Label,$Expected,$Actual) }
}
function Expect-Failure { param([scriptblock]$Action,[string]$Label)
    $failed=$false
    try { & $Action | Out-Null } catch { $failed=$true }
    Assert-WtValue $failed $true $Label
}
$parent=Join-Path ([System.IO.Path]::GetTempPath()) ('wt-acl-fixture-' + [guid]::NewGuid().ToString('N'))
try {
    $run=New-WtPrivateReportDirectory -ParentDirectory $parent -RunId 'SYNTHETIC_RUN_123'
    Assert-WtValue (Test-Path -LiteralPath $run -PathType Container) $true 'directory created'
    Assert-WtValue (Assert-WtPrivateDirectoryAcl -Directory $run) $true 'private access verified'
    $acl=Get-Acl -LiteralPath $run
    Assert-WtValue $acl.AreAccessRulesProtected $true 'report inheritance disabled'
    $current=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $allowed=@($current,'S-1-5-18','S-1-5-32-544')
    $rules=@($acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]))
    foreach ($rule in $rules) {
        if ($rule.IdentityReference.Value -notin $allowed) { throw 'Unexpected access principal in fixture' }
    }
    # Children should inherit the private directory's new DACL.
    $file=Join-Path $run 'invented.json'
    Set-Content -LiteralPath $file -Value '{"Synthetic":true}' -Encoding UTF8
    $fileAcl=Get-Acl -LiteralPath $file
    foreach ($rule in @($fileAcl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]))) {
        if ($rule.IdentityReference.Value -notin $allowed) { throw 'Report file got broad inherited access' }
    }
    Expect-Failure { New-WtPrivateReportDirectory -ParentDirectory $parent -RunId 'SYNTHETIC_RUN_123' } 'run cannot be reused'
    Assert-WtValue (Get-Content -LiteralPath $file -Raw -Encoding UTF8).Contains('Synthetic') $true 'collision leaves old report untouched'
    Expect-Failure { New-WtPrivateReportDirectory -ParentDirectory $parent -RunId '..\outside' } 'directory traversal denied'
    Expect-Failure { New-WtPrivateReportDirectory -ParentDirectory '\\fictional-server\share' -RunId 'SYNTHETIC_RUN_234' } 'UNC report path denied'
    # ACL verification is fail-closed on an ordinary inherited directory.
    $openDirectory=Join-Path $parent 'deliberately-inherited'
    New-Item -ItemType Directory -Path $openDirectory -Force | Out-Null
    Expect-Failure { Assert-WtPrivateDirectoryAcl -Directory $openDirectory } 'inherited access is not private'

    # A junction is an NTFS reparse point even when its target is a local folder.
    # This fixture uses only test-owned folders. Some environments disallow
    # junction creation; in that case the invariant remains enforced in code.
    $junction=Join-Path $parent 'synthetic-junction'
    $junctionCreated=$false
    try {
        New-Item -ItemType Junction -Path $junction -Target $run -ErrorAction Stop | Out-Null
        $junctionCreated=$true
    } catch {
        Write-Host 'SKIP: this runner cannot create an NTFS junction fixture'
    }
    if ($junctionCreated) {
        try {
            Expect-Failure { New-WtPrivateReportDirectory -ParentDirectory $junction -RunId 'SYNTHETIC_RUN_999' } 'reparse-point ancestry forbidden'
            if (Test-Path -LiteralPath (Join-Path $run 'SYNTHETIC_RUN_999')) {
                throw 'A private report was created through a junction'
            }
        } finally {
            # Remove the link itself only; never delete or follow its target.
            Remove-Item -LiteralPath $junction -Force -ErrorAction Stop
        }
    }
    Write-Host 'PASS synthetic private report ACL, child inheritance, collision, traversal, UNC and reparse rejection'
} finally {
    if (Test-Path -LiteralPath $parent) { Remove-Item -LiteralPath $parent -Recurse -Force }
}
