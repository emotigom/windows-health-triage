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
    # New directory must be private from the first observable instant. The
    # production creator never invokes Set-Acl after creating this run dir.
    $mandatory=@([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544') | Select-Object -Unique
    $readable=@($acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]))
    foreach ($sid in $mandatory) {
        $matches=@($readable | Where-Object {
            $_.IdentityReference.Value -eq $sid -and
            ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -eq [System.Security.AccessControl.FileSystemRights]::FullControl -and
            ($_.InheritanceFlags -band ([System.Security.AccessControl.InheritanceFlags]::ObjectInherit -bor [System.Security.AccessControl.InheritanceFlags]::ContainerInherit)) -eq ([System.Security.AccessControl.InheritanceFlags]::ObjectInherit -bor [System.Security.AccessControl.InheritanceFlags]::ContainerInherit)
        })
        if ($matches.Count -lt 1) { throw 'Missing required inheritable FullControl security rule in new directory' }
    }
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
    # An already existing unprotected directory must NEVER be "fixed" or reused.
    $preexisting=Join-Path $parent 'SYNTHETIC_PREEXISTING'
    New-Item -ItemType Directory -Path $preexisting -ErrorAction Stop | Out-Null
    $beforeAcl=(Get-Acl -LiteralPath $preexisting).Sddl
    Expect-Failure { New-WtPrivateReportDirectory -ParentDirectory $parent -RunId 'SYNTHETIC_PREEXISTING' } 'preexisting folder is never retouched'
    Assert-WtValue (Get-Acl -LiteralPath $preexisting).Sddl $beforeAcl 'existing folder ACL unchanged'
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
            # Windows PowerShell 5.1 Remove-Item may throw NullReferenceException
            # for an NTFS junction. Directory.Delete removes the link itself.
            [System.IO.Directory]::Delete($junction)
            if (-not (Test-Path -LiteralPath $run -PathType Container)) {
                throw 'Junction cleanup unexpectedly removed its target'
            }
        }
    }
    Write-Host 'PASS synthetic private report ACL, child inheritance, collision, traversal, UNC and reparse rejection'
} finally {
    if (Test-Path -LiteralPath $parent) { Remove-Item -LiteralPath $parent -Recurse -Force }
}
