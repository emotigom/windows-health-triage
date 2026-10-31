#requires -Version 5.1
<#
.SYNOPSIS
    Create a local report directory with restricted ACL before any evidence is written.
.DESCRIPTION
    Uses Windows DACLs; allows only the invoking account, LOCAL SYSTEM and
    BUILTIN Administrators. Passes the DACL to Windows directory creation.
    Never changes ACLs of pre-existing report folders.
    Failure is fatal: do not collect sensitive evidence if protection is unknown.
#>
function Assert-WtPrivateDirectoryAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Directory)

    $acl=Get-Acl -LiteralPath $Directory -ErrorAction Stop
    if (-not $acl.AreAccessRulesProtected) {
        throw 'Report directory inherits access rights; private report protection is not confirmed.'
    }
    $sidType=[System.Security.Principal.SecurityIdentifier]
    $current=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $allowed=@($current,'S-1-5-18','S-1-5-32-544')
    $rules=@($acl.GetAccessRules($true,$true,$sidType))
    if ($rules.Count -lt 1) { throw 'Report directory has no verifiable access rules.' }
    $foundCurrent=$false
    foreach ($rule in $rules) {
        if ($rule.IsInherited) { throw 'Unexpected inherited report directory rule.' }
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
            throw 'Unexpected deny or non-Allow report directory access rule.'
        }
        if ($rule.IdentityReference.Value -notin $allowed) {
            throw 'Unexpected principal has access to the report directory.'
        }
        if ($rule.IdentityReference.Value -eq $current) { $foundCurrent=$true }
    }
    if (-not $foundCurrent) { throw 'Current account has no explicit report directory access.' }
    return $true
}

function Assert-WtNoReportPathReparsePoint {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Directory)

    # GetFullPath alone does not follow NTFS junctions/symlinks. Reject any
    # existing reparse point in the ancestor chain, including the destination.
    # Do not read or change permissions of the reparse target.
    $cursor=[System.IO.Path]::GetFullPath($Directory)
    while ($true) {
        if (Test-Path -LiteralPath $cursor) {
            $item=Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
            if (([int]$item.Attributes -band [int][System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'A reparse point exists in the report path; select a direct local directory.'
            }
        }
        $ancestor=[System.IO.Directory]::GetParent($cursor)
        if ($null -eq $ancestor) { break }
        $cursor=$ancestor.FullName
    }
    return $true
}

function New-WtPrivateReportDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$ParentDirectory,
        [Parameter(Mandatory=$true)][string]$RunId
    )
    if ($RunId -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_-]{5,80}$') {
        throw 'Invalid report directory identifier.'
    }
    $parent=[System.IO.Path]::GetFullPath($ParentDirectory)
    if ($parent.StartsWith('\\') -or $parent.StartsWith('//')) {
        throw 'UNC/network report paths are not supported; use a local NTFS directory.'
    }
    $drive=[System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot($parent))
    if ($drive.DriveType -eq [System.IO.DriveType]::Network) {
        throw 'Mapped network report drives are not supported.'
    }
    [void](Assert-WtNoReportPathReparsePoint -Directory $parent)
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null
    }
    # Recheck created ancestors before creating a private per-run folder.
    [void](Assert-WtNoReportPathReparsePoint -Directory $parent)
    $newRun=Join-Path $parent $RunId
    # A security descriptor is constructed BEFORE the directory exists. On
    # supported Windows runtimes it is passed to the create syscall, rather
    # than applied by a separate, later Set-Acl operation.
    if (Test-Path -LiteralPath $newRun) { throw 'Report directory already exists; refusing reuse.' }
    $acl=New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    $current=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $inherit=[System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
             [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $rights=[System.Security.AccessControl.FileSystemRights]::FullControl
    $allow=[System.Security.AccessControl.AccessControlType]::Allow
    foreach ($sidValue in @($current,'S-1-5-18','S-1-5-32-544') | Select-Object -Unique) {
        $sid=New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $sidValue
        $access=New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList $sid,$rights,$inherit,([System.Security.AccessControl.PropagationFlags]::None),$allow
        $acl.AddAccessRule($access)
    }
    try {
        # .NET Framework (Windows PowerShell 5.1) exposes the security-aware
        # overload directly. .NET (PowerShell 7) exposes it as a Windows-only
        # FileSystemAclExtensions static method. No insecure fallback is allowed.
        if ($PSVersionTable.PSEdition -eq 'Desktop') {
            [void][System.IO.Directory]::CreateDirectory($newRun,$acl)
        } else {
            [void][System.IO.FileSystemAclExtensions]::CreateDirectory($acl,$newRun)
        }
        # .NET create APIs can return an existing directory in a concurrent
        # race. Independently verify its DACL before ANY report evidence.
        [void](Assert-WtNoReportPathReparsePoint -Directory $newRun)
        [void](Assert-WtPrivateDirectoryAcl -Directory $newRun)
    } catch {
        # No evidence has been written. Leave the folder in place for review,
        # never delete it or relax existing ACLs on failure.
        throw "Private report ACL could not be established; no collection started: $($_.Exception.Message)"
    }
    return $newRun
}
Export-ModuleMember -Function New-WtPrivateReportDirectory,Assert-WtPrivateDirectoryAcl,Assert-WtNoReportPathReparsePoint
