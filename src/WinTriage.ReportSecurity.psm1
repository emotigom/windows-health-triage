#requires -Version 5.1
<#
.SYNOPSIS
    Create a local report directory with restricted ACL before any evidence is written.
.DESCRIPTION
    Uses Windows DACLs; allows only the invoking account, LOCAL SYSTEM and
    BUILTIN Administrators. Verifies a trusted owner as well as DACL rules.
    Passes the DACL to exclusive Win32 directory creation (no reuse).
    Never changes ACLs of pre-existing report folders.
    Failure is fatal: do not collect sensitive evidence if protection is unknown.
#>
function Assert-WtPrivateSecurityDescriptor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][System.Security.AccessControl.DirectorySecurity]$Acl,
        [Parameter(Mandatory=$true)][string]$CurrentSid
    )
    # A DACL is not sufficient if an unrelated account OWNS the directory:
    # Windows owners can generally change the DACL and read the report.
    $sidType=[System.Security.Principal.SecurityIdentifier]
    $allowed=@($CurrentSid,'S-1-5-18','S-1-5-32-544')
    try {
        $owner=$Acl.GetOwner($sidType)
    } catch {
        throw 'Report directory owner could not be verified.'
    }
    if ($null -eq $owner -or $owner.Value -notin $allowed) {
        throw 'Report directory has an unexpected owner; private access is not confirmed.'
    }
    if (-not $Acl.AreAccessRulesProtected) {
        throw 'Report directory inherits access rights; private report protection is not confirmed.'
    }
    $rules=@($Acl.GetAccessRules($true,$true,$sidType))
    if ($rules.Count -lt 1) { throw 'Report directory has no verifiable access rules.' }
    $requiredSids=@($allowed | Select-Object -Unique)
    $verified=@{}
    $neededFlags=[System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                 [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $fullRights=[System.Security.AccessControl.FileSystemRights]::FullControl
    foreach ($rule in $rules) {
        if ($rule.IsInherited) { throw 'Unexpected inherited report directory rule.' }
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
            throw 'Unexpected deny or non-Allow report directory access rule.'
        }
        if ($rule.IdentityReference.Value -notin $allowed) {
            throw 'Unexpected principal has access to the report directory.'
        }
        # The protected run folder must grant every intended identity
        # inheritable FullControl; a matching SID with Read-only is insufficient.
        if (($rule.FileSystemRights -band $fullRights) -eq $fullRights -and
            ($rule.InheritanceFlags -band $neededFlags) -eq $neededFlags -and
            $rule.PropagationFlags -eq [System.Security.AccessControl.PropagationFlags]::None) {
            $verified[$rule.IdentityReference.Value]=$true
        }
    }
    foreach ($sid in $requiredSids) {
        if (-not $verified.ContainsKey($sid)) {
            throw 'Report directory is missing a required inheritable full-access rule.'
        }
    }
    return $true
}

function Assert-WtPrivateDirectoryAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Directory)

    $acl=Get-Acl -LiteralPath $Directory -ErrorAction Stop
    $current=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    [void](Assert-WtPrivateSecurityDescriptor -Acl $acl -CurrentSid $current)
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
    # A security descriptor is constructed BEFORE the directory exists and
    # applied by an exclusive Win32 create operation, not a later Set-Acl.
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
        # Load our small, locally shipped Win32 wrapper only when needed.
        # CreateDirectoryW fails with ERROR_ALREADY_EXISTS even if another
        # process wins the race after Test-Path; .NET CreateDirectory does not.
        if (-not ('WinTriage.NativeReportDirectory' -as [type])) {
            Add-Type -Path (Join-Path $PSScriptRoot 'WinTriage.NativeReportDirectory.cs') -ErrorAction Stop
        }
        [WinTriage.NativeReportDirectory]::CreateNew($newRun,$acl.GetSecurityDescriptorBinaryForm())
        # A concurrent parent-directory swap is still possible. Recheck path
        # redirection and actual DACL before ANY report evidence is written.
        [void](Assert-WtNoReportPathReparsePoint -Directory $newRun)
        [void](Assert-WtPrivateDirectoryAcl -Directory $newRun)
    } catch {
        # No evidence has been written. Leave the folder in place for review,
        # never delete it or relax existing ACLs on failure.
        throw 'Private report directory could not be created exclusively or verified; no collection started.'
    }
    return $newRun
}
Export-ModuleMember -Function New-WtPrivateReportDirectory,Assert-WtPrivateDirectoryAcl,Assert-WtNoReportPathReparsePoint,Assert-WtPrivateSecurityDescriptor
