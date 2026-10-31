#requires -Version 5.1
<#
.SYNOPSIS
    Read-only, status-only Windows ACL review of an existing field-status JSON.
.DESCRIPTION
    No JSON is opened; only file attributes, owner and discretionary ACL are read.
    A restricted-looking ACL is not proof of privacy, non-sync or authenticity.
    Fixed labels only; caller-provided paths, SIDs, errors never leave this module.
    This is not imported by the production WinTriage collector.
#>
function Get-WtFieldStatusAclClassification {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][System.Security.AccessControl.FileSecurity]$Acl,
        [Parameter(Mandatory=$true)][string]$CurrentSid
    )
    try {
        $sidType=[System.Security.Principal.SecurityIdentifier]
        $allowed=@($CurrentSid,'S-1-5-18','S-1-5-32-544') | Select-Object -Unique
        $owner=$Acl.GetOwner($sidType)
        if ($null -eq $owner -or $owner.Value -notin $allowed) { return 'review' }
        $rules=@($Acl.GetAccessRules($true,$true,$sidType))
        if ($rules.Count -eq 0) { return 'review' }
        $full=[System.Security.AccessControl.FileSystemRights]::FullControl
        $found=@{}
        foreach ($rule in $rules) {
            if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
                return 'review'
            }
            if ($rule.IdentityReference.Value -notin $allowed) { return 'review' }
            # A protected or inherited rule may qualify; inspect its actual
            # principals and rights, never assume inherited == safe.
            if (($rule.FileSystemRights -band $full) -eq $full) {
                $found[$rule.IdentityReference.Value]=$true
            }
        }
        foreach ($sid in $allowed) {
            if (-not $found.ContainsKey($sid)) { return 'review' }
        }
        return 'restricted'
    } catch {
        return 'review'
    }
}

function Test-WtFieldStatusDirectLocalPath {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$MetadataPath)
    try {
        $full=[System.IO.Path]::GetFullPath($MetadataPath)
        if (-not [System.IO.Path]::IsPathRooted($MetadataPath)) { return $false }
        if ($full.StartsWith('\\') -or $full.StartsWith('//')) { return $false }
        $drive=New-Object System.IO.DriveInfo -ArgumentList ([System.IO.Path]::GetPathRoot($full))
        if ($drive.DriveType -ne [System.IO.DriveType]::Fixed) { return $false }
        $cursor=$full
        for ($i=0; $i -lt 128; $i++) {
            if (-not (Test-Path -LiteralPath $cursor -ErrorAction Stop)) { return $false }
            $item=Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
            if (([int]$item.Attributes -band [int][System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                return $false
            }
            $parent=[System.IO.Directory]::GetParent($cursor)
            if ($null -eq $parent) { return $true }
            $cursor=$parent.FullName
        }
    } catch {}
    return $false
}

function Get-WtFieldStatusOutputAssessment {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$MetadataPath)
    # Never print the input path or an exception message; no file bytes read.
    $aclResult='review'
    $pathResult='review'
    try {
        if (Test-WtFieldStatusDirectLocalPath -MetadataPath $MetadataPath) {
            $file=Get-Item -LiteralPath $MetadataPath -Force -ErrorAction Stop
            if (-not $file.PSIsContainer -and
                (([int]$file.Attributes -band [int][System.IO.FileAttributes]::ReparsePoint) -eq 0)) {
                $pathResult='direct_local_observed'
                $security=Get-Acl -LiteralPath $MetadataPath -ErrorAction Stop
                $current=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                if ($security -is [System.Security.AccessControl.FileSecurity]) {
                    $aclResult=Get-WtFieldStatusAclClassification -Acl $security -CurrentSid $current
                }
            }
        }
    } catch {
        # Fail closed without disclosing exception text, path, SID, SDDL.
    }
    [pscustomobject][ordered]@{
        MetadataAcl=$aclResult
        PathObservation=$pathResult
        SyncAndBackup='unknown'
        Decision='NO_GO'
    }
}
Export-ModuleMember -Function Get-WtFieldStatusAclClassification,Test-WtFieldStatusDirectLocalPath,Get-WtFieldStatusOutputAssessment
