#requires -Version 5.1
# ADR-062: read-only field planning only. Never grants OS, path or release approval.
function Get-WtFieldPreflightPathState {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Directory)
    # Reject relative, drive-relative, UNC and device namespace spellings before
    # any filesystem observation; never print the supplied string.
    if ([string]::IsNullOrWhiteSpace($Directory)) { return 'REJECTED' }
    if ($Directory.StartsWith('\\') -or
        $Directory -notmatch '^[A-Za-z]:[\\/]') { return 'REJECTED' }
    try {
        $path=[System.IO.Path]::GetFullPath($Directory)
        $drive=[System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot($path))
        if ($drive.DriveType -eq [System.IO.DriveType]::Network) { return 'REJECTED' }
        if (-not $drive.IsReady -or
            $drive.DriveType -ne [System.IO.DriveType]::Fixed -or
            $drive.DriveFormat -ne 'NTFS') { return 'UNKNOWN' }
        $cursor=$path
        while ($true) {
            if (Test-Path -LiteralPath $cursor -ErrorAction Stop) {
                $item=Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
                if (([int]$item.Attributes -band [int][System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                    return 'REJECTED'
                }
                if (-not $item.PSIsContainer) { return 'REJECTED' }
            }
            $parent=[System.IO.Directory]::GetParent($cursor)
            if ($null -eq $parent) { break }
            $cursor=$parent.FullName
        }
        # No pathname check attests source authority, ACL, sync or backup policy.
        return 'REVIEW_REQUIRED'
    } catch {
        return 'UNKNOWN'
    }
}

function Get-WtFieldPreflightAssessment {
    [CmdletBinding()]
    param(
        [int]$Build,
        [int]$ProductType,
        [int]$PSMajor,
        [int]$PSMinor,
        [ValidateSet('standard','elevated','unknown')][string]$Privilege,
        [ValidateSet('REJECTED','REVIEW_REQUIRED','UNKNOWN')][string]$PathState,
        [ValidateSet('BROAD_ACCESS_REVIEW','SHARED_REVIEW','NO_NON_SPECIAL_SHARE_OBSERVED',
                     'UNKNOWN','NOT_CHECKED')][string]$SmbExposure='UNKNOWN'
    )
    $os='UNKNOWN'
    if ($ProductType -eq 1 -and $Build -ge 10240 -and $Build -lt 22000) {
        $os='WINDOWS10'
    } elseif ($ProductType -eq 1 -and $Build -ge 22000 -and $Build -lt 100000) {
        $os='WINDOWS11'
    } elseif ($ProductType -gt 0 -and $Build -gt 0) {
        $os='UNSUPPORTED'
    }
    $shell='UNSUPPORTED'
    if ($PSMajor -eq 5 -and $PSMinor -eq 1) {
        $shell='POWERSHELL51'
    } elseif ($PSMajor -eq 7) {
        $shell='POWERSHELL7'
    }
    $privilege=$Privilege.ToUpperInvariant()
    $candidate='UNVERIFIED'
    if ($os -in @('WINDOWS10','WINDOWS11') -and
        $shell -in @('POWERSHELL51','POWERSHELL7') -and
        $privilege -in @('STANDARD','ELEVATED')) {
        # Candidate cell spelling never claims elevation authorization or a run.
        $candidate=$os+'_'+$shell+'_'+$privilege
    }
    $action='INDEPENDENT_APPROVAL_REQUIRED'
    if ($PathState -eq 'REJECTED') {
        $action='SELECT_LOCAL_PRIVATE_PATH'
    } elseif ($os -eq 'UNSUPPORTED') {
        $action='USE_SUPPORTED_WINDOWS_CLIENT'
    } elseif ($shell -eq 'UNSUPPORTED') {
        $action='USE_SUPPORTED_POWERSHELL'
    } elseif ($os -eq 'UNKNOWN' -or $privilege -eq 'UNKNOWN' -or
              $PathState -eq 'UNKNOWN') {
        $action='VERIFY_ENVIRONMENT_PRIVATELY'
    }
    # Shared parent visibility is a warning, not an authenticated remote access
    # test. Missing SMB provider or ACL data must never imply no shared path.
    if ($action -eq 'INDEPENDENT_APPROVAL_REQUIRED') {
        if ($SmbExposure -eq 'BROAD_ACCESS_REVIEW') {
            $action='REVIEW_BROAD_SMB_SHARE_PRIVATELY'
        } elseif ($SmbExposure -eq 'SHARED_REVIEW') {
            $action='REVIEW_SMB_SHARE_PRIVATELY'
        } elseif ($SmbExposure -in @('UNKNOWN','NOT_CHECKED')) {
            $action='VERIFY_SHARE_POLICY_PRIVATELY'
        }
    }
    # No boolean is ever interpreted as a field-validation pass or launch consent.
    [pscustomobject][ordered]@{
        Decision='NO_GO'
        Preflight='NO_AUTOMATIC_FIELD_RUN'
        OperatingSystem=$os
        PowerShell=$shell
        Privilege=$privilege
        CandidateCell=$candidate
        OutputPath=$PathState
        SmbExposure=$SmbExposure
        NextAction=$action
        RootAuthority='NOT_VERIFIED'
        StorageSyncBackup='NOT_VERIFIED'
        OperatorAuthorization='NOT_VERIFIED'
        IndependentReview='NOT_AUTHENTICATED'
        ReleaseDecision='NO_GO'
    }
}
Export-ModuleMember -Function Get-WtFieldPreflightPathState,Get-WtFieldPreflightAssessment
