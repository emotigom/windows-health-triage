#requires -Version 5.1
# ADR-064: Optional, bounded read-only SMB ancestry hints. No remote probing.
# These results are not access proofs or storage/release authorization.
function Get-WtFieldSmbExposure {
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$Directory,
        [ValidateSet('REJECTED','REVIEW_REQUIRED','UNKNOWN')][string]$PathState='UNKNOWN',
        [scriptblock]$ShareProvider = { Get-SmbShare -Special $false -ErrorAction Stop },
        [scriptblock]$AccessProvider = {
            param($Share)
            Get-SmbShareAccess -InputObject $Share -ErrorAction Stop
        }
    )
    if ($PathState -ne 'REVIEW_REQUIRED') { return 'NOT_CHECKED' }
    if ([string]::IsNullOrWhiteSpace($Directory) -or
        $Directory.StartsWith('\\') -or $Directory -notmatch '^[A-Za-z]:[\\/]') {
        return 'NOT_CHECKED'
    }
    try {
        # Lexical containment only. Initial root, reparse/race, managed sync and
        # effective remote access remain independent external review matters.
        $target=[System.IO.Path]::GetFullPath($Directory).TrimEnd('\','/')
        $comparison=[System.StringComparison]::OrdinalIgnoreCase
        # Capture ALL record streams from the provider. A provider can emit a
        # nonterminating error or warning and then silently return an empty or
        # partial list; treating that as proof of no ordinary shares is unsafe.
        # Diagnostic records become invalid entries (UNKNOWN), never stdout.
        $shares=@(& $ShareProvider *>&1)
        if ($shares.Count -gt 200) { return 'UNKNOWN' }
        $seenNames=@{}
        $observed=$false
        $uncertain=$false
        $broad=$false
        $broadSids=@('S-1-1-0','S-1-5-11','S-1-5-32-545',
                     'S-1-5-32-546','S-1-5-7','S-1-5-2')
        foreach ($share in $shares) {
            # Native Get-SmbShare objects have a nonempty string Name and Path.
            # Never coerce an error/warning/string to a fake share record.
            if ($null -eq $share -or $share -is [string] -or
                $null -eq $share.PSObject.Properties['Name'] -or
                $null -eq $share.PSObject.Properties['Path'] -or
                $share.Name -isnot [string] -or $share.Path -isnot [string] -or
                [string]::IsNullOrWhiteSpace($share.Name) -or
                [string]::IsNullOrWhiteSpace($share.Path)) {
                $uncertain=$true
                continue
            }
            $shareName=[string]$share.Name
            if ($seenNames.ContainsKey($shareName)) {
                # Same logical name twice means inventory provenance is unclear.
                $uncertain=$true
                continue
            }
            $seenNames[$shareName]=$true
            $sharePath=[string]$share.Path
            if ($sharePath.StartsWith('\\') -or
                $sharePath -notmatch '^[A-Za-z]:[\\/]') {
                $uncertain=$true
                continue
            }
            try {
                $ancestor=[System.IO.Path]::GetFullPath($sharePath).TrimEnd('\','/')
            } catch {
                $uncertain=$true
                continue
            }
            if (-not ($target.Equals($ancestor,$comparison) -or
                      $target.StartsWith(($ancestor+'\'),$comparison))) {
                continue
            }
            $observed=$true
            try {
                # Account ACL providers may also stream warnings or nonterminating
                # errors together with otherwise plausible Allow records.
                $access=@(& $AccessProvider $share *>&1)
                if ($access.Count -eq 0 -or $access.Count -gt 200) {
                    $uncertain=$true
                    continue
                }
                foreach ($rule in $access) {
                    if ($null -eq $rule -or $rule -is [string] -or
                        $null -eq $rule.PSObject.Properties['AccessControlType'] -or
                        $null -eq $rule.PSObject.Properties['AccessRight'] -or
                        $null -eq $rule.PSObject.Properties['AccountName'] -or
                        $rule.AccessControlType -isnot [string] -or
                        $rule.AccessRight -isnot [string] -or
                        $rule.AccountName -isnot [string]) {
                        $uncertain=$true
                        continue
                    }
                    $kind=[string]$rule.AccessControlType
                    if ($kind -notin @('Allow','Deny')) {
                        $uncertain=$true
                        continue
                    }
                    if ($kind -ne 'Allow') { continue }
                    if ([string]$rule.AccessRight -notin @('Read','Change','Full')) {
                        $uncertain=$true
                        continue
                    }
                    $account=[string]$rule.AccountName
                    if ([string]::IsNullOrWhiteSpace($account)) {
                        $uncertain=$true
                        continue
                    }
                    try {
                        if ($account -match '^S-1-[0-9]+(?:-[0-9]+)+$') {
                            $sid=$account
                        } else {
                            $sid=(New-Object System.Security.Principal.NTAccount -ArgumentList $account).Translate(
                                [System.Security.Principal.SecurityIdentifier]).Value
                        }
                        if ($sid -in $broadSids) { $broad=$true }
                    } catch {
                        $uncertain=$true
                    }
                }
            } catch {
                $uncertain=$true
            }
        }
        if ($broad) { return 'BROAD_ACCESS_REVIEW' }
        if ($uncertain) { return 'UNKNOWN' }
        if ($observed) { return 'SHARED_REVIEW' }
        # Does not inspect special/admin shares, all policy domains or real access.
        return 'NO_NON_SPECIAL_SHARE_OBSERVED'
    } catch {
        # Never emit provider errors, paths, share names or Windows identities.
        return 'UNKNOWN'
    }
}
# ADR-065: An optional pre-collection stop, not an access or release approval.
# Only absence of an observed ordinary share removes this *additional* blocker.
# UNKNOWN, administrative-share blind spots and time-of-check races remain external.
function Assert-WtFieldSmbCollectionGate {
    [CmdletBinding()]
    param(
        [ValidateSet('REJECTED','REVIEW_REQUIRED','UNKNOWN')][string]$PathState,
        [ValidateSet('BROAD_ACCESS_REVIEW','SHARED_REVIEW','NO_NON_SPECIAL_SHARE_OBSERVED',
                     'UNKNOWN','NOT_CHECKED')][string]$SmbExposure
    )
    if ($PathState -ne 'REVIEW_REQUIRED' -or
        $SmbExposure -ne 'NO_NON_SPECIAL_SHARE_OBSERVED') {
        # Fixed text only: never echo the destination, provider error or share.
        throw 'SMB field collection guard blocked or inconclusive; review storage privately.'
    }
    # Silent return means "no additional ordinary-SMB blocker was observed".
    # It is never a privacy approval, network proof, or release GO.
}
Export-ModuleMember -Function Get-WtFieldSmbExposure,Assert-WtFieldSmbCollectionGate
