#requires -Version 5.1
<#
.SYNOPSIS
    Bounded, read-only metadata audit of local Windows Health Triage reports.
.DESCRIPTION
    Never opens report contents or follows reparse-point directories.
    Never deletes, changes, moves, uploads or prints report names/paths.
    Only explicit protected run folders contribute to approximate byte totals.
#>
# Import once; forcing a nested reload can hide the already imported commands.
Import-Module (Join-Path $PSScriptRoot 'WinTriage.ReportSecurity.psm1')

function Get-WtReportRetentionSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$ReportRoot,
        [ValidateRange(1,3650)][int]$OlderThanDays=30,
        [ValidateRange(1,1000)][int]$MaxRuns=200,
        [ValidateRange(1,2000)][int]$MaxEntriesPerRun=500,
        [datetime]$NowUtc=[datetime]::UtcNow
    )
    if ($env:OS -ne 'Windows_NT') { throw 'Windows-only report metadata audit.' }
    $root=[System.IO.Path]::GetFullPath($ReportRoot)
    if ($root.StartsWith('\\') -or $root.StartsWith('//')) {
        throw 'Report retention audit requires a direct local directory.'
    }
    $drive=New-Object System.IO.DriveInfo -ArgumentList ([System.IO.Path]::GetPathRoot($root))
    if ($drive.DriveType -eq [System.IO.DriveType]::Network) {
        throw 'Report retention audit rejects mapped network drives.'
    }
    # Reject junction/symlink ancestor indirection before listing any files.
    [void](Assert-WtNoReportPathReparsePoint -Directory $root)

    $result=[ordered]@{
        Audit='metadata-only'
        Status='complete'
        OlderThanDays=$OlderThanDays
        RunFolders=0
        PrivateFolders=0
        PermissionReview=0
        OlderFolders=0
        RecentFolders=0
        AgeUnknown=0
        FileCount=0
        SizeMiB=0
        IgnoredFolders=0
        Incomplete=$false
        Action='none'
    }
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        $result.Status='not-found'
        return [pscustomobject]$result
    }

    $entries=@(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction Stop |
        Select-Object -First ($MaxRuns + 1))
    if ($entries.Count -gt $MaxRuns) {
        $result.Incomplete=$true
        $entries=@($entries | Select-Object -First $MaxRuns)
    }
    $sizeBytes=[long]0
    $now=$NowUtc.ToUniversalTime()
    $threshold=$now.AddDays(-$OlderThanDays)
    foreach ($folder in $entries) {
        # This exact name format is issued by the main CLI. Other folders are
        # never inspected and are not assumed to be report directories.
        if ($folder.Name -cnotmatch '^[0-9]{8}_[0-9]{6}_[a-f0-9]{6}$') {
            $result.IgnoredFolders++
            continue
        }
        $result.RunFolders++
        if (([int]$folder.Attributes -band [int][System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            $result.PermissionReview++
            $result.AgeUnknown++
            $result.Incomplete=$true
            continue
        }
        try {
            [void](Assert-WtPrivateDirectoryAcl -Directory $folder.FullName)
            $result.PrivateFolders++
        } catch {
            # Do not inspect files in a folder with unverified access rules.
            $result.PermissionReview++
            $result.AgeUnknown++
            $result.Incomplete=$true
            continue
        }
        try {
            $created=[datetime]$folder.CreationTimeUtc
            if ($created -lt [datetime]'2000-01-01' -or $created -gt $now.AddMinutes(5)) {
                $result.AgeUnknown++
                $result.Incomplete=$true
            } elseif ($created -lt $threshold) {
                $result.OlderFolders++
            } else {
                $result.RecentFolders++
            }

            # Metadata only, direct children only: never recurse into nested
            # directories or open raw JSON, CSV, malware output or event text.
            $items=@(Get-ChildItem -LiteralPath $folder.FullName -Force -ErrorAction Stop |
                Select-Object -First ($MaxEntriesPerRun + 1))
            if ($items.Count -gt $MaxEntriesPerRun) {
                $result.Incomplete=$true
                $items=@($items | Select-Object -First $MaxEntriesPerRun)
            }
            foreach ($item in $items) {
                if ($item.PSIsContainer -or
                    (([int]$item.Attributes -band [int][System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
                    $result.Incomplete=$true
                    continue
                }
                $result.FileCount++
                $sizeBytes += [long]$item.Length
            }
        } catch {
            $result.Incomplete=$true
            # Never return untrusted OS error text, paths or account names.
        }
    }
    $result.SizeMiB=[math]::Round(($sizeBytes / 1MB),2)
    if ($result.Incomplete -or $result.PermissionReview -gt 0) {
        $result.Status='review'
    }
    return [pscustomobject]$result
}
Export-ModuleMember -Function Get-WtReportRetentionSummary
