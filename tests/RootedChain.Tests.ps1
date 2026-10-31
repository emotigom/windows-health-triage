#requires -Version 5.1
# ADR-028 test-owned temp tree and a read-only local fixed-volume root.
# NO report access or mutation, optional native scanners, uploads or repairs.
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows required for synthetic rooted chain.' }
Add-Type -Path (Join-Path $PSScriptRoot 'HandleChainProbe.cs') -ErrorAction Stop
Add-Type -Path (Join-Path $PSScriptRoot 'RootPathPolicyProbe.cs') -ErrorAction Stop

function Assert-RootResearch { param([bool]$Condition,[string]$Label)
    if (-not $Condition) { throw ('Rooted chain research failed: ' + $Label) }
}
function Expect-RootRejection { param([string]$Path)
    $rejected=$false
    try {
        [void][WinTriageTests.RootPathPolicyProbe]::SplitStrictDrivePath($Path)
    } catch [System.ArgumentException] { $rejected=$true }
    Assert-RootResearch $rejected 'unsafe path spelling accepted'
}
# Inputs here are LITERAL research samples, never file operations.
foreach ($invalid in @(
    '', 'C:', 'C:relative', '\rooted\missing_drive',
    '\\server\share\private', '\\?\C:\private', '\\.\C:\private',
    'C:/forward/slash', 'C:\one\\two', 'C:\one\..\two',
    'C:\one\.\two', 'C:\one\bad:ads', 'C:\CON\report',
    'C:\NUL.txt\report', 'C:\COM1\report', 'C:\LPT9\report',
    'C:\one\trail.', 'C:\one\trail ', 'C:\one\bad|name',
    'C:\one\', 'C:\'
)) { Expect-RootRejection -Path $invalid }

$known=[WinTriageTests.RootPathPolicyProbe]::SplitStrictDrivePath('c:\Safe Folder\RUN_123')
Assert-RootResearch ($known.Count -eq 3 -and $known[0] -eq 'C:\' -and $known[1] -eq 'Safe Folder' -and $known[2] -eq 'RUN_123') 'rooted parser positive control failed'
Write-Host 'PASS: strict local drive path namespace and reserved-name rejection'

$fixture=Join-Path ([System.IO.Path]::GetTempPath()) ('wt-root-chain-' + [guid]::NewGuid().ToString('N'))
$target=Join-Path $fixture 'synthetic-target'
$junction=Join-Path $fixture 'synthetic-junction'
$rootHandle=$null
$leafHandle=$null
$knownHandle=$null
$madeLink=$false
try {
    [void][System.IO.Directory]::CreateDirectory($target)
    $parts=[WinTriageTests.RootPathPolicyProbe]::SplitStrictDrivePath($fixture)
    $root=$parts[0]
    if (-not [WinTriageTests.RootPathPolicyProbe]::IsFixedNtfsVolumeForResearch($root)) {
        Write-Host 'SKIP: synthetic volume root is not a ready fixed NTFS drive'
    } else {
        # Independent ID is from our own freshly-created fixture, NOT from a
        # preexisting real report path or a self-certified production root.
        $knownHandle=[WinTriageTests.HandleChainProbe]::PinSyntheticAnchor($fixture)
        $expected=[WinTriageTests.HandleChainProbe]::Identity($knownHandle)
        $rootHandle=[WinTriageTests.HandleChainProbe]::PinReadOnlySyntheticVolumeRoot($root)
        $components=[string[]]$parts[1..($parts.Count-1)]
        $leafHandle=[WinTriageTests.HandleChainProbe]::WalkRootReadOnly($rootHandle,$components)
        Assert-RootResearch ([WinTriageTests.HandleChainProbe]::Identity($leafHandle) -eq $expected) 'rooted traversal did not reach the synthetic fixture'
        Assert-RootResearch ([WinTriageTests.HandleChainProbe]::Identity($rootHandle) -ne $expected) 'volume root identity unexpectedly equals child'
        Write-Host 'PASS: fixed NTFS root to synthetic leaf via read-only pinned handles'

        try {
            New-Item -ItemType Junction -Path $junction -Target $target -ErrorAction Stop | Out-Null
            $madeLink=$true
        } catch {
            Write-Host 'SKIP: synthetic junction creation unavailable to current Windows account'
        }
        if ($madeLink) {
            $badParts=[WinTriageTests.RootPathPolicyProbe]::SplitStrictDrivePath($junction)
            $badOpen=$null
            $rejected=$false
            try {
                $badOpen=[WinTriageTests.HandleChainProbe]::WalkRootReadOnly($rootHandle,[string[]]$badParts[1..($badParts.Count-1)])
            } catch [System.IO.IOException] { $rejected=$true }
            finally { if ($null -ne $badOpen) { $badOpen.Dispose() } }
            Assert-RootResearch $rejected 'rooted chain followed synthetic junction'
            Write-Host 'PASS: rooted chain rejected synthetic reparse hop'
        }
    }
} finally {
    if ($null -ne $leafHandle) { $leafHandle.Dispose() }
    if ($null -ne $knownHandle) { $knownHandle.Dispose() }
    if ($null -ne $rootHandle) { $rootHandle.Dispose() }
    if ($madeLink) {
        $attribute=[System.IO.File]::GetAttributes($junction)
        Assert-RootResearch (([int]$attribute -band [int][System.IO.FileAttributes]::ReparsePoint) -ne 0) 'test junction attribute missing at cleanup'
        [System.IO.Directory]::Delete($junction) # link itself only; never recursive
        Assert-RootResearch ([System.IO.Directory]::Exists($target)) 'test junction target was removed'
    }
    if (Test-Path -LiteralPath $fixture) {
        Remove-Item -LiteralPath $fixture -Recurse -Force
    }
}
Write-Host 'PASS: root-chain path policy and synthetic research; production unchanged'
