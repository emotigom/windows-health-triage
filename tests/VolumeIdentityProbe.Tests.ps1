#requires -Version 5.1
# ADR-029: synthetic-only volume and full file ID observations.
# No drive-letter remapping, mount changes, real report access or native scans.
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows required for volume identity research.' }
Add-Type -Path (Join-Path $PSScriptRoot 'HandleChainProbe.cs') -ErrorAction Stop
Add-Type -Path (Join-Path $PSScriptRoot 'RootPathPolicyProbe.cs') -ErrorAction Stop
Add-Type -Path (Join-Path $PSScriptRoot 'VolumeIdentityProbe.cs') -ErrorAction Stop

function Assert-VolumeResearch { param([bool]$Condition,[string]$Label)
    if (-not $Condition) { throw ('Volume identity research failed: ' + $Label) }
}
function Expect-VolumeResearchFailure { param([scriptblock]$Body,[string]$Label)
    $failed=$false
    try { & $Body | Out-Null } catch { $failed=$true }
    Assert-VolumeResearch $failed $Label
}

$fixture=Join-Path ([System.IO.Path]::GetTempPath()) ('wt-volume-id-' + [guid]::NewGuid().ToString('N'))
$original=Join-Path $fixture 'original'
$moved=Join-Path $fixture 'moved-original'
$rootHandle=$null
$secondRoot=$null
$originalHandle=$null
$decoyHandle=$null
$fixtureHandle=$null
$renamed=$false
try {
    [void][System.IO.Directory]::CreateDirectory($original)
    $parts=[WinTriageTests.RootPathPolicyProbe]::SplitStrictDrivePath($original)
    $root=$parts[0]
    if (-not [WinTriageTests.RootPathPolicyProbe]::IsFixedNtfsVolumeForResearch($root)) {
        Write-Host 'SKIP: native volume identity experiment requires a ready fixed NTFS drive'
    } else {
        $rootHandle=[WinTriageTests.HandleChainProbe]::PinReadOnlySyntheticVolumeRoot($root)
        $secondRoot=[WinTriageTests.HandleChainProbe]::PinReadOnlySyntheticVolumeRoot($root)
        $fixtureHandle=[WinTriageTests.HandleChainProbe]::PinSyntheticAnchor($fixture)
        $originalHandle=[WinTriageTests.HandleChainProbe]::PinSyntheticAnchor($original)

        # Same root via two independent handles has the same full identity.
        $rootId=[WinTriageTests.VolumeIdentityProbe]::FileIdentity($rootHandle)
        [WinTriageTests.VolumeIdentityProbe]::RequireFileIdentity($secondRoot,$rootId)
        $rootSerial=[WinTriageTests.VolumeIdentityProbe]::VolumeSerial($rootHandle)
        [WinTriageTests.VolumeIdentityProbe]::RequireVolumeSerial($fixtureHandle,$rootSerial)
        [WinTriageTests.VolumeIdentityProbe]::RequireVolumeSerial($originalHandle,$rootSerial)
        $originalId=[WinTriageTests.VolumeIdentityProbe]::FileIdentity($originalHandle)
        Assert-VolumeResearch ($originalId -ne $rootId) 'root and synthetic child IDs unexpectedly equal'
        Expect-VolumeResearchFailure {
            [WinTriageTests.VolumeIdentityProbe]::RequireFileIdentity($rootHandle,$originalId)
        } 'different same-volume objects passed full-ID check'
        Expect-VolumeResearchFailure {
            [WinTriageTests.VolumeIdentityProbe]::RequireVolumeSerial($rootHandle,'000000000000000')
        } 'invalid volume serial baseline accepted'
        Write-Host 'PASS: independent root handles agree on 128-bit file identity and child volume serial'

        $guidRoot=[WinTriageTests.VolumeIdentityProbe]::TryVolumeGuidPrefix($rootHandle)
        $guidChild=[WinTriageTests.VolumeIdentityProbe]::TryVolumeGuidPrefix($originalHandle)
        if ($null -eq $guidRoot -or $null -eq $guidChild) {
            Write-Host 'SKIP: handle volume-GUID name unavailable on this volume'
        } else {
            Assert-VolumeResearch ($guidRoot -eq $guidChild) 'root/child handle volume-GUID prefixes differ'
            Write-Host 'PASS: root and synthetic child report same volume-GUID prefix'
        }

        # A same-volume rename and decoy keeps volume serial constant.
        # Full 128-bit file ID must reject the decoy, even though it has
        # a valid path and exactly the same volume serial as the original.
        try {
            [System.IO.Directory]::Move($original,$moved)
            $renamed=$true
        } catch [System.IO.IOException] {
            Write-Host 'SKIP: test-only pinned child rename refused'
        }
        if ($renamed) {
            [void][System.IO.Directory]::CreateDirectory($original)
            $decoyHandle=[WinTriageTests.HandleChainProbe]::PinSyntheticAnchor($original)
            [WinTriageTests.VolumeIdentityProbe]::RequireVolumeSerial($decoyHandle,$rootSerial)
            Assert-VolumeResearch ([WinTriageTests.VolumeIdentityProbe]::FileIdentity($decoyHandle) -ne $originalId) 'synthetic decoy has original 128-bit file ID'
            Expect-VolumeResearchFailure {
                [WinTriageTests.VolumeIdentityProbe]::RequireFileIdentity($decoyHandle,$originalId)
            } 'same-volume decoy bypassed trusted file ID'
            [WinTriageTests.VolumeIdentityProbe]::RequireFileIdentity($originalHandle,$originalId)
            Write-Host 'PASS: same-volume decoy kept serial but failed full 128-bit file identity check'
        }
        $originalHandle.Dispose()
        Expect-VolumeResearchFailure {
            [void][WinTriageTests.VolumeIdentityProbe]::FileIdentity($originalHandle)
        } 'closed handle identity was accepted'
        $originalHandle=$null
        Write-Host 'PASS: test-only volume fingerprint research; production unchanged'
    }
} finally {
    foreach ($handle in @($decoyHandle,$originalHandle,$fixtureHandle,$secondRoot,$rootHandle)) {
        if ($null -ne $handle) { $handle.Dispose() }
    }
    if (Test-Path -LiteralPath $fixture) {
        # Newly generated GUID temp fixture ONLY. Never delete a real report.
        Remove-Item -LiteralPath $fixture -Recurse -Force
    }
}
