#requires -Version 5.1
# ADR-027: synthetic-only anchor substitution and pre-open junction interleaving.
# No production report paths, scanner, repair, upload, or existing user data.
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows required for synthetic anchor race tests.' }
foreach ($name in @('HandleChainProbe.cs')) {
    Add-Type -Path (Join-Path $PSScriptRoot $name) -ErrorAction Stop
}
function Assert-Anchored {
    param([bool]$Condition,[string]$Label)
    if (-not $Condition) { throw ('Anchor race research failed: ' + $Label) }
}
function Read-SyntheticIdentity {
    param([string]$Directory)
    $h=[WinTriageTests.HandleChainProbe]::PinSyntheticAnchor($Directory)
    try { return [WinTriageTests.HandleChainProbe]::Identity($h) }
    finally { $h.Dispose() }
}

$fixture=Join-Path ([System.IO.Path]::GetTempPath()) ('wt-anchor-race-' + [guid]::NewGuid().ToString('N'))
$anchor=Join-Path $fixture 'anchor'
$movedAnchor=Join-Path $fixture 'anchor-original'
$middle=Join-Path $movedAnchor 'middle'
$movedMiddle=Join-Path $movedAnchor 'middle-original'
$redirect=Join-Path $fixture 'redirect'
$trusted=$null
$state=@{Invoked=$false; Moved=$false; JunctionCreated=$false; RenameBlocked=$false; JunctionBlocked=$false}
try {
    [void][System.IO.Directory]::CreateDirectory((Join-Path (Join-Path $anchor 'middle') 'leaf'))
    [void][System.IO.Directory]::CreateDirectory((Join-Path $redirect 'leaf'))
    # Capture an identity only from a test-controlled pre-swap handle.
    $expectedAnchor=(Read-SyntheticIdentity -Directory $anchor)
    $expectedLeaf=(Read-SyntheticIdentity -Directory (Join-Path (Join-Path $anchor 'middle') 'leaf'))

    # The initial absolute-path anchor open is the vulnerable trust boundary.
    # Name now points to a completely different but valid directory object.
    [System.IO.Directory]::Move($anchor,$movedAnchor)
    [void][System.IO.Directory]::CreateDirectory((Join-Path (Join-Path $anchor 'middle') 'leaf'))
    $decoyIdentity=(Read-SyntheticIdentity -Directory $anchor)
    Assert-Anchored ($decoyIdentity -ne $expectedAnchor) 'synthetic anchor substitution did not change file ID'

    $refused=$false
    try {
        $wrong=[WinTriageTests.HandleChainProbe]::PinSyntheticAnchorExpectIdentity($anchor,$expectedAnchor)
        $wrong.Dispose()
    } catch [System.IO.IOException] { $refused=$true }
    Assert-Anchored $refused 'decoy anchor was trusted despite mismatched identity'
    Write-Host 'PASS: synthetic pre-pin path substitution refused against independent trusted file ID'

    $trusted=[WinTriageTests.HandleChainProbe]::PinSyntheticAnchorExpectIdentity($movedAnchor,$expectedAnchor)
    $leaf=[WinTriageTests.HandleChainProbe]::Walk($trusted,@('middle','leaf'))
    try {
        Assert-Anchored ([WinTriageTests.HandleChainProbe]::Identity($leaf) -eq $expectedLeaf) 'matched anchor walk returned incorrect descendant'
    } finally { $leaf.Dispose() }

    # Deterministically swap a hop immediately before its native FILE_OPEN.
    # The target also has a 'leaf', so accidentally following the junction
    # would otherwise produce a plausible-looking successful two-hop walk.
    $hook=[Action[int]]{
        param([int]$hop)
        if ($hop -ne 0) { return }
        $state.Invoked=$true
        try {
            [System.IO.Directory]::Move($middle,$movedMiddle)
            $state.Moved=$true
        } catch [System.IO.IOException] {
            $state.RenameBlocked=$true
            return
        }
        try {
            New-Item -ItemType Junction -Path $middle -Target $redirect -ErrorAction Stop | Out-Null
            $state.JunctionCreated=$true
        } catch {
            $state.JunctionBlocked=$true
        }
    }
    $opened=$null
    $denied=$false
    try {
        $opened=[WinTriageTests.HandleChainProbe]::WalkWithSyntheticBeforeHop($trusted,@('middle','leaf'),$hook)
    } catch [System.IO.IOException] {
        $denied=$true
    } finally {
        if ($null -ne $opened) { $opened.Dispose() }
    }
    Assert-Anchored $state.Invoked 'synthetic before-hop hook never executed'
    if ($state.JunctionCreated) {
        Assert-Anchored $denied 'pre-open junction path was followed instead of refused'
        Write-Host 'PASS: synthetic pre-open junction substitution failed closed'
    } elseif ($state.RenameBlocked) {
        Write-Host 'SKIP: synthetic child rename blocked by current filesystem/sharing'
    } elseif ($state.JunctionBlocked) {
        Write-Host 'SKIP: synthetic junction creation blocked after child rename'
    } else {
        throw 'Unexpected synthetic hook state.'
    }
    # A previously-held trusted anchor retains its identity regardless of
    # the name now pointing at a decoy. It does not make the first pin trusted.
    Assert-Anchored ([WinTriageTests.HandleChainProbe]::Identity($trusted) -eq $expectedAnchor) 'held original anchor changed identity'
    $trusted.Dispose()
    $trusted=$null
    Write-Host 'PASS: anchor provenance and deterministic hop interleaving research; production unchanged'
} finally {
    if ($null -ne $trusted) { $trusted.Dispose() }
    if ($state.JunctionCreated) {
        # Remove only a test-created junction itself, never follow its target.
        Remove-Item -LiteralPath $middle -Force -ErrorAction Stop
        $state.JunctionCreated=$false
    }
    if ($state.Moved -and (Test-Path -LiteralPath $movedMiddle)) {
        [System.IO.Directory]::Move($movedMiddle,$middle)
    }
    if (Test-Path -LiteralPath $fixture) {
        # GUID-owned scratch fixture only, including its synthetic decoy.
        Remove-Item -LiteralPath $fixture -Recurse -Force
    }
}
