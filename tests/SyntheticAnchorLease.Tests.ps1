#requires -Version 5.1
# ADR-030 test only. No drive remap, mount edits, scans or real report paths.
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows required for synthetic anchor trust test.' }
foreach ($source in @('HandleChainProbe.cs','VolumeIdentityProbe.cs','SyntheticAnchorLease.cs')) {
    Add-Type -Path (Join-Path $PSScriptRoot $source) -ErrorAction Stop
}
function Assert-LeaseResearch { param([bool]$Condition,[string]$Label)
    if (-not $Condition) { throw ('Anchor lease research failed: ' + $Label) }
}
function Expect-LeaseFailure { param([scriptblock]$Body,[string]$Label)
    $failed=$false
    try { & $Body | Out-Null } catch { $failed=$true }
    Assert-LeaseResearch $failed $Label
}
$fixture=Join-Path ([System.IO.Path]::GetTempPath()) ('wt-anchor-lease-' + [guid]::NewGuid().ToString('N'))
$alias=Join-Path $fixture 'synthetic-alias'
$moved=Join-Path $fixture 'original-moved'
$reference=$null
$originalCandidate=$null
$decoy=$null
$decoyReference=$null
$lease=$null
$selfCertified=$null
$expiredLease=$null
try {
    [void][System.IO.Directory]::CreateDirectory($alias)
    $reference=[WinTriageTests.HandleChainProbe]::PinSyntheticAnchor($alias)
    $originalCandidate=[WinTriageTests.HandleChainProbe]::PinSyntheticAnchor($alias)
    $epoch=[guid]::NewGuid()
    $lease=New-Object WinTriageTests.SyntheticAnchorLease -ArgumentList $reference,$epoch
    $lease.RequireSameObject($originalCandidate,$epoch)
    Expect-LeaseFailure {
        $lease.RequireSameObject($originalCandidate,[guid]::NewGuid())
    } 'wrong synthetic session epoch accepted'
    Expect-LeaseFailure {
        $lease.RequireSameObject($reference,$epoch)
    } 'same reference handle passed independent candidate check'
    Expect-LeaseFailure {
        $bad=New-Object WinTriageTests.SyntheticAnchorLease -ArgumentList $reference,([guid]::Empty)
        $bad.Dispose()
    } 'empty epoch accepted'
    Write-Host 'PASS: synthetic handle reference and session epoch checks'

    $renamed=$false
    try {
        [System.IO.Directory]::Move($alias,$moved)
        $renamed=$true
    } catch [System.IO.IOException] {
        Write-Host 'SKIP: test-only anchor alias rename blocked'
    }
    if ($renamed) {
        # A new, valid directory now occupies exactly the former name.
        [void][System.IO.Directory]::CreateDirectory($alias)
        $decoy=[WinTriageTests.HandleChainProbe]::PinSyntheticAnchor($alias)
        [WinTriageTests.VolumeIdentityProbe]::RequireVolumeSerial(
            $decoy,[WinTriageTests.VolumeIdentityProbe]::VolumeSerial($reference))
        $lease.RequireSameObject($originalCandidate,$epoch)
        Expect-LeaseFailure {
            $lease.RequireSameObject($decoy,$epoch)
        } 'stale synthetic anchor alias accepted as original'
        Write-Host 'PASS: synthetic alias replacement rejected despite same volume serial'

        # Negative control: self-consistency is not provenance. If a caller
        # chooses a bogus reference after substitution, it can validate
        # the bogus candidate. No production trust is implied.
        $decoyReference=[WinTriageTests.HandleChainProbe]::PinSyntheticAnchor($alias)
        $decoyEpoch=[guid]::NewGuid()
        $selfCertified=New-Object WinTriageTests.SyntheticAnchorLease -ArgumentList $decoyReference,$decoyEpoch
        $selfCertified.RequireSameObject($decoy,$decoyEpoch)
        Write-Host 'PASS: synthetic self-consistent decoy shows identity alone cannot authenticate source'
    }
    $lease.Dispose()
    Expect-LeaseFailure {
        $lease.RequireSameObject($originalCandidate,$epoch)
    } 'revoked synthetic session accepted'
    $lease=$null
    Write-Host 'PASS: revoked synthetic trust session fails closed'

    $newEpoch=[guid]::NewGuid()
    $expiredLease=New-Object WinTriageTests.SyntheticAnchorLease -ArgumentList $reference,$newEpoch
    $reference.Dispose()
    Expect-LeaseFailure {
        $expiredLease.RequireSameObject($originalCandidate,$newEpoch)
    } 'disposed reference handle silently reused cached baseline'
    $reference=$null
    Write-Host 'PASS: disposed synthetic reference invalidates borrowed baseline'
    Write-Host 'PASS: test-only ephemeral anchor baseline lifecycle; production unchanged'
} finally {
    foreach ($l in @($expiredLease,$selfCertified,$lease)) {
        if ($null -ne $l) { $l.Dispose() }
    }
    foreach ($h in @($decoyReference,$decoy,$originalCandidate,$reference)) {
        if ($null -ne $h) { $h.Dispose() }
    }
    if (Test-Path -LiteralPath $fixture) {
        # Remove ONLY this newly generated GUID-owned scratch fixture.
        Remove-Item -LiteralPath $fixture -Recurse -Force
    }
}
