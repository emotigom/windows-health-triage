#requires -Version 5.1
# All paths are synthetic/test-owned. Do not use a real report root.
# Deterministic checkpoint interleaving: no timing loops or native scans.
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows required for report path lease testing.' }
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'src\WinTriage.ReportSecurity.psm1') -Force

function Assert-Race {
    param([bool]$Condition,[string]$Label)
    if (-not $Condition) { throw ('Synthetic path race assertion failed: ' + $Label) }
}
$fixture=Join-Path ([System.IO.Path]::GetTempPath()) ('wt-acquire-race-' + [guid]::NewGuid().ToString('N'))
$parent=Join-Path $fixture 'reports'
$renamed=Join-Path $fixture 'reports-moved'
$run=$null
$probe=$null
try {
    $run=New-WtPrivateReportDirectory -ParentDirectory $parent -RunId 'SYNTHETIC_ACQUIRE_123'
    $probe=Enter-WtReportPathLease -Directory $run
    $probe.AssertStable()
    $probe.Dispose()
    $probe=$null

    $state=[pscustomobject]@{VisitedParent=$false;VisitedRun=$false;Moved=$false;Decoy=$false}
    # This hook is solely for tests. It executes after an ancestor handle has
    # opened and before the next descendant handle. It does NOT run in the CLI.
    $hook=[System.Action[string]] {
        param([string]$opened)
        if ($opened -eq $run) { $state.VisitedRun=$true }
        if ($opened -ne $parent) { return }
        $state.VisitedParent=$true
        try {
            [System.IO.Directory]::Move($parent,$renamed)
            $state.Moved=$true
        } catch [System.IO.IOException] {
            # Windows can deny renaming an open directory on some hosts.
        }
        if ($state.Moved) {
            # Create only an empty, test-owned replacement directory.
            # Without an immediate checkpoint the next hop could traverse it.
            [void][System.IO.Directory]::CreateDirectory($parent)
            $state.Decoy=$true
        }
    }.GetNewClosure()
    try {
        $failed=$false
        try {
            $probe=[WinTriage.ReportPathLease]::AcquireForSyntheticTest($run,$hook)
        } catch { $failed=$true }
        Assert-Race $state.VisitedParent 'test hook was never called for parent'
        if ($state.Moved) {
            Assert-Race $failed 'parent path replacement must fail closed'
            Assert-Race (-not $state.VisitedRun) 'lease traversed the swapped child after detection'
            Assert-Race (-not (Test-Path -LiteralPath (Join-Path $parent 'SYNTHETIC_ACQUIRE_123'))) 'decoy contains unexpected report'
        } else {
            Assert-Race (-not $failed) 'ordinary path acquisition was rejected'
            Write-Host 'SKIP: runner denied synthetic parent rename while leased'
        }
    } finally {
        if ($null -ne $probe) { $probe.Dispose();$probe=$null }
        if ($state.Decoy -and (Test-Path -LiteralPath $parent)) {
            # Empty replacement directory is ours. Never recurse or follow a link.
            [System.IO.Directory]::Delete($parent)
        }
        if ($state.Moved) { [System.IO.Directory]::Move($renamed,$parent) }
    }
    # Failure must not permanently change the original protected report.
    Assert-Race ([bool](Assert-WtPrivateDirectoryAcl -Directory $run)) 'restored private ACL'
    $probe=Enter-WtReportPathLease -Directory $run
    $probe.AssertStable()
    $probe.Dispose()
    $probe=$null

    # An exception from the injected hook must release all opened handles.
    $hookFailure=[System.Action[string]] { param([string]$opened) throw 'synthetic hook failure' }
    $failed=$false
    try { $probe=[WinTriage.ReportPathLease]::AcquireForSyntheticTest($run,$hookFailure) }
    catch { $failed=$true }
    Assert-Race $failed 'injected acquisition failure must propagate'
    if ($null -ne $probe) { $probe.Dispose();$probe=$null }
    $probe=Enter-WtReportPathLease -Directory $run
    $probe.AssertStable()
    Write-Host 'PASS: synthetic per-hop parent replacement detected before child traversal; clean recovery'
} finally {
    if ($null -ne $probe) { $probe.Dispose() }
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force }
}
