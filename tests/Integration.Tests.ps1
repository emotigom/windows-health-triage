#requires -Version 5.1
# Intended for Windows CI or a user-approved Windows validation run. No scanning/repair.
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows required' }
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'src\WinTriage.ReportSecurity.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'ReportContract.psm1') -Force
$target=Join-Path ([System.IO.Path]::GetTempPath()) ('wt-integration-' + [guid]::NewGuid().ToString('N'))
try {
    foreach ($mode in @('Quick','Events','Monitor','Hardware','Integrity')) {
        $options=@{Mode=$mode;OutputDir=$target;EventHours=1;MaxEventsPerLog=20}
        if ($mode -eq 'Monitor') { $options.Samples=2; $options.IntervalSeconds=1 }
        $before=@(Get-ChildItem -LiteralPath $target -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
        & (Join-Path $root 'WinTriage.ps1') @options
        $runs=@(Get-ChildItem -LiteralPath $target -Directory | Where-Object { $before -notcontains $_.Name })
        if ($runs.Count -ne 1) { throw "Expected 1 new report for $mode, got $($runs.Count)" }
        $run=$runs[0].FullName
        [void](Assert-WtPrivateDirectoryAcl -Directory $run)
        $manifest=Get-Content -LiteralPath (Join-Path $run 'manifest.json') -Raw | ConvertFrom-Json
        if ($manifest.Mode -ne $mode) { throw "Manifest mode mismatch: $mode" }
        if ($mode -eq 'Integrity') {
            $integrity=Get-Content -LiteralPath (Join-Path $run 'integrity.json') -Raw | ConvertFrom-Json
            if ($integrity.SfcVerifyOnly -ne 'not-requested' -or $integrity.DismScanHealth -ne 'not-requested') {
                throw 'Passive integrity mode unexpectedly launched a scanner'
            }
            if (Test-Path -LiteralPath (Join-Path $run 'sfc-verifyonly.txt')) {
                throw 'Passive integrity mode generated a native scanner file'
            }
        }
        if ($mode -eq 'Hardware') {
            $hardware=Get-Content -LiteralPath (Join-Path $run 'hardware.json') -Raw | ConvertFrom-Json
            if ($null -eq $hardware.StorageAssessments) { throw 'Missing storage assessment field' }
        }
        [void](Assert-WtReportContract -RunDirectory $run)
        foreach ($f in $manifest.Files) {
            $file=Join-Path $run $f
            if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing report file: $file" }
            if ($f -like '*.json') { $null=Get-Content -LiteralPath $file -Raw | ConvertFrom-Json }
        }
    }
    Write-Host 'PASS: Windows read-only Quick, Events, Monitor, Hardware, Integrity and report completeness'
} finally {
    # Local temporary test reports only; never delete user's existing reports.
    if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
}
