#requires -Version 5.1
<#
.SYNOPSIS
    Runs local read-only Windows validation without installing anything.
.DESCRIPTION
    Parses PowerShell sources, exercises deterministic classifiers, and performs
    a minimal temporary live-data integration scan. No Defender/ClamAV/SFC/DISM
    native scans or repairs are launched by these tests.
#>
[CmdletBinding()]
param([switch]$SmokeOnly)
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Validation requires Windows.' }
Write-Host 'Windows Health Triage verification: syntax and deterministic tests'
& (Join-Path $PSScriptRoot 'tests\Smoke.Tests.ps1')
Write-Host 'Windows Health Triage verification: injected process/OS collector tests'
& (Join-Path $PSScriptRoot 'tests\Collector.Tests.ps1')
Write-Host 'Windows Health Triage verification: synthetic privacy tests'
& (Join-Path $PSScriptRoot 'tests\Privacy.Tests.ps1')
if (-not $SmokeOnly) {
    Write-Host 'Windows Health Triage verification: live read-only integration'
    & (Join-Path $PSScriptRoot 'tests\Integration.Tests.ps1')
}
Write-Host 'PASS: selected tests finished. Review warnings in real reports before declaring the workstation healthy.'
