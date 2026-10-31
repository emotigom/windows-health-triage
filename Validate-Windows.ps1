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
Write-Host 'Windows Health Triage verification: injected event collector tests'
& (Join-Path $PSScriptRoot 'tests\EventCollector.Tests.ps1')
Write-Host 'Windows Health Triage verification: mocked storage/PnP/memory diagnostics'
& (Join-Path $PSScriptRoot 'tests\HardwareCollector.Tests.ps1')
Write-Host 'Windows Health Triage verification: synthetic passive security provider tests'
& (Join-Path $PSScriptRoot 'tests\SecurityCollector.Tests.ps1')
Write-Host 'Windows Health Triage verification: mocked opt-in Defender/ClamAV execution'
& (Join-Path $PSScriptRoot 'tests\ScanExecutor.Tests.ps1')
Write-Host 'Windows Health Triage verification: mock explicit integrity executor'
& (Join-Path $PSScriptRoot 'tests\IntegrityCollector.Tests.ps1')
Write-Host 'Windows Health Triage verification: synthetic field-validation statuses'
& (Join-Path $PSScriptRoot 'tests\FieldValidation.Tests.ps1')
Write-Host 'Windows Health Triage verification: schema v1 contract tests'
& (Join-Path $PSScriptRoot 'tests\ReportContract.Tests.ps1')
Write-Host 'Windows Health Triage verification: handle-relative, no-overwrite report file tests'
& (Join-Path $PSScriptRoot 'tests\HandleBoundWriter.Tests.ps1')
Write-Host 'Windows Health Triage verification: synthetic early lease acquisition races'
& (Join-Path $PSScriptRoot 'tests\ReportPathAcquisition.Tests.ps1')
Write-Host 'Windows Health Triage verification: synthetic native parent-relative research probe'
& (Join-Path $PSScriptRoot 'tests\RelativeDirectoryProbe.Tests.ps1')
Write-Host 'Windows Health Triage verification: synthetic pinned-directory ACL/owner probe'
& (Join-Path $PSScriptRoot 'tests\HandleSecurityProbe.Tests.ps1')
Write-Host 'Windows Health Triage verification: test-only relative private directory creation'
& (Join-Path $PSScriptRoot 'tests\DirectoryCreationProbe.Tests.ps1')
Write-Host 'Windows Health Triage verification: synthetic pinned-anchor multi-hop chain'
& (Join-Path $PSScriptRoot 'tests\HandleChainProbe.Tests.ps1')
Write-Host 'Windows Health Triage verification: synthetic anchor identity and pre-open junction race'
& (Join-Path $PSScriptRoot 'tests\AnchorRace.Tests.ps1')
Write-Host 'Windows Health Triage verification: restricted report directory ACL tests'
& (Join-Path $PSScriptRoot 'tests\ReportSecurity.Tests.ps1')
Write-Host 'Windows Health Triage verification: synthetic retention metadata and privacy tests'
& (Join-Path $PSScriptRoot 'tests\ReportRetention.Tests.ps1')
Write-Host 'Windows Health Triage verification: synthetic privacy tests'
& (Join-Path $PSScriptRoot 'tests\Privacy.Tests.ps1')
if (-not $SmokeOnly) {
    Write-Host 'Windows Health Triage verification: passive field runner end-to-end (test-owned temp folder)'
    & (Join-Path $PSScriptRoot 'tests\FieldValidation.Integration.Tests.ps1')
    Write-Host 'Windows Health Triage verification: live read-only integration'
    & (Join-Path $PSScriptRoot 'tests\Integration.Tests.ps1')
}
Write-Host 'PASS: selected tests finished. Review warnings in real reports before declaring the workstation healthy.'
