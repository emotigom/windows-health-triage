#requires -Version 5.1
<#
.SYNOPSIS
    Optional read-only preflight before authorized physical field validation.
.DESCRIPTION
    Makes no reports or directories and never launches the field runner.
    All stdout values are fixed tokens; path and exceptions are never echoed.
    It always exits 2 / NO_GO, including on an apparently supported Windows PC.
.EXAMPLE
    .\Test-WtFieldPreflight.ps1 -OutputDir 'C:\ApprovedPrivateTriage'
#>
[CmdletBinding()]
param([string]$OutputDir=(Join-Path $env:LOCALAPPDATA 'WinTriage\field-validation'))
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'tools\WinTriage.FieldPreflight.psm1') -Force
$build=0
$productType=0
$privilege='unknown'
if ($env:OS -eq 'Windows_NT') {
    try {
        $build=[int][System.Environment]::OSVersion.Version.Build
        # Win32_OperatingSystem.ProductType=1 is a client workstation.
        # A Server build must never be silently labeled Windows 10/11.
        $productType=[int](Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).ProductType
    } catch {
        $build=0
        $productType=0
    }
    try {
        $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
        $principal=New-Object Security.Principal.WindowsPrincipal($identity)
        $privilege=if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            'elevated'
        } else {
            'standard'
        }
    } catch { $privilege='unknown' }
}
$pathState=Get-WtFieldPreflightPathState -Directory $OutputDir
$decision=Get-WtFieldPreflightAssessment -Build $build -ProductType $productType `
    -PSMajor $PSVersionTable.PSVersion.Major -PSMinor $PSVersionTable.PSVersion.Minor `
    -Privilege $privilege -PathState $pathState
foreach ($key in @('Decision','Preflight','OperatingSystem','PowerShell','Privilege',
                   'CandidateCell','OutputPath','NextAction','RootAuthority',
                   'StorageSyncBackup','OperatorAuthorization','IndependentReview',
                   'ReleaseDecision')) {
    Write-Output ($key+': '+$decision.$key)
}
foreach ($blocker in @('PHYSICAL_WINDOWS_10_11','TRUSTED_INITIAL_ROOT',
                      'INDEPENDENT_SECURITY_PRIVACY','EXTERNAL_RELEASE_AUTHORITY')) {
    Write-Output ('ReleaseBlocker: '+$blocker)
}
exit 2
