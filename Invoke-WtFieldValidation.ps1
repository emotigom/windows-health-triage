#requires -Version 5.1
<#
.SYNOPSIS
    Explicit, passive Windows 10/11 field-validation checklist, no upload.
.DESCRIPTION
    Runs five low-volume read-only diagnostic modes and verifies report contracts
    and the private per-run ACL. Full raw data stays local; stdout contains only
    fixed status labels plus Windows build / PowerShell version / elevation.
    It never runs Defender QuickScan, ClamAV, SFC or DISM native checks.
    It never deletes any report, including partial/failed reports.
.EXAMPLE
    .\Invoke-WtFieldValidation.ps1
.EXAMPLE
    .\Invoke-WtFieldValidation.ps1 -OutputDir 'C:\PrivateTriageValidation'
.EXAMPLE
    .\Invoke-WtFieldValidation.ps1 -OutputDir 'C:\ApprovedPrivateTriage' -RequireSmbPreflight
.NOTES
    The opt-in SMB guard cannot verify effective remote access, administrative
    shares, cloud backup, path races, initial root trust or independent approval.
#>
[CmdletBinding()]
param(
    [string]$OutputDir=(Join-Path $env:LOCALAPPDATA 'WinTriage\field-validation'),
    [switch]$RequireSmbPreflight
)
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows required for field validation.' }
Import-Module (Join-Path $PSScriptRoot 'src\WinTriage.ReportSecurity.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'src\WinTriage.IntegrityCollector.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'src\WinTriage.FieldValidation.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'tests\ReportContract.psm1') -Force
if ($RequireSmbPreflight) {
    # Explicit opt-in only. A missing SMB cmdlet or unreadable share ACL is UNKNOWN.
    Import-Module (Join-Path $PSScriptRoot 'tools\WinTriage.FieldPreflight.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot 'tools\WinTriage.FieldSmbPreflight.psm1') -Force
}

$build=[System.Environment]::OSVersion.Version.Build
$psVersion=('{0}.{1}' -f $PSVersionTable.PSVersion.Major,$PSVersionTable.PSVersion.Minor)
$privilege=if (Test-WtAdministrator) { 'elevated' } else { 'standard-or-unknown' }
# Do not print arbitrary OS captions, account names, logs, warnings or paths.
Write-Output ('Environment: Windows build={0}; PowerShell={1}; privilege={2}' -f $build,$psVersion,$privilege)
Write-Output 'Classification checks local structure and access permissions only; report origin is NOT authenticated and this is NOT a system-health verdict.'
Write-Output 'Full reports remain local and are never uploaded or deleted by this script.'
$allPassed=$true
foreach ($mode in @('Quick','Events','Hardware','Monitor','Integrity')) {
    if ($RequireSmbPreflight) {
        # Re-evaluate immediately before EACH collector invocation. This limits
        # staleness between modes, but cannot close SMB or path TOCTOU races.
        # Fail closed before creating this mode's report folder or reading data.
        try {
            # Silence provider warning/information streams: they can contain
            # private share, account or path metadata even on a failed query.
            $pathState=Get-WtFieldPreflightPathState -Directory $OutputDir 3>$null 4>$null 5>$null 6>$null
            $smbState=Get-WtFieldSmbExposure -Directory $OutputDir -PathState $pathState 3>$null 4>$null 5>$null 6>$null
            Assert-WtFieldSmbCollectionGate -PathState $pathState -SmbExposure $smbState
        } catch {
            # A thrown PowerShell exception may print the caller's checkout
            # path and line number. Use only a fixed status and explicit exit.
            Write-Output 'SmbCollectionGate: BLOCKED_OR_UNKNOWN'
            exit 2
        }
    }
    # A separate run folder is created with a private ACL by WinTriage.ps1.
    $before=@()
    if (Test-Path -LiteralPath $OutputDir -PathType Container) {
        $before=@(Get-ChildItem -LiteralPath $OutputDir -Directory -ErrorAction Stop |
            Select-Object -ExpandProperty Name)
    }
    $contract=$false
    $acl=$false
    $nativeArtifactsPresent=$false
    $manifest=$null
    $security=$null
    $hardware=$null
    $integrity=$null
    try {
        $options=@{
            Mode=$mode;OutputDir=$OutputDir;EventHours=1
            MaxEventsPerLog=20;Top=5
        }
        if ($mode -eq 'Monitor') {
            $options.Samples=2
            $options.IntervalSeconds=1
        }
        # Suppress raw collector diagnostics from stdout. A user can inspect
        # private reports locally; do not leak them in a public issue comment.
        & (Join-Path $PSScriptRoot 'WinTriage.ps1') @options *>$null
        $newRuns=@(Get-ChildItem -LiteralPath $OutputDir -Directory -ErrorAction Stop |
            Where-Object { $before -notcontains $_.Name })
        if ($newRuns.Count -ne 1) { throw 'Invalid report count' }
        $directory=$newRuns[0].FullName
        $acl=[bool](Assert-WtPrivateDirectoryAcl -Directory $directory)
        if (-not $acl) { throw 'Private report ACL not verified' }
        # Only metadata/existence checks after ACL verification, no native log reads.
        $nativeArtifactsPresent=[bool](Test-WtPassiveNativeArtifact -RunDirectory $directory)
        $contract=[bool](Assert-WtReportContract -RunDirectory $directory)
        $manifest=Get-Content -LiteralPath (Join-Path $directory 'manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($mode -eq 'Quick') {
            $security=Get-Content -LiteralPath (Join-Path $directory 'security.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        }
        if ($mode -in @('Quick','Hardware')) {
            $hardware=Get-Content -LiteralPath (Join-Path $directory 'hardware.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        }
        if ($mode -eq 'Integrity') {
            $integrity=Get-Content -LiteralPath (Join-Path $directory 'integrity.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        }
    } catch {
        # No raw exception details are printed; these can contain host or paths.
        $contract=$false
    }
    $assessment=@{
        Mode=$mode;ContractPassed=$contract;AclPassed=$acl
        NativeArtifactsPresent=$nativeArtifactsPresent
        Manifest=$manifest;Security=$security;Hardware=$hardware;Integrity=$integrity
    }
    $row=Get-WtFieldValidationAssessment @assessment
    Write-Output ('Mode={0}; Validation={1}; Contract={2}; PrivateAcl={3}; PassiveNativeScans={4}; Warnings={5}' -f $row.Mode,$row.Validation,$row.Contract,$row.PrivateAcl,$row.PassiveNativeScans,$row.Warnings)
    if ($row.Validation -eq 'fail') { $allPassed=$false }
}
if (-not $allPassed) {
    Write-Output 'Some modes failed: inspect retained private reports locally, do not publish raw logs.'
    throw 'Field-validation failed; private reports were retained for local review.'
}
Write-Output 'Completed: statuses are structural-only, not proof of real-hardware compatibility; release remains NO-GO.'
