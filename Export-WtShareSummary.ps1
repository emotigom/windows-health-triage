#requires -Version 5.1
<#
.SYNOPSIS
    Explicitly produce a small allowlisted summary; never uploads data.
.EXAMPLE
    .\Export-WtShareSummary.ps1 -RunDirectory "$env:LOCALAPPDATA\WinTriage\reports\RUN_ID" -OutputPath "$env:TEMP\triage-share.json"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$RunDirectory,
    [Parameter(Mandatory=$true)][string]$OutputPath
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'src\WinTriage.Privacy.psm1') -Force

if (-not (Test-Path -LiteralPath $RunDirectory -PathType Container)) {
    throw 'RunDirectory must be an existing local report directory.'
}
$manifestPath = Join-Path $RunDirectory 'manifest.json'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw 'manifest.json is required: do not export an arbitrary directory.'
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($null -eq $manifest -or [string]::IsNullOrWhiteSpace([string]$manifest.Mode)) {
    throw 'The report manifest is invalid.'
}

$events = @()
$eventFile = Join-Path $RunDirectory 'event-summary.json'
if (Test-Path -LiteralPath $eventFile -PathType Leaf) {
    $parsed = Get-Content -LiteralPath $eventFile -Raw -Encoding UTF8 | ConvertFrom-Json
    $events = @($parsed)
}
$hardware = $null
$hardwareFile = Join-Path $RunDirectory 'hardware.json'
if (Test-Path -LiteralPath $hardwareFile -PathType Leaf) {
    $hardware = Get-Content -LiteralPath $hardwareFile -Raw -Encoding UTF8 | ConvertFrom-Json
}
$integrity = $null
$integrityFile = Join-Path $RunDirectory 'integrity.json'
if (Test-Path -LiteralPath $integrityFile -PathType Leaf) {
    $integrity = Get-Content -LiteralPath $integrityFile -Raw -Encoding UTF8 | ConvertFrom-Json
}

$share = ConvertTo-WtShareSummary -Manifest $manifest -EventSummary $events -Hardware $hardware -Integrity $integrity
$target = [System.IO.Path]::GetFullPath($OutputPath)
$parent = [System.IO.Path]::GetDirectoryName($target)
if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
    throw 'Output directory does not exist. Create it explicitly before exporting.'
}
# CreateNew prevents overwriting any existing data, including another export.
$stream = [System.IO.File]::Open($target,[System.IO.FileMode]::CreateNew,[System.IO.FileAccess]::Write,[System.IO.FileShare]::None)
try {
    $encoding = New-Object System.Text.UTF8Encoding -ArgumentList $false
    $writer = New-Object System.IO.StreamWriter -ArgumentList $stream,$encoding
    try {
        $writer.Write((ConvertTo-Json -InputObject $share -Depth 8))
    } finally {
        $writer.Dispose()
    }
} finally {
    $stream.Dispose()
}
Write-Host "Local-only minimal summary created: $target"
Write-Host 'Review the JSON before uploading it anywhere; the source report was not modified.'
