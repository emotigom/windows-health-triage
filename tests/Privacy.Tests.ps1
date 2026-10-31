#requires -Version 5.1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'src\WinTriage.Privacy.psm1') -Force
function Assert-Equal {
    param($Actual,$Expected,[string]$Label)
    if ($Actual -ne $Expected) { throw ("{0}: expected {1}, got {2}" -f $Label,$Expected,$Actual) }
}
$fixture = Join-Path $PSScriptRoot 'fixtures\synthetic-report'
$manifest = Get-Content (Join-Path $fixture 'manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$events = @(Get-Content (Join-Path $fixture 'event-summary.json') -Raw -Encoding UTF8 | ConvertFrom-Json)
$hardware = Get-Content (Join-Path $fixture 'hardware.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$integrity = Get-Content (Join-Path $fixture 'integrity.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$result = ConvertTo-WtShareSummary -Manifest $manifest -EventSummary $events -Hardware $hardware -Integrity $integrity
Assert-Equal $result.Mode 'Quick' 'mode allowlist'
Assert-Equal $result.Events.SampledCount 5 'aggregate known and unknown category counts'
Assert-Equal $result.Events.Groups.Count 2 'category grouping'
Assert-Equal $result.Storage.Attention 1 'attention count'
Assert-Equal $result.Storage.Inconclusive 1 'inconclusive count'
Assert-Equal $result.Integrity.Sfc 'not-requested' 'sfc allowlist'
Assert-Equal $result.Integrity.Dism 'failed' 'dism status normalization'

$raw = ConvertTo-Json -InputObject $result -Depth 8
foreach ($secret in @('CANARY-HOST-SECRET','CANARY-USERNAME','CANARY-PATH-SECRET',
    'CANARY-DEVICE-SECRET','CANARY-IP-SECRET','CANARY-RAW-EVENT-SECRET',
    'CANARY-UNKNOWN-CATEGORY-SECRET','CANARY-INTEGRITY-SECRET')) {
    if ($raw.Contains($secret)) { throw "Leaked source information: $secret" }
}
if ($raw -match '"(Computer|RunId|Message|Provider|EventId|DeviceId|FriendlyName|Pid|Name|Warnings|Files)"\s*:') {
    throw 'Forbidden raw-report field reached share output'
}

$temp = Join-Path ([System.IO.Path]::GetTempPath()) ('wt-public-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp -Force | Out-Null
try {
    $target = Join-Path $temp 'public.json'
    & (Join-Path $root 'Export-WtShareSummary.ps1') -RunDirectory $fixture -OutputPath $target
    if (-not (Test-Path -LiteralPath $target -PathType Leaf)) { throw 'Export not created' }
    $exported = Get-Content -LiteralPath $target -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-Equal $exported.Events.SampledCount 5 'CLI event total'
    $exportText = Get-Content -LiteralPath $target -Raw -Encoding UTF8
    foreach ($secret in @('CANARY-HOST-SECRET','CANARY-USERNAME','CANARY-PATH-SECRET','CANARY-DEVICE-SECRET','CANARY-IP-SECRET')) {
        if ($exportText.Contains($secret)) { throw "CLI leaked source information: $secret" }
    }
    $failed = $false
    try {
        & (Join-Path $root 'Export-WtShareSummary.ps1') -RunDirectory $fixture -OutputPath $target
    } catch { $failed = $true }
    if (-not $failed) { throw 'Overwrite should be prohibited' }
    Assert-Equal (Get-Content -LiteralPath $target -Raw -Encoding UTF8) $exportText 'No overwrite on retry'
} finally {
    Remove-Item -LiteralPath $temp -Recurse -Force
}
Write-Host 'PASS: field allowlist, malicious fixtures, CLI output and fail-on-overwrite'
