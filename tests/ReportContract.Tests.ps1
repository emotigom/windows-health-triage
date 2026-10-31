#requires -Version 5.1
# Synthetic only: no real computer information or native command execution.
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ReportContract.psm1') -Force
$dir=Join-Path ([System.IO.Path]::GetTempPath()) ('wt-contract-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $dir -Force | Out-Null
function Write-Fixture {
    param([string]$Name,[object]$Data)
    ConvertTo-Json -InputObject $Data -Depth 8 | Out-File -LiteralPath (Join-Path $dir $Name) -Encoding UTF8
}
function Expect-Failure {
    param([string]$Label)
    $failed=$false
    try { [void](Assert-WtReportContract -RunDirectory $dir) } catch { $failed=$true }
    if (-not $failed) { throw "Expected contract rejection: $Label" }
}
try {
    $m=[ordered]@{
        ReportSchemaVersion=1;ToolVersion='0.3.1';RunId='SYNTHETIC-RUN'
        StartedUtc='2026-10-31T00:00:00Z';CompletedUtc='2026-10-31T00:00:01Z'
        Mode='Integrity';Computer='SYNTHETIC-HOST'
        Files=@('system.json','integrity.json','SUMMARY.md','manifest.json')
        Warnings=@('Synthetic unavailable evidence');Scan=@{}
    }
    $s=[ordered]@{OS='unknown';Version='unknown';LastBootUtc=$null;TotalRamGiB=$null;FreePhysicalRamGiB=$null;ReportedFreeVirtualMemoryGiB=$null}
    $i=[ordered]@{Administrator=$false;SfcVerifyOnly='not-requested';DismScanHealth='unavailable';Notes=@('Synthetic')}
    Write-Fixture 'manifest.json' $m
    Write-Fixture 'system.json' $s
    Write-Fixture 'integrity.json' $i
    Set-Content -LiteralPath (Join-Path $dir 'SUMMARY.md') -Value '# Synthetic' -Encoding UTF8
    if (-not (Assert-WtReportContract -RunDirectory $dir)) { throw 'Valid synthetic report rejected' }
    $m.ReportSchemaVersion=2; Write-Fixture 'manifest.json' $m
    Expect-Failure 'unknown major version'
    $m.ReportSchemaVersion=1
    $m.Files+= '../leak.json'; Write-Fixture 'manifest.json' $m
    Expect-Failure 'path traversal'
    $m.Files=@('system.json','integrity.json','SUMMARY.md','manifest.json'); Write-Fixture 'manifest.json' $m
    $i.SfcVerifyOnly='healthy'; Write-Fixture 'integrity.json' $i
    Expect-Failure 'false healthy integrity'
    $i.SfcVerifyOnly='not-requested'; Write-Fixture 'integrity.json' $i
    $s.Remove('TotalRamGiB'); Write-Fixture 'system.json' $s
    Expect-Failure 'missing system field'
    $s.TotalRamGiB=$null; Write-Fixture 'system.json' $s
    if (-not (Assert-WtReportContract -RunDirectory $dir)) { throw 'Unknown memory evidence should be allowed' }
    Write-Host 'PASS synthetic raw report schema v1, unknown evidence and intentional corruption'
} finally {
    if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
}
