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
    # Monitor schema-v1 supports safe aggregate counts and old reports without them.
    $m.Mode='Monitor'
    $m.Files=@('system.json','processes.json','memory-samples.csv','memory-growth.csv','SUMMARY.md','manifest.json')
    $m.MonitorSampling=[ordered]@{
        RequestedAttempts=2;AttemptedAttempts=2;NonEmptyAttempts=0;ComparableProcesses=0;RejectedGrowthGroups=0
        SingletonGroups=0;InvalidSingletonGroups=0;UnkeyedSamples=0
    }
    $m.SkippedUnreliableIdentitySamples=0
    $m.MemoryGrowthTop=@()
    Write-Fixture 'processes.json' @()
    Set-Content -LiteralPath (Join-Path $dir 'memory-samples.csv') -Value ('"' + (@('SampleTimeUtc','InstanceKey','IdentityReliable','Name','Pid','StartedUtc','WorkingSetMiB','PrivateMiB','CpuSeconds','Handles') -join '","') + '"') -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $dir 'memory-growth.csv') -Value ('"' + (@('Name','Pid','Samples','FirstUtc','LastUtc','FirstPrivateMiB','LastPrivateMiB','PrivateGrowthMiB','FirstWorkingSetMiB','LastWorkingSetMiB','WorkingSetGrowthMiB') -join '","') + '"') -Encoding UTF8
    Write-Fixture 'manifest.json' $m
    if (-not (Assert-WtReportContract -RunDirectory $dir)) { throw 'Partial synthetic Monitor must remain structurally valid for review' }
    $m.MonitorSampling.NonEmptyAttempts=3; Write-Fixture 'manifest.json' $m
    Expect-Failure 'impossible nonempty count'
    $m.MonitorSampling.NonEmptyAttempts=0
    $m.MonitorSampling.RequestedAttempts=$true; Write-Fixture 'manifest.json' $m
    Expect-Failure 'boolean Monitor count'
    $m.MonitorSampling.RequestedAttempts=2
    $m.MonitorSampling.RejectedGrowthGroups=$true; Write-Fixture 'manifest.json' $m
    Expect-Failure 'boolean rejected growth count'
    $m.MonitorSampling.RejectedGrowthGroups=-1; Write-Fixture 'manifest.json' $m
    Expect-Failure 'negative rejected growth count'
    $m.MonitorSampling.RejectedGrowthGroups=1
    $m.SkippedUnreliableIdentitySamples=$true; Write-Fixture 'manifest.json' $m
    Expect-Failure 'boolean unreliable sample count'
    $m.SkippedUnreliableIdentitySamples=-1; Write-Fixture 'manifest.json' $m
    Expect-Failure 'negative unreliable sample count'
    $m.SkippedUnreliableIdentitySamples=0
    $m.MonitorSampling.InvalidSingletonGroups=$true; Write-Fixture 'manifest.json' $m
    Expect-Failure 'boolean invalid singleton count'
    $m.MonitorSampling.InvalidSingletonGroups=0
    $m.MonitorSampling.UnkeyedSamples=-1; Write-Fixture 'manifest.json' $m
    Expect-Failure 'negative unkeyed count'
    $m.MonitorSampling.UnkeyedSamples=0
    $m.MonitorSampling.SingletonGroups=1000001; Write-Fixture 'manifest.json' $m
    Expect-Failure 'oversized singleton count'
    $m.MonitorSampling.SingletonGroups=0
    Write-Fixture 'manifest.json' $m
    Expect-Failure 'rejected group count without source rows'
    $m.MonitorSampling.RejectedGrowthGroups=0
    Write-Fixture 'manifest.json' $m
    if (-not (Assert-WtReportContract -RunDirectory $dir)) { throw 'Consistent empty Monitor report should be structurally valid for review' }
    $m.Remove('SkippedUnreliableIdentitySamples')
    $m.Remove('MonitorSampling')
    Write-Fixture 'manifest.json' $m
    if (-not (Assert-WtReportContract -RunDirectory $dir)) { throw 'Old schema-v1 Monitor report is structurally backward compatible' }
    Write-Host 'PASS synthetic raw report schema v1, optional Monitor counts, corruption and legacy compatibility'
} finally {
    if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
}
