#requires -Version 5.1
# Deterministic tests: no real Get-Process or CIM access required.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'src\WinTriage.ProcessCollector.psm1') -Force
Import-Module (Join-Path $root 'src\WinTriage.Core.psm1') -Force
function Assert-WtEqual {
    param($Actual,$Expected,[string]$Description)
    if ($Actual -ne $Expected) {
        throw ("{0}: expected [{1}], got [{2}]" -f $Description,$Expected,$Actual)
    }
}

$w = New-Object 'System.Collections.Generic.List[string]'
$failedPids = @{}
$now = [datetime]'2026-10-31T01:00:00Z'
$fake = @(
    [pscustomobject]@{
        Id=101; ProcessName='mock-good'; StartTime=$now
        WorkingSet64=104857600; PrivateMemorySize64=52428800
        CPU=2.03; HandleCount=14
    },
    [pscustomobject]@{
        Id=202; ProcessName='mock-protected'; StartTime=$null
        WorkingSet64=10485760; PrivateMemorySize64=5242880
        CPU=$null; HandleCount=0
    },
    [pscustomobject]@{
        Id=303; ProcessName='mock-invalid'; StartTime=$now
        WorkingSet64='bad numeric data'; PrivateMemorySize64=0
        CPU=0; HandleCount=0
    }
)
$rows = @(Get-WtProcesses -Warnings $w -ReadFailures $failedPids -SampleTime $now -ProcessProvider { $fake })
Assert-WtEqual $rows.Count 2 'valid row count'
Assert-WtEqual $rows[0].Name 'mock-good' 'name preserved'
Assert-WtEqual $rows[0].PrivateMiB 50 'MiB conversion'
Assert-WtEqual $rows[0].IdentityReliable $true 'known identity reliable'
Assert-WtEqual $rows[1].IdentityReliable $false 'protected or absent start-time is unreliable'
Assert-WtEqual $rows[1].StartedUtc 'unknown' 'start-time unknown'
Assert-WtEqual $w.Count 1 'per-process decoding error retained'
Assert-WtEqual $failedPids.ContainsKey('303') $true 'per-process warning deduplication'

$null = @(Get-WtProcesses -Warnings $w -ReadFailures $failedPids -SampleTime $now -ProcessProvider { $fake })
Assert-WtEqual $w.Count 1 'repeated failure does not flood warnings'

$before = $w.Count
$empty = @(Get-WtProcesses -Warnings $w -ProcessProvider { throw 'synthetic process provider denied' })
Assert-WtEqual $empty.Count 0 'provider failure returns zero rows'
Assert-WtEqual $w.Count ($before + 1) 'provider error warned and did not throw'
$empty = @(Get-WtProcesses -Warnings $w -ProcessProvider { @() })
Assert-WtEqual $empty.Count 0 'zero process rows'

$afterRestart = [pscustomobject]@{
    Id=101; ProcessName='mock-good'; StartTime=([datetime]'2026-10-31T01:00:01Z')
    WorkingSet64=209715200; PrivateMemorySize64=104857600; CPU=3.0; HandleCount=5
}
$later = @(Get-WtProcesses -Warnings $w -SampleTime ([datetime]'2026-10-31T01:00:10Z') -ProcessProvider { $afterRestart })
$growth = @(Get-WtProcessGrowth -Samples @($rows[0],$later[0]))
Assert-WtEqual $growth.Count 0 'PID reuse is not memory growth'

$system = Get-WtSystemSnapshot -Warnings $w -OperatingSystemProvider { throw 'OS CIM unavailable' } -ComputerSystemProvider {
    [pscustomobject]@{ TotalPhysicalMemory=8589934592 }
}
Assert-WtEqual $system.OS 'unknown' 'OS failure fallback'
Assert-WtEqual $system.TotalRamGiB 8 'computer CIM independent from OS CIM'
Assert-WtEqual $system.LastBootUtc $null 'unavailable boot time'
$system = Get-WtSystemSnapshot -Warnings $w -OperatingSystemProvider {
    [pscustomobject]@{ Caption='Windows Synthetic';Version='11';LastBootUpTime='invalid-date';FreePhysicalMemory='bad' }
} -ComputerSystemProvider { throw 'computer CIM unavailable' }
Assert-WtEqual $system.OS 'Windows Synthetic' 'OS succeeds without computer CIM'
Assert-WtEqual $system.TotalRamGiB $null 'RAM null on provider failure'
Assert-WtEqual $system.FreePhysicalRamGiB $null 'invalid RAM value null'
if (@($w | Where-Object { $_ -match '실패|해석' }).Count -lt 4) {
    throw 'Expected independent provider and data parsing warnings'
}
Write-Host 'PASS: mock process collection, unknown identities, PID reuse, deduplication, independent CIM failures'
