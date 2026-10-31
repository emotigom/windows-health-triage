#requires -Version 5.1
<#
.SYNOPSIS
    Read-only process and OS collectors with replaceable data providers.
.DESCRIPTION
    OS-facing operations are injected as scriptblocks for deterministic failure
    tests. Calling code owns the warnings collection; there are no script-scoped
    mutable warning variables. This module never launches scans or repairs.
#>
function Get-WtProcesses {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.Collections.Generic.List[string]]$Warnings,
        [hashtable]$ReadFailures = @{},
        [scriptblock]$ProcessProvider = { Get-Process -ErrorAction Stop },
        [datetime]$SampleTime = [datetime]::UtcNow
    )
    $now = $SampleTime.ToUniversalTime().ToString('o')
    $processList = @()
    try {
        $processList = @(& $ProcessProvider)
    } catch {
        [void]$Warnings.Add("프로세스 조회 실패: $($_.Exception.Message)")
        return
    }
    foreach ($p in $processList) {
        if ($null -eq $p) { continue }
        $pidValue = 'unknown'
        try { $pidValue = [string]$p.Id } catch { }
        try {
            $start = 'unknown'
            $reliable = $false
            try {
                if ($null -ne $p.StartTime) {
                    $start = ([datetime]$p.StartTime).ToUniversalTime().ToString('o')
                    $reliable = $true
                }
            } catch { }
            $cpuSeconds = $null
            try {
                if ($null -ne $p.CPU) {
                    $cpuSeconds = [math]::Round([double]$p.CPU,1)
                }
            } catch { }
            [pscustomobject]@{
                SampleTimeUtc = $now
                InstanceKey = ('{0}|{1}' -f $p.Id,$start)
                IdentityReliable = $reliable
                Name = $p.ProcessName
                Pid = $p.Id
                StartedUtc = $start
                WorkingSetMiB = [math]::Round(([double]$p.WorkingSet64 / 1MB),2)
                PrivateMiB = [math]::Round(([double]$p.PrivateMemorySize64 / 1MB),2)
                CpuSeconds = $cpuSeconds
                Handles = $p.HandleCount
            }
        } catch {
            # Multiple samples of an inaccessible process must not flood reports.
            if (-not $ReadFailures.ContainsKey($pidValue)) {
                $ReadFailures[$pidValue] = $true
                [void]$Warnings.Add("일부 프로세스 샘플을 읽지 못했습니다 (PID $pidValue): $($_.Exception.Message)")
            }
        }
    }
}

function Get-WtSystemSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.Collections.Generic.List[string]]$Warnings,
        [scriptblock]$OperatingSystemProvider = { Get-CimInstance Win32_OperatingSystem -ErrorAction Stop },
        [scriptblock]$ComputerSystemProvider = { Get-CimInstance Win32_ComputerSystem -ErrorAction Stop }
    )
    $os = $null
    $sys = $null
    try { $os = & $OperatingSystemProvider }
    catch { [void]$Warnings.Add("OS 메타데이터 조회 실패: $($_.Exception.Message)") }
    try { $sys = & $ComputerSystemProvider }
    catch { [void]$Warnings.Add("RAM/시스템 메타데이터 조회 실패: $($_.Exception.Message)") }

    $boot = $null
    $total = $null
    $freePhysical = $null
    $freeVirtual = $null
    try {
        if ($os -and $os.LastBootUpTime) {
            $boot = ([datetime]$os.LastBootUpTime).ToUniversalTime().ToString('o')
        }
    } catch { [void]$Warnings.Add('OS 시작 시각을 해석할 수 없습니다.') }
    try {
        if ($sys -and $null -ne $sys.TotalPhysicalMemory) {
            $total = [math]::Round(([double]$sys.TotalPhysicalMemory / 1GB),2)
        }
    } catch { [void]$Warnings.Add('총 메모리 크기를 해석할 수 없습니다.') }
    try {
        if ($os -and $null -ne $os.FreePhysicalMemory) {
            $freePhysical = [math]::Round(([double]$os.FreePhysicalMemory * 1KB / 1GB),2)
        }
    } catch { [void]$Warnings.Add('여유 물리 메모리를 해석할 수 없습니다.') }
    try {
        if ($os -and $null -ne $os.FreeVirtualMemory) {
            $freeVirtual = [math]::Round(([double]$os.FreeVirtualMemory * 1KB / 1GB),2)
        }
    } catch { [void]$Warnings.Add('여유 가상 메모리를 해석할 수 없습니다.') }

    [pscustomobject]@{
        OS = $(if ($os -and $os.Caption) { $os.Caption } else { 'unknown' })
        Version = $(if ($os -and $os.Version) { $os.Version } else { 'unknown' })
        LastBootUtc = $boot
        TotalRamGiB = $total
        FreePhysicalRamGiB = $freePhysical
        ReportedFreeVirtualMemoryGiB = $freeVirtual
    }
}
Export-ModuleMember -Function Get-WtProcesses,Get-WtSystemSnapshot
