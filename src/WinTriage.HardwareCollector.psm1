#requires -Version 5.1
<#
.SYNOPSIS
    Read-only, failure-isolated storage, PnP and memory-diagnostic collector.
.DESCRIPTION
    Scriptblock providers permit deterministic tests without real devices.
    Does not modify disks, PnP devices, registry or Windows configuration.
#>
Import-Module (Join-Path $PSScriptRoot 'WinTriage.Core.psm1') -ErrorAction Stop

function Get-WtHardware {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$Warnings,
        [scriptblock]$DiskDriveProvider={
            Get-CimInstance Win32_DiskDrive -ErrorAction Stop
        },
        [scriptblock]$CommandAvailable={
            param([string]$Name)
            [bool](Get-Command $Name -ErrorAction SilentlyContinue)
        },
        [scriptblock]$PhysicalDiskProvider={
            Get-PhysicalDisk -ErrorAction Stop
        },
        [scriptblock]$ReliabilityProvider={
            param($Disk)
            Get-StorageReliabilityCounter -PhysicalDisk $Disk -ErrorAction Stop
        },
        [scriptblock]$PnpProvider={
            Get-PnpDevice -PresentOnly -ErrorAction Stop
        },
        [scriptblock]$MemoryEventProvider={
            param($Filter,$Limit)
            Get-WinEvent -FilterHashtable $Filter -MaxEvents $Limit -ErrorAction Stop
        },
        [datetime]$Now=[datetime]::Now
    )

    # Keep the public hardware.json schema stable. Unknown != healthy.
    $result=[ordered]@{
        Disks=@(); PhysicalDisks=@(); ReliabilityCounters=@(); StorageAssessments=@()
        DeviceWarnings=@(); MemoryDiagnosticEvents=@()
        Notes=@(
            'Storage provider health is not a comprehensive SMART test; unavailable readings do not mean healthy.'
            'Counters are provider-dependent; 0 or missing values require context and cannot rule out failures.'
            'Disk identity is only associated within Get-PhysicalDisk results; CIM records are not automatically matched.'
            'Back up important data before troubleshooting recurring storage errors.'
        )
    }

    try {
        $result.Disks=@(& $DiskDriveProvider |
            Select-Object Model,InterfaceType,DeviceID,Size,Status)
    } catch {
        [void]$Warnings.Add("디스크 목록 조회 실패: $($_.Exception.Message)")
    }

    $physicalAvailable=$false
    try { $physicalAvailable=[bool](& $CommandAvailable 'Get-PhysicalDisk') }
    catch { [void]$Warnings.Add("물리 디스크 명령 확인 실패: $($_.Exception.Message)") }
    if ($physicalAvailable) {
        $physical=@()
        try {
            $physical=@(& $PhysicalDiskProvider)
            $result.PhysicalDisks=@($physical |
                Select-Object FriendlyName,DeviceId,MediaType,HealthStatus,OperationalStatus,Size)
        } catch {
            [void]$Warnings.Add("물리 디스크 상태 조회 실패: $($_.Exception.Message)")
        }

        $countersAvailable=$false
        try { $countersAvailable=[bool](& $CommandAvailable 'Get-StorageReliabilityCounter') }
        catch { [void]$Warnings.Add("신뢰성 카운터 명령 확인 실패: $($_.Exception.Message)") }
        foreach ($disk in $physical) {
            if ($null -eq $disk) { continue }
            $label='unknown'
            $idValue=''
            try {
                $label=[string]$disk.FriendlyName
                $idValue=[string]$disk.DeviceId
            } catch { }
            $counter=$null
            $counterError=$null
            if ($countersAvailable) {
                try { $counter=& $ReliabilityProvider $disk }
                catch {
                    $counterError=$_.Exception.Message
                    [void]$Warnings.Add("저장장치 신뢰성 카운터 조회 실패 [$label]: $counterError")
                }
            } else {
                $counterError='Get-StorageReliabilityCounter unavailable'
            }
            $sample=$null
            if ($null -ne $counter) {
                try {
                    $sample=[pscustomobject]@{
                        FriendlyName=$label;DeviceId=$idValue
                        Temperature=$counter.Temperature;Wear=$counter.Wear
                        PowerOnHours=$counter.PowerOnHours
                        ReadErrorsTotal=$counter.ReadErrorsTotal
                        ReadErrorsUncorrected=$counter.ReadErrorsUncorrected
                        WriteErrorsTotal=$counter.WriteErrorsTotal
                        WriteErrorsUncorrected=$counter.WriteErrorsUncorrected
                    }
                    $result.ReliabilityCounters+= $sample
                } catch {
                    $sample=$null
                    $counterError='Storage reliability record could not be decoded'
                    [void]$Warnings.Add("신뢰성 카운터 해석 실패 [$label]")
                }
            } elseif (-not $counterError) {
                $counterError='Storage provider returned no reliability counters'
            }
            try {
                $assessment=Get-WtStorageAssessment -HealthStatus ([string]$disk.HealthStatus) `
                    -OperationalStatus ([string]($disk.OperationalStatus -join ', ')) `
                    -Counters $sample -CountersAvailable ([bool]($null -ne $sample))
                $result.StorageAssessments+= [pscustomobject]@{
                    FriendlyName=$label;DeviceId=$idValue
                    Assessment=$assessment.Assessment;Evidence=$assessment.Evidence
                    CountersAvailable=[bool]($null -ne $sample);CounterError=$counterError
                }
            } catch {
                [void]$Warnings.Add("저장장치 평가 실패 [$label]: $($_.Exception.Message)")
                $result.StorageAssessments+= [pscustomobject]@{
                    FriendlyName=$label;DeviceId=$idValue;Assessment='inconclusive'
                    Evidence=@('Device assessment failed; no healthy conclusion')
                    CountersAvailable=[bool]($null -ne $sample);CounterError=$counterError
                }
            }
        }
    } else {
        [void]$Warnings.Add('Get-PhysicalDisk를 사용할 수 없습니다. 디스크 상태 판정 불가.')
    }

    $pnpAvailable=$false
    try { $pnpAvailable=[bool](& $CommandAvailable 'Get-PnpDevice') }
    catch { [void]$Warnings.Add("PnP 명령 확인 실패: $($_.Exception.Message)") }
    if ($pnpAvailable) {
        try {
            $result.DeviceWarnings=@(& $PnpProvider |
                Where-Object { $_.Status -ne 'OK' } |
                Select-Object -First 30 Status,Class,FriendlyName,InstanceId)
        } catch {
            [void]$Warnings.Add("PnP 장치 조회 실패: $($_.Exception.Message)")
        }
    }

    try {
        $filter=@{
            LogName='System';ProviderName='Microsoft-Windows-MemoryDiagnostics-Results'
            StartTime=$Now.AddDays(-30)
        }
        $result.MemoryDiagnosticEvents=@(& $MemoryEventProvider $filter 10 |
            Select-Object -First 10 TimeCreated,Id,Message)
    } catch {
        if ([string]$_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') {
            [void]$Warnings.Add('메모리 진단 이벤트 기록에 접근할 수 없습니다.')
        }
    }
    [pscustomobject]$result
}

Export-ModuleMember -Function Get-WtHardware
