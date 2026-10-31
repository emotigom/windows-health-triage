#requires -Version 5.1
<#
.SYNOPSIS
    Read-only Defender evidence from injectable providers.
.DESCRIPTION
    Does not initiate antivirus scans or alter protection settings.
#>
function Get-WtSecurityEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$Warnings,
        [scriptblock]$StatusCommandAvailable={ [bool](Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) },
        [scriptblock]$StatusProvider={ Get-MpComputerStatus -ErrorAction Stop },
        [scriptblock]$DetectionCommandAvailable={ [bool](Get-Command Get-MpThreatDetection -ErrorAction SilentlyContinue) },
        [scriptblock]$DetectionProvider={ Get-MpThreatDetection -ErrorAction Stop }
    )
    # Keep OrderedDictionary to allow the explicit scan handler to append log fields.
    $result=[ordered]@{
        Defender=$null;RecentDetections=@();RequestedScan='none'
        DefenderScanResult='not-requested';ClamAVResult='not-requested'
    }
    $statusAvailable=$false
    try { $statusAvailable=[bool](& $StatusCommandAvailable) }
    catch { [void]$Warnings.Add("Defender 상태 명령 확인 실패: $($_.Exception.Message)") }
    if ($statusAvailable) {
        try {
            $result.Defender=& $StatusProvider |
                Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureAge,AntivirusSignatureVersion,QuickScanEndTime,FullScanEndTime
        } catch { [void]$Warnings.Add("Defender 상태 조회 실패: $($_.Exception.Message)") }
    } else {
        [void]$Warnings.Add('Defender PowerShell 상태 명령을 사용할 수 없습니다. 다른 백신 또는 시스템 구성을 확인하세요.')
    }
    # Independent provider: failure reading status must not hide detection evidence.
    $detectionAvailable=$false
    try { $detectionAvailable=[bool](& $DetectionCommandAvailable) }
    catch { [void]$Warnings.Add("Defender 위협 기록 명령 확인 실패: $($_.Exception.Message)") }
    if ($detectionAvailable) {
        try {
            $result.RecentDetections=@(& $DetectionProvider |
                Sort-Object InitialDetectionTime -Descending |
                Select-Object -First 20 ThreatID,InitialDetectionTime,LastThreatStatusChangeTime,ActionSuccess)
        } catch { [void]$Warnings.Add("Defender 위협 기록 조회 실패: $($_.Exception.Message)") }
    } else {
        [void]$Warnings.Add('Defender 위협 기록을 조회할 수 없습니다. 탐지가 없었다는 의미는 아닙니다.')
    }
    return $result
}
Export-ModuleMember -Function Get-WtSecurityEvidence
