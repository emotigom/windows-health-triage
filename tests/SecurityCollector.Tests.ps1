#requires -Version 5.1
# Fictional providers only. Never reads real Defender data or launches a scan.
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'src\WinTriage.SecurityCollector.psm1') -Force
function Assert-Security {
    param($Actual,$Expected,[string]$Label)
    if ($Actual -ne $Expected) { throw ("{0}: expected [{1}], got [{2}]" -f $Label,$Expected,$Actual) }
}
$w=New-Object 'System.Collections.Generic.List[string]'
$providers=@{
    StatusCommandAvailable={ $true }
    StatusProvider={ [pscustomobject]@{AMServiceEnabled=$true;AntivirusEnabled=$true;RealTimeProtectionEnabled=$true;AntivirusSignatureAge=1;AntivirusSignatureVersion='SYNTHETIC';QuickScanEndTime=$null;FullScanEndTime=$null} }
    DetectionCommandAvailable={ $true }
    DetectionProvider={
        [pscustomobject]@{ThreatID=101;InitialDetectionTime=[datetime]'2026-10-01';LastThreatStatusChangeTime=$null;ActionSuccess=$true}
        [pscustomobject]@{ThreatID=102;InitialDetectionTime=[datetime]'2026-10-02';LastThreatStatusChangeTime=$null;ActionSuccess=$false}
    }
}
$normal=Get-WtSecurityEvidence -Warnings $w @providers
Assert-Security $normal.Defender.AntivirusEnabled $true 'status observed'
Assert-Security $normal.RecentDetections.Count 2 'detections retained'
Assert-Security $normal.RecentDetections[0].ThreatID 102 'newest first'
Assert-Security $normal.RequestedScan 'none' 'passive no scan request'
Assert-Security $normal.DefenderScanResult 'not-requested' 'no native Defender scan'
Assert-Security $normal.ClamAVResult 'not-requested' 'no native ClamAV scan'
Assert-Security $w.Count 0 'no synthetic provider warning'

$w2=New-Object 'System.Collections.Generic.List[string]'
$partial=@{
    StatusCommandAvailable={ $false }
    StatusProvider={ throw 'status source must not run' }
    DetectionCommandAvailable={ $true }
    DetectionProvider={ [pscustomobject]@{ThreatID=103;InitialDetectionTime=[datetime]'2026-10-03';ActionSuccess=$false} }
}
$one=Get-WtSecurityEvidence -Warnings $w2 @partial
Assert-Security $null $one.Defender 'status unavailable'
Assert-Security $one.RecentDetections.Count 1 'independent detection remains'
Assert-Security $w2.Count 1 'status missing warning'

$w3=New-Object 'System.Collections.Generic.List[string]'
$denied=@{
    StatusCommandAvailable={ $true }
    StatusProvider={ throw 'synthetic status access denied' }
    DetectionCommandAvailable={ $true }
    DetectionProvider={ throw 'synthetic detection access denied' }
}
$none=Get-WtSecurityEvidence -Warnings $w3 @denied
Assert-Security $null $none.Defender 'denied status remains unknown'
Assert-Security $none.RecentDetections.Count 0 'no fabricated detection evidence'
Assert-Security $w3.Count 2 'independent warnings'

$w4=New-Object 'System.Collections.Generic.List[string]'
$absent=@{
    StatusCommandAvailable={ $false }
    StatusProvider={ throw 'must not run' }
    DetectionCommandAvailable={ $false }
    DetectionProvider={ throw 'must not run' }
}
$missing=Get-WtSecurityEvidence -Warnings $w4 @absent
Assert-Security $w4.Count 2 'missing APIs not mistaken for clean'
Assert-Security $missing.RequestedScan 'none' 'no default native scan'
Write-Host 'PASS passive Defender providers, denied status/history, preserved independent evidence'
