#requires -Version 5.1
# Never reads real drives or event logs; all hardware data is synthetic.
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'src\WinTriage.HardwareCollector.psm1') -Force
function Assert-WtHardware {
    param($Actual,$Expected,[string]$Label)
    if ($Actual -ne $Expected) { throw ("{0}: expected [{1}], got [{2}]" -f $Label,$Expected,$Actual) }
}
$disks=@(
    [pscustomobject]@{FriendlyName='synthetic-A';DeviceId='A';MediaType='SSD';HealthStatus='Healthy';OperationalStatus=@('OK');Size=100},
    [pscustomobject]@{FriendlyName='synthetic-B';DeviceId='B';MediaType='HDD';HealthStatus='Healthy';OperationalStatus=@('OK');Size=200},
    [pscustomobject]@{FriendlyName='synthetic-C';DeviceId='C';MediaType='Unknown';HealthStatus='Unknown';OperationalStatus=@('Unknown');Size=300}
)
$warnings=New-Object 'System.Collections.Generic.List[string]'
$data=Get-WtHardware -Warnings $warnings -Now ([datetime]'2026-10-31T12:00:00Z') `
    -DiskDriveProvider { throw 'synthetic Win32_DiskDrive unavailable' } `
    -CommandAvailable { param($name) return $true } `
    -PhysicalDiskProvider { $disks } `
    -ReliabilityProvider {
        param($disk)
        if ($disk.DeviceId -eq 'B') { throw 'synthetic counter access denied' }
        if ($disk.DeviceId -eq 'C') { return $null }
        [pscustomobject]@{
            Temperature=35;Wear=4;PowerOnHours=10
            ReadErrorsTotal=2;ReadErrorsUncorrected=1
            WriteErrorsTotal=0;WriteErrorsUncorrected=0
        }
    } `
    -PnpProvider {
        [pscustomobject]@{Status='OK';Class='USB';FriendlyName='synthetic-OK';InstanceId='DEV-OK'}
        [pscustomobject]@{Status='Error';Class='Display';FriendlyName='synthetic-warning';InstanceId='DEV-ERR'}
    } `
    -MemoryEventProvider {
        param($filter,$limit)
        if ($filter.ProviderName -ne 'Microsoft-Windows-MemoryDiagnostics-Results') { throw 'wrong provider' }
        if ($limit -ne 10) { throw 'wrong event cap' }
        if ($filter.StartTime -ne [datetime]'2026-10-01T12:00:00Z') { throw 'wrong lookback' }
        [pscustomobject]@{TimeCreated=[datetime]'2026-10-31T11:00:00Z';Id=1201;Message='synthetic memory test'}
    }
Assert-WtHardware $data.Disks.Count 0 'CIM failure does not fabricate disks'
Assert-WtHardware $data.PhysicalDisks.Count 3 'physical disks preserved independently of CIM failure'
Assert-WtHardware $data.StorageAssessments.Count 3 'each physical disk assessed'
Assert-WtHardware $data.ReliabilityCounters.Count 1 'one counter accessible'
Assert-WtHardware $data.StorageAssessments[0].Assessment 'attention' 'uncorrectable read errors require attention'
Assert-WtHardware $data.StorageAssessments[1].Assessment 'inconclusive' 'missing counter is not healthy'
Assert-WtHardware $data.StorageAssessments[1].CountersAvailable $false 'counter unavailable flagged'
Assert-WtHardware $data.StorageAssessments[2].Assessment 'inconclusive' 'unknown device status is not healthy'
Assert-WtHardware $data.DeviceWarnings.Count 1 'PnP error retained'
Assert-WtHardware $data.MemoryDiagnosticEvents.Count 1 'memory diagnostic independently retained'
Assert-WtHardware $warnings.Count 2 'CIM and one counter failure warnings'
Assert-WtHardware ($data.StorageAssessments[1].CounterError -match 'access denied') $true 'counter failure recorded'

$warnings2=New-Object 'System.Collections.Generic.List[string]'
$noHardware=Get-WtHardware -Warnings $warnings2 `
    -DiskDriveProvider { @() } `
    -CommandAvailable { param($name) $false } `
    -PhysicalDiskProvider { throw 'should not call physical provider' } `
    -ReliabilityProvider { throw 'should not call counter provider' } `
    -PnpProvider { throw 'should not call PnP provider' } `
    -MemoryEventProvider {
        param($filter,$limit)
        Write-Error -Message 'No matching synthetic events' -ErrorId 'NoMatchingEventsFound' -ErrorAction Stop
    }
Assert-WtHardware $noHardware.StorageAssessments.Count 0 'unavailable disk command yields no assessments'
Assert-WtHardware $noHardware.DeviceWarnings.Count 0 'PnP unavailable yields zero rows'
Assert-WtHardware $warnings2.Count 1 'no memory events is ordinary, physical unavailable warned'

$warnings3=New-Object 'System.Collections.Generic.List[string]'
$partial=Get-WtHardware -Warnings $warnings3 `
    -DiskDriveProvider { [pscustomobject]@{Model='synthetic-cim';InterfaceType='SATA';DeviceID='D';Size=12;Status='OK'} } `
    -CommandAvailable { param($name) $true } `
    -PhysicalDiskProvider { throw 'synthetic physical disks denied' } `
    -PnpProvider { throw 'synthetic PnP denied' } `
    -MemoryEventProvider { param($filter,$limit) throw 'synthetic event channel access denied' }
Assert-WtHardware $partial.Disks.Count 1 'CIM preserved when physical provider failed'
Assert-WtHardware $partial.PhysicalDisks.Count 0 'physical provider failure empty'
Assert-WtHardware $partial.DeviceWarnings.Count 0 'PnP failure empty'
Assert-WtHardware $partial.MemoryDiagnosticEvents.Count 0 'memory event failure empty'
Assert-WtHardware $warnings3.Count 3 'independent physical PnP memory warnings'
$forbidden=@('Clear-Disk','Reset-PhysicalDisk','Set-PhysicalDisk','Remove-PnpDevice','Disable-PnpDevice')
$src=Get-Content -LiteralPath (Join-Path $root 'src\WinTriage.HardwareCollector.psm1') -Raw
foreach ($bad in $forbidden) { if ($src.Contains($bad)) { throw "Unexpected mutation command $bad" } }
Write-Host 'PASS: mocked disk/CIM/counter/PnP/memory provider failures and inconclusive classifications'
