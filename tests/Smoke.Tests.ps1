#requires -Version 5.1
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'src\WinTriage.Core.psm1') -Force
function Assert-Equal { param($Actual,$Expected,[string]$Label)
    if ($Actual -ne $Expected) { throw "FAIL $Label : expected [$Expected], got [$Actual]" }
}
function Test-Parse([string]$Path) {
    $tokens=$null; $parseErrors=$null
    [void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$parseErrors)
    if ($parseErrors -and $parseErrors.Count -gt 0) { throw "PowerShell parse errors in ${Path}: $($parseErrors | Out-String)" }
}
Get-ChildItem -LiteralPath $root -Recurse -File |
    Where-Object { $_.Extension -in @('.ps1','.psm1') } |
    ForEach-Object { Test-Parse $_.FullName }

$examples=@(
    @('Microsoft-Windows-WHEA-Logger',18,'hardware-signal','high'),
    @('Microsoft-Windows-WHEA-Logger',17,'hardware-signal','review'),
    @('Microsoft-Windows-Kernel-Power',41,'unexpected-shutdown','review'),
    @('Microsoft-Windows-Kernel-EventTracing',2,'tracing-session','info'),
    @('Microsoft-Windows-DeviceAssociationService',3509,'device-pairing','info'),
    @('Microsoft-Windows-Resource-Exhaustion-Detector',2004,'memory-pressure','high'),
    @('disk',7,'storage-signal','high'),
    @('Service Control Manager',7031,'service-crash','review'),
    @('Microsoft-Windows-Windows Defender',1116,'malware-detected','high'),
    @('Microsoft-Windows-Windows Defender',1118,'malware-action-failed','high'),
    @('Application Error',1000,'application-crash','review'),
    @('Display',4101,'graphics-reset','review'),
    @('Vendor-Unknown',8,'general','review')
)
foreach ($e in $examples) {
    $f=Get-WtEventFinding -Provider $e[0] -EventId $e[1]
    Assert-Equal $f.Category $e[2] ("Event {0}/{1} Category" -f $e[0],$e[1])
    Assert-Equal $f.Severity $e[3] ("Event {0}/{1} Severity" -f $e[0],$e[1])
}
$sampleRows=@(
    [pscustomobject]@{InstanceKey='100|A';IdentityReliable=$true;Name='test';Pid=100;SampleTimeUtc='2026-10-31T01:00:00Z';PrivateMiB=100;WorkingSetMiB=80},
    [pscustomobject]@{InstanceKey='100|A';IdentityReliable=$true;Name='test';Pid=100;SampleTimeUtc='2026-10-31T01:00:10Z';PrivateMiB=140;WorkingSetMiB=120},
    [pscustomobject]@{InstanceKey='100|B';IdentityReliable=$true;Name='test';Pid=100;SampleTimeUtc='2026-10-31T01:00:20Z';PrivateMiB=200;WorkingSetMiB=170},
    [pscustomobject]@{InstanceKey='200|unknown';IdentityReliable=$false;Name='protected';Pid=200;SampleTimeUtc='2026-10-31T01:00:00Z';PrivateMiB=10;WorkingSetMiB=10},
    [pscustomobject]@{InstanceKey='200|unknown';IdentityReliable=$false;Name='protected';Pid=200;SampleTimeUtc='2026-10-31T01:00:10Z';PrivateMiB=100;WorkingSetMiB=100}
)
$growth=@(Get-WtProcessGrowth -Samples $sampleRows)
Assert-Equal $growth.Count 1 'PID reuse / untrusted identities excluded'
Assert-Equal $growth[0].PrivateGrowthMiB 40 'Growth amount'
Assert-Equal @(Get-WtProcessGrowth -Samples @()).Count 0 'Empty process list'
$eventRows=@(
    [pscustomobject]@{ Provider='disk';EventId=7;Category='storage-signal';Severity='high';TimeUtc='2026-10-31T01:00:00Z';Interpretation='backup' },
    [pscustomobject]@{ Provider='disk';EventId=7;Category='storage-signal';Severity='high';TimeUtc='2026-10-31T02:00:00Z';Interpretation='backup' },
    [pscustomobject]@{ Provider='disk';EventId=51;Category='storage-signal';Severity='high';TimeUtc='2026-10-31T03:00:00Z';Interpretation='backup' }
)
$summary=@(Get-WtEventSummary -Events $eventRows)
Assert-Equal $summary.Count 2 'Event group count'
Assert-Equal $summary[0].Count 2 'Event repetition'
Assert-Equal $summary[0].FirstUtc '2026-10-31T01:00:00Z' 'Event first occurrence'
Assert-Equal @(Get-WtEventSummary -Events @()).Count 0 'Empty event list'
$advice=@(Get-WtTriageAdvice -Events $eventRows)
Assert-Equal $advice[0].Category 'storage-signal' 'Storage action'
Assert-Equal $advice[0].Priority 'high' 'Storage priority'
Assert-Equal @(Get-WtTriageAdvice -Events @()).Count 0 'Empty advice list'
# Storage provider information is incomplete on many controllers and USB enclosures.
$a=Get-WtStorageAssessment -HealthStatus 'Healthy' -OperationalStatus 'OK' -CountersAvailable:$false
Assert-Equal $a.Assessment 'inconclusive' 'Healthy provider status is not full SMART validation'
$a=Get-WtStorageAssessment -HealthStatus 'Unknown' -OperationalStatus 'Unknown' -CountersAvailable:$false
Assert-Equal $a.Assessment 'inconclusive' 'Unknown storage is inconclusive'
$a=Get-WtStorageAssessment -HealthStatus 'Healthy' -OperationalStatus 'Unknown' -CountersAvailable:$false
Assert-Equal $a.Assessment 'inconclusive' 'Unknown operational status cannot be a fault or healthy conclusion'
$a=Get-WtStorageAssessment -HealthStatus 'Healthy' -OperationalStatus 'No Contact' -CountersAvailable:$false
Assert-Equal $a.Assessment 'attention' 'Real operational failure requires attention'
$a=Get-WtStorageAssessment -HealthStatus 'Warning' -OperationalStatus 'OK' -CountersAvailable:$false
Assert-Equal $a.Assessment 'attention' 'Storage warning requires attention'
$a=Get-WtStorageAssessment -HealthStatus 'Healthy' -OperationalStatus 'OK' -CountersAvailable:$true -Counters ([pscustomobject]@{ ReadErrorsUncorrected=1;WriteErrorsUncorrected=0 })
Assert-Equal $a.Assessment 'attention' 'Uncorrected read errors require attention'
$a=Get-WtStorageAssessment -HealthStatus 'Healthy' -OperationalStatus 'Degraded' -CountersAvailable:$false
Assert-Equal $a.Assessment 'attention' 'Degraded storage operation requires attention'
$a=Get-WtStorageAssessment -HealthStatus 'Healthy' -OperationalStatus 'OK' -CountersAvailable:$true -Counters ([pscustomobject]@{ ReadErrorsUncorrected=$null;WriteErrorsUncorrected=$null })
Assert-Equal $a.Assessment 'inconclusive' 'Absent counters do not equal zero errors'

# Static regression guards for non-destructive native checks (in addition to manual review).
$main=Get-Content -LiteralPath (Join-Path $root 'WinTriage.ps1') -Raw
foreach ($required in @("'/verifyonly'", "'/Online','/Cleanup-Image','/ScanHealth'", 'Test-WtAdministrator')) {
    if (-not $main.Contains($required)) { throw "Missing integrity safety guard: $required" }
}
foreach ($forbidden in @('Invoke-Expression','/RestoreHealth','/scannow','Reset-PhysicalDisk','Clear-Disk')) {
    # Check the native invocation section, where only safe fixed arguments are allowed.
    $from=$main.IndexOf('function Get-WtIntegrity {')
    $to=$main.IndexOf('function Get-WtSecurity {')
    if ($from -lt 0 -or $to -le $from) { throw 'Integrity function boundaries not found' }
    $part=$main.Substring($from,$to-$from)
    if ($part -match [regex]::Escape($forbidden)) { throw "Unsafe integrity operation found: $forbidden" }
}
Write-Host ("PASS: parsing, {0} event scenarios, PID identity, grouping, storage caution, integrity guards" -f $examples.Count)
