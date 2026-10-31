#requires -Version 5.1
# Injectable synthetic data: never reads personal event logs.
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'src\WinTriage.EventCollector.psm1') -Force
function Assert-WtEvent {
    param($Actual,$Expected,[string]$Title)
    if ($Actual -ne $Expected) { throw "$Title : expected [$Expected], got [$Actual]" }
}
function New-FakeEvent {
    param([string]$Provider,[int]$Id,[int]$Record,[string]$Time)
    [pscustomobject]@{
        ProviderName=$Provider
        Id=$Id
        RecordId=$Record
        TimeCreated=[datetime]$Time
        LevelDisplayName='Warning'
        Message='synthetic-only CANARY-EVENT-TEXT'
    }
}
$fixtures=@{
    System=@(
        (New-FakeEvent -Provider 'disk' -Id 7 -Record 21 -Time '2026-10-31T01:00:00Z'),
        (New-FakeEvent -Provider 'disk' -Id 51 -Record 22 -Time '2026-10-31T02:00:00Z'),
        (New-FakeEvent -Provider 'disk' -Id 7 -Record 23 -Time '2026-10-31T03:00:00Z')
    )
    DefenderNormal=@(
        (New-FakeEvent -Provider 'Microsoft-Windows-Windows Defender' -Id 1116 -Record 10 -Time '2026-10-31T02:30:00Z'),
        (New-FakeEvent -Provider 'Microsoft-Windows-Windows Defender' -Id 1000 -Record 11 -Time '2026-10-31T02:45:00Z')
    )
    DefenderDetection=@(
        (New-FakeEvent -Provider 'Microsoft-Windows-Windows Defender' -Id 1116 -Record 10 -Time '2026-10-31T02:30:00Z'),
        (New-FakeEvent -Provider 'Microsoft-Windows-Windows Defender' -Id 1118 -Record 12 -Time '2026-10-31T04:00:00Z')
    )
}
$provider={
    param($Filter,$Limit)
    if ($Limit -ne 2) { throw "Collector requested unexpected per-query cap: $Limit" }
    switch ([string]$Filter.LogName) {
        'System' { return $fixtures.System }
        'Application' { throw 'Synthetic access denied' }
        'Microsoft-Windows-Windows Defender/Operational' {
            if ($Filter.ContainsKey('ID')) { return $fixtures.DefenderDetection }
            return $fixtures.DefenderNormal
        }
    }
}
$w=New-Object 'System.Collections.Generic.List[string]'
$sampling=@{}
$rows=@(Get-WtEvents -Warnings $w -EventHours 1 -MaxEventsPerLog 2 -Now ([datetime]'2026-10-31T04:30:00Z') -EventProvider $provider -SamplingInfo $sampling)
Assert-WtEvent $rows.Count 4 'total 2 system plus 2 defender'
Assert-WtEvent @($rows | Where-Object { $_.Log -eq 'System' }).Count 2 'system total cap'
Assert-WtEvent @($rows | Where-Object { $_.Log -eq 'Application' }).Count 0 'failed application independent'
$defender=@($rows | Where-Object { $_.Log -eq 'Microsoft-Windows-Windows Defender/Operational' })
Assert-WtEvent $defender.Count 2 'Defender combined cap applies'
Assert-WtEvent @($defender | Where-Object { $_.EventId -eq 1118 }).Count 1 'informational detection included'
Assert-WtEvent $defender[0].RecordId 12 'most recent event retained'
Assert-WtEvent (@($rows | Where-Object { $_.Log -eq 'System' -and $_.RecordId -eq 23 }).Count) 1 'newest system record retained from unordered provider'
Assert-WtEvent $sampling['System'].Retained 2 'system count retained'
Assert-WtEvent $sampling['System'].Incomplete $true 'system limit reports incomplete'
Assert-WtEvent $sampling['Application'].QueryFailures 1 'query failure metadata'
Assert-WtEvent $sampling['Application'].Incomplete $true 'denied access flagged'
Assert-WtEvent $sampling['Microsoft-Windows-Windows Defender/Operational'].ObservedDistinct 3 'defender record dedup before cap'
Assert-WtEvent $sampling['Microsoft-Windows-Windows Defender/Operational'].TruncatedByCombinedCap $true 'defender cap enforced'
Assert-WtEvent $w.Count 1 'one failed log warns'
Assert-WtEvent $rows[0].TimeUtc '2026-10-31T04:00:00.0000000Z' 'global chronological sort'

$w2=New-Object 'System.Collections.Generic.List[string]'
$sampling2=@{}
$emptyProvider={
    param($Filter,$Limit)
    Write-Error -Message 'No matching events in synthetic log' -ErrorId 'NoMatchingEventsFound' -ErrorAction Stop
}
$none=@(Get-WtEvents -Warnings $w2 -EventHours 1 -MaxEventsPerLog 2 -EventProvider $emptyProvider -SamplingInfo $sampling2)
Assert-WtEvent $none.Count 0 'empty logs'
Assert-WtEvent $w2.Count 0 'normal no match does not warn'
Assert-WtEvent $sampling2['System'].Incomplete $false 'empty match not marked partial'

$w3=New-Object 'System.Collections.Generic.List[string]'
$sampling3=@{}
$badProvider={
    param($Filter,$Limit)
    if ($Filter.LogName -eq 'System') {
        [pscustomobject]@{ ProviderName='disk'; Id=7;RecordId=4;TimeCreated=$null;Message='malformed' }
        New-FakeEvent -Provider 'disk' -Id 7 -Record 5 -Time '2026-10-31T03:00:00Z'
    }
}
$valid=@(Get-WtEvents -Warnings $w3 -EventHours 1 -MaxEventsPerLog 2 -EventProvider $badProvider -SamplingInfo $sampling3)
Assert-WtEvent $valid.Count 1 'malformed row isolated'
Assert-WtEvent $sampling3['System'].ProjectionFailures 1 'malformed row sampled metadata'
Assert-WtEvent $w3.Count 1 'single projection warning'
Assert-WtEvent $sampling3['System'].Incomplete $true 'malformed sample reports partial'
Write-Host 'PASS: event cap per log, overlapping Defender query deduplication, independent access errors and metadata'
