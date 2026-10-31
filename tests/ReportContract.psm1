#requires -Version 5.1
# Test-only, local report structural validator. Does not execute native commands.
function Assert-WtJsonKeys {
    param([object]$Object,[string[]]$Keys,[string]$Label)
    if ($null -eq $Object) { throw "Null JSON object: $Label" }
    foreach ($key in $Keys) {
        if ($null -eq $Object.PSObject.Properties[$key]) {
            throw ("Missing JSON field: {0}.{1}" -f $Label,$key)
        }
    }
}
function Read-WtContractJson {
    param([string]$Directory,[string]$Name)
    ConvertFrom-Json -InputObject (Get-Content -LiteralPath (Join-Path $Directory $Name) -Raw -Encoding UTF8)
}
function Assert-WtReportContract {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$RunDirectory)
    $m=Read-WtContractJson $RunDirectory 'manifest.json'
    Assert-WtJsonKeys $m @('ReportSchemaVersion','ToolVersion','RunId','StartedUtc','CompletedUtc','Mode','Computer','Files','Warnings','Scan') 'manifest'
    if ($m.ReportSchemaVersion -isnot [int] -and $m.ReportSchemaVersion -isnot [long]) { throw 'Schema version must be an integer' }
    if ($m.ReportSchemaVersion -ne 1) { throw 'Unsupported raw report schema version' }
    if ($m.Mode -notin @('Quick','Processes','Monitor','Events','Security','Hardware','Integrity','Full')) { throw 'Unknown mode' }
    if ($m.Files -isnot [array] -or $m.Warnings -isnot [array]) { throw 'Files and Warnings must be arrays' }
    $files=@($m.Files)
    if (@($files | Sort-Object -Unique).Count -ne $files.Count) { throw 'Duplicate report file' }
    foreach ($f in $files) {
        if ([string]$f -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') { throw 'Unsafe report path' }
        if (-not (Test-Path -LiteralPath (Join-Path $RunDirectory $f) -PathType Leaf)) { throw ("Missing file: {0}" -f $f) }
    }
    $required=@('manifest.json','SUMMARY.md','system.json')
    if ($m.Mode -in @('Quick','Processes','Monitor','Full')) { $required+= 'processes.json' }
    if ($m.Mode -in @('Quick','Events','Full')) { $required+= @('events.json','event-summary.json','triage-advice.json') }
    if ($m.Mode -in @('Quick','Security','Full')) { $required+= 'security.json' }
    if ($m.Mode -in @('Quick','Hardware','Full')) { $required+= 'hardware.json' }
    if ($m.Mode -in @('Integrity','Full')) { $required+= 'integrity.json' }
    if ($m.Mode -eq 'Monitor') { $required+= @('memory-samples.csv','memory-growth.csv') }
    foreach ($f in $required) { if ($files -notcontains $f) { throw ("Missing required file: {0}" -f $f) } }
    $system=Read-WtContractJson $RunDirectory 'system.json'
    Assert-WtJsonKeys $system @('OS','Version','LastBootUtc','TotalRamGiB','FreePhysicalRamGiB','ReportedFreeVirtualMemoryGiB') 'system'
    if ($files -contains 'hardware.json') {
        $h=Read-WtContractJson $RunDirectory 'hardware.json'
        Assert-WtJsonKeys $h @('Disks','PhysicalDisks','ReliabilityCounters','StorageAssessments','DeviceWarnings','MemoryDiagnosticEvents','Notes') 'hardware'
        if ($h.StorageAssessments -isnot [array]) { throw 'Hardware assessments must be an array' }
        foreach ($a in @($h.StorageAssessments)) {
            Assert-WtJsonKeys $a @('Assessment','Evidence','CountersAvailable','CounterError') 'storage assessment'
            if ($a.Assessment -notin @('attention','inconclusive')) { throw 'False-healthy or unknown storage assessment' }
        }
    }
    if ($files -contains 'events.json') {
        Assert-WtJsonKeys $m @('EventSampling','MaxEventsPerLog','EventHours') 'manifest'
        if ($null -eq $m.EventSampling) { throw 'Missing event sampling' }
        foreach ($log in $m.EventSampling.PSObject.Properties) {
            $s=$log.Value
            Assert-WtJsonKeys $s @('QueriesAttempted','QueryFailures','ProjectionFailures','ObservedDistinct','Retained','MaxPerLog','TruncatedByCombinedCap','AnyQueryReachedLimit','Incomplete') 'event sampling'
            if ([int]$s.Retained -gt [int]$s.MaxPerLog -or [int]$s.ObservedDistinct -lt [int]$s.Retained) { throw 'Invalid sampling totals' }
            if ([int]$s.MaxPerLog -ne [int]$m.MaxEventsPerLog) { throw 'Sampling cap contract drift' }
        }
        # PS 5.1 can wrap a parsed JSON array one level deeper than PS 7.
        foreach ($batch in @(Read-WtContractJson $RunDirectory 'events.json')) {
            foreach ($e in @($batch)) {
                if ($null -ne $e) { Assert-WtJsonKeys $e @('TimeUtc','Log','Provider','EventId','Level','RecordId','Category','Severity','Interpretation','Message') 'event' }
            }
        }
    }
    if ($files -contains 'security.json') {
        $s=Read-WtContractJson $RunDirectory 'security.json'
        Assert-WtJsonKeys $s @('Defender','RecentDetections','RequestedScan','DefenderScanResult','ClamAVResult') 'security'
        if ($s.RecentDetections -isnot [array]) { throw 'Security detections must be an array' }
    }
    if ($files -contains 'integrity.json') {
        $i=Read-WtContractJson $RunDirectory 'integrity.json'
        Assert-WtJsonKeys $i @('Administrator','SfcVerifyOnly','DismScanHealth','Notes') 'integrity'
        if ($i.Administrator -isnot [bool]) { throw 'Administrator must be boolean' }
        foreach ($state in @($i.SfcVerifyOnly,$i.DismScanHealth)) {
            if ($state -notin @('not-requested','skipped-requires-admin','unavailable','indeterminate','execution-error','completed-review-output') -and
                [string]$state -notmatch '^failed-exit-[-]?[0-9]+$') { throw 'Invalid or misleading integrity state' }
        }
    }
    if ($m.Mode -eq 'Monitor') {
        if ((Get-Content (Join-Path $RunDirectory 'memory-samples.csv') -TotalCount 1) -notmatch 'InstanceKey') { throw 'Missing process identity CSV field' }
        if ((Get-Content (Join-Path $RunDirectory 'memory-growth.csv') -TotalCount 1) -notmatch 'PrivateGrowthMiB') { throw 'Missing growth CSV field' }
    }
    return $true
}
Export-ModuleMember -Function Assert-WtReportContract
