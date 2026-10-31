#requires -Version 5.1
<#
.SYNOPSIS
    Read-only Windows event collector with injectable log query provider.
.DESCRIPTION
    Applies a total per-log sample cap AFTER merging overlapping query results.
    Neither the sampled rows nor the cap are a complete log/event count.
#>
Import-Module (Join-Path $PSScriptRoot 'WinTriage.Core.psm1') -ErrorAction Stop

function Get-WtEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$Warnings,
        [ValidateRange(1,720)][int]$EventHours=48,
        [ValidateRange(1,1000)][int]$MaxEventsPerLog=250,
        [datetime]$Now=[datetime]::Now,
        [scriptblock]$EventProvider={
            param($Filter,$Limit)
            Get-WinEvent -FilterHashtable $Filter -MaxEvents $Limit -ErrorAction Stop
        },
        [AllowNull()][hashtable]$SamplingInfo=$null
    )
    $since=$Now.AddHours(-$EventHours)
    $logs=@('System','Application','Microsoft-Windows-Windows Defender/Operational')
    $output=New-Object 'System.Collections.Generic.List[object]'
    foreach ($log in $logs) {
        $queryList=@(@{LogName=$log;StartTime=$since;Level=@(1,2,3)})
        if ($log -eq 'Microsoft-Windows-Windows Defender/Operational') {
            # Defender detections may be informational and not in Level 1/2/3.
            $queryList += @{LogName=$log;StartTime=$since;ID=@(1116,1117,1118,1119)}
        }
        $logRows=New-Object 'System.Collections.Generic.List[object]'
        $seen=@{}
        $queryFailures=0
        $projectionFailures=0
        $queryReachedLimit=$false
        foreach ($filter in $queryList) {
            try {
                # A query may return as many as the requested per-log cap,
                # but different queries must share ONE total output cap.
                $queried=@(& $EventProvider $filter $MaxEventsPerLog)
                if ($queried.Count -ge $MaxEventsPerLog) { $queryReachedLimit=$true }
                foreach ($e in @($queried | Select-Object -First $MaxEventsPerLog)) {
                    if ($null -eq $e) { continue }
                    try {
                        $providerName=[string]$e.ProviderName
                        $eventId=[int]$e.Id
                        $time=([datetime]$e.TimeCreated).ToUniversalTime().ToString('o')
                        if ($null -eq $e.TimeCreated) { throw 'Missing event timestamp' }
                        $recordId=$null
                        if ($null -ne $e.RecordId -and [string]$e.RecordId -ne '') {
                            $recordId=[string]$e.RecordId
                            $identity=$log+'|'+$recordId
                            if ($seen.ContainsKey($identity)) { continue }
                        }
                        $finding=Get-WtEventFinding -Provider $providerName -EventId $eventId
                        $message=[string]$e.Message
                        if ($message.Length -gt 2000) {
                            $message=$message.Substring(0,2000)+' [truncated]'
                        }
                        $row=[pscustomobject]@{
                            TimeUtc=$time;Log=$log;Provider=$providerName
                            EventId=$eventId;Level=$e.LevelDisplayName;RecordId=$e.RecordId
                            Category=$finding.Category;Severity=$finding.Severity
                            Interpretation=$finding.Explanation;Message=$message
                        }
                        $logRows.Add($row)
                        if ($null -ne $recordId) { $seen[$identity]=$true }
                    } catch {
                        # A malformed event must not suppress independent evidence.
                        $projectionFailures++
                    }
                }
            } catch {
                # Empty result sets are normal. Permission/provider failures are not.
                if ([string]$_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') {
                    $queryFailures++
                    [void]$Warnings.Add("이벤트 조회 실패 [$log]: $($_.Exception.Message)")
                }
            }
        }
        if ($projectionFailures -gt 0) {
            [void]$Warnings.Add("이벤트 변환 실패 [$log]: $projectionFailures개 샘플 제외")
        }
        $allSorted=@($logRows.ToArray() | Sort-Object TimeUtc -Descending)
        $selected=@($allSorted | Select-Object -First $MaxEventsPerLog)
        $wasCapped=($allSorted.Count -gt $MaxEventsPerLog)
        if ($null -ne $SamplingInfo) {
            $SamplingInfo[$log]=[pscustomobject]@{
                QueriesAttempted=$queryList.Count
                QueryFailures=$queryFailures
                ProjectionFailures=$projectionFailures
                ObservedDistinct=$allSorted.Count
                Retained=$selected.Count
                MaxPerLog=$MaxEventsPerLog
                TruncatedByCombinedCap=$wasCapped
                AnyQueryReachedLimit=$queryReachedLimit
                Incomplete=($wasCapped -or $queryReachedLimit -or $queryFailures -gt 0 -or $projectionFailures -gt 0)
            }
        }
        foreach ($item in $selected) { $output.Add($item) }
    }
    @($output.ToArray() | Sort-Object TimeUtc -Descending)
}
Export-ModuleMember -Function Get-WtEvents
