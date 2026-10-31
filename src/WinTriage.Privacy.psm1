#requires -Version 5.1
<#
.SYNOPSIS
    Pure, field-allowlisted transformation for an opt-in public summary.
.DESCRIPTION
    Never forwards raw event messages, process names, host/user names,
    timestamps, paths, IP addresses, serials, device IDs or warning strings.
    Classification labels are constrained to a hardcoded vocabulary.
#>
function ConvertTo-WtShareSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][object]$Manifest,
        [AllowNull()][object[]]$EventSummary = @(),
        [AllowNull()][object]$Hardware = $null,
        [AllowNull()][object]$Integrity = $null
    )

    $allowedModes = @('Quick','Processes','Monitor','Events','Security','Hardware','Integrity','Full')
    $mode = 'unknown'
    if ([string]$Manifest.Mode -in $allowedModes) { $mode = [string]$Manifest.Mode }

    $categories = @(
        'general','hardware-signal','storage-signal','unexpected-shutdown',
        'memory-pressure','application-crash','application-hang','service-crash',
        'tracing-session','device-pairing','graphics-reset','windows-error-report',
        'malware-detected','malware-action','malware-action-failed'
    )
    $severities = @('high','review','info')
    $counts = @{}
    foreach ($entry in @($EventSummary)) {
        if ($null -eq $entry) { continue }
        $category = [string]$entry.Category
        $severity = [string]$entry.Severity
        if ($category -notin $categories) { $category = 'other' }
        if ($severity -notin $severities) { $severity = 'review' }

        $count = 0L
        if (-not [long]::TryParse([string]$entry.Count,[ref]$count)) { continue }
        # Ignore anomalous counts: the share export is not a raw forensic dump.
        if ($count -le 0 -or $count -gt 1000000) { continue }
        $key = $category + '|' + $severity
        if (-not $counts.ContainsKey($key)) { $counts[$key] = 0L }
        $counts[$key] += $count
    }
    $eventRows = @(
        foreach ($key in @($counts.Keys | Sort-Object)) {
            $parts = $key -split '\|',2
            [pscustomobject]@{
                Category = $parts[0]
                Severity = $parts[1]
                SampledCount = [long]$counts[$key]
            }
        }
    )
    $eventCount = 0L
    foreach ($row in $eventRows) { $eventCount += $row.SampledCount }

    $storage = [ordered]@{ Collected = $false; Attention = 0; Inconclusive = 0 }
    if ($null -ne $Hardware) {
        $storage['Collected'] = $true
        foreach ($entry in @($Hardware.StorageAssessments)) {
            if ($null -eq $entry) { continue }
            if ([string]$entry.Assessment -eq 'attention') { $storage['Attention']++ }
            elseif ([string]$entry.Assessment -eq 'inconclusive') { $storage['Inconclusive']++ }
        }
    }

    $integrityStates = [ordered]@{ Collected = $false; Sfc = 'not-collected'; Dism = 'not-collected' }
    if ($null -ne $Integrity) {
        $integrityStates['Collected'] = $true
        foreach ($pair in @(@('SfcVerifyOnly','Sfc'),@('DismScanHealth','Dism'))) {
            $raw = [string]($Integrity.($pair[0]))
            $state = 'unknown'
            if ($raw -in @('not-requested','skipped-requires-admin','unavailable','indeterminate','execution-error','completed-review-output')) {
                $state = $raw
            } elseif ($raw -match '^failed-exit-[-]?[0-9]+$') {
                $state = 'failed'
            }
            $integrityStates[$pair[1]] = $state
        }
    }

    [pscustomobject]@{
        SchemaVersion = 1
        ExportType = 'explicit-local-minimal-summary'
        Mode = $mode
        Events = [pscustomobject]@{
            SampledCount = $eventCount
            Groups = @($eventRows)
        }
        Storage = [pscustomobject]$storage
        Integrity = [pscustomobject]$integrityStates
        Limitations = @(
            'Sampled counts are incomplete and are not proof that a device is healthy or infected.',
            'Storage counters and event categories are clues, not hardware diagnoses.',
            'A minimal summary can still reveal your software and device symptoms; review before sharing.'
        )
    }
}
Export-ModuleMember -Function ConvertTo-WtShareSummary
