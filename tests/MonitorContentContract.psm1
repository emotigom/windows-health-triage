#requires -Version 5.1
# Read-only, test/field-validation-only, never returns private report content.
Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'src\WinTriage.Core.psm1') -Force

function Get-WtMonitorMirrorText {
    param([AllowNull()][object]$Value)
    # PowerShell 7 may turn JSON ISO8601 text into DateTime automatically.
    if ($Value -is [datetime]) {
        return $Value.ToUniversalTime().ToString('o',[Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [datetimeoffset]) {
        return $Value.UtcDateTime.ToString('o',[Globalization.CultureInfo]::InvariantCulture)
    }
    return [string]$Value
}
# The collector emits canonical seven-digit UTC instants. Reject invalid
# normalized instants or impossible dates; PowerShell 7 may normalize offsets.
function Get-WtMonitorUtcTicks {
    param([AllowNull()][object]$Value)
    $utc=Get-WtMonitorMirrorText $Value
    if ($utc -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z$') {
        throw 'Monitor run UTC timestamp invalid'
    }
    $parsed=[datetimeoffset]::MinValue
    if (-not [datetimeoffset]::TryParseExact(
            $utc,'yyyy-MM-ddTHH:mm:ss.fffffffZ',
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AssumeUniversal,
            [ref]$parsed)) {
        throw 'Monitor run UTC timestamp invalid'
    }
    return [long]$parsed.UtcDateTime.Ticks
}

function Assert-WtMonitorCsvMirror {
    param([string]$Directory,[string]$Name,[object[]]$Rows,[string[]]$Columns)
    $path=Join-Path $Directory $Name
    $header=[string](Get-Content -LiteralPath $path -TotalCount 1 -Encoding UTF8)
    if ($header -cne ('"' + ($Columns -join '","') + '"')) { throw 'Monitor CSV header mismatch' }
    $parsed=@(Import-Csv -LiteralPath $path -Encoding UTF8)
    if ($parsed.Count -ne $Rows.Count) { throw 'Monitor CSV row count mismatch' }
    for ($i=0; $i -lt $Rows.Count; $i++) {
        foreach ($column in $Columns) {
            $left=$Rows[$i].PSObject.Properties[$column]
            $right=$parsed[$i].PSObject.Properties[$column]
            if ($null -eq $left -or $null -eq $right -or
                (Get-WtMonitorMirrorText $left.Value) -cne [string]$right.Value) {
                throw 'Monitor CSV value mismatch'
            }
        }
    }
}
function Assert-WtMonitorContentContract {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$RunDirectory,
          [Parameter(Mandatory=$true)][object]$Manifest)
    # Legacy schema-v1 quality metadata can be absent. The field assessor
    # already maps such reports to REVIEW, never PASS.
    $s=$Manifest.MonitorSampling
    if ($null -eq $s) { return $true }
    foreach ($name in @('RejectedGrowthGroups','SingletonGroups',
                        'InvalidSingletonGroups','UnkeyedSamples')) {
        if ($null -eq $s.PSObject.Properties[$name]) { return $true }
    }
    if ($null -eq $Manifest.PSObject.Properties['SkippedUnreliableIdentitySamples']) {
        return $true
    }
    # Windows PowerShell 5.1 may wrap a parsed JSON array one level deeper.
    $rows=@(foreach ($batch in @(ConvertFrom-Json -InputObject (Get-Content -LiteralPath (Join-Path $RunDirectory 'processes.json') -Raw -Encoding UTF8))) {
        foreach ($entry in @($batch)) { if ($null -ne $entry) { $entry } }
    })
    foreach ($row in $rows) {
        if ($null -eq $row) { continue }
        foreach ($field in @('SampleTimeUtc','StartedUtc')) {
            $property=$row.PSObject.Properties[$field]
            if ($null -ne $property -and
                ($property.Value -is [datetime] -or $property.Value -is [datetimeoffset])) {
                $property.Value=Get-WtMonitorMirrorText $property.Value
            }
        }
    }
    # ADR-049: require every retained sample to fall in the declared UTC
    # run window. Inconsistency fails closed, without asserting authenticity.
    $runStart=Get-WtMonitorUtcTicks $Manifest.StartedUtc
    $runEnd=Get-WtMonitorUtcTicks $Manifest.CompletedUtc
    if ($runEnd -lt $runStart) { throw 'Monitor run UTC window invalid' }
    foreach ($row in $rows) {
        $capture=Get-WtMonitorUtcTicks $row.SampleTimeUtc
        if ($capture -lt $runStart -or $capture -gt $runEnd) {
            throw 'Monitor sample outside run UTC window'
        }
    }
    $sampleColumns=@('SampleTimeUtc','InstanceKey','IdentityReliable','Name','Pid','StartedUtc','WorkingSetMiB','PrivateMiB','CpuSeconds','Handles')
    Assert-WtMonitorCsvMirror $RunDirectory 'memory-samples.csv' $rows $sampleColumns

    # The process collector assigns one shared UTC timestamp to each batch.
    # Empty batches cannot be recovered; nonempty batch count can be checked.
    $timestamps=@{}
    foreach ($row in $rows) {
        if ($null -eq $row -or
            $null -eq $row.PSObject.Properties['SampleTimeUtc'] -or
            [string]$row.SampleTimeUtc -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z$') {
            throw 'Monitor sample timestamp invalid'
        }
        $timestamps[[string]$row.SampleTimeUtc]=$true
    }
    if ($timestamps.Count -ne [long]$s.NonEmptyAttempts) {
        throw 'Monitor nonempty attempt count mismatch'
    }

    # ADR-048: ledger binds each nonempty attempt to consecutive sample rows.
    # Empty attempts are assertions by the collector, not independently proven.
    $ledgerProperty=$s.PSObject.Properties['AttemptSampleCounts']
    if ($null -ne $ledgerProperty) {
        $ledger=$ledgerProperty.Value
        if ($ledger -isnot [array] -or $ledger.Count -ne [long]$s.AttemptedAttempts) {
            throw 'Monitor attempt ledger shape mismatch'
        }
        $offset=0
        $nonempty=0
        $previousStamp=$null
        foreach ($count in $ledger) {
            if (($count -isnot [int] -and $count -isnot [long]) -or
                $count -lt 0 -or $count -gt 1000000) {
                throw 'Monitor attempt ledger value invalid'
            }
            if ($count -eq 0) { continue }
            if ($count -gt ($rows.Count - $offset)) {
                throw 'Monitor attempt ledger row count mismatch'
            }
            $stamp=[string]$rows[$offset].SampleTimeUtc
            if ($null -ne $previousStamp -and $stamp -cle $previousStamp) {
                throw 'Monitor attempt ledger time order mismatch'
            }
            for ($j=0; $j -lt $count; $j++) {
                if ([string]$rows[$offset+$j].SampleTimeUtc -cne $stamp) {
                    throw 'Monitor attempt ledger batch mismatch'
                }
            }
            $offset += [int]$count
            $nonempty++
            $previousStamp=$stamp
        }
        if ($offset -ne $rows.Count -or $nonempty -ne [long]$s.NonEmptyAttempts) {
            throw 'Monitor attempt ledger totals mismatch'
        }
    }

    $quality=@{}
    $growth=@(Get-WtProcessGrowth -Samples $rows -QualityInfo $quality)
    $expected=@{
        ComparableProcesses=$growth.Count
        RejectedGrowthGroups=$quality['RejectedGrowthGroups']
        SingletonGroups=$quality['SingletonGroups']
        InvalidSingletonGroups=$quality['InvalidSingletonGroups']
        UnkeyedSamples=$quality['UnkeyedSamples']
    }
    foreach ($name in $expected.Keys) {
        if ([long]$s.PSObject.Properties[$name].Value -ne [long]$expected[$name]) {
            throw 'Monitor quality/source count mismatch'
        }
    }
    if ([long]$Manifest.SkippedUnreliableIdentitySamples -ne
        @($rows | Where-Object { -not $_.IdentityReliable }).Count) {
        throw 'Monitor unreliable identity count mismatch'
    }
    $growthColumns=@('Name','Pid','Samples','FirstUtc','LastUtc','FirstPrivateMiB','LastPrivateMiB','PrivateGrowthMiB','FirstWorkingSetMiB','LastWorkingSetMiB','WorkingSetGrowthMiB')
    Assert-WtMonitorCsvMirror $RunDirectory 'memory-growth.csv' $growth $growthColumns
    $top=@($Manifest.MemoryGrowthTop)
    if ($null -eq $Manifest.PSObject.Properties['MemoryGrowthTop'] -or
        $top.Count -gt $growth.Count) { throw 'Monitor top growth mismatch' }
    for ($i=0; $i -lt $top.Count; $i++) {
        foreach ($name in $growthColumns) {
            $value=$top[$i].PSObject.Properties[$name]
            if ($null -eq $value -or
                (Get-WtMonitorMirrorText $value.Value) -cne (Get-WtMonitorMirrorText $growth[$i].PSObject.Properties[$name].Value)) {
                throw 'Monitor top growth mismatch'
            }
        }
    }
    return $true
}
Export-ModuleMember -Function Assert-WtMonitorContentContract
