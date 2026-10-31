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
    $rows=@(ConvertFrom-Json -InputObject (Get-Content -LiteralPath (Join-Path $RunDirectory 'processes.json') -Raw -Encoding UTF8))
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
