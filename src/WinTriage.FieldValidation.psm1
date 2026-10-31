#requires -Version 5.1
<#
.SYNOPSIS
    Pure privacy-minimized classification of passive field-validation runs.
.DESCRIPTION
    Caller must check the local report contract and private DACL separately.
    Never includes free-form messages, paths, users, hosts, identifiers or raw
    event/security/drive content in its returned object.
    A PASS means structural validation only, NOT a healthy computer.
#>
function Get-WtFieldValidationAssessment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('Quick','Events','Monitor','Hardware','Integrity')]
        [string]$Mode,
        [Parameter(Mandatory=$true)][bool]$ContractPassed,
        [Parameter(Mandatory=$true)][bool]$AclPassed,
        [AllowNull()][object]$Manifest=$null,
        [AllowNull()][object]$Security=$null,
        [AllowNull()][object]$Hardware=$null,
        [AllowNull()][object]$Integrity=$null
    )
    $validation='pass'
    $evidence='review-not-health-proof'
    $native='not-applicable'
    $warningStatus='unknown'
    if (-not $ContractPassed -or -not $AclPassed -or $null -eq $Manifest) {
        $validation='fail'
    } else {
        if ($Manifest.Mode -ne $Mode) { $validation='fail' }
        if ($null -eq $Manifest.Warnings) {
            $warningStatus='unknown'
            $validation='fail'
        } elseif (@($Manifest.Warnings).Count -gt 0) {
            $warningStatus='present'
            if ($validation -ne 'fail') { $validation='review' }
        } else {
            $warningStatus='none'
        }
        if ($Mode -eq 'Monitor') {
            $samplingProperty=$Manifest.PSObject.Properties['MonitorSampling']
            if ($null -eq $samplingProperty -or $null -eq $samplingProperty.Value) {
                # Older schema-v1 reports lack per-attempt telemetry: never say pass.
                if ($validation -ne 'fail') { $validation='review' }
            } else {
                $s=$samplingProperty.Value
                $valid=$true
                foreach ($name in @('RequestedAttempts','AttemptedAttempts','NonEmptyAttempts','ComparableProcesses')) {
                    $property=$s.PSObject.Properties[$name]
                    if ($null -eq $property -or
                        ($property.Value -isnot [int] -and $property.Value -isnot [long])) {
                        $valid=$false
                    }
                }
                if ($valid) {
                    $requested=[long]$s.RequestedAttempts
                    $attempted=[long]$s.AttemptedAttempts
                    $nonempty=[long]$s.NonEmptyAttempts
                    $comparable=[long]$s.ComparableProcesses
                    if ($requested -lt 2 -or $requested -gt 300 -or
                        $attempted -lt 0 -or $attempted -gt $requested -or
                        $nonempty -lt 0 -or $nonempty -gt $attempted -or
                        $comparable -lt 0 -or
                        ($nonempty -lt 2 -and $comparable -ne 0)) {
                        $valid=$false
                    }
                }
                # A valid growth group does not excuse another rejected group
                # or an unreadable process identity. Older v1 reports without
                # these quality fields stay readable but cannot claim pass.
                $rejectedProperty=$s.PSObject.Properties['RejectedGrowthGroups']
                $singletonProperty=$s.PSObject.Properties['SingletonGroups']
                $invalidSingletonProperty=$s.PSObject.Properties['InvalidSingletonGroups']
                $unkeyedProperty=$s.PSObject.Properties['UnkeyedSamples']
                $unreliableProperty=$Manifest.PSObject.Properties['SkippedUnreliableIdentitySamples']
                $qualityKnown=($null -ne $rejectedProperty -and $null -ne $unreliableProperty -and
                    $null -ne $singletonProperty -and $null -ne $invalidSingletonProperty -and
                    $null -ne $unkeyedProperty)
                if ($qualityKnown) {
                    if (($rejectedProperty.Value -isnot [int] -and $rejectedProperty.Value -isnot [long]) -or
                        ($unreliableProperty.Value -isnot [int] -and $unreliableProperty.Value -isnot [long]) -or
                        ($singletonProperty.Value -isnot [int] -and $singletonProperty.Value -isnot [long]) -or
                        ($invalidSingletonProperty.Value -isnot [int] -and $invalidSingletonProperty.Value -isnot [long]) -or
                        ($unkeyedProperty.Value -isnot [int] -and $unkeyedProperty.Value -isnot [long])) {
                        $valid=$false
                    } else {
                        $rejected=[long]$rejectedProperty.Value
                        $unreliable=[long]$unreliableProperty.Value
                        $singletons=[long]$singletonProperty.Value
                        $invalidSingletons=[long]$invalidSingletonProperty.Value
                        $unkeyed=[long]$unkeyedProperty.Value
                        if ($rejected -lt 0 -or $unreliable -lt 0 -or
                            $singletons -lt 0 -or $invalidSingletons -lt 0 -or $unkeyed -lt 0 -or
                            $rejected -gt 1000000 -or $unreliable -gt 1000000 -or
                            $singletons -gt 1000000 -or $invalidSingletons -gt 1000000 -or
                            $unkeyed -gt 1000000) { $valid=$false }
                    }
                }
                if (-not $valid) {
                    $validation='fail'
                } elseif (-not $qualityKnown) {
                    if ($validation -ne 'fail') { $validation='review' }
                } elseif ($attempted -ne $requested -or $nonempty -ne $requested -or
                    $comparable -eq 0 -or $rejected -gt 0 -or $unreliable -gt 0 -or
                    $invalidSingletons -gt 0 -or $unkeyed -gt 0) {
                    # A partial set is inconclusive, even if another group grew.
                    if ($validation -ne 'fail') { $validation='review' }
                }
            }
        }
        if ($Mode -in @('Quick','Events')) {
            if ($null -eq $Manifest.EventSampling -or
                @($Manifest.EventSampling.PSObject.Properties).Count -eq 0) {
                if ($validation -ne 'fail') { $validation='review' }
            } else {
                foreach ($item in $Manifest.EventSampling.PSObject.Properties) {
                    $s=$item.Value
                    if ($null -eq $s -or [bool]$s.Incomplete -or
                        [bool]$s.AnyQueryReachedLimit -or
                        [int]$s.QueryFailures -gt 0 -or
                        [int]$s.ProjectionFailures -gt 0) {
                        if ($validation -ne 'fail') { $validation='review' }
                    }
                }
            }
        }
        if ($Mode -in @('Quick','Hardware')) {
            if ($null -eq $Hardware -or $null -eq $Hardware.StorageAssessments -or
                @($Hardware.StorageAssessments).Count -eq 0) {
                if ($validation -ne 'fail') { $validation='review' }
            } else {
                # Neither "attention" nor "inconclusive" licenses a healthy-system claim.
                if ($validation -ne 'fail') { $validation='review' }
            }
        }
        if ($Mode -eq 'Quick') {
            $native='not-requested'
            if ($null -eq $Security -or
                $Security.RequestedScan -ne 'none' -or
                $Security.DefenderScanResult -ne 'not-requested' -or
                $Security.ClamAVResult -ne 'not-requested') {
                $native='unexpected'
                $validation='fail'
            }
        }
        if ($Mode -eq 'Integrity') {
            $native='not-requested'
            if ($null -eq $Integrity -or
                $Integrity.SfcVerifyOnly -ne 'not-requested' -or
                $Integrity.DismScanHealth -ne 'not-requested') {
                $native='unexpected'
                $validation='fail'
            }
        }
        if ($Manifest.Scan -and $Mode -eq 'Quick') {
            if (($Manifest.Scan.Defender -and $Manifest.Scan.Defender -ne 'not-requested') -or
                ($Manifest.Scan.ClamAV -and $Manifest.Scan.ClamAV -ne 'not-requested')) {
                $native='unexpected'
                $validation='fail'
            }
        }
    }
    # All values are fixed enumerations; do not pass through data from reports.
    [pscustomobject][ordered]@{
        Mode=$Mode
        Validation=$validation
        Contract=if ($ContractPassed) { 'pass' } else { 'fail' }
        PrivateAcl=if ($AclPassed) { 'pass' } else { 'fail' }
        PassiveNativeScans=$native
        Warnings=$warningStatus
        Interpretation=$evidence
    }
}
Export-ModuleMember -Function Get-WtFieldValidationAssessment
