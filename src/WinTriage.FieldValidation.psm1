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
