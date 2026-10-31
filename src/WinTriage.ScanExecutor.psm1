#requires -Version 5.1
<#
.SYNOPSIS
    Explicitly requested Defender and ClamAV scan execution (never passive).
.DESCRIPTION
    The caller owns user consent and mode validation. This module also gates
    every native invocation behind a corresponding opt-in switch. Do not call
    native scanners in unit tests: inject fake resolvers and runners instead.
    A requested Defender scan may quarantine files according to Defender policy.
#>
function Invoke-WtRequestedScans {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.Collections.Specialized.OrderedDictionary]$SecurityEvidence,
        [Parameter(Mandatory=$true)][AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$Warnings,
        [Parameter(Mandatory=$true)][AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$RecordedFiles,
        [switch]$RunDefenderQuickScan,
        [switch]$RunClamAV,
        [string]$ScanPath='',
        [string]$ClamAVExe='clamscan.exe',
        [string]$OutputDirectory='',
        [scriptblock]$DefenderCommandAvailable={
            [bool](Get-Command Start-MpScan -ErrorAction SilentlyContinue)
        },
        [scriptblock]$DefenderRunner={
            Start-MpScan -ScanType QuickScan -ErrorAction Stop
        },
        [scriptblock]$ClamAVCommandResolver={
            param([string]$Executable)
            Get-Command -Name $Executable -CommandType Application -ErrorAction SilentlyContinue
        },
        [scriptblock]$ClamAVRunner={
            param([string]$Source,[string]$ScanPath,[string]$LogPath)
            & $Source '--recursive=yes' '--infected' $ScanPath 2>&1 | Out-File -LiteralPath $LogPath -Encoding utf8
            [pscustomobject]@{ExitCode=$LASTEXITCODE}
        }
    )
    # This early return is an important non-scanning trust boundary.
    if (-not $RunDefenderQuickScan -and -not $RunClamAV) { return $SecurityEvidence }
    # Validate all opted-in scan requirements BEFORE launching either scanner.
    if ($RunClamAV) {
        if ([string]::IsNullOrWhiteSpace($ScanPath) -or
            -not (Test-Path -LiteralPath $ScanPath)) {
            throw 'An existing explicitly selected local ScanPath is required for ClamAV.'
        }
        if ([string]::IsNullOrWhiteSpace($ClamAVExe)) {
            throw 'A ClamAV executable must be specified.'
        }
        if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
            throw 'A local OutputDirectory is required for ClamAV output.'
        }
    }
    if ($RunDefenderQuickScan) {
        $SecurityEvidence['RequestedScan']='Defender QuickScan'
        $available=$false
        try { $available=[bool](& $DefenderCommandAvailable) }
        catch { [void]$Warnings.Add("Start-MpScan availability failed: $($_.Exception.Message)") }
        if (-not $available) {
            $SecurityEvidence['DefenderScanResult']='unavailable'
            [void]$Warnings.Add('Start-MpScan unavailable; the requested Defender scan was not started.')
        } else {
            try {
                [void](& $DefenderRunner)
                $SecurityEvidence['DefenderScanResult']='scan-request-submitted'
            } catch {
                $SecurityEvidence['DefenderScanResult']='failed'
                [void]$Warnings.Add("Defender QuickScan request failed: $($_.Exception.Message)")
            }
        }
    }
    if ($RunClamAV) {
        $SecurityEvidence['RequestedScan']=if ($RunDefenderQuickScan) { 'Defender QuickScan + ClamAV' } else { 'ClamAV' }
        $cmd=$null
        try { $cmd=& $ClamAVCommandResolver $ClamAVExe }
        catch { [void]$Warnings.Add("ClamAV command lookup failed: $($_.Exception.Message)") }
        if (-not $cmd -or [string]::IsNullOrWhiteSpace([string]$cmd.Source)) {
            $SecurityEvidence['ClamAVResult']='not-installed'
            [void]$Warnings.Add('ClamAV command not installed or unavailable; no scan was started.')
        } else {
            $logFile=Join-Path $OutputDirectory 'clamav-output.txt'
            try {
                $nativeResult=& $ClamAVRunner ([string]$cmd.Source) $ScanPath $logFile
                $exitCode=$null
                if ($null -ne $nativeResult) { $exitCode=$nativeResult.ExitCode }
                $logExists=Test-Path -LiteralPath $logFile -PathType Leaf
                if ($logExists) {
                    $SecurityEvidence['ClamAVOutput']='clamav-output.txt'
                    [void]$RecordedFiles.Add('clamav-output.txt')
                }
                if ($null -eq $exitCode -or -not $logExists) {
                    $SecurityEvidence['ClamAVResult']='scan-error'
                } elseif ([int]$exitCode -eq 0) {
                    $SecurityEvidence['ClamAVResult']='no-detection'
                } elseif ([int]$exitCode -eq 1) {
                    $SecurityEvidence['ClamAVResult']='detection-review-required'
                } else {
                    $SecurityEvidence['ClamAVResult']='scan-error'
                }
                $SecurityEvidence['ClamAVExitCode']=$exitCode
                if ($SecurityEvidence['ClamAVResult'] -eq 'detection-review-required') {
                    [void]$Warnings.Add('ClamAV reported a detection. Review local output; nothing was deleted.')
                } elseif ($SecurityEvidence['ClamAVResult'] -eq 'scan-error') {
                    [void]$Warnings.Add('ClamAV output or exit code is missing or indicates an error; no clean result can be inferred.')
                }
            } catch {
                $SecurityEvidence['ClamAVResult']='failed'
                if (Test-Path -LiteralPath $logFile -PathType Leaf) {
                    $SecurityEvidence['ClamAVOutput']='clamav-output.txt'
                    [void]$RecordedFiles.Add('clamav-output.txt')
                }
                [void]$Warnings.Add("ClamAV execution failed: $($_.Exception.Message)")
            }
        }
    }
    return $SecurityEvidence
}
Export-ModuleMember -Function Invoke-WtRequestedScans
