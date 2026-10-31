#requires -Version 5.1
<#
.SYNOPSIS
    Passive Windows integrity status and opt-in verification-only executor.
.DESCRIPTION
    No SFC/DISM executable is launched unless a matching explicit request is true.
    Test providers and native runner are injectable for deterministic tests.
    Only fixed /verifyonly and /Online /Cleanup-Image /ScanHealth are allowed.
#>
function Test-WtAdministrator {
    [CmdletBinding()]
    param(
        [scriptblock]$AdministratorProvider = {
            $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
            $principal=New-Object -TypeName System.Security.Principal.WindowsPrincipal -ArgumentList $identity
            $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        },
        [AllowNull()][System.Collections.Generic.List[string]]$Warnings=$null
    )
    try { return [bool](& $AdministratorProvider) }
    catch {
        if ($null -ne $Warnings) {
            [void]$Warnings.Add('Unable to determine administrator status; verification was not permitted.')
        }
        return $false
    }
}

function Get-WtIntegrity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$Warnings,
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$RecordedFiles,
        [switch]$RunSfcVerifyOnly,
        [switch]$RunDismScanHealth,
        [string]$OutputDirectory='',
        [scriptblock]$AdministratorProvider = {
            $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
            $principal=New-Object -TypeName System.Security.Principal.WindowsPrincipal -ArgumentList $identity
            $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        },
        [scriptblock]$CommandResolver = {
            param([string]$Executable)
            Get-Command -Name $Executable -CommandType Application -ErrorAction SilentlyContinue
        },
        [scriptblock]$NativeRunner = {
            param([string]$Source,[string[]]$NativeArguments,[string]$LogPath)
            & $Source @NativeArguments 2>&1 | Out-File -LiteralPath $LogPath -Encoding utf8
            [pscustomobject]@{ ExitCode=$LASTEXITCODE }
        }
    )
    if (($RunSfcVerifyOnly -or $RunDismScanHealth) -and
        [string]::IsNullOrWhiteSpace($OutputDirectory)) {
        throw 'An explicit local OutputDirectory is required for native verification.'
    }
    # Evaluate the current privilege status rather than writing a function name.
    $status=[ordered]@{
        Administrator=(Test-WtAdministrator -AdministratorProvider $AdministratorProvider -Warnings $Warnings)
        SfcVerifyOnly='not-requested'
        DismScanHealth='not-requested'
        Notes=@(
            'No repair option is used: /verifyonly and /ScanHealth only.'
            'Native scan exit code alone is not proof that Windows is fully healthy.'
            'Windows may create its own maintenance/diagnostic logs.'
        )
    }
    $requested=@(
        [pscustomobject]@{Flag=[bool]$RunSfcVerifyOnly;Key='SfcVerifyOnly';Executable='sfc.exe';Arguments=@('/verifyonly');Filename='sfc-verifyonly.txt'}
        [pscustomobject]@{Flag=[bool]$RunDismScanHealth;Key='DismScanHealth';Executable='dism.exe';Arguments=@('/Online','/Cleanup-Image','/ScanHealth');Filename='dism-scanhealth.txt'}
    )
    foreach ($item in $requested) {
        if (-not $item.Flag) { continue }
        if (-not $status.Administrator) {
            $status[$item.Key]='skipped-requires-admin'
            [void]$Warnings.Add("Verification not started ($($item.Executable)): elevated PowerShell required.")
            continue
        }
        $cmd=$null
        try { $cmd=& $CommandResolver $item.Executable }
        catch { [void]$Warnings.Add("Executable resolution failed ($($item.Executable)): $($_.Exception.Message)") }
        if (-not $cmd -or [string]::IsNullOrWhiteSpace([string]$cmd.Source)) {
            $status[$item.Key]='unavailable'
            [void]$Warnings.Add("Verification executable unavailable: $($item.Executable)")
            continue
        }
        $outputPath=Join-Path $OutputDirectory $item.Filename
        try {
            # No string evaluation or caller-controlled argument arrays: verify-only.
            $nativeResult=& $NativeRunner ([string]$cmd.Source) ([string[]]$item.Arguments) $outputPath
            $code=$null
            if ($null -ne $nativeResult) { $code=$nativeResult.ExitCode }
            $logExists=Test-Path -LiteralPath $outputPath -PathType Leaf
            if ($logExists) {
                $status["$($item.Key)Log"]=$item.Filename
                [void]$RecordedFiles.Add($item.Filename)
            }
            if ($null -eq $code -or -not $logExists) {
                $status[$item.Key]='indeterminate'
            } elseif ([int]$code -eq 0) {
                $status[$item.Key]='completed-review-output'
            } else {
                $status[$item.Key]="failed-exit-$code"
            }
            $status["$($item.Key)ExitCode"]=$code
            if ($status[$item.Key] -ne 'completed-review-output') {
                [void]$Warnings.Add("Verification outcome requires review ($($item.Key)): $($status[$item.Key]).")
            }
        } catch {
            $status[$item.Key]='execution-error'
            if (Test-Path -LiteralPath $outputPath -PathType Leaf) {
                $status["$($item.Key)Log"]=$item.Filename
                [void]$RecordedFiles.Add($item.Filename)
            }
            [void]$Warnings.Add("Verification execution failed ($($item.Key)): $($_.Exception.Message)")
        }
    }
    return [pscustomobject]$status
}
Export-ModuleMember -Function Test-WtAdministrator,Get-WtIntegrity
