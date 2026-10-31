#requires -Version 5.1
# ADR-042: all samples invented; no live process querying, scanners or user reports.
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repo 'src\WinTriage.ProcessCollector.psm1') -Force
Import-Module (Join-Path $repo 'src\WinTriage.Core.psm1') -Force
Import-Module (Join-Path $repo 'src\WinTriage.FieldValidation.psm1') -Force
function Assert-Monitor { param([bool]$Condition,[string]$Label)
    if (-not $Condition) { throw ('Synthetic Monitor assertion failed: ' + $Label) }
}
$fakeProvider={
    [pscustomobject]@{
        Id=4242;StartTime=[datetime]'2026-01-01T00:00:00Z'
        ProcessName='SYNTHETIC_MONITOR';CPU=0;WorkingSet64=104857600
        PrivateMemorySize64=104857600;HandleCount=1
    }
}
$t1=[datetime]'2026-01-01T02:00:00Z'
$t2=$t1.AddSeconds(1)
$baselineWarnings=New-Object 'System.Collections.Generic.List[string]'
$baselineFirst=@(Get-WtProcesses -Warnings $baselineWarnings -ProcessProvider $fakeProvider -SampleTime $t1)
$baselineSecond=@(Get-WtProcesses -Warnings $baselineWarnings -ProcessProvider $fakeProvider -SampleTime $t2)
$baselineRows=@($baselineFirst)+@($baselineSecond)
$baselineGrowth=@(Get-WtProcessGrowth -Samples $baselineRows)
Assert-Monitor ($baselineWarnings.Count -eq 0) 'invented successful provider has no warning'
Assert-Monitor ($baselineGrowth.Count -eq 1) 'two invented samples produce a growth row'
Assert-Monitor ($baselineGrowth[0].Samples -eq 2) 'two time samples retained'
$baselineManifest=[pscustomobject]@{
    Mode='Monitor';Warnings=@();SkippedUnreliableIdentitySamples=0
    MonitorSampling=[pscustomobject]@{
        RequestedAttempts=2;AttemptedAttempts=2;NonEmptyAttempts=2;ComparableProcesses=1;RejectedGrowthGroups=0
    }
}
$baseline=Get-WtFieldValidationAssessment -Mode Monitor -ContractPassed:$true -AclPassed:$true -Manifest $baselineManifest
Assert-Monitor ($baseline.Validation -eq 'pass') 'baseline only validates synthetic structure'
$warnings=New-Object 'System.Collections.Generic.List[string]'
$first=@(Get-WtProcesses -Warnings $warnings -ProcessProvider $fakeProvider -SampleTime $t1)
$missing=@(Get-WtProcesses -Warnings $warnings -ProcessProvider {
    throw 'SYNTHETIC_MONITOR_PRIVATE_CANARY'
} -SampleTime $t2)
$partialRows=@($first)+@($missing)
$partialGrowth=@(Get-WtProcessGrowth -Samples $partialRows)
Assert-Monitor ($first.Count -eq 1) 'first invented sample exists'
Assert-Monitor ($missing.Count -eq 0) 'second provider refusal yields no fabricated row'
Assert-Monitor ($warnings.Count -eq 1) 'second-sample denial records warning'
Assert-Monitor ($partialGrowth.Count -eq 0) 'single sample never proves memory growth'
$failedManifest=[pscustomobject]@{
    Mode='Monitor';Warnings=@($warnings.ToArray());SkippedUnreliableIdentitySamples=0
    MonitorSampling=[pscustomobject]@{
        RequestedAttempts=2;AttemptedAttempts=2;NonEmptyAttempts=1;ComparableProcesses=0;RejectedGrowthGroups=0
    }
}
$failedAssessment=Get-WtFieldValidationAssessment -Mode Monitor -ContractPassed:$true -AclPassed:$true -Manifest $failedManifest
Assert-Monitor ($failedAssessment.Validation -eq 'review') 'synthetic Monitor provider failure requires review'
Assert-Monitor ($failedAssessment.Warnings -eq 'present') 'warning becomes fixed presence label'
Assert-Monitor ($failedAssessment.Interpretation -eq 'review-not-health-proof') 'not a health verdict'
$serialized=ConvertTo-Json -InputObject $failedAssessment -Depth 4
Assert-Monitor (-not $serialized.Contains('SYNTHETIC_MONITOR_PRIVATE_CANARY')) 'warning cannot escape allowlist'
$emptyWarnings=New-Object 'System.Collections.Generic.List[string]'
$empty=@(Get-WtProcesses -Warnings $emptyWarnings -ProcessProvider {
    throw 'SYNTHETIC_MONITOR_PRIVATE_CANARY'
} -SampleTime $t1)
Assert-Monitor ($empty.Count -eq 0) 'entirely denied sample creates no record'
Assert-Monitor ($emptyWarnings.Count -eq 1) 'entirely denied provider emits warning'
# Silent empty provider success is not a valid complete sample despite zero warnings.
$quietWarnings=New-Object 'System.Collections.Generic.List[string]'
$quiet=@(Get-WtProcesses -Warnings $quietWarnings -ProcessProvider { @() } -SampleTime $t2)
Assert-Monitor ($quiet.Count -eq 0 -and $quietWarnings.Count -eq 0) 'invented empty provider returns quietly'
$quietManifest=[pscustomobject]@{
    Mode='Monitor';Warnings=@();SkippedUnreliableIdentitySamples=0
    MonitorSampling=[pscustomobject]@{
        RequestedAttempts=2;AttemptedAttempts=2;NonEmptyAttempts=1;ComparableProcesses=0;RejectedGrowthGroups=0
    }
}
$quietAssessment=Get-WtFieldValidationAssessment -Mode Monitor -ContractPassed:$true -AclPassed:$true -Manifest $quietManifest
Assert-Monitor ($quietAssessment.Validation -eq 'review') 'silent empty second sample must require review'
Assert-Monitor ($quietAssessment.Warnings -eq 'none') 'silent emptiness does not fabricate warning'
$quietManifest.MonitorSampling.AttemptedAttempts=1
$short=Get-WtFieldValidationAssessment -Mode Monitor -ContractPassed:$true -AclPassed:$true -Manifest $quietManifest
Assert-Monitor ($short.Validation -eq 'review') 'attempt count less than requested must require review'
$quietManifest.MonitorSampling.AttemptedAttempts=2
$quietManifest.MonitorSampling.NonEmptyAttempts=2
$noComparable=Get-WtFieldValidationAssessment -Mode Monitor -ContractPassed:$true -AclPassed:$true -Manifest $quietManifest
Assert-Monitor ($noComparable.Validation -eq 'review') 'no comparable identity across two nonempty samples requires review'
$quietManifest.MonitorSampling.ComparableProcesses=1
$complete=Get-WtFieldValidationAssessment -Mode Monitor -ContractPassed:$true -AclPassed:$true -Manifest $quietManifest
Assert-Monitor ($complete.Validation -eq 'pass') 'complete invented comparable samples only pass structural check'
Write-Host 'PASS: invented Monitor provider failure and silent empty/short/no-comparable cases require review'
