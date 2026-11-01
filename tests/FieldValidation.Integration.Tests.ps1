#requires -Version 5.1
# Runs only the bounded passive manual validation harness in a test-owned folder.
# Never invokes native security/integrity scanners or modifies real user reports.
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows-only passive integration' }
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'tests\ReportContract.psm1') -Force
Import-Module (Join-Path $root 'src\WinTriage.ReportSecurity.psm1') -Force
$parent=Join-Path ([System.IO.Path]::GetTempPath()) ('wt-field-e2e-' + [guid]::NewGuid().ToString('N'))
$folder=Join-Path $parent 'validation'
try {
    # The real field-runner command line has no native scanner flags.
    $lines=@(& (Join-Path $root 'Invoke-WtFieldValidation.ps1') -OutputDir $folder)
    if ($lines.Count -ne 9) { throw 'Unexpected number of field validation status lines' }
    if ([string]$lines[0] -cnotmatch '^Environment: Windows build=[0-9]+; PowerShell=[0-9]+\.[0-9]+; privilege=(elevated|standard-or-unknown)$') {
        throw 'Environment output includes an unexpected field'
    }
    if ($lines[1] -ne 'Classification checks local structure and access permissions only; report origin is NOT authenticated and this is NOT a system-health verdict.') { throw 'Missing health disclaimer' }
    if ($lines[2] -ne 'Full reports remain local and are never uploaded or deleted by this script.') { throw 'Missing retention disclaimer' }
    $modes=@('Quick','Events','Hardware','Monitor','Integrity')
    for ($i=0; $i -lt $modes.Count; $i++) {
        $status=[string]$lines[$i+3]
        $pattern='^Mode='+[regex]::Escape($modes[$i])+'; Validation=(pass|review); Contract=pass; PrivateAcl=pass; PassiveNativeScans=(not-requested|not-applicable); Warnings=(present|none)$'
        if ($status -cnotmatch $pattern) {
            throw ('Invalid/redaction-unsafe field status for mode {0}' -f $modes[$i])
        }
    }
    if ($lines[8] -ne 'Completed: statuses are structural-only, not proof of real-hardware compatibility; release remains NO-GO.') {
        throw 'Missing final validation disclaimer'
    }
    $runs=@(Get-ChildItem -LiteralPath $folder -Directory -ErrorAction Stop)
    if ($runs.Count -ne 5) { throw 'Expected exactly 5 restricted local reports' }
    $found=@()
    foreach ($run in $runs) {
        [void](Assert-WtPrivateDirectoryAcl -Directory $run.FullName)
        [void](Assert-WtReportContract -RunDirectory $run.FullName)
        $manifest=Get-Content -LiteralPath (Join-Path $run.FullName 'manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($manifest.Mode -notin $modes) { throw 'Unexpected report mode' }
        if ($manifest.Mode -eq 'Monitor') {
            if ($null -eq $manifest.MonitorSampling) { throw 'New Monitor report lacks aggregate sampling completeness' }
            if ($manifest.MonitorSampling.RequestedAttempts -ne 2 -or
                $manifest.MonitorSampling.AttemptedAttempts -ne 2 -or
                $manifest.MonitorSampling.NonEmptyAttempts -gt 2 -or
                $manifest.MonitorSampling.AttemptSampleCounts -isnot [array] -or
                $manifest.MonitorSampling.AttemptSampleCounts.Count -ne 2 -or
                $manifest.MonitorSampling.ComparableProcesses -lt 0 -or
                $null -eq $manifest.MonitorSampling.RejectedGrowthGroups -or
                $manifest.MonitorSampling.RejectedGrowthGroups -lt 0 -or
                $null -eq $manifest.MonitorSampling.SingletonGroups -or
                $manifest.MonitorSampling.SingletonGroups -lt 0 -or
                $null -eq $manifest.MonitorSampling.InvalidSingletonGroups -or
                $manifest.MonitorSampling.InvalidSingletonGroups -lt 0 -or
                $null -eq $manifest.MonitorSampling.UnkeyedSamples -or
                $manifest.MonitorSampling.UnkeyedSamples -lt 0 -or
                $null -eq $manifest.SkippedUnreliableIdentitySamples -or
                $manifest.SkippedUnreliableIdentitySamples -lt 0) {
                throw 'New Monitor report contains invalid attempted sampling aggregates'
            }
        }
        if ($found -contains $manifest.Mode) { throw 'Duplicate mode report' }
        $found+= [string]$manifest.Mode
        foreach ($nativeFile in @('sfc-verifyonly.txt','dism-scanhealth.txt','clamav-output.txt')) {
            if (Test-Path -LiteralPath (Join-Path $run.FullName $nativeFile)) {
                throw 'Native scanner unexpectedly ran in passive field validation'
            }
        }
    }
    if ($found.Count -ne 5) { throw 'Missing passive report mode' }
    Write-Host 'PASS: real field runner on hosted Windows produced only allowlisted console labels, five private reports, schema v1 and no native scans'
} finally {
    # Only remove the temporary directory owned by THIS test (not user reports).
    if (Test-Path -LiteralPath $parent) { Remove-Item -LiteralPath $parent -Recurse -Force }
}
