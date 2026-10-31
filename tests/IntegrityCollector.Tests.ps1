#requires -Version 5.1
# Fictional providers only: no SFC, DISM, Defender or ClamAV launched.
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'src\WinTriage.IntegrityCollector.psm1') -Force
function Assert-I {
    param($Actual,$Expected,[string]$Label)
    if ($Actual -ne $Expected) { throw ("{0}: expected [{1}], got [{2}]" -f $Label,$Expected,$Actual) }
}
# Synthetic writers are memory-only; no real SFC or DISM is ever run.
$fakeLogFactory={ param([string]$name) New-Object System.IO.StringWriter }
function New-Sink { New-Object 'System.Collections.Generic.List[string]' }
$temp=Join-Path ([System.IO.Path]::GetTempPath()) ('wt-integrity-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp -Force | Out-Null
try {
    $w=New-Sink; $files=New-Sink
    $passive=Get-WtIntegrity -Warnings $w -RecordedFiles $files -AdministratorProvider { $false } -CommandResolver { throw 'must not resolve' } -NativeRunner { throw 'must never execute' }
    Assert-I $passive.Administrator $false 'passive admin'
    Assert-I $passive.SfcVerifyOnly 'not-requested' 'SFC passive'
    Assert-I $passive.DismScanHealth 'not-requested' 'DISM passive'
    Assert-I $w.Count 0 'passive warnings'
    Assert-I $files.Count 0 'passive files'
    Assert-I (Test-WtAdministrator -AdministratorProvider { $true }) $true 'admin injection'

    $w=New-Sink; $files=New-Sink
    $opts=@{ Warnings=$w; RecordedFiles=$files; RunSfcVerifyOnly=$true; RunDismScanHealth=$true; OutputDirectory=$temp;LogWriterFactory=$fakeLogFactory; AdministratorProvider={ $false }; CommandResolver={ throw 'must not resolve without admin' }; NativeRunner={ throw 'must not execute' } }
    $limited=Get-WtIntegrity @opts
    Assert-I $limited.SfcVerifyOnly 'skipped-requires-admin' 'no admin SFC'
    Assert-I $limited.DismScanHealth 'skipped-requires-admin' 'no admin DISM'
    Assert-I $w.Count 2 'privilege warning count'
    Assert-I $files.Count 0 'no privileged files'

    $w=New-Sink; $files=New-Sink
    $opts=@{Warnings=$w;RecordedFiles=$files;RunSfcVerifyOnly=$true;OutputDirectory=$temp;LogWriterFactory=$fakeLogFactory;AdministratorProvider={ throw 'synthetic administrator lookup failure' };CommandResolver={ throw 'never resolve if privileges unknown' };NativeRunner={ throw 'never execute' }}
    $failedAdmin=Get-WtIntegrity @opts
    Assert-I $failedAdmin.Administrator $false 'admin lookup exception fails closed'
    Assert-I $failedAdmin.SfcVerifyOnly 'skipped-requires-admin' 'admin lookup prevents scan'
    Assert-I $w.Count 2 'admin failure and skipped warnings'

    $w=New-Sink; $files=New-Sink
    $opts=@{Warnings=$w;RecordedFiles=$files;RunDismScanHealth=$true;OutputDirectory=$temp;LogWriterFactory=$fakeLogFactory;AdministratorProvider={ $true };CommandResolver={ param($name) return $null };NativeRunner={ throw 'unavailable executable never starts' }}
    $missing=Get-WtIntegrity @opts
    Assert-I $missing.DismScanHealth 'unavailable' 'not installed'
    Assert-I $missing.SfcVerifyOnly 'not-requested' 'unrequested independent'
    Assert-I $files.Count 0 'unavailable file not recorded'

    $seen=New-Sink
    $mock={
        param($source,$arguments,$path)
        [void]$seen.Add(("{0}:{1}" -f $source,($arguments -join ' ')))
        $path.WriteLine('FICTIONAL-RESULT')
        if ($source -eq 'SYNTHETIC-dism.exe') { return [pscustomobject]@{ExitCode=5} }
        [pscustomobject]@{ExitCode=0}
    }.GetNewClosure()
    $w=New-Sink; $files=New-Sink
    $opts=@{Warnings=$w;RecordedFiles=$files;RunSfcVerifyOnly=$true;RunDismScanHealth=$true;OutputDirectory=$temp;LogWriterFactory=$fakeLogFactory;AdministratorProvider={ $true };CommandResolver={ param($name) [pscustomobject]@{Source=('SYNTHETIC-'+$name)} };NativeRunner=$mock}
    $success=Get-WtIntegrity @opts
    Assert-I $success.SfcVerifyOnly 'completed-review-output' 'SFC completion requires log review'
    Assert-I $success.DismScanHealth 'failed-exit-5' 'DISM nonzero'
    Assert-I $success.SfcVerifyOnlyExitCode 0 'SFC exit'
    Assert-I $success.DismScanHealthExitCode 5 'DISM exit'
    Assert-I $seen[0] 'SYNTHETIC-sfc.exe:/verifyonly' 'SFC fixed args'
    Assert-I $seen[1] 'SYNTHETIC-dism.exe:/Online /Cleanup-Image /ScanHealth' 'DISM fixed args'
    Assert-I $files.Count 2 'native logs indexed'
    Assert-I $w.Count 1 'unexpected native exit warns'

    $w=New-Sink; $files=New-Sink
    $opts=@{
        Warnings=$w;RecordedFiles=$files;RunSfcVerifyOnly=$true;RunDismScanHealth=$true;OutputDirectory=$temp;LogWriterFactory=$fakeLogFactory
        AdministratorProvider={ $true }
        CommandResolver={param($name) [pscustomobject]@{Source=('SYNTHETIC-'+$name)}}
        NativeRunner={
            param($source,$arguments,$path)
            if ($source -eq 'SYNTHETIC-sfc.exe') { throw 'synthetic native exception' }
            $path.WriteLine('FICTIONAL-PARTIAL')
            [pscustomobject]@{ExitCode=$null}
        }
    }
    $partial=Get-WtIntegrity @opts
    Assert-I $partial.SfcVerifyOnly 'execution-error' 'SFC exception isolated'
    Assert-I $partial.DismScanHealth 'indeterminate' 'missing exit code'
    Assert-I $w.Count 2 'independent failure warnings'

    $unexpectedNative=New-Sink
    $neverRun={ [void]$unexpectedNative.Add('sfc'); [pscustomobject]@{ExitCode=0} }.GetNewClosure()
    $fresh=Join-Path $temp 'missing-output'
    New-Item -ItemType Directory -Path $fresh -Force | Out-Null
    $w=New-Sink; $files=New-Sink
    $opts=@{Warnings=$w;RecordedFiles=$files;RunSfcVerifyOnly=$true;OutputDirectory=$fresh;LogWriterFactory={ throw 'SYNTHETIC writer unavailable' };AdministratorProvider={ $true };CommandResolver={ [pscustomobject]@{Source='SYNTHETIC'} };NativeRunner=$neverRun}
    $noLog=Get-WtIntegrity @opts
    Assert-I $noLog.SfcVerifyOnly 'execution-error' 'missing secure writer prevents execution'
    Assert-I $unexpectedNative.Count 0 'unsafe output must never launch SFC'
    Assert-I $files.Count 0 'missing log not indexed'

    $w=New-Sink; $files=New-Sink; $threw=$false
    try { $null=Get-WtIntegrity -Warnings $w -RecordedFiles $files -RunSfcVerifyOnly -AdministratorProvider { $true } -CommandResolver { throw 'must not resolve' } } catch { $threw=$true }
    Assert-I $threw $true 'explicit output directory required'
    Write-Host 'PASS synthetic passive integrity, admin gate, fixed safe args, native failure isolation'
} finally {
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
}
