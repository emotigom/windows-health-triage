#requires -Version 5.1
# Fictional runners only: this test NEVER invokes a real antivirus scanner.
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'src\WinTriage.ScanExecutor.psm1') -Force
function Assert-Scan {
    param($Actual,$Expected,[string]$Label)
    if ($Actual -ne $Expected) { throw ("{0}: expected [{1}], got [{2}]" -f $Label,$Expected,$Actual) }
}
function New-Sink { New-Object 'System.Collections.Generic.List[string]' }
# In tests only, a memory-only fake TextWriter stands in for the handle-bound sink.
$fakeLogFactory={ param([string]$name) New-Object System.IO.StringWriter }
function New-Status {
    [ordered]@{Defender=$null;RecentDetections=@();RequestedScan='none';DefenderScanResult='not-requested';ClamAVResult='not-requested'}
}
$dir=Join-Path ([System.IO.Path]::GetTempPath()) ('wt-scans-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $dir -Force | Out-Null
try {
    $w=New-Sink; $files=New-Sink
    $s=Invoke-WtRequestedScans -SecurityEvidence (New-Status) -Warnings $w -RecordedFiles $files -DefenderCommandAvailable { throw 'unexpected Defender command' } -DefenderRunner { throw 'unexpected Defender scan' } -ClamAVCommandResolver { throw 'unexpected ClamAV resolve' } -ClamAVRunner { throw 'unexpected ClamAV scan' }
    Assert-Scan $s.RequestedScan 'none' 'passive never requests a scan'
    Assert-Scan $s.DefenderScanResult 'not-requested' 'passive Defender'
    Assert-Scan $s.ClamAVResult 'not-requested' 'passive ClamAV'
    Assert-Scan $w.Count 0 'passive no warning'
    Assert-Scan $files.Count 0 'passive no native log'

    $w=New-Sink; $files=New-Sink
    $s=Invoke-WtRequestedScans -SecurityEvidence (New-Status) -Warnings $w -RecordedFiles $files -RunDefenderQuickScan -DefenderCommandAvailable { $false } -DefenderRunner { throw 'must not start unavailable Defender' }
    Assert-Scan $s.DefenderScanResult 'unavailable' 'Defender unavailable'
    Assert-Scan $s.ClamAVResult 'not-requested' 'ClamAV independent'
    Assert-Scan $w.Count 1 'Defender missing warning'

    $w=New-Sink; $files=New-Sink
    $s=Invoke-WtRequestedScans -SecurityEvidence (New-Status) -Warnings $w -RecordedFiles $files -RunDefenderQuickScan -DefenderCommandAvailable { $true } -DefenderRunner { throw 'synthetic quick scan error' }
    Assert-Scan $s.DefenderScanResult 'failed' 'Defender executor failure'
    Assert-Scan $w.Count 1 'Defender exception warning'

    $w=New-Sink; $files=New-Sink
    $defenderCalls=New-Sink
    $fakeDefender={ [void]$defenderCalls.Add('quick') }.GetNewClosure()
    $opts=@{
        SecurityEvidence=(New-Status);Warnings=$w;RecordedFiles=$files
        RunDefenderQuickScan=$true;RunClamAV=$true;ScanPath=(Join-Path $dir 'DOES-NOT-EXIST');OutputDirectory=$dir;LogWriterFactory=$fakeLogFactory
        DefenderCommandAvailable={ $true };DefenderRunner=$fakeDefender
        ClamAVCommandResolver={ throw 'should never resolve invalid scan path' }
    }
    $invalid=$false
    try { $null=Invoke-WtRequestedScans @opts } catch { $invalid=$true }
    Assert-Scan $invalid $true 'invalid ClamAV path rejected up front'
    Assert-Scan $defenderCalls.Count 0 'invalid path blocks even Defender before scan'

    $w=New-Sink; $files=New-Sink
    $opts=@{SecurityEvidence=(New-Status);Warnings=$w;RecordedFiles=$files;RunClamAV=$true;ScanPath=$dir;OutputDirectory=$dir;LogWriterFactory=$fakeLogFactory;ClamAVCommandResolver={ $null };ClamAVRunner={ throw 'never run without binary' }}
    $s=Invoke-WtRequestedScans @opts
    Assert-Scan $s.ClamAVResult 'not-installed' 'ClamAV unavailable'
    Assert-Scan $s.RequestedScan 'ClamAV' 'ClamAV request recorded'
    Assert-Scan $files.Count 0 'missing binary no log'

    $seen=New-Sink
    $detect={
        param($source,$scanPath,$log)
        [void]$seen.Add(("{0}|{1}" -f $source,$scanPath))
        $log.WriteLine('FICTIONAL-DETECTION')
        [pscustomobject]@{ExitCode=1}
    }.GetNewClosure()
    $w=New-Sink; $files=New-Sink
    $opts=@{SecurityEvidence=(New-Status);Warnings=$w;RecordedFiles=$files;RunClamAV=$true;ScanPath=$dir;OutputDirectory=$dir;LogWriterFactory=$fakeLogFactory;ClamAVCommandResolver={param($name) [pscustomobject]@{Source='SYNTHETIC-clamscan.exe'} };ClamAVRunner=$detect}
    $s=Invoke-WtRequestedScans @opts
    Assert-Scan $s.ClamAVResult 'detection-review-required' 'ClamAV exit 1'
    Assert-Scan $s.ClamAVExitCode 1 'ClamAV exit code'
    Assert-Scan $s.ClamAVOutput 'clamav-output.txt' 'local output referenced'
    Assert-Scan $files.Count 1 'local output manifest index'
    Assert-Scan $seen[0] ("SYNTHETIC-clamscan.exe|"+$dir) 'only explicit path passed'
    Assert-Scan $w.Count 1 'detection warning'

    $unexpectedNative=New-Sink
    $neverRun={ [void]$unexpectedNative.Add('clamscan'); [pscustomobject]@{ExitCode=0} }.GetNewClosure()
    $missing=Join-Path $dir 'no-output'
    New-Item -ItemType Directory -Path $missing -Force | Out-Null
    $w=New-Sink; $files=New-Sink
    $opts=@{SecurityEvidence=(New-Status);Warnings=$w;RecordedFiles=$files;RunClamAV=$true;ScanPath=$dir;OutputDirectory=$missing;LogWriterFactory={ throw 'SYNTHETIC output unavailable' };ClamAVCommandResolver={ [pscustomobject]@{Source='SYNTHETIC'} };ClamAVRunner=$neverRun}
    $s=Invoke-WtRequestedScans @opts
    Assert-Scan $s.ClamAVResult 'failed' 'log factory failure never clean'
    Assert-Scan $unexpectedNative.Count 0 'unsafe output must never launch ClamAV'
    Assert-Scan $files.Count 0 'no missing log indexed'

    $w=New-Sink; $files=New-Sink
    $opts=@{
        SecurityEvidence=(New-Status);Warnings=$w;RecordedFiles=$files
        RunDefenderQuickScan=$true;RunClamAV=$true;ScanPath=$dir;OutputDirectory=$dir;LogWriterFactory=$fakeLogFactory
        DefenderCommandAvailable={ $true }
        DefenderRunner={ throw 'synthetic Defender failed' }
        ClamAVCommandResolver={ [pscustomobject]@{Source='SYNTHETIC-clamscan.exe'} }
        ClamAVRunner={param($source,$path,$log) $log.WriteLine('FICTIONAL-ERROR');[pscustomobject]@{ExitCode=2}}
    }
    $s=Invoke-WtRequestedScans @opts
    Assert-Scan $s.RequestedScan 'Defender QuickScan + ClamAV' 'both requested'
    Assert-Scan $s.DefenderScanResult 'failed' 'Defender failure isolated'
    Assert-Scan $s.ClamAVResult 'scan-error' 'ClamAV unexpected exit'
    Assert-Scan $w.Count 2 'both failures reported'

    $w=New-Sink; $files=New-Sink
    $opts=@{SecurityEvidence=(New-Status);Warnings=$w;RecordedFiles=$files;RunClamAV=$true;ScanPath=$dir;OutputDirectory=$dir;LogWriterFactory=$fakeLogFactory;ClamAVCommandResolver={ [pscustomobject]@{Source='SYNTHETIC'} };ClamAVRunner={ throw 'synthetic scanner exception' }}
    $s=Invoke-WtRequestedScans @opts
    Assert-Scan $s.ClamAVResult 'failed' 'ClamAV exception'
    Write-Host 'PASS: zero default scanning, explicit fixed requests, absent executables, independent failures, private logs'
} finally {
    if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
}
