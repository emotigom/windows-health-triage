#requires -Version 5.1
# Test-owned synthetic directories only. No existing report or Windows settings.
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows required for handle-bound I/O.' }
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'src\WinTriage.ReportSecurity.psm1') -Force
function Must-Fail { param([scriptblock]$Action,[string]$Label)
    $failed=$false
    try { & $Action | Out-Null } catch { $failed=$true }
    if (-not $failed) { throw "Expected rejection: $Label" }
}
function Assert-Equal { param($A,$B,[string]$Label)
    if ($A -ne $B) { throw ('{0}: unexpected result' -f $Label) }
}
$fixture=Join-Path ([System.IO.Path]::GetTempPath()) ('wt-native-write-' + [guid]::NewGuid().ToString('N'))
$parent=Join-Path $fixture 'reports'
$run=$null
$lease=$null
try {
    $run=New-WtPrivateReportDirectory -ParentDirectory $parent -RunId 'SYNTHETIC_WRITE_101'
    $lease=Enter-WtReportPathLease -Directory $run
    $canary='SYNTHETIC_CANARY_UNIQUE_REPORT_291'
    $lease.WriteNewUtf8('system.json',('{"Synthetic":"' + $canary + '"}' + [Environment]::NewLine),$true)
    $actual=Get-Content -LiteralPath (Join-Path $run 'system.json') -Raw -Encoding UTF8
    if (-not $actual.Contains($canary)) { throw 'Handle-relative UTF-8 file was not created.' }
    $data=[System.IO.File]::ReadAllBytes((Join-Path $run 'system.json'))
    Assert-Equal $data[0] 239 'UTF-8 BOM first byte'
    Assert-Equal $data[1] 187 'UTF-8 BOM second byte'
    Assert-Equal $data[2] 191 'UTF-8 BOM third byte'
    Must-Fail { $lease.WriteNewUtf8('system.json','overwrite',$true) } 'no file reuse or overwrite'
    Assert-Equal (Get-Content -LiteralPath (Join-Path $run 'system.json') -Raw -Encoding UTF8).Contains($canary) $true 'existing evidence unchanged'
    Must-Fail { $lease.WriteNewUtf8('..\synthetic.json','bad',$false) } 'relative traversal'
    Must-Fail { $lease.WriteNewUtf8('C:\synthetic.txt','bad',$false) } 'absolute path'
    Must-Fail { $lease.WriteNewUtf8('not-an-approved.txt','bad',$false) } 'unknown report filename'
    Must-Fail { $lease.WriteNewUtf8('system.json:alt','bad',$false) } 'alternate stream'
    Must-Fail { $lease.WriteNewUtf8('SYSTEM.JSON','bad',$false) } 'case-insensitive native collision'
    $lease.WriteNewUtf8('manifest.json',('{"OK":true}' + [Environment]::NewLine),$false)
    Assert-Equal (([System.IO.File]::ReadAllBytes((Join-Path $run 'manifest.json')))[0]) 123 'UTF-8 without BOM'
    [void](Assert-WtPrivateDirectoryAcl -Directory $run)
    $current=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $fileAcl=Get-Acl -LiteralPath (Join-Path $run 'system.json')
    $allow=@($current,'S-1-5-18','S-1-5-32-544')
    foreach ($rule in @($fileAcl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]))) {
        if ($rule.IdentityReference.Value -notin $allow) { throw 'Child inherited broad access.' }
    }
    # A renamed folder is never silently replaced at the original path.
    $renamed=Join-Path $parent 'SYNTHETIC_MOVED'
    $moved=$false
    try { [System.IO.Directory]::Move($run,$renamed); $moved=$true } catch [System.IO.IOException] {}
    if ($moved) {
        try {
            Must-Fail { $lease.WriteNewUtf8('security.json','unsafe',$false) } 'changed identity before write'
            if (Test-Path -LiteralPath (Join-Path $renamed 'security.json')) { throw 'Unexpected file written to moved folder.' }
        } finally {
            [System.IO.Directory]::Move($renamed,$run)
        }
        $lease.AssertStable()
    }
    Write-Host 'PASS: handle-relative UTF-8 file create, no overwrite, filename allowlist, child ACL and identity-change detection'
} finally {
    if ($null -ne $lease) { $lease.Dispose() }
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force }
}
