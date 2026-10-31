#requires -Version 5.1
# ADR-026: GUID-owned synthetic temp tree only; no actual user report access.
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows is required for synthetic handle chain.' }
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'src\WinTriage.ReportSecurity.psm1') -Force
foreach ($source in @('HandleSecurityProbe.cs','DirectoryCreationProbe.cs','HandleChainProbe.cs')) {
    Add-Type -Path (Join-Path $PSScriptRoot $source) -ErrorAction Stop
}

function Assert-Chain { param([bool]$Condition,[string]$Label)
    if (-not $Condition) { throw ('Handle chain probe failed: ' + $Label) }
}
function Expect-ChainFailure { param([scriptblock]$Action,[string]$Label)
    $failed=$false
    try { & $Action | Out-Null } catch { $failed=$true }
    Assert-Chain $failed $Label
}
function Get-SyntheticPathIdentity {
    param([string]$Path)
    $testHandle=[WinTriageTests.HandleChainProbe]::PinSyntheticAnchor($Path)
    try { return [WinTriageTests.HandleChainProbe]::Identity($testHandle) }
    finally { $testHandle.Dispose() }
}
function New-SyntheticPrivateDescriptor {
    $current=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $acl=New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    $sid=New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $current
    $acl.SetOwner($sid)
    $inherit=[System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
             [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $rights=[System.Security.AccessControl.FileSystemRights]::FullControl
    $allow=[System.Security.AccessControl.AccessControlType]::Allow
    foreach ($sidValue in @($current,'S-1-5-18','S-1-5-32-544') | Select-Object -Unique) {
        $who=New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $sidValue
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList $who,$rights,$inherit,([System.Security.AccessControl.PropagationFlags]::None),$allow))
    }
    return $acl.GetSecurityDescriptorBinaryForm()
}
function Assert-CreatedPrivate {
    param([Microsoft.Win32.SafeHandles.SafeFileHandle]$Handle)
    $who=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $acl=[WinTriageTests.HandleSecurityProbe]::ReadSecurity($Handle)
    [void](Assert-WtPrivateSecurityDescriptor -Acl $acl -CurrentSid $who)
}

$fixture=Join-Path ([System.IO.Path]::GetTempPath()) ('wt-handle-chain-' + [guid]::NewGuid().ToString('N'))
$anchor=Join-Path $fixture 'anchor'
$moved=Join-Path $fixture 'anchor-moved'
$original=Join-Path (Join-Path $anchor 'level_one') 'level_two'
$redirect=Join-Path $fixture 'redirect-target'
$parentHandle=$null
$renamed=$false
$junctionCreated=$false
try {
    [void][System.IO.Directory]::CreateDirectory($original)
    [void][System.IO.Directory]::CreateDirectory($redirect)
    [System.IO.File]::WriteAllText((Join-Path $anchor 'ordinary_file'),'synthetic')
    $expected=(Get-SyntheticPathIdentity -Path $original)
    $parentHandle=[WinTriageTests.HandleChainProbe]::PinSyntheticAnchor($anchor)
    $anchorId=[WinTriageTests.HandleChainProbe]::Identity($parentHandle)

    $normal=[WinTriageTests.HandleChainProbe]::Walk($parentHandle,@('level_one','level_two'))
    try {
        Assert-Chain ([WinTriageTests.HandleChainProbe]::Identity($normal) -eq $expected) 'baseline two-hop identity differs'
    } finally { $normal.Dispose() }

    foreach ($invalid in @(@('..'),@('level_one','..'),@('ordinary_file'),@('C:\outside'),@('level_one','level_two:stream'),@('level_one','bad\path'))) {
        Expect-ChainFailure {
            $bad=[WinTriageTests.HandleChainProbe]::Walk($parentHandle,[string[]]$invalid)
            $bad.Dispose()
        } 'invalid or nondirectory synthetic hop was accepted'
    }
    Expect-ChainFailure {
        $bad=[WinTriageTests.HandleChainProbe]::Walk($parentHandle,[string[]]@())
        $bad.Dispose()
    } 'zero-hop traversal accepted'

    # Optional junction attack: access policy can block junction creation.
    # If created, a hop MUST reject it rather than return the target directory.
    $junction=Join-Path $anchor 'junction'
    try {
        New-Item -ItemType Junction -Path $junction -Target $redirect -ErrorAction Stop | Out-Null
        $junctionCreated=$true
    } catch {
        Write-Host 'SKIP: synthetic junction creation unavailable on this Windows runner'
    }
    if ($junctionCreated) {
        Expect-ChainFailure {
            $linked=[WinTriageTests.HandleChainProbe]::Walk($parentHandle,@('junction'))
            $linked.Dispose()
        } 'junction traversal was not rejected'
        Write-Host 'PASS: test-only reparse/junction hop refused'
        # Avoid following a link during cleanup even on Windows PowerShell 5.1.
        Remove-Item -LiteralPath $junction -Force -ErrorAction Stop
        $junctionCreated=$false
    }

    try {
        [System.IO.Directory]::Move($anchor,$moved)
        $renamed=$true
    } catch [System.IO.IOException] {
        Write-Host 'SKIP: synthetic anchor rename refused under current sharing/policy'
    }
    if ($renamed) {
        [void][System.IO.Directory]::CreateDirectory((Join-Path (Join-Path $anchor 'level_one') 'level_two'))
        $decoyLeaf=Join-Path (Join-Path $anchor 'level_one') 'level_two'
        $decoyId=(Get-SyntheticPathIdentity -Path $decoyLeaf)
        Assert-Chain ($decoyId -ne $expected) 'synthetic path decoy did not change identity'
    }

    $held=[WinTriageTests.HandleChainProbe]::Walk($parentHandle,@('level_one','level_two'))
    try {
        Assert-Chain ([WinTriageTests.HandleChainProbe]::Identity($parentHandle) -eq $anchorId) 'held anchor identity changed'
        Assert-Chain ([WinTriageTests.HandleChainProbe]::Identity($held) -eq $expected) 'handle chain resolved to path decoy'
        $runName='RUN_'+[guid]::NewGuid().ToString('N')
        $created=[WinTriageTests.DirectoryCreationProbe]::CreateChildRelative($held,$runName,(New-SyntheticPrivateDescriptor))
        try {
            Assert-CreatedPrivate -Handle $created
            $correctParent=if ($renamed) { Join-Path (Join-Path $moved 'level_one') 'level_two' } else { $original }
            $runPath=Join-Path $correctParent $runName
            Assert-Chain (Test-Path -LiteralPath $runPath -PathType Container) 'private run not created under held chain'
            if ($renamed) {
                Assert-Chain (-not (Test-Path -LiteralPath (Join-Path $decoyLeaf $runName))) 'private run appeared beneath decoy'
            }
            $check=[WinTriageTests.HandleSecurityProbe]::PinForSyntheticTest($runPath)
            try {
                Assert-Chain ([WinTriageTests.HandleSecurityProbe]::Identity($check) -eq [WinTriageTests.HandleSecurityProbe]::Identity($created)) 'returned creation handle differs from original chain'
            } finally { $check.Dispose() }
        } finally { $created.Dispose() }
    } finally { $held.Dispose() }
    if ($renamed) { Write-Host 'PASS: synthetic held anchor chain ignored path decoy and created private run in original parent' }
    $parentHandle.Dispose()
    Expect-ChainFailure {
        $closed=[WinTriageTests.HandleChainProbe]::Walk($parentHandle,@('level_one'))
        $closed.Dispose()
    } 'closed anchor handle accepted'
    Write-Host 'PASS: test-only two-hop handle lineage and private run creation; production unchanged'
} finally {
    if ($null -ne $parentHandle) { $parentHandle.Dispose() }
    if ($junctionCreated) {
        $junctionRoot=if ($renamed) { Join-Path $moved 'junction' } else { $junction }
        if (Test-Path -LiteralPath $junctionRoot) {
            Remove-Item -LiteralPath $junctionRoot -Force
        }
    }
    if (Test-Path -LiteralPath $fixture) {
        # Only this one newly generated, disposable GUID-named fixture.
        Remove-Item -LiteralPath $fixture -Recurse -Force
    }
}
