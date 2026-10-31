#requires -Version 5.1
# ADR-025 synthetic-only: parent-relative directory creation with returned handle.
# Only GUID test-owned temp folders; never inspect or change real reports.
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows required for relative directory creation probe.' }
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'src\WinTriage.ReportSecurity.psm1') -Force
if (-not ('WinTriageTests.HandleSecurityProbe' -as [type])) {
    Add-Type -Path (Join-Path $PSScriptRoot 'HandleSecurityProbe.cs') -ErrorAction Stop
}
if (-not ('WinTriageTests.DirectoryCreationProbe' -as [type])) {
    Add-Type -Path (Join-Path $PSScriptRoot 'DirectoryCreationProbe.cs') -ErrorAction Stop
}
function Assert-CreateResearch { param([bool]$Condition,[string]$Label)
    if (-not $Condition) { throw ('Directory creation research failed: '+$Label) }
}
function Expect-CreateFailure { param([scriptblock]$Action,[string]$Label)
    $rejected=$false
    try { & $Action | Out-Null } catch { $rejected=$true }
    Assert-CreateResearch $rejected $Label
}
function Assert-PrivateCreatedHandle {
    param([Microsoft.Win32.SafeHandles.SafeFileHandle]$Handle,[string]$CurrentSid)
    $acl=[WinTriageTests.HandleSecurityProbe]::ReadSecurity($Handle)
    [void](Assert-WtPrivateSecurityDescriptor -Acl $acl -CurrentSid $CurrentSid)
}

$fixture=Join-Path ([System.IO.Path]::GetTempPath()) ('wt-relative-create-' + [guid]::NewGuid().ToString('N'))
$parent=Join-Path $fixture 'parent'
$movedParent=Join-Path $fixture 'parent-moved'
$parentHandle=$null
$renamed=$false
try {
    [void][System.IO.Directory]::CreateDirectory($parent)
    $current=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $sd=New-Object System.Security.AccessControl.DirectorySecurity
    $sd.SetAccessRuleProtection($true,$false)
    $identity=New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $current
    $sd.SetOwner($identity)
    $inherit=[System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
             [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $rights=[System.Security.AccessControl.FileSystemRights]::FullControl
    $allow=[System.Security.AccessControl.AccessControlType]::Allow
    foreach ($sid in @($current,'S-1-5-18','S-1-5-32-544') | Select-Object -Unique) {
        $who=New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $sid
        $rule=New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList $who,$rights,$inherit,([System.Security.AccessControl.PropagationFlags]::None),$allow
        $sd.AddAccessRule($rule)
    }
    $descriptor=$sd.GetSecurityDescriptorBinaryForm()
    $parentHandle=[WinTriageTests.DirectoryCreationProbe]::PinParentForSyntheticTest($parent)
    $parentId=[WinTriageTests.HandleSecurityProbe]::Identity($parentHandle)
    $firstName='RUN_' + [guid]::NewGuid().ToString('N')
    $first=[WinTriageTests.DirectoryCreationProbe]::CreateChildRelative($parentHandle,$firstName,$descriptor)
    try {
        Assert-PrivateCreatedHandle -Handle $first -CurrentSid $current
        $firstPath=Join-Path $parent $firstName
        Assert-CreateResearch (Test-Path -LiteralPath $firstPath -PathType Container) 'first new directory not created under parent'
        $fromPath=[WinTriageTests.HandleSecurityProbe]::PinForSyntheticTest($firstPath)
        try {
            Assert-CreateResearch ([WinTriageTests.HandleSecurityProbe]::Identity($fromPath) -eq [WinTriageTests.HandleSecurityProbe]::Identity($first)) 'new directory returned handle differs from path object'
        } finally { $fromPath.Dispose() }
        Expect-CreateFailure {
            $duplicate=[WinTriageTests.DirectoryCreationProbe]::CreateChildRelative($parentHandle,$firstName,$descriptor)
            $duplicate.Dispose()
        } 'FILE_CREATE must refuse an existing leaf'
        foreach ($bad in @('','..','..\other','C:\outside','folder:stream','bad.','bad ','short')) {
            Expect-CreateFailure {
                $badHandle=[WinTriageTests.DirectoryCreationProbe]::CreateChildRelative($parentHandle,$bad,$descriptor)
                $badHandle.Dispose()
            } 'invalid single-leaf name was accepted'
        }
        Assert-PrivateCreatedHandle -Handle $first -CurrentSid $current
    } finally { $first.Dispose() }

    try {
        [System.IO.Directory]::Move($parent,$movedParent)
        $renamed=$true
    } catch [System.IO.IOException] {
        Write-Host 'SKIP: test-only pinned parent rename blocked; baseline create/ACL checks still passed'
    }
    if ($renamed) {
        # A different parent now occupies the ORIGINAL path: the native call
        # must create below the HELD parent or refuse, never below the decoy.
        [void][System.IO.Directory]::CreateDirectory($parent)
        $secondName='RUN_' + [guid]::NewGuid().ToString('N')
        $created=[WinTriageTests.DirectoryCreationProbe]::CreateChildRelative($parentHandle,$secondName,$descriptor)
        try {
            Assert-PrivateCreatedHandle -Handle $created -CurrentSid $current
            Assert-CreateResearch ([WinTriageTests.HandleSecurityProbe]::Identity($parentHandle) -eq $parentId) 'held parent ID changed'
            Assert-CreateResearch (Test-Path -LiteralPath (Join-Path $movedParent $secondName) -PathType Container) 'relative creation not found under moved original parent'
            Assert-CreateResearch (-not (Test-Path -LiteralPath (Join-Path $parent $secondName))) 'relative creation landed in decoy parent'
            $originalPathChild=[WinTriageTests.HandleSecurityProbe]::PinForSyntheticTest((Join-Path $movedParent $secondName))
            try {
                Assert-CreateResearch ([WinTriageTests.HandleSecurityProbe]::Identity($originalPathChild) -eq [WinTriageTests.HandleSecurityProbe]::Identity($created)) 'returned handle diverged from original moved parent child'
            } finally { $originalPathChild.Dispose() }
            Write-Host 'PASS: test-only relative creation stayed under held parent after path decoy substitution'
        } finally { $created.Dispose() }
    }
    $parentHandle.Dispose()
    Expect-CreateFailure {
        $late=[WinTriageTests.DirectoryCreationProbe]::CreateChildRelative($parentHandle,('RUN_'+[guid]::NewGuid().ToString('N')),$descriptor)
        $late.Dispose()
    } 'closed parent handle was accepted'
    Write-Host 'PASS: test-only relative directory FILE_CREATE, immediate owner/DACL and collision/leaf checks'
} finally {
    if ($null -ne $parentHandle) { $parentHandle.Dispose() }
    if (Test-Path -LiteralPath $fixture) {
        # Delete only disposable GUID-named directory owned by this fixture.
        Remove-Item -LiteralPath $fixture -Recurse -Force
    }
}
