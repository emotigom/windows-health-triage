#requires -Version 5.1
# ADR-024: test-owned GUID temp fixture only; never touch real report folders.
# GetKernelObjectSecurity returns owner/DACL for a pinned directory handle.
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows required for handle ACL research.' }
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'src\WinTriage.ReportSecurity.psm1') -Force
Add-Type -Path (Join-Path $PSScriptRoot 'HandleSecurityProbe.cs') -ErrorAction Stop

function Assert-Research { param([bool]$Condition,[string]$Label)
    if (-not $Condition) { throw ('Handle ACL research failed: ' + $Label) }
}
function Expect-ResearchFailure { param([scriptblock]$Action,[string]$Label)
    $failed=$false
    try { & $Action | Out-Null } catch { $failed=$true }
    Assert-Research $failed $Label
}

$fixture=Join-Path ([System.IO.Path]::GetTempPath()) ('wt-handle-acl-' + [guid]::NewGuid().ToString('N'))
$runName='SYNTHETIC_RUN_' + [guid]::NewGuid().ToString('N')
$run=Join-Path $fixture $runName
$moved=Join-Path $fixture ($runName + '-moved')
$handle=$null
$renamed=$false
$decoyCreated=$false
try {
    $run=New-WtPrivateReportDirectory -ParentDirectory $fixture -RunId $runName
    $current=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $handle=[WinTriageTests.HandleSecurityProbe]::PinForSyntheticTest($run)
    $originalId=[WinTriageTests.HandleSecurityProbe]::Identity($handle)
    $pathAcl=Get-Acl -LiteralPath $run -ErrorAction Stop
    $handleAcl=[WinTriageTests.HandleSecurityProbe]::ReadSecurity($handle)
    [void](Assert-WtPrivateSecurityDescriptor -Acl $pathAcl -CurrentSid $current)
    [void](Assert-WtPrivateSecurityDescriptor -Acl $handleAcl -CurrentSid $current)
    $sections=[System.Security.AccessControl.AccessControlSections]::Owner -bor
              [System.Security.AccessControl.AccessControlSections]::Access
    $originalSddl=$handleAcl.GetSecurityDescriptorSddlForm($sections)
    Assert-Research ($originalSddl -eq $pathAcl.GetSecurityDescriptorSddlForm($sections)) 'path and pinned handle owner/DACL differ'

    # The granted access mask matters even for an otherwise readable directory.
    $narrow=[WinTriageTests.HandleSecurityProbe]::PinWithoutReadControlForNegativeTest($run)
    try {
        Expect-ResearchFailure {
            [void][WinTriageTests.HandleSecurityProbe]::ReadSecurity($narrow)
        } 'READ_CONTROL omission was not rejected'
    } finally { $narrow.Dispose() }

    try {
        [System.IO.Directory]::Move($run,$moved)
        $renamed=$true
    } catch [System.IO.IOException] {
        Write-Host 'SKIP: test-only pinned directory rename blocked by current runner'
    }

    if ($renamed) {
        # Different path object: never write to or remove a real report.
        [void][System.IO.Directory]::CreateDirectory($run)
        $decoyCreated=$true
        # Deliberately weaker ACL on a disposable synthetic decoy.
        $decoyAcl=New-Object System.Security.AccessControl.DirectorySecurity
        $decoyAcl.SetAccessRuleProtection($true,$false)
        $sid=New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $current
        $decoyAcl.SetOwner($sid)
        $inherit=[System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                 [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        $full=[System.Security.AccessControl.FileSystemRights]::FullControl
        $allow=[System.Security.AccessControl.AccessControlType]::Allow
        $decoyAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList $sid,$full,$inherit,([System.Security.AccessControl.PropagationFlags]::None),$allow))
        try { Set-Acl -LiteralPath $run -AclObject $decoyAcl -ErrorAction Stop }
        catch { throw 'Synthetic decoy ACL setup failed.' }
        $decoyHandle=[WinTriageTests.HandleSecurityProbe]::PinForSyntheticTest($run)
        try {
            Assert-Research ([WinTriageTests.HandleSecurityProbe]::Identity($decoyHandle) -ne $originalId) 'decoy identity matched original'
            Expect-ResearchFailure {
                $insecure=[WinTriageTests.HandleSecurityProbe]::ReadSecurity($decoyHandle)
                [void](Assert-WtPrivateSecurityDescriptor -Acl $insecure -CurrentSid $current)
            } 'weak decoy ACL was accepted'
        } finally { $decoyHandle.Dispose() }

        $after=[WinTriageTests.HandleSecurityProbe]::ReadSecurity($handle)
        Assert-Research ([WinTriageTests.HandleSecurityProbe]::Identity($handle) -eq $originalId) 'pinned directory identity changed'
        Assert-Research ($after.GetSecurityDescriptorSddlForm($sections) -eq $originalSddl) 'pinned owner/DACL followed decoy'
        [void](Assert-WtPrivateSecurityDescriptor -Acl $after -CurrentSid $current)
        Write-Host 'PASS: pinned handle kept original owner/DACL while path resolved to weaker decoy'
    }
    $handle.Dispose()
    Expect-ResearchFailure {
        [void][WinTriageTests.HandleSecurityProbe]::ReadSecurity($handle)
    } 'closed handle was accepted'
    Write-Host 'PASS: test-only directory handle ACL/owner probe and READ_CONTROL guard'
} finally {
    if ($null -ne $handle) { $handle.Dispose() }
    if ($decoyCreated -and (Test-Path -LiteralPath $run)) {
        # Only this GUID-named empty synthetic decoy.
        Remove-Item -LiteralPath $run -Recurse -Force
    }
    if ($renamed -and (Test-Path -LiteralPath $moved)) {
        [System.IO.Directory]::Move($moved,$run)
    }
    if (Test-Path -LiteralPath $fixture) {
        # Removes only the GUID-named fixture this test created.
        Remove-Item -LiteralPath $fixture -Recurse -Force
    }
}
