#requires -Version 5.1
# ADR-036 synthetic test, GUID-owned temporary filesystem fixtures ONLY.
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows-only NT relative-file experiment.' }
$repo=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repo 'tools\WinTriage.FieldStatusAclReview.psm1') -Force
Add-Type -Path (Join-Path $PSScriptRoot 'RelativeFieldFileProbe.cs') -ErrorAction Stop
function Assert-Relative { param([bool]$Condition,[string]$Label)
    if (-not $Condition) { throw ('Relative field-file research failed: '+$Label) }
}
function Expect-RelativeFailure { param([scriptblock]$Action,[string]$Label)
    $failed=$false
    try { & $Action | Out-Null } catch { $failed=$true }
    Assert-Relative $failed $Label
}
function New-PrivateSyntheticFileAcl {
    param([string]$CurrentSid)
    $acl=New-Object System.Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $CurrentSid))
    $full=[System.Security.AccessControl.FileSystemRights]::FullControl
    $none=[System.Security.AccessControl.InheritanceFlags]::None
    $prop=[System.Security.AccessControl.PropagationFlags]::None
    $allow=[System.Security.AccessControl.AccessControlType]::Allow
    foreach ($sidText in @($CurrentSid,'S-1-5-18','S-1-5-32-544') | Select-Object -Unique) {
        $sid=New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $sidText
        $rule=New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList $sid,$full,$none,$prop,$allow
        $acl.AddAccessRule($rule)
    }
    return $acl
}
function Assert-PrivateSyntheticFileAcl {
    param([System.Security.AccessControl.FileSecurity]$Acl,[string]$CurrentSid)
    Assert-Relative $Acl.AreAccessRulesProtected 'protected DACL must disable inheritance'
    Assert-Relative ((Get-WtFieldStatusAclClassification -Acl $Acl -CurrentSid $CurrentSid) -eq 'restricted') 'private file owner/DACL'
    $rules=@($Acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]))
    Assert-Relative (@($rules | Where-Object { $_.IsInherited }).Count -eq 0) 'must have no inherited ACE'
}
function Write-InventedHandleBytes {
    param([Microsoft.Win32.SafeHandles.SafeFileHandle]$Handle,[byte[]]$Payload)
    # Write invented bytes through returned handle only. FileStream owns it.
    $stream=New-Object System.IO.FileStream -ArgumentList $Handle,([System.IO.FileAccess]::Write)
    try { $stream.Write($Payload,0,$Payload.Length); $stream.Flush() }
    finally { $stream.Dispose() }
}
$fixture=Join-Path ([System.IO.Path]::GetTempPath()) ('wt-relative-file-synthetic-' + [guid]::NewGuid().ToString('N'))
$parent=Join-Path $fixture 'parent'
$moved=Join-Path $fixture 'parent-moved'
$h=$null
$movedSuccessfully=$false
try {
    [void][System.IO.Directory]::CreateDirectory($parent)
    $current=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $acl=New-PrivateSyntheticFileAcl -CurrentSid $current
    Assert-PrivateSyntheticFileAcl -Acl $acl -CurrentSid $current
    $sd=$acl.GetSecurityDescriptorBinaryForm()
    $invented=[System.Text.Encoding]::UTF8.GetBytes('{"schema":1,"synthetic":true}')
    $h=[WinTriageTests.RelativeFieldFileProbe]::PinSyntheticParent($parent)
    $originalIdentity=[WinTriageTests.RelativeFieldFileProbe]::Identity($h,$true)
    $leaf='STATUS_INITIAL.json'
    $created=[WinTriageTests.RelativeFieldFileProbe]::CreateSyntheticChild($h,$leaf,$sd)
    try {
        $initialIdentity=[WinTriageTests.RelativeFieldFileProbe]::Identity($created,$false)
        $actualAcl=[WinTriageTests.RelativeFieldFileProbe]::ReadCreatedFileSecurity($created)
        Assert-PrivateSyntheticFileAcl -Acl $actualAcl -CurrentSid $current
        Write-InventedHandleBytes -Handle $created -Payload $invented
    } finally { $created.Dispose() }
    Assert-Relative (Test-Path -LiteralPath (Join-Path $parent $leaf) -PathType Leaf) 'first child created under pinned parent'
    Assert-Relative ($initialIdentity.Length -gt 6) 'new file identity read from returned handle'
    $oldBytes=[System.IO.File]::ReadAllBytes((Join-Path $parent $leaf))
    $oldSddl=(Get-Acl -LiteralPath (Join-Path $parent $leaf)).Sddl
    Expect-RelativeFailure {
        $duplicate=[WinTriageTests.RelativeFieldFileProbe]::CreateSyntheticChild($h,$leaf,$sd)
        $duplicate.Dispose()
    } 'exclusive FILE_CREATE rejects existing status filename'
    $afterBytes=[System.IO.File]::ReadAllBytes((Join-Path $parent $leaf))
    Assert-Relative ([System.Linq.Enumerable]::SequenceEqual([byte[]]$oldBytes,[byte[]]$afterBytes)) 'collision did not overwrite invented bytes'
    Assert-Relative ((Get-Acl -LiteralPath (Join-Path $parent $leaf)).Sddl -eq $oldSddl) 'collision did not alter file DACL'

    foreach ($bad in @('','..','..\outside.json','C:\escaped.json','folder:ads.json','bad.','bad ','SHORT','linked\name.json','file/name.json')) {
        Expect-RelativeFailure {
            $badHandle=[WinTriageTests.RelativeFieldFileProbe]::CreateSyntheticChild($h,$bad,$sd)
            $badHandle.Dispose()
        } 'strict single-leaf filename'
    }
    Expect-RelativeFailure {
        $empty=[WinTriageTests.RelativeFieldFileProbe]::CreateSyntheticChild($h,'STATUS_EMPTY.json',([byte[]]@()))
        $empty.Dispose()
    } 'refuse missing DACL before NT create'
    Assert-Relative (-not (Test-Path -LiteralPath (Join-Path $parent 'STATUS_EMPTY.json'))) 'no file for missing DACL'

    # TEST-ONLY deterministic race: rename a pinned directory and replace its
    # original lexical path with a decoy. The operation must remain bound to
    # original held handle (or fail), never create in the decoy.
    try {
        [System.IO.Directory]::Move($parent,$moved)
        $movedSuccessfully=$true
    } catch [System.IO.IOException] {
        Write-Output 'SKIP synthetic parent-rename check: host refused rename with held handle'
    }
    if ($movedSuccessfully) {
        [void][System.IO.Directory]::CreateDirectory($parent)
        Assert-Relative ([WinTriageTests.RelativeFieldFileProbe]::Identity($h,$true) -eq $originalIdentity) 'pinned parent identity survives rename'
        $second='STATUS_AFTER_SWAP.json'
        $secondHandle=[WinTriageTests.RelativeFieldFileProbe]::CreateSyntheticChild($h,$second,$sd)
        try {
            $returnedIdentity=[WinTriageTests.RelativeFieldFileProbe]::Identity($secondHandle,$false)
            $secondAcl=[WinTriageTests.RelativeFieldFileProbe]::ReadCreatedFileSecurity($secondHandle)
            Assert-PrivateSyntheticFileAcl -Acl $secondAcl -CurrentSid $current
            Write-InventedHandleBytes -Handle $secondHandle -Payload $invented
        } finally { $secondHandle.Dispose() }
        Assert-Relative (Test-Path -LiteralPath (Join-Path $moved $second) -PathType Leaf) 'new status file is under moved original parent'
        Assert-Relative (-not (Test-Path -LiteralPath (Join-Path $parent $second))) 'decoy parent contains no status file'
        $pathIdentity=[WinTriageTests.RelativeFieldFileProbe]::PinSyntheticParent($moved)
        try {
            Assert-Relative ([WinTriageTests.RelativeFieldFileProbe]::Identity($pathIdentity,$true) -eq $originalIdentity) 'moved path still references trusted held parent'
        } finally { $pathIdentity.Dispose() }
        Assert-Relative ($returnedIdentity.Length -gt 6) 'returned second file identity verified'
        Write-Output 'PASS synthetic parent-path replacement did not redirect creation to decoy'
    }

    # Optional test-owned junction: leaf reparse detection at pinning boundary.
    $junction=Join-Path $fixture 'synthetic-junction'
    $madeJunction=$false
    try {
        $target=if ($movedSuccessfully) { $moved } else { $parent }
        New-Item -ItemType Junction -Path $junction -Target $target -ErrorAction Stop | Out-Null
        $madeJunction=$true
    } catch [System.Management.Automation.RuntimeException] {
        Write-Output 'SKIP test-owned junction: unsupported runner policy'
    } catch [System.UnauthorizedAccessException] {
        Write-Output 'SKIP test-owned junction: denied by runner policy'
    }
    if ($madeJunction) {
        Expect-RelativeFailure {
            $j=[WinTriageTests.RelativeFieldFileProbe]::PinSyntheticParent($junction)
            $j.Dispose()
        } 'junction parent rejected without following'
        $item=Get-Item -LiteralPath $junction -Force
        Assert-Relative (([int]$item.Attributes -band [int][System.IO.FileAttributes]::ReparsePoint) -ne 0) 'cleanup only real junction'
        [System.IO.Directory]::Delete($junction)
    }
    $h.Dispose()
    Expect-RelativeFailure {
        $closed=[WinTriageTests.RelativeFieldFileProbe]::CreateSyntheticChild($h,'STATUS_CLOSED.json',$sd)
        $closed.Dispose()
    } 'closed parent handle cannot create child'
    Write-Output 'PASS test-only held-parent FILE_CREATE with immediate handle ACL and NO_GO-only interpretation'
} finally {
    if ($null -ne $h) { $h.Dispose() }
    # Dispose is strictly limited to our GUID-owned synthetic fixture.
    if (Test-Path -LiteralPath $fixture -PathType Container) {
        $junction=Join-Path $fixture 'synthetic-junction'
        if (Test-Path -LiteralPath $junction) {
            $item=Get-Item -LiteralPath $junction -Force
            if (([int]$item.Attributes -band [int][System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                [System.IO.Directory]::Delete($junction)
            }
        }
        Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction Stop
    }
}
