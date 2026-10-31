#requires -Version 5.1
# ADR-037: synthetic-only externally pinned anchor/decoy regression.
# All files under one GUID-owned temp directory; no real reports or user ACL changes.
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows is required for native anchor research.' }
$repo=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repo 'tools\WinTriage.FieldStatusAclReview.psm1') -Force
# PS 5.1 Add-Type needs cross-file research dependencies compiled together.
$sources=@('HandleChainProbe.cs','VolumeIdentityProbe.cs','SyntheticAnchorLease.cs',
    'RelativeFieldFileProbe.cs','AnchorBoundFieldFileSession.cs') |
    ForEach-Object { Join-Path $PSScriptRoot $_ }
Add-Type -Path $sources -ErrorAction Stop

function Assert-Anchor { param([bool]$Condition,[string]$Label)
    if (-not $Condition) { throw ('Synthetic anchor-bound status file failed: '+$Label) }
}
function Expect-AnchorFailure { param([scriptblock]$Action,[string]$Label)
    $failed=$false
    try { & $Action | Out-Null } catch { $failed=$true }
    Assert-Anchor $failed $Label
}
function New-AnchorTestAcl {
    param([string]$Sid)
    $acl=New-Object System.Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $Sid))
    $full=[System.Security.AccessControl.FileSystemRights]::FullControl
    $none=[System.Security.AccessControl.InheritanceFlags]::None
    $prop=[System.Security.AccessControl.PropagationFlags]::None
    $allow=[System.Security.AccessControl.AccessControlType]::Allow
    foreach ($value in @($Sid,'S-1-5-18','S-1-5-32-544') | Select-Object -Unique) {
        $who=New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $value
        $rule=New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList $who,$full,$none,$prop,$allow
        $acl.AddAccessRule($rule)
    }
    return $acl
}
function Write-OnlyInventedData {
    param([Microsoft.Win32.SafeHandles.SafeFileHandle]$Handle)
    $bytes=[System.Text.Encoding]::UTF8.GetBytes('{"synthetic":true}')
    $stream=New-Object System.IO.FileStream -ArgumentList $Handle,([System.IO.FileAccess]::Write)
    try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush() }
    finally { $stream.Dispose() }
}
$fixture=Join-Path ([System.IO.Path]::GetTempPath()) ('wt-anchor-file-synthetic-'+[guid]::NewGuid().ToString('N'))
$path=Join-Path $fixture 'anchor'
$moved=Join-Path $fixture 'anchor-moved'
$reference=$null
$candidate=$null
$decoyCandidate=$null
$decoyReference=$null
$session=$null
$forgedSession=$null
try {
    [void][System.IO.Directory]::CreateDirectory($path)
    $reference=[WinTriageTests.RelativeFieldFileProbe]::PinSyntheticParent($path)
    $candidate=[WinTriageTests.RelativeFieldFileProbe]::PinSyntheticParent($path)
    $epoch=[guid]::NewGuid()
    $sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $acl=New-AnchorTestAcl -Sid $sid
    Assert-Anchor ($acl.AreAccessRulesProtected) 'synthetic descriptor must not inherit'
    Assert-Anchor ((Get-WtFieldStatusAclClassification -Acl $acl -CurrentSid $sid) -eq 'restricted') 'synthetic descriptor must be restricted'
    $descriptor=$acl.GetSecurityDescriptorBinaryForm()

    $session=New-Object WinTriageTests.AnchorBoundFieldFileSession -ArgumentList $reference,$candidate,$epoch
    $session.RequireCurrent($epoch)
    Expect-AnchorFailure { $session.RequireCurrent([guid]::NewGuid()) } 'wrong epoch must fail before creation'
    Expect-AnchorFailure {
        $badSession=New-Object WinTriageTests.AnchorBoundFieldFileSession -ArgumentList $reference,$reference,([guid]::NewGuid())
        $badSession.Dispose()
    } 'same handle must not be its own independent candidate'

    $leaf='STATUS_BASELINE.json'
    $new=[WinTriageTests.AnchorBoundFieldFileSession]::CreateCheckedSyntheticChild($session,$epoch,$leaf,$descriptor)
    try {
        $actual=[WinTriageTests.RelativeFieldFileProbe]::ReadCreatedFileSecurity($new)
        Assert-Anchor ($actual.AreAccessRulesProtected) 'created DACL must be protected'
        Assert-Anchor ((Get-WtFieldStatusAclClassification -Acl $actual -CurrentSid $sid) -eq 'restricted') 'returned-handle ACL differs'
        $createdId=[WinTriageTests.RelativeFieldFileProbe]::Identity($new,$false)
        Assert-Anchor ($createdId.Length -gt 6) 'returned handle identity missing'
        $session.RequireCurrent($epoch)
        Write-OnlyInventedData -Handle $new
    } finally { $new.Dispose() }
    Assert-Anchor (Test-Path -LiteralPath (Join-Path $path $leaf) -PathType Leaf) 'baseline invented file missing'
    $bytesBefore=[System.IO.File]::ReadAllBytes((Join-Path $path $leaf))
    $sddlBefore=(Get-Acl -LiteralPath (Join-Path $path $leaf)).Sddl
    Expect-AnchorFailure {
        $again=$session.CreateCheckedSyntheticChild($epoch,$leaf,$descriptor)
        $again.Dispose()
    } 'FILE_CREATE must refuse repeated leaf'
    $bytesAfter=[System.IO.File]::ReadAllBytes((Join-Path $path $leaf))
    Assert-Anchor ([System.Linq.Enumerable]::SequenceEqual([byte[]]$bytesBefore,[byte[]]$bytesAfter)) 'collision changed invented bytes'
    Assert-Anchor ((Get-Acl -LiteralPath (Join-Path $path $leaf)).Sddl -eq $sddlBefore) 'collision changed original DACL'
    Write-Output 'PASS synthetic independent held reference binds creation without overwrite'

    $renamed=$false
    try {
        [System.IO.Directory]::Move($path,$moved)
        $renamed=$true
    } catch [System.IO.IOException] {
        Write-Output 'SKIP synthetic rename/decoy: runner prevented moved held parent'
    }
    if ($renamed) {
        [void][System.IO.Directory]::CreateDirectory($path)
        $decoyCandidate=[WinTriageTests.RelativeFieldFileProbe]::PinSyntheticParent($path)
        Assert-Anchor ([WinTriageTests.VolumeIdentityProbe]::VolumeSerial($reference) -eq
            [WinTriageTests.VolumeIdentityProbe]::VolumeSerial($decoyCandidate)) 'decoy should be on same volume'
        Expect-AnchorFailure {
            $bad=New-Object WinTriageTests.AnchorBoundFieldFileSession -ArgumentList $reference,$decoyCandidate,([guid]::NewGuid())
            $bad.Dispose()
        } 'pre-pin decoy must not match earlier externally supplied reference'
        Assert-Anchor (-not (Test-Path -LiteralPath (Join-Path $path 'STATUS_DECOY.json'))) 'decoy should have no invented file'

        # Existing candidate stays bound to the moved original after alias swap.
        $session.RequireCurrent($epoch)
        $second=$session.CreateCheckedSyntheticChild($epoch,'STATUS_ORIGINAL.json',$descriptor)
        try {
            $realAcl=[WinTriageTests.RelativeFieldFileProbe]::ReadCreatedFileSecurity($second)
            Assert-Anchor ((Get-WtFieldStatusAclClassification -Acl $realAcl -CurrentSid $sid) -eq 'restricted') 'moved-original handle ACL'
            $session.RequireCurrent($epoch)
            Write-OnlyInventedData -Handle $second
        } finally { $second.Dispose() }
        Assert-Anchor (Test-Path -LiteralPath (Join-Path $moved 'STATUS_ORIGINAL.json') -PathType Leaf) 'held original must contain created file'
        Assert-Anchor (-not (Test-Path -LiteralPath (Join-Path $path 'STATUS_ORIGINAL.json'))) 'decoy parent must remain untouched'
        Write-Output 'PASS synthetic name replacement cannot redirect held original parent'

        # Deliberate counterexample: if both reference and candidate come from
        # the decoy *after* replacement, identity matching cannot certify origin.
        $decoyReference=[WinTriageTests.RelativeFieldFileProbe]::PinSyntheticParent($path)
        $forgedSession=New-Object WinTriageTests.AnchorBoundFieldFileSession -ArgumentList $decoyReference,$decoyCandidate,([guid]::NewGuid())
        # No file is created; this success is evidence of missing provenance.
        $decoyEpoch=[guid]::NewGuid()
        Expect-AnchorFailure { $forgedSession.RequireCurrent($decoyEpoch) } 'forged session still needs same epoch'
        Write-Output 'PASS counterexample: self-consistent decoy does NOT authenticate a trusted root'
    }
    $session.Dispose()
    Expect-AnchorFailure { $session.RequireCurrent($epoch) } 'revoked session must refuse use'
    $session=$null

    $expiredEpoch=[guid]::NewGuid()
    $expired=New-Object WinTriageTests.AnchorBoundFieldFileSession -ArgumentList $reference,$candidate,$expiredEpoch
    try {
        $reference.Dispose()
        $reference=$null
        Expect-AnchorFailure { $expired.RequireCurrent($expiredEpoch) } 'closed held reference must invalidate baseline'
    } finally { $expired.Dispose() }
    Write-Output 'PASS test-only external baseline/epoch lifecycle; production unchanged and NO_GO'
} finally {
    foreach ($s in @($forgedSession,$session)) {
        if ($null -ne $s) { $s.Dispose() }
    }
    foreach ($h in @($decoyReference,$decoyCandidate,$candidate,$reference)) {
        if ($null -ne $h) { $h.Dispose() }
    }
    # Only the GUID-named disposable synthetic folder is removed.
    if (Test-Path -LiteralPath $fixture -PathType Container) {
        Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction Stop
    }
}
