#requires -Version 5.1
# ADR-035: test-only, GUID-owned disposable synthetic JSON. No real user reports.
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows-only native file create research.' }
$repo=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repo 'src\WinTriage.ReportSecurity.psm1') -Force
Import-Module (Join-Path $repo 'tools\WinTriage.FieldStatusAclReview.psm1') -Force
Add-Type -Path (Join-Path $PSScriptRoot 'FieldStatusFileCreateProbe.cs') -ErrorAction Stop

function Assert-Synthetic {
    param([bool]$Condition,[string]$Label)
    if (-not $Condition) { throw ('Synthetic native file DACL failed: '+$Label) }
}
function Expect-SyntheticFailure {
    param([scriptblock]$Action,[string]$Label)
    $refused=$false
    try { & $Action | Out-Null } catch { $refused=$true }
    Assert-Synthetic $refused $Label
}
function New-SyntheticFileAcl {
    param([string]$CurrentSid,[switch]$Everyone,[switch]$MissingSystem,
          [switch]$ForeignOwner,[switch]$Inheritable)
    $acl=New-Object System.Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection((-not $Inheritable.IsPresent),$false)
    $owner=if ($ForeignOwner) { 'S-1-5-21-12345-67890-11111-5555' } else { $CurrentSid }
    $acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $owner))
    $allow=[System.Security.AccessControl.AccessControlType]::Allow
    $full=[System.Security.AccessControl.FileSystemRights]::FullControl
    $inherit=[System.Security.AccessControl.InheritanceFlags]::None
    $prop=[System.Security.AccessControl.PropagationFlags]::None
    foreach ($sidText in @($CurrentSid,'S-1-5-18','S-1-5-32-544') | Select-Object -Unique) {
        if ($MissingSystem -and $sidText -eq 'S-1-5-18') { continue }
        $sid=New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $sidText
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList $sid,$full,$inherit,$prop,$allow))
    }
    if ($Everyone) {
        $sid=New-Object System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-1-0'
        $everyoneRule=New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList $sid,([System.Security.AccessControl.FileSystemRights]::ReadData),$inherit,$prop,$allow
        $acl.AddAccessRule($everyoneRule)
    }
    return $acl
}
function Assert-SyntheticDescriptor {
    param([System.Security.AccessControl.FileSecurity]$Acl,[string]$CurrentSid)
    # Preflight is NOT supplied by CreateFileW; enforce exact policy before
    # passing the security descriptor to native create.
    if (-not $Acl.AreAccessRulesProtected) {
        throw 'Synthetic file descriptor inherits access rules.'
    }
    if ((Get-WtFieldStatusAclClassification -Acl $Acl -CurrentSid $CurrentSid) -ne 'restricted') {
        throw 'Synthetic file descriptor contains unapproved ACL or owner.'
    }
}
function New-SyntheticFile {
    param([string]$Output,[System.Security.AccessControl.FileSecurity]$Acl,
          [string]$CurrentSid,[byte[]]$Bytes)
    [void](Assert-SyntheticDescriptor -Acl $Acl -CurrentSid $CurrentSid)
    [WinTriage.Research.FieldStatusFileCreateProbe]::CreateNew(
        $Output,$Acl.GetSecurityDescriptorBinaryForm(),$Bytes)
}
$scratch=Join-Path ([System.IO.Path]::GetTempPath()) ('wt-create-file-synthetic-' + [guid]::NewGuid().ToString('N'))
$fixtureCreated=$false
try {
    $private=New-WtPrivateReportDirectory -ParentDirectory $scratch -RunId 'SYNTHETIC_FILE_RUN'
    $fixtureCreated=$true
    $current=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $acl=New-SyntheticFileAcl -CurrentSid $current
    [void](Assert-SyntheticDescriptor -Acl $acl -CurrentSid $current)
    $file=Join-Path $private 'synthetic-status.json'
    $invented=[System.Text.Encoding]::UTF8.GetBytes('{"schema":1,"synthetic":true}')
    Assert-Synthetic (-not (Test-Path -LiteralPath $file)) 'new output must not exist'
    New-SyntheticFile -Output $file -Acl $acl -CurrentSid $current -Bytes $invented

    # ACL is inspectable immediately after the single native create+write.
    # No Set-Acl or parent inheritance of an unprotected DACL was used.
    Assert-Synthetic (Test-Path -LiteralPath $file -PathType Leaf) 'native file exists'
    $applied=Get-Acl -LiteralPath $file -ErrorAction Stop
    Assert-Synthetic ($applied -is [System.Security.AccessControl.FileSecurity]) 'actual file ACL available'
    Assert-Synthetic $applied.AreAccessRulesProtected 'DACL inheritance disabled at create'
    Assert-Synthetic ((Get-WtFieldStatusAclClassification -Acl $applied -CurrentSid $current) -eq 'restricted') 'owner and DACL restricted'
    $rules=@($applied.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]))
    Assert-Synthetic ($rules.Count -ge 3) 'required SID entries present'
    Assert-Synthetic (@($rules | Where-Object { $_.IsInherited }).Count -eq 0) 'no inherited ACL entries'
    Assert-Synthetic ([System.Linq.Enumerable]::SequenceEqual([byte[]]([System.IO.File]::ReadAllBytes($file)),[byte[]]$invented)) 'invented content unchanged'
    $observed=Get-WtFieldStatusOutputAssessment -MetadataPath $file
    Assert-Synthetic ($observed.MetadataAcl -eq 'restricted') 'read-only ACL reviewer agrees'
    Assert-Synthetic ($observed.PathObservation -eq 'direct_local_observed') 'local path observed'
    Assert-Synthetic ($observed.SyncAndBackup -eq 'unknown' -and $observed.Decision -eq 'NO_GO') 'never approve sync or release'

    # CREATE_NEW must refuse reusing an existing file without changing bytes or ACL.
    $priorBytes=[System.IO.File]::ReadAllBytes($file)
    $priorSddl=(Get-Acl -LiteralPath $file).Sddl
    Expect-SyntheticFailure {
        New-SyntheticFile -Output $file -Acl $acl -CurrentSid $current -Bytes ([byte[]](1,2,3))
    } 'CREATE_NEW rejects collision'
    Assert-Synthetic ([System.Linq.Enumerable]::SequenceEqual([byte[]]([System.IO.File]::ReadAllBytes($file)),[byte[]]$priorBytes)) 'collision retains contents'
    Assert-Synthetic ((Get-Acl -LiteralPath $file).Sddl -eq $priorSddl) 'collision retains original ACL'

    # These policy negatives must be refused BEFORE native creation.
    $negative=@(
        @{ Label='Everyone ACE'; Acl=(New-SyntheticFileAcl -CurrentSid $current -Everyone) },
        @{ Label='missing SYSTEM'; Acl=(New-SyntheticFileAcl -CurrentSid $current -MissingSystem) },
        @{ Label='foreign owner'; Acl=(New-SyntheticFileAcl -CurrentSid $current -ForeignOwner) },
        @{ Label='unprotected inheritance'; Acl=(New-SyntheticFileAcl -CurrentSid $current -Inheritable) }
    )
    $n=0
    foreach ($variant in $negative) {
        $n++
        $candidate=Join-Path $private ('denied-synthetic-'+$n+'.json')
        Expect-SyntheticFailure {
            New-SyntheticFile -Output $candidate -Acl $variant.Acl -CurrentSid $current -Bytes $invented
        } $variant.Label
        Assert-Synthetic (-not (Test-Path -LiteralPath $candidate)) 'unsafe descriptor must leave no file'
    }
    $noDescriptor=Join-Path $private 'empty-descriptor.json'
    Expect-SyntheticFailure {
        [WinTriage.Research.FieldStatusFileCreateProbe]::CreateNew($noDescriptor,([byte[]]@()),$invented)
    } 'native missing descriptor refused'
    Assert-Synthetic (-not (Test-Path -LiteralPath $noDescriptor)) 'no file on missing descriptor'
    Write-Output 'PASS research-only create-time ACL, collision and policy negatives; NO_GO maintained'
} finally {
    # Delete ONLY the GUID-owned disposable fixture. Never touch user reports.
    if ($fixtureCreated -and (Test-Path -LiteralPath $scratch -PathType Container)) {
        Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction Stop
    }
}
