#requires -Version 5.1
# Test-owned synthetic temporary files only. Never inspect an actual user report.
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows-only ACL fixture.' }
$repo=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repo 'src\WinTriage.ReportSecurity.psm1') -Force
Import-Module (Join-Path $repo 'tools\WinTriage.FieldStatusAclReview.psm1') -Force
function Assert-Test { param([bool]$Condition,[string]$Label)
    if (-not $Condition) { throw ('Synthetic field ACL failed: '+$Label) }
}
$scratch=Join-Path ([System.IO.Path]::GetTempPath()) ('wt-field-acl-synthetic-' + [guid]::NewGuid().ToString('N'))
$cleanupAllowed=$false
try {
    # Production report ACL constructor used only for a disposable test folder.
    $private=New-WtPrivateReportDirectory -ParentDirectory $scratch -RunId 'SYNTHETIC_STATUS_RUN'
    $cleanupAllowed=$true
    $output=Join-Path $private 'synthetic-status.json'
    # Exercise the actual opt-in Python recorder with synthetic enum statuses.
    $labels=@(
        'Quick:review:pass:pass:not-requested:none',
        'Events:pass:pass:pass:not-applicable:none',
        'Hardware:review:pass:pass:not-applicable:present',
        'Monitor:pass:pass:pass:not-applicable:none',
        'Integrity:pass:pass:pass:not-requested:none'
    )
    $argsList=@(
        (Join-Path $repo 'tools\field_status_recorder.py'),
        '--metadata',(Join-Path $repo 'docs\field-evidence-template.json'),
        '--output',$output,
        '--os','windows11','--shell','powershell7','--privilege','standard',
        '--observed-local-only'
    )
    foreach ($s in $labels) { $argsList+=@('--status',$s) }
    $stdout=@(& python @argsList 2>&1 | Out-String)
    Assert-Test ($LASTEXITCODE -eq 0) 'test-owned recorder output created'
    Assert-Test (Test-Path -LiteralPath $output -PathType Leaf) 'synthetic status file exists'
    Assert-Test (-not ($stdout -match [regex]::Escape($scratch))) 'recorder stdout does not expose scratch path'
    Assert-Test ((Get-Item -LiteralPath $output).Length -lt 32768) 'metadata bounded'

    $result=Get-WtFieldStatusOutputAssessment -MetadataPath $output
    Assert-Test ($result.MetadataAcl -eq 'restricted') 'restricted ACL on file inherited from protected parent'
    Assert-Test ($result.PathObservation -eq 'direct_local_observed') 'direct local path observed'
    Assert-Test ($result.SyncAndBackup -eq 'unknown') 'no false negative cloud-sync claim'
    Assert-Test ($result.Decision -eq 'NO_GO') 'readiness remains NO_GO'

    # Synthetic in-memory ACL negative controls: no actual ACL modification.
    $current=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $acl=New-Object System.Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $current))
    $allow=[System.Security.AccessControl.AccessControlType]::Allow
    $full=[System.Security.AccessControl.FileSystemRights]::FullControl
    $none=[System.Security.AccessControl.InheritanceFlags]::None
    $prop=[System.Security.AccessControl.PropagationFlags]::None
    foreach ($sidValue in @($current,'S-1-5-18','S-1-5-32-544') | Select-Object -Unique) {
        $sid=New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $sidValue
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList $sid,$full,$none,$prop,$allow))
    }
    Assert-Test ((Get-WtFieldStatusAclClassification -Acl $acl -CurrentSid $current) -eq 'restricted') 'synthetic clean DACL'
    $everyone=New-Object System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-1-0'
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList $everyone,([System.Security.AccessControl.FileSystemRights]::ReadData),$none,$prop,$allow))
    Assert-Test ((Get-WtFieldStatusAclClassification -Acl $acl -CurrentSid $current) -eq 'review') 'Everyone must not be accepted'
    [void]$acl.RemoveAccessRuleAll((New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList $everyone,([System.Security.AccessControl.FileSystemRights]::ReadData),$none,$prop,$allow))
    $foreignOwner=New-Object System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-21-12345-67890-11223-4444'
    $acl.SetOwner($foreignOwner)
    Assert-Test ((Get-WtFieldStatusAclClassification -Acl $acl -CurrentSid $current) -eq 'review') 'foreign owner refused'

    $missing=Get-WtFieldStatusOutputAssessment -MetadataPath (Join-Path $private 'nonexistent-status.json')
    Assert-Test ($missing.MetadataAcl -eq 'review' -and $missing.Decision -eq 'NO_GO') 'missing file fails closed'

    # A test-owned junction is an optional environmental case. If unsupported,
    # never claim it proves all Windows reparse behavior.
    $junction=Join-Path $scratch 'synthetic-linked'
    $madeJunction=$false
    try {
        New-Item -ItemType Junction -Path $junction -Target $private -ErrorAction Stop | Out-Null
        $madeJunction=$true
    } catch [System.Management.Automation.RuntimeException] {
        Write-Output 'SKIP synthetic junction fixture: unsupported host policy'
    } catch [System.UnauthorizedAccessException] {
        Write-Output 'SKIP synthetic junction fixture: restricted host policy'
    }
    if ($madeJunction) {
        $viaLink=Get-WtFieldStatusOutputAssessment -MetadataPath (Join-Path $junction 'synthetic-status.json')
        Assert-Test ($viaLink.MetadataAcl -eq 'review') 'linked ancestor may not pass ACL audit'
        Assert-Test ($viaLink.PathObservation -eq 'review') 'linked ancestor path not direct'
        # Do not recursively remove the reparse target.
        $j=(Get-Item -LiteralPath $junction -Force)
        Assert-Test (([int]$j.Attributes -band [int][System.IO.FileAttributes]::ReparsePoint) -ne 0) 'fixture link must be reparse point'
        [System.IO.Directory]::Delete($junction)
    }

    # Review command always uses fixed outputs and nonzero NO-GO exit code.
    $exe=[System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $public=@(& $exe -NoProfile -NonInteractive -File (Join-Path $repo 'Test-WtFieldStatusAcl.ps1') -MetadataPath $output 2>&1 | Out-String)
    Assert-Test ($LASTEXITCODE -eq 2) 'CLI always exit code 2'
    Assert-Test ($public -match 'MetadataAcl=restricted;' -and $public -match 'Decision=NO_GO') 'CLI only fixed labels'
    Assert-Test (-not ($public -match [regex]::Escape($scratch))) 'CLI never echoes output location'
    Assert-Test (-not ($public -match [regex]::Escape($current))) 'CLI never prints account SID'
    # The child CLI is *supposed* to exit 2 (NO_GO). Do not propagate its
    # checked expected exit code as the CI test runner's own exit status.
    $global:LASTEXITCODE=0
    Write-Output 'PASS synthetic field-status ACL/privacy boundary (NO_GO only)'
} finally {
    # One GUID-owned test fixture only. Never touch a real diagnostic report.
    if ($cleanupAllowed -and (Test-Path -LiteralPath $scratch -PathType Container)) {
        $possible=Join-Path $scratch 'synthetic-linked'
        if (Test-Path -LiteralPath $possible) {
            $item=Get-Item -LiteralPath $possible -Force
            if (([int]$item.Attributes -band [int][System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                [System.IO.Directory]::Delete($possible)
            }
        }
        Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction Stop
    }
}
