#requires -Version 5.1
# Synthetic temporary directories only; never touches existing diagnostic reports.
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows ACL checks require Windows.' }
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'src\WinTriage.ReportSecurity.psm1') -Force
function Assert-WtValue { param($Actual,$Expected,[string]$Label)
    if ($Actual -ne $Expected) { throw ("{0}: expected {1}, got {2}" -f $Label,$Expected,$Actual) }
}
function Expect-Failure { param([scriptblock]$Action,[string]$Label)
    $failed=$false
    try { & $Action | Out-Null } catch { $failed=$true }
    Assert-WtValue $failed $true $Label
}
$parent=Join-Path ([System.IO.Path]::GetTempPath()) ('wt-acl-fixture-' + [guid]::NewGuid().ToString('N'))
try {
    $run=New-WtPrivateReportDirectory -ParentDirectory $parent -RunId 'SYNTHETIC_RUN_123'
    Assert-WtValue (Test-Path -LiteralPath $run -PathType Container) $true 'directory created'
    Assert-WtValue (Assert-WtPrivateDirectoryAcl -Directory $run) $true 'private access verified'
    # Directly exercise the native boundary: an *already private* directory
    # must still be rejected. An ACL match never licenses reusing that run.
    $privateSddl=(Get-Acl -LiteralPath $run).Sddl
    $descriptor=(Get-Acl -LiteralPath $run).GetSecurityDescriptorBinaryForm()
    Expect-Failure { [WinTriage.NativeReportDirectory]::CreateNew($run,$descriptor) } 'native collision refuses even matching DACL'
    Assert-WtValue (Get-Acl -LiteralPath $run).Sddl $privateSddl 'native collision preserves original ACL'
    $acl=Get-Acl -LiteralPath $run
    Assert-WtValue $acl.AreAccessRulesProtected $true 'report inheritance disabled'
    # New directory must be private from the first observable instant. The
    # production creator never invokes Set-Acl after creating this run dir.
    $mandatory=@([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544') | Select-Object -Unique
    $readable=@($acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]))
    foreach ($sid in $mandatory) {
        $matches=@($readable | Where-Object {
            $_.IdentityReference.Value -eq $sid -and
            ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -eq [System.Security.AccessControl.FileSystemRights]::FullControl -and
            ($_.InheritanceFlags -band ([System.Security.AccessControl.InheritanceFlags]::ObjectInherit -bor [System.Security.AccessControl.InheritanceFlags]::ContainerInherit)) -eq ([System.Security.AccessControl.InheritanceFlags]::ObjectInherit -bor [System.Security.AccessControl.InheritanceFlags]::ContainerInherit)
        })
        if ($matches.Count -lt 1) { throw 'Missing required inheritable FullControl security rule in new directory' }
    }
    $current=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $allowed=@($current,'S-1-5-18','S-1-5-32-544')
    $rules=@($acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]))
    foreach ($rule in $rules) {
        if ($rule.IdentityReference.Value -notin $allowed) { throw 'Unexpected access principal in fixture' }
    }
    # Hold root-to-run handles for the entire collection lifetime. A rename
    # attempted by another process must fail until the lease is disposed.
    $lease=Enter-WtReportPathLease -Directory $run
    $renamed=Join-Path $parent 'SYNTHETIC_RENAMED_RUN'
    try {
        $lease.AssertStable()
        Expect-Failure { [System.IO.Directory]::Move($run,$renamed) } 'leased run cannot be renamed'
        $renamedParent=$parent + '-renamed'
        Expect-Failure { [System.IO.Directory]::Move($parent,$renamedParent) } 'leased ancestor cannot be renamed'
        Assert-WtValue (Test-Path -LiteralPath $run -PathType Container) $true 'run still at its original path'
    } finally {
        $lease.Dispose()
    }
    Expect-Failure { $lease.AssertStable() } 'disposed guard rejects use'
    # Once the guard releases its handles, test-owned directories can be
    # renamed again. This confirms no handle leakage on the success path.
    [System.IO.Directory]::Move($run,$renamed)
    Assert-WtValue (Test-Path -LiteralPath $renamed -PathType Container) $true 'rename allowed after dispose'
    [System.IO.Directory]::Move($renamed,$run)
    [void](Assert-WtPrivateDirectoryAcl -Directory $run)

    # Verify owner identity, not only the DACL. An unauthorized owner can
    # change access rules even if every listed DACL principal is trusted.
    $realOwner=$acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($realOwner -notin $allowed) { throw 'Unexpected owner on newly created private folder' }
    $selfSid=New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $current
    $foreignSid=New-Object System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-21-123456-789012-345678-1001'
    $full=[System.Security.AccessControl.FileSystemRights]::FullControl
    $inherit=[System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $none=[System.Security.AccessControl.PropagationFlags]::None
    $allow=[System.Security.AccessControl.AccessControlType]::Allow
    $deny=[System.Security.AccessControl.AccessControlType]::Deny

    function New-SyntheticDescriptor {
        param([string]$OwnerSid,[bool]$SkipSystem=$false)
        $descriptor=New-Object System.Security.AccessControl.DirectorySecurity
        $descriptor.SetAccessRuleProtection($true,$false)
        $descriptor.SetOwner((New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $OwnerSid))
        foreach ($identity in (@($current,'S-1-5-18','S-1-5-32-544') | Select-Object -Unique)) {
            if ($SkipSystem -and $identity -eq 'S-1-5-18') { continue }
            $who=New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $identity
            $descriptor.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList $who,$full,$inherit,$none,$allow))
        }
        return $descriptor
    }
    $normal=New-SyntheticDescriptor -OwnerSid $current
    Assert-WtValue (Assert-WtPrivateSecurityDescriptor -Acl $normal -CurrentSid $current) $true 'synthetic allowlisted descriptor'
    $adminOwner=New-SyntheticDescriptor -OwnerSid 'S-1-5-32-544'
    Assert-WtValue (Assert-WtPrivateSecurityDescriptor -Acl $adminOwner -CurrentSid $current) $true 'managed administrator ownership accepted'
    $foreignOwner=New-SyntheticDescriptor -OwnerSid $foreignSid.Value
    Expect-Failure { Assert-WtPrivateSecurityDescriptor -Acl $foreignOwner -CurrentSid $current } 'foreign owner must fail closed'
    $missingSystem=New-SyntheticDescriptor -OwnerSid $current -SkipSystem $true
    Expect-Failure { Assert-WtPrivateSecurityDescriptor -Acl $missingSystem -CurrentSid $current } 'required system SID missing'
    $extraPrincipal=New-SyntheticDescriptor -OwnerSid $current
    $extraPrincipal.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList $foreignSid,$full,$inherit,$none,$allow))
    Expect-Failure { Assert-WtPrivateSecurityDescriptor -Acl $extraPrincipal -CurrentSid $current } 'unapproved group rule'
    $denied=New-SyntheticDescriptor -OwnerSid $current
    $denied.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList $selfSid,([System.Security.AccessControl.FileSystemRights]::ReadData),$inherit,$none,$deny))
    Expect-Failure { Assert-WtPrivateSecurityDescriptor -Acl $denied -CurrentSid $current } 'unexpected deny rule'
    $inherited=New-SyntheticDescriptor -OwnerSid $current
    $inherited.SetAccessRuleProtection($false,$false)
    Expect-Failure { Assert-WtPrivateSecurityDescriptor -Acl $inherited -CurrentSid $current } 'inherited descriptor protection disabled'

    # Children should inherit the private directory's new DACL.
    $file=Join-Path $run 'invented.json'
    Set-Content -LiteralPath $file -Value '{"Synthetic":true}' -Encoding UTF8
    $fileAcl=Get-Acl -LiteralPath $file
    foreach ($rule in @($fileAcl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]))) {
        if ($rule.IdentityReference.Value -notin $allowed) { throw 'Report file got broad inherited access' }
    }
    Expect-Failure { New-WtPrivateReportDirectory -ParentDirectory $parent -RunId 'SYNTHETIC_RUN_123' } 'run cannot be reused'
    # An already existing unprotected directory must NEVER be "fixed" or reused.
    $preexisting=Join-Path $parent 'SYNTHETIC_PREEXISTING'
    New-Item -ItemType Directory -Path $preexisting -ErrorAction Stop | Out-Null
    $beforeAcl=(Get-Acl -LiteralPath $preexisting).Sddl
    Expect-Failure { New-WtPrivateReportDirectory -ParentDirectory $parent -RunId 'SYNTHETIC_PREEXISTING' } 'preexisting folder is never retouched'
    Assert-WtValue (Get-Acl -LiteralPath $preexisting).Sddl $beforeAcl 'existing folder ACL unchanged'
    Assert-WtValue (Get-Content -LiteralPath $file -Raw -Encoding UTF8).Contains('Synthetic') $true 'collision leaves old report untouched'
    Expect-Failure { New-WtPrivateReportDirectory -ParentDirectory $parent -RunId '..\outside' } 'directory traversal denied'
    Expect-Failure { New-WtPrivateReportDirectory -ParentDirectory '\\fictional-server\share' -RunId 'SYNTHETIC_RUN_234' } 'UNC report path denied'
    # ACL verification is fail-closed on an ordinary inherited directory.
    $openDirectory=Join-Path $parent 'deliberately-inherited'
    New-Item -ItemType Directory -Path $openDirectory -Force | Out-Null
    Expect-Failure { Assert-WtPrivateDirectoryAcl -Directory $openDirectory } 'inherited access is not private'

    # A junction is an NTFS reparse point even when its target is a local folder.
    # This fixture uses only test-owned folders. Some environments disallow
    # junction creation; in that case the invariant remains enforced in code.
    $junction=Join-Path $parent 'synthetic-junction'
    $junctionCreated=$false
    try {
        New-Item -ItemType Junction -Path $junction -Target $run -ErrorAction Stop | Out-Null
        $junctionCreated=$true
    } catch {
        Write-Host 'SKIP: this runner cannot create an NTFS junction fixture'
    }
    if ($junctionCreated) {
        try {
            Expect-Failure { New-WtPrivateReportDirectory -ParentDirectory $junction -RunId 'SYNTHETIC_RUN_999' } 'reparse-point ancestry forbidden'
            if (Test-Path -LiteralPath (Join-Path $run 'SYNTHETIC_RUN_999')) {
                throw 'A private report was created through a junction'
            }
        } finally {
            # Remove the link itself only; never delete or follow its target.
            # Windows PowerShell 5.1 Remove-Item may throw NullReferenceException
            # for an NTFS junction. Directory.Delete removes the link itself.
            [System.IO.Directory]::Delete($junction)
            if (-not (Test-Path -LiteralPath $run -PathType Container)) {
                throw 'Junction cleanup unexpectedly removed its target'
            }
        }
    }
    # Race two independent Windows PowerShell workers against a synthetic,
    # pre-created parent. Exactly one run may be created; no reuse allowed.
    # The race is test-owned only; no Windows telemetry or real reports touched.
    $raceParent=Join-Path $parent 'race-root'
    New-Item -ItemType Directory -Path $raceParent -ErrorAction Stop | Out-Null
    $module=Join-Path $root 'src\WinTriage.ReportSecurity.psm1'
    $jobs=@()
    try {
        foreach ($index in 1..2) {
            $jobs+=Start-Job -ScriptBlock {
                param($modulePath,$outputRoot)
                $ErrorActionPreference='Stop'
                Import-Module -Name $modulePath -Force -ErrorAction Stop
                try {
                    [void](New-WtPrivateReportDirectory -ParentDirectory $outputRoot -RunId 'SYNTHETIC_RACE_101')
                    'created'
                } catch {
                    # Fixed output only, never emit exceptions or report paths.
                    'rejected'
                }
            } -ArgumentList $module,$raceParent
        }
        [void](Wait-Job -Job $jobs -Timeout 90)
        if (@($jobs | Where-Object State -ne 'Completed').Count -ne 0) {
            throw 'Concurrent synthetic creator jobs did not complete'
        }
        $results=@($jobs | Receive-Job -ErrorAction Stop)
        Assert-WtValue @($results | Where-Object { $_ -eq 'created' }).Count 1 'only one exclusive creator'
        Assert-WtValue @($results | Where-Object { $_ -eq 'rejected' }).Count 1 'losing concurrent creator rejected'
        $raceRun=Join-Path $raceParent 'SYNTHETIC_RACE_101'
        Assert-WtValue (Assert-WtPrivateDirectoryAcl -Directory $raceRun) $true 'raced result remains protected'
    } finally {
        foreach ($job in $jobs) {
            if ($job.State -in @('Running','NotStarted')) { Stop-Job -Job $job -ErrorAction SilentlyContinue }
        }
        if ($jobs.Count -gt 0) { Remove-Job -Job $jobs -Force -ErrorAction SilentlyContinue }
    }
    Write-Host 'PASS native exclusive report creation, synthetic creator race, ACL, collision, traversal, UNC and reparse rejection'
} finally {
    if (Test-Path -LiteralPath $parent) { Remove-Item -LiteralPath $parent -Recurse -Force }
}
