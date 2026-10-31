"""Dependency-free, cross-platform preflight (NOT a PowerShell parser).

Run the actual PowerShell parser/functional tests using tests/Smoke.Tests.ps1 on Windows.
"""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def balanced_powershell(text: str, path: str) -> None:
    """Conservative bracket check outside comments and quoted strings."""
    opens = "([{"
    closing = ")]}"
    pairs = dict(zip(closing, opens))
    stack = []
    state = "code"
    line = 1
    i = 0
    while i < len(text):
        ch = text[i]
        next_ch = text[i + 1] if i + 1 < len(text) else ""
        if ch == "\n":
            line += 1
            if state == "comment":
                state = "code"
        elif state == "comment":
            pass
        elif state == "single":
            if ch == "'" and next_ch == "'":
                i += 1
            elif ch == "'":
                state = "code"
        elif state == "double":
            if ch == "`":
                i += 1
            elif ch == '"':
                state = "code"
        elif state == "block":
            if ch == "#" and next_ch == ">":
                state = "code"
                i += 1
        else:
            if ch == "<" and next_ch == "#":
                state = "block"
                i += 1
            elif ch == "#":
                state = "comment"
            elif ch == "'":
                state = "single"
            elif ch == '"':
                state = "double"
            elif ch == "`":
                i += 1
            elif ch in opens:
                stack.append((ch, line))
            elif ch in closing:
                if not stack or stack[-1][0] != pairs[ch]:
                    raise AssertionError(f"{path}:{line} unbalanced {ch}")
                stack.pop()
        i += 1
    assert not stack, f"{path}: unmatched brackets: {stack}"
    assert state not in ("single", "double", "block"), f"{path}: unterminated {state}"


def check():
    psfiles = sorted(ROOT.rglob("*.ps1")) + sorted(ROOT.rglob("*.psm1"))
    assert len(psfiles) >= 5, "Expected main, publishing, module and tests"
    for file in psfiles:
        balanced_powershell(file.read_text(encoding="utf-8"), str(file.relative_to(ROOT)))

    main = (ROOT / "WinTriage.ps1").read_text(encoding="utf-8")
    core = (ROOT / "src/WinTriage.Core.psm1").read_text(encoding="utf-8")
    hardware = (ROOT / "src/WinTriage.HardwareCollector.psm1").read_text(encoding="utf-8")
    security = (ROOT / "src/WinTriage.SecurityCollector.psm1").read_text(encoding="utf-8")
    if any(ord(ch) > 127 for ch in security):
        assert security.startswith("\ufeff"), "PS 5.1 requires UTF-8 BOM for non-ASCII security module"
    report_security = (ROOT / "src/WinTriage.ReportSecurity.psm1").read_text(encoding="utf-8")
    assert "New-WtPrivateReportDirectory -ParentDirectory $OutputDir -RunId $runId" in main, "Private folder must be created before any report writes"
    assert "Assert-WtNoReportPathReparsePoint -Directory $parent" in report_security, "Report paths must reject NTFS reparse ancestors"
    assert "Assert-WtNoReportPathReparsePoint -Directory $newRun" in report_security, "New folder must be checked for reparse points"
    assert "SetAccessRuleProtection($true,$false)" in report_security, "Private DACL must disable inheritance"
    assert "[WinTriage.NativeReportDirectory]::CreateNew($newRun,$acl.GetSecurityDescriptorBinaryForm())" in report_security, "Report create must reject existing dirs at native boundary"
    native_file = (ROOT / "src/WinTriage.NativeReportDirectory.cs").read_text(encoding="utf-8")
    assert 'EntryPoint = "CreateDirectoryW"' in native_file and "SetLastError = true" in native_file, "Native create-new Win32 interop required"
    assert "error == 183" in native_file, "Native ERROR_ALREADY_EXISTS needs explicit refusal"
    assert "attrs.SecurityDescriptor = nativeDescriptor" in native_file, "Native creation must use supplied security descriptor"
    assert "Marshal.FreeHGlobal(nativeDescriptor)" in native_file, "Native descriptor memory must be released"
    assert "FileSystemAclExtensions]::CreateDirectory" not in report_security, "Do not revert to create-or-open semantics"
    assert "Directory]::CreateDirectory($newRun,$acl)" not in report_security, "Do not revert to create-or-open semantics"
    assert "Set-Acl -LiteralPath $newRun" not in report_security, "Do not create a window with a separate Set-Acl"
    assert "New-Item -ItemType Directory -Path $newRun" not in report_security, "Do not create evidence folders with broad inherited ACL"
    assert "missing a required inheritable full-access rule" in report_security, "ACL verifier must check required full-control rules"
    assert "function Assert-WtPrivateSecurityDescriptor" in report_security, "Security descriptor must be independently testable"
    assert "$Acl.GetOwner($sidType)" in report_security, "Report owner must be validated by SID"
    assert "Report directory has an unexpected owner" in report_security, "Unknown ACL owner must fail closed"
    assert "Assert-WtPrivateSecurityDescriptor -Acl $acl -CurrentSid $current" in report_security, "Live post-create ACL validation must include owner"

    assert "Assert-WtPrivateDirectoryAcl -Directory $newRun" in report_security, "Applied DACL must be checked"
    assert "WinTriage.ReportSecurity.psm1" in main, "Missing report security module import"
    lease = (ROOT / "src/WinTriage.ReportPathLease.cs").read_text(encoding="utf-8")
    assert 'EntryPoint = "CreateFileW"' in lease and 'FILE_FLAG_OPEN_REPARSE_POINT' in lease, "Path lease must open direct directory handles"
    assert "FILE_SHARE_READ | FILE_SHARE_WRITE" in lease and "const uint FILE_SHARE_DELETE" not in lease, "Path lease must exclude delete sharing"
    assert "GetFileInformationByHandle" in lease and "VolumeSerial" in lease and "FileIndexHigh" in lease, "Compare on-disk directory identities"
    assert "lease.AssertStable();" in lease and "lease.Dispose();" in lease, "Lease must verify identity and release on failure"
    assert "AcquireForSyntheticTest" in lease and "if (afterPin != null) afterPin(current);" in lease, "Deterministic synthetic race checkpoint required"
    assert lease.count("lease.AssertStable();") >= 2, "Verify each pinned prefix during acquisition"
    relative_test = (ROOT / "tests/RelativeDirectoryProbe.Tests.ps1").read_text(encoding="utf-8")
    relative_probe = (ROOT / "tests/RelativeDirectoryProbe.cs").read_text(encoding="utf-8")
    assert "IdentifyChildRelative" in relative_test and "PinTestParent" in relative_test and "parent-moved" in relative_test, "Synthetic relative probe must cover held-parent swaps"
    assert "FILE_OPEN," in relative_probe and "FILE_DIRECTORY_FILE" in relative_probe and "FILE_OPEN_REPARSE_POINT" in relative_probe, "Test-only relative directory probing must not create files"
    assert "FILE_CREATE" not in relative_probe and "FILE_OVERWRITE" not in relative_probe, "Research probe must be read-only"
    assert "PinTestParentAllowSyntheticMove" in relative_probe and "FILE_SHARE_DELETE" in relative_probe, "Synthetic-only move mode required"
    assert "FILE_SHARE_DELETE" not in lease, "Production directory lease must not be relaxed by research"
    assert "RelativeDirectoryProbe.cs" not in (ROOT / "src/WinTriage.ReportSecurity.psm1").read_text(encoding="utf-8"), "Research probe must not be imported in production"
    assert "RelativeDirectoryProbe.Tests.ps1" in (ROOT / ".github/workflows/smoke.yml").read_text(encoding="utf-8"), "Research probe CI missing"
    assert "RelativeDirectoryProbe.Tests.ps1" in (ROOT / "Validate-Windows.ps1").read_text(encoding="utf-8"), "Research probe local validator missing"
    handle_acl_probe = (ROOT / "tests/HandleSecurityProbe.cs").read_text(encoding="utf-8")
    handle_acl_test = (ROOT / "tests/HandleSecurityProbe.Tests.ps1").read_text(encoding="utf-8")
    assert "GetKernelObjectSecurity" in handle_acl_probe and "READ_CONTROL" in handle_acl_probe and "OWNER_SECURITY_INFORMATION" in handle_acl_probe and "DACL_SECURITY_INFORMATION" in handle_acl_probe, "Test-only handle ACL query must use documented owner/DACL rights"
    assert "OPEN_EXISTING" in handle_acl_probe and "FILE_FLAG_OPEN_REPARSE_POINT" in handle_acl_probe and "SetSecurityDescriptorBinaryForm" in handle_acl_probe, "Handle ACL fixture must read only existing direct directories"
    assert "FILE_CREATE" not in handle_acl_probe and "FILE_OVERWRITE" not in handle_acl_probe, "ACL research interop must never create or overwrite report files"
    assert "Assert-WtPrivateSecurityDescriptor" in handle_acl_test and "PinWithoutReadControlForNegativeTest" in handle_acl_test and "decoy" in handle_acl_test, "Synthetic security descriptor attack fixtures missing"
    assert "HandleSecurityProbe.cs" not in report_security and "HandleSecurityProbe.cs" not in main, "No research native import in production"
    assert "HandleSecurityProbe.Tests.ps1" in (ROOT / ".github/workflows/smoke.yml").read_text(encoding="utf-8"), "Handle ACL fixture CI missing"
    assert "HandleSecurityProbe.Tests.ps1" in (ROOT / "Validate-Windows.ps1").read_text(encoding="utf-8"), "Handle ACL local validator missing"
    create_probe = (ROOT / "tests/DirectoryCreationProbe.cs").read_text(encoding="utf-8")
    create_test = (ROOT / "tests/DirectoryCreationProbe.Tests.ps1").read_text(encoding="utf-8")
    assert 'FILE_CREATE' in create_probe and 'FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT' in create_probe, "Research create must use exclusive documented directory flags"
    assert 'attrs.RootDirectory = ' not in create_probe and 'attributes.RootDirectory = parent.DangerousGetHandle()' in create_probe, "Research creation must use pinned parent"
    assert 'attributes.SecurityDescriptor = securityPointer' in create_probe and 'FILE_ADD_SUBDIRECTORY' in create_probe, "Research creation must bind ACL and parent right"
    assert 'FILE_OPEN_REPARSE_POINT' not in create_probe and 'FILE_OPEN_IF' not in create_probe and 'FILE_OVERWRITE' not in create_probe, "Research must avoid unsupported directory creation combinations"
    assert 'Assert-WtPrivateSecurityDescriptor' in create_test and 'parent-moved' in create_test and 'FILE_CREATE must refuse' in create_test, "Synthetic relative creation tests missing"
    assert 'DirectoryCreationProbe.cs' not in report_security and 'DirectoryCreationProbe.cs' not in main, "Research native creation imported into production"
    assert 'DirectoryCreationProbe.Tests.ps1' in (ROOT / ".github/workflows/smoke.yml").read_text(encoding="utf-8"), "Research create CI missing"
    assert 'DirectoryCreationProbe.Tests.ps1' in (ROOT / "Validate-Windows.ps1").read_text(encoding="utf-8"), "Research create validator missing"
    chain_probe = (ROOT / "tests/HandleChainProbe.cs").read_text(encoding="utf-8")
    chain_fixture = (ROOT / "tests/HandleChainProbe.Tests.ps1").read_text(encoding="utf-8")
    assert "FILE_OPEN_REPARSE_POINT" in chain_probe and "FILE_DIRECTORY_FILE" not in chain_probe, "Research walk must be type-neutral and request no-follow"
    assert "attributes.RootDirectory = parent.DangerousGetHandle()" in chain_probe and "FILE_OPEN," in chain_probe and "FILE_CREATE" not in chain_probe, "Each hop must open under its held parent only"
    assert "FILE_ATTRIBUTE_REPARSE_POINT" in chain_probe and "FILE_ATTRIBUTE_DIRECTORY" in chain_probe and "held.RemoveAt(held.Count - 1)" in chain_probe, "Research hop check and handle lifetime missing"
    assert "Assert-WtPrivateSecurityDescriptor" in chain_fixture and "CreateChildRelative" in chain_fixture and "anchor-moved" in chain_fixture, "Synthetic multi-hop create test missing"
    assert "HandleChainProbe.cs" not in main and "HandleChainProbe.cs" not in report_security, "Research code must not be imported into production"
    assert "Get-SyntheticPathIdentity" in chain_fixture and "IdentifyTestDirectory" not in chain_fixture, "Path identity fixture must use verified local pinned-handle helper"
    assert "HandleChainProbe.Tests.ps1" in (ROOT / ".github/workflows/smoke.yml").read_text(encoding="utf-8"), "CI missing synthetic handle chain"
    assert "HandleChainProbe.Tests.ps1" in (ROOT / "Validate-Windows.ps1").read_text(encoding="utf-8"), "Local validation missing synthetic handle chain"
    anchor_probe = (ROOT / "tests/HandleChainProbe.cs").read_text(encoding="utf-8")
    anchor_fixture = (ROOT / "tests/AnchorRace.Tests.ps1").read_text(encoding="utf-8")
    assert "PinSyntheticAnchorExpectIdentity" in anchor_probe and "String.Equals(Identity(handle), trustedId" in anchor_probe, "Test anchor must verify the returned handle against independent identity"
    assert "WalkWithSyntheticBeforeHop" in anchor_probe and "if (beforeHop != null) beforeHop(index)" in anchor_probe, "Synthetic pre-open interleaving seam missing"
    assert "PinSyntheticAnchorExpectIdentity" in anchor_fixture and "pre-pin path substitution refused" in anchor_fixture, "Synthetic anchor spoofing test missing"
    assert "New-Item -ItemType Junction" in anchor_fixture and "pre-open junction substitution failed closed" in anchor_fixture, "Synthetic pre-hop junction fixture missing"
    assert "[System.IO.Directory]::Delete($middle)" in anchor_fixture and "ReparsePoint" in anchor_fixture, "Synthetic junction cleanup must be non-recursive and guard its link"
    assert "AnchorRace.Tests.ps1" in (ROOT / ".github/workflows/smoke.yml").read_text(encoding="utf-8"), "Anchor race CI coverage missing"
    assert "AnchorRace.Tests.ps1" in (ROOT / "Validate-Windows.ps1").read_text(encoding="utf-8"), "Anchor race local validation missing"
    assert "HandleChainProbe.cs" not in main and "HandleChainProbe.cs" not in report_security, "Experimental native code must stay out of production"
    root_probe = (ROOT / "tests/RootPathPolicyProbe.cs").read_text(encoding="utf-8")
    root_fixture = (ROOT / "tests/RootedChain.Tests.ps1").read_text(encoding="utf-8")
    assert "SplitStrictDrivePath" in root_probe and "IsFixedNtfsVolumeForResearch" in root_probe, "Root policy and volume classification missing"
    assert '@"^[A-Za-z]:\\' in root_probe and "Reserved DOS device" in root_probe and "Path.GetFullPath" in root_probe, "Root path must reject unsafe spelling before normalization"
    assert "PinReadOnlySyntheticVolumeRoot" in chain_probe and "WalkRootReadOnly" in chain_probe, "Test-only least-privilege root traversal missing"
    assert "FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE" in chain_probe, "Read-only chain must not request directory creation rights"
    assert "rooted chain rejected synthetic reparse hop" in root_fixture.lower() and "SplitStrictDrivePath" in root_fixture, "Synthetic rooted chain fixture incomplete"
    assert "[System.IO.Directory]::Delete($junction)" in root_fixture and "ReparsePoint" in root_fixture, "Junction cleanup must be guarded, nonrecursive"
    assert "RootPathPolicyProbe.cs" not in report_security and "RootPathPolicyProbe.cs" not in main, "Research path policy imported in production"
    assert "RootedChain.Tests.ps1" in (ROOT / ".github/workflows/smoke.yml").read_text(encoding="utf-8"), "Rooted CI coverage missing"
    assert "RootedChain.Tests.ps1" in (ROOT / "Validate-Windows.ps1").read_text(encoding="utf-8"), "Rooted local validation missing"
    volume_probe = (ROOT / "tests/VolumeIdentityProbe.cs").read_text(encoding="utf-8")
    volume_fixture = (ROOT / "tests/VolumeIdentityProbe.Tests.ps1").read_text(encoding="utf-8")
    assert "GetFileInformationByHandleEx" in volume_probe and "FileIdInfo = 18" in volume_probe and "FILE_ID_INFO_BYTES = 24" in volume_probe, "Native 128-bit file/volume identity required"
    assert "Marshal.Copy(buffer, result" in volume_probe and "Marshal.FreeHGlobal(buffer)" in volume_probe, "Identity native buffer must be bounded and disposed"
    assert "GetFinalPathNameByHandleW" in volume_probe and "VOLUME_NAME_GUID" in volume_probe, "Optional handle volume-GUID lookup missing"
    assert "RequireFileIdentity" in volume_probe and "RequireVolumeSerial" in volume_probe, "Full file identity and volume identity comparison must be separate"
    assert "same-volume decoy kept serial but failed full 128-bit file identity check" in volume_fixture, "Synthetic same-volume decoy rejection missing"
    assert "GetFileInformationByHandleEx" not in report_security and "VolumeIdentityProbe.cs" not in main and "VolumeIdentityProbe.cs" not in report_security, "Test-only native file ID query imported into production"
    assert "VolumeIdentityProbe.Tests.ps1" in (ROOT / ".github/workflows/smoke.yml").read_text(encoding="utf-8"), "Volume fingerprint CI missing"
    assert "VolumeIdentityProbe.Tests.ps1" in (ROOT / "Validate-Windows.ps1").read_text(encoding="utf-8"), "Volume fingerprint local validator missing"
    lease_probe = (ROOT / "tests/SyntheticAnchorLease.cs").read_text(encoding="utf-8")
    lease_fixture = (ROOT / "tests/SyntheticAnchorLease.Tests.ps1").read_text(encoding="utf-8")
    assert "VolumeIdentityProbe.FileIdentity(reference)" in lease_probe and "VolumeIdentityProbe.RequireFileIdentity(reference, baselineFileId)" in lease_probe and "VolumeIdentityProbe.RequireFileIdentity(candidate, baselineFileId)" in lease_probe, "Lease must use full held-handle file ID for reference and candidate"
    assert "sessionEpoch == Guid.Empty" in lease_probe and "revoked" in lease_probe and "reference.IsClosed" in lease_probe, "Lease must enforce explicit session lifecycle and borrowed-reference validity"
    assert "Object.ReferenceEquals(reference, candidate)" in lease_probe and "public void Dispose()" in lease_probe, "Lease must refuse identical reference handle and allow explicit revocation"
    assert "synthetic self-consistent decoy shows identity alone cannot authenticate source" in lease_fixture and "disposed synthetic reference invalidates borrowed baseline" in lease_fixture, "Negative control and expired reference missing"
    assert "Add-Type -Path $sourcePaths" in lease_fixture and "HandleChainProbe.cs\',\'VolumeIdentityProbe.cs\',\'SyntheticAnchorLease.cs" in lease_fixture, "PowerShell 5.1 Add-Type must compile dependent C# files together"
    assert "SyntheticAnchorLease.cs" not in main and "SyntheticAnchorLease.cs" not in report_security, "Research trust lease imported into production"
    assert "SyntheticAnchorLease.Tests.ps1" in (ROOT / ".github/workflows/smoke.yml").read_text(encoding="utf-8"), "Anchor lease CI missing"
    assert "SyntheticAnchorLease.Tests.ps1" in (ROOT / "Validate-Windows.ps1").read_text(encoding="utf-8"), "Anchor lease local validator missing"
    field_gate = (ROOT / "tools/field_evidence_gate.py").read_text(encoding="utf-8")
    field_gate_test = (ROOT / "tests/FieldEvidenceGate.Tests.py").read_text(encoding="utf-8")
    assert '"decision": "NO_GO"' in field_gate and 'return 2' in field_gate and 'MANUAL_APPROVAL_REQUIRED' in field_gate, "Field gate must never imply automated release approval"
    assert '"no_authenticated_external_release_approval"' in field_gate and 'MAX_FILE_BYTES = 32768' in field_gate, "Reject unauthenticated approval and large metadata"
    assert 'test_complete_self_asserted_is_still_no_go' in field_gate_test and 'test_native_scan_in_passive_mode_blocks' in field_gate_test and 'test_duplicate_row_and_extra_sensitive_field_are_invalid' in field_gate_test, "Negative gate tests missing"
    assert (ROOT / "docs/field-evidence-template.json").is_file(), "Pending-only evidence template missing"
    assert '"not_run"' in (ROOT / "docs/field-evidence-template.json").read_text(encoding="utf-8"), "Field evidence template must start pending"
    ci_text = (ROOT / ".github/workflows/smoke.yml").read_text(encoding="utf-8")
    assert ci_text.count("python tests/FieldEvidenceGate.Tests.py") == 2, "Both Windows jobs must run synthetic field evidence gate tests"
    assert "field_evidence_gate.py" not in main and "field_evidence_gate.py" not in report_security, "No production import of field gate"
    race_test = (ROOT / "tests/ReportPathAcquisition.Tests.ps1").read_text(encoding="utf-8")
    assert "AcquireForSyntheticTest" in race_test and "VisitedRun" in race_test, "Synthetic interleaving must detect parent swap before child traversal"
    assert "ReportPathAcquisition.Tests.ps1" in (ROOT / ".github/workflows/smoke.yml").read_text(encoding="utf-8"), "Acquisition race CI missing"
    assert "ReportPathAcquisition.Tests.ps1" in (ROOT / "Validate-Windows.ps1").read_text(encoding="utf-8"), "Local acquisition race test missing"
    assert "function Enter-WtReportPathLease" in report_security, "Report path lease entrypoint missing"
    assert "$reportPathLease = Enter-WtReportPathLease -Directory $runDir" in main, "Acquire path lease before collecting evidence"
    assert "$reportPathLease.Dispose()" in main, "Release path lease even on failure"
    assert "$script:reportPathLease.AssertStable()" in main, "Validate pinned directory before report writes"
    native_writer = (ROOT / "src/WinTriage.HandleBoundReportWriter.cs").read_text(encoding="utf-8")
    assert 'DllImport("ntdll.dll"' in native_writer and 'NtCreateFile(' in native_writer, "Handle-bound user-mode creation required"
    assert "attrs.RootDirectory = directory.DangerousGetHandle()" in native_writer, "Native report file must use pinned RootDirectory"
    assert "FILE_CREATE," in native_writer and "FILE_NON_DIRECTORY_FILE" in native_writer, "New regular file only, no overwrite/reuse"
    assert "AllowedNames" in native_writer and "Marshal.FreeHGlobal" in native_writer and "DangerousRelease()" in native_writer, "Constrain file names and release unmanaged resources"
    assert "OpenNewUtf8Writer(" in native_writer and "OpenNewUtf8Writer(string leafName" in lease, "Pinned streaming log factory required"
    assert all(name in native_writer for name in ('"clamav-output.txt"', '"sfc-verifyonly.txt"', '"dism-scanhealth.txt"')), "Optional native log allowlist missing"
    assert "LogWriterFactory $nativeLogWriterFactory" in main, "CLI must supply pinned native output sink"
    assert "WriteNewUtf8(string leafName" in lease and "HandleBoundReportWriter.WriteNewUtf8" in lease, "Lease must bind core report file writes"
    assert "WinTriage.HandleBoundReportWriter.cs" in report_security and "WinTriage.ReportPathLease.cs" in report_security, "Compile new writer with lease"
    assert "WriteNewUtf8('manifest.json'" in main and "WriteNewUtf8('SUMMARY.md'" in main, "Core manifest and summary must be handle-relative"
    assert "$script:reportPathLease.WriteNewUtf8($Name" in main, "Core JSON/CSV writes must be handle-relative"
    for obsolete_write in ("Out-File -FilePath", "Export-Csv -Path", "Set-Content -LiteralPath"):
        assert obsolete_write not in main, f"Core report must not revert to path-only writer: {obsolete_write}"


    retention = (ROOT / "src/WinTriage.ReportRetention.psm1").read_text(encoding="utf-8")
    retention_cli = (ROOT / "Get-WtReportRetention.ps1").read_text(encoding="utf-8")
    assert "Assert-WtNoReportPathReparsePoint -Directory $root" in retention, "Retention must reject path indirection"
    assert "Assert-WtPrivateDirectoryAcl -Directory $folder.FullName" in retention, "Retention must verify permissions"
    assert "Select-Object -First ($MaxRuns + 1)" in retention, "Retention enumeration must be bounded"
    assert "Select-Object -First ($MaxEntriesPerRun + 1)" in retention, "Per-report metadata enumeration must be bounded"
    assert "Get-WtReportRetentionSummary" in retention_cli, "CLI must use metadata-only report inspector"
    assert "Assert-WtNoReportPathReparsePoint" in report_security.split("Export-ModuleMember")[-1], "Safe path check must be available to audit"
    for forbidden in ("Remove-Item", "Delete(", "Set-Content", "Set-Acl", "Export-Csv", "Invoke-Expression", "ConvertFrom-Json", "Start-MpScan", "sfc.exe", "dism.exe"):
        assert forbidden not in retention and forbidden not in retention_cli, f"Retention must be read-only: {forbidden}"
    field_script = (ROOT / "Invoke-WtFieldValidation.ps1").read_text(encoding="utf-8")
    field_mod = (ROOT / "src/WinTriage.FieldValidation.psm1").read_text(encoding="utf-8")
    assert "Get-WtFieldValidationAssessment" in field_script and "Assert-WtReportContract" in field_script, "Field verification must enforce report contract"
    assert "Assert-WtPrivateDirectoryAcl" in field_script, "Field verification must enforce private ACL"
    assert "if ($mode -eq 'Monitor')" in field_script, "Manual validation should include bounded Monitor sampling"
    for forbidden in ("-RunDefenderQuickScan", "-RunClamAV", "-RunSfcVerifyOnly", "-RunDismScanHealth", "Invoke-Expression"):
        assert forbidden not in field_script, f"Manual validation must be passive: {forbidden}"
    field_e2e = (ROOT / "tests/FieldValidation.Integration.Tests.ps1").read_text(encoding="utf-8")
    assert "Invoke-WtFieldValidation.ps1" in field_e2e and "Assert-WtReportContract" in field_e2e, "Field runner must be tested end to end"
    assert "Assert-WtPrivateDirectoryAcl" in field_e2e, "E2E must check private report ACLs"
    assert "SYNTHETIC_SECRET_HOST" not in field_mod, "Pure validation module must never contain personal data"
    assert "ToolVersion='0.3.1'" in main
    assert "-Mode Integrity" in (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Get-WtStorageAssessment" in core
    # PR #8 moved the read-only storage call behind the hardware collector boundary.
    assert "WinTriage.HardwareCollector.psm1" in main, "Entrypoint must import hardware collector"
    assert "Get-StorageReliabilityCounter -PhysicalDisk" in hardware, "Missing read-only storage provider in hardware collector"
    for forbidden in ("Clear-Disk", "Reset-PhysicalDisk", "Initialize-Disk", "Format-Volume", "Remove-Partition", "Set-PhysicalDisk"):
        assert forbidden not in hardware, f"Unexpected storage mutation command in hardware collector: {forbidden}"
    assert "WinTriage.IntegrityCollector.psm1" in main, "Entrypoint must import explicit integrity module"
    assert "Get-WtIntegrity -Warnings $warnings -RecordedFiles $nativeFiles" in main, "CLI must supply warnings and log-file sink"
    integrity = (ROOT / "src/WinTriage.IntegrityCollector.psm1").read_text(encoding="utf-8")
    if any(ord(ch) > 127 for ch in integrity):
        assert integrity.startswith("\ufeff"), "PS 5.1 requires UTF-8 BOM for non-ASCII integrity module"
    assert "if (-not $item.Flag)" in integrity, "Native integrity verification must be opt-in"
    assert "Administrator=(Test-WtAdministrator" in integrity, "Admin check must evaluate"
    assert "if (-not $status.Administrator)" in integrity, "Native verification requires admin"
    assert "Get-Command -Name $Executable -CommandType Application" in integrity, "Native resolver must select applications"
    assert "'/verifyonly'" in integrity and "'/Online','/Cleanup-Image','/ScanHealth'" in integrity, "Allowed native args must be fixed and verify-only"
    for bad in ("Invoke-Expression", "'/scannow'", "'/RestoreHealth'", "'Clear-Disk'", "'Reset-PhysicalDisk'"):
        assert bad not in integrity, f"Unexpected integrity mutation command: {bad}"
    assert "Get-WtSecurityEvidence -Warnings $warnings" in main, "Entrypoint must use read-only Defender collector"
    for forbidden in ("Start-MpScan", "clamscan.exe", "--remove", "--move"):
        assert forbidden not in security, f"Passive collector must not invoke scanners: {forbidden}"
    scan_executor = (ROOT / "src/WinTriage.ScanExecutor.psm1").read_text(encoding="utf-8")
    if any(ord(ch) > 127 for ch in scan_executor):
        assert scan_executor.startswith("\ufeff"), "PS 5.1 requires UTF-8 BOM for non-ASCII scan executor"
    assert "WinTriage.ScanExecutor.psm1" in main, "CLI must import explicit scan executor"
    assert "Invoke-WtRequestedScans -SecurityEvidence $s" in main, "CLI must forward only explicit scan flags"
    assert "if (-not $RunDefenderQuickScan -and -not $RunClamAV)" in scan_executor, "No-op passive scan boundary required"
    assert "LogWriterFactory" in scan_executor and "LogWriterFactory" in integrity, "Native executors must accept secure log stream factory"
    assert "Out-File -LiteralPath $LogPath" not in scan_executor and "Out-File -LiteralPath $LogPath" not in integrity, "No path-based native log output"
    assert "$LogWriter.WriteLine" in scan_executor and "$LogWriter.WriteLine" in integrity, "Native stdout must stream to injected TextWriter"
    assert "Start-MpScan -ScanType QuickScan -ErrorAction Stop" in scan_executor, "Only fixed Defender QuickScan request supported"
    assert "& $Source '--recursive=yes' '--infected' $ScanPath" in scan_executor, "ClamAV must remain detection-only"
    for forbidden in ("Invoke-Expression", "'--remove'", "'--move'", "'--copy'", "'--tempdir'"):
        assert forbidden not in scan_executor, f"Destructive or unapproved ClamAV action: {forbidden}"
    assert "-RunDefenderQuickScan" in main
    print(f"PASS static preflight: {len(psfiles)} PowerShell files, structural brackets, safety invariants")
    print("NOTE: this is NOT syntax/runtime validation; execute Windows smoke and integration tests.")


if __name__ == "__main__":
    try:
        check()
    except Exception as ex:
        print("FAIL:", ex, file=sys.stderr)
        sys.exit(1)
