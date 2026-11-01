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
    # ADR-038: claims never turn synthetic root provenance into release authority.
    # ADR-039: two-sheet manual handoff cannot elevate self-asserted status.
    # ADR-040: no user-supplied raw field data may enter the fixture index.
    triage = (ROOT / "tools/field_failure_triage.py").read_text(encoding="utf-8")
    triage_tests = (ROOT / "tests/FieldFailureTriage.Tests.py").read_text(encoding="utf-8")
    assert "CASES:" in triage and '"decision": "NO_GO"' in triage and "return 2" in triage, "Field triage must be enum only, NO_GO"
    assert "add_help=False" in triage and "raise ValueError" in triage, "CLI must not echo private malformed arguments or return release-approval success"
    assert '"physical_evidence": "UNVERIFIED"' in triage and '"public_disclosure": "REVIEW_REQUIRED"' in triage, "Synthetic refs cannot attest physical device evidence"
    assert '"synthetic_fixture": "NONE"' in triage and "PRIVATE_MANUAL_REVIEW_ONLY" in triage, "Unknown and managed-storage cases must fail closed"
    assert "test_all_cases_refer_only_to_existing_allowlisted_synthetic_fixtures" in triage_tests and "test_invalid_cli_args_missing_unknown_extra_and_help_never_leak" in triage_tests, "Synthetic allowlist and privacy CLI tests required"
    for forbidden in ("subprocess", "os.system", "eval(", "exec(", "open(", "read_text(", "read_bytes(", "write_text(", "write_bytes(", "Path(", "requests", "urllib"):
        assert forbidden not in triage, "Triage must never inspect, run or mutate real data"
    assert "COVERAGE: dict[str, str]" in triage and '"coverage": COVERAGE[category]' in triage and 'print("Coverage:"' in triage, "ADR-041 coverage label missing"
    monitor_test = (ROOT / "tests/MonitorSampling.Tests.ps1").read_text(encoding="utf-8")
    assert "SYNTHETIC_MONITOR_PRIVATE_CANARY" in monitor_test and "failedAssessment.Validation -eq 'review'" in monitor_test, "Synthetic Monitor missing-sample assertions required"
    assert (ROOT / ".github/workflows/smoke.yml").read_text(encoding="utf-8").count("MonitorSampling.Tests.ps1") == 2, "Both Windows shells must exercise synthetic Monitor failure"
    assert "COVERAGE: ANCHOR_JUNCTION=EXECUTED_SYNTHETIC" in anchor_fixture and "COVERAGE: ANCHOR_JUNCTION=SKIPPED_HOST_CONSTRAINT" in anchor_fixture, "Anchor junction SKIP/EXECUTED markers required"
    root_decoy_fixture = (ROOT / "tests/AnchorBoundFieldFileSession.Tests.ps1").read_text(encoding="utf-8")
    assert "COVERAGE: ROOT_DECOY=EXECUTED_SYNTHETIC" in root_decoy_fixture and "COVERAGE: ROOT_DECOY=SKIPPED_HOST_CONSTRAINT" in root_decoy_fixture, "Root decoy SKIP/EXECUTED markers required"
    assert "test_adr041_assertion_witnesses_and_conservative_coverage" in triage_tests and "test_adr041_absent_assertion_witness_is_not_evidence" in triage_tests, "ADR-041 fixture witness audit missing"
    assert "ADR-041" in (ROOT / "docs/FIELD-FAILURE-TRIAGE.md").read_text(encoding="utf-8"), "ADR-041 scope notice missing"
    assert "field_failure_triage.py" not in main and "field_failure_triage.py" not in report_security, "Research-only triage cannot enter production"
    assert (ROOT / ".github/workflows/smoke.yml").read_text(encoding="utf-8").count("FieldFailureTriage.Tests.py") == 2, "Both hosted Windows shells must test field triage"
    assert (ROOT / "docs/FIELD-FAILURE-TRIAGE.md").is_file(), "Privacy-safe synthetic reproduction protocol missing"
    # ADR-063: public issue templates must not direct contributors to share
    # raw or lightly redacted logs, and both hosted jobs audit that policy.
    public_guide = (ROOT / "docs/PUBLIC-ISSUE-GUIDE.md").read_text(encoding="utf-8")
    public_template = (ROOT / ".github/ISSUE_TEMPLATE/bug_report.md").read_text(encoding="utf-8")
    policy_test = (ROOT / "tests/PublicIssueGuide.Tests.py").read_text(encoding="utf-8")
    validation_doc = (ROOT / "docs/VALIDATION.md").read_text(encoding="utf-8")
    public_ci = (ROOT / ".github/workflows/smoke.yml").read_text(encoding="utf-8")
    assert "**Default: keep the observation private.**" in public_guide and "**NO-GO:**" in public_guide, "Missing synthetic-only public disclosure boundary"
    assert "Synthetic-only bug report" in public_template and "separate disclosure review" in public_template and "Release decision: NO-GO" in public_template, "Unsafe public issue template"
    assert "Specific warning text from `SUMMARY.md` (redact user name" not in validation_doc, "Never request lightly redacted raw warnings in a public issue"
    assert "test_public_template_requires_review_and_synthetic_only" in policy_test, "Missing synthetic public disclosure regression test"
    assert public_ci.count("python tests/PublicIssueGuide.Tests.py") == 2, "Both hosted PowerShell jobs must validate public disclosure policy"

    # ADR-061: only fixed field console labels may cross the optional manual
    # follow-up boundary. It is not invoked by any production collector.
    followup = (ROOT / "tools/field_status_followup.py").read_text(encoding="utf-8")
    followup_tests = (ROOT / "tests/FieldStatusFollowup.Tests.py").read_text(encoding="utf-8")
    assert "STATUS_LINE.fullmatch(item)" in followup and "invalid_readout()" in followup and "return 2" in followup, "Follow-up must reject private arbitrary input and stay NO_GO-only"
    assert "InputStatus: SELF_DECLARED_ONLY" in followup and "PhysicalEvidence: UNVERIFIED" in followup and "ReleaseBlocker:" in followup, "Follow-up cannot claim independent evidence or release authority"
    assert "test_malformed_private_input_and_conflicts_fail_closed_without_echo" in followup_tests and "test_all_five_self_entered_passes_still_no_go" in followup_tests and "test_partial_multi_safety_failure_identifies_only_known_labels" in followup_tests, "Missing privacy and incomplete field follow-up regressions"
    followup_ci = (ROOT / ".github/workflows/smoke.yml").read_text(encoding="utf-8")
    assert followup_ci.count("python tests/FieldStatusFollowup.Tests.py") == 2, "Both Windows hosted jobs must exercise fixed-only field follow-up"
    assert "field_status_followup.py" not in main and "field_status_followup.py" not in report_security, "Manual field follow-up must not run inside production collectors"

    handoff = (ROOT / "tools/field_review_readout.py").read_text(encoding="utf-8")
    handoff_tests = (ROOT / "tests/FieldReviewReadout.Tests.py").read_text(encoding="utf-8")
    assert "field.load_evidence(path)" in handoff, "Readout must reuse strict bounded metadata-only loader"
    assert "field.evaluate(field_claim)" in handoff and "anchor.evaluate(anchor_claim)" in handoff, "Both underlying NO-GO schemas must be validated"
    assert '"decision": "NO_GO"' in handoff and "return 2" in handoff, "Combined readout must never approve release"
    assert "CLAIMS_ONLY" in handoff and "NOT_AUTHENTICATED" in handoff, "Self-asserted completeness must not become approval"
    assert "claimed_complete_cells" in handoff and "MANUAL_APPROVAL_REQUIRED" in handoff, "Only fixed 8-cell claim progress allowed"
    assert "REQUIRED_CELL_LABELS" in handoff and "unaccepted_claim_cells" in handoff and "SELF_DECLARED_ONLY" in handoff, "Missing privacy-minimized field coverage gap status"
    assert "def render_readout(" in handoff and "def _valid_output(" in handoff and "OUTPUT_KEYS" in handoff, "Missing bounded fixed-only rendering contract"
    assert "def _valid_evaluation(" in handoff and "def _invalid_readout(" in handoff and "UPSTREAM_SINGLE_REASON" in handoff, "Handoff must reject unexpected upstream verdict and reason data"
    assert "test_upstream_field_result_mutations_fail_closed" in handoff_tests and "test_upstream_anchor_decision_reason_and_runtime_errors_fail_closed" in handoff_tests and "test_renderer_fallback_is_independent_from_broken_evaluators" in handoff_tests, "Handoff evaluator-drift and error-path regression coverage missing"
    assert "test_rendered_full_claim_has_exact_stable_order_without_raw_fields" in handoff_tests and "test_invalid_internal_output_contract_fails_closed_without_leaking" in handoff_tests and "test_cli_partial_and_corrupt_input_exact_bounded_no_echo" in handoff_tests, "Fixed output ordering and private canary negatives missing"
    assert "test_unaccepted_cells_identify_missing_and_review_only_claims" in handoff_tests and "test_blocked_handoff_withholds_all_eight_fixed_cell_claims" in handoff_tests, "Unaccepted field cell negative regressions must remain"
    assert "test_fabricated_fully_complete_8_cells_are_claims_only" in handoff_tests and "test_self_certification_mismatch_and_storage_risk" in handoff_tests, "Handoff negative controls missing"
    assert "field_review_readout.py" not in main and "field_review_readout.py" not in report_security, "Field handoff cannot be imported in production"
    assert (ROOT / ".github/workflows/smoke.yml").read_text(encoding="utf-8").count("FieldReviewReadout.Tests.py")==2, "Both hosted Windows jobs must run handoff tests"
    assert (ROOT / "docs/FIELD-REVIEW-HANDOFF.md").is_file(), "Operator and reviewer handoff checklist is required"
    checklist_tests = (ROOT / "tests/ReleaseChecklistContract.Tests.py")
    assert checklist_tests.is_file(), "Release gate and physical matrix contract tests must exist"
    checklist_source = checklist_tests.read_text(encoding="utf-8")
    assert "test_missing_one_real_environment_in_either_checklist_fails" in checklist_source
    assert "test_deleting_release_blocker_or_issue_mapping_fails" in checklist_source
    assert "test_provider_and_human_privacy_requirement_downgrade_fails" in checklist_source
    assert (ROOT / ".github/workflows/smoke.yml").read_text(encoding="utf-8").count(
        "ReleaseChecklistContract.Tests.py") == 2, "Both hosted Windows shells must guard release checklist drift"

    trust_gate=(ROOT / "tools/anchor_trust_review.py").read_text(encoding="utf-8")
    trust_tests=(ROOT / "tests/AnchorTrustReview.Tests.py").read_text(encoding="utf-8")
    assert "gate.load_evidence(path)" in trust_gate, "Claim parser must reuse strict bounded metadata loader"
    assert '"decision": "NO_GO"' in trust_gate and "return 2" in trust_gate, "Claim evaluator must never grant release"
    assert "SELF_CERTIFICATION_REJECTED" in trust_gate and "CLAIMS_UNAUTHENTICATED" in trust_gate, "Self-selected and claimed-only origins must remain blocked"
    assert "approved_claimed" in trust_gate and "no_authenticated_root_or_external_approval" in trust_gate, "Externally claimed review is not cryptographic approval"
    assert "test_self_certified_reference_rejected" in trust_tests and "test_complete_fabricated_claims_are_not_authority" in trust_tests, "Synthetic decoy/self-attestation negative tests missing"
    assert "anchor_trust_review.py" not in main and "anchor_trust_review.py" not in report_security, "Review gate imported into production"
    assert (ROOT / ".github/workflows/smoke.yml").read_text(encoding="utf-8").count("AnchorTrustReview.Tests.py")==2, "Both Windows jobs must check trust claims"
    assert (ROOT / "docs/ANCHOR-TRUST-PROTOCOL.md").is_file(), "Independent trust approval procedure missing"
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
    # ADR-034 research-only, fixed-label ACL observation: never infer sync safety.
    acl_module = (ROOT / "tools/WinTriage.FieldStatusAclReview.psm1").read_text(encoding="utf-8")
    acl_entry = (ROOT / "Test-WtFieldStatusAcl.ps1").read_text(encoding="utf-8")
    acl_fixture = (ROOT / "tests/FieldStatusAclResearch.Tests.ps1").read_text(encoding="utf-8")
    assert "Get-WtFieldStatusOutputAssessment" in acl_module and "Get-Acl -LiteralPath" in acl_module, "Metadata ACL reviewer missing"
    assert "SyncAndBackup='unknown'" in acl_module and "Decision='NO_GO'" in acl_module, "Review tool must not certify cloud sync or release"
    assert "exit 2" in acl_entry and "Get-WtFieldStatusOutputAssessment" in acl_entry, "ACL entrypoint must remain NO_GO-only"
    assert "SYNTHETIC_STATUS_RUN" in acl_fixture and "Get-WtFieldStatusAclClassification" in acl_fixture, "Synthetic ACL fixture missing"
    assert "field_status_recorder.py" in acl_fixture and "S-1-1-0" in acl_fixture, "Recorder output and broad ACL negative control needed"
    assert (ROOT / ".github/workflows/smoke.yml").read_text(encoding="utf-8").count("FieldStatusAclResearch.Tests.ps1") == 2, "Both Windows jobs must test field ACL research"
    assert "FieldStatusAclResearch.Tests.ps1" in (ROOT / "Validate-Windows.ps1").read_text(encoding="utf-8"), "Local validator must run research"
    assert "WinTriage.FieldStatusAclReview.psm1" not in main and "Test-WtFieldStatusAcl.ps1" not in main, "No field ACL probe import into production"
    # ADR-035 test-only create-time DACL research: never import this native
    # helper into production or the field status recorder.
    # ADR-036 only test NT file creation beneath a held parent; never ship it.
    # ADR-037 research only: no implicit trust from a self-chosen basename.
    baseline_file=(ROOT / "tests/AnchorBoundFieldFileSession.cs").read_text(encoding="utf-8")
    baseline_test=(ROOT / "tests/AnchorBoundFieldFileSession.Tests.ps1").read_text(encoding="utf-8")
    assert "SyntheticAnchorLease" in baseline_file and "RequireSameObject(independentlyOpenedCandidate, epoch)" in baseline_file, "Require independent reference and candidate identity match"
    assert "RelativeFieldFileProbe.CreateSyntheticChild(" in baseline_file and "RequireCurrent(epoch);" in baseline_file, "Creation must be guarded by live anchor validation"
    assert "ReadCreatedFileSecurity(created)" in baseline_file, "New handle must be reviewed before exposure"
    assert "lease.Dispose()" in baseline_file and "created.Dispose()" in baseline_file, "Borrowed lease and failure must release own resources"
    assert "pre-pin decoy" in baseline_test and "decoy parent must remain untouched" in baseline_test, "Pre-pin and post-pin decoy regressions required"
    assert "self-consistent decoy does NOT authenticate" in baseline_test, "Self-certification counterexample required"
    assert "closed held reference must invalidate baseline" in baseline_test, "Expired reference refusal missing"
    assert "AnchorBoundFieldFileSession.cs" not in main and "AnchorBoundFieldFileSession.cs" not in report_security, "Research-only trust boundary imported into production"
    assert (ROOT / ".github/workflows/smoke.yml").read_text(encoding="utf-8").count("AnchorBoundFieldFileSession.Tests.ps1")==2, "Both hosted Windows shells must run baseline tests"
    assert "AnchorBoundFieldFileSession.Tests.ps1" in (ROOT / "Validate-Windows.ps1").read_text(encoding="utf-8"), "Local smoke missing baseline fixture"
    relative_file_probe=(ROOT / "tests/RelativeFieldFileProbe.cs").read_text(encoding="utf-8")
    relative_file_test=(ROOT / "tests/RelativeFieldFileProbe.Tests.ps1").read_text(encoding="utf-8")
    assert "attributes.RootDirectory = parent.DangerousGetHandle()" in relative_file_probe and "FILE_CREATE, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT" in relative_file_probe, "Relative file creation must use held parent and exclusive NT create"
    assert "FILE_ADD_FILE" in relative_file_probe and "OBJ_CASE_INSENSITIVE" in relative_file_probe, "Parent access and NT object flags missing"
    assert "attributes.SecurityDescriptor = securityPointer" in relative_file_probe and "ReadCreatedFileSecurity" in relative_file_probe, "Create-time file DACL and returned-handle ACL read required"
    assert "FILE_OPEN_IF" not in relative_file_probe and "FILE_OVERWRITE" not in relative_file_probe, "Never permit overwrite or open-if-exists"
    assert "FILE_ATTRIBUTE_REPARSE_POINT" in relative_file_probe and "FILE_FLAG_OPEN_REPARSE_POINT" in relative_file_probe, "Reject linked synthetic parent"
    assert "parent.DangerousAddRef(ref borrowed)" in relative_file_probe and "if (borrowed) parent.DangerousRelease()" in relative_file_probe, "Held parent lifetime guards required"
    assert "parent-moved" in relative_file_test and "decoy parent contains no status file" in relative_file_test, "Deterministic parent swap/decoy test missing"
    assert "junction parent rejected without following" in relative_file_test and "strict single-leaf filename" in relative_file_test, "Namespace negative tests missing"
    assert "ReadCreatedFileSecurity" in relative_file_test and "Get-WtFieldStatusAclClassification" in relative_file_test, "Immediate native-handle ACL validation required"
    assert "RelativeFieldFileProbe.cs" not in main and "RelativeFieldFileProbe.cs" not in report_security, "Research file probe imported into production"
    assert (ROOT / ".github/workflows/smoke.yml").read_text(encoding="utf-8").count("RelativeFieldFileProbe.Tests.ps1") == 2, "Both Windows jobs must test relative file primitive"
    assert "RelativeFieldFileProbe.Tests.ps1" in (ROOT / "Validate-Windows.ps1").read_text(encoding="utf-8"), "Local Windows validation must include relative file primitive"
    file_probe=(ROOT / "tests/FieldStatusFileCreateProbe.cs").read_text(encoding="utf-8")
    file_fixture=(ROOT / "tests/FieldStatusFileCreateProbe.Tests.ps1").read_text(encoding="utf-8")
    assert 'EntryPoint = "CreateFileW"' in file_probe and "SetLastError = true" in file_probe, "Win32 file create probe required"
    assert "ref SecurityAttributes securityAttributes" in file_probe and "attrs.SecurityDescriptor = nativeDescriptor" in file_probe, "File DACL must be supplied during native creation"
    assert "ref attrs, 1U, 0x80U, IntPtr.Zero" in file_probe and "0x40000000U, 0U" in file_probe, "CREATE_NEW with no sharing required"
    assert "attrs.InheritHandle = 0" in file_probe and "Marshal.FreeHGlobal(nativeDescriptor)" in file_probe, "No child handle inheritance or leaked security descriptor"
    assert "CREATE_ALWAYS" not in file_probe and "SetFileSecurity" not in file_probe, "Never overwrite or repair ACL after creation"
    assert "SetAccessRuleProtection((-not $Inheritable.IsPresent),$false)" in file_fixture, "Protected owner-and-DACL preflight required"
    assert "Assert-SyntheticDescriptor -Acl $Acl -CurrentSid $CurrentSid" in file_fixture, "Do not trust arbitrary descriptor"
    assert "Everyone ACE" in file_fixture and "missing SYSTEM" in file_fixture and "foreign owner" in file_fixture, "Weak ACL negatives required"
    assert "CREATE_NEW rejects collision" in file_fixture and "collision retains original ACL" in file_fixture, "No-overwrite regression required"
    assert "SyncAndBackup -eq 'unknown'" in file_fixture and "Decision -eq 'NO_GO'" in file_fixture, "Never certify privacy or release"
    assert (ROOT / ".github/workflows/smoke.yml").read_text(encoding="utf-8").count("FieldStatusFileCreateProbe.Tests.ps1") == 2, "Both Windows shells must run synthetic create-time ACL tests"
    assert "FieldStatusFileCreateProbe.Tests.ps1" in (ROOT / "Validate-Windows.ps1").read_text(encoding="utf-8"), "Local validator must exercise synthetic native create test"
    assert "FieldStatusFileCreateProbe.cs" not in main and "FieldStatusFileCreateProbe.cs" not in report_security, "Never promote test-native file create into production"
    field_recorder = (ROOT / "tools/field_status_recorder.py").read_text(encoding="utf-8")
    recorder_test = (ROOT / "tests/FieldStatusRecorder.Tests.py").read_text(encoding="utf-8")
    assert "O_EXCL" in field_recorder and "MAX_FILE_BYTES" in field_recorder and "NO_GO" in field_recorder, "Offline recorder must create new bounded NO-GO metadata"
    assert "gate.evaluate(data)" in field_recorder and "observed-local-only" in field_recorder, "Recorder must validate existing gate schema and request deliberate manual transcription"
    assert "test_unknown_duplicate_missing_and_sensitive_status_rejected" in recorder_test and "test_fail_is_not_downgraded_to_review_or_pass" in recorder_test, "Recorder must test privacy and failure priority"
    assert ci_text.count("python tests/FieldStatusRecorder.Tests.py") == 2, "Both Windows CI jobs must test synthetic recorder"
    assert "field_status_recorder.py" not in main and "field_status_recorder.py" not in report_security, "Do not import recorder into production collectors"
    assert "object_pairs_hook=_unique_json_object" in field_gate and "parse_constant=_reject_nonfinite" in field_gate, "Reject JSON duplicate keys and non-finite constants"
    assert "os.fstat(stream.fileno())" in field_gate and '"O_NOFOLLOW"' in field_gate, "Metadata loader must bind to an opened regular object"
    assert "gate.load_evidence(path)" in field_recorder, "Recorder must reuse strict gate loader"
    assert "test_duplicate_json_keys_rejected_even_when_last_value_is_valid" in field_gate_test, "Nested duplicate-key regression missing"
    assert "test_duplicate_source_keys_cannot_be_silently_overwritten" in recorder_test, "Recorder duplicate-source regression missing"
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
    # ADR-062: observation-only, not an authorizing or production collector step.
    preflight_entry = (ROOT / "Test-WtFieldPreflight.ps1").read_text(encoding="utf-8")
    preflight_mod = (ROOT / "tools/WinTriage.FieldPreflight.psm1").read_text(encoding="utf-8")
    preflight_tests = (ROOT / "tests/FieldPreflight.Tests.ps1").read_text(encoding="utf-8")
    assert "Get-WtFieldPreflightPathState" in preflight_entry and "Get-WtFieldPreflightAssessment" in preflight_entry and "exit 2" in preflight_entry, "Preflight must be observation-only and NO_GO"
    for forbidden in ("Invoke-WtFieldValidation.ps1", "Set-Acl", "New-Item", "Remove-Item", "Start-MpScan", "Invoke-Expression", "Set-Content", "Export-Csv"):
        assert forbidden not in preflight_entry and forbidden not in preflight_mod, "Preflight cannot collect or change reports: " + forbidden
    assert "GetFullPath" in preflight_mod and "ReparsePoint" in preflight_mod and "DriveType" in preflight_mod and "NOT_VERIFIED" in preflight_mod, "Read-only path classification and external trust limits missing"
    assert "server cannot become Windows 11" in preflight_tests and "CLI always returns exit 2" in preflight_tests and "no caller path on stdout" in preflight_tests, "Missing synthetic preflight safety witnesses"
    assert (ROOT / ".github/workflows/smoke.yml").read_text(encoding="utf-8").count("FieldPreflight.Tests.ps1") == 2, "Both PowerShell versions must execute preflight tests"
    assert "FieldPreflight.Tests.ps1" in (ROOT / "Validate-Windows.ps1").read_text(encoding="utf-8"), "Local validation must include preflight"
    # ADR-064: SMB read-only risk hints, never a declaration of confidentiality.
    smb_preflight = (ROOT / "tools/WinTriage.FieldSmbPreflight.psm1").read_text(encoding="utf-8")
    smb_tests = (ROOT / "tests/FieldSmbPreflight.Tests.ps1").read_text(encoding="utf-8")
    assert "Get-WtFieldSmbExposure" in smb_preflight and "Get-SmbShare -Special $false -ErrorAction Stop" in smb_preflight and "Get-SmbShareAccess -InputObject $Share -ErrorAction Stop" in smb_preflight, "Optional SMB inventory must be read-only and ignore admin special shares"
    assert "Get-WtFieldSmbExposure -Directory $OutputDir -PathState $pathState" in preflight_entry, "SMB parent checks only after path classification"
    assert "SmbExposure=$SmbExposure" in preflight_mod and "'SmbExposure'" in preflight_entry and "exit 2" in preflight_entry, "SMB exposure cannot be omitted or grant field approval"
    assert "BROAD_ACCESS_REVIEW" in smb_preflight and "NO_NON_SPECIAL_SHARE_OBSERVED" in smb_preflight and "UNKNOWN" in smb_preflight, "Fail-closed fixed SMB privacy categories missing"
    assert "fictional smb" in smb_tests.lower() and "positive broad evidence survives another unknown ACL" in smb_tests, "Synthetic-only SMB failure precedence regression required"
    assert (ROOT / ".github/workflows/smoke.yml").read_text(encoding="utf-8").count("FieldSmbPreflight.Tests.ps1") == 2, "Both hosted Windows shells must execute synthetic SMB preflight"
    assert "FieldSmbPreflight.Tests.ps1" in (ROOT / "Validate-Windows.ps1").read_text(encoding="utf-8"), "Local validator must include SMB fixture"
    for forbidden in ("Set-SmbShare", "Remove-SmbShare", "Grant-SmbShareAccess", "Revoke-SmbShareAccess",
                      "New-SmbShare", "Set-Acl", "icacls", "Invoke-Expression", "Invoke-WtFieldValidation"):
        assert forbidden not in smb_preflight and forbidden not in preflight_entry, "SMB preflight cannot mutate or collect: " + forbidden
    assert "WinTriage.FieldSmbPreflight.psm1" not in main and "Get-WtFieldSmbExposure" not in main, "No production collector SMB auto-inventory"
    # ADR-065: no default collection change; the optional field runner alone can
    # re-evaluate the read-only SMB state before each report-producing mode.
    field_guard = (ROOT / "Invoke-WtFieldValidation.ps1").read_text(encoding="utf-8")
    smb_gate_tests = (ROOT / "tests/FieldSmbCollectionGate.Tests.ps1").read_text(encoding="utf-8")
    assert "[switch]$RequireSmbPreflight" in field_guard, "SMB guard must be opt-in"
    assert "if ($RequireSmbPreflight)" in field_guard and "Get-WtFieldSmbExposure" in field_guard, "Optional SMB read before collection required"
    assert "Assert-WtFieldSmbCollectionGate -PathState $pathState -SmbExposure $smbState" in field_guard, "SMB guard must enforce fixed states"
    assert "Write-Output 'SmbCollectionGate: BLOCKED_OR_UNKNOWN'" in field_guard and "exit 2" in field_guard, "Field guard must not emit raw PowerShell error paths"
    assert "-Force -ErrorAction Stop 3>$null 4>$null 5>$null 6>$null" in field_guard, "Optional loader must suppress warnings and fail closed"
    assert "if ($RequireSmbPreflight)" in field_guard and "Import-Module (Join-Path $PSScriptRoot 'src\\WinTriage.ReportSecurity.psm1') -Force -ErrorAction Stop" in field_guard, "Opted-in generic module import failure must be fixed-only"
    assert "$firstMode=$true" in field_guard and "if ($firstMode)" in field_guard, "Field banner must be delayed to first allowed mode"
    assert field_guard.index("Test-WtOptionalSmbGate -Directory $OutputDir") < field_guard.index("Write-Output ('Environment:"), "No environment details before initial SMB collection guard"
    assert "missing optional module has no PowerShell loader path" in smb_gate_tests, "Missing-module privacy regression required"
    assert field_guard.index("Import-Module (Join-Path $PSScriptRoot 'tools\\WinTriage.FieldPreflight.psm1')") < field_guard.index("Import-Module (Join-Path $PSScriptRoot 'src\\WinTriage.ReportSecurity.psm1')"), "Optional SMB imports must precede collector imports for early failure privacy"
    assert "early rejection emits exactly one fixed line" in smb_gate_tests, "Early-block complete-output snapshot required"
    assert "3>$null 4>$null 5>$null 6>$null" in field_guard, "SMB provider warning channels must be suppressed on opt-in"
    assert field_guard.count("Test-WtOptionalSmbGate -Directory $OutputDir") == 3, "SMB gate must check before imports, before metadata, and immediately before collection"
    assert field_guard.index("Test-WtOptionalSmbGate -Directory $OutputDir") < field_guard.index("$before=@()"), "SMB gate must run before report list/collection"
    assert field_guard.rindex("Test-WtOptionalSmbGate -Directory $OutputDir") < field_guard.index("& (Join-Path $PSScriptRoot 'WinTriage.ps1') @options"), "Final SMB gate required before collector"
    assert "fake collection-stage failure exits 2" in smb_gate_tests and "stage failure must emit only fixed one-line denial" in smb_gate_tests, "Synthetic late-share and generic-loader fail-closed regression required"
    assert "'NO_NON_SPECIAL_SHARE_OBSERVED'" in smb_preflight and "function Assert-WtFieldSmbCollectionGate" in smb_preflight, "Missing conservative SMB policy"
    assert "SMB field collection guard blocked or inconclusive; review storage privately." in smb_gate_tests, "Synthetic fixed-error no-echo regression missing"
    assert (ROOT / ".github/workflows/smoke.yml").read_text(encoding="utf-8").count("FieldSmbCollectionGate.Tests.ps1") == 2, "Both Windows shells must run guard tests"
    assert "FieldSmbCollectionGate.Tests.ps1" in (ROOT / "Validate-Windows.ps1").read_text(encoding="utf-8"), "Local guard regression required"
    for forbidden in ("Remove-SmbShare", "Set-SmbShare", "Grant-SmbShareAccess", "Set-Acl", "Remove-Item", "Start-MpScan"):
        assert forbidden not in field_guard, "Opt-in field guard cannot change sharing or run active scans"

    assert "WinTriage.FieldPreflight.psm1" not in main and "Test-WtFieldPreflight.ps1" not in main, "Production collector must not invoke preflight"
    field_script = (ROOT / "Invoke-WtFieldValidation.ps1").read_text(encoding="utf-8")
    field_mod = (ROOT / "src/WinTriage.FieldValidation.psm1").read_text(encoding="utf-8")
    assert "Get-WtFieldValidationAssessment" in field_script and "Assert-WtReportContract" in field_script, "Field verification must enforce report contract"
    assert "Test-WtPassiveNativeArtifact" in field_script and "NativeArtifactsPresent" in field_script and "if (-not $acl)" in field_script, "Field runner must inspect fixed native artifacts only after private ACL"
    assert "function Test-WtPassiveNativeArtifact" in field_mod and "clamav-output.txt" in field_mod and "sfc-verifyonly.txt" in field_mod and "dism-scanhealth.txt" in field_mod, "Passive native artifact detector missing"
    native_test = (ROOT / "tests/FieldValidation.Tests.ps1").read_text(encoding="utf-8")
    assert "function Get-WtEventSamplingAssessment" in field_mod and "QueriesAttempted" in field_mod and "Retained" in field_mod, "Missing bounded field event query coverage guard"
    assert "no attempted event provider query remains review" in native_test and "retained count larger than observed fails" in native_test and "valid empty event queries stay structural-only pass" in native_test, "Missing event provider attempt and consistency regression cases"
    assert "unlisted native file fails" in native_test and "listed native artifact fails every passive mode" in native_test, "Missing native-artifact negative controls"
    assert "Assert-WtPrivateDirectoryAcl" in field_script, "Field verification must enforce private ACL"
    assert "if ($mode -eq 'Monitor')" in field_script, "Manual validation should include bounded Monitor sampling"
    # ADR-043: a successful but empty Monitor attempt cannot silently pass field review.
    field_assessment = (ROOT / "src/WinTriage.FieldValidation.psm1").read_text(encoding="utf-8")
    # ADR-044: reject forged time ordering and process identity, avoid claims
    # based on noncomparable PID reuse or malformed timestamps.
    growth_source = (ROOT / "src/WinTriage.Core.psm1").read_text(encoding="utf-8")
    temporal_test = (ROOT / "tests/MonitorGrowthTemporal.Tests.ps1").read_text(encoding="utf-8")
    assert "Get-WtProcessGrowth" in growth_source and "UtcDateTime.Ticks" in growth_source and "previousUtcTicks" in growth_source, "Monitor temporal identity check missing"
    assert "InstanceKey -cne" in growth_source and "IdentityReliable" in growth_source and "StartedUtc" in growth_source, "Monitor stable process identity check missing"
    # ADR-045: accepted growth cannot mask a separately rejected candidate.
    field_assessment_source = (ROOT / "src/WinTriage.FieldValidation.psm1").read_text(encoding="utf-8")
    temporal_test = (ROOT / "tests/MonitorGrowthTemporal.Tests.ps1").read_text(encoding="utf-8")
    field_test = (ROOT / "tests/FieldValidation.Tests.ps1").read_text(encoding="utf-8")
    report_contract_source = (ROOT / "tests/ReportContract.psm1").read_text(encoding="utf-8")
    for marker in ("RejectedGrowthGroups", "SkippedUnreliableIdentitySamples"):
        assert marker in main and marker in field_assessment_source and marker in report_contract_source, "Missing private Monitor quality marker: " + marker
    assert "QualityInfo['RejectedGrowthGroups']++" in growth_source, "Rejected candidate groups must be counted without identifiers"
    # ADR-046: singleton churn must not hide missing/malformed one-off evidence.
    singleton_fixture = (ROOT / "tests/MonitorSingleton.Tests.ps1").read_text(encoding="utf-8")
    for key in ("SingletonGroups", "InvalidSingletonGroups", "UnkeyedSamples"):
        assert key in growth_source and key in main and key in field_assessment_source and key in report_contract_source, "Monitor singleton quality contract missing: " + key
    assert "legitimate process churn is structural only" in singleton_fixture and "missing identity key tracked without exposure" in singleton_fixture, "Singleton and unkeyed synthetic witnesses missing"
    assert "malformed singleton alongside valid growth requires review" in singleton_fixture, "Invalid singleton must review even with valid growth"
    assert (ROOT / ".github/workflows/smoke.yml").read_text(encoding="utf-8").count("MonitorSingleton.Tests.ps1") == 2, "Both Windows shells must exercise singleton quality"
    assert "MonitorSingleton.Tests.ps1" in (ROOT / "Validate-Windows.ps1").read_text(encoding="utf-8"), "Local singleton regression missing"
    assert "Get-WtProcessGrowth -Samples $records -QualityInfo $growthQuality" in main, "Production must pass the candidate-rejection counter"
    assert "one good and one rejected group must review, never pass" in temporal_test, "Mixed candidate-group review regression missing"
    assert "one unreliable identity despite valid growth must review" in field_test, "Partial unreliable sample review regression missing"
    assert "backward sample timestamp" in temporal_test and "PID/key disagreement" in temporal_test and "duplicate sample timestamp" in temporal_test and "start/key disagreement" in temporal_test, "Temporal counterexample assertions missing"
    assert (ROOT / ".github/workflows/smoke.yml").read_text(encoding="utf-8").count("MonitorGrowthTemporal.Tests.ps1") == 2, "Both Windows shells must run temporal growth test"
    assert "MonitorGrowthTemporal.Tests.ps1" in (ROOT / "Validate-Windows.ps1").read_text(encoding="utf-8"), "Local validation must run temporal growth test"
    monitor_fixture = (ROOT / "tests/MonitorSampling.Tests.ps1").read_text(encoding="utf-8")
    field_fixture = (ROOT / "tests/FieldValidation.Tests.ps1").read_text(encoding="utf-8")
    contract_fixture = (ROOT / "tests/ReportContract.Tests.ps1").read_text(encoding="utf-8")
    for token in ("RequestedAttempts", "AttemptedAttempts", "NonEmptyAttempts", "ComparableProcesses"):
        assert token in main and token in field_assessment and token in (ROOT / "tests/ReportContract.psm1").read_text(encoding="utf-8"), "Monitor aggregate contract drift: " + token
    assert "if ($batch.Count -gt 0)" in main and "$report['MonitorSampling']['ComparableProcesses'] = $growth.Count" in main, "Monitor must record empty attempts and comparable process groups"
    assert "silent empty second sample must require review" in monitor_fixture and "no comparable identity across two nonempty samples" in monitor_fixture, "Silent Monitor regression absent"
    assert "legacy Monitor without attempt counts is inconclusive" in field_fixture and "boolean count is invalid" in field_fixture, "Monitor old/corrupt metadata must fail closed"
    assert "Old schema-v1 Monitor report is structurally backward compatible" in contract_fixture and "boolean Monitor count" in contract_fixture, "Schema-v1 compatibility and strict counts missing"
    assert "MonitorSampling.Tests.ps1" in (ROOT / "Validate-Windows.ps1").read_text(encoding="utf-8"), "Local Monitor test parity missing"
    assert "MonitorSampling.Tests.ps1" in (ROOT / ".github/workflows/smoke.yml").read_text(encoding="utf-8"), "Both Windows CI jobs must include Monitor test"
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
