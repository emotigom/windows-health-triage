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
    assert "[System.IO.Directory]::CreateDirectory($newRun,$acl)" in report_security, "PS 5.1 must create the folder with its ACL"
    assert "[System.IO.FileSystemAclExtensions]::CreateDirectory($acl,$newRun)" in report_security, "PS 7 must create with ACL"
    assert "Set-Acl -LiteralPath $newRun" not in report_security, "Do not create a window with a separate Set-Acl"
    assert "New-Item -ItemType Directory -Path $newRun" not in report_security, "Do not create evidence folders with broad inherited ACL"
    assert "missing a required inheritable full-access rule" in report_security, "ACL verifier must check required full-control rules"
    assert "function Assert-WtPrivateSecurityDescriptor" in report_security, "Security descriptor must be independently testable"
    assert "$Acl.GetOwner($sidType)" in report_security, "Report owner must be validated by SID"
    assert "Report directory has an unexpected owner" in report_security, "Unknown ACL owner must fail closed"
    assert "Assert-WtPrivateSecurityDescriptor -Acl $acl -CurrentSid $current" in report_security, "Live post-create ACL validation must include owner"

    assert "Assert-WtPrivateDirectoryAcl -Directory $newRun" in report_security, "Applied DACL must be checked"
    assert "WinTriage.ReportSecurity.psm1" in main, "Missing report security module import"
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
