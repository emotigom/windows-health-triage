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
    assert "ToolVersion='0.3.1'" in main
    assert "-Mode Integrity" in (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Get-WtStorageAssessment" in core
    # PR #8 moved the read-only storage call behind the hardware collector boundary.
    assert "WinTriage.HardwareCollector.psm1" in main, "Entrypoint must import hardware collector"
    assert "Get-StorageReliabilityCounter -PhysicalDisk" in hardware, "Missing read-only storage provider in hardware collector"
    for forbidden in ("Clear-Disk", "Reset-PhysicalDisk", "Initialize-Disk", "Format-Volume", "Remove-Partition", "Set-PhysicalDisk"):
        assert forbidden not in hardware, f"Unexpected storage mutation command in hardware collector: {forbidden}"
    assert "-not $item.Flag" in main, "Native verification must be opt-in"
    assert "Administrator=(Test-WtAdministrator)" in main, "Admin check must evaluate (not use bare string literal)"
    assert "if (-not $status.Administrator)" in main, "Native verification requires admin"
    section = main.split("function Get-WtIntegrity {", 1)[1].split("function Get-WtSecurity {", 1)[0]
    for bad in ("Invoke-Expression", "'/scannow'", "'/RestoreHealth'", "'Clear-Disk'", "'Reset-PhysicalDisk'"):
        assert bad not in section, f"Unexpected native mutation code: {bad}"
    assert "Get-WtSecurityEvidence -Warnings $warnings" in main, "Entrypoint must use read-only Defender collector"
    for forbidden in ("Start-MpScan", "clamscan.exe", "--remove", "--move"):
        assert forbidden not in security, f"Passive collector must not invoke scanners: {forbidden}"
    assert "-RunDefenderQuickScan" in main
    assert "& $cmd.Source '--recursive=yes' '--infected' $ScanPath" in main, "ClamAV must remain detection-only"
    assert "'--remove'" not in main and "'--move'" not in main, "Destructive ClamAV options must not be invoked"
    print(f"PASS static preflight: {len(psfiles)} PowerShell files, structural brackets, safety invariants")
    print("NOTE: this is NOT syntax/runtime validation; execute Windows smoke and integration tests.")


if __name__ == "__main__":
    try:
        check()
    except Exception as ex:
        print("FAIL:", ex, file=sys.stderr)
        sys.exit(1)
