"""ADR-061: optional offline follow-up for manually copied FIXED field-status lines.

No report/metadata file reads, event queries, uploads or native commands.
Only known labels are accepted. This never authenticates a field observation
or grants release approval. All CLI paths return exit status 2 / NO_GO.
"""
from __future__ import annotations

import argparse
import re
from typing import Any

MODES = ("Quick", "Events", "Hardware", "Monitor", "Integrity")
NATIVE_EXPECTED = {
    "Quick": "not-requested",
    "Events": "not-applicable",
    "Hardware": "not-applicable",
    "Monitor": "not-applicable",
    "Integrity": "not-requested",
}
# Exact console-line contract from Invoke-WtFieldValidation.ps1; no free text.
STATUS_LINE = re.compile(
    r"Mode=(Quick|Events|Hardware|Monitor|Integrity); "
    r"Validation=(pass|review|fail); "
    r"Contract=(pass|fail); "
    r"PrivateAcl=(pass|fail); "
    r"PassiveNativeScans=(not-requested|not-applicable|unexpected); "
    r"Warnings=(none|present|unknown)"
)
# Existing, reviewed fixture references; nothing is opened or executed.
REFERENCES = {
    "CONTRACT_FAILED": "tests/ReportContract.Tests.ps1",
    "PRIVATE_ACL_FAILED": "tests/ReportSecurity.Tests.ps1",
    "PASSIVE_SCAN_UNEXPECTED": "tests/FieldValidation.Tests.ps1",
    "WARNINGS_PRESENT": "NONE",
    "WARNINGS_UNKNOWN": "NONE",
    "UNCLASSIFIED_FAILURE": "NONE",
    "UNCLASSIFIED_REVIEW": "NONE",
}
BLOCKERS = (
    "PHYSICAL_WINDOWS_10_11",
    "TRUSTED_INITIAL_ROOT",
    "INDEPENDENT_SECURITY_PRIVACY",
    "EXTERNAL_RELEASE_AUTHORITY",
)
STATUS_LABELS = {"pass": "STRUCTURAL_PASS_ONLY",
                 "review": "REVIEW_REQUIRED", "fail": "FAILURE_REPORTED"}


def _review_reasons(fields: dict[str, str]) -> tuple[str, ...]:
    reasons: list[str] = []
    if fields["contract"] == "fail":
        reasons.append("CONTRACT_FAILED")
    if fields["acl"] == "fail":
        reasons.append("PRIVATE_ACL_FAILED")
    if fields["native"] == "unexpected":
        reasons.append("PASSIVE_SCAN_UNEXPECTED")
    if fields["warnings"] == "present":
        reasons.append("WARNINGS_PRESENT")
    elif fields["warnings"] == "unknown":
        reasons.append("WARNINGS_UNKNOWN")
    if not reasons and fields["validation"] != "pass":
        reasons.append("UNCLASSIFIED_FAILURE" if fields["validation"] == "fail"
                       else "UNCLASSIFIED_REVIEW")
    return tuple(reasons)


def review_statuses(items: Any) -> tuple[str, ...]:
    """Convert at most five exact, self-entered status lines to fixed labels.

    A generic REVIEW cannot identify which provider failed. A missing mode is
    merely unrecorded, not proof of a failed or never-executed physical scan.
    """
    if type(items) is not list or len(items) > len(MODES):
        raise ValueError("invalid fixed status list")
    parsed: dict[str, dict[str, str]] = {}
    for item in items:
        if type(item) is not str or len(item) > 240:
            raise ValueError("invalid status field")
        match = STATUS_LINE.fullmatch(item)
        if match is None:
            raise ValueError("non-allowlisted input")
        mode, validation, contract, acl, native, warnings = match.groups()
        if mode in parsed:
            raise ValueError("duplicate mode")
        if native not in ("unexpected", NATIVE_EXPECTED[mode]):
            raise ValueError("native applicability conflict")
        if (contract == "fail" or acl == "fail" or native == "unexpected") and validation != "fail":
            raise ValueError("safety failure cannot be downgraded")
        if validation == "pass" and warnings != "none":
            raise ValueError("warning cannot be a structural pass")
        parsed[mode] = {
            "validation": validation, "contract": contract, "acl": acl,
            "native": native, "warnings": warnings,
        }

    lines = [
        "Decision: NO_GO",
        "InputStatus: SELF_DECLARED_ONLY",
        "PhysicalEvidence: UNVERIFIED",
        "RecordedModes: {}/5".format(len(parsed)),
    ]
    for mode in MODES:
        if mode not in parsed:
            lines.append("UnrecordedMode: " + mode)
            lines.append("ModeStatus: " + mode + ":NOT_RECORDED")
            continue
        fields = parsed[mode]
        lines.append("ModeStatus: " + mode + ":" + STATUS_LABELS[fields["validation"]])
        for code in _review_reasons(fields):
            lines.append("ReviewReason: " + mode + ":" + code)
            lines.append("SyntheticReference: " + mode + ":" + REFERENCES[code])
    lines.extend("ReleaseBlocker: " + blocker for blocker in BLOCKERS)
    return tuple(lines)


def invalid_readout() -> tuple[str, ...]:
    # Does not re-enter the parser or depend on any caller-supplied fields.
    return (
        "Decision: NO_GO",
        "InputStatus: INVALID_FIXED_STATUS",
        "PhysicalEvidence: UNVERIFIED",
        "RecordedModes: 0/5",
        *(("UnrecordedMode: " + mode) for mode in MODES),
        *(("ReleaseBlocker: " + blocker) for blocker in BLOCKERS),
    )


class PrivateParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        # Default argparse errors echo user-provided paths and arbitrary text.
        raise ValueError("invalid arguments")


def main(argv: list[str] | None = None) -> int:
    parser = PrivateParser(
        add_help=False,
        description="Only five fixed field status labels; offline NO_GO follow-up.",
    )
    parser.add_argument("--status", action="append", default=[])
    try:
        args = parser.parse_args(argv)
        lines = review_statuses(args.status)
    except Exception:
        lines = invalid_readout()
    for line in lines:
        print(line)
    return 2  # A structural PASS is never a release authorization.


if __name__ == "__main__":
    raise SystemExit(main())
