"""Explicit offline recorder for fixed field-validation status labels (ADR-032).

Does not run collectors, parse raw reports, upload data, or approve a release.
Creates only a brand-new private-location metadata snapshot; no overwrite.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys

import field_evidence_gate as gate

MODES = tuple(gate.MODES)
RUN_FIELDS = ("validation", "contract", "private_acl", "passive_native_scans", "warnings")
LABELS = {
    "validation": ("pass", "review", "fail"),
    "contract": ("pass", "fail"),
    "private_acl": ("pass", "fail"),
    "passive_native_scans": ("not-requested", "not-applicable", "unexpected"),
    "warnings": ("none", "present", "unknown"),
}
ERROR = "Invalid or unsafe fixed-status request; no release approval was granted."


class PrivateParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # argparse normally repeats unrecognized arguments (which may be private).
        raise ValueError("invalid fixed-status arguments")


def _read_metadata(path: Path) -> dict:
    if path.is_symlink():
        raise ValueError("linked input")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError("input is not a regular file")
        raw = handle.read(gate.MAX_FILE_BYTES + 1)
    if len(raw) > gate.MAX_FILE_BYTES:
        raise ValueError("oversized input")
    data = json.loads(raw.decode("utf-8"))
    if gate.evaluate(data)["readiness"] == "INVALID_METADATA":
        raise ValueError("invalid schema")
    expected = {(a, b, c) for a in gate.OS for b in gate.SHELLS for c in gate.PRIVILEGES}
    actual = {(r["os"], r["shell"], r["privilege"]) for r in data["matrix"]}
    if actual != expected:
        raise ValueError("incomplete template")
    return data


def _parse_statuses(items: list[str]) -> dict[str, dict[str, str]]:
    if len(items) != len(MODES):
        raise ValueError("exactly five statuses required")
    result: dict[str, dict[str, str]] = {}
    for item in items:
        parts = item.split(":")
        if len(parts) != 6:
            raise ValueError("status format")
        mode = parts[0].lower()
        if mode not in MODES or mode in result:
            raise ValueError("invalid or duplicate mode")
        values = dict(zip(RUN_FIELDS, parts[1:]))
        if any(values[name] not in LABELS[name] for name in RUN_FIELDS):
            raise ValueError("unknown status")
        validation = values["validation"]
        contract = values["contract"]
        acl = values["private_acl"]
        native = values["passive_native_scans"]
        warnings = values["warnings"]
        if ((contract == "fail" or acl == "fail" or native == "unexpected")
                and validation != "fail"):
            raise ValueError("cannot downgrade failed safety status")
        if validation == "pass" and warnings != "none":
            raise ValueError("warnings require review or failure")
        if mode in ("quick", "integrity"):
            if native == "not-applicable":
                raise ValueError("native scan evidence required")
        elif native == "not-requested":
            raise ValueError("unrecognized scan applicability")
        if validation == "pass" and native == "unexpected":
            raise ValueError("native scan conflict")
        result[mode] = values
    if set(result) != set(MODES):
        raise ValueError("missing mode")
    return result


def record(data: dict, os_name: str, shell: str, privilege: str,
           statuses: dict[str, dict[str, str]]) -> dict:
    if os_name not in gate.OS or shell not in gate.SHELLS or privilege not in gate.PRIVILEGES:
        raise ValueError("unknown environment")
    row = next(r for r in data["matrix"] if
               (r["os"], r["shell"], r["privilege"]) == (os_name, shell, privilege))
    # No silent replacement of previously entered field evidence.
    if (any(v != "not_run" for v in row["modes"].values()) or
            row["schema_contract"] != "not_run" or
            row["private_acl"] != "not_run" or
            row["passive_scans"] != "not_checked"):
        raise ValueError("this cell has already been recorded")
    for mode in MODES:
        row["modes"][mode] = statuses[mode]["validation"]
    row["schema_contract"] = ("fail" if any(
        v["contract"] == "fail" for v in statuses.values()) else "pass")
    row["private_acl"] = ("fail" if any(
        v["private_acl"] == "fail" for v in statuses.values()) else "pass")
    row["passive_scans"] = ("unexpected" if any(
        v["passive_native_scans"] == "unexpected" for v in statuses.values()) else "absent")
    if gate.evaluate(data)["readiness"] == "INVALID_METADATA":
        raise ValueError("invalid result")
    return data


def _write_new(path: Path, data: dict) -> None:
    # Refuse a checked-in or accidentally public snapshot; this is NOT a Windows
    # reparse/ACL/sync guarantee. Operator must choose an approved private folder.
    project = Path(__file__).resolve().parents[1]
    if path.resolve(strict=False).is_relative_to(project):
        raise ValueError("repository output refused")
    if path.is_symlink():
        raise ValueError("linked output")
    payload = (json.dumps(data, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
    if len(payload) > gate.MAX_FILE_BYTES:
        raise ValueError("oversized output")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)


def main(argv: list[str] | None = None) -> int:
    parser = PrivateParser(description="Record manually transcribed, fixed status labels only; NO_GO always applies.")
    parser.add_argument("--metadata", required=True, type=Path, help="Existing local status-only template or snapshot")
    parser.add_argument("--output", required=True, type=Path, help="New private, non-synced JSON file (never overwritten)")
    parser.add_argument("--os", required=True)
    parser.add_argument("--shell", required=True)
    parser.add_argument("--privilege", required=True)
    parser.add_argument("--status", action="append", required=True,
                        help="Repeat five times: Mode:Validation:Contract:PrivateAcl:PassiveNativeScans:Warnings")
    parser.add_argument("--observed-local-only", action="store_true",
                        help="Acknowledge you transcribed only statuses from an authorized local field run")
    try:
        args = parser.parse_args(argv)
        if not args.observed_local_only:
            raise ValueError("explicit acknowledgement required")
        statuses = _parse_statuses(args.status)
        evidence = _read_metadata(args.metadata)
        updated = record(evidence, args.os, args.shell, args.privilege, statuses)
        _write_new(args.output, updated)
    except Exception:
        # Do not disclose user-supplied paths, arguments, traceback, metadata or report contents.
        print(ERROR, file=sys.stderr)
        return 2
    print("Local fixed-status snapshot created. Decision remains NO_GO; this is not verified hardware evidence.")
    return 0  # File creation succeeded, NOT a release gate; the gate always exits 2.


if __name__ == "__main__":
    raise SystemExit(main())
