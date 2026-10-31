"""Offline, metadata-only field validation gate (ADR-031).

This gate NEVER grants permission to release or migrate research-only native
probes into production. It accepts fixed enumerated statuses, not raw reports.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

OS = ("windows10", "windows11")
SHELLS = ("powershell51", "powershell7")
PRIVILEGES = ("standard", "elevated")
MODES = ("quick", "events", "hardware", "monitor", "integrity")
SCENARIOS = ("defender_unavailable", "event_access_denied", "storage_provider_unavailable")
REVIEWS = ("trusted_initial_root", "in_call_reparse_and_mount", "real_acl_and_privacy", "managed_or_synced_storage")
RESULTS = ("not_run", "pass", "review", "fail")
SCENARIO_RESULTS = ("not_observed", "observed_inconclusive", "unexpected_success", "fail")
REVIEW_RESULTS = ("unverified", "reviewed", "failed")
MAX_FILE_BYTES = 32768


def _dict_exact(value: Any, keys: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == keys


def _reject() -> dict[str, Any]:
    return {"decision": "NO_GO", "readiness": "INVALID_METADATA", "reasons": ["invalid_or_extra_metadata"]}


def evaluate(evidence: Any) -> dict[str, Any]:
    """Return only fixed, non-sensitive labels; never echo user data."""
    if not _dict_exact(evidence, {"schema", "matrix", "negative_scenarios", "security_reviews"}):
        return _reject()
    if type(evidence["schema"]) is not int or evidence["schema"] != 1:
        return _reject()
    rows = evidence["matrix"]
    if not isinstance(rows, list) or len(rows) > 8:
        return _reject()
    if not _dict_exact(evidence["negative_scenarios"], set(SCENARIOS)):
        return _reject()
    if not _dict_exact(evidence["security_reviews"], set(REVIEWS)):
        return _reject()
    if any(not isinstance(v, str) or v not in SCENARIO_RESULTS for v in evidence["negative_scenarios"].values()):
        return _reject()
    if any(not isinstance(v, str) or v not in REVIEW_RESULTS for v in evidence["security_reviews"].values()):
        return _reject()
    seen: set[tuple[str, str, str]] = set()
    status_bad = False
    scans_bad = False
    mode_not_pass = False
    for row in rows:
        if not _dict_exact(row, {"os", "shell", "privilege", "modes", "schema_contract", "private_acl", "passive_scans"}):
            return _reject()
        a, b, c = row["os"], row["shell"], row["privilege"]
        if (not isinstance(a, str) or a not in OS or
                not isinstance(b, str) or b not in SHELLS or
                not isinstance(c, str) or c not in PRIVILEGES):
            return _reject()
        key = (a, b, c)
        if key in seen:
            return _reject()
        seen.add(key)
        if not _dict_exact(row["modes"], set(MODES)):
            return _reject()
        if any(not isinstance(v, str) or v not in RESULTS for v in row["modes"].values()):
            return _reject()
        if row["schema_contract"] not in RESULTS or row["private_acl"] not in RESULTS:
            return _reject()
        if row["passive_scans"] not in ("not_checked", "absent", "unexpected"):
            return _reject()
        status_bad |= any(v == "fail" for v in row["modes"].values()) or row["schema_contract"] == "fail" or row["private_acl"] == "fail"
        scans_bad |= row["passive_scans"] == "unexpected"
        mode_not_pass |= (any(v != "pass" for v in row["modes"].values()) or
                          row["schema_contract"] != "pass" or row["private_acl"] != "pass" or
                          row["passive_scans"] != "absent")
    reasons: list[str] = []
    if len(seen) != len(OS) * len(SHELLS) * len(PRIVILEGES):
        reasons.append("missing_windows_shell_privilege_coverage")
    if status_bad:
        reasons.append("field_validation_failed")
    if scans_bad:
        reasons.append("unexpected_native_scan")
    if mode_not_pass:
        reasons.append("field_mode_or_acl_not_passed")
    if any(v != "observed_inconclusive" for v in evidence["negative_scenarios"].values()):
        reasons.append("provider_negative_scenarios_unverified")
    if any(v != "reviewed" for v in evidence["security_reviews"].values()):
        reasons.append("manual_security_review_missing")
    if reasons:
        return {"decision": "NO_GO", "readiness": "INCOMPLETE", "reasons": reasons}
    # A synthetic JSON can be fabricated or self-certified. Completeness is
    # NOT independent proof of the initial root or real-device testing.
    return {"decision": "NO_GO", "readiness": "MANUAL_APPROVAL_REQUIRED", "reasons": ["no_authenticated_external_release_approval"]}


def read_evidence(path: Path) -> dict[str, Any]:
    # Never read user reports; only a specifically supplied, small metadata file.
    try:
        if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
            return _reject()
        with path.open("rb") as stream:
            raw = stream.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            return _reject()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, UnicodeError):
        return _reject()
    return evaluate(value)


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline, NO-GO-only field evidence checker")
    parser.add_argument("--metadata", required=True, type=Path, help="Local enumerated-status JSON only (never a raw report)")
    args = parser.parse_args()
    result = read_evidence(args.metadata)
    print("Decision:", result["decision"])
    print("Readiness:", result["readiness"])
    for reason in result["reasons"]:
        print("Reason:", reason)
    # Deliberately ALWAYS nonzero: do not use this CLI as a release-approval gate.
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
