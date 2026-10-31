"""ADR-038: offline, claim-only initial-anchor trust and review protocol.

This does NOT authenticate a reference handle, sign an approval, read reports,
or authorize release. Even every "claimed" check returns NO_GO / exit 2.
No raw paths, identities, hostnames, signatures or free text are accepted.
"""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import field_evidence_gate as gate

FIELDS = {
    "anchor": {
        "reference_origin": ("unknown", "self_selected", "external_reference_claimed"),
        "handle_identity": ("not_checked", "match_claimed", "mismatch"),
        "reference_lifecycle": ("unknown", "live_claimed", "expired"),
    },
    "namespace": {
        "ancestor_chain": ("unknown", "reviewed_claimed", "unsafe"),
        "mount_and_reparse": ("unknown", "reviewed_claimed", "unsafe"),
        "volume_policy": ("unknown", "fixed_ntfs_claimed", "unsupported"),
    },
    "storage": {
        "file_acl": ("unknown", "restricted_claimed", "unsafe"),
        "sync_and_backup": ("unknown", "not_synced_claimed", "risk_present"),
    },
    "review": {
        "operator_review": ("not_recorded", "completed_claimed"),
        "independent_review": ("not_recorded", "completed_claimed"),
        "authorization": ("not_recorded", "approved_claimed"),
    },
}
EXPECTED = {
    "anchor": {
        "reference_origin": "external_reference_claimed",
        "handle_identity": "match_claimed",
        "reference_lifecycle": "live_claimed",
    },
    "namespace": {
        "ancestor_chain": "reviewed_claimed",
        "mount_and_reparse": "reviewed_claimed",
        "volume_policy": "fixed_ntfs_claimed",
    },
    "storage": {
        "file_acl": "restricted_claimed",
        "sync_and_backup": "not_synced_claimed",
    },
    "review": {
        "operator_review": "completed_claimed",
        "independent_review": "completed_claimed",
        "authorization": "approved_claimed",
    },
}
UNSAFE = {
    ("anchor", "handle_identity", "mismatch"),
    ("anchor", "reference_lifecycle", "expired"),
    ("namespace", "ancestor_chain", "unsafe"),
    ("namespace", "mount_and_reparse", "unsafe"),
    ("namespace", "volume_policy", "unsupported"),
    ("storage", "file_acl", "unsafe"),
    ("storage", "sync_and_backup", "risk_present"),
}


def _result(readiness: str, reasons: list[str]) -> dict[str, Any]:
    return {"decision": "NO_GO", "readiness": readiness, "reasons": reasons}


def evaluate(value: Any) -> dict[str, Any]:
    """Reject unknown input; return only fixed, nonidentifying reason labels."""
    if not isinstance(value, dict) or set(value) != {"schema", *FIELDS}:
        return _result("INVALID_METADATA", ["invalid_or_extra_metadata"])
    if type(value["schema"]) is not int or value["schema"] != 1:
        return _result("INVALID_METADATA", ["invalid_or_extra_metadata"])
    for section, names in FIELDS.items():
        item = value[section]
        if not isinstance(item, dict) or set(item) != set(names):
            return _result("INVALID_METADATA", ["invalid_or_extra_metadata"])
        for name, allowed in names.items():
            val = item[name]
            if not isinstance(val, str) or val not in allowed:
                return _result("INVALID_METADATA", ["invalid_or_extra_metadata"])

    if any(value[s][k] == bad for s, k, bad in UNSAFE):
        return _result("UNSAFE_CLAIM", ["identity_or_path_or_storage_risk"])
    if value["anchor"]["reference_origin"] == "self_selected":
        # A same-file match against a self-chosen baseline is NOT provenance.
        return _result("SELF_CERTIFICATION_REJECTED", ["self_selected_anchor_is_not_trusted"])

    missing = []
    if any(value["anchor"][k] != expected for k, expected in EXPECTED["anchor"].items()):
        missing.append("external_anchor_claim_or_identity_missing")
    if any(value["namespace"][k] != expected for k, expected in EXPECTED["namespace"].items()):
        missing.append("namespace_checks_incomplete")
    if any(value["storage"][k] != expected for k, expected in EXPECTED["storage"].items()):
        missing.append("storage_review_incomplete")
    if any(value["review"][k] != expected for k, expected in EXPECTED["review"].items()):
        missing.append("independent_review_or_authorization_claim_missing")
    if missing:
        return _result("INCOMPLETE", missing)

    # All claims could be fabricated by one person or copied from a template.
    # Without an authenticated external authority, even "approved_claimed"
    # is *not* an approval. Never output a GO or a success exit status.
    return _result("CLAIMS_UNAUTHENTICATED", ["no_authenticated_root_or_external_approval"])


def check(path: Path) -> dict[str, Any]:
    try:
        return evaluate(gate.load_evidence(path))
    except (OSError, ValueError, UnicodeError, RecursionError):
        return _result("INVALID_METADATA", ["invalid_or_extra_metadata"])


class FixedErrorParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise ValueError("invalid claim metadata arguments")


def main(argv: list[str] | None = None) -> int:
    parser = FixedErrorParser(description="Offline NO_GO-only initial anchor claim review")
    parser.add_argument("--metadata", required=True, type=Path,
                        help="Status-only local claim sheet; never a report or attestation")
    try:
        args = parser.parse_args(argv)
        decision = check(args.metadata)
    except ValueError:
        decision = _result("INVALID_METADATA", ["invalid_or_extra_metadata"])
    print("Decision:", decision["decision"])
    print("Readiness:", decision["readiness"])
    for reason in decision["reasons"]:
        print("Reason:", reason)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
