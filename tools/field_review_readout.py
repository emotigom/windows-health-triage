"""ADR-039: offline, fixed-label field review handoff. ALWAYS NO_GO.

Reads only two explicitly supplied, enum-only metadata files using the strict,
bounded reader. It is not a collector, authenticated approval, or upload tool.
No raw reports, personal data, paths, file IDs, notes or arbitrary text are
echoed or written. Both inputs are self-asserted and can be fabricated.
"""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import anchor_trust_review as anchor
import field_evidence_gate as field

TOTAL_CELLS = len(field.OS) * len(field.SHELLS) * len(field.PRIVILEGES)
FIELD_READINESS = {"INVALID_METADATA", "INCOMPLETE", "MANUAL_APPROVAL_REQUIRED"}
ANCHOR_READINESS = {
    "INVALID_METADATA", "INCOMPLETE", "UNSAFE_CLAIM",
    "SELF_CERTIFICATION_REJECTED", "CLAIMS_UNAUTHENTICATED",
}


def _load(path: Path) -> Any:
    try:
        return field.load_evidence(path)
    except (OSError, ValueError, UnicodeError, RecursionError):
        return None


def _claimed_complete(row: dict[str, Any]) -> bool:
    """Counts enum claims, NOT verified physical Windows executions."""
    return (all(row["modes"][mode] == "pass" for mode in field.MODES)
            and row["schema_contract"] == "pass"
            and row["private_acl"] == "pass"
            and row["passive_scans"] == "absent")


def summarize(field_claim: Any, anchor_claim: Any) -> dict[str, Any]:
    """Safely combine already-independent validation results without GO."""
    field_result = field.evaluate(field_claim)
    anchor_result = anchor.evaluate(anchor_claim)
    field_state = field_result["readiness"]
    anchor_state = anchor_result["readiness"]

    # Never count untrusted malformed rows. The schema check must first pass.
    count = 0
    if field_state != "INVALID_METADATA":
        count = sum(1 for row in field_claim["matrix"] if _claimed_complete(row))
    # Fail-closed if upstream code unexpectedly gains a new readiness label.
    if field_state not in FIELD_READINESS or anchor_state not in ANCHOR_READINESS:
        return {
            "decision": "NO_GO", "readiness": "INVALID_METADATA",
            "field_review": "INVALID_METADATA",
            "anchor_review": "INVALID_METADATA",
            "claimed_complete_cells": 0,
            "external_approval": "NOT_AUTHENTICATED",
        }

    if field_state == "INVALID_METADATA" or anchor_state == "INVALID_METADATA":
        state = "INVALID_METADATA"
    elif anchor_state == "UNSAFE_CLAIM":
        state = "UNSAFE_CLAIM"
    elif anchor_state == "SELF_CERTIFICATION_REJECTED":
        state = "SELF_CERTIFICATION_REJECTED"
    elif (field_state != "MANUAL_APPROVAL_REQUIRED"
          or anchor_state != "CLAIMS_UNAUTHENTICATED"):
        state = "INCOMPLETE"
    else:
        # Even two complete fabricated documents carry zero release authority.
        state = "CLAIMS_ONLY"

    return {
        "decision": "NO_GO",
        "readiness": state,
        "field_review": field_state,
        "anchor_review": anchor_state,
        "claimed_complete_cells": count,
        "external_approval": "NOT_AUTHENTICATED",
    }


def review(field_path: Path, anchor_path: Path) -> dict[str, Any]:
    return summarize(_load(field_path), _load(anchor_path))


class PrivateErrorParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        # argparse normally repeats unsafe user input, including paths.
        raise ValueError("invalid field handoff arguments")


def main(argv: list[str] | None = None) -> int:
    parser = PrivateErrorParser(
        description="Two local fixed-status review sheets; no physical attestation, NO_GO only")
    parser.add_argument("--field-metadata", required=True, type=Path)
    parser.add_argument("--anchor-metadata", required=True, type=Path)
    try:
        args = parser.parse_args(argv)
        result = review(args.field_metadata, args.anchor_metadata)
    except ValueError:
        result = summarize(None, None)
    print("Decision:", result["decision"])
    print("Readiness:", result["readiness"])
    print("FieldReview:", result["field_review"])
    print("AnchorReview:", result["anchor_review"])
    print("ClaimedCompleteCells:", str(result["claimed_complete_cells"]) + "/" + str(TOTAL_CELLS))
    print("ExternalApproval:", result["external_approval"])
    # A completed worksheet or hosted CI is NEVER an authorization to release.
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
