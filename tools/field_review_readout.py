"""ADR-039: offline, fixed-label field review handoff. ALWAYS NO_GO.

Reads only two explicitly supplied, enum-only metadata files using the strict,
bounded reader. It is not a collector, authenticated approval, or upload tool.
No raw reports, personal data, paths, file IDs, notes or arbitrary text are
echoed or written. Both inputs are self-asserted and may refer to unrelated runs or reviewers.
Pairing, freshness, lifecycle retention/revocation, independent review and
repeat-use detection are never verified.
"""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import anchor_trust_review as anchor
import field_evidence_gate as field

TOTAL_CELLS = len(field.OS) * len(field.SHELLS) * len(field.PRIVILEGES)
# Only enum-defined cell tokens; never print filenames, actual OS probe data or paths.
REQUIRED_CELLS = tuple(
    (os_name, shell, privilege)
    for os_name in field.OS
    for shell in field.SHELLS
    for privilege in field.PRIVILEGES
)
REQUIRED_CELL_LABELS = tuple("_".join(cell).upper() for cell in REQUIRED_CELLS)
# Fixed, externally required release gates; never proof that checks happened.
RELEASE_BLOCKERS = (
    "PHYSICAL_WINDOWS_10_11",
    "TRUSTED_INITIAL_ROOT",
    "INDEPENDENT_SECURITY_PRIVACY",
    "EXTERNAL_RELEASE_AUTHORITY",
)
FIELD_SAFETY_REASONS = {"field_validation_failed", "unexpected_native_scan"}

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

    # Reported safety failure takes precedence over reassuring coverage counts.
    # This remains a self-entered *failure claim*, not independent evidence.
    # Ordinary REVIEW/not-run rows remain countable as partial claims only.
    safety_failure = False
    if field_state in FIELD_READINESS and field_state != "INVALID_METADATA":
        safety_failure = (
            any(reason in FIELD_SAFETY_REASONS for reason in field_result["reasons"])
            or any(v == "failed" for v in field_claim["security_reviews"].values())
        )
    safety_label = (
        "UNKNOWN" if field_state not in FIELD_READINESS or field_state == "INVALID_METADATA"
        else "FAILURE_REPORTED" if safety_failure else "NONE_REPORTED"
    )
    # A cell is provisionally accepted only as a *self-entered structural claim*.
    # An unsafe/invalid companion sheet or reported safety failure withholds ALL
    # eight claims; otherwise enumerate missing and incomplete combinations.
    accepted: set[tuple[str, str, str]] = set()
    blocked_anchor = {"INVALID_METADATA", "UNSAFE_CLAIM", "SELF_CERTIFICATION_REJECTED"}
    if (field_state in FIELD_READINESS and anchor_state in ANCHOR_READINESS
            and field_state != "INVALID_METADATA"
            and anchor_state not in blocked_anchor and not safety_failure):
        accepted = {
            (row["os"], row["shell"], row["privilege"])
            for row in field_claim["matrix"] if _claimed_complete(row)
        }
    unaccepted_cells = tuple(
        "_".join(cell).upper() for cell in REQUIRED_CELLS if cell not in accepted
    )
    count = TOTAL_CELLS - len(unaccepted_cells)
    # Fail-closed if upstream code unexpectedly gains a new readiness label.
    if field_state not in FIELD_READINESS or anchor_state not in ANCHOR_READINESS:
        return {
            "decision": "NO_GO", "readiness": "INVALID_METADATA",
            "field_review": "INVALID_METADATA",
            "anchor_review": "INVALID_METADATA",
            "claimed_complete_cells": 0,
            "unaccepted_claim_cells": REQUIRED_CELL_LABELS,
            "claim_coverage_source": "SELF_DECLARED_ONLY",
            "external_approval": "NOT_AUTHENTICATED",
            "sheet_pairing": "NOT_VERIFIED",
            "evidence_freshness": "NOT_VERIFIED",
            "replay_detection": "NOT_AVAILABLE",
            "retention_review": "NOT_VERIFIED",
            "approval_revocation": "NOT_CHECKED",
            "independent_review": "NOT_AUTHENTICATED",
            "field_safety_claims": "UNKNOWN",
            "release_blockers": RELEASE_BLOCKERS,
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
        "unaccepted_claim_cells": unaccepted_cells,
        "claim_coverage_source": "SELF_DECLARED_ONLY",
        "external_approval": "NOT_AUTHENTICATED",
        "sheet_pairing": "NOT_VERIFIED",
        "evidence_freshness": "NOT_VERIFIED",
        "replay_detection": "NOT_AVAILABLE",
        "retention_review": "NOT_VERIFIED",
        "approval_revocation": "NOT_CHECKED",
        "independent_review": "NOT_AUTHENTICATED",
        "field_safety_claims": safety_label,
        "release_blockers": RELEASE_BLOCKERS,
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
    print("ClaimCoverageSource:", result["claim_coverage_source"])
    for cell in result["unaccepted_claim_cells"]:
        print("UnacceptedClaimCell:", cell)
    print("ExternalApproval:", result["external_approval"])
    print("SheetPairing:", result["sheet_pairing"])
    print("IndependentReview:", result["independent_review"])
    print("EvidenceFreshness:", result["evidence_freshness"])
    print("ReplayDetection:", result["replay_detection"])
    print("RetentionReview:", result["retention_review"])
    print("ApprovalRevocation:", result["approval_revocation"])
    print("FieldSafetyClaims:", result["field_safety_claims"])
    for blocker in result["release_blockers"]:
        print("ReleaseBlocker:", blocker)
    # A completed worksheet or hosted CI is NEVER an authorization to release.
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
