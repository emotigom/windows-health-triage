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



FIELD_REASON_CODES = {
    "missing_windows_shell_privilege_coverage", "field_validation_failed",
    "unexpected_native_scan", "field_mode_or_acl_not_passed",
    "provider_negative_scenarios_unverified", "manual_security_review_missing",
}
ANCHOR_REASON_CODES = {
    "external_anchor_claim_or_identity_missing", "namespace_checks_incomplete",
    "storage_review_incomplete", "independent_review_or_authorization_claim_missing",
}
UPSTREAM_SINGLE_REASON = {
    "INVALID_METADATA": "invalid_or_extra_metadata",
    "MANUAL_APPROVAL_REQUIRED": "no_authenticated_external_release_approval",
    "CLAIMS_UNAUTHENTICATED": "no_authenticated_root_or_external_approval",
    "UNSAFE_CLAIM": "identity_or_path_or_storage_risk",
    "SELF_CERTIFICATION_REJECTED": "self_selected_anchor_is_not_trusted",
}


def _valid_evaluation(result: Any, *, is_field: bool) -> bool:
    """Strict NO_GO decision/reason contract for both upstream evaluators."""
    if (type(result) is not dict
            or set(result) != {"decision", "readiness", "reasons"}
            or type(result["decision"]) is not str
            or result["decision"] != "NO_GO"
            or type(result["readiness"]) is not str
            or type(result["reasons"]) is not list):
        return False
    state = result["readiness"]
    if state not in (FIELD_READINESS if is_field else ANCHOR_READINESS):
        return False
    reasons = result["reasons"]
    if not reasons or len(reasons) > 6 or any(type(x) is not str for x in reasons):
        return False
    if len(reasons) != len(set(reasons)):
        return False
    if state == "INCOMPLETE":
        return set(reasons) <= (FIELD_REASON_CODES if is_field else ANCHOR_REASON_CODES)
    return reasons == [UPSTREAM_SINGLE_REASON.get(state)]


def _invalid_readout() -> dict[str, Any]:
    """Evaluator-independent, fixed-token fallback with no private input."""
    return {
        "decision": "NO_GO", "readiness": "INVALID_METADATA",
        "field_review": "INVALID_METADATA", "anchor_review": "INVALID_METADATA",
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


def _summarize(field_claim: Any, anchor_claim: Any) -> dict[str, Any]:
    """Safely combine already-independent validation results without GO."""
    field_result = field.evaluate(field_claim)
    anchor_result = anchor.evaluate(anchor_claim)
    if not _valid_evaluation(field_result, is_field=True) or not _valid_evaluation(anchor_result, is_field=False):
        return _invalid_readout()
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
        return _invalid_readout()

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

def summarize(field_claim: Any, anchor_claim: Any) -> dict[str, Any]:
    """Guard unexpected evaluator changes without leaking exception text."""
    try:
        return _summarize(field_claim, anchor_claim)
    except Exception:
        return _invalid_readout()


# Exact, allowlisted output contract; never serialize caller-supplied dictionaries.
OUTPUT_KEYS = frozenset({
    "decision", "readiness", "field_review", "anchor_review",
    "claimed_complete_cells", "unaccepted_claim_cells", "claim_coverage_source",
    "external_approval", "sheet_pairing", "independent_review",
    "evidence_freshness", "replay_detection", "retention_review",
    "approval_revocation", "field_safety_claims", "release_blockers",
})
SUMMARY_STATES = {
    "INVALID_METADATA", "INCOMPLETE", "UNSAFE_CLAIM",
    "SELF_CERTIFICATION_REJECTED", "CLAIMS_ONLY",
}
SAFETY_STATES = {"UNKNOWN", "NONE_REPORTED", "FAILURE_REPORTED"}
TRUST_CONSTANTS = {
    "decision": "NO_GO",
    "claim_coverage_source": "SELF_DECLARED_ONLY",
    "external_approval": "NOT_AUTHENTICATED",
    "sheet_pairing": "NOT_VERIFIED",
    "independent_review": "NOT_AUTHENTICATED",
    "evidence_freshness": "NOT_VERIFIED",
    "replay_detection": "NOT_AVAILABLE",
    "retention_review": "NOT_VERIFIED",
    "approval_revocation": "NOT_CHECKED",
}


def _valid_output(result: Any) -> bool:
    """Reject unrecognized, inconsistent or untrusted summary fields."""
    if type(result) is not dict or set(result) != OUTPUT_KEYS:
        return False
    for key, expected in TRUST_CONSTANTS.items():
        if type(result[key]) is not str or result[key] != expected:
            return False
    if (type(result["readiness"]) is not str
            or result["readiness"] not in SUMMARY_STATES
            or type(result["field_review"]) is not str
            or result["field_review"] not in FIELD_READINESS
            or type(result["anchor_review"]) is not str
            or result["anchor_review"] not in ANCHOR_READINESS
            or type(result["field_safety_claims"]) is not str
            or result["field_safety_claims"] not in SAFETY_STATES):
        return False
    count = result["claimed_complete_cells"]
    cells = result["unaccepted_claim_cells"]
    if (type(count) is not int or not 0 <= count <= TOTAL_CELLS
            or type(cells) is not tuple
            or type(result["release_blockers"]) is not tuple
            or result["release_blockers"] != RELEASE_BLOCKERS):
        return False
    if cells != tuple(label for label in REQUIRED_CELL_LABELS if label in cells):
        return False
    if count + len(cells) != TOTAL_CELLS:
        return False
    if (result["readiness"] in {"INVALID_METADATA", "UNSAFE_CLAIM",
                                "SELF_CERTIFICATION_REJECTED"}
            or result["field_safety_claims"] == "FAILURE_REPORTED"):
        if count != 0 or cells != REQUIRED_CELL_LABELS:
            return False
    return True


def render_readout(result: Any) -> tuple[str, ...]:
    """Exact ordered fixed-only lines; fail closed on unexpected internals.

    The rendered lines are never evidence of a physical run or release.
    """
    if not _valid_output(result):
        result = _invalid_readout()
    lines = [
        "Decision: NO_GO",
        "Readiness: " + result["readiness"],
        "FieldReview: " + result["field_review"],
        "AnchorReview: " + result["anchor_review"],
        "ClaimedCompleteCells: " + str(result["claimed_complete_cells"]) + "/" + str(TOTAL_CELLS),
        "ClaimCoverageSource: SELF_DECLARED_ONLY",
    ]
    lines.extend("UnacceptedClaimCell: " + cell for cell in result["unaccepted_claim_cells"])
    lines.extend([
        "ExternalApproval: NOT_AUTHENTICATED",
        "SheetPairing: NOT_VERIFIED",
        "IndependentReview: NOT_AUTHENTICATED",
        "EvidenceFreshness: NOT_VERIFIED",
        "ReplayDetection: NOT_AVAILABLE",
        "RetentionReview: NOT_VERIFIED",
        "ApprovalRevocation: NOT_CHECKED",
        "FieldSafetyClaims: " + result["field_safety_claims"],
    ])
    lines.extend("ReleaseBlocker: " + blocker for blocker in RELEASE_BLOCKERS)
    return tuple(lines)


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
    for line in render_readout(result):
        print(line)
    # A completed worksheet or hosted CI is NEVER an authorization to release.
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
