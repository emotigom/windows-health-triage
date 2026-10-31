"""ADR-040: optional privacy-safe failure-category to synthetic-fixture index.

This tool NEVER reads device logs or reports, runs scanners/tests, writes files,
accepts raw evidence, or authenticates a physical observation. All CLI results
remain NO_GO and exit 2. A fixture is a *reference*, not proof that the
reported physical failure was reproduced.
"""
from __future__ import annotations

import argparse
from typing import Any

# Fixed, pre-reviewed repo-relative references ONLY. No user-supplied file path.
# tuple = review domain, existing synthetic fixture or NONE, next step.
CASES: dict[str, tuple[str, str, str]] = {
    "schema_contract_failure": ("SCHEMA_CONTRACT", "tests/ReportContract.Tests.ps1", "SYNTHETIC_REFERENCE_ONLY"),
    "event_provider_denied": ("PROVIDER_ACCESS", "tests/EventCollector.Tests.ps1", "SYNTHETIC_REFERENCE_ONLY"),
    "defender_provider_unavailable": ("PROVIDER_COVERAGE", "tests/SecurityCollector.Tests.ps1", "SYNTHETIC_REFERENCE_ONLY"),
    "storage_provider_unavailable": ("PROVIDER_COVERAGE", "tests/HardwareCollector.Tests.ps1", "SYNTHETIC_REFERENCE_ONLY"),
    "monitor_sampling_inconclusive": ("FIELD_STATUS", "tests/MonitorSampling.Tests.ps1", "SYNTHETIC_REFERENCE_ONLY"),
    "passive_native_scan_unexpected": ("PASSIVE_SCAN_BOUNDARY", "tests/FieldValidation.Tests.ps1", "SYNTHETIC_REFERENCE_ONLY"),
    "report_directory_acl_failed": ("FILESYSTEM_ACL", "tests/ReportSecurity.Tests.ps1", "SYNTHETIC_REFERENCE_ONLY"),
    "report_path_reparse_detected": ("NAMESPACE_REPARSE", "tests/AnchorRace.Tests.ps1", "SYNTHETIC_REFERENCE_ONLY"),
    "initial_root_identity_mismatch": ("INITIAL_ROOT_TRUST", "tests/AnchorBoundFieldFileSession.Tests.ps1", "SYNTHETIC_REFERENCE_ONLY"),
    "status_snapshot_acl_review": ("STATUS_FILE_ACL", "tests/FieldStatusAclResearch.Tests.ps1", "SYNTHETIC_REFERENCE_ONLY"),
    "status_metadata_invalid": ("METADATA_VALIDATION", "tests/FieldEvidenceGate.Tests.py", "SYNTHETIC_REFERENCE_ONLY"),
    "privacy_export_unexpected_field": ("REDACTION_BOUNDARY", "tests/Privacy.Tests.ps1", "SYNTHETIC_REFERENCE_ONLY"),
    "cloud_sync_or_backup_unknown": ("MANAGED_STORAGE_POLICY", "NONE", "PRIVATE_MANUAL_REVIEW_ONLY"),
    "external_root_authority_absent": ("INDEPENDENT_AUTHORITY", "NONE", "PRIVATE_MANUAL_REVIEW_ONLY"),
    "unclassified_incomplete": ("UNKNOWN_FAILURE", "NONE", "PRIVATE_MANUAL_REVIEW_ONLY"),
}

# ADR-041: reviewed synthetic test scope, never physical evidence.
COVERAGE: dict[str, str] = {
    "schema_contract_failure": "DIRECT_SYNTHETIC_ASSERTION",
    "event_provider_denied": "DIRECT_SYNTHETIC_ASSERTION",
    "defender_provider_unavailable": "DIRECT_SYNTHETIC_ASSERTION",
    "storage_provider_unavailable": "DIRECT_SYNTHETIC_ASSERTION",
    "monitor_sampling_inconclusive": "DIRECT_SYNTHETIC_ASSERTION",
    "passive_native_scan_unexpected": "DIRECT_SYNTHETIC_ASSERTION",
    "report_directory_acl_failed": "DIRECT_SYNTHETIC_ASSERTION",
    "report_path_reparse_detected": "RELATED_SYNTHETIC_ONLY",
    "initial_root_identity_mismatch": "RELATED_SYNTHETIC_ONLY",
    "status_snapshot_acl_review": "DIRECT_SYNTHETIC_ASSERTION",
    "status_metadata_invalid": "DIRECT_SYNTHETIC_ASSERTION",
    "privacy_export_unexpected_field": "DIRECT_SYNTHETIC_ASSERTION",
    "cloud_sync_or_backup_unknown": "MANUAL_ONLY",
    "external_root_authority_absent": "MANUAL_ONLY",
    "unclassified_incomplete": "MANUAL_ONLY",
}
ALLOWED_COVERAGE = frozenset({"DIRECT_SYNTHETIC_ASSERTION", "RELATED_SYNTHETIC_ONLY", "MANUAL_ONLY"})

ALLOWED_DOMAINS = frozenset(v[0] for v in CASES.values())
ALLOWED_FIXTURES = frozenset(v[1] for v in CASES.values())
ALLOWED_STEPS = frozenset(v[2] for v in CASES.values())


def classify(category: Any) -> dict[str, str]:
    """Return only approved fixed tokens; do not echo unknown input."""
    if type(category) is not str or category not in CASES:
        return {
            "decision": "NO_GO",
            "classification": "INVALID_CATEGORY",
            "review": "PRIVATE_MANUAL_REVIEW",
            "synthetic_fixture": "NONE",
            "coverage": "MANUAL_ONLY",
            "next_step": "PRIVATE_MANUAL_REVIEW_ONLY",
            "physical_evidence": "UNVERIFIED",
            "public_disclosure": "REVIEW_REQUIRED",
        }
    domain, fixture, step = CASES[category]
    return {
        "decision": "NO_GO",
        "classification": "CATEGORY_ONLY",
        "review": domain,
        "synthetic_fixture": fixture,
        "coverage": COVERAGE[category],
        "next_step": step,
        "physical_evidence": "UNVERIFIED",
        "public_disclosure": "REVIEW_REQUIRED",
    }


class PrivateParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        # The default argparse error prints private unexpected CLI arguments.
        raise ValueError("invalid fixed-category arguments")


def main(argv: list[str] | None = None) -> int:
    # No --help auto-exit 0: this CLI is NEVER a release check.
    parser = PrivateParser(
        add_help=False,
        description="Offline fixed failure-to-synthetic-fixture index; never release approval",
    )
    parser.add_argument("--category", required=True)
    try:
        args = parser.parse_args(argv)
        result = classify(args.category)
    except ValueError:
        result = classify(None)
    print("Decision:", result["decision"])
    print("Classification:", result["classification"])
    print("Review:", result["review"])
    print("SyntheticFixture:", result["synthetic_fixture"])
    print("Coverage:", result["coverage"])
    print("NextStep:", result["next_step"])
    print("PhysicalEvidence:", result["physical_evidence"])
    print("PublicDisclosure:", result["public_disclosure"])
    # Also invalid and unclassified paths return 2, never silent GO.
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
