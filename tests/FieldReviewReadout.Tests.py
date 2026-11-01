"""ADR-039 synthetic only: strict, privacy-bounded two-sheet handoff."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import field_review_readout as readout
import anchor_trust_review as trust
import field_evidence_gate as field


def full_field():
    return {
        "schema": 1,
        "matrix": [
            {
                "os": os_name, "shell": shell, "privilege": privilege,
                "modes": {mode: "pass" for mode in field.MODES},
                "schema_contract": "pass",
                "private_acl": "pass",
                "passive_scans": "absent",
            }
            for os_name in field.OS
            for shell in field.SHELLS
            for privilege in field.PRIVILEGES
        ],
        "negative_scenarios": {x: "observed_inconclusive" for x in field.SCENARIOS},
        "security_reviews": {x: "reviewed" for x in field.REVIEWS},
    }


def full_anchor():
    return {"schema": 1, **copy.deepcopy(trust.EXPECTED)}


class FieldReviewReadoutTests(unittest.TestCase):
    def test_checked_in_pending_templates_are_not_verified(self):
        field_data = json.loads((ROOT / "docs/field-evidence-template.json").read_text(encoding="utf-8"))
        anchor_data = json.loads((ROOT / "docs/anchor-trust-template.json").read_text(encoding="utf-8"))
        result = readout.summarize(field_data, anchor_data)
        self.assertEqual(result["decision"], "NO_GO")
        self.assertEqual(result["readiness"], "INCOMPLETE")
        self.assertEqual(result["claimed_complete_cells"], 0)
        self.assertEqual(result["external_approval"], "NOT_AUTHENTICATED")

    def test_fabricated_fully_complete_8_cells_are_claims_only(self):
        result = readout.summarize(full_field(), full_anchor())
        self.assertEqual(result, {
            "decision": "NO_GO", "readiness": "CLAIMS_ONLY",
            "field_review": "MANUAL_APPROVAL_REQUIRED",
            "anchor_review": "CLAIMS_UNAUTHENTICATED",
            "claimed_complete_cells": 8, "external_approval": "NOT_AUTHENTICATED",
            "sheet_pairing": "NOT_VERIFIED",
            "independent_review": "NOT_AUTHENTICATED",
            "evidence_freshness": "NOT_VERIFIED",
            "replay_detection": "NOT_AVAILABLE",
            "retention_review": "NOT_VERIFIED",
            "approval_revocation": "NOT_CHECKED",
        })

    def test_two_independently_valid_sheets_do_not_prove_same_session_or_reviewer(self):
        field_claim = full_field()
        anchor_claim = full_anchor()
        # Both worksheets may have been fabricated at unrelated times.
        # No source/session identifier or reviewer identity is accepted.
        outcome = readout.summarize(field_claim, anchor_claim)
        self.assertEqual(outcome["claimed_complete_cells"], 8)
        self.assertEqual(outcome["sheet_pairing"], "NOT_VERIFIED")
        self.assertEqual(outcome["independent_review"], "NOT_AUTHENTICATED")
        self.assertEqual(outcome["external_approval"], "NOT_AUTHENTICATED")
        self.assertEqual(outcome["decision"], "NO_GO")

        anchor_claim["review"]["independent_review"] = "not_recorded"
        pending = readout.summarize(field_claim, anchor_claim)
        self.assertEqual(pending["sheet_pairing"], "NOT_VERIFIED")
        self.assertEqual(pending["independent_review"], "NOT_AUTHENTICATED")
        self.assertEqual(pending["readiness"], "INCOMPLETE")

    def test_invalid_other_sheet_cannot_launder_complete_field_claims(self):
        field_claim = full_field()
        anchor_claim = full_anchor()
        anchor_claim["review"]["reviewer_identity"] = "SECRET_SYNTHETIC_CANARY"
        result = readout.summarize(field_claim, anchor_claim)
        self.assertEqual(result["readiness"], "INVALID_METADATA")
        self.assertEqual(result["claimed_complete_cells"], 0)
        self.assertEqual(result["sheet_pairing"], "NOT_VERIFIED")
        self.assertEqual(result["independent_review"], "NOT_AUTHENTICATED")
        for fake in ("reviewer_identity", "session_id", "verified_signature", "approval"):
            modified = full_field()
            modified[fake] = "SECRET_SYNTHETIC_CANARY"
            rejected = readout.summarize(modified, full_anchor())
            self.assertEqual(rejected["readiness"], "INVALID_METADATA")
            self.assertEqual(rejected["claimed_complete_cells"], 0)
            self.assertNotIn("SECRET_SYNTHETIC_CANARY", repr(rejected))

    def test_backdated_and_copied_self_reports_never_prove_freshness_or_replay_safety(self):
        # These are invented status-only metadata, not real physical evidence.
        with tempfile.TemporaryDirectory(prefix="wt-stale-handoff-synthetic-") as temp:
            root = Path(temp)
            original = root / "older-field.json"
            anchor = root / "older-anchor.json"
            original.write_text(json.dumps(full_field()), encoding="utf-8")
            anchor.write_text(json.dumps(full_anchor()), encoding="utf-8")
            old_time = 946684800  # Year 2000; not a verified collection timestamp.
            os.utime(original, (old_time, old_time))
            os.utime(anchor, (old_time, old_time))
            first = readout.review(original, anchor)
            self.assertEqual(first["readiness"], "CLAIMS_ONLY")
            self.assertEqual(first["evidence_freshness"], "NOT_VERIFIED")
            self.assertEqual(first["replay_detection"], "NOT_AVAILABLE")
            self.assertEqual(first["decision"], "NO_GO")

            # A byte-for-byte copy has a new filesystem metadata timestamp;
            # neither it nor repeated invocations gains a trusted provenance.
            copied = root / "copied-field.json"
            copied.write_bytes(original.read_bytes())
            copied_anchor = root / "copied-anchor.json"
            copied_anchor.write_bytes(anchor.read_bytes())
            second = readout.review(copied, copied_anchor)
            third = readout.review(copied, copied_anchor)
            self.assertEqual(first, second)
            self.assertEqual(second, third)
            self.assertEqual(second["claimed_complete_cells"], 8)
            self.assertEqual(second["evidence_freshness"], "NOT_VERIFIED")
            self.assertEqual(second["replay_detection"], "NOT_AVAILABLE")

    def test_self_declared_freshness_and_replay_proofs_cannot_elevate_readout(self):
        for extra in ("collected_at", "valid_until", "run_id", "freshness_verified",
                      "nonce", "replay_proof", "authenticated_review"):
            field_claim = full_field()
            field_claim[extra] = "SYNTHETIC_SECRET_CANARY"
            denied = readout.summarize(field_claim, full_anchor())
            self.assertEqual(denied["readiness"], "INVALID_METADATA")
            self.assertEqual(denied["claimed_complete_cells"], 0)
            self.assertEqual(denied["evidence_freshness"], "NOT_VERIFIED")
            self.assertEqual(denied["replay_detection"], "NOT_AVAILABLE")
            self.assertEqual(denied["decision"], "NO_GO")
            self.assertNotIn("SYNTHETIC_SECRET_CANARY", repr(denied))

        anchor_claim = full_anchor()
        anchor_claim["review"]["observed_on"] = "SYNTHETIC_SECRET_CANARY"
        denied = readout.summarize(full_field(), anchor_claim)
        self.assertEqual(denied["claimed_complete_cells"], 0)
        self.assertEqual(denied["evidence_freshness"], "NOT_VERIFIED")
        self.assertEqual(denied["replay_detection"], "NOT_AVAILABLE")

    def test_expired_or_unsafe_reference_suppresses_complete_claim_count(self):
        # These are synthetic self-entered enum claims, never a real revocation check.
        scenarios = (
            ("anchor", "reference_lifecycle", "expired", "UNSAFE_CLAIM"),
            ("anchor", "handle_identity", "mismatch", "UNSAFE_CLAIM"),
            ("anchor", "reference_origin", "self_selected", "SELF_CERTIFICATION_REJECTED"),
            ("storage", "sync_and_backup", "risk_present", "UNSAFE_CLAIM"),
            ("storage", "file_acl", "unsafe", "UNSAFE_CLAIM"),
            ("namespace", "ancestor_chain", "unsafe", "UNSAFE_CLAIM"),
        )
        for group, key, value, expected in scenarios:
            with self.subTest(negative_label=value):
                anchor_claim = full_anchor()
                anchor_claim[group][key] = value
                result = readout.summarize(full_field(), anchor_claim)
                self.assertEqual(result["readiness"], expected)
                self.assertEqual(result["claimed_complete_cells"], 0)
                self.assertEqual(result["retention_review"], "NOT_VERIFIED")
                self.assertEqual(result["approval_revocation"], "NOT_CHECKED")
                self.assertEqual(result["decision"], "NO_GO")

        # A well-formed yet incomplete worksheet is not unsafe by definition:
        # counting syntactic field claims remains allowed but unverified.
        pending_anchor = full_anchor()
        pending_anchor["review"]["authorization"] = "not_recorded"
        partial = readout.summarize(full_field(), pending_anchor)
        self.assertEqual(partial["readiness"], "INCOMPLETE")
        self.assertEqual(partial["claimed_complete_cells"], 8)
        self.assertEqual(partial["approval_revocation"], "NOT_CHECKED")

    def test_retention_or_revocation_claim_does_not_become_an_approval(self):
        original_field = full_field()
        original_anchor = full_anchor()
        for key in ("retention_days", "purged_claimed", "revocation_checked",
                    "approved_until", "legal_hold", "previous_approval"):
            field_claim = copy.deepcopy(original_field)
            field_claim[key] = "SYNTHETIC_PRIVATE_CANARY"
            result = readout.summarize(field_claim, original_anchor)
            self.assertEqual(result["readiness"], "INVALID_METADATA")
            self.assertEqual(result["claimed_complete_cells"], 0)
            self.assertNotIn("SYNTHETIC_PRIVATE_CANARY", repr(result))
            self.assertEqual(result["retention_review"], "NOT_VERIFIED")
            self.assertEqual(result["approval_revocation"], "NOT_CHECKED")
        anchor_claim = full_anchor()
        anchor_claim["review"]["revocation_checked"] = "SYNTHETIC_PRIVATE_CANARY"
        rejected = readout.summarize(original_field, anchor_claim)
        self.assertEqual(rejected["readiness"], "INVALID_METADATA")
        self.assertEqual(rejected["claimed_complete_cells"], 0)
        self.assertEqual(rejected["approval_revocation"], "NOT_CHECKED")

    def test_partial_and_failed_cells_do_not_count_as_completed_claims(self):
        evidence = full_field()
        evidence["matrix"][0]["modes"]["hardware"] = "review"
        evidence["matrix"][1]["private_acl"] = "fail"
        evidence["matrix"][2]["passive_scans"] = "unexpected"
        evidence["matrix"][3]["schema_contract"] = "not_run"
        outcome = readout.summarize(evidence, full_anchor())
        self.assertEqual(outcome["claimed_complete_cells"], 4)
        self.assertEqual(outcome["readiness"], "INCOMPLETE")
        self.assertEqual(outcome["field_review"], "INCOMPLETE")

    def test_missing_matrix_cell_and_provider_negative_observation(self):
        evidence = full_field()
        evidence["matrix"].pop()
        result = readout.summarize(evidence, full_anchor())
        self.assertEqual(result["claimed_complete_cells"], 7)
        self.assertEqual(result["readiness"], "INCOMPLETE")
        evidence = full_field()
        evidence["negative_scenarios"]["defender_unavailable"] = "not_observed"
        result = readout.summarize(evidence, full_anchor())
        self.assertEqual(result["claimed_complete_cells"], 8)
        self.assertEqual(result["readiness"], "INCOMPLETE")

    def test_self_certification_mismatch_and_storage_risk(self):
        scenarios = [
            ("anchor", "reference_origin", "self_selected", "SELF_CERTIFICATION_REJECTED"),
            ("anchor", "handle_identity", "mismatch", "UNSAFE_CLAIM"),
            ("storage", "sync_and_backup", "risk_present", "UNSAFE_CLAIM"),
            ("review", "independent_review", "not_recorded", "INCOMPLETE"),
        ]
        for section, key, label, expected in scenarios:
            anchor_data = full_anchor()
            anchor_data[section][key] = label
            result = readout.summarize(full_field(), anchor_data)
            self.assertEqual(result["readiness"], expected)
            self.assertEqual(result["decision"], "NO_GO")
            self.assertEqual(result["external_approval"], "NOT_AUTHENTICATED")

    def test_invalid_schema_never_counts_and_no_sensitive_fields_accepted(self):
        data = full_field()
        data["matrix"][1] = copy.deepcopy(data["matrix"][0])
        result = readout.summarize(data, full_anchor())
        self.assertEqual(result["readiness"], "INVALID_METADATA")
        self.assertEqual(result["claimed_complete_cells"], 0)
        bad_anchor = full_anchor()
        bad_anchor["review"]["reviewer_email"] = "synthetic-hidden@invalid"
        self.assertEqual(readout.summarize(full_field(), bad_anchor)["readiness"], "INVALID_METADATA")
        self.assertEqual(readout.summarize(None, full_anchor())["claimed_complete_cells"], 0)
        self.assertEqual(readout.summarize(full_field(), None)["readiness"], "INVALID_METADATA")
        self.assertEqual(readout.summarize({"raw_report": "SECRET"}, full_anchor())["readiness"], "INVALID_METADATA")

    def test_cli_two_independent_files_fixed_labels_no_leaks_or_write(self):
        with tempfile.TemporaryDirectory(prefix="wt-field-handoff-synthetic-") as temp:
            root = Path(temp)
            field_path = root / "field.json"
            anchor_path = root / "anchor.json"
            field_path.write_text(json.dumps(full_field()), encoding="utf-8")
            anchor_path.write_text(json.dumps(full_anchor()), encoding="utf-8")
            before = (field_path.read_bytes(), anchor_path.read_bytes())
            cmd = [sys.executable, str(ROOT / "tools/field_review_readout.py"),
                   "--field-metadata", str(field_path),
                   "--anchor-metadata", str(anchor_path)]
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 2)
            self.assertIn("Decision: NO_GO", result.stdout)
            self.assertIn("Readiness: CLAIMS_ONLY", result.stdout)
            self.assertIn("ClaimedCompleteCells: 8/8", result.stdout)
            self.assertIn("ExternalApproval: NOT_AUTHENTICATED", result.stdout)
            self.assertIn("SheetPairing: NOT_VERIFIED", result.stdout)
            self.assertIn("IndependentReview: NOT_AUTHENTICATED", result.stdout)
            self.assertIn("EvidenceFreshness: NOT_VERIFIED", result.stdout)
            self.assertIn("ReplayDetection: NOT_AVAILABLE", result.stdout)
            self.assertIn("RetentionReview: NOT_VERIFIED", result.stdout)
            self.assertIn("ApprovalRevocation: NOT_CHECKED", result.stdout)
            self.assertEqual(before, (field_path.read_bytes(), anchor_path.read_bytes()))
            self.assertNotIn(temp, result.stdout + result.stderr)
            self.assertNotIn("windows10", result.stdout + result.stderr)
            self.assertEqual(sorted(p.name for p in root.iterdir()), ["anchor.json", "field.json"])

            secret = "SYNTHETIC_PRIVATE_CANARY"
            for payload in [
                '{"schema":1,"schema":1}',
                '{"x":NaN}',
                json.dumps(full_field() | {"hostname": secret}),
                "X" * 32769,
            ]:
                field_path.write_text(payload, encoding="utf-8")
                rejected = subprocess.run(cmd, capture_output=True, text=True, check=False)
                self.assertEqual(rejected.returncode, 2)
                self.assertIn("Readiness: INVALID_METADATA", rejected.stdout)
                self.assertIn("ClaimedCompleteCells: 0/8", rejected.stdout)
                self.assertIn("SheetPairing: NOT_VERIFIED", rejected.stdout)
                self.assertIn("IndependentReview: NOT_AUTHENTICATED", rejected.stdout)
                self.assertIn("RetentionReview: NOT_VERIFIED", rejected.stdout)
                self.assertIn("ApprovalRevocation: NOT_CHECKED", rejected.stdout)
                self.assertNotIn(temp, rejected.stdout + rejected.stderr)
                self.assertNotIn(secret, rejected.stdout + rejected.stderr)
            field_path.write_text(json.dumps(full_field()), encoding="utf-8")
            anchor_path.write_text(json.dumps(full_anchor() | {"email": secret}), encoding="utf-8")
            rejected = subprocess.run(cmd, capture_output=True, text=True, check=False)
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("Readiness: INVALID_METADATA", rejected.stdout)
            self.assertNotIn(secret, rejected.stdout + rejected.stderr)
            self.assertIn("ClaimedCompleteCells: 0/8", rejected.stdout)
            self.assertIn("SheetPairing: NOT_VERIFIED", rejected.stdout)
            self.assertIn("IndependentReview: NOT_AUTHENTICATED", rejected.stdout)
            self.assertIn("RetentionReview: NOT_VERIFIED", rejected.stdout)
            self.assertIn("ApprovalRevocation: NOT_CHECKED", rejected.stdout)

    def test_missing_invalid_cli_arguments_and_link_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="wt-field-handoff-args-") as temp:
            root = Path(temp)
            canary = "PRIVATE_PATH_AND_ARG_CANARY"
            script = str(ROOT / "tools/field_review_readout.py")
            for extra in [[], ["--unknown", canary],
                          ["--field-metadata", canary, "--anchor-metadata", canary],
                          ["--field-metadata", canary, "--anchor-metadata", canary,
                           "--extra", canary]]:
                done = subprocess.run([sys.executable, script, *extra],
                                      capture_output=True, text=True, check=False)
                self.assertEqual(done.returncode, 2)
                self.assertIn("Decision: NO_GO", done.stdout)
                self.assertNotIn(canary, done.stdout + done.stderr)
                self.assertNotIn(temp, done.stdout + done.stderr)

            anchor_path = root / "anchor.json"
            anchor_path.write_text(json.dumps(full_anchor()), encoding="utf-8")
            missing = readout.review(root / "missing.json", anchor_path)
            self.assertEqual(missing["readiness"], "INVALID_METADATA")
            real_file = root / "real.json"
            real_file.write_text(json.dumps(full_field()), encoding="utf-8")
            link = root / "alias.json"
            try:
                os.symlink(real_file, link)
            except (OSError, NotImplementedError):
                pass  # Windows runner may disallow unprivileged symlink creation.
            else:
                self.assertEqual(readout.review(link, anchor_path)["readiness"], "INVALID_METADATA")


if __name__ == "__main__":
    unittest.main(verbosity=2)
