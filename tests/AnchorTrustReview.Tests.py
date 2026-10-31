"""ADR-038 synthetic claim-protocol tests only; no real paths or status reports."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import anchor_trust_review as protocol


def complete_claim():
    return {"schema": 1, **copy.deepcopy(protocol.EXPECTED)}


class AnchorTrustReviewTests(unittest.TestCase):
    def test_initial_template_never_approves(self):
        source = json.loads((ROOT / "docs" / "anchor-trust-template.json").read_text(encoding="utf-8"))
        outcome = protocol.evaluate(source)
        self.assertEqual(outcome["decision"], "NO_GO")
        self.assertEqual(outcome["readiness"], "INCOMPLETE")

    def test_complete_fabricated_claims_are_not_authority(self):
        outcome = protocol.evaluate(complete_claim())
        self.assertEqual(outcome, {
            "decision": "NO_GO",
            "readiness": "CLAIMS_UNAUTHENTICATED",
            "reasons": ["no_authenticated_root_or_external_approval"],
        })

    def test_self_certified_reference_rejected_even_when_everything_else_claims_pass(self):
        bad = complete_claim()
        bad["anchor"]["reference_origin"] = "self_selected"
        self.assertEqual(protocol.evaluate(bad)["readiness"], "SELF_CERTIFICATION_REJECTED")
        self.assertIn("self_selected_anchor_is_not_trusted", protocol.evaluate(bad)["reasons"])

    def test_expired_reference_and_identity_mismatch_fail_closed(self):
        for item, value in [("handle_identity", "mismatch"), ("reference_lifecycle", "expired")]:
            bad = complete_claim()
            bad["anchor"][item] = value
            self.assertEqual(protocol.evaluate(bad)["readiness"], "UNSAFE_CLAIM")

    def test_namespace_and_privacy_risks(self):
        cases = [
            ("namespace", "ancestor_chain", "unsafe"),
            ("namespace", "mount_and_reparse", "unsafe"),
            ("namespace", "volume_policy", "unsupported"),
            ("storage", "file_acl", "unsafe"),
            ("storage", "sync_and_backup", "risk_present"),
        ]
        for section, field, label in cases:
            bad = complete_claim()
            bad[section][field] = label
            self.assertEqual(protocol.evaluate(bad)["readiness"], "UNSAFE_CLAIM")

    def test_separation_of_duties_and_non_synced_claim_missing(self):
        bad = complete_claim()
        bad["review"]["independent_review"] = "not_recorded"
        bad["review"]["authorization"] = "not_recorded"
        self.assertIn(
            "independent_review_or_authorization_claim_missing",
            protocol.evaluate(bad)["reasons"],
        )
        bad = complete_claim()
        bad["storage"]["sync_and_backup"] = "unknown"
        self.assertIn("storage_review_incomplete", protocol.evaluate(bad)["reasons"])

    def test_extra_private_fields_duplicate_keys_and_bad_types_refused(self):
        bad = complete_claim()
        bad["anchor"]["hostname"] = "SECRET_SYNTHETIC_HOST"
        self.assertEqual(protocol.evaluate(bad)["readiness"], "INVALID_METADATA")
        bad = complete_claim()
        bad["review"]["independent_review"] = True
        self.assertEqual(protocol.evaluate(bad)["readiness"], "INVALID_METADATA")
        bad = complete_claim()
        bad["schema"] = True
        self.assertEqual(protocol.evaluate(bad)["readiness"], "INVALID_METADATA")
        for invalid in ({}, [], "claims", None):
            self.assertEqual(protocol.evaluate(invalid)["readiness"], "INVALID_METADATA")

    def test_strict_descriptor_bound_file_read_and_fixed_cli_output(self):
        with tempfile.TemporaryDirectory(prefix="wt-anchor-claims-synthetic-") as temp:
            path = Path(temp) / "claims.json"
            script = ROOT / "tools" / "anchor_trust_review.py"
            canary = "PRIVATE_SYNTHETIC_CANARY"
            for content in [
                json.dumps(complete_claim()),
                '{"schema":1,"schema":1}',
                '{"a":NaN}',
                json.dumps(complete_claim() | {"comment": canary}),
                "X" * (32768 + 1),
            ]:
                path.write_text(content, encoding="utf-8")
                done = subprocess.run(
                    [sys.executable, str(script), "--metadata", str(path)],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(done.returncode, 2)
                self.assertIn("Decision: NO_GO", done.stdout)
                self.assertNotIn(canary, done.stdout + done.stderr)
                self.assertNotIn(temp, done.stdout + done.stderr)
                self.assertNotIn(str(path), done.stdout + done.stderr)
            path.write_text(json.dumps(complete_claim()), encoding="utf-8")
            self.assertEqual(protocol.check(path)["readiness"], "CLAIMS_UNAUTHENTICATED")
            path.unlink()
            self.assertEqual(protocol.check(path)["readiness"], "INVALID_METADATA")
            for args in (["--bad-argument", canary], [], ["--metadata", canary, "--bad", canary]):
                done = subprocess.run(
                    [sys.executable, str(script), *args],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(done.returncode, 2)
                self.assertNotIn(canary, done.stdout + done.stderr)
                self.assertIn("Decision: NO_GO", done.stdout)

    def test_no_signature_or_go_bypass_by_unknown_fields(self):
        bad = complete_claim()
        bad["cryptographic_signature"] = "fake"
        self.assertEqual(protocol.evaluate(bad)["readiness"], "INVALID_METADATA")
        bad = complete_claim()
        bad["review"]["authorization"] = "GO"
        self.assertEqual(protocol.evaluate(bad)["readiness"], "INVALID_METADATA")


if __name__ == "__main__":
    unittest.main(verbosity=2)
