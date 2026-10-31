"""Synthetic only. Does NOT run real field collectors or produce reports."""
from pathlib import Path
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("field_evidence_gate", ROOT / "tools" / "field_evidence_gate.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def complete_fixture():
    return {
        "schema": 1,
        "matrix": [
            {"os": os_name, "shell": shell, "privilege": privilege,
             "modes": {mode: "pass" for mode in gate.MODES},
             "schema_contract": "pass", "private_acl": "pass", "passive_scans": "absent"}
            for os_name in gate.OS for shell in gate.SHELLS for privilege in gate.PRIVILEGES
        ],
        "negative_scenarios": {scenario: "observed_inconclusive" for scenario in gate.SCENARIOS},
        "security_reviews": {review: "reviewed" for review in gate.REVIEWS},
    }


class FieldEvidenceGateTests(unittest.TestCase):
    def test_empty_metadata_is_no_go(self):
        self.assertEqual(gate.evaluate({})["readiness"], "INVALID_METADATA")
        self.assertEqual(gate.evaluate(complete_fixture() | {"untrusted_note": "host:SECRET"})["readiness"], "INVALID_METADATA")

    def test_complete_self_asserted_is_still_no_go(self):
        result = gate.evaluate(complete_fixture())
        self.assertEqual(result, {"decision": "NO_GO", "readiness": "MANUAL_APPROVAL_REQUIRED", "reasons": ["no_authenticated_external_release_approval"]})

    def test_missing_windows_11_or_ps7_is_not_a_pass(self):
        data = complete_fixture()
        data["matrix"] = [r for r in data["matrix"] if r["os"] == "windows10" or r["shell"] == "powershell51"]
        self.assertIn("missing_windows_shell_privilege_coverage", gate.evaluate(data)["reasons"])

    def test_inconclusive_field_mode_and_private_acl_block(self):
        data = complete_fixture()
        data["matrix"][0]["modes"]["events"] = "review"
        data["matrix"][0]["private_acl"] = "not_run"
        self.assertIn("field_mode_or_acl_not_passed", gate.evaluate(data)["reasons"])

    def test_native_scan_in_passive_mode_blocks(self):
        data = complete_fixture()
        data["matrix"][0]["passive_scans"] = "unexpected"
        self.assertIn("unexpected_native_scan", gate.evaluate(data)["reasons"])

    def test_actual_failure_blocks(self):
        data = complete_fixture()
        data["matrix"][0]["schema_contract"] = "fail"
        self.assertIn("field_validation_failed", gate.evaluate(data)["reasons"])

    def test_negative_provider_scenarios_and_security_review(self):
        data = complete_fixture()
        data["negative_scenarios"]["defender_unavailable"] = "not_observed"
        data["security_reviews"]["trusted_initial_root"] = "unverified"
        self.assertIn("provider_negative_scenarios_unverified", gate.evaluate(data)["reasons"])
        self.assertIn("manual_security_review_missing", gate.evaluate(data)["reasons"])

    def test_duplicate_row_and_extra_sensitive_field_are_invalid(self):
        data = complete_fixture()
        data["matrix"][1] = dict(data["matrix"][0])
        self.assertEqual(gate.evaluate(data)["readiness"], "INVALID_METADATA")
        data = complete_fixture()
        data["matrix"][0]["hostname"] = "synthetic hostname should be rejected"
        self.assertEqual(gate.evaluate(data)["readiness"], "INVALID_METADATA")

    def test_wrong_types_rejected_instead_of_coerced(self):
        for key, value in [("schema", True), ("matrix", {}), ("negative_scenarios", []), ("security_reviews", "yes")]:
            data = complete_fixture()
            data[key] = value
            self.assertEqual(gate.evaluate(data)["readiness"], "INVALID_METADATA")

    def test_missing_bad_or_oversized_file_and_no_leaking(self):
        with tempfile.TemporaryDirectory(prefix="wt-field-gate-test-") as temp:
            path = Path(temp) / "status.json"
            self.assertEqual(gate.read_evidence(path)["readiness"], "INVALID_METADATA")
            path.write_text("not json", encoding="utf-8")
            self.assertEqual(gate.read_evidence(path)["readiness"], "INVALID_METADATA")
            path.write_bytes(b"A" * (gate.MAX_FILE_BYTES + 1))
            self.assertEqual(gate.read_evidence(path)["readiness"], "INVALID_METADATA")
            path.write_text(json.dumps(complete_fixture() | {"password": "sensitive-canary-dont-print"}), encoding="utf-8")
            result = subprocess.run([sys.executable, str(ROOT / "tools" / "field_evidence_gate.py"), "--metadata", str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn("Decision: NO_GO", result.stdout)
            self.assertNotIn("sensitive-canary-dont-print", result.stdout + result.stderr)
            self.assertNotIn(str(path), result.stdout + result.stderr)

    def test_duplicate_json_keys_rejected_even_when_last_value_is_valid(self):
        with tempfile.TemporaryDirectory(prefix="wt-field-duplicate-synthetic-") as temp:
            path = Path(temp) / "metadata.json"
            clean = json.dumps(complete_fixture())
            variants = [
                clean.replace('"schema": 1,', '"schema": 0, "schema": 1,', 1),
                clean.replace('"privilege": "standard",', '"privilege": "elevated", "privilege": "standard",', 1),
                clean.replace('"defender_unavailable": "observed_inconclusive"',
                              '"defender_unavailable": "fail", "defender_unavailable": "observed_inconclusive"', 1),
            ]
            for raw in variants:
                with self.subTest(duplicate_position=raw.find('": "fail"')):
                    path.write_text(raw, encoding="utf-8")
                    self.assertEqual(gate.read_evidence(path)["readiness"], "INVALID_METADATA")
                    result = subprocess.run(
                        [sys.executable, str(ROOT / "tools" / "field_evidence_gate.py"),
                         "--metadata", str(path)], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 2)
                    self.assertIn("Decision: NO_GO", result.stdout)
                    self.assertIn("Readiness: INVALID_METADATA", result.stdout)
                    self.assertNotIn(str(path), result.stdout + result.stderr)

    def test_nonfinite_json_and_symlink_are_not_evidence(self):
        with tempfile.TemporaryDirectory(prefix="wt-field-nonfinite-synthetic-") as temp:
            path = Path(temp) / "data.json"
            raw = json.dumps(complete_fixture()).replace('"schema": 1,', '"schema": NaN,', 1)
            path.write_text(raw, encoding="utf-8")
            self.assertEqual(gate.read_evidence(path)["readiness"], "INVALID_METADATA")
            path.write_text(json.dumps(complete_fixture()), encoding="utf-8")
            link = Path(temp) / "link.json"
            try:
                link.symlink_to(path)
            except (OSError, NotImplementedError):
                return  # Windows policy may deny creation; do not claim a positive test.
            self.assertEqual(gate.read_evidence(link)["readiness"], "INVALID_METADATA")

    def test_nonregular_file_and_safe_argument_errors(self):
        with tempfile.TemporaryDirectory(prefix="wt-field-path-synthetic-") as temp:
            directory = Path(temp)
            self.assertEqual(gate.read_evidence(directory)["readiness"], "INVALID_METADATA")
            if hasattr(__import__("os"), "mkfifo"):
                fifo = directory / "named-pipe"
                __import__("os").mkfifo(fifo)
                self.assertEqual(gate.read_evidence(fifo)["readiness"], "INVALID_METADATA")
            result = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "field_evidence_gate.py"),
                 "--metadata", "SENSITIVE-PATH-CANARY", "--unrecognized=SECRET-CANARY"],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn("Decision: NO_GO", result.stdout)
            self.assertNotIn("SENSITIVE-PATH-CANARY", result.stdout + result.stderr)
            self.assertNotIn("SECRET-CANARY", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
