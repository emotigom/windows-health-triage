"""ADR-040: test fixed synthetic case map and privacy boundary only."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "field_failure_triage", ROOT / "tools/field_failure_triage.py"
)
triage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(triage)


class FieldFailureTriageTests(unittest.TestCase):
    def test_all_cases_refer_only_to_existing_allowlisted_synthetic_fixtures(self):
        self.assertEqual(len(triage.CASES), 15)
        for key, (domain, fixture, step) in triage.CASES.items():
            self.assertRegex(key, r"^[a-z][a-z0-9_]+$")
            self.assertIn(domain, triage.ALLOWED_DOMAINS)
            self.assertIn(fixture, triage.ALLOWED_FIXTURES)
            self.assertIn(step, triage.ALLOWED_STEPS)
            result = triage.classify(key)
            self.assertEqual(result["decision"], "NO_GO")
            self.assertEqual(result["classification"], "CATEGORY_ONLY")
            self.assertEqual(result["review"], domain)
            self.assertEqual(result["synthetic_fixture"], fixture)
            self.assertEqual(result["next_step"], step)
            self.assertEqual(result["physical_evidence"], "UNVERIFIED")
            self.assertEqual(result["public_disclosure"], "REVIEW_REQUIRED")
            if fixture == "NONE":
                self.assertEqual(step, "PRIVATE_MANUAL_REVIEW_ONLY")
            else:
                self.assertEqual(step, "SYNTHETIC_REFERENCE_ONLY")
                self.assertTrue(fixture.startswith("tests/"))
                self.assertIn(Path(fixture).suffix, (".ps1", ".py"))
                self.assertTrue((ROOT / fixture).is_file(), key)
                self.assertFalse(Path(fixture).is_absolute())
                self.assertNotIn("..", Path(fixture).parts)

    def test_known_provider_and_security_categories_map_correctly(self):
        expected = {
            "event_provider_denied": "tests/EventCollector.Tests.ps1",
            "defender_provider_unavailable": "tests/SecurityCollector.Tests.ps1",
            "storage_provider_unavailable": "tests/HardwareCollector.Tests.ps1",
            "passive_native_scan_unexpected": "tests/FieldValidation.Tests.ps1",
            "report_directory_acl_failed": "tests/ReportSecurity.Tests.ps1",
            "report_path_reparse_detected": "tests/AnchorRace.Tests.ps1",
            "initial_root_identity_mismatch": "tests/AnchorBoundFieldFileSession.Tests.ps1",
            "privacy_export_unexpected_field": "tests/Privacy.Tests.ps1",
        }
        for symptom, fixture in expected.items():
            self.assertEqual(triage.classify(symptom)["synthetic_fixture"], fixture)

    def test_absence_of_independent_authority_and_sync_risk_cannot_auto_reproduce(self):
        for category in (
            "cloud_sync_or_backup_unknown", "external_root_authority_absent",
            "unclassified_incomplete",
        ):
            result = triage.classify(category)
            self.assertEqual(result["next_step"], "PRIVATE_MANUAL_REVIEW_ONLY")
            self.assertEqual(result["synthetic_fixture"], "NONE")
            self.assertEqual(result["decision"], "NO_GO")

    def test_unknown_raw_report_and_sensitive_strings_are_never_echoed(self):
        for raw in (None, "", 123, [], {}, "C:\\PRIVATE\\RAW_REPORT.txt",
                    "SYNTHETIC_PRIVATE_SECRET", "events; --run-scanner",
                    "--category=report_directory_acl_failed", "../run.ps1"):
            self.assertEqual(triage.classify(raw), {
                "decision": "NO_GO", "classification": "INVALID_CATEGORY",
                "review": "PRIVATE_MANUAL_REVIEW", "synthetic_fixture": "NONE",
                "next_step": "PRIVATE_MANUAL_REVIEW_ONLY",
                "physical_evidence": "UNVERIFIED", "public_disclosure": "REVIEW_REQUIRED",
            })

    def test_cli_only_fixed_labels_always_exit_2(self):
        script = str(ROOT / "tools/field_failure_triage.py")
        for category in triage.CASES:
            result = subprocess.run(
                [sys.executable, script, "--category", category],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stderr, "")
            self.assertIn("Decision: NO_GO", result.stdout)
            self.assertIn("PhysicalEvidence: UNVERIFIED", result.stdout)
            self.assertIn("PublicDisclosure: REVIEW_REQUIRED", result.stdout)
            self.assertIn("SyntheticFixture:", result.stdout)
            self.assertNotIn("GO\n", result.stdout.replace("NO_GO\n", ""))

    def test_invalid_cli_args_missing_unknown_extra_and_help_never_leak(self):
        script = str(ROOT / "tools/field_failure_triage.py")
        secret = "SYNTHETIC_PRIVATE_CANARY"
        for args in (
            [], ["--category", secret],
            ["--category", "event_provider_denied", "--private", secret],
            ["--category", secret, "--category", secret],
            ["--help"],
            ["--category", "event_provider_denied", "--", secret],
            ["--category", "event_provider_denied", "\n" + secret],
        ):
            result = subprocess.run(
                [sys.executable, script, *args],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("Decision: NO_GO", result.stdout)
            self.assertNotIn(secret, result.stdout + result.stderr)
            self.assertNotIn("C:\\PRIVATE", result.stdout + result.stderr)
            self.assertEqual(result.stderr, "")

    def test_cli_fixture_reference_never_executes_file_or_reads_report(self):
        # Pure classification; tests themselves execute no other scripts.
        script = ROOT / "tools/field_failure_triage.py"
        source = script.read_text(encoding="utf-8")
        for forbidden in (
            "subprocess", "os.system", "eval(", "exec(", "open(",
            "read_text(", "read_bytes(", "write_text(", "write_bytes(",
            "Path(", "shutil", "requests", "urllib",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("return 2", source)
        self.assertIn("add_help=False", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
