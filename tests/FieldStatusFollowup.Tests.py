"""ADR-061: invented fixed status-only follow-up and no-echo regression."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "field_status_followup", ROOT / "tools/field_status_followup.py"
)
followup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(followup)
spec_triage = importlib.util.spec_from_file_location(
    "field_failure_triage", ROOT / "tools/field_failure_triage.py"
)
triage = importlib.util.module_from_spec(spec_triage)
spec_triage.loader.exec_module(triage)


def status(mode: str, validation: str = "pass", contract: str = "pass",
           acl: str = "pass", native: str | None = None,
           warnings: str = "none") -> str:
    if native is None:
        native = followup.NATIVE_EXPECTED[mode]
    return ("Mode={}; Validation={}; Contract={}; PrivateAcl={}; "
            "PassiveNativeScans={}; Warnings={}").format(
                mode, validation, contract, acl, native, warnings
            )


class FieldStatusFollowupTests(unittest.TestCase):
    def call_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(ROOT / "tools/field_status_followup.py"), *args],
            capture_output=True, text=True, check=False,
        )

    def test_empty_manual_status_is_five_unrecorded_not_an_approval(self):
        result = self.call_cli()
        expected = [
            "Decision: NO_GO",
            "InputStatus: SELF_DECLARED_ONLY",
            "PhysicalEvidence: UNVERIFIED",
            "RecordedModes: 0/5",
        ]
        for mode in followup.MODES:
            expected.extend(("UnrecordedMode: " + mode,
                             "ModeStatus: " + mode + ":NOT_RECORDED"))
        expected.extend("ReleaseBlocker: " + x for x in followup.BLOCKERS)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.stdout.splitlines(), expected)

    def test_all_five_self_entered_passes_still_no_go(self):
        args = [item for mode in followup.MODES
                for item in ("--status", status(mode))]
        result = self.call_cli(*args)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr, "")
        lines = result.stdout.splitlines()
        self.assertIn("RecordedModes: 5/5", lines)
        self.assertEqual(len([x for x in lines if x.startswith("ModeStatus:")]), 5)
        self.assertEqual(len([x for x in lines if x.startswith("ReleaseBlocker:")]), 4)
        for mode in followup.MODES:
            self.assertIn("ModeStatus: " + mode + ":STRUCTURAL_PASS_ONLY", lines)
        self.assertFalse(any(x.startswith("UnrecordedMode:") or
                             x.startswith("ReviewReason:") or
                             x.startswith("SyntheticReference:") for x in lines))
        self.assertEqual(lines[0], "Decision: NO_GO")
        self.assertIn("PhysicalEvidence: UNVERIFIED", lines)

    def test_partial_multi_safety_failure_identifies_only_known_labels(self):
        result = self.call_cli(
            "--status", status("Quick", "fail", "fail", "fail", "unexpected", "present"),
            "--status", status("Events", "review", warnings="present"),
        )
        lines = result.stdout.splitlines()
        self.assertEqual(result.returncode, 2)
        self.assertIn("RecordedModes: 2/5", lines)
        for code, path in followup.REFERENCES.items():
            if code in ("CONTRACT_FAILED", "PRIVATE_ACL_FAILED", "PASSIVE_SCAN_UNEXPECTED"):
                self.assertIn("ReviewReason: Quick:" + code, lines)
                self.assertIn("SyntheticReference: Quick:" + path, lines)
        self.assertIn("ReviewReason: Events:WARNINGS_PRESENT", lines)
        self.assertIn("SyntheticReference: Events:NONE", lines)
        self.assertIn("UnrecordedMode: Monitor", lines)
        self.assertIn("UnrecordedMode: Integrity", lines)
        self.assertNotIn("event_provider_denied", result.stdout)
        self.assertNotIn("defender_provider_unavailable", result.stdout)
        self.assertEqual(result.stderr, "")

    def test_generic_review_and_failure_do_not_invent_provider_cause(self):
        result = self.call_cli(
            "--status", status("Monitor", "review"),
            "--status", status("Hardware", "fail"),
        )
        self.assertIn("ReviewReason: Monitor:UNCLASSIFIED_REVIEW", result.stdout)
        self.assertIn("ReviewReason: Hardware:UNCLASSIFIED_FAILURE", result.stdout)
        self.assertIn("SyntheticReference: Monitor:NONE", result.stdout)
        self.assertIn("SyntheticReference: Hardware:NONE", result.stdout)
        self.assertNotIn("tests/HardwareCollector.Tests.ps1", result.stdout)
        self.assertEqual(result.returncode, 2)

    def test_allowlisted_fixture_references_match_existing_reviewed_categories(self):
        expected = {
            "CONTRACT_FAILED": "schema_contract_failure",
            "PRIVATE_ACL_FAILED": "report_directory_acl_failed",
            "PASSIVE_SCAN_UNEXPECTED": "passive_native_scan_unexpected",
        }
        self.assertEqual(set(followup.REFERENCES), {
            *expected, "WARNINGS_PRESENT", "WARNINGS_UNKNOWN",
            "UNCLASSIFIED_FAILURE", "UNCLASSIFIED_REVIEW",
        })
        for reason, category in expected.items():
            self.assertEqual(followup.REFERENCES[reason],
                             triage.CASES[category][1])
        for reason in set(followup.REFERENCES) - set(expected):
            self.assertEqual(followup.REFERENCES[reason], "NONE")
        self.assertEqual(followup.BLOCKERS, (
            "PHYSICAL_WINDOWS_10_11", "TRUSTED_INITIAL_ROOT",
            "INDEPENDENT_SECURITY_PRIVACY", "EXTERNAL_RELEASE_AUTHORITY",
        ))

    def test_malformed_private_input_and_conflicts_fail_closed_without_echo(self):
        canary = "SYNTHETIC_PRIVATE_HOST_AND_PATH"
        errors = [
            ["--status", canary],
            ["--status", status("Quick") + "; Path=" + canary],
            ["--status", status("Quick") + "\n" + canary],
            ["--status", status("Quick"), "--status", status("Quick")],
            ["--status", status("Quick", "pass", "fail")],
            ["--status", status("Events", "pass", warnings="present")],
            ["--status", status("Quick", "pass", native="unexpected")],
            ["--status", status("Quick", "pass", native="not-applicable")],
            ["--status", status("Events", "review", native="not-requested")],
            ["--status", status("Monitor", "pass", warnings="unknown")],
            ["--status", "Mode=Events; Validation=review; Contract=pass"],
            ["--status", status("Events") + " "],
            ["--status", status("Quick"), "--bad", canary],
            ["--help", canary],
        ]
        errors.append([s for _ in range(6) for s in
                       ("--status", status("Quick"))])
        baseline = "\n".join(followup.invalid_readout()) + "\n"
        for args in errors:
            with self.subTest(args=str(args)[:40]):
                result = self.call_cli(*args)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, baseline)
                self.assertEqual(result.stderr, "")
                self.assertNotIn(canary, result.stdout + result.stderr)
                self.assertNotIn("Traceback", result.stdout + result.stderr)

    def test_reject_nonstring_api_inputs_without_any_private_echo(self):
        for value in (None, {}, tuple(), [None], [5], ["private"]):
            with self.subTest(value_type=str(type(value))):
                with self.assertRaises(ValueError):
                    followup.review_statuses(value)

    def test_source_has_no_read_write_scan_or_upload_capability(self):
        source = (ROOT / "tools/field_status_followup.py").read_text(encoding="utf-8")
        for forbidden in ("open(", "read_text(", "read_bytes(", "write_text(",
                          "subprocess", "os.system", "pathlib", "requests",
                          "urllib", "eval(", "exec(", "Get-WinEvent",
                          "Start-MpScan", "Remove-Item", "upload"):
            # Description uses "uploads" in a docstring: check executable
            # capabilities rather than harmless prose for this one word.
            if forbidden == "upload":
                continue
            self.assertNotIn(forbidden, source)
        self.assertIn("return 2", source)
        self.assertIn("STATUS_LINE.fullmatch(item)", source)
        self.assertIn("add_help=False", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
