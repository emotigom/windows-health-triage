"""Synthetic-only offline field status recorder tests. No real hardware/reports."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
RECORDER = ROOT / "tools" / "field_status_recorder.py"
GATE = ROOT / "tools" / "field_evidence_gate.py"
TEMPLATE = ROOT / "docs" / "field-evidence-template.json"
GOOD = [
    "Quick:review:pass:pass:not-requested:none",
    "Events:pass:pass:pass:not-applicable:none",
    "Hardware:review:pass:pass:not-applicable:present",
    "Monitor:pass:pass:pass:not-applicable:none",
    "Integrity:pass:pass:pass:not-requested:none",
]


def run_cli(source, out, statuses=GOOD, *extra):
    return subprocess.run([
        sys.executable, str(RECORDER), "--metadata", str(source),
        "--output", str(out), "--os", "windows11", "--shell", "powershell7",
        "--privilege", "standard", "--observed-local-only",
        *[x for s in statuses for x in ("--status", s)], *extra,
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


class FieldStatusRecorderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wt-private-status-synthetic-")
        self.addCleanup(self.temp.cleanup)
        self.input = Path(self.temp.name) / "input.json"
        self.output = Path(self.temp.name) / "new.json"
        self.input.write_bytes(TEMPLATE.read_bytes())

    def test_creates_only_new_snapshot_and_preserves_pending_rows(self):
        before = self.input.read_bytes()
        result = run_cli(self.input, self.output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.input.read_bytes(), before)
        data = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(len(data["matrix"]), 8)
        rows = [r for r in data["matrix"] if
                (r["os"], r["shell"], r["privilege"]) == ("windows11", "powershell7", "standard")]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["modes"]["quick"], "review")
        self.assertEqual(row["modes"]["hardware"], "review")
        self.assertEqual(row["schema_contract"], "pass")
        self.assertEqual(row["private_acl"], "pass")
        self.assertEqual(row["passive_scans"], "absent")
        self.assertEqual(sum(r["modes"]["quick"] == "not_run" for r in data["matrix"]), 7)
        self.assertEqual(data["negative_scenarios"]["defender_unavailable"], "not_observed")
        self.assertEqual(data["security_reviews"]["trusted_initial_root"], "unverified")
        gate = subprocess.run([sys.executable, str(GATE), "--metadata", str(self.output)],
                              capture_output=True, text=True)
        self.assertEqual(gate.returncode, 2)
        self.assertIn("Decision: NO_GO", gate.stdout)
        self.assertIn("Readiness: INCOMPLETE", gate.stdout)
        self.assertNotIn(str(self.output), result.stdout + result.stderr + gate.stdout + gate.stderr)

    def test_refuses_overwrite_and_reentry(self):
        self.assertEqual(run_cli(self.input, self.output).returncode, 0)
        first = self.output.read_bytes()
        again = run_cli(self.input, self.output)
        self.assertEqual(again.returncode, 2)
        self.assertEqual(self.output.read_bytes(), first)
        third = run_cli(self.output, Path(self.temp.name) / "another.json")
        self.assertEqual(third.returncode, 2)

    def test_unknown_duplicate_missing_and_sensitive_status_rejected(self):
        bads = [
            GOOD[:-1], GOOD[:-1] + [GOOD[0]],
            GOOD[:-1] + ["Integrity:pass:pass:pass:not-requested:HOSTNAME-CANARY"],
            GOOD[:-1] + ["Integrity:pass:pass:pass:unexpected:none"],
            ["Quick:pass:pass:pass:not-requested:present", *GOOD[1:]],
            ["Quick:review:fail:pass:not-requested:none", *GOOD[1:]],
            ["Quick:pass:pass:pass:not-applicable:none", *GOOD[1:]],
            [GOOD[0], "Events:pass:pass:pass:not-requested:none", *GOOD[2:]],
        ]
        for statuses in bads:
            with self.subTest(statuses=statuses):
                result = run_cli(self.input, self.output, statuses)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(self.output.exists())
                self.assertNotIn("HOSTNAME-CANARY", result.stdout + result.stderr)
                self.assertNotIn(str(self.input), result.stdout + result.stderr)
                self.assertNotIn(str(self.output), result.stdout + result.stderr)

    def test_fail_is_not_downgraded_to_review_or_pass(self):
        statuses = [
            "Quick:fail:pass:pass:unexpected:none",
            "Events:fail:fail:pass:not-applicable:unknown",
            *GOOD[2:],
        ]
        result = run_cli(self.input, self.output, statuses)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(self.output.read_text(encoding="utf-8"))
        row = data["matrix"][-2]
        self.assertEqual(row["modes"]["quick"], "fail")
        self.assertEqual(row["schema_contract"], "fail")
        self.assertEqual(row["passive_scans"], "unexpected")

    def test_invalid_input_public_repo_output_and_extra_args(self):
        self.input.write_text('{"host":"CANARY-PRIVATE"}', encoding="utf-8")
        result = run_cli(self.input, self.output)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("CANARY-PRIVATE", result.stdout + result.stderr)
        self.input.write_bytes(TEMPLATE.read_bytes())
        result = run_cli(self.input, ROOT / "docs" / "NEVER-CREATE-FIELD-STATUS.json")
        self.assertEqual(result.returncode, 2)
        self.assertFalse((ROOT / "docs" / "NEVER-CREATE-FIELD-STATUS.json").exists())
        result = run_cli(self.input, self.output, GOOD, "--private-raw-path=CANARY-SECRET")
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("CANARY-SECRET", result.stdout + result.stderr)

    def test_explicit_acknowledgement_and_invalid_template(self):
        args = [
            sys.executable, str(RECORDER), "--metadata", str(self.input),
            "--output", str(self.output), "--os", "windows11", "--shell", "powershell7",
            "--privilege", "standard", *[x for s in GOOD for x in ("--status", s)],
        ]
        result = subprocess.run(args, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.output.exists())
        data = json.loads(self.input.read_text(encoding="utf-8"))
        data["matrix"].pop()
        self.input.write_text(json.dumps(data), encoding="utf-8")
        self.assertEqual(run_cli(self.input, self.output).returncode, 2)

    def test_input_symlink_not_consumed_when_supported(self):
        source = Path(self.temp.name) / "link.json"
        try:
            source.symlink_to(self.input)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation denied by host policy")
        result = run_cli(source, self.output)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.output.exists())

    def test_duplicate_source_keys_cannot_be_silently_overwritten(self):
        base = self.input.read_text(encoding="utf-8")
        duplicate = base.replace('"schema": 1,', '"schema": 0, "schema": 1,', 1)
        self.assertNotEqual(duplicate, base)
        self.input.write_text(duplicate, encoding="utf-8")
        result = run_cli(self.input, self.output)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.output.exists())
        self.assertNotIn(str(self.input), result.stdout + result.stderr)
        self.assertNotIn(str(self.output), result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
