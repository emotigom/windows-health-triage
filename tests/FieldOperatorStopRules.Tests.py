"""ADR-072 public procedural stop-rule contract; no private device data."""
from __future__ import annotations
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import field_review_readout as readout
import field_evidence_gate as gate

EXPECTED = [
    ("OPERATOR_AUTHORIZATION_ABSENT", "PRE_RUN", "FIELD_OPERATOR", "DO_NOT_START", "NONE_CREATED", "PHYSICAL_WINDOWS_10_11"),
    ("INITIAL_ROOT_NOT_AUTHENTICATED", "PRE_RUN", "INDEPENDENT_REVIEWER", "DO_NOT_START", "NONE_CREATED", "TRUSTED_INITIAL_ROOT"),
    ("STORAGE_SYNC_BACKUP_POLICY_UNKNOWN", "PRE_RUN", "INDEPENDENT_REVIEWER", "DO_NOT_START", "NONE_CREATED", "INDEPENDENT_SECURITY_PRIVACY"),
    ("SMB_EXPOSURE_SHARED_OR_UNKNOWN", "PRE_RUN", "FIELD_OPERATOR", "DO_NOT_START", "NONE_CREATED", "INDEPENDENT_SECURITY_PRIVACY"),
    ("ELEVATION_NOT_APPROVED", "PRE_RUN", "FIELD_OPERATOR", "DO_NOT_START", "NONE_CREATED", "PHYSICAL_WINDOWS_10_11"),
    ("OPT_IN_SMB_GATE_BLOCKED", "IN_RUN", "FIELD_OPERATOR", "STOP_ADDITIONAL_RUNS", "RETAIN_LOCAL_NO_UPLOAD", "INDEPENDENT_SECURITY_PRIVACY"),
    ("PRIVATE_REPORT_ACL_OR_SCHEMA_FAILED", "IN_RUN", "FIELD_OPERATOR", "STOP_ADDITIONAL_RUNS", "RETAIN_LOCAL_NO_UPLOAD", "INDEPENDENT_SECURITY_PRIVACY"),
    ("PASSIVE_SCAN_UNEXPECTED", "IN_RUN", "FIELD_OPERATOR", "STOP_ADDITIONAL_RUNS", "RETAIN_LOCAL_NO_UPLOAD", "INDEPENDENT_SECURITY_PRIVACY"),
    ("INCOMPLETE_MODES_OR_PROVIDER_UNCERTAINTY", "POST_RUN", "FIELD_OPERATOR", "HOLD_PRIVATE_REVIEW", "RETAIN_LOCAL_NO_UPLOAD", "PHYSICAL_WINDOWS_10_11"),
    ("PRIVATE_EVIDENCE_DISCLOSURE_RISK", "POST_RUN", "INDEPENDENT_REVIEWER", "HOLD_PRIVATE_REVIEW", "RETAIN_LOCAL_NO_UPLOAD", "INDEPENDENT_SECURITY_PRIVACY"),
    ("MISSING_INDEPENDENT_APPROVAL", "RELEASE", "RELEASE_AUTHORITY", "KEEP_NO_GO", "PRIVATE_MINIMIZED_ONLY", "EXTERNAL_RELEASE_AUTHORITY"),
    ("SOURCE_REVOKED_OR_STALE", "RELEASE", "RELEASE_AUTHORITY", "KEEP_NO_GO", "PRIVATE_MINIMIZED_ONLY", "TRUSTED_INITIAL_ROOT"),
]
KEYS = ("id", "stage", "owner", "action", "evidence_disposition", "blocker")

def validate(data, guide, workflow):
    assert type(data) is dict and set(data) == {"schema", "decision", "source", "automatic_execution", "rules"}
    assert type(data["schema"]) is int and data["schema"] == 1
    assert data["decision"] == "NO_GO" and data["source"] == "SYNTHETIC_PROCEDURE_ONLY"
    assert data["automatic_execution"] is False
    assert len(gate.OS) * len(gate.SHELLS) * len(gate.PRIVILEGES) == 8
    assert len(readout.RELEASE_BLOCKERS) == 4
    assert type(data["rules"]) is list and len(data["rules"]) == len(EXPECTED)
    for row, values in zip(data["rules"], EXPECTED):
        assert type(row) is dict and set(row) == set(KEYS)
        assert all(type(row[k]) is str for k in KEYS)
        assert tuple(row[k] for k in KEYS) == values
        assert row["blocker"] in readout.RELEASE_BLOCKERS
        md_row = "| " + " | ".join(chr(96) + v + chr(96) for v in values) + " |"
        assert guide.count(md_row) == 1
    assert guide.startswith("# Physical field operator stop rules")
    for required in (
        "Decision: NO-GO", "issues #2 and #3 OPEN",
        "not a new runner mode", "does not", "retained",
        "not a physical test report", "independent", "SmbCollectionGate: BLOCKED_OR_UNKNOWN"
    ):
        assert required.lower() in guide.lower(), "missing manual guardrail: " + required
    assert workflow.count("run: python tests/FieldOperatorStopRules.Tests.py") == 2
    assert (ROOT / "docs/FIELD-ASSURANCE-BOUNDARIES.md").is_file()
    assert (ROOT / "docs/field-assurance-boundaries.json").is_file()

class FieldOperatorStopRulesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads((ROOT / "docs/field-operator-stop-rules.json").read_text(encoding="utf-8"))
        cls.guide = (ROOT / "docs/FIELD-OPERATOR-STOP-RULES.md").read_text(encoding="utf-8")
        cls.workflow = (ROOT / ".github/workflows/smoke.yml").read_text(encoding="utf-8")
    def check(self, data=None, guide=None, workflow=None):
        validate(self.data if data is None else data,
                 self.guide if guide is None else guide,
                 self.workflow if workflow is None else workflow)
    def test_live_fixed_rules(self):
        self.check()
    def test_no_go_or_auto_execution(self):
        for key, value in (("decision", "GO"), ("automatic_execution", True)):
            data = copy.deepcopy(self.data)
            data[key] = value
            with self.subTest(key=key), self.assertRaises(AssertionError):
                self.check(data=data)
    def test_no_private_identity_fields(self):
        data = copy.deepcopy(self.data)
        data["rules"][0]["host_name"] = "FICTIONAL_PRIVATE_CANARY"
        with self.assertRaises(AssertionError): self.check(data=data)
    def test_operator_cannot_self_approve_root(self):
        data = copy.deepcopy(self.data)
        data["rules"][1]["owner"] = "FIELD_OPERATOR"
        with self.assertRaises(AssertionError): self.check(data=data)
    def test_no_delete_upload_or_continue_action(self):
        for action in ("DELETE_EXISTING_REPORTS", "UPLOAD_RAW_REPORTS", "CONTINUE_COLLECTION"):
            data = copy.deepcopy(self.data)
            data["rules"][5]["action"] = action
            with self.subTest(action=action), self.assertRaises(AssertionError):
                self.check(data=data)
    def test_missing_rule_and_nonexistent_blocker_fail(self):
        data = copy.deepcopy(self.data)
        data["rules"].pop(7)
        with self.assertRaises(AssertionError): self.check(data=data)
        data = copy.deepcopy(self.data)
        data["rules"][-1]["blocker"] = "NONE"
        with self.assertRaises(AssertionError): self.check(data=data)
    def test_both_windows_shell_workflow_requirements(self):
        changed = self.workflow.replace("run: python tests/FieldOperatorStopRules.Tests.py", "run: echo skipped", 1)
        with self.assertRaises(AssertionError): self.check(workflow=changed)
    def test_doc_table_row_drift(self):
        token = "| " + chr(96) + "OPT_IN_SMB_GATE_BLOCKED" + chr(96) + " |"
        guide = self.guide.replace(token, "| REMOVED |", 1)
        with self.assertRaises(AssertionError): self.check(guide=guide)

if __name__ == "__main__":
    unittest.main(verbosity=2)
