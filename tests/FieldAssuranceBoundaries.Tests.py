"""ADR-071: static, synthetic-only evidence-boundary drift and negative controls.

The public ledger records NO observed physical Windows cells. This test does not
authenticate any approval, consult a real PC, inspect raw reports or grant GO.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import field_evidence_gate as gate
import field_review_readout as readout

REGISTRY = ROOT / "docs/field-assurance-boundaries.json"
GUIDE = ROOT / "docs/FIELD-ASSURANCE-BOUNDARIES.md"
WORKFLOW = ROOT / ".github/workflows/smoke.yml"

WITNESSES = {
    "ORDINARY_SMB_SHARE_CLASSIFIER": ("tests/FieldSmbPreflight.Tests.ps1", "SYNTHETIC_ONLY", "EMPTY_OR_PARTIAL_PROVIDER_OUTPUT_IS_NOT_PRIVACY_PROOF"),
    "OPTIONAL_SMB_COLLECTION_GUARD": ("tests/FieldSmbCollectionGate.Tests.ps1", "SYNTHETIC_ONLY", "FINAL_SNAPSHOT_DOES_NOT_CLOSE_TOCTOU"),
    "LOCAL_PATH_PREFLIGHT": ("tests/FieldPreflight.Tests.ps1", "SYNTHETIC_ONLY", "PATH_REVIEW_IS_NOT_ROOT_AUTHENTICATION"),
    "PASSIVE_FIVE_MODE_RUNNER": ("tests/FieldValidation.Integration.Tests.ps1", "HOSTED_CI_ONLY", "HOSTED_WINDOWS_SERVER_IS_NOT_REAL_WINDOWS_10_11_WORKSTATION"),
    "OFFLINE_FIELD_STATUS_CLAIMS": ("tests/FieldEvidenceGate.Tests.py", "SYNTHETIC_ONLY", "SELF_ENTERED_STATUS_IS_NOT_AUTHENTICATED_EVIDENCE"),
    "ANCHOR_REVIEW_CLAIMS": ("tests/AnchorTrustReview.Tests.py", "SYNTHETIC_ONLY", "CLAIMED_ROOT_OR_APPROVAL_IS_NOT_INDEPENDENT_ATTESTATION"),
}
BLOCKERS = {
    "PHYSICAL_WINDOWS_10_11": "#2",
    "TRUSTED_INITIAL_ROOT": "#2 / #3",
    "INDEPENDENT_SECURITY_PRIVACY": "#3",
    "EXTERNAL_RELEASE_AUTHORITY": "#2 / #3",
}
SMB_LIMITS = {
    "ADMINISTRATIVE_OR_SPECIAL_SHARES_NOT_ENUMERATED",
    "EFFECTIVE_REMOTE_ACCESS_NOT_VERIFIED",
    "SILENTLY_INCOMPLETE_SHARE_INVENTORY_UNDETECTABLE",
    "POST_CHECK_SMB_OR_PATH_TOCTOU_UNRESOLVED",
    "MANAGED_SYNC_BACKUP_AND_DLP_NOT_VERIFIED",
    "ROOT_PROVENANCE_NOT_AUTHENTICATED",
}


def validate(data: object, workflow: str, guide: str, template: object) -> None:
    assert type(data) is dict
    assert set(data) == {
        "schema", "decision", "source", "observed_physical_cells",
        "physical_cells", "code_witnesses", "external_release_blockers",
        "unverified_smb_limits",
    }
    assert type(data["schema"]) is int and data["schema"] == 1
    assert data["decision"] == "NO_GO"
    assert data["source"] == "SYNTHETIC_AND_HOSTED_CI_ONLY"
    assert type(data["observed_physical_cells"]) is int
    assert data["observed_physical_cells"] == 0
    assert len(gate.OS) * len(gate.SHELLS) * len(gate.PRIVILEGES) == 8
    expected = {(o, s, p) for o in gate.OS for s in gate.SHELLS for p in gate.PRIVILEGES}
    rows = data["physical_cells"]
    assert type(rows) is list and len(rows) == 8
    seen = []
    for row in rows:
        assert type(row) is dict and set(row) == {"os", "shell", "privilege", "status"}
        assert row["status"] == "NOT_AUTHENTICATED"
        assert all(type(row[k]) is str for k in row)
        seen.append((row["os"], row["shell"], row["privilege"]))
    assert len(set(seen)) == 8 and set(seen) == expected
    assert type(template) is dict and type(template.get("matrix")) is list
    assert {(r["os"], r["shell"], r["privilege"]) for r in template["matrix"]} == expected
    assert all(all(v == "not_run" for v in r["modes"].values())
               and r["schema_contract"] == "not_run"
               and r["private_acl"] == "not_run"
               and r["passive_scans"] == "not_checked" for r in template["matrix"])

    witnesses = data["code_witnesses"]
    assert type(witnesses) is list and len(witnesses) == len(WITNESSES)
    names = [w["id"] for w in witnesses]
    assert len(set(names)) == len(WITNESSES) and set(names) == set(WITNESSES)
    for w in witnesses:
        assert type(w) is dict and set(w) == {"id", "scope", "test_path", "boundary"}
        path, scope, boundary = WITNESSES[w["id"]]
        assert w == {"id": w["id"], "scope": scope, "test_path": path, "boundary": boundary}
        assert (ROOT / path).is_file(), "Referenced synthetic witness does not exist"
        assert workflow.count("run: ./" + path) == 2, "Both Windows shells must invoke witness"
        assert path in guide and boundary in json.dumps(w, ensure_ascii=False)
    assert workflow.count("run: python tests/FieldAssuranceBoundaries.Tests.py") == 2

    blockers = data["external_release_blockers"]
    assert type(blockers) is list and len(blockers) == 4
    assert [b["id"] for b in blockers] == list(readout.RELEASE_BLOCKERS)
    assert set(BLOCKERS) == set(readout.RELEASE_BLOCKERS)
    for b in blockers:
        assert type(b) is dict and set(b) == {"id", "issue", "status"}
        assert b["issue"] == BLOCKERS[b["id"]]
        assert b["status"] == "PENDING_EXTERNAL"
        assert b["id"] in guide and b["issue"] in guide
    limits = data["unverified_smb_limits"]
    assert type(limits) is list and len(limits) == len(SMB_LIMITS)
    assert len(set(limits)) == len(limits) and set(limits) == SMB_LIMITS
    assert "Decision: NO-GO" in guide
    assert "NOT_AUTHENTICATED" in guide
    assert "not a physical test report" in guide
    assert "Issues **#2 and #3 remain OPEN**" in guide


class FieldAssuranceBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = json.loads(REGISTRY.read_text(encoding="utf-8"))
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.guide = GUIDE.read_text(encoding="utf-8")
        cls.template = json.loads((ROOT / "docs/field-evidence-template.json").read_text(encoding="utf-8"))

    def check(self, data=None, workflow=None, guide=None, template=None) -> None:
        validate(
            self.data if data is None else data,
            self.workflow if workflow is None else workflow,
            self.guide if guide is None else guide,
            self.template if template is None else template,
        )

    def test_live_registry_never_claims_release_approval(self):
        self.check()

    def test_one_physical_cell_cannot_be_marked_passed(self):
        changed = copy.deepcopy(self.data)
        changed["physical_cells"][0]["status"] = "PASS"
        with self.assertRaises(AssertionError): self.check(data=changed)

    def test_even_complete_synthetic_matrix_cannot_claim_one_real_cell(self):
        changed = copy.deepcopy(self.data)
        changed["observed_physical_cells"] = 8
        with self.assertRaises(AssertionError): self.check(data=changed)

    def test_external_blocker_may_not_be_self_approved(self):
        changed = copy.deepcopy(self.data)
        changed["external_release_blockers"][2]["status"] = "APPROVED"
        with self.assertRaises(AssertionError): self.check(data=changed)

    def test_missing_or_relabeled_smb_witness_fails(self):
        changed = copy.deepcopy(self.data)
        changed["code_witnesses"][0]["scope"] = "REAL_WINDOWS_WORKSTATION"
        with self.assertRaises(AssertionError): self.check(data=changed)
        changed = copy.deepcopy(self.data)
        changed["code_witnesses"].pop(1)
        with self.assertRaises(AssertionError): self.check(data=changed)

    def test_removed_workflow_step_must_fail_for_both_shells(self):
        altered = self.workflow.replace("run: ./tests/FieldSmbPreflight.Tests.ps1", "run: echo skip", 1)
        with self.assertRaises(AssertionError): self.check(workflow=altered)

    def test_silent_incomplete_inventory_limit_is_mandatory(self):
        altered = copy.deepcopy(self.data)
        altered["unverified_smb_limits"].remove("SILENTLY_INCOMPLETE_SHARE_INVENTORY_UNDETECTABLE")
        with self.assertRaises(AssertionError): self.check(data=altered)

    def test_private_free_text_canary_is_invalid_schema(self):
        altered = copy.deepcopy(self.data)
        altered["private_hostname"] = "FICTIONAL_DO_NOT_PUBLISH_CANARY"
        with self.assertRaises(AssertionError): self.check(data=altered)

    def test_pending_template_cannot_be_rewritten_as_observed(self):
        altered = copy.deepcopy(self.template)
        altered["matrix"][0]["modes"]["quick"] = "pass"
        with self.assertRaises(AssertionError): self.check(template=altered)


if __name__ == "__main__":
    unittest.main(verbosity=2)
