"""ADR-055: synthetic-only regression contract for human release checklists.

Checks documented obligations and code-owned NO_GO labels. Does NOT verify
actual Windows hardware, external approval, report provenance, or privacy.
"""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import field_evidence_gate as gate
import field_review_readout as readout

REQUIRED = ("Quick, Events, Hardware, Monitor, passive Integrity; "
            "schema v1; private ACL; passive scans absent")
ENVIRONMENTS = {(o, p, privilege)
                for o in ("Windows 10", "Windows 11")
                for p in ("5.1", "7")
                for privilege in ("Standard", "Authorized elevated")}
BLOCKERS = {
    "PHYSICAL_WINDOWS_10_11": ("#2", "naturally observed"),
    "TRUSTED_INITIAL_ROOT": ("#2 / #3", "source revocation"),
    "INDEPENDENT_SECURITY_PRIVACY": ("#3", "cloud backup/sync"),
    "EXTERNAL_RELEASE_AUTHORITY": ("#2 / #3", "revocation outside this repository"),
}
ANCHOR_REQUIREMENTS = (
    "independently authorized, revocable source",
    "Real Windows 10/11 test devices",
    "Path/namespace/race/volume",
    "Actual Windows owner/DACL",
    "Privacy/security/release authority decisions",
    "Issues #2 and #3 assessed",
)


def section(md: str, heading: str) -> list[str]:
    lines = md.splitlines()
    positions = [i for i, line in enumerate(lines) if line == "## " + heading]
    assert len(positions) == 1, "missing or duplicated checklist heading " + heading
    start = positions[0] + 1
    stop = next((i for i in range(start, len(lines))
                 if lines[i].startswith("## ")), len(lines))
    return lines[start:stop]


def table(md: str, heading: str, headers: tuple[str, ...]) -> list[tuple[str, ...]]:
    lines = section(md, heading)
    hdr = "| " + " | ".join(headers) + " |"
    positions = [i for i, line in enumerate(lines) if line == hdr]
    assert len(positions) == 1, "missing or duplicated table " + heading
    pos = positions[0]
    sep = "| " + " | ".join(["---"] * len(headers)) + " |"
    assert lines[pos + 1] == sep, "missing table separator " + heading
    rows: list[tuple[str, ...]] = []
    for line in lines[pos + 2:]:
        if not line.startswith("|"):
            break
        fields = tuple(x.strip() for x in line.strip().strip("|").split("|"))
        assert len(fields) == len(headers), "truncated row in " + heading
        assert all(fields), "blank cell in " + heading
        rows.append(fields)
    return rows


def check(docs: dict[str, str]) -> None:
    assert set(docs) == {"field", "handoff", "anchor"}
    assert tuple(gate.OS) == ("windows10", "windows11")
    assert tuple(gate.SHELLS) == ("powershell51", "powershell7")
    assert tuple(gate.PRIVILEGES) == ("standard", "elevated")
    assert tuple(gate.MODES) == ("quick", "events", "hardware", "monitor", "integrity")
    assert tuple(gate.SCENARIOS) == (
        "defender_unavailable", "event_access_denied", "storage_provider_unavailable")
    assert tuple(gate.REVIEWS) == (
        "trusted_initial_root", "in_call_reparse_and_mount",
        "real_acl_and_privacy", "managed_or_synced_storage")
    assert len(ENVIRONMENTS) == 8

    for label, heading in (("field", "Manual matrix"),
                           ("handoff", "Eight environment combinations")):
        rows = table(docs[label], heading,
                     ("Real OS", "PowerShell", "Privilege", "Required checks"))
        environments = [(o, shell, privilege)
                        for o, shell, privilege, checks in rows]
        assert len(environments) == 8 and set(environments) == ENVIRONMENTS, (
            "missing or duplicate physical test environment: " + label)
        assert all(checks == REQUIRED for _, _, _, checks in rows), (
            "missing required mode/ACL/schema/passive check: " + label)

    handoff_matrix = "\n".join(section(docs["handoff"], "Eight environment combinations"))
    for item in ("8 distinct observations", "not 8 repetitions of a hosted Windows CI job",
                 "Defender-unavailable", "Event Log access-denied",
                 "storage-provider-unavailable", "only when naturally observed",
                 "Never simulate"):
        assert item.lower() in handoff_matrix.lower(), "physical scope weakened: " + item
    assert "does not establish hardware compatibility" in docs["field"]
    assert "Never attach raw diagnostic reports to public issues" in docs["field"]
    assert "No process termination" in docs["field"]

    rows = table(docs["handoff"],
        "PR #59 / ADR-054 — field failure precedence and explicit release blockers",
        ("Fixed ReleaseBlocker label", "External evidence and responsible reviewer", "Issue"))
    names = [row[0] for row in rows]
    assert len(rows) == 4 and len(set(names)) == 4, "release blockers removed or duplicated"
    assert tuple(names) == tuple(readout.RELEASE_BLOCKERS), "doc/code release blockers drifted"
    assert set(names) == set(BLOCKERS), "release blocker enum unexpectedly changed"
    for name, desc, issue in rows:
        expected_issue, phrase = BLOCKERS[name]
        assert issue == expected_issue, "issue ownership lost: " + name
        assert phrase.lower() in desc.lower(), "required external verification weakened: " + name
    assert "required, not satisfied" in docs["handoff"].lower()
    assert "all-PASS fabricated worksheet is still NO_GO" in docs["handoff"]
    assert "leave issues #2/#3 OPEN" in docs["handoff"]

    anchor = section(docs["anchor"], "Release blocking criteria")
    bullets = [row for row in anchor if row.startswith("- [ ] ")]
    assert len(bullets) == 6, "independent anchor approval checklist changed"
    for required in ANCHOR_REQUIREMENTS:
        assert sum(required.lower() in item.lower() for item in bullets) == 1, (
            "missing independent review duty: " + required)
    assert "**Current decision: NO-GO.**" in docs["anchor"]
    assert "This project currently has no mechanism to verify that approval" in docs["anchor"]


def sources() -> dict[str, str]:
    return {
        "field": (ROOT / "docs/FIELD-VALIDATION.md").read_text(encoding="utf-8"),
        "handoff": (ROOT / "docs/FIELD-REVIEW-HANDOFF.md").read_text(encoding="utf-8"),
        "anchor": (ROOT / "docs/ANCHOR-TRUST-PROTOCOL.md").read_text(encoding="utf-8"),
    }


class ReleaseChecklistContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.docs = sources()

    def test_live_documents_and_fixed_release_blocker_code(self):
        check(self.docs)

    def reject_mutation(self, file_key: str, old: str, new: str):
        self.assertIn(old, self.docs[file_key], "test setup must match actual checklist")
        changed = dict(self.docs)
        changed[file_key] = changed[file_key].replace(old, new, 1)
        with self.assertRaises(AssertionError):
            check(changed)

    def test_missing_one_real_environment_in_either_checklist_fails(self):
        for file_key, os_name in (("field", "Windows 11"), ("handoff", "Windows 10")):
            row = "| " + os_name + " | 7 | Authorized elevated | " + REQUIRED + " |"
            self.reject_mutation(file_key, row, "")

    def test_downgrading_one_acl_or_monitor_check_fails(self):
        original = "| Windows 10 | 5.1 | Standard | " + REQUIRED + " |"
        self.reject_mutation("field", original, original.replace("private ACL", "optional ACL"))
        self.reject_mutation("handoff", original, original.replace("Monitor", "optional Monitor"))

    def test_deleting_release_blocker_or_issue_mapping_fails(self):
        row = ("| TRUSTED_INITIAL_ROOT | Authorized initial volume/root authority, "
               "held-object lineage, actual Windows ACL/namespace/mount behavior, "
               "and source revocation; the test-only probes are not production "
               "attestation. | #2 / #3 |")
        self.reject_mutation("handoff", row, "")
        row2 = ("| EXTERNAL_RELEASE_AUTHORITY | Accountable release authority "
                "verifies the preceding external evidence, documents the decision, "
                "and handles revocation outside this repository. | #2 / #3 |")
        self.reject_mutation("handoff", row2, row2.replace("#2 / #3", "#3"))

    def test_provider_and_human_privacy_requirement_downgrade_fails(self):
        self.reject_mutation("handoff", "only when naturally observed", "whenever simulated")
        self.reject_mutation("anchor",
            "- [ ] Actual Windows owner/DACL and cloud/managed storage backup/sync independently reviewed on the real device.",
            "")
        self.reject_mutation("anchor", "**Current decision: NO-GO.**",
                             "**Current decision: GO.**")
        self.reject_mutation("field", "does not establish hardware compatibility",
                             "establishes hardware compatibility")


if __name__ == "__main__":
    unittest.main(verbosity=2)
