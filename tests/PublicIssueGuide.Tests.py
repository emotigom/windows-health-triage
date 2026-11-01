"""ADR-063: document/issue-template disclosure boundary, invented mutations only.

This checks documentation policy drift, not real disclosure prevention,
authentic physical test results, or effective Windows privacy controls.
"""
from __future__ import annotations

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]

FILES = {
    "validation": ROOT / "docs/VALIDATION.md",
    "development": ROOT / "docs/DEVELOPMENT.md",
    "guide": ROOT / "docs/PUBLIC-ISSUE-GUIDE.md",
    "template": ROOT / ".github/ISSUE_TEMPLATE/bug_report.md",
    "security": ROOT / "SECURITY.md",
    "triage": ROOT / "docs/FIELD-FAILURE-TRIAGE.md",
    "readme": ROOT / "README.md",
}


def policy_contract(docs: dict[str, str]) -> None:
    v, d = docs["validation"], docs["development"]
    g, t = docs["guide"], docs["template"]

    assert "## Public bug reports — synthetic-only, independently reviewed" in v
    assert "## Approved physical validation — still pending" in v
    assert "test-owned passive five-mode field runner" in v
    assert "**eight real observations**" in v
    assert "**Release remains NO-GO**" in v
    assert "Issues #2 and #3 remain OPEN" in v
    assert "docs/PUBLIC-ISSUE-GUIDE.md" in v
    assert "docs/FIELD-REVIEW-HANDOFF.md" in v

    # Old, privacy-unsafe wording and stale hosted-CI claims must not return.
    for forbidden in (
        "Specific warning text from `SUMMARY.md` (redact user name",
        "before attaching diagnostic reports to any issue",
        "CI executes only this synthetic test, **not** the manual field runner",
        "No actual Windows runtime test is possible in this Linux execution",
    ):
        assert forbidden not in v

    assert "## Releasing — independent approval required" in d
    assert "**Current decision: NO-GO. No tagged pre-release" in d
    assert "docs/PUBLIC-ISSUE-GUIDE.md" in d
    assert "issues #2 and #3" not in d.lower() or "stay OPEN" in d

    for required in (
        "**Default: keep the observation private.**",
        "**Never attach, paste, link or commit**",
        "**synthetic**",
        "entirely invented",
        "Security vulnerabilities",
    ):
        assert required.lower() in g.lower(), required
    assert "SUMMARY.md" in g and "screenshots" in g.lower()
    assert "independent" in g.lower()
    assert "**NO-GO:**" in g
    assert "issues #2/#3 remain OPEN" in g

    assert t.startswith("---\nname: \"Synthetic-only bug report\"\n")
    assert "## Disclosure checklist" in t
    assert "invented/synthetic data" in t
    assert "No real Windows diagnostic reports" in t
    assert "separate disclosure review" in t
    assert "## Approved fixed symptom category" in t
    assert "`unclassified_incomplete`" in t
    assert "## Completely invented synthetic reproduction" in t
    assert "Synthetic fixture reference: `NONE`" in t
    assert "Release decision: NO-GO" in t
    assert "Security vulnerabilities" not in t or "security vulnerabilities" in t.lower()
    for forbidden in (
        "Paste your log", "Attach your logs", "Paste the warning",
        "Upload a report", "Copy your terminal output",
        "paste the original error message here",
    ):
        assert forbidden.lower() not in t.lower()
    assert "docs/PUBLIC-ISSUE-GUIDE.md" in t

    assert "docs/PUBLIC-ISSUE-GUIDE.md" in docs["triage"]
    assert "docs/PUBLIC-ISSUE-GUIDE.md" in docs["readme"]
    assert "docs/PUBLIC-ISSUE-GUIDE.md" in docs["security"]


class PublicIssueGuideTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.docs = {key: path.read_text(encoding="utf-8")
                    for key, path in FILES.items()}

    def test_public_disclosure_and_release_documents_are_consistent(self) -> None:
        policy_contract(self.docs)

    def mutation(self, path: str, old: str, new: str) -> None:
        self.assertIn(old, self.docs[path])
        edited = dict(self.docs)
        edited[path] = edited[path].replace(old, new, 1)
        with self.assertRaises(AssertionError):
            policy_contract(edited)

    def test_old_raw_warning_invitation_is_rejected(self) -> None:
        self.mutation(
            "validation",
            "## Public bug reports — synthetic-only, independently reviewed",
            "## Public bug reports\nSpecific warning text from `SUMMARY.md` "
            "(redact user name, host name, directories)",
        )

    def test_hosted_ci_does_not_become_physical_evidence(self) -> None:
        self.mutation("validation", "**eight real observations**",
                      "**two hosted Windows CI runs**")
        self.mutation("validation", "**Release remains NO-GO**",
                      "**Release approved by hosted CI**")

    def test_public_template_requires_review_and_synthetic_only(self) -> None:
        self.mutation("template", "No real Windows diagnostic reports",
                      "Attach your logs")
        self.mutation("template", "separate disclosure review",
                      "share automatically")
        self.mutation("template", "Release decision: NO-GO",
                      "Release decision: GO")

    def test_release_policy_cannot_auto_promote_pre_release(self) -> None:
        self.mutation(
            "development",
            "**Current decision: NO-GO. No tagged pre-release",
            "**Current decision: GO. Tagged pre-release",
        )

    def test_file_scopes_are_only_public_guidance(self) -> None:
        self.assertTrue((ROOT / ".github/ISSUE_TEMPLATE/bug_report.md").is_file())
        self.assertNotIn("users' real data", self.docs["guide"])
        self.assertIn("No tool automatically submits any issue", self.docs["guide"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
