"""ADR-073: compare field/public/operator instructions to guarded source flow.

Synthetic text-mutation checks only; do not read physical PCs, actual reports
or credentials. Lexical source checks do not prove operational compliance.
"""
from __future__ import annotations

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
FILES = {
    "field": "docs/FIELD-VALIDATION.md",
    "handoff": "docs/FIELD-REVIEW-HANDOFF.md",
    "runbook": "docs/FIELD-OPERATOR-STOP-RULES.md",
    "public": "docs/PUBLIC-ISSUE-GUIDE.md",
    "assurance": "docs/FIELD-ASSURANCE-BOUNDARIES.md",
    "readme": "README.md",
    "runner": "Invoke-WtFieldValidation.ps1",
    "preflight": "Test-WtFieldPreflight.ps1",
    "workflow": ".github/workflows/smoke.yml",
}

def validate(docs):
    assert type(docs) is dict and set(docs) == set(FILES)
    field = docs["field"]
    handoff = docs["handoff"]
    runbook = docs["runbook"]
    public = docs["public"]
    assurance = docs["assurance"]
    runner = docs["runner"]
    preflight = docs["preflight"]
    wf = docs["workflow"]

    # A copied fixed status is a private manual worksheet claim, not
    # permission for public disclosure, even if it looks pseudonymous.
    assert "Private status transcription is not public disclosure authorization." in field
    assert "Exclude the Environment line" in field
    assert "actual Windows build/version metadata" in field
    assert "fully invented synthetic reproduction" in field
    assert "Private transcription is not public disclosure authorization:" in public
    assert "real five-mode status lines and the Environment/build line" in public
    assert "entirely invented reproduction" in public
    assert "Private transcription only:" in handoff
    assert "without separate independent disclosure review" in handoff

    # Human STOP_ADDITIONAL_RUNS stops new invocations, not the existing
    # five-mode loop which catches ordinary report/schema/ACL failures.
    assert "A mode failure does not automatically abort the remaining five-mode loop." in field
    assert "STOP_ADDITIONAL_RUNS" in field
    assert "not that all later modes" in field
    assert "may continue attempting later modes" in runbook
    assert "do not initiate more manual collection" in runbook
    assert "This does **not** guarantee the current process stops" in runbook
    assert "opted-in SMB guard" in field

    # Source-flow text witnesses are intentionally narrower than runtime
    # assertions; they catch accidental documentation/code drift.
    assert "foreach ($mode in @('Quick','Events','Hardware','Monitor','Integrity'))" in runner
    assert "if ($row.Validation -eq 'fail') { $allPassed=$false }" in runner
    assert runner.index("if ($row.Validation -eq 'fail')") < runner.index("if (-not $allPassed)")
    assert re.search(r"\[switch\]\$RequireSmbPreflight\s*[,)]", runner)
    assert runner.count("Test-WtOptionalSmbGate -Directory $OutputDir") == 3
    assert runner.count("if ($RequireSmbPreflight -and -not (Test-WtOptionalSmbGate -Directory $OutputDir))") == 3
    assert "Write-Output 'SmbCollectionGate: BLOCKED_OR_UNKNOWN'" in runner
    assert "exit 2" in runner
    collection = runner.index("& (Join-Path $PSScriptRoot 'WinTriage.ps1') @options")
    first_gate = runner.index("if ($RequireSmbPreflight -and -not (Test-WtOptionalSmbGate -Directory $OutputDir))", runner.index("foreach ($mode"))
    assert first_gate < collection
    assert runner.index("if ($row.Validation -eq 'fail')") > collection

    # Standalone preflight is read-only and NO_GO by design; it cannot
    # replace authenticated initial storage authority or release approval.
    assert "exit 2" in preflight
    assert "never launches the field runner" in preflight.lower()
    assert "-RequireSmbPreflight" in handoff
    assert "opt-in" in assurance.lower()
    assert "FIELD-OPERATOR-STOP-RULES.md" in docs["readme"]
    assert wf.count("run: python tests/FieldProcedureConsistency.Tests.py") == 2
    assert "Release NO-GO" in runbook
    assert "issues #2 and #3 OPEN" in runbook
    assert "NOT_AUTHENTICATED" in assurance


class FieldProcedureConsistencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.docs = {key: (ROOT / path).read_text(encoding="utf-8")
                    for key, path in FILES.items()}

    def check(self, changed_key=None, changed_text=None):
        docs = dict(self.docs)
        if changed_key is not None:
            docs[changed_key] = changed_text
        validate(docs)

    def mutate(self, key, before, after):
        self.assertIn(before, self.docs[key], "negative control anchor must exist")
        with self.assertRaises(AssertionError):
            # Replace all copies: repeated policy references in runbooks,
            # source gates and README must all fail when their rule is erased.
            self.check(key, self.docs[key].replace(before, after))

    def test_current_field_procedures_and_source_agree(self):
        self.check()

    def test_private_status_is_not_public_disclosure(self):
        self.mutate("field", "Private status transcription is not public disclosure authorization.",
                    "Private transcription authorizes public posting.")
        self.mutate("public", "Private transcription is not public disclosure authorization:",
                    "Private transcription is public posting permission:")
        self.mutate("handoff", "without separate independent disclosure review",
                    "without any review")

    def test_manual_stop_cannot_claim_automatic_abort(self):
        self.mutate("field", "A mode failure does not automatically abort the remaining five-mode loop.",
                    "A mode failure automatically aborts every future mode.")
        self.mutate("runbook", "may continue attempting later modes",
                    "always cancels all later modes")

    def test_opt_in_smb_guard_not_automatic(self):
        self.mutate("runner", "[switch]$RequireSmbPreflight",
                    "[switch]$RequireSmbPreflight=$true")
        self.mutate("runner", "$RequireSmbPreflight -and -not",
                    "$RequireSmbPreflight -or -not")
        self.mutate("runner", "if ($row.Validation -eq 'fail') { $allPassed=$false }",
                    "if ($row.Validation -eq 'fail') { exit 0 }")
        self.mutate("runner", "Write-Output 'SmbCollectionGate: BLOCKED_OR_UNKNOWN'",
                    "Write-Output 'Approved for collection'")

    def test_standalone_preflight_never_grants_go(self):
        self.mutate("preflight", "exit 2", "exit 0")
        self.mutate("handoff", "-RequireSmbPreflight", "-RequireSmbAlways")

    def test_both_windows_jobs_must_run_consistency_test(self):
        self.mutate("workflow", "run: python tests/FieldProcedureConsistency.Tests.py",
                    "run: echo skipped")

    def test_no_claim_of_real_release_authority(self):
        self.mutate("runbook", "Release NO-GO", "Release GO")
        self.mutate("assurance", "NOT_AUTHENTICATED", "PASS")

    def test_readme_links_original_stop_protocol(self):
        self.mutate("readme", "FIELD-OPERATOR-STOP-RULES.md",
                    "missing-stop-protocol.md")


if __name__ == "__main__":
    unittest.main(verbosity=2)
