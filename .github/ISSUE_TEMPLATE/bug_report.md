---
name: "Synthetic-only bug report"
about: "Report an invented regression without exposing a real Windows workstation"
title: "bug: "
labels: []
assignees: []
---

<!-- ADR-063: PUBLIC issues are NOT approved places for private diagnostic evidence.
Do not paste or attach real reports, logs, unredacted or lightly redacted event
messages, process names, paths, command lines, PIDs, host/user names, device
identifiers, exact build numbers, threat results or screenshots.
If independent disclosure review has not approved even the fixed status code,
keep the observation private and do not submit this template. -->

## Disclosure checklist

- [ ] I used only invented/synthetic data, not copied or lightly edited real logs.
- [ ] No real Windows diagnostic reports, full console output, screenshots, paths, identifiers, warnings, or attachments are included.
- [ ] A separate disclosure review approved the non-sensitive information below.
- [ ] This issue does not claim real Windows 10/11 validation or release approval.

## Approved fixed symptom category

Use one exact code from `docs/FIELD-FAILURE-TRIAGE.md`; choose `unclassified_incomplete` if it cannot be safely characterized. Do not paste the original error message.

Category: `unclassified_incomplete`

## Completely invented synthetic reproduction

Describe only fictional values and the pre-existing `tests/` synthetic reference, or explain why a safe reproduction is not available. Never run native scans or change device security settings to manufacture a failure.

Synthetic fixture reference: `NONE`

## Expected behavior versus **synthetic** observed behavior

Describe the expected invariant and what an invented test demonstrated, **not** an excerpt of an actual report. Link a public GitHub-hosted synthetic CI run only if relevant; do not attach a private artifact.

## Outstanding evidence and privacy limits

**Physical Windows 10/11 field validation: UNVERIFIED.** **Independent root, security/privacy and release authority: NOT VERIFIED.** **Release decision: NO-GO.** Issues #2 and #3 remain OPEN.

For security vulnerabilities or sensitive evidence, stop and follow `SECURITY.md` and `docs/PUBLIC-ISSUE-GUIDE.md` instead of posting here.
