# Field assurance boundaries and independent release evidence — ADR-071 / PR #76

**Decision: NO-GO.** This document is a *public, fictional-code-only coverage map*, not a physical test report, root attestation, confidentiality audit, approval, or evidence of eight independently observed workstations. The associated [machine-checked registry](field-assurance-boundaries.json) deliberately records **zero authenticated physical cells** and all four external release blockers as pending.

## What hosted CI can establish

| Code witness | CI scope | What it checks | It does **not** establish |
| --- | --- | --- | --- |
| `tests/FieldSmbPreflight.Tests.ps1` | `SYNTHETIC_ONLY` | Invented share and ACL providers; broad-share/unknown precedence, warnings/errors, partial and malformed inventories | Completeness of a real SMB share listing, effective remote NTFS/share access, absence of special/admin shares |
| `tests/FieldSmbCollectionGate.Tests.ps1` | `SYNTHETIC_ONLY` | Invented optional field-run gate states, error-stream refusal, first/last guard ordering and fixed denial output | Atomic object-pinned sharing policy, protection against changes after the last check, user data privacy |
| `tests/FieldPreflight.Tests.ps1` | `SYNTHETIC_ONLY` | Invented path, OS-label and always-NO-GO preflight cases | Authorized originating root, permission to operate or release |
| `tests/FieldValidation.Integration.Tests.ps1` | `HOSTED_CI_ONLY` | Full passive five-mode runner on a Windows-hosted, **test-owned disposable** folder | A genuine Windows 10/11 workstation observation, normal user privileges on real endpoints |
| `tests/FieldEvidenceGate.Tests.py` | `SYNTHETIC_ONLY` | Strict offline schema, fictional eight-cell statuses, deliberately NO_GO-only decisions | Authenticity or independent review of self-entered status claims |
| `tests/AnchorTrustReview.Tests.py` | `SYNTHETIC_ONLY` | Fake anchor/reviewer claim handling, invalid metadata and refusal conditions | Independent source authority, root provenance, revocation or external signoff |

The hosted CI also runs component tests. A green workflow run means those tests passed at a particular commit, **not** that the user's PC was inspected. Some optional namespace/race probes may produce SKIP markers on unsupported hosts; neither the registry nor a green CI result can turn a skipped scenario into an executed assertion. `NO_NON_SPECIAL_SHARE_OBSERVED` means only no *ordinary* covering share was seen at that instant. A silently incomplete provider listing, admin/special shares, actual remote reachability, sync/backup/DLP and SMB/path TOCTOU remain outside that result.

## External evidence still required — private workflow only

| Fixed blocker | Responsible issue | Independent evidence required outside public GitHub |
| --- | --- | --- |
| `PHYSICAL_WINDOWS_10_11` | #2 | Eight **distinct, authorized physical** Windows 10/11 × PowerShell 5.1/7 × standard/authorized elevated observations; every cell's five passive modes, schema v1, per-run private ACL and absent unrequested native scans; naturally encountered provider-negatives only |
| `TRUSTED_INITIAL_ROOT` | #2 / #3 | Independently appointed, revocable original volume/root identity, real namespace/alias/race review, matched held-object identity, and externally checked source lifecycle |
| `INDEPENDENT_SECURITY_PRIVACY` | #3 | Real share/ACL and effective-access review, initial-root trust, cloud sync/backup/DLP/retention and controlled disclosure assessed by an authorized reviewer separate from collection |
| `EXTERNAL_RELEASE_AUTHORITY` | #2 / #3 | Accountable, independent, revocable release decision based on the external evidence and approved retention/privacy procedure; repository code must not self-certify |

The fixed matrix of eight pending combinations is in `field-assurance-boundaries.json`; its `NOT_AUTHENTICATED` entries are **not runtime statuses**, nor an assertion that an actual PC failed. Use [FIELD-VALIDATION.md](FIELD-VALIDATION.md) and [FIELD-REVIEW-HANDOFF.md](FIELD-REVIEW-HANDOFF.md) only after authorization. `docs/field-evidence-template.json` is merely an all-`not_run` private-workflow starter; `tools/field_evidence_gate.py` and `tools/field_review_readout.py` can check *self-entered fixed labels*, but always return NO_GO and do not verify identity, freshness, approval, pairing or source authority.

## How to use the registry safely

1. Keep the public registry limited to fixed enumerations, synthetic test paths and invariant boundaries. **Never add** hostnames, usernames, real directory paths, SMB share names, hashes, source root identities, review tickets, timestamps, raw JSON reports, screenshots or copy/pasted console output.
2. When code/test scope changes, update the registry and document the limitation. `tests/FieldAssuranceBoundaries.Tests.py` checks stable witness IDs, referenced tests, both Windows-shell workflow wiring, all eight pending cells, four blockers and unresolved SMB boundaries; it **does not prove the tests are semantically sound**.
3. Record any genuinely authorized physical observations and reviewer approval **only in independently managed private systems**. Unavailable or unapproved cells stay `not_run`; never manufacture negative scenarios or disable Defender to fill a spreadsheet.
4. Do not infer GO from the registry, fixed-status CLI, synthetic all-PASS sheet, hosted workflow or opt-in SMB pass. Issues **#2 and #3 remain OPEN**; publication of synthetic source and safety docs is not authorization to release a validated product.

**Change boundaries:** No Windows collector, `WinTriage.ps1`, `Invoke-WtFieldValidation.ps1`, SMB share, ACL, existing report, upload or cleanup operation is modified by ADR-071.

## ADR-072 / PR #77 — operator stop guidance remains procedural-only

The [manual stop and independent handoff table](FIELD-OPERATOR-STOP-RULES.md) is a public procedure with a fixed synthetic registry. Its new CI contract checks schema, role and no-upload/no-delete boundaries. It does **not** add any authenticated physical workstation observation, privacy proof, source-root attestation or independent external release approval. Eight physical cells remain `NOT_AUTHENTICATED` and four external release blockers `PENDING_EXTERNAL`; no code path now grants GO.
