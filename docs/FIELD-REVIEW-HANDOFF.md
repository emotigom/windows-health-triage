# Physical Windows field review handoff — ADR-039 / PR #44

This is a **human-operated, offline checklist** for issue #2 (physical compatibility) and #3 (privacy). The sole automation reports how many *self-entered status claims* meet a fixed schema. It **cannot** identify real Windows devices, confirm who observed them, authenticate an initial storage root, detect all sync agents or authorize a release. Nothing in this guide turns the product into GO.

## Operator: before each field run

- [ ] Use only a Windows 10 or Windows 11 computer that you are authorized to test. Review the exact checkout and local command before execution.
- [ ] Choose a locally approved, non-shared, non-synced NTFS directory. Investigate parent path, junctions, mount points, reparse points, storage policy and the **actual ACL** locally. Avoid OneDrive/managed redirected folders unless authorized reviewers explicitly assess them.
- [ ] Prefer a standard-privilege shell first. Elevated runs require separate explicit authorization. Do not manipulate Defender, Event Log permissions, security software, hardware or failures to create successful results.
- [ ] Keep full reports **only on the local approved workstation**. Do not paste raw warnings, device identifiers, user/process/event data, hostnames, paths, SIDs, command lines, logs, JSON reports, `SUMMARY.md`, signatures or reviewer identities into GitHub or CI.
- [ ] Run the existing passive validation exactly as described in `docs/FIELD-VALIDATION.md`: `.\Invoke-WtFieldValidation.ps1` from a trusted checkout, without active Defender/ClamAV or repair operations.
- [ ] Inspect locally that actual file permissions are restricted, and check cloud/enterprise backup policy separately. The status recorder's `0o600` does not guarantee Windows DACL protection.

## Eight environment combinations

The matrix is Windows 10/11 × Windows PowerShell 5.1/PowerShell 7 × standard/authorized elevated. This is **8 distinct observations**, not 8 repetitions of a hosted Windows CI job. Mark `not_run` for combinations not actually performed.

| Real OS | Shell | Privilege | Verification |
| --- | --- | --- | --- |
| Windows 10 | 5.1 | Standard | Quick, Events, Hardware, Monitor, passive Integrity |
| Windows 10 | 5.1 | Authorized elevated | Same five modes |
| Windows 10 | 7 | Standard | Same five modes |
| Windows 10 | 7 | Authorized elevated | Same five modes |
| Windows 11 | 5.1 | Standard | Same five modes |
| Windows 11 | 5.1 | Authorized elevated | Same five modes |
| Windows 11 | 7 | Standard | Same five modes |
| Windows 11 | 7 | Authorized elevated | Same five modes |

For each run, independently inspect schema contract, restricted ACL, passive-scan absence and warnings. Missing or inaccessible providers are **not** evidence of a healthy computer. Separately document genuine Defender-unavailable, Event Log access-denied, and storage-provider-unavailable cases **only when naturally observed**; otherwise keep their statuses pending. Never simulate an actual physical scenario by modifying security settings.

## Transcribe only existing fixed status labels

In an approved private folder outside the repository, make separate local copies of `docs/field-evidence-template.json` and `docs/anchor-trust-template.json`. After each authorized physical run, use the existing manual-only `tools/field_status_recorder.py` to enter precisely five validated status labels for that OS/shell/privilege cell. It creates a **new** snapshot; it does not modify the previous version. See `docs/FIELD-VALIDATION.md` for the exact command.

The anchor worksheet is separate: follow `docs/ANCHOR-TRUST-PROTOCOL.md` and never mark `external_reference_claimed` simply because a second handle matches the first. A **different authorized reviewer** must review initial root provenance, ACL/namespace and managed cloud/backup risks in a private, revocable process. An `approved_claimed` status is a claim, not authenticated approval.

For a **read-only local handoff summary**, choose the latest new field snapshot and anchor status sheet:

```powershell
python tools/field_review_readout.py `
  --field-metadata 'C:\ApprovedPrivate\field-status-latest.json' `
  --anchor-metadata 'C:\ApprovedPrivate\anchor-status.json'
```

Example output from **invented complete metadata, not a verified device**:

```text
Decision: NO_GO
Readiness: CLAIMS_ONLY
FieldReview: MANUAL_APPROVAL_REQUIRED
AnchorReview: CLAIMS_UNAUTHENTICATED
ClaimedCompleteCells: 8/8
ExternalApproval: NOT_AUTHENTICATED
```

Even `8/8` means **eight syntactically complete claims**, not eight corroborated physical tests. Missing or invalid data, a self-selected root, a failed privilege/ACL observation or an unreviewed sync risk remains blocking. The script **always exits 2**, even when complete; it reads no raw diagnostics and creates no output files. It accepts only the two strict bounded status JSON schemas, and prints fixed labels and a count from 0–8. It does **not** validate user consent, independence of reviewers, timestamps, file origin or actual signoff.

## Separate handoff / disclosure boundary

**Operator → independent reviewer:** Share approved access to original detailed findings only through the organization's controlled private channel. The local summary cannot replace that private review. Reviewer must compare the claimed statuses to actual observed device state and confirm consent, privilege bounds, independently trusted initial root, native interop limitations, reparse/TOCTOU risks, actual DACL and all sync/backup behaviors.

**Independent reviewer → release authority:** Use the private audit/approval process described in ADR-038. The repo has no cryptographic root attestation or authenticated approval endpoint. Do **not** post the completed private worksheets publicly; even counts and claimed statuses can reveal test coverage. Public GitHub updates should contain only a non-sensitive progress statement reviewed for disclosure and invented reproductions.

**Release authority:** Until real Windows 10/11 evidence and independent privacy/security approval are verified outside this project, leave issues #2 and #3 OPEN and release **NO-GO**, regardless of the status script's output.

This workflow has no background automation, uploading, retention changes or automatic deletion of field reports. The on-disk reports remain under the operator's manual retention control.

## When a field mode fails (ADR-040)

Keep detailed evidence in an approved private local process; do not post raw or lightly edited failures to GitHub. Follow `docs/FIELD-FAILURE-TRIAGE.md`: choose an approved fixed symptom code, examine the existing synthetic `tests/` reference, and develop a wholly invented reproduction under separate review. Cases involving unverified cloud backup, missing reference authority or uncertain symptoms remain manual. The CLI always says `PhysicalEvidence: UNVERIFIED` and `Decision: NO_GO`, even after a claimed physical observation.
