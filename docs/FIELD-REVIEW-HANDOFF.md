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
SheetPairing: NOT_VERIFIED
IndependentReview: NOT_AUTHENTICATED
EvidenceFreshness: NOT_VERIFIED
ReplayDetection: NOT_AVAILABLE
RetentionReview: NOT_VERIFIED
ApprovalRevocation: NOT_CHECKED
```

Even `8/8` means **eight syntactically complete claims**, not eight corroborated physical tests. Missing or invalid data, a self-selected root, a failed privilege/ACL observation or an unreviewed sync risk remains blocking. The script **always exits 2**, even when complete; it reads no raw diagnostics and creates no output files. It accepts only the two strict bounded status JSON schemas, and prints fixed labels and a count from 0–8. It does **not** validate user consent, independence of reviewers, timestamps, file origin or actual signoff.

## Separate handoff / disclosure boundary

**Operator → independent reviewer:** Share approved access to original detailed findings only through the organization's controlled private channel. The local summary cannot replace that private review. Reviewer must compare the claimed statuses to actual observed device state and confirm consent, privilege bounds, independently trusted initial root, native interop limitations, reparse/TOCTOU risks, actual DACL and all sync/backup behaviors.

**Independent reviewer → release authority:** Use the private audit/approval process described in ADR-038. The repo has no cryptographic root attestation or authenticated approval endpoint. Do **not** post the completed private worksheets publicly; even counts and claimed statuses can reveal test coverage. Public GitHub updates should contain only a non-sensitive progress statement reviewed for disclosure and invented reproductions.

**Release authority:** Until real Windows 10/11 evidence and independent privacy/security approval are verified outside this project, leave issues #2 and #3 OPEN and release **NO-GO**, regardless of the status script's output.

This workflow has no background automation, uploading, retention changes or automatic deletion of field reports. The on-disk reports remain under the operator's manual retention control.

## When a field mode fails (ADR-040)

Keep detailed evidence in an approved private local process; do not post raw or lightly edited failures to GitHub. Follow `docs/FIELD-FAILURE-TRIAGE.md`: choose an approved fixed symptom code, examine the existing synthetic `tests/` reference, and develop a wholly invented reproduction under separate review. Cases involving unverified cloud backup, missing reference authority or uncertain symptoms remain manual. The CLI always says `PhysicalEvidence: UNVERIFIED` and `Decision: NO_GO`, even after a claimed physical observation.

## PR #56 / ADR-051 — two-sheet handoff trust boundary

A field worksheet and an anchor worksheet submitted together do not prove they came from the same device, test run, operator or independent reviewer. Both sheets can be fabricated or stale. The readout now displays fixed SheetPairing: NOT_VERIFIED and IndependentReview: NOT_AUTHENTICATED labels, even when claimed complete cells show 8/8. If either sheet is malformed, the combined claimed-complete count becomes 0/8.

Real reviewer independence, source correspondence, timing, authority and revocation need a separately approved private process; never attach linkage identifiers, signatures, personal data or raw reports to public issues or PRs. The local tool continues to read only fixed status metadata, creates no files, exits 2 and always reports NO_GO.

## PR #57 / ADR-052 — stale and replayed status sheets

The handoff summary now prints the fixed `EvidenceFreshness: NOT_VERIFIED` and `ReplayDetection: NOT_AVAILABLE` labels. A copied JSON status sheet may have a new filesystem timestamp without a new device observation. Likewise, an old sheet may look complete (even 8/8) and can be resubmitted, while the tool remains intentionally stateless. **Neither file creation/modified time nor a worksheet's self-entered claim proves when testing occurred or that the results are still current.** This tool does not perform replay detection, expiry/revocation checks or cryptographic verification.

The reviewer must privately verify the correct device and authorized session, collection date, custody, record freshness and revocation status against independent records held outside these worksheets. If that is unavailable, treat all status claims as historical and unverified; retain NO-GO. Do not add timestamps, operator names, device identifiers, hashes, linkable tokens or reviewer signatures to either status sheet or public GitHub issues; extra fields are rejected. Original reports remain local and subject to approved privacy retention, never automatically deleted or uploaded. The CLI still only reads bounded metadata and always exits 2.

## PR #58 / ADR-053 — retention, disposal and revoked-approval lifecycle

The readout reports **RetentionReview: NOT_VERIFIED** and **ApprovalRevocation: NOT_CHECKED** on every outcome. These fixed fields do not claim actual disposal, permission to retain private diagnostic reports, legal-hold status, current external authorization or an independent revocation check. The tool has no trusted record of who approved use or when that approval expired. It cannot learn those facts from filenames, copied worksheets, file timestamps, an old approval claim or a local hash.

If a strict anchor worksheet explicitly reports expired reference authority, an identity mismatch, a self-selected reference, unsafe ACL/namespace or known synchronization risk, the combined readout now suppresses any complete-looking field-cell count to **0/8**, even when every field status is self-entered PASS. This is an **evidence-quality refusal**, not proof that deletion or revocation was independently confirmed. Other well-formed but incomplete sheets may still display claimed coverage, always NO_GO.

**Independent operator and security/privacy reviewer checklist (outside this repo):**

1. Establish an authorized, written **minimum-necessary retention schedule** for raw reports and for smaller local status sheets; classify the sensitive fields and who may access each. Keep the source device and backups in scope. A retention schedule is not granted by this tool.
2. Before manual disposal, check consent, contractual/legal hold, current incident needs, backup/snapshot copies, organizational retention requirements and approval to delete. Do not run deletion or cleanup from the Git checkout or public issue; obtain a separate authorized operator's execution and evidence.
3. Check whether an external initial-root reference or human approval was **withdrawn, expired, superseded or revoked** using the approved independent authority's current, private register. A past `approved_claimed` value is not a revocation check. On doubt, stop relying on the worksheet; keep NO_GO and request renewed private verification.
4. Record reviewer independence, source/collection chronology, revocation decision and disposal/hold outcome in a protected **external** process with access and audit control. Do not add reviewer names, tickets, timestamps, hashes, subject identifiers, approvals or free-form notes to the two fixed-enum sheets, and do not upload raw reports.
5. After approved disposal, separately address remaining backups, aliases and retention copies under organizational policies. The script neither deletes any file nor attests to secure erasure, complete backup removal or absence of cloud sync.

Issues #2/#3 stay OPEN and release stays NO-GO until actual Windows 10/11 field verification and independent security/privacy/root-source approvals. Hosted Windows CI tests use fabricated fixtures only.
