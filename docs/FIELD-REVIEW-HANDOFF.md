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

| Real OS | PowerShell | Privilege | Required checks |
| --- | --- | --- | --- |
| Windows 10 | 5.1 | Standard | Quick, Events, Hardware, Monitor, passive Integrity; schema v1; private ACL; passive scans absent |
| Windows 10 | 5.1 | Authorized elevated | Quick, Events, Hardware, Monitor, passive Integrity; schema v1; private ACL; passive scans absent |
| Windows 10 | 7 | Standard | Quick, Events, Hardware, Monitor, passive Integrity; schema v1; private ACL; passive scans absent |
| Windows 10 | 7 | Authorized elevated | Quick, Events, Hardware, Monitor, passive Integrity; schema v1; private ACL; passive scans absent |
| Windows 11 | 5.1 | Standard | Quick, Events, Hardware, Monitor, passive Integrity; schema v1; private ACL; passive scans absent |
| Windows 11 | 5.1 | Authorized elevated | Quick, Events, Hardware, Monitor, passive Integrity; schema v1; private ACL; passive scans absent |
| Windows 11 | 7 | Standard | Quick, Events, Hardware, Monitor, passive Integrity; schema v1; private ACL; passive scans absent |
| Windows 11 | 7 | Authorized elevated | Quick, Events, Hardware, Monitor, passive Integrity; schema v1; private ACL; passive scans absent |


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
ClaimCoverageSource: SELF_DECLARED_ONLY
ExternalApproval: NOT_AUTHENTICATED
SheetPairing: NOT_VERIFIED
IndependentReview: NOT_AUTHENTICATED
EvidenceFreshness: NOT_VERIFIED
ReplayDetection: NOT_AVAILABLE
RetentionReview: NOT_VERIFIED
ApprovalRevocation: NOT_CHECKED
FieldSafetyClaims: NONE_REPORTED
ReleaseBlocker: PHYSICAL_WINDOWS_10_11
ReleaseBlocker: TRUSTED_INITIAL_ROOT
ReleaseBlocker: INDEPENDENT_SECURITY_PRIVACY
ReleaseBlocker: EXTERNAL_RELEASE_AUTHORITY
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

## PR #59 / ADR-054 — field failure precedence and explicit release blockers

The offline readout now distinguishes a **reported safety failure** from mere incomplete claims. A self-entered field mode FAIL, report-contract FAIL, ACL FAIL, passive native scan UNEXPECTED, or security_review FAILED causes FieldSafetyClaims: FAILURE_REPORTED and ClaimedCompleteCells to be shown as 0/8. This is a conservative refusal to display reassuring coverage, NOT independent proof of an actual Windows fault. A review/not_run entry without reported failures may still count other syntactically complete cells and shows FieldSafetyClaims: NONE_REPORTED; that only means there was **no failure label in the submitted metadata**, not that an independent security audit found no faults. Invalid field metadata reports UNKNOWN. Never change an actual failing outcome to REVIEW or PASS to inflate coverage.

Every readout, including all-synthetic PASS and malformed data, prints these four fixed release blockers with no personal data:

| Fixed ReleaseBlocker label | External evidence and responsible reviewer | Issue |
| --- | --- | --- |
| PHYSICAL_WINDOWS_10_11 | Authorized Windows 10/11 devices, PowerShell 5.1/7, normal/elevated as authorized, five modes, private ACL and naturally observed negative provider scenarios. Independently verify real devices, not hosted CI. | #2 |
| TRUSTED_INITIAL_ROOT | Authorized initial volume/root authority, held-object lineage, actual Windows ACL/namespace/mount behavior, and source revocation; the test-only probes are not production attestation. | #2 / #3 |
| INDEPENDENT_SECURITY_PRIVACY | Separate privacy/security reviewer verifies local data access, cloud backup/sync, retention/holds, root and failure modes using protected evidence. | #3 |
| EXTERNAL_RELEASE_AUTHORITY | Accountable release authority verifies the preceding external evidence, documents the decision, and handles revocation outside this repository. | #2 / #3 |

These are **required, not satisfied, conditions**. The tool cannot prove they occurred; therefore the list never shrinks, an all-PASS fabricated worksheet is still NO_GO, and the CLI still exits 2. The script prints only allowlisted labels and summary numbers, never reviewer identity, device fingerprints, raw reports or paths. Validate and retain detailed records using approved private processes, and leave issues #2/#3 OPEN until the independent reviewers explicitly verify the gates.

## PR #60 / ADR-055 — required field checklist contract

Both field checklists now enumerate each of the eight physical Windows 10/11 x PowerShell 5.1/7 x standard/authorized-elevated combinations separately, with the five passive modes, schema v1, private ACL and passive scans absent for every row. Unavailable combinations remain pending and cannot be replaced by a hosted CI run.

The two hosted Windows CI jobs also run a synthetic document contract suite. It rejects deliberately omitted environments, weakened ACL or Monitor duties, missing or reassigned release blockers, simulated negative-provider scenarios, and removed independently reviewed root or privacy requirements. The tests mutate only temporary in-memory text, not real reports. This protects the wording and scope of the release gate, **not the completion or authenticity of real field testing**. Physical verification and separate security/privacy/root/release approvals still block release; issues #2 and #3 stay OPEN.

## PR #61 / ADR-056 — fixed-token unaccepted field combinations

The local readout now adds `ClaimCoverageSource: SELF_DECLARED_ONLY` on **every** result. It may also print zero to eight `UnacceptedClaimCell:` lines. Each line is one fixed, predeclared combination such as `WINDOWS10_POWERSHELL51_STANDARD`; no user/device identifier, hostname, path, report content or free text is ever printed. The order is the documented Windows 10/11, PowerShell 5.1/7, standard/authorized-elevated matrix order.

For two syntactically valid and non-blocked status sheets, these lines identify which of the eight combinations is **absent or not wholly marked PASS** for the five modes, schema contract, restricted ACL and passive scan absence. A REVIEW/not_run mode is not a completed claim. Explicitly failed modes, missing/unsafe reference trust, invalid field/anchor JSON or reported security failure suppress **all** accepted claims, so all eight fixed names are printed as unaccepted. This conservative rule does not assert that every physical device test failed; it simply withholds a reassuring combined completion count.

A fabricated all-PASS worksheet can still display `ClaimedCompleteCells: 8/8` and no unaccepted cell lines. **That never proves eight real physical observations.** Pairing, source origin, actual field tests, reviewer independence, freshness and approval remain unauthenticated. Every result stays NO_GO, prints the same four ReleaseBlocker labels and exits 2. Use the fixed names only as a private, manually checked planning aid; never upload full local status sheets or raw reports to a public issue.

## PR #62 / ADR-057 — fixed-order privacy-safe readout output contract

The offline handoff now builds stdout through one allowlisted renderer. For invented complete metadata it prints **exactly 18 fixed lines** in a documented order: decision, claim-only readiness and source summaries, the count and SELF_DECLARED_ONLY disclosure, optional fixed UnacceptedClaimCell lines, fixed provenance/retention/approval limits, safety label and four fixed external ReleaseBlocker lines. Invalid or explicitly blocked sheets may print all eight UnacceptedClaimCell tokens (up to **26 lines**) but never arbitrary JSON fields, user-supplied free text, paths or report bodies.

The renderer checks that all expected fields and only those fields are present; fixed values and label enumerations are allowed; release blockers retain their exact order; cell names are an ordered subset of eight predeclared tokens; and the accepted count plus unaccepted labels totals eight. If an unexpected internal value, count, duplicate/unknown token or extra field is introduced, stdout falls back to a single deterministic INVALID_METADATA / NO_GO representation, with all eight cells unaccepted. The CLI still returns exit code 2.

Both hosted Windows shells exercise exact-line snapshots and malformed input/private synthetic canary regressions. This prevents accidental output drift and possible personal-data exposure, **not fabrication or replay of a valid self-reported worksheet**. The real eight Windows 10/11 field observations and independently verified trusted initial root, security/privacy approval and release authority remain external requirements. Issues #2/#3 stay OPEN; release remains NO-GO.
