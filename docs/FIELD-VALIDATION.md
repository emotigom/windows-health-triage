# Windows 10/11 field-validation protocol — issue #2

This checklist is for a **real Windows workstation**. Hosted GitHub CI on Windows runners
does not establish hardware compatibility on the user's device. Use read-only,
non-elevated checks first. Never attach raw diagnostic reports to public issues.

## Before running

1. Review the repository script and ensure you trust its origin. Avoid synchronized
   folders (OneDrive etc.) and shared/network drives for any raw diagnostic data.
2. Use a local drive with NTFS permissions; managed devices may enforce their own
   restrictions. The tool refuses to write a report if the new folder's ACL cannot
   be verified.
3. For full coverage, run Windows PowerShell 5.1 and PowerShell 7 on approved real Windows 10/11 devices, using a standard shell first. Repeat elevated only when authorized; unavailable cells must remain not_run and block release. Hosted CI is not an alternative to physical testing.
4. Review disk space: raw reports persist locally. No process termination, report
   cleanup, repair, Defender quick scan, ClamAV or SFC/DISM verification is invoked.

## Run

From a trusted checkout:

```powershell
.\Invoke-WtFieldValidation.ps1
# Optional alternate local-only folder (must not be shared or synchronized):
.\Invoke-WtFieldValidation.ps1 -OutputDir 'C:\PrivateTriageValidation'
```

The harness exercises **Quick, Events, Hardware, Monitor (two samples at a
one-second interval), and passive Integrity**. It checks each report's schema v1
and restricted folder ACL. The console displays only bounded statuses plus Windows
build, PowerShell version, and whether privileges appear elevated. Full data stays
in separate local run folders; the tool never cleans them up automatically.

Meaning of the labels:

- `pass`: structural report and ACL validation succeeded. **Not** "healthy PC".
  Structural PASS does not authenticate report origin or authorize a build release.
- `review`: provider coverage, sampled event data, warnings or storage
  interpretation needs inspection. Not a diagnosis and not necessarily a bug.
- `fail`: a report contract/ACL/explicit-scan invariant failed, or the
  collector did not finish. Retain raw reports only on your PC for private diagnosis.
- `PassiveNativeScans=unexpected`: a passive-mode invariant was violated.
  Do not rerun active scans; report the minimal finding privately.

## Manual matrix

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


If Defender is absent, event logs are denied, or storage counters are unavailable,
verify the report says missing/unknown/inconclusive rather than asserting "healthy".
Do not intentionally disable Defender, alter system access rights or manipulate
hardware to manufacture these conditions.

## Reporting and retention

Copy only the console's fixed **Mode / Validation / Contract / PrivateAcl /
PassiveNativeScans / Warnings** status labels and, if necessary, OS build and PS
version after deciding they are appropriate to disclose. The output may still
reveal system characteristics. Do not copy exception messages, hardware identifiers,
process lists, host or user names, original warnings, paths, threat records,
`SUMMARY.md`, raw JSON or CSV, or scan logs. No automatic upload exists.

By default raw field reports are under the local application-data WinTriage
field-validation directory. Review the data locally and choose any manual
retention or disposal only after you no longer need it. There is **no automatic
deletion or cleanup**. For privacy minimization, use a distinct ephemeral local
volume or an explicitly approved non-synchronized path where practical.

If something fails, report only which mode and which fixed status is failing,
plus a fully invented minimal reproduction in a synthetic fixture; do not
paste potentially sensitive command-line output.

## Output-path junctions and hosted end-to-end coverage

Output paths that contain a Windows filesystem junction, symlink or another
existing reparse-point ancestor are rejected; use a direct local folder on a
non-synchronized NTFS volume instead. This is deliberately conservative for
redirected/managed profiles, and the tool never tries to delete or rewrite a
preexisting folder. Windows CI executes the full passive field runner in a
separate **test-owned temporary** folder and then deletes only those test
fixtures. Your manually collected field reports are always retained. Passing
hosted tests still does not certify an end-user Windows 10/11 PC.


## PR #36 / ADR-031 — offline fail-closed field evidence review gate

The metadata-only script is **not the diagnostic runner** and does not inspect any report. Follow the physical workstation procedure above first, using only systems and elevation levels you are authorized to test.

For a local-only checklist, copy `docs/field-evidence-template.json` to a **private, non-synced local folder** and fill only the enumerated status values (never paste raw JSON reports, process/event data, hostnames, local paths, user IDs, IP addresses, serial numbers or comments). The checked-in template is deliberately all pending.

From a trusted checkout with Python 3.11 available:

```powershell
python tools/field_evidence_gate.py --metadata 'C:\ApprovedPrivate\field-status.json'
```

The CLI prints only fixed categories and **always returns exit code 2 / NO_GO**. `INCOMPLETE` means field coverage, privacy, provider negatives or security review is missing. `MANUAL_APPROVAL_REQUIRED` means the status matrix is structurally filled, **not that the results were observed**. An independent human authorization decision and validated initial root design are still required.

Coverage is Windows 10/11 × Windows PowerShell 5.1/PowerShell 7 × standard/authorized elevated (8 combinations). Each combination requires Quick, Events, Hardware, Monitor, passive Integrity, schema v1, restricted ACL and absent passive native scans. Do not manufacture unavailable Defender, denied Event Log or unsupported storage conditions; mark `not_observed` and keep NO_GO until genuine examples can be safely assessed. User-managed/cloud-synced paths and no-access policy need review, not automated fixes.

CI only runs `python tests/FieldEvidenceGate.Tests.py` with **invented** results and asserts even all-pass synthetic metadata cannot grant GO. CI never reads real workstation output or uploads the private manifest. Issues #2 and #3 remain OPEN.

## PR #37 / ADR-032 — optional manual fixed-status recorder

This helper is **not a collector**. After running `Invoke-WtFieldValidation.ps1` on a physical PC with appropriate approval, *manually transcribe only* its five `Mode / Validation / Contract / PrivateAcl / PassiveNativeScans / Warnings` console lines. Do not pipe the whole console stream, or provide any report directory, `manifest.json`, `SUMMARY.md`, user name, device ID or event text.

Make a local private, **non-synced** copy of `docs/field-evidence-template.json` outside the Git checkout. The following is an **invented syntax example, not actual field evidence**; substitute only the fixed status labels you actually observed:

```powershell
python tools/field_status_recorder.py `
  --metadata 'C:\ApprovedPrivate\field-status.json' `
  --output 'C:\ApprovedPrivate\field-status-w11-ps7-standard.json' `
  --os windows11 --shell powershell7 --privilege standard --observed-local-only `
  --status 'Quick:review:pass:pass:not-requested:none' `
  --status 'Events:pass:pass:pass:not-applicable:none' `
  --status 'Hardware:review:pass:pass:not-applicable:present' `
  --status 'Monitor:pass:pass:pass:not-applicable:none' `
  --status 'Integrity:pass:pass:pass:not-requested:none'
python tools/field_evidence_gate.py --metadata 'C:\ApprovedPrivate\field-status-w11-ps7-standard.json'
```

The helper requires all five distinct modes in one invocation and a deliberate acknowledgement; it writes a **new** status-only JSON file, never overwrites a prior snapshot or fills other OS/shell/privilege cells. For subsequent authorized workstation combinations use the last created snapshot as `--metadata` and a different, previously nonexistent `--output` file. A failed check, warning or unexpected native scan must be recorded honestly as `fail` or `review`, not changed to `pass`. If the field script fails, retain the private reports locally and do not fabricate missing mode labels; leave that matrix cell as `not_run` until a complete manual review is possible.

Recorder exit code **0 only means the snapshot was created**. The evidence gate still returns **2 / NO_GO**, even if all fields were typed as pass. Status labels are self-reported, not independently authenticated. Manually review the output folder's Windows ACL, profile redirection/sync/backup policy, and who may read the file: the recorder cannot enforce secure DACLs or prevent Windows reparse/TOCTOU conditions. Do not put any private snapshot in Git, an issue, CI artifact or a shared/synced folder. Exceptional provider scenarios and trusted-root/security-review fields must be evaluated separately from genuine authorized observations, never invented to achieve a complete matrix.

## PR #38 / ADR-033 — strict status metadata import

The offline NO-GO checker and optional manual recorder now reject JSON duplicate keys (including deeply nested keys), Python-only non-finite JSON constants, symlink/reparse leaf files, file-object mismatches during read, non-regular input files and oversized metadata. An earlier hidden key is no longer silently replaced by a later one. Invalid metadata produces fixed failure labels only; it is **not** repaired or interpreted as valid field evidence. Use the original pending-only template and keep approved snapshots private. This hardening does not establish source authenticity, safely traverse untrusted parent paths, set Windows file ACLs or detect cloud synchronization. Continue to review local permission/sync policies and retain NO-GO pending physical Windows 10/11 validation.

## PR #39 / ADR-034 — optional offline ACL observation of a local status snapshot

After the manually transcribed status-only JSON has been created in an **approved, private, non-synced** location, you may separately inspect the file's Windows metadata *without reading its JSON content*:

```powershell
.\Test-WtFieldStatusAcl.ps1 -MetadataPath 'C:\ApprovedPrivate\field-status-w11-ps7-standard.json'
```

It prints only fixed labels, for example `MetadataAcl=restricted; PathObservation=direct_local_observed; SyncAndBackup=unknown; Decision=NO_GO`, and **always exits code 2**. A `restricted` DACL is only an observation; it does not certify privacy or that a corporate policy/backup agent has not copied data. If `MetadataAcl=review` or `PathObservation=review`, inspect the effective Windows ACL and path **locally**, not in public GitHub issues. The reviewer does not set, fix or delete any ACLs. A direct local path does not rule out OneDrive Known Folder Move or other synchronization. The Python recorder's output is **not automatically protected by a Windows DACL**—select and verify its parent directory yourself until a separately reviewed native creation mechanism exists. Run only on devices you are allowed to inspect. NO-GO and #2/#3 remain unchanged.

## PR #40 / ADR-035 — native create-time ACL research (not an operator command)

A test-only `CreateFileW` experiment now checks that a synthetic JSON file created with a prevalidated protected security descriptor can have a restricted Windows ACL from its first native creation operation, without subsequent `Set-Acl` repair. It also tests collisions and unsafe descriptors. **Do not use this research probe on actual reports or field snapshots**; the manual recorder still has the ADR-034 permissions and synchronization limitations. Continue using approved non-synced local storage and independently review ACLs; `Test-WtFieldStatusAcl.ps1` is read-only, always NO-GO. No Windows 10/11 physical data or external release signoff has been obtained.

## ADR-036 / PR #41 — held-parent file creation is research only

A Windows CI-only experiment now creates an invented status JSON under a held parent directory handle instead of resolving an absolute parent path again. Its exact returned file handle is used to observe ACL/owner immediately; synthetic parent rename/decoy and optional junction negative tests exercise this distinction. It neither authenticates a production root nor changes the manual Python recorder. Do **not** invoke this native probe on local field reports. Real Windows 10/11 physical field coverage, redirected/synced managed profiles, private ACL behavior and external authorization remain outstanding. NO-GO, #2/#3 OPEN.

## ADR-037 / PR #42 — initial root provenance remains unverified

Hosted Windows CI now tests the difference between a previously held independent synthetic parent handle and a decoy opened after a path swap. A forged reference and forged candidate can still agree with one another: **identity equality alone is not proof of where either handle came from**. This research code remains under `tests/`, does not read field reports or update the recorder, and produces no actual Windows 10/11 attestations. Keep snapshots private, maintain independent authorized review, and do not turn self-asserted metadata into a GO decision. Issues #2/#3 remain OPEN.

## PR #43 / ADR-038 — root trust review process, not automatic GO

See `docs/ANCHOR-TRUST-PROTOCOL.md` for separate root-origin, filesystem, privacy and release approval responsibilities. A status-only `docs/anchor-trust-template.json` may be privately checked via `python tools/anchor_trust_review.py --metadata 'C:\ApprovedPrivate\anchor-status.json'`. It never reads raw reports, always returns NO_GO/exit 2 and cannot authenticate any claim, including `approved_claimed`. A self-selected reference is not independent provenance. Real Windows 10/11 authorized matrix and external release approval are outstanding; #2/#3 stay OPEN.

## PR #44 / ADR-039 — offline minimum-info handoff (no upload)

Use `docs/FIELD-REVIEW-HANDOFF.md` as the operator → independent reviewer → release authority checklist. The optional `tools/field_review_readout.py` reads an existing private field-status sheet and a separate anchor-trust claim sheet and prints only fixed categorical states and a count of *claimed complete* OS/shell/privilege cells (0–8). It never opens raw reports, saves combined artifacts or makes GO possible. `8/8` is not evidence of real hardware runs or authenticated external approval. All physical validation and privacy approvals remain pending; #2/#3 OPEN and release NO-GO.

## PR #45 / ADR-040 — privacy-safe real-failure to synthetic-reference mapping

If a real authorized Windows field run reports a failure, keep the raw reports on the approved private device. Use `docs/FIELD-FAILURE-TRIAGE.md` to choose a *fixed* symptom token, then optionally run `python tools/field_failure_triage.py --category event_provider_denied`. The CLI never accepts raw messages or paths, performs no scans, and identifies only an existing synthetic regression starting point, always `NO_GO` / exit 2. No automated physical repro or privacy release signoff occurs. A fixture reference cannot prove an actual physical failure or qualify as independently reviewed #2/#3 evidence.

## PR #48 / ADR-043 — Monitor sampling completeness (private structural status)

New Monitor runs store only four bounded aggregate counters in the **private manifest**: requested sampling attempts, attempted calls, nonempty calls, and groups eligible for growth comparison. They are not new public status labels, do not include process names/PIDs/pathnames, and must not be pasted from real workstation reports into GitHub or chat. The field assessor returns `review` if any attempt was empty, too few attempts ran, or no comparable process identities appeared—even when the collector produced no warning. Historical schema-v1 Monitor reports without these fields remain structurally readable but must return `review`, not `pass`. Invalid counts return `fail`.

A structural `pass` is **not** a conclusion about memory health, absence of leaks or permission coverage. An empty sample may mean a provider/permission issue or simply no returned observations; only an authorized operator can investigate privately. Continue Windows 10/11 physical checks on approved devices, hold report data private, never enable scanners or change system settings to force errors, and leave release NO-GO until independent security and privacy reviews.

## PR #49 / ADR-044 — process growth ordering is a structural limit

Monitor memory growth requires at least two synthetic/observed rows with the same reliable **PID plus process start time**, an exact matching identity key, and strictly increasing valid UTC capture instants in original collection order. Identical or backward timestamps, untrusted/changed start identities and malformed times are excluded instead of producing a growth estimate. If no comparable process survives, the existing Monitor field assessment is `review`, not a memory-health verdict. One excluded process group among several can still coexist with structural `pass`; this does not certify complete observability. Real clock behavior, process churn and memory-leak conclusions require authorized private device review.

## PR #50 / ADR-045 — mixed valid and rejected growth groups

Even when `memory-growth.csv` contains valid growth rows, an unrelated process group rejected for inconsistent identity/UTC sequence can make the overall Monitor evidence incomplete. The private Monitor manifest now records integer-only `MonitorSampling.RejectedGrowthGroups`, and the status assessor also checks the existing `SkippedUnreliableIdentitySamples` total. **Either positive count requires `review`**, not `pass`. Older schema-v1 reports without these quality fields remain readable but require review; invalid/negative/boolean counts fail. The public field-validation output contains only existing fixed classifications, never real counts, PID, paths or raw errors. A 0 count cannot prove that Windows exposed all running processes, nor that memory growth is a confirmed leak. Review any true machine results privately; NO-GO.

## PR #51 / ADR-046 — Monitor singleton and missing-key coverage

A process seen once may simply have started or exited during sampling. The private Monitor manifest now distinguishes `SingletonGroups` (valid one-off groups, informational), `InvalidSingletonGroups` (a one-off group with inconsistent identity/time), and `UnkeyedSamples` (missing/blank instance key). Valid singleton groups alone do **not** make a structural Monitor run fail or require review; invalid singletons and unkeyed rows require `review` even when another process generated a growth row. Missing historical quality metadata returns `review`; malformed counts return `fail`. The public field validation prints only existing fixed labels. Do not paste real raw reports or private counts into public issues. A structural `pass` does not imply the collector observed all running processes or established memory health.

## PR #55 / ADR-050 — report-origin trust boundary

Passive field-validation stdout now says, using fixed strings, that report origin is **not authenticated** and release stays **NO-GO**. The five existing status lines retain the Mode / Validation / Contract / PrivateAcl / PassiveNativeScans / Warnings grammar, so offline manual transcription stays unchanged.

The local in-memory assessment additionally exposes OriginVerification='not-authenticated' and ReleaseDecision='NO_GO' on PASS, REVIEW **and** FAIL. No self-declared signature, independently verified provenance, trusted initial root or release-approval property from an untrusted report can promote these two constants. A coherent report still lacks independent source authentication; a fixed status is not proof of a real signature check. Hosted CI is not physical Windows 10/11 validation or independent approval. Keep local raw data private and #2 / #3 OPEN.

## PR #60 / ADR-055 — eight real-device cells are mandatory

The manually executed Windows 10/11 validation matrix includes eight distinct OS/shell/privilege cells. Each requires Quick, Events, Hardware, Monitor and passive Integrity plus schema v1, private ACL and no unexpected passive native scanning. The document and independent reviewer handoff are guarded by synthetic Markdown mutation tests in both hosted Windows CI shells. Those tests do not provide physical evidence or external release approval. Missing or unauthorized test coverage remains not_run with release NO-GO.

## PR #64 / ADR-059 — passive native log artifact check

The manual five-mode field runner now checks three fixed scanner-output names (`sfc-verifyonly.txt`, `dism-scanhealth.txt`, `clamav-output.txt`) **after confirming the private run-directory ACL**. It also checks whether those names appear among the manifest's declared files, across Quick, Events, Hardware, Monitor and Integrity. If either signal is present, the mode's fixed console status reports `Validation=fail; PassiveNativeScans=unexpected` even when other structural checks look successful. The tool does not open or print native logs, does not automatically run scanners, and does not delete retained reports. Do not upload the files to GitHub or a public issue.

This is a conservative anomaly signal, **not proof that a scanner executed**, nor proof that its absence certifies physical-device coverage. File/path swapping and private ACL/backup trust still require independent on-device review. Keep #2/#3 OPEN and release NO-GO.

## PR #65 / ADR-060 — attempted event-provider coverage is not the same as an empty log

Quick and Events field statuses now inspect only the existing per-log numeric `EventSampling` telemetry. A genuine zero-match System/Application/Defender query can remain structural `pass`; **zero attempted queries, absent log coverage, old missing aggregate fields or a reported provider failure become `review`**, not a fabricated PASS. Malformed counts, boolean numbers, cap mismatches and impossible retained-event totals become `fail`. No new event log data are collected or shared.

The status still cannot prove that any physical workstation ran the queries, that a disabled/denied provider behaves correctly on a particular machine, or that any report is safe to publish. Record only approved fixed status labels; keep all original logs private. Issues #2/#3 remain OPEN and release remains NO-GO.

## PR #66 / ADR-061 — optional offline fixed-status follow-up (not evidence)

After an authorized local field run, operators can **manually copy only the five fixed `Mode=...` console lines**, excluding the Environment line, any private report content, paths, account names or event messages. The separate Python 3.11 follow-up accepts zero to five lines for **one** OS/shell/privilege session. Its role is to identify missing mode entries and point explicit `Contract=fail`, `PrivateAcl=fail`, or `PassiveNativeScans=unexpected` labels to the **existing synthetic reference tests**, without attempting to reproduce a real fault.

Example using entirely **invented** status labels (not physical evidence):

```powershell
python tools/field_status_followup.py `
  --status 'Mode=Quick; Validation=review; Contract=pass; PrivateAcl=pass; PassiveNativeScans=not-requested; Warnings=present' `
  --status 'Mode=Events; Validation=fail; Contract=fail; PrivateAcl=pass; PassiveNativeScans=not-applicable; Warnings=unknown'
```

The fixed response shows `RecordedModes: 2/5`, the three `UnrecordedMode` labels, explicit `ReviewReason: Events:CONTRACT_FAILED` and its allowlisted `tests/ReportContract.Tests.ps1` synthetic reference. Generic `review` or `Warnings=present` does **not** identify a particular provider error or justify automatically selecting a cause. No input file is opened; no output file, network request, scan, repair or deletion occurs. Invalid, duplicate, non-allowlisted and inconsistent statuses fail closed without echoing caller text. Every invocation returns **2 / NO_GO**, including a five-mode all-PASS self-report.

This helper neither writes the existing eight-cell private evidence matrix nor authenticates device OS/build, user privileges, run pairing, initial root, ACL/sync/backup protections or the independence of any reviewer. Treat any results as optional local review hints; do not paste raw logs or private identifiers into public issues. Continue the existing approved `field_status_recorder.py` and independent human review protocol if status evidence needs to be recorded privately. Issues #2/#3 remain OPEN; public release remains NO-GO.

## PR #67 / ADR-062 — optional read-only physical test preflight

Before the five-mode field test, an **authorized human operator** may run a standalone environment/path review that creates **no** diagnostic data:

```powershell
.\Test-WtFieldPreflight.ps1 -OutputDir 'C:\ApprovedPrivateTriage'
```

It observes Windows client versus Server (via Win32_OperatingSystem.ProductType and OS build, when accessible), PowerShell version, effective standard/elevated token and output path spelling/ancestor metadata. Known relative, UNC/network or reparse paths are rejected; unknown or unsupported drives require review. **Even a normal local NTFS path is only `OutputPath: REVIEW_REQUIRED`, never a verified safe storage destination.** Its stdout is fixed-token only: no paths, exception messages, names, full raw report content or OS event data. The script does not create directories or reports, invoke the field runner, start active security/integrity scans, upload files, delete reports, elevate privileges or change ACLs.

A `CandidateCell` for Windows 10/11 × PS 5.1/7 × standard/elevated is merely a preliminary environment hint; **elevated is not proof of authorized elevated** and a candidate does not mark any physical verification cell complete. `RootAuthority: NOT_VERIFIED`, `StorageSyncBackup: NOT_VERIFIED`, `OperatorAuthorization: NOT_VERIFIED` and `IndependentReview: NOT_AUTHENTICATED` are unconditional. The script **always exits 2 / NO_GO**, including when the environment looks suitable. It must not become an automatic collector-launch gate.

Only **after separate explicit operator authorization and independent private review** of the actual trusted root, DACL/owner, junction/race risk, enterprise policy, cloud sync/backup/DLP and data-retention requirements should the operator run the existing passive `Invoke-WtFieldValidation.ps1 -OutputDir ...` for each genuinely approved environment. Begin with standard privilege, elevate only if specifically approved. If review is unavailable, **do not collect raw data** and leave that cell `not_run`; a hosted Windows CI run or preflight output never substitutes for it. Keep issues #2/#3 OPEN and release NO-GO.


## PR #69 / ADR-064 — optional SMB ancestor visibility is not remote-access proof

The standalone `Test-WtFieldPreflight.ps1 -OutputDir 'C:\ApprovedPrivateTriage'` now prints one additional **fixed-value** line, `SmbExposure`, after `OutputPath`. It reads only locally available SMB **non-special** share definitions and their SMB share ACLs; it does not create, change or remove any share, probe the network, read report contents, or publish share names, user identities or full paths. Provider failures are caught and classified without echoing exception text. It is **not** run automatically by the product collector or by `Invoke-WtFieldValidation.ps1`.

- `BROAD_ACCESS_REVIEW`: a visible share directly covers or is an ancestor of the requested output directory and has an allowed Read, Change or Full entry for an identified broad Windows principal such as Everyone, Authenticated Users, Users, Guests or NETWORK. **This does not prove real remote reachability**; NTFS ACL, firewall and network conditions still matter. Obtain independent private review; do not auto-change shares.
- `SHARED_REVIEW`: a visible covering share has only other recognized allowed entries. This is **not safe-by-default**; separate review is still mandatory.
- `NO_NON_SPECIAL_SHARE_OBSERVED`: no covering share was observed among the ordinary, enumerated SMB shares. This **does not rule out** administrative/special shares, cloud sync, backup agents, enterprise policies or effective remote access.
- `UNKNOWN`: SMB enumeration, share-path inspection or ACL identity resolution was unavailable or uncertain. **Never convert to a safe state.**
- `NOT_CHECKED`: path was rejected or was not sufficiently classified for SMB observation.

`NextAction` recommends only manual private review, and `Decision`/`ReleaseDecision` remain **NO_GO**, exit code **2**. A known local fixed NTFS path remains `OutputPath: REVIEW_REQUIRED`. The new visibility is not an external initial-root, confidentiality, permission-to-collect or release attestation. An OS shell may require different permissions to enumerate shares; an `UNKNOWN` result is inconclusive, not evidence of no sharing.

For existing reports, inspect only bounded local metadata with `Get-WtReportRetention.ps1` and keep all original reports privately in place. Do not paste a real share name, account, user/group list, root path, device build or screenshots into public GitHub issues. No retroactive claim is made for previously generated reports. Windows 10 physical validation, privacy/security/root authority and release approval remain external gates; issues #2/#3 stay OPEN, release NO-GO.

## ADR-065: explicit SMB collection guard (optional, never privacy approval)

For an authorized private field run, a cautious operator **may opt in** to blocking new five-mode collections when the bounded ordinary-SMB ancestry check reports any share or cannot answer:

```powershell
.\Invoke-WtFieldValidation.ps1 -OutputDir 'C:\ApprovedPrivateTriage' -RequireSmbPreflight
```

With this switch, immediately before each mode the runner rechecks the candidate path and calls the read-only ordinary SMB metadata probe. Broad or otherwise observed parent shares, unsupported/unavailable SMB commands, access denied/ACL provider failures, ambiguous paths, reparse/path rejection and UNKNOWN all **block before that mode's data collection**, with a fixed error that reveals no path/share/account. Windows 10, non-elevated and PS 5.1/7 availability cannot be assumed; on hosts where the provider is missing or restricted, the opt-in guard blocks rather than guessing. Choose a separately authorized private storage location and review it offline; the utility will not fix permissions or remove shares. Previous report folders remain untouched, even if a later mode is blocked. This option is **not** enabled by default and is not enforced by direct `WinTriage.ps1` invocation.

When no ordinary share is observed, collection may continue through the existing local-NTFS/private per-run ACL and handle-lease controls, **not** because storage has been approved. Administrative shares, cloud sync/backup/DLP, effective remote access, independent owner/root verification and concurrent SMB/path changes are not verified. A share observation never proves raw report disclosure, and an empty list never proves a secure destination. Review and authorization remain private and external; release stays NO-GO.

### ADR-066 — fixed SMB refusal output

When the optional `-RequireSmbPreflight` gate cannot verify its **narrow ordinary-share prerequisite**, it prints only `SmbCollectionGate: BLOCKED_OR_UNKNOWN` as its refusal category and returns exit code **2**; it does not expose underlying SMB provider exceptions or script-source paths. This is not a diagnosis, denial of all remote access, approval or reason to share whole terminal output publicly. Existing report folders are not deleted or moved. Any completed earlier modes remain privately retained for the operator's review.

### ADR-067 — first refusal does not print an environment banner

If `-RequireSmbPreflight` is explicitly selected, a refusal **before the first mode** (including optional SMB module-load failure, rejected path or uninspectable share) now emits exactly one fixed category, `SmbCollectionGate: BLOCKED_OR_UNKNOWN`, then exits 2. No Windows build/privilege banner is printed on that early refusal. If an earlier mode was permitted, a **later** refusal can follow already printed environment and fixed mode-status lines; this is *not* a whole-transcript anonymization feature. An apparently permitted first check merely allows the existing independent path/ACL protections to operate, not a security approval. Avoid posting any real terminal output, even with a fixed refusal line, without private review.
