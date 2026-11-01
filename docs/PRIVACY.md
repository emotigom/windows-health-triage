# Minimal report export: privacy model

**Default:** Windows Health Triage keeps full reports locally. It does not automatically upload, publish, email, or redact reports.

A full report can contain machine names, process names/PIDs, account names, device identifiers, installed software, event messages, network addresses, and malware detection paths. **Do not attach raw reports to public GitHub issues.**

## Explicit, minimized export (issue #3)

After generating a diagnostic report, the user can make a separate local-only JSON summary:

```powershell
.\Export-WtShareSummary.ps1 -RunDirectory "$env:LOCALAPPDATA\WinTriage\reports\YOUR_RUN_ID" -OutputPath "$env:TEMP\triage-minimal.json"
```

Replace `YOUR_RUN_ID` with the actual report subfolder. The output path must be new; the tool refuses to overwrite an existing file. The original report is unchanged.

The exported JSON is a **reconstructed allowlist**, not regex replacement of sensitive strings. It may include only:
- schema version, export kind and allowlisted diagnostic mode
- sampled event counts grouped by allowlisted category/severity (unrecognized categories become `other`)
- storage assessment counts (`attention`, `inconclusive`) without disk names
- fixed-value SFC/DISM execution states without command output
- static caveats

The export **never copies** event messages, provider/event IDs, names, timestamps, paths, IPs, malware details, command lines, free-text warning strings, process IDs or hardware identifiers. Unknown values are deliberately dropped or mapped to fixed labels.

## Limitations and review

This is data minimization, **not a guarantee of anonymity**. Even category counts and diagnostic modes may disclose symptoms or hints about a system. Inspect the generated JSON and share only the subset necessary. Do not publish raw `SUMMARY.md`, `events.json`, `hardware.json`, `security.json`, `processes.json`, scan outputs or memory CSVs.

Never submit real device logs as unit-test fixtures. Use invented canaries in `tests/fixtures/synthetic-report/` instead.

## Trust boundaries

- Input: existing untrusted local diagnostic files. JSON parsing may fail closed; it must not execute contained strings.
- Transformation: `src/WinTriage.Privacy.psm1` pure allowlisted conversion; no OS collection or network access.
- Output: local JSON written with create-new semantics; no overwrites or uploads.
- Tests: synthetic adversarial strings in unknown fields, event details and identifiers must not appear in the exported JSON.
- Future schema additions require privacy review and tests before expanding the allowlist.

## Local raw-report access permissions (ADR-012)

For **new runs**, the tool restricts the new per-run folder's Windows DACL to the invoking account, LOCAL SYSTEM and BUILTIN Administrators before collecting data. Existing reports and their permissions are **not** changed. If that access policy cannot be established, collection stops rather than generating sensitive reports in an unknown-permission directory. UNC/mapped-network output paths are not supported. The parent output folder may retain existing permissions; the new report subfolder has protected inheritance.

ACL restrictions do **not** protect against administrators, the invoking account, compromise of that account, backup software, or automatic cloud synchronization. Local folders inside OneDrive or other syncing software may still upload data; choose a local non-synchronized path. The tool does not automatically delete old reports. Review and manually manage local retention. To inspect permissions yourself use `Get-Acl -LiteralPath '<your run folder>' | Format-List` and avoid posting the output publicly if it reveals user names.

## Private field validation (#2)

`Invoke-WtFieldValidation.ps1` is a **separately requested, passive** five-mode PC validation. It retains raw reports locally, prints only fixed statuses and Windows build/PowerShell/privilege metadata, and neither uploads nor deletes files. **Even these reduced statuses are not guaranteed anonymous.** Inspect the console output before sharing; do not paste unredacted error messages, `manifest.json`, paths or report directories. Its `pass` label means structural contract/ACL checks, never a health diagnosis. See `docs/FIELD-VALIDATION.md`.

The report security module also refuses existing reparse points (junctions,
symlinks) in the report path ancestry so a local-looking path cannot silently
redirect to another destination. This does not prevent race conditions from
malicious processes controlling writable parent directories. Choose a direct,
trusted local NTFS directory and avoid sync/backup paths for highly sensitive logs.

## Manual metadata-only report retention review (ADR-015)

Run `Get-WtReportRetention.ps1` only when you want to review accumulated **local** reports. It counts eligible run folders by directory creation time, totals direct-child file sizes only after restricted ACL verification, and reports no names or paths. It never opens report contents, follows junction/symlink folders, writes reports, deletes old data, schedules cleanup or sends information elsewhere. `Status=review` / `Incomplete=True` means some entries were skipped, unprotected, unreadable or outside an enumeration cap—**not** that every report was counted. The time and size values are approximate filesystem metadata, not an authenticated manifest history.

The summary still reveals device activity through totals, even without names. Review before publication. Retain or dispose of old reports **manually**, using your own system retention and backup policy; the tool does not decide what is safe to erase.

## Creation-time ACL protection (ADR-016)

New raw report run directories are created with the protected Windows ACL as a **creation parameter** on PowerShell 5.1 (.NET Framework) and 7 (.NET Windows ACL extension), rather than by creating an inherited-permission directory and modifying it afterward. The tool verifies final rights and child inheritance before any data collection and fails closed on unsupported filesystems or policies. This reduces exposure from a briefly broader ACL on an empty run directory; it does not close concurrent path-swap races or grant encryption. Old reports are never modified.

## Owner validation on managed Windows devices (ADR-017)

A directory may have an allowlisted DACL but an unexpected **owner** who can change its access rules. New per-run report folders must therefore have a verified owner SID belonging to the invoking account, LOCAL SYSTEM or BUILTIN Administrators, as well as the already required protected DACL. If corporate policy forces another owner, collection stops before writing evidence rather than weakening the policy; the metadata-only retention checker excludes such a folder from private report totals. System-wide privileges, backups, OneDrive/sync and path races still need separate controls. No existing report ACLs/owners are modified.

## No existing-folder reuse on concurrent collisions (ADR-018)

The raw-report writer now requests a **new** directory via Windows `CreateDirectoryW` with its protected ACL as part of creation. If the same run folder already exists—even if its ACL appears secure—Windows returns an error, and this run does not append evidence to that directory. This strengthens the protection against two processes accidentally selecting the same run name. It does **not** guarantee that a malicious process cannot change a writable parent-directory path between checks and later file writes. Never place sensitive reports in a folder whose parent can be changed by untrusted users. Existing reports and their permissions are untouched.

## Pinned directory handles during evidence writes (ADR-019)

New report runs now keep metadata-only Windows directory handles open for their drive-root-to-run ancestor chain. The handles omit deletion/rename sharing and are released in `finally` after the collector stops. **Omitting delete sharing does not reliably prevent directory renames on Windows**, as a hosted Windows runner demonstrated. Each component is checked for reparse-point indirection and file-identity changes at the next checkpoint; failure before capture or during a later write stops collection. A rename **between the check and a file open** can still redirect a file; this is only a detection layer, **not** a guarantee against local interference, same-user content tampering, unusual Windows filesystems or network/backup agents. No files are encrypted, removed or uploaded.

## Handle-relative core JSON, CSV and summary output (ADR-020)

Unlike earlier path-based `Out-File`/`Export-Csv` writes, the standard diagnostic report now creates its JSON, memory CSV, `SUMMARY.md` and manifest files **relative to the previously opened run-folder handle**, with a fixed allowlist of leaf names and exclusive new-file semantics. It does not reopen the path to choose where those core bytes go. Unsupported Windows configurations fail without a path-based fallback. This does not make reports anonymous, encrypted or immune to same-user/administrator tampering. **At this ADR-020 stage optional external ClamAV/SFC/DISM outputs remained path-based; ADR-021 below replaces these writers.** Only manual inspection should determine whether local raw reports can be shared.


## Optional native scan text logs (ADR-021)

The user-requested ClamAV and verify-only SFC/DISM process output now streams to a new file opened **relative to the already pinned run-directory handle**, not to `Out-File` using an absolute path. If the safe writer cannot be created, the optional executable is **not started**. The file remains local, private and never overwritten or uploaded by this tool; partial output can remain after an error. This does not constrain Windows logs produced independently by SFC/DISM or Defender, and does not prevent authorized local tampering. Raw output may contain personal data and must not be posted publicly without manual review. These actions remain explicit opt-in only.


## Earlier detection during run-directory handle acquisition (ADR-022)

The report path lease now rechecks all currently pinned ancestor file identities **after every new directory handle**, instead of waiting for the complete path. This helps reject a sustained ancestor replacement before visiting later descendants. The checks are not atomic and do not eliminate a rename-and-restore between calls or the creation-to-first-handle gap. The diagnostic report remains local with no automatic export or deletion; actual Windows 10/11 enterprise/desktop compatibility must still be tested.


## Test-only relative directory traversal research (ADR-023)

The native relative-directory proof-of-concept is isolated under `tests/` and never loaded by the normal collector. The synthetic harness may reopen only its GUID-named test parent with permissive delete sharing to exercise controlled renames; production directory sharing remains unchanged. It opens existing synthetic directories for metadata only, does not create report outputs or invoke scans, and uses a unique temporary root that the test itself owns. The current product still relies on non-atomic admission/path identity checkpoints. No new security guarantee, removal of user reports, or automatic report sharing is introduced.


## Handle ACL research (ADR-024)
The handle-based ACL/owner probe is **test-only** and operates exclusively inside GUID-named synthetic temporary directories. It never reads or mutates an existing report, never uploads or prints SIDs/SDDLs, and never enables an optional scanner. Hosted Windows success does not remove the path acquisition race, stronger-actor tampering risk, or need to validate real Windows 10/11 and enterprise policies before any production change.


## ADR-025 research-only directory creation
A new synthetic-only directory-creation probe runs exclusively in GUID-owned temporary test folders. It supplies a private descriptor at native creation and validates the returned handle without collecting or altering any real report. No user data, SIDs or ACL strings are published or uploaded. Production uses its existing path policy until separate review and field validation.


## ADR-026 pinned-anchor research isolation
A synthetic-only anchored handle traversal probe operates exclusively in a newly generated GUID-owned temp tree. Its private run creation and optional junction/decoy simulation do not read, change, upload or publish real reports, security identifiers or ACLs. Existing production privacy controls remain unchanged; the initial anchor identity and non-redirection policy require separate field review before adoption.


## ADR-027 anchor race research
The new provenance and pre-open junction fixtures manipulate **only disposable GUID-owned synthetic directories**. All status messages are fixed strings, without SIDs, ACL/SDDL, actual filesystem paths or report data. Neither the production report-location policy nor opt-in native tools change. Initial anchor trust and managed policy risks remain unresolved.


## ADR-028 research-only root traversal
The root traversal experiment **reads volume and existing ancestor metadata only** and creates/removes only one GUID-owned synthetic temporary fixture. Its strict path test uses literal static examples, never user reports. No personal filesystem paths, SIDs, ACL/SDDL, hostnames or report contents are emitted. Production code, native scanners and upload policy remain unchanged. A fixed volume does not prove initial anchor trust.


## ADR-029 — synthetic full file-ID and volume alias research
The experiment requests only existing directory-handle metadata and optionally a volume-GUID alias; **no file IDs, serial numbers, GUID strings or real filesystem paths are logged**. All created and removed directories are under a new GUID-named test-owned fixture. No user reports, native scanners, uploads, or production path handling change.


## ADR-030 synthetic trust-baseline lifecycle
Research checks a borrowed handle and temporary session token entirely within a disposable GUID-named fixture. The token and raw file identities are not logged, copied into a report, uploaded or persisted. No user reports, drive mappings, scans or operational export behavior change. Source authenticity remains an open design and field-review requirement.


## ADR-031 — privacy-bounded field readiness evidence
The new local-only manifest accepts fixed enumerated labels and strictly rejects extra/free-text fields. Keep all raw field reports, original machine details and the completed private checklist off public GitHub. The checker never uploads, logs input values or grants production approval; even an all-pass synthetic manifest remains NO_GO. Do not attach workstation logs, hostnames, paths, SIDs, volume IDs or provider event text to issues.

## ADR-032 — explicit status-only recorder privacy boundary

`tools/field_status_recorder.py` accepts only *manually typed* enum labels from the field harness console and an OS/shell/privilege selection. It does not ingest raw reports or console transcripts, nor automatically post diagnostics. It refuses unknown/free-text fields, input symlinks where detectable, previously recorded matrix cells, existing output files, and output inside the checkout. Error messages do not echo values or paths; tests use invented data.

Use an approved **local non-synchronized private** directory and inspect effective Windows ACLs before recording. Exclusive file creation and a user-provided confirmation switch do not secure arbitrary parent folders, hostile reparse/mount changes, mapped/managed storage, backup agents or same-user/admin access. The status JSON can still reveal testing activity and is not anonymous. Keep snapshots off GitHub and CI, and manually decide retention. Creation success (exit 0) is not a GO signal: the separate readiness gate always emits NO_GO and exits 2.

## ADR-033 — ambiguous status JSON refused

The readiness gate and status-only recorder use the same bounded, strict metadata loader. They reject duplicate keys, non-finite numbers, non-regular/linked leaf inputs and changed file identities, without echoing input values or paths. This avoids permissive last-key-wins interpretation of untrusted metadata. It is *not* a defense against trusted-path substitution via writable ancestors or a guarantee of encrypted/private output, Windows ACL strength, cloud-sync avoidance or authenticated evidence. Operator-managed, non-synced local storage and independent release/privacy approval remain required; no raw Windows reports are opened by either helper.

## ADR-034 — Windows status snapshot ACL review, not a privacy guarantee

`Test-WtFieldStatusAcl.ps1` reads **only** the explicitly named status file's ACL/owner/attributes and ancestor path metadata, never its contents or raw diagnostic reports. It emits fixed status labels and always reports `NO_GO`. `restricted` is a point-in-time allowlist observation, not proof of effective access, a securely created file or controlled backups. `SyncAndBackup=unknown` is deliberate: OneDrive Known Folder Move, backup agents and managed sync can copy apparently local files. The recorder still uses Windows-inherited ACL at file creation, so do not assume `0o600` created a protected DACL. Choose a locally reviewed restricted parent, exclude synchronization where authorized and inspect file permissions manually before considering any sharing. This command does not repair or change anything.

## ADR-035 — creation-time DACL is test-only, not production coverage

The Windows `CreateFileW`/`SECURITY_ATTRIBUTES` proof-of-concept resides under `tests/` and operates only on GUID-owned temporary synthetic fixtures. The user-facing Python status recorder **has not been replaced**; it still relies on user-selected private storage and may inherit Windows ACLs. In the new test the descriptor is supplied *at creation*, but this does not guarantee trusted ancestors, no cloud/backup copying, strong endpoint privacy or file identity against malicious path races. No real report is read, no ACL repair is performed and no private data is sent to GitHub. Real Windows 10/11 field review and independent approval remain required; release is NO-GO.

## ADR-036 — held-parent file handle experiment does not certify private storage

The parent-relative `NtCreateFile` experiment in `tests/` operates exclusively on invented JSON under disposable CI fixtures. It preserves the new file's handle for immediate ACL observation and avoids a second parent pathname lookup during creation, but **the initial parent is not independently authenticated**. Ancestor traversal, reparse/mount aliases, same-user interference, managed endpoint policies and cloud backup remain unresolved. The user-facing status recorder and all production report collectors are unchanged; its Windows output ACL must still be assessed locally. No real diagnostic content is read or uploaded, and release remains NO-GO.

## ADR-037 — externally held synthetic identity is not proof of origin

A test-only helper compares a previously held reference handle with a separately opened parent before creating synthetic status files. Its decoy counterexample intentionally shows that two matching, attacker-selected handles can still be wrong. No new production file writer, real report intake, upload, privacy certification, root provenance authority or release decision is introduced. Real filesystem, managed/synced storage and initial root trust must be verified separately, so release remains NO-GO.

## ADR-038 — independent root review claims are not trusted records

The optional `tools/anchor_trust_review.py` reads only a bounded, fixed-enum claim sheet. It rejects unknown/free-text fields and never prints input paths, identifiers, signatures, or values; every evaluation remains NO_GO. A fake `approved_claimed` label is not a signature or an independently verified approval. Keep all actual security evidence, root identity and reviewer attestations in private, explicitly authorized channels—not public GitHub or CI. No field data is gathered, no storage privileges altered, and production code remains unchanged. Full protocol: `docs/ANCHOR-TRUST-PROTOCOL.md`.

## ADR-039 — two-sheet field handoff exposes only claims, never evidence

`tools/field_review_readout.py` is opt-in and reads two locally selected, strict status-only files. It prints only fixed labels plus an aggregate 0–8 count, always NO-GO/exit 2, without writing or uploading any result. Even the count can reveal which testing milestones were reported: do not publish output or private worksheets without an explicit disclosure review. No raw reports, machine identities, root paths, signature information, security policies or reviewer details belong in the sheets. Use `docs/FIELD-REVIEW-HANDOFF.md` for the independent offline review steps; no real Windows 10/11 or managed storage validation has been authenticated by this change.

## ADR-040 — failure classification never ingests real diagnostic evidence

The optional `tools/field_failure_triage.py` accepts one fixed symptom code only; it is not a redactor or a safe channel to paste log text. It never reads reports, scans drives, opens local paths, sends data or executes the mapped test. A displayed fixture name is a pre-reviewed **synthetic** example, not evidence of a real user's problem. Invalid/private-text inputs never echo back and produce only NO-GO. External cloud-sync policy and trusted-root authority cannot be automatically reproduced and must be reviewed privately. See `docs/FIELD-FAILURE-TRIAGE.md` before making public issues or testing on a real PC.

## ADR-043 — private Monitor aggregate sampling counts do not mean anonymized evidence

The Monitor manifest now records four **aggregate** numeric attempt/comparability fields. Even aggregate values may reveal facts about local activity; keep the manifest under the same restricted, unsynced/independently reviewed private storage controls as all other reports. No per-process identifiers or raw errors are added to these fields, and the public field-validation line still contains fixed labels only. Silent empty or insufficient samples force review; missing older metadata cannot be treated as a positive result. Do not upload an actual manifest, event log, host name, process name, account/path or other device data for this test. No report upload, scanner, cleanup, additional ACL mutation or independent release approval is introduced; NO-GO.

## ADR-044 — process growth counterexamples are fabricated only

New process-growth time and PID-reuse regression inputs are entirely fictional; they do not inspect any actual process or export a process list. Existing real process reports remain local with restricted ACLs. Group validity checks use pre-existing data without writing new private fields or adding public output. Private `SUMMARY.md`, memory CSV and manifest data can still contain sensitive information and must not be shared. Neither test-only time assertions nor a structural `pass` authenticate an initial root or guarantee no OneDrive/backup/DLP copying. Real field and independent approval still pending; NO-GO.

## ADR-045 — additional private Monitor quality count

Monitor adds a **single aggregate integer** `RejectedGrowthGroups` to the existing private `MonitorSampling` block and uses the already present `SkippedUnreliableIdentitySamples` integer for structural review. These numerical observations can reveal aspects of workstation activity and therefore inherit the existing strict local, reviewed, non-synced handling; they are **not** authorized public or anonymized evidence. Public field validation still emits only fixed PASS/REVIEW/FAIL and warning-presence labels. No new process name/PID, original path, user account, event, raw exception, scanner, upload or ACL alteration is introduced. No independent original-root verification or real-device privacy signoff is implied; NO-GO.

## ADR-046 — Monitor one-off identity completeness counts are private

Three additional numeric, **aggregate-only** fields stay inside the same existing restricted Monitor `manifest.json`: `SingletonGroups`, `InvalidSingletonGroups` and `UnkeyedSamples`. These numbers can still indirectly describe local activity and are **not safe to publish without separate disclosure review**. The public field-status output remains allowlisted and never returns process IDs, identities, timestamps, paths or arbitrary error text. Neither new synthetic tests nor these counters authenticate root origin, managed OneDrive/backup/DLP behavior or real-device permissions. No new scanner, upload, ACL mutation or report deletion is introduced; independent security/privacy authorization and release NO-GO remain unchanged.


## ADR-064 — SMB ancestry cannot be certified by per-run ACL PASS

Private report ACL PASS checks the current run folder; it is **not** proof that a parent path is unshared, that a broad SMB share grants effective remote read, or that backups/sync never copy data. The optional operator-only `Test-WtFieldPreflight.ps1` now reports fixed `SmbExposure` labels by inspecting only non-special SMB share definitions and share ACLs. It neither reads report contents nor publishes paths, share names or account IDs, and it does not change the share or run any collector. A broad principal triggers review; a missing, unreadable or ambiguous SMB listing cannot grant approval. Even `NO_NON_SPECIAL_SHARE_OBSERVED` leaves special/admin shares, effective NTFS access, firewall, managed sync/backup/DLP, provenance and retention outside proof. All release decisions remain NO-GO pending independent privacy/security review.

## ADR-065 — optional SMB gate is not an access verdict

The manual field runner offers `-RequireSmbPreflight` to refuse new report creation for an observed or uninspectable **ordinary** parent SMB share. Unknown/missing provider capability blocks this **opted-in** run rather than being treated as safe. The guard prints only a fixed error; tests use fabricated data. It never edits share/NTFS ACLs, deletes or transfers existing reports, or adds active scans. An unobserved non-special share does **not** certify storage privacy, administrator-share absence, effective remote access, sync/backup/DLP policy, or freedom from TOCTOU. Direct collector and default field workflow stay unchanged. Keep private findings off public GitHub; independent release/privacy/root/8-cell approval remains NO-GO.

## ADR-066 — fixed refusal does not include source paths

The opted-in field runner catches the SMB gate's fixed internal exception before PowerShell's unhandled-error formatter can add a checkout path or line number. It suppresses provider warning/verbose/debug/information streams, emits the bounded `SmbCollectionGate: BLOCKED_OR_UNKNOWN` refusal label and exits 2. This does not make the *rest* of a physical field-run transcript safe for public posting; keep actual build, device, directory, security and diagnostic records private. No share/ACL/report is changed, and release remains NO-GO.

## ADR-067 — first SMB block and module loader are privacy-minimized

An opted-in SMB guard refusal before the first mode, including failed import of its optional policy modules, now returns **only** `SmbCollectionGate: BLOCKED_OR_UNKNOWN` with exit code 2. The field runner defers its potentially identifying Windows build banner until a first guard has permitted ordinary collection checks. Later refusal after a completed mode may be preceded by the existing private banner and mode statuses: no whole-session public sharing guarantee is made. Synthetic-only CLI regressions test a rejected relative path and a missing optional module; no real machine metadata enters GitHub. Release NO-GO, independent Windows/initial root/security/privacy review pending.

## ADR-068 — guard failure before generic import and immediately before collection

The optional SMB guard now refuses on a bad/unknown initial path/share state before generic module imports; opted-in generic import and report-folder listing errors also use only a fixed denial line instead of raw paths or exceptions. A second per-mode snapshot is made just before collector invocation, after listing existing folder names, so changes observed during this interval can block new evidence collection. Test inputs and mock checkout files are fictional; no actual Windows shares or user report contents are inspected. This remains a *best-effort read-only snapshot*, not an atomic object-pinned access guarantee or a release signoff. NO-GO.
