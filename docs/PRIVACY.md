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
