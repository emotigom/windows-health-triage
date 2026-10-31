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

Unlike earlier path-based `Out-File`/`Export-Csv` writes, the standard diagnostic report now creates its JSON, memory CSV, `SUMMARY.md` and manifest files **relative to the previously opened run-folder handle**, with a fixed allowlist of leaf names and exclusive new-file semantics. It does not reopen the path to choose where those core bytes go. Unsupported Windows configurations fail without a path-based fallback. This does not make reports anonymous, encrypted or immune to same-user/administrator tampering. **Optional external ClamAV/SFC/DISM text outputs are not yet handle-bound.** Only manual inspection should determine whether local raw reports can be shared.


## Optional native scan text logs (ADR-021)

The user-requested ClamAV and verify-only SFC/DISM process output now streams to a new file opened **relative to the already pinned run-directory handle**, not to `Out-File` using an absolute path. If the safe writer cannot be created, the optional executable is **not started**. The file remains local, private and never overwritten or uploaded by this tool; partial output can remain after an error. This does not constrain Windows logs produced independently by SFC/DISM or Defender, and does not prevent authorized local tampering. Raw output may contain personal data and must not be posted publicly without manual review. These actions remain explicit opt-in only.
