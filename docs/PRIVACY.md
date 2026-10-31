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
