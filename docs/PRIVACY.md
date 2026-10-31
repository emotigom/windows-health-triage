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
