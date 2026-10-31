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
3. Run in Windows PowerShell 5.1 (ordinary user); optionally repeat in PowerShell 7.
   For privilege coverage, repeat in an elevated shell only if authorized.
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
- `review`: provider coverage, sampled event data, warnings or storage
  interpretation needs inspection. Not a diagnosis and not necessarily a bug.
- `fail`: a report contract/ACL/explicit-scan invariant failed, or the
  collector did not finish. Retain raw reports only on your PC for private diagnosis.
- `PassiveNativeScans=unexpected`: a passive-mode invariant was violated.
  Do not rerun active scans; report the minimal finding privately.

## Manual matrix

| Environment | Privilege | Required checks |
| --- | --- | --- |
| Windows 10 (real PC) | Standard | Quick / Events / Hardware / Monitor / Integrity, ACL |
| Windows 10 (real PC) | Elevated if allowed | Same, compare provider access |
| Windows 11 (real PC) | Standard | Same, compare storage/Defender sampling |
| Windows 11 (real PC) | Elevated if allowed | Same, compare provider access |
| Windows PowerShell 5.1 | Both where available | Source parser, synthetic tests and manual matrix |
| PowerShell 7 | Both where available | Same tests; compare with 5.1 |

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
