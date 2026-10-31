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
