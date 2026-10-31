# Validation, known limitations, and triage protocol

## Executed in this delivery environment
- Inspected and modified source code and documentation.
- Checked archive/structure and used cross-platform static assertions.
- **No actual Windows runtime test is possible in this Linux execution environment without PowerShell/Windows.** Do not interpret this as a Windows certification.

## Validation to execute on Windows before calling it stable
1. Run `./tests/Smoke.Tests.ps1` in **Windows PowerShell 5.1** and in **PowerShell 7.x**. It parses all project scripts and tests deterministic logic.
2. Run `./tests/Integration.Tests.ps1` in each shell. It collects read-only Quick, Events and Monitor snapshots into a newly created temp folder and validates every file referenced in `manifest.json`.
3. Repeat `Quick` as non-admin/admin with a normal Windows 10/11 workstation. Check errors in `manifest.json` and validate health/Defender command behavior on that OS.
4. Check corner cases: no recent events, Defender disabled, inaccessible event logs, protected process without accessible start time, absence of physical disk cmdlets.
5. With ClamAV independently installed and signatures current, explicitly test a benign sample folder and a known **official** test signature. Verify exit code and report; do not use actual malware.
6. Inspect report contents for sensitive local paths before attaching diagnostic reports to any issue.

## Current known limitations
- Event queries are capped; sampling can miss older high-severity events. 'Not observed' is not 'not present'.
- Some hardware collectors do not include true SMART attribute health. Firmware/drive status `OK` is insufficient evidence.
- Private memory increase alone is not evidence of a memory leak; workload, cache, and garbage collection matter.
- Security scans are not done by default. A requested Defender scan may quarantine according to Defender policy.
- No automated system recovery or self-modifying repair in this version.

## Diagnostics to send for a bug report (remove sensitive details first)
- Windows build and PowerShell `$PSVersionTable.PSVersion`
- `Mode` and options used (no secrets or sensitive file paths)
- Specific warning text from `SUMMARY.md` (redact user name, host name, directories)
- A minimal reproducible case; **do not publish unredacted events.json or processes.json**

## Official technical references
- Microsoft `Get-WinEvent`: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent
- Microsoft `Start-MpScan`: https://learn.microsoft.com/en-us/powershell/module/defender/start-mpscan
- Microsoft Defender Antivirus event IDs: https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus
- Microsoft SFC verification: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sfc
- Microsoft DISM health checks: https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/repair-a-windows-image
- ClamAV manual: https://docs.clamav.net/manual/Usage/Scanning.html


## #4 collector seam verification (2026-10-31)
- `tests/Collector.Tests.ps1` must pass for Windows PowerShell 5.1 and PowerShell 7 in PR and main CI.
- Both `tests/Integration.Tests.ps1` and `tests/Smoke.Tests.ps1` must continue passing with unmodified report keys and native-read-only collection.
- Injected fixtures must not require administrator access or real personal process/OS data.


## Event collector sampling regression (2026-10-31)
- Run `tests/EventCollector.Tests.ps1` in Windows PowerShell 5.1 and 7, both from GitHub CI and `Validate-Windows.ps1`.
- Verify Defender ID 1116/1118 records appear despite information level; duplicate log/record IDs cannot consume cap twice.
- Verify total retained records per log never exceed `MaxEventsPerLog`. `manifest.json.EventSampling` is explicit about query caps, query failures and projection failures. Reported counts remain sampled, not full-log totals.
- Confirm existing smoke/privacy/collector/integration suites pass without elevated privileges or native scans.

## Hardware collector regression (2026-10-31)

- `tests/HardwareCollector.Tests.ps1` tests no actual hardware; all providers are synthetic.
- Run from both PowerShell 5.1 and PowerShell 7 in CI and locally via `Validate-Windows.ps1`.
- Test separate CIM, physical disk, individual reliability counter, PnP, MemoryDiagnostics error paths. Unavailable providers must not imply health.
- Existing Quick/Hardware/Integrity/Events/Monitor integration test must pass without launching native repairs or security scans.

## Static preflight drift regression (PR #9, 2026-10-31)

- Cause: after PR #8 moved the storage call into `WinTriage.HardwareCollector.psm1`, `tools/check_static.py` still required the literal call in `WinTriage.ps1`.
- Reproduced: first PR #9 Windows CI run 41183394468 failed at `python tools/check_static.py` in both jobs (exit code 1) while later jobs were skipped.
- Remedy: inspect the module that now owns the call, assert the entrypoint imports it, and reject known disk mutation cmdlets there. Keep integrity and scan opt-in guards.
- Each Windows CI job now runs Python 3.11 static preflight **before** PS 5.1 / PS 7 parser, deterministic and read-only integration tests. This preflight is a conservative text check, NOT a PowerShell parser or security proof.
- Local invocation: `python tools/check_static.py`. Actual hardware/Windows 10/11 testing remains outside hosted CI.

## Raw report schema v1 contract tests (2026-10-31)

- Run tests/ReportContract.Tests.ps1 in both Windows PowerShell 5.1 and PowerShell 7; fixtures are invented and intentionally contain invalid versions/paths/states.
- tests/Integration.Tests.ps1 validates each passive CI report using Assert-WtReportContract; no scanner is invoked.
- ReportSchemaVersion in raw manifest.json is separate from the explicit minimal-sharing schema. New raw fields are never automatically added to the allowlist.
- Unknown/null provider evidence remains acceptable; incompatible field/type drift and false-healthy judgments fail CI. These checks do not establish diagnosis accuracy or Windows 10/11 hardware support.

## Passive security collector tests (2026-10-31)

- Synthetic SecurityCollector.Tests.ps1 covers unavailable APIs, denied status/history, independent detection preservation and default scan state.
- Windows PS 5.1 and 7 CI invoke the tests before report schema and integration checks. No test performs an antivirus scan.
- Unknown/unreadable Defender evidence is not proof of no threat. Active native scan executor remains gated in the main CLI for a later separately reviewed refactor.

- PR #14 first PS 5.1 CI caught an encoding parse error: new non-ASCII PowerShell source without UTF-8 BOM. Added BOM and module-level static preflight check; PS 7 alone cannot establish PS 5.1 encoding compatibility.

## Integrity verification executor regression (2026-10-31)

- `tests/IntegrityCollector.Tests.ps1` injects all command resolvers and fake runners. Tests never execute `sfc.exe` or `dism.exe`.
- Assert passive no-opt-in, no-admin and privilege-check-error all block native command execution, regardless of fake runner availability.
- Assert hardcoded verify-only arguments; unavailable executable, missing output, indeterminate/nonzero status and one-command exceptions retain independent evidence and warnings.
- Both Windows PowerShell 5.1 and 7 CI include this test, parser guards, report schema checks and passive Integrity integration.
- Explicit native verification is NOT exercised on hosted CI. A real administrator-initiated verification may produce native logs and substantial I/O; no repair or auto-kill is requested.

## Native scan executor boundary (2026-10-31)

- `tests/ScanExecutor.Tests.ps1` runs fake Defender/ClamAV providers without accessing real threat data or starting live scans.
- Test passive no-op, unavailable command, false/missing scan path, missing output, nonzero/detection/indeterminate exit codes, independent scanner failures, and local log file registration.
- Static/PowerShell parser guards ensure only hardcoded detection flags and explicitly selected Defender QuickScan, with no delete/move flags.
- Both Windows CI jobs run new tests and passive integration; native Defender may quarantine according to its configured policy **only when a user explicitly requests a scan**. No actual scanner is run in CI.

## Raw report access control regression (2026-10-31)

- `tests/ReportSecurity.Tests.ps1` creates only fictional temporary report folders. Verify no inherited DACL, explicit current user + SYSTEM + Administrators only, child file inheritance, collision/unsafe path/UNC rejection, and failure on an ordinary inherited directory.
- `tests/Integration.Tests.ps1` checks the newly produced report folder's ACL before inspecting reports, with no native scans or repair.
- Both Windows PowerShell 5.1 and PowerShell 7 CI jobs run ACL tests. A filesystem that cannot enforce private Windows ACLs must fail before diagnostic data is collected.
- Real user Windows 10/11, managed corporate endpoints, redirected profiles, non-NTFS and OneDrive-synced paths remain unverified; user should examine ACLs and synchronization settings before sharing.

## Manual workstation validation (#2, 2026-10-31)

- `Invoke-WtFieldValidation.ps1` deliberately performs **passive** Quick, Events, Hardware, Monitor (2 one-second samples), Integrity; flags for Defender/ClamAV/SFC/DISM remain absent. It leaves full reports on that PC in a local private field-validation folder; it neither uploads nor automatically deletes reports.
- Each mode uses report schema v1 and private ACL verification. Its public-friendly one-line results include only fixed status codes; warning text, event messages, usernames and report paths are deliberately suppressed. OS build, PowerShell version and elevation are shown to make workstation observations actionable; these still count as system metadata.
- `tests/FieldValidation.Tests.ps1` is purely synthetic; test missing ACL, invalid schema, truncated event sampling, warnings, unknown disk providers, and unexpected active scan states. It asserts malicious canary values do not pass through output. CI executes only this synthetic test, **not** the manual field runner.
- On an actual Windows 10/11 PC run separately in **non-admin** and **admin** shells, Windows PowerShell 5.1 and optionally PowerShell 7, without changing Windows policies. Record failures and environment build while keeping raw logs local; compare warnings and private ACLs. Use `docs/FIELD-VALIDATION.md` for the manual matrix and issue-sharing guidance.
- **Hosted Windows CI success is NOT verification of a physical Windows 10/11 device**. Track real field runs under #2; do not close until suitable device evidence exists.

## Field runner composed integration (#2, 2026-10-31)

- `tests/FieldValidation.Integration.Tests.ps1` now invokes the actual passive `Invoke-WtFieldValidation.ps1` in both hosted Windows PS 5.1/7 CI jobs, checks nine allowlisted console lines, per-mode schema, ACL and forbidden native output files; only this test's own temporary report tree is removed in its `finally` block.
- Hosted CI field-runner integration does not establish real Windows 10/11 physical-hardware compatibility; #2 stays open pending actual workstations/privilege combinations.
- `ReportSecurity.Tests.ps1` attempts a test-owned junction, verifies reparse ancestors are rejected and conditionally skips only junction creation when the runner lacks permission. Ordinary case still verifies ACL/UNC/path collision.

## Read-only local report retention metadata checks (#3, 2026-10-31)

- `Get-WtReportRetention.ps1` is a separately requested, **read-only** inventory of *existing* report folders. It never creates, deletes or changes user report data, and does not start native security/integrity scans.
- `tests/ReportRetention.Tests.ps1` creates fabricated reports in a test-owned temporary folder. It confirms private-ACL-only file inspection, skipped unsafe ACLs, older/recent buckets, bounded directory/file counts, missing-root no-creation semantics and no private names/paths/content in stdout. The test deletes **only its own synthetic fixtures**.
- Windows PowerShell 5.1 and PowerShell 7 CI include the retention tests and static guard disallowing writes/mutations or raw JSON reads in the audit. It is not a security proof of live NTFS managed policies; #3 remains open for manual workstation inspection.

## Creation-time private DACL on both Windows runtimes (ADR-016)

- Run `tests/ReportSecurity.Tests.ps1` and the passive integration/field runner in both Windows PowerShell 5.1 and PowerShell 7 CI; verify the security-aware directory creation methods are present, restricted DACL and child inherited DACL, required SIDs with inheritable FullControl, collision preservation and no existing ACL changes.
- Cross-platform preflight rejects reintroduction of `New-Item` + `Set-Acl` for the per-run directory. Non-NTFS and managed policy failures remain fail-closed; do **not** silently fall back to a later Set-Acl.
- The previous empty-folder inherited ACL interval is avoided when the operating system honors creation-time security descriptors. Race conditions for concurrently swapped paths or an existing created run name still require separate threat-model review, and physical Windows 10/11 endpoints remain unverified.

## Folder ownership and managed-policy fail-closed tests (#3, 2026-10-31)

- `Assert-WtPrivateDirectoryAcl` now checks the live security descriptor's **owner SID**, not only its DACL. Only the invoking user, SYSTEM and BUILTIN Administrators are accepted as owners.
- `tests/ReportSecurity.Tests.ps1` adds in-memory synthetic descriptors with allowed user/admin owner, unexpected domain-style owner, missing SYSTEM grant, extra ACE principal, explicit deny and disabled DACL protection. These tests never change live system ownership.
- Both Windows PS 5.1 and PS 7 CI still validate a newly created private report directory, child-file inheritance, and read-only collector integrations. Domain/GPO environments with forced owners require **manual** validation and may fail closed; owner checking is not an effective-access proof or race-free path defense.

## Exclusive native report creation (ADR-018, 2026-10-31)

- Windows PS 5.1/7 smoke CI dynamically compiles the project-owned C# `CreateDirectoryW` wrapper and confirms that a matching-ACL existing folder *still* fails native creation rather than being reused.
- The report security suite races two independent **test-only** PowerShell workers to create the same private run folder and asserts exactly one success, one rejection, and a protected owner/DACL on the winner. It does not launch Defender, ClamAV, SFC/DISM, write user reports or contact networks.
- The previous creation-time DACL checks, privacy export, retention and full passive collector end-to-end tests remain mandatory.
- Win32 exclusive creation closes the same-run-name collision window but does **not** prevent a malicious process from swapping a writable ancestor after checks. The application does not claim race-free path binding or a fully verified Windows 10/11 managed workstation.

## Path handle lease (ADR-019, 2026-10-31)

- Both hosted Windows PowerShell 5.1 and PowerShell 7 CI run a test-owned private directory fixture. While the disposable lease is held, normal `.NET Directory.Move` attempts on the synthetic report and ancestor must fail; after disposal, moving the test-owned directory and restoring it must succeed. Reparse-point rejection and owner/DACL verification remain enabled.
- The real passive five-mode field-validation integration runs with the same lease and records only temporary synthetic/test-owned report paths; no system repair or native Defender, ClamAV, SFC or DISM scan.
- On physical Windows 10/11, also inspect managed filesystem policies, backup/sync agents, non-NTFS permissions, and behavior of root-to-run directory locks. If the lease cannot be established, **no diagnostic evidence should be written**. Not yet verified on physical unmanaged or enterprise-managed endpoints.
