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
