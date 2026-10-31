# Meta design / 설계 판단 기록 (2026-10-31)

## Goal, boundaries
- Goal: on-demand Windows triage in local PowerShell, evidence-first and human-supervised.
- Out of scope: real-time antivirus, automatic arbitrary 'repair', driver installation, telemetry, machine learning root-cause certainty.
- No persistence, scheduled tasks, registry changes, service modification, network upload, or unconsented remediation.
- Optional Defender scan has **native Defender protection-side effects** (including quarantine); must be explicitly selected.

## System interfaces and trust boundaries
1. **Collection** (`WinTriage.ps1`): Windows OS/process/CIM/event/Defender APIs are fallible; failure of one collector should warn, not erase independent evidence. Native tool execution only with explicit user flags.
2. **Classification** (`src/WinTriage.Core.psm1`): pure functions classify *event metadata*, never infer confirmed root cause or run commands. Input contains untrusted event messages.
3. **Presentation** (`SUMMARY.md`, JSON/CSV): explain evidence quality, reporting window and per-log cap. Raw event messages may include private data and must not be uploaded automatically.
4. **Distribution** (`Publish-GitHub.ps1`): explicit opt-in, owner auth, private-by-default; no GitHub token in project files.

## Decision register / 메타설계
| Problem | Decision | Tradeoff |
| --- | --- | --- |
| A single broken system interface stops all work | Isolate system snapshot and optional collectors behind warnings; preserve partial report | Partial data must never be labeled 'healthy' |
| Process PID reuse or permission-denied process start time | Exclude uncertain instance identities from growth calculations | Some system processes intentionally omitted |
| Huge Windows event logs | Capture bounded recent errors/warnings and a separate set of Defender detection IDs irrespective of Level; deduplicate by Log+RecordId | Older events and high-volume bursts may still be missed |
| Hardware errors vs software errors | Heuristic categories with cautious language and sample counts | No automatic diagnosis or replacements |
| Malware vs treatment | Explicit optional native scanner only; no removal/quarantine by our code | Defender itself may quarantine according to policy |
| Repair | Guidance and official verify-only commands first; no automatic repair | Less 'one-click' convenience, higher operational safety |
| Compatibility | Windows PowerShell 5.1 baseline; PowerShell 7 CI additional | Cannot fully simulate Windows collectors on Linux |

## Acceptance gates
- All `.ps1` and `.psm1` pass PowerShell parser (Windows CI).
- Pure classifiers pass deterministic examples and edge cases (PID reuse, unknown identities, 1116/1118, SCM 7031, WHEA).
- Windows runner: read-only `Quick`, `Events` and `Monitor` create valid manifest/SUMMARY without an exception under normal CI conditions. Defender/ClamAV scanning not invoked in CI.
- No mutations unless a user selects Defender scan. No system repairs in this milestone.
- Results and warnings are retained when individual collectors fail.

## Known gaps
- A real Windows workstation test (including elevated/non-elevated PowerShell 5.1/7 and diverse hardware) remains required.
- ClamAV was not executed with a real signature database in this environment.
- Disk SMART interrogation and auto-remediation are intentionally not implemented.


## ADR-004 (2026-10-31): explicit allowlisted privacy export

**Problem:** Regex-based redaction of arbitrary event/antivirus messages is prone to omission. Public issues may accidentally expose host names, local paths, credentials, IPs and device IDs.

**Decision:** Keep original reports local. Add a separate, user-invoked `Export-WtShareSummary.ps1` with a *pure* transformation module. The module reconstructs an intentionally narrow schema from bounded enums and counts, never copying unknown strings or identifiers. Output uses create-new semantics and there is no network operation.

**Trade-off:** Some diagnostic context is lost; a public summary cannot replace a full local investigation. Group counts themselves can disclose symptoms; explicit review remains necessary.

**Validation:** Synthetic canary fixture tests run on PowerShell 5.1 and PowerShell 7. Unsupported categories and unexpected integrity states cannot flow into the output as arbitrary text. This isolates a first pure module boundary for issue #4; OS collectors remain in WinTriage.ps1 for later staged refactoring.


## ADR-005 (2026-10-31): process and OS collector seam

**Context:** Process and system metadata collection were embedded in the entrypoint and wrote to script-level warning objects, preventing reproducible Windows access-denied scenarios in tests.

**Decision:** Move `Get-WtProcesses` and `Get-WtSystemSnapshot` into `src/WinTriage.ProcessCollector.psm1`. Inject optional read-only scriptblock providers and a sample clock for tests, but use the same native Get-Process / Get-CimInstance calls in production. Make warnings and per-PID deduplication explicit inputs. Preserve the fields and public CLI schema; leave report serialization and separate event/security/storage collectors unchanged.

**Failure policy:** A process provider error yields zero samples and a warning; an individual malformed or protected process is skipped without discarding independent rows. OS and ComputerSystem CIM failures are independently recoverable; unknown values remain null or `unknown` rather than implying health. Never guess process identity when start time is missing. No synthetic fixtures are taken from real user machines.

**Validation gate:** Mocked process/CIM failure-injection tests plus existing PowerShell 5.1/7 smoke/privacy/integration checks must pass before merge. Next PR isolates event-log and storage collectors with analogous warning and cap semantics.


## ADR-006 (2026-10-31): event collection sampling boundaries

**Problem:** Defender information-level detection events are retrieved separately from errors/warnings. Previously both queries each used `MaxEventsPerLog`, so a Defender log could return twice the advertised per-log cap. Also, failed event-log access was coupled to the entrypoint's implicit warnings state, preventing deterministic testing.

**Decision:** Move the event collector to `src/WinTriage.EventCollector.psm1` with an injectable read-only event provider, explicit `Warnings` sink, fixed lookback and max caps. Each query may fetch up to the cap, but overlapping records are deduplicated by (log, RecordId), sorted newest-first, then bounded to a TOTAL per-log cap. Record sample metadata (observed distinct records, retained count, query failures, malformed record count, whether a query reached its limit, whether the combined cap truncated rows). Preserve `events.json`, `event-summary.json`, event field names and passive mode. Add an optional `EventSampling` manifest field; this is sampled data, never a full event count.

**Failure policy:** Empty logs are ordinary; access errors keep other logs' evidence and mark the affected log incomplete. Malformed event rows are skipped and counted; single malformed records do not discard independent records. Defender detection event IDs 1116/1117/1118/1119 are searched even if their level is informational. If query size equals the cap, mark sampling incomplete/possibly truncated without claiming the actual total count.

**Limitations:** A finite query cap may omit relevant older events. The newest retained events are chosen across query results; category coverage is not guaranteed. Do not interpret an empty sampled query or an inaccessible log as evidence of health.

**Validation:** Synthetic events test overlapping Defender record IDs, total per-log cap, lost permissions, zero matching records, malformed records, and chronological order. Run on Windows PowerShell 5.1 and PowerShell 7, followed by existing passive integration tests.

## ADR-007 (2026-10-31): hardware collector failure isolation

**Problem:** CIM disk enumeration, PhysicalDisk, per-device reliability counters, PnP and MemoryDiagnostics were coupled in the entrypoint to script-scoped warnings, preventing deterministic validation on hardware-independent CI.

**Decision:** Move `Get-WtHardware` into `src/WinTriage.HardwareCollector.psm1`, use injected read-only providers for each source and a caller-supplied warning sink. Keep `hardware.json` keys, original disk/counter fields, evidence categories and public flags unchanged. A counter failure on a single physical disk becomes a per-device `CounterError` plus a warning, without dropping other physical disks. Use the pure `Get-WtStorageAssessment` classifier; missing information remains `inconclusive` and NEVER a healthy verdict.

**Boundaries:** No physical disk identity matching to CIM records, no SMART-healthy assertion from incomplete counters, no repair/registry/driver/scan operations. MemoryDiagnostics is limited to 10 recent provider events (30 days); no matching events is not a diagnostic success. PnP failures do not discard disk readings. Original raw identifiers may appear in local `hardware.json`; explicit minimal sharing continues to aggregate categories only.

**Validation:** Synthetic fixtures test one disk's counter access denied amid other disks, CIM vs physical provider failure isolation, PnP failure, empty MemoryDiagnostics and unavailable commands, plus existing Windows 5.1/7 smoke/privacy/events/integration tests.

## ADR-008: raw report schema v1 (2026-10-31)

Add additive integer ReportSchemaVersion=1 to raw manifest.json, independently of the privacy-minimized export SchemaVersion. Test-only ReportContract.psm1 validates mode-specific files, mandatory JSON fields/arrays, conservative storage states, event sampling caps, integrity state vocabulary, and Monitor CSV headers. It accepts null/missing evidence VALUES, but never missing required FIELDS or false-healthy states. Breaking changes require a new raw schema major version. Synthetic fixture tests and CI-generated read-only reports both use the same checks; no native scanners are launched.

## ADR-009: passive Defender evidence boundary (2026-10-31)

Extract read-only Defender status and capped threat history into injected WinTriage.SecurityCollector.psm1. The main CLI retains explicit opt-in native scan invocation. State and history failures are isolated, recorded as warnings, and never interpreted as no threats. Preserve security.json keys and the local report boundary. Phase 2 of #10 will extract optional native scan execution behind a dedicated explicit runner after separate review.

## ADR-010 (2026-10-31): isolated opt-in integrity execution

The CLI delegates passive status and explicit SFC/DISM verification to `WinTriage.IntegrityCollector.psm1`; only the CLI owns user-facing flags and mode validation. The module uses injected privilege, command resolver and native-runner providers. No resolver or runner is called unless a flag is true and admin privileges are confirmed. The allowed arguments are fixed: SFC `/verifyonly` and DISM `/Online /Cleanup-Image /ScanHealth`. Missing privilege/provider/executable remains skipped or unavailable; unknown exit code or missing output is indeterminate, not healthy. Each tool's failure is isolated; produced local output files are explicitly registered with the manifest. This is diagnostic-only, not remediation. Native tools can take significant time; there is no unsafe implicit process termination/timeout in this stage. Only fake runners are exercised in CI.

## ADR-011 (2026-10-31): explicit native security scan boundary

The passive Defender collector remains read-only. Native Defender `Start-MpScan -ScanType QuickScan` and ClamAV `--recursive=yes --infected` run only through a separate `WinTriage.ScanExecutor.psm1` module with explicit opt-in CLI flags. Validate both requested scan inputs before launching either scanner; no scan command is resolved or invoked in passive mode. Keep existing `security.json` outcomes, including Defender's own quarantine policy caveat. An absent ClamAV log or unknown native exit is an error/unknown result rather than 'no-detection'. Failure to run either scanner does not suppress results of the other. Injection tests invoke only fictional executors, never native scanners or real malware. No automatic deletion, quarantine command, upload or system repair is introduced.

## ADR-012 (2026-10-31): protect raw report folder before collection

**Problem:** Full local reports include potentially private events, scan output, paths and account/process details. A user-supplied broad-ACL output directory could expose reports to unintended local accounts. Previous code simply inherited permissions, and Windows CI did not verify ACLs.

**Decision:** Every invocation creates a fresh per-run folder and applies a protected DACL to it before any OS data is collected. Explicit access is restricted to the current Windows user SID, LOCAL SYSTEM and BUILTIN Administrators, with inheritable child entries; independent verification fails closed if permissions cannot be applied or unexpected access principals remain. Existing older report folders are **never** modified or removed. Reject UNC/network paths and reuse/collisions. Incompatible filesystems that cannot enforce Windows ACLs cause an error rather than silently writing sensitive reports.

**Limitations:** This is not encryption or a defense from the account owner, local administrators, backup privileges or malware already running under that account. Files synced by OneDrive, third-party clients or corporate backup software may leave the PC even if stored on a local drive; users must choose a non-synchronized local output path. There is a short empty-directory creation-to-ACL window; no sensitive evidence is written in that window. Future hardening may use atomic creation ACLs where supported. Never delete old reports automatically.

**Validation:** Synthetic temporary-folder ACL tests plus Windows PS 5.1/7 passive integration must inspect the DACL before reading a report, not assume success from the exit code alone. Real workstation and managed endpoint ACL policy testing remains manual (#2, #3).

## ADR-013 (2026-10-31): privacy-minimized physical Windows field validation

Hosted GitHub Windows runners validate PS 5.1/7 and synthetic failure fixtures, but cannot certify actual Windows 10/11 hardware, endpoint policy, ACL inheritance or non-admin/elevated behavior. A separately invoked `Invoke-WtFieldValidation.ps1` runs the five existing passive diagnostics with low bounded sampling into local private folders. Every report must pass the established versioned report contract and per-run protected ACL. A pure `WinTriage.FieldValidation.psm1` reduces evidence to fixed `pass/review/fail`, scan-request, ACL and warning-presence labels; full raw warnings, host/user/device names, log contents and paths never enter the status output. Reports are retained locally, not deleted or uploaded; callers choose when to inspect and dispose them. No native scans, remediations or backups are run. Windows build/PowerShell/privilege metadata are bounded but may still reveal environment details; review status text before public sharing. Test with invented canaries only. IMPORTANT: a structural `pass` is never a conclusion of system health.

## ADR-014 (2026-10-31): enforce field-runner integration and reject report path indirection

**Gap:** The manual field-validation entrypoint was only syntax-checked in Windows CI. Its synthetic assessment module and the main read-only integration passed separately; no hosted test exercised the *composed* command, stdout privacy boundary and private report output together. Additionally, lexical `GetFullPath` and DriveType checks alone do not protect against NTFS reparse-point ancestors that resolve an output path through a junction or symbolic link.

**Decision:** Each Windows CI job now executes the full manually callable field runner in a freshly owned temporary test location and verifies exactly five passive reports, v1 schema, per-run ACL, no SFC/DISM/ClamAV output, and strictly allowlisted stdout. This is hosted-runner coverage only, not Windows 10/11 physical hardware certification. Report creation rejects existing reparse points in the output path ancestry, rechecking after parent creation and immediately after per-run creation, before setting ACLs or collecting evidence. This restriction intentionally rejects some symlinked/redirected profile configurations rather than accidentally writing sensitive reports to a different destination. Reports and their ancestors are never removed or rewritten by the field runner. The test harness cleans only its own explicitly created temporary reports.

**Residual limitations:** A malicious concurrent process with directory write access can race filesystem changes; this is not a fully atomic Windows handle-based creation/protection design. Administrators, user-owned sync services and backups remain outside the local ACL guarantee. Real managed Windows 10/11 PCs require manual testing.

## ADR-015 (2026-10-31): bounded report retention metadata review, never automated deletion

**Need:** Raw local diagnostic reports may accumulate and can contain sensitive event messages, account paths, process details and detection histories. Neither the CLI nor an automated cleanup process should assume it is safe to delete evidence. Users need a minimal, explicit view of age and disk impact.

**Decision:** New separately invoked `Get-WtReportRetention.ps1` audits a chosen, already existing local report root. It lists only immediate child directories matching the CLI run-id format; the pure-metadata module never opens raw reports, reads JSON, recurses into nested paths, follows reparse points, or echoes names/paths. Only folders with verified restricted ACLs contribute to file-count and size estimates. Other folders count toward `PermissionReview` without opening their contents. Enumeration is bounded per root and per run; any truncation, ambiguous age or access problem produces `Incomplete=True` and `Status=review`. The 'older than N days' tally uses directory creation-time metadata, which is not the same as confirmed original collection date. Review is not a deletion suggestion.

**Safety:** No delete, move, overwrite, ACL mutation, network upload, scheduled job, retention timer or automatic cleanup. Full reports remain unchanged. Metadata aggregates (counts, sizes and age) still reveal some system usage; inspect before sharing. CI uses synthetic test-owned temporary folders; only tests clean their own fixtures.

**Gate:** Both Windows PS 5.1/7 synthetic ACL and retention checks, privacy no-canary assertions, static read-only guard, schema and field-runner integration green. Real Windows 10/11 managed/redirected/synced folders remain unverified.

## ADR-016 (2026-10-31): apply report ACL at directory creation, across two PowerShell runtimes

**Former threat:** PR #17 used an ordinary inherited-ACL directory creation followed by `Set-Acl`; although it wrote no sensitive evidence until after ACL verification, there was a short **empty-folder** interval with inherited permissions. CI tests also confirmed the final ACL, but not creation-time protection.

**Change:** Construct a protected `DirectorySecurity` **before** creating the run folder, with inheritable FullControl for the current Windows user SID, LOCAL SYSTEM and BUILTIN Administrators. Windows PowerShell 5.1 uses .NET Framework `Directory.CreateDirectory(path, security)`; PowerShell 7 uses the .NET Windows ACL extension `FileSystemAclExtensions.CreateDirectory(security, path)`. No insecure two-stage fallback is permitted if either runtime lacks the method or filesystem refuses the descriptor. Recheck both reparse-point ancestry and the *actual* resulting ACL before collecting any evidence. Strengthen verification to require appropriate inheritable full-control rules, not merely allowlisted principals. The security descriptor is applied during directory creation, rather than after the new folder becomes visible.

**Compatibility and limits:** These APIs may return an already existing folder without applying the supplied descriptor. Reject preexisting names, verify actual ACL and refuse collection if any mismatch; this is **not** an atomic create-new collision guarantee against a malicious concurrent local writer. A malicious process with rights to writable ancestors can still race junction or path swaps between checks. Strict company GPO/ACL policies, redirected profiles and non-NTFS storage may legitimately fail closed. This is *not encryption*, and SYSTEM, administrators, backup agents and cloud sync can still access the report. No existing reports are changed or removed.

**References:** [Microsoft Directory.CreateDirectory security overload](https://learn.microsoft.com/en-us/dotnet/api/system.io.directory.createdirectory) and [.NET FileSystemAclExtensions.CreateDirectory](https://learn.microsoft.com/en-us/dotnet/api/system.io.filesystemaclextensions.createdirectory).

## ADR-017 (2026-10-31): report owner is part of the private-data trust boundary

**Issue:** Restricting a directory's discretionary access-control list (DACL) does not fully restrict its owner. On Windows, an owner may generally be able to alter a DACL even when the owner is not explicitly listed with FullControl. ADR-016 ensured that the *creation-time* DACL has three allowed SID principals, but verification did not check the resulting descriptor's owner. A managed endpoint, external policy or unexpected filesystem state could produce an unexpected owner with authority to change ACLs.

**Decision:** Extract a purely descriptive `Assert-WtPrivateSecurityDescriptor` validator from the live `Assert-WtPrivateDirectoryAcl` wrapper. Verify the owner as a SID and reject any owner other than the current Windows account, LOCAL SYSTEM (`S-1-5-18`) or BUILTIN Administrators (`S-1-5-32-544`). Continue to reject inherited DACLs, unexpected ACE principals and deny ACEs, and require inheritable FullControl for the intended SIDs. Any mismatch stops collection *before evidence is written* and leaves existing folders untouched. The same validator is used by the metadata-only retention auditor to skip untrusted reports.

**Tests:** Synthetic `DirectorySecurity` descriptors exercise ordinary user ownership, administrator group ownership, unapproved owner, missing SYSTEM ACE, unexpected extra principal, explicit deny, and unprotected DACL, with no Windows account changes. The usual live Windows PS 5.1/7 reporter ACL and passive five-mode integrations remain the merge gates.

**Limits:** This guard is not a proof of effective access, privilege policy, directory parent integrity or race freedom. Administrators and processes holding applicable Windows privileges can bypass some DACL restrictions. Some managed machines may assign a legitimate but different owner; stop and review policy instead of weakening the allowlist automatically. No encryption, automatic repair, backup, deletion or upload is added.

## ADR-018 (2026-10-31): exclusive report-run creation without directory reuse

**Problem:** Creation-time .NET APIs from ADR-016 (`Directory.CreateDirectory` and `FileSystemAclExtensions.CreateDirectory`) return an existing directory without replacing its security descriptor. A competing local process could create the *same* run path between the preflight `Test-Path` and the .NET create operation. A protected DACL on the preexisting folder was not sufficient evidence that this invocation exclusively created it; the writer must never append to a different process's report.

**Decision:** A small project-owned C# Win32 interop wrapper (`src/WinTriage.NativeReportDirectory.cs`, compiled locally through PowerShell `Add-Type`) calls Windows `CreateDirectoryW` with the protected `DirectorySecurity` binary descriptor supplied through `SECURITY_ATTRIBUTES`. Windows reports `ERROR_ALREADY_EXISTS` (183) if creation loses a concurrent collision, even if the existing folder has an identical protected ACL. The code fails immediately, never treats an existing folder as its own, and never uses a fall-back create-or-open or separate `Set-Acl`. The security descriptor is supplied *with* creation, not attached afterwards. Unmanaged descriptor memory is released in a `finally` block. Error messages are fixed or numeric only; no raw host, user, log, path or ACL data.

**Tests:** Private matching-ACL collision is rejected directly at the native boundary. Two concurrently started test-only PowerShell processes race to create the same synthetic run: exactly one must succeed, the other must fail, and the final folder must pass ACL/owner verification. Existing report contents and permissions stay unchanged. CI runs on both Windows PowerShell 5.1 and PowerShell 7.

**Residual:** This resolves **same-name create-or-open collision**, not all parent-directory races. A concurrently replaced/mutated ancestor path can still defeat path-based pre/post checks; a future handle-relative implementation would be needed for a stronger attacker model. New report files are still created by path after validation. This is not an atomic transaction, encryption, or proof against an administrator. Managed endpoint compatibility still requires physical Windows 10/11 testing.

**Reference:** [Microsoft Win32 CreateDirectory and ERROR_ALREADY_EXISTS](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createdirectory) and [SECURITY_ATTRIBUTES](https://learn.microsoft.com/en-us/windows/win32/api/wtypesbase/ns-wtypesbase-security_attributes).
