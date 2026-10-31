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

## ADR-019 (2026-10-31): keep ancestor directory handles alive while writing reports

**Threat:** ADR-018 prevents a concurrent *same-name run* folder from being silently reused, but the caller still constructs file paths and writes files after directory creation. If another process can rename an ancestor or replace it with a junction between checks, path-based writes could be redirected.

**Decision:** Following exclusive private folder creation and ACL/owner verification, acquire a disposable `ReportPathLease` covering each existing directory from the local drive root down to the new run folder. The project-owned Windows-only C# helper calls `CreateFileW` on each component using `FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT`, requests only metadata access, *shares read/write but not delete*, and rejects any non-directory or reparse-point handle. It compares volume serial and file ID from `GetFileInformationByHandle` against newly opened paths, and keeps those handles until the collector ends (including error paths with `finally`). The main CLI validates the lease before each JSON/CSV/summary/manifest write and before invoking optional external scan output writers. It fails closed if handles or identities cannot be verified; no evidence is collected before acquiring the lease.

**Observed Windows runner limitation:** Even with `FILE_READ_ATTRIBUTES` and no `FILE_SHARE_DELETE`, the Windows CI runner permitted a rename of the open run directory. The original design assertion that an open directory handle blocks all such renames was **falsified by CI and withdrawn**. A parent directory's `DELETE_CHILD` rights or Windows rename semantics can permit movement despite a handle's sharing flags. The supported invariant is now **identity-change detection at a checkpoint** using volume serial/file ID and rejection of a changed or vanished path, not prevention of all renames. The test fixture attempts renaming the synthetic run and ancestor, and if the operating system permits either operation, asserts that `AssertStable` fails before restoring the original path. It also checks that handles are disposed and that a later rename works.

**Residual:** It is **not** a formal handle-relative write API: collectors still write via absolute paths, and even ordinary directory renames may remain possible while handles are held. An attacker may swap a path immediately **after a checkpoint and before a file open**; data could be redirected before the next checkpoint detects the change. Do not treat this as a complete security fix. On systems with unusual filesystem semantics or high-strength attackers, share-mode enforcement may not suffice. Obtaining each handle is not one atomic transaction; the implementation rejects reparse points and checks identities but cannot close all hostile races during acquisition. It does not protect against modification of file content by the authorized user/administrator, tampering with individual output file names, backup/sync capture or malware running in the same user context. File IDs vary by filesystem. Managed/non-NTFS compatibility and physical Windows 10/11 tests remain required. No existing report is changed or deleted.

**Microsoft references:** [CreateFile sharing and directory flags](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew), [GetFileInformationByHandle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileinformationbyhandle).

## ADR-020 (2026-10-31): core file creation relative to the held run-directory handle

**Prior issue:** ADR-019 file-ID checkpoints catch some path changes but did not bind `Out-File` or `Export-Csv` to the already verified run directory. A local adversary who swapped the path *after* a checkpoint and *before* the next file open could redirect sensitive evidence. The path lease also did not prevent all renames in hosted Windows tests.

**Decision:** Keep the protected, verified run-directory handle from ADR-019 and create **core diagnostic files** relative to that already-open Windows directory with the user-mode Windows `NtCreateFile` API and `OBJECT_ATTRIBUTES.RootDirectory`. The object name is a single allowlisted report filename only, `FILE_CREATE` fails if an entry already exists, and `FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT` requests a new normal file with no symlink-following fallback. The returned file handle is transferred to a `.NET FileStream/StreamWriter`, which writes the provided UTF-8 content (PowerShell 5.1 BOM vs PowerShell 7 no BOM) without reopening it by path. The protected parent ACL remains inherited, verified by the Windows synthetic tests. `AssertStable` remains useful as a preliminary detection checkpoint, but the relative creation binds a new core file to the held directory even when its original path is later renamed.

**Scope:** `WinTriage.ps1` now creates `system.json`, `processes.json`, events/summary/security/hardware/integrity JSON, two memory CSVs, `SUMMARY.md`, and `manifest.json` this way. It does not overwrite an existing report filename, allow a traversal or alternate stream name, upload data, delete prior reports or change native scan intent. Legacy report serialization and schema-v1 validation remain gated by both PowerShell editions' CI.

**Explicit residual and compatibility:** This is an incremental mitigation, **not** a complete security boundary for every output. Optional `RunClamAV` or `RunSfcVerifyOnly`/`RunDismScanHealth` still use independently injected native-tool runners that write `*.txt` via filesystem paths; do not describe them as handle-bound. The initial directory handle may be obtained after an adversary changed its ancestor, and admin/same-user modification, backup/sync, antivirus interaction and managed/non-NTFS compatibility remain outside the guarantee. `NtCreateFile` is documented as a user-mode native Windows API using a filesystem directory `RootDirectory`, but its precise flag/parent-access edge cases need Windows version and enterprise policy validation. **Fail closed if the native API refuses creation; never fall back to path-based writing.**

**Microsoft sources:** [NtCreateFile user-mode documented interface](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile), [OBJECT_ATTRIBUTES](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes).


## ADR-021 (2026-10-31): stream opted-in native tool output into pinned report files

**Threat:** ADR-020 secured core JSON/CSV/Markdown/manifest creation but did not bind the three optional text logs (`clamav-output.txt`, `sfc-verifyonly.txt`, `dism-scanhealth.txt`). Their previous `Out-File -LiteralPath` ran in the native executor after a path checkpoint, reopening the mutable absolute run directory.

**Decision:** Extend the existing allowlisted `NtCreateFile` + `OBJECT_ATTRIBUTES.RootDirectory` helper to return a disposable, exclusive new-file `.NET StreamWriter`. The main CLI passes a closure bound to its pinned run-directory lease into the opt-in scan and integrity executor. Before any executable is launched, the executor asks for this writer. Native stdout/stderr is piped line by line into the writer, not into a filename; it is flushed and disposed even on failure. If writer creation fails, the scan is not started (fail closed). The factory defaults to a throw for standalone executor calls; there is **no path fallback**. No implicit scan or repair is added. No log cleanup, overwrite, automatic upload or report deletion is added. Partial diagnostic output may remain after a tool failure and must not be interpreted as a clean result.

**Trade-offs:** Output is converted to strings line by line by PowerShell, not retained as raw native byte-for-byte output; source stderr/exit semantics require field review. Windows PowerShell 5.1 UTF-8 BOM and PowerShell 7 no-BOM are retained. Secure file creation is tied to an already-open directory, but earlier lease acquisition, same-user/admin modification, native tools' *own* operating-system logs, enterprise policy, and physical Windows 10/11 compatibility are outside the guarantee. The `OutputDirectory` argument remains for compatibility/validation but is **not used to open native tool logs**. A malicious local user with sufficient privileges can still modify the newly created files after opening. This is a mitigation, not an atomic security sandbox.


## ADR-022 (2026-10-31): fail early on sustained ancestor swaps during path-lease acquisition

**Threat and observation:** ADR-019 acquired root-to-run directory handles sequentially but rechecked the entire chain **only after** the last handle had opened. A concurrent process could rename or replace an ancestor during acquisition and cause subsequent descendants to be opened through a different path before the first identity check. The already handle-bound output writers from ADR-020/021 prevent reopening an ordinary file path later, but cannot prove the *original* run directory was pinned.

**Decision (incremental):** After **each** component is pinned with the existing `CreateFileW` + `FILE_FLAG_OPEN_REPARSE_POINT` metadata handle, immediately call the existing `AssertStable()` over the acquired prefix, before traversing another child. If a sustained rename/replacement has changed a pinned path, abort and dispose **all** handles. A new `AcquireForSyntheticTest(directory, afterPin)` hook is exclusively for deterministic test interleavings: after the synthetic parent is pinned but before a child is attempted, rename the test-owned parent and replace it with an empty decoy folder. If Windows permits this rename, assert failure before the test hook sees the run directory; restore the fixture and confirm the original protected ACL. If Windows denies the rename, verify normal acquisition and report the conditional skip. A separate thrown-hook fixture checks failure recovery. The production `Acquire` calls the same code with a **null** test hook; there is no new CLI flag and no new Windows native interop.

**Limits:** These additional checkpoints increase initial directory-open work (approximately quadratic with path depth) and can fail on unusually restrictive Windows policies; we do not silently fall back to path-only writes. An attacker able to change and restore a path *between* checks may still escape detection. The gap from `CreateDirectoryW` to acquiring the first report handle remains, as does non-atomic parent-to-child handle binding. The checkpoint also does **not** prove each child handle is an object-manager-relative child of the pinned parent; that would need a carefully reviewed native handle-relative traversal and creation API. A same-user/admin process can still tamper with files after creation. Do not describe this change as race-free.

**Verification:** Both Windows PowerShell 5.1 and PowerShell 7 CI run `tests/ReportPathAcquisition.Tests.ps1`, the established security fixtures, full passive five-mode integration and static safety preflight. Tests may remove **only disposable synthetic folders**. No existing report changes, native antivirus scan, SFC/DISM run, system repair or upload.


## ADR-023 (2026-10-31): test-only parent-relative directory traversal research

**Prior gap:** ADR-022 retries the identity lookup on every path prefix, but those lookups are still **absolute path names**, not open-from-pinned-parent operations. A parent can be swapped and restored between tests; no atomic parent→child provenance is established. Production modifications using undocumented native flag combinations are unacceptable without review.

**Public Windows documentation:** User-mode `NtCreateFile` explicitly accepts a `RootDirectory` handle and a relative `ObjectName`. `FILE_DIRECTORY_FILE` requests a directory. `FILE_OPEN_REPARSE_POINT` requests opening the reparse point rather than following it. However, the current published **user-mode directory-option compatibility list** does not clearly certify the exact `FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT` combination. `OBJECT_ATTRIBUTES` documents `OBJ_DONT_REPARSE`, while the user-mode `NtCreateFile` page's attribute description is narrower. These documents do not establish that concurrent junction conversion, renamed ancestors or all filesystem filters are protected against redirection. A forum or hosted runner observation cannot settle the support contract.

**Decision:** Do **not** modify `src/` or the production `ReportPathLease.Acquire` flow for this unqualified API combination. Add a test-only `tests/RelativeDirectoryProbe.cs` that uses `NtCreateFile` solely to `FILE_OPEN` one existing child directory, rooted in a separate pinned `CreateFileW` parent handle. The probe does not request any file create, modification or delete. Its synthetic PowerShell fixture compares the child volume/file ID before a swap, then (if Windows permits) renames **only a GUID-named test-owned parent**, creates an empty test-owned decoy with a different ID, and observes whether the relative lookup still identifies the original child or fails. Any success opening the decoy through the held parent fails the test. A known unsupported native option or blocked directory rename is recorded explicitly as SKIP, **not** proof of safety. Reject malformed leaf names in the research helper; release unmanaged memory and handles on all paths. Both PowerShell editions run it along with existing security tests. Production never imports the research C# file.

**Go/no-go before production code:** Require a documented and reviewed supported combination, a clear parent/root rights and no-reparse policy, direct handle-derived ACL/owner validation, a create-to-handle provenance plan, deterministic tests for rejection under swaps/junctions, and physical Windows 10/11 plus managed filesystem evidence. Do not promote relative directory probing, let alone directory creation, solely because a hosted Windows runner succeeds. Issues #2 and #3 stay OPEN.

**References:** [Microsoft NtCreateFile user-mode documentation](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile), [Microsoft OBJECT_ATTRIBUTES](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes), [Microsoft Reparse Points and File Operations](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points-and-file-operations).
