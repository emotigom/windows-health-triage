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
