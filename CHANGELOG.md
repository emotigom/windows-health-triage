## Unreleased — 2026-11-01
- Audit 15 field-failure fixture references for assertion-level scope (9 direct synthetic, 3 related/conditional, 3 manual-only), fixed Coverage labels and regression witnesses (ADR-041). No production code change, still NO-GO.
- Add fixed-category privacy-safe field-failure to existing invented synthetic test reference index and operator/private-review protocol (ADR-040); no raw log ingestion, automatic execution or production changes, always NO-GO.
- Add privacy-bounded physical Windows field-review handoff checklist and two-sheet offline NO-GO-only claim count readout; synthetic counterfeits and no-echo tests on both Windows shells (ADR-039). No production code changes.
- Add independent initial-root authority and privacy/release reviewer protocol (ADR-038) with optional fixed-enum NO-GO-only claim reviewer and synthetic counterfeit-approval/decoy tests in both Windows CI jobs. No production changes.
- Research only: externally held synthetic reference guards held-parent status file create, with before/after identity checks and explicit forged-decoy self-certification negative control (ADR-037). Production unchanged; NO-GO.
- Research only: held-parent NtCreateFile FILE_CREATE synthetic status file with create-time private DACL and returned-handle ACL, plus parent-decoy/junction negatives in both Windows CI shells (ADR-036). No production changes; NO-GO.
- Research only: Win32 CREATE_NEW of invented field status file with protected creation-time DACL; dual-shell synthetic tests for allowlist, no-overwrite and weak descriptors (ADR-035). Production recorder remains unchanged; release NO-GO.
- Add optional read-only field-status file ACL/path observer, unknown-by-design cloud sync status and synthetic Windows owner/DACL/junction negative tests (ADR-034); NO-GO and production collectors unchanged.
- Fail closed on duplicate/nonfinite JSON and substituted/nonregular field metadata inputs through a shared bounded reader in gate and recorder (ADR-033); privacy-safe CLI errors, synthetic regressions, NO-GO unchanged.
- Add optional offline field-status-only recorder with non-overwriting snapshots, strict fail-safe labels, synthetic leak tests and NO-GO preservation (ADR-032); no raw report access or hardware certification.
- Introduced an offline, NO-GO-only Windows 10/11 field evidence matrix checker with invented-data negative regression tests and pending-only template (ADR-031). No production changes or hardware certification.
- Research session-scoped held-reference anchor trust contracts, self-certifying decoy negative controls, and stale/revoked baseline refusal (ADR-030); no production code changes.
- Test-only 128-bit file ID / volume serial and optional volume-GUID alias research with same-volume decoy rejection (ADR-029). Production src/ unchanged.

## Unreleased — 2026-10-31
- Research strict local fixed-drive path grammar and read-only root-to-disposable-fixture handle lineage/junction rejection (ADR-028), without production changes.
- Add synthetic-only independent anchor file-ID check and deterministic pre-open junction swap regression research (ADR-027); production source and user reports unchanged.
- Research test-only pinned-anchor multi-hop handle-relative directory traversal with synthetic decoy/junction, private run creation and handle ACL checks (ADR-026). Production modules unchanged.
- Add test-only NtCreateFile exclusive parent-relative private directory creation with immediate returned-handle ACL/owner and synthetic rename/decoy verification (ADR-025); production src/ unchanged.
- Research test-only pinned-directory owner/DACL reading with READ_CONTROL and GetKernelObjectSecurity, including synthetic weak decoy and missing-rights tests on Windows PowerShell 5.1/7 (ADR-024); production code unchanged.
- Add test-only NtCreateFile RootDirectory relative directory-open research probe with synthetic pinned-parent / unpinned-ancestor rename and decoy file-ID observations; no production native API behavior changed (ADR-023).
- Check pinned report ancestor file identities after each acquisition hop; add deterministic synthetic swap/decoy and error recovery fixtures on Windows PowerShell 5.1/7 (ADR-022). This is earlier detection, not atomic path isolation.
- Stream opt-in ClamAV and verification-only SFC/DISM stdout/stderr to exclusive, handle-bound report text writers; refuse native execution if safe log acquisition fails, with synthetic sink tests. No native scans are run by CI.
- Create core JSON, CSV, SUMMARY and manifest files relative to the pinned report-directory handle with native exclusive FILE_CREATE and allowlisted names; preserve UTF-8 serialization, legacy schema and synthetic privacy/ACL tests. Optional native scanner text outputs remain path-based.
- Add a Win32 metadata-only ancestor-directory identity lease and fail-closed file-ID checkpoints during report writing; synthetic rename-detection/disposal tests on PS 5.1/7. Windows CI showed that omitting delete sharing does NOT reliably prevent renames; check-to-write races remain.
- Reject concurrent report name collisions using native Win32 CreateDirectoryW with creation-time protected ACL; add two-worker synthetic race tests on PS 5.1/7 and document remaining parent-path swap risk.
- Verify new report directory owner SID as part of private ACL gate; fail closed for unexpected managed-policy ownership and cover synthetic access-descriptor edge cases on PS 5.1/7.
- Apply restricted report ACL atomically at new-directory creation for Windows PS 5.1 and PS 7, verify required inheritable FullControl SIDs, reject insecure fallback; retain residual path-race limitation.
- Add explicit, metadata-only local report retention audit (age/size/ACL counts), bounded scan and synthetic privacy fixtures; no deletion, schedule, uploading or raw report reads.
- Exercise complete passive field-validation entrypoint in Windows PS 5.1/7 CI with allowlisted stdout and five ACL-protected reports; reject report path symlink/junction ancestors.
- Add separately invoked passive Windows workstation field-validation matrix with privacy-minimized fixed statuses, local-only report retention and synthetic no-leak/failed-ACL/active-scan fixtures for both PS runtimes.
- Restrict new raw-report run folders to current user, SYSTEM and Administrators before collecting evidence; fail closed on ACL errors, no auto cleanup or old-report changes; add Windows 5.1/7 ACL regression tests.
- Separate opt-in Defender/ClamAV native scans from passive security collector, retain fixed detection-only flags, and add fake-executor safety tests for PS 5.1/7.
- Extract privilege-aware passive integrity and explicit verify-only SFC/DISM runner into injected module; add synthetic failure tests and keep old JSON fields.
- Extract passive Defender status/history into an injected security collector; preserve explicit opt-in native scanners in CLI and add PS 5.1/7 failure tests.
- Add raw manifest report schema v1 marker and synthetic/live JSON and Monitor CSV contracts on PS 5.1/7, independent of privacy export.
- Fix static safety preflight drift after PR #8 and run Python preflight in both Windows CI jobs before other tests.
- Record the deliberately red pre-fix CI run and new hardware collector ownership guard.
- Extracted read-only disk/CIM/reliability/PnP/MemoryDiagnostics collector into an independently testable hardware module.
- Preserved hardware.json schema; added synthetic tests for independent provider failures and incomplete signals.
- Kept per-disk reliability errors from suppressing other drive assessments, and ensured unknown never means healthy.

- Extracted WinEvent collection into an injectable, read-only event module with independent log failure handling.
- Enforced a combined per-log sample cap after deduplicating overlapping Defender error and detection queries.
- Added EventSampling metadata to manifest for incomplete/bounded queries, retained sampled counts and decoding failures.
- Added synthetic Windows PS 5.1/7 regression tests for capped logs, Defender detection sampling, denied access and malformed events.

- Extracted process snapshots and OS/CIM information into an injected, read-only collector module.
- Removed implicit script-scoped process warning dependencies; preserved CLI and report fields.
- Added deterministic tests for protected/invalid process records, provider failures, unknown start times and PID reuse.
- Independently recovered OS and RAM provider failures with explicit missing-value reporting.

- Added explicit, local-only allowlisted minimal JSON sharing export, with no automatic network transfer.
- Excluded raw event messages, host/user/path details, device identifiers, process data and free-form strings by construction.
- Added synthetic adversarial fixtures and PowerShell 5.1/7 CI tests for privacy and no-overwrite behavior.
- Documented data minimization and trust boundaries in docs/PRIVACY.md.

# Changelog

## v0.3.0 — 2026-10-31 (unverified on Windows)
- Added optional Storage reliability counter collection through Windows Storage cmdlets, handling unsupported providers without claiming health.
- Added pure storage signal classifier with no inferred healthy outcome; uncorrected I/O errors and warning/degraded statuses require review.
- Added passive `Integrity` mode and explicitly requested `-RunSfcVerifyOnly` / `-RunDismScanHealth` verification, never repair.
- Requires administrator privileges for native integrity checks, otherwise skips with a warning.
- Fixed `Monitor` top process snapshot to select only the most recent sampling time.
- Expanded deterministic classifier tests and Windows read-only integration modes. Added `Validate-Windows.ps1` and cross-platform preflight.
- Updated meta-design, validation, roadmap, and user-facing warnings.


## 0.2.0 — 2026-10-31 (candidate; not Windows-validated)
- Added engineering metadesign and acceptance gates.
- Resilient OS/RAM collection when CIM fails; preserve partial reports with warnings.
- Excluded unknown process start times from growth estimates, avoiding PID reuse false positives.
- Added non-invasive triage advice per event category.
- Added repeated event grouping by provider + ID with first/last timestamps.
- Added informative Defender detection/action event queries and duplicate suppression.
- Extended event classifier for service failures, Windows Defender, GPU reset and Windows error reporting.
- Added CSV header-only output when there are no process records.
- Added deterministic classifier tests and read-only Windows integration tests; manual CI tests both PowerShell 5.1 and 7.
- Prevented accidental upload through an incorrect `gh` active GitHub account.
- Added links to Microsoft non-repair system integrity verification commands.

## 0.1.0 — 2026-10-31
- Initial on-demand diagnostic collector, local reports, explicit Defender/ClamAV integration.
