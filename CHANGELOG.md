## Unreleased — 2026-11-01
- Separate ordinary one-off process churn from malformed singleton/missing-key Monitor samples using private aggregate-only counters, conservative field review and dual-Windows invented regressions (ADR-046, PR #51). Release NO-GO.
- Keep Monitor status REVIEW for any rejected comparison candidate group or unreliable identity sample despite another valid growth row; add one private aggregate count, legacy/corrupt guard and synthetic dual-Windows regressions (ADR-045 / PR #50). NO-GO unchanged.
- Refuse unreliable, mismatched or time-inverted Monitor growth groups (UTC/PID/start invariants) with invented dual-Windows regression and ADR-044; privacy, release NO-GO unchanged (PR #49).
- Prevent false structural Monitor PASS for silent empty, short or non-comparable samples with private aggregate manifest counts; legacy reports return REVIEW, malformed counts fail; synthetic PS 5.1/7 regression and ADR-043 (PR #48). Still NO-GO.
- Invented Monitor second-provider-failure assertions and test-only conditional junction/root-decoy EXECUTED/SKIPPED CI labels (ADR-042). Current 15-case scopes: 10 direct synthetic, 2 related, 3 manual. No production changes; NO-GO.
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

- PR #52 / ADR-047 (2026-11-01): local Monitor report contract cross-checks private JSON, CSV and quality counters with synthetic tampering tests. Release NO-GO.

- PR #53 / ADR-048 (2026-11-01): additive private Monitor per-attempt row-count ledger; cross-check ordered JSON batches and conservative legacy/empty-attempt status, with synthetic PS 5.1/7 regression tests. Release NO-GO.

- PR #54 / ADR-049 (2026-11-01): validate Monitor sample timestamps against canonical UTC report start/end; add synthetic temporal counterexamples and explicit internally consistent rewrite limitations. No release approval; NO-GO.

- PR #55 / ADR-050 (2026-11-01): fixed-origin unverified / NO-GO release status on field assessments, privacy-safe fixed operator disclaimers, coherent-forgery and fake-approval synthetic regressions; release remains blocked.

- PR #56 / ADR-051 (2026-11-01): the offline two-sheet reviewer handoff now marks sheet pairing and reviewer independence unauthenticated; invalid field or anchor metadata zeroes all claimed-complete cells. Synthetic privacy/negative tests; physical verification and independent approval still required, release NO-GO.

- PR #57 / ADR-052 (2026-11-01): offline handoff explicitly marks evidence freshness unverified and replay detection unavailable; add backdated/copied/reused sheet and forged-time negative tests without changing sensitive schemas or NO-GO gate.
- PR #58 / ADR-053 (2026-11-01): NO-GO handoff now suppresses all complete-looking field claims if anchor evidence is expired, unsafe or self-certified; discloses unauthenticated retention and unverified external approval revocation, with synthetic privacy/lifecycle tests. No automatic deletion, schema, collector or scan change; physical review still blocks release.

- PR #59 / ADR-054 (2026-11-01): offline field handoff suppresses misleading positive claim counts for explicit field validation, ACL, native scan or manual security review failure; new fixed-only safety-claim classification and four always-open release blocker labels linked to #2/#3, with synthetic Windows regression tests. NO-GO unchanged.
- PR #60 / ADR-055 (2026-11-01): both physical Windows field checklists now enumerate eight real OS/shell/privilege combinations with five passive modes and schema/ACL/no-scan requirements; synthetic CI mutation tests guard against lost cells, weakened privacy/root duties and four release blocker issue mappings. Real field verification and independent approval still required; NO-GO.

- PR #61 / ADR-056 (2026-11-01): privacy-minimized offline handoff enumerates fixed OS/PowerShell/privilege cell labels not accepted as complete claims; invalid/unsafe status sheets or reported safety failures withhold all eight. Fixed SELF_DECLARED_ONLY warning and synthetic missing/review/forgery/no-echo regressions; release NO-GO, real hardware and independent approvals pending.

- PR #62 / ADR-057 (2026-11-01): fixed-order allowlisted offline field-review output with internal schema/complement checks and privacy-safe INVALID_METADATA fallback; exact-line and synthetic canary regressions in both Windows CI shells. NO-GO, external release blockers and physical review requirements unchanged.
- PR #63 / ADR-058 (2026-11-01): offline field handoff now validates both sub-reviewers' NO_GO decisions, bounded fixed reason lists and schema shapes; upstream exceptions and malformed summaries use an evaluator-independent INVALID_METADATA/0-of-8 fallback, with synthetic private-canary regressions. Physical verification and external approval still missing; NO-GO.

- PR #64 / ADR-059 (2026-11-01): the manual field runner checks fixed native scan log artifacts after private ACL verification, while the pure assessor rejects native log entries in any passive-mode manifest; both unlisted and listed synthetic artifacts force fixed unexpected/fail status. No native scans, log content reads, upload or automatic cleanup. Physical Windows 10/11 and independent security/privacy approval pending; NO-GO.

- PR #65 / ADR-060 (2026-11-01): Quick/Events field status now checks existing per-log provider query attempts, aggregate counter and cap consistency; missing or unattempted coverage remains review, malformed totals fail, legitimate zero-event queries still structural-only pass. Synthetic 5.1/7 regressions, no new event collection or privacy exposure, release NO-GO.
