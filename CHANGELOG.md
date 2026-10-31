## Unreleased — 2026-10-31
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
