# Privacy-safe field failure classification and synthetic reproduction — ADR-040/041/042 / PRs #45–47

**Goal:** Make a repeatable, safe path from a *locally observed* Windows 10/11 issue to a **completely invented synthetic regression**, without copying a workstation's raw logs or implying real-device validation. This is an optional development aid for issues #2 and #3; it is **not** a diagnostic collector or evidence-authentication mechanism.

## Three separate boundaries

1. **Authorized physical observation (private):** On your approved Windows 10/11 device, follow `docs/FIELD-VALIDATION.md` and `docs/FIELD-REVIEW-HANDOFF.md`. Observe only the fixed validation statuses. Keep original reports, Event Viewer messages, user/device IDs, process names and commands, full paths and screenshots on the approved workstation; do not paste them into public GitHub, CI, chat transcripts or issue comments. Do not intentionally disable Defender, break event-log access or weaken permissions to make a failure happen.
2. **Local classification (fixed enum, no input reports):** Select **one** closest symptom from the list below. The optional `tools/field_failure_triage.py` accepts only `--category` with the exact approved code. It does **not** take a report pathname, JSON content, error text, command line, hardware ID, user name, timestamp, run ID or a URL. It does not read any input files, execute a test, change ACL, delete data, or upload.
3. **Invented reproduction and independent review:** The output points to a pre-existing `tests/` **synthetic reference**, never asserts the real failure has been reproduced. When approved for development, create a **new synthetic fixture** with invented names, events, data and no copied real identifiers. Use the relevant repo test in a trusted checkout under test-owned disposable paths, check both Windows shells in CI and review the change before making a public issue or PR. If no safe existing fixture matches, keep `PRIVATE_MANUAL_REVIEW_ONLY`; do **not** generalize raw private data into public pseudo-samples.

## Fixed symptom index

| Safe symptom code | Existing synthetic reference or boundary |
| --- | --- |
| `schema_contract_failure` | `tests/ReportContract.Tests.ps1` |
| `event_provider_denied` | `tests/EventCollector.Tests.ps1` |
| `defender_provider_unavailable` | `tests/SecurityCollector.Tests.ps1` |
| `storage_provider_unavailable` | `tests/HardwareCollector.Tests.ps1` |
| `monitor_sampling_inconclusive` | `tests/MonitorSampling.Tests.ps1` |
| `passive_native_scan_unexpected` | `tests/FieldValidation.Tests.ps1` |
| `report_directory_acl_failed` | `tests/ReportSecurity.Tests.ps1` |
| `report_path_reparse_detected` | `tests/AnchorRace.Tests.ps1` |
| `initial_root_identity_mismatch` | `tests/AnchorBoundFieldFileSession.Tests.ps1` |
| `status_snapshot_acl_review` | `tests/FieldStatusAclResearch.Tests.ps1` |
| `status_metadata_invalid` | `tests/FieldEvidenceGate.Tests.py` |
| `privacy_export_unexpected_field` | `tests/Privacy.Tests.ps1` |
| `cloud_sync_or_backup_unknown` | **No safe automated reproduction; private policy review** |
| `external_root_authority_absent` | **No automatic trust assertion; private independent approval** |
| `unclassified_incomplete` | **Manual privacy/security triage required** |

## ADR-041: audit of actual synthetic assertion scope (PR #46)

The optional CLI now reports a fixed `Coverage:` token. `DIRECT_SYNTHETIC_ASSERTION` means a **fabricated condition** has a corresponding test assertion; `RELATED_SYNTHETIC_ONLY` means the linked test exercises only adjacent or conditional research; `MANUAL_ONLY` means no automated evidence is appropriate. None proves a physical failure was reproduced or that all conditional test branches executed.

| Category | Coverage classification | Actual assertion scope and caveat |
| --- | --- | --- |
| `schema_contract_failure` | `DIRECT_SYNTHETIC_ASSERTION` | Synthetic invalid schema rejects via contract assertion; not real report compatibility |
| `event_provider_denied` | `DIRECT_SYNTHETIC_ASSERTION` | Injected Application access denial sets incomplete status and warning |
| `defender_provider_unavailable` | `DIRECT_SYNTHETIC_ASSERTION` | Mock absent Defender status command yields unknown/warning |
| `storage_provider_unavailable` | `DIRECT_SYNTHETIC_ASSERTION` | Injected CIM failure does not fabricate disk results |
| `monitor_sampling_inconclusive` | `DIRECT_SYNTHETIC_ASSERTION` | Invented second provider denial: growth remains absent, warnings retained, assessment is review. No complete Monitor-run or live provider validation |
| `passive_native_scan_unexpected` | `DIRECT_SYNTHETIC_ASSERTION` | Injected active-scan state fails assessor; no real scanner launched |
| `report_directory_acl_failed` | `DIRECT_SYNTHETIC_ASSERTION` | Synthetic protected DACL/owner negative assertions, not managed workstation ACL |
| `report_path_reparse_detected` | `RELATED_SYNTHETIC_ONLY` | Test-only anchor junction path, potentially SKIP; not production report path |
| `initial_root_identity_mismatch` | `RELATED_SYNTHETIC_ONLY` | Synthetic decoy mismatch requires rename, potentially SKIP; source unauthenticated |
| `status_snapshot_acl_review` | `DIRECT_SYNTHETIC_ASSERTION` | Synthetic status file restricted/review ACL assertions |
| `status_metadata_invalid` | `DIRECT_SYNTHETIC_ASSERTION` | Malformed/duplicate JSON rejected by strict metadata gate |
| `privacy_export_unexpected_field` | `DIRECT_SYNTHETIC_ASSERTION` | Invented forbidden report field and secret canaries rejected |
| `cloud_sync_or_backup_unknown` | `MANUAL_ONLY` | Cloud/backup configuration requires authorized manual policy inspection |
| `external_root_authority_absent` | `MANUAL_ONLY` | Authenticated external origin and approval not implemented |
| `unclassified_incomplete` | `MANUAL_ONLY` | Requires private manual assessment before inventing safe regression |

The Python audit regression uses a separate, fixed set of synthetic setup/assertion witnesses for all 12 referenced cases. This catches textual drift more strongly than file existence, but **string matching does not prove semantic correctness or runtime execution**. Existing CI executes the underlying suites on hosted Windows PowerShell 5.1 and PowerShell 7; junction/rename branches may emit `SKIP` and still allow the suite to pass. `AnchorRace.Tests.ps1` is test-only and not an operational report reparse regression; `AnchorBoundFieldFileSession.Tests.ps1` does not authenticate the initial root. At the time of ADR-041 the Monitor fixture only confirmed schema acceptance; ADR-042 below adds an injected-provider test. Avoid claiming these three related categories were directly reproduced. An invented active scan state is not an actual scanner invocation.

## ADR-042: injected Monitor sample failure and conditional research SKIP markers (PR #47)

New `tests/MonitorSampling.Tests.ps1` injects a wholly invented successful first process sample followed by a simulated provider refusal on the second call. Assertions verify no fabricated growth, a warning, and `Get-WtFieldValidationAssessment -Mode Monitor` returning `review` / fixed `Warnings: present`, without leaking the fabricated private warning. A two-sample invented control checks the growth function. **This is a component-level injected failure, not an end-to-end Monitor command or a guarantee about silent empty-but-successful reads, scheduling, permissions or real physical workstations.**

Research-only anchor junction and root decoy tests now emit fixed `COVERAGE: ...=EXECUTED_SYNTHETIC` or `...=SKIPPED_HOST_CONSTRAINT`. GitHub Actions gets a fixed notice when executed and a warning when skipped; either outcome can coexist with a green suite. No warning is derived from a device path, username, report or private exception. A conditional pass does not authenticate trusted root origin or production report paths.

The updated 15-case mapping is **10 direct synthetic assertions, 2 related/conditional, 3 manual-only**. ADR-041's historical 9/3/3 classification remains a correct description of the earlier revision. Field-failure triage still accepts only fixed tokens, accesses no raw data, never runs an actual test or scan, and always returns NO_GO / UNVERIFIED / REVIEW_REQUIRED and exit 2.

For unknown/invalid arguments the response remains fixed `Coverage: MANUAL_ONLY` without echo. The original 15 accepted tokens and private observation protocol do not change; no raw data, paths, executable test references or dynamic device evidence are read or run. Every result retains `Decision: NO_GO`, `PhysicalEvidence: UNVERIFIED`, `PublicDisclosure: REVIEW_REQUIRED` and exit 2. Physical Windows 10/11 and independent security/privacy approval are separate, still outstanding.

If the symptom is ambiguous, use `unclassified_incomplete`; never choose a more positive category for convenience. Some synthetic references exercise only a *related branch* of code, not the exact field condition: a mapping is a starting point for writing a new fully invented regression, not proof of identical runtime behavior.

## Offline example

```powershell
# Only a fixed enum; no real reports or private paths in the arguments.
python tools/field_failure_triage.py --category event_provider_denied
```

Outputs only static labels:

```text
Decision: NO_GO
Classification: CATEGORY_ONLY
Review: PROVIDER_ACCESS
SyntheticFixture: tests/EventCollector.Tests.ps1
NextStep: SYNTHETIC_REFERENCE_ONLY
Coverage: DIRECT_SYNTHETIC_ASSERTION
PhysicalEvidence: UNVERIFIED
PublicDisclosure: REVIEW_REQUIRED
```

Exit code is **always 2**: it is neither a passing test result nor a release approval. `PhysicalEvidence: UNVERIFIED` is deliberate even when a human claims the category was observed; the CLI does not authenticate the observation. Unsupported categories (including raw private error messages) are rejected without echoing input. The tool does not initiate a background job or automatically run the named test.

## Public issue/PR disclosure template (invented reproductions only)

The independent reviewer must first decide whether even the fixed label is appropriate to disclose. A safe, manually authored public update can contain: the approved `category` token, the pre-existing `tests/` synthetic reference, the expected behavior of newly invented objects, actual results of **synthetic** CI, and the remaining unknowns. Avoid OS-specific precise versions, software inventories, timestamps, employee identities, screenshots, real logs, local file paths, hash/file IDs, SIDs or private error messages unless a separate disclosure process explicitly authorizes them.

No automated posting, issue creation, or report export is provided. Do not infer real device compatibility from hosted CI, or treat an invented test that passes as closure of issues #2/#3. Continue the separate approval and revocation model in `docs/ANCHOR-TRUST-PROTOCOL.md`. **Release remains NO-GO.**
