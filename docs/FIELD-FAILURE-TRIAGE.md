# Privacy-safe field failure classification and synthetic reproduction — ADR-040 / PR #45

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
| `monitor_sampling_inconclusive` | `tests/FieldValidation.Tests.ps1` |
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
PhysicalEvidence: UNVERIFIED
PublicDisclosure: REVIEW_REQUIRED
```

Exit code is **always 2**: it is neither a passing test result nor a release approval. `PhysicalEvidence: UNVERIFIED` is deliberate even when a human claims the category was observed; the CLI does not authenticate the observation. Unsupported categories (including raw private error messages) are rejected without echoing input. The tool does not initiate a background job or automatically run the named test.

## Public issue/PR disclosure template (invented reproductions only)

The independent reviewer must first decide whether even the fixed label is appropriate to disclose. A safe, manually authored public update can contain: the approved `category` token, the pre-existing `tests/` synthetic reference, the expected behavior of newly invented objects, actual results of **synthetic** CI, and the remaining unknowns. Avoid OS-specific precise versions, software inventories, timestamps, employee identities, screenshots, real logs, local file paths, hash/file IDs, SIDs or private error messages unless a separate disclosure process explicitly authorizes them.

No automated posting, issue creation, or report export is provided. Do not infer real device compatibility from hosted CI, or treat an invented test that passes as closure of issues #2/#3. Continue the separate approval and revocation model in `docs/ANCHOR-TRUST-PROTOCOL.md`. **Release remains NO-GO.**
