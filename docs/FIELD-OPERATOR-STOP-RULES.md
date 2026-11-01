# Physical field operator stop rules and independent handoff — ADR-072 / PR #77

**Decision: NO-GO.** This is a public, synthetic procedural reference, not a physical test report, independent approval, live decision engine, collection script, or proof of privacy. It never operates on a real Windows PC. The public [fixed registry](field-operator-stop-rules.json) contains no identifying evidence.

## Responsibilities before any run

**FIELD_OPERATOR**: Obtain explicit device/operator authorization, use standard privileges first, and elevate only with separate approval. Use the existing passive field validation procedure only after the storage/root/privacy review. Do not change antivirus, shares, NTFS ACLs or other safeguards to manufacture a result. The operator can refuse further manual runs, not independently approve privacy or release.

**INDEPENDENT_REVIEWER**: Separately authenticate the initial storage root from an out-of-band, revocable authority; privately review actual filesystem object/owner/DACL, effective remote access, shared/administrative shares, reparse/mount/race risks, managed sync, backups, DLP and retention. An optional `NO_NON_SPECIAL_SHARE_OBSERVED` means only that no covering ordinary share was observed in a bounded snapshot, not confidential storage; silently incomplete inventories and TOCTOU remain.

**RELEASE_AUTHORITY**: Decide release externally and independently using genuinely authorized Windows 10/11 × PowerShell 5.1/7 × standard/authorized elevated eight-cell observations, private security/privacy review, trusted root lifecycle and revocation. CI success, a self-entered all-PASS worksheet, and an apparent SMB pass **never authorize release**. Issues #2 and #3 remain OPEN; this repository always reports NO-GO.

## Fixed procedural stop/hold table

The table describes **human actions**, not a new runner mode. It does not claim an ongoing five-mode command is automatically stopped. Missing authorization or unknown outcomes cannot be rewritten as PASS.

| Trigger | Phase | Responsible role | Manual action | Prior evidence treatment | Release blocker |
| --- | --- | --- | --- | --- | --- |
| `OPERATOR_AUTHORIZATION_ABSENT` | `PRE_RUN` | `FIELD_OPERATOR` | `DO_NOT_START` | `NONE_CREATED` | `PHYSICAL_WINDOWS_10_11` |
| `INITIAL_ROOT_NOT_AUTHENTICATED` | `PRE_RUN` | `INDEPENDENT_REVIEWER` | `DO_NOT_START` | `NONE_CREATED` | `TRUSTED_INITIAL_ROOT` |
| `STORAGE_SYNC_BACKUP_POLICY_UNKNOWN` | `PRE_RUN` | `INDEPENDENT_REVIEWER` | `DO_NOT_START` | `NONE_CREATED` | `INDEPENDENT_SECURITY_PRIVACY` |
| `SMB_EXPOSURE_SHARED_OR_UNKNOWN` | `PRE_RUN` | `FIELD_OPERATOR` | `DO_NOT_START` | `NONE_CREATED` | `INDEPENDENT_SECURITY_PRIVACY` |
| `ELEVATION_NOT_APPROVED` | `PRE_RUN` | `FIELD_OPERATOR` | `DO_NOT_START` | `NONE_CREATED` | `PHYSICAL_WINDOWS_10_11` |
| `OPT_IN_SMB_GATE_BLOCKED` | `IN_RUN` | `FIELD_OPERATOR` | `STOP_ADDITIONAL_RUNS` | `RETAIN_LOCAL_NO_UPLOAD` | `INDEPENDENT_SECURITY_PRIVACY` |
| `PRIVATE_REPORT_ACL_OR_SCHEMA_FAILED` | `IN_RUN` | `FIELD_OPERATOR` | `STOP_ADDITIONAL_RUNS` | `RETAIN_LOCAL_NO_UPLOAD` | `INDEPENDENT_SECURITY_PRIVACY` |
| `PASSIVE_SCAN_UNEXPECTED` | `IN_RUN` | `FIELD_OPERATOR` | `STOP_ADDITIONAL_RUNS` | `RETAIN_LOCAL_NO_UPLOAD` | `INDEPENDENT_SECURITY_PRIVACY` |
| `INCOMPLETE_MODES_OR_PROVIDER_UNCERTAINTY` | `POST_RUN` | `FIELD_OPERATOR` | `HOLD_PRIVATE_REVIEW` | `RETAIN_LOCAL_NO_UPLOAD` | `PHYSICAL_WINDOWS_10_11` |
| `PRIVATE_EVIDENCE_DISCLOSURE_RISK` | `POST_RUN` | `INDEPENDENT_REVIEWER` | `HOLD_PRIVATE_REVIEW` | `RETAIN_LOCAL_NO_UPLOAD` | `INDEPENDENT_SECURITY_PRIVACY` |
| `MISSING_INDEPENDENT_APPROVAL` | `RELEASE` | `RELEASE_AUTHORITY` | `KEEP_NO_GO` | `PRIVATE_MINIMIZED_ONLY` | `EXTERNAL_RELEASE_AUTHORITY` |
| `SOURCE_REVOKED_OR_STALE` | `RELEASE` | `RELEASE_AUTHORITY` | `KEEP_NO_GO` | `PRIVATE_MINIMIZED_ONLY` | `TRUSTED_INITIAL_ROOT` |

**DO_NOT_START**: no new collection until an authorized person completes missing review. `NONE_CREATED` is only a planned pre-run action; it does not mean previous private reports do not exist.

**STOP_ADDITIONAL_RUNS**: do not initiate more manual collection after observing the condition. The existing field runner may continue attempting later modes after an ordinary collector, ACL or schema failure; only the explicitly opted-in SMB gate has its own fixed exit-2 refusal before the guarded collector. This does **not** guarantee the current process stops immediately or undo any earlier mode. Use approved incident/safety procedures if a command is in progress. Retain earlier and partial private reports in place; no automated deletion, relocation, permission changes, exports or uploads.

**HOLD_PRIVATE_REVIEW**: preserve reports locally, treat unresolved mode/provider statuses as incomplete, and seek separate private review before making new claims. No public console transcript, event message, root/host identifier, share/ACL details, screenshot, raw report, approval ticket, or reviewer identity belongs in a GitHub issue, public CI or chat.

**KEEP_NO_GO**: external release blockers remain even after all synthetic and hosted tests succeed. Reviewer absence, reference revocation or stale evidence requires an independently authorized new decision outside this repository. `PRIVATE_MINIMIZED_ONLY` never means publishing raw logs or private metadata.

## Practical sequence

1. **Before**: privately verify consent, physical device, intended root provenance, approved non-synced local retention, actual ACL/share/privacy policy, privilege and external review; if any is unknown, do not start. `Test-WtFieldPreflight.ps1` always returns NO_GO / exit 2 and cannot replace these checks.
2. **During**: if an opt-in guard prints `SmbCollectionGate: BLOCKED_OR_UNKNOWN` (exit 2), a per-run ACL/schema check fails, or a passive native scan unexpectedly occurs, do not initiate another manual run. Previous local reports are retained, including if a later mode refuses after earlier modes ran. Do not publish entire console output.
3. **After**: record only genuine fixed statuses in the existing approved private workflow. `review`, `not_run`, provider uncertainty and unavailable tests are not PASS; never simulate negative provider failures, weaken safeguards, delete old reports or upload raw files to fill coverage.
4. **Release**: an independent authority must review actual eight-cell observations and root/revocation/privacy evidence. An invented all-PASS sheet remains NO_GO; no public document automatically satisfies any blocker.

See [field assurance boundaries](FIELD-ASSURANCE-BOUNDARIES.md), [field validation](FIELD-VALIDATION.md), [independent review handoff](FIELD-REVIEW-HANDOFF.md), and [trusted root protocol](ANCHOR-TRUST-PROTOCOL.md). The registry's tests are **only literal contract checks**, not verification of actual operator compliance, source authority, privacy, or a genuine Windows workstation.

**Release NO-GO; issues #2 and #3 OPEN.**
