# Initial root trust and independent approval — ADR-038 / PR #43

**Scope:** Defines a *manual* evidence/approval boundary for the research-only held-parent status-file writer (ADRs 030, 035–037). It does **not** authorize production use, real patient/customer data, release, or changing ACLs. Existing Windows Health Triage CLI and Python recorder are unchanged.

## What is — and is not — proved

Microsoft `FILE_ID_INFO` pairs a volume serial number with a 128-bit file identifier. Matching values for separately opened handles on one computer can establish the *same file object*, **not who selected that object or whether the parent name was trustworthy**. Reparse points, mount points, network and synchronized roots can redirect or replicate files independently of a matching file ID. There is no trusted initial-root oracle in this project. Treat any root selected from the same untrusted path as **self-selected**; reject self-certified correctness. A screenshot, completed JSON, hash of a self-selected path, identical handles or CI result cannot bootstrap independent trust.

## Human responsibilities (outside the status sheet)

1. **Authorized device/operator:** Establish the physical test device and consent to read-only diagnostics. Run a *separately reviewed* local root and storage policy check without pasting sensitive device/account IDs into GitHub. Prefer standard privilege; elevated cases require explicit authorization.
2. **Independent source/reference owner:** Identify the intended local volume and directory from an organizationally approved **out-of-band configuration** or comparable authority that the field operator cannot quietly replace. Define an approval and revocation process. The reference must be acquired and pinned **before** trusting a candidate path; compare separate held handles in one bounded session. If no independent authority exists, mark `self_selected` or `unknown`—not `external_reference_claimed`.
3. **Filesystem/security reviewer (a different authorized person or independent process):** Examine actual root-to-leaf namespace behavior, initial ancestor trust, reparse and mount behavior, Windows ACL/owner on the actual opened objects, tenant/policy effects, network/redirected profiles, and same-user/administrator attacker capabilities. File IDs/volume strings can be copied and should not be treated as secrets, credentials or durable attestations. Store detailed sensitive findings only in privately approved local records.
4. **Privacy and backup approver:** Separately establish whether OneDrive Known Folder Move, endpoint backup, DLP, cloud agents, shared folders or enterprise policies can exfiltrate/copy status files. Merely seeing `C:\` or `restricted` is insufficient. When unknown, leave the result `unknown`.
5. **Release authority:** Review real Windows 10/11 × PowerShell 5.1/7 × standard/elevated field matrix, negative provider scenarios, trusted reference provenance and privacy findings in a protected process. Issue an *actual external decision*, with revocation and auditability outside this repository. **This project currently has no mechanism to verify that approval.** Never paste evidence/identity/signature text or sensitive reports into a public PR or issue.

## Claim-only offline worksheet (optional)

`docs/anchor-trust-template.json` contains only fixed labels. Make a **private local** copy in a known approved non-synced location, manually change values only to accurately represent claimed progress, and use:

```powershell
python tools/anchor_trust_review.py --metadata 'C:\ApprovedPrivate\anchor-status.json'
```

The tool reuses the strict 32 KiB, no-duplicate-key, regular-file metadata reader. No report body, paths, names, SID, volume GUID, file IDs, signatures or free-text evidence belongs in the worksheet. A valid worksheet is **neither independently authenticated nor proof of the claims**, and even if every field is set to `*_claimed`, it returns `Decision: NO_GO`, `Readiness: CLAIMS_UNAUTHENTICATED`, and exit **2**. `approved_claimed` is **not** approval. `self_selected` is rejected as self-certification, and any `unsafe`, `mismatch`, `expired`, `unsupported` or `risk_present` produces `UNSAFE_CLAIM`. A wholly pending sheet remains `INCOMPLETE`. Invalid/extra fields are rejected.

This sheet is optional and does not extend the schema of `docs/field-evidence-template.json` or make either existing NO-GO gate produce GO. Do not check completed private worksheets into GitHub, even though they contain fixed labels.

## Release blocking criteria

- [ ] An independently authorized, revocable source of trusted initial volume/root/parent reference exists, separate from the operator's untrusted candidate.
- [ ] Real Windows 10/11 test devices, PowerShell 5.1 and 7, standard/elevated where authorized, and known negative provider cases verified; CI synthetic Windows runners do not count.
- [ ] Path/namespace/race/volume and native interop support policy independently reviewed, including remote, junction, mount and alias behavior.
- [ ] Actual Windows owner/DACL and cloud/managed storage backup/sync independently reviewed on the real device.
- [ ] Privacy/security/release authority decisions recorded privately via a verifiable and authorized process. No release token, signature, or mechanism exists in this repo.
- [ ] Issues #2 and #3 assessed and explicitly closed by accountable human reviewers, not by fabricated worksheet values.

**Current decision: NO-GO.** The workstation's actual provenance and privacy were not verified by this PR.

References: [Microsoft FILE_ID_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info); [Windows reparse points](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points).

## PR #58 / ADR-053 — revocable root and retained worksheet claims

`reference_lifecycle=live_claimed` and `authorization=approved_claimed` are **not current, independently checked authority**. A third party can reuse a previous sheet after external approval has been withdrawn or the reference has been revoked. The status reader has no private revocation registry, secure clock or authenticated approval service. A worksheet that explicitly says `expired` or `self_selected`, or acknowledges storage/namespace risks, causes the combined readout to suppress its complete-looking field coverage count to 0/8; this is not evidence that a revocation or deletion itself was independently verified.

The accountable authority must verify status with its current private and revocable source, define required retention/backup/legal-hold treatment and independently document subsequent renewal, withdrawal or disposal. Never modify original local reports, overwrite an old status sheet to conceal a rejection, treat a retained copy as approval or attach personal identifiers/approval records to this repository. `RetentionReview: NOT_VERIFIED` and `ApprovalRevocation: NOT_CHECKED` are deliberately fixed; release remains NO-GO.
