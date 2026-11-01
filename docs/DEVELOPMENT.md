# Development operating agreement

This project uses evidence-first, opt-in Windows diagnostics. **Experimental: not a validated system repair tool.**

## Decision and delivery loop (repeat each milestone)

1. Observe a reproducible bug, user-supplied redacted sample, or defensible feature requirement.
2. Update `docs/META-DESIGN.md` if trust boundaries, data formats, system privileges or user-visible behavior change.
3. Make a focused change on `feat/*`, `fix/*`, or `chore/*`; keep backward compatibility or document migration.
4. Update deterministic tests and cross-platform static checks; inspect potentially sensitive output and fixed native command arguments.
5. Run Windows PowerShell 5.1 and PowerShell 7 CI. Keep experimental label until both pass. Log any missing environment coverage.
6. Open PR and review changes. Prefer squash merge after checks. Record visible result in changelog.

## Protected behaviors

- No auto-elevation, persistence, hidden network transmission, upload, process killing, registry modification, or unprompted repairs.
- Native Defender scan requires explicit flag and may quarantine via Windows policies. ClamAV integration is detection only.
- Never interpret event message text as executable instructions or accept system output as trustworthy commands.
- Store reports locally; do not commit collected reports or examples containing hostnames, paths, usernames, IP addresses, or threat details.
- No premature 'Healthy' conclusions from missing SMART/WinEvent data. Use unknown/inconclusive.

## Releasing — independent approval required

- **Current decision: NO-GO. No tagged pre-release, stable release or other release authorization** based only on successful hosted Windows PowerShell 5.1/7 CI or invented fixtures.
- An authorized physical Windows 10/11 eight-cell test matrix, initial trusted-root evidence, actual owner/DACL/cloud-sync/backup review, independent security/privacy approval and accountable external release authority must all be verified first. Issues #2 and #3 stay OPEN until those external requirements are assessed.
- Review native opt-in scanner boundary, no automatic repairs and local report confidentiality. Do not commit, publish or attach raw user reports, even if lightly redacted. Public issues use **invented synthetic reproduction only** (see `docs/PUBLIC-ISSUE-GUIDE.md`).
- CI cannot prove vendor-specific device compatibility, privilege policy, private storage guarantees or the correctness of release approval.

## Near-term roadmap

1. Bootstrap source repository and CI; fix known inconsistent storage-status classification.
2. Address first real Windows CI failures, tighten collection error containment and output privacy.
3. Add fixture-driven event classifiers, explicit confidence/evidence quality; modularize collectors.
4. Add longer memory trends with safe retention and bounds; add repeatable hardware test matrix.
5. Audit native tool invocation, security posture, docs and release packaging before beta.
