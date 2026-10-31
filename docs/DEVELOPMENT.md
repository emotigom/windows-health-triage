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

## Releasing

- PR review and green Windows smoke/integration on 5.1 and 7, plus manual Windows computer spot checks.
- Confirm scanner options only call documented safe args, confirm no secret/PII in docs/fixtures.
- Publish tagged pre-release with explicit limitations before producing an official stable release.
- This CI cannot prove correctness on every vendor driver/firmware or scan signature database.

## Near-term roadmap

1. Bootstrap source repository and CI; fix known inconsistent storage-status classification.
2. Address first real Windows CI failures, tighten collection error containment and output privacy.
3. Add fixture-driven event classifiers, explicit confidence/evidence quality; modularize collectors.
4. Add longer memory trends with safe retention and bounds; add repeatable hardware test matrix.
5. Audit native tool invocation, security posture, docs and release packaging before beta.
