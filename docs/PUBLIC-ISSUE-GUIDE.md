# Public bug-report disclosure boundary — ADR-063

**Default: keep the observation private.** Actual Windows Health Triage reports are not anonymous, and the project has **not** completed authorized physical Windows 10/11 validation or independent privacy/security/release approval. An issue, pull request, Actions artifact, screenshot, chat message, or pasted terminal output is a disclosure channel.

## Before writing a public issue

1. Keep actual `manifest.json`, `SUMMARY.md`, `events.json`, `processes.json`, `security.json`, `hardware.json`, Monitor CSV, ClamAV/Defender/SFC/DISM output and raw warnings **on an approved private workstation**. **Never attach, paste, link or commit** them to a public issue, even after ad-hoc text replacement.
2. Also keep user/computer names, exact Windows build, timestamps, account identifiers/SIDs, PIDs, device/serial/PnP IDs, IP addresses, file paths, process command lines and threat details private. Screenshots and GitHub Actions logs can contain these too. Minimized counts and fixed field-status tokens still require a separate disclosure review.
3. If independently authorized for a public update, choose a **pre-reviewed category token** from `docs/FIELD-FAILURE-TRIAGE.md`. The offline `tools/field_failure_triage.py --category <approved-token>` references **synthetic tests only**; it does not process, redact or authenticate a real incident.
4. Write an **entirely invented reproduction** using fictional actors, identifiers and data. State what was expected and what the **synthetic** test actually showed. Do not recreate a genuine event message or lightly alter a copied real record. If a safe reproduction is unavailable, say `unclassified_incomplete`, keep the details in the approved private reviewer channel, and avoid inventing test coverage.
5. Report security vulnerabilities **through the approved private channel**, following `SECURITY.md`; do not open a public security issue with exploit details or private device context. No tool automatically submits any issue, report or evidence.

## Public issue content limit

An approved public issue may contain the fixed synthetic symptom code, an existing repository `tests/` fixture reference, expected-versus-synthetic behavior, the relevant **hosted synthetic CI** result, and the unresolved limitations. It should **not** ask users to upload attachments or diagnostic files, quote `SUMMARY.md` warnings, or copy full terminal output. Even an allowlisted status may identify private device activity: if disclosure review has not approved the text, omit it.

**NO-GO:** Hosted Windows PowerShell 5.1/7 CI and synthetic reproductions are not physical Windows 10/11 evidence. The eight actual OS/shell/privilege cells, separately trusted initial root, independent security/privacy review and external release authorization remain unsatisfied; issues #2/#3 remain OPEN. No automatic upload, cleanup, repair, scanner execution or change to stored reports is authorized by this guide.
