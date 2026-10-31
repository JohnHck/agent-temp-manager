# Changelog

## Unreleased

* V0.3 V3, phase V3b (tests only, no product change): new entries, changes, a third-party ACL (fixture ACE on planted
  roots only) and new processes (of the same account, and in leg A of another account, started by a watcher of the
  e2e and ending by themselves) after the plan, in each window, with the real deleter. Proves that the deleter does not
  read the ACL again once everything is pinned (a declared limit). Details: docs/TESTING.md, "New entries, ACL and
  processes after the plan".
* V0.3 V3, phase V3a (tests only, no product change): the CI-only harness also attacks planted roots with reparse
  points and links and with files and folders in use, in each window of the flow (before the plan, before the final
  confirmation, before the revalidation, before the deleter and inside it once everything is pinned). Inside the deleter
  it uses the real deleter through a wrapper with the engine's own arguments (compared by a static test). Each case
  asserts its code, the log read back from the file, the number of calls to the deleter and that nothing outside the
  planned root changed. Details: docs/TESTING.md, "Adversarial cases on disposable VMs (V0.3 V3, phase V3a)".
* V0.3 V2 (tests only, no product change): the `install e2e` jobs run the real clean end to end on disposable
  GitHub-hosted VMs, through the CI-only harness `tests/e2e/Invoke-CleanE2E.ps1`, on roots it plants itself in a run root
  it creates. It loads the installed engine and opens the deletion gate only in its own process memory; the installed
  copy stays closed (checked by SHA-256). Real deleter, T1 log file, B8 lock and revalidation; automated confirmation,
  never a human acceptance; simulated recency (write times set back). Leg A as a non-elevated standard user (B1
  restricted exception), leg B elevated (ELIGIBLE only with complete measured coverage). The harness never ships:
  `tools/Build-Release.ps1` leaves it out and refuses an archive that contains it. Only a summary is uploaded. Details:
  docs/TESTING.md, "Real clean on disposable VMs (V0.3 V2)".
* V0.3 T1 (F-04, not closed until released): `clean -LogFile` becomes a new file per run, required once real deletion
  is enabled; written through a handle kept for the run (append-only, flushed per record, JSON Lines). Per-root
  `intent` before the deletion and `result` after it; a refusal, a partial deletion, an exception, an inconclusive
  verification or a log failure stops the run (exit code `3`). With the deletion gate closed (every copy) the plan-only
  flow is unchanged. Details and limits: docs/USAGE.md, "Clean log".
* V0.3 B8: one clean run at a time per machine once real deletion is enabled: the named mutex
  `Global\AgentTempManager.Clean`, taken without waiting before the first inventory and released last; a lock that is
  not available, an abandoned lock (a previous run may have been interrupted) or a nested run refuses to start (exit
  code `3`). It excludes only cooperating clean runs; a local account can block it (denial of service). With the gate
  closed nothing changes. Details and limits: docs/USAGE.md, "One clean at a time".
* V0.3 B2-1: preview, the clean plan (also with the deletion gate closed) and each root's revalidation add reasons from
  the read-only V0.2 collectors: observed use or a live session of the root blocks; ambiguous relations, unverified
  sessions and failed or timed-out collection need investigation. Nothing is ever made eligible by it, and no
  evidence is not evidence of non-use. Details and the time limits: docs/USAGE.md, "Runtime evidence in preview and plan".
* V0.3 B1 restricted exception (**a change of the product contract**: until V0.2 incomplete process coverage had no
  override; past the deletion gate only, no distributed copy reaches it): a root whose only refusal is B1, in the own
  non-elevated profile, a Claude Code session root with no other refusal and complete process identities, is shown as
  `ELIGIBLE_WITH_DECLARED_RISK` (never `ELIGIBLE`, "not released" in preview, audit and the TUI). Only
  `clean -AcceptB1ResidualRisk` (CLI) past the gate can act: one root per run (fixed in code), the AUT-2 questions plus a
  per-root `ACEITO RISCO B1` with the count; the identities of the processes not inspected are recorded and bound to the
  plan id; any new one, or the process snapshot no longer complete, refuses before the deletion. Residual risk declared,
  no rollback. Details: docs/USAGE.md, "B1 restricted exception"; docs/SECURITY-MODEL.md, gate 6.
* V0.3 AUT-2 (past the deletion gate only; no distributed copy reaches it): the clean confirmation is bound to the plan.
  An interactive console is required (CLI) and observed by the engine; for each root of the executable set, with its
  path, the task and the content decision (AUT-1 meanings: results preserved, or nothing needed, neither verified);
  then one phrase `APAGAR <N> CAMINHOS <plan id>` for the exact set. Declarations and confirmation are logged and
  flushed before any deletion; a plan check refuses any change during the questions; any refusal aborts the whole run.
  A revalidation refusal after the confirmation now stops the run before that root (`REVALIDATION_REFUSED`) instead of
  skipping it and going on; not all-or-nothing and no rollback (earlier operations stay done; `run-end` names the root
  that stopped the run and the roots not attempted). The phrase carries the first 8 characters of the plan id.
  With the gate closed the plan-only flow is unchanged. Details and limits: docs/USAGE.md, "Plan-bound confirmation".
* V0.3 AUT-1: `agent-temp authorize -Path <root> -RecordFile <new file>` records the operator's discard authorization of
  one root bound to the plan shown (three confirmations, interactive console only, plan presented again and compared,
  new file). It deletes nothing, is read by nothing in the product and makes nothing eligible; the technical result
  (B1, RECENT included) is recorded apart. Schema `atm.discard-authorization/2`: two separate content declarations
  ("results preserved" or "nothing needed"), neither verified by the product (`TOOL_VERIFIED` reserved, never
  emitted); the process identity, not the respondent; the caller and its console requirement as reported, the console
  observed by the engine in that call; B1 recorded apart as the coverage observed and the gate's state (`BLOCKED`, `PASSED`,
  `NOT_EVALUATED`); the justification revalidated in a stable semantic form (runtime refusals carry the process keys they come from, field
  `Sources`, so the same code from another process is a change); success only when the line is written, flushed and
  the file closed (a file kept after a failure, even with a complete line, is not a recorded authorization). Details and
  limits: docs/USAGE.md, "Discard authorization".

## 0.2.0

Published only as the GitHub Release `v0.2.0` (tag `v0.2.0`), created with the maintainer's explicit authorization.
Details, limits and open decisions: [docs/release/V0.2.0-RELEASE-NOTES.md](docs/release/V0.2.0-RELEASE-NOTES.md).

* `agent-temp diagnose` and TUI area **D**: read-only runtime diagnostics with coverage per collector (process
  identity, agent processes and sessions from evidence, resource totals per verified tree, provider-declared Windows
  services, Hyper-V platform and VMs, dependency graph, temporary partitions with runtime evidence, profile
  discovery); keyed pseudonyms instead of paths; never elevates, runs no Git, writes no file.
* Runtime-only Claude Desktop provider; `CoworkVMService` identified by a provisional, publicly reported name.
* Closed gates in every copy, checked in source, build and installation: real deletion, worktree diagnostics, open-file
  diagnostics, diagnose JSON export. D-1 (process working directories) deferred.
* Security audit (FINAL-A, FINAL-B): F-01, F-02, F-03, F-06, F-07, F-08, F-11, F-13 fixed. F-04, F-05 and F-14 were
  deferred by the maintainer (F-04 to V0.3, before the deletion gate can open; F-05 and F-14 to a later 0.2.x) and
  stay listed as known limits. F-01 and F-02 also affected 0.1.0 and are fixed there in 0.1.1 (below).
* Job runner result contract (PR #54):
  * a refused termination, a reader error, output not read to its end, members terminated after the exit, and members
    still active at the end are reported, never taken for a complete run;
  * the Git mapping gives `COMPLETE` only for exit code 0 with none of them.
  * A real refusal of `TerminateJobObject` is NOT TESTED (synthetic results only).
* Installation: `verify` and the installer bootstrap run no unverified code (R-B5); update and rollback never destroy
  the only intact installation (R-B6); the staged copy is verified against the source manifest (F-07); the post-install
  verify runs `cmd.exe` from System32 (F-13); the release build refuses an archive unless all four gates are `$false`.
* Audit coverage (PR #57): a `TEMP` base that is not audited makes the coverage incomplete (`PROFILES_NOT_AUDITED`)
  and a profile with a base read and a base not audited is `AUDITADO_PARCIAL`.
* Read errors (PR #58, PR #59): in the path chain check, the Claude Code sessions folder, the activity evidence of a
  root and, behind closed gates, the post-delete verification and the export destination check, an access denied or an
  unexpected error is no longer taken for a confirmed absence (Windows PowerShell 5.1 could run a typed `catch` clause
  for the wrong exception); an unreadable project folder now leaves a root to investigate, never eligible.
* TUI (PR #59, PR #60): the dashboard puts four cards on a row only from 130 columns; the busy screen of R, D and U
  replaces the previous screen; keys typed while they run are discarded.
* Behaviour changes since 0.1.0 (stricter `audit -ExportJson` creation and protected DACL, network or device paths from
  other users' environment refused, control characters shown as `?`, `verify` exit code `5` for a missing library):
  listed with the gate that approved each one in the release notes.
* CI: ARM64 suite jobs (Windows PowerShell 5.1 full, PowerShell 7 subset with 16 cases NOT TESTED), install e2e with
  integrity variants, installed audit export, encoding and an update from the published 0.1.0 and from the published
  0.1.1 and back; artifacts
  sanitized and scanned before upload; the suite's child calls run inside their own Job Object.

## 0.1.1 (published 2026-10-26, 0.1.x line)

Security fix release of 0.1.0, built and published from the `release/0.1.x` line: tag `v0.1.1`, commit `5c18a6e`,
[GitHub Release](https://github.com/JohnHck/agent-temp-manager/releases/tag/v0.1.1). That commit is not part of this branch's history. 0.2.0 carries its own fixes for the
same findings (FINAL-A). It is recorded here as part of the version history.

* F-01, MEDIUM, CVSS 3.1: 5.0 ([GHSA-c68f-jj6j-92r7](https://github.com/JohnHck/agent-temp-manager/security/advisories/GHSA-c68f-jj6j-92r7)): another local user's `TEMP`,
  `CLAUDE_CONFIG_DIR` or `CLAUDE_CODE_TMPDIR` in network or device form is refused before any file API, and path
  normalization no longer traverses a reparse point. The higher-impact scenario (NTLM relay) was not demonstrated.
* F-02, MEDIUM, CVSS 3.1: 6.0 ([GHSA-5m78-qp92-5f9v](https://github.com/JohnHck/agent-temp-manager/security/advisories/GHSA-5m78-qp92-5f9v)): `audit -ExportJson` creates its file through a
  pinned, handle-relative writer. The create-or-truncate impact in 0.1.0 was identified by code inspection, not
  demonstrated dynamically.

## 0.1.0

* Initial limited release: audit, preview and TUI. `clean` is **plan only** (release gate); real deletion is
  disabled.
* `-AcceptProcessCoverageGap` removed: incomplete process coverage always blocks deletion.
* Deleter pins ancestors and the tree by handle, deletes by handle, and requires the pinned plan to match the
  validated measurement (security review H1 and TOCTOU hardening).
* Installer: precompiled, manifest-verified native assembly; allow-list ACL audit; rollback script; testable
  install/update/rollback/uninstall flow.
* Install/uninstall/rollback run with a private, administrator-only TEMP (no compiler intermediates in a
  user-writable %TEMP% of the elevating account).
* Interface in en-US and pt-BR (`-Lang`, `ATM_LANG`, Windows UI language; safe fallback to English). Engine
  decisions and codes are language-neutral.
* ASCII mode transliterates accented text.
* Clean-environment test kit for Windows Sandbox / VM (`tools/clean-env`).
* Portability: unidentified projects shown as `Projeto não identificado` (session working directory used as
  evidence when consistent); profiles whose environment cannot be read are reported as TEMP not verifiable
  (incomplete coverage) instead of "no agent temp"; path joins never depend on the drive existing.
* Privacy scanner (`tools/Test-AtmPrivacy.ps1`) gating every release build.
* Launcher pins `PSModulePath` for the Windows PowerShell child (works when invoked from PowerShell 7).
* Static analysis: PSScriptAnalyzer 1.25.0 pinned by version and package SHA-512, module signatures verified;
  0 findings in security and compatibility rules; one reviewed, per-file signature exception for
  `Newtonsoft.Json.dll` when a runner image resolves it through a Windows catalog (exact path and SHA-256; the signer
  allow-list is unchanged). Remediation: `$Profile` parameters renamed to `$ProfileInfo` (`-Profile` kept as an
  alias; providers written with `param($Profile)` keep working), unused variables removed, every empty `catch` made
  explicit with its conservative value; reviewed, narrow exceptions only.
* The privacy scanner warns when the Windows profile list cannot be read (previously a silently weaker scan).
* CI: commit identity check (no personal e-mail in author, committer or trailers); real installation, update,
  rollback, tamper detection, standard-user run and uninstall on disposable Windows Server 2025, Windows Server
  2022 and Windows 11 ARM64 VMs, installer under PowerShell 5.1 and 7, with one package built once.
* Documentation: privileges and UAC (`docs/ELEVATION.md`, PRIV-1 to PRIV-11), privilege matrix and runbook with a
  read-only probe (`tools/privilege-matrix`), roadmap V0.1 to V1.0 including Git worktree diagnostics (V0.2) and
  safety before deletion (V0.3), release notes and known limitations (`docs/release`).

## Initial development notes

* First version: `agent-temp` global command with TUI, `audit`, `preview`, `clean`, `verify`.
* Provider architecture; V1 provider: Claude Code on Windows.
* Multi-profile discovery through Windows (ProfileList, loaded hives, Public/Default, residual folders).
* Read-only single-pass inventory with exclusive partitions, reparse-point protection and bounded memory.
* Conservative classification (ACTIVE_EVIDENCE, RECENT, LIVENESS_UNKNOWN, ORPHAN_SUSPECTED).
* Fail-closed assisted cleanup with allowlist, exact plan, typed confirmation and per-path revalidation.
* Installer/uninstaller with manifest verification and ACL audit; release builder.
* Automated test suite for Windows PowerShell 5.1 and PowerShell 7.
