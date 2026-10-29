# Changelog

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
