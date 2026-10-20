# Changelog

## 0.1.0 (unreleased)

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

## Initial development notes

* First version: `agent-temp` global command with TUI, `audit`, `preview`, `clean`, `verify`.
* Provider architecture; V1 provider: Claude Code on Windows.
* Multi-profile discovery through Windows (ProfileList, loaded hives, Public/Default, residual folders).
* Read-only single-pass inventory with exclusive partitions, reparse-point protection and bounded memory.
* Conservative classification (ACTIVE_EVIDENCE, RECENT, LIVENESS_UNKNOWN, ORPHAN_SUSPECTED).
* Fail-closed assisted cleanup with allowlist, exact plan, typed confirmation and per-path revalidation.
* Installer/uninstaller with manifest verification and ACL audit; release builder.
* Automated test suite for Windows PowerShell 5.1 and PowerShell 7.
