# Testing

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-Tests.ps1                 # Windows PowerShell 5.1
pwsh       -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-Tests.ps1                 # PowerShell 7
...\Run-Tests.ps1 -SkipHeavy                 # skip the 200k-file scale test
...\Run-Tests.ps1 -ReportFile results.json   # machine-readable report
```

* Self-contained harness (no Pester).
* Every write happens inside a sandbox `%TEMP%\atm-tests-<random>` created and removed by the suite,
  **outside** any real agent temp directory. Junctions are unlinked before removal; `rd` never follows them.
* Tests touching the real machine are read-only (profile discovery, full inventory, CLI `verify`/`version`).
* Optional: set `ATM_PRIVATE_NEEDLES` to a file (kept outside the repository) listing private identifiers;
  the privacy test fails if any of them appears in the repository.

## Coverage

| Area | Cases |
|---|---|
| Empty collections | no profiles, missing base, empty base, empty process list |
| Paths | spaces, Unicode (Latin + CJK), case-insensitive references, forward slashes |
| Classification | RECENT, ORPHAN_SUSPECTED, clock skew, loose files, non-UUID dirs, invalid scopes, unrecognised base, shared TEMP |
| Partitions | sum of partitions = independent total; no duplicates; logical vs allocated |
| Permissions | unreadable subdirectory, unreadable base, no delete right, read-only file, other user (non-admin / admin), NTFS owner mismatch |
| Processes | uninspectable processes, snapshot failure, real process referencing a root, self-exclusion of the launcher chain |
| References | direct, ancestor-only (scope/base), ambiguous (8.3/wildcard) |
| Sessions | live sessions in two profiles, PID reuse, PID without start time, corrupt registry, recent transcript, unloaded profile |
| Reparse points | junction as root, junction inside root, junction in ancestor (TEMP), directory symlink (if permitted) |
| In use | open file (exclusive and fully shared), process working directory inside root |
| Allowlist | traversal, relative, UNC, `\\?\`, wildcards, ADS, trailing separator/dot, 8.3, whitespace, double separators, profile/TEMP/base/scope/drive roots, case mismatch, duplicates, outside allowlist |
| Clean flow | missing presenter/reader, absent/wrong confirmation, change between preview and clean, change after confirmation, root removed, successful deletion with siblings intact, post-audit |
| Read-only | audit + preview leave the sandbox byte-for-byte and timestamp identical |
| TUI | headless navigation of every screen, ASCII fallback, 60x20 terminal, cleanup through the engine |
| Layering | TUI/report contain no deletion APIs; audit engine neither prints nor deletes; single deletion call site |
| Providers | contract validation, test-only second provider through the same engine and gates |
| Installer | copy + manifest + verify, tamper detection, ACL audit, refusal without elevation, launcher exit codes |
| Security review regressions | rename/junction swap of subdirectory, scope and base during deletion is impossible (with a no-pin control), pre-existing redirection refused, third-party write ACL on base blocks, `%WINDIR%\Temp` shared, unexpected `procStart` never means "ended", drill-down/output path validation, no command-line fragments in evidence |
| Native assembly | installer-compiled DLL loads only with matching manifest hash (5.1 and 7); tampered DLL refused |
| I18n | catalog parity and identical placeholders; every used key translated; language resolution and safe fallback; en-US audit/preview/plan/TUI with no pt-BR text; identical engine codes across languages; CLI `-Lang`/`ATM_LANG`; ASCII transliteration |
| Clean environment | Windows Sandbox configuration generator (valid `.wsb`, networking disabled, release read-only); the in-sandbox script itself needs an administrator-enabled Windows Sandbox or VM (`NAO_TESTADO` on this machine) |
| Scale | 200,000 files in one root, bounded managed memory |
| Privacy | scanner self-test with planted data; working tree and Git index free of SIDs, e-mails, user paths, tokens, machine/user names and private identifiers; only `dist/` ignored |
| Portability | one user; several users (audited / inaccessible / hive not loaded / no Claude Code); profile on another drive letter (`subst`); no Claude Code; empty TEMP and empty root; unidentified projects and session-based identification with collision handling; Unicode, spaces, apostrophe, `&`, `#`, parentheses in profile and install paths; per-profile TEMP expansion (redirected, other drive, unresolvable variable) |

## Privilege matrix

Requirement PRIV-11 ([ELEVATION.md](ELEVATION.md)): behaviour that depends on privileges is verified with **real**
tokens, not only with the injected test identities the suite uses for gate logic. Expected results for V0.1:

| Scenario | Expected | Covered today |
|---|---|---|
| Standard user, not elevated | audit/preview/TUI work; other profiles inaccessible and other accounts' processes not observable are reported; coverage incomplete; clean blocked; installer scripts refuse | Suite, locally (Windows 10, PS 5.1 and 7) |
| Administrator, not elevated (filtered UAC token) | Same as a standard user (`elevated administrator: NO`) | Not yet (manual) |
| Administrator, elevated (consent prompt) | Full process coverage where Windows allows; other users' paths need `-IncludeOtherUsers`; installer works | Suite in CI (elevated Windows Server runner, PS 5.1 and 7); real installation: not yet (clean environment) |
| Elevated with another account's credentials (standard user, or policy requiring credentials) | Process identity = that administrator account (its profile is "own"); the requester's profile is another user's and needs `-IncludeOtherUsers`; installer records the administrator | Not yet (manual) |
| UAC prompt cancelled | No elevated session, nothing changed | Not yet (manual) |
| Non-interactive session (SSH, WinRM, scheduled task) | Runs with the caller's token; never waits for a prompt | Not yet (manual) |
| Windows 11 | Same results as Windows 10 for every row above | Not yet (manual) |

Gate logic for administrators and other users is also exercised with injected identities (`IsAdmin`, profile SID
different from the process SID) in every run, on both shells. Manual rows are recorded in the release notes as
done or `NAO_TESTADO`, never assumed.

Results are `PASS`, `FAIL` or `NAO_TESTADO` (a prerequisite was unavailable, e.g. no free drive letter for
`subst` or no symlink privilege); `NAO_TESTADO` is never counted as a pass.
