# Contributing

* Keep the layering: engines never print, presentation never deletes, providers only read.
* Every behaviour change needs a test in `tests/Run-Tests.ps1`, and the suite must pass on Windows PowerShell 5.1
  **and** PowerShell 7.
* C# in `src/lib/Native.cs` must stay C# 5 (Windows PowerShell 5.1 compiles it with the .NET Framework compiler).
* PowerShell code runs under `Set-StrictMode -Version 2.0`; wrap function results in `@()` when counting them.
* Destructive tests run only in the suite's sandbox. Never use real user data in tests, fixtures or issues.
* Do not commit real paths, user names, machine names, SIDs or site-specific project names
  (`config/projects.local.json` is git-ignored).
* New agents: add one file in `src/providers/` following [docs/PROVIDERS.md](docs/PROVIDERS.md).
* User-facing text lives only in `src/lib/I18n.ps1` (en-US and pt-BR). Add every new key to **both** languages
  with the same `{n}` placeholders; the suite fails on missing keys or placeholder mismatches. Never translate
  reason/flag/class/status codes: they are stable identifiers. To add a language, add a catalog and map its
  culture prefix in `Resolve-AtmLanguage`.
* Never write real paths, user names, machine names or SIDs in tests or docs; run
  `tools/Test-AtmPrivacy.ps1 -Path .` before opening a pull request.
