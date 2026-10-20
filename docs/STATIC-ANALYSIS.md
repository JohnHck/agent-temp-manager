# Static analysis

CodeQL (GitHub code scanning) covers `src/lib/Native.cs` and the workflow files, but **it does not analyse
PowerShell**, which is most of this project. PowerShell is analysed with PSScriptAnalyzer.

## How it runs

* `tools/Invoke-AtmStaticAnalysis.ps1`, job `static analysis (PSScriptAnalyzer)` in `.github/workflows/ci.yml`.
* **Pinned and verified:** PSScriptAnalyzer **1.25.0** is downloaded from the PowerShell Gallery into a temporary
  folder (nothing is installed, no module path is changed). The package SHA-512 must equal the value published by
  the Gallery, and every code file of the module must carry a valid Authenticode signature from an allowed signer
  (Microsoft Corporation, Microsoft 3rd Party Application Component, Json.NET (.NET Foundation)). The module is then
  imported by path and its version checked. Any integrity or tool failure fails the job (exit code 3).
* **Scope:** every `*.ps1`, `*.psm1` and `*.psd1` under `src/`, `install/`, `tools/` and `tests/`.
* **Rules:** every default rule, with nothing excluded, plus compatibility rules for Windows PowerShell 5.1
  (Windows 10 and Windows Server 2019 profiles) and PowerShell 7 on Windows: `PSUseCompatibleSyntax`,
  `PSUseCompatibleCommands`, `PSUseCompatibleTypes`. Settings: `tools/PSScriptAnalyzerSettings.psd1`.
* **Mode:** phase 1 is **informative**: the job reports findings (log, job summary, `static-analysis` artifact) and
  never fails because of them; it is not a required check. The workflow token stays read-only.
* Locally: `pwsh -NoProfile -File tools/Invoke-AtmStaticAnalysis.ps1 -ReportFile static-analysis.json`.

## First analysis (PSScriptAnalyzer 1.25.0, 20 files, 498 findings)

No security rule fired: `PSAvoidUsingInvokeExpression`, `PSAvoidUsingPlainTextForPassword`,
`PSAvoidUsingConvertToSecureStringWithPlainText`, `PSUsePSCredentialType`, `PSAvoidUsingUsernameAndPasswordParams`,
`PSAvoidUsingComputerNameHardcoded`, `PSAvoidUsingBrokenHashAlgorithms` and `PSAvoidUsingAllowUnencryptedAuthentication`
have **0** findings. `PSUseCompatibleSyntax` and `PSUseCompatibleTypes` have **0** findings.

| Findings | Severity | Rule | Where | Triage |
|---:|---|---|---|---|
| 307 | Information | PSAvoidUsingPositionalParameters | tests 289, src 16, install 2 | Style. Mostly `Get-AtmText 'key' ...` and test assertions; positional use is deliberate and readable. Accepted. |
| 73 | Warning | PSAvoidUsingWriteHost | CLI, report, TUI, installer, tools, tests | **False positive by design:** these are the interactive presentation layers (coloured console output). The engines (`Engine.Audit.ps1`, `Engine.Clean.ps1`) have none, and a test already forbids it there. |
| 24 | Warning | PSUseSingularNouns | function names such as `Get-AtmProfiles` | Naming style; renaming internal functions is churn without safety value. Accepted. |
| 22 | Warning | PSAvoidUsingEmptyCatchBlock | src 14, tests 4, install 2, tools 2 | **Reviewed one by one in the engines**: all are optional enrichment (volatile environment, `ProfilesDirectory`, `Public`/`Default`, process start time, 8.3 short path, ACL owner, console encoding). When they fail, the conservative default stays: an unreadable owner becomes `OWNER_ILEGIVEL` (blocks), a path that cannot be read is not treated as gone, a missing start time never proves a session ended. Remediation: document each with a comment (no behaviour change). |
| 18 | Warning | PSReviewUnusedParameter | tests 13, src 5 | Test fakes must match a signature (false positives). In `src`: unused `Width`/`Height`/`G` in `Tui.ps1`, `Inventory` in `Report.ps1` - dead parameters to remove. |
| 17 | Warning | PSAvoidAssignmentToAutomaticVariable | `$Profile` parameters (src 11, tests 6) | **Real hazard, latent:** a parameter named `Profile` shadows the automatic `$PROFILE`. No current bug (it is never used as the profile script path), but it is the same class of mistake as `$HOME`/`$args`. Remediation: rename to `ProfileInfo`. |
| 16 | Warning | PSUseShouldProcessForStateChangingFunctions | src 6, tests 7, install 3 | `New-*`/`Set-*` that only build in-memory objects or set in-process state (`New-AtmRow`, `New-AtmSeg`, `Set-AtmClassification`, `Set-AtmLanguage`, `Start-AtmTui`, test helpers): false positives. `Remove-AtmOwnTree`, `Remove-AtmMachinePath`, `New-AtmNativeAssembly` change the system but run only inside the elevated installer after its own checks; `-WhatIf` support is a possible improvement, not a safety gap. |
| 11 | Warning | PSUseDeclaredVarsMoreThanAssignments | tests 10, src 1 | Tests: `$o = icacls ...` keeps native output out of the console (intended). `src/lib/Tui.ps1`: `$kv` is unused - remove. |
| 10 | Warning | PSUseCompatibleCommands | `Clear-Host` in `Tui.ps1` | **False positive:** in Windows PowerShell 5.1 `Clear-Host` is a built-in function, not a cmdlet, so the cmdlet profile does not list it. The TUI tests run on 5.1. |

## Remediation plan

| Phase | Action | Exit criterion |
|---|---|---|
| 1 (now) | Informative job; this triage. | Report produced on every push and pull request. |
| 2 | Small, separate pull requests, each with the full test suite: rename `$Profile` parameters; remove dead parameters and `$kv`; comment every intentional empty `catch`. No change to engine decisions. | Only accepted/false-positive findings remain. |
| 3 | Settings: exclude `PSAvoidUsingWriteHost` for presentation files and positional/naming style rules, each exclusion with its reason in `tools/PSScriptAnalyzerSettings.psd1` (no blanket suppression, engines keep every rule). Switch the job to `-Mode Enforce` for the security and compatibility rules. | Zero findings in security and compatibility rules. |
| 4 | Make `static analysis (PSScriptAnalyzer)` a required check. | Two consecutive green runs in Enforce mode. |

Updating PSScriptAnalyzer means changing `$Version` and `$PackageSha512` together in
`tools/Invoke-AtmStaticAnalysis.ps1`, taking the hash from the Gallery, in a pull request of its own.
