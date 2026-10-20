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
* **Reviewed exceptions:** `tools/static-analysis-exceptions.psd1`. Each entry covers one rule, explicitly listed
  files and, optionally, a message pattern, and carries a justification. Excepted findings stay counted and listed in
  the report; an entry that matches nothing is reported as stale. An exception to an enforced rule must be narrowed
  by a message pattern. The test suite validates the file (justifications, existing files, no wildcards, the
  engines never exempt from the console-output rule).
* **Enforced rules:** security, compatibility, and the rules brought to zero by the remediation
  (`PSAvoidAssignmentToAutomaticVariable`, `PSAvoidUsingEmptyCatchBlock`, `PSUseDeclaredVarsMoreThanAssignments`).
  `-Mode Enforce` fails on any non-excepted finding in them (and on stale exceptions).
* **Mode in CI:** **informative**: the job reports findings (log, job summary, `static-analysis` artifact) and
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

## After remediation (ATM-V0.1-FINAL, R1-R4)

| Step | Change | Result |
|---|---|---|
| R1 | `$Profile` parameters renamed to `$ProfileInfo`; `-Profile` kept as an alias; providers called by position (old name still works, tested) | `PSAvoidAssignmentToAutomaticVariable` 17 -> 0 |
| R2 | Proven-unused variables removed; output-discarding assignments use `$null =` | `PSUseDeclaredVarsMoreThanAssignments` 11 -> 0 |
| R3 | Every empty `catch` assigns the conservative value that already applied (or `$null = $_` for cosmetic calls), with the reason; the privacy scanner warns when the profile list is unreadable | `PSAvoidUsingEmptyCatchBlock` 22 -> 0 |
| R4 | Reviewed, narrow exceptions; enforced rule set | 447 findings in 21 files: **27 active**, 420 under reviewed exceptions, **0 in enforced rules** |

Active findings (accepted backlog, informative):

| Findings | Rule | Decision |
|---:|---|---|
| 24 | PSUseSingularNouns | Naming style of internal functions; renaming has no safety value. Kept visible. |
| 3 | PSUseShouldProcessForStateChangingFunctions | `Remove-AtmOwnTree`, `Remove-AtmMachinePath`, `New-AtmNativeAssembly` change the system inside the elevated installer, after its own checks. `-WhatIf` support is a possible improvement; kept visible. |

Reviewed exceptions (details and justifications in `tools/static-analysis-exceptions.psd1`): `Clear-Host` compatibility
false positive in the TUI; `Write-Host` in the presentation layers, installer entry scripts, tools and tests; positional
calls of TUI rendering helpers, `Get-AtmText` and the test harness; unused-parameter false positives (plan presenter
contract, values read from nested script blocks, test callback stubs); ShouldProcess false positives (in-memory
constructors, in-process state, TUI loop, test helpers).

## Proposal: enforced, required check (not active)

1. Switch the CI job to `-Mode Enforce` (fails only on enforced rules and stale exceptions).
2. After two consecutive green runs on `main`, add `static analysis (PSScriptAnalyzer)` to the required checks of
   `main`.

Both steps change the CI gate and need the maintainer's approval.

Updating PSScriptAnalyzer means changing `$Version` and `$PackageSha512` together in
`tools/Invoke-AtmStaticAnalysis.ps1`, taking the hash from the Gallery, in a pull request of its own, and re-checking
that no exception became stale.