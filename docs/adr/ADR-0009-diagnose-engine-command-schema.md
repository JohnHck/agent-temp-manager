# ADR-0009: Diagnose engine, command, JSON schema and layering

Status: ACCEPTED (maintainer gate 2026-10-20, after PR #19); D-6 accepted: the command is `agent-temp diagnose`
Date: 2026-10-20
Phase: P1 (engine skeleton, command, schema v1), P5 (TUI view, final presentation)

## Context

"Engines decide, presentation shows" is enforced by the layering test, which today checks `Engine.Audit.ps1`,
`Engine.Clean.ps1`, `Report.ps1` and `Tui.ps1`. V0.2 adds collectors that touch processes, services, WMI and Git,
which are exactly the APIs that could change system state if misused. The roadmap asks for a diagnose command (name to
be confirmed), JSON export and a TUI view. Testing each phase end to end needs the command and the export early, not
only in the presentation phase.

## Decision

1. **New engine file `src/lib/Engine.Diagnose.ps1`** (read-only, no terminal output, progress through a callback),
   with collectors in the same file or in `src/lib/Diagnose.*.ps1` files loaded by it. Every collector takes an
   injectable source (`-Source` override), like `-ProcessesOverride` in V0.1, so tests can feed present, absent,
   denied, partial and timeout data.
2. **Entry point** `Invoke-AtmDiagnose` returns one object: identity and elevation (ADR-0003), coverage records
   (ADR-0001), findings, dependency graph (ADR-0002), the V0.1 inventory it was built on, timings and limits used.
   It never calls the clean engine.
3. **D-6 (proposed): command name `diagnose`**: `agent-temp diagnose [-ExportJson <file>] [-Repository <path>]...
   [-RepositoryListFile <file>] [-NoProgress] [-Lang ...]`. Read-only, no elevation requested, exit code `0` when the
   run completes (even with partial coverage), `10` on unexpected error, as today. Partial coverage is a result, not
   an error. `-ExportJson` uses the existing `Test-AtmOutputPathOutsideBases` and also refuses paths inside any
   diagnosed repository or worktree.
4. **JSON schema** `schemaVersion = "atm.diagnose/1"`, separate from the V0.1 audit export (which is unchanged).
   Codes only (language-neutral); no command lines, environment values, service `PathName` arguments, Git
   configuration values, file contents or tokens. Field additions keep the version; removals or meaning changes bump
   it. A schema document is added under `docs/` in P1 and kept in sync by a test that compares it with a fixture
   export.
5. **Layering test extended (P1)** to `Engine.Diagnose.ps1` and every `Diagnose.*.ps1`:
   * no terminal output (`Write-Host`, `Write-Progress`, `Read-Host`) and no deletion APIs (same list as the audit
     engine);
   * no process, service or VM control: `Stop-Process`, `Start-Process` (Git is started only through the native
     bounded runner of ADR-0006), `Stop-Service`, `Start-Service`, `Set-Service`, `Restart-Service`,
     `Suspend-Service`, `Invoke-CimMethod`, `Invoke-WmiMethod`, `Set-CimInstance`, `Remove-CimInstance`, `*-VM`
     cmdlets, `sc.exe`, `net stop`/`net start`;
   * no registry or ACL writes (`Set-ItemProperty`, `New-Item`, `Set-Acl`, `CreateSubKey`, `SetValue`);
   * no reference to `AtmLockProbe`, `AtmDeleter` or `Invoke-AtmClean`;
   * Git only through the allow-listed runner (ADR-0006 rule 4).
   `Report.ps1`/`Tui.ps1` keep their current restrictions and must not call collectors directly, only
   `Invoke-AtmDiagnose`.
6. **Presentation:** a CLI report (`Show-AtmDiagnose` in `Report.ps1`) from P1, extended per phase; a TUI diagnostics
   view in P5 (menu entry, drill-down per node with incoming edges and evidence, coverage screen). Unknown, partial and
   denied are always visible; there is no "hide unknown" filter. Text through the catalog, both languages, in every
   phase that adds output.
7. **Release gate untouched:** `Engine.Diagnose.ps1` does not reference `$script:AtmRealDeletionEnabled`; the existing
   gate tests and the build check stay as they are.

## Rejected alternatives

* *Adding diagnostics to `audit`:* changes the meaning and cost of a V0.1 command and of its JSON export.
* *Command and JSON only in P5:* every earlier phase would be tested only through internal functions, and the export
  privacy rules would be checked late.

## Consequences

* `docs/USAGE.md`, `docs/ARCHITECTURE.md` and the help text are updated in the phases that add the behaviour.
* The audit export and the diagnose export may both contain paths; both carry the privacy warning.

## Verification

* Layering test (static) as listed; a test that `Invoke-AtmDiagnose` with all sources mocked produces the same JSON in
  en-US and pt-BR (only `language` differs).
* Privacy test over a fixture export: planted command-line fragments, environment values, `PathName` arguments and Git
  configuration values never appear.
* CLI tests: exit code `0` with partial coverage, `-ExportJson` refused inside bases, repositories and worktrees.
* The existing V0.1 tests (audit export, gate, layering) stay green unchanged.

## Implementation (P5-A, 2026-10-25): TUI diagnostics area

The presentation layer gains a diagnostics area in the existing TUI (menu `D`); the layering rules above are unchanged.

* **One entry point.** The TUI calls only `Invoke-AtmDiagnose` (through an injectable runner for tests), on an explicit
  action: entering the area when there is no result, or `U`. Navigation, paging, filters and details reuse the result
  and run nothing (headless test counts the runs).
* **Schema-only view.** The result is converted with `ConvertTo-AtmDiagnoseJson` and parsed back; the area renders that
  view, so it shows exactly what the export may show. The identity block, the machine name and the V0.1 inventory
  are not rendered (the V0.1 screens keep their own content; tests check the separation).
* **Indexes.** Built once per result (findings by category and key, worst coverage per collector, nodes, incoming and
  outgoing edges, pending items); a list frame formats only its visible page.
* **Meaning.** `UNKNOWN` is never shown as free; `NOT_OBSERVABLE`, `DENIED` or `TIMEOUT` are never shown as zero
  items; strengths have text markers (`[D]`, `[A]`, `[?]`), not only colors; an ambiguous `ATTRIBUTED_TO` is marked
  "ambiguous, not exclusive"; a node without a finding is "a reference without its own finding"; elevation is
  promised only when `ElevationWouldHelp` is `YES`.
* **Failures.** A failed run shows the exception type only; a previous result is kept and marked as outdated in the
  header and the summary; nothing is retried automatically.
* **Engine change for the view.** `worktree-discovery` is now always reported (`NOT_OBSERVABLE`,
  `WORKTREE_DIAGNOSTICS_GATE_CLOSED`) when the worktree gate is closed, so the area never has to invent a coverage
  record; and the run's worst record of a relevant collector is attached to a rebuilt partition or worktree finding
  even when the finding already carries a conclusive record of it (defense in depth, P4-B).

## Implementation (P5-B, 2026-10-25): CLI, JSON contract and export

* **Contract test.** The suite parses `DIAGNOSE-SCHEMA.md` and checks every exported object (top level, identity,
  providers, coverage, findings and evidence, agent resources and counters, graph nodes, edges, evidence, summaries and
  coverage, pseudonymization, inventory) for exactly its documented fields and types, on a synthetic result with a
  graph, an integrated run, a run with a zero deadline and a run without providers; plus stable identifiers, arrays for
  empty lists, `null` kept, no conclusive absence over incomplete coverage, positive states with their evidence, and
  identical documents in pt-BR and en-US except `language`. No published field changed meaning.
* **Export.** `Test-AtmDiagnoseExportPath` adds to the V0.1 destination rules a refusal inside Git repositories and
  worktrees (an ancestor holding `.git`; existence checks, no Git) and returns a code; `Write-AtmNewTextFile` creates
  the file with `CreateNew`. The CLI reports refusals and write failures by code only (exit code `10`), never by
  exception message. Remaining window (a folder replaced by a junction between check and creation): SECURITY-MODEL.
* **CLI.** No option gives repository paths, opens a gate or requests elevation (static test); `diagnose` never calls
  the clean engine and writes nothing without `-ExportJson`; version, help and exit codes are checked through the
  launcher.

## Security addendum (P5-B-S, 2026-10-25): diagnose export gate

The maintainer's review of PR #48 accepted P5-B and blocked the export: the destination is checked by name and the
file is created by name, so a folder replaced by a junction in between can redirect the new file, and the document holds
the machine name, the account and its SID. Decision:

* **Gate.** `$script:AtmDiagnoseExportEnabled = $false` (single assignment, `Report.ps1`; no option, environment
  variable or configuration). `diagnose -ExportJson` is refused first (`EXPORT_SECURITY_GATE_CLOSED`, exit code 10):
  nothing collected, no destination checked, no file. `Test-AtmDiagnoseExportPath` and `Write-AtmNewTextFile` refuse
  on their own while it is closed (defense in depth).
* **Kept, not rewritten.** The destination rules (substituted drives, repositories, worktrees, reparse points) and
  `CreateNew` stay, tested on fixtures with the gate opened by the harness only and closed again in `finally`. A harness
  counter-proof shows the redirection the gate guards against; fixture tests are not proof against the real race.
* **Unchanged.** `diagnose` without `-ExportJson`, the report and the TUI area (rendered from the in-memory document).
* **Opening the gate** needs a demonstrated mitigation (FINAL-A: creation relative to a handle on the validated parent,
  for example `NtCreateFile` with `OBJ_DONT_REPARSE`; adversarial concurrency in a sandbox; AMD64 and ARM64; Windows
  PowerShell 5.1 and PowerShell 7; the supported Windows 10, 11 and Server versions; fail closed; no overwrite; ACL and
  privacy of the created file) and a new maintainer decision; without it the export stays disabled in V0.2. The `subst`
  gap of the V0.1 outputs (`audit -ExportJson`, `clean -LogFile`) is not changed by this addendum.
