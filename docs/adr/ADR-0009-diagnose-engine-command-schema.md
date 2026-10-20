# ADR-0009: Diagnose engine, command, JSON schema and layering

Status: PROPOSED, with one open decision (D-6)
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
