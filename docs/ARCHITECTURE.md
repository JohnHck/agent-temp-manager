# Architecture

```
src/
├─ agent-temp.ps1            CLI dispatcher (no args -> TUI)
├─ bin/agent-temp.cmd        global launcher placed on the machine PATH
├─ config/                   projects.json (generic) + optional projects.local.json (never versioned)
├─ providers/ClaudeCode.ps1  provider: temp + runtime (contract v2)
├─ providers/ClaudeDesktop.ps1  provider: runtime only (V0.2, contract v2)
└─ lib/
   ├─ Native.cs              scanner / handle probe / deleter (C# 5, compiled in memory by Add-Type)
   ├─ Engine.Audit.ps1       AUDIT ENGINE  - discovery, inventory, evidence, classification (read-only)
   ├─ Engine.Clean.ps1       CLEAN ENGINE  - allowlist, gates, plan, confirmation, revalidation, deletion
   ├─ Engine.Diagnose.ps1    DIAGNOSE ENGINE (V0.2, read-only) - evidence/coverage/findings, identity, collectors,
   │                         dependency graph (correlation) and partition/worktree states from it
   ├─ I18n.ps1               message catalog (en-US, pt-BR) and language resolution
   ├─ Report.ps1             presentation: CLI text report
   └─ Tui.ps1                presentation: interactive TUI (V0.1 screens + the V0.2 diagnostics area, menu D)
```

## Layering rules (enforced by tests)

* `Engine.Audit.ps1` never writes to the terminal and never deletes. Progress goes through a callback.
* `Engine.Clean.ps1` contains the **only** call to the deleter, reached only after every gate, the plan
  presenter, the typed confirmation and a per-path revalidation. It refuses to run without both a plan
  presenter and a confirmation reader (`SEM_APRESENTACAO_OU_CONFIRMACAO`).
* `Report.ps1` and `Tui.ps1` never reference deletion APIs. The TUI's cleanup screen only collects an
  allowlist and forwards it to `Invoke-AtmClean`.
* Providers only read evidence. They never decide eligibility.
* `Engine.Diagnose.ps1` (and any `Diagnose.*.ps1`) never writes to the terminal, never deletes, never controls
  processes, services or virtual machines, never writes the registry or ACLs and never uses the clean engine or its
  handle probe. Presentation calls only `Invoke-AtmDiagnose`, never a collector. Design: [docs/adr](adr/README.md)
  (ADR-0001, ADR-0003, ADR-0008, ADR-0009).

## Inventory pipeline (`Invoke-AtmInventory`)

1. **Profiles**: `HKLM\...\ProfileList` (+ `.bak` entries), loaded hives in `HKU`, per-user `Environment`
   (unexpanded, expanded with *that* user's profile), `Public`/`Default` declared by Windows, residual
   directories under `ProfilesDirectory` (one level; reparse points recorded, not traversed). Hives are never loaded.
2. **Bases**: for every profile x provider: `<TEMP candidate>\<provider.TempSubdir>`, long-path normalised,
   whole ancestor chain validated (`Test-AtmPathChain`: exists, readable, not a reparse point, fixed drive).
   Shared bases are flagged.
3. **Filesystem**: one pass per partition root (`AtmScanner.ScanTree`): bytes, estimated allocation, files,
   dirs, direct children, newest write, reparse points (counted, never followed), read-only/system files,
   per-entry errors with bounded samples. Memory is O(depth + samples), not O(files).
4. **Processes**: one `Win32_Process` CIM query. Uninspectable processes are counted by name.
5. **Evidence**: an index of base paths (long + 8.3 forms) resolves every command line with `IndexOf` and
   component parsing: O(processes x bases), never O(files x processes), no per-file regex. Direct
   references, ancestor references and ambiguous references are kept apart. Provider evidence: live-session
   registry and activity (transcript) timestamps.
6. **Classification**: conservative classes + flags (hard flags block, soft flags require investigation).

Totals are computed bottom-up from partitions; nothing is enumerated twice.

## Partitions

Each base yields exclusive partitions: one per direct child of every scope directory
(`SessionRoot`, `UnrecognizedDir`, `LooseFile`, `ReparsePoint`, `Unmeasured`) plus one `BaseLooseFiles`
partition for files directly under the base. Only `SessionRoot` partitions can ever become eligible.

## Diagnose pipeline (`Invoke-AtmDiagnose`, V0.2)

Collection -> normalization -> evidence -> correlation -> presentation:

1. **Collection** (read-only): token identity, provider runtime hints, the V0.1 inventory (with profile discovery and
   its gaps), declared services, the virtualization platform and VMs, the process snapshot and sessions, and, behind
   closed gates, worktrees and open files (`NOT_OBSERVABLE` in every shipped copy); working directories are deferred.
2. **Normalization and evidence**: findings (ADR-0001) with evidence codes and the coverage records they depend on;
   identifiers are keyed pseudonyms or process keys (ADR-0010).
3. **Correlation**: the dependency graph (ADR-0002) over that evidence only: verified edges, strengths `DIRECT`,
   `ANCESTOR`, `AMBIGUOUS`, limits declared as coverage; partition and worktree states come from its summaries, and a
   no-dependency state is accepted only with conclusive coverage (checked twice).
4. **Presentation**: the text report (`Report.ps1`), the JSON export (`ConvertTo-AtmDiagnoseJson`, schema
   `atm.diagnose/2`) and the TUI area (rendered from that same export). None of them collects anything.
