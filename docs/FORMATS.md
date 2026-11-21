# Output and input formats

This document is the contract of every file and code the product writes or reads. It covers the formats of
[ADR-0018](adr/ADR-0018-v10-stabilization-multi-agent.md) section 2.1, the classes of decision V10-D3 (a) (2026-11-21)
and the rules of ADR-0018 section 2.2. It does not change any format.

Line numbers are those of the commit that added this document. The suite checks that each file it cites holds the
schema id, so a moved line does not break the contract. The area "Contratos de formato" of `tests/Run-Tests.ps1`
proves this document. Its cases are listed under [Tests](#tests).

## Classes

| Class | Formats | What the product promises |
|---|---|---|
| **Stable** | `audit -ExportJson` (`atm.audit/1`), `diagnose -ExportJson` (`atm.diagnose/2`), `monitor.json`, `config\quarantine.policy.json` (`atm.quarantine-policy/1`), the exit codes | Scripts and people may rely on them. Changes follow the rules below. |
| **Internal** | the monitoring record (`atm.monitor/1`), the quarantine manifest (`atm.quarantine/1`), the plan ids, the pseudonym domains, `manifest.json`, `install-state.json` | The product reads its own files back. Nothing outside the product should read them. |
| **Log** | clean, discard authorization, isolate, purge, auto-purge, recover | Append-only evidence. People read it, and so do two named readers. |

A removal or a break of a **Stable** format needs notice in one published minor version: the CHANGELOG and this
document announce it, and the old form is still written or accepted during that version.

### Stable: evolution and deprecation

- **Documents** (`atm.audit/1`, `atm.diagnose/2`): a new field may be added without changing the version. Consumers
  must ignore fields they do not know. Each of these needs `/n+1`:
  - removing a field or renaming it;
  - changing a field's type or meaning;
  - making an optional field mandatory.
- **Strict inputs** (`monitor.json`, the quarantine policy): **a new key is a new version of the file.** The reader of
  the current version refuses every key it does not know, as a whole file, with its existing code. A newer file given
  to an older copy is therefore refused, never half read. When a second version exists, the reader will accept both
  versions for the whole 1.x line. No second version exists today, and none is defined here.
- **Exit codes**: a verb may gain a new code only for a new outcome. An existing code never changes its meaning for a
  verb. The suite's table and both copies of the table (here and in [USAGE.md](USAGE.md#exit-codes)) change together.
- **Deprecation**: the old version is still written, or still accepted, for one published minor version after the new
  one. The CHANGELOG and this document announce it.

### Internal: evolution

The product may change an internal format in any version. A change must keep reading what an earlier published
version wrote, or refuse it with a code. It never misreads it. Each internal format the product reads back has a fixed
fixture of its current form in the suite, and a test that an unknown version is refused.

### Log: evolution

A new field or a new record type may be added. The version changes only when a record's meaning changes. Each reader
checks the schema id it knows and refuses any other.

## Naming conventions

There are two conventions, and both are kept.

- **`atm.x/n` names a document**: a file or a JSON line the product writes and something reads (`atm.audit/1`,
  `atm.monitor/1`, `atm.cleanlog/1`).
- **`atm-x/n` names a hash domain**: the fixed prefix of the text that is hashed into an id or a pseudonym. It names no
  document. The plan ids (`atm-recover-plan/1`, `atm-clean-plan/1`) and the pseudonym domains (`atm-session/2`) use it.

The two recovery plan ids keep their names (ADR-0018 section 2.3), even though they look like the odd ones out.
Renaming a domain changes every id hashed from it:
- a plan shown before an update would no longer match at `recover start`;
- the `undo` provenance of recorded runs would break.

**`schemaVersion` and `schema`.** `atm.diagnose/2` names its version field `schemaVersion`. Every other document and
log names it `schema`, `atm.audit/1` included. Both names stay as they are: renaming `schemaVersion` would break every
reader of `atm.diagnose/2`.

## Human-readable text is not an interface

The text of `audit`, `preview`, the TUI, the GUI, `version`, `monitor status` and every message is not a format. It is
translated (`-Lang`, `ATM_LANG`), it changes between versions without notice, and scripts must **never parse** it.
Scripts read the exit code, and the JSON exports where they exist. JSON documents carry language-neutral codes; only
the `language` field says which language the run used.

## Stable formats

### `audit -ExportJson`: `atm.audit/1`

- **Schema id:** `atm.audit/1`, the first member (`schema`), in `src/lib/Report.ps1:230`.
- **Producer:** `ConvertTo-AtmExportJson` (`src/lib/Report.ps1:225-241`), written by `agent-temp audit -ExportJson
  <new file>` (`src/agent-temp.ps1:287-293`) to a new file outside the audited directories.
- **Consumer:** none in the repository. The installer's end-to-end test only parses it.
- **Compatibility:** V1.0 S2 added `schema` as the first member. The rest of the document is byte for byte the same as
  before, so a reader of the old export that ignores unknown fields reads the new one unchanged.
- **Privacy:** the export writes the machine name, the account names, the SIDs and the paths as they are, without
  pseudonyms. It is a local file the operator asks for, outside the audited directories. `atm.diagnose/2`
  pseudonymizes instead ([ADR-0010](adr/ADR-0010-pseudonymization-of-exported-identifiers.md)). A pseudonymized audit export
  would be a new version, and a decision of its own. See [SECURITY-MODEL.md](SECURITY-MODEL.md).

| Object | Members, in order |
|---|---|
| top level | `schema`, `toolVersion`, `language`, `machine`, `user`, `startedUtc`, `coverageComplete`, `processes`, `profiles`, `partitions` |
| `processes` | `total`, `readable`, `uninspectable`, `failed` |
| `profiles[]` | `sid`, `user`, `path`, `origin`, `status` |
| `partitions[]` | `sid`, `user`, `project`, `projectIdentified`, `projectSource`, `scope`, `kind`, `path`, `class`, `bytes`, `allocatedBytesEstimate`, `files`, `dirs`, `directChildren`, `reparsePoints`, `errors`, `measurementComplete`, `creationUtc`, `lastWriteUtc`, `newestWriteUtc`, `flags`, `evidence`, `fingerprint` |

Times are ISO 8601 UTC. `creationUtc` and `fingerprint` may be `null`. `flags` and `evidence` are always arrays of
codes. The export holds aggregates only: no file listing, no command line, no session file content.

### `diagnose -ExportJson`: `atm.diagnose/2`

- **Schema id:** `atm.diagnose/2` in `src/lib/Engine.Diagnose.ps1:3066`, written as `schemaVersion`
  (`src/lib/Report.ps1:1283`).
- **Producer:** `ConvertTo-AtmDiagnoseJson` (`src/lib/Report.ps1:1275`).
- **Consumer:** none in the repository. The export is behind `AtmDiagnoseExportEnabled`, closed in every copy, so no
  copy writes the file today.
- **Fields:** [DIAGNOSE-SCHEMA.md](DIAGNOSE-SCHEMA.md), the field-level specification, with its compatibility rules.

### `monitor.json`

- **Schema id:** none. The file is a strict input, and its version is its set of keys: `totalGiB`, `growthGiBPerDay`,
  `orphanSuspectedGiB`, `livenessUnknownGiB`, `failedCollections` (`AtmMonitorConfigFields`,
  `src/lib/Engine.Monitor.ps1:59`).
- **Producer:** the user, in the history folder. The product never writes, creates or fixes it.
- **Consumer:** `Get-AtmMonitorConfig` (`src/lib/Engine.Monitor.ps1:943`), through `Get-AtmMonitorConfigValues` (`:913`).
  A key it does not know refuses the whole file with `MON_CONFIG_INVALID` (reason `UNKNOWN_KEY`, `:930`); the
  defaults apply. Bounds and defaults: [USAGE.md](USAGE.md).

### `config\quarantine.policy.json`: `atm.quarantine-policy/1`

- **Schema id:** `atm.quarantine-policy/1` in `src/lib/Engine.Isolate.ps1:45`. The members are `schema`,
  `retentionDays`, `quotaBytes` and `autoPurge`, nothing else (`:718`).
- **Producer:** the administrator of the installation.
- **Consumer:** `Get-AtmQuarantinePolicy` (`src/lib/Engine.Isolate.ps1:690`), for `quarantine` and the automatic purge.
  A file that breaks the schema, a key it does not know or another version included, counts as off: the defaults
  apply, with the warning `QUARANTINE_POLICY_INVALID`.

### Exit codes

Stable contract, per verb. Each row lists the codes that verb's own code can return. Every verb can also return the
codes of the first row. A script must read the code together with the verb, because the same number means a different
outcome in different verbs.

<!-- atm-exit-codes:begin -->
| Verb | Codes | Meaning |
|---|---|---|
| `(every verb)` | 5, 10 | `5` integrity mismatch, nothing loaded (also when the integrity check of an installed copy fails); `10` unexpected error (every verb except `verify`) |
| `verify` | 0, 4, 5 | `0` every listed file matches; `4` no manifest (not an installation); `5` a problem |
| `gui` | 0, 7, 8 | `0` the window opened and closed; `7` GUI gate closed (every copy); `8` no window can be shown here |
| `tui` | 0, 6 | `0` closed; `6` no interactive console |
| `audit` | 0 | `0` shown, and exported with `-ExportJson`; a refused export ends with `10` |
| `preview` | 0 | `0` shown |
| `diagnose` | 0, 2, 10 | `0` ran (partial coverage included); `2` key file refused; `10` export refused or not written (its gate is closed in every copy) |
| `clean` | 0, 2, 3, 6 | `0` done; `2` invalid invocation; `3` aborted or stopped, nothing deleted; `6` interactive console needed (only with deletion enabled) |
| `isolate` | 0, 2, 3, 6 | `0` done; `2` no path or allow list, a missing allow list, `-IncludeOtherUsers`, or a refused log file; `3` stopped after the plan, nothing moved; `6` interactive console needed (only past its gate) |
| `authorize` | 0, 2, 3, 6 | `0` recorded; `2` missing `-Path` or `-RecordFile`; `3` not recorded; `6` no interactive console |
| `quarantine` | 2 | no subcommand or an unknown one; with any subcommand, an `-Entry` that is not an entry id |
| `quarantine list` | 0, 2 | `0` shown |
| `quarantine inspect` | 0, 2, 3 | `0` shown; `2` no `-Entry`; `3` no such entry |
| `quarantine verify` | 0, 2 | `0` checked; `2` neither `-Entry` nor `-All` |
| `quarantine restore` | 0, 2, 3, 6 | `0` done; `2` no `-Entry`, or a refused log file; `3` stopped after the plan; `6` interactive console needed (only past its gate) |
| `quarantine purge` | 0, 2, 3, 6 | `0` done; `2` no `-Entry`, or a refused log file; `3` stopped after the plan; `6` interactive console needed (only past its gate) |
| `quarantine schedule-autopurge` | 0, 2, 3, 6 | `0` scheduled; `3` refused or not confirmed; `6` interactive console needed |
| `quarantine unschedule-autopurge` | 0, 2, 3, 6 | `0` removed; `3` refused or not confirmed; `6` interactive console needed |
| `recover list, plan` | 0, 2, 3, 10 | `0` shown or offered; `2` usage; `3` plan refused; `10` collection failed |
| `recover start, undo` | 2, 3, 5, 10, 20-31, 40-44 | the codes of the recovery command, each outcome in its table in [USAGE.md](USAGE.md#recover-start-and-recover-undo-v04-r4); `27` in every copy |
| `monitor` | 0, 2, 3, 6 | `0` status shown, or the action done and read back; `2` usage; `3` refused, not confirmed or stopped (always, with the gate closed); `6` interactive console needed |
| `version` | 0 | `0` shown |
| `help` | 0 | `0` shown (also `-h`, `--help` and `/?`) |
| `(unknown command)` | 1 | `1` unknown command |
| `bin\agent-temp-monitor.ps1` | 0, 2, 3, 5, 10 | collector entry point: `0` one collection recorded; `2` an argument; `3` gate closed or collection refused; `5` integrity; `10` unexpected |
| `bin\agent-temp-autopurge.ps1` | 0, 2, 3, 5, 10 | automatic purge entry point: `0` off, report only, quarantine absent, or done; `2` an argument; `3` minimum retention, lock, or a pass stopped on an error; `5` integrity; `10` unexpected |
<!-- atm-exit-codes:end -->

**Overloaded codes.** Four codes mean different things in different verbs:
- `2` is a usage error, but also a refused key file in `diagnose` and a refused log file in `isolate`, `quarantine restore`
  and `quarantine purge`;
- `3` is a refusal, a stop after the plan, or "not recorded";
- `6` is "no interactive console" in nine rows of the table;
- `10` is an unexpected error, but also a refused `diagnose` export and a failed `recover` collection.

They stay as they are: renumbering them would break the scheduled tasks and the scripts.

**Known limit.** A failure before the launcher's main error handler can run, such as a library or a provider that does
not load in a source checkout, ends with PowerShell's own code for an uncaught error, usually `1`. That collides with
"unknown command". An installed copy whose integrity check fails ends with `5` instead. The `agent-temp.cmd` shim only relays the launcher's code (`exit /b %ERRORLEVEL%`); if Windows PowerShell itself cannot start, the code is cmd's own.

## Internal formats

| Format | Schema id (file:line) | Producer | Consumer | Fixture test |
|---|---|---|---|---|
| monitoring record | `atm.monitor/1` (`src/lib/Engine.Monitor.ps1:30`, written `:315`) | the collector, behind the monitoring gate | `Test-AtmMonitorRecordText` (`:382`): exact members, types, hash, the time of the name; anything else is skipped as `HISTORY_RECORD_INVALID` | yes (S2) |
| quarantine manifest | `atm.quarantine/1` (`src/lib/Engine.Isolate.ps1:33`, written by `Write-AtmIsolationRecord` `:177`) | `isolate`, `quarantine restore`, `quarantine purge` | `Read-AtmQuarantineManifest` (`:536`) and `Get-AtmQuarantineEntrySummary` (`:597`): another schema is `MANIFEST_INVALID`, and the entry is never restored or purged | yes (S2) |
| clean plan id | `atm-clean-plan/1` (`src/lib/Engine.Clean.ps1:817`) | the clean plan | the plan check of `clean` | hash domain |
| isolation plan id | `atm-isolate-plan/1` (`src/lib/Engine.Isolate.ps1:114`) | the isolation plan | the plan check of `isolate` | hash domain |
| restore plan id | `atm-restore-plan/1` (`src/lib/Engine.Isolate.ps1:845`) | the restore plan | `quarantine restore` | hash domain |
| purge plan id | `atm-purge-plan/1` (`src/lib/Engine.Isolate.ps1:1177`) | the purge plan | `quarantine purge` | hash domain |
| recovery plan id | `atm-recover-plan/1` (`src/lib/Engine.Recover.ps1:59`) | `Get-AtmRecoverPlanId` (`:255`) | `recover start` (the id the operator confirms) | hash domain |
| undo plan id | `atm-recover-undo-plan/1` (`src/lib/Engine.Recover.ps1:722`) | the undo plan | `recover undo` | hash domain |
| pseudonym domains | `atm-repository/1`, `atm-worktree/1` (`src/lib/Engine.Diagnose.ps1:2665-2666`), `atm-repository-target/1` (`:2723`), `atm-key-id/1` (`:2935`), `atm-session/2` (`:2965`), `atm-partition/1` (`:2973`), `atm-virtual-machine/1` (`:4126`) | the diagnose | the pseudonyms inside `atm.diagnose/2` | hash domain |
| `manifest.json`, `install-state.json` | none | the installer | the launcher's integrity check and `verify` | the installation area |

ADR-0018 section 2.1 names the recovery plan ids. The clean, isolation, restore and purge plan ids are the same kind
of value, a hash domain the product checks against itself, and are classed with them.

A hash domain is not a file: nothing reads it back except the product, and only in the same version that wrote it.
Changing a domain's text changes every id built from it, so a plan shown before an update no longer matches after it.
That is refused, never misread.

## Logs

| Log | Schema id (file:line) | Writer | Readers, and the schema each knows |
|---|---|---|---|
| clean | `atm.cleanlog/1` (`src/lib/Engine.Clean.ps1:321`) | `clean`, past the deletion gate | the operator; the pilot summary (`tools/v5-pilot/Get-AtmPilotSummary.ps1:83`), which knows `atm.cleanlog/1` |
| discard authorization | `atm.discard-authorization/2` (`src/lib/Engine.Clean.ps1:769`) | `authorize` | the operator only; nothing in the product reads it |
| isolate | `atm.isolatelog/1` (`src/lib/Engine.Isolate.ps1:32`) | `isolate` and `quarantine restore`, past their gate | the operator; the pilot summary, which knows `atm.isolatelog/1` |
| purge | `atm.purgelog/1` (`src/lib/Engine.Isolate.ps1:47`) | `quarantine purge`, past its gate | the operator; the pilot summary, which knows `atm.purgelog/1` |
| auto-purge | `atm.autopurgelog/1` (`src/lib/Engine.Isolate.ps1:51`) | `bin\agent-temp-autopurge.ps1` | the operator; the pilot summary refuses it (`LOG_SCHEMA_UNKNOWN`) |
| recover | `atm.recoverlog/1` (`src/lib/Engine.Recover.ps1:337`) | `recover start` and `recover undo`, past their gate | the operator; `recover undo` (`Read-AtmRecoverRunLog`, `src/lib/Engine.Recover.ps1:938`), which knows `atm.recoverlog/1` |

The pilot summary refuses a schema outside its list (`LOG_SCHEMA_UNKNOWN`) and a log that mixes two schemas
(`LOG_SCHEMA_MIXED`). `recover undo` refuses another schema as `UNDO_SOURCE_INVALID`, before anything is collected,
shown or asked.

## Tests

The area "Contratos de formato" of `tests/Run-Tests.ps1` runs in both shells.

| Format | Case |
|---|---|
| `atm.audit/1` | "atm.audit/1: schema e o primeiro campo": over the V10-S1 golden fixture, the export of before (the function of `ede257d`, embedded verbatim) plus the `schema` line equals the export of now, byte for byte |
| `atm.audit/1` | "atm.audit/1: golden da versao": the shape of the document (each path, the members in order, the JSON type) equals the golden, with no member more or less; a member removed and one added are reported |
| `atm.diagnose/2` | "atm.diagnose/2: golden da versao": the same, over the golden fixture with every diagnose source injected; the field-level test against [DIAGNOSE-SCHEMA.md](DIAGNOSE-SCHEMA.md) stays in the area "Diagnose" |
| exit codes | "Codigos de saida por verbo": the table here and the one in USAGE equal the suite's table; a static reading of every `exit` of the launcher and of the two entry points gives the same codes per verb, with the non-literal exits resolved from `Invoke-AtmGuiCommand`, the recovery code table and the collector's `ExitCode` values; no other script of `src` has an `exit`, and the shim only relays the code; a planted `exit 9`, an exit that cannot be resolved, an `exit` planted in a library, and a code removed from or added to the table each fail |
| exit codes | "Codigos da recuperacao nos dois sentidos": every literal code of the recovery engine's four exit functions is in its table, and every code of the table is literal, relayed or an outcome |
| `monitor.json` | "monitor.json (entrada estavel)": the five keys accepted with their values; `schema`, a key in another case and another key each refuse the file with `MON_CONFIG_INVALID` (`UNKNOWN_KEY`); the key list is pinned. The full reader is covered in the area "V0.5 M2" ("M2: monitor.json (so leitura)") |
| `atm.quarantine-policy/1` | "atm.quarantine-policy/1 (entrada estavel)": the four members accepted with their values; an unknown key, a key in another case, another version and no schema each give `QUARANTINE_POLICY_INVALID`. The full reader is covered in the area "Isolamento P4" ("Politica config\quarantine.policy.json") |
| monitoring record | "Registro do monitoramento (interno)": a fixed `atm.monitor/1` record, embedded in the suite, read by the current code; the same record with another version (hash recomputed) refused with `SCHEMA`. Also the area "V0.5 M1" ("M1: leitor") |
| quarantine manifest | "Manifesto da quarentena (interno)": a fixed `atm.quarantine/1` manifest, embedded in the suite, read by the current code (state, counts, verification, expiry); with another version the entry is `ENTRY_MANIFEST_INVALID` (`MANIFEST_INVALID`). Also the area "Isolamento P3b" |
| this document | "FORMATS.md: o inventario fechado de ids de schema": every schema id of the code is listed here with its file, and every id listed here is in the code |
| logs | the area "V5 tools" ("Resumo (V5-TOOLS-ISO)": `LOG_SCHEMA_UNKNOWN`, `LOG_SCHEMA_MIXED`) and the area "V0.4 R3" ("R3 origem recusada": another schema is `UNDO_SOURCE_INVALID`) |

Exit codes are also run in child processes in other areas, with every gate closed:
- "Instalacao" (`verify`: `0`, `4` and `5`);
- "GUI P1" (`7`, and `8` simulated);
- "Diagnose" P5-B (`version`, `help`: `0`; an unknown command: `1`);
- "Isolamento P2" (`isolate`: `2`, `3`);
- "Isolamento P6a" (the automatic purge entry point: `2`, `3`, `5`, `0`);
- "V0.5 M3a" (the collector entry point: `2`, `3`, `5`; `monitor enable`: `3`);
- "V0.4 R1" (`recover list`: `0`; `recover plan`: `3`; usage: `2`);
- "V0.4 R4" (`recover start`: `27`);
- "Autorizacao de descarte (AUT-1)" (`authorize`: `2`, `6`).
