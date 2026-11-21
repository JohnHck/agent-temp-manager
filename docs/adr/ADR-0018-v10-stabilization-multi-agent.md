# ADR-0018: V1.0 stabilization and multi-agent support

Status: PROPOSED (V10-D1 to V10-D8 open; nothing implemented)
Date: 2026-11-21
Phase: V1.0 (phases S0 to S7 below, each a future round with its own contract and tests)

This record designs V1.0 ([ROADMAP, "V1.0 — Stabilization and multi-agent support"](../ROADMAP.md)). It is a design
only. It changes no code, no test, no format and no gate. Every line reference is to `main` at `d7b03a9` (after V05-M5).
The decisions it asks for are listed in section 10. The maintainer decides each one; the record recommends but does not
decide.

## Context

The ROADMAP asks V1.0 for the following.

**Deliverables:**
- a stable, versioned provider contract;
- documentation for third-party providers;
- at least one provider beyond the Claude scenarios;
- stable CLI and JSON output formats, with compatibility rules;
- a completed security review of every engine and of the installer.

**Acceptance:**
- every earlier acceptance criterion still holds;
- clean-environment, elevated and multi-user tests pass;
- the full privilege matrix passes on Windows 10 and 11, with PowerShell 5.1 and 7;
- a new provider can be added without changing the engines.

**Safety limits:** those of V0.3 and V0.4. A provider can never weaken a gate.

Rules already in force:
- **D-A (maintainer):** a version lands on `main` dark, behind closed gates, with its acceptance proven in CI. Opening a
  gate, publishing and tagging are the maintainer's decisions.
- **Today on `main`:**
  - nine gates, all `$false`: `AtmRealDeletionEnabled`, `AtmWorktreeDiagnosticsEnabled`, `AtmHandleDiagnosticsEnabled`,
    `AtmIsolationEnabled`, `AtmQuarantinePurgeEnabled`, `AtmMonitoringEnabled`, `AtmRecoveryEnabled`, `AtmGuiEnabled` and
    `AtmDiagnoseExportEnabled`;
  - V0.2.1, 0.3.x, V0.4 and V0.5 are on `main` and unpublished;
  - 0.3.0 is the latest published version;
  - the acceptance of V0.3 real deletion waits for the V5 pilot in a disposable VM ([ADR-0015](ADR-0015-v5-pilot-disposable-vm.md)),
    which is the operator's.

## 1. The provider contract today

### 1.1 What `Register-AtmProvider` validates

`src/lib/Engine.Audit.ps1`:

| Line | Rule |
|---|---|
| :35-36 | `AtmProviderMembers`: `Id`, `DisplayName`, `TempSubdir`, `ScopePattern`, `RootPattern`, `EnvVarNames`, `GetExtraTempDirs`, `GetConfigDirs`, `GetSessionEvidence`, `GetActivityEvidence`, `GetProjectKey` (the eleven `temp` members). |
| :39 | Capability names: `temp`, `runtime`. |
| :40 | Runtime members: `GetProcessMatchers`, `GetServiceHints`, `GetVirtualizationHints`, `GetWorktreeHints`. |
| :42-54 | `Get-AtmProviderContract`: no `ContractVersion` means v1 with `@('temp')`. `ContractVersion` must parse as the integer `2`, or `err.providerContract` is thrown. `Capabilities` must be non-empty, of exact strings from :39 and without duplicates (`err.providerCapabilities`). |
| :58-64 | `Test-AtmProviderId`: v1 `-match '^[a-z0-9-]+$'` (case-insensitive); v2 `-cmatch` (lower case exactly). |
| :71-72 | With `temp`: all eleven members must be present; without it, only `Id` and `DisplayName` (`err.providerMember`). |
| :74 | With `temp`: `TempSubdir` must match `^[A-Za-z0-9._-]+$` (`err.providerSubdir`). |
| :75-78 | A runtime member, when present, needs the `runtime` capability and must be a script block (`err.providerRuntimeMember`). |
| :79-80 | The same `Id` registered again replaces the earlier object. |

What is **not** validated at registration:
- the types of `DisplayName`, `ScopePattern`, `RootPattern` and `EnvVarNames`;
- that the eleven `temp` members are script blocks or that the patterns are valid regexes;
- anything a member returns.

Return values are checked where they are read: the runtime hints in `Engine.Diagnose.ps1:240-264` (`Test-AtmHintItem`, `Test-AtmServiceExpectedImage`) and `:266-305`. The
`temp` members are read as they are, and a missing field is read as `$null`.

### 1.2 Where an engine reads a provider member

| Engine (file:line) | Member and field read | Effect |
|---|---|---|
| Audit `:757` | `Get-AtmProviderCapabilities` | only `temp` providers enter the inventory |
| Audit `:764`, `:85-90` | `EnvVarNames` | which per-user variables are read from the registry |
| Audit `:783` | `GetExtraTempDirs($ProfileInfo)` → items `{TempPath; Source}` | extra TEMP candidates |
| Audit `:788` | `TempSubdir` | the base `<TEMP>\<TempSubdir>` |
| Audit `:790`, `:799`, `:815`, `:831`, `:597`, `:928` | `Id` | base and partition records, registry key |
| Audit `:872`, `:1107` | `ScopePattern` | scope recognized; `UNRECOGNIZED_SLUG` (a hard flag, `:21-22`) |
| Audit `:885` | `RootPattern` | `SessionRoot` versus other kinds |
| Audit `:929` | `GetSessionEvidence($ProfileInfo, $Snapshot)` → `Readable`, `Unparseable`, `Entries` | the registry of a profile |
| Audit `:1110-1111` | `Readable`, `Unparseable` | `SESSION_REGISTRY_UNREADABLE`, `SESSION_REGISTRY_ENTRY_UNPARSEABLE` |
| Audit `:1118-1128` | `Entries[].SessionId`, `.State`, `.Pid` | `LIVE` (live session evidence), `SESSION_PID_ALIVE_UNVERIFIED`, `SESSION_LIVENESS_UNVERIFIABLE`, evidence |
| Audit `:285-288` | `Entries[].Scope`, `.ProjectName` | project display name only |
| Audit `:1114` | `GetConfigDirs($ProfileInfo).Known` | `CONFIG_DIR_UNKNOWN` |
| Audit `:1130-1134` | `GetActivityEvidence($ProfileInfo, $Scope, $RootName)` → `Readable`, `LastWriteUtc` | `TRANSCRIPTS_UNREADABLE`, `TRANSCRIPT_RECENT` (`AtmRecentHours = 72`, `:16`) |
| Audit `:268-269` | `GetProjectKey($Scope, $ProfilePath)` → `IsHome`, `Key` | project display name only |
| Audit `:1122`, `:985`; Report `:97`; launcher `agent-temp.ps1:604` | `DisplayName`, `TempSubdir` | text only |
| Diagnose `:4975-4996` | contract, `Id`, `DisplayName` | `PROVIDER_CONTRACT_INVALID` coverage for a provider that fails the contract; the provider list of the export |
| Diagnose `:220-224`, `:266-305` | `GetProcessMatchers`, `GetServiceHints`, `GetVirtualizationHints` (validated items) | process, service and VM attribution; `HINT_FAILED_*` / `HINT_MALFORMED_*` |
| Diagnose `:5049`, `:5071`, `:1090-1113` | `GetSessionEvidence` again; `Entries[].SessionId`, `.Pid`, `.StartUtc` | session records and the exact identity rule |
| Recover `:99-114` | contract, `Id`, `GetServiceHints` (through `Get-AtmProviderRuntimeHints`) | declared services only |
| Clean `:174` | the partition's provider **id**, `'claude-code'` | the B1 restricted exception (V0.3) applies only to Claude Code roots |
| Isolate `:468`; Monitor `:229`, `:255` | the partition's provider id, copied from the inventory | records only; no provider member is called |

### 1.3 Gaps between the contract and the code

- **Validated but never called:** `GetWorktreeHints`.
  - It is accepted at registration (`:40`, `:75-78`) and documented in `docs/PROVIDERS.md:55` as "used from V0.2-P3".
  - No engine calls it, and no shipped provider declares it.
  - The worktree discovery (ADR-0007) uses other sources.
- **Returned but never read by an engine:**
  - `GetConfigDirs().Dirs` and `.Refused`: only `.Known` is read (`Engine.Audit.ps1:1114`). `Dirs` and `Refused` are used only inside `ClaudeCode.ps1`.
  - `GetSessionEvidence().Notes` (`ClaudeCode.ps1:58`, `:68`): no engine, report or TUI reads it, and the contract does not document it.
  - `GetExtraTempDirs()[].Source`: copied into the base records, which is what reports show. The `{TempPath; Source}` shape is documented only in the header of `ClaudeCode.ps1:9`, not in `docs/PROVIDERS.md:15`.
- **Inputs the engine passes, never documented:**
  - `$ProfileInfo`, of which providers read `EnvValues`, `EnvKnown`, `ProfilePath` and `Sid` (`ClaudeCode.ps1:31-46`);
  - `$Snapshot`, of which they read `Processes[].Pid`, `.CreationUtc` and `.Failed` (`ClaudeCode.ps1:56`, `:86-92`).

  A third-party provider can only learn these by reading the Claude Code provider.
- **An engine that depends on a provider id:** `Engine.Clean.ps1:174`. A new provider never gets the B1 restricted
  exception: it fails closed and is stricter, not weaker. A new provider therefore needs no engine change, but its roots
  stay under the full B1 rule. Extending the exception to it would be an eligibility change, which section 8 forbids
  without a decision of its own.
- **The liveness tolerance is in the provider:** `ClaudeCode.ps1:92` uses `-lt 2` seconds to turn a matching PID into
  `LIVE`. The engine trusts `State` (`Engine.Audit.ps1:1120-1126`). A provider that returned `DEAD` too readily would
  weaken the liveness evidence. Today this is a provider rule, not an engine-enforced one, and section 3 makes it a
  conformance check.

### 1.4 Versioning (proposal)

- **The stable contract is contract 2, frozen.** V1.0 documents it completely, including the inputs, the return shapes
  and the reserved members of 1.3. It does not bump the number.
  - Reason: the gaps in 1.3 are documentation gaps. Closing them changes no accepted value, so a new number would only
    force every provider to change one line.
- **Compatible change** (no version change):
  - a new optional runtime member, which engines read as "no hints" when absent;
  - a new optional field in a return value, which engines read as "no evidence" when absent, never as a negative fact (as `StartUtc` was added);
  - a new capability name that existing providers do not declare;
  - a stricter validation of a value that no shipped or documented provider uses.
- **Breaking change** (needs `ContractVersion = 3`):
  - a new required member;
  - a removed member;
  - a member or field whose meaning changes;
  - an argument added, removed or reordered (arguments are positional, `docs/PROVIDERS.md:21`);
  - an existing optional field becoming required.
- **How a provider declares its version:** `ContractVersion = <integer>` and `Capabilities`, as today. A missing
  `ContractVersion` stays v1.
  - v1 stays accepted throughout 1.x. Its removal is a breaking change of the product and needs a deprecation notice
    in one published minor version first.
- **An unknown version: refused, with the reason shown** (fail closed):
  - At registration, `Get-AtmProviderContract` already throws `err.providerContract` for any value but 2 (`:48`).
  - In diagnose and recover, the provider becomes coverage `FAILED` with `PROVIDER_CONTRACT_INVALID` and takes no part in the run (Diagnose `:4983-4988`, Recover `:102-107`).
  - **Gap to close in S1:** provider files are dot-sourced at `agent-temp.ps1:216`, before the main `try` (`:247`). A provider whose registration throws therefore stops the launcher:
    - the error message, `err.providerContract` included, is shown;
    - no command runs, the other providers included;
    - the exit code is PowerShell's for an uncaught error, not one of the documented codes.

    In an installed copy, only manifest-verified provider files are loaded (`:212`), so this takes a shipped provider that fails its own contract. V10-D5 asks whether the product should instead refuse that one provider, record it and go on.
- **Reserved members:**
  - `GetWorktreeHints` stays validated, so a third-party provider that declares it keeps loading. It is documented as "reserved: not called in 1.x".
  - Removing it would break such a provider. Calling it would be a new feature, behind the worktree diagnostics gate.

### 1.5 Changes proposed to the contract

| Change | Kind | Proof that classification, eligibility, B1 and RECENT do not change |
|---|---|---|
| Document `$ProfileInfo`, `$Snapshot`, the `GetExtraTempDirs` items, `Readable` semantics and the `State` values as the contract | docs only | no code changes; the existing suite stays green unchanged |
| Mark `GetWorktreeHints` reserved, and `Dirs`/`Refused`/`Notes` provider-private | docs only | as above |
| A conformance helper `Test-AtmProviderConformance` in the suite (section 3), not in `src/` | tests only | not shipped; no engine change |
| Optionally: validate at registration that the eleven `temp` members are script blocks and that `ScopePattern`/`RootPattern` compile as regexes (today a bad value throws later, at use) | stricter validation (compatible: both shipped providers pass) | the change only moves a failure earlier. A golden test runs `Invoke-AtmInventory` on the existing fixtures before and after and compares the partitions' `Class`, `Flags`, `Eligible`, the B1 result and `TRANSCRIPT_RECENT` field by field; any difference fails |

No member's meaning changes. The engine's safety logic (flags, gates, B1, RECENT, the 72 hours) stays in the engines.

## 2. CLI and JSON formats

### 2.1 Inventory

| Output | Schema id (file:line) | Produced by | Consumed by | Proposed promise |
|---|---|---|---|---|
| `audit -ExportJson` | **none**: no schema field (`Report.ps1:225-241`); it has `toolVersion` | `ConvertTo-AtmExportJson` | no consumer in the repository (the suite checks it) | **stable**, once it gains `schema = "atm.audit/1"` (additive, S2) |
| `diagnose -ExportJson` | `atm.diagnose/2` (`Engine.Diagnose.ps1:3066`, field `schemaVersion`, `Report.ps1:1283`); spec `docs/DIAGNOSE-SCHEMA.md` | `ConvertTo-AtmDiagnoseJson` | none in the repository; the export is behind `AtmDiagnoseExportEnabled` (closed) | **stable**: its rules exist (`DIAGNOSE-SCHEMA.md:19-20`) |
| monitoring record | `atm.monitor/1` (`Engine.Monitor.ps1:30`, `:315`) | the collector (behind the monitoring gate) | the reader, strict (`:401`, unknown keys refused) | **internal** (the product reads its own files; not a public interface) |
| `monitor.json` | **none**: strict keys `AtmMonitorConfigFields` (`Engine.Monitor.ps1:59-61`); an unknown key is `MON_CONFIG_INVALID` | the user | the monitoring reader | **stable input** (users write it); adding a key is breaking for older copies, which fall back to defaults and say so |
| clean log | `atm.cleanlog/1` (`Engine.Clean.ps1:321`, `:350`) | `clean` (past the deletion gate) | the operator; `tools/v5-pilot/Get-AtmPilotSummary.ps1:83` | **log** (append-only evidence; readable, not an API) |
| discard authorization | `atm.discard-authorization/2` (`Engine.Clean.ps1:769`, `:1002`) | `authorize` | the operator; nothing in the product reads it (`:758-768`) | **log** |
| isolation log | `atm.isolatelog/1` (`Engine.Isolate.ps1:32`) | `isolate` (past its gate) | the operator; pilot summary | **log** |
| quarantine manifest | `atm.quarantine/1` (`Engine.Isolate.ps1:33`; checked `:555`) | `isolate`, `restore`, `purge` | `quarantine list/restore/purge` | **internal** (read back strictly by the product) |
| quarantine policy | `atm.quarantine-policy/1` (`Engine.Isolate.ps1:45`; strict `:719`) | the administrator | `quarantine` and the auto-purge | **stable input** |
| purge log | `atm.purgelog/1` (`Engine.Isolate.ps1:47`) | `quarantine purge` | the operator; pilot summary | **log** |
| auto-purge log | `atm.autopurgelog/1` (`Engine.Isolate.ps1:51`) | the auto-purge entry point | the operator | **log** |
| recovery plan id | `atm-recover-plan/1` (`Engine.Recover.ps1:59`, `:264`) | `Get-AtmRecoverPlanId` | `recover start` (the id the operator confirms) | **internal hash domain**, not a document (see 2.3) |
| undo plan id | `atm-recover-undo-plan/1` (`Engine.Recover.ps1:722`, `:1087`) | the undo plan | `recover undo` | **internal hash domain** |
| recovery log | `atm.recoverlog/1` (`Engine.Recover.ps1:337`, `:430`) | `recover start/undo` (past their gate) | `recover undo` (provenance) and the operator | **log**, read back strictly by `undo` |
| pseudonym domains | `atm-session/2`, `atm-partition/1`, `atm-repository/1`, `atm-worktree/1`, `atm-repository-target/1`, `atm-virtual-machine/1`, `atm-key-id/1` (`Engine.Diagnose.ps1:2665-2973`, `:4126`) | the diagnose | the pseudonyms in `atm.diagnose/2` | **internal hash domains** |
| `manifest.json`, `install-state.json` | none | the installer | the launcher and `verify` | **internal** |
| exit codes | `docs/USAGE.md:1372-1386`, plus per-verb lists (`:229`, `:419`, `:687`, `:975`, `:1013`, `:1220`, `:1316`) | every verb | scripts and the scheduled tasks | **stable** |
| human-readable text (audit, TUI, GUI, `version`) | none | the reports | people | **not stable** (translated text; never parse it) |

**Exit codes per verb, as documented at `d7b03a9`.** This table is the starting point of the per-verb contract proposed
in 2.3; it adds no code and changes none.

| Verb | Codes | Source |
|---|---|---|
| any (launcher) | `1` unknown command; `4` no manifest (`verify` only); `5` integrity mismatch, nothing loaded | `docs/USAGE.md:1374-1387` |
| `diagnose` | `0` ran (partial coverage included); `2` key file refused; `10` export refused or not written, or unexpected | `docs/USAGE.md:229-231` |
| `clean` | `2` invalid invocation; `3` aborted, nothing deleted; `6` interactive console needed (only with deletion enabled) | `docs/USAGE.md:1374-1387` |
| `authorize` | `0` recorded; `2` missing `-Path` or `-RecordFile`; `3` not recorded; `6` no interactive console | `docs/USAGE.md:419-421` |
| `isolate`, `quarantine restore`, `quarantine purge` | `2` usage (`isolate` without a path or with `-IncludeOtherUsers`); `3` stopped after the plan | `docs/USAGE.md:1374-1387` |
| `quarantine schedule-autopurge`, `unschedule-autopurge` | `3` refused or not confirmed; `6` interactive console needed | `docs/USAGE.md:1374-1387` |
| automatic purge (scheduled entry point) | `0` off, report only, quarantine absent, or done; `2` argument; `3` minimum retention, lock, or a pass stopped on an error; `5` integrity; `10` unexpected | `docs/USAGE.md:687-688` |
| `recover list`, `recover plan` | `0` shown or offered; `2` usage; `3` plan refused; `10` collection failed | `docs/USAGE.md:975-981` |
| `recover start`, `recover undo` | `2`, `3`, `5`, `10`, then `20` to `31` and `40` to `44` (each outcome in its table); `27` in every copy | `docs/USAGE.md:1013` and the table after it, `:1386-1387` |
| `monitor` | `0` status, or enable/disable/remove-history done and read back; `2` usage; `3` refused, not confirmed or stopped (always, with the gate closed); `6` interactive console needed | `docs/USAGE.md:1316-1323` |
| collector entry point `bin\agent-temp-monitor.ps1` | `0` one collection recorded; `2` an argument; `3` gate closed or collection refused; `5` integrity (a source checkout included); `10` unexpected | `docs/USAGE.md:1220-1223` |
| `tui` | `6` no interactive console | `docs/USAGE.md:1374-1387` |
| `gui` | `7` GUI gate closed; `8` no window can be shown here | `docs/USAGE.md:1374-1387` |

The overload stays visible in this table: `2` (usage, but also a refused key file in `diagnose`), `3` (a refusal, a
stop after the plan, or "not recorded"), `6` (no interactive console, in five verbs) and `10` (unexpected, but also a
refused `diagnose` export and a failed `recover` collection) each mean a different outcome per verb. A script must read
the code together with the verb.

### 2.2 Rules per class

- **Stable** (`audit -ExportJson`, `atm.diagnose/2`, `monitor.json`, `atm.quarantine-policy/1`, exit codes):
  - **Evolution:**
    - for documents, a new field may be added without changing the version, and consumers must ignore unknown fields;
    - removing a field, renaming it, changing its type or meaning, or making a field that was optional mandatory needs `/n+1`;
    - for strict inputs (`monitor.json`, the policy), a new key is a new version of the file. The reader accepts both versions for the whole 1.x line;
    - for exit codes, a new code may be added to a verb only for a new outcome, and an existing code never changes meaning.
  - **Deprecation:**
    - the old version is still written, or still accepted, for one published minor version after the new one;
    - the CHANGELOG and the format's document announce it.
  - **Test:**
    - a golden file per version in the suite, checked field by field, with no extra field and no missing field, as `DIAGNOSE-SCHEMA.md:20` already requires;
    - a "reader of the previous version" test for strict inputs;
    - a table test of exit codes per verb.
- **Internal** (monitoring record, quarantine manifest, recovery plan ids, pseudonym domains, manifest, install state):
  - the product may change them in any version;
  - a change must keep reading what an earlier published version wrote, or refuse it with a code. It never misreads it.
  - **Test:** a fixture written by the previous published format, read by the new code.
- **Log** (clean, discard authorization, isolate, purge, auto-purge, recover):
  - append-only evidence;
  - a new field or record type is allowed;
  - a version bump only when a record's meaning changes;
  - the pilot summary tool and `recover undo` are their only readers, and each checks the schema id it knows.
  - **Test:** the existing strict-read tests, plus the pilot summary's schema list.

### 2.3 Inconsistencies

| Inconsistency | Proposal | Breaks anyone? |
|---|---|---|
| `audit -ExportJson` has no schema id | add `schema: "atm.audit/1"` as the first field (S2) | no: adding a field is compatible, and no consumer in the repository |
| `atm.diagnose/2` names its field `schemaVersion`; the logs and the monitoring record name it `schema` | keep both as they are and document the difference | renaming would break every reader of `atm.diagnose/2` |
| `atm-recover-plan/1` and `atm-recover-undo-plan/1` use `atm-x/n`; the documents use `atm.x/n` | **no change.** `atm-x/n` is the convention of hash domains (the pseudonym domains use it too); these two are hash inputs, not documents. Document the two conventions | renaming would change every plan id, so a plan shown before an update would no longer match at `recover start`, and the `undo` provenance of recorded runs would break |
| `audit -ExportJson` writes raw `machine`, `user`, `sid` and `path` (`Report.ps1:230-234`); `atm.diagnose/2` pseudonymizes (ADR-0010) | keep: the audit export is a local file the operator asks for, outside the bases. Document the difference in the format's document and in SECURITY-MODEL. A pseudonymized audit export would be `atm.audit/2` and a decision of its own | no |
| Exit codes overload `2`, `3`, `6` and `10` across verbs (`USAGE.md:1374-1386`) | keep, and publish a per-verb table as the stable contract | a renumbering would break the scheduled tasks and scripts |

## 3. "A new provider can be added without changing the engines"

### 3.1 The criterion as tests
1. **A test-only provider through the whole read path:**
   - a fixture provider, registered in the suite process (never shipped), with `temp` and `runtime`;
   - it runs through `Invoke-AtmInventory` (the audit), `Test-AtmCandidate` (the preview) and `Invoke-AtmDiagnose`;
   - the suite's "provider ficticio" (`tests/Run-Tests.ps1:7341`) and the contract v2 cases (`:11004`, `:11052`, `:11066`) already do most of this. S1 widens them into the conformance suite below.
2. **A static proof:** adding a provider touches `src/providers/<id>.ps1`, the manifest and the tests, and nothing in
   `src/lib/Engine.*.ps1`.
   - The check: no engine file contains a provider id or a provider's display name as a string literal, except a closed, listed set. Today that set has one entry, `Engine.Clean.ps1:174`, the B1 exception.
   - A new literal fails the suite.
3. **A dry addition in CI:**
   - the suite copies the source tree to its sandbox and adds a fixture provider file to `src/providers/`;
   - it rebuilds the manifest of the copy, runs `audit` and `diagnose` in a child process, and compares the `Engine.*.ps1` hashes with the originals: they must be equal;
   - this also proves that the installer manifest takes a new provider file without an installer change (ADR-0008 decision 7).

### 3.2 The conformance suite
A suite area, "Contrato de provider", in `tests/Run-Tests.ps1`, run on both shells in the four CI test jobs. It covers:
- **validation:** every rule of 1.1, with one refused fixture per rule and the exact error key;
- **an unknown version:** `ContractVersion` 3, `'2'` with spaces, `2.0`, negative and `$null` are all refused with `err.providerContract`. In diagnose and recover the provider is `PROVIDER_CONTRACT_INVALID` and the others still run;
- **"cannot look" versus "nothing found":**
  - for each evidence member, a provider returning `Readable = $false` must give the flag (`SESSION_REGISTRY_UNREADABLE`, `TRANSCRIPTS_UNREADABLE`) and never `DEAD` or "no activity";
  - a provider that throws gives `UNVERIFIABLE`/`FAILED` coverage, never an empty result;
  - the check runs on the two shipped providers and on any new one;
- **liveness:** a provider's `GetSessionEvidence` against a snapshot fixture must return `LIVE` for a PID whose creation time equals the recorded start, and never `DEAD` for a PID that exists. This makes the provider-side tolerance of 1.3 a checked rule;
- **no credential reads:** each provider runs over a fixture profile that holds decoy credential files.
  - For Claude Code: `*.key`, `.credentials.json`.
  - For a candidate: the files its vendor documents as credentials (section 4).
  - The files are planted with an ACL that denies read to the test identity, and a read attempt is detected (access denied counted through a file-system seam, or the decoy's last access checked).
  - The static part: no provider file names those files except in a deny list;
- **no writes:** every provider runs with the sandbox's write seam failing; any write attempt fails the case;
- **a provider never weakens a gate:**
  - a provider returning `LIVE`, `Readable = $true` and a recent activity for a fixture root, with all gates closed, leaves the preview at the gate's result;
  - a provider cannot turn a hard flag into eligibility (fixtures for each hard flag).

## 4. The provider beyond Claude (V10-D1, the maintainer's decision)

Research was done on public vendor documentation only, on 2026-11-21. Nothing was installed, downloaded or run.
Anything a vendor does not document is marked **operator observation needed**. The disk layouts below are quoted
from vendor pages, not written from memory.

**One finding applies to all three candidates.** None documents per-session **temporary** directories under `%TEMP%`,
as Claude Code's `<TEMP>\claude\<scope>\<session id>` (`docs/PROVIDERS.md:75-76`) is. What they document are session
**histories** under the user profile, which the user resumes or reviews. Treating those as temporary, deletable
partitions would change what "temporary" means for this tool. So for each candidate, the `temp` capability is either
inapplicable or needs a new decision.

| Candidate | Where it keeps per-session data (vendor documentation) | Liveness evidence | Privacy risk (credentials beside the data) | Effort | Testable in CI without the agent |
|---|---|---|---|---|---|
| **GitHub Copilot CLI** | `~/.copilot` (or `COPILOT_HOME`); `session-state/` "organized by session ID in subdirectories", each with an event log `events.jsonl` and "workspace artifacts (plans, checkpoints, tracked files)"; the vendor's Windows example sits under the user profile (`%USERPROFILE%\.copilot\...` in this record's notation) ([config directory reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference); [session data](https://docs.github.com/en/copilot/concepts/security-governance-and-network-settings/session-data): "the complete record of each session under `~/.copilot/session-state/`", plus a local SQLite "session store"; sessions are synced to the user's GitHub account by default) | no session/PID file documented: **operator observation needed**; the process image name is not documented on these pages: **operator observation needed** | high: the same folder holds `mcp-oauth-config/` (OAuth tokens), `mcp-secrets/` and `providers.json` (API keys "stored as plain text"), per the same reference | medium for `runtime` (once the image is observed); high for `temp` (the session folders are history, not temporary) | yes: a fixture tree with only the documented names; the conformance suite; decoy credential files at the documented names |
| **Google Gemini CLI** | sessions in `~/.gemini/tmp/<project_hash>/chats/`, the hash "based on your project's root directory"; the CLI cleans its own sessions by default (`sessionRetention`, `maxAge` default `30d`) ([session management](https://geminicli.com/docs/cli/session-management/)); checkpoints under `~/.gemini/tmp/<project_hash>/checkpoints` and a shadow Git repository in `~/.gemini/history/<project_hash>` when checkpointing is enabled ([checkpointing](https://geminicli.com/docs/cli/checkpointing/)) | none documented: **operator observation needed**; the process image is not documented either (**operator observation needed**). The configuration page has a setting to "Automatically configure Node.js memory limits"; if the image turns out to be a generic runtime host, a validated command-line marker would be needed (an inference, not a vendor statement) | medium: the user settings file is `~/.gemini/settings.json`, `GEMINI_CLI_HOME` moves the root where `.gemini` is created, and `.env` files may be loaded ([configuration](https://geminicli.com/docs/reference/configuration/)); the authentication file names are not on these pages: **operator observation needed** | high: the "tmp" folder is chat history with its own retention; a second cleaner would compete with the agent's | yes, as above |
| **OpenAI Codex CLI** | state under `CODEX_HOME` (default `~/.codex`): `config.toml`, `auth.json` "if you use file-based credential storage", `history.jsonl` "if history persistence is enabled", "other per-user state such as logs and caches" ([advanced configuration](https://developers.openai.com/codex/config-advanced), which redirects to [learn.chatgpt.com](https://learn.chatgpt.com/docs/config-file/config-advanced)); a per-session folder layout is **not** in the vendor page: **operator observation needed** | none documented: **operator observation needed** | high: `auth.json` holds credentials in the same folder | high: no documented per-session unit at all | only the documented file names |
| **Generic provider, configured by a file, no real agent** (the mandatory alternative) | whatever the file declares: `TempSubdir`, `ScopePattern`, `RootPattern`, a liveness file pattern | whatever the file declares | depends on the operator's file; the tool still never opens what the deny list names | low to medium | fully: it is a fixture by nature |

### 4.1 Comparison with the ROADMAP acceptance
- **"At least one provider beyond the Claude scenarios" and "a new provider can be added without changing the engines":**
  - The generic provider proves the second criterion completely in CI. Whether it satisfies the first depends on reading "provider": it is a mechanism, not an agent.
  - A real agent satisfies the first literally, but the evidence it rests on is either undocumented (liveness) or not temporary (history).
- **Safety:**
  - A real agent's `temp` capability would make history folders candidates for deletion behind the deletion gate. A liveness rule that is not documented would rest on guesses, which section 8 rules out.
  - A shipped generic provider would let any file make any folder pattern a candidate. It must not ship with `temp`.
  - A `runtime`-only real provider touches no eligibility: it only attributes processes, services and VMs in the diagnose, which is read only.

### 4.2 Options (V10-D1)
- **(a)** A real agent with `runtime` only, chosen by the maintainer.
  - The recommended agent is **GitHub Copilot CLI**: its folder layout is the best documented, and it has Windows examples.
  - The image name and any command-line marker must first be observed by the operator, under ADR-0008 decision 6, before the provider declares them.
  - No `temp` capability in 1.0.
- **(b)** A real agent with `temp` and `runtime`.
  - This needs the operator to observe liveness, and a decision that the agent's session history is temporary data.
  - Not recommended.
- **(c)** The generic provider only, test-only and never shipped. It proves the mechanism; the "beyond Claude" deliverable is then read as "the contract admits it".
- **(d)** (a) plus (c).

**Recommendation: (d).**
- (c) closes the acceptance criterion in CI with no operator dependency.
- (a) satisfies the literal deliverable without touching eligibility, B1 or RECENT. Its CI tests use only documented names, and its real-agent check is an operator observation, recorded as NOT_TESTED until then, as with Claude Desktop (ADR-0008 implementation record).

## 5. The security review (V10-D4)

### 5.1 What "completed" means
For each engine (Audit, Clean, Isolate, Diagnose, Recover, Monitor), the presentation (Report, TUI, GUI) and the
installer (`install/*`, the manifest, `verify`, the uninstaller), one review record, `docs/release/V1.0-SECURITY-REVIEW.md`.

**Checklist per component:**
1. **Trust boundaries:** inputs from other users (registry, environment, files), from the current user, from the network (none expected) and from an elevated or non-elevated side (PRIV-5, PRIV-6).
2. **File-system safety:** every write or delete opened through the pinned primitives (`AtmSafeCreate`, the deleter); reparse points refused; TOCTOU windows listed with their residual. The sources are F-01, F-02, F-04, F-10 and X-01 in `release/V0.2-SECURITY-AUDIT.md`.
3. **Gates:**
   - each gate has one assignment and is read before anything it guards;
   - no option, variable or file opens a gate;
   - a provider cannot weaken one;
   - the evidence is the existing static tests, listed per gate.
4. **Privacy:** no SID, account, machine name or path in exports, logs or CI artifacts beyond what each format documents; pseudonymization (ADR-0010); the privacy scanner on CI artifacts (FINAL-B).
5. **Process and execution:** no `cmd.exe`/PATH lookup (F-13); `-NoProfile`; fixed arguments; the job executor's limits.
6. **Elevation:** PRIV-1 to PRIV-11 (`docs/ELEVATION.md:50-60`), each with its status and the test or runbook row that proves it.
7. **Failure modes:** every refusal fails closed; "cannot look" is never "nothing found"; deadlines give `TIMEOUT`, never `COMPLETE`.

**Sources:**
- `docs/SECURITY-MODEL.md`, including "Known limits", `:574`;
- `docs/release/V0.2-SECURITY-AUDIT.md` (FINAL-A, FINAL-B), its threat matrix (`:309`) and its findings table (`:21-39`);
- `docs/incidents/2026-11-01-profile-login-temp-isolation.md`;
- the ADRs 0013 to 0017, each with its own threat sections;
- the previous auditor reports.

**Artifact:** the review record, with per component:
- the checklist with evidence (test name or file:line);
- the findings, with severity, status and residual;
- a closing statement.

### 5.2 Who signs
The auditor session reviews and writes the record. **The maintainer accepts it** (V10-D4). An executor never signs its
own component's review.

### 5.3 Fixes
- A fix that changes behaviour lands behind a gate (the component's own gate, or a new one that stays closed), or it carries a test proving the observable behaviour is unchanged.
- A fix that touches classification, eligibility, B1 or RECENT is out of the review's scope. It needs its own decision record.

### 5.4 Known findings already on record

| Id | Source | Status on record | Note for the review |
|---|---|---|---|
| F-01 residual | `release/V0.2-SECURITY-AUDIT.md:41-77` | FIXED, residual | reads by textual path after checks; ancestor swap not excluded |
| X-01 | same, `:262-291` | MITIGATED in code; export stays disabled | volume root not pinned; a refusal after creation can leave a file |
| F-09 | same, `:158-168` | INFO, documented | key file opened by name |
| F-04 | same, `:111-124`; `release/V0.3-RC.md:109`; `CHANGELOG.md` 0.3.0 | the audit table still says "not closed"; T1 shipped in 0.3.0 | the review must close it on record, or say why not; the table in the V0.2 audit is stale on this row |
| F-05, F-14 | same table; `CHANGELOG.md`, Unreleased, the bullets F05-OWNER-ATTRIBUTION and F14-VERIFY-WARN | fixed on `main` (F05-OWNER-ATTRIBUTION, F14-VERIFY-WARN), unpublished | the V0.2 table still says "proposal": stale until published |
| Job executor residual | `release/V0.2-FINAL-C-RC.md:136` | real refusal of `TerminateJobObject` and a reader still running: NOT TESTED | accept or test |
| ARM64 PowerShell 7 | `release/V0.2-FINAL-C-RC.md:139` | known limit: NOT TESTED on that combination | the CI's ARM64 pwsh job runs a subset (`-Except` list) |

## 6. The acceptance the CI does not prove

The CI runners are Windows Server 2022, Windows Server 2025 and Windows 11 ARM64. There is no Windows 10 client, no
interactive UAC consent and no second real administrator.

| Acceptance line | Provable in CI on disposable runners? | How, or who |
|---|---|---|
| Clean environment | **yes** | each job starts from a fresh runner; the install e2e installs the package and checks it (`tests/e2e/Invoke-InstallE2E.ps1`) |
| Elevated | **partly** | the runner account is an elevated administrator with no prompt (`TESTING.md:56`); the elevated **requester** path through a real UAC consent is not provable: operator |
| Multi-user | **partly, extendable** | one disposable standard user exists today: created at `Invoke-InstallE2E.ps1:693-711` (Users group only, by SID, random `SecureString` password, asserted not an administrator) and reused through `Start-Process -Credential` (all in `Invoke-InstallE2E.ps1`): `audit`, `preview` and `verify` as that user (`:721`); the write probe on the install folder (`:735`); the automatic-purge task helper (`:782`); the V2 clean harness, leg A (`:864`); the isolation harness, leg A (`:914`); R6, leg A (`:974`); M3b, leg A (`:1019`; `Invoke-MonitorE2E.ps1:10` says it reuses this user); and the lock held and probed across identities (`:1059`, `:1073`). A second disposable standard user created the same way would prove the cross-user rows (another profile's base, `-IncludeOtherUsers`, F-05's owner rule with two real owners); proposed in S5 |
| Windows 10 | **no** | no Windows 10 client runner: operator (the manual rows of `release/PRIVILEGE-MATRIX-RUNBOOK.md`) |
| Windows 11 | **partly** | ARM64 in CI; x64: operator (`TESTING.md:60`) |
| PowerShell 5.1 | **yes** | the `test (powershell)`, ARM64 powershell and installer-powershell jobs |
| PowerShell 7 | **yes, with a known gap** | the `test (pwsh)` job; ARM64 pwsh runs a subset; the GUI's real window is NOT_TESTED on 7 by design (GUI-D7) |
| The PRIV matrix (`TESTING.md:47-60`) | **partly** | standard user and elevated administrator: CI; filtered admin token, consent prompt, credentials prompt, cancelled prompt, non-interactive SSH/WinRM: operator, with the probe `tools/privilege-matrix/Invoke-PrivilegeProbe.ps1` |
| The V5 pilot (real deletion) | **no** | operator, disposable VM (ADR-0015), still pending |

**What stays with the operator:**
- a real UAC consent;
- a second real administrator;
- a Windows 10 client;
- Windows 11 x64;
- the pilot V5.

The record does not hide this gap. V1.0's acceptance is complete only when the operator's rows are executed and
recorded, or the maintainer accepts them as open (V10-D6).

## 7. "Stable" with the gates closed (V10-D2)

With the gates closed, a "1.0" is a read-only tool: audit, preview, diagnose (no export), the plans, `version` and
`verify`. Real deletion, isolation, purge, recovery, the GUI, monitoring, worktree/handle diagnostics and the diagnose
export are all present and tested, but unreachable. "Stable" would then promise:
- the read-only formats and exit codes (section 2);
- the provider contract (section 1).

It would promise nothing about the features behind the gates.

**Options:**
- **(a)** 1.0 is published with every gate closed. The stability promise covers what runs. Each gate opens later in a minor version (1.1, 1.2...), after its own acceptance.
- **(b)** 1.0 waits for the V5 pilot and for the opening of gates the maintainer chooses (for example deletion and the GUI). "1.0" then means "the core product works".
- **(c)** V1.0's work lands on `main` dark, as D-A requires. The number "1.0" and the publication are decided later and separately, possibly after (b)'s conditions hold.

**Recommendation: (c).**
- It follows D-A without stretching it, and it keeps the version number from promising what the gates hold back.
- The phases below are worth doing under any of the three.
- The question "what does 1.0 mean" is then answered with the pilot's result and the gate decisions in hand, not before.

## 8. Limits that do not change

- The safety limits of V0.3 and V0.4 hold unchanged.
- No provider weakens a gate, and the conformance suite (3.2) proves it per provider.
- Nothing changes in B1, RECENT (72 hours), the hard and soft flags, the classification or eligibility. In particular,
  the B1 restricted exception stays Claude Code's (`Engine.Clean.ps1:174`).
- No gate opens in any V1.0 phase. A new feature behind a new gate keeps that gate closed.
- Providers only read: no credential or token file is ever opened, no file content is printed, and "cannot look" is
  never "nothing found".

## 9. Phases

| Phase | Scope | Files | Tests | Depends on the maintainer | Depends on the operator |
|---|---|---|---|---|---|
| **S0** | This record; ROADMAP status | `docs/adr/ADR-0018-*.md`, README, ROADMAP, CHANGELOG | CI green | V10-D1 to V10-D8 | — |
| **S1** | Contract 2 frozen and documented (1.4, 1.5): inputs, return shapes, reserved members; the conformance suite (3.2); the static provider-literal check (3.1.2); the dry addition (3.1.3); optional stricter registration | `docs/PROVIDERS.md`, ADR-0008 record, `tests/Run-Tests.ps1`; `Engine.Audit.ps1:66-81` only if V10-D5 chooses stricter validation or the skip-and-record loading | conformance on both shells, both shipped providers; the golden inventory comparison | V10-D5 | — |
| **S2** | Format contracts (2.2, 2.3): `atm.audit/1` field; a per-format document; golden files; the per-verb exit-code table | `Report.ps1` (one added field), `docs/USAGE.md`, a new `docs/FORMATS.md`, `docs/DIAGNOSE-SCHEMA.md`, tests | golden files per format and version; previous-version readers; exit-code table | V10-D3 | — |
| **S3** | The generic test-only provider (4.2 (c)) | `tests/Run-Tests.ps1` fixtures only | the provider through audit, preview and diagnose; the dry addition | V10-D1 | — |
| **S4** | The real agent provider, `runtime` only (4.2 (a)) | `src/providers/<id>.ps1`, `docs/PROVIDERS.md`, ADR-0008 record, tests | conformance; fixtures with only documented names; attribution ambiguity cases | V10-D1 | the image name and marker observed read only on a machine with the agent (until then the real agent is NOT_TESTED) |
| **S5** | Multi-user in CI: a second disposable standard user in the install e2e, the cross-user rows | `tests/e2e/Invoke-InstallE2E.ps1` (the existing pattern), `docs/TESTING.md` | cross-user audit and preview, `-IncludeOtherUsers`, F-05 with two owners | V10-D7 | — |
| **S6** | The security review (5.1): the record per component; fixes behind gates or proved neutral | `docs/release/V1.0-SECURITY-REVIEW.md`; any fix under its own round | the evidence the checklist cites | V10-D4 (acceptance) | — |
| **S7** | The operator's acceptance rows (section 6) and their record | `docs/release/PRIVILEGE-MATRIX-RUNBOOK.md` results, `docs/TESTING.md` | manual rows recorded | V10-D2, V10-D6 | Windows 10, Windows 11 x64, UAC consent, second administrator, the V5 pilot |

S1, S2 and S3 do not depend on each other's results. S4 needs S1's conformance suite. S6 can run in parallel with S1 to
S5 and must close after them.

## 10. Decisions for the maintainer

- **V10-D1, the provider beyond Claude (section 4):**
  - Options:
    - (a) a real agent, `runtime` only;
    - (b) a real agent with `temp`;
    - (c) the generic provider, test-only;
    - (d) (a) + (c).
  - **Recommendation: (d), with GitHub Copilot CLI for (a).** (c) proves the acceptance in CI. (a) gives a real agent without touching eligibility. Copilot CLI has the best-documented layout.
- **V10-D2, "stable" with the gates closed (section 7):**
  - Options: (a) publish 1.0 dark; (b) wait for the pilot and chosen gates; (c) land dark and decide numbering and publication later.
  - **Recommendation: (c).** It follows D-A, and the number promises nothing the gates hold back.
- **V10-D3, the format stability policy (section 2):**
  - Options:
    - (a) the classes of 2.2: stable, internal and log, with one published minor version of deprecation;
    - (b) everything machine-readable stable;
    - (c) only `atm.diagnose/2` and the exit codes stable.
  - **Recommendation: (a).** It promises stability where outside readers exist and keeps the product free to change its own files safely.
- **V10-D4, who signs the security review (section 5):**
  - Options:
    - (a) the auditor reviews, the maintainer accepts;
    - (b) an external reviewer;
    - (c) the maintainer alone.
  - **Recommendation: (a)**, with (b) optional before a public 1.0. It separates the writer from the acceptor without an outside dependency.
- **V10-D5, the contract's strictness:**
  - Options:
    - (a) documentation only;
    - (b) also stricter registration (script blocks, regexes);
    - (c) (b) and a provider whose file throws while loading is refused alone and recorded, while the others run.
  - **Recommendation: (b).** It fails earlier, with no behaviour change for shipped providers. (c) changes the launcher's failure mode and deserves its own review.
- **V10-D6, open acceptance rows:**
  - Options: (a) V1.0 is accepted only with every operator row executed; (b) the maintainer may accept named rows as open, listed in the release notes.
  - **Recommendation: (a) for a published 1.0; (b) for landing dark.**
- **V10-D7, multi-user in CI (S5):**
  - Options: (a) a second disposable standard user in the install e2e; (b) operator only.
  - **Recommendation: (a).** It reuses a proven pattern and removes rows from the operator's list.
- **V10-D8, the v1 contract's lifetime:**
  - Options: (a) accepted throughout 1.x; (b) deprecated in 1.0, removed in 1.1.
  - **Recommendation: (a).** Third-party v1 providers keep working, and removal can be announced later.

## Rejected alternatives

- **Bumping the contract to 3 for V1.0:** every provider would change, and no accepted value changes.
- **Renaming `atm-recover-plan/1` and `atm-recover-undo-plan/1`:** it would break plan ids and the `undo` provenance.
- **A shipped generic provider with `temp`:** any file could turn any folder pattern into a deletion candidate.
- **Treating another agent's session history as temporary:** it changes what the tool deletes. It is not a provider detail.
- **Extending the B1 restricted exception to new providers:** it is an eligibility change. It is out of V1.0 unless decided on its own.

## Consequences (including new limits)

- V1.0 adds no gate opening and no eligibility rule.
- The provider contract becomes a documented, tested interface. Third parties can write providers against
  `docs/PROVIDERS.md` alone.
- Machine-readable outputs get explicit promises. Human-readable text is explicitly not an interface.
- The acceptance has a documented, operator-owned part that CI cannot replace.
- A real agent beyond Claude, if chosen, starts as `runtime`-only and NOT_TESTED against the real agent until observed.

## Verification

- **This record:**
  - every line reference resolves at `d7b03a9`;
  - the vendor URLs are the ones cited on 2026-11-21;
  - nothing in `src/`, `tests/`, `tools/`, `install/` or `.github/` changes;
  - CI green.
- **Each phase brings its own tests (section 9).** None may open a gate or change B1, RECENT, the classification or
  eligibility. The golden inventory comparison (1.5) and the conformance suite (3.2) prove the provider changes;
  golden files prove the format changes.
