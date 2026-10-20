# Provider contract

A provider tells the engines **where** an agent keeps per-session temporary directories and **how** to read
its liveness evidence. It is a single `.ps1` file in `src/providers/` that calls `Register-AtmProvider` with
an object exposing exactly these members (validated at registration):

| Member | Type | Meaning |
|---|---|---|
| `Id` | string `^[a-z0-9-]+$` | Stable identifier (`claude-code`). |
| `DisplayName` | string | Shown in reports and the TUI. |
| `TempSubdir` | string `^[A-Za-z0-9._-]+$` | Directory created under each TEMP candidate (the *base*). |
| `ScopePattern` | regex | First-level directories under the base (project scopes). |
| `RootPattern` | regex | Second-level directories: session roots, the only deletable unit. |
| `EnvVarNames` | string[] | Per-user environment variables the engine reads (registry + current process). |
| `GetExtraTempDirs` | `{ param($ProfileInfo) }` | Additional TEMP-like directories (e.g. an override variable). |
| `GetConfigDirs` | `{ param($ProfileInfo) }` | `{ Dirs; Known }`, where the agent keeps its configuration. |
| `GetSessionEvidence` | `{ param($ProfileInfo, $Snapshot) }` | `{ Readable; Unparseable; Entries[{SessionId; Pid; State; Scope; ProjectName}] }` with State `LIVE`, `LIVE_UNVERIFIED`, `PID_REUSED`, `DEAD` or `UNVERIFIABLE`. `Scope`/`ProjectName` (optional) come from the session's working directory and are used only to name projects. |
| `GetActivityEvidence` | `{ param($ProfileInfo, $Scope, $RootName) }` | `{ Readable; LastWriteUtc }` of an activity artifact. |
| `GetProjectKey` | `{ param($Scope, $ProfilePath) }` | `{ IsHome; Key }` used by informational project rules. |

Arguments are passed **by position**, so parameter names are free. `$ProfileInfo` is the recommended name; providers
written with `$Profile` keep working, but `$Profile` shadows the PowerShell automatic variable and is reported by
static analysis.

Rules:

* Providers are **read-only**. They must never open credential/token files, never print file contents,
  and must report "cannot look" (`Readable = $false`) instead of "nothing found" when access fails.
* Providers do not classify, gate or delete. All safety logic is shared and identical for every agent.
* Unknown structure is not a provider error: the engine flags it and blocks it.

## Contract v2 (V0.2): capabilities and runtime hints

Decision record: [ADR-0008](adr/ADR-0008-provider-contract-v2.md). A provider **without** `ContractVersion` is a v1
provider: it is validated exactly as described above and has the single capability `temp`. Nothing changes for it.

A v2 provider declares:

| Member | Type | Meaning |
|---|---|---|
| `ContractVersion` | `2` | Contract version. Any other value is refused. |
| `Capabilities` | string[] | Non-empty subset of `temp` and `runtime` (exact, lower case, no duplicates). |

* `temp`: the eleven v1 members above are required and validated as in v1. Only providers with this capability are
  used by the temporary-directory inventory (audit, preview, clean).
* `runtime`: optional members describing runtime evidence for `agent-temp diagnose`. Each one, when present, must be
  a script block; declaring one without the `runtime` capability is refused. An absent member means "no hints from
  this provider", never "nothing is running".

| Runtime member | Signature | Returns |
|---|---|---|
| `GetProcessMatchers` | `{ }` | `@({ ImageName; CommandLineMarker })`: exact image file name (`*.exe`), optional marker matched in memory against the command line (the command line is never stored or printed). |
| `GetServiceHints` | `{ }` | `@({ Name; Role })`: exact Windows service names; `Role` is an optional lower-case id. |
| `GetVirtualizationHints` | `{ }` | `@({ Kind; Value })` with `Kind` `ServiceOwner` (a service that owns a VM) or `VmName`. |
| `GetWorktreeHints` | `{ param($ProfileInfo, $Registry) }` | `{ Readable; Dirs }`: absolute local starting directories (used from V0.2-P3). |

Hint results are validated when diagnose reads them. A member that throws or returns a malformed value gives that
provider's coverage record (`provider-<id>`) the status `FAILED` (`HINT_FAILED` / `HINT_MALFORMED`); diagnostics
continue with the other providers. The same rules as v1 apply: providers only read, never decide, never open
credential or token files, and can never weaken a gate or a coverage status.

## V1: Claude Code

* Base: `<TEMP>\claude` (also `<CLAUDE_CODE_TMPDIR>\claude` when set).
* Scopes: project slugs (`[^A-Za-z0-9]` -> `-`). Roots: session UUIDs.
* Live sessions: `<config>\sessions\<pid>.json` (`pid`, `sessionId`, `procStart`); a PID counts as live
  only when its creation time matches `procStart`. `*.key` files are never read.
* Activity: last write time of `<config>\projects\<slug>\<sessionId>.jsonl`.
* Config dir: `CLAUDE_CONFIG_DIR` or `<profile>\.claude`.

Adding another agent = one new file in `src/providers/` + tests. No engine, gate, report or TUI change is
expected; the automated test "provider ficticio" demonstrates this with a test-only provider.
