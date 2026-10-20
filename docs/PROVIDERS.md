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
| `GetExtraTempDirs` | `{ param($Profile) }` | Additional TEMP-like directories (e.g. an override variable). |
| `GetConfigDirs` | `{ param($Profile) }` | `{ Dirs; Known }`, where the agent keeps its configuration. |
| `GetSessionEvidence` | `{ param($Profile, $Snapshot) }` | `{ Readable; Unparseable; Entries[{SessionId; Pid; State; Scope; ProjectName}] }` with State `LIVE`, `LIVE_UNVERIFIED`, `PID_REUSED`, `DEAD` or `UNVERIFIABLE`. `Scope`/`ProjectName` (optional) come from the session's working directory and are used only to name projects. |
| `GetActivityEvidence` | `{ param($Profile, $Scope, $RootName) }` | `{ Readable; LastWriteUtc }` of an activity artifact. |
| `GetProjectKey` | `{ param($Scope, $ProfilePath) }` | `{ IsHome; Key }` used by informational project rules. |

Rules:

* Providers are **read-only**. They must never open credential/token files, never print file contents,
  and must report "cannot look" (`Readable = $false`) instead of "nothing found" when access fails.
* Providers do not classify, gate or delete. All safety logic is shared and identical for every agent.
* Unknown structure is not a provider error: the engine flags it and blocks it.

## V1: Claude Code

* Base: `<TEMP>\claude` (also `<CLAUDE_CODE_TMPDIR>\claude` when set).
* Scopes: project slugs (`[^A-Za-z0-9]` -> `-`). Roots: session UUIDs.
* Live sessions: `<config>\sessions\<pid>.json` (`pid`, `sessionId`, `procStart`); a PID counts as live
  only when its creation time matches `procStart`. `*.key` files are never read.
* Activity: last write time of `<config>\projects\<slug>\<sessionId>.jsonl`.
* Config dir: `CLAUDE_CONFIG_DIR` or `<profile>\.claude`.

Adding another agent = one new file in `src/providers/` + tests. No engine, gate, report or TUI change is
expected; the automated test "provider ficticio" demonstrates this with a test-only provider.
