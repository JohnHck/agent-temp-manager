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
| `GetServiceHints` | `{ }` | `@({ Name; Role })`: exact Windows service names; `Role` is an optional lower-case id. Since V0.2-P2-A the diagnose queries only these names (one local `Win32_Service` query, read-only), never similar names; a name declared by two providers is reported once with the attribution ambiguous. Declaring no service means that no service is checked, never that none exists; a declared name that is not listed is reported `UNKNOWN`, never absent. |
| `GetVirtualizationHints` | `{ }` | `@({ Kind; Value })` with `Kind` `ServiceOwner` (a service that owns a VM) or `VmName`. Since V0.2-P2-B: a `VmName` attributes an observed VM whose display name matches exactly (the name is never exported); a `ServiceOwner` attributes a VM only when its worker process is a verified child of the running service, which the same provider must also declare in `GetServiceHints`. A worker process is never attributed by its name. |
| `GetWorktreeHints` | `{ param($ProfileInfo, $Registry) }` | `{ Readable; Dirs }`: absolute local starting directories (used from V0.2-P3). |

Session evidence (v2, optional and additive): each `GetSessionEvidence` entry may also carry `StartUtc`, the process
creation time the agent recorded for the session (UTC, with the agent's own precision). The diagnose engine matches it
against the collected process with an exact identity rule (`LIVE` only when equal at the CIM resolution of 1 us; a
difference within 2 s that is not exact is inconclusive; beyond 2 s the PID belongs to another process). The V0.1
`State` of each entry and its 2 s tolerance are unchanged and keep feeding the audit and its gates.

Hint results are validated when diagnose reads them. A member that throws or returns a malformed value gives that
provider's coverage record (`provider-<id>`) the status `FAILED` (`HINT_FAILED` / `HINT_MALFORMED`); diagnostics
continue with the other providers. The same rules as v1 apply: providers only read, never decide, never open
credential or token files, and can never weaken a gate or a coverage status.

## Claude Code (contract v2: `temp` and `runtime`)

* Runtime (V0.2-P1-B4-b): process matcher `claude.exe`, without a command-line marker. Observed read-only on Windows
  on 2026-10-23 with Claude Code 2.1.307 (entrypoint `cli`) and 2.1.308 (entrypoint `claude-desktop`): both run as
  `claude.exe`, and the `procStart` each session records (a 100 ns FILETIME) equals the CIM creation time once
  truncated to 1 us. Installations that run through another host (for example `node.exe`) are not declared: a generic
  image name would need a validated marker. Session entries carry `StartUtc` (the parsed `procStart`).
* Base: `<TEMP>\claude` (also `<CLAUDE_CODE_TMPDIR>\claude` when set).
* Scopes: project slugs (`[^A-Za-z0-9]` -> `-`). Roots: session UUIDs.
* Live sessions: `<config>\sessions\<pid>.json` (`pid`, `sessionId`, `procStart`); a PID counts as live
  only when its creation time matches `procStart`. `*.key` files are never read.
* Activity: last write time of `<config>\projects\<slug>\<sessionId>.jsonl`.
* Config dir: `CLAUDE_CONFIG_DIR` or `<profile>\.claude`.

## Claude Desktop (contract v2: `runtime` only, V0.2-P2-C)

`src/providers/ClaudeDesktop.ps1`, id `claude-desktop`. Every hint is a published or publicly reported fact, with its
source recorded in the file; nothing of the installation (files, logs, registry, configuration, package database) is
read. Sources checked on 2026-10-24:

| Fact | Source | Status |
|---|---|---|
| MSIX package name `Claude`, family `Claude_pzs8sxrjxfjjc`, publisher Anthropic, PBC; the values do not change between versions or architectures | Anthropic documentation (Windows fleet checklist) | documented |
| Cowork needs the `.msix` package (the legacy `.exe` installer has no Cowork); the package registers a Windows service that Cowork uses | Anthropic documentation (fleet checklist, installation and setup) | documented (service name not given) |
| Cowork runs in a VM the app manages; needs Virtual Machine Platform (not the Hyper-V role); the VM runs under `NT VIRTUAL MACHINE\Virtual Machines` | Anthropic documentation | documented |
| Agent helper `claude.exe` under `%APPDATA%\Claude\claude-code\<version>\<build-id>\` | Anthropic documentation | documented |
| Service `CoworkVMService` ("Claude (CoworkVMService)"), start type Manual with 1.1.3647 and Running/Automatic later | anthropics/claude-code#27010 (2026-02-19, Claude Desktop 1.1.3647, Windows 10 Pro 22H2), #59035 (2026-05-14, Windows 11) | publicly reported |
| The Cowork VM is created through HCS as `cowork-vm-<8 hex>` | anthropics/claude-code#59035 | publicly reported |

* **Process matcher:** `claude.exe` with the command-line marker `pzs8sxrjxfjjc`, the publisher id of the package
  family name: an executable started from the MSIX package runs from a folder named after the package full name, so
  its path carries that id. The marker is matched in memory and never stored. The agent helper (`claude.exe` under the
  user profile) carries no marker and is not matched here. Claude Code's own matcher (`claude.exe`, no marker) also
  matches the package's processes: such a process is reported as attributable to both providers
  (`PROVIDER_ATTRIBUTION_AMBIGUOUS`), never resolved by guessing. A command line that cannot be read leaves the
  process unchecked (`COMMAND_LINE_MARKER_UNAVAILABLE`).
* **Service hint:** `CoworkVMService` (role `cowork-vm`), exact name. A running service with a verified process is
  positive evidence of the local Cowork service, not of a running VM; a service not listed is `UNKNOWN` (Cowork in a
  remote environment, the `.exe` installer, or a service the account cannot see), never "not installed".
* **No virtualization hint:** the Cowork VM is an HCS compute system with a per-installation name, not a Hyper-V
  Manager VM, so it is not expected in `Msvm_ComputerSystem`; a `VmName` hint would depend on an arbitrary name, and
  no `ServiceOwner` relation (service -> worker process) is established. `vmmem`, `vmwp`, `vmcompute` and HCS
  processes are never attributed to Claude Desktop.
* **No temp capability:** no per-session temporary directory of Claude Desktop is confirmed for this tool.
* **Version:** not read from the installation; the hints apply to MSIX builds since the reported 1.1.3647.

Adding another agent = one new file in `src/providers/` + tests. No engine, gate, report or TUI change is
expected; the automated test "provider ficticio" demonstrates this with a test-only provider.
