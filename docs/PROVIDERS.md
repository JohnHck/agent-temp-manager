# Provider contract

A provider tells the engines **where** an agent keeps per-session temporary directories and **how** to read
its liveness evidence. It is a single `.ps1` file in `src/providers/` that calls `Register-AtmProvider` with
one object. This file is the whole contract: a third party can write a provider from it alone.

**Contract 2 is the stable contract of V1.0**, frozen by [ADR-0018](adr/ADR-0018-v10-stabilization-multi-agent.md)
(V10-S1, sections 1.3 to 1.5). Its first form is in [ADR-0008](adr/ADR-0008-provider-contract-v2.md). V1.0 documents
it completely and does not change its number.

## Contract 2

### Identity, version and capabilities

| Member | Type | Meaning |
|---|---|---|
| `Id` | string | Stable identifier, `^[a-z0-9-]+$`, lower case exactly (`claude-code`). The same `Id` registered again replaces the earlier object. |
| `DisplayName` | string | Shown in reports and the TUI. Text only: no decision reads it. |
| `ContractVersion` | integer `2` | The value 2 of an integer type (`2`, `[long]2`). Any other value is refused (see "Versioning"). |
| `Capabilities` | string[] | Non-empty subset of `temp` and `runtime` (exact, lower case, no duplicates). |

* `temp`: the eleven members of the next table are required. Only providers with this capability enter the
  temporary-directory inventory (audit, preview, clean).
* `runtime`: optional members describing runtime evidence for `agent-temp diagnose` and `agent-temp recover`. An absent
  member means "no hints from this provider", never "nothing is running".

### The `temp` members

| Member | Type | Meaning |
|---|---|---|
| `TempSubdir` | string `^[A-Za-z0-9._-]+$` | Directory the agent creates under each TEMP candidate (the *base*). |
| `ScopePattern` | regex (a `[string]` that compiles, or a `[regex]`) | First-level directories under the base (project scopes). A scope that does not match gets the hard flag `UNRECOGNIZED_SLUG`. |
| `RootPattern` | regex (as above) | Second-level directories: session roots, the only deletable unit. Anything else is another kind and never a session root. |
| `EnvVarNames` | string[] | Per-user environment variables the engine reads for this provider (user registry and, for the current user, the current process). |
| `GetExtraTempDirs` | script block `{ param($ProfileInfo) }` | Additional TEMP-like directories: `@({ TempPath; Source })`. `TempPath` is a directory; the base is `<TempPath>\<TempSubdir>`. `Source` is a short label copied into the base record and shown in reports (for example the variable name). |
| `GetConfigDirs` | script block `{ param($ProfileInfo) }` | `{ Known; Dirs; Refused }`. The engine reads **only `Known`**: `$false` gives the soft flag `CONFIG_DIR_UNKNOWN`. |
| `GetSessionEvidence` | script block `{ param($ProfileInfo, $Snapshot) }` | The session registry: `{ Readable; Unparseable; Entries }`, see below. |
| `GetActivityEvidence` | script block `{ param($ProfileInfo, $Scope, $RootName) }` | `{ Readable; LastWriteUtc }` of the activity artifact of one session root (`$Scope` = scope directory name, `$RootName` = root directory name). |
| `GetProjectKey` | script block `{ param($Scope, $ProfilePath) }` | `{ IsHome; Key }`, used only to name projects in reports. |

`Register-AtmProvider` checks, in this order, and refuses with one error key per rule. Every message names the member.
The keys added in V1.0 (`err.providerTempMember`, `err.providerPattern`) never repeat the refused value; the older
keys (`err.providerContract`, `err.providerCapabilities`, `err.providerId`, `err.providerSubdir`) also show the
refused value:

| Rule | Key |
|---|---|
| `ContractVersion` absent (v1) or the integer 2 | `err.providerContract` |
| `Capabilities` non-empty, exact names, no duplicates | `err.providerCapabilities` |
| with `temp`, the eleven members present; without it, `Id` and `DisplayName` | `err.providerMember` |
| `Id` matches `^[a-z0-9-]+$` (v2: lower case exactly; v1: case-insensitive) | `err.providerId` |
| with `temp`, `TempSubdir` matches `^[A-Za-z0-9._-]+$` | `err.providerSubdir` |
| with `temp`, the five `Get*` members are script blocks (V1.0, V10-D5 (b)) | `err.providerTempMember` |
| with `temp`, `ScopePattern` and `RootPattern` compile as regular expressions (V1.0, V10-D5 (b)) | `err.providerPattern` |
| a runtime member, when present, needs `runtime` and is a script block | `err.providerRuntimeMember` |

What a member **returns** is not validated at registration. The `temp` members are read as they are (a missing field
reads as `$null`); the runtime hints are validated when diagnose reads them.

### What the engine passes in

Arguments are passed **by position**, so parameter names are free. `$ProfileInfo` is the recommended name; providers
written with `$Profile` keep working, but `$Profile` shadows the PowerShell automatic variable and is reported by
static analysis.

`$ProfileInfo`, one Windows profile. A provider may read these fields, and no others:

| Field | Type | Meaning |
|---|---|---|
| `Sid` | string | The account's SID, or a label (`RESIDUAL`, `SHARED-PUBLIC`, `TEMPLATE-DEFAULT`) for a folder with no account. Never print it. |
| `ProfilePath` | string or `$null` | The profile folder. `$null` when Windows records none. |
| `EnvValues` | hashtable | Name → array of values, only for the provider's `EnvVarNames`, already expanded. A name is absent when no value was found. |
| `EnvKnown` | bool | `$true` when the environment of that profile was read (its registry hive, or the current process for the current user). `$false` means "could not look": an absent name in `EnvValues` then proves nothing. |

`$Snapshot`, one process snapshot taken once per run:

| Field | Type | Meaning |
|---|---|---|
| `Failed` | bool | `$true` when the process list could not be read. A provider must then return `UNVERIFIABLE`, never `DEAD`. |
| `Processes[].Pid` | int | Process id. |
| `Processes[].CreationUtc` | datetime (UTC) or `$null` | Creation time at the 1 us resolution of CIM. `$null` when unreadable. |

### What a provider returns

`GetSessionEvidence`:

| Field | Meaning |
|---|---|
| `Readable` | `$false` when any place the registry may be could not be read (access denied, refused location). Gives the soft flag `SESSION_REGISTRY_UNREADABLE` on every root of the profile. |
| `Unparseable` | Count of registry entries that exist but could not be read as entries. More than 0 gives `SESSION_REGISTRY_ENTRY_UNPARSEABLE`. |
| `Entries[].SessionId` | The session id; matched in lower case against the root directory name. |
| `Entries[].Pid` | The process the session recorded. |
| `Entries[].State` | One of the five values below. |
| `Entries[].StartUtc` | Optional (v2): the process creation time the agent recorded, UTC. Diagnose compares it with the collected process (`LIVE` only when equal at 1 us; within 2 s but not equal, inconclusive; beyond 2 s, another process). |
| `Entries[].Scope`, `.ProjectName` | Optional: the scope directory name and display name derived from the session's working directory. Used only to name projects, never for a safety decision. |

The five `State` values and what the engine does with each:

| State | Meaning | Engine (audit) |
|---|---|---|
| `LIVE` | The PID exists and its creation time equals the recorded start (within the provider's tolerance, Claude Code: 2 s). | live session evidence: class `ACTIVE_EVIDENCE`, never eligible |
| `LIVE_UNVERIFIED` | The PID exists but a start time is missing on either side. | soft flag `SESSION_PID_ALIVE_UNVERIFIED` |
| `PID_REUSED` | The PID exists with a different creation time: another process. | evidence line only |
| `DEAD` | The snapshot was read and the PID is not in it. | evidence line only |
| `UNVERIFIABLE` | The snapshot failed (`$Snapshot.Failed`). | soft flag `SESSION_LIVENESS_UNVERIFIABLE` |

**The provider-side liveness rule** (checked by the conformance suite): `DEAD` only when `$Snapshot.Failed` is `$false`
and the PID is absent from `$Snapshot.Processes`. A PID that is present is never `DEAD`: it is `LIVE`, `PID_REUSED` or
`LIVE_UNVERIFIED`. A PID whose creation time equals the recorded start is `LIVE`. The engine trusts `State`, so a
provider that answered `DEAD` too readily would weaken the liveness evidence.

`GetActivityEvidence`: `Readable = $false` gives the soft flag `TRANSCRIPTS_UNREADABLE`. `LastWriteUtc` (UTC, or
`$null` when no artifact exists) younger than 72 hours gives `TRANSCRIPT_RECENT`. Only the time is returned, never the
content.

`GetProjectKey`: `IsHome` is `$true` for the profile folder itself; `Key` names the project. Display only.

**Private to the provider.** `GetConfigDirs().Dirs` and `.Refused`, and any `Notes` field of `GetSessionEvidence`, are
for the provider's own use (the Claude Code provider calls its own `GetConfigDirs` from its evidence members). No engine,
report or TUI reads them, and a provider may leave them out. Do not rely on them being shown.

### "Cannot look" is never "nothing found"

* A provider returns `Readable = $false` when it could not look: access denied, an unreadable folder, a location it
  refused to read. Only a **confirmed absence** (the file or folder does not exist) is "nothing found".
* An empty `Entries` with `Readable = $true` means "looked, and no session is recorded". An empty `LastWriteUtc` with
  `Readable = $true` means "looked, and no activity artifact exists".
* A `temp` member that throws stops the inventory (fail closed): nothing is classified, the audit reports the error,
  and diagnose reports its `inventory` coverage `FAILED` (`INVENTORY_FAILED`). A runtime member that throws or returns a
  malformed value gives that provider's coverage `FAILED` (`HINT_FAILED_*`, `HINT_MALFORMED_*`) and the other providers
  continue.

### Rules

* Providers are **read-only**. They never write, never open credential, key or token files (Claude Code: `*.key`,
  `.credentials.json`), and never print file contents.
* Providers do not classify, gate or delete. All safety logic is shared and identical for every agent. Unknown
  structure is not a provider error: the engine flags it and blocks it.
* **A provider can never weaken a gate.** Returning `LIVE`, `Readable = $true` and recent activity can only add
  evidence; a hard flag is never turned into eligibility by anything a provider returns.
* **The B1 restricted exception belongs to `claude-code`.** The V0.3 exception that lets a Claude Code session root pass
  the process-coverage rule (B1) when the only uncovered processes are identified ones (`Engine.Clean.ps1:174`) is tied
  to the id `claude-code`. A new provider's roots stay under the **full** B1 rule. That is fail closed and stricter,
  not a bug, and it needs no engine change. Extending the exception to another provider is an eligibility change that
  needs its own decision (ADR-0018, section 8). It is the only provider literal in `src/lib/Engine.*.ps1`, and the
  conformance suite fails on any new one.
* **Loading.** The launcher dot-sources every provider file before running a command (in an installed copy, only
  manifest-verified files). A file whose registration throws stops the launcher with that error. The product does not
  skip a failing provider (V10-D5 kept this).

### Versioning

* **Contract 2 is frozen for 1.x.** A provider declares `ContractVersion = 2` and `Capabilities`.
* **Compatible changes** (no version change): a new optional runtime member (absent = "no hints"); a new optional field
  in a return value (absent = "no evidence", never a negative fact, as `StartUtc` was added); a new capability name that
  existing providers do not declare; a stricter validation of a value that no shipped or documented provider uses (as
  the V1.0 checks of script blocks, patterns and integer versions).
* **Breaking changes** (need `ContractVersion = 3`): a new required member; a removed member; a member or field whose
  meaning changes; an argument added, removed or reordered (arguments are positional); an optional field becoming
  required.
* **An unknown version is refused, with the reason shown** (fail closed). `3`, `' 2 '`, `'2'`, `2.0`, `-2` and `$null`
  are all refused with `err.providerContract`. In diagnose and recover such a provider becomes coverage `FAILED` with
  `PROVIDER_CONTRACT_INVALID` and takes no part in the run; the other providers still run.
* **v1 stays accepted throughout 1.x** (V10-D8). A provider **without** `ContractVersion` is a v1 provider with the
  single capability `temp`, validated as above (its `Id` check is case-insensitive). Removing v1 would be a breaking
  change of the product, announced first in one published minor version.

### Reserved: `GetWorktreeHints`

`GetWorktreeHints` (`{ param($ProfileInfo, $Registry) }`, returning `{ Readable; Dirs }`) is **reserved: it is not called
in 1.x.** It stays validated (a script block, with `runtime`) so that a provider that declares it keeps loading. Calling
it would be a new feature behind the worktree diagnostics gate; the worktree discovery (ADR-0007) uses other sources.

## Runtime members (contract 2)

Each runtime member, when present, must be a script block; declaring one without the `runtime` capability is refused.

| Runtime member | Signature | Returns |
|---|---|---|
| `GetProcessMatchers` | `{ }` | `@({ ImageName; CommandLineMarker })`: exact image file name (`*.exe`), optional marker matched in memory against the command line (the command line is never stored or printed). |
| `GetServiceHints` | `{ }` | `@({ Name; Role; ExpectedImage })`: exact Windows service names; `Role` is an optional lower-case id. Since V0.2-P2-A the diagnose queries only these names (one local `Win32_Service` query, read-only), never similar names; a name declared by two providers is reported once with the attribution ambiguous. Declaring no service means that no service is checked, never that none exists; a declared name that is not listed is reported `UNKNOWN`, never absent. `ExpectedImage` (optional, V0.4 R0, ADR-0016 V04-D5 (b)): the service's expected executable, either a file name only (`name.exe`) or a location under `%SystemRoot%`, `%ProgramFiles%`, `%ProgramFiles(x86)%` or `%ProgramW6432%` with plain folders (`%ProgramFiles%\Vendor\name.exe`). Never a drive letter, a profile folder or another variable, `..` or `~`: such a value makes the provider's service hints malformed. Declare only what a public source supports; when the folder is not known, give the file name or nothing. The diagnose compares it with the service's reduced executable in memory and reports only `IMAGE_MATCH`, `IMAGE_MISMATCH` or `IMAGE_UNKNOWN` (`SERVICE_IMAGE`), or `SERVICE_IMAGE_NOT_DECLARED`; the path is never reported. |
| `GetVirtualizationHints` | `{ }` | `@({ Kind; Value })` with `Kind` `ServiceOwner` (a service that owns a VM) or `VmName`. Since V0.2-P2-B: a `VmName` attributes an observed VM whose display name matches exactly (the name is never exported); a `ServiceOwner` attributes a VM only when its worker process is a verified child of the running service, which the same provider must also declare in `GetServiceHints`. A worker process is never attributed by its name. |
| `GetWorktreeHints` | `{ param($ProfileInfo, $Registry) }` | Reserved, not called in 1.x (see above). |

Session evidence (v2, optional and additive): `StartUtc`, described above. The V0.1 `State` of each entry and its 2 s
tolerance are unchanged and keep feeding the audit and its gates.

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
  (`PROVIDER_ATTRIBUTION_AMBIGUOUS`), never resolved by guessing; with Claude Code installed alongside, Claude Desktop
  is therefore never the only provider of a process. A command line that cannot be read leaves the marker unchecked
  (`COMMAND_LINE_MARKER_UNAVAILABLE`), and the process stays ambiguous, never resolved to Claude Code. A consequence for
  every machine: a `claude.exe` whose command line cannot be read (another account's process, or no inventory snapshot)
  now makes `agent-processes` `PARTIAL`. The marker is a substring of the whole command line, so an argument that
  mentions the package path, or another package of the same publisher, also matches: the result is then ambiguous,
  not a wrong attribution. A launch whose command line lacks the package path would not match.
* **Service hint:** `CoworkVMService` (role `cowork-vm`), exact name. A running service with a verified process is
  positive evidence of the local Cowork service, not of a running VM; a service not listed is `UNKNOWN` (Cowork in a
  remote environment, the `.exe` installer, or a service the account cannot see), never "not installed".
* **No `ExpectedImage` (V0.4 R0):** neither Anthropic's documentation nor the two public reports above name the
  executable of `CoworkVMService` or its folder, so the provider declares nothing and the diagnose reports
  `SERVICE_IMAGE_NOT_DECLARED`. No path or file name is invented. Even a known file name could only be compared by
  name if, as for a service that an MSIX package declares, the executable sits in the package folder (`WindowsApps`),
  whose full path the diagnose never keeps.
* **No virtualization hint:** the Cowork VM is an HCS compute system with a per-installation name, not a Hyper-V
  Manager VM, so it is not expected in `Msvm_ComputerSystem`; a `VmName` hint would depend on an arbitrary name, and
  no `ServiceOwner` relation (service -> worker process) is established. `vmmem`, `vmwp`, `vmcompute` and HCS
  processes are never attributed to Claude Desktop.
* **No temp capability:** no per-session temporary directory of Claude Desktop is confirmed for this tool.
* **Version:** not read from the installation, and not exported: an executable inside a packaged app folder
  (`\WindowsApps\`, which carries the version) is reported by file name only. The hints apply to MSIX builds since
  the reported 1.1.3647.

## Provider attribution is not a dependency

A provider attribution says which agent the evidence points to (a matched process, a declared service, a session
registry). It is not, by itself, proof that a temporary partition, a worktree or a VM depends on that agent: a
dependency needs an edge of the dependency graph from a verified source (ADR-0002). When the evidence fits several
providers (Claude Code and Claude Desktop both run `claude.exe`), the attribution is ambiguous: no provider is chosen,
and transitivity never turns it into an exclusive link. **Claude Code** is the CLI agent; **Claude Desktop** is the
desktop app; **Cowork** is a Claude Desktop feature that runs in an app-managed VM, of which only the local
`CoworkVMService` service is observed, under a publicly reported (provisional) name.

## Adding a provider

Adding another agent = one new file in `src/providers/`, the manifest entry and tests. No engine, gate, report or TUI
change is expected. The conformance suite ("Contrato de provider" in `tests/Run-Tests.ps1`, both shells) proves it: a
test-only fixture provider (never in `src/providers/` or the package) is added to a copy of `src`, the copy's manifest is
rebuilt, `audit` and `diagnose` run against it in a child process, and the `Engine.*.ps1` hashes stay equal. The same
suite checks every rule of this file against both shipped providers and the fixture; a new provider must pass it.
