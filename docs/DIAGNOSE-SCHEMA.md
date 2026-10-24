# Diagnose JSON schema (`atm.diagnose/2`)

Written by `agent-temp diagnose -ExportJson <new file>` (V0.2, in development). Decision record:
[ADR-0009](adr/ADR-0009-diagnose-engine-command-schema.md); evidence and coverage model:
[ADR-0001](adr/ADR-0001-evidence-coverage-findings.md); pseudonyms of exported identifiers:
[ADR-0010](adr/ADR-0010-pseudonymization-of-exported-identifiers.md). The V0.1 audit export (`agent-temp audit
-ExportJson`) is a different document and is unchanged.

Rules:

* Codes (statuses, reasons, states, evidence codes) are stable, upper-case and language-neutral; only `language`
  differs between an en-US and a pt-BR export of the same run.
* Times are ISO 8601 in UTC (`2026-01-01T12:00:00.0000000Z`); absent values are `null`; lists are always arrays.
* Never exported: command lines, environment values, tokens, exception messages, service command-line arguments, Git
  configuration values, file contents.
* Compatibility: new fields may be added without changing `schemaVersion`; removing a field or changing its meaning
  requires a new version. The suite checks that every field below, and no other, is exported.
* Privacy: no path and no session identifier is exported. Temporary partitions and agent sessions are identified by
  keyed pseudonyms (HMAC-SHA256, 128 bits, see `pseudonymization`): without the key nobody can compute or check them,
  the export included. The key is ephemeral (one run) unless the operator supplies a key file
  (`-PseudonymKeyFile`); only then are the pseudonyms of two exports comparable (same `keyId`). The export still
  contains the machine name, the user name and SID and the token elevation state; process keys, counts and coverage
  are not pseudonymized and stay linkable between runs. Review the export before sharing.
* Order: temporary partitions come first, ordered by `key` (ordinal) after collisions are grouped, all with the same
  observation time: the position of a directory in the file-system enumeration is not kept (ADR-0010, D-8); open-file
  evidence, when present, has its own single time (the start of the handle batch). Runtime
  findings (`Process`, `AgentSession`) follow, ordered by `kind` and then `key` (ordinal). For one key, the order of
  providers, registries, profiles or directories never changes the document; with another key (an ephemeral key in
  every run) the order follows the new pseudonyms.

Changes from `atm.diagnose/1` (P1-B4-d):

* `schemaVersion` is `atm.diagnose/2`.
* Temporary partitions are ordered by `key` instead of the V0.1 inventory order.
* `findings[].key` of a `TempPartition` is `<provider>/p-<32 hex>` (it was the partition path) and of an
  `AgentSession` `<provider>/s-<32 hex>` computed with a key (it was an unkeyed hash).
* New top-level object `pseudonymization`.
* Everything else is unchanged; version 1 is no longer written.

A coverage status other than `COMPLETE` or `NOT_PRESENT` means **unknown**: it is never a statement that something is
absent, stopped or unused.

## Top level

| Field | Type | Meaning |
|---|---|---|
| `schemaVersion` | string | `atm.diagnose/2`. |
| `toolVersion` | string | Version of Agent Temp Manager that produced the file. |
| `language` | string | Language of the run (`en-US`, `pt-BR`); does not affect any other field. |
| `machine` | string | Machine name. |
| `startedUtc` | string | Start of the run. |
| `finishedUtc` | string | End of the run. |
| `deadlineUtc` | string | Global deadline of the run. |
| `deadlineSeconds` | number | Deadline in seconds (`-DeadlineSeconds`, default 300). |
| `coverageComplete` | boolean | `true` only if every coverage record is `COMPLETE` or `NOT_PRESENT`. |
| `identity` | object | Identity and elevation state of the process that ran the diagnostics. |
| `providers` | array | Providers taking part in the run. |
| `coverage` | array | One record per collector. |
| `findings` | array | Findings with their evidence. |
| `agentResources` | object | Resource totals of the agent processes, each process counted once. |
| `pseudonymization` | object | How the keys of partitions and sessions were pseudonymized. |
| `inventory` | object | Summary of the V0.1 temporary-directory inventory the run was built on. |

## identity

| Field | Type | Meaning |
|---|---|---|
| `user` | string or null | Account name of the process token. |
| `sid` | string or null | SID of the process token. |
| `elevatedAdministrator` | boolean or null | The token is in the Administrators role (elevated). |
| `elevationType` | string | `DEFAULT`, `FULL`, `LIMITED` or `UNKNOWN` (token elevation type). |
| `integrityLevel` | string | `UNTRUSTED`, `LOW`, `MEDIUM`, `MEDIUM_PLUS`, `HIGH`, `SYSTEM`, `PROTECTED` or `UNKNOWN`. |
| `sessionId` | number or null | Windows logon session of the process (not an agent session). |

## providers[]

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Provider id. |
| `displayName` | string | Display name. |
| `contractVersion` | number | `1` or `2` ([PROVIDERS.md](PROVIDERS.md)). |
| `capabilities` | array | `temp` and/or `runtime`. |

## coverage[]

| Field | Type | Meaning |
|---|---|---|
| `collector` | string | `identity`, `provider-<id>`, `inventory`, `processes`, `temp-profiles`, `process-snapshot` (process identities, creation times and parent links), `sessions-<id>` (session registries of a provider over every profile; one record per provider), `agent-processes` (discovery of agent processes from the providers' evidence sources; `COMPLETE` covers only those sources), `agent-resources` (the totals in `agentResources`) and, only while the worktree diagnostics gate is open (closed in every shipped copy), `worktree-discovery` (always `PARTIAL` with `DISCOVERY_BOUNDED`: discovery sees only its sources, so no absence is ever concluded; `NOT_OBSERVABLE` with `WORKTREE_DIAGNOSTICS_GATE_CLOSED` when repository paths are given while the gate is closed) and `git` (the Git calls of the discovery), `local-work-status` (Git `status` of each worktree a source led to; never `COMPLETE`: `HIDDEN_ENTRIES_NOT_OBSERVED`, since changes inside gitlinks and in entries flagged assume-unchanged or skip-worktree are not shown; `Observed` counts the runs that completed; a worktree with submodules declared or a D-3 block is not run) `local-work-files` (operation markers and the stash reflog, read as files) `publication-files` (P3-D: HEAD and the repository's references read as files, never Git), `services` (P2-A: one local query of `Win32_Service` for the exact names providers declare; `NOT_OBSERVABLE` with `SERVICE_HINTS_NONE` when no provider declares a service, and then nothing is queried, which is never an absence of services; `DENIED`, `FAILED` or `TIMEOUT` when the query did not complete; `PARTIAL` when the declared names are incomplete or capped, the answer holds an unexpected or repeated name, or a declared name is not listed (`SERVICE_NOT_LISTED_FOR_ACCOUNT`: the account may not be allowed to see it); otherwise `COMPLETE`), `service-properties` (P2-A: the values and process links of the services that were listed: `PARTIAL` with `SERVICE_PROPERTY_UNREADABLE` or `SERVICE_PROCESS_UNVERIFIED`; `NOT_OBSERVABLE` when the query did not complete or nothing is declared), `virtualization-platform` (P2-B: the hypervisor flag, the WMI namespace `root\virtualization\v2` listed and the state of the Hyper-V management service `vmms`, read-only; `PARTIAL` with `VIRTUALIZATION_NAMESPACE_NOT_LISTED`, `VMMS_NOT_LISTED` or `PLATFORM_NOT_OBSERVED` when a sign is not listed, which is never an absence; `DENIED` or `FAILED` when every read was refused or failed), `virtual-machines` (P2-B: one `Msvm_ComputerSystem` query, only when the namespace is listed and `vmms` is running, since its provider is hosted by `vmms.exe` and a query could otherwise start it; `NOT_OBSERVABLE` with the reason otherwise; `DENIED` with `elevationWouldHelp` `YES`; `PARTIAL` for more objects than the limit of 256, ambiguous or malformed objects; `COMPLETE` with no VM means "no VM observed for this account", never "no VM"), `virtualization-processes` (P2-B: `vmwp.exe` and `vmmem*` from the process snapshot of the run, by class only), `process-cwd` (P1-C: always `NOT_OBSERVABLE`, `WORKING_DIRECTORY_DEFERRED`) and `handles` (P1-C: in every shipped copy `NOT_OBSERVABLE` with `HANDLE_SECURITY_GATE_CLOSED`: the open-file diagnostics gate is closed, so no file is listed and Restart Manager is not called; this is never an absence of open files. Only with the gate open, which only the tests do on fixtures: Restart Manager over a sample of files of each temporary partition, and of each worktree's index when discovery runs; never `COMPLETE`); later phases add more. Each collector has exactly one record, `TIMEOUT` when the deadline came first. |
| `status` | string | `COMPLETE`, `PARTIAL`, `DENIED`, `TIMEOUT`, `NOT_PRESENT`, `NOT_OBSERVABLE`, `UNAVAILABLE` or `FAILED`. |
| `reasons` | array | Reason codes (for example `DEADLINE_EXCEEDED`, `UNINSPECTABLE_PROCESSES`, `PROFILES_INACCESSIBLE`, `HINT_MALFORMED_SERVICE_HINTS`, `EXCEPTION_<TYPE>`). Empty for `COMPLETE`/`NOT_PRESENT`, and only for them: a conclusive status never carries a reason (ADR-0001 amendment). |
| `elevationWouldHelp` | string | `YES`, `NO` or `UNKNOWN`. |
| `observed` | number or null | Items observed, when known. |
| `expected` | number or null | Items that exist, when known. |
| `startedUtc` | string or null | Start of the collector. |
| `elapsedMs` | number or null | Time spent. |
| `budgetMs` | number or null | Time budget enforced on the collector; `null` when none is enforced (for example the V0.1 inventory, which cannot be interrupted). |

## findings[]

| Field | Type | Meaning |
|---|---|---|
| `kind` | string | `Process`, `Service`, `VirtualMachine`, `VirtualizationPlatform` (P2-B), `Worktree`, `Repository`, `AgentSession` or `TempPartition`. |
| `key` | string | Identity of the item. Temporary partition: `<provider>/p-<32 hex>`, the keyed pseudonym of the provider and the partition path (the path is never exported). Process: `<pid>@<creation ticks UTC>`, or `pid:<pid>` when the identity could not be verified (never an identity); not pseudonymized. Agent session: `<provider>/s-<32 hex>`, the keyed pseudonym of the provider, the profile (SID and path) and the session id: with the same key, the same session of the same profile has the same pseudonym and the same session id in another profile has another one; the session id is never exported. Two partitions or sessions with the same pseudonym are one `UNKNOWN` finding (`PARTITION_KEY_COLLISION`, `SESSION_KEY_COLLISION`). Repository: `git/r-<32 hex>` (domain `atm-repository/1`, the normalized common Git directory), or `git/t-<32 hex>` (domain `atm-repository-target/1`, a candidate refused by the preflight, never given to Git). Worktree: `git/w-<32 hex>` (domain `atm-worktree/1`, the normalized worktree directory). Service: the service name as a provider declared it (matched without regard to case; not pseudonymized: it is a published product name). Virtualization platform: `host`. Virtual machine: `vm/v-<32 hex>` (domain `atm-virtual-machine/1`, the lower-case VM GUID); the GUID, the display name and the host name are never exported; two VMs with one key are one `UNKNOWN` finding (`VM_KEY_COLLISION`). No repository or worktree path, branch, lock reason or configuration value is exported (D-5). |
| `state` | string | State code from the closed list of the finding's kind (any other is refused). Temporary partitions: `RUNTIME_NOT_DIAGNOSED`. `Process`: `SELF` (this run, its launcher or its own children), `AGENT_PROCESS`, `AGENT_DESCENDANT`, `IDENTITY_UNVERIFIED`, `UNKNOWN`. `AgentSession`: `LIVE` (exact identity), `PID_REUSED` (not proof that the session ended), `IDENTITY_UNVERIFIED`, `SESSION_PROCESS_NOT_FOUND`, `UNKNOWN`. `Repository`: `UNKNOWN`. `VirtualizationPlatform` (P2-B): `PRESENT` only when the namespace or the management service is listed (the hypervisor flag alone is not enough: it is true inside a virtual machine), otherwise `UNKNOWN`; `NOT_PRESENT` is in the list but never produced. `VirtualMachine` (P2-B): from the documented `EnabledState`: `RUNNING` (2), `OFF` (3), `PENDING` (4 shutting down, 10 starting), `PAUSED` (32768), `SAVED` (32769), any other value `UNKNOWN`. `Service` (P2-A): `RUNNING`, `STOPPED`, `PAUSED`, `PENDING` (start, stop, pause or continue pending) as the service control manager reports them; a declared name that is not listed is `UNKNOWN` (never `NOT_PRESENT`: the service control manager may leave out services the account may not query; `NOT_PRESENT` stays in the list for a future source and is not produced); otherwise `UNKNOWN`. `Worktree`: `LOCAL_WORK` (P3-C: a positive local work fact), `UNPUBLISHED_COMMITS` (in the closed list; not given by any collector yet: files cannot prove it), `APPARENT_ORPHAN` only when its administrative entry is positively not found (never for a refused or unreadable target), otherwise `UNKNOWN` (with `LOCAL_WORK_NONE_OBSERVED` or `LOCAL_WORK_UNKNOWN`, and `PUBLICATION_NOT_DIAGNOSED` until P3-D); `CLEAN_AND_PUBLISHED_UNKNOWN` is never given yet. A "no dependency" or an absence state (`SESSION_PROCESS_NOT_FOUND`, `NOT_PRESENT`) becomes `UNKNOWN` unless every coverage record of the finding is conclusive. No state frees or authorizes the deletion of a temporary directory. |
| `requestedState` | string | State before that rule was applied. |
| `provider` | string or null | Provider that contributed the item. `null` for a process related to several providers (the evidence `PROVIDER_ATTRIBUTION_AMBIGUOUS` lists them; none is chosen) or to none. |
| `coverage` | array | Collectors (ids in `coverage[]`) the state depends on. |
| `incompleteCoverage` | array | Those of them that are not `COMPLETE`/`NOT_PRESENT`. |
| `evidence` | array | Evidence records. |

## findings[].evidence[]

| Field | Type | Meaning |
|---|---|---|
| `code` | string | Evidence code: `AUDIT_CLASS`, `AUDIT_FLAG`; `PROCESS_MATCHER_IMAGE`, `PROCESS_MATCHER_MARKER` (checked in memory, never exported), `COMMAND_LINE_MARKER_UNAVAILABLE`, `SESSION_REGISTRY`, `SESSION_PROCESS`, `SESSION_PROCESS_MATCH`, `PATH_REFERENCE`, `SELF_EXCLUSION`, `PARENT_LINK_VERIFIED`, `PROVIDER_ATTRIBUTION_AMBIGUOUS`, `PROCESS_EXITED_DURING_RUN` (the process exited between the two process collections of the run, both complete: the rest of the evidence is stale), `SESSION_KEY_COLLISION`, `SESSION_ENTRIES_CONFLICT`, `PARTITION_KEY_COLLISION` (detail: how many partitions); worktree discovery (P3-B): `REPOSITORY_DISCOVERED` (detail `PARTITION` or `EXPLICIT`), `REPOSITORY_PREFLIGHT_REFUSED` (detail: the preflight code), `REPOSITORY_CONFIRMED_BY_GIT`, `REPOSITORY_MISMATCH`, `GIT_NOT_RUN` (detail: a reason code, `REPOSITORY_OUTSIDE_SOURCES` for a repository reached only through a worktree's gitdir), `ALTERNATES`, `WORKTREES_REGISTERED` (detail: count), `WORKTREE_MAIN`, `WORKTREE_REGISTERED`, `WORKTREE_LOCKED` (presence only; the reason is never read), `WORKTREE_DIRECTORY_MISSING`, `ADMINISTRATIVE_ENTRY_NOT_FOUND`, `LOCAL_WORK_UNKNOWN`, `IN_REPOSITORY` (detail: the repository key); local work (P3-C, counts only, never a path or name): `STAGED`, `UNSTAGED`, `UNTRACKED`, `IGNORED`, `CONFLICTS` (detail: entries), `SUBMODULES` (detail: a count or `DECLARED`), `OPERATION_IN_PROGRESS` (detail: `MERGE`, `REBASE`, `CHERRY_PICK`, `REVERT`, `BISECT` or `SEQUENCER`), `STASHES_IN_REPOSITORY` (repository; detail: count), `STASH_MENTIONS_BRANCH` (detail: count), `LOCAL_WORK_NONE_OBSERVED`, `LOCAL_WORK_NOT_OBSERVED` (detail: the reason code), `PUBLICATION_NOT_DIAGNOSED`; publication (P3-D, files only, never a reference name): `HEAD_STATE` (detail `BRANCH`, `DETACHED` or `UNBORN`), `UPSTREAM_CONFIGURED`, `NO_UPSTREAM`, `NO_REMOTE_TRACKING_REFS` (an observation: never proof that the commits were never published), `PUBLICATION_UNVERIFIED` (detail `HEAD_TIP_ON_REMOTE_TRACKING`; never proof that a server has the commits), `PUBLICATION_UNKNOWN` (detail `REACHABILITY_NOT_READ` or `NO_REMOTE_TRACKING_REFS`), `PUBLICATION_NOT_OBSERVED` (detail: the reason code), `DETACHED_TIP_REFERENCED`, `COMMITS_ONLY_IN_THIS_WORKTREE_POSSIBLE`, `LAST_FETCH_AGE_DAYS` (informative); open files (P1-C, on `TempPartition` and `Worktree` findings, only when a process holds one of the files checked, and only while the open-file diagnostics gate is open, which it never is in a shipped copy; `observedUtc` is the start of the handle batch (its query phase: after the files were sampled, before the first query), equal to the `startedUtc` of the `handles` coverage record and the same for every item, never the partitions' observation time): `OPEN_FILES_SAMPLED` (detail: files checked), `FILE_HELD_OPEN` (detail: the holder's process key `<pid>@<creation ticks>`), `FILE_HELD_OPEN_UNVERIFIED` (detail `pid:<pid>`: identity not verified); never a file path or process name; virtualization (P2-B, on the `VirtualizationPlatform` finding): `HYPERVISOR_PRESENT_FLAG` (`TRUE`/`FALSE`), `HYPERVISOR_FLAG_UNREADABLE`, `VIRTUALIZATION_NAMESPACE_LISTED`, `VIRTUALIZATION_NAMESPACE_NOT_LISTED` (detail `NOT_LISTED_FOR_ACCOUNT`), `VIRTUALIZATION_NAMESPACE_NOT_QUERIED`, `VMMS_SERVICE_STATE`, `VMMS_SERVICE_NOT_LISTED`, `VMMS_NOT_QUERIED`, `VIRTUALIZATION_WORKER` (detail `VMWP|<process key>` or `VMMEM|<process key>`), `VIRTUALIZATION_WORKER_UNVERIFIED` (detail `<class>|pid:<pid>`), `VIRTUALIZATION_WORKERS_WORKING_SET_BYTES`, `VIRTUALIZATION_WORKERS_PRIVATE_BYTES`, `VIRTUALIZATION_WORKERS_CPU_TIME_100NS` (totals over the workers whose counters were read; absent when none was read, never 0), `VIRTUALIZATION_WORKER_COUNTERS_INCOMPLETE` (detail `<read>/<workers>`), `VM_HINT_NOT_OBSERVED` (detail: provider id; never the name); on `VirtualMachine` findings: `VM_ENABLED_STATE` (detail: the numeric code), `VM_STATE_UNREADABLE`, `VM_WORKER_VERIFIED` (detail: process key of its `vmwp.exe`, created before the query and in the snapshot taken after it), `VM_WORKER_UNVERIFIED` (detail: the reason, including `NOT_A_WORKER_PROCESS`), `VM_ATTRIBUTED_BY_NAME` (detail: provider id), `VM_ATTRIBUTED_BY_SERVICE` (detail `<provider>|<service>`), `VM_UNATTRIBUTED`, `VM_KEY_COLLISION`; no raw process name (a `vmmem.<suffix>` can carry a VM name), VM name, GUID, disk path or configuration value is exported; Services (P2-A, on `Service` findings): `SERVICE_HINT` (detail: provider id, and `:<role>` when declared), `SERVICE_NOT_LISTED` (detail `NOT_LISTED_FOR_ACCOUNT`: an observation, not proof of absence), `SERVICE_NOT_QUERIED` (detail: the coverage status, or `SERVICE_HINTS_CAPPED`), `SERVICE_STATE`, `SERVICE_START_MODE` (`BOOT`, `SYSTEM`, `AUTO`, `MANUAL`, `DISABLED`), `SERVICE_DELAYED_AUTO_START` (`TRUE`/`FALSE`), `SERVICE_ACCOUNT_KIND` (`LOCAL_SYSTEM`, `LOCAL_SERVICE`, `NETWORK_SERVICE`, `VIRTUAL`, `BUILTIN`, `MANAGED`, `USER`), `SERVICE_ACCOUNT` (only `LocalSystem`, `NT AUTHORITY\LocalService` or `NT AUTHORITY\NetworkService`, in that standard spelling; no other account name is ever exported, ADR-0012), `SERVICE_EXECUTABLE` (the full executable path, only in a well-known program location), `SERVICE_EXECUTABLE_NAME` (the file name only, anywhere else), each with an `_UNREADABLE` code when the value could not be read (never 0 or false; `SERVICE_EXECUTABLE_UNREADABLE` carries `EXECUTABLE_UNREADABLE` or `EXECUTABLE_UNPARSEABLE`), `SERVICE_PROCESS_VERIFIED` (detail: process key; the process was created before the query and is in the snapshot taken after it), `SERVICE_PROCESS_UNVERIFIED` (detail: `PID_NOT_REPORTED`, `SERVICE_NOT_RUNNING`, `PROCESS_SNAPSHOT_UNAVAILABLE`, `SNAPSHOT_BEFORE_QUERY`, `DUPLICATE_PID`, `PROCESS_NOT_COLLECTED`, `CREATION_TIME_UNKNOWN`, `CREATED_AFTER_QUERY`), `SERVICE_DUPLICATE_ROW`; the service command line and its arguments are never exported; later phases add more. |
| `source` | string | Where it comes from (`audit`, `process-matcher`, `session-registry`, `path-reference`, `diagnose`, `restart-manager`, `service-control-manager`, `provider`, `virtualization`, ...). |
| `collector` | string | Collector that produced it. |
| `observedUtc` | string | When it was observed. |
| `detail` | string or null | Short code-like value (the V0.1 class or flag, a reason code, a process key, provider ids), at most 512 characters. |

## agentResources

Totals over the union of the `AGENT_PROCESS` and `AGENT_DESCENDANT` processes, `SELF` excluded: a process in several
overlapping trees (nested agent processes) is counted once. Processes that are `UNKNOWN` or `IDENTITY_UNVERIFIED` are
not counted, so the totals are complete only when `agent-processes` is conclusive. With no agent process identified
by the observed sources and a conclusive `agent-processes`, the sums are `0`; otherwise an unread value is `null`,
never `0`.

| Field | Type | Meaning |
|---|---|---|
| `collected` | boolean | `false` when the runtime was not observed (deadline); the other fields are then `null` or empty. |
| `processes` | number or null | Processes counted. |
| `complete` | boolean | Every counter of every process was read, the CPU was sampled and `agent-processes` is conclusive. |
| `reasons` | array | Why the totals are not complete (for example `AGENT_PROCESSES_INCOMPLETE`, `CPU_NOT_SAMPLED`, `COUNTERS_UNREADABLE`, `CPU_PROCESS_EXITED`). |
| `cpuIntervalMs` | number or null | Interval between the two process collections of the CPU sample. |
| `counters` | object or null | One entry per counter. |

## agentResources.counters

| Field | Type | Meaning |
|---|---|---|
| `cpuTime100ns` | object | Kernel plus user CPU time, in 100 ns units. |
| `kernelTime100ns` | object | Kernel CPU time, in 100 ns units. |
| `userTime100ns` | object | User CPU time, in 100 ns units. |
| `workingSetBytes` | object | Working set, in bytes. |
| `privateBytes` | object | Private memory, in bytes. |
| `handleCount` | object | Open handles. |
| `readTransferBytes` | object | Bytes read by I/O operations since each process started. |
| `writeTransferBytes` | object | Bytes written by I/O operations since each process started. |
| `otherTransferBytes` | object | Bytes of other I/O operations since each process started. |
| `cpuPercent` | object | CPU percentage of all logical processors over `cpuIntervalMs`. |

## agentResources.counters.*

| Field | Type | Meaning |
|---|---|---|
| `sum` | number or null | Sum of the values read; a lower bound when `complete` is `false`; `null` when none was read. |
| `known` | number | Processes whose value was read. |
| `complete` | boolean | Every counted process was read (and, for `cpuPercent`, the CPU was sampled). |

## pseudonymization

| Field | Type | Meaning |
|---|---|---|
| `scheme` | string | `HMAC-SHA256-128/1`. |
| `keySource` | string | `EPHEMERAL` (a random key for this run only; pseudonyms are not comparable with another run) or `OPERATOR_KEY_FILE` (the key file given with `-PseudonymKeyFile`). |
| `keyId` | string or null | Identifier of an operator key (32 hex, its own HMAC domain): two exports with the same `keyId` used the same key. `null` for an ephemeral key. It does not reveal a random key, but it does not guarantee entropy: a weak operator key (a passphrase) can be tested offline against it. |

## inventory

| Field | Type | Meaning |
|---|---|---|
| `collected` | boolean | `false` when the inventory did not run (deadline or failure); the other fields are then `null`. |
| `coverageComplete` | boolean or null | V0.1 coverage verdict of the inventory. |
| `partitions` | number or null | Number of measured partitions. |
| `bytes` | number or null | Logical bytes of those partitions. |
