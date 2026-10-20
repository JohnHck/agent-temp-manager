# Diagnose JSON schema (`atm.diagnose/1`)

Written by `agent-temp diagnose -ExportJson <new file>` (V0.2, in development). Decision record:
[ADR-0009](adr/ADR-0009-diagnose-engine-command-schema.md); evidence and coverage model:
[ADR-0001](adr/ADR-0001-evidence-coverage-findings.md). The V0.1 audit export (`agent-temp audit -ExportJson`) is a
different document and is unchanged.

Rules:

* Codes (statuses, reasons, states, evidence codes) are stable, upper-case and language-neutral; only `language`
  differs between an en-US and a pt-BR export of the same run.
* Times are ISO 8601 in UTC (`2026-01-01T12:00:00.0000000Z`); absent values are `null`; lists are always arrays.
* Never exported: command lines, environment values, tokens, exception messages, service command-line arguments, Git
  configuration values, file contents.
* Compatibility: new fields may be added without changing `schemaVersion`; removing a field or changing its meaning
  requires a new version. The suite checks that every field below, and no other, is exported.
* Privacy: the export contains the machine name, the user name and SID, the token elevation state and the paths of
  temporary partitions. Review it before sharing.

A coverage status other than `COMPLETE` or `NOT_PRESENT` means **unknown**: it is never a statement that something is
absent, stopped or unused.

## Top level

| Field | Type | Meaning |
|---|---|---|
| `schemaVersion` | string | `atm.diagnose/1`. |
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
| `inventory` | object | Summary of the V0.1 temporary-directory inventory the run was built on. |

## identity

| Field | Type | Meaning |
|---|---|---|
| `user` | string or null | Account name of the process token. |
| `sid` | string or null | SID of the process token. |
| `elevatedAdministrator` | boolean or null | The token is in the Administrators role (elevated). |
| `elevationType` | string | `DEFAULT`, `FULL`, `LIMITED` or `UNKNOWN` (token elevation type). |
| `integrityLevel` | string | `UNTRUSTED`, `LOW`, `MEDIUM`, `MEDIUM_PLUS`, `HIGH`, `SYSTEM`, `PROTECTED` or `UNKNOWN`. |
| `sessionId` | number or null | Windows session of the process. |

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
| `collector` | string | `identity`, `inventory`, `processes`, `temp-profiles`, `provider-<id>`; later phases add more. |
| `status` | string | `COMPLETE`, `PARTIAL`, `DENIED`, `TIMEOUT`, `NOT_PRESENT`, `NOT_OBSERVABLE`, `UNAVAILABLE` or `FAILED`. |
| `reasons` | array | Reason codes (for example `DEADLINE_EXCEEDED`, `UNINSPECTABLE_PROCESSES`, `PROFILES_INACCESSIBLE`, `HINT_MALFORMED_SERVICE_HINTS`, `EXCEPTION_<TYPE>`). Empty only for `COMPLETE`/`NOT_PRESENT`. |
| `elevationWouldHelp` | string | `YES`, `NO` or `UNKNOWN`. |
| `observed` | number or null | Items observed, when known. |
| `expected` | number or null | Items that exist, when known. |
| `startedUtc` | string or null | Start of the collector. |
| `elapsedMs` | number or null | Time spent. |
| `budgetMs` | number or null | Time budget enforced on the collector; `null` when none is enforced (for example the V0.1 inventory, which cannot be interrupted). |

## findings[]

| Field | Type | Meaning |
|---|---|---|
| `kind` | string | `Process`, `Service`, `VirtualMachine`, `Worktree`, `Repository`, `AgentSession` or `TempPartition`. |
| `key` | string | Stable identity of the item (for a temporary partition: its path). |
| `state` | string | State code. In P1-A temporary partitions are `RUNTIME_NOT_DIAGNOSED`. A "no dependency" state becomes `UNKNOWN` unless every coverage record of the finding is conclusive. |
| `requestedState` | string | State before that rule was applied. |
| `provider` | string or null | Provider that contributed the item. |
| `coverage` | array | Collectors (ids in `coverage[]`) the state depends on. |
| `incompleteCoverage` | array | Those of them that are not `COMPLETE`/`NOT_PRESENT`. |
| `evidence` | array | Evidence records. |

## findings[].evidence[]

| Field | Type | Meaning |
|---|---|---|
| `code` | string | Evidence code (`AUDIT_CLASS`, `AUDIT_FLAG`; later phases add more). |
| `source` | string | Where it comes from (`audit`). |
| `collector` | string | Collector that produced it. |
| `observedUtc` | string | When it was observed. |
| `detail` | string or null | Short code-like value (for example the V0.1 class or flag), at most 512 characters. |

## inventory

| Field | Type | Meaning |
|---|---|---|
| `collected` | boolean | `false` when the inventory did not run (deadline or failure); the other fields are then `null`. |
| `coverageComplete` | boolean or null | V0.1 coverage verdict of the inventory. |
| `partitions` | number or null | Number of measured partitions. |
| `bytes` | number or null | Logical bytes of those partitions. |
