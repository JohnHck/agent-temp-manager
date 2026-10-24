# ADR-0005: Services and virtualization

Status: ACCEPTED (maintainer gate 2026-10-20, after PR #19); rule 6 replaced by [ADR-0012](ADR-0012-service-account-privacy.md) (2026-10-24)
Date: 2026-10-20
Phase: P2

## Context

The roadmap asks for the state, start type and account of agent-related services (for example `CoworkVMService`
when present, Claude Desktop scenario) and for Hyper-V / virtual-machine worker processes such as `vmmem`, attributed
to an agent scenario only when that can be established. Absence must be reported as "not present", never as an
error; nothing may be started, stopped or reconfigured.

## Decision

### Services

1. Source: one CIM query of `Win32_Service` (properties `Name`, `DisplayName`, `State`, `StartMode`,
   `DelayedAutoStart`, `StartName`, `ProcessId`, `PathName`). No `Get-Service`/`sc.exe` mutating verbs, no
   `Set-Service`, `Start-Service`, `Stop-Service`, `Restart-Service`, `Suspend-Service` anywhere in the engine
   (static test).
2. **Which services:** only names declared by providers (ADR-0008 `GetServiceHints`), matched exactly
   (case-insensitive). No heuristic matching on display names or paths.
3. **Coverage:** query succeeded and the declared name is absent: `NOT_PRESENT`. Query failed or was denied: `DENIED`
   / `FAILED` (the service is `UNKNOWN`, never "not present").
4. **Privacy:** `PathName` contains the service command line. It is used in memory only to extract the executable
   path; the arguments are never stored, printed or exported. The report shows the executable file name, and the full
   executable path only if it lies in a well-known program location (`%ProgramFiles%`, `%ProgramFiles(x86)%`,
   `%SystemRoot%`); otherwise the file name only.
5. **Link to processes:** `ProcessId` is linked to a process only through ADR-0003 identity (the process must exist
   in the snapshot; the service state must be running); otherwise the link is `UNVERIFIED`.
6. `StartName` (the account) is reported as the account name; for `LocalSystem`, `NT AUTHORITY\...` and virtual
   service accounts it is shown as such. Elevation does not change what is shown; if a property is not readable it is
   `$null` with `PARTIAL`.

### Virtualization

7. **Detection is read-only and layered**, each layer with its own coverage:
   * presence of the Hyper-V platform: read-only checks that do not require administrative rights where available
     (for example the existence of the `root\virtualization\v2` namespace and of the `vmms` service through the
     services collector);
   * virtual machines: CIM `root\virtualization\v2` `Msvm_ComputerSystem` (read). A standard user is normally denied:
     `DENIED` with `ElevationWouldHelp = YES` (or membership of *Hyper-V Administrators*); never "no VMs";
   * worker processes: `vmmem`/`vmmem.<name>` and `vmwp.exe` from the process snapshot, with resources (ADR-0003).
   The Hyper-V PowerShell module is **not** required and not imported by default (it may be absent, and importing it
   is not needed to read WMI).
8. **Attribution:** a VM or worker is attributed to a provider scenario only through evidence declared by the
   provider (ADR-0008 `GetVirtualizationHints`, for example a service that owns the VM, a VM name declared by the
   provider, or a worker process whose verified parent is the provider's service). Otherwise it is
   `UNATTRIBUTED`. `vmmem` alone is never attributed (WSL 2, Windows Sandbox and other features also use it).
9. No VM operation is referenced anywhere (`Start-VM`, `Stop-VM`, `Save-VM`, `Checkpoint-VM`, `RequestStateChange`,
   any `Msvm_*` method invocation): static test. WMI is used only with queries (`Get-CimInstance` /
   `Get-CimAssociatedInstance`), never `Invoke-CimMethod`.

## Rejected alternatives

* *`Get-VM` as the main source:* requires the Hyper-V module and Hyper-V administrator rights; absent module would be
  mistaken for absent VMs.
* *Matching services by display name or path patterns:* produces false attributions; providers declare exact names.
* *Exporting `PathName`:* it is a command line.

## Consequences

* A standard user usually sees services and worker processes but not VM configuration: the report shows the
  platform as present, VMs as `UNKNOWN (DENIED)` and workers as `UNATTRIBUTED`.
* Hints for Claude Desktop (service names, VM names) must be confirmed by read-only observation on a machine where it
  is installed (P2), recorded in the provider with the date and version observed; tests use mocks only.

## Verification

* Mocked CIM sources: service present (each state and start mode), absent, denied, query failure; Hyper-V namespace
  absent, present and denied; VM list with and without a matching hint; `vmmem` with and without a verified parent.
* Read-only assertion on the real machine: services' `State` and `StartMode` snapshot identical before and after a
  diagnose run.
* Static tests listed above; privacy test that no `PathName` argument appears in output or JSON.

## Implementation (P2-A, 2026-10-24)

The decisions above are unchanged; this records how P2-A implemented rules 1 to 6 (virtualization, rules 7 to 9, is
P2-B; the Claude Desktop hints are P2-C).

* **Query.** `Get-AtmServiceRaw`: one local `Get-CimInstance -ClassName Win32_Service` with the properties of rule 1
  except `DisplayName` (not needed: it is never used to match), filtered by `Name='...'` for the declared names (at most
  64 per run; names are checked again against the contract's character set before the filter is built) and
  `-OperationTimeoutSec 30`. The answer is matched again in memory, case-insensitively, with the declared names; a name
  that was not asked for (for example a similar name) or a repeated name makes the query `PARTIAL`.
* **Coverage.** `services` (one per run): `TIMEOUT` when the deadline came first; `NOT_OBSERVABLE` / `SERVICE_HINTS_NONE` when no provider declares a service
  (nothing is queried; this is the case of every run until a provider declares one), `TIMEOUT` (deadline before the
  query, or a failure after the budget), `DENIED` (access denied by exception type, CIM code or HRESULT), `FAILED`,
  `PARTIAL` (declared names incomplete because a provider's member failed or a provider was not read, names capped,
  unexpected or repeated rows, or a declared name not listed: `SERVICE_NOT_LISTED_FOR_ACCOUNT`) or `COMPLETE` (every
  declared name listed; never with a reason). Only the exception type is kept. `service-properties` (one per run) carries unreadable values and
  unverified process links, so an unreadable value of one service never turns another service's absence into
  `UNKNOWN`.
* **States.** `Service`: `RUNNING`, `STOPPED`, `PAUSED`, `PENDING`, `NOT_PRESENT`, `UNKNOWN`. Since P2-A-S the
  collector never produces (or requests) `NOT_PRESENT`: a declared name that the service control manager does not
  list is `UNKNOWN` with `SERVICE_NOT_LISTED` (an observation), because `EnumServicesStatusEx` may silently leave out
  services the caller may not query, and no source used here tells a missing service from a hidden one. This
  narrows rule 3 for services. `NOT_PRESENT` stays in the closed list (an absence state that `New-AtmFinding` keeps
  only with conclusive coverage) for a future source with that semantics. Denied, failed, timed-out, capped or
  incomplete queries give `UNKNOWN`.
* **Process link (rule 5).** `Win32_Service.ProcessId` has no creation time, so the services query runs before the
  process snapshot of the run, which must start after the query ended. A PID is linked (`SERVICE_PROCESS_VERIFIED`, with the process key) only when the service
  is running and the snapshot, taken after the query, holds that PID with a verified identity created at least 1 us
  before the query started: such a process was alive during the whole query, and a live PID belongs to one process.
  Otherwise `SERVICE_PROCESS_UNVERIFIED` with the reason. No process is opened.
* **Privacy (rule 4).** `ConvertFrom-AtmServicePathName` reads the command line as untrusted text only (P2-A-S):
  nothing is opened, run, resolved or looked up on any disk (no existence or metadata check: a fixed drive letter does
  not prove that a folder on the way is not redirected, possibly to the network). It keeps only the executable: the
  full path when every folder is plain and it is textually under the Windows folder or a program files folder,
  otherwise the file name. A quoted candidate may hold spaces when `.exe` appears once, at its end; an unquoted one
  may not hold white space (it would be ambiguous); `=`, `/`, a second `:`, variables other than the program
  folders, network and device forms (`\\server`, `\\.\`, `\\?\`) and a file name with white space give a code only.
  The command line is dropped when the row is read.
* **Accounts (rule 6, replaced by ADR-0012).** Only the kind is exported, plus a standard identifier for
  `LocalSystem`, `NT AUTHORITY\LocalService` and `NT AUTHORITY\NetworkService`; user, managed, virtual and other
  built-in account names are never exported.
* **Two providers** declaring one name: one finding, provider `null`, `PROVIDER_ATTRIBUTION_AMBIGUOUS`.
* **Not resolved:** a service whose security descriptor denies the caller the right to query it may be omitted by the
  service control manager. Since P2-A-S such a name reads `UNKNOWN`, the same as a name that does not exist
  (simulated with an injected source; a real hidden service was not created, since that needs a modified security
  descriptor).
