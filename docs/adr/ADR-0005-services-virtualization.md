# ADR-0005: Services and virtualization

Status: PROPOSED
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
