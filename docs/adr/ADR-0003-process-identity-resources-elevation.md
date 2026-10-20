# ADR-0003: Process identity, resources and elevation state

Status: PROPOSED
Date: 2026-10-20
Phase: P1

## Context

V0.1 takes one `Win32_Process` snapshot (PID, name, parent PID, command line, creation date) and treats a process
without a readable command line as uninspectable. The Claude Code provider already guards against PID reuse by
comparing the session's `procStart` with the process creation time. V0.2 needs process trees, per-tree resource
consumption and an explicit statement of the identity and elevation state the diagnostics ran with (PRIV-10).

## Decision

### Identity and PID reuse

1. A process is identified by **`pid@creationTicksUtc`**, never by PID alone. Every reference to a process (session
   registry, service `ProcessId`, parent link, handle owner) is matched on both; a PID whose creation time differs or
   is unknown is reported as `PID_REUSED` or `IDENTITY_UNVERIFIED`, never as the same process.
2. **Parent chains are verified:** `ParentProcessId` survives the parent's exit and can point to an unrelated process
   that later received the same PID. A parent link is accepted only if the parent exists in the same snapshot and its
   creation time is earlier than or equal to the child's; otherwise the link is `PARENT_EXITED_OR_REUSED` and the
   chain stops there (shown as a broken chain, not as a parent).
3. **Snapshot consistency:** processes seen at the start and gone (or with another creation time) at the end of the
   run are marked `EXITED_DURING_RUN`; their evidence is kept but labelled as stale.
4. **Self-exclusion:** the diagnose process, its launcher chain (V0.1 `Get-AtmSelfChainPids`) and every child the
   diagnose engine starts itself (Git, ADR-0006) are marked `SELF` and never counted as agent activity.
5. **Agent-related processes** are found only through evidence: provider process matchers (ADR-0008), provider session
   registries, V0.1 path references, working-directory and handle evidence (ADR-0004), and descendants of those through
   verified chains. A process is never "agent-related" because of its name alone unless the provider declares that name
   as a signature, and the evidence says so.

### Resources

6. Per process and summed per verified tree: CPU time (kernel + user), working set, private bytes, handle count, I/O
   read/write transfer counts. These counters come from the same CIM class (`Win32_Process`) and are expected to be
   readable even for processes whose command line is not (to be confirmed in P1 on a standard user and an elevated
   session; unreadable values are `$null` with coverage `PARTIAL`, never 0).
7. **CPU percentage needs two samples.** The report states the sampling interval and computes
   `delta(CPU time) / (interval x logical processors)`. A single snapshot reports cumulative CPU time only and says so.
   The interval is bounded (default 1 s, maximum 5 s).
8. "Disk" means two different things and they are never mixed: process I/O transfer counts (from the counters
   above) and space used by paths (V0.1 inventory for temporary partitions; ADR-0007 for worktrees).

### Identity and elevation state (PRIV-10)

9. The diagnose report shows: process user (name and SID), whether the token is an elevated administrator,
   **token elevation type** (`DEFAULT`, `FULL`, `LIMITED`, read with `GetTokenInformation(TokenElevationType)`),
   integrity level, and session id. `agent-temp version` shows the same identity line (closes the open PRIV-10 gap of
   V0.1).
10. Diagnostics never request elevation, never enable privileges (no `SeDebugPrivilege`) and never relaunch
    themselves. Each coverage record says whether elevation would add coverage (`ElevationWouldHelp`).

### Native code

11. New P/Invoke (token information, process parameters if D-1 is accepted) goes into `Native.cs`, stays C# 5, opens
    processes with the least access that works (`PROCESS_QUERY_LIMITED_INFORMATION`, plus `PROCESS_VM_READ` only for
    ADR-0004), and closes every handle in `finally`.

## Rejected alternatives

* *PID-only correlation:* PID reuse is common on long-running machines; V0.1 already had to guard against it.
* *`Get-Process` for everything:* its properties throw per process on access denial and are slower for full trees;
  it may still be used for a single, bounded second CPU sample if CIM sampling proves too slow (decided in P1 with
  measurements).
* *Enabling `SeDebugPrivilege` when elevated:* expands what the tool can read in other processes; not needed for the
  roadmap and contrary to PRIV-9.

## Consequences

* Trees may be cut at a broken parent link; the report shows the orphaned subtree separately.
* CPU percentage costs one sampling interval per run.

## Verification

* Mocked snapshots: PID reuse (same PID, different creation time) in session registry, service and parent link;
  parent created after the child; process exiting between the two samples; missing creation time.
* Resource sums over a fixture tree equal the sum of its members; `$null` counters make the sum `PARTIAL`.
* Identity line rendered in both languages; elevation type for mocked tokens; real token on CI (elevated) and locally
  (standard user).
* Static test: no `SeDebugPrivilege`, `AdjustTokenPrivileges`, `RunAs` or `-Verb` in the sources.
