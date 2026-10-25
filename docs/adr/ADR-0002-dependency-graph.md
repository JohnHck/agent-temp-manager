# ADR-0002: Dependency graph and correlation

Status: ACCEPTED (maintainer gate 2026-10-20, after PR #19)
Date: 2026-10-20
Phase: P4 (collectors of P1 to P3 produce the nodes and the raw evidence)

## Context

The roadmap asks which temporary paths, worktrees, services, virtual machines, agent sessions and processes depend on
each other, and V0.3 may only delete a candidate when the diagnostics show that nothing depends on it. The V0.1
reference index already resolves process command lines against temporary bases (direct, ancestor, ambiguous). V0.2
needs the same idea across more node kinds and more evidence sources, without letting one weak link become a proof.

## Decision

1. **Nodes** are the findings of ADR-0001 (`Process`, `Service`, `VirtualMachine`, `Worktree`, `Repository`,
   `AgentSession`, `TempPartition`), identified by their `Key`.
2. **Edges** are directed `From -> To` with a `Relation` and the evidence that created them:

   | Relation | Typical evidence |
   |---|---|
   | `PARENT_OF` | Verified parent chain (ADR-0003). |
   | `HOSTS_SERVICE` | `Win32_Service.ProcessId` equals the process key (PID and creation time checked). |
   | `RUNS_SESSION` | Provider session registry (V0.1 Claude Code `sessions\<pid>.json`, PID and start time checked). |
   | `WORKING_DIRECTORY_IN` | Process working directory inside the node's path (ADR-0004), when observable. |
   | `HOLDS_HANDLE_IN` | Open-handle evidence inside the node's path (ADR-0004), when observable. |
   | `REFERENCES_PATH` | Command-line reference, resolved in memory exactly like V0.1 (direct, ancestor or ambiguous; never stored). |
   | `WORKTREE_OF` | Worktree administrative entry and `gitdir` file agree (ADR-0006). |
   | `MAPS_PATH` | A service or virtual machine configuration maps the path (only when the source exposes it). |
   | `ATTRIBUTED_TO` | A virtual machine worker or service attributed to a provider scenario with evidence (ADR-0005). |

   Edges carry a `Strength`: `DIRECT` (the source names the exact node), `ANCESTOR` (the source names a parent path)
   or `AMBIGUOUS` (short names, wildcards, unresolved components; V0.1 rules). There is no numeric weight.
3. **Correlation is transitive only along proven edges.** A temporary partition depends on a process tree if any
   process of the tree has an edge into it; a worktree is `IN_USE` if any process, session, service or VM has an
   edge into it. Ambiguous edges mark the target as `UNKNOWN`/investigate, never as free.
4. **Absence of an edge is only meaningful with full coverage** of every collector that could have produced one
   (ADR-0001, rule 3). The per-node summary lists which collectors were complete and which were not.
5. **Bounded cost.** Correlation is computed from indexes (normalized path prefixes, process keys), never by
   comparing every file with every process: O(nodes + edges + processes x indexed roots), as in V0.1.
6. **Temporary directories (roadmap item):** each V0.1 `TempPartition` gains the runtime edges above. The V0.1
   classification and gates are unchanged in V0.2; the new evidence is shown next to them. V0.3 decides, in its own
   reviewed change, how the gates consume it.

## Rejected alternatives

* *Inferring dependencies from names, locations or age* (for example "anything under `.claude\worktrees` belongs to
  Claude Code"): forbidden by the roadmap; it may be shown as a hint but never creates an edge.
* *Feeding V0.2 evidence into V0.1 gates now:* changes deletion semantics before V0.3's reviewed design.

## Consequences

* The graph is a read-only, per-run structure; it is not persisted (persistence is V0.5).
* Presentation can show "why is this in use" as the list of incoming edges with their evidence.

## Verification

* Fixture graphs (fictional processes, services, worktrees, partitions) covering each relation and strength.
* Transitivity: a grandchild process with its working directory in a worktree marks the worktree `IN_USE` and links
  the root agent process.
* With any contributing collector not complete, a node without edges is `UNKNOWN`, never `NO_DEPENDENCY_OBSERVED`.
* Performance test: thousands of nodes and processes, bounded time and memory.

## Amendment (P4-A, 2026-10-24)

The decisions above are kept. Implementing them on the evidence that P1 to P3 actually produce raised four structural
points. Each one is recorded with its alternatives; points 1 and 2 are **proposed** and implemented in P4-A for the
maintainer's review of the P4-A pull request, and the implementation changes if the maintainer chooses an
alternative. Points 3 and 4 add nothing to the graph.

1. **`ATTRIBUTED_TO` targets a provider node (kind `Provider`, key = provider id) — proposed.** Rule 2 names the
   relation but no target kind: a provider is not a finding of ADR-0001.
   *Alternatives:* (a) no edge, the attribution stays a property of the finding (`provider`) — loses "why" chains
   for ambiguous attribution, because an ambiguous finding has `provider = null`; (b) a new finding kind `Provider`
   — a finding needs a state and coverage that a provider id does not have. *Chosen:* a graph-only node kind with
   `finding = false`. A finding with a provider gives one `DIRECT` edge; an ambiguous attribution
   (`PROVIDER_ATTRIBUTION_AMBIGUOUS`) gives one `AMBIGUOUS` edge per candidate provider and never a `DIRECT` one
   (P2-C, D2).
2. **Endpoints without a finding are nodes (`finding = false`) — proposed.** Rule 1 says nodes are the findings, but
   verified evidence names endpoints that have no finding: the verified process of a service (`HOSTS_SERVICE`), the
   holder of a file, a process whose identity could not be verified (`pid:<n>`, always `AMBIGUOUS`).
   *Alternatives:* (a) drop the edge — loses positive evidence; (b) create findings for them — the graph would
   change the findings, which P4-A must not do. *Chosen:* such endpoints are graph nodes marked `finding = false`;
   they carry only their key (a process key or `pid:<n>`, both already exported by the findings).
3. **`VirtualizationPlatform` (ADR-0001, P2-B amendment) is a node and host context, not a dependency.** It has no
   relation in rule 2 and no edge is created to or from it; its presence never makes anything depend on a VM.
4. **VM and worker process — not implemented, proposal only.** `VM_WORKER_VERIFIED` (P2-B) links a VM to its
   verified `vmwp.exe`, but no relation of rule 2 means "runs the VM" (`HOSTS_SERVICE` is for services). It stays
   evidence on the VM finding. *Alternatives for a later phase:* a new relation `RUNS_VM` (Process -> VirtualMachine),
   or reusing `HOSTS_SERVICE` (rejected: a different meaning under the same name). No chain through a VM is possible
   in P4-A: `vmmem` is never attributed, `CoworkVMService` never proves a VM, and compute-system (HCS) VMs stay
   unattributed.

Implementation record (P4-A):

* **Layer.** `Get-AtmDependencyGraph` (Engine.Diagnose) runs after every collector, over the findings, the process
  snapshot, the V0.1 inventory and the coverage records of the same run. It runs no query, opens no file and calls no
  collector (static test). The result is `graph` in the JSON (`docs/DIAGNOSE-SCHEMA.md`) and a section of the report.
* **Relations by source.** `PARENT_OF`: verified parent link (ADR-0003) between two process findings, `DIRECT`.
  `HOSTS_SERVICE`: `SERVICE_PROCESS_VERIFIED` (temporal proof of P2-A), `DIRECT`. `RUNS_SESSION`: a `LIVE`,
  reconciled session record names its process key (`SESSION_PROCESS_KEY`); stale or conflicting sessions give none.
  `REFERENCES_PATH`: the V0.1 direct, ancestor and ambiguous references of each temporary partition, resolved in
  memory to a verified process identity (`DIRECT`, `ANCESTOR`, `AMBIGUOUS`); an identity that cannot be verified
  gives an `AMBIGUOUS` edge from `pid:<n>` and `REFERENCE_IDENTITY_UNVERIFIED`; the reference text never leaves the
  function. `HOLDS_HANDLE_IN`: `FILE_HELD_OPEN` (`DIRECT`) or `FILE_HELD_OPEN_UNVERIFIED` (`AMBIGUOUS`); the
  collector is behind the closed open-file gate, so only fixtures produce it. `WORKING_DIRECTORY_IN`: no collector
  produces it (D-1 DEFERRED); fixtures only. `WORKTREE_OF`: `IN_REPOSITORY` with `WORKTREE_REGISTERED` or
  `WORKTREE_MAIN` (`DIRECT`), otherwise `AMBIGUOUS`; worktree findings exist only with the worktree gate open, so
  only fixtures produce it. `MAPS_PATH`: no source exposes it; never produced. `ATTRIBUTED_TO`: point 1.
* **Transitivity (rule 3).** A summary per `TempPartition` and `Worktree` collects the incoming `REFERENCES_PATH`,
  `HOLDS_HANDLE_IN` and `WORKING_DIRECTORY_IN` edges and walks `PARENT_OF` upward from every verified source to its
  agent roots (`AGENT_PROCESS`), with a visited set and a depth limit. The summary strength is the best source
  strength; a source without a verified identity is `AMBIGUOUS` whatever the edge says. Nothing is inferred from
  names, locations, age or probability.
* **Summary vocabulary (not finding states).** `DEPENDENCY_OBSERVED` (a `DIRECT` source), `ANCESTOR_REFERENCE`,
  `DEPENDENCY_AMBIGUOUS`, `NONE_OBSERVED` (no source, every relevant collector conclusive and no limit hit),
  `UNKNOWN` (default; `COVERAGE_INCOMPLETE` or `KEY_COLLISION`). Relevant collectors: `inventory`, `processes`,
  `process-snapshot`, `handles`, `process-cwd` for partitions; `worktree-discovery`, `process-snapshot`, `handles`,
  `process-cwd` for worktrees. In a shipped run `handles` and `process-cwd` are `NOT_OBSERVABLE`, so
  `NONE_OBSERVED` never appears (test). P4-A changes no finding state; promoting partition states is P4-B, and no
  summary authorizes deleting anything.
* **Limits.** Nodes 100000, edges 400000, upward depth 256, 30 s. A limit hit is a graph coverage reason
  (`GRAPH_NODE_LIMIT`, `GRAPH_EDGE_LIMIT`, `GRAPH_DEPTH_LIMIT`, `GRAPH_TIME_LIMIT`), dropped edges are counted, the
  edges already found are kept and no summary says `NONE_OBSERVED`. Everything is indexed (by kind, by edge target,
  by PID); no step compares every item with every other.
* **Privacy.** Only finding keys (pseudonyms and process keys), provider ids, relation, strength and evidence codes
  leave the function; no path, command line, VM name or GUID, account, token or session id. The graph lives in
  memory for the run and is not persisted.
