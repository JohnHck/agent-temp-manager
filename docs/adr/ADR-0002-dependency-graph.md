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
   they carry only their key (a process key or `pid:<n>`). Process keys are allowed exported identifiers; a process
   named only by an ambiguous reference appears in the graph and not among the process findings. Every edge from a
   `pid:<n>` source is `AMBIGUOUS`.
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
  agent roots (`AGENT_PROCESS`), with a visited set and a depth limit, only from the sources of `DIRECT` edges (a root
  is never stronger than its chain). The summary strength is the best incoming edge strength; an edge from a source
  without a verified identity is always `AMBIGUOUS`. A finding with an ambiguous attribution never gets a `DIRECT`
  `ATTRIBUTED_TO` edge. The tool's own process (`SELF`) is the source of no edge, on purpose. Nothing is inferred from
  names, locations, age or probability.
* **Summary vocabulary (not finding states).** `DEPENDENCY_OBSERVED` (a `DIRECT` source), `ANCESTOR_REFERENCE`,
  `DEPENDENCY_AMBIGUOUS`, `NONE_OBSERVED` (no source, every relevant collector conclusive and no limit hit),
  `UNKNOWN` (default; `COVERAGE_INCOMPLETE`, `GRAPH_LIMIT`, `REFERENCE_UNREADABLE` or `KEY_COLLISION`). A collector
  with several coverage records counts by its worst one. Relevant collectors: `inventory`, `processes`,
  `process-snapshot`, `handles`, `process-cwd` for partitions; `worktree-discovery`, `process-snapshot`, `handles`,
  `process-cwd` for worktrees. In a shipped run `handles` and `process-cwd` are `NOT_OBSERVABLE`, so
  `NONE_OBSERVED` never appears (test). P4-A changes no finding state; promoting partition states is P4-B, and no
  summary authorizes deleting anything.
* **Limits.** Nodes 100000, edges 400000, upward depth 256, 30 s. A limit hit is a graph coverage reason
  (`GRAPH_NODE_LIMIT`, `GRAPH_EDGE_LIMIT`, `GRAPH_DEPTH_LIMIT`, `GRAPH_TIME_LIMIT`), dropped edges are counted, the
  edges already found are kept and no summary says `NONE_OBSERVED`; the time limit is also bounded by the run deadline.
  Every phase runs in ordinal key order, so what a limit keeps does not depend on the input order. Everything is indexed (by kind, by edge target,
  by PID); no step compares every item with every other.
* **Privacy.** Only finding keys (pseudonyms and process keys), provider ids, relation, strength and evidence codes
  leave the function; no path, command line, VM name or GUID, account, token or session id. The graph lives in
  memory for the run and is not persisted.

## Maintainer decisions (P4-A gate, 2026-10-25)

The maintainer's gate after PR #45 ("MACRO-P4-A FINAL") decided the points of the P4-A amendment. The amendment text
above is kept as written for the review (with its alternatives); these decisions are binding:

* **D1 — `Provider` as a graph node: ACCEPTED** (amendment point 1). `ATTRIBUTED_TO` targets a `Provider` node keyed
  by the provider id. `Provider` is a graph-only kind: it is **not** added to the finding kinds of ADR-0001, and the
  node has `finding = false`. Its presence does not prove that the software is installed, running or active. An
  ambiguous attribution gives only `AMBIGUOUS` edges, one per candidate provider, and transitivity never turns an
  ambiguous attribution into an exclusive link.
* **D2 — endpoints without a finding: ACCEPTED** (amendment point 2). An entity named by evidence may be a node
  without a finding (`finding = false`). Such a node is a correlation reference, not an independent observation that
  the entity exists. A verified process identity keeps the proofs of its source; `pid:<n>` is an unverified identity
  and never supports a `DIRECT` edge. The absence of a finding proves neither absence nor activity of the process.
  The graph never creates findings to complete edges.
* **D3 — `VirtualizationPlatform`: ACCEPTED as context** (amendment point 3). The node stays; its presence creates no
  dependency edge. `vmms`, `vmmem` or the platform alone never link anything to Claude Desktop.
* **D4 — VM and worker: `RUNS_VM` stays PROPOSED, not implemented** (amendment point 4). It is not added without a
  later decision.

## Implementation (P4-B, 2026-10-25)

Rule 6 as implemented: the graph summaries decide the diagnose state of each `TempPartition` and `Worktree` finding,
inside the closed lists of ADR-0001 (no contract change).

* **Partitions:** `DEPENDENCY_OBSERVED` gives `IN_USE`; `NONE_OBSERVED` requests `NO_DEPENDENCY_OBSERVED`; anything else
  (`ANCESTOR_REFERENCE`, `DEPENDENCY_AMBIGUOUS`, `UNKNOWN`, a key collision) gives `UNKNOWN`. Worktrees: `IN_USE` first
  (ADR-0006 rule 14), otherwise their own facts; a no-dependency worktree state (`CLEAN_AND_PUBLISHED_UNKNOWN`) needs
  the graph to observe nothing, and an `APPARENT_ORPHAN` with ambiguous or ancestor evidence is `UNKNOWN` (ambiguous
  evidence never leaves an item looking free; `LOCAL_WORK` and `UNPUBLISHED_COMMITS` stay).
* **Absence is checked twice:** the rebuilt finding carries the coverage of every relevant collector and of the graph
  (`dependency-graph`), so `New-AtmFinding` refuses `NO_DEPENDENCY_OBSERVED` with any non-conclusive record even if a
  summary said otherwise; a relevant collector that did not run is attached as `NOT_OBSERVABLE` (`COLLECTOR_NOT_RUN`).
* **Why:** evidence `GRAPH_DEPENDENCY` (the summary), `GRAPH_SOURCE_<STRENGTH>` (relation and process key of each
  incoming edge, at most 16, then `GRAPH_SOURCES_CAPPED`), `GRAPH_AGENT_ROOT` and `GRAPH_REASON`. Provenance is the
  process key; no finding is created for a node without one (D2), and no provider is claimed for an ambiguous
  attribution (D1).
* **Cost:** one pass over the edges and the summaries of the graph already built (indexed by target and key); the graph
  is never rebuilt per partition.
* **V0.1:** the audit classes and flags stay as evidence (`AUDIT_CLASS`, `AUDIT_FLAG`); the audit, the preview and
  `clean` read no diagnose state (static test).
