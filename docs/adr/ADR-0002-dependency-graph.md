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
