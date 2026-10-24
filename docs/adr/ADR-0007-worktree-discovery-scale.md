# ADR-0007: Worktree discovery scope and scale limits

Status: PARTIALLY ACCEPTED (maintainer gate 2026-10-20, after PR #19): the closed list of discovery sources is accepted; D-5 (b), showing full repository and worktree paths in reports and JSON, needs a privacy review before P3-B
Date: 2026-10-20
Phase: P3

## Context

To diagnose worktrees, the engine must first find them. A recursive search of user profiles or drives would be slow,
would read other projects the user never asked about, and is forbidden ("no unbounded scans of the profile or of
other projects"). The roadmap also requires results grouped by repository, progressive results, per-repository time,
memory and process limits, and tests with thousands of worktrees.

## Decision

### Discovery sources (closed list)

1. **Temporary partitions (V0.1):** the root of each inventoried partition and its direct children are checked for a
   `.git` entry (file or directory). Nothing deeper.
2. **Provider hints** (ADR-0008 `GetWorktreeHints`): locations a provider knows its agent uses, for example a
   session's recorded working directory. A hint is a starting directory, not a repository; it is resolved by rule 4.
3. **Process working directories** (ADR-0004, if D-1 is accepted): only for agent-related processes (ADR-0003 rule 5)
   and their verified descendants.
4. **Resolution of a starting directory to a repository:** walk up from the directory, checking only for a `.git`
   entry in each ancestor (attributes, no listing), at most 64 levels, never through a reparse point, stopping at
   the drive root. The first `.git` found is the candidate; Git then confirms it (ADR-0006 rule 6).
5. **Explicit list (D-5):** `-Repository <path>` (repeatable) and `-RepositoryListFile <file>`, validated like V0.1
   paths (absolute, local, canonical, no wildcards). No path is added implicitly.
6. **Registration:** for every repository found by rules 1 to 5, all its registered worktrees (`git worktree list
   --porcelain -z` and the administrative entries under `<common>\worktrees\`) are diagnosed, wherever they live.
   This is how a worktree outside every hint is found, and how administrative entries whose directory is missing are
   reported.
7. An orphaned worktree **directory** (its `.git` file points to a missing administrative entry) can only be found if
   one of rules 1 to 5 reaches it. The report states that discovery is bounded and lists the sources used, so "no
   orphan found" is never read as "no orphan exists" (coverage `PARTIAL`, reason `DISCOVERY_BOUNDED`).

**D-5 (proposed):** accept the closed list above, including (a) provider hints derived from the agent's recorded
working directory and (b) reporting repository and worktree paths in the output and JSON export. V0.1 kept only the
leaf name of a session's working directory; reporting repository paths is new and is covered by the existing export
privacy warning, which will name repositories explicitly. If (b) is rejected, repositories are shown by leaf name and
a stable hash, and paths only on the console of the user who owns them.

### Scale and limits (defaults fixed in P3 from measurements, all overridable downwards only)

8. Results are grouped by repository; worktrees of one repository share one `worktree list` call and one set of
   reference reads.
9. Caps per run: repositories, worktrees per repository, total worktrees, Git processes running at once (default 1),
   per-call timeout, per-repository budget, global deadline, output bytes per call. Anything not examined because of a
   cap is counted and makes the coverage `PARTIAL`; those worktrees are `UNKNOWN`.
10. Progressive results: the engine reports per-repository completion through the progress callback (it never
    prints); a run interrupted by the deadline returns everything finished so far, marked partial.
11. Disk space of a worktree is measured with the V0.1 scanner under a file-count cap per worktree (new optional
    parameter of `AtmScanner`); above the cap the size is a lower bound marked `PARTIAL`.
12. Memory: per-repository data is released after its findings are built; the run keeps findings, not Git output.

## Rejected alternatives

* *Recursive scan of `%USERPROFILE%`, drives or "common project folders":* unbounded and forbidden.
* *Reading every repository listed in tools' configuration files (IDEs, Git GUIs):* reads third-party configuration
  for data the user did not ask about; may be reconsidered as an explicit option later.

## Consequences

* A worktree that no agent, process, temporary partition or explicit list points to is not found; the report says so.
* The explicit list gives the user full control over which projects are read.

## Verification

* Fixture tree in the sandbox with repositories inside and outside every source: only the reachable ones are
  diagnosed; a repository next to them, never mentioned, is never opened (verified by the Git runner spy and by
  last-access-independent listing checks).
* Upward resolution stops at the drive root, at 64 levels and at a junction in an ancestor.
* Scale: 2,000 synthetic administrative entries in one repository (CI, light) and 1,000+ real worktrees with status
  (heavy, `-SkipHeavy` skips it; run locally and in a manual CI job): bounded time and memory, caps honoured, partial
  coverage when a cap is reached.

## Amendment (P3-E, 2026-10-24)

Implementation notes; the decisions above are unchanged.

* The common-directory part of the preflight is computed once per repository per run and reused while its
  fingerprint is unchanged (never by the Git runner); the reference facts are read once per repository. The cost per
  worktree no longer grows with the number of references or of worktrees of the same repository.
* Limits: candidates, repositories, worktrees per repository, administrative entries, reference entries, bytes read
  per run (`READ_BUDGET`) and the deadline give `PARTIAL` with their reason.
* Scale tests: 300 worktrees and 2,000 references per repository in CI (both shells); 2,000 worktrees and 20,000
  references in the heavy set (`-SkipHeavy` skips it). Worktrees in these tests are files written by the suite, not
  repositories of the user.
