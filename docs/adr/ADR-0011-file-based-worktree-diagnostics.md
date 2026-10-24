# ADR-0011: File-based worktree diagnostics without Git

Status: PROPOSED (for the maintainer's decision; nothing in this ADR is enabled)
Date: 2026-10-24
Phase: P3 (P3-D)

## Context

ADR-0006 diagnoses worktrees by running Git (allow-listed, bounded, sanitized), reading plain files where the
information is in a plain file (rule 9). P3-B0 and P3-C0 showed that Git, on repositories that other processes running
as the same user can write, cannot be protected against every redirection. A file that did not exist at the preflight
cannot be pinned, and two such files lead Git to follow them: `objects\info\alternates` (read by any command that reads
objects) and a `.git` file in the work tree (`status` untracked scan). Read pins also interfere with legitimate
operations of other agents (a concurrent `git config` write or `checkout` fails while pinned). The maintainer did not
approve the pins for real use, decided that the Git runner stays implemented, tested on fixtures and disabled, and set
the direction: prioritize safe, file-based diagnosis without running Git on real repositories.

## Decision (proposed)

1. **Two gates instead of one.** Split `$script:AtmWorktreeDiagnosticsEnabled` into a *file reading* gate (the engine
   reads repository files itself, never follows a path it did not validate, never runs a process) and the existing *Git
   execution* gate (stays closed; reopening it needs its own decision). Until the maintainer decides, both stay behind
   the single closed gate; no new flag exists in code.
2. **Sources read as files (no Git, no object read):**
   * discovery and registration (P3-B): `.git` files, `commondir`, administrative entries, alternates (validated, never
     followed by a process);
   * HEAD of each worktree (its Git directory) and the shared references of the repository (its common directory):
     `refs\heads`, `refs\tags`, `refs\remotes` (loose) and `packed-refs`; per-worktree namespaces (`refs\bisect`,
     `refs\worktree`, `refs\rewritten`) are not used for publication;
   * the repository configuration through the strict parser (reference storage, upstreams as names in memory; remote
     URLs are never resolved or opened);
   * in-progress operation markers and the stash reflog (P3-C);
   * `FETCH_HEAD` time (informative only).
3. **Reading rules.**
   * Every path goes through the single resolver (text checks, fixed local drive, no reparse point).
   * Reads share read, write and delete with everyone (`New-AtmGitSharedReadStream`), so they never block another
     process. Git writes by lockfile and rename, so a whole version is read; a torn read by another writer must fail the
     strict parsers (a `packed-refs` without its final line break is refused).
   * The file system is not assumed stable: references are read loose first, then `packed-refs` (a ref moved into
     `packed-refs` meanwhile is seen in one of them), in two full passes that must agree; otherwise `UNSTABLE`.
   * Unsupported formats (reftable, an unknown `packed-refs` trait, a line it does not recognize) and any read failure
     give `UNKNOWN` with a reason, never absence.
4. **What files can prove, and what they cannot.**
   * Proven: the repository has **no** remote-tracking reference (complete, stable, supported read), so no commit of
     a HEAD with commits is reachable from one: `UNPUBLISHED_COMMITS`.
   * Observed, never proof of publication: the tip equals a remote-tracking reference: `PUBLICATION_UNVERIFIED`.
   * Risk only: a detached tip that is no reference tip: `COMMITS_ONLY_IN_THIS_WORKTREE_POSSIBLE`.
   * Not provable without reading objects (commit graph): whether a tip is an ancestor of a remote-tracking reference,
     and every local-work fact that needs the index or the work tree (staged, unstaged, untracked, ignored, conflicts):
     `UNKNOWN`. A loose annotated tag points at a tag object and is not peeled (packed `^` lines are), so a detached tip
     on an annotated tag is only "possible".
5. **Cost model.** One reference read per common directory per run (two passes, bounded by `AtmGitRefEntriesMax`),
   shared by every worktree of the repository; per worktree only HEAD and the operation markers. With *W* worktrees and
   *R* references in one repository the publication facts cost O(R + W). The preflight still walks the reference store
   for each candidate (O(W x R)); reusing one walk per common directory belongs to P3-E (scale).

## Rejected alternatives

* *Read pins as a guarantee (P3-C0):* creation cannot be prevented, and pinning interferes with other agents.
* *More preflights before each call:* narrows the window, closes nothing.
* *Index parsing* (rejected in ADR-0006): would restore staged/unstaged/conflicts without Git, at the cost of a binary
  format with versions, extensions, split index and sparse checkout; needs its own ADR.
* *Object reading* (loose zlib objects, packs, commit-graph) for reachability: a binary parser with deltas; out of
  scope (the maintainer excluded complex binary parsers).
* *System precondition* (outbound NTLM restricted, outbound SMB blocked) as the guarantee for Git: needs a
  comprehensive analysis; can at most be detected read-only, never changed by the tool.

## Consequences (including new limits)

* With only the file gate open, local work is limited to in-progress operations and stashes; changes in the index or
  the work tree stay `UNKNOWN` (`LOCAL_WORK_UNKNOWN`), so no worktree is ever "clean".
* Publication is limited to the proven case (no remote-tracking reference) and observations; most worktrees with
  remotes stay `UNKNOWN` for publication (`REACHABILITY_NOT_READ`). Server publication is never proven.
* Reftable repositories are `UNKNOWN` for publication.
* No process is started and nothing is pinned: no interference with other agents.

## Verification

* Fixture tests with Git `$null` (spy: zero processes) and a read-only snapshot (sizes, times, SHA-256, `.git` and the
  index included) before and after.
* Concurrency and formats through an injected reader: a change between the passes gives `UNSTABLE`; an unknown line,
  an unknown trait, a missing final line break and a file held without sharing give `UNKNOWN`, never absence.
* Non-interference: while a shared read is open another handle replaces the file (counter-proof: a non-shared read
  blocks it).
* Privacy: no reference name, branch, remote or path in findings, coverage or JSON.
