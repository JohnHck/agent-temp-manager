# ADR-0011: File-based worktree diagnostics without Git

Status: PROPOSED (architecture approved in principle at the gate of 2026-10-24; stays PROPOSED until the next gate;
nothing in this ADR is enabled and no capability may be activated on real repositories)
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
   * Every path, each loose reference included, goes through the single resolver (text checks, fixed local drive, no
     reparse point), and the file is opened without following a reparse point, which is refused on the handle itself
     (a swap after the path check is refused, never followed).
   * Reads share read, write and delete with everyone (`New-AtmGitSharedReadStream`), so they reduce interference with
     other processes; they do not prevent replacements. Bytes are read as Git reads them (no byte-order-mark detection:
     a UTF-16 file fails as it does in Git). Git writes by lockfile and rename, so usually a whole version is read; a
     file partly rewritten by another kind of writer may still be syntactically valid (a `packed-refs` without its final
     line break is refused, but nothing more can be guaranteed).
   * The file system is not assumed stable: references are read loose first, then `packed-refs` (a ref moved into
     `packed-refs` meanwhile is seen in one of them), in two full passes that must agree; otherwise `UNSTABLE`. Two equal
     passes are not a transactional snapshot.
   * **NOT RESOLVED - ancestor TOCTOU.** The chain is validated, then the file is opened by name; only the final
     component is opened without following a reparse point. An ancestor directory replaced between the check and the
     open (renamed, and a junction put in its place) redirects the read: proved on fixtures with a local junction. There
     is therefore no guarantee that every read stays on the local volume under adversarial concurrency (a directory
     symbolic link to a network path needs the symbolic-link privilege or Developer Mode; junctions cannot point to
     network paths; no SMB authentication was attempted). Closing it would need handle-relative opening of each
     component (not implemented). Until it is closed, the worktree diagnostics gate stays closed.
   * Unsupported formats (reftable, an unknown `packed-refs` trait: `NOT_OBSERVABLE`) and failures (a line it does not
     recognize, a read failure: `PARTIAL`) give `UNKNOWN` with a reason, never absence. Names Git ignores (starting with a
     dot, `.lock`) are ignored; a packed peeled id is used only when its packed entry is (a loose ref overriding it
     makes it stale); branch names are compared case-sensitively.
   * HEAD is read per worktree after the references: a HEAD branch with no tip (unborn, moved meanwhile, or a symbolic
     branch) claims nothing (`HEAD_BRANCH_NOT_FOUND`), never "no commits". With `extensions.worktreeConfig` the upstream
     is also looked for in the worktree's `config.worktree`; when that cannot be read nothing is said about it.
4. **What files can prove, and what they cannot.** Files give observations, never a publication state.
   * Observed, never proof of non-publication: the repository holds no remote-tracking reference (complete, stable,
     supported read): `NO_REMOTE_TRACKING_REFS`. Commits may have been pushed and the references removed, or pushed
     without tracking references, so publication stays `UNKNOWN` (`PUBLICATION_UNKNOWN` with that reason) and
     `UNPUBLISHED_COMMITS` is not given (gate decision of 2026-10-24).
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

6. **Proposed mitigation of the ancestor TOCTOU (examined in P3-E, not implemented).** Open each repository file with
   `NtCreateFile` relative to a handle of the volume root and with `OBJ_DONT_REPARSE`: the kernel then refuses a reparse
   point in any component while parsing the name, in the same call that opens the file (no window between a check and
   the open). Examined on fixtures with a local junction: a clean path opens; with an ancestor replaced by a junction
   the open fails with `STATUS_REPARSE_POINT_ENCOUNTERED`; with the flag on a `\??\C:` name even the drive letter is
   refused (it is an object-manager link), hence the volume-root handle. Open questions before adopting it: the
   minimum Windows build that honours the flag (and refusing to run where it is not), 8.3 and case behaviour, error
   mapping, and that the volume-root handle itself is opened on a fixed drive. It changes how every repository file is
   opened, so it needs the maintainer's decision; until then the ancestor TOCTOU stays NOT RESOLVED.

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
* Publication is limited to observations; every worktree stays `UNKNOWN` for publication (`NO_REMOTE_TRACKING_REFS`,
  `REACHABILITY_NOT_READ`, or `PUBLICATION_UNVERIFIED`). Neither publication nor non-publication on a server is ever
  proven from files.
* None of the limits above, and no result of these reads, may be used as proof that a worktree can be discarded.
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
