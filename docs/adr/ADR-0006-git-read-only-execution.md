# ADR-0006: Git read-only execution and worktree states

Status: PROPOSED, with two open decisions (D-3, D-4)
Date: 2026-10-20
Phase: P3

## Context

Worktrees can hold the only copy of someone's work, so the roadmap requires read-only Git diagnostics: no fetch,
pull, prune, gc, checkout, stash or index refresh that writes, and no network. Running `git` inside a repository we do
not control is not automatically read-only or safe:

* `git status` normally **refreshes the index** and may write `.git/index` (stat information, untracked cache);
* a repository's own configuration can name commands that read-only Git commands execute, for example
  `core.fsmonitor` (a hook run by `status`) and content filters (`filter.<driver>.clean` / `.process`, used when the
  working tree has to be compared by content);
* in a partial clone, reading a missing object can trigger a **lazy fetch** from the promisor remote (network);
* if the target directory is not a repository, Git searches the parent directories and may report on a different,
  unrelated repository (for example a repository at the profile root);
* a repository owned by another account is refused by Git ("dubious ownership") unless `safe.directory` allows it;
* credential helpers and terminal prompts must never appear.

## Decision

### Executable

1. `git.exe` is resolved once per run from `PATH` as an application (never from the current directory or from an
   inspected directory) and its absolute path and `git --version` are recorded. Not found: collector `git` is
   `UNAVAILABLE` (`GIT_NOT_FOUND`) and every worktree is `UNKNOWN`; this is not a fatal error.
2. When the diagnose process is **elevated**, the resolved `git.exe` and its directory must not be writable by
   non-administrators (same ACL rule as the installer); otherwise `UNAVAILABLE` (`GIT_LOCATION_NOT_TRUSTED`). An
   elevated tool must not run a binary a standard user could replace.
3. A minimum Git version is fixed in P3 from the features actually used (porcelain v2 status, `worktree list
   --porcelain -z`, `GIT_NO_LAZY_FETCH`); an older Git yields `PARTIAL` for the missing features, never a guess.

### Invocation (every call)

4. **Allow-list of subcommands**, enforced in one function and by a static test: `--version`, `rev-parse`,
   `worktree list --porcelain -z`, `status --porcelain=v2 -z`, `for-each-ref`, `rev-list`, `config --name-only
   --get-regexp` (names only, never values), `cat-file -e`. Any other verb, and any of `fetch`, `pull`, `push`,
   `prune`, `gc`, `maintenance`, `repack`, `checkout`, `switch`, `restore`, `reset`, `clean`, `stash`, `worktree
   add/remove/prune/move/repair/lock/unlock`, `update-index`, `reflog expire/delete`, `commit-graph write`, is
   refused before a process is started.
5. **Global options:** `--no-optional-locks` and environment `GIT_OPTIONAL_LOCKS=0` (no opportunistic index write);
   `-c core.fsmonitor=false`; `-c core.untrackedCache=false`; `-c protocol.allow=never` and `GIT_NO_LAZY_FETCH=1` (no
   network, including lazy fetches); `-c color.ui=never`; `-c core.quotePath=false`; machine-readable `-z` output.
6. **Environment sanitized** for the child: `GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_OBJECT_DIRECTORY`,
   `GIT_ALTERNATE_OBJECT_DIRECTORIES`, `GIT_COMMON_DIR`, `GIT_NAMESPACE`, `GIT_CONFIG_PARAMETERS`,
   `GIT_CONFIG_COUNT`/`KEY_*`/`VALUE_*` inherited from the caller are removed; `GIT_TERMINAL_PROMPT=0`,
   `GCM_INTERACTIVE=never`, empty `GIT_ASKPASS` and `SSH_ASKPASS`; `GIT_CEILING_DIRECTORIES` = parent of the target
   and `GIT_DISCOVERY_ACROSS_FILESYSTEM=0`, so discovery cannot escape to another repository. After the first call,
   `rev-parse --show-toplevel --git-dir --git-common-dir` must match what the `.git` file and administrative entry
   say; otherwise the worktree is `UNKNOWN` (`REPOSITORY_MISMATCH`).
7. `safe.directory` is **never** set or overridden. "Dubious ownership" makes that repository `UNKNOWN`
   (`GIT_OWNERSHIP_REFUSED`, `ElevationWouldHelp = NO`).
8. **D-3 (proposed): repositories whose configuration can execute commands during reads.** Before `status`, the
   engine lists configuration **names** (never values) matching content filters, `textconv` and `fsmonitor`. P3 starts
   with a test that proves, with a throwaway repository whose filter writes a marker file, whether our `status`
   invocation can execute it. If it can, such repositories get `LOCAL_WORK` coverage `NOT_OBSERVABLE`
   (`REPOSITORY_CONFIG_EXECUTES_COMMANDS`) and the worktree is `UNKNOWN` for local work, unless a per-driver override
   is proven by the same test to prevent execution. Nothing configured by the repository is ever executed on purpose.
9. **Files read directly instead of running Git** whenever the information is in a plain file: the worktree's `.git`
   file, `<common>\worktrees\<name>\{gitdir,locked,HEAD,commondir}`, in-progress operation markers (`MERGE_HEAD`,
   `CHERRY_PICK_HEAD`, `REVERT_HEAD`, `BISECT_LOG`, `rebase-merge\`, `rebase-apply\`, `sequencer\`), and the stash
   reflog `<common>\logs\refs\stash` (line count only). Reads are bounded in size.

### Limits (D-4)

10. Each call runs with a timeout, an output cap and limits on memory and child processes; each repository has a
    time budget and the run has a global deadline. Exceeding any of them gives `TIMEOUT`/`PARTIAL` for that fact and
    `UNKNOWN` for the worktree, never clean.
11. **D-4 (proposed): the engine may terminate processes it started itself, and only those.** Git children are
    started through a native helper that places them in a Windows job object (kill on close, memory limit, active
    process limit; created suspended, assigned, then resumed, so no grandchild escapes the job). On timeout the
    engine terminates **that job**, identified by the handle it created; it never terminates any other process. This
    is the only termination in V0.2 and is stated in `SECURITY-MODEL.md` when implemented. The commands in the
    allow-list run without optional locks, so terminating one leaves no lock file behind (verified by test).

### Worktree facts and states

12. Facts, each with its own coverage: `REGISTERED` (listed by the repository), `LOCKED` (+ reason length only),
    `PRUNABLE` (as Git reports it), `STAGED`, `UNSTAGED`, `UNTRACKED`, `IGNORED` (counted separately: build output or
    secrets), `CONFLICTS`, `OPERATION_IN_PROGRESS` (which one), `STASHES_IN_REPOSITORY` (stashes belong to the
    repository, not to a worktree; attributed to a worktree only when the stash message names its branch, and then as
    `STASH_MENTIONS_BRANCH`), `SUBMODULES` (state reported; not recursed in V0.2 unless P3 proves it read-only).
13. **Publication** (no network, ever): `COMMITS_NOT_ON_REMOTE_TRACKING` (commits of `HEAD` not reachable from any
    `refs/remotes/*`: proven local), `COMMITS_ONLY_IN_THIS_WORKTREE` (detached `HEAD` commits reachable from no branch,
    tag or remote-tracking ref: lost if the worktree's administrative entry goes), `PUBLICATION_UNVERIFIED` (everything
    is reachable from remote-tracking refs, which **are not proof** the server has it: they can be stale, rewritten or
    pruned). The age of the last observed fetch (`FETCH_HEAD` time) is informative only.
14. **Summary state** (precedence, first match): `IN_USE` (ADR-0002 edge) > `LOCAL_WORK` > `UNPUBLISHED_COMMITS` >
    `APPARENT_ORPHAN` > `UNKNOWN` > `CLEAN_AND_PUBLISHED_UNKNOWN`. `APPARENT_ORPHAN` requires a **positive** "not
    found" for the repository or the administrative entry (unreadable is `UNKNOWN`, never orphan) and always carries
    "local work unknown". `CLEAN_AND_PUBLISHED_UNKNOWN` requires every fact to be `COMPLETE`. The summary never
    replaces the facts: every fact and its coverage is listed.
15. A directory is never classified as disposable by location, name or age; the states above are diagnostics only and
    authorize nothing (V0.3 adds its own gates).

## Rejected alternatives

* *libgit2 or a managed Git library:* new dependency and native code, and still has to honour the same repository
  configuration rules.
* *Parsing the index file ourselves to detect changes:* fragile (index versions, split index, sparse checkout) and
  untestable against Git's own semantics.
* *`git status` with default options:* writes the index.
* *Remote-tracking refs as proof of publication:* explicitly forbidden by the roadmap.

## Consequences

* Repositories with content filters (for example large-file filters) may show local work as `UNKNOWN` if D-3's test
  shows filters can run.
* Elevated runs with a per-user Git installation report Git as unavailable.

## Verification

* Throwaway repositories created by the suite inside its sandbox (with its own `GIT_CONFIG_GLOBAL`, no system config)
  for every fact above, including locked, prunable and orphaned worktrees, detached `HEAD`, stale remote-tracking refs,
  conflicts and each in-progress operation.
* **Read-only proof:** before and after each diagnose run, a full listing of every fixture repository and worktree
  (paths, sizes, last-write times and SHA-256 of every file under `.git`, including `index`) must be identical.
* Filter/fsmonitor marker tests (D-3); lazy-fetch test with a fixture promisor remote that is a local path the suite
  watches (no network) and must never be read; ceiling test (a non-repository directory inside a repository is not
  attributed to it); dubious-ownership simulation where possible, otherwise `NAO_TESTADO`.
* Allow-list static test and a runtime spy: every argument vector passed to the runner is recorded and checked.
* Timeout test with a fixture that makes Git slow (for example a large untracked tree and a tiny timeout): `TIMEOUT`,
  job terminated, no `index.lock` left, no other process affected (D-4).
* Git not installed: runner pointed at a missing executable: `UNAVAILABLE`, worktrees `UNKNOWN`, run succeeds.
