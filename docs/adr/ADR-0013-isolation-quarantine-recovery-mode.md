# ADR-0013: Isolation, quarantine and Recovery Mode

Status: PROPOSED (nothing implemented; open decisions ISO-D1 to ISO-D6 belong to the maintainer)
Date: 2026-11-01
Phase: V0.4 (proposed placement, see "Roadmap placement")

## Context

* **Incident.** On 2026-11-01 a user could not sign in to their own Windows profile. Access came back after the whole
  agent temporary folder of that profile was moved to a quarantine on the same volume, an empty folder was created in
  its place and Windows was restarted. Nothing was deleted by that step. The record is observed operational evidence,
  not a root cause: [incident record](../incidents/2026-11-01-profile-login-temp-isolation.md).
* **What the product does today.** It can audit (V0.1, V0.2) and, in the 0.3.0 candidate, delete (V0.3, gate closed in
  every copy). It cannot take something out of the active environment while keeping it. Deletion is irreversible by
  design: "no rollback" is a declared limit of the B1 exception, and the deleter has no undo.
* **The request.** The maintainer asked for this documentation (2026-11-01): a third operation, **isolate**, with
  restore and quarantine management, and a guided **Recovery Mode** for a profile that cannot be used. This record
  states the proposed design and its limits, maps the request onto what the product already has, and lists what is
  still the maintainer's to decide.

## Decision (proposed)

### 1. Three distinct operations

| Operation | What it does | Status |
|---|---|---|
| **Audit** | Reads and reports; changes nothing | Exists (`audit`, `preview`, `diagnose`) |
| **Isolate** | Takes a target out of the active environment and keeps it intact in a controlled quarantine, with a manifest, so it can be inspected and restored | New (this record) |
| **Delete** | Removes approved session roots; irreversible | V0.3 (`clean`, gate closed in every copy) |

Around isolation: **restore** (back to where it was), **inspect** (read-only summary of a quarantine entry),
**verify** (the entry still matches its manifest) and **purge** (delete a quarantine entry). Purge is a deletion: it
is irreversible, refused by default and goes through the deletion gates (section 8).

Isolation never makes anything eligible for deletion, and deletion never isolates. They are separate commands,
separate gates and separate confirmations.

### 2. The request's vocabulary, mapped onto the product

Some of the words in the request come from another project. They are mapped onto what this product already has;
nothing parallel is imported.

| Request | In Agent Temp Manager | Note |
|---|---|---|
| owner | The **owner SID** of the root, scope directory and base (clean gate 4), and the profile SID they belong to | Same check, same trusted principals |
| scope (file, directory, session, project, user, whole `Temp\claude`) | **Isolation targets**, mapped onto inventory objects: `LooseFile`/`BaseLooseFiles`, `UnrecognizedDir`, a `SessionRoot` partition, a project's scope directory, every base of one profile, the base `<TEMP>\claude` | "Scope" already names the scope directory (profile → TEMP → base → scope → root), so this record says **target** |
| lifecycle | The conservative **classes** (`RECENT`, `ORPHAN_SUSPECTED`, ...) plus the liveness evidence (clean gate 5, B2-1 runtime evidence) | There is no state machine for a root; none is added |
| canonical storage | The **base**, and the decided **dedicated base** through `CLAUDE_CODE_TMPDIR` | |
| storage budget | **No equivalent.** The nearest thing is the V0.5 proposal of thresholds and alerts, which only observes | Not imported |
| quarantine | **No equivalent today**: new | Sections 5 to 8 |

### 3. Targets

Every target is an exact path that the inventory produced and the person named, as for clean. A class or a state
never selects a target by itself.

* **File or directory** of the base that is not a session root (`LooseFile`, `BaseLooseFiles`, `UnrecognizedDir`).
* **Session root** (`SessionRoot`).
* **Project:** one scope directory with everything in it.
* **User:** every base of one profile.
* **The whole base `<TEMP>\claude`** of one profile. Clean gate 2 refuses the base, and isolation does not reuse
  the clean allowlist. Isolation has its own target rule, and this target needs a separate, explicit human
  confirmation that names the base and its totals.

Never targets: a profile, a TEMP root, a drive root, anything outside an agent's temporary area, a repository or a
worktree outside the temporary scope, `%WINDIR%\Temp` and any other system TEMP (the system TEMP stays an exception,
as it is for clean).

### 4. Safety requirements

* **Fail closed.** Any error, ambiguity, unknown state or change blocks the operation, before anything moves.
* **No reparse points**, in the target or its ancestor chain (clean gate 3), and no traversal: the target and the
  destination are exact, canonical, local, fixed-drive paths, with the same syntax rules as the clean allowlist.
* **Race protection.** The ancestors are pinned by handle without `FILE_SHARE_DELETE`, as the deleter does. The target
  is opened by handle and moved through that handle, never by name between checks.
* **Re-validation at the critical points:** when the plan is built; immediately before the confirmation; immediately
  before the move (every gate, liveness evidence and fingerprint again); and after the move (integrity against the
  manifest).
* **Permissions.**
  * The tool never changes the ACL or the owner of anything that exists. It enables no privilege (backup, restore,
    take-ownership, debug), as PRIV-9 requires.
  * The quarantine folder is **created** by the tool with a protected, restrictive DACL. That is setting the security
    of a new object, not changing an existing ACL.
  * What is moved keeps its own security descriptor.
* **No process is ever terminated**, and no service or session is stopped, by any isolation or Recovery Mode step.
* **Nothing is overwritten silently.** An existing destination refuses the move, and a restore never replaces newer
  content (section 7).
* **One operation at a time:** the same machine-wide lock as clean (`Global\AgentTempManager.Clean`, B8), so a clean
  and an isolation never run together.
* **A log:** T1, a new file per run through the pinned writer, with an `intent` record before each move and a `result`
  record after it.
* **Its own closed gate.** Isolation ships behind a new release gate, closed in every copy until a reviewed change
  opens it (the name is to be decided; nothing is added to the code by this record).
* **Unchanged:** B1, RECENT, the clean eligibility rules and the four existing gates. Isolation reads the same
  evidence but never changes how deletion decides.

### 5. Moving on the same volume, and its limits

The move is a rename **on the same volume**, through the target's handle (`SetFileInformationByHandle`, rename
information), into a fresh folder inside the quarantine. A move to another volume would be a copy followed by a
deletion, which is not atomic and is a deletion. It is **refused**, never emulated. These limits are documented and
tested, not hidden:

* **Atomicity:** one rename is atomic for the name of that one directory. Nothing makes a tree move atomic against
  writers that already hold handles inside it, and writes into the moved tree through those handles still land in it.
* **Open files:** a file or directory open below the target can make the rename fail. The target then stays where it
  was. Behaviour is measured on Windows 10 and 11, not assumed.
* **Existing destination:** refused. The quarantine entry is created new, with a random name, and refused if the name
  exists.
* **Long paths and Unicode:** handled with the inventory's long-path forms. A name that cannot be represented exactly
  refuses.
* **Concurrency:** the lock excludes other cooperating runs only (B8's declared limit). Any other writer is detected
  by the fingerprint and the post-move verification, or the move refuses.
* **Interruption:** the `intent` record without a `result` record marks the entry as **incomplete** (section 8). It is
  never treated as done or as safe to restore.
* **Integrity:** after the move, the counts, bytes and newest write of the moved tree are compared with the
  measurement in the plan. Any difference is reported and blocks the cleanup of the plan.
* **Inherited permissions:** a same-volume rename keeps the security descriptor. Inherited entries are not recomputed
  from the new parent. The protected DACL of the quarantine folder protects the entry's name, while the moved tree
  keeps the permissions it had.
* **File systems without these guarantees** (FAT, exFAT, network or removable drives): refused. Fixed NTFS volumes
  only, as for clean.

### 6. Manifest

One manifest per quarantine entry, written through the pinned writer next to the entry in the quarantine (the
administrator-only area). Minimum content:

* format version, entry id, UTC times of intent and result;
* the operation, the target kind and its exact original path, and the quarantine path;
* the identity of the acting process (SID and elevation, as `version` shows). The requester's identity is recorded
  too, once PRIV-5 is in place;
* the plan id, the counts, bytes and newest write measured before the move, and the same values verified after it;
* the outcome (`COMPLETE`, `PARTIAL`, `INCOMPLETE`, `FAILED`) and the exact reason;
* the restore history.

**Data minimization:** no list of file names, no file contents, no command lines, no environment, no tokens. The
manifest stays on the machine. Anything exported from it follows ADR-0010 (keyed pseudonyms, no absolute paths), and
the artifact sanitizer and privacy scanner apply as they do today.

### 7. Restore

* Restore is a separate, individually confirmed operation, with the same lock, log, re-validation and
  pinning.
* It moves the entry back **only if the original location is free**. It never overwrites, merges or interleaves:
  * if the original base or root was recreated in the meantime, for example by an agent's new session, restore lists
    the conflicts and refuses by default;
  * old and new sessions are never mixed in one folder;
  * a restore to a different, free location is offered instead.
* A failed or partial restore reports exactly what moved and what did not. The manifest records it, and the entry
  stays in the quarantine.
* Restoring never deletes the newer content, and never decides that it is disposable.

### 8. Quarantine management

* Commands: **list**, **inspect**, **verify**, **restore**, **purge**. All read-only except restore and purge.
* **Retention** is configurable and only marks an entry as **expired**. 7, 15 or 30 days are examples, not defaults.
  Nothing is purged automatically.
* **Quotas**: an optional size limit for the quarantine. Reaching it warns and refuses new isolations; it never purges
  older entries.
* **Abandoned** entries (the original profile no longer exists, or the manifest's owner cannot be identified) and
  **incomplete** entries (an intent without a result, or a manifest that does not match the content) are reported,
  never purged automatically.
* **Purge** is irreversible:
  * refused by default;
  * one entry per run, with its own typed confirmation bound to the entry id and its totals;
  * through the V0.3 deleter, its pinning and its gate, so it is not available while the deletion gate is closed;
  * no automatic, scheduled or bulk purge without an explicit decision of the maintainer (ISO-D4).

### 9. Recovery Mode

A guided flow for a profile that cannot be used, run by an administrator from **another** account. It is not a
general Windows repair tool: it only isolates agent temporary data, and it never edits the registry, profile list,
services, policies or user settings.

1. The operator signs in with another account and opens an elevated session (the manual model, until the elevation
   decision says otherwise).
2. The tool shows the acting identity and its elevation state, the requester when known (PRIV-5), and asks for the
   target profile. Nothing is chosen for the operator.
3. Read-only inventory of that profile's agent bases (`-IncludeOtherUsers`), with coverage.
4. Activity evidence for that profile (section 10): interactive sessions, processes running as that user (elevated or
   not), live agent sessions, recent activity, the profile's load state.
5. A blocking decision: any activity, or any unknown, refuses. The refusal explains what blocks it and what a person
   can do (sign the user out, restart). It never terminates or stops anything.
6. Destination check: the quarantine is on the same NTFS fixed volume, free space is sufficient, the quarantine folder
   exists or can be created with its DACL, and the destination name is new.
7. Plan: the targets, their counts and bytes, the destination, what changes, and how to undo it (restore).
8. Typed confirmation bound to the plan id (as AUT-2 does), plus the separate confirmation for the whole base.
9. Re-validation immediately before acting: every gate, the activity evidence and the fingerprint again.
10. Lock and log: the B8 lock, then the T1 log with its `intent` record.
11. The move through the pinned handle, then integrity verification against the plan, and the manifest written.
12. The empty base is **not** recreated by the tool. Creating a folder in another user's profile would make the
    acting administrator its owner. The agent recreates its folder as that user on its next run. In the incident the
    folder was recreated by hand; whether the tool should offer it is ISO-D6.
13. Report and next steps: what moved, where, how to restore, and the human steps outside the tool (restart, sign-in
    test). Restore stays a separate, explicit operation.

### 10. A loaded profile and activity criteria

* `Loaded = True` (the user hive is loaded) **does not prove** an interactive session: services, scheduled tasks or a
  leaked handle can keep a hive loaded.
* `Loaded = True` **does not authorize** moving files of that profile either.
* Proceeding requires all of the following, each verifiable and each recorded in the plan:
  * no interactive or remote session of that user (the session list of the machine);
  * no process running as that user, with process coverage measured complete;
  * no live agent session and no recent activity in the targets (clean gate 5 evidence, B2-1);
  * the targets' handle probe passes.
* A loaded hive with every other criterion clear still needs the operator's explicit confirmation of that fact.
* Any process running as that user refuses, elevated or not. This covers the incident's state, where an elevated
  process ran with the affected user's identity.
* Incomplete coverage refuses. The B1 exception does not apply to isolation: it is limited to the own profile without
  elevation.

### 11. What is reused

| Existing mechanism | Use in isolation |
|---|---|
| Inventory, partitions, owner SID, classes, profile discovery | Targets and their measurement; nothing new is enumerated |
| Clean gates 1, 3, 4, 7, 8, 9, 10 | Syntax, ancestor chain, owner and ACL, measurement, handle probe, fingerprint, pinned plan, with their own target rule instead of gate 2 |
| B2-1 runtime evidence | Activity evidence; it can only make a target stricter |
| AUT-2 confirmation and plan id | The typed confirmation bound to the exact plan |
| T1 log and the pinned writer | The isolation log and the manifest |
| B8 lock | One clean or isolation at a time |
| Handle pinning of the deleter | Pinned ancestors and the move by handle; the deleter itself only for purge |
| Privacy of artifacts (ADR-0010, sanitizer, scanner) | Whatever leaves the machine |

## Roadmap placement

**Proposed: V0.4 "Assisted recovery".** V0.4 already requires operations that are reversible, authorized one by one,
with before/after state and an undo path, a recovery log, and per-operation elevation (PRIV-2, PRIV-8, PRIV-9).
Isolation and restore are exactly that.

Four points of V0.4's current text conflict with this proposal and are stated, not hidden:

1. Its safety limit says "no changes to ... other users' sessions". Recovery Mode never touches a session, but it
   moves files **in another user's profile**. That needs an explicit amendment.
2. It says "no ... ACLs". The quarantine folder is a new object with its own DACL; no existing ACL changes. The
   amendment has to say so.
3. "Reversible, or refused by default": isolation and restore are reversible. Purge is not, so it is refused by
   default and gated by the deletion gate.
4. "Versions are delivered in order": in V0.4, isolation waits for V0.2.1 and V0.3. Moving it earlier is a real
   alternative (ISO-D1).

**Dependencies:**

* V0.3 published, with its confirmation and re-validation model, T1, B8 and the pinning deleter;
* the V0.2 diagnostics (activity evidence);
* the elevation-model decision (manual or on demand, [ELEVATION.md](../ELEVATION.md)) and PRIV-5, for acting on
  another user's profile;
* the dedicated base runbook (prevention, before containment).

## Open decisions (maintainer)

| Id | Decision | Alternatives | Recommendation |
|---|---|---|---|
| ISO-D1 | Roadmap placement | (a) V0.4, in order; (b) an earlier V0.3.x release with isolation only (no Recovery Mode, own profile), as a safer alternative to deletion | (a), unless the incident's risk is judged urgent; (b) still needs V0.3's mechanisms published first |
| ISO-D2 | Default quarantine location | (a) a fixed administrator-only folder per volume, outside every profile; (b) inside the profile, next to the base; (c) chosen per run | (a): same volume, outside the active tree, one ACL to verify |
| ISO-D3 | Acting on another user's profile | (a) manual elevation only, from another account (PRIV-5 first); (b) elevation on demand for this single operation | (a) |
| ISO-D4 | Retention and purge policy | (a) mark expired only, purge always manual and one entry at a time; (b) opt-in scheduled purge | (a) |
| ISO-D5 | Isolation as the preferred alternative to deletion | (a) offered next to deletion, never instead of it; (b) preferred for whole bases and user targets; (c) preferred everywhere | (b): deletion keeps its narrower targets |
| ISO-D6 | Recreating the empty base after an isolation | (a) never; the agent recreates it as the user; (b) offered, with the owner question solved first | (a) |

## Rejected alternatives

* **Copy, then delete** (also across volumes): not atomic, doubles the space, and is a deletion. It would bypass the
  deletion gate.
* **Changing ACLs or taking ownership** to make a target movable: forbidden by the security model (no ACL or owner
  changes, no privileges).
* **Terminating processes** that hold the target: never; the operation refuses instead.
* **Reusing the clean allowlist and gate 2:** it forbids the base, which is the main Recovery Mode target. A separate
  target rule is clearer than widening gate 2.
* **Automatic quarantine purge by age:** irreversible without a human decision.
* **A general profile repair mode:** out of scope; the product only handles agent temporary data.

## Consequences (including new limits)

* A new closed gate, a new command family and new log and manifest formats, all to be reviewed before
  implementation.
* Moving data out of a profile changes that profile while it cannot be used. The protection is refusal on any
  activity evidence, not speed.
* The quarantine holds sensitive data (whatever the agent wrote) for as long as it is kept. Its DACL and retention are
  part of the design, not options.
* A tree move is not atomic against writers that already hold handles. That limit is declared, and verification
  after the move is mandatory.
* The incident's sequence (a manual move, the folder recreated, a restart) is **not** what the proposed tool does. It
  would have refused while the elevated process ran, it does not recreate the folder (ISO-D6), and it never restarts
  anything.

## Verification

Criteria before any implementation is accepted: [TESTING.md](../TESTING.md#future-isolation-quarantine-and-recovery-mode-v04-proposed).
Destructive cases run only on disposable VMs through the V2/V3 harness pattern, never on a real profile.
