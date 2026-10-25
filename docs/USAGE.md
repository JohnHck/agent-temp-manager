# Usage

## Language

The interface is available in **English (en-US)** and **Portuguese (pt-BR)**. Order of precedence:
`-Lang en-US|pt-BR` > environment variable `ATM_LANG` > Windows UI language. `pt-*` selects pt-BR; any other or
unknown value selects English. Missing translations fall back to English. Reason, flag, class and status
**codes** (e.g. `COBERTURA_DE_PROCESSOS_INCOMPLETA`, `ACTIVE_EVIDENCE`, `AUDITADO`) are stable identifiers and are
the same in every language; JSON exports always use them.

```powershell
agent-temp audit -Lang en-US
$env:ATM_LANG = "pt-BR"; agent-temp
```

## Interactive dashboard

```powershell
agent-temp            # opens the TUI (requires an interactive console)
agent-temp -Ascii     # ASCII frames for fonts/terminals without box-drawing glyphs
```

Keys: arrows / PgUp / PgDn / Home / End to move, **Enter** to open, **Esc** or Backspace to go back,
**R** to re-audit, **Q** to quit. Menu shortcuts: `1` Dashboard, `2` Users/SIDs, `3` Projects, `4` Roots,
`5` ACTIVE_EVIDENCE, `6` RECENT, `7` LIVENESS_UNKNOWN, `8` Blocked paths, `9` Errors & coverage,
`P` Preview, `D` Diagnostics V0.2, `L` Assisted cleanup, `H` Help.

**Diagnostics V0.2 (`D`, read-only).** Entering the area runs `diagnose` once (it can take a while: the V0.1
inventory cannot be interrupted); navigating, paging and opening details reuse that result and run nothing.
**U** collects a new observation on request. The area shows a summary, the coverage of every collector (with
`NOT_OBSERVABLE`, `DENIED`, `TIMEOUT` and their reasons), agent processes and sessions, services, the virtualization
platform and VMs, repositories and worktrees, temporary partitions, the graph nodes and their edges (`[D]` direct,
`[A]` reference to a parent path, `[?]` ambiguous), and why items are `UNKNOWN`. It shows only what the
`diagnose` JSON export contains (pseudonyms and codes: no path, account, machine name or command line). A node
marked "reference" has no finding of its own. If a refresh fails, the previous result stays, marked as outdated,
with the exception type only. The results do not authorize deleting files or terminating processes.

The TUI uses console colors (no ANSI escape sequences), so it works on Windows PowerShell 5.1 conhost,
PowerShell 7 and Windows Terminal. Set `ATM_ASCII=1` (or `-Ascii`) to force ASCII: frames and text are
transliterated (accents removed) and anything outside printable ASCII is shown as `?`.

## Audit (read-only)

```powershell
agent-temp audit
agent-temp audit -User alice                  # one user (name or SID)
agent-temp audit -Project "My Project"         # one project
agent-temp audit -Root 0b1c...-uuid            # one root
agent-temp audit -Path "C:\Users\alice\AppData\Local\Temp\claude\C--src-app\<uuid>"   # children breakdown
agent-temp audit -ExportJson D:\reports\audit.json   # optional, explicit, outside audited dirs
```

Sections: general summary (exclusive partitions), per user/SID, per project, per direct root,
LIVENESS_UNKNOWN older than 72 h, errors/ambiguities/coverage, final summary.

**Export safety (V0.2 FINAL-A).** The audit export keeps its rules (a new file outside the audited directories, no
reparse point in its folders) and is now created with the folder and its ancestors pinned, relative to the folder, with
access limited to its owner, SYSTEM and Administrators; a folder swapped during the export, or a `subst` drive letter, is
refused with the same message, now preceded by a refusal code. Also refused now (accepted by V0.1): a file directly in
a volume root (`C:\x.json`), a folder path of 240 characters or more, a network or non-fixed drive, and a folder that
cannot be opened (reported as a refusal, not as an error). A file exported from an elevated window may not be readable
from a non-elevated one (its owner is then usually Administrators).

## Preview (no deletion)

```powershell
agent-temp preview
```

Paths are grouped into **A. blocked**, **B. needs investigation**, **C. technically eligible** (for human
review). Eligible paths are printed as allowlist lines `path|fingerprint`.

## Diagnose (read-only, V0.2 in development)

V0.2 is **not released**: `diagnose` exists in the development version only, and its output may still change.

```powershell
agent-temp diagnose
agent-temp diagnose -Lang en-US -NoProgress
agent-temp diagnose -DeadlineSeconds 60                     # global deadline (default 300 s), see below
agent-temp diagnose -PseudonymKeyFile D:\private\atm-pseudonym.key   # comparable pseudonyms between runs
```

Options of `diagnose`: `-DeadlineSeconds <seconds>`, `-PseudonymKeyFile <file>`, `-NoProgress`, `-Lang en-US|pt-BR`;
`-ExportJson <new file>` exists but is refused in every copy (see *Export*). There is no option to give repository paths, to open a security gate or to request
elevation. In the TUI, the same diagnostics are under **D** (see *Interactive dashboard*).

### What it adds to V0.1

V0.1 already audits every profile's temporary directories, classifies them conservatively and shows a cleanup plan
without deleting anything. `diagnose` adds, read-only:

* the identity of the process (user, elevated administrator, token elevation type, integrity level, session);
* the Windows profile discovery and its gaps (`profile-discovery`);
* the agent runtime: agent processes and sessions found through evidence (provider matchers, session registries,
  path references of the audit, verified parent links), and their resource totals;
* Windows services that providers declare (for example `CoworkVMService` for Claude Desktop), the virtualization
  platform and its virtual machines;
* a dependency graph (`graph`) that correlates that evidence, and from it the state of each temporary partition.

### What it does not observe (yet)

* Process working directories: deferred (`process-cwd` is `NOT_OBSERVABLE`).
* Open files: the collector exists but is behind a closed security gate in every copy (`handles` is
  `NOT_OBSERVABLE`, `HANDLE_SECURITY_GATE_CLOSED`).
* Git worktrees: behind a closed security gate in every copy (`worktree-discovery` is `NOT_OBSERVABLE`,
  `WORKTREE_DIAGNOSTICS_GATE_CLOSED`); no Git command is run.
* Remote Cowork sessions, and the Cowork VM itself (an HCS compute system, not a Hyper-V Manager VM).

The three gates (real deletion, open-file diagnostics, worktree diagnostics) are closed in every copy, and no option,
environment variable or configuration file opens them.

### How to read the results

* **Coverage first.** Each collector reports `COMPLETE`, `PARTIAL`, `DENIED`, `TIMEOUT`, `NOT_PRESENT`,
  `NOT_OBSERVABLE`, `UNAVAILABLE` or `FAILED`, with reason codes. Only `COMPLETE` and `NOT_PRESENT` are conclusive.
  `PARTIAL` means some items were seen and some were not; `NOT_OBSERVABLE` means the source was not read at all (a
  gate, a deferred collector, a missing prerequisite). Neither is ever "nothing there": **the absence of evidence does
  not show that something is unused**, because the evidence that would show use may simply not have been observed.
* **Temporary partitions.** `IN_USE`: a verified process references it directly (or holds a file in it, or works in
  it). `UNKNOWN`: anything else (a reference to a parent folder, ambiguous evidence, incomplete coverage, a limit of the
  graph, a key collision); `UNKNOWN` never means free. `NO_DEPENDENCY_OBSERVED` needs every relevant collector to be
  conclusive, so it does not appear while open files and working directories are not observable. The V0.1 class and
  flags of the partition stay next to it, unchanged.
* **Providers are not dependencies.** A finding attributed to a provider says which agent the evidence points to; it
  does not prove that a temporary partition depends on that agent. When the evidence fits two providers (a `claude.exe`
  can belong to Claude Code or to Claude Desktop), the attribution is ambiguous and no provider is chosen.
* **Claude Code, Claude Desktop and Cowork.** Claude Code is the CLI agent (temporary directories and runtime).
  Claude Desktop is the desktop app (runtime only: its packaged processes and its service). Cowork is a Claude Desktop
  feature that runs in a VM managed by the app; the tool sees only the local `CoworkVMService` service, which is
  identified by a **publicly reported** name (provisional, not documented by Anthropic): a running service with a
  verified process is evidence of the local Cowork service, never of a running VM.
* **Privileges.** `diagnose` never asks for elevation. Without it, other accounts' processes and some services may be
  unreadable; that is reported as `PARTIAL` or `DENIED` with `elevationWouldHelp` (`YES`, `NO` or `UNKNOWN`: unknown
  means it is not known whether elevation would help).
* **Nothing is authorized.** No state, coverage or graph result authorizes deleting files, terminating processes,
  stopping services or shutting down VMs.

**The deadline is not a maximum duration.** Collectors that have not started when it passes are skipped and reported
as `TIMEOUT`. The V0.1 temporary-directory inventory cannot be interrupted once it has started: it runs to the end and
is reported as `PARTIAL` (`DEADLINE_EXCEEDED`) if it finishes after the deadline. `-DeadlineSeconds 0` reads only the
process identity.

### Export

**Disabled in every copy (security gate closed).** `agent-temp diagnose -ExportJson <file>` is refused at once with
`EXPORT_SECURITY_GATE_CLOSED` and exit code `10`: nothing is collected, no destination is checked and no file is
created. Reason: the export checks the destination folders by name and then creates the file by name, so a folder
replaced by a junction in between could redirect the new file (an ancestor race, not resolved), and the document holds
the machine name, the account and its SID. Creating a *new* file does not prevent that redirection. The export is
implemented and tested on disposable fixtures only; enabling it needs a demonstrated mitigation and a maintainer
decision. This concerns the export only: `diagnose` itself and the TUI area (D) are read-only and unaffected. Without
`-ExportJson`, no file is written.

The rules below are those the export applies when its gate is open (tests only). The destination must be a **new** file (an existing file is never overwritten), given as an absolute local
path (no network, device or relative path, no wildcard, stream or `..`), whose folders contain no junction or other
reparse point, outside every audited temporary directory, and not inside a Git repository or worktree (no folder above
it holds a `.git` entry, and no folder above it is a bare repository; Git itself is not run), and not on a drive letter
made with `subst`. The export is also refused when the inventory did not run, because the audited directories are then
unknown. A refusal prints a code (`EXPORT_INVENTORY_NOT_RUN`, `EXPORT_DESTINATION_NOT_ALLOWED`,
`EXPORT_SUBSTITUTED_DRIVE`, `EXPORT_INSIDE_REPOSITORY`, `EXPORT_ANCESTOR_UNREADABLE`), creates no file and exits with
`10`; a write failure prints the exception type only and exits with `10` (a file it already created may then be
incomplete; it is not deleted). A folder replaced by a junction after the check redirects the new file: this ancestor
race is NOT RESOLVED, which is why the gate is closed (SECURITY-MODEL, *Diagnose export gate*).

The export contains the machine name, the user name and SID and the token elevation state; temporary partitions and
agent sessions appear only as keyed pseudonyms, and no path, command line, token or session id is exported. Review it
before sharing.

**Pseudonyms (ADR-0010).** Temporary partitions and agent sessions appear only as keyed pseudonyms
(`<provider>/p-<32 hex>`, `<provider>/s-<32 hex>`): no path and no session identifier is shown or exported. By default
the key exists for one run only, so two runs cannot be compared item by item, and partition findings, which are
listed in pseudonym order, come in another order each run. To correlate runs, keep a key file of
32 to 4096 bytes from a random generator (not a passphrase: the exported `keyId` lets anyone test guesses of a weak
key offline) that only you, SYSTEM and Administrators can read or change, and pass it every time with
`-PseudonymKeyFile`.

The file is only read, never created or changed; it is refused (exit code `2`, nothing run, only a code is shown) when
the path is not a drive-absolute path on a fixed drive, a folder in the path or the file is a reparse point, it is not a
regular file, its size is out of range, its owner is not you, SYSTEM or Administrators, or any other account may read
or change it. While `diagnose` runs, the progress line shows no path. With the same key, the pseudonyms of two runs are
the same (and an export, while disabled, would carry the same `keyId`). Anyone holding the key file can compute the pseudonyms from known identifiers: protect it like a password.
Process keys, counts and coverage are not pseudonymized.

Exit codes of `diagnose`: `0` when it ran (partial coverage is a result, not an error), `2` key file refused, `10`
export refused (`EXPORT_SECURITY_GATE_CLOSED` in every copy) or not written, or an unexpected failure (reported by its
exception type only; nothing is deleted).

## Clean (assisted, fail-closed)

1. Run `agent-temp preview`, copy the eligible lines you **reviewed** into a text file (UTF-8), one per line.
   Lines starting with `#` are comments.
2. Run:

```powershell
agent-temp clean -AllowListFile C:\review\allowlist.txt
agent-temp clean -Path "C:\Users\alice\AppData\Local\Temp\claude\C--src-app\<uuid>"
agent-temp clean -AllowListFile list.txt -LogFile D:\logs\clean.jsonl
```

3. Read the plan. It ends with **NADA FOI APAGADO AINDA**. Type the exact phrase shown
   (e.g. `APAGAR 2 CAMINHOS`) to proceed; anything else aborts.
4. Each path is revalidated immediately before deletion; paths that changed are preserved. A read-only audit
   runs afterwards.

**V0.1:** `clean` runs every gate and prints the exact plan, then stops with
`EXCLUSAO_REAL_DESABILITADA_V0_1`; no confirmation is requested and nothing is deleted. Steps 3-4 above describe
the behaviour of a future release in which deletion is explicitly authorized.

Administrator-only switch: `-IncludeOtherUsers`. Incomplete process coverage cannot be overridden.

## Exit codes

`0` ok (for `diagnose`, partial coverage included) · `1` unknown command · `2` invalid clean invocation, or a refused
`-PseudonymKeyFile` · `3` clean aborted (nothing deleted) ·
`4` no manifest (source checkout, `verify` only) · `5` integrity mismatch (a listed file missing, altered or
unreadable, a missing or unreadable `providers` directory, an unlisted library or provider, an unreadable or
invalid manifest, or an installed copy without one; nothing is loaded) · `6` TUI needs an interactive console · `10` unexpected error,
or a `diagnose` export refused or not written (nothing deleted because of it).

## Project names

Project recognition is informational and never affects eligibility. Order: the owner's home profile
(`Perfil (home)`), optional site rules, the agent's own session evidence (a recorded working directory whose
scope matches; conflicting evidence is ignored), otherwise **`Projeto não identificado`** (reports keep each
unidentified scope separate and show its directory name). No configuration is required.

### Optional site-specific rules

Project recognition is informational. Put local rules in `config\projects.local.json`
(see `projects.local.example.json`) or pass `-ProjectsFile` to the installer. This file is never versioned.
