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

## Preview (no deletion)

```powershell
agent-temp preview
```

Paths are grouped into **A. blocked**, **B. needs investigation**, **C. technically eligible** (for human
review). Eligible paths are printed as allowlist lines `path|fingerprint`.

## Diagnose (read-only, V0.2 in development)

```powershell
agent-temp diagnose
agent-temp diagnose -ExportJson D:\reports\diagnose.json   # schema atm.diagnose/2, new file outside audited dirs
agent-temp diagnose -DeadlineSeconds 60                     # global deadline (default 300 s), see below
```

**The deadline is not a maximum duration.** Collectors that have not started when it passes are skipped and reported
as `TIMEOUT`. The V0.1 temporary-directory inventory cannot be interrupted once it has started: it runs to the end and
is reported as `PARTIAL` (`DEADLINE_EXCEEDED`) if it finishes after the deadline. `-DeadlineSeconds 0` reads only the
process identity.

Shows the identity of the process (user, elevated administrator, token elevation type, integrity level, session),
the providers, one **coverage** record per collector and the findings. In this development stage the collectors are
the token identity, provider runtime hints, the V0.1 temporary-directory inventory and the **agent runtime**
(`process-snapshot`, `sessions-<provider>`, `agent-processes`, `agent-resources`); services, virtualization and Git
worktrees are added by later V0.2 phases.

The agent runtime section lists the processes and sessions related to agents, found only through evidence: the
providers' process matchers, their session registries (every profile; the inventory's own reading is reused), path
references of the V0.1 audit and descendants through verified parent links. This run, its launcher and its own children
are `SELF` and are left out of the totals. A process related to several providers is shown as ambiguous: no provider is
chosen. Resource totals count each process once, even when agent processes are nested, and are a lower bound of agent
activity (only the processes identified by the observed sources). The CPU is sampled with a 500 ms wait inside the
remaining time limit; the interval shown is the one measured between the two process queries, and values that could
not be read are shown as unknown or partial, never as 0. Processes that exited during the run are marked, and their
evidence is stale. `COMPLETE` covers only the observed sources: it never means that no other agent exists. No runtime
state frees, authorizes or blocks the deletion of a temporary directory.

**Pseudonyms (ADR-0010).** Temporary partitions and agent sessions appear only as keyed pseudonyms
(`<provider>/p-<32 hex>`, `<provider>/s-<32 hex>`): no path and no session identifier is shown or exported. By default
the key exists for one run only, so two runs cannot be compared item by item, and partition findings, which are
listed in pseudonym order, come in another order each run. To correlate runs, keep a key file of
32 to 4096 bytes from a random generator (not a passphrase: the exported `keyId` lets anyone test guesses of a weak
key offline) that only you, SYSTEM and Administrators can read or change, and pass it every time:

```powershell
agent-temp diagnose -PseudonymKeyFile D:\private\atm-pseudonym.key -ExportJson D:\reports\diagnose.json
```

The file is only read, never created or changed; it is refused (exit code `2`, nothing run, only a code is shown) when
the path is not a drive-absolute path on a fixed drive, a folder in the path or the file is a reparse point, it is not a
regular file, its size is out of range, its owner is not you, SYSTEM or Administrators, or any other account may read
or change it. While `diagnose` runs, the progress line shows no path. Exports made with the same key show the same `keyId`. Anyone holding the key file can compute
the pseudonyms from known identifiers: protect it like a password. Process keys, counts and coverage are not
pseudonymized.

Coverage statuses: `COMPLETE`, `PARTIAL`, `DENIED`, `TIMEOUT`, `NOT_PRESENT`, `NOT_OBSERVABLE`, `UNAVAILABLE`, `FAILED`.
Only `COMPLETE` and `NOT_PRESENT` are conclusive; anything else means **unknown** and is never reported as absent,
stopped or unused. Partial coverage is a result, not an error (exit code `0`). The export is refused (exit code `10`)
when the inventory did not run, because the audited directories are then unknown. JSON fields:
[DIAGNOSE-SCHEMA.md](DIAGNOSE-SCHEMA.md). `diagnose` never requests elevation and changes nothing.

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

`0` ok · `1` unknown command · `2` invalid clean invocation · `3` clean aborted (nothing deleted) ·
`4` no manifest (source checkout, `verify` only) · `5` integrity mismatch (a listed file missing, altered or
unreadable, a missing or unreadable `providers` directory, an unlisted library or provider, an unreadable or
invalid manifest, or an installed copy without one; nothing is loaded) · `6` TUI needs an interactive console · `10` unexpected error
(nothing deleted because of it).

## Project names

Project recognition is informational and never affects eligibility. Order: the owner's home profile
(`Perfil (home)`), optional site rules, the agent's own session evidence (a recorded working directory whose
scope matches; conflicting evidence is ignored), otherwise **`Projeto não identificado`** (reports keep each
unidentified scope separate and show its directory name). No configuration is required.

### Optional site-specific rules

Project recognition is informational. Put local rules in `config\projects.local.json`
(see `projects.local.example.json`) or pass `-ProjectsFile` to the installer. This file is never versioned.
