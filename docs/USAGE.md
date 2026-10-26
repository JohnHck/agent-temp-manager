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
`P` Preview, `L` Assisted cleanup, `H` Help.

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

`-ExportJson` (0.1.1): a new file only, outside the audited directories, with no reparse point in its path, on a fixed
local drive that is not a `subst` letter, not directly in a volume root, in a folder path shorter than 240 characters.
The folder and its ancestors are held by handle while the file is created and the rules are checked again inside that
window; the file gets a protected DACL (owner, SYSTEM, Administrators). A refusal prints its code and exits with `10`.

Sections: general summary (exclusive partitions), per user/SID, per project, per direct root,
LIVENESS_UNKNOWN older than 72 h, errors/ambiguities/coverage, final summary.

## Preview (no deletion)

```powershell
agent-temp preview
```

Paths are grouped into **A. blocked**, **B. needs investigation**, **C. technically eligible** (for human
review). Eligible paths are printed as allowlist lines `path|fingerprint`.

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
`4` no manifest · `5` integrity mismatch · `6` TUI needs an interactive console · `10` unexpected error
(nothing deleted because of it).

## Project names

Project recognition is informational and never affects eligibility. Order: the owner's home profile
(`Perfil (home)`), optional site rules, the agent's own session evidence (a recorded working directory whose
scope matches; conflicting evidence is ignored), otherwise **`Projeto não identificado`** (reports keep each
unidentified scope separate and show its directory name). No configuration is required.

### Optional site-specific rules

Project recognition is informational. Put local rules in `config\projects.local.json`
(see `projects.local.example.json`) or pass `-ProjectsFile` to the installer. This file is never versioned.
