# Agent Temp Manager

Read-only auditing and preview of the temporary directories that AI coding agents leave behind on Windows,
across **every local user profile**, with a safety engine built for a future human-approved cleanup.

> **Version 0.2.0 is a release candidate, not published (the latest published version is
> [0.1.1](https://github.com/JohnHck/agent-temp-manager/releases/tag/v0.1.1), a security fix of 0.1.0).** Scope: audit,
> preview, the interactive dashboard and read-only runtime diagnostics. **Real deletion is disabled.**
> `agent-temp clean` runs every safety gate and shows the exact plan, then stops without deleting anything.
> Real cleanup is planned for V0.3, after the runtime diagnostics of V0.2: see the [roadmap](docs/ROADMAP.md).

* Global command: `agent-temp` (interactive TUI + scriptable subcommands)
* Agents (providers): **Claude Code**; V0.2 adds a runtime-only **Claude Desktop** provider
* Languages: **English (en-US)** and **Portuguese (pt-BR)**, chosen automatically from the Windows UI language,
  or with `-Lang en-US|pt-BR` / `ATM_LANG`; unknown values fall back to English
* Windows PowerShell 5.1 and PowerShell 7; no modules, Node, Python, network, browser or agent installation needed

**Design rule: safety over reclaimed space. When in doubt, preserve.**

## Commands

| Command | Effect |
|---|---|
| `agent-temp` | Interactive dashboard: profiles, files, space, errors, coverage; drill-down by user, project and root. |
| `agent-temp audit` | Full audit. **Strictly read-only.** Writes no file unless `-ExportJson` is given. |
| `agent-temp preview` | Splits every path into *blocked*, *needs investigation* and *technically eligible*. Deletes nothing. |
| `agent-temp clean -AllowListFile <file>` | **Plan only.** Validates an allowlist of exact paths against every gate and prints the exact plan. |
| `agent-temp diagnose` | **V0.2.** Read-only runtime diagnostics with coverage per collector; writes no file (its JSON export is implemented but disabled by a closed security gate). |
| `agent-temp verify` | Checks the installed files against their SHA-256 manifest. |
| `agent-temp version` | Version, native mode, deletion state and language. |

Drill-down: `-User <name|SID>`, `-Project <name>`, `-Root <uuid|path>`, `-Path <path>`. Language: `-Lang`.

## Diagnostics (V0.2)

V0.1 audits the temporary directories and classifies them conservatively. The V0.2 `diagnose` command (and the
**D** area of the TUI) adds what is running around them: agent processes and sessions, provider services, the
virtualization platform and its VMs, and a dependency graph that explains why a temporary partition looks in use.

* It only reads. It never deletes, stops, starts or changes anything, never asks for elevation and runs no Git.
* Every collector reports its **coverage**. `PARTIAL`, `DENIED`, `TIMEOUT`, `NOT_OBSERVABLE`, `UNAVAILABLE` and
  `FAILED` mean "we do not know", never "nothing there". A partition is `IN_USE` only with direct evidence from a
  verified process; otherwise it is `UNKNOWN`, which never means free. **No result authorizes deleting files or
  terminating processes.**
* What it cannot observe yet: process working directories (deferred), open files and Git worktrees (both behind
  closed security gates in every copy), remote Cowork sessions and the Cowork VM itself.
* Reports show pseudonyms and codes, not paths. The JSON export (`-ExportJson`) is implemented but disabled in every
  copy until a file-creation race is closed: it is refused with `EXPORT_SECURITY_GATE_CLOSED`.
  Details: [docs/USAGE.md](docs/USAGE.md#diagnose-read-only-v02).

## Works on any Windows machine

No user names, SIDs, drives, paths or projects are built in. Profiles come from the Windows profile list; each
profile's TEMP comes from that profile's own environment (any drive, redirected TEMP supported). Shared and
template folders (`Public`, `Default`) and junctions are recognised and never treated as accounts. Profiles that
cannot be read are reported as **incomplete coverage**, never as "nothing found". No configuration file is
needed; projects that cannot be identified safely are reported as *Unidentified project*.

## Safety model (summary)

* Reparse points (junctions, symlinks, mount points) are never traversed, including in ancestors.
* Every byte belongs to exactly one partition; logical bytes and estimated on-disk size are reported separately.
* Conservative classes: `ACTIVE_EVIDENCE`, `RECENT` (< 72 h), `LIVENESS_UNKNOWN`, `ORPHAN_SUSPECTED`
  (informational only). **No class authorises deletion.**
* Incomplete process coverage always blocks deletion; there is no override.
* The deleter (disabled in V0.1) pins every ancestor and directory by handle, deletes by handle and refuses any
  difference from the validated measurement.
* The TUI and reports are presentation only; they cannot bypass the engine.
* Command lines, tokens, credentials and file contents are never printed or exported.

Full model and documented limits (TOCTOU, unobservable handles): [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md).

## Install

1. Download the release zip and `SHA256SUMS.txt`, check the hash, extract into a folder that **only
   administrators can write** (e.g. under `%ProgramFiles%`).
2. From an **elevated** PowerShell started with `-NoProfile`:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\install\Install-AgentTempManager.ps1
```

No configuration is required. Open a new terminal and run `agent-temp`. Update, rollback, uninstall and the
clean-environment test: [docs/INSTALL.md](docs/INSTALL.md).

## Documentation

* [docs/USAGE.md](docs/USAGE.md) - commands, TUI keys, languages, examples
* [docs/INSTALL.md](docs/INSTALL.md) - install, update, rollback, uninstall, clean-environment test
* [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md) - threat model, gates, limitations
* [docs/ELEVATION.md](docs/ELEVATION.md) - privileges and UAC: requirements, current model, elevation on demand
* [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - engines, presentation layers, data flow
* [docs/PROVIDERS.md](docs/PROVIDERS.md) - provider contract (adding an agent)
* [docs/TESTING.md](docs/TESTING.md) - test suite and coverage
* [docs/STATIC-ANALYSIS.md](docs/STATIC-ANALYSIS.md) - PSScriptAnalyzer in CI, findings and remediation plan
* [docs/RELEASING.md](docs/RELEASING.md) - versioning, release packaging, publication checklist
* [docs/ROADMAP.md](docs/ROADMAP.md) - planned versions V0.2 to V1.0 (including the V0.2.1 desktop GUI), acceptance criteria and safety limits
* [CONTRIBUTING.md](CONTRIBUTING.md) - contribution rules, translations
* [SECURITY.md](SECURITY.md) - reporting vulnerabilities

## License

MIT, see [LICENSE](LICENSE).
