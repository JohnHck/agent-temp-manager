# Privileges and UAC

How Agent Temp Manager uses administrative privileges today, the requirements every version must meet, and the
comparison that has to be decided before any version (V0.3 at the earliest) changes the elevation model.

**Current model (V0.1): manual elevation.** No shipped copy elevates itself, and the tool never asks for credentials.
Since V0.4 R4 the code holds one elevation request on demand, for `recover start` and `recover undo` only (V04-D3 (b),
[ADR-0016](adr/ADR-0016-v04-assisted-recovery.md)). It is reached only past the recovery gate, which is closed in every
copy, so no shipped copy requests elevation.

## Current behaviour (V0.1)

| Situation | Behaviour |
|---|---|
| `agent-temp` (audit, preview, TUI, verify, version, clean plan) | Runs with the token of the process that started it. It never elevates, relaunches itself or asks for credentials. |
| `recover start`, `recover undo` (V0.4 R4) | Recovery gate closed (every copy): the plan, or the request, then exit 27. No elevation is requested and nothing is asked, locked or logged. Past the gate (the suite only, in its own process): an elevated administrator token acts in its own process; any other token relaunches the installed `bin\agent-temp.cmd` once through UAC, with fixed arguments (ADR-0016, R4 implementation record). |
| Not elevated (standard user, or administrator with the filtered UAC token) | Own profile audited. Other profiles are reported as inaccessible and other accounts' processes as not observable, so coverage is declared **incomplete**. `clean` is blocked by `COBERTURA_DE_PROCESSOS_INCOMPLETA`, except the B1 restricted exception (V0.3, version 0.3.0: own non-elevated profile only, deletion gate open, `-AcceptB1ResidualRisk` and a per-root acceptance; SECURITY-MODEL gate 6). |
| Elevated administrator | Full process coverage where Windows allows it (protected processes still count as uninspectable). Another user's paths additionally need `-IncludeOtherUsers`. |
| Install, update, rollback, uninstall | Must be started from an elevated PowerShell. `Assert-AtmElevated` runs before anything is changed and refuses otherwise: message `inst.needAdmin` ("no automatic elevation is performed"), non-zero exit code (currently the generic 1), nothing created. The suite tests the refusal in non-elevated runs. |
| Identity used for decisions | The **process token's** user SID, and whether that token is an elevated administrator (`Get-AtmCurrentIdentity`). The audit header and the TUI show it. |
| Real deletion | Disabled by the release gate, whatever the privileges. |

### Elevating with another account's credentials

When UAC asks for **credentials** (a standard user, or any user when policy requires credentials) and someone
types the password of an administrator account, the elevated process runs **as that administrator account**, not
as the person who asked:

* its user SID, `%USERPROFILE%`, `%TEMP%`, `HKCU` and agent configuration directory are the administrator's; the
  requester's mapped drives and per-user settings are not visible to it. Windows may create the administrator's
  profile if that account never signed in on the machine;
* `agent-temp` started there treats the administrator's profile as "own" and the **requester's profile as another
  user's**: `-IncludeOtherUsers` and every other-user gate apply to it. The audit header shows the administrator,
  not the requester;
* the installer records the administrator as the installing account (the process identity becomes the extra
  trusted SID of its ACL audit). The
  installation is machine-wide; afterwards every user runs `agent-temp` without elevation.

The tool does not know who requested the elevation; it reasons only about the process identity. A relaunched recovery
copy (V0.4 R4, past the recovery gate only) says that its requester could not be verified. Showing the verified
requester as well is a planned requirement (PRIV-5).

## Requirements

Status: **Implemented** = true in V0.1; **Partial** = the part described is implemented, the rest is planned;
**Planned** = not implemented yet. "Validated" lists what has actually been verified; anything else is not validated.

| Id | Requirement | Status in V0.1 | Validated |
|---|---|---|---|
| PRIV-1 | **Least privilege.** Everything that can run without administrative rights does. Missing rights reduce coverage and are reported; they never make the tool fail open or guess. | **Implemented** for audit, preview, TUI, verify, version and the clean plan. | Suite as a standard user (Windows 10, PS 5.1 and 7) and elevated (CI); installed product as a real standard user in CI. Administrator with filtered token: not validated. |
| PRIV-2 | **Explicit elevation only.** Elevation is requested only for an operation that cannot work without it, says which operation and why, and is never silent, implicit or persistent. Read-only commands never trigger it. | **Implemented** by the manual model in every shipped copy: no shipped copy requests elevation; only the installer scripts require an elevated session that the user opens. V0.4 R4, past the recovery gate (closed in every copy; reached only by the suite): `recover start` and `recover undo` request elevation for that one operation only, after showing the plan (or, for undo, the run id) and a notice that names the operation, its target or run and why. `recover list` and `recover plan` never request it. | Code search: the elevation verb appears once in `src`, in the default launcher of `Engine.Recover.ps1` (R4 static check); installer refusal test; the plan and the notice before the request, with an injected launcher (suite). A real UAC prompt: not validated. |
| PRIV-3 | **UAC only.** Authentication is exclusively the Windows UAC prompt (consent or credentials, on the secure desktop). The tool never asks for, receives, stores, logs or forwards passwords, tokens or credentials, and never uses `runas /savecred`, scheduled tasks, services, credentials or any other means **to elevate or to get around UAC**. At most two scheduled tasks exist, each one per user. Each is created only by an explicit, confirmed command of the user, refused in an elevated process, run on the user's non-elevated token (run level Limited) and only while the user's session is open (logon type Interactive), with no stored credential: (1) the optional task of the automatic purge (decision J-ISO-7, complement of 2026-11-03), created by `quarantine schedule-autopurge`; (2) the optional task of the preventive monitoring (V05-D1, [ADR-0017](adr/ADR-0017-v05-preventive-monitoring.md)), created by `monitor enable` only with the monitoring gate `AtmMonitoringEnabled` open and a typed phrase of its own (ADR-0017 section 5); with the gate closed `monitor enable` refuses before asking anything. | **Implemented**: no credential handling exists; the auto-purge task is registered with no password, interactive and limited. The monitoring task: **Implemented (V0.5 M3a), gate closed in every copy; the real scheduler exercised only by the CI harness of M3b.** | Code search (no `Get-Credential`, `SecureString`, `savecred`). Auto-purge task (CI only, a disposable runner): refused elevated; created and read back as interactive, limited, no password, the exact action, by the suite and by a real standard user in the install e2e. Monitoring task (V0.5 M3a, suite): the definition built and never registered, checked field by field (interactive, limited, no password, the exact action); refused on a token that is not standard; registered only into an in-memory fake scheduler. Monitoring task (V0.5 M3b, CI only, a disposable runner, under a test task name, gate opened only in the harness's memory): created by the engine as the install e2e's real standard user, with no elevation; read back as that user's, interactive, limited, no password, the exact action; a second registration refused; removed by the harness only; read back absent. `monitor enable` refused on the elevated runner token before any plan or phrase, with nothing registered. The installed `monitor enable` exits 3 with the gate closed. A real scheduled run (first CI run 44452989213, all six install e2e jobs): the runner account's own test task, registered with run level 0 on runners with UAC enabled, ran once with last result 3 (the installed gate closed). The standard user's run: not validated; the scheduler accepted the run request but did not start the interactive task of a user with no interactive session (state Ready, last result 0x00041303). A scheduled run's console window, and the real scheduler outside a disposable runner: not validated. |
| PRIV-4 | **Cancellation and failure.** Any outcome other than a verified elevated start (prompt cancelled, request denied, UAC disabled, policy that denies elevation, no interactive desktop, any error) ends the operation with nothing changed, a clear message and a documented exit code. The reason is never inferred from one error code: cancelling often surfaces as `ERROR_CANCELLED` (1223), but denials and failures can surface as other errors or as a process that never starts. No retry loop, no fallback to a weaker path. | **Partial**: a script started without elevation refuses before changing anything, with a clear message and a non-zero exit code. V0.4 R4, past the recovery gate: the recovery requester reports only by documented exit codes and never infers a reason: Win32 error 1223 gives 40 (usually a cancelled prompt, not proof of it), another error 41, a launcher exception 42, no process 43, and an elevated copy that ended with an unknown code 44 (it may have acted). No retry, no fallback. With UAC turned off the relaunched copy is not elevated and refuses (29). The installer's own refusal keeps the generic exit code. | Refusal test (non-zero exit, message, nothing created). Recovery: every launcher result injected in the suite. Real prompt outcomes (cancel, deny, UAC off, no interactive desktop): not validated. |
| PRIV-5 | **Requester vs elevated identity.** Decisions use the elevated process identity; when the requester differs, the tool shows both and treats the requester's profile as another user's. Nothing assumes they are the same account. | **Partial**: decisions use only the process identity, and another account's profile is always treated as another user's (see the section above). V0.4 R4, past the recovery gate: a relaunched recovery copy shows the identity that acts (name, elevation type, integrity) and says that its requester was not verified (`UNVERIFIED`). It does not read the requester's token: a parent process id can be forged or reused, and that would need a handle to another process (ADR-0016, R4 implementation record). Showing the verified requester is planned. | Injected identities in the suite (profile SID different from process SID); the requester evidence injected as `SAME`, `DIFFERENT` and unreadable. Real credentials-prompt elevation and a real requester: not validated. |
| PRIV-6 | **Re-validation after elevation.** The elevated side trusts nothing from the non-elevated side: it re-reads inputs, re-runs the inventory and every gate, re-checks paths (canonical form, reparse points, ownership and ACLs of root, scope and base) and the integrity of the installed files before acting. A plan computed without elevation is only a request. | **Partial**: within one process, `clean` re-runs the inventory and every gate immediately before acting, and the launcher checks every installed file against the manifest at start. V0.4 R4, past the recovery gate: the relaunched recovery copy receives only the operation and the service name, or the run id. It runs its own launcher's integrity check, then the collection, the criteria, the plan, the phrase in its own console, the lock, the log and the revalidation, as one process; nothing computed by the requester is used. | Suite (re-validation, tamper detection; the relaunched side's refusals and a full run, in process). A real relaunch: not validated. |
| PRIV-7 | **Trusted code only.** Elevated code runs only from the administrator-owned, manifest-verified installation, with `-NoProfile`, a pinned module path and a private TEMP; never from a user-writable checkout, the current directory or a path supplied by the non-elevated side. | **Partial**: the installed launcher pins the module path, uses `-NoProfile` and verifies integrity; the administrative scripts use a private TEMP, and the installer verifies the source against the release manifest and refuses an install directory whose parent ordinary users can write. That the release itself is extracted to an administrator-only folder is **documented, not enforced**. V0.4 R4, past the recovery gate: the requester relaunches only `bin\agent-temp.cmd` of its own verified installation, with a fixed argument line and no path (otherwise exit 31), and the relaunched copy refuses unless it is an installed, verified copy. | Suite (launcher, manifest, private TEMP, unsafe parent; the exact relaunched file and argument line, and the not-installed refusals). A real relaunch: not validated. |
| PRIV-8 | **Human confirmation independent of UAC.** Consenting to UAC authorizes a process, not an operation. Every destructive operation still requires the typed confirmation of the exact plan, shown and read inside the process that will act, after re-validation. | **Implemented as a mechanism, inactive**: the typed confirmation exists and is tested; V0.1 stops before asking because real deletion is disabled. | Suite (in-process deletion tests in the sandbox). |
| PRIV-9 | **Minimal elevated scope.** An elevated process performs one requested operation and exits; it enables no extra privileges (backup, restore, take-ownership, debug) and elevates no other tool. | **Partial**: no privilege is ever enabled. With manual elevation the scope is the terminal the user opened. V0.4 R4, past the recovery gate: one recovery operation per process (a second one exits 30); the relaunched copy requests no further elevation and exits after a key. | Code search; suite (a second operation; the R4 static check). |
| PRIV-10 | **Observable.** Identity and elevation state are shown, and reports say which coverage limits come from missing elevation. | **Partial**: the audit header, the TUI header and the coverage reasons do this; since V0.2-P1-A `agent-temp version` also shows the identity, whether the token is an elevated administrator, the token elevation type (`DEFAULT`, `FULL`, `LIMITED`), the integrity level and the session. The diagnose report (V0.2) is planned to show the same. | Coverage reasons: suite. Identity display: suite (`version` in both languages; real token consistency on the runner and locally; mocked token types). |
| PRIV-11 | **Real tests** on the [privilege matrix](TESTING.md#privilege-matrix) before a release that changes privilege behaviour. | **Partial**: standard user (real token in CI; an earlier local run is not re-verified) and elevated administrator (CI, real installation) are covered; Windows 11 only on ARM64; filtered token, consent prompt and cancellation run manually on Windows 10 x64; credentials of another account and a real non-interactive session not yet ([runbook](release/PRIVILEGE-MATRIX-RUNBOOK.md)). | See the matrix. |

## Manual elevation vs elevation on demand

"On demand" means: the non-elevated tool asks for elevation for one operation by relaunching the installed launcher
through UAC (`ShellExecute` verb `runas`) with fixed arguments; the elevated copy re-validates everything (PRIV-6)
and asks for its own confirmation (PRIV-8).

| Aspect | Manual (keep current model) | On demand (relaunch through UAC) |
|---|---|---|
| Attack surface | Smallest: no boundary crossing, no data passed from a non-elevated process. | New boundary: arguments and files come from a lower-integrity process that may be compromised; every input must be treated as untrusted (PRIV-6, PRIV-7). |
| What the UAC prompt shows | The user decides to open an elevated terminal. | The prompt names Windows PowerShell (publisher Microsoft Windows), not this tool: the user cannot tell which script asks. Any non-elevated code can raise an identical prompt (consent fatigue). Signing the scripts would not change what the prompt shows for `powershell.exe`. |
| Elevated scope | Whole terminal session; the user may run other commands elevated. Mitigated by the documented `-NoProfile` usage and closing the window. | One operation, then exit (PRIV-9). |
| Time-of-check vs time-of-use | One process: inventory, plan, confirmation and action share one privilege context. | Two processes: the non-elevated plan can be stale or tampered with by the time the elevated process runs; full re-inventory and re-confirmation are mandatory. |
| Credentials of another account | Visible: the user opens the terminal as that administrator. | Happens inside a flow the user started as themselves; easy to misread whose profile is "own" (PRIV-5). |
| Prompt outcomes | Handled by Windows before the tool starts. | The tool must handle cancellation, denial and failure without relying on one error code (PRIV-4). |
| Usability | Requires knowing how to open an elevated terminal; clear refusal messages guide the user. | Smoother start, but output appears in a separate elevated window; results must be read there. |
| Non-interactive sessions, UAC disabled, Server Core, remote shells | Work (the caller provides the token). | No prompt is possible: must fail cleanly (PRIV-4) and fall back to the manual instructions. |
| Implementation and test cost | None now. | Launcher changes, argument encoding, outcome handling, identity display, a second process to test on Windows 10/11 and PowerShell 5.1/7. |

**Recommendation.** Keep **manual elevation** through V0.2, where nothing except installation needs it. Revisit the
question as a documented decision before V0.3: elevation on demand is acceptable only as an explicit, opt-in
option for a single destructive operation that meets PRIV-2 to PRIV-9, with the plan rebuilt and confirmed in the
elevated window. If those conditions cannot all be met and tested, manual elevation stays.

**Decision for assisted recovery (V04-D3 (b), 2026-11-17).** The maintainer chose elevation on demand for V0.4's
recovery operations ([ADR-0016](adr/ADR-0016-v04-assisted-recovery.md) section 3). Phase R4 implements it behind the
recovery gate, which stays closed in every copy: manual elevation remains the model of every shipped copy and of the
installer. The relaunched file is `bin\agent-temp.cmd`, so the prompt is expected to name the Windows command processor,
not this tool (the "What the UAC prompt shows" row above). That is not verified: neither the suite nor the CI raises a
real prompt.

**Acting on another user's profile (V0.4, PROPOSED).** The Recovery Mode proposed in
[ADR-0013](adr/ADR-0013-isolation-quarantine-recovery-mode.md) runs from another, elevated administrator account and
moves agent temporary data out of a profile that cannot be used. That is the `-IncludeOtherUsers` case of this
document, and it depends on:

* this elevation-model decision;
* PRIV-5 (showing the requester next to the acting identity);
* PRIV-6, PRIV-8 and PRIV-9 inside the acting process.

Its own open decision is ISO-D3: manual elevation only (recommended), or elevation on demand for that single
operation. Nothing in the current behaviour changes.
