# Privileges and UAC

How Agent Temp Manager uses administrative privileges today, the requirements every version must meet, and the
comparison that has to be decided before any version (V0.3 at the earliest) changes the elevation model.

**Current model (V0.1): manual elevation.** The tool never elevates itself and never asks for credentials. No
self-elevation exists, and none is planned before the decision described at the end of this document.

## Current behaviour (V0.1)

| Situation | Behaviour |
|---|---|
| `agent-temp` (audit, preview, TUI, verify, version, clean plan) | Runs with the token of the process that started it. It never elevates, relaunches itself or asks for credentials. |
| Not elevated (standard user, or administrator with the filtered UAC token) | Own profile audited. Other profiles are reported as inaccessible and other accounts' processes as not observable, so coverage is declared **incomplete**. `clean` is always blocked by `COBERTURA_DE_PROCESSOS_INCOMPLETA` (no override). |
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

The tool does not know who requested the elevation; it reasons only about the process identity. Showing the
requester as well is a planned requirement (PRIV-5).

## Requirements

Status: **Implemented** = true in V0.1; **Partial** = the part described is implemented, the rest is planned;
**Planned** = not implemented yet. "Validated" lists what has actually been verified; anything else is not validated.

| Id | Requirement | Status in V0.1 | Validated |
|---|---|---|---|
| PRIV-1 | **Least privilege.** Everything that can run without administrative rights does. Missing rights reduce coverage and are reported; they never make the tool fail open or guess. | **Implemented** for audit, preview, TUI, verify, version and the clean plan. | Suite as a standard user (Windows 10, PS 5.1 and 7) and elevated (CI). Administrator with filtered token: not validated. |
| PRIV-2 | **Explicit elevation only.** Elevation is requested only for an operation that cannot work without it, says which operation and why, and is never silent, implicit or persistent. Read-only commands never trigger it. | **Implemented** by the manual model: the tool never requests elevation; only the installer scripts require an elevated session that the user opens. | Code search (no `RunAs`, `-Verb`); installer refusal test. |
| PRIV-3 | **UAC only.** Authentication is exclusively the Windows UAC prompt (consent or credentials, on the secure desktop). The tool never asks for, receives, stores, logs or forwards passwords, tokens or credentials, and never uses `runas /savecred`, scheduled tasks, services or other ways around UAC. | **Implemented**: no credential handling exists. | Code search (no `Get-Credential`, `SecureString`, `savecred`). No automated test yet. |
| PRIV-4 | **Cancellation and failure.** Any outcome other than a verified elevated start (prompt cancelled, request denied, UAC disabled, policy that denies elevation, no interactive desktop, any error) ends the operation with nothing changed, a clear message and a documented exit code. The reason is never inferred from one error code: cancelling often surfaces as `ERROR_CANCELLED` (1223), but denials and failures can surface as other errors or as a process that never starts. No retry loop, no fallback to a weaker path. | **Partial**: a script started without elevation refuses before changing anything, with a clear message and a non-zero exit code. A distinct, documented exit code and the handling of prompt outcomes are planned (only relevant if the tool ever requests elevation itself). | Refusal test (non-zero exit, message, nothing created). Prompt outcomes: not validated. |
| PRIV-5 | **Requester vs elevated identity.** Decisions use the elevated process identity; when the requester differs, the tool shows both and treats the requester's profile as another user's. Nothing assumes they are the same account. | **Partial**: decisions use only the process identity, and another account's profile is always treated as another user's (see the section above). Showing the requester is planned. | Injected identities in the suite (profile SID different from process SID). Real credentials-prompt elevation: not validated. |
| PRIV-6 | **Re-validation after elevation.** The elevated side trusts nothing from the non-elevated side: it re-reads inputs, re-runs the inventory and every gate, re-checks paths (canonical form, reparse points, ownership and ACLs of root, scope and base) and the integrity of the installed files before acting. A plan computed without elevation is only a request. | **Partial**: within one process, `clean` re-runs the inventory and every gate immediately before acting, and the launcher checks every installed file against the manifest at start. Cross-process re-validation is planned (only relevant for elevation on demand). | Suite (re-validation, tamper detection). |
| PRIV-7 | **Trusted code only.** Elevated code runs only from the administrator-owned, manifest-verified installation, with `-NoProfile`, a pinned module path and a private TEMP; never from a user-writable checkout, the current directory or a path supplied by the non-elevated side. | **Partial**: the installed launcher pins the module path, uses `-NoProfile` and verifies integrity; the administrative scripts use a private TEMP, and the installer verifies the source against the release manifest and refuses an install directory whose parent ordinary users can write. That the release itself is extracted to an administrator-only folder is **documented, not enforced**. | Suite (launcher, manifest, private TEMP, unsafe parent). |
| PRIV-8 | **Human confirmation independent of UAC.** Consenting to UAC authorizes a process, not an operation. Every destructive operation still requires the typed confirmation of the exact plan, shown and read inside the process that will act, after re-validation. | **Implemented as a mechanism, inactive**: the typed confirmation exists and is tested; V0.1 stops before asking because real deletion is disabled. | Suite (in-process deletion tests in the sandbox). |
| PRIV-9 | **Minimal elevated scope.** An elevated process performs one requested operation and exits; it enables no extra privileges (backup, restore, take-ownership, debug) and elevates no other tool. | **Partial**: no privilege is ever enabled. With manual elevation the scope is the terminal the user opened; one operation per process is planned for elevation on demand. | Code search. |
| PRIV-10 | **Observable.** Identity and elevation state are shown, and reports say which coverage limits come from missing elevation. | **Partial**: the audit header, the TUI header and the coverage reasons do this; `agent-temp version` does not show identity or elevation yet. | Coverage reasons: suite. Identity display: no dedicated test yet (not validated). |
| PRIV-11 | **Real tests** on the [privilege matrix](TESTING.md#privilege-matrix) before a release that changes privilege behaviour. | **Planned**: matrix defined; 2 of its 7 rows are covered today. | See the matrix. |

## Manual elevation (current) vs elevation on demand

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
