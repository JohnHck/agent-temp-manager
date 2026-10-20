# Privilege matrix runbook (manual rows)

The rows of the [privilege matrix](../TESTING.md#privilege-matrix) that need UAC prompts, a filtered administrator
token or a second account cannot run in CI (the GitHub-hosted runners start elevated, without prompts). This runbook
lists, for each of those rows, how to run it on a real Windows machine and what to record.

Every step below is **read-only**: the probe runs `agent-temp version` and `agent-temp audit` from a checkout of the
repository, installs nothing and changes nothing. Keep the evidence folder **outside** the repository (it contains
user names and SIDs of that machine). Type passwords only into the Windows UAC prompt.

```powershell
$probe = '<checkout>\tools\privilege-matrix\Invoke-PrivilegeProbe.ps1'
$out   = '<evidence folder outside the repository>'
```

| Scenario (`-Scenario`) | How to start the session | Expected evidence |
|---|---|---|
| `standard-user` | Sign in as a standard user; normal PowerShell | `isElevatedAdministrator = false`, medium integrity, audit `elevated administrator: NO`, coverage incomplete |
| `admin-not-elevated` | Sign in as an administrator; normal (not "Run as administrator") PowerShell | Same as above: filtered token, `Administrators` group present but *deny only*, medium integrity |
| `admin-elevated-consent` | Same administrator; **Run as administrator**, approve the consent prompt | `isElevatedAdministrator = true`, high integrity, audit `elevated administrator: YES`, process identity = that administrator |
| `elevated-other-account-credentials` | Signed in as user A; **Run as administrator**; at the credentials prompt enter administrator B | Process identity = **B** (not A); high integrity; A's profile appears as another user's in the audit |
| cancellation | Start "Run as administrator" and press **No** / cancel | No elevated window opens; nothing to run; record the observation |
| `non-interactive` | From an existing session, e.g. `powershell -NonInteractive -File $probe ...` started by a scheduled task or remote shell you already use | Same token as the caller; no prompt ever appears |

Each scenario:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File $probe -Scenario <scenario> -OutDir $out
```

Repeat on Windows 10 and Windows 11 (x64), and once with `pwsh` as the starting shell where it applies. Record each
row as PASS (evidence matches), FAIL (attach the evidence) or NOT TESTED (with the reason) in the release notes.
