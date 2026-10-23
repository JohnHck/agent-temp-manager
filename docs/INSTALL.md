# Install, update, uninstall

All three operations require an **elevated** PowerShell (Run as administrator). Nothing elevates silently.
Running the tool afterwards does **not** require elevation.

## Elevation (UAC)

The installer never asks for elevation itself: you open the elevated PowerShell, Windows shows the UAC prompt, and
the scripts refuse to run without it ("no automatic elevation is performed"). See [ELEVATION.md](ELEVATION.md).

1. Start menu, type `PowerShell`, choose **Run as administrator**, approve the UAC prompt. Start the scripts with
   `powershell -NoProfile ...` as below, so no profile script runs elevated, and close the window when done.
2. **Consent prompt** (your account is an administrator): the elevated session runs as you.
3. **Credentials prompt** (a standard account, or a policy that always asks for credentials, and someone types an
   administrator account's password): the elevated session runs as **that administrator account**, with its own
   profile, `%TEMP%` and `HKCU`, not as the person who asked. The installation is machine-wide and the installer
   records that administrator as the installing account. Afterwards, every user runs `agent-temp` without
   elevation. Details: [ELEVATION.md](ELEVATION.md#elevating-with-another-accounts-credentials).
4. **Cancelling** the UAC prompt opens no elevated session and changes nothing. If the scripts are started without
   elevation they stop before changing anything.
5. Never type an administrator password anywhere except the Windows UAC prompt. The tool never asks for one.

## Install

Extract the release into a directory that **only administrators can write** (the installer runs elevated and
executes the scripts it finds there), and verify the archive first:

```powershell
(Get-FileHash .\agent-temp-manager-<version>.zip -Algorithm SHA256).Hash   # compare with SHA256SUMS.txt
```

```powershell
cd <extracted release>
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-Tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\install\Install-AgentTempManager.ps1
# optional site rules (informational project names):
#   ... Install-AgentTempManager.ps1 -ProjectsFile C:\path\projects.local.json
```

From a git checkout (no `src\manifest.json`) add `-SourceWithoutManifest` consciously; release archives are
verified against their manifest automatically.

What it does:

* loads its message catalog only after it matches the release manifest (from a git checkout, only with
  `-SourceWithoutManifest`; otherwise built-in texts are shown);
* validates the source (required files, PowerShell syntax);
* stages a copy in `%ProgramFiles%\AgentTempManager.staging-*`, compiles
  `lib\AgentTempManager.Native.dll` there (compiler temp files kept inside the staging directory), writes
  `manifest.json` (SHA-256), verifies that only SYSTEM, Administrators, TrustedInstaller, CREATOR OWNER and the
  installing administrator own or can write any installed file, then swaps it into
  `%ProgramFiles%\AgentTempManager`;
* appends `%ProgramFiles%\AgentTempManager\bin` to the **machine** `Path` (value type preserved,
  `WM_SETTINGCHANGE` broadcast);
* runs `agent-temp verify`.

All three administrative scripts redirect the process TEMP/TMP to a private directory next to the install
directory (administrator-only ACL), removed at the end, because the elevating account's own %TEMP% may be writable
by other principals. Open the elevated console with `-NoProfile` so no user profile script runs elevated.

It does not modify execution policies, ACLs of existing directories, or any agent temporary directory.
Open a new terminal afterwards.

## Update

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\install\Install-AgentTempManager.ps1 -Update
```

The previous version is kept in `%ProgramFiles%\AgentTempManager.previous` (one generation) for rollback.
`projects.local.json` is carried over unless `-ProjectsFile` is given.

Nothing is deleted before the new version verified. The new copy verifies itself before it replaces anything; an
older `.previous` is set aside in `%ProgramFiles%\AgentTempManager.recovery-<id>` and discarded only after the new
version passed `verify`. If anything fails after the swap (PATH, state, ACL check, `verify`), the installed version
and its `.previous` are put back and the update reports the failure. If putting them back fails too, nothing is
deleted and the message says where each copy is and how to rename them back.

Only one install, update, rollback or uninstall runs on an installation at a time: a second one, from any console or
session, stops with "another administrative operation is running" and changes nothing (the running one holds
`%ProgramFiles%\AgentTempManager.lock` open; the file disappears when it ends).

An update or rollback in progress is recorded in `%ProgramFiles%\AgentTempManager.transaction.json`, written before
the first directory is moved and removed only when the operation completed or every copy is back.
`AgentTempManager.recovery-*` directories may hold the only intact installation. While the transaction file or a
recovery directory exists, **update, rollback and uninstall refuse to run** and list what they found: **do not
uninstall**; check each copy with `<copy>\bin\agent-temp.cmd verify`, put the intact one back as
`AgentTempManager` by renaming, remove what you no longer need, delete the transaction file, and run again. A run
killed abruptly (power loss, terminated process) is not recovered automatically; the next run finds the transaction
file and refuses. These recovery messages are built into the installer, so they are complete whatever message
catalog the installed copy has.

## Rollback

After an `-Update`, the previous version is in `%ProgramFiles%\AgentTempManager.previous`:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\install\Restore-AgentTempManagerPrevious.ps1
```

It checks the previous version (manifest, SHA-256), swaps it back and runs `agent-temp verify`; the retired version
is removed only after that verify passed, and both are put back otherwise. The PATH entry is unchanged. To roll
back a first installation, uninstall.

## Uninstall

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\install\Uninstall-AgentTempManager.ps1
```

Removes the PATH entry and the product directories only. Agent temporary directories, allowlists, logs and
exported reports are left untouched. With a pending update or rollback (a transaction file or an
`AgentTempManager.recovery-*` directory) it refuses before changing anything: resolve the recovery first.

## Clean-environment test (Windows Sandbox)

To validate a release on a machine with no developer configuration, the machine owner can enable the optional
feature **Windows Sandbox** (administrator + restart; Windows 10/11 Pro, Enterprise, Education) and run:

```powershell
.\tools\clean-env\New-CleanEnvSandbox.ps1 -ReleaseDir .\dist -OutDir D:\atm-clean-env
Start-Process D:\atm-clean-env\agent-temp-clean-env.wsb
```

The disposable sandbox has networking disabled and the release mapped read-only. Inside it,
`Invoke-CleanEnvTest.ps1` checks the SHA-256, runs the test suite, installs **without** `-ProjectsFile`, runs
`verify`, `version`, `audit`, `preview` (read-only), uninstalls and writes `summary.json` to the output folder.
A Hyper-V VM with a fresh Windows image can run the same script.

## Verify

```powershell
agent-temp verify
```
