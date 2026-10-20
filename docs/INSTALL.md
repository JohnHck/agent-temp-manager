# Install, update, uninstall

All three operations require an **elevated** PowerShell (Run as administrator). Nothing elevates silently.
Running the tool afterwards does **not** require elevation.

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

## Rollback

After an `-Update`, the previous version is in `%ProgramFiles%\AgentTempManager.previous`:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\install\Restore-AgentTempManagerPrevious.ps1
```

It swaps the previous version back, removes the retired one and runs `agent-temp verify`. The PATH entry is
unchanged. To roll back a first installation, uninstall.

## Uninstall

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\install\Uninstall-AgentTempManager.ps1
```

Removes the PATH entry and the product directories only. Agent temporary directories, allowlists, logs and
exported reports are left untouched.

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
