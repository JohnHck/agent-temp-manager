<#
.SYNOPSIS
  Read-only probe for one row of the privilege matrix (docs/TESTING.md). Run it once per scenario, in the session
  that the scenario describes (standard user, administrator not elevated, elevated by consent, elevated with
  another account's credentials...). It records who the process is, how its token is elevated, the UAC policy, and
  what `agent-temp` reports, so the row can be marked PASS / FAIL / NOT TESTED with evidence.
.DESCRIPTION
  Read-only: it installs nothing, changes nothing, writes only the evidence file in -OutDir (keep that folder
  outside the repository: it contains user names and SIDs of this machine). It runs `src\agent-temp.ps1` from
  this checkout (version and audit, no export) with Windows PowerShell 5.1, and the installed `agent-temp` only if
  it is on PATH. Never type a password anywhere except the Windows UAC prompt.
.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\privilege-matrix\Invoke-PrivilegeProbe.ps1 -Scenario standard-user -OutDir D:\atm-evidence
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('standard-user', 'admin-not-elevated', 'admin-elevated-consent', 'elevated-other-account-credentials', 'non-interactive')][string]$Scenario,
    [Parameter(Mandatory)][string]$OutDir
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($id)
# Column names of whoami are localized: read them by position.
$groups = @(& whoami.exe /groups /fo csv /nh 2>$null | ConvertFrom-Csv -Header 'Group Name', 'Type', 'SID', 'Attributes')
$integrity = @($groups | Where-Object { $_.'SID' -like 'S-1-16-*' } | ForEach-Object { $_.'Group Name' }) -join ', '
$adminGroup = @($groups | Where-Object { $_.'SID' -eq 'S-1-5-32-544' } | ForEach-Object { $_.'Attributes' }) -join ', '
$uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue

function Invoke-Capture([string]$Exe, [string[]]$ArgList) {
    $o = @(& $Exe @ArgList 2>&1 | ForEach-Object { "$_" })
    return [pscustomobject]@{ Code = $LASTEXITCODE; Text = ($o -join "`n") }
}
$entry = Join-Path $repo 'src\agent-temp.ps1'
$ver = Invoke-Capture -Exe $ps51 -ArgList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $entry, 'version', '-Lang', 'en-US')
$aud = Invoke-Capture -Exe $ps51 -ArgList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $entry, 'audit', '-NoProgress', '-Lang', 'en-US')
$installed = Get-Command agent-temp -ErrorAction SilentlyContinue

$evidence = [ordered]@{
    scenario = $Scenario; utc = [datetime]::UtcNow.ToString('o')
    os = (Get-CimInstance Win32_OperatingSystem).Caption; osVersion = [Environment]::OSVersion.Version.ToString()
    probeShell = "$($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)"
    processUser = $id.Name; processSid = $id.User.Value; sessionUser = $env:USERNAME
    isElevatedAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    integrityLevel = $integrity; administratorsGroupAttributes = $adminGroup
    uac = [ordered]@{
        EnableLUA = $(if ($uac) { $uac.EnableLUA } else { $null })
        ConsentPromptBehaviorAdmin = $(if ($uac) { $uac.ConsentPromptBehaviorAdmin } else { $null })
        ConsentPromptBehaviorUser = $(if ($uac) { $uac.ConsentPromptBehaviorUser } else { $null })
        PromptOnSecureDesktop = $(if ($uac) { $uac.PromptOnSecureDesktop } else { $null })
    }
    interactive = [Environment]::UserInteractive
    checkoutVersion = [ordered]@{ exit = $ver.Code; output = $ver.Text }
    checkoutAudit = [ordered]@{ exit = $aud.Code; runByLine = (@($aud.Text -split "`n" | Where-Object { $_ -match 'Run by' }) -join ' '); coverageLines = @($aud.Text -split "`n" | Where-Object { $_ -match '(?i)coverage|incomplete|not observable' }) }
    installedOnPath = [bool]$installed
}
[void][IO.Directory]::CreateDirectory($OutDir)
$file = Join-Path $OutDir ("privilege-probe-{0}-{1}.json" -f $Scenario, [datetime]::UtcNow.ToString('yyyyMMddHHmmss'))
[IO.File]::WriteAllText($file, ($evidence | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($false)))
Write-Output "evidence: $file"
Write-Output ("process: {0} | elevated administrator: {1} | integrity: {2} | UAC EnableLUA: {3}" -f $id.Name, $evidence.isElevatedAdministrator, $integrity, $evidence.uac.EnableLUA)
Write-Output ("checkout version exit {0} | audit exit {1} | {2}" -f $ver.Code, $aud.Code, $evidence.checkoutAudit.runByLine.Trim())
