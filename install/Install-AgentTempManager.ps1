<#
.SYNOPSIS
  Installs or updates Agent Temp Manager (global command: agent-temp). Requires an elevated PowerShell.

.DESCRIPTION
  * Copies src\ to %ProgramFiles%\AgentTempManager through a staging directory (atomic swap on update).
  * Compiles lib\AgentTempManager.Native.dll inside the admin-only staging directory (no user-writable temp).
  * Run it from an administrator-only location holding a release whose SHA256SUMS you verified.
  * Writes manifest.json (SHA-256 of every installed file) used by "agent-temp verify".
  * Verifies that only SYSTEM / Administrators / TrustedInstaller / CREATOR OWNER / the installing administrator
    own or can write any installed file; aborts otherwise.
  * Adds <InstallDir>\bin to the MACHINE Path (REG_EXPAND_SZ preserved) unless -SkipPath.
  * Never changes execution policies, never touches any agent temporary directory, never deletes user data.

.PARAMETER SourceWithoutManifest
  Accept a source directory that has no src\manifest.json (e.g. a git checkout). Without it, the source must
  match the release manifest exactly (no extra, missing or modified files).

.PARAMETER ProjectsFile
  Optional site-specific project rules (copied as config\projects.local.json). Informational only.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\install\Install-AgentTempManager.ps1
.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\install\Install-AgentTempManager.ps1 -Update
#>
[CmdletBinding()]
param(
    [string]$SourceDir,
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'AgentTempManager'),
    [string]$ProjectsFile,
    [switch]$Update,
    [switch]$SkipPath,
    [switch]$SourceWithoutManifest
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
if (-not $SourceDir) { $SourceDir = Join-Path (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)) 'src' }
. (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'InstallCommon.ps1')

Assert-AtmElevated
Write-Host (Get-AtmText 'inst.source' ([IO.Path]::GetFullPath($SourceDir)))
Write-Host (Get-AtmText 'inst.target' $InstallDir)
$privateTemp = Enter-AtmPrivateTemp -InstallDir $InstallDir
try {
    $r = Install-AtmProduct -SourceDir $SourceDir -InstallDir $InstallDir -ProjectsFile $ProjectsFile -Update:$Update -SkipPath:$SkipPath -SourceWithoutManifest:$SourceWithoutManifest `
        -TrustSid ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
} finally { Exit-AtmPrivateTemp -State $privateTemp -InstallDir $InstallDir }
Write-Host ''
Write-Host (Get-AtmText 'inst.done' $r.Version $r.InstallDir $r.PathAdded $r.PreviousKept) -ForegroundColor Green
Write-Host (Get-AtmText 'inst.openNew') -ForegroundColor Green
