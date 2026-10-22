<#
.SYNOPSIS
  Rolls Agent Temp Manager back to the version kept by the last "-Update" (<InstallDir>.previous).
  Requires an elevated PowerShell. The PATH entry is unchanged. Agent temporary directories are never touched.
#>
[CmdletBinding()]
param([string]$InstallDir = (Join-Path $env:ProgramFiles 'AgentTempManager'))
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
# Message catalog: the package's, or the installed copy's, verified against its manifest (InstallCommon).
$script:AtmCatalogInstallDir = $InstallDir
. (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'InstallCommon.ps1')

Assert-AtmElevated
$privateTemp = Enter-AtmPrivateTemp -InstallDir $InstallDir
try { $v = Restore-AtmPrevious -InstallDir $InstallDir } finally { Exit-AtmPrivateTemp -State $privateTemp -InstallDir $InstallDir }
Write-Host (Get-AtmText 'inst.rollbackDone' $v $InstallDir) -ForegroundColor Green
