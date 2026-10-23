<#
.SYNOPSIS
  Uninstalls Agent Temp Manager. Requires an elevated PowerShell.
.DESCRIPTION
  Removes the product's PATH entry and the product's own directories (install, .previous, leftover staging).
  Never touches agent temporary directories, reports or allowlists created by users elsewhere.
#>
[CmdletBinding()]
param([string]$InstallDir = (Join-Path $env:ProgramFiles 'AgentTempManager'))
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
# Message catalog: the package's, or the installed copy's, verified against its manifest (InstallCommon).
$script:AtmCatalogInstallDir = $InstallDir
. (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'InstallCommon.ps1')

Assert-AtmElevated
# A pending recovery (R-B6) is refused before anything is created, the private TEMP included.
Assert-AtmNoRecoveryPending -InstallDir ([IO.Path]::GetFullPath($InstallDir).TrimEnd('\'))
$privateTemp = Enter-AtmPrivateTemp -InstallDir $InstallDir
try { $removed = Uninstall-AtmProduct -InstallDir $InstallDir } finally { Exit-AtmPrivateTemp -State $privateTemp -InstallDir $InstallDir }
Write-Host (Get-AtmText 'inst.pathRemoved' $removed)
Write-Host (Get-AtmText 'inst.uninstalled') -ForegroundColor Green
