<#
.SYNOPSIS
  Writes a Windows Sandbox configuration (.wsb) that runs tools\clean-env\Invoke-CleanEnvTest.ps1 against a release
  in a disposable, clean Windows instance. It only WRITES the .wsb file; it does not enable Windows features and
  does not start anything.
.DESCRIPTION
  Requirements (decided by the machine owner): Windows 10/11 Pro, Enterprise or Education with the optional
  feature "Windows Sandbox" enabled (administrator + restart). Mapped folders:
    * the release folder (read-only) -> C:\atm\release
    * the tools folder (read-only)   -> C:\atm\tools
    * an output folder (writable)    -> C:\atm\out
  Networking is disabled in the sandbox: the product must not need the internet.
.EXAMPLE
  .\tools\clean-env\New-CleanEnvSandbox.ps1 -ReleaseDir .\dist -OutDir D:\atm-clean-env
  # then, after reviewing the .wsb: Start-Process D:\atm-clean-env\agent-temp-clean-env.wsb
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ReleaseDir, [Parameter(Mandatory)][string]$OutDir)
$ErrorActionPreference = 'Stop'
$rel = (Resolve-Path -LiteralPath $ReleaseDir).ProviderPath
$tools = Split-Path -Parent $MyInvocation.MyCommand.Path
[void][IO.Directory]::CreateDirectory($OutDir)
$out = (Resolve-Path -LiteralPath $OutDir).ProviderPath
$esc = { param($s) [Security.SecurityElement]::Escape($s) }
$wsb = @"
<Configuration>
  <Networking>Disable</Networking>
  <vGPU>Disable</vGPU>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <MappedFolders>
    <MappedFolder><HostFolder>$(& $esc $rel)</HostFolder><SandboxFolder>C:\atm\release</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>
    <MappedFolder><HostFolder>$(& $esc $tools)</HostFolder><SandboxFolder>C:\atm\tools</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>
    <MappedFolder><HostFolder>$(& $esc $out)</HostFolder><SandboxFolder>C:\atm\out</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\atm\tools\Invoke-CleanEnvTest.ps1 -ReleaseDir C:\atm\release -OutDir C:\atm\out</Command>
  </LogonCommand>
</Configuration>
"@
$file = Join-Path $out 'agent-temp-clean-env.wsb'
[IO.File]::WriteAllText($file, $wsb, (New-Object Text.UTF8Encoding($false)))
Write-Host "Windows Sandbox configuration written: $file"
Write-Host 'Review it, then (feature enabled) start it with: Start-Process <file>. Results: summary.json in the output folder.'
