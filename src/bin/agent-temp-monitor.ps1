<#
.SYNOPSIS
  agent-temp-monitor (Agent Temp Manager): the entry point of the preventive monitoring collector (docs/adr/ADR-0017,
  phase M3a). It takes no parameter. It is the only action of the user's own scheduled task (monitor enable), and can be
  run by hand. It reads the monitoring gate on every run: with the gate closed (every distributed copy) it exits without
  collecting, without creating the history folder and without taking the collectors' mutex. With the gate open it runs
  one collection: the audit only, one record of aggregates in the user's own history.
  Exit codes: 0 collected; 2 an argument was given; 3 the gate is closed or the collection was refused (busy, the folder
  refused, a record too large); 5 installation integrity; 10 unexpected.
#>
# No param block, no CmdletBinding: every argument (common parameters included) arrives in $args and is refused.
# Output goes through Write-Output: a run of the scheduled task has no console, and a run by hand shows the lines.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
# Cosmetic only: a redirected or legacy console keeps its encoding.
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { $null = $_ }

if ($args.Count -gt 0) {
    # Decided before anything is read or loaded: nothing of the history or the library is touched.
    Write-Output 'agent-temp-monitor takes no arguments; nothing was done. / agent-temp-monitor nao aceita argumentos; nada foi feito.'
    exit 2
}

$here = Split-Path -Parent $PSScriptRoot
# The installed library is loaded only if every file of the manifest matches its SHA-256, every file loaded below
# (this entry point and the native source included) is listed and no unlisted provider exists: the rules of the
# launcher's own check (agent-temp.ps1), with .NET hashes and messages in both languages, because no code is loaded
# before it passes. A copy without manifest.json (a source checkout included) is refused: the collector runs only from an
# installation. The list is what a collection uses: the audit (with I18n), the providers, the monitoring engine and the
# native types of the pinned folder; nothing else is loaded.
$loadedLibs = @('lib\Engine.Audit.ps1', 'lib\I18n.ps1', 'lib\Engine.Monitor.ps1', 'lib\Native.cs', 'bin\agent-temp-monitor.ps1')
$providersDir = Join-Path $here 'providers'

function Get-AtmMonitorEntrySha256 {
    param([string]$File)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $stream = [IO.File]::OpenRead($File)
        try { return [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '') } finally { $stream.Dispose() }
    } finally { $sha.Dispose() }
}

function Test-AtmMonitorEntryIntegrity {
    # Problems (relative names only, never an absolute path or exception text) and the listed providers to load.
    $r = [pscustomobject]@{ Listed = @{}; Providers = @(); Problems = (New-Object System.Collections.Generic.List[string]) }
    $mfPath = Join-Path $here 'manifest.json'
    if (-not (Test-Path -LiteralPath $mfPath -PathType Leaf)) { $r.Problems.Add('manifest missing / manifesto ausente: manifest.json'); return $r }
    $entries = $null
    try { $entries = @(([IO.File]::ReadAllText($mfPath) | ConvertFrom-Json).files) } catch { $entries = $null }
    if ($null -eq $entries -or $entries.Count -eq 0) { $r.Problems.Add('manifest unreadable or empty / manifesto ilegivel ou vazio: manifest.json'); return $r }
    foreach ($e in $entries) {
        $p = ''; $h = ''
        try { $p = [string]$e.path; $h = [string]$e.sha256 } catch { $p = ''; $h = '' }
        $k = $p.ToLowerInvariant()
        $segments = @($p -split '\\')
        # Relative product paths only: no drive, no root, no . or .. segment, no duplicate, a SHA-256 in hex.
        if ($p -notmatch '^[A-Za-z0-9_. -]+(\\[A-Za-z0-9_. -]+)*$' -or $segments -contains '.' -or $segments -contains '..' -or
            $h -notmatch '^[0-9A-Fa-f]{64}$' -or $r.Listed.ContainsKey($k)) {
            $r.Problems.Add("invalid manifest entry / entrada invalida no manifesto: $p")
            continue
        }
        $r.Listed[$k] = $h
        $fp = Join-Path $here $p
        if (-not (Test-Path -LiteralPath $fp -PathType Leaf)) { $r.Problems.Add("missing/ausente: $k"); continue }
        $actual = $null
        try { $actual = Get-AtmMonitorEntrySha256 $fp } catch { $actual = $null }
        if ($null -eq $actual) { $r.Problems.Add("unreadable/ilegivel: $k") }
        elseif ($actual -ne $h) { $r.Problems.Add("modified/alterado: $k") }
    }
    foreach ($lib in $loadedLibs) { if (-not $r.Listed.ContainsKey($lib.ToLowerInvariant())) { $r.Problems.Add("not in manifest / fora do manifesto: $lib") } }
    # -Force: hidden or system files are listed too, so no provider escapes the check or is silently left out.
    $found = $null
    try { $found = @(Get-ChildItem -LiteralPath $providersDir -Filter '*.ps1' -File -Force -ErrorAction Stop | Sort-Object Name) } catch { $found = $null }
    if ($null -eq $found) { $r.Problems.Add('providers directory missing or unreadable / diretorio de providers ausente ou ilegivel: providers'); return $r }
    foreach ($pf in $found) { if (-not $r.Listed.ContainsKey(('providers\' + $pf.Name).ToLowerInvariant())) { $r.Problems.Add("provider not in manifest / provider fora do manifesto: $($pf.Name)") } }
    $r.Providers = @($found | Where-Object { $r.Listed.ContainsKey(('providers\' + $_.Name).ToLowerInvariant()) })
    # Every listed provider that exists must be among those loaded: never run with an incomplete provider set.
    $loadedKeys = @($r.Providers | ForEach-Object { ('providers\' + $_.Name).ToLowerInvariant() })
    foreach ($k in @($r.Listed.Keys | Where-Object { $_ -match '^providers\\[^\\]+\.ps1$' })) {
        if ($loadedKeys -notcontains $k -and (Test-Path -LiteralPath (Join-Path $here $k) -PathType Leaf)) { $r.Problems.Add("provider not enumerated / provider nao enumerado: $k") }
    }
    return $r
}

$integrity = $null
try { $integrity = Test-AtmMonitorEntryIntegrity } catch { $integrity = $null }
if ($null -eq $integrity) {
    Write-Output 'Installation integrity could not be checked; nothing was loaded or run. / Nao foi possivel verificar a integridade da instalacao; nada foi carregado nem executado.'
    exit 5
}
if ($integrity.Problems.Count -gt 0) {
    Write-Output ('Installation integrity violated; nothing was loaded or run. / Integridade da instalacao violada; nada foi carregado nem executado: ' + ($integrity.Problems -join '; '))
    Write-Output 'Run "agent-temp verify" and reinstall from a verified release. / Execute "agent-temp verify" e reinstale a partir de um release verificado.'
    exit 5
}

$loaded = $false
try {
    . (Join-Path $here 'lib\Engine.Audit.ps1')     # also loads lib\I18n.ps1
    Set-AtmLanguage -Requested $null
    foreach ($providerFile in $integrity.Providers) { . $providerFile.FullName }
    . (Join-Path $here 'lib\Engine.Monitor.ps1')
    $loaded = $true
    # The engine reads the monitoring gate first, on every run: closed, it returns before the native types, the folder,
    # the mutex or the audit are reached.
    $invArgs = @{ SelfMarkers = @((Join-Path $here 'bin\agent-temp-monitor.ps1')); ConfigDir = (Join-Path $here 'config'); NoProgress = $true }
    $run = Invoke-AtmMonitorEntry -InventoryArgs $invArgs -NativeLibDir (Join-Path $here 'lib')
    if ($run.Code -ceq 'MONITORING_GATE_CLOSED') { Write-Output (Get-AtmText 'monep.gateClosed') }
    elseif ($run.ExitCode -eq 0) { Write-Output (Get-AtmText 'monep.done' ([string]$run.Result.Outcome)) }
    else { Write-Output (Get-AtmText 'monep.refused' $run.Code) }
    exit ([int]$run.ExitCode)
} catch {
    # The exception's type only: never its text (it may carry a path).
    $t = $_.Exception.GetBaseException().GetType().Name
    if ($loaded) { Write-Output (Get-AtmText 'monep.failed' $t) }
    else { Write-Output ("The monitoring collector failed unexpectedly ($t); nothing more was done. / O coletor do monitoramento falhou de forma inesperada ($t); nada mais foi feito.") }
    exit 10
}
