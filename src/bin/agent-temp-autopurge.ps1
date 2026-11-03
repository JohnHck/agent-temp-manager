<#
.SYNOPSIS
  agent-temp-autopurge (Agent Temp Manager): the entry point of the automatic quarantine purge (contract section 11,
  phase P6a). It takes no parameter. It acts only when config\quarantine.policy.json is valid and has autoPurge = true,
  and only on the process user's own EXPIRED entries; with the purge gate closed (every distributed copy) it only
  reports what it would purge. No scheduled task runs it in this version: it acts only when run by hand.
  Exit codes: 0 off, report only or done; 2 an argument was given; 3 refused or stopped (retention below the minimum,
  the clean lock not available, a pass that ended or stopped on an error); 5 installation integrity; 10 unexpected.
#>
# No param block, no CmdletBinding: every argument (common parameters included) arrives in $args and is refused.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
# Cosmetic only: a redirected or legacy console keeps its encoding.
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { $null = $_ }

if ($args.Count -gt 0) {
    # Decided before anything is read or loaded: nothing of the policy, the quarantine or the library is touched.
    Write-Host 'agent-temp-autopurge takes no arguments; nothing was done. / agent-temp-autopurge nao aceita argumentos; nada foi feito.' -ForegroundColor Red
    exit 2
}

$here = Split-Path -Parent $PSScriptRoot
# The installed library is loaded only if every file of the manifest matches its SHA-256, every file loaded below
# (this entry point included) is listed and no unlisted provider exists: the rules of the launcher's own check
# (agent-temp.ps1), with .NET hashes and messages in both languages, because no code is loaded before it passes. A copy
# without manifest.json (a source checkout included) is refused: the automatic purge runs only from an installation.
$loadedLibs = @('lib\Engine.Audit.ps1', 'lib\I18n.ps1', 'lib\Engine.Clean.ps1', 'lib\Engine.Isolate.ps1', 'lib\Engine.Diagnose.ps1', 'lib\Report.ps1', 'bin\agent-temp-autopurge.ps1')
$providersDir = Join-Path $here 'providers'

function Get-AtmAutoPurgeSha256 {
    param([string]$File)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $stream = [IO.File]::OpenRead($File)
        try { return [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '') } finally { $stream.Dispose() }
    } finally { $sha.Dispose() }
}

function Test-AtmAutoPurgeIntegrity {
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
        try { $actual = Get-AtmAutoPurgeSha256 $fp } catch { $actual = $null }
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
try { $integrity = Test-AtmAutoPurgeIntegrity } catch { $integrity = $null }
if ($null -eq $integrity) {
    Write-Host 'Installation integrity could not be checked; nothing was loaded or run. / Nao foi possivel verificar a integridade da instalacao; nada foi carregado nem executado.' -ForegroundColor Red
    exit 5
}
if ($integrity.Problems.Count -gt 0) {
    Write-Host ('Installation integrity violated; nothing was loaded or run. / Integridade da instalacao violada; nada foi carregado nem executado: ' + ($integrity.Problems -join '; ')) -ForegroundColor Red
    Write-Host 'Run "agent-temp verify" and reinstall from a verified release. / Execute "agent-temp verify" e reinstale a partir de um release verificado.' -ForegroundColor Yellow
    exit 5
}

$loaded = $false
try {
    . (Join-Path $here 'lib\Engine.Audit.ps1')     # also loads lib\I18n.ps1
    Set-AtmLanguage -Requested $null
    foreach ($providerFile in $integrity.Providers) { . $providerFile.FullName }
    . (Join-Path $here 'lib\Engine.Clean.ps1')
    . (Join-Path $here 'lib\Engine.Isolate.ps1')
    . (Join-Path $here 'lib\Engine.Diagnose.ps1')
    . (Join-Path $here 'lib\Report.ps1')
    $loaded = $true
    # This entry point is its own process-reference marker; the policy is the copy's own config folder.
    $invArgs = @{ SelfMarkers = @((Join-Path $here 'bin\agent-temp-autopurge.ps1')); ConfigDir = (Join-Path $here 'config'); NoProgress = $true }
    $result = Invoke-AtmAutoPurge -InventoryArgs $invArgs
    Show-AtmAutoPurgeResult -Result $result
    if ($result.StoppedBy) { exit 3 }
    if (-not $result.Aborted -or $result.Aborted -ceq 'AUTOPURGE_OFF' -or $result.Aborted -ceq 'EXPURGO_REAL_DESABILITADO' -or $result.Aborted -ceq 'QUARANTINE_ABSENT') { exit 0 }
    exit 3
} catch {
    # The exception's type only: never its text (it may carry a path).
    $t = $_.Exception.GetBaseException().GetType().Name
    if ($loaded) { Write-Host (Get-AtmText 'ap.failed' $t) -ForegroundColor Red }
    else { Write-Host ("The automatic purge failed unexpectedly ($t); nothing more was done. / O expurgo automatico falhou de forma inesperada ($t); nada mais foi feito.") -ForegroundColor Red }
    exit 10
}
