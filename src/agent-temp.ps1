<#
.SYNOPSIS
  agent-temp (Agent Temp Manager): read-only audit and preview of AI coding agents' temporary directories across
  all local Windows profiles. V0.1 provider: Claude Code. Run "agent-temp help" for localized help.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$Command = 'tui',
    [string]$User,
    [string]$Project,
    [string]$Root,
    [string]$Path,
    [string]$AllowListFile,
    [switch]$IncludeOtherUsers,
    [string]$ExportJson,
    [string]$LogFile,
    [switch]$NoProgress,
    [switch]$Ascii,
    [string]$Lang,
    [int]$DeadlineSeconds = -1
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
# Cosmetic only: a redirected or legacy console keeps its encoding.
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { $null = $_ }

$here = $PSScriptRoot
# Installed copies carry manifest.json: before loading ANY code, for every command including verify (R-B5), every
# listed file must match its SHA-256, every library loaded below must be listed and no unlisted provider may exist
# (fail closed). A manifest that cannot be read, or an installed copy (install-state.json) without one, is refused.
# Source checkouts (neither file) load as-is. Hashes are computed with .NET and messages are printed in both
# languages, because no code (not even the message catalog) is loaded before the check passes.
$loadedLibs = @('lib\Engine.Audit.ps1', 'lib\I18n.ps1', 'lib\Engine.Clean.ps1', 'lib\Engine.Diagnose.ps1', 'lib\Report.ps1', 'lib\Tui.ps1')
$providerFiles = @(Get-ChildItem -LiteralPath (Join-Path $here 'providers') -Filter '*.ps1' -File | Sort-Object Name)

function Get-AtmLauncherSha256 {
    param([string]$File)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $stream = [IO.File]::OpenRead($File)
        try { return [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '') } finally { $stream.Dispose() }
    } finally { $sha.Dispose() }
}

function Test-AtmLauncherIntegrity {
    # Installed: a manifest or install-state.json exists. Lines: one (OK|FAIL, label) per checked item, for verify.
    $r = [pscustomobject]@{ Installed = $false; Version = '?'; Listed = @{}; Lines = (New-Object System.Collections.Generic.List[object]); Problems = (New-Object System.Collections.Generic.List[string]) }
    $mfPath = Join-Path $here 'manifest.json'
    if (-not (Test-Path -LiteralPath $mfPath -PathType Leaf)) {
        if (Test-Path -LiteralPath (Join-Path $here 'install-state.json') -PathType Leaf) {
            $r.Installed = $true
            $r.Problems.Add('manifest missing in an installed copy / manifesto ausente em uma instalacao: manifest.json')
            $r.Lines.Add(@('FAIL', 'manifest.json'))
        }
        return $r
    }
    $r.Installed = $true
    $entries = $null
    try {
        $doc = [IO.File]::ReadAllText($mfPath) | ConvertFrom-Json
        $entries = @($doc.files)
    } catch { $entries = $null }
    try { $r.Version = [string]$doc.version } catch { $r.Version = '?' }
    if ($null -eq $entries -or $entries.Count -eq 0) {
        $r.Problems.Add('manifest unreadable or empty / manifesto ilegivel ou vazio: manifest.json')
        $r.Lines.Add(@('FAIL', 'manifest.json'))
        return $r
    }
    foreach ($e in $entries) {
        $p = ''; $h = ''
        try { $p = [string]$e.path; $h = [string]$e.sha256 } catch { $p = ''; $h = '' }
        $k = $p.ToLowerInvariant()
        $segments = @($p -split '\\')
        # Relative product paths only: no drive, no root, no . or .. segment, no duplicate, a SHA-256 in hex.
        if ($p -notmatch '^[A-Za-z0-9_. -]+(\\[A-Za-z0-9_. -]+)*$' -or $segments -contains '.' -or $segments -contains '..' -or
            $h -notmatch '^[0-9A-Fa-f]{64}$' -or $r.Listed.ContainsKey($k)) {
            $r.Problems.Add("invalid manifest entry / entrada invalida no manifesto: $p")
            $r.Lines.Add(@('FAIL', "manifest.json: $p"))
            continue
        }
        $r.Listed[$k] = $h
        $fp = Join-Path $here $p
        $ok = $false
        if (-not (Test-Path -LiteralPath $fp -PathType Leaf)) { $r.Problems.Add("missing/ausente: $k") }
        elseif ((Get-AtmLauncherSha256 $fp) -ne $h) { $r.Problems.Add("modified/alterado: $k") }
        else { $ok = $true }
        $r.Lines.Add(@($(if ($ok) { 'OK' } else { 'FAIL' }), $p))
    }
    foreach ($lib in $loadedLibs) {
        if (-not $r.Listed.ContainsKey($lib.ToLowerInvariant())) {
            $r.Problems.Add("not in manifest / fora do manifesto: $lib")
            $r.Lines.Add(@('FAIL', "$lib (not in manifest / fora do manifesto)"))
        }
    }
    foreach ($pf in $providerFiles) {
        if (-not $r.Listed.ContainsKey(('providers\' + $pf.Name).ToLowerInvariant())) {
            $r.Problems.Add("provider not in manifest / provider fora do manifesto: $($pf.Name)")
            $r.Lines.Add(@('FAIL', "providers\$($pf.Name) (not in manifest / fora do manifesto)"))
        }
    }
    return $r
}

$integrity = Test-AtmLauncherIntegrity
if ($Command -eq 'verify') {
    # Decided before anything is loaded; on failure nothing is loaded at all.
    if (-not $integrity.Installed) { Write-Host 'manifest.json missing (not running from an installation). / manifest.json ausente (execucao fora de uma instalacao).' -ForegroundColor Yellow; exit 4 }
    foreach ($line in $integrity.Lines) { Write-Host ("  {0,-4} {1}" -f $line[0], $line[1]) -ForegroundColor $(if ($line[0] -eq 'OK') { 'Green' } else { 'Red' }) }
    if ($integrity.Problems.Count -gt 0) {
        Write-Host ('Version {0}; {1} problem(s); nothing was loaded or run. / Versao {0}; {1} problema(s); nada foi carregado nem executado.' -f $integrity.Version, $integrity.Problems.Count) -ForegroundColor Red
        exit 5
    }
    # Every file matched its SHA-256: the message catalog is verified and only it is loaded, for the summary.
    . (Join-Path $here 'lib\I18n.ps1')
    Set-AtmLanguage -Requested $Lang
    Write-Host (Get-AtmText 'cli.verifySummary' $integrity.Version 0)
    exit 0
}
if ($integrity.Problems.Count -gt 0) {
    Write-Host ('Installation integrity violated; nothing was loaded or run. / Integridade da instalacao violada; nada foi carregado nem executado: ' + ($integrity.Problems -join '; ')) -ForegroundColor Red
    Write-Host 'Run "agent-temp verify" and reinstall from a verified release. / Execute "agent-temp verify" e reinstale a partir de um release verificado.' -ForegroundColor Yellow
    exit 5
}
if ($integrity.Installed) { $providerFiles = @($providerFiles | Where-Object { $integrity.Listed.ContainsKey(('providers\' + $_.Name).ToLowerInvariant()) }) }
. (Join-Path $here 'lib\Engine.Audit.ps1')     # also loads lib\I18n.ps1
Set-AtmLanguage -Requested $Lang
foreach ($providerFile in $providerFiles) { . $providerFile.FullName }
. (Join-Path $here 'lib\Engine.Clean.ps1')
. (Join-Path $here 'lib\Engine.Diagnose.ps1')
. (Join-Path $here 'lib\Report.ps1')
. (Join-Path $here 'lib\Tui.ps1')

# Markers used to exclude this invocation's own launcher chain from process-reference evidence.
$selfMarkers = @((Join-Path $here 'agent-temp.ps1'), (Join-Path $here 'bin\agent-temp.cmd'))
$invArgs = @{ SelfMarkers = $selfMarkers; ConfigDir = (Join-Path $here 'config') }
$cliInvArgs = @{} + $invArgs
$cliInvArgs['NoProgress'] = [bool]$NoProgress
$cliInvArgs['ProgressCallback'] = { param($pct, $msg) $act = Get-AtmText 'cli.progressActivity'; if ($pct -ge 100) { Write-Progress -Activity $act -Completed } else { Write-Progress -Activity $act -Status $msg -PercentComplete $pct } }

function Show-Help {
    foreach ($k in @('help.title', 'help.blank', 'help.tui', 'help.audit', 'help.preview', 'help.diagnose', 'help.clean', 'help.clean2', 'help.verify', 'help.version', 'help.help', 'help.blank',
            'help.drill', 'help.export', 'help.diagOpts', 'help.cleanOpts', 'help.cleanOpts2', 'help.cleanOpts3', 'help.tuiOpts', 'help.lang', 'help.blank', 'help.examples')) { Write-Host (Get-AtmText $k) }
    Write-Host '  agent-temp'
    Write-Host '  agent-temp audit'
    Write-Host '  agent-temp diagnose -ExportJson D:\reports\diagnose.json'
    Write-Host '  agent-temp audit -User alice'
    Write-Host '  agent-temp audit -Project MyProject'
    Write-Host '  agent-temp audit -Path "C:\Users\alice\AppData\Local\Temp\claude\<slug>\<uuid>"'
    Write-Host '  agent-temp preview -Lang en-US'
    Write-Host '  agent-temp clean -AllowListFile C:\review\allowlist.txt'
}

try {
    switch ($Command.ToLowerInvariant()) {
        'tui' {
            if (-not (Test-AtmTuiInteractive)) {
                Write-Host (Get-AtmText 'cli.tuiNeedsConsole') -ForegroundColor Yellow
                Write-Host (Get-AtmText 'cli.tuiUse')
                exit 6
            }
            $null = Start-AtmTui -InventoryArgs $invArgs -Ascii:$Ascii
            exit 0
        }
        'audit' {
            $inv = Invoke-AtmInventory @cliInvArgs
            if ($Path) { Show-AtmPathDetail -Inventory $inv -Path $Path }
            else { Show-AtmAudit -Inventory $inv -User $User -Project $Project -Root $Root }
            if ($ExportJson) {
                if (-not (Test-AtmOutputPathOutsideBases -Path $ExportJson -Inventory $inv -MustNotExist)) { throw (Get-AtmText 'cli.exportRefused') }
                [IO.File]::WriteAllText($ExportJson, (ConvertTo-AtmExportJson -Inventory $inv), (New-Object Text.UTF8Encoding($false)))
                Write-Host (Get-AtmText 'cli.exportWritten' $ExportJson)
                Write-Host (Get-AtmText 'cli.exportPrivacy') -ForegroundColor Yellow
            }
            exit 0
        }
        'preview' {
            $inv = Invoke-AtmInventory @cliInvArgs
            $rows = Invoke-AtmPreview -Inventory $inv -IncludeOtherUsers:$IncludeOtherUsers
            Show-AtmPreview -Inventory $inv -Rows $rows -User $User -Project $Project -Root $Root
            exit 0
        }
        'diagnose' {
            # Read-only (docs/adr/ADR-0009). Partial coverage is a result, not an error: exit code 0.
            $diagArgs = @{ InventoryArgs = $cliInvArgs }
            if ($DeadlineSeconds -ge 0) { $diagArgs['DeadlineSeconds'] = $DeadlineSeconds }
            $res = Invoke-AtmDiagnose @diagArgs
            Show-AtmDiagnose -Result $res
            if ($ExportJson) {
                # Fail closed: without an inventory the audited directories are unknown, so no path can be validated.
                if ($null -eq $res.Inventory -or -not (Test-AtmOutputPathOutsideBases -Path $ExportJson -Inventory $res.Inventory -MustNotExist)) { throw (Get-AtmText 'cli.diagExportRefused') }
                [IO.File]::WriteAllText($ExportJson, (ConvertTo-AtmDiagnoseJson -Result $res), (New-Object Text.UTF8Encoding($false)))
                Write-Host (Get-AtmText 'cli.exportWritten' $ExportJson)
                Write-Host (Get-AtmText 'cli.diagExportPrivacy') -ForegroundColor Yellow
            }
            exit 0
        }
        'clean' {
            if (-not $AllowListFile -and -not $Path) { Write-Host (Get-AtmText 'cli.cleanNeedsList') -ForegroundColor Red; exit 2 }
            if ($AllowListFile -and -not (Test-Path -LiteralPath $AllowListFile -PathType Leaf)) { Write-Host (Get-AtmText 'cli.allowlistMissing' $AllowListFile) -ForegroundColor Red; exit 2 }
            $entries = Read-AtmAllowList -File $AllowListFile -Paths @($Path)
            if ($LogFile) {
                $probe = Invoke-AtmInventory @cliInvArgs
                if (-not (Test-AtmOutputPathOutsideBases -Path $LogFile -Inventory $probe)) { Write-Host (Get-AtmText 'cli.logRefused') -ForegroundColor Red; exit 2 }
            }
            $presenter = { param($v, $r, $i) Show-AtmCleanPlan -Verified $v -Rejected $r -Inventory $i }
            $reader = { param($phrase) Write-Host ''; Write-Host (Get-AtmText 'cli.typePhrase' $phrase) -ForegroundColor Yellow; Read-Host (Get-AtmText 'cli.confirmPrompt') }
            $res = Invoke-AtmClean -Entries $entries -IncludeOtherUsers:$IncludeOtherUsers `
                -PlanPresenter $presenter -ConfirmationReader $reader -InventoryArgs $cliInvArgs -LogFile $LogFile
            Show-AtmCleanResult -Result $res
            if ($res.PostInventory) {
                Write-Host ''
                Write-Host (Get-AtmText 'cli.postAudit') -ForegroundColor Cyan
                Show-AtmAudit -Inventory $res.PostInventory
            }
            exit $(if ($res.Aborted) { 3 } else { 0 })
        }
        'version' {
            Initialize-AtmNative -LibDir (Join-Path $here 'lib')
            Write-Host "agent-temp $script:AtmVersion"
            Write-Host ("providers: {0}" -f ((Get-AtmProviders | ForEach-Object { $_.DisplayName }) -join ', '))
            Write-Host (Get-AtmText 'cli.native' (Get-AtmText "native.$script:AtmNativeMode"))
            Write-Host (Get-AtmText 'cli.realDeletion' $(if ($script:AtmRealDeletionEnabled) { Get-AtmText 'cli.enabled' } else { Get-AtmText 'cli.disabledV01' }))
            Write-Host (Get-AtmText 'cli.language' (Get-AtmLanguage))
            $idState = Get-AtmIdentityState
            Write-Host (Get-AtmText 'cli.identity' $idState.Name (Get-AtmYesNo ([bool]$idState.IsElevatedAdministrator)) $idState.ElevationType $idState.IntegrityLevel $idState.SessionId)
            exit 0
        }
        default { Show-Help; exit $(if ($Command -in @('help', '-h', '--help', '/?')) { 0 } else { 1 }) }
    }
} catch {
    Write-Host ((Get-AtmText 'cli.error') + ' ' + $_.Exception.Message) -ForegroundColor Red
    Write-Host (Get-AtmText 'cli.errorNoDeletion') -ForegroundColor Yellow
    exit 10
}
