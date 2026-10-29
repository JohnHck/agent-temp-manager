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
    [int]$DeadlineSeconds = -1,
    [string]$PseudonymKeyFile
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
# languages, because no code (not even the message catalog) is loaded before the check passes. A file or directory
# that cannot be read is a problem too, reported by its relative name only (no exception text, no absolute path).
$loadedLibs = @('lib\Engine.Audit.ps1', 'lib\I18n.ps1', 'lib\Engine.Clean.ps1', 'lib\Engine.Diagnose.ps1', 'lib\Report.ps1', 'lib\Tui.ps1')
$providersDir = Join-Path $here 'providers'

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
    # Providers: the listed provider files to load (installed copies only).
    $r = [pscustomobject]@{ Installed = $false; Version = '?'; Listed = @{}; Providers = @(); Lines = (New-Object System.Collections.Generic.List[object]); Problems = (New-Object System.Collections.Generic.List[string]) }
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
        $label = $p
        if (-not (Test-Path -LiteralPath $fp -PathType Leaf)) { $r.Problems.Add("missing/ausente: $k") }
        else {
            $actual = $null
            try { $actual = Get-AtmLauncherSha256 $fp } catch { $actual = $null }
            if ($null -eq $actual) { $r.Problems.Add("unreadable/ilegivel: $k"); $label = "$p (unreadable / ilegivel)" }
            elseif ($actual -ne $h) { $r.Problems.Add("modified/alterado: $k") }
            else { $ok = $true }
        }
        $r.Lines.Add(@($(if ($ok) { 'OK' } else { 'FAIL' }), $label))
    }
    foreach ($lib in $loadedLibs) {
        if (-not $r.Listed.ContainsKey($lib.ToLowerInvariant())) {
            $r.Problems.Add("not in manifest / fora do manifesto: $lib")
            $r.Lines.Add(@('FAIL', "$lib (not in manifest / fora do manifesto)"))
        }
    }
    # A providers directory that is missing or cannot be listed is refused: the provider set would be incomplete.
    # -Force: hidden or system files are listed too, so none escapes the check or is silently left out.
    $found = $null
    try { $found = @(Get-ChildItem -LiteralPath $providersDir -Filter '*.ps1' -File -Force -ErrorAction Stop | Sort-Object Name) } catch { $found = $null }
    if ($null -eq $found) {
        $r.Problems.Add('providers directory missing or unreadable / diretorio de providers ausente ou ilegivel: providers')
        $r.Lines.Add(@('FAIL', 'providers (missing or unreadable / ausente ou ilegivel)'))
        return $r
    }
    foreach ($pf in $found) {
        if (-not $r.Listed.ContainsKey(('providers\' + $pf.Name).ToLowerInvariant())) {
            $r.Problems.Add("provider not in manifest / provider fora do manifesto: $($pf.Name)")
            $r.Lines.Add(@('FAIL', "providers\$($pf.Name) (not in manifest / fora do manifesto)"))
        }
    }
    $r.Providers = @($found | Where-Object { $r.Listed.ContainsKey(('providers\' + $_.Name).ToLowerInvariant()) })
    # Every listed provider that exists must be among those loaded: never run with an incomplete provider set.
    $loadedKeys = @($r.Providers | ForEach-Object { ('providers\' + $_.Name).ToLowerInvariant() })
    foreach ($k in @($r.Listed.Keys | Where-Object { $_ -match '^providers\\[^\\]+\.ps1$' })) {
        if ($loadedKeys -notcontains $k -and (Test-Path -LiteralPath (Join-Path $here $k) -PathType Leaf)) {
            $r.Problems.Add("provider not enumerated / provider nao enumerado: $k")
            $r.Lines.Add(@('FAIL', "$k (not enumerated / nao enumerado)"))
        }
    }
    return $r
}

try { $integrity = Test-AtmLauncherIntegrity }
catch {
    # Unexpected failure of the check itself: an installation is refused (exit 5, no exception text); a source
    # checkout fails as before.
    if ((Test-Path -LiteralPath (Join-Path $here 'manifest.json')) -or (Test-Path -LiteralPath (Join-Path $here 'install-state.json'))) {
        Write-Host 'Installation integrity could not be checked; nothing was loaded or run. / Nao foi possivel verificar a integridade da instalacao; nada foi carregado nem executado.' -ForegroundColor Red
        exit 5
    }
    throw
}
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
# Installed: only the verified, listed providers. Source checkout: every provider file, as before.
if ($integrity.Installed) { $providerFiles = $integrity.Providers }
else { $providerFiles = @(Get-ChildItem -LiteralPath $providersDir -Filter '*.ps1' -File | Sort-Object Name) }
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
    Write-Host '  agent-temp diagnose -Lang en-US'
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
                # FINAL-A (F-02): the same rules, checked again with the folder and its ancestors pinned; the file is created
                # relative to the pinned folder (new file only, no reparse point, protected DACL), never by name.
                $exported = New-AtmPinnedTextFile -Path $ExportJson -Text (ConvertTo-AtmExportJson -Inventory $inv) -Policy { param($P) if (Test-AtmOutputPathOutsideBases -Path $P -Inventory $inv -MustNotExist) { $null } else { 'EXPORT_DESTINATION_NOT_ALLOWED' } }
                if ($null -ne $exported) { Write-Host (Get-AtmText $(if ($exported -like 'EXPORT_CREATE_CREATED_*') { 'cli.exportRefusedAfterCreate' } else { 'cli.diagExportRefusedCode' }) $exported) -ForegroundColor Red; throw (Get-AtmText 'cli.exportRefused') }
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
            # Diagnose export gate (P5-B-S): closed in every shipped copy (the ancestor TOCTOU of the export is NOT
            # RESOLVED). With -ExportJson the command refuses first: nothing is collected or printed, no destination is
            # checked and no file is created; exit code 10.
            if ($PSBoundParameters.ContainsKey('ExportJson') -and -not $script:AtmDiagnoseExportEnabled) {
                Write-Host (Get-AtmText 'cli.diagExportRefusedCode' 'EXPORT_SECURITY_GATE_CLOSED') -ForegroundColor Red
                Write-Host (Get-AtmText 'cli.diagExportGateClosed') -ForegroundColor Yellow
                Write-Host (Get-AtmText 'cli.errorNoDeletion') -ForegroundColor Yellow
                exit 10
            }
            # Progress never shows a path during diagnose (ADR-0010): the inventory's own messages name temporary bases.
            $diagInvArgs = @{} + $cliInvArgs
            $diagInvArgs['ProgressCallback'] = { param($pct, $msg) $act = Get-AtmText 'cli.progressActivity'; if ($pct -ge 100) { Write-Progress -Activity $act -Completed } else { Write-Progress -Activity $act -Status (Get-AtmText 'cli.diagProgressStatus') -PercentComplete $pct } }
            $diagArgs = @{ InventoryArgs = $diagInvArgs }
            if ($DeadlineSeconds -ge 0) { $diagArgs['DeadlineSeconds'] = $DeadlineSeconds }
            # Correlation between runs only with the operator's key file (ADR-0010): read only, fail closed, and
            # neither its path nor its content is printed.
            $keyRead = $null
            if ($PSBoundParameters.ContainsKey('PseudonymKeyFile')) {
                $keyRead = Read-AtmPseudonymKeyFile -Path $PseudonymKeyFile
                if ($null -eq $keyRead.Key) { Write-Host (Get-AtmText 'cli.pseudonymKeyRefused' $keyRead.Reason) -ForegroundColor Red; exit 2 }
                $diagArgs['PseudonymKey'] = $keyRead.Key
            }
            # An unexpected failure is reported by its exception type only: its message could carry collected data.
            try { $res = Invoke-AtmDiagnose @diagArgs }
            catch { Write-Host (Get-AtmText 'cli.diagFailed' $_.Exception.GetBaseException().GetType().Name) -ForegroundColor Red; Write-Host (Get-AtmText 'cli.errorNoDeletion') -ForegroundColor Yellow; exit 10 }
            finally { if ($null -ne $keyRead -and $null -ne $keyRead.Key) { [Array]::Clear($keyRead.Key, 0, $keyRead.Key.Length) } }
            # The report and the export are reported by exception type only as well (P5-B): their data is collected data.
            try { Show-AtmDiagnose -Result $res }
            catch { Write-Host (Get-AtmText 'cli.diagFailed' $_.Exception.GetBaseException().GetType().Name) -ForegroundColor Red; Write-Host (Get-AtmText 'cli.errorNoDeletion') -ForegroundColor Yellow; exit 10 }
            if ($ExportJson) {
                # Fail closed (P5-B): without an inventory the audited directories are unknown; the destination must be a
                # new absolute path outside them, without reparse points, and not inside a Git repository or worktree.
                # The refusal and a write failure are reported by a code only (no exception message); exit code 10.
                $refusal = $null
                try { $refusal = Test-AtmDiagnoseExportPath -Path $ExportJson -Inventory $res.Inventory } catch { $refusal = ConvertTo-AtmExceptionCode $_.Exception.GetBaseException().GetType().Name }
                if ($null -ne $refusal) { Write-Host (Get-AtmText 'cli.diagExportRefusedCode' $refusal) -ForegroundColor Red; Write-Host (Get-AtmText 'cli.diagExportRefused') -ForegroundColor Red; Write-Host (Get-AtmText 'cli.errorNoDeletion') -ForegroundColor Yellow; exit 10 }
                # The policy is checked again inside the pinned window and the file is created relative to the pinned folder.
                $written = $null
                try { $written = Write-AtmNewTextFile -Path $ExportJson -Text (ConvertTo-AtmDiagnoseJson -Result $res) -Inventory $res.Inventory }
                catch { Write-Host (Get-AtmText 'cli.diagExportFailed' (ConvertTo-AtmExceptionCode $_.Exception.GetBaseException().GetType().Name)) -ForegroundColor Red; Write-Host (Get-AtmText 'cli.errorNoDeletion') -ForegroundColor Yellow; exit 10 }
                if ($null -ne $written) { Write-Host (Get-AtmText $(if ($written -like 'EXPORT_CREATE_CREATED_*') { 'cli.exportRefusedAfterCreate' } else { 'cli.diagExportRefusedCode' }) $written) -ForegroundColor Red; Write-Host (Get-AtmText 'cli.errorNoDeletion') -ForegroundColor Yellow; exit 10 }
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
            # A run stopped after a deletion (T1) is never reported as a success.
            exit $(if ($res.Aborted -or $res.StoppedBy) { 3 } else { 0 })
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
