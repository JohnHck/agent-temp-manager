<#
.SYNOPSIS
  agent-temp (Agent Temp Manager): read-only audit and preview of AI coding agents' temporary directories across
  all local Windows profiles. V0.1 provider: Claude Code. Run "agent-temp help" for localized help.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$Command = 'tui',
    # quarantine: list | inspect | verify | restore | purge. recover (V0.4): list | plan | start (-Operation, -Service) | undo (-RunId).
    [Parameter(Position = 1)][string]$SubCommand,
    [string]$User,
    [string]$Project,
    [string]$Root,
    [string]$Path,
    [string]$AllowListFile,
    [switch]$IncludeOtherUsers,
    [switch]$AcceptB1ResidualRisk,
    [string]$ExportJson,
    [string]$LogFile,
    [string]$RecordFile,
    [string]$Entry,
    [switch]$All,
    [switch]$NoProgress,
    [switch]$Ascii,
    [string]$Lang,
    [int]$DeadlineSeconds = -1,
    [string]$PseudonymKeyFile, [string]$Operation, [string]$Service, [string]$RunId,
    # V0.5 M3a: the repetition interval of monitor enable only (1, 2, 4, 6, 12 or 24 hours; checked by that verb).
    [string]$IntervalHours,
    # V0.4 R4: the marker of a recovery copy relaunched elevated through UAC. It proves nothing: that copy only gets stricter.
    [switch]$AtmElevatedRecovery
)

# SR-03: a recovery copy relaunched elevated starts without bin\agent-temp.cmd, so it pins its module path here, as the
# shim does, before any command that could load a module: the system module directory, taken from GetSystemDirectory
# and never from the environment it was given (with another account's credentials, the requester's). .NET only here.
if ($AtmElevatedRecovery) { [Environment]::SetEnvironmentVariable('PSModulePath', [IO.Path]::Combine([Environment]::SystemDirectory, 'WindowsPowerShell\v1.0\Modules'), 'Process') }
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
$loadedLibs = @('lib\Engine.Audit.ps1', 'lib\I18n.ps1', 'lib\Engine.Clean.ps1', 'lib\Engine.Isolate.ps1', 'lib\Engine.Diagnose.ps1', 'lib\Engine.Recover.ps1', 'lib\Report.ps1', 'lib\Engine.Monitor.ps1', 'lib\Tui.ps1', 'lib\GuiModel.ps1', 'lib\Gui.ps1')
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

function Get-AtmLauncherUnlisted {
    # F-14 (verify only; after the integrity check; loads nothing; never changes the exit code): every file of the
    # installation the manifest does not list is a warning, except manifest.json and install-state.json at the root. A
    # reparse point is a warning and is never followed; a folder that cannot be listed is a warning, with no exception
    # text. -Force: hidden and system files are listed too. Relative names only, never an absolute path.
    param([hashtable]$Listed)
    $warn = New-Object System.Collections.Generic.List[string]
    $stack = New-Object System.Collections.Generic.Stack[object]
    $stack.Push(@($here, ''))
    while ($stack.Count -gt 0) {
        $cur = $stack.Pop()
        $items = $null
        try { $items = @(Get-ChildItem -LiteralPath $cur[0] -Force -ErrorAction Stop) } catch { $items = $null }
        if ($null -eq $items) { $warn.Add("$(if ($cur[1]) { $cur[1] } else { '.' }) (folder cannot be listed / pasta que nao pode ser listada)"); continue }
        foreach ($e in $items) {
            $rel = $(if ($cur[1]) { $cur[1] + '\' + $e.Name } else { $e.Name })
            if (($e.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { $warn.Add("$rel (reparse point, not followed / ponto de reparse, nao seguido)"); continue }
            if (($e.Attributes -band [IO.FileAttributes]::Directory) -ne 0) { $stack.Push(@($e.FullName, $rel)); continue }
            $k = $rel.ToLowerInvariant()
            if ($Listed.ContainsKey($k) -or $k -ceq 'manifest.json' -or $k -ceq 'install-state.json') { continue }
            # An unlisted provider script is already a problem (FAIL) of the integrity check: not repeated as a warning.
            if ($k -match '^providers\\[^\\]+\.ps1$') { continue }
            # The administrator's quarantine policy created in the installation is listed only by the next update.
            $hint = $(if ($k -ceq 'config\quarantine.policy.json') { '; policy file not in the manifest until the next update: running the installer again (-Update) records it / arquivo de politica fora do manifesto ate a proxima atualizacao: rodar o instalador de novo (-Update) passa a registra-lo' } else { '' })
            $warn.Add("$rel (not in manifest / fora do manifesto$hint)")
        }
    }
    $out = $warn.ToArray()
    [Array]::Sort($out, [StringComparer]::OrdinalIgnoreCase)
    return $out
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
    # F-14: files the manifest does not list are warnings only (WARN, yellow), with OK and FAIL; a warning never turns
    # exit 0 into 5. Only with a readable manifest (otherwise every file would be unlisted).
    $warnings = @()
    if ($integrity.Listed.Count -gt 0) {
        try { $warnings = @(Get-AtmLauncherUnlisted -Listed $integrity.Listed) } catch { $warnings = @('. (installation not fully scanned / instalacao nao varrida por inteiro)') }
    }
    foreach ($line in $integrity.Lines) { Write-Host ("  {0,-4} {1}" -f $line[0], $line[1]) -ForegroundColor $(if ($line[0] -eq 'OK') { 'Green' } else { 'Red' }) }
    foreach ($w in $warnings) { Write-Host ("  {0,-4} {1}" -f 'WARN', $w) -ForegroundColor Yellow }
    if ($integrity.Problems.Count -gt 0) {
        Write-Host ('Version {0}; {1} problem(s); {2} warning(s); nothing was loaded or run. / Versao {0}; {1} problema(s); {2} aviso(s); nada foi carregado nem executado.' -f $integrity.Version, $integrity.Problems.Count, $warnings.Count) -ForegroundColor Red
        exit 5
    }
    # Every file matched its SHA-256: the message catalog is verified and only it is loaded, for the summary.
    . (Join-Path $here 'lib\I18n.ps1')
    Set-AtmLanguage -Requested $Lang
    Write-Host (Get-AtmText 'cli.verifySummary' $integrity.Version 0)
    if ($warnings.Count -gt 0) { Write-Host (Get-AtmText 'cli.verifyWarnings' $warnings.Count) -ForegroundColor Yellow } else { Write-Host (Get-AtmText 'cli.verifyWarnings' 0) }
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
. (Join-Path $here 'lib\Engine.Isolate.ps1')
. (Join-Path $here 'lib\Engine.Diagnose.ps1')
. (Join-Path $here 'lib\Report.ps1')
. (Join-Path $here 'lib\Tui.ps1')
# V0.2.1 (ADR-0014): the desktop GUI. Loading these two files defines functions and constants only; WinForms is loaded
# by `gui` alone, past its release gate (closed in every copy) and its environment checks.
. (Join-Path $here 'lib\GuiModel.ps1')
. (Join-Path $here 'lib\Gui.ps1')

# Markers used to exclude this invocation's own launcher chain from process-reference evidence.
$selfMarkers = @((Join-Path $here 'agent-temp.ps1'), (Join-Path $here 'bin\agent-temp.cmd'))
$invArgs = @{ SelfMarkers = $selfMarkers; ConfigDir = (Join-Path $here 'config') }
$cliInvArgs = @{} + $invArgs
$cliInvArgs['NoProgress'] = [bool]$NoProgress
$cliInvArgs['ProgressCallback'] = { param($pct, $msg) $act = Get-AtmText 'cli.progressActivity'; if ($pct -ge 100) { Write-Progress -Activity $act -Completed } else { Write-Progress -Activity $act -Status $msg -PercentComplete $pct } }

function Show-Help {
    foreach ($k in @('help.title', 'help.blank', 'help.tui', 'help.audit', 'help.preview', 'help.diagnose', 'help.clean', 'help.clean2', 'help.isolate', 'help.isolate2', 'help.quarantine', 'help.quarantine2', 'help.quarantine3', 'help.authorize', 'help.verify', 'help.version', 'help.gui', 'help.recover', 'help.recover2', 'help.recover3', 'help.recover4', 'help.monitor', 'help.help', 'help.blank',
            'help.drill', 'help.export', 'help.diagOpts', 'help.cleanOpts', 'help.cleanOpts2', 'help.cleanOpts3', 'help.cleanOpts4', 'help.tuiOpts', 'help.lang', 'help.blank', 'help.examples')) { Write-Host (Get-AtmText $k) }
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
        'gui' {
            # V0.2.1 (ADR-0014): presentation only. With the release gate closed (every copy): GUI_GATE_CLOSED, exit 7,
            # no window and no WinForms assembly. Past it: an STA thread and an interactive desktop, or exit 8 with the
            # reason; never relaunched in another shell (GUI-D7). V0.4 R5: past the gate, the recovery engine is loaded too,
            # for the read-only recovery area (its collection, list and plan; the window never executes). V0.5 M5: past the
            # gate, the monitoring engine too, for the view-only monitoring area (its status only; loading it defines
            # functions and constants only).
            if ($script:AtmGuiEnabled) {
                Initialize-AtmNative -LibDir (Join-Path $here 'lib')
                . (Join-Path $here 'lib\Engine.Recover.ps1')
                . (Join-Path $here 'lib\Engine.Monitor.ps1')
            }
            exit (Invoke-AtmGuiCommand)
        }
        'tui' {
            if (-not (Test-AtmTuiInteractive)) {
                Write-Host (Get-AtmText 'cli.tuiNeedsConsole') -ForegroundColor Yellow
                Write-Host (Get-AtmText 'cli.tuiUse')
                exit 6
            }
            # V0.4 R5: the recovery engine, for the TUI's read-only recovery area (its collection, list and plan; the TUI
            # never executes). Loading it defines functions and constants only. V0.5 M5: the monitoring engine, for the
            # TUI's view-only monitoring screen (M; it reads the status and the task state, never acts).
            . (Join-Path $here 'lib\Engine.Recover.ps1')
            . (Join-Path $here 'lib\Engine.Monitor.ps1')
            $null = Start-AtmTui -InventoryArgs $invArgs -Ascii:$Ascii
            exit 0
        }
        'audit' {
            $inv = Invoke-AtmInventory @cliInvArgs
            if ($Path) { Show-AtmPathDetail -Inventory $inv -Path $Path }
            else {
                # V0.5 M5: at most one alert line under the first header. The engine's summary decides first whether
                # anything is read (in every distributed copy nothing is, and no line is written); it never throws, and
                # the line never enters -ExportJson nor changes the exit code.
                . (Join-Path $here 'lib\Engine.Monitor.ps1')
                Show-AtmAudit -Inventory $inv -User $User -Project $Project -Root $Root -MonitorLine (Get-AtmMonitorAuditLine -Summary (Get-AtmMonitorAuditSummary))
            }
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
            $rows = Invoke-AtmPreview -Inventory $inv -IncludeOtherUsers:$IncludeOtherUsers -InventoryArgs $cliInvArgs
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
            # AUT-2: only with real deletion enabled (never in a distributed copy) the run asks questions; then an
            # interactive console is required here and observed again by the engine. With the gate closed nothing changes.
            if ($script:AtmRealDeletionEnabled -and -not (Test-AtmTuiInteractive)) { Write-Host (Get-AtmText 'cli.cleanNeedsConsole') -ForegroundColor Yellow; exit 6 }
            $presenter = { param($v, $r, $i) Show-AtmCleanPlan -Verified $v -Rejected $r -Inventory $i }
            $reader = { param($phrase, $kind, $rootPath, $choices, $info) Read-AtmCleanAnswer -Phrase $phrase -Kind $kind -RootPath $rootPath -Choices $choices -Info $info -LineReader { param($pr) Read-Host $pr } }
            # -AcceptB1ResidualRisk (B1 restricted exception): considered by the engine only past the release gate; it
            # answers nothing and skips no console requirement (each root still needs its typed acceptance).
            $res = Invoke-AtmClean -Entries $entries -IncludeOtherUsers:$IncludeOtherUsers -AcceptB1ResidualRisk:$AcceptB1ResidualRisk `
                -PlanPresenter $presenter -ConfirmationReader $reader -InventoryArgs $cliInvArgs -LogFile $LogFile -Interaction @{ Caller = 'CLI'; ConsoleRequired = [bool]$script:AtmRealDeletionEnabled }
            Show-AtmCleanResult -Result $res
            if ($res.PostInventory) {
                Write-Host ''
                Write-Host (Get-AtmText 'cli.postAudit') -ForegroundColor Cyan
                Show-AtmAudit -Inventory $res.PostInventory
            }
            # A run stopped after a deletion (T1) is never reported as a success.
            exit $(if ($res.Aborted -or $res.StoppedBy) { 3 } else { 0 })
        }
        'isolate' {
            # 0.3.x isolation (docs/adr/ADR-0013): the engine applies the 0.3.x target rule (own profile, one session root)
            # and the clean gates and shows the exact plan. With the isolation gate closed (every distributed copy) it stops
            # there: it asks nothing, takes no lock, opens no log, creates no quarantine and moves nothing. Past the gate
            # (never in a distributed copy) the run needs an interactive console, a new -LogFile and the typed confirmation.
            if (-not $AllowListFile -and -not $Path) { Write-Host (Get-AtmText 'cli.isolateNeedsList') -ForegroundColor Red; exit 2 }
            if ($IncludeOtherUsers) { Write-Host (Get-AtmText 'cli.isolateOwnProfileOnly') -ForegroundColor Red; exit 2 }
            if ($AllowListFile -and -not (Test-Path -LiteralPath $AllowListFile -PathType Leaf)) { Write-Host (Get-AtmText 'cli.allowlistMissing' $AllowListFile) -ForegroundColor Red; exit 2 }
            $isoEntries = Read-AtmAllowList -File $AllowListFile -Paths @($Path)
            if ($script:AtmIsolationEnabled -and $LogFile) {
                $isoProbe = Invoke-AtmInventory @cliInvArgs
                if (-not (Test-AtmOutputPathOutsideBases -Path $LogFile -Inventory $isoProbe)) { Write-Host (Get-AtmText 'cli.logRefused') -ForegroundColor Red; exit 2 }
            }
            if ($script:AtmIsolationEnabled -and -not (Test-AtmTuiInteractive)) { Write-Host (Get-AtmText 'cli.isolateNeedsConsole') -ForegroundColor Yellow; exit 6 }
            $isoPresenter = { param($v, $r, $i, $planId) Show-AtmIsolatePlan -Verified $v -Rejected $r -Inventory $i -PlanId $planId }
            $isoReader = { param($phrase, $kind, $rootPath, $choices, $info) Read-AtmCleanAnswer -Phrase $phrase -Kind $kind -RootPath $rootPath -Choices $choices -Info $info -LineReader { param($pr) Read-Host $pr } }
            # -AcceptB1ResidualRisk: considered by the engine only past the isolation gate; it answers nothing.
            $isoRes = Invoke-AtmIsolate -Entries $isoEntries -PlanPresenter $isoPresenter -ConfirmationReader $isoReader -InventoryArgs $cliInvArgs -LogFile $LogFile `
                -AcceptB1ResidualRisk:$AcceptB1ResidualRisk -Interaction @{ Caller = 'CLI'; ConsoleRequired = [bool]$script:AtmIsolationEnabled }
            Show-AtmIsolateResult -Result $isoRes
            exit $(if ($isoRes.Aborted -or $isoRes.StoppedBy) { 3 } else { 0 })
        }
        'quarantine' {
            # 0.3.x quarantine (contract section 8). list, inspect and verify only read (bytes and times unchanged, manifests
            # included), with the isolation gate open or closed. restore: with the gate closed (every distributed copy) only
            # the plan; past it, an interactive console, a new -LogFile and the phrases bound to the entry. -Entry takes only
            # an entry id, never a path; the destination is never given by the user (T-ISO-8). The retention of the policy
            # (config\quarantine.policy.json) only marks EXPIRED in list and inspect.
            $qSub = $(if ($SubCommand) { $SubCommand.ToLowerInvariant() } else { '' })
            if ($Entry -and $Entry -cnotmatch $script:AtmQuarantineEntryIdPattern) { Write-Host (Get-AtmText 'cli.quarantineEntryInvalid') -ForegroundColor Red; exit 2 }
            $qPolicy = Get-AtmQuarantinePolicy -ConfigDir $invArgs.ConfigDir
            switch ($qSub) {
                'list' { Show-AtmQuarantineList -List (Get-AtmQuarantineList -Policy $qPolicy) -AutoPurgeTask (Get-AtmAutoPurgeTaskState); exit 0 }
                'inspect' {
                    if (-not $Entry) { Write-Host (Get-AtmText 'cli.quarantineUsage') -ForegroundColor Red; exit 2 }
                    $qEntry = Get-AtmQuarantineEntry -Id $Entry -Policy $qPolicy
                    if ($null -eq $qEntry) { Write-Host (Get-AtmText 'cli.quarantineEntryNotFound' $Entry) -ForegroundColor Yellow; exit 3 }
                    Show-AtmQuarantineEntry -Entry $qEntry
                    exit 0
                }
                'verify' {
                    if (-not $Entry -and -not $All) { Write-Host (Get-AtmText 'cli.quarantineUsage') -ForegroundColor Red; exit 2 }
                    $qIds = $(if ($Entry) { @($Entry) } else { @((Get-AtmQuarantineList -Policy $qPolicy).Entries | Where-Object { $_.Id -cmatch $script:AtmQuarantineEntryIdPattern } | ForEach-Object { $_.Id }) })
                    Show-AtmQuarantineVerify -Results @($qIds | ForEach-Object { Test-AtmQuarantineEntry -Id $_ -Policy $qPolicy })
                    exit 0
                }
                'restore' {
                    if (-not $Entry) { Write-Host (Get-AtmText 'cli.quarantineUsage') -ForegroundColor Red; exit 2 }
                    if ($script:AtmIsolationEnabled -and $LogFile) {
                        $rstProbe = Invoke-AtmInventory @cliInvArgs
                        if (-not (Test-AtmOutputPathOutsideBases -Path $LogFile -Inventory $rstProbe)) { Write-Host (Get-AtmText 'cli.logRefused') -ForegroundColor Red; exit 2 }
                    }
                    if ($script:AtmIsolationEnabled -and -not (Test-AtmTuiInteractive)) { Write-Host (Get-AtmText 'cli.restoreNeedsConsole') -ForegroundColor Yellow; exit 6 }
                    $rstPresenter = { param($plan, $i, $planId) Show-AtmRestorePlan -Plan $plan -Inventory $i -PlanId $planId }
                    $rstReader = { param($phrase, $kind, $rootPath, $choices) Read-AtmCleanAnswer -Phrase $phrase -Kind $kind -RootPath $rootPath -Choices $choices -LineReader { param($pr) Read-Host $pr } }
                    $rstRes = Invoke-AtmRestore -Id $Entry -PlanPresenter $rstPresenter -ConfirmationReader $rstReader -InventoryArgs $cliInvArgs -LogFile $LogFile `
                        -Interaction @{ Caller = 'CLI'; ConsoleRequired = [bool]$script:AtmIsolationEnabled }
                    Show-AtmRestoreResult -Result $rstRes
                    exit $(if ($rstRes.Aborted -or $rstRes.StoppedBy) { 3 } else { 0 })
                }
                'purge' {
                    # One entry per run, from here only (J-ISO-1 (C)). With the purge gate closed (every distributed copy)
                    # only the plan: nothing is asked, locked, logged or purged, and no space is freed. Past it (only that
                    # gate: neither the isolation nor the deletion gate is read), an interactive console, a new -LogFile,
                    # the AUT-2 declarations of this purge and the phrase bound to the entry.
                    if (-not $Entry) { Write-Host (Get-AtmText 'cli.quarantineUsage') -ForegroundColor Red; exit 2 }
                    if ($script:AtmQuarantinePurgeEnabled -and $LogFile) {
                        $purProbe = Invoke-AtmInventory @cliInvArgs
                        if (-not (Test-AtmOutputPathOutsideBases -Path $LogFile -Inventory $purProbe)) { Write-Host (Get-AtmText 'cli.logRefused') -ForegroundColor Red; exit 2 }
                    }
                    if ($script:AtmQuarantinePurgeEnabled -and -not (Test-AtmTuiInteractive)) { Write-Host (Get-AtmText 'cli.purgeNeedsConsole') -ForegroundColor Yellow; exit 6 }
                    $purPresenter = { param($plan, $i, $planId, $phrase) Show-AtmPurgePlan -Plan $plan -PlanId $planId -Phrase $phrase }
                    $purReader = { param($phrase, $kind, $rootPath, $choices) Read-AtmCleanAnswer -Phrase $phrase -Kind $kind -RootPath $rootPath -Choices $choices -LineReader { param($pr) Read-Host $pr } }
                    $purRes = Invoke-AtmPurge -Id $Entry -PlanPresenter $purPresenter -ConfirmationReader $purReader -InventoryArgs $cliInvArgs -LogFile $LogFile `
                        -Interaction @{ Caller = 'CLI'; ConsoleRequired = [bool]$script:AtmQuarantinePurgeEnabled }
                    Show-AtmPurgeResult -Result $purRes
                    exit $(if ($purRes.Aborted -or $purRes.StoppedBy) { 3 } else { 0 })
                }
                { $_ -in @('schedule-autopurge', 'unschedule-autopurge') } {
                    # The user's own optional task of the automatic purge (J-ISO-7, complement of 2026-11-03): the only two
                    # commands that change the Task Scheduler. schedule refuses an elevated process, a copy that is not
                    # installed and an existing task; both need the console the engine observes, show the plan and ask
                    # their own phrase. No credential is asked for; the policy (autoPurge = true) stays the authorization.
                    $apPresenter = { param($plan) Show-AtmAutoPurgeTaskPlan -Plan $plan -Operation $(if ($qSub -ceq 'schedule-autopurge') { 'schedule' } else { 'unschedule' }) }
                    $apReader = { param($phrase, $kind) Read-AtmCleanAnswer -Phrase $phrase -Kind $kind -LineReader { param($pr) Read-Host $pr } }
                    if ($qSub -ceq 'schedule-autopurge') { $apRes = Invoke-AtmAutoPurgeSchedule -ConfigDir $invArgs.ConfigDir -Installed:([bool]$integrity.Installed) -PlanPresenter $apPresenter -ConfirmationReader $apReader }
                    else { $apRes = Invoke-AtmAutoPurgeUnschedule -PlanPresenter $apPresenter -ConfirmationReader $apReader }
                    Show-AtmAutoPurgeTaskResult -Result $apRes
                    exit $(if ($apRes.Done) { 0 } elseif ($apRes.Aborted -ceq 'CONSOLE_NOT_OBSERVED') { 6 } else { 3 })
                }
                default { Write-Host (Get-AtmText 'cli.quarantineUsage') -ForegroundColor Red; exit 2 }
            }
        }
        'authorize' {
            # AUT-1: records the operator's discard authorization of ONE root and the plan shown; deletes nothing and makes
            # nothing eligible. Only from an interactive console: piped or scripted input never records an acceptance
            # (which is still not proof that a person answered).
            if (-not $Path -or -not $RecordFile) { Write-Host (Get-AtmText 'cli.authNeeds') -ForegroundColor Red; exit 2 }
            $authConsole = [bool](Test-AtmTuiInteractive)
            if (-not $authConsole) { Write-Host (Get-AtmText 'cli.authNeedsConsole') -ForegroundColor Yellow; exit 6 }
            $authPresenter = { param($pr) Show-AtmDiscardPresentation -Presentation $pr }
            $authReader = {
                param($kind, $phrase)
                Write-Host ''
                # One phrase, or the two accepted for the content decision (each one a format argument of the prompt).
                $fa = @($phrase)
                if ($phrase) { Write-Host (Get-AtmText ('auth.prompt.' + $kind) @fa) -ForegroundColor Yellow } else { Write-Host (Get-AtmText 'auth.prompt.description' $script:AtmDiscardDescriptionMax) }
                Read-Host (Get-AtmText 'cli.confirmPrompt')
            }
            # Reported by the CLI: the caller and its console requirement (the engine observes the console itself and
            # refuses if none is observed; never proof of who answered).
            $authInteraction = @{ Caller = 'CLI'; ConsoleRequired = $true }
            $authRes = Invoke-AtmDiscardAuthorization -Path $Path -InventoryArgs $cliInvArgs -RecordFile $RecordFile -Presenter $authPresenter -Reader $authReader -Interaction $authInteraction
            Show-AtmDiscardResult -Result $authRes
            exit $(if ($authRes.Accepted) { 0 } else { 3 })
        }
        'recover' {
            # V0.4 R1 (docs/adr/ADR-0016): list and plan, from a fresh read-only collection made in this process. The
            # recovery engine is loaded here, by version, and (V0.4 R5) by tui and gui for their read-only area. list and
            # plan never ask, lock, log or write anything and open no service. The operation comes only from the catalog
            # and the service only from the exact name a provider declares: never a path, wildcard, file or plan. One
            # operation and one target per call. Exit 0 list or plan shown, 3 target refused, 2 usage.
            . (Join-Path $here 'lib\Engine.Recover.ps1')
            $recSub = $(if ($SubCommand) { $SubCommand.ToLowerInvariant() } else { '' })
            foreach ($opt in @('User', 'Project', 'Root', 'Path', 'AllowListFile', 'IncludeOtherUsers', 'AcceptB1ResidualRisk', 'ExportJson', 'LogFile', 'RecordFile', 'Entry', 'All', 'PseudonymKeyFile', 'IntervalHours')) {
                if ($PSBoundParameters.ContainsKey($opt)) { Write-Host (Get-AtmText 'cli.recoverOptionRefused' $opt) -ForegroundColor Red; exit 2 }
            }
            if ($recSub -cne 'list' -and $recSub -cne 'plan' -and $recSub -cne 'start' -and $recSub -cne 'undo') { Write-Host (Get-AtmText 'cli.recoverUsage') -ForegroundColor Red; exit 2 }
            if ($recSub -ceq 'list' -and ($PSBoundParameters.ContainsKey('Operation') -or $PSBoundParameters.ContainsKey('Service'))) { Write-Host (Get-AtmText 'cli.recoverUsage') -ForegroundColor Red; exit 2 }
            # The run id and the relaunch marker belong to start and undo only; undo takes no operation or service, start
            # no run id.
            if (($recSub -ceq 'list' -or $recSub -ceq 'plan') -and ($PSBoundParameters.ContainsKey('RunId') -or $PSBoundParameters.ContainsKey('AtmElevatedRecovery'))) { Write-Host (Get-AtmText 'cli.recoverUsage') -ForegroundColor Red; exit 2 }
            if ($recSub -ceq 'undo' -and ($PSBoundParameters.ContainsKey('Operation') -or $PSBoundParameters.ContainsKey('Service'))) { Write-Host (Get-AtmText 'cli.recoverUsage') -ForegroundColor Red; exit 2 }
            if ($recSub -ceq 'start' -and $PSBoundParameters.ContainsKey('RunId')) { Write-Host (Get-AtmText 'cli.recoverUsage') -ForegroundColor Red; exit 2 }
            if ($recSub -ceq 'start' -or $recSub -ceq 'undo') {
                # V0.4 R4 (ADR-0016, R4 implementation record): one operation per process, through the recovery engine
                # (Invoke-AtmRecoverCommand). With the recovery gate closed (every copy): the plan, or the inverse plan, then
                # exit 27, with no elevation requested and nothing asked, locked or logged. Past the gate: an elevated token
                # acts here; any other relaunches this installation's own agent-temp.ps1 once, through UAC, by Windows
                # PowerShell from the system directory (SR-03: no file association), with fixed arguments and no path but
                # that script's, and reports only by that copy's exit code. The exit codes are in docs/USAGE.md.
                if ($recSub -ceq 'start') {
                    if ($null -eq $(if ($Operation) { Get-AtmRecoveryOperation $Operation } else { $null })) { Write-Host (Get-AtmText 'cli.recoverOperationInvalid' (@($script:AtmRecoveryCatalog | ForEach-Object { $_.Id }) -join ', ')) -ForegroundColor Red; exit 2 }
                    if (-not $Service -or $Service.Length -gt 256 -or $Service -cnotmatch '^[A-Za-z0-9_.\- ]+$') { Write-Host (Get-AtmText 'cli.recoverServiceInvalid') -ForegroundColor Red; exit 2 }
                } elseif (-not (Test-AtmRecoverRunIdForm $RunId)) { Write-Host (Get-AtmText 'cli.recoverRunIdInvalid') -ForegroundColor Red; exit 2 }
                $recCmd = @{ Verb = $recSub; Operation = $Operation; Service = $Service; RunId = $RunId; Elevated = [bool]$AtmElevatedRecovery; BoundNames = [string[]]@($PSBoundParameters.Keys)
                    Installed = [bool]$integrity.Installed; LauncherListed = [bool]$integrity.Listed.ContainsKey('agent-temp.ps1'); InstallRoot = $here; InventoryArgs = $invArgs
                    Presenter = { param($kind, $data) Show-AtmRecoverCommandOutput -Kind $kind -Data $data }
                    ConfirmationReader = { param($phrase, $kind, $rootPath, $choices, $info) Read-AtmCleanAnswer -Phrase $phrase -Kind $kind -RootPath $rootPath -Choices $choices -Info $info -LineReader { param($pr) Read-Host $pr } }
                    KeyReader = { Wait-AtmRecoverKey } }
                if ($DeadlineSeconds -ge 0) { $recCmd['DeadlineSeconds'] = $DeadlineSeconds }
                $recOut = Invoke-AtmRecoverCommand @recCmd
                exit ([int]$recOut.ExitCode)
            }
            $recOp = $null
            if ($recSub -ceq 'plan') {
                $recOp = $(if ($Operation) { Get-AtmRecoveryOperation $Operation } else { $null })
                if ($null -eq $recOp) { Write-Host (Get-AtmText 'cli.recoverOperationInvalid' (@($script:AtmRecoveryCatalog | ForEach-Object { $_.Id }) -join ', ')) -ForegroundColor Red; exit 2 }
                # The characters of a service name the diagnose accepts (no separator, wildcard, quote or drive).
                if (-not $Service -or $Service.Length -gt 256 -or $Service -cnotmatch '^[A-Za-z0-9_.\- ]+$') { Write-Host (Get-AtmText 'cli.recoverServiceInvalid') -ForegroundColor Red; exit 2 }
            }
            $recArgs = @{}
            if ($DeadlineSeconds -ge 0) { $recArgs['DeadlineSeconds'] = $DeadlineSeconds }
            # An unexpected failure is reported by its exception type only: its message could carry collected data.
            try { $recColl = Get-AtmRecoverCollection @recArgs }
            catch { Write-Host (Get-AtmText 'cli.recoverFailed' (ConvertTo-AtmExceptionCode $_.Exception.GetBaseException().GetType().Name)) -ForegroundColor Red; exit 10 }
            if ($recSub -ceq 'list') { Show-AtmRecoverList -List (Get-AtmRecoverList -Collection $recColl); exit 0 }
            $recPlan = Get-AtmRecoverPlan -Collection $recColl -Operation $recOp.Id -Service $Service
            if (-not $recPlan.Declared) { Write-Host (Get-AtmText 'cli.recoverNotDeclared') -ForegroundColor Red; exit 2 }
            Show-AtmRecoverPlan -Plan $recPlan
            exit $(if ($recPlan.Offered) { 0 } else { 3 })
        }
        'monitor' {
            # V0.5 M1, M3a, M4a and M4b (docs/adr/ADR-0017): status, enable, disable and remove-history. The monitoring engine is loaded here and
            # by version. status reads the monitoring gate as this copy has it, the history as it is and the collection
            # task's state: it never creates the history folder or the task folder, never collects, takes no lock and
            # writes nothing. enable registers the user's own collection task, through the engine only: with the
            # monitoring gate closed (every distributed copy) the engine refuses before anything is read or asked; past it,
            # a standard token, an installed copy, the console the engine observes, no existing task, the plan and its own
            # phrase. disable removes that task, through the engine only, behind the same gate: past it, the console the
            # engine observes, exactly the product's task, the plan and its own phrase, then the task folder when empty.
            # remove-history (V0.5 M4b) removes the product's history files, through the engine only, behind the same
            # gate: past it, the console the engine observes, no collection task, the folder and its items checked, the
            # plan and its own phrase, then the collector's mutex; the user's thresholds file and the parent folder stay.
            # -IntervalHours belongs to enable only. Exit 0 status shown or task created or removed or history removed,
            # 2 usage, 3 refused or not confirmed, 6 no interactive console.
            . (Join-Path $here 'lib\Engine.Monitor.ps1')
            foreach ($opt in @('User', 'Project', 'Root', 'Path', 'AllowListFile', 'IncludeOtherUsers', 'AcceptB1ResidualRisk', 'ExportJson', 'LogFile', 'RecordFile', 'Entry', 'All', 'PseudonymKeyFile', 'Operation', 'Service', 'RunId', 'AtmElevatedRecovery', 'DeadlineSeconds')) {
                if ($PSBoundParameters.ContainsKey($opt)) { Write-Host (Get-AtmText 'cli.monitorUsage') -ForegroundColor Red; exit 2 }
            }
            $monSub = $(if ($SubCommand) { $SubCommand.ToLowerInvariant() } else { '' })
            if ($monSub -cne 'status' -and $monSub -cne 'enable' -and $monSub -cne 'disable' -and $monSub -cne 'remove-history') { Write-Host (Get-AtmText 'cli.monitorUsage') -ForegroundColor Red; exit 2 }
            if ($monSub -ceq 'status') {
                if ($PSBoundParameters.ContainsKey('IntervalHours')) { Write-Host (Get-AtmText 'cli.monitorUsage') -ForegroundColor Red; exit 2 }
                Show-AtmMonitorStatus -Status (Get-AtmMonitorStatus) -Task (Get-AtmMonitorTaskState)
                exit 0
            }
            if ($monSub -ceq 'disable') {
                if ($PSBoundParameters.ContainsKey('IntervalHours')) { Write-Host (Get-AtmText 'cli.monitorUsage') -ForegroundColor Red; exit 2 }
                $monDisPresenter = { param($plan) Show-AtmMonitorDisablePlan -Plan $plan }
                $monDisReader = { param($phrase, $kind) Read-AtmCleanAnswer -Phrase $phrase -Kind $kind -LineReader { param($pr) Read-Host $pr } }
                $monDisRes = Invoke-AtmMonitorDisable -PlanPresenter $monDisPresenter -ConfirmationReader $monDisReader
                Show-AtmMonitorDisableResult -Result $monDisRes
                exit $(if ($monDisRes.Done) { 0 } elseif ($monDisRes.Aborted -ceq 'CONSOLE_NOT_OBSERVED') { 6 } else { 3 })
            }
            if ($monSub -ceq 'remove-history') {
                if ($PSBoundParameters.ContainsKey('IntervalHours')) { Write-Host (Get-AtmText 'cli.monitorUsage') -ForegroundColor Red; exit 2 }
                $monRhPresenter = { param($plan) Show-AtmMonitorRemoveHistoryPlan -Plan $plan }
                $monRhReader = { param($phrase, $kind) Read-AtmCleanAnswer -Phrase $phrase -Kind $kind -LineReader { param($pr) Read-Host $pr } }
                $monRhRes = Invoke-AtmMonitorRemoveHistory -PlanPresenter $monRhPresenter -ConfirmationReader $monRhReader
                Show-AtmMonitorRemoveHistoryResult -Result $monRhRes
                exit $(if ($monRhRes.Done) { 0 } elseif ($monRhRes.Aborted -ceq 'CONSOLE_NOT_OBSERVED') { 6 } else { 3 })
            }
            $monInterval = $script:AtmMonitorTaskDefaultInterval
            if ($PSBoundParameters.ContainsKey('IntervalHours')) {
                if ($IntervalHours -cnotmatch '^[0-9]{1,2}$' -or @($script:AtmMonitorTaskIntervals) -notcontains [int]$IntervalHours) { Write-Host (Get-AtmText 'cli.monitorIntervalInvalid' (@($script:AtmMonitorTaskIntervals) -join ', ')) -ForegroundColor Red; exit 2 }
                $monInterval = [int]$IntervalHours
            }
            $monPresenter = { param($plan) Show-AtmMonitorEnablePlan -Plan $plan }
            $monReader = { param($phrase, $kind) Read-AtmCleanAnswer -Phrase $phrase -Kind $kind -LineReader { param($pr) Read-Host $pr } }
            $monRes = Invoke-AtmMonitorEnable -IntervalHours $monInterval -Installed:([bool]$integrity.Installed) -PlanPresenter $monPresenter -ConfirmationReader $monReader
            Show-AtmMonitorEnableResult -Result $monRes
            exit $(if ($monRes.Done) { 0 } elseif ($monRes.Aborted -ceq 'CONSOLE_NOT_OBSERVED') { 6 } else { 3 })
        }
        'version' {
            Initialize-AtmNative -LibDir (Join-Path $here 'lib')
            Write-Host "agent-temp $script:AtmVersion"
            Write-Host ("providers: {0}" -f ((Get-AtmProviders | ForEach-Object { $_.DisplayName }) -join ', '))
            Write-Host (Get-AtmText 'cli.native' (Get-AtmText "native.$script:AtmNativeMode"))
            Write-Host (Get-AtmText 'cli.realDeletion' $(if ($script:AtmRealDeletionEnabled) { Get-AtmText 'cli.enabled' } else { Get-AtmText 'cli.disabledV01' }))
            Write-Host (Get-AtmText 'cli.isolation' $(if ($script:AtmIsolationEnabled) { Get-AtmText 'cli.enabled' } else { Get-AtmText 'cli.isolationDisabled' }))
            Write-Host (Get-AtmText 'cli.purge' $(if ($script:AtmQuarantinePurgeEnabled) { Get-AtmText 'cli.enabled' } else { Get-AtmText 'cli.purgeDisabled' }))
            Write-Host (Get-AtmText 'cli.gui' $(if ($script:AtmGuiEnabled) { Get-AtmText 'cli.enabled' } else { Get-AtmText 'cli.guiDisabled' }))
            # V0.4 (ADR-0016 section 5): the eighth release gate, read from the recovery engine (loaded by version and recover).
            . (Join-Path $here 'lib\Engine.Recover.ps1')
            Write-Host (Get-AtmText 'cli.recovery' $(if ($script:AtmRecoveryEnabled) { Get-AtmText 'cli.enabled' } else { Get-AtmText 'cli.recoveryDisabled' }))
            # V0.5 (ADR-0017 section 5): the ninth release gate, read from the monitoring engine (loaded by version and monitor).
            . (Join-Path $here 'lib\Engine.Monitor.ps1')
            Write-Host (Get-AtmText 'cli.monitoring' $(if ($script:AtmMonitoringEnabled) { Get-AtmText 'cli.enabled' } else { Get-AtmText 'cli.monitoringDisabled' }))
            # The effective quarantine policy (contract section 11.2), with its warnings (an invalid file counts as off).
            foreach ($pl in (Get-AtmQuarantinePolicyLines -Policy (Get-AtmQuarantinePolicy -ConfigDir $invArgs.ConfigDir))) { Write-Host $pl.Text -ForegroundColor $pl.Color }
            # The user's scheduled task of the automatic purge, read only (P6b).
            foreach ($tl in (Get-AtmAutoPurgeTaskLines -Task (Get-AtmAutoPurgeTaskState))) { Write-Host $tl.Text -ForegroundColor $tl.Color }
            # The user's collection task of preventive monitoring, read only (V0.5 M3a; a leftover stays visible).
            foreach ($tl in (Get-AtmMonitorTaskLines -Task (Get-AtmMonitorTaskState))) { Write-Host $tl.Text -ForegroundColor $tl.Color }
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
