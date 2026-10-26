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
    [string]$Lang
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
# Cosmetic only: a redirected or legacy console keeps its encoding.
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { $null = $_ }

$here = $PSScriptRoot
# Installed copies carry manifest.json: before loading ANY code, every listed file must match its SHA-256 and no
# unlisted provider may exist (fail closed). Source checkouts (no manifest) load as-is. This message is printed in
# both languages because no code (not even the message catalog) is loaded before the check passes.
$manifestPath = Join-Path $here 'manifest.json'
$providerFiles = @(Get-ChildItem -LiteralPath (Join-Path $here 'providers') -Filter '*.ps1' -File | Sort-Object Name)
if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
    $atmManifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $listed = @{}
    foreach ($mfEntry in $atmManifest.files) { $listed[$mfEntry.path.ToLowerInvariant()] = $mfEntry.sha256 }
    $integrityProblems = @()
    if ($Command -ne 'verify') {
        foreach ($k in $listed.Keys) {
            $fp = Join-Path $here $k
            if (-not (Test-Path -LiteralPath $fp -PathType Leaf)) { $integrityProblems += "missing/ausente: $k"; continue }
            if ((Get-FileHash -LiteralPath $fp -Algorithm SHA256).Hash -ne $listed[$k]) { $integrityProblems += "modified/alterado: $k" }
        }
        foreach ($pf in $providerFiles) { if (-not $listed.ContainsKey(('providers\' + $pf.Name).ToLowerInvariant())) { $integrityProblems += "provider not in manifest / provider fora do manifesto: $($pf.Name)" } }
        if ($integrityProblems.Count -gt 0) {
            Write-Host ('Installation integrity violated; nothing was loaded or run. / Integridade da instalacao violada; nada foi carregado nem executado: ' + ($integrityProblems -join '; ')) -ForegroundColor Red
            Write-Host 'Run "agent-temp verify" and reinstall from a verified release. / Execute "agent-temp verify" e reinstale a partir de um release verificado.' -ForegroundColor Yellow
            exit 5
        }
    }
    $providerFiles = @($providerFiles | Where-Object { $listed.ContainsKey(('providers\' + $_.Name).ToLowerInvariant()) })
}
. (Join-Path $here 'lib\Engine.Audit.ps1')     # also loads lib\I18n.ps1
Set-AtmLanguage -Requested $Lang
foreach ($providerFile in $providerFiles) { . $providerFile.FullName }
. (Join-Path $here 'lib\Engine.Clean.ps1')
. (Join-Path $here 'lib\Report.ps1')
. (Join-Path $here 'lib\Tui.ps1')

# Markers used to exclude this invocation's own launcher chain from process-reference evidence.
$selfMarkers = @((Join-Path $here 'agent-temp.ps1'), (Join-Path $here 'bin\agent-temp.cmd'))
$invArgs = @{ SelfMarkers = $selfMarkers; ConfigDir = (Join-Path $here 'config') }
$cliInvArgs = @{} + $invArgs
$cliInvArgs['NoProgress'] = [bool]$NoProgress
$cliInvArgs['ProgressCallback'] = { param($pct, $msg) $act = Get-AtmText 'cli.progressActivity'; if ($pct -ge 100) { Write-Progress -Activity $act -Completed } else { Write-Progress -Activity $act -Status $msg -PercentComplete $pct } }

function Show-Help {
    foreach ($k in @('help.title', 'help.blank', 'help.tui', 'help.audit', 'help.preview', 'help.clean', 'help.clean2', 'help.verify', 'help.version', 'help.help', 'help.blank',
            'help.drill', 'help.export', 'help.cleanOpts', 'help.cleanOpts2', 'help.cleanOpts3', 'help.tuiOpts', 'help.lang', 'help.blank', 'help.examples')) { Write-Host (Get-AtmText $k) }
    Write-Host '  agent-temp'
    Write-Host '  agent-temp audit'
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
                # V0.1.1 (F-02): the same rules, checked again with the folder and its ancestors pinned; the file is created
                # relative to the pinned folder (new file only, no reparse point, protected DACL), never by name.
                $exported = New-AtmPinnedTextFile -Path $ExportJson -Text (ConvertTo-AtmExportJson -Inventory $inv) -Policy { param($P) if (Test-AtmOutputPathOutsideBases -Path $P -Inventory $inv -MustNotExist) { $null } else { 'EXPORT_DESTINATION_NOT_ALLOWED' } }
                if ($null -ne $exported) { Write-Host (Get-AtmText $(if ($exported -like 'EXPORT_CREATE_CREATED_*') { 'cli.exportRefusedAfterCreate' } else { 'cli.exportRefusedCode' }) $exported) -ForegroundColor Red; throw (Get-AtmText 'cli.exportRefused') }
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
        'verify' {
            $manifest = Join-Path $here 'manifest.json'
            if (-not (Test-Path -LiteralPath $manifest)) { Write-Host (Get-AtmText 'cli.noManifest') -ForegroundColor Yellow; exit 4 }
            $m = Get-Content -LiteralPath $manifest -Raw -Encoding UTF8 | ConvertFrom-Json
            $bad = 0
            foreach ($f in $m.files) {
                $fp = Join-Path $here $f.path
                $h = $(if (Test-Path -LiteralPath $fp) { (Get-FileHash -LiteralPath $fp -Algorithm SHA256).Hash } else { 'MISSING' })
                $ok = $h -eq $f.sha256
                if (-not $ok) { $bad++ }
                Write-Host ("  {0,-4} {1}" -f $(if ($ok) { 'OK' } else { 'FAIL' }), $f.path) -ForegroundColor $(if ($ok) { 'Green' } else { 'Red' })
            }
            Write-Host (Get-AtmText 'cli.verifySummary' $m.version $bad)
            exit $(if ($bad -eq 0) { 0 } else { 5 })
        }
        'version' {
            Initialize-AtmNative -LibDir (Join-Path $here 'lib')
            Write-Host "agent-temp $script:AtmVersion"
            Write-Host ("providers: {0}" -f ((Get-AtmProviders | ForEach-Object { $_.DisplayName }) -join ', '))
            Write-Host (Get-AtmText 'cli.native' (Get-AtmText "native.$script:AtmNativeMode"))
            Write-Host (Get-AtmText 'cli.realDeletion' $(if ($script:AtmRealDeletionEnabled) { Get-AtmText 'cli.enabled' } else { Get-AtmText 'cli.disabledV01' }))
            Write-Host (Get-AtmText 'cli.language' (Get-AtmLanguage))
            exit 0
        }
        default { Show-Help; exit $(if ($Command -in @('help', '-h', '--help', '/?')) { 0 } else { 1 }) }
    }
} catch {
    Write-Host ((Get-AtmText 'cli.error') + ' ' + $_.Exception.Message) -ForegroundColor Red
    Write-Host (Get-AtmText 'cli.errorNoDeletion') -ForegroundColor Yellow
    exit 10
}
