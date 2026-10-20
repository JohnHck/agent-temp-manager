<#
.SYNOPSIS
  Static analysis of every PowerShell script of the repository with a pinned, verified PSScriptAnalyzer.
.DESCRIPTION
  1. Downloads PSScriptAnalyzer $Version from the PowerShell Gallery into -WorkDir (never into a module path,
     nothing is installed) and verifies the package SHA-512 published by the Gallery.
  2. Verifies the Authenticode signature of every code file of the module against an allow-list of signers, plus
     the reviewed, per-file exceptions of tools/StaticAnalysisSignature.ps1 (exact path and SHA-256).
  3. Imports the module by path and analyses src/, install/, tools/ and tests/ (*.ps1, *.psm1, *.psd1) with
     tools/PSScriptAnalyzerSettings.psd1.
  4. Applies the reviewed exceptions of tools/static-analysis-exceptions.psd1 (one rule, listed files, optional
     message pattern, mandatory justification). Excepted findings stay counted and listed; unused entries are
     reported as stale.
  5. Prints a summary, writes a JSON report and, under GitHub Actions, a job summary.
  Exit codes: 0 = analysis done (Informative mode: always, whatever the findings), 1 = Enforce mode and at least
  one non-excepted finding in an enforced rule (security, compatibility, rules brought to zero), 3 = integrity,
  configuration or tool failure (never ignored).
.EXAMPLE
  ./tools/Invoke-AtmStaticAnalysis.ps1 -ReportFile static-analysis.json
#>
[CmdletBinding()]
param(
    [string]$WorkDir = (Join-Path ([IO.Path]::GetTempPath()) 'atm-static-analysis'),
    [string]$ReportFile,
    [ValidateSet('Informative', 'Enforce')][string]$Mode = 'Informative'
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$Version = '1.25.0'
$PackageUrl = "https://www.powershellgallery.com/api/v2/package/PSScriptAnalyzer/$Version"
# SHA-512 (base64) published by the PowerShell Gallery for PSScriptAnalyzer 1.25.0.
$PackageSha512 = '5/tXMmLmBLqymRSuYpIdJLl8L4i1GbQSd7QD72zhY/FLfRs23HNEmmjlrlqNlQKJGxDCZBMf0YE63ym/ExwWYw=='
$ScanDirs = @('src', 'install', 'tools', 'tests')

$repo = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$settings = Join-Path $repo 'tools\PSScriptAnalyzerSettings.psd1'
$exceptionsFile = Join-Path $repo 'tools\static-analysis-exceptions.psd1'
. (Join-Path $repo 'tools\StaticAnalysisSignature.ps1')

function Get-Sha512Base64([string]$Path) {
    $alg = [Security.Cryptography.SHA512]::Create()
    $fs = [IO.File]::OpenRead($Path)
    try { return [Convert]::ToBase64String($alg.ComputeHash($fs)) } finally { $fs.Dispose(); $alg.Dispose() }
}

try {
    # 0. Reviewed exceptions: validated before anything else, a malformed entry is a configuration error.
    $cfg = Import-PowerShellDataFile -LiteralPath $exceptionsFile
    foreach ($k in @($cfg.Keys)) { if ($k -notin @('Exceptions', 'EnforcedRules')) { throw "chave desconhecida em static-analysis-exceptions.psd1: $k" } }
    $exceptions = @($cfg.Exceptions)
    $enforced = @($cfg.EnforcedRules)
    if ($enforced.Count -eq 0) { throw 'EnforcedRules vazio' }
    foreach ($e in $exceptions) {
        foreach ($k in @($e.Keys)) { if ($k -notin @('Rule', 'Files', 'Match', 'Justification')) { throw "chave desconhecida em uma excecao: $k" } }
        if (-not $e.Rule -or @($e.Files).Count -eq 0 -or -not ([string]$e.Justification).Trim()) { throw "excecao incompleta (Rule, Files e Justification sao obrigatorios): $($e.Rule)" }
        if ($enforced -contains $e.Rule -and -not $e['Match']) { throw "excecao de regra imposta sem Match restrito: $($e.Rule)" }
    }

    # 1. Pinned package, verified before anything is extracted.
    [void][IO.Directory]::CreateDirectory($WorkDir)
    $pkg = Join-Path $WorkDir "PSScriptAnalyzer.$Version.nupkg"
    if (-not (Test-Path -LiteralPath $pkg) -or (Get-Sha512Base64 $pkg) -cne $PackageSha512) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -UseBasicParsing -Uri $PackageUrl -OutFile $pkg -TimeoutSec 300
    }
    $actual = Get-Sha512Base64 $pkg
    if ($actual -cne $PackageSha512) { throw "SHA-512 do pacote difere do publicado (obtido $($actual.Substring(0, 16))...)" }
    Write-Host "PSScriptAnalyzer $Version : SHA-512 do pacote verificado"

    $moduleDir = Join-Path $WorkDir "PSScriptAnalyzer-$Version"
    if (Test-Path -LiteralPath $moduleDir) { Remove-Item -LiteralPath $moduleDir -Recurse -Force }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory($pkg, $moduleDir)

    $code = @(Get-ChildItem -LiteralPath $moduleDir -Recurse -File | Where-Object { $_.Extension -in @('.dll', '.psd1', '.psm1', '.ps1', '.ps1xml') })
    if ($code.Count -eq 0) { throw 'pacote sem arquivos de codigo' }
    # 2. Every code file signed by an allowed signer, or matching a reviewed per-file exception.
    $badSignatures = New-Object System.Collections.Generic.List[string]
    $signatureExceptionsUsed = New-Object System.Collections.Generic.List[object]
    foreach ($f in $code) {
        $facts = Get-AtmAnalyzerSignatureInfo -Path $f.FullName -RelativePath $f.FullName.Substring($moduleDir.Length + 1)
        $verdict = Test-AtmAnalyzerSignature -Facts $facts
        $line = "{0} | sha256 {1} | status {2} | type {3} | signer '{4}' | embedded '{5}'" -f $facts.RelativePath, $facts.Sha256, $facts.Status, $facts.SignatureType, $facts.Signer, $facts.EmbeddedSigner
        if (-not $verdict.Accepted) { $badSignatures.Add("$line | $($verdict.Reason)"); continue }
        if ($verdict.Exception) {
            Write-Host "EXCECAO DE ASSINATURA REVISADA aplicada: $line" -ForegroundColor Yellow
            $signatureExceptionsUsed.Add([ordered]@{ path = $facts.RelativePath; sha256 = $facts.Sha256; signatureType = $facts.SignatureType; signer = $facts.Signer; embeddedSigner = $facts.EmbeddedSigner })
        }
    }
    if ($badSignatures.Count -gt 0) {
        Write-Host "PowerShell $($PSVersionTable.PSVersion) | arquivos rejeitados: $($badSignatures.Count)"
        foreach ($b in $badSignatures) { Write-Host "  $b" }
        throw "assinatura invalida ou nao permitida: $($badSignatures.Count) arquivo(s)"
    }
    # On images where Windows has no catalog for these files the exceptions are simply not needed (not stale).
    if ($signatureExceptionsUsed.Count -eq 0) { Write-Host 'Excecoes de assinatura revisadas: nenhuma necessaria nesta maquina' }
    Write-Host "Assinaturas Authenticode verificadas: $($code.Count) arquivos"

    # 3. Import by path (no module path changes) and analyse.
    Import-Module (Join-Path $moduleDir 'PSScriptAnalyzer.psd1') -Force
    $loaded = Get-Module PSScriptAnalyzer
    if (-not $loaded -or $loaded.Version.ToString() -ne $Version) { throw 'versao carregada difere da fixada' }

    $files = New-Object System.Collections.Generic.List[string]
    foreach ($d in $ScanDirs) {
        $p = Join-Path $repo $d
        if (Test-Path -LiteralPath $p) { foreach ($f in @(Get-ChildItem -LiteralPath $p -Recurse -File | Where-Object { $_.Extension -in @('.ps1', '.psm1', '.psd1') })) { $files.Add($f.FullName) } }
    }
    $findings = New-Object System.Collections.Generic.List[object]
    foreach ($f in $files) {
        $rel = $f.Substring($repo.Length + 1).Replace('\', '/')
        foreach ($r in @(Invoke-ScriptAnalyzer -Path $f -Settings $settings)) {
            $findings.Add([pscustomobject]@{ File = $rel; Line = $r.Line; Rule = $r.RuleName; Severity = [string]$r.Severity; Message = $r.Message; Exception = $null })
        }
    }

    # Exceptions: first matching entry wins; record which one.
    $used = New-Object 'System.Collections.Generic.HashSet[int]'
    foreach ($x in $findings) {
        for ($i = 0; $i -lt $exceptions.Count; $i++) {
            $e = $exceptions[$i]
            if ($x.Rule -ne $e.Rule -or @($e.Files) -notcontains $x.File) { continue }
            if ($e['Match'] -and $x.Message -notmatch $e['Match']) { continue }
            $x.Exception = $i; [void]$used.Add($i); break
        }
    }
    $active = @($findings | Where-Object { $null -eq $_.Exception })
    $excepted = @($findings | Where-Object { $null -ne $_.Exception })
    $enforcedActive = @($active | Where-Object { $enforced -contains $_.Rule })
    $stale = @(for ($i = 0; $i -lt $exceptions.Count; $i++) { if (-not $used.Contains($i)) { $exceptions[$i] } })

    # 5. Report.
    Write-Host ''
    Write-Host ("Arquivos analisados: {0} | achados: {1} | ativos: {2} | excecoes revisadas: {3} | regras impostas com achados: {4}" -f $files.Count, $findings.Count, $active.Count, $excepted.Count, $enforcedActive.Count)
    $byRule = @($active | Group-Object Rule | Sort-Object Count -Descending)
    Write-Host 'Ativos por regra:'
    foreach ($g in $byRule) { Write-Host ("  {0,5}  {1,-12} {2}{3}" -f $g.Count, @($g.Group)[0].Severity, $g.Name, $(if ($enforced -contains $g.Name) { '  [IMPOSTA]' } else { '' })) }
    Write-Host 'Excecoes revisadas aplicadas:'
    foreach ($g in @($excepted | Group-Object Exception | Sort-Object { [int]$_.Name })) { $e = $exceptions[[int]$g.Name]; Write-Host ("  {0,5}  {1} em {2}" -f $g.Count, $e.Rule, (@($e.Files) -join ', ')) }
    foreach ($e in $stale) { Write-Host ("AVISO: excecao sem efeito (obsoleta): {0} em {1}" -f $e.Rule, (@($e.Files) -join ', ')) -ForegroundColor Yellow }
    Write-Host ''
    foreach ($x in ($active | Sort-Object File, Line)) {
        $m = $x.Message -replace '\s+', ' '; if ($m.Length -gt 160) { $m = $m.Substring(0, 157) + '...' }
        Write-Host ("{0}:{1} [{2}] {3}: {4}" -f $x.File, $x.Line, $x.Severity, $x.Rule, $m)
    }
    if ($ReportFile) {
        $rep = [ordered]@{
            tool = 'PSScriptAnalyzer'; version = $Version; packageSha512 = $PackageSha512; mode = $Mode
            files = @($files | ForEach-Object { $_.Substring($repo.Length + 1).Replace('\', '/') })
            enforcedRules = $enforced; enforcedActive = $enforcedActive.Count
            exceptions = @($exceptions | ForEach-Object { [ordered]@{ rule = $_.Rule; files = @($_.Files); match = $_['Match']; justification = $_.Justification } })
            staleExceptions = $stale.Count
            signatureExceptionsUsed = $signatureExceptionsUsed
            findings = $findings
        }
        [IO.File]::WriteAllText($ReportFile, ($rep | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($false)))
    }
    if ($env:GITHUB_STEP_SUMMARY) {
        $md = New-Object System.Text.StringBuilder
        [void]$md.AppendLine("### PSScriptAnalyzer $Version ($Mode)").AppendLine()
        [void]$md.AppendLine("Files analysed: $($files.Count) - findings: $($findings.Count) - active: $($active.Count) - reviewed exceptions: $($excepted.Count) - enforced rules with findings: $($enforcedActive.Count)").AppendLine()
        [void]$md.AppendLine('| Count | Severity | Rule | Enforced |').AppendLine('|---:|---|---|---|')
        foreach ($g in $byRule) { [void]$md.AppendLine("| $($g.Count) | $(@($g.Group)[0].Severity) | $($g.Name) | $(if ($enforced -contains $g.Name) { 'yes' } else { '' }) |") }
        [IO.File]::AppendAllText($env:GITHUB_STEP_SUMMARY, $md.ToString())
    }
    if ($stale.Count -gt 0 -and $Mode -eq 'Enforce') { Write-Host 'ERRO: excecoes obsoletas devem ser removidas.' -ForegroundColor Red; exit 3 }
    if ($Mode -eq 'Enforce' -and $enforcedActive.Count -gt 0) { exit 1 }
    exit 0
} catch {
    Write-Host "ERRO: $($_.Exception.Message)" -ForegroundColor Red
    exit 3
}
