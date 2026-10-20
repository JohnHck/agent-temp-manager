<#
.SYNOPSIS
  Static analysis of every PowerShell script of the repository with a pinned, verified PSScriptAnalyzer.
.DESCRIPTION
  1. Downloads PSScriptAnalyzer $Version from the PowerShell Gallery into -WorkDir (never into a module path,
     nothing is installed) and verifies the package SHA-512 published by the Gallery.
  2. Verifies the Authenticode signature of every code file of the module against an allow-list of signers.
  3. Imports the module by path and analyses src/, install/, tools/ and tests/ (*.ps1, *.psm1, *.psd1) with
     tools/PSScriptAnalyzerSettings.psd1.
  4. Prints a summary, writes a JSON report and, under GitHub Actions, a job summary.
  Exit codes: 0 = analysis done (Informative mode: always, whatever the findings), 1 = findings in Enforce mode,
  3 = integrity or tool failure (never ignored).
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
$AllowedSigners = @('Microsoft Corporation', 'Microsoft 3rd Party Application Component', 'Json.NET (.NET Foundation)')
$ScanDirs = @('src', 'install', 'tools', 'tests')

$repo = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$settings = Join-Path $repo 'tools\PSScriptAnalyzerSettings.psd1'

function Get-Sha512Base64([string]$Path) {
    $alg = [Security.Cryptography.SHA512]::Create()
    $fs = [IO.File]::OpenRead($Path)
    try { return [Convert]::ToBase64String($alg.ComputeHash($fs)) } finally { $fs.Dispose(); $alg.Dispose() }
}

try {
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

    # 2. Every code file signed by an allowed signer.
    $code = @(Get-ChildItem -LiteralPath $moduleDir -Recurse -File | Where-Object { $_.Extension -in @('.dll', '.psd1', '.psm1', '.ps1', '.ps1xml') })
    if ($code.Count -eq 0) { throw 'pacote sem arquivos de codigo' }
    foreach ($f in $code) {
        $s = Get-AuthenticodeSignature -LiteralPath $f.FullName
        $signer = $(if ($s.SignerCertificate) { $s.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) } else { '' })
        if ($s.Status -ne 'Valid' -or $AllowedSigners -notcontains $signer) { throw "assinatura invalida ou nao permitida: $($f.Name) ($($s.Status), '$signer')" }
    }
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
            $findings.Add([pscustomobject]@{ File = $rel; Line = $r.Line; Rule = $r.RuleName; Severity = [string]$r.Severity; Message = $r.Message })
        }
    }

    # 4. Report.
    Write-Host ''
    Write-Host ("Arquivos analisados: {0} | achados: {1}" -f $files.Count, $findings.Count)
    $byRule = @($findings | Group-Object Rule | Sort-Object Count -Descending)
    foreach ($g in $byRule) { Write-Host ("  {0,5}  {1,-12} {2}" -f $g.Count, @($g.Group)[0].Severity, $g.Name) }
    Write-Host ''
    foreach ($x in ($findings | Sort-Object File, Line)) {
        $m = $x.Message -replace '\s+', ' '; if ($m.Length -gt 160) { $m = $m.Substring(0, 157) + '...' }
        Write-Host ("{0}:{1} [{2}] {3}: {4}" -f $x.File, $x.Line, $x.Severity, $x.Rule, $m)
    }
    if ($ReportFile) {
        $rep = [ordered]@{ tool = 'PSScriptAnalyzer'; version = $Version; packageSha512 = $PackageSha512; mode = $Mode; files = @($files | ForEach-Object { $_.Substring($repo.Length + 1).Replace('\', '/') }); findings = $findings }
        [IO.File]::WriteAllText($ReportFile, ($rep | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding($false)))
    }
    if ($env:GITHUB_STEP_SUMMARY) {
        $md = New-Object System.Text.StringBuilder
        [void]$md.AppendLine("### PSScriptAnalyzer $Version ($Mode)").AppendLine()
        [void]$md.AppendLine("Files analysed: $($files.Count) - findings: $($findings.Count)").AppendLine()
        [void]$md.AppendLine('| Count | Severity | Rule |').AppendLine('|---:|---|---|')
        foreach ($g in $byRule) { [void]$md.AppendLine("| $($g.Count) | $(@($g.Group)[0].Severity) | $($g.Name) |") }
        [IO.File]::AppendAllText($env:GITHUB_STEP_SUMMARY, $md.ToString())
    }
    if ($Mode -eq 'Enforce' -and $findings.Count -gt 0) { exit 1 }
    exit 0
} catch {
    Write-Host "ERRO: $($_.Exception.Message)" -ForegroundColor Red
    exit 3
}
