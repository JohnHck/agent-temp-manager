<#
.SYNOPSIS
  Prepares CI artifacts for upload (FINAL-B): replaces this machine's identifiers in their text files with placeholders
  (AtmArtifactSanitizer.ps1), then runs the privacy scanner (Test-AtmPrivacy.ps1) on them. Fails closed.
.OUTPUTS
  Exit 0: the scan ran and found nothing. Exit 1: findings, listed by file, line and kind only (never the value).
  Exit 2: the scan cannot be trusted (scanner missing or failing, an unexpected scanner warning, an unreadable file).
  Archives (.zip) are scanned as they are and never modified (their hashes are published); -NoSanitize scans only.
  A path that does not exist is reported and skipped (there is nothing to upload from it).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$Path,
    [string]$Scanner = '',
    [switch]$NoSanitize
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
# Resolved here: $PSScriptRoot is empty in a parameter default under Windows PowerShell 5.1.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Scanner) { $Scanner = Join-Path $here 'Test-AtmPrivacy.ps1' }
$textExt = @('.json', '.txt', '.log', '.md', '.xml', '.csv', '.html', '.ps1', '.psd1', '.psm1', '.cmd', '.yml', '.wsb')
$lines = New-Object System.Collections.Generic.List[string]
$stage = $null
$code = 0
try {
    if (-not (Test-Path -LiteralPath $Scanner -PathType Leaf)) { throw 'SCANNER_MISSING' }
    . (Join-Path $here 'AtmArtifactSanitizer.ps1')
    $ids = Get-AtmArtifactIdentifiers
    $stage = Join-Path ([IO.Path]::GetTempPath()) ('atm-artifact-scan-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    [void][IO.Directory]::CreateDirectory($stage)
    $zips = New-Object System.Collections.Generic.List[string]
    $sanitized = 0; $staged = 0
    foreach ($p in $Path) {
        if (-not (Test-Path -LiteralPath $p)) { $lines.Add("not present (nothing to upload): $(Split-Path -Leaf $p)"); continue }
        $item = Get-Item -LiteralPath $p -Force
        $root = $(if ($item.PSIsContainer) { $item.FullName } else { Split-Path -Parent $item.FullName })
        $files = $(if ($item.PSIsContainer) { @(Get-ChildItem -LiteralPath $item.FullName -File -Recurse -Force) } else { @($item) })
        foreach ($f in $files) {
            if (($f.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'ARTIFACT_REPARSE_POINT' }
            $ext = $f.Extension.ToLowerInvariant()
            if ($ext -eq '.zip') { $zips.Add($f.FullName); continue }
            if ($textExt -contains $ext -and -not $NoSanitize) {
                $old = [IO.File]::ReadAllText($f.FullName)
                $new = ConvertTo-AtmArtifactSafeText -Text $old -Identifiers $ids
                if ($new -cne $old) { [IO.File]::WriteAllText($f.FullName, $new, (New-Object Text.UTF8Encoding($false))); $sanitized++ }
            }
            # Staged copy for the scanner: the relative name inside the artifact, never the runner's path.
            $rel = $f.FullName.Substring($root.Length).TrimStart('\')
            $dst = Join-Path $stage $rel
            [void][IO.Directory]::CreateDirectory((Split-Path -Parent $dst))
            [IO.File]::Copy($f.FullName, $dst)
            $staged++
        }
    }
    $hits = New-Object System.Collections.Generic.List[object]
    $warns = New-Object System.Collections.Generic.List[string]
    $targets = @()
    if ($staged -gt 0) { $targets += $stage }
    $targets += @($zips)
    foreach ($t in $targets) {
        $w = $null
        foreach ($h in @(& $Scanner -Path $t -WarningVariable w -WarningAction SilentlyContinue)) { $hits.Add($h) }
        foreach ($x in @($w)) { $warns.Add([string]$x) }
    }
    foreach ($x in @($warns | Sort-Object -Unique)) {
        # The product-word warning (a machine name equal to a word of the product) is expected and only reported.
        if ($x -match "equals the product word '[a-z]+': not searched") { $lines.Add("scanner note: $x") }
        else { $lines.Add('scanner warning (scan not trusted)'); $code = 2 }
    }
    foreach ($h in $hits) { $lines.Add(('FINDING {0}:{1} {2}' -f $h.File, $h.Line, $h.Kind)) }
    if ($hits.Count -gt 0 -and $code -eq 0) { $code = 1 }
    $lines.Insert(0, ('artifact privacy: {0} file(s) scanned, {1} archive(s), {2} sanitized, {3} finding(s)' -f $staged, $zips.Count, $sanitized, $hits.Count))
} catch {
    # Exception type or code only: a message could carry a path.
    $why = $(if ($_.Exception.Message -match '^[A-Z_]+$') { $_.Exception.Message } else { $_.Exception.GetType().Name })
    $lines.Add("artifact privacy: scan not trusted ($why)")
    $code = 2
} finally {
    if ($stage -and (Test-Path -LiteralPath $stage)) { try { [IO.Directory]::Delete($stage, $true) } catch { $null = $_ } }
}
foreach ($l in $lines) { Write-Host $l }
if ($env:GITHUB_STEP_SUMMARY) { try { [IO.File]::AppendAllText($env:GITHUB_STEP_SUMMARY, (($lines | ForEach-Object { "* $_" }) -join "`n") + "`n") } catch { $null = $_ } }
exit $code
