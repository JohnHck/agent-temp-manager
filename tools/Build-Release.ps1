<#
.SYNOPSIS
  Builds a release archive: dist\agent-temp-manager-<version>.zip + SHA256SUMS.txt.
  Runs the test suite first unless -SkipTests (not recommended). Does not publish anything.
#>
[CmdletBinding()]
param([switch]$SkipTests)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
. (Join-Path $repo 'install\InstallCommon.ps1')
$version = Get-AtmSourceVersion -SourceDir (Join-Path $repo 'src')
if (-not $SkipTests) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo 'tests\Run-Tests.ps1') -SkipHeavy
    if ($LASTEXITCODE -ne 0) { throw 'Testes falharam; release nao gerada.' }
}
$dist = Join-Path $repo 'dist'
$name = "agent-temp-manager-$version"
$stage = Join-Path $dist $name
# Never leave an older artifact next to the new one: dist\ is rebuilt from scratch.
if (Test-Path -LiteralPath $dist) { [IO.Directory]::Delete($dist, $true) }
[void][IO.Directory]::CreateDirectory($stage)
foreach ($rel in @('src', 'install', 'docs', 'tests', 'tools')) { Copy-AtmTree -From (Join-Path $repo $rel) -To (Join-Path $stage $rel) }
foreach ($f in @('README.md', 'LICENSE', 'CHANGELOG.md', 'SECURITY.md', 'CONTRIBUTING.md')) { Copy-Item -LiteralPath (Join-Path $repo $f) -Destination $stage }
Write-AtmManifest -Root (Join-Path $stage 'src') -Version $version
# Privacy gate on exactly what will be published (optional private identifiers via ATM_PRIVATE_NEEDLES, kept
# outside the repository).
$leaks = @(& (Join-Path $repo 'tools\Test-AtmPrivacy.ps1') -Path $stage -NeedlesFile $env:ATM_PRIVATE_NEEDLES)
if ($leaks.Count -gt 0) {
    [IO.Directory]::Delete($dist, $true)
    throw ('Release recusada: possiveis dados pessoais/privados: ' + (($leaks | ForEach-Object { "$($_.File):$($_.Line) $($_.Kind)" }) -join '; '))
}
$zip = Join-Path $dist "$name.zip"
if (Test-Path -LiteralPath $zip) { [IO.File]::Delete($zip) }
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($stage, $zip, [IO.Compression.CompressionLevel]::Optimal, $true)
[IO.Directory]::Delete($stage, $true)
$script:zaClosed = $false
# Post-build verification of the ARCHIVE itself: version and release gate must be what the sources say.
$za = [IO.Compression.ZipFile]::OpenRead($zip)
try {
    $read = {
        param($rel)
        $want = ("$name/$rel").Replace('\', '/')
        $e = @($za.Entries | Where-Object { $_.FullName.Replace('\', '/') -eq $want })
        if ($e.Count -ne 1) { $za.Dispose(); $script:zaClosed = $true; [IO.File]::Delete($zip); throw "Release recusada e removida: $rel ausente no arquivo" }
        $sr = New-Object IO.StreamReader($e[0].Open()); try { $sr.ReadToEnd() } finally { $sr.Dispose() }
    }
    $cleanTxt = & $read 'src/lib/Engine.Clean.ps1'
    $auditTxt = & $read 'src/lib/Engine.Audit.ps1'
    $gateOk = ([regex]::Matches($cleanTxt, '\$script:AtmRealDeletionEnabled\s*=').Count -eq 1) -and ($cleanTxt -match '\$script:AtmRealDeletionEnabled = \$false')
    if (-not $gateOk -or $cleanTxt.Contains('AcceptProcessCoverageGap') -or -not $auditTxt.Contains("`$script:AtmVersion = '$version'")) {
        $za.Dispose(); $za = $null; [IO.File]::Delete($zip)
        throw 'Release recusada: o arquivo gerado nao contem a trava de exclusao/versao esperadas.'
    }
} finally { if ($za -and -not $script:zaClosed) { $za.Dispose() } }
$hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText((Join-Path $dist 'SHA256SUMS.txt'), "$hash  $name.zip`n", (New-Object Text.UTF8Encoding($false)))
Write-Host "Release: $zip"
Write-Host "SHA256 : $hash"
