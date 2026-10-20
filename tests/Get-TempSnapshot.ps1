# Read-only evidence snapshot of real agent temp roots (default: <TEMP>\claude of the CURRENT user; -Base for another readable base).
# Output: JSON with one fingerprint per partition root (files, dirs, bytes, newest write).
# Used before/after tests and installation to prove that nothing was modified.
param([Parameter(Mandatory)][string]$OutFile, [string]$LibDir, [string]$Base)
if (-not $LibDir) { $LibDir = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) '..\src\lib' }
. (Join-Path $LibDir 'Engine.Audit.ps1')
Initialize-AtmNative -LibDir $LibDir
$base = Get-AtmNormalizedPath $(if ($Base) { $Base } else { Join-Path $env:TEMP 'claude' })
$rows = New-Object System.Collections.Generic.List[object]
if ([IO.Directory]::Exists($base)) {
    foreach ($slug in (New-Object IO.DirectoryInfo($base)).GetFileSystemInfos()) {
        $targets = @($slug)
        if (($slug.Attributes -band [IO.FileAttributes]::Directory) -and -not ($slug.Attributes -band [IO.FileAttributes]::ReparsePoint)) { $targets = @($slug.GetFileSystemInfos()) }
        foreach ($t in $targets) {
            $s = [AgentTempManager.AtmScanner]::ScanTree($t.FullName, 3, 4096)
            $rows.Add([ordered]@{ path = $t.FullName; files = $s.Files; dirs = $s.Dirs; bytes = $s.Bytes; newestUtc = $s.NewestWriteTimeUtc.ToString('o'); fingerprint = (Get-AtmFingerprint $s) })
        }
    }
}
$doc = [ordered]@{ takenUtc = [datetime]::UtcNow.ToString('o'); base = $base; roots = $rows.ToArray() }
[IO.File]::WriteAllText($OutFile, ($doc | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding($false)))
Write-Host "snapshot: $($rows.Count) roots -> $OutFile"
