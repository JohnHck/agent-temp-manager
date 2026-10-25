<#
.SYNOPSIS
  Privacy scanner for everything that could be published (repository files, a release folder or a release zip).
  Reports PERSONAL/ENVIRONMENT data: real user names, machine names, SIDs, e-mail addresses, user-profile paths,
  credential-like tokens, Claude Code session identifiers, and any identifier listed in an optional private
  needles file (kept OUTSIDE the repository).
.OUTPUTS
  One object per finding: File, Line, Kind, Excerpt (always '[redacted]': no part of the value is printed). No
  output = clean.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,          # directory or .zip
    [string]$NeedlesFile,                          # optional, one identifier per line ('#' = comment)
    [string[]]$ExtraNeedles = @()
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Fictitious values that the project deliberately uses in tests and docs.
$allowedUserDirs = @('alice', 'x', 'EXAMPL~1', 'Public', 'Default', '<name>', '<user>', 'U', 'nome')
$allowedSids = @('S-1-5-21-1-2-3-777', 'S-1-5-21-1-2-3-4444', 'S-1-5-21-9-9-9-1000')
$allowedEmails = @('noreply@anthropic.com')
$binaryExt = @('.zip', '.dll', '.exe', '.png', '.jpg', '.ico', '.pdb')
# Words of the product's own text that a machine may also use as an account or profile folder name. Evidence
# (FINAL-A-S): on the Windows 11 ARM64 runner a profile folder of the image is named like the first word; the 91
# lines it flagged were exactly the 91 published lines holding it (installer scripts, docs, 'TrustedInstaller').
# Only a needle taken from this machine and EQUAL to a listed word (ignoring case) is skipped, with a warning;
# a needle given by -ExtraNeedles or -NeedlesFile is always searched, and so is any longer name holding the word.
$productWords = @('installer')

$needles = New-Object System.Collections.Generic.List[string]
foreach ($n in $ExtraNeedles) { if ($n -and $n.Length -ge 3) { $needles.Add($n) } }
if ($NeedlesFile -and (Test-Path -LiteralPath $NeedlesFile)) {
    foreach ($l in (Get-Content -LiteralPath $NeedlesFile -Encoding UTF8)) { $t = $l.Trim(); if ($t -and -not $t.StartsWith('#') -and $t.Length -ge 3) { $needles.Add($t) } }
}
# The machine running the scan must not leak into what it scans (each needle keeps its source for the warning).
$machineNeedles = New-Object System.Collections.Generic.List[object]
foreach ($e in @(@('USERNAME', $env:USERNAME), @('COMPUTERNAME', $env:COMPUTERNAME), @('USERDOMAIN', $env:USERDOMAIN))) { if ($e[1] -and $e[1].Length -ge 3 -and $e[1] -notin @('WORKGROUP')) { $machineNeedles.Add(@($e[0], $e[1])) } }
# Accounts without a machine or domain SID (e.g. SYSTEM): nothing to add.
try { $machineNeedles.Add(@('AccountDomainSid', ([Security.Principal.WindowsIdentity]::GetCurrent().User.AccountDomainSid.Value))) } catch { $null = $_ }
try {
    $pl = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList')
    foreach ($s in $pl.GetSubKeyNames()) {
        if ($s -notlike 'S-1-5-21-*') { continue }
        $img = [string]$pl.OpenSubKey($s).GetValue('ProfileImagePath')
        if ($img) { $leaf = Split-Path -Leaf $img; if ($leaf.Length -ge 3) { $machineNeedles.Add(@('ProfileList', $leaf)) } }
    }
    $pl.Close()
# Never silent: a weaker scan must be visible.
} catch { Write-Warning "ProfileList unreadable: this machine's profile names are not added as private identifiers ($($_.Exception.Message))" }
foreach ($m in $machineNeedles) {
    $w = @($productWords | Where-Object { $_ -eq $m[1] })
    # Never silent: the skipped needle is named only by its source and the listed product word.
    if ($w.Count -gt 0) { Write-Warning "private identifier from $($m[0]) equals the product word '$($w[0])': not searched (it cannot be told apart from the product's own text)"; continue }
    $needles.Add([string]$m[1])
}
$needles = @($needles | Select-Object -Unique)

$patterns = @(
    @{ Kind = 'SID'; Rx = 'S-1-5-21-\d+-\d+-\d+(-\d+)?' }
    @{ Kind = 'EMAIL'; Rx = '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' }
    @{ Kind = 'USER_PATH'; Rx = '(?i)[A-Z]:\\Users\\([^\\\s"''`<>|*?]+)' }
    @{ Kind = 'TOKEN'; Rx = '(sk-ant-[A-Za-z0-9_-]{10,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)' }
    @{ Kind = 'SECRET_ASSIGN'; Rx = '(?i)(password|passwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*[''"][^''"\s]{6,}[''"]' }
    @{ Kind = 'MACHINE'; Rx = '(?i)\bDESKTOP-[A-Z0-9]{5,}\b|\bLAPTOP-[A-Z0-9]{5,}\b' }
)

function Get-Items {
    param([string]$P)
    if ($P -match '\.zip$') {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $z = [IO.Compression.ZipFile]::OpenRead($P)
        try {
            foreach ($e in $z.Entries) {
                if ($e.Length -eq 0 -and $e.FullName.EndsWith('/')) { continue }
                $ext = [IO.Path]::GetExtension($e.FullName).ToLowerInvariant()
                $text = $null
                if ($binaryExt -notcontains $ext) { $sr = New-Object IO.StreamReader($e.Open()); try { $text = $sr.ReadToEnd() } finally { $sr.Dispose() } }
                [pscustomobject]@{ Name = $e.FullName.Replace('\', '/'); Text = $text; Binary = ($binaryExt -contains $ext) }
            }
        } finally { $z.Dispose() }
        return
    }
    # Relative names are built from the tree itself (never by trimming a prefix), so an 8.3 or long form of the
    # root cannot shift them. The .git directory is skipped.
    $stack = New-Object System.Collections.Generic.Stack[object]
    $stack.Push(@((New-Object IO.DirectoryInfo((Resolve-Path -LiteralPath $P).ProviderPath)), ''))
    while ($stack.Count -gt 0) {
        $cur = $stack.Pop()
        foreach ($e in $cur[0].GetFileSystemInfos()) {
            $rel = $(if ($cur[1]) { $cur[1] + '\' + $e.Name } else { $e.Name })
            if (($e.Attributes -band [IO.FileAttributes]::Directory) -ne 0) {
                if ($e.Name -ne '.git' -and ($e.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) { $stack.Push(@($e, $rel)) }
                continue
            }
            $ext = $e.Extension.ToLowerInvariant()
            [pscustomobject]@{ Name = $rel; Text = $(if ($binaryExt -contains $ext) { $null } else { [IO.File]::ReadAllText($e.FullName) }); Binary = ($binaryExt -contains $ext) }
        }
    }
}

foreach ($it in (Get-Items $Path)) {
    if ($it.Binary) { [pscustomobject]@{ File = $it.Name; Line = 0; Kind = 'BINARY'; Excerpt = 'arquivo binario no conjunto publicavel' }; continue }
    if ($null -eq $it.Text) { continue }
    $lines = $it.Text -split "`r?`n"
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $ln = $lines[$i]
        foreach ($p in $patterns) {
            foreach ($m in [regex]::Matches($ln, $p.Rx)) {
                $v = $m.Value
                if ($p.Kind -eq 'SID' -and ($allowedSids -contains $v -or $v -match '^S-1-5-21-\d-\d-\d')) { continue }
                if ($p.Kind -eq 'EMAIL' -and $allowedEmails -contains $v) { continue }
                if ($p.Kind -eq 'USER_PATH' -and $allowedUserDirs -contains $m.Groups[1].Value) { continue }
                [pscustomobject]@{ File = $it.Name; Line = $i + 1; Kind = $p.Kind; Excerpt = '[redacted]' }
            }
        }
        foreach ($n in $needles) {
            if ($ln.IndexOf($n, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                [pscustomobject]@{ File = $it.Name; Line = $i + 1; Kind = 'PRIVATE_IDENTIFIER'; Excerpt = '[redacted]' }
            }
        }
    }
}
