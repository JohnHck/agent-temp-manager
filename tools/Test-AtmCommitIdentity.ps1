<#
.SYNOPSIS
  Checks the identity metadata of Git commits (author, committer, Co-authored-by and Signed-off-by trailers) and
  reports e-mail addresses that would publish a personal address. Read-only. Addresses are never printed in full.
.DESCRIPTION
  Allowed without configuration:
    * GitHub noreply addresses of users and bots (<id>+<login>@users.noreply.github.com and the older
      <login>@users.noreply.github.com form);
    * the fixed address GitHub uses as committer of commits it creates (web-flow);
    * as trailer only: organizational addresses such as the one AI assistants use for Co-authored-by lines and
      the one Dependabot uses for Signed-off-by (see $allowedTrailerOnly).
  Anything else is reported, unless listed in the allow-list file (default .github/commit-identity-allowlist.txt):
    email:<address>       a contributor who chose to publish that address (exact, case-insensitive)
    commit:<40-hex sha>   a known historical commit that was reviewed and deliberately kept
  Run on a pull request (base..head), a push (before..after) or the whole history (-All).

  A check that runs after a push only DETECTS an exposure: the commit is already public by then. Prevention needs
  the account setting "Keep my email addresses private" (it also covers merges made by GitHub) and local commits
  made with a noreply address.
.OUTPUTS
  One line per finding plus a summary. Exit code: 0 = clean, 1 = findings, 2 = usage or git error.
.EXAMPLE
  ./tools/Test-AtmCommitIdentity.ps1 -Range "$base..$head"
  ./tools/Test-AtmCommitIdentity.ps1 -All
#>
[CmdletBinding()]
param(
    [string]$Range,
    [string]$Commit,
    [switch]$All,
    [string]$RepoDir = '.',
    [string]$AllowListFile
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$allowedIdentity = @(
    '^\d+\+[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(?:\[bot\])?@users\.noreply\.github\.com$'
    '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(?:\[bot\])?@users\.noreply\.github\.com$'
    '^noreply@github\.com$'
)
# Organizational addresses that only appear in trailers: AI assistant co-author lines and Dependabot's sign-off.
$allowedTrailerOnly = @('^noreply@anthropic\.com$', '^support@github\.com$')
$trailerKeys = @('Co-authored-by', 'Signed-off-by')

function Get-MaskedAddress {
    param([string]$Address)
    if ($Address -match '^(.)[^@]*@(.)') { return "$($Matches[1])***@$($Matches[2])***" }
    return '***'
}

function Test-Pattern {
    param([string]$Value, [string[]]$Patterns)
    foreach ($p in $Patterns) { if ($Value -match $p) { return $true } }
    return $false
}

function Invoke-Git {
    param([string[]]$GitArgs)
    $out = & git -C $RepoDir @GitArgs 2>&1
    if ($LASTEXITCODE -ne 0) { throw "git $($GitArgs[0]) falhou ($LASTEXITCODE)" }
    return @($out)
}

try {
    $modes = @(@($Range, $Commit) | Where-Object { $_ }).Count + [int][bool]$All
    if ($modes -ne 1) { throw 'Use exactly one of -Range, -Commit or -All.' }
    if (-not $AllowListFile) { $AllowListFile = Join-Path $RepoDir '.github\commit-identity-allowlist.txt' }

    $allowedEmails = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $acceptedCommits = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    if (Test-Path -LiteralPath $AllowListFile) {
        foreach ($line in [IO.File]::ReadAllLines($AllowListFile)) {
            $t = $line.Trim()
            if (-not $t -or $t.StartsWith('#')) { continue }
            if ($t -match '^email:\s*(\S+@\S+)$') { [void]$allowedEmails.Add($Matches[1]) }
            elseif ($t -match '^commit:\s*([0-9a-fA-F]{40})$') { [void]$acceptedCommits.Add($Matches[1]) }
            else { throw "linha invalida na allow-list: '$t'" }
        }
    }

    # One record per commit; fields separated by US (0x1f), records by RS (0x1e).
    $us = [char]0x1f; $rs = [char]0x1e
    $format = "--format=%H$us%ae$us%ce$us%(trailers:only,unfold)$rs"
    $gitArgs = @('log', $format)
    if ($All) { $gitArgs += '--all' }
    elseif ($Commit) { $gitArgs += @('-1', $Commit) }
    else { $gitArgs += $Range }
    $raw = (Invoke-Git $gitArgs) -join "`n"

    $checked = 0; $accepted = 0
    $findings = New-Object System.Collections.Generic.List[object]
    foreach ($record in ($raw -split $rs)) {
        $record = $record.Trim("`r", "`n", ' ')
        if (-not $record) { continue }
        $f = $record -split $us
        $sha = $f[0]; $checked++
        if ($acceptedCommits.Contains($sha)) { $accepted++; continue }
        $items = New-Object System.Collections.Generic.List[object]
        $items.Add(@('author', $f[1], $false))
        $items.Add(@('committer', $f[2], $false))
        foreach ($tl in ($f[3] -split "`n")) {
            foreach ($k in $trailerKeys) {
                if ($tl -match ('^' + [regex]::Escape($k) + ':\s*.*<([^<>\s]+)>\s*$')) { $items.Add(@($k, $Matches[1], $true)) }
            }
        }
        foreach ($it in $items) {
            $addr = [string]$it[1]
            $patterns = $(if ($it[2]) { $allowedIdentity + $allowedTrailerOnly } else { $allowedIdentity })
            if ((Test-Pattern $addr $patterns) -or $allowedEmails.Contains($addr)) { continue }
            $findings.Add([pscustomobject]@{ Commit = $sha.Substring(0, 12); Field = $it[0]; Address = (Get-MaskedAddress $addr) })
        }
    }

    foreach ($x in $findings) { Write-Output ("FINDING {0} {1}: e-mail nao autorizado ({2})" -f $x.Commit, $x.Field, $x.Address) }
    Write-Output ("commits verificados: {0} | excecoes aceitas: {1} | achados: {2}" -f $checked, $accepted, $findings.Count)
    if ($findings.Count -gt 0) {
        Write-Output 'Use o endereco noreply do GitHub (Settings > Emails) ou, para um endereco que o contribuidor decidiu publicar, adicione-o a allow-list com a aprovacao de um mantenedor.'
        exit 1
    }
    exit 0
} catch {
    Write-Output "ERRO: $($_.Exception.Message)"
    exit 2
}
