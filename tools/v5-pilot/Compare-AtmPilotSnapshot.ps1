<#
.SYNOPSIS
  V5 pilot evidence tool (ADR-0015, section 6; decision V5-D7 (a)): compares two snapshots of Get-AtmPilotSnapshot.ps1
  and says whether only the expected change happened (S0 to S1: only new logs and transcripts; S1 to S2: only the root
  removed and the new log).
.DESCRIPTION
  Every entry is matched by its root label and relative path (ignoring case) and counted as removed, new, changed or
  unchanged, each split into expected and unexpected:
  * removed: expected only under -ExpectedRemoved ('<label>:<relative path>'), which covers that item and everything
    below it. '<label>:' alone is the whole root.
  * new: expected only when matched by -ExpectedNew: an exact '<label>:<relative path>', or a folder prefix ending in
    '\' ('<label>:<folder>\'), which covers that folder and everything below it. An item matched by -ExpectedNew may
    also change (a log or a transcript that grows).
  * changed: unexpected, except an item matched by -ExpectedNew, and a folder whose only change is its last write time
    (type, size, hash and code the same) when it is the direct parent of the expected removed item or of an expected
    new item (Windows updates a folder's last write time when an entry is added to it or removed from it), or when it
    is named by -ExpectedTouched ('<label>:<relative folder>', exact; counted again in touched.expected). That is the
    parent of a root that left and came back (isolate, then restore). Any other change of a named folder is unexpected.
  * unchanged: unexpected under -ExpectedRemoved (it should be gone), expected anywhere else.
  * a root that exists in one snapshot and is missing in the other is an unexpected change, except: PRESENT to MISSING
    when that root is exactly the -ExpectedRemoved ('<label>:'), and MISSING to PRESENT when an -ExpectedNew covers the
    whole root ('<label>:\'), as the quarantine folder that the first isolation creates.
  -ExpectedRemoved must exist in -Before and be gone from -After; otherwise only-expected-change is false.
  Refusals (exit 2): a file that is not a complete snapshot (unknown format, malformed or truncated), snapshots that are
  not of the same roots (labels or paths differ in the header), an -Expected* value with an unknown label or format
  (an -ExpectedTouched that names no folder), and an -Out that already exists (never overwritten).
  The output, on the console and in -Out, holds no path at all: the root labels, counts and yes/no only. Relative paths
  are left out too (folder names under a base can hold a user's path). It does not load the product's engine and never
  uses the network. Read only, except -Out, created as a new file.
.FORMAT
  -Out (and the console): UTF-8 text, one 'key <tab> value' per line: 'atm-pilot-compare <tab> 2', onlyExpectedChange,
  roots, expectedRemovedGiven, expectedRemovedFound, expectedNewPatterns, expectedTouchedPatterns, removed.expected,
  removed.unexpected, new.expected, new.unexpected, changed.expected, changed.unexpected, touched.expected,
  unchanged.expected, unchanged.unexpected, rootsChanged.expected, rootsChanged.unexpected, and a last line
  'end <tab> compare'. Format 2 (V5-TOOLS-ISO) adds expectedTouchedPatterns and touched.expected to format 1.
.EXITCODES
  0  compared: only the expected change.
  1  compared: some change was not expected (or the expected removal did not happen).
  2  refused: nothing was compared or written (see the message).
  3  unexpected failure.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Before,
    [Parameter(Mandatory)][string]$After,
    [string]$ExpectedRemoved,
    [string[]]$ExpectedNew = @(),
    [string[]]$ExpectedTouched = @(),
    [string]$Out
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Stop-Pilot {
    param([int]$Code, [string]$Message)
    Write-Host $Message -ForegroundColor $(if ($Code -le 1) { 'Gray' } else { 'Red' })
    exit $Code
}

function Read-PilotSnapshot {
    # Parses one snapshot file; $null with the reason when it is not a complete snapshot of the known format.
    param([string]$Path, [string]$Name)
    if (-not [IO.File]::Exists($Path)) { return [pscustomobject]@{ Error = "$Name does not exist (SNAPSHOT_MISSING)" } }
    $roots = New-Object System.Collections.Generic.List[object]
    $map = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
    $n = 0; $declared = -1; $ended = $false; $phase = 0
    $fs = New-Object IO.FileStream($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    $sr = New-Object IO.StreamReader($fs, (New-Object System.Text.UTF8Encoding($false)))
    try {
        $ln = 0
        while ($null -ne ($line = $sr.ReadLine())) {
            $ln++
            if ($line -eq '') { continue }
            if ($ended) { return [pscustomobject]@{ Error = "$Name has lines after its end (SNAPSHOT_MALFORMED)" } }
            $f = $line.Split("`t")
            if ($ln -eq 1) { if ($line -cne "atm-pilot-snapshot`t1") { return [pscustomobject]@{ Error = "$Name is not a pilot snapshot of a known format (FORMAT_UNKNOWN)" } }; continue }
            switch -CaseSensitive ($f[0]) {
                'taken' { continue }
                'root' {
                    if ($phase -ne 0 -or $f.Count -ne 4 -or $f[1] -cnotmatch '^R[1-9][0-9]*$') { return [pscustomobject]@{ Error = "$Name has a malformed root line (SNAPSHOT_MALFORMED)" } }
                    $roots.Add([pscustomobject]@{ Label = $f[1]; State = $f[2]; Path = $f[3] })
                }
                'entries' { if ($phase -ne 0 -or $f.Count -ne 2 -or $f[1] -cnotmatch '^[0-9]{1,9}$') { return [pscustomobject]@{ Error = "$Name is malformed (SNAPSHOT_MALFORMED)" } }; $declared = [int]$f[1]; $phase = 1 }
                'E' {
                    if ($phase -ne 1 -or $f.Count -ne 8 -or $f[2] -cnotin @('FILE', 'DIR', 'REPARSE_FILE', 'REPARSE_DIR')) { return [pscustomobject]@{ Error = "$Name has a malformed entry (SNAPSHOT_MALFORMED)" } }
                    if (@($roots | Where-Object { $_.Label -ceq $f[1] }).Count -ne 1) { return [pscustomobject]@{ Error = "$Name has an entry of an unknown root (SNAPSHOT_MALFORMED)" } }
                    $map[$f[1] + '|' + $f[7]] = [pscustomobject]@{ Label = $f[1]; Rel = $f[7]; Type = $f[2]; Size = $f[3]; Write = $f[4]; Sha = $f[5]; Code = $f[6] }
                    $n++
                }
                'end' { if ($phase -ne 1 -or $f.Count -ne 2 -or $f[1] -cnotmatch '^[0-9]{1,9}$' -or [int]$f[1] -ne $n -or $declared -ne $n) { return [pscustomobject]@{ Error = "$Name is truncated or its counts do not match (SNAPSHOT_TRUNCATED)" } }; $ended = $true }
                default { return [pscustomobject]@{ Error = "$Name has an unknown line (SNAPSHOT_MALFORMED)" } }
            }
        }
    } finally { $sr.Dispose(); $fs.Dispose() }
    if (-not $ended) { return [pscustomobject]@{ Error = "$Name is truncated (SNAPSHOT_TRUNCATED)" } }
    if ($map.Count -ne $n) { return [pscustomobject]@{ Error = "$Name has duplicate entries (SNAPSHOT_MALFORMED)" } }
    return [pscustomobject]@{ Error = $null; Roots = $roots.ToArray(); Map = $map }
}

function ConvertTo-PilotTarget {
    # '<label>:<relative>' -> Label, Rel (backslashes, no leading backslash), Prefix (ended by a backslash).
    param([string]$Value, [string[]]$Labels, [string]$Name)
    if ($Value -cnotmatch '^(R[1-9][0-9]*):(.*)$') { Stop-Pilot 2 "refused: $Name is not '<label>:<relative path>' (EXPECTED_FORMAT)" }
    $label = $Matches[1]; $raw = $Matches[2].Replace('/', '\')
    if ($Labels -cnotcontains $label) { Stop-Pilot 2 "refused: $Name names a label that is not in the snapshots (EXPECTED_LABEL_UNKNOWN)" }
    # A trailing backslash makes a folder prefix; '<label>:' or '<label>:\' alone is the whole root.
    $prefix = ($raw.EndsWith('\') -or $raw.Trim('\') -eq '' -or $raw -eq '.')
    $rel = $raw.Trim('\')
    if ($rel -eq '.') { $rel = '' }
    return [pscustomobject]@{ Label = $label; Rel = $rel; Prefix = $prefix }
}

function Test-PilotUnder {
    # True when $Rel is $Base itself or below it ('' = the whole root), ignoring case.
    param([string]$Rel, [string]$Base)
    if ($Base -eq '') { return $true }
    return ([string]::Equals($Rel, $Base, [StringComparison]::OrdinalIgnoreCase) -or $Rel.StartsWith($Base + '\', [StringComparison]::OrdinalIgnoreCase))
}

function Get-PilotParent {
    param([string]$Rel)
    $i = $Rel.LastIndexOf('\')
    if ($i -lt 0) { return '' }
    return $Rel.Substring(0, $i)
}

try {
    if ($Out -and ([IO.File]::Exists($Out) -or [IO.Directory]::Exists($Out))) { Stop-Pilot 2 'refused: -Out already exists; it is never overwritten (OUT_EXISTS)' }
    $b = Read-PilotSnapshot $Before '-Before'
    if ($b.Error) { Stop-Pilot 2 ('refused: ' + $b.Error) }
    $a = Read-PilotSnapshot $After '-After'
    if ($a.Error) { Stop-Pilot 2 ('refused: ' + $a.Error) }
    $sameRoots = ($b.Roots.Count -eq $a.Roots.Count)
    if ($sameRoots) {
        for ($i = 0; $i -lt $b.Roots.Count; $i++) {
            if ($b.Roots[$i].Label -cne $a.Roots[$i].Label -or -not [string]::Equals($b.Roots[$i].Path, $a.Roots[$i].Path, [StringComparison]::OrdinalIgnoreCase)) { $sameRoots = $false }
        }
    }
    if (-not $sameRoots) { Stop-Pilot 2 'refused: the two snapshots are not of the same roots (labels or paths differ) (SNAPSHOTS_INCOMPATIBLE)' }
    $labels = [string[]]@($b.Roots | ForEach-Object { $_.Label })

    $rem = $null
    if ($ExpectedRemoved) { $rem = ConvertTo-PilotTarget $ExpectedRemoved $labels '-ExpectedRemoved'; if ($rem.Prefix -and $rem.Rel -eq '') { $rem.Prefix = $false } }
    $news = @(foreach ($x in $ExpectedNew) { if ($x) { ConvertTo-PilotTarget $x $labels '-ExpectedNew' } })
    $isRemoved = { param($e) ($null -ne $rem) -and $e.Label -ceq $rem.Label -and (Test-PilotUnder $e.Rel $rem.Rel) }
    $isNew = {
        param($e)
        foreach ($t in $news) {
            if ($e.Label -cne $t.Label) { continue }
            if ($t.Prefix) { if (Test-PilotUnder $e.Rel $t.Rel) { return $true } }
            elseif ([string]::Equals($e.Rel, $t.Rel, [StringComparison]::OrdinalIgnoreCase)) { return $true }
        }
        return $false
    }
    # -ExpectedTouched: exact folders (never a prefix, never the root itself) that may change their last write time only.
    $touch = @(foreach ($x in $ExpectedTouched) {
            if (-not $x) { continue }
            $t = ConvertTo-PilotTarget $x $labels '-ExpectedTouched'
            if ($t.Rel -eq '') { Stop-Pilot 2 "refused: -ExpectedTouched names no folder under its root (EXPECTED_FORMAT)" }
            $t
        })
    $isTouched = {
        param($e)
        foreach ($t in $touch) { if ($e.Label -ceq $t.Label -and [string]::Equals($e.Rel, $t.Rel, [StringComparison]::OrdinalIgnoreCase)) { return $true } }
        return $false
    }

    $c = [ordered]@{ 'removed.expected' = 0; 'removed.unexpected' = 0; 'new.expected' = 0; 'new.unexpected' = 0; 'changed.expected' = 0; 'changed.unexpected' = 0
        'touched.expected' = 0; 'unchanged.expected' = 0; 'unchanged.unexpected' = 0; 'rootsChanged.expected' = 0; 'rootsChanged.unexpected' = 0 }

    # Roots present in one snapshot and missing in the other: expected only when it is the whole expected removal, or
    # when a root that did not exist is born covered whole by -ExpectedNew ('<label>:\').
    for ($i = 0; $i -lt $b.Roots.Count; $i++) {
        $sb = $b.Roots[$i].State; $sa = $a.Roots[$i].State
        if ($sb -ceq $sa) { continue }
        $lb = $b.Roots[$i].Label
        $whole = ($null -ne $rem -and $rem.Label -ceq $lb -and $rem.Rel -eq '')
        $born = (@($news | Where-Object { $_.Label -ceq $lb -and $_.Prefix -and $_.Rel -eq '' }).Count -gt 0)
        if (($sb -ceq 'PRESENT' -and $sa -ceq 'MISSING' -and $whole) -or ($sb -ceq 'MISSING' -and $sa -ceq 'PRESENT' -and $born)) { $c['rootsChanged.expected']++ } else { $c['rootsChanged.unexpected']++ }
    }

    # Direct parents of the expected removal and of the expected new items: their last write time may change.
    $parents = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $remFound = $false
    if ($null -ne $rem) {
        if ($rem.Rel -ne '') {
            [void]$parents.Add($rem.Label + '|' + (Get-PilotParent $rem.Rel))
            $remFound = ($b.Map.ContainsKey($rem.Label + '|' + $rem.Rel) -and -not $a.Map.ContainsKey($rem.Label + '|' + $rem.Rel))
        } else {
            $ri = [array]::IndexOf($labels, $rem.Label)
            $remFound = ($b.Roots[$ri].State -ceq 'PRESENT' -and $a.Roots[$ri].State -ceq 'MISSING')
        }
    }
    $newRows = New-Object System.Collections.Generic.List[object]
    foreach ($k in $a.Map.Keys) {
        if ($b.Map.ContainsKey($k)) { continue }
        $e = $a.Map[$k]
        if (& $isNew $e) { $c['new.expected']++; [void]$parents.Add($e.Label + '|' + (Get-PilotParent $e.Rel)) } else { $c['new.unexpected']++ }
    }
    foreach ($k in $b.Map.Keys) {
        $e = $b.Map[$k]
        if (-not $a.Map.ContainsKey($k)) {
            if (& $isRemoved $e) { $c['removed.expected']++ } else { $c['removed.unexpected']++ }
            continue
        }
        $f = $a.Map[$k]
        $same = ($e.Type -ceq $f.Type -and $e.Size -ceq $f.Size -and $e.Write -ceq $f.Write -and $e.Sha -ceq $f.Sha -and $e.Code -ceq $f.Code)
        if ($same) {
            if (& $isRemoved $e) { $c['unchanged.unexpected']++ } else { $c['unchanged.expected']++ }
            continue
        }
        $onlyWrite = ($e.Type -ceq 'DIR' -and $f.Type -ceq 'DIR' -and $e.Size -ceq $f.Size -and $e.Sha -ceq $f.Sha -and $e.Code -ceq $f.Code)
        $touched = ($onlyWrite -and (& $isTouched $e))
        if ((-not (& $isRemoved $e)) -and ((& $isNew $f) -or ($onlyWrite -and $parents.Contains($k)) -or $touched)) {
            $c['changed.expected']++
            if ($touched) { $c['touched.expected']++ }
        } else { $c['changed.unexpected']++ }
    }

    $unexpected = $c['removed.unexpected'] + $c['new.unexpected'] + $c['changed.unexpected'] + $c['unchanged.unexpected'] + $c['rootsChanged.unexpected']
    $only = ($unexpected -eq 0 -and ($null -eq $rem -or $remFound))
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("atm-pilot-compare`t2")
    $lines.Add("onlyExpectedChange`t" + $(if ($only) { 'true' } else { 'false' }))
    $lines.Add("roots`t" + ($labels -join ','))
    $lines.Add("expectedRemovedGiven`t" + $(if ($null -ne $rem) { 'true' } else { 'false' }))
    $lines.Add("expectedRemovedFound`t" + $(if ($remFound) { 'true' } else { 'false' }))
    $lines.Add("expectedNewPatterns`t" + $news.Count)
    $lines.Add("expectedTouchedPatterns`t" + $touch.Count)
    foreach ($k in $c.Keys) { $lines.Add("$k`t" + $c[$k]) }
    $lines.Add("end`tcompare")
    $text = ($lines -join "`r`n") + "`r`n"
    foreach ($l in $lines) { Write-Host $l }
    if ($Out) {
        $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($text)
        $fs = $null
        try { $fs = New-Object IO.FileStream($Out, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None) } catch { Stop-Pilot 2 'refused: -Out could not be created as a new file (OUT_CREATE_FAILED)' }
        try { $fs.Write($bytes, 0, $bytes.Length); $fs.Flush($true) } finally { $fs.Dispose() }
    }
    if ($only) { Stop-Pilot 0 'only the expected change' }
    Stop-Pilot 1 'some change was not expected (see the counts)'
} catch {
    Write-Host ('failed: ' + $_.Exception.GetBaseException().GetType().Name) -ForegroundColor Red
    exit 3
}
