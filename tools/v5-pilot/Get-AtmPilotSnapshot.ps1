<#
.SYNOPSIS
  V5 pilot evidence tool (ADR-0015, section 6; decision V5-D7 (a)): a read-only listing of one or more folders, taken
  inside the pilot VM before any run (S0), right before the deleting run (S1) and after it (S2).
.DESCRIPTION
  For every item under each -Root (labelled R1, R2, ... in the order given) it records: the root label, the path
  relative to that root, the type (FILE, DIR, REPARSE_FILE, REPARSE_DIR), the size of a file, the last write time (UTC)
  and the SHA-256 of a file.
  * Read only. Files are opened for reading with full sharing (ReadWrite and Delete), so a file in use by another
    process is not disturbed. Nothing is created, changed, moved or deleted under any root; no date is set. (The last
    access time is kept by the volume's own policy, not by this script.) Times and sizes are read from each item itself,
    never from the folder listing, whose copy NTFS updates lazily.
  * Reparse points (junctions, symbolic links, any other reparse point, on a folder or a file) are recorded with their
    type and never followed: nothing under them is listed and a linked file is not read.
  * An item that cannot be read (access denied, a file held with exclusive sharing, a folder that cannot be listed) is
    recorded with a code (ACCESS_DENIED, SHARING_VIOLATION, LOCK_VIOLATION, VANISHED, PATH_TOO_LONG, IO_<type>) and no
    content. Nothing is skipped in silence.
  * The absolute paths of the roots are written only in the header of the snapshot file, which stays in the VM. Every
    entry carries the root label and a relative path only. The console shows counts only.
  * It does not load the product's engine nor its native library: .NET and read cmdlets only. It never uses the network.
  Refusals (nothing is written): -Out inside any -Root (the paths are compared after resolving every existing component
  to its long name; a reparse point on the path of -Out or of a root is itself a refusal), -Out that already exists
  (never overwritten), a folder of -Out that does not exist, a -Root that is a file or a reparse point, roots that are
  the same folder or nested in each other. A -Root that does not exist is recorded as MISSING, with a warning.
  Run it from a PowerShell console with `& <this script> -Root $a, $b -Out $file` (an array is not passed through
  `powershell -File`).
.FORMAT
  UTF-8 text, one record per line, fields separated by a tab:
    atm-pilot-snapshot <tab> 1
    taken <tab> <UTC time>
    root <tab> <label> <tab> PRESENT|MISSING|UNREADABLE_<code> <tab> <absolute path>     (one per -Root)
    entries <tab> <count>
    E <tab> <label> <tab> <type> <tab> <size or -> <tab> <last write UTC> <tab> <SHA-256 or -> <tab> <code or -> <tab> <relative path>
    end <tab> <count>
.EXITCODES
  0  the snapshot was written to -Out.
  2  refused: nothing was written (see the message).
  3  unexpected failure; if -Out was created it may be incomplete, and it is never removed by this script.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$Root,
    [Parameter(Mandatory)][string]$Out
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Resolve-PilotPath {
    # The absolute path with every existing component replaced by its name on disk (long form, real case), whether any
    # existing component is a reparse point, and whether the whole path exists (and is a folder). Read only.
    param([string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    $top = [IO.Path]::GetPathRoot($full)
    if (-not $top) { throw 'PATH_INVALID' }
    $rest = $full.Substring($top.Length).Trim('\')
    $parts = @(); if ($rest) { $parts = @($rest.Split('\')) }
    $cur = $top; $reparse = $false; $exists = $true; $isDir = $true
    foreach ($comp in $parts) {
        if (-not $comp) { continue }
        if (-not $exists -or -not $isDir) { $exists = $false; $cur = [IO.Path]::Combine($cur, $comp); continue }
        $hits = @((New-Object IO.DirectoryInfo($cur)).GetFileSystemInfos($comp))
        $hit = $null
        if ($hits.Count -eq 1) { $hit = $hits[0] } elseif ($hits.Count -gt 1) { $hit = @($hits | Where-Object { [string]::Equals($_.Name, $comp, [StringComparison]::OrdinalIgnoreCase) })[0] }
        if ($null -eq $hit) { $exists = $false; $cur = [IO.Path]::Combine($cur, $comp); continue }
        if (($hit.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { $reparse = $true }
        $isDir = (($hit.Attributes -band [IO.FileAttributes]::Directory) -ne 0)
        $cur = [IO.Path]::Combine($cur, $hit.Name)
    }
    if ($cur.Length -gt $top.Length) { $cur = $cur.TrimEnd('\') }
    return [pscustomobject]@{ Path = $cur; Reparse = $reparse; Exists = $exists; IsDir = ($exists -and $isDir) }
}

function Test-PilotInside {
    # True when $Path is $Parent itself or below it (resolved paths, ignoring case).
    param([string]$Path, [string]$Parent)
    $p = $Parent.TrimEnd('\')
    return ([string]::Equals($Path, $p, [StringComparison]::OrdinalIgnoreCase) -or $Path.StartsWith($p + '\', [StringComparison]::OrdinalIgnoreCase))
}

function Get-PilotReadCode {
    # A short code for an item that could not be read; never the exception text (it may hold a path).
    param($Err)
    $ex = $Err.Exception.GetBaseException()
    if ($ex -is [UnauthorizedAccessException]) { return 'ACCESS_DENIED' }
    if ($ex -is [IO.FileNotFoundException] -or $ex -is [IO.DirectoryNotFoundException]) { return 'VANISHED' }
    if ($ex -is [IO.PathTooLongException]) { return 'PATH_TOO_LONG' }
    if ($ex -is [IO.IOException]) {
        $hr = $ex.HResult -band 0xFFFF
        if ($hr -eq 32) { return 'SHARING_VIOLATION' }
        if ($hr -eq 33) { return 'LOCK_VIOLATION' }
    }
    return ('IO_' + $ex.GetType().Name)
}

function Get-PilotFileHash {
    # SHA-256 of one file, read with full sharing; the code instead when it cannot be read.
    param([string]$Path)
    $fs = $null; $sha = $null
    try {
        $fs = New-Object IO.FileStream($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete), 65536, [IO.FileOptions]::SequentialScan)
        $sha = [Security.Cryptography.SHA256]::Create()
        $h = $sha.ComputeHash($fs)
        return [pscustomobject]@{ Sha = ([BitConverter]::ToString($h) -replace '-', ''); Code = $null }
    } catch {
        return [pscustomobject]@{ Sha = $null; Code = (Get-PilotReadCode $_) }
    } finally {
        if ($null -ne $fs) { $fs.Dispose() }
        if ($null -ne $sha) { $sha.Dispose() }
    }
}

function Stop-Pilot {
    param([int]$Code, [string]$Message)
    Write-Host $Message -ForegroundColor $(if ($Code -eq 0) { 'Green' } else { 'Red' })
    exit $Code
}

$inv = [Globalization.CultureInfo]::InvariantCulture
try {
    # --- checks: nothing is written before all of them pass ---
    $outR = $null
    try { $outR = Resolve-PilotPath $Out } catch { Stop-Pilot 2 'refused: -Out is not a valid path (OUT_PATH_INVALID)' }
    if ($outR.Exists) { Stop-Pilot 2 'refused: -Out already exists; it is never overwritten (OUT_EXISTS)' }
    if ($outR.Reparse) { Stop-Pilot 2 'refused: a reparse point is on the path of -Out (OUT_PATH_REPARSE)' }
    $outDir = Resolve-PilotPath ([IO.Path]::GetDirectoryName($outR.Path))
    if (-not $outDir.IsDir) { Stop-Pilot 2 'refused: the folder of -Out does not exist (OUT_FOLDER_MISSING)' }

    $roots = New-Object System.Collections.Generic.List[object]
    $i = 0
    foreach ($r in $Root) {
        $i++
        $label = 'R' + $i
        $rr = $null
        try { $rr = Resolve-PilotPath $r } catch { Stop-Pilot 2 "refused: $label is not a valid path (ROOT_PATH_INVALID)" }
        if ($rr.Reparse) { Stop-Pilot 2 "refused: a reparse point is on the path of $label, or $label is one (ROOT_PATH_REPARSE)" }
        if ($rr.Exists -and -not $rr.IsDir) { Stop-Pilot 2 "refused: $label is not a folder (ROOT_NOT_FOLDER)" }
        if (Test-PilotInside -Path $outR.Path -Parent $rr.Path) { Stop-Pilot 2 "refused: -Out is inside $label (OUT_INSIDE_ROOT)" }
        foreach ($o in $roots) {
            if ((Test-PilotInside -Path $rr.Path -Parent $o.Path) -or (Test-PilotInside -Path $o.Path -Parent $rr.Path)) { Stop-Pilot 2 "refused: $label and $($o.Label) are the same folder or nested (ROOTS_OVERLAP)" }
        }
        $roots.Add([pscustomobject]@{ Label = $label; Path = $rr.Path; State = $(if ($rr.Exists) { 'PRESENT' } else { 'MISSING' }) })
    }

    # --- listing (read only) ---
    $entries = New-Object System.Collections.Generic.List[object]
    $nRep = 0; $nCode = 0
    foreach ($ro in $roots) {
        if ($ro.State -ne 'PRESENT') { Write-Warning "$($ro.Label) does not exist: recorded as MISSING"; continue }
        $stack = New-Object System.Collections.Generic.Stack[object]
        $stack.Push(@((New-Object IO.DirectoryInfo($ro.Path)), '', $null))
        while ($stack.Count -gt 0) {
            $cur = $stack.Pop()
            $kids = $null
            try { $kids = $cur[0].GetFileSystemInfos() } catch {
                # A folder that cannot be listed keeps its entry, with the code; the root itself: in the header.
                $c = Get-PilotReadCode $_
                if ($null -eq $cur[2]) { $ro.State = 'UNREADABLE_' + $c } else { $cur[2].Code = $c }
                continue
            }
            foreach ($e in $kids) {
                $rel = $(if ($cur[1]) { $cur[1] + '\' + $e.Name } else { $e.Name })
                $isDir = (($e.Attributes -band [IO.FileAttributes]::Directory) -ne 0)
                $isRep = (($e.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
                $row = [pscustomobject]@{ Label = $ro.Label; Rel = $rel; Type = $null; Size = '-'; Write = '-'; Sha = '-'; Code = $null }
                # Times and size from the item itself (Refresh: its own attributes, a reparse point's own, not its
                # target's), never from the folder listing: NTFS updates the copy in the parent's index lazily, so two
                # listings with nothing changed in between could differ.
                try { $e.Refresh(); $row.Write = $e.LastWriteTimeUtc.ToString('o', $inv) } catch { $row.Code = Get-PilotReadCode $_ }
                if ($isRep) {
                    # Recorded, never followed: no listing under it and no read through it.
                    $row.Type = $(if ($isDir) { 'REPARSE_DIR' } else { 'REPARSE_FILE' })
                    $nRep++
                } elseif ($isDir) {
                    $row.Type = 'DIR'
                    $stack.Push(@($e, $rel, $row))
                } else {
                    $row.Type = 'FILE'
                    try { $row.Size = ([long]$e.Length).ToString($inv) } catch { $row.Code = Get-PilotReadCode $_ }
                    if (-not $row.Code) {
                        $h = Get-PilotFileHash $e.FullName
                        if ($h.Code) { $row.Code = $h.Code } else { $row.Sha = $h.Sha }
                    }
                }
                $entries.Add($row)
            }
        }
    }
    foreach ($row in $entries) { if ($row.Code) { $nCode++ } }

    # Stable order: by root label, then by relative path (ordinal, ignoring case).
    $keys = [string[]]@($entries | ForEach-Object { $_.Label + "`t" + $_.Rel })
    $arr = $entries.ToArray()
    [Array]::Sort($keys, $arr, [StringComparer]::OrdinalIgnoreCase)

    $sb = New-Object System.Text.StringBuilder
    $nl = "`r`n"
    [void]$sb.Append("atm-pilot-snapshot`t1" + $nl)
    [void]$sb.Append("taken`t" + [datetime]::UtcNow.ToString('o', $inv) + $nl)
    foreach ($ro in $roots) { [void]$sb.Append("root`t$($ro.Label)`t$($ro.State)`t$($ro.Path)" + $nl) }
    [void]$sb.Append("entries`t" + $arr.Count + $nl)
    foreach ($row in $arr) {
        $code = $(if ($row.Code) { $row.Code } else { '-' })
        [void]$sb.Append("E`t$($row.Label)`t$($row.Type)`t$($row.Size)`t$($row.Write)`t$($row.Sha)`t$code`t$($row.Rel)" + $nl)
    }
    [void]$sb.Append("end`t" + $arr.Count + $nl)

    # --- the only write: a NEW file at -Out (never an existing one) ---
    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($sb.ToString())
    $fs = $null
    try {
        $fs = New-Object IO.FileStream($outR.Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    } catch { Stop-Pilot 2 'refused: -Out could not be created as a new file (OUT_CREATE_FAILED)' }
    try { $fs.Write($bytes, 0, $bytes.Length); $fs.Flush($true) } finally { $fs.Dispose() }

    $states = ($roots | ForEach-Object { "$($_.Label)=$($_.State)" }) -join ' '
    Stop-Pilot 0 "snapshot written: $($arr.Count) entries; roots $states; reparse points recorded (not followed): $nRep; items with a read code: $nCode"
} catch {
    Write-Host ('failed: ' + $_.Exception.GetBaseException().GetType().Name + ' (nothing under any root was changed)') -ForegroundColor Red
    exit 3
}
