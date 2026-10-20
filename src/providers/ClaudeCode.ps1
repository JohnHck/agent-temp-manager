# Agent Temp Manager - provider: Claude Code (V1, Windows).
#
# Provider contract (consumed by Engine.Audit.ps1; see docs/PROVIDERS.md):
#   Id, DisplayName      identity
#   TempSubdir           directory created by the agent under each TEMP candidate (the "base")
#   ScopePattern         regex for first-level directories under the base (project scopes)
#   RootPattern          regex for second-level directories (session roots = the only deletable unit)
#   EnvVarNames          per-user environment variables the engine must read (registry + current process)
#   GetExtraTempDirs     { param($Profile) } -> @([pscustomobject]@{ TempPath; Source })
#   GetConfigDirs        { param($Profile) } -> [pscustomobject]@{ Dirs = @(); Known = $bool }
#   GetSessionEvidence   { param($Profile, $Snapshot) } -> [pscustomobject]@{ Readable; Unparseable; Entries = @(@{ SessionId; Pid; State; Scope; ProjectName }) }
#                          State: LIVE | LIVE_UNVERIFIED | PID_REUSED | DEAD | UNVERIFIABLE
#                          Scope/ProjectName (optional): scope directory name and display name derived from the
#                          session's working directory; used only to name projects, never for safety decisions.
#   GetActivityEvidence  { param($Profile, $Scope, $RootName) } -> [pscustomobject]@{ Readable; LastWriteUtc }
#   GetProjectKey        { param($Scope, $ProfilePath) } -> [pscustomobject]@{ IsHome; Key }
# Providers only READ. They never decide eligibility and never delete.
Set-StrictMode -Version 2.0

function ConvertTo-AtmClaudeSlug {
    param([string]$Path)
    # Claude Code project slug: every non [A-Za-z0-9] character becomes '-'.
    return [regex]::Replace($Path, '[^A-Za-z0-9]', '-')
}

function Get-AtmClaudeConfigDirs {
    param($Profile)
    $dirs = New-Object System.Collections.Generic.List[string]
    $vals = @()
    if ($Profile.EnvValues -and $Profile.EnvValues.ContainsKey('CLAUDE_CONFIG_DIR')) { $vals = @($Profile.EnvValues['CLAUDE_CONFIG_DIR']) }
    foreach ($v in $vals) { if ($v) { $dirs.Add($v) } }
    if ($dirs.Count -eq 0 -and $Profile.ProfilePath) { $dirs.Add((Join-AtmPath $Profile.ProfilePath '.claude')) }
    return [pscustomobject]@{ Dirs = @($dirs | Select-Object -Unique); Known = [bool]$Profile.EnvKnown }
}

function Get-AtmClaudeSessionEvidence {
    # Claude Code writes <configDir>\sessions\<pid>.json (pid, sessionId, procStart). Only *.json files are read;
    # *.key files and credentials are never opened. Contents are never printed or stored beyond these 3 fields.
    param($Profile, $Snapshot)
    $r = [ordered]@{ Readable = $true; Unparseable = 0; Entries = @(); Notes = @() }
    $entries = New-Object System.Collections.Generic.List[object]
    $byPid = @{}
    foreach ($p in $Snapshot.Processes) { $byPid[$p.Pid] = $p }
    foreach ($cfg in (Get-AtmClaudeConfigDirs $Profile).Dirs) {
        $dir = Join-AtmPath $cfg 'sessions'
        $files = @()
        try {
            $null = [IO.File]::GetAttributes($dir)
            $files = [IO.Directory]::GetFiles($dir, '*.json')
        } catch [IO.FileNotFoundException] { continue }
        catch [IO.DirectoryNotFoundException] { continue }
        catch { $r.Readable = $false; $r.Notes += (Get-AtmText 'note.sessionsUnreadable' $_.Exception.GetType().Name); continue }
        foreach ($f in $files) {
            if (-not $f.EndsWith('.json', [StringComparison]::OrdinalIgnoreCase)) { continue }
            $o = $null
            try { $o = [IO.File]::ReadAllText($f) | ConvertFrom-Json } catch { $r.Unparseable++; continue }
            if (-not $o -or -not ($o.PSObject.Properties.Name -contains 'sessionId') -or -not ($o.PSObject.Properties.Name -contains 'pid')) { $r.Unparseable++; continue }
            $pidVal = 0
            if (-not [int]::TryParse([string]$o.pid, [ref]$pidVal)) { $r.Unparseable++; continue }
            $state = 'DEAD'
            if ($Snapshot.Failed) { $state = 'UNVERIFIABLE' }
            elseif ($byPid.ContainsKey($pidVal)) {
                $proc = $byPid[$pidVal]
                $ps = $null
                if ($o.PSObject.Properties.Name -contains 'procStart') { $ps = [string]$o.procStart }
                # procStart is a FILETIME. A value that does not look like one (other unit, future format) must
                # never be read as "process ended": it becomes LIVE_UNVERIFIED (investigate) instead.
                $ft = 0L; $started = $null
                if ($ps -and [long]::TryParse($ps, [ref]$ft) -and $ft -gt 0) {
                    try { $started = [datetime]::FromFileTimeUtc($ft) } catch { $started = $null }
                    if ($started -and ($started -lt [datetime]'2000-01-01' -or $started -gt [datetime]::UtcNow.AddDays(1))) { $started = $null }
                }
                if ($started -and $proc.CreationUtc) {
                    $diff = [math]::Abs(($started - $proc.CreationUtc).TotalSeconds)
                    if ($diff -lt 2) { $state = 'LIVE' } else { $state = 'PID_REUSED' }
                } else { $state = 'LIVE_UNVERIFIED' }
            }
            # Project evidence: the session's working directory. Only its slug (to match the scope directory) and
            # its leaf name (display) are kept; the full path is not stored.
            $scope = $null; $projName = $null
            if ($o.PSObject.Properties.Name -contains 'cwd') {
                $cwd = ([string]$o.cwd).TrimEnd('\', '/')
                if ($cwd) { $scope = ConvertTo-AtmClaudeSlug $cwd; $projName = Split-Path -Leaf $cwd }
            }
            $entries.Add([pscustomobject]@{ SessionId = ([string]$o.sessionId).ToLowerInvariant(); Pid = $pidVal; State = $state; Scope = $scope; ProjectName = $projName })
        }
    }
    $r.Entries = $entries.ToArray()
    return [pscustomobject]$r
}

function Get-AtmClaudeActivityEvidence {
    # Session transcript <configDir>\projects\<slug>\<sessionId>.jsonl: last write time only, never content.
    param($Profile, [string]$Scope, [string]$RootName)
    $res = [ordered]@{ Readable = $true; LastWriteUtc = $null }
    foreach ($cfg in (Get-AtmClaudeConfigDirs $Profile).Dirs) {
        $pd = Join-AtmPath (Join-AtmPath $cfg 'projects') $Scope
        $f = Join-AtmPath $pd ($RootName + '.jsonl')
        try {
            $fi = New-Object IO.FileInfo($f)
            if ($fi.Exists) {
                if (-not $res.LastWriteUtc -or $fi.LastWriteTimeUtc -gt $res.LastWriteUtc) { $res.LastWriteUtc = $fi.LastWriteTimeUtc }
            } elseif ([IO.Directory]::Exists($pd)) {
                # Distinguish "absent" from "cannot look": the project directory must be listable.
                try { [void][IO.Directory]::GetFiles($pd, ($RootName + '*')) } catch { $res.Readable = $false }
            }
        } catch { $res.Readable = $false }
    }
    return [pscustomobject]$res
}

Register-AtmProvider ([pscustomobject]@{
        Id                  = 'claude-code'
        DisplayName         = 'Claude Code'
        TempSubdir          = 'claude'
        ScopePattern        = '^[A-Za-z0-9-]+$'
        RootPattern         = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
        EnvVarNames         = @('CLAUDE_CODE_TMPDIR', 'CLAUDE_CONFIG_DIR')
        GetExtraTempDirs    = {
            param($Profile)
            $out = @()
            if ($Profile.EnvValues -and $Profile.EnvValues.ContainsKey('CLAUDE_CODE_TMPDIR')) {
                foreach ($v in @($Profile.EnvValues['CLAUDE_CODE_TMPDIR'])) { if ($v) { $out += [pscustomobject]@{ TempPath = $v; Source = 'CLAUDE_CODE_TMPDIR' } } }
            }
            return $out
        }
        GetConfigDirs       = { param($Profile) Get-AtmClaudeConfigDirs $Profile }
        GetSessionEvidence  = { param($Profile, $Snapshot) Get-AtmClaudeSessionEvidence -Profile $Profile -Snapshot $Snapshot }
        GetActivityEvidence = { param($Profile, $Scope, $RootName) Get-AtmClaudeActivityEvidence -Profile $Profile -Scope $Scope -RootName $RootName }
        GetProjectKey       = {
            param($Scope, $ProfilePath)
            if ($ProfilePath) {
                $ps = ConvertTo-AtmClaudeSlug $ProfilePath
                if ($Scope.StartsWith($ps, [StringComparison]::OrdinalIgnoreCase)) {
                    $rest = $Scope.Substring($ps.Length)
                    return [pscustomobject]@{ IsHome = ($rest -eq ''); Key = $rest }
                }
            }
            return [pscustomobject]@{ IsHome = $false; Key = $Scope }
        }
    })
