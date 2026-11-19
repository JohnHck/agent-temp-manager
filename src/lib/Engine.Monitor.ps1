# AgentTempManager MONITORING ENGINE (V0.5, docs/adr/ADR-0017, phase M1): the collector and the storage of the preventive
# monitoring history. Depends on Engine.Audit.ps1: a collection runs the audit and nothing else (V05-D8 (a)). No terminal
# output of its own; presentation lives in Report.ps1. Nothing here schedules anything (phase M3) or removes the history
# or the folder on request (phase M4). Phase M2 adds the trends, the thresholds (monitor.json, read only) and the alerts:
# pure functions over what the reader found, computed only with the gate open; an alert NAMES a command and runs none.
#
# With the monitoring gate closed (every distributed copy) nothing is collected, created or written: the collector, the
# folder, the writer, the rotation and the single removal function return MONITORING_GATE_CLOSED before anything else,
# and the collector takes no mutex and calls no audit. Reading the history needs no gate, so a leftover stays visible.
#
# A record (schema atm.monitor/1, one new file per collection, never appended to) keeps aggregates only, the values the
# audit already shows locally (ADR-0017 section 1, rows 1 to 6; row 8 as NOT_OBSERVABLE, never zero; row 9 not collected):
# the collection header, the coverage counts, the base states counted per provider, and per group (provider, project
# display name (V05-D5 (a)), class) the sizes, the age and the flag counts. It NEVER keeps a SID, an account name, a
# profile, temporary, base or partition path, a slug, a partition name, the machine name, the identity block, an error
# or reparse sample, a command line, a process id, a service account or a VM name.
Set-StrictMode -Version 2.0

# MONITORING GATE (V0.5, ADR-0017 section 5, the ninth release gate): preventive monitoring is DISABLED. There is
# deliberately no switch, environment variable, config file or UI option to change this: enabling it requires a code
# change in this administrator-owned, manifest-verified file, released under a specific authorization. Only the
# automated test suite flips it, inside its own process.
$script:AtmMonitoringEnabled = $false

# The record and its bounds (V05-D3 (a)): 16 KB per record, at most 64 groups (the rest summed into one "other" group).
$script:AtmMonitorSchema = 'atm.monitor/1'
$script:AtmMonitorMaxRecordBytes = 16384
$script:AtmMonitorMaxGroups = 64
# Retention of the history (V05-D3 (a), V05-D4 (a)): 90 days, 400 files and 8 MB, whichever comes first; a leftover
# .partial file (a run that was ended) is removed once it is older than a day.
$script:AtmMonitorRetentionDays = 90
$script:AtmMonitorMaxFiles = 400
$script:AtmMonitorMaxTotalBytes = 8MB
$script:AtmMonitorPartialMaxAgeHours = 24
# Closed lists of the record.
$script:AtmMonitorOutcomes = @('OK', 'INCOMPLETE', 'AUDIT_FAILED')
$script:AtmMonitorBaseStates = @('OK', 'NOT_FOUND', 'NOT_DIRECTORY', 'INACCESSIBLE', 'POLICY_REFUSED', 'OTHER')
$script:AtmMonitorGroupFields = @('provider', 'project', 'projectIdentified', 'class', 'other', 'partitions', 'files', 'bytes', 'allocatedBytes', 'complete', 'ageHours', 'reparsePartitions', 'readErrorPartitions', 'incompletePartitions')
$script:AtmMonitorClasses = @('ACTIVE_EVIDENCE', 'RECENT', 'ORPHAN_SUSPECTED', 'LIVENESS_UNKNOWN', 'NOT_SCANNED', 'UNCLASSIFIED')
# The names of the product's history files: <UTC time>-<8 random hex digits>.json, and the same with .partial while the
# file is being written. The UTC time is fixed in form, so the names sort as the times do.
$script:AtmMonitorTimeFormat = "yyyyMMdd'T'HHmmssfff'Z'"
$script:AtmMonitorNamePattern = '^(\d{8}T\d{9}Z)-([0-9a-f]{8})\.json$'
$script:AtmMonitorPartialPattern = '^(\d{8}T\d{9}Z)-([0-9a-f]{8})\.json\.partial$'
# The folder, next to the quarantine root, outside every audited base: %LOCALAPPDATA%\AgentTempManager\Monitor.
$script:AtmMonitorFolderName = 'Monitor'
# The per-user mutex of the collectors: the prefix, then 16 hex digits of SHA-256 of the user's SID. It is not the clean
# lock (B8): monitoring changes nothing, so it never blocks or waits for a clean, an isolation or a recovery.
$script:AtmMonitorMutexPrefix = 'Global\AgentTempManager.Monitor-'
# The alert thresholds (V05-D10 (a), phase M2): monitor.json in the history folder, per user, written by the user only.
# The product never writes, creates or fixes it. Each field has a default and bounds fixed here; a value outside them
# refuses the whole file. Only failedCollections must be a whole number.
$script:AtmMonitorConfigName = 'monitor.json'
$script:AtmMonitorConfigMaxBytes = 4096
$script:AtmMonitorConfigFields = @(
    [pscustomobject]@{ Name = 'totalGiB'; Default = 20.0; Min = 1.0; Max = 4096.0; Integer = $false }
    [pscustomobject]@{ Name = 'growthGiBPerDay'; Default = 2.0; Min = 0.1; Max = 1024.0; Integer = $false }
    [pscustomobject]@{ Name = 'orphanSuspectedGiB'; Default = 5.0; Min = 1.0; Max = 4096.0; Integer = $false }
    [pscustomobject]@{ Name = 'livenessUnknownGiB'; Default = 5.0; Min = 1.0; Max = 4096.0; Integer = $false }
    [pscustomobject]@{ Name = 'failedCollections'; Default = 3.0; Min = 2.0; Max = 30.0; Integer = $true }
)
# The trends (ADR-0017 section 4): a fixed window of 7 days up to the newest record (no key changes it); fewer than 4
# points, or points that span less than 24 hours, are INSUFFICIENT_DATA; monitor status lists at most 5 groups.
$script:AtmMonitorTrendWindowDays = 7
$script:AtmMonitorTrendMinPoints = 4
$script:AtmMonitorTrendMinSpanHours = 24
$script:AtmMonitorTrendTopGroups = 5
# The alerts (phase M2) and the commands each one NAMES. A command is never run: the text only tells the user what to
# run. MON_CONFIG_INVALID names the format in docs/USAGE.md instead. MON_RECOVERY is out of the V0.5 (V05-D8 (a)).
$script:AtmMonitorAlertCommands = [ordered]@{
    MON_TOTAL            = @('agent-temp preview', 'agent-temp clean')
    MON_GROWTH           = @('agent-temp audit')
    MON_ORPHAN_SUSPECTED = @('agent-temp preview', 'agent-temp isolate')
    MON_LIVENESS_UNKNOWN = @('agent-temp diagnose')
    MON_COLLECTION       = @('agent-temp monitor status')
    MON_CONFIG_INVALID   = @()
}

# Test seams, a single assignment each, all $null in every distributed copy: the CLI never sets them. The suite replaces
# them inside its own process only.
#   clock: a scriptblock that returns the UTC time of a collection;
#   folder: the history folder (a folder of the suite's sandbox);
#   audit: a scriptblock param($InventoryArgs) that returns an inventory;
#   random: a scriptblock that returns the 8 hex digits of a name;
#   mutex: the mutex name (a test name of the suite's own);
#   owner: a scriptblock param($Path) that returns the owner SID of a history file.
$script:AtmMonitorClockSource = $null
$script:AtmMonitorFolderPath = $null
$script:AtmMonitorAuditSource = $null
$script:AtmMonitorRandomSource = $null
$script:AtmMonitorMutexName = $null
$script:AtmMonitorOwnerSource = $null

function Get-AtmMonitorUtcNow {
    if ($null -ne $script:AtmMonitorClockSource) {
        $t = [datetime](& $script:AtmMonitorClockSource)
        if ($t.Kind -eq [DateTimeKind]::Unspecified) { $t = [datetime]::SpecifyKind($t, [DateTimeKind]::Utc) }
        return $t.ToUniversalTime()
    }
    return [datetime]::UtcNow
}

function ConvertTo-AtmMonitorTimeText {
    param([datetime]$Utc)
    return $Utc.ToUniversalTime().ToString($script:AtmMonitorTimeFormat, [Globalization.CultureInfo]::InvariantCulture)
}

function ConvertFrom-AtmMonitorTimeText {
    # The UTC time of the fixed form, or $null.
    param([string]$Text)
    if ($Text -cnotmatch '^\d{8}T\d{9}Z$') { return $null }
    $d = [datetime]::MinValue
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    if ([datetime]::TryParseExact($Text, $script:AtmMonitorTimeFormat, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { return $d }
    return $null
}

function Get-AtmMonitorFolder {
    # The history folder of the process user, or the suite's sandbox folder (test seam). $null when it cannot be known.
    if ($null -ne $script:AtmMonitorFolderPath) { return [string]$script:AtmMonitorFolderPath }
    $la = [Environment]::GetFolderPath('LocalApplicationData')
    if (-not $la) { return $null }
    return (Join-Path $la ('AgentTempManager\' + $script:AtmMonitorFolderName))
}

function Get-AtmMonitorIdentity {
    # The user SID of this process's token, and the owners a file created by this process can have: that user, or the
    # token's default owner (the Administrators group for an elevated administrator).
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $sid = [string]$id.User.Value
        $owners = @($sid)
        if ($null -ne $id.Owner -and $owners -cnotcontains [string]$id.Owner.Value) { $owners += [string]$id.Owner.Value }
        return [pscustomobject]@{ Sid = $sid; Owners = $owners }
    } finally { $id.Dispose() }
}

function Get-AtmMonitorMutexName {
    # The per-user mutex name (or the suite's test name). The SID never appears in it, only a hash.
    param([string]$Sid)
    if ($null -ne $script:AtmMonitorMutexName) { return [string]$script:AtmMonitorMutexName }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Sid)) } finally { $sha.Dispose() }
    return ($script:AtmMonitorMutexPrefix + (-join @($h[0..7] | ForEach-Object { $_.ToString('x2') })))
}

function New-AtmMonitorSuffix {
    # The 8 random hex digits of a new name (or the suite's test value).
    if ($null -ne $script:AtmMonitorRandomSource) { return [string](& $script:AtmMonitorRandomSource) }
    $b = New-Object byte[] 4
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($b) } finally { $rng.Dispose() }
    return (-join @($b | ForEach-Object { $_.ToString('x2') }))
}

function Get-AtmMonitorValue {
    # A property of an inventory object or a dictionary, $null when it does not exist (strict mode safe).
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

function Get-AtmMonitorFileOwner {
    # The owner SID of a history file, or $null when it cannot be read.
    param([string]$Path)
    if ($null -ne $script:AtmMonitorOwnerSource) { return [string](& $script:AtmMonitorOwnerSource $Path) }
    try { return [string](Get-Acl -LiteralPath $Path -ErrorAction Stop).GetOwner([Security.Principal.SecurityIdentifier]).Value } catch { return $null }
}

# ---------------------------------------------------------------------------------------------
# The record
# ---------------------------------------------------------------------------------------------

function Get-AtmMonitorCoverage {
    # Row 2: whether the coverage is complete, and counts of profiles; never which profiles.
    param($Inventory)
    return [ordered]@{
        complete                = [bool](Get-AtmMonitorValue $Inventory 'CoverageComplete')
        processCoverageComplete = [bool](Get-AtmMonitorValue $Inventory 'ProcessCoverageComplete')
        profilesInaccessible    = [long]@(Get-AtmInventoryProfileList -Inventory $Inventory -Name 'InaccessibleProfiles').Count
        profilesTempUnverified  = [long]@(Get-AtmInventoryProfileList -Inventory $Inventory -Name 'UnverifiedTempProfiles').Count
        profilesNotAudited      = [long]@(Get-AtmInventoryProfileList -Inventory $Inventory -Name 'NotAuditedProfiles').Count
        profilesIncomplete      = [long](Get-AtmIncompleteProfileCount -Inventory $Inventory)
    }
}

function Get-AtmMonitorBaseCounts {
    # Row 3: the bases counted per provider and state (the audit's resolved state, reduced to the closed list); never a
    # base path. An alias whose base is known is counted once, under the profile that holds the base.
    param($Inventory)
    $idx = Get-AtmBaseIndex -Bases @(Get-AtmMonitorValue $Inventory 'Bases')
    $counts = @{}
    $pbs = Get-AtmMonitorValue $Inventory 'ProfileBaseStatus'
    if ($pbs -is [System.Collections.IDictionary]) {
        foreach ($k in @($pbs.Keys)) {
            foreach ($e in @($pbs[$k])) {
                if ($null -eq $e) { continue }
                $res = @(Get-AtmResolvedBaseStates -Entries @($e) -BaseIndex $idx)
                if ($res.Count -ne 1) { continue }
                $bp = [string](Get-AtmMonitorValue $e 'BasePath')
                if ($res[0].Alias -and $bp -and $idx.ContainsKey($bp.ToLowerInvariant())) { continue }
                $r = [string]$res[0].Resolved
                $state = $(if ($script:AtmAuditedBaseStates -ccontains $r) { $r } elseif ($script:AtmInaccessibleBaseStates -ccontains $r) { 'INACCESSIBLE' } elseif ($script:AtmPolicyRefusedBaseStates -ccontains $r) { 'POLICY_REFUSED' } else { 'OTHER' })
                $prov = [string](Get-AtmMonitorValue $e 'Provider')
                $ck = $prov + "`n" + $state
                if (-not $counts.ContainsKey($ck)) { $counts[$ck] = [ordered]@{ provider = $prov; state = $state; count = 0L } }
                $counts[$ck].count = [long]$counts[$ck].count + 1
            }
        }
    }
    $keys = [string[]]@($counts.Keys)
    [Array]::Sort($keys, [StringComparer]::Ordinal)
    return @(foreach ($k in $keys) { $counts[$k] })
}

function Get-AtmMonitorGroups {
    <#
      Rows 4 to 6, per group (provider, project, class). The project is the display name the audit shows (V05-D5 (a));
      every project the audit did not identify is summed into one group (project $null, projectIdentified false). Per
      group: bytes, allocated bytes (estimate), files and partitions; "complete" when every partition of the group was
      measured completely; the age in whole hours since the newest write of the group's least recently written partition
      (never a time of a partition; $null when none has one); and counts of partitions with reparse points, read errors and
      incomplete measurement (never a sample). At most AtmMonitorMaxGroups groups, the largest first; the rest is summed
      into one group marked "other". Returns Groups and Summed (how many groups went into "other").
    #>
    param($Inventory, [datetime]$NowUtc)
    $map = @{}
    foreach ($p in @(Get-AtmMonitorValue $Inventory 'Partitions')) {
        if ($null -eq $p) { continue }
        $prov = [string](Get-AtmMonitorValue $p 'Provider')
        $ident = [bool](Get-AtmMonitorValue $p 'ProjectIdentified')
        $proj = $(if ($ident) { [string](Get-AtmMonitorValue $p 'Project') } else { $null })
        $cls = [string](Get-AtmMonitorValue $p 'Class')
        if ($script:AtmMonitorClasses -cnotcontains $cls) { $cls = 'UNCLASSIFIED' }
        $key = $prov + "`n" + $(if ($ident) { '1' + $proj } else { '0' }) + "`n" + $cls
        if (-not $map.ContainsKey($key)) {
            $map[$key] = @{ Provider = $prov; Project = $proj; Identified = $ident; Class = $cls; Bytes = 0L; Alloc = 0L; Files = 0L; Parts = 0L; Complete = $true; Oldest = $null; Reparse = 0L; Errors = 0L; Incomplete = 0L }
        }
        $g = $map[$key]
        $g.Bytes += [long](Get-AtmMonitorValue $p 'Bytes')
        $g.Alloc += [long](Get-AtmMonitorValue $p 'AllocatedBytesEstimate')
        $g.Files += [long](Get-AtmMonitorValue $p 'Files')
        $g.Parts += 1
        $measured = [bool](Get-AtmMonitorValue $p 'MeasurementComplete')
        if (-not $measured) { $g.Complete = $false; $g.Incomplete += 1 }
        if ([long](Get-AtmMonitorValue $p 'ReparsePoints') -gt 0) { $g.Reparse += 1 }
        if ([long](Get-AtmMonitorValue $p 'ErrorCount') -gt 0) { $g.Errors += 1 }
        $nw = Get-AtmMonitorValue $p 'NewestWriteTimeUtc'
        if ($null -ne $nw) {
            $nwu = ([datetime]$nw).ToUniversalTime()
            if ($null -eq $g.Oldest -or $nwu -lt $g.Oldest) { $g.Oldest = $nwu }
        }
    }
    # The largest first; equal sizes in the ordinal order of their key, so the cut is the same on every machine.
    $sortKeys = [string[]]@(foreach ($k in $map.Keys) { ([long]::MaxValue - [long]$map[$k].Bytes).ToString('D19', [Globalization.CultureInfo]::InvariantCulture) + "`n" + $k })
    [Array]::Sort($sortKeys, [StringComparer]::Ordinal)
    # One group is an array in the order of AtmMonitorGroupFields (the record names the order once, in "groupFields"),
    # so 64 groups fit in 16 KB.
    $toRecord = {
        param($G, [bool]$Other)
        $age = $null
        if ($null -ne $G.Oldest) { $age = [long][math]::Max(0, [math]::Floor(($NowUtc - $G.Oldest).TotalHours)) }
        return , [object[]]@(
            $(if ($Other) { $null } else { $G.Provider }), $(if ($Other) { $null } else { $G.Project }),
            $(if ($Other) { $false } else { [bool]$G.Identified }), $(if ($Other) { $null } else { $G.Class }),
            $Other, [long]$G.Parts, [long]$G.Files, [long]$G.Bytes, [long]$G.Alloc, [bool]$G.Complete, $age,
            [long]$G.Reparse, [long]$G.Errors, [long]$G.Incomplete)
    }
    $groups = New-Object System.Collections.Generic.List[object]
    $rest = $null
    $summed = 0
    for ($i = 0; $i -lt $sortKeys.Length; $i++) {
        $g = $map[$sortKeys[$i].Substring(20)]
        if ($i -lt $script:AtmMonitorMaxGroups) { $groups.Add((& $toRecord $g $false)); continue }
        $summed++
        if ($null -eq $rest) { $rest = @{ Bytes = 0L; Alloc = 0L; Files = 0L; Parts = 0L; Complete = $true; Oldest = $null; Reparse = 0L; Errors = 0L; Incomplete = 0L } }
        foreach ($f in @('Bytes', 'Alloc', 'Files', 'Parts', 'Reparse', 'Errors', 'Incomplete')) { $rest[$f] = [long]$rest[$f] + [long]$g[$f] }
        if (-not $g.Complete) { $rest.Complete = $false }
        if ($null -ne $g.Oldest -and ($null -eq $rest.Oldest -or $g.Oldest -lt $rest.Oldest)) { $rest.Oldest = $g.Oldest }
    }
    if ($null -ne $rest) { $groups.Add((& $toRecord $rest $true)) }
    return [pscustomobject]@{ Groups = $groups.ToArray(); Summed = [long]$summed }
}

function New-AtmMonitorRecord {
    # The record of one collection, without its hash. -Inventory $null: the audit failed (outcome AUDIT_FAILED, the
    # exception's type name only in -Failure), with no coverage, bases or groups.
    param($Inventory, [datetime]$Utc, [long]$DurationMs, [long]$AuditMs, [string]$Failure, [string]$Previous)
    $rec = [ordered]@{
        schema = $script:AtmMonitorSchema; utc = (ConvertTo-AtmMonitorTimeText $Utc); toolVersion = [string]$script:AtmVersion
        outcome = 'AUDIT_FAILED'; failure = $(if ($Failure) { $Failure } else { $null })
        durationMs = $DurationMs; auditMs = $AuditMs; previous = $(if ($Previous) { $Previous } else { $null })
        coverage = $null; bases = @(); groupFields = $script:AtmMonitorGroupFields; groups = @(); groupsSummed = 0L
        # Row 8: the worktrees are not observable while their gate is closed; never zero. Row 9: not collected.
        worktrees = 'NOT_OBSERVABLE'; holders = 'NOT_COLLECTED'
    }
    if ($null -ne $Inventory) {
        $gr = Get-AtmMonitorGroups -Inventory $Inventory -NowUtc $Utc
        $rec.coverage = Get-AtmMonitorCoverage -Inventory $Inventory
        $rec.bases = @(Get-AtmMonitorBaseCounts -Inventory $Inventory)
        $rec.groups = [object[]]$gr.Groups
        $rec.groupsSummed = $gr.Summed
        $complete = [bool]$rec.coverage.complete
        foreach ($g in $gr.Groups) { if (-not $g[9]) { $complete = $false } }
        $rec.outcome = $(if ($complete) { 'OK' } else { 'INCOMPLETE' })
    }
    return $rec
}

function ConvertTo-AtmMonitorRecordText {
    <#
      The text of a record file: the record as compact JSON, with "sha256" as its last member. The hash is SHA-256 of the
      UTF-8 bytes of the same text with the 64 hex digits of the hash replaced by zeros, so it is checked on the stored
      bytes and never on a re-serialization. It detects accidental damage, NOT forgery: anyone with the user's rights can
      write the folder and recompute it. That is acceptable only because the history authorizes nothing.
    #>
    param([System.Collections.IDictionary]$Record)
    $body = ConvertTo-Json -InputObject $Record -Compress -Depth 6
    $t0 = $body.Substring(0, $body.Length - 1) + ',"sha256":"' + ('0' * 64) + '"}'
    return ($t0.Substring(0, $t0.Length - 66) + (Get-AtmMonitorTextHash $t0) + '"}')
}

function Get-AtmMonitorTextHash {
    param([string]$Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash((New-Object Text.UTF8Encoding($false)).GetBytes($Text)) } finally { $sha.Dispose() }
    return (-join @($h | ForEach-Object { $_.ToString('x2') }))
}

function Test-AtmMonitorHash {
    param([string]$Text)
    $m = [regex]::Match($Text, ',"sha256":"([0-9a-f]{64})"\}$')
    if (-not $m.Success) { return $false }
    $t0 = $Text.Substring(0, $m.Groups[1].Index) + ('0' * 64) + '"}'
    return ((Get-AtmMonitorTextHash $t0) -ceq $m.Groups[1].Value)
}

function Test-AtmMonitorKeys {
    # Exactly these members, no other (names compared with case).
    param($Object, [string[]]$Keys)
    if ($null -eq $Object -or $Object -isnot [System.Management.Automation.PSCustomObject]) { return $false }
    $names = @($Object.PSObject.Properties | ForEach-Object { [string]$_.Name })
    if ($names.Count -ne $Keys.Count) { return $false }
    foreach ($k in $Keys) { if ($names -cnotcontains $k) { return $false } }
    return $true
}

function Test-AtmMonitorInteger {
    # A whole number (as either shell's JSON reader returns it) of at least -Min.
    param($Value, [long]$Min = 0)
    if ($null -eq $Value -or $Value -is [bool] -or $Value -is [string]) { return $false }
    if ($Value -is [int] -or $Value -is [long]) { return ([long]$Value -ge $Min) }
    if ($Value -is [decimal] -or $Value -is [double]) { return ($Value -eq [math]::Floor($Value) -and $Value -ge $Min -and $Value -le [long]::MaxValue) }
    return $false
}

function Test-AtmMonitorRecordText {
    <#
      Checks one record file read as text against its name: size, hash, JSON, the exact members of the schema, their
      types and closed lists, and the time of the name. Returns Valid, Reason (a short code of the first failure), Record
      (the parsed record) and Utc (the record's time). A record that fails is never read as zero: the reader skips it and
      counts it as HISTORY_RECORD_INVALID.
    #>
    param([string]$Text, [string]$Name)
    $bad = { param([string]$Why) [pscustomobject]@{ Valid = $false; Reason = $Why; Record = $null; Utc = $null } }
    $nm = [regex]::Match([string]$Name, $script:AtmMonitorNamePattern)
    if (-not $nm.Success) { return (& $bad 'NAME') }
    $nameUtc = ConvertFrom-AtmMonitorTimeText $nm.Groups[1].Value
    if ($null -eq $nameUtc) { return (& $bad 'NAME_TIME') }
    if ($null -eq $Text -or (New-Object Text.UTF8Encoding($false)).GetByteCount($Text) -gt $script:AtmMonitorMaxRecordBytes) { return (& $bad 'SIZE') }
    if (-not (Test-AtmMonitorHash $Text)) { return (& $bad 'HASH') }
    $o = $null
    try { $o = ConvertFrom-Json -InputObject $Text -ErrorAction Stop } catch { return (& $bad 'JSON') }
    $top = @('schema', 'utc', 'toolVersion', 'outcome', 'failure', 'durationMs', 'auditMs', 'previous', 'coverage', 'bases', 'groupFields', 'groups', 'groupsSummed', 'worktrees', 'holders', 'sha256')
    if (-not (Test-AtmMonitorKeys $o $top)) { return (& $bad 'MEMBERS') }
    if ($o.schema -isnot [string] -or $o.schema -cne $script:AtmMonitorSchema) { return (& $bad 'SCHEMA') }
    if ($o.utc -isnot [string] -or $o.utc -cne $nm.Groups[1].Value) { return (& $bad 'UTC') }
    if ($o.toolVersion -isnot [string] -or $o.toolVersion -cnotmatch '^[0-9A-Za-z.+-]{1,32}$') { return (& $bad 'VERSION') }
    if ($o.outcome -isnot [string] -or $script:AtmMonitorOutcomes -cnotcontains $o.outcome) { return (& $bad 'OUTCOME') }
    if ($null -ne $o.failure -and ($o.failure -isnot [string] -or $o.failure -cnotmatch '^[A-Za-z][A-Za-z0-9_]{0,127}$')) { return (& $bad 'FAILURE') }
    if (($o.outcome -ceq 'AUDIT_FAILED') -ne ($null -ne $o.failure)) { return (& $bad 'FAILURE') }
    if (-not (Test-AtmMonitorInteger $o.durationMs) -or -not (Test-AtmMonitorInteger $o.auditMs)) { return (& $bad 'DURATION') }
    if ($null -ne $o.previous -and ($o.previous -isnot [string] -or $o.previous -cnotmatch $script:AtmMonitorNamePattern)) { return (& $bad 'PREVIOUS') }
    if ($o.worktrees -isnot [string] -or $o.worktrees -cne 'NOT_OBSERVABLE' -or $o.holders -isnot [string] -or $o.holders -cne 'NOT_COLLECTED') { return (& $bad 'NOT_COLLECTED_ROWS') }
    if (-not (Test-AtmMonitorInteger $o.groupsSummed)) { return (& $bad 'GROUPS_SUMMED') }
    if ($o.bases -isnot [System.Array] -or $o.groups -isnot [System.Array]) { return (& $bad 'ARRAYS') }
    if ($o.outcome -ceq 'AUDIT_FAILED') {
        if ($null -ne $o.coverage -or $o.bases.Count -ne 0 -or $o.groups.Count -ne 0 -or [long]$o.groupsSummed -ne 0) { return (& $bad 'AUDIT_FAILED_CONTENT') }
    } else {
        $cov = $o.coverage
        if (-not (Test-AtmMonitorKeys $cov @('complete', 'processCoverageComplete', 'profilesInaccessible', 'profilesTempUnverified', 'profilesNotAudited', 'profilesIncomplete'))) { return (& $bad 'COVERAGE') }
        if ($cov.complete -isnot [bool] -or $cov.processCoverageComplete -isnot [bool]) { return (& $bad 'COVERAGE') }
        foreach ($f in @('profilesInaccessible', 'profilesTempUnverified', 'profilesNotAudited', 'profilesIncomplete')) { if (-not (Test-AtmMonitorInteger $cov.$f)) { return (& $bad 'COVERAGE') } }
    }
    if ($o.bases.Count -gt 64) { return (& $bad 'BASES') }
    foreach ($b in $o.bases) {
        if (-not (Test-AtmMonitorKeys $b @('provider', 'state', 'count'))) { return (& $bad 'BASES') }
        if ($b.provider -isnot [string] -or $b.provider -cnotmatch '^[A-Za-z0-9-]{1,64}$' -or $b.state -isnot [string] -or $script:AtmMonitorBaseStates -cnotcontains $b.state -or -not (Test-AtmMonitorInteger $b.count 1)) { return (& $bad 'BASES') }
    }
    if ($o.groupFields -isnot [System.Array] -or (@($o.groupFields) -join ',') -cne ($script:AtmMonitorGroupFields -join ',')) { return (& $bad 'GROUP_FIELDS') }
    if ($o.groups.Count -gt ($script:AtmMonitorMaxGroups + 1)) { return (& $bad 'GROUPS') }
    $others = 0
    foreach ($g in $o.groups) {
        # The members in the order of groupFields: 0 provider, 1 project, 2 projectIdentified, 3 class, 4 other,
        # 5 partitions, 6 files, 7 bytes, 8 allocatedBytes, 9 complete, 10 ageHours, 11 reparsePartitions,
        # 12 readErrorPartitions, 13 incompletePartitions.
        if ($g -isnot [System.Array] -or $g.Count -ne $script:AtmMonitorGroupFields.Count) { return (& $bad 'GROUPS') }
        if ($g[4] -isnot [bool] -or $g[2] -isnot [bool] -or $g[9] -isnot [bool]) { return (& $bad 'GROUPS') }
        if ($g[4]) {
            $others++
            if ($null -ne $g[0] -or $null -ne $g[1] -or $null -ne $g[3] -or $g[2]) { return (& $bad 'GROUPS') }
        } else {
            if ($g[0] -isnot [string] -or $g[0] -cnotmatch '^[A-Za-z0-9-]{1,64}$') { return (& $bad 'GROUPS') }
            if ($g[3] -isnot [string] -or $script:AtmMonitorClasses -cnotcontains $g[3]) { return (& $bad 'GROUPS') }
            if ($g[2] -and $g[1] -isnot [string]) { return (& $bad 'GROUPS') }
            if (-not $g[2] -and $null -ne $g[1]) { return (& $bad 'GROUPS') }
        }
        foreach ($i in @(6, 7, 8, 11, 12, 13)) { if (-not (Test-AtmMonitorInteger $g[$i])) { return (& $bad 'GROUPS') } }
        if (-not (Test-AtmMonitorInteger $g[5] 1)) { return (& $bad 'GROUPS') }
        if ($null -ne $g[10] -and -not (Test-AtmMonitorInteger $g[10])) { return (& $bad 'GROUPS') }
    }
    if ($others -gt 1 -or (($others -eq 1) -ne ([long]$o.groupsSummed -gt 0))) { return (& $bad 'GROUPS') }
    if ($o.sha256 -isnot [string]) { return (& $bad 'HASH') }
    return [pscustomobject]@{ Valid = $true; Reason = $null; Record = $o; Utc = $nameUtc }
}

# ---------------------------------------------------------------------------------------------
# The history folder, the writer and the rotation (every one checks the gate first)
# ---------------------------------------------------------------------------------------------

function Open-AtmMonitorFolder {
    <#
      The history folder, pinned like the folder of a T1 log. When it is missing it is created (at most two levels: the
      product folder and the history folder) as new folders relative to pinned parents (AtmSafeCreate.CreateNewDirectory:
      never an existing name, never through a reparse point, a protected DACL of the new object only: owner, SYSTEM and
      Administrators). It is then checked as a record folder (AtmCleanLog's folder rule: no reparse point in its chain,
      owned by the user (or SYSTEM, Administrators), no other principal that can add, remove or re-permission) and never
      fixed. Returns $null, or a code; nothing is written when it refuses.
    #>
    param([string]$Path, [string]$UserSid)
    if (-not $script:AtmMonitoringEnabled) { return 'MONITORING_GATE_CLOSED' }
    if (-not $Path -or $Path -cnotmatch '^[A-Za-z]:\\' -or $Path.Contains('/')) { return 'MONITOR_FOLDER_PATH_INVALID' }
    $canon = $null
    try { $canon = [IO.Path]::GetFullPath($Path).TrimEnd('\') } catch { $canon = $null }
    if (-not $canon -or -not [string]::Equals($canon, $Path.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) { return 'MONITOR_FOLDER_PATH_INVALID' }
    $parent = [IO.Path]::GetDirectoryName($canon)
    if (-not [IO.Directory]::Exists($canon)) {
        $levels = @()
        if (-not [IO.Directory]::Exists($parent)) { $levels += , @([IO.Path]::GetDirectoryName($parent), [IO.Path]::GetFileName($parent)) }
        $levels += , @($parent, [IO.Path]::GetFileName($canon))
        foreach ($lv in $levels) {
            $pin = [AgentTempManager.AtmSafeCreate]::Pin($lv[0])
            try {
                if (-not $pin.IsPinned) { return ('MONITOR_FOLDER_PARENT_' + $pin.Error) }
                $n = [AgentTempManager.AtmSafeCreate]::CreateNewDirectory($pin, $lv[1], $UserSid)
                try { if ($null -ne $n.Error -and $n.Error -cne 'EXISTS') { return ('MONITOR_FOLDER_CREATE_' + $n.Error) } } finally { $n.Dispose() }
            } finally { $pin.Dispose() }
        }
    }
    $chk = [AgentTempManager.AtmCleanLog]::Pin($canon, $UserSid)
    try { if ($null -ne $chk.Error) { return ('MONITOR_FOLDER_' + $chk.Error) } } finally { $chk.Dispose() }
    return $null
}

function Write-AtmMonitorRecordFile {
    <#
      Writes one record as a NEW file: an existing name is refused; the bytes go to <name>.partial, created relative to
      the pinned folder (AtmSafeCreate.CreateNew: never an existing name, never through a reparse point, protected DACL,
      written and flushed), then renamed to <name>. A run ended before the rename leaves only the .partial file, which no
      reader reads. The rename runs after the folder's pin is released (a pin without write sharing refuses a rename in
      the folder): in that short window the folder is not pinned, which is accepted because the history protects against
      accidental damage, not against the user's own rights (ADR-0017 section 3); the renamed file is then checked. $null,
      or a code.
    #>
    param([string]$Folder, [string]$Name, [byte[]]$Bytes)
    if (-not $script:AtmMonitoringEnabled) { return 'MONITORING_GATE_CLOSED' }
    if ([string]$Name -cnotmatch $script:AtmMonitorNamePattern -or $null -eq $Bytes) { return 'MONITOR_NAME_INVALID' }
    $final = Join-Path $Folder $Name
    $partialName = $Name + '.partial'
    if ((Get-AtmPathPresence $final) -ne $false -or (Get-AtmPathPresence (Join-Path $Folder $partialName)) -ne $false) { return 'MONITOR_NAME_EXISTS' }
    $pin = [AgentTempManager.AtmSafeCreate]::Pin($Folder)
    try {
        if (-not $pin.IsPinned) { return ('MONITOR_FOLDER_PIN_' + $pin.Error) }
        $err = [AgentTempManager.AtmSafeCreate]::CreateNew($pin, $partialName, $Bytes)
        if ($null -ne $err) { return ('MONITOR_WRITE_' + $err) }
    } finally { $pin.Dispose() }
    try { [IO.File]::Move((Join-Path $Folder $partialName), $final) } catch { return ('MONITOR_RENAME_' + (Get-AtmInnerException $_.Exception).GetType().Name) }
    try {
        $fi = New-Object IO.FileInfo($final)
        if (-not $fi.Exists -or ($fi.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or ($fi.Attributes -band [IO.FileAttributes]::Directory) -ne 0 -or $fi.Length -ne $Bytes.Length) { return 'MONITOR_RENAMED_NOT_VERIFIED' }
    } catch { return 'MONITOR_RENAMED_NOT_VERIFIED' }
    return $null
}

function Invoke-AtmMonitorPrune {
    <#
      THE ONLY REMOVAL OF THE MONITORING ENGINE (V05-D4 (a)): one file of the product's own history, by exact name, in the
      product's history folder. Immediately before the removal it checks, in this order: the gate; the name (the exact
      pattern of a record or of a .partial file); the folder (the product's history folder, with no reparse point in its
      chain); the item (a plain file, not a reparse point); its owner (the user, or the token's default owner). Any
      failure refuses with a code and removes nothing. $null when the file was removed.
    #>
    param([string]$Folder, [string]$Name, [string[]]$Owners)
    if (-not $script:AtmMonitoringEnabled) { return 'MONITORING_GATE_CLOSED' }
    if ([string]$Name -cnotmatch $script:AtmMonitorNamePattern -and [string]$Name -cnotmatch $script:AtmMonitorPartialPattern) { return 'MONITOR_PRUNE_NAME_REFUSED' }
    $expected = Get-AtmMonitorFolder
    if (-not $expected -or -not $Folder -or -not [string]::Equals($Folder.TrimEnd('\'), $expected.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) { return 'MONITOR_PRUNE_FOLDER_REFUSED' }
    $chain = Test-AtmPathChain $Folder.TrimEnd('\')
    if ($chain.Status -cne 'OK') { return ('MONITOR_PRUNE_FOLDER_' + $chain.Status) }
    $path = Join-Path $Folder.TrimEnd('\') $Name
    if (-not [string]::Equals([IO.Path]::GetDirectoryName($path), $Folder.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) { return 'MONITOR_PRUNE_FOLDER_REFUSED' }
    $a = $null
    try { $a = [IO.File]::GetAttributes($path) } catch { return ('MONITOR_PRUNE_' + (Get-AtmFileErrorKind $_.Exception)) }
    if (($a -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return 'MONITOR_PRUNE_REPARSE' }
    if (($a -band [IO.FileAttributes]::Directory) -ne 0) { return 'MONITOR_PRUNE_NOT_A_FILE' }
    $owner = Get-AtmMonitorFileOwner $path
    if (-not $owner -or @($Owners) -cnotcontains $owner) { return 'MONITOR_PRUNE_FOREIGN_OWNER' }
    try { [IO.File]::Delete($path) } catch { return ('MONITOR_PRUNE_FAILED_' + (Get-AtmInnerException $_.Exception).GetType().Name) }
    return $null
}

function Invoke-AtmMonitorRotation {
    <#
      Keeps the history bounded (V05-D3 (a), V05-D4 (a)), after a record was written: the .partial files older than a day,
      then the oldest records (by the time in their names) while a record is older than 90 days, or there are more than
      400 records, or they take more than 8 MB. The record just written (-KeepName) is never removed. Every item of the
      folder is checked first: an item with another name, a folder, a reparse point or another owner REFUSES THE WHOLE
      ROTATION with a code and removes nothing. The code is in the collector's result only: no alert of phase M2 reads it
      (the alerts are computed from the history as the reader finds it). The user's thresholds file (monitor.json) is
      accepted when it is a plain file, not a reparse point, with the expected owner, and it is NEVER removed (it is not
      in the removal plan, and Invoke-AtmMonitorPrune refuses its name). Each removal goes through
      Invoke-AtmMonitorPrune, which checks again. Returns Code ($null when nothing was refused), Removed (names), Problems
      (how many items refused it) and Kept (records kept).
    #>
    param([string]$Folder, [datetime]$NowUtc, [string[]]$Owners, [string]$KeepName)
    if (-not $script:AtmMonitoringEnabled) { return [pscustomobject]@{ Code = 'MONITORING_GATE_CLOSED'; Removed = @(); Problems = 0; Kept = 0 } }
    $out = [ordered]@{ Code = $null; Removed = @(); Problems = 0; Kept = 0 }
    $items = $null
    try { $items = @((New-Object IO.DirectoryInfo($Folder)).GetFileSystemInfos()) } catch { $out.Code = 'MONITOR_ROTATION_LIST_FAILED'; return [pscustomobject]$out }
    $finals = New-Object System.Collections.Generic.List[object]
    $partials = New-Object System.Collections.Generic.List[object]
    $problems = @{}
    foreach ($it in $items) {
        if (($it.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { $problems['MONITOR_ROTATION_REPARSE'] = 1 + [int]$problems['MONITOR_ROTATION_REPARSE']; continue }
        if (($it.Attributes -band [IO.FileAttributes]::Directory) -ne 0) { $problems['MONITOR_ROTATION_UNEXPECTED_ITEM'] = 1 + [int]$problems['MONITOR_ROTATION_UNEXPECTED_ITEM']; continue }
        if ($it.Name -ceq $script:AtmMonitorConfigName) {
            # The user's thresholds file: a plain file here (reparse points and folders were refused above) with the
            # expected owner passes, and is never planned for removal.
            $cOwner = Get-AtmMonitorFileOwner $it.FullName
            if (-not $cOwner -or @($Owners) -cnotcontains $cOwner) { $problems['MONITOR_ROTATION_FOREIGN_OWNER'] = 1 + [int]$problems['MONITOR_ROTATION_FOREIGN_OWNER'] }
            continue
        }
        $mf = [regex]::Match($it.Name, $script:AtmMonitorNamePattern)
        $mp = [regex]::Match($it.Name, $script:AtmMonitorPartialPattern)
        $t = $null
        if ($mf.Success) { $t = ConvertFrom-AtmMonitorTimeText $mf.Groups[1].Value } elseif ($mp.Success) { $t = ConvertFrom-AtmMonitorTimeText $mp.Groups[1].Value }
        if ($null -eq $t) { $problems['MONITOR_ROTATION_UNEXPECTED_ITEM'] = 1 + [int]$problems['MONITOR_ROTATION_UNEXPECTED_ITEM']; continue }
        $owner = Get-AtmMonitorFileOwner $it.FullName
        if (-not $owner -or @($Owners) -cnotcontains $owner) { $problems['MONITOR_ROTATION_FOREIGN_OWNER'] = 1 + [int]$problems['MONITOR_ROTATION_FOREIGN_OWNER']; continue }
        $entry = [pscustomobject]@{ Name = $it.Name; Utc = $t; Length = [long]$it.Length }
        if ($mf.Success) { $finals.Add($entry) } else { $partials.Add($entry) }
    }
    if ($problems.Count -gt 0) {
        foreach ($c in @('MONITOR_ROTATION_REPARSE', 'MONITOR_ROTATION_FOREIGN_OWNER', 'MONITOR_ROTATION_UNEXPECTED_ITEM')) { if ($problems.ContainsKey($c)) { $out.Code = $c; break } }
        $out.Problems = [int](($problems.Values | Measure-Object -Sum).Sum)
        return [pscustomobject]$out
    }
    $plan = New-Object System.Collections.Generic.List[string]
    foreach ($p in $partials) { if (($NowUtc - $p.Utc).TotalHours -gt $script:AtmMonitorPartialMaxAgeHours) { $plan.Add($p.Name) } }
    $names = [string[]]@($finals | ForEach-Object { $_.Name })
    [Array]::Sort($names, [StringComparer]::Ordinal)
    $byName = @{}; foreach ($f in $finals) { $byName[$f.Name] = $f }
    $keep = New-Object System.Collections.Generic.List[object]
    foreach ($n in $names) { $keep.Add($byName[$n]) }
    $total = [long]0; foreach ($k in $keep) { $total += $k.Length }
    $cut = $NowUtc.AddDays(-$script:AtmMonitorRetentionDays)
    $i = 0
    while ($i -lt $keep.Count) {
        $k = $keep[$i]
        $over = ($k.Utc -lt $cut) -or ($keep.Count -gt $script:AtmMonitorMaxFiles) -or ($total -gt $script:AtmMonitorMaxTotalBytes)
        if (-not $over) { break }
        if ($k.Name -ceq $KeepName) { $i++; continue }
        $plan.Add($k.Name); $total -= $k.Length; $keep.RemoveAt($i)
    }
    $removed = New-Object System.Collections.Generic.List[string]
    foreach ($n in $plan) {
        $c = Invoke-AtmMonitorPrune -Folder $Folder -Name $n -Owners $Owners
        if ($null -ne $c) { $out.Code = $c; break }
        $removed.Add($n)
    }
    $out.Removed = $removed.ToArray()
    $out.Kept = $keep.Count
    return [pscustomobject]$out
}

# ---------------------------------------------------------------------------------------------
# The collector
# ---------------------------------------------------------------------------------------------

function Get-AtmMonitorNewestName {
    # The newest record name in the folder (the greatest name, which is the latest time), or $null. Read only.
    param([string]$Folder)
    $items = $null
    try { $items = @((New-Object IO.DirectoryInfo($Folder)).GetFiles()) } catch { return $null }
    $names = [string[]]@($items | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and $_.Name -cmatch $script:AtmMonitorNamePattern } | ForEach-Object { $_.Name })
    if ($names.Length -eq 0) { return $null }
    [Array]::Sort($names, [StringComparer]::Ordinal)
    return $names[$names.Length - 1]
}

function Invoke-AtmMonitorCollection {
    <#
      One collection (ADR-0017 sections 1 and 3). With the gate closed: MONITORING_GATE_CLOSED, before anything else (no
      audit, no folder, no mutex, nothing written). Past the gate:
        1. the per-user mutex, without waiting: busy is MONITOR_BUSY with nothing written (an abandoned one is taken);
        2. the audit only (V05-D8 (a)): Invoke-AtmInventory with -InventoryArgs (or the audit seam); a failure becomes a
           record with outcome AUDIT_FAILED and the exception's type name only;
        3. the record (New-AtmMonitorRecord), with "previous": the newest record name present before this one, so the
           reader can tell a collection whose time is earlier than the one before it (CLOCK_SKEW);
        4. above 16 KB: MONITOR_RECORD_TOO_LARGE, nothing written;
        5. the folder (Open-AtmMonitorFolder), the new file (Write-AtmMonitorRecordFile), then the rotation.
      Returns Code (OK when the record was written), Outcome, File (the name), Bytes, AuditMs, TotalMs, Rotation and
      MutexAbandoned.
    #>
    param([hashtable]$InventoryArgs = @{})
    if (-not $script:AtmMonitoringEnabled) { return [pscustomobject]@{ Code = 'MONITORING_GATE_CLOSED'; Outcome = $null; File = $null; Bytes = 0; AuditMs = 0L; TotalMs = 0L; Rotation = $null; MutexAbandoned = $false } }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $state = @{ Code = $null; Outcome = $null; File = $null; Bytes = 0; AuditMs = 0L; TotalMs = 0L; Rotation = $null; MutexAbandoned = $false }
    $ident = $null
    try { $ident = Get-AtmMonitorIdentity } catch { $ident = $null }
    if ($null -eq $ident -or -not $ident.Sid) { $state.Code = 'MONITOR_IDENTITY_UNAVAILABLE' }
    else {
        $mutex = $null; $held = $false
        try { $mutex = New-Object System.Threading.Mutex($false, (Get-AtmMonitorMutexName -Sid $ident.Sid)) } catch { $state.Code = 'MONITOR_MUTEX_' + (Get-AtmInnerException $_.Exception).GetType().Name }
        if ($null -ne $mutex) {
            try {
                try { $held = $mutex.WaitOne(0) }
                catch {
                    $inner = Get-AtmInnerException $_.Exception
                    if ($inner -is [Threading.AbandonedMutexException]) { $held = $true; $state.MutexAbandoned = $true }
                    else { $state.Code = 'MONITOR_MUTEX_' + $inner.GetType().Name }
                }
                if ($held) { Invoke-AtmMonitorCollectionCore -State $state -Identity $ident -InventoryArgs $InventoryArgs -Stopwatch $sw }
                elseif ($null -eq $state.Code) { $state.Code = 'MONITOR_BUSY' }
            } finally {
                if ($held) { try { $mutex.ReleaseMutex() } catch { $null = $_ } }
                $mutex.Dispose()
            }
        }
    }
    $sw.Stop()
    $state.TotalMs = [long]$sw.ElapsedMilliseconds
    return [pscustomobject]@{ Code = $state.Code; Outcome = $state.Outcome; File = $state.File; Bytes = $state.Bytes; AuditMs = $state.AuditMs; TotalMs = $state.TotalMs; Rotation = $state.Rotation; MutexAbandoned = $state.MutexAbandoned }
}

function Invoke-AtmMonitorCollectionCore {
    # Steps 2 to 5 of Invoke-AtmMonitorCollection, with the mutex held. Fills -State.
    param([hashtable]$State, $Identity, [hashtable]$InventoryArgs, [Diagnostics.Stopwatch]$Stopwatch)
    $folder = Get-AtmMonitorFolder
    if (-not $folder) { $State.Code = 'MONITOR_FOLDER_UNKNOWN'; return }
    $utc = Get-AtmMonitorUtcNow
    $previous = Get-AtmMonitorNewestName -Folder $folder
    $inv = $null; $failure = $null
    $aw = [Diagnostics.Stopwatch]::StartNew()
    try {
        if ($null -ne $script:AtmMonitorAuditSource) { $inv = & $script:AtmMonitorAuditSource $InventoryArgs }
        else { $inv = Invoke-AtmInventory @InventoryArgs }
        if ($null -eq $inv) { $failure = 'AUDIT_NO_RESULT' }
    } catch { $inv = $null; $failure = (Get-AtmInnerException $_.Exception).GetType().Name }
    $aw.Stop()
    $State.AuditMs = [long]$aw.ElapsedMilliseconds
    if ($null -ne $failure) { $inv = $null }
    $rec = New-AtmMonitorRecord -Inventory $inv -Utc $utc -DurationMs ([long]$Stopwatch.ElapsedMilliseconds) -AuditMs $State.AuditMs -Failure $failure -Previous $previous
    $State.Outcome = $rec.outcome
    $text = ConvertTo-AtmMonitorRecordText -Record $rec
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($text)
    $State.Bytes = $bytes.Length
    if ($bytes.Length -gt $script:AtmMonitorMaxRecordBytes) { $State.Code = 'MONITOR_RECORD_TOO_LARGE'; return }
    $suffix = New-AtmMonitorSuffix
    if ($suffix -cnotmatch '^[0-9a-f]{8}$') { $State.Code = 'MONITOR_NAME_INVALID'; return }
    $name = (ConvertTo-AtmMonitorTimeText $utc) + '-' + $suffix + '.json'
    $fc = Open-AtmMonitorFolder -Path $folder -UserSid $Identity.Sid
    if ($null -ne $fc) { $State.Code = $fc; return }
    $wc = Write-AtmMonitorRecordFile -Folder $folder -Name $name -Bytes $bytes
    if ($null -ne $wc) { $State.Code = $wc; return }
    $State.File = $name
    $State.Rotation = Invoke-AtmMonitorRotation -Folder $folder -NowUtc $utc -Owners $Identity.Owners -KeepName $name
    $State.Code = 'OK'
}

# ---------------------------------------------------------------------------------------------
# The reader (no gate, no lock: reading is allowed with the gate closed, so a leftover stays visible)
# ---------------------------------------------------------------------------------------------

function Get-AtmMonitorHistory {
    <#
      Reads the history, read only: never creates the folder, takes no lock and needs no gate (ADR-0014 section 3 names it
      as the GUI's future read function, phase M5). A missing folder is an empty history. A folder with a reparse point in
      its chain is not read (FolderState REFUSED). Only final names are read: a .partial file is counted and never read, a
      folder, a reparse point or another name is counted as unexpected and never read (the user's thresholds file,
      monitor.json, a plain file with the expected owner, is not counted: phase M2), and a file that vanished between
      the listing and the read is skipped. Each record is checked (Test-AtmMonitorRecordText); one that fails is listed as
      HISTORY_RECORD_INVALID and skipped, never read as zero. A record whose time is earlier than the time of the record
      it names as "previous" is marked CLOCK_SKEW (Get-AtmMonitorTrends leaves it out, as a gap).
      Returns FolderState (ABSENT | OK | REFUSED | UNREADABLE), FolderCode, Records (Name, Utc, Record, Codes; in name
      order), Invalid (Name, Code, Reason), Skipped, Partial, Unexpected and ClockSkew.
    #>
    $out = [ordered]@{ FolderState = 'ABSENT'; FolderCode = $null; Records = @(); Invalid = @(); Skipped = 0; Partial = 0; Unexpected = 0; ClockSkew = 0 }
    $folder = Get-AtmMonitorFolder
    if (-not $folder) { $out.FolderState = 'UNREADABLE'; $out.FolderCode = 'MONITOR_FOLDER_UNKNOWN'; return [pscustomobject]$out }
    $chain = Test-AtmPathChain $folder.TrimEnd('\')
    if ($chain.Status -ceq 'NOT_FOUND') { return [pscustomobject]$out }
    if ($chain.Status -cne 'OK') {
        $out.FolderState = $(if ($chain.Status -ceq 'REPARSE_IN_PATH') { 'REFUSED' } else { 'UNREADABLE' })
        $out.FolderCode = 'MONITOR_FOLDER_' + $chain.Status
        return [pscustomobject]$out
    }
    $items = $null
    try { $items = @((New-Object IO.DirectoryInfo($folder)).GetFileSystemInfos()) } catch { $out.FolderState = 'UNREADABLE'; $out.FolderCode = 'MONITOR_FOLDER_LIST_FAILED'; return [pscustomobject]$out }
    $out.FolderState = 'OK'
    $names = New-Object System.Collections.Generic.List[string]
    $owners = $null
    foreach ($it in $items) {
        if (($it.Attributes -band ([IO.FileAttributes]::ReparsePoint -bor [IO.FileAttributes]::Directory)) -ne 0) { $out.Unexpected++; continue }
        if ($it.Name -ceq $script:AtmMonitorConfigName) {
            # The user's thresholds file (phase M2) is not a record and is not counted, when it has the expected owner;
            # otherwise it is counted as unexpected, as before. Get-AtmMonitorConfig reads it.
            if ($null -eq $owners) { try { $owners = @((Get-AtmMonitorIdentity).Owners) } catch { $owners = @() } }
            $cOwner = Get-AtmMonitorFileOwner $it.FullName
            if (-not $cOwner -or @($owners) -cnotcontains $cOwner) { $out.Unexpected++ }
            continue
        }
        if ($it.Name -cmatch $script:AtmMonitorNamePattern) { $names.Add($it.Name) }
        elseif ($it.Name -cmatch $script:AtmMonitorPartialPattern) { $out.Partial++ }
        else { $out.Unexpected++ }
    }
    $sorted = $names.ToArray()
    [Array]::Sort($sorted, [StringComparer]::Ordinal)
    $records = New-Object System.Collections.Generic.List[object]
    $invalid = New-Object System.Collections.Generic.List[object]
    $strict = New-Object Text.UTF8Encoding($false, $true)
    foreach ($n in $sorted) {
        $path = Join-Path $folder $n
        $text = $null; $why = $null
        try {
            $fi = New-Object IO.FileInfo($path)
            if (-not $fi.Exists) { $out.Skipped++; continue }
            if ($fi.Length -gt $script:AtmMonitorMaxRecordBytes) { $why = 'SIZE' }
            else { $text = $strict.GetString([IO.File]::ReadAllBytes($path)) }
        } catch {
            if ((Get-AtmFileErrorKind $_.Exception) -ceq 'NOT_FOUND') { $out.Skipped++; continue }
            $why = 'READ'
        }
        if ($null -eq $why) {
            $v = Test-AtmMonitorRecordText -Text $text -Name $n
            if ($v.Valid) { $records.Add([pscustomobject]@{ Name = $n; Utc = $v.Utc; Record = $v.Record; Codes = @() }); continue }
            $why = $v.Reason
        }
        $invalid.Add([pscustomobject]@{ Name = $n; Code = 'HISTORY_RECORD_INVALID'; Reason = $why })
    }
    foreach ($r in $records) {
        $prev = $r.Record.previous
        if ($null -eq $prev) { continue }
        $pm = [regex]::Match([string]$prev, $script:AtmMonitorNamePattern)
        $pt = $(if ($pm.Success) { ConvertFrom-AtmMonitorTimeText $pm.Groups[1].Value } else { $null })
        if ($null -ne $pt -and $r.Utc -lt $pt) { $r.Codes = @('CLOCK_SKEW'); $out.ClockSkew++ }
    }
    $out.Records = $records.ToArray()
    $out.Invalid = $invalid.ToArray()
    return [pscustomobject]$out
}

function Get-AtmMonitorStatus {
    <#
      monitor status (V0.5 M1, M2): the gate as this copy has it, the history as the reader finds it, and the latest
      valid record summed up (time, outcome, groups, bytes measured), or $null. With the gate open (the suite only) also
      the thresholds (Get-AtmMonitorConfig), the trends and the alerts. With it closed none of them is computed and
      monitor.json is not read: a history left by another copy feeds no alert in a copy that does not collect (Config
      and Trends $null, Alerts empty). Reads only.
    #>
    $h = Get-AtmMonitorHistory
    $latest = $null
    $n = @($h.Records).Count
    if ($n -gt 0) {
        $r = @($h.Records)[$n - 1]
        $latest = [pscustomobject]@{ Utc = $r.Utc; Outcome = [string]$r.Record.outcome; Groups = @($r.Record.groups).Count; Bytes = (Get-AtmMonitorRecordBytes $r.Record) }
    }
    $config = $null; $trends = $null; $alerts = @()
    if ($script:AtmMonitoringEnabled) {
        $config = Get-AtmMonitorConfig
        $trends = Get-AtmMonitorTrends -History $h
        $alerts = @(Get-AtmMonitorAlerts -History $h -Config $config -Trends $trends)
    }
    return [pscustomobject]@{ GateOpen = [bool]$script:AtmMonitoringEnabled; History = $h; Latest = $latest; Config = $config; Trends = $trends; Alerts = $alerts }
}

# ---------------------------------------------------------------------------------------------
# Phase M2: the thresholds, the trends and the alerts. Read only and pure: nothing here writes, creates or fixes a file
# (monitor.json included), runs a command, or calls an engine, a process, the scheduler or the network. An alert NAMES
# a command for the user to run; it never runs it.
# ---------------------------------------------------------------------------------------------

function Get-AtmMonitorConfigFile {
    <#
      The checks of monitor.json in -Folder, before its values, in this order: the folder's chain (no reparse point;
      absent: no file); the file (absent: no file; not a reparse point; a plain file); its owner (the user, or the
      token's default owner); at most 4 KB; strict UTF-8 (one leading byte order mark is accepted and dropped); JSON;
      an object. Returns Reason (ABSENT when there is no file, $null when it passed, otherwise the short reason of the
      refusal) and Object (the parsed object).
    #>
    param([string]$Folder)
    $chain = Test-AtmPathChain $Folder.TrimEnd('\')
    if ($chain.Status -ceq 'NOT_FOUND') { return [pscustomobject]@{ Reason = 'ABSENT'; Object = $null } }
    if ($chain.Status -ceq 'REPARSE_IN_PATH') { return [pscustomobject]@{ Reason = 'REPARSE'; Object = $null } }
    if ($chain.Status -cne 'OK') { return [pscustomobject]@{ Reason = 'FOLDER'; Object = $null } }
    $path = Join-Path $Folder.TrimEnd('\') $script:AtmMonitorConfigName
    $a = $null
    try { $a = [IO.File]::GetAttributes($path) }
    catch {
        if ((Get-AtmFileErrorKind $_.Exception) -ceq 'NOT_FOUND') { return [pscustomobject]@{ Reason = 'ABSENT'; Object = $null } }
        return [pscustomobject]@{ Reason = 'READ'; Object = $null }
    }
    if (($a -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return [pscustomobject]@{ Reason = 'REPARSE'; Object = $null } }
    if (($a -band [IO.FileAttributes]::Directory) -ne 0) { return [pscustomobject]@{ Reason = 'NOT_A_FILE'; Object = $null } }
    $owners = @()
    try { $owners = @((Get-AtmMonitorIdentity).Owners) } catch { $owners = @() }
    $owner = Get-AtmMonitorFileOwner $path
    if (-not $owner -or @($owners) -cnotcontains $owner) { return [pscustomobject]@{ Reason = 'OWNER'; Object = $null } }
    $bytes = $null
    try {
        if ((New-Object IO.FileInfo($path)).Length -gt $script:AtmMonitorConfigMaxBytes) { return [pscustomobject]@{ Reason = 'SIZE'; Object = $null } }
        $bytes = [IO.File]::ReadAllBytes($path)
    } catch {
        if ((Get-AtmFileErrorKind $_.Exception) -ceq 'NOT_FOUND') { return [pscustomobject]@{ Reason = 'ABSENT'; Object = $null } }
        return [pscustomobject]@{ Reason = 'READ'; Object = $null }
    }
    if ($bytes.Length -gt $script:AtmMonitorConfigMaxBytes) { return [pscustomobject]@{ Reason = 'SIZE'; Object = $null } }
    $off = 0
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { $off = 3 }
    $text = $null
    try { $text = (New-Object Text.UTF8Encoding($false, $true)).GetString($bytes, $off, $bytes.Length - $off) } catch { return [pscustomobject]@{ Reason = 'ENCODING'; Object = $null } }
    $o = $null
    try { $o = ConvertFrom-Json -InputObject $text -ErrorAction Stop } catch { return [pscustomobject]@{ Reason = 'JSON'; Object = $null } }
    if ($null -eq $o) { return [pscustomobject]@{ Reason = 'JSON'; Object = $null } }
    # The text itself must be an object: one shell unrolls a one-element array into its element.
    if (-not $text.TrimStart().StartsWith('{', [StringComparison]::Ordinal) -or $o -isnot [System.Management.Automation.PSCustomObject]) { return [pscustomobject]@{ Reason = 'TYPE'; Object = $null } }
    return [pscustomobject]@{ Reason = $null; Object = $o }
}

function Get-AtmMonitorConfigValues {
    <#
      The values of a parsed monitor.json (-Object $null: the defaults). Each member must be a field of
      AtmMonitorConfigFields (names compared with case: UNKNOWN_KEY), a JSON number (TYPE; a whole number for
      failedCollections, so 3.0 is accepted and 3.5 is not) within the field's bounds, both ends included (RANGE; a
      number too large for either shell's reader is RANGE). A missing member takes its default. Returns Reason ($null
      when every member passed) and Values (one per field, the defaults when refused).
    #>
    param($Object)
    $values = [ordered]@{}
    foreach ($f in $script:AtmMonitorConfigFields) { $values[$f.Name] = $(if ($f.Integer) { [int]$f.Default } else { [double]$f.Default }) }
    $defaults = [ordered]@{}
    foreach ($k in @($values.Keys)) { $defaults[$k] = $values[$k] }
    if ($null -eq $Object) { return [pscustomobject]@{ Reason = $null; Values = $values } }
    foreach ($p in @($Object.PSObject.Properties)) {
        $f = $null
        foreach ($c in $script:AtmMonitorConfigFields) { if ($c.Name -ceq [string]$p.Name) { $f = $c } }
        if ($null -eq $f) { return [pscustomobject]@{ Reason = 'UNKNOWN_KEY'; Values = $defaults } }
        $v = $p.Value
        if ($null -ne $v -and $v.GetType().FullName -ceq 'System.Numerics.BigInteger') { return [pscustomobject]@{ Reason = 'RANGE'; Values = $defaults } }
        if (-not ($v -is [int] -or $v -is [long] -or $v -is [double] -or $v -is [decimal])) { return [pscustomobject]@{ Reason = 'TYPE'; Values = $defaults } }
        $d = [double]$v
        if ([double]::IsNaN($d) -or [double]::IsInfinity($d)) { return [pscustomobject]@{ Reason = 'RANGE'; Values = $defaults } }
        if ($f.Integer -and $d -ne [math]::Floor($d)) { return [pscustomobject]@{ Reason = 'TYPE'; Values = $defaults } }
        if ($d -lt $f.Min -or $d -gt $f.Max) { return [pscustomobject]@{ Reason = 'RANGE'; Values = $defaults } }
        $values[$f.Name] = $(if ($f.Integer) { [int]$d } else { $d })
    }
    return [pscustomobject]@{ Reason = $null; Values = $values }
}

function Get-AtmMonitorConfig {
    <#
      The alert thresholds (V05-D10 (a)), read only: monitor.json in the history folder, which only the user writes. The
      product never writes, creates or fixes it. No file (or no folder): the defaults and no alert (State DEFAULTS). A
      file that passes every check: its values, a missing member taking its default (State FILE). Otherwise the WHOLE
      file is refused: the defaults, Code MON_CONFIG_INVALID and the short Reason of the first failed check (State
      REFUSED): REPARSE, NOT_A_FILE, OWNER, SIZE, ENCODING, JSON, TYPE, UNKNOWN_KEY, RANGE, READ or FOLDER (the folder
      could not be known or checked). Returns State, Code, Reason and Values.
    #>
    $defaults = (Get-AtmMonitorConfigValues -Object $null).Values
    $folder = Get-AtmMonitorFolder
    if (-not $folder) { return [pscustomobject]@{ State = 'REFUSED'; Code = 'MON_CONFIG_INVALID'; Reason = 'FOLDER'; Values = $defaults } }
    $chk = Get-AtmMonitorConfigFile -Folder $folder
    if ($chk.Reason -ceq 'ABSENT') { return [pscustomobject]@{ State = 'DEFAULTS'; Code = $null; Reason = $null; Values = $defaults } }
    if ($null -ne $chk.Reason) { return [pscustomobject]@{ State = 'REFUSED'; Code = 'MON_CONFIG_INVALID'; Reason = $chk.Reason; Values = $defaults } }
    $val = Get-AtmMonitorConfigValues -Object $chk.Object
    if ($null -ne $val.Reason) { return [pscustomobject]@{ State = 'REFUSED'; Code = 'MON_CONFIG_INVALID'; Reason = $val.Reason; Values = $defaults } }
    return [pscustomobject]@{ State = 'FILE'; Code = $null; Reason = $null; Values = $val.Values }
}

function Get-AtmMonitorRecordBytes {
    # The bytes measured by a record: the sum of its groups, the "other" group included.
    param($Record)
    $b = [long]0
    foreach ($g in @($Record.groups)) { $b += [long]$g[7] }
    return $b
}

function Get-AtmMonitorGroupKey {
    # The key of a group of a record (provider, identified project or not, class); $null for the "other" group.
    param($Group)
    if ($Group[4]) { return $null }
    return ([string]$Group[0] + "`n" + $(if ($Group[2]) { '1' + [string]$Group[1] } else { '0' }) + "`n" + [string]$Group[3])
}

function Get-AtmMonitorSlope {
    <#
      The least-squares slope of -Points (each: Utc, Bytes) in bytes per day, rounded to whole bytes (so a series built
      on whole days and whole bytes gives its exact slope). Fewer than 4 points, or points that span less than 24 hours,
      are INSUFFICIENT_DATA; 4 points that span exactly 24 hours are enough. Returns State (OK | INSUFFICIENT_DATA),
      Slope ($null when insufficient), Points and SpanHours.
    #>
    param([object[]]$Points)
    $pts = @($Points)
    $n = $pts.Count
    $span = [TimeSpan]::Zero
    $min = $null
    if ($n -gt 0) {
        $min = $pts[0].Utc; $max = $pts[0].Utc
        foreach ($p in $pts) { if ($p.Utc -lt $min) { $min = $p.Utc }; if ($p.Utc -gt $max) { $max = $p.Utc } }
        $span = $max - $min
    }
    if ($n -lt $script:AtmMonitorTrendMinPoints -or $span -lt [TimeSpan]::FromHours($script:AtmMonitorTrendMinSpanHours)) {
        return [pscustomobject]@{ State = 'INSUFFICIENT_DATA'; Slope = $null; Points = $n; SpanHours = $span.TotalHours }
    }
    $sx = 0.0; $sy = 0.0
    foreach ($p in $pts) { $sx += ($p.Utc - $min).TotalDays; $sy += [double]$p.Bytes }
    $mx = $sx / $n; $my = $sy / $n
    $num = 0.0; $den = 0.0
    foreach ($p in $pts) {
        $dx = ($p.Utc - $min).TotalDays - $mx
        $num += $dx * ([double]$p.Bytes - $my); $den += $dx * $dx
    }
    $slope = [long][math]::Round($num / $den, [MidpointRounding]::AwayFromZero)
    return [pscustomobject]@{ State = 'OK'; Slope = $slope; Points = $n; SpanHours = $span.TotalHours }
}

function Get-AtmMonitorEntryNames {
    # Every entry of the history in name (time) order: the valid records and the invalid files.
    param($History)
    $names = [string[]]@(@(@($History.Records) | ForEach-Object { [string]$_.Name }) + @(@($History.Invalid) | ForEach-Object { [string]$_.Name }))
    [Array]::Sort($names, [StringComparer]::Ordinal)
    return , $names
}

function Get-AtmMonitorTrends {
    <#
      The trends (ADR-0017 section 4) over the history as Get-AtmMonitorHistory found it; pure, no file read.
        - The window: the 7 days up to the newest record that is not CLOCK_SKEW, both ends included.
        - The total (every group summed, "other" included): points only from OK records.
        - A group (provider, project, identified, class): points only from a record that is not AUDIT_FAILED, whose
          coverage is complete, and in which that group's flag is complete. So an INCOMPLETE record with complete
          coverage still gives the points of its complete groups (an OK record never holds an incomplete group, so this
          is the only way one incomplete group is a gap for its own trend alone). The "other" group has no trend: its
          content changes from one record to the next.
        - Gaps, never points (never a decrease): INCOMPLETE and AUDIT_FAILED records for the total, invalid files,
          CLOCK_SKEW records, an incomplete group, a record with incomplete coverage for the groups.
        - The delta: the total of the newest entry (a record or an invalid file, by name) minus the total of the entry
          before it, only when both are valid OK records and neither is CLOCK_SKEW; otherwise GAP (never a decrease nor
          "resolved"); NONE when there is no entry before it.
      Returns WindowEndUtc, LatestOk (the newest OK record that is not CLOCK_SKEW: Name, Utc, Record; or $null),
      LatestOkBytes (its total), Total
      (Get-AtmMonitorSlope), Groups (Key, Provider, Project, Identified, Class, Trend), Top (at most 5 groups whose
      trend is OK, the largest slope first) and Delta (State OK | GAP | NONE, Bytes).
    #>
    param($History)
    $recs = @(@($History.Records) | Where-Object { $null -ne $_ -and @($_.Codes) -cnotcontains 'CLOCK_SKEW' })
    $end = $null
    $latestOk = $null
    foreach ($r in $recs) {
        if ($null -eq $end -or $r.Utc -gt $end) { $end = $r.Utc }
        if ([string]$r.Record.outcome -ceq 'OK' -and ($null -eq $latestOk -or $r.Utc -gt $latestOk.Utc)) { $latestOk = $r }
    }
    $total = New-Object System.Collections.Generic.List[object]
    $byKey = @{}
    if ($null -ne $end) {
        $start = $end.AddDays(-$script:AtmMonitorTrendWindowDays)
        foreach ($r in $recs) {
            if ($r.Utc -lt $start -or $r.Utc -gt $end) { continue }
            $outcome = [string]$r.Record.outcome
            if ($outcome -ceq 'OK') { $total.Add([pscustomobject]@{ Utc = $r.Utc; Bytes = (Get-AtmMonitorRecordBytes $r.Record) }) }
            if ($outcome -ceq 'AUDIT_FAILED' -or $null -eq $r.Record.coverage -or $r.Record.coverage.complete -ne $true) { continue }
            foreach ($g in @($r.Record.groups)) {
                $k = Get-AtmMonitorGroupKey $g
                if ($null -eq $k -or $g[9] -ne $true) { continue }
                if (-not $byKey.ContainsKey($k)) {
                    $byKey[$k] = [pscustomobject]@{ Key = $k; Provider = [string]$g[0]; Project = $(if ($g[2]) { [string]$g[1] } else { $null }); Identified = [bool]$g[2]; Class = [string]$g[3]; Points = (New-Object System.Collections.Generic.List[object]) }
                }
                $byKey[$k].Points.Add([pscustomobject]@{ Utc = $r.Utc; Bytes = [long]$g[7] })
            }
        }
    }
    $keys = [string[]]@($byKey.Keys)
    [Array]::Sort($keys, [StringComparer]::Ordinal)
    $groups = New-Object System.Collections.Generic.List[object]
    foreach ($k in $keys) {
        $e = $byKey[$k]
        $groups.Add([pscustomobject]@{ Key = $k; Provider = $e.Provider; Project = $e.Project; Identified = $e.Identified; Class = $e.Class; Trend = (Get-AtmMonitorSlope -Points $e.Points.ToArray()) })
    }
    # The largest slope first; equal slopes in the ordinal order of their key, so the list is the same on every machine.
    $withTrend = @($groups | Where-Object { $_.Trend.State -ceq 'OK' })
    $sortKeys = [string[]]@(for ($i = 0; $i -lt $withTrend.Count; $i++) {
            ([decimal][long]::MaxValue - [decimal]$withTrend[$i].Trend.Slope).ToString('00000000000000000000', [Globalization.CultureInfo]::InvariantCulture) + "`n" + $withTrend[$i].Key + "`n" + $i
        })
    [Array]::Sort($sortKeys, [StringComparer]::Ordinal)
    $top = New-Object System.Collections.Generic.List[object]
    foreach ($sk in $sortKeys) {
        if ($top.Count -ge $script:AtmMonitorTrendTopGroups) { break }
        $top.Add($withTrend[[int]$sk.Substring($sk.LastIndexOf("`n") + 1)])
    }
    $delta = [pscustomobject]@{ State = 'NONE'; Bytes = $null }
    $names = Get-AtmMonitorEntryNames -History $History
    if ($names.Length -ge 2) {
        $byName = @{}
        foreach ($r in @($History.Records)) { $byName[[string]$r.Name] = $r }
        $pair = @($names[$names.Length - 1], $names[$names.Length - 2])
        $ok = $true
        foreach ($nm in $pair) {
            $r = $byName[$nm]
            if ($null -eq $r -or [string]$r.Record.outcome -cne 'OK' -or @($r.Codes) -ccontains 'CLOCK_SKEW') { $ok = $false }
        }
        $delta = $(if ($ok) { [pscustomobject]@{ State = 'OK'; Bytes = ((Get-AtmMonitorRecordBytes $byName[$pair[0]].Record) - (Get-AtmMonitorRecordBytes $byName[$pair[1]].Record)) } } else { [pscustomobject]@{ State = 'GAP'; Bytes = $null } })
    }
    $latestOkBytes = $(if ($null -ne $latestOk) { Get-AtmMonitorRecordBytes $latestOk.Record } else { $null })
    return [pscustomobject]@{ WindowEndUtc = $end; LatestOk = $latestOk; LatestOkBytes = $latestOkBytes; Total =(Get-AtmMonitorSlope -Points $total.ToArray()); Groups = $groups.ToArray(); Top = $top.ToArray(); Delta = $delta }
}

function Get-AtmMonitorAlerts {
    <#
      The alerts (phase M2), a pure function of the history, the thresholds and the trends. Each alert has a Code, the
      Commands it NAMES (AtmMonitorAlertCommands; never run), a Value and a Threshold (bytes, or the count). A threshold
      fires only when the value is STRICTLY greater:
        MON_TOTAL: the total of the newest OK record over totalGiB;
        MON_GROWTH: the slope of the total over growthGiBPerDay (never with INSUFFICIENT_DATA);
        MON_ORPHAN_SUSPECTED, MON_LIVENESS_UNKNOWN: the sum of the groups of that class in the newest OK record over
          its threshold (the groups summed into "other" have no class, so the sum is a lower bound when the record
          summed any);
        MON_COLLECTION: none of the failedCollections newest entries (records or invalid files) is an OK record;
        MON_CONFIG_INVALID: monitor.json was refused (Value: the reason); the defaults are in use.
      Returns the alerts in that order.
    #>
    param($History, $Config, $Trends)
    $vals = $Config.Values
    $found = @{}
    $latest = $Trends.LatestOk
    if ($null -ne $latest) {
        $tb = Get-AtmMonitorRecordBytes $latest.Record
        $thr = [double]$vals['totalGiB'] * 1GB
        if ([double]$tb -gt $thr) { $found['MON_TOTAL'] = @($tb, $thr) }
        foreach ($pair in @(@('MON_ORPHAN_SUSPECTED', 'ORPHAN_SUSPECTED', 'orphanSuspectedGiB'), @('MON_LIVENESS_UNKNOWN', 'LIVENESS_UNKNOWN', 'livenessUnknownGiB'))) {
            $sum = [long]0
            foreach ($g in @($latest.Record.groups)) { if ($g[4] -ne $true -and [string]$g[3] -ceq $pair[1]) { $sum += [long]$g[7] } }
            $thr = [double]$vals[$pair[2]] * 1GB
            if ([double]$sum -gt $thr) { $found[$pair[0]] = @($sum, $thr) }
        }
    }
    if ($null -ne $Trends.Total -and $Trends.Total.State -ceq 'OK') {
        $thr = [double]$vals['growthGiBPerDay'] * 1GB
        if ([double]$Trends.Total.Slope -gt $thr) { $found['MON_GROWTH'] = @($Trends.Total.Slope, $thr) }
    }
    $n = [int]$vals['failedCollections']
    $names = Get-AtmMonitorEntryNames -History $History
    if ($names.Length -ge $n) {
        $okNames = @{}
        foreach ($r in @($History.Records)) { if ([string]$r.Record.outcome -ceq 'OK') { $okNames[[string]$r.Name] = $true } }
        $anyOk = $false
        for ($i = $names.Length - $n; $i -lt $names.Length; $i++) { if ($okNames.ContainsKey($names[$i])) { $anyOk = $true } }
        if (-not $anyOk) { $found['MON_COLLECTION'] = @($n, $n) }
    }
    if ([string]$Config.State -ceq 'REFUSED') { $found['MON_CONFIG_INVALID'] = @([string]$Config.Reason, $null) }
    $alerts = New-Object System.Collections.Generic.List[object]
    foreach ($code in @($script:AtmMonitorAlertCommands.Keys)) {
        if (-not $found.ContainsKey($code)) { continue }
        $alerts.Add([pscustomobject]@{ Code = $code; Commands = @($script:AtmMonitorAlertCommands[$code]); Value = $found[$code][0]; Threshold = $found[$code][1] })
    }
    return $alerts.ToArray()
}
