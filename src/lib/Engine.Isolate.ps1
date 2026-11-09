# AgentTempManager ISOLATION ENGINE (0.3.x, docs/adr/ADR-0013: isolate one session root per run, list, inspect, verify,
# restore and purge quarantine entries). Depends on Engine.Audit.ps1 and Engine.Clean.ps1, whose gates, plan check,
# revalidation, lock, log writer and deleter it reuses unchanged. No terminal output of its own: the plan is shown through
# a mandatory presenter callback and the confirmation is read through a mandatory reader. With the isolation gate closed
# (every distributed copy) isolate and restore stop after the plan: nothing is asked, locked, logged, created or moved.
# With the purge gate closed (every distributed copy) purge stops after its plan too: nothing is purged.
Set-StrictMode -Version 2.0

# ISOLATION GATE (0.3.x): real isolation is DISABLED. Invoke-AtmIsolate applies the target rule and every gate and
# presents the exact plan, then stops. There is deliberately no switch, environment variable, config file or UI option to
# change this: enabling isolation requires a code change in this administrator-owned, manifest-verified file, released
# under a specific authorization. Only the automated test suite flips it, inside its own process.
$script:AtmIsolationEnabled = $false

# QUARANTINE PURGE GATE (0.3.x, J-ISO-1 (C)): purging a quarantine entry is DISABLED. quarantine purge checks the entry and
# every gate of the purge and presents the exact plan, then stops: it asks nothing, takes no lock, opens no log and purges
# nothing, so no space is freed. It is a gate of its own: opening the isolation gate does not open it, and it does not
# depend on the deletion gate of clean (AtmRealDeletionEnabled). As every gate, there is no switch, environment variable,
# config file or UI option for it; only the automated test suite flips it, inside its own process.
$script:AtmQuarantinePurgeEnabled = $false

# Codes of the 0.3.x target rule (contract section 4). Isolation is limited to the own profile (ISO-D1), and in this
# version only to a session root (J-ISO-9 (a)): a scope (project) or the whole base is recognized and refused with its
# own code, never treated as an unknown path.
$script:AtmIsolationOwnProfileOnly = 'ALVO_FORA_DO_PROPRIO_PERFIL'
$script:AtmIsolationScopeRefused = 'ISOLAMENTO_ESCOPO_NAO_LIBERADO_0_3X'
$script:AtmIsolationBaseRefused = 'ISOLAMENTO_BASE_NAO_LIBERADA_0_3X'
$script:AtmIsolationKindRefused = 'ALVO_NAO_ISOLAVEL_0_3X'
# Fixed in code, no parameter changes it: one session root per run (phase P3a).
$script:AtmIsolationMaxRoots = 1
# The isolation log (T1 writer, its own schema) and the manifest of a quarantine entry (contract section 7.3).
$script:AtmIsolateLogSchema = 'atm.isolatelog/1'
$script:AtmQuarantineSchema = 'atm.quarantine/1'
# Test seam, single assignment: the quarantine root. $null means the process user's %LOCALAPPDATA%\AgentTempManager\Q
# (J-ISO-5 (b)). The suite replaces it inside its own process with a folder of its sandbox; the CLI and the TUI never set
# it. It is read only past the isolation gate.
$script:AtmIsolationQuarantineRoot = $null
# Retention, quota and free space (contract section 10; J-ISO-6 (b)). Retention only marks an entry EXPIRED and never
# purges; the quota (off unless the policy sets one) and the free-space minimum of the quarantine's volume only refuse new
# isolations. The minimum is fixed in code: no policy key changes it.
$script:AtmQuarantineDefaultRetentionDays = 30
$script:AtmQuarantineMinFreeBytes = 64MB
# The policy file of the installation (config\quarantine.policy.json, contract section 11.2) and its schema.
$script:AtmQuarantinePolicyFile = 'quarantine.policy.json'
$script:AtmQuarantinePolicySchema = 'atm.quarantine-policy/1'
# The purge log (T1 writer, its own schema).
$script:AtmPurgeLogSchema = 'atm.purgelog/1'
# The automatic purge (contract section 11, J-ISO-7 (ii), phase P6a): the log of each pass (T1 writer, its own schema),
# in a folder at a place fixed in code next to the quarantine root (outside it), and the minimum retention fixed in code
# (section 11.3): with retentionDays below it nothing expires automatically. No policy key changes either.
$script:AtmAutoPurgeLogSchema = 'atm.autopurgelog/1'
$script:AtmAutoPurgeLogFolder = 'AutoPurgeLog'
$script:AtmAutoPurgeMinRetentionDays = 7
# The scheduled task of the automatic purge (J-ISO-7 and its complement of 2026-11-03, phase P6b): optional, created only
# by the user with quarantine schedule-autopurge (never by the installer or the TUI). One task per user, in a folder of
# its own, named after a hash of the user's SID (the name never shows the SID). It runs on the user's own token, not
# elevated (RunLevel Limited), and only while that user's session is open (LogonType Interactive): no password or other
# credential is asked for, stored or passed. Its only action is the entry point of the installation, with no arguments.
# The trigger is daily at a local hour fixed in code with a bounded random delay; a missed run starts at the next
# opportunity. What a run may do is still decided by the policy (autoPurge = true, changed only by the administrator).
$script:AtmAutoPurgeTaskFolder = '\AgentTempManager'
$script:AtmAutoPurgeTaskPrefix = 'AutoPurge-'
$script:AtmAutoPurgeTaskHour = 12
$script:AtmAutoPurgeTaskRandomDelay = 'PT1H'
$script:AtmAutoPurgeTaskTimeLimit = 'PT2H'
$script:AtmAutoPurgeSchedulePhrase = 'AGENDAR EXPURGO AUTOMATICO'
$script:AtmAutoPurgeScheduleOffPhrase = 'AGENDAR COM EXPURGO DESLIGADO'
$script:AtmAutoPurgeUnschedulePhrase = 'DESAGENDAR EXPURGO AUTOMATICO'
# Test seams, single assignment each; the CLI and the TUI never set them. The task name: the suite replaces it inside its
# own process with a name marked as a test (AutoPurgeTest-<8 hex digits>), and nothing else is accepted in its place.
# The token read by the elevation refusal (a scriptblock returning the shape of Get-AtmIdentityState): the suite runs
# elevated and replaces it to reach the rest of schedule-autopurge.
$script:AtmAutoPurgeTaskNameOverride = $null
$script:AtmAutoPurgeElevationSource = $null
# Test seam, single assignment: the clock of the retention (a scriptblock that returns a UTC time). $null is the system
# clock. The suite replaces it inside its own process; the CLI and the TUI never set it.
$script:AtmQuarantineClock = $null

function Get-AtmIsolationTarget {
    <#
      The 0.3.x target rule for one exact path of the request, against an inventory. Returns Partition (the session root
      to submit to the gates, or $null) and Reasons (why the path is refused). The base and its scope directories are
      recognized from the inventoried partitions; everything else must be exactly one partition of the inventory.
    #>
    param($Inventory, [string]$Path)
    $out = [ordered]@{ Partition = $null; Reasons = @() }
    $ownSid = [string]$Inventory.Identity.Sid
    $parts = @($Inventory.Partitions | Where-Object { $_.Kind -ne 'NotScanned' })
    $asBase = @($parts | Where-Object { [string]::Equals([string]$_.BasePath, $Path, [StringComparison]::OrdinalIgnoreCase) })
    if ($asBase.Count -gt 0) {
        $out.Reasons = @(@($script:AtmIsolationBaseRefused) + $(if (@($asBase | Where-Object { [string]$_.Sid -cne $ownSid }).Count -gt 0) { @($script:AtmIsolationOwnProfileOnly) } else { @() }))
        return [pscustomobject]$out
    }
    $asScope = @($parts | Where-Object { $_.Slug -and ([string]::Equals([IO.Path]::GetDirectoryName([string]$_.Path), $Path, [StringComparison]::OrdinalIgnoreCase) -or ([string]$_.Kind -ceq 'Unmeasured' -and [string]::Equals([string]$_.Path, $Path, [StringComparison]::OrdinalIgnoreCase))) })
    if ($asScope.Count -gt 0) {
        $out.Reasons = @(@($script:AtmIsolationScopeRefused) + $(if (@($asScope | Where-Object { [string]$_.Sid -cne $ownSid }).Count -gt 0) { @($script:AtmIsolationOwnProfileOnly) } else { @() }))
        return [pscustomobject]$out
    }
    $m = @($parts | Where-Object { [string]::Equals([string]$_.Path, $Path, [StringComparison]::OrdinalIgnoreCase) -and $_.Kind -ne 'BaseLooseFiles' })
    if ($m.Count -ne 1) { $out.Reasons = @('FORA_DAS_ROOTS_PERMITIDAS (' + (Get-AtmText 'reason.notRoot') + ')'); return [pscustomobject]$out }
    $p = $m[0]
    $why = New-Object System.Collections.Generic.List[string]
    if (-not [string]::Equals([string]$p.Path, $Path, [StringComparison]::Ordinal)) { $why.Add('CAIXA_DIVERGENTE (' + (Get-AtmText 'reason.useExactly' $p.Path) + ')') }
    if ([string]$p.Sid -cne $ownSid) { $why.Add($script:AtmIsolationOwnProfileOnly) }
    if ([string]$p.Kind -cne 'SessionRoot') { $why.Add($script:AtmIsolationKindRefused + ' (' + $p.Kind + ')') }
    if ($why.Count -gt 0) { $out.Reasons = $why.ToArray() } else { $out.Partition = $p }
    return [pscustomobject]$out
}

function Get-AtmIsolatePlanId {
    # The plan id of an isolation: as clean's (Get-AtmCleanPlanId), with a prefix of its own, so a clean plan id and an
    # isolation plan id are never the same for the same run and set.
    param([string]$RunId, $Parts, [string[]]$RiskKeys = @())
    $text = 'atm-isolate-plan/1;' + $RunId + ';' + ((@($Parts) | ForEach-Object { Get-AtmCleanPlanItemKey $_ }) -join '|')
    if (@($RiskKeys).Count -gt 0) { $text += ';b1-accepted:' + ((@($RiskKeys) | Sort-Object -Unique) -join ',') }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)) } finally { $sha.Dispose() }
    return (-join @($h | ForEach-Object { $_.ToString('x2') }))
}

function Get-AtmQuarantineRootPath {
    # The quarantine root of the process user (J-ISO-5 (b)), or the suite's sandbox folder (test seam).
    if ($null -ne $script:AtmIsolationQuarantineRoot) { return [string]$script:AtmIsolationQuarantineRoot }
    $la = [Environment]::GetFolderPath('LocalApplicationData')
    if (-not $la) { return $null }
    return (Join-Path $la 'AgentTempManager\Q')
}

function Get-AtmOtherVolumeRefusal {
    <#
      MOVE_OTHER_VOLUME when -Path is on another volume than -QuarantinePath (contract sections 4.2 and 5): the rule of
      both plans (isolate: the root against the quarantine root; restore: the destination's parent against the entry).
      The path roots are compared as text, ignoring case, so the rule holds before the quarantine exists. The mover keeps
      its own check of the volume serial numbers (OTHER_VOLUME) as the second barrier: a mount point that passes this
      comparison is still refused there. Empty when either path is missing. Returned as plain output (callers wrap it in
      @()).
    #>
    param([string]$Path, [string]$QuarantinePath)
    if (-not $Path -or -not $QuarantinePath) { return @() }
    if ([string]::Equals([IO.Path]::GetPathRoot($Path), [IO.Path]::GetPathRoot($QuarantinePath), [StringComparison]::OrdinalIgnoreCase)) { return @() }
    return @('MOVE_OTHER_VOLUME')
}

function Open-AtmQuarantine {
    <#
      The quarantine root, pinned for the run. When it does not exist it is created: new folders relative to pinned parents
      (AtmSafeCreate.CreateNewDirectory: never an existing name, never through a reparse point, protected DACL of the new
      object only). When it exists it is checked as a record folder (AtmCleanLog folder rule: owner, no other principal
      that can add, remove or re-permission) and never fixed. Returns Check (the AtmCleanLog pin that holds the checked
      folder), Session (AtmSafeCreateSession pinned on it) and Code; the caller disposes both.
    #>
    param([string]$Path, [string]$ProcessUserSid)
    $out = [ordered]@{ Check = $null; Session = $null; Code = $null }
    if (-not $Path -or (Test-AtmAllowListPathSyntax $Path)) { $out.Code = 'QUARANTINE_PATH_INVALID'; return [pscustomobject]$out }
    $parent = [IO.Path]::GetDirectoryName($Path)
    if (-not [IO.Directory]::Exists($Path)) {
        $levels = @()
        if (-not [IO.Directory]::Exists($parent)) { $levels += , @([IO.Path]::GetDirectoryName($parent), [IO.Path]::GetFileName($parent)) }
        $levels += , @($parent, [IO.Path]::GetFileName($Path))
        foreach ($lv in $levels) {
            $pin = [AgentTempManager.AtmSafeCreate]::Pin($lv[0])
            try {
                if (-not $pin.IsPinned) { $out.Code = 'QUARANTINE_PARENT_' + $pin.Error; return [pscustomobject]$out }
                $n = [AgentTempManager.AtmSafeCreate]::CreateNewDirectory($pin, $lv[1], $ProcessUserSid)
                try { if ($null -ne $n.Error -and $n.Error -cne 'EXISTS') { $out.Code = 'QUARANTINE_CREATE_' + $n.Error; return [pscustomobject]$out } } finally { $n.Dispose() }
            } finally { $pin.Dispose() }
        }
    }
    $chk = [AgentTempManager.AtmCleanLog]::Pin($Path, $ProcessUserSid)
    if ($null -ne $chk.Error) { $out.Code = 'QUARANTINE_' + $chk.Error; $chk.Dispose(); return [pscustomobject]$out }
    $s = [AgentTempManager.AtmSafeCreate]::Pin($Path)
    if (-not $s.IsPinned) { $out.Code = 'QUARANTINE_PIN_' + $s.Error; $s.Dispose(); $chk.Dispose(); return [pscustomobject]$out }
    $out.Check = $chk; $out.Session = $s
    return [pscustomobject]$out
}

function Write-AtmIsolationRecord {
    # One JSON line of the isolation log or of an entry's manifest, written and flushed by -Log. $null, or the code.
    param($Log, [hashtable]$State, [string]$Schema, [string]$Type, [System.Collections.IDictionary]$Fields = @{})
    $State.Seq++
    $rec = [ordered]@{ schema = $Schema; type = $Type; id = $State.Id; recSeq = $State.Seq; utc = [datetime]::UtcNow.ToString('o') }
    foreach ($k in $Fields.Keys) { $rec[$k] = $Fields[$k] }
    $line = $null
    try { $line = ConvertTo-Json -InputObject $rec -Compress -Depth 5 } catch { return 'RECORD_INVALID' }
    try { return $Log.AppendLine($line) } catch { return ('WRITE_' + $_.Exception.GetBaseException().GetType().Name) }
}

function Get-AtmIsolatePlanCheck {
    <#
      The plan check of isolate (Invoke-AtmIsolateCore, step 7) and why it did not match, for the log. The same three
      checks as always, in the same order and with the same short-circuit: the planned root must be seen exactly once in
      the fresh inventory (ROOT_NOT_SEEN_ONCE (N)); then its plan item key must be unchanged (PLAN_ITEM_CHANGED, with the
      names of the components that changed in ChangedFields); then the gates (Get-AtmCleanGateRefusal), each reason
      reduced to its leading code (B1_EXCEPTION_NEW_UNINSPECTABLE_PROCESS keeps its count; a reason without a leading code
      is UNCODED_REASON). Only codes, counts and field names: never process identities, names, command lines, accounts,
      SIDs, paths or localized text. The caller refuses on any reason, as before (PLAN_CHANGED_BEFORE_EXECUTION).
    #>
    param($Planned, $Inventory, $RuntimeEvidence, [bool]$AcceptRisk, $Risk)
    $m3 = @($Inventory.Partitions | Where-Object { [string]::Equals($_.Path, $Planned.Path, [StringComparison]::Ordinal) -and $_.Kind -ne 'NotScanned' -and $_.Kind -ne 'BaseLooseFiles' })
    if ($m3.Count -ne 1) { return [pscustomobject]@{ Reasons = @("ROOT_NOT_SEEN_ONCE ($($m3.Count))"); ChangedFields = @() } }
    $now = $m3[0]
    if ((Get-AtmCleanPlanItemKey $now) -cne (Get-AtmCleanPlanItemKey $Planned)) {
        # The components of Get-AtmCleanPlanItemKey, compared as it compares them; only their names are kept.
        $ticks = { param($x) if ($x.NewestWriteTimeUtc) { [string]([datetime]$x.NewestWriteTimeUtc).ToUniversalTime().Ticks } else { '' } }
        $fields = @(foreach ($f in @(@('path', 'Path'), @('fingerprint', 'Fingerprint'), @('files', 'Files'), @('dirs', 'Dirs'), @('bytes', 'Bytes'))) {
                if ([string]$now.($f[1]) -cne [string]$Planned.($f[1])) { $f[0] } })
        if ((& $ticks $now) -cne (& $ticks $Planned)) { $fields += 'newestWrite' }
        return [pscustomobject]@{ Reasons = @('PLAN_ITEM_CHANGED'); ChangedFields = @($fields) }
    }
    $why = @(Get-AtmCleanGateRefusal -Gate (Test-AtmCandidate -Partition $now -Inventory $Inventory -ForClean -RuntimeEvidence $RuntimeEvidence -AcceptB1ResidualRisk:$AcceptRisk) -Risk $Risk)
    $codes = @(foreach ($w in $why) {
            $t = [string]$w
            if ($t -cmatch '^B1_EXCEPTION_NEW_UNINSPECTABLE_PROCESS \(\d+\)$') { $t }
            elseif ($t -cmatch '^([A-Z][A-Z0-9_]*)(?=$|[\s:(])') { $Matches[1] }
            else { 'UNCODED_REASON' } })
    return [pscustomobject]@{ Reasons = @($codes); ChangedFields = @() }
}

function Invoke-AtmIsolate {
    <#
      Entry point of isolate (CLI). With the isolation gate closed (every distributed copy) it runs the plan-only flow of
      Invoke-AtmIsolateCore and never touches the lock. Past the gate it first takes the clean lock (B8, the same name:
      T-ISO-7) without waiting, before any inventory, and holds it through the plan, the confirmation and the move; it is
      released last. A refusal (CLEAN_LOCK_BUSY, _ABANDONED, ...) starts nothing. Parameters: as Invoke-AtmIsolateCore.
    #>
    [CmdletBinding()]
    param(
        [object[]]$Entries,
        [scriptblock]$PlanPresenter,
        [scriptblock]$ConfirmationReader,
        [hashtable]$InventoryArgs = @{},
        [string]$LogFile,
        [hashtable]$Interaction = @{},
        [switch]$AcceptB1ResidualRisk,
        [scriptblock]$BeforeMoveHook,
        [scriptblock]$MoveTreeImpl
    )
    if (-not $script:AtmIsolationEnabled) { return (Invoke-AtmIsolateCore @PSBoundParameters) }
    # No closure: the body runs in this session state, where the engine's functions are, and finds $isoBound here.
    $isoBound = @{} + $PSBoundParameters
    $u = Invoke-AtmUnderSharedLock -Body { Invoke-AtmIsolateCore @isoBound }
    if (-not $u.Acquired) { return (Invoke-AtmIsolateCore @PSBoundParameters -LockRefusal ('CLEAN_LOCK_' + $u.Status) -LockReleaseError $u.ReleaseError) }
    $res = $u.Result
    # A failed release never replaces the main code; with none it makes the run incomplete.
    if ($null -ne $u.ReleaseError -and $null -ne $res) {
        $res.LockReleaseError = $u.ReleaseError
        if (-not $res.Aborted -and -not $res.StoppedBy) { if (@($res.Results).Count -gt 0) { $res.StoppedBy = 'LOCK_RELEASE_FAILED' } else { $res.Aborted = 'LOCK_RELEASE_FAILED' } }
    }
    return $res
}

function Invoke-AtmIsolateCore {
    <#
      Fail-closed isolation of ONE session root of the own profile, called only by Invoke-AtmIsolate (which owns the lock).
        1. syntax of every exact path (the clean allowlist rules), duplicates refused;
        2. a fresh inventory and one runtime collection (B2-1) for the plan;
        3. the 0.3.x target rule (Get-AtmIsolationTarget), then the same gates as clean (Test-AtmCandidate -ForClean, lock
           probe included): ELIGIBLE, or the B1 restricted exception per root (J-ISO-2 (b)) only past the gate with
           -AcceptB1ResidualRisk; RECENT blocks (J-ISO-3 (a)); a fingerprint given with a path must still match; a root
           on another volume than the quarantine refuses (MOVE_OTHER_VOLUME, sections 4.2 and 5: nothing is asked,
           logged or created; past the gate the lock B8 was taken before the plan, as for every refusal of the plan, and
           is released); the quota of the policy and the free space of the quarantine's volume refuse
           (QUARANTINE_QUOTA_REACHED, LOW_DISK_SPACE; section 10), here and at the revalidation;
        4. the plan id (isolation prefix) and the plan through -PlanPresenter scriptblock(verified, rejected, inventory,
           planId). With the isolation gate closed the run stops here (ISOLAMENTO_REAL_DESABILITADO).
      Past the gate:
        5. one root per run (fixed in code); a confirmation reader, a NEW -LogFile (T1 writer, atm.isolatelog/1) and an
           interactive console observed by the engine are required; the log is created before any question;
        6. for a root under the B1 exception, its residual-risk phrase; then ISOLAR <N> CAMINHOS <planid8>. No AUT-2
           declarations (J-ISO-4 (a)): nothing is discarded. Any refusal or wrong phrase stops the run;
        7. the plan check (a fresh inventory, the same gates, the same statistics) and, after -BeforeMoveHook (tests), the
           revalidation of the root immediately before the move;
        8. the quarantine root (Open-AtmQuarantine), a new entry folder <yyyyMMddTHHmmssZ>-<8 hex> and its manifest
           (atm.quarantine/1: entry); then move-intent in the log and in the manifest, flushed, BEFORE the mover;
        9. the mover (AtmMover.MoveTree: same volume, pinned, through the handle, measured before and after) into
           <entry>\payload, then move-result in the manifest and in the log. Anything but a moved and verified tree stops
           the run (STOPPED_AFTER_<outcome>); nothing is undone.
      -MoveTreeImpl: test seam, never passed by the CLI: a stand-in mover scriptblock(partition, entrySession, name) that
      returns an object like AtmMoveResult. Reached only past the gate. Aborted: the mover was never called. StoppedBy:
      it was called. Returns arrays only.
    #>
    [CmdletBinding()]
    param(
        [object[]]$Entries,
        [scriptblock]$PlanPresenter,
        [scriptblock]$ConfirmationReader,
        [hashtable]$InventoryArgs = @{},
        [string]$LogFile,
        [hashtable]$Interaction = @{},
        [switch]$AcceptB1ResidualRisk,
        [scriptblock]$BeforeMoveHook,
        [scriptblock]$MoveTreeImpl,
        [string]$LockRefusal,
        [string]$LockReleaseError
    )
    $rejected = New-Object System.Collections.Generic.List[object]
    $verified = New-Object System.Collections.Generic.List[object]
    $results = New-Object System.Collections.Generic.List[object]
    $logErrors = New-Object System.Collections.Generic.List[object]
    $state = @{ Aborted = $null; Stopped = $null; PlanId = $null; Phrase = $null; RunId = $null; LogCreated = $false; RefusedAt = $null; EntryId = $null; EntryPath = $null }
    $finish = {
        [pscustomobject]@{
            Requested = @($Entries).Count; Rejected = $rejected.ToArray(); Verified = $verified.ToArray(); PlanId = $state.PlanId; Phrase = $state.Phrase
            Aborted = $state.Aborted; StoppedBy = $state.Stopped; Results = $results.ToArray(); EntryId = $state.EntryId; EntryPath = $state.EntryPath
            RunId = $state.RunId; LogFile = $(if ($state.RunId) { $LogFile } else { $null }); LogCreated = $state.LogCreated; LogErrors = $logErrors.ToArray()
            LockReleaseError = $(if ($LockReleaseError) { $LockReleaseError } else { $null }); RefusedAt = $state.RefusedAt
        }
    }
    if ($LockRefusal) { $state.Aborted = $LockRefusal; return (& $finish) }
    if (@($Entries).Count -eq 0) { $state.Aborted = 'ALLOWLIST_VAZIA'; return (& $finish) }
    if (-not $PlanPresenter) { $state.Aborted = 'SEM_APRESENTACAO'; return (& $finish) }

    $syntaxOk = New-Object System.Collections.Generic.List[object]
    foreach ($e in $Entries) {
        $why = Test-AtmAllowListPathSyntax $e.Path
        if ($why) { $rejected.Add([pscustomobject]@{ Path = $e.Path; Source = $e.Source; Reasons = @($why) }) } else { $syntaxOk.Add($e) }
    }
    # B1 restricted exception: considered only past the isolation gate, as clean considers it only past the deletion gate.
    $acceptRisk = ([bool]$AcceptB1ResidualRisk -and $script:AtmIsolationEnabled)
    $riskByPath = @{}
    $ia = @{} + $InventoryArgs
    $inv = Invoke-AtmInventory @ia
    $rt = Get-AtmCleanRuntimeEvidence -Inventory $inv -InventoryArgs $ia
    $inv | Add-Member -NotePropertyName RuntimeEvidence -NotePropertyValue $rt
    $policy = Get-AtmQuarantinePolicy -ConfigDir ([string]$InventoryArgs['ConfigDir'])
    $seen = @{}
    foreach ($e in $syntaxOk) {
        $k = $e.Path.ToLowerInvariant()
        if ($seen.ContainsKey($k)) { $rejected.Add([pscustomobject]@{ Path = $e.Path; Source = $e.Source; Reasons = @('DUPLICADO_NA_ALLOWLIST') }); continue }
        $seen[$k] = $true
        $t = Get-AtmIsolationTarget -Inventory $inv -Path $e.Path
        if ($null -eq $t.Partition) { $rejected.Add([pscustomobject]@{ Path = $e.Path; Source = $e.Source; Reasons = @($t.Reasons) }); continue }
        $p = $t.Partition
        $g = Test-AtmCandidate -Partition $p -Inventory $inv -ForClean -RuntimeEvidence $rt -AcceptB1ResidualRisk:$acceptRisk
        $reasons = @($g.Reasons)
        $fpChanged = [bool]($e.Fingerprint -and $e.Fingerprint -ne $p.Fingerprint)
        if ($fpChanged) { $reasons += "ALTERADO_DESDE_O_PREVIEW (fingerprint $($e.Fingerprint) -> $($p.Fingerprint))" }
        $okRisk = ($acceptRisk -and [string]$g.Category -ceq $script:AtmB1ExceptionCategory -and $null -ne $g.B1Risk -and -not $fpChanged)
        # Another volume than the quarantine (sections 4.2 and 5): refused here, under the B1 exception too, before the
        # capacity rules (whose free space is the quarantine's volume).
        $vol = @(Get-AtmOtherVolumeRefusal -Path $p.Path -QuarantinePath (Get-AtmQuarantineRootPath))
        if (-not $okRisk -and ($g.Category -ne 'ELIGIBLE' -or $reasons.Count -gt 0)) { $rejected.Add([pscustomobject]@{ Path = $e.Path; Source = $e.Source; Reasons = @($reasons + $vol) }); continue }
        if ($vol.Count -gt 0) { $rejected.Add([pscustomobject]@{ Path = $e.Path; Source = $e.Source; Reasons = $vol }); continue }
        # The quota of the policy and the free space of the quarantine's volume (section 10): they refuse, never purge.
        $cap = @(Get-AtmQuarantineCapacityRefusal -QuarantineRoot (Get-AtmQuarantineRootPath) -Bytes ([long]$p.Bytes) -Policy $policy)
        if ($cap.Count -gt 0) { $rejected.Add([pscustomobject]@{ Path = $e.Path; Source = $e.Source; Reasons = $cap }); continue }
        $verified.Add($p)
        if ($okRisk) { $riskByPath[$p.Path] = $g.B1Risk }
    }
    if ($verified.Count -eq 0) { $state.Aborted = 'NENHUM_CAMINHO_ISOLAVEL'; return (& $finish) }

    $runId = [guid]::NewGuid().ToString()
    $riskKeys = @(@($riskByPath.Values | ForEach-Object { @($_.Keys) }) | Sort-Object -Unique)
    $state.PlanId = Get-AtmIsolatePlanId -RunId $runId -Parts $verified.ToArray() -RiskKeys $riskKeys
    $state.Phrase = "ISOLAR $($verified.Count) CAMINHOS $($state.PlanId.Substring(0, 8).ToUpperInvariant())"
    & $PlanPresenter $verified.ToArray() $rejected.ToArray() $inv $state.PlanId
    if (-not $script:AtmIsolationEnabled) { $state.Aborted = 'ISOLAMENTO_REAL_DESABILITADO'; return (& $finish) }

    # ---- past the isolation gate (the suite only, in its own process) ----
    if ($verified.Count -gt $script:AtmIsolationMaxRoots) { $state.Aborted = 'ISOLAMENTO_UMA_RAIZ_POR_EXECUCAO'; return (& $finish) }
    if (-not $ConfirmationReader) { $state.Aborted = 'SEM_APRESENTACAO_OU_CONFIRMACAO'; return (& $finish) }
    if (-not $LogFile) { $state.Aborted = 'LOG_REQUIRED'; return (& $finish) }
    $qPath = Get-AtmQuarantineRootPath
    if (-not $qPath) { $state.Aborted = 'QUARANTINE_PATH_INVALID'; return (& $finish) }
    if ($LogFile.StartsWith($qPath.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { $state.Aborted = 'LOG_DESTINATION_NOT_ALLOWED'; return (& $finish) }
    $console = Get-AtmEngineConsoleObservation
    if (-not $console.Observed) { $state.Aborted = 'CONSOLE_NOT_OBSERVED'; return (& $finish) }
    $callerName = [string]$Interaction['Caller']
    $interactionRec = [ordered]@{ caller = $(if ($callerName -ceq 'CLI' -or $callerName -ceq 'TUI') { $callerName } else { 'DIRECT_CALL' }); consoleRequiredByCaller = ($Interaction['ConsoleRequired'] -eq $true)
        callerFieldsVerified = $false; interactiveConsoleObserved = $true; observedBy = $console.By; identifiesRespondent = $false }
    $state.RunId = $runId
    $me = Get-AtmCurrentIdentity
    $ls = @{ Id = $runId; Seq = 0 }
    $halt = { param([string]$Code) if ($results.Count -gt 0) { $state.Stopped = $Code } else { $state.Aborted = $Code } }
    $logFail = { param([string]$Stage, [string]$Code) $logErrors.Add([pscustomobject]@{ Stage = $Stage; OpId = $null; Code = $Code }) }
    $p = $verified[0]
    $opId = '{0}:1' -f $runId
    $risk = $(if ($riskByPath.ContainsKey($p.Path)) { $riskByPath[$p.Path] } else { $null })
    $log = $null; $quar = $null; $entry = $null; $man = $null
    try {
        $opened = Open-AtmCleanLog -Path $LogFile -Inventory $inv -ProcessUserSid $me.Sid
        $state.LogCreated = [bool]$opened.Created
        if ($null -eq $opened.Log) { & $logFail 'open' $opened.Code; $state.Aborted = 'LOG_OPEN_FAILED'; return (& $finish) }
        $log = $opened.Log
        $nw = $(if ($p.NewestWriteTimeUtc) { ([datetime]$p.NewestWriteTimeUtc).ToUniversalTime().ToString('o') } else { $null })
        $lc = Write-AtmIsolationRecord -Log $log -State $ls -Schema $script:AtmIsolateLogSchema -Type 'run-start' -Fields ([ordered]@{ tool = $script:AtmVersion; user = $inv.Identity.Name; sid = $inv.Identity.Sid; elevated = [bool]$inv.Identity.IsAdmin
                planned = 1; planId = $state.PlanId; b1Exception = ($null -ne $risk); uninspectableProcesses = $(if ($null -ne $risk) { $risk.Uninspectable } else { $null }) })
        if ($null -eq $lc) {
            $lc = Write-AtmIsolationRecord -Log $log -State $ls -Schema $script:AtmIsolateLogSchema -Type 'plan' -Fields ([ordered]@{ opId = $opId; path = $p.Path; fingerprint = $p.Fingerprint; files = $p.Files; dirs = $p.Dirs; bytes = $p.Bytes; newestWriteUtc = $nw
                    category = $(if ($null -ne $risk) { $script:AtmB1ExceptionCategory } else { 'ELIGIBLE' }); uninspectableKeys = $(if ($null -ne $risk) { @($risk.Keys) } else { $null }) })
        }
        if ($null -ne $lc) { & $logFail 'plan' $lc; $state.Aborted = 'LOG_WRITE_FAILED'; return (& $finish) }

        # The B1 residual risk of the root (when it is under the exception), then the confirmation of the exact set.
        $refusal = $null
        if ($null -ne $risk) {
            $riskPhrase = Get-AtmText 'clean.phrase.b1Risk'
            $rk = Test-AtmTypedPhrase -Typed (& $ConfirmationReader $riskPhrase 'risk' $p.Path @($riskPhrase) $risk.Uninspectable) -Phrases @($riskPhrase)
            if ($rk.Code) { $refusal = [pscustomobject]@{ Code = 'DECLARATION_' + $rk.Code; Step = 'risk'; Path = $p.Path } }
        }
        if ($null -eq $refusal) {
            $fc = Test-AtmTypedPhrase -Typed (& $ConfirmationReader $state.Phrase 'confirm' $null @($state.Phrase)) -Phrases @($state.Phrase)
            if ($fc.Code) { $refusal = [pscustomobject]@{ Code = 'CONFIRMACAO_AUSENTE_OU_DIVERGENTE'; Step = 'confirm'; Path = $null } }
        }
        if ($null -ne $refusal) {
            $state.RefusedAt = $refusal
            $lc = Write-AtmIsolationRecord -Log $log -State $ls -Schema $script:AtmIsolateLogSchema -Type 'confirmation' -Fields ([ordered]@{ accepted = $false; planId = $state.PlanId; step = $refusal.Step; refusal = $refusal.Code; interaction = $interactionRec })
            if ($null -ne $lc) { & $logFail 'confirmation' $lc }
            $state.Aborted = $refusal.Code
        } else {
            $lc = Write-AtmIsolationRecord -Log $log -State $ls -Schema $script:AtmIsolateLogSchema -Type 'confirmation' -Fields ([ordered]@{ accepted = $true; planId = $state.PlanId; roots = 1; b1ResidualRiskAccepted = ($null -ne $risk); interaction = $interactionRec })
            if ($null -ne $lc) { & $logFail 'confirmation' $lc; $state.Aborted = 'LOG_WRITE_FAILED' }
        }
        if (-not $state.Aborted) {
            # The set must not have changed while the operator answered: a fresh inventory, the same gates, the same statistics.
            $iaChk = @{} + $InventoryArgs; $iaChk['NoProgress'] = $true
            $invChk = Invoke-AtmInventory @iaChk
            $rtChk = Get-AtmCleanRuntimeEvidence -Inventory $invChk -InventoryArgs $iaChk
            $chk = Get-AtmIsolatePlanCheck -Planned $p -Inventory $invChk -RuntimeEvidence $rtChk -AcceptRisk $acceptRisk -Risk $risk
            $changed = (@($chk.Reasons).Count -gt 0)
            $pcf = [ordered]@{ planId = $state.PlanId; matched = (-not $changed); reasons = @($chk.Reasons) }
            if (@($chk.ChangedFields).Count -gt 0) { $pcf['changedFields'] = @($chk.ChangedFields) }
            $lc = Write-AtmIsolationRecord -Log $log -State $ls -Schema $script:AtmIsolateLogSchema -Type 'plan-check' -Fields $pcf
            if ($null -ne $lc) { & $logFail 'plan-check' $lc; $state.Aborted = 'LOG_WRITE_FAILED' }
            elseif ($changed) { $state.Aborted = 'PLAN_CHANGED_BEFORE_EXECUTION' }
        }
        if (-not $state.Aborted) {
            # Revalidation immediately before the move (fresh inventory of the root, fresh runtime evidence, every gate).
            if ($BeforeMoveHook) { & $BeforeMoveHook $p }
            $args2 = @{} + $InventoryArgs; $args2['OnlyRootPath'] = $p.Path; $args2['NoProgress'] = $true
            $re = Invoke-AtmInventory @args2
            $rtRe = Get-AtmCleanRuntimeEvidence -Inventory $re -InventoryArgs $args2
            $cur = @($re.Partitions | Where-Object { [string]::Equals($_.Path, $p.Path, [StringComparison]::OrdinalIgnoreCase) -and $_.Kind -ne 'NotScanned' -and $_.Kind -ne 'BaseLooseFiles' })
            $why = @()
            $c = $null
            if ($cur.Count -ne 1) { $why += 'DESAPARECEU_OU_AMBIGUO_NA_REVALIDACAO' }
            else {
                $c = $cur[0]
                if ($c.Fingerprint -ne $p.Fingerprint) { $why += "ALTERADO_APOS_CONFIRMACAO (fingerprint $($p.Fingerprint) -> $($c.Fingerprint))" }
                $why += @(Get-AtmCleanGateRefusal -Gate (Test-AtmCandidate -Partition $c -Inventory $re -ForClean -RuntimeEvidence $rtRe -AcceptB1ResidualRisk:$acceptRisk) -Risk $risk)
                $why += @(Get-AtmQuarantineCapacityRefusal -QuarantineRoot $qPath -Bytes ([long]$c.Bytes) -Policy $policy)
            }
            if ($why.Count -gt 0) {
                $lc = Write-AtmIsolationRecord -Log $log -State $ls -Schema $script:AtmIsolateLogSchema -Type 'skip' -Fields ([ordered]@{ opId = $opId; path = $p.Path; reasons = @($why) })
                if ($null -ne $lc) { & $logFail 'skip' $lc }
                $state.Aborted = 'REVALIDATION_REFUSED'
            }
        }
        if (-not $state.Aborted) {
            # The quarantine, a new entry and its manifest (no file names, contents or command lines: section 7.3).
            $quar = Open-AtmQuarantine -Path $qPath -ProcessUserSid $me.Sid
            if ($null -ne $quar.Code) { $state.Aborted = $quar.Code }
        }
        if (-not $state.Aborted) {
            $state.EntryId = [datetime]::UtcNow.ToString('yyyyMMdd\THHmmss\Z', [Globalization.CultureInfo]::InvariantCulture) + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
            $entry = [AgentTempManager.AtmSafeCreate]::CreateNewDirectory($quar.Session, $state.EntryId, $me.Sid)
            if ($null -ne $entry.Error) { $state.Aborted = 'QUARANTINE_ENTRY_' + $entry.Error }
            else {
                $state.EntryPath = $entry.ParentPath
                $man = [AgentTempManager.AtmCleanLog]::Pin($entry.ParentPath, $me.Sid)
                $mc = $(if ($null -ne $man.Error) { $man.Error } else { $man.Create('manifest.jsonl') })
                if ($null -ne $mc) { $state.Aborted = 'MANIFEST_' + $mc }
            }
        }
        $ms = @{ Id = $state.EntryId; Seq = 0 }
        if (-not $state.Aborted) {
            $lc = Write-AtmIsolationRecord -Log $man -State $ms -Schema $script:AtmQuarantineSchema -Type 'entry' -Fields ([ordered]@{ tool = $script:AtmVersion; runId = $runId; planId = $state.PlanId
                    actor = [ordered]@{ sid = $inv.Identity.Sid; elevated = [bool]$inv.Identity.IsAdmin }; targetKind = 'SessionRoot'; originalPath = $c.Path; provider = $c.Provider })
            if ($null -ne $lc) { $state.Aborted = 'MANIFEST_WRITE_FAILED' }
        }
        if (-not $state.Aborted) {
            # The intent is written and flushed, in the log and in the manifest, BEFORE the mover; without both, no move.
            $nwc = $(if ($c.NewestWriteTimeUtc) { ([datetime]$c.NewestWriteTimeUtc).ToUniversalTime().ToString('o') } else { $null })
            $lc = Write-AtmIsolationRecord -Log $log -State $ls -Schema $script:AtmIsolateLogSchema -Type 'move-intent' -Fields ([ordered]@{ opId = $opId; path = $c.Path; entryId = $state.EntryId; fingerprint = $c.Fingerprint; files = $c.Files; dirs = $c.Dirs; bytes = $c.Bytes; newestWriteUtc = $nwc })
            if ($null -ne $lc) { & $logFail 'move-intent' $lc; & $halt 'LOG_INTENT_FAILED' }
            else {
                $lc = Write-AtmIsolationRecord -Log $man -State $ms -Schema $script:AtmQuarantineSchema -Type 'move-intent' -Fields ([ordered]@{ opId = $opId; fingerprint = $c.Fingerprint; files = $c.Files; dirs = $c.Dirs; bytes = $c.Bytes; newestWriteUtc = $nwc })
                if ($null -ne $lc) { & $halt 'MANIFEST_INTENT_FAILED' }
            }
            # The manifest writer pins the entry folder shared for reading only, which a rename into that folder cannot
            # pass: it is closed before the move and reopened (OpenExisting, the same checks) for the result.
            if (-not $state.Aborted -and -not $state.Stopped) {
                $mcl = $man.Close(); $man.Dispose(); $man = $null
                if ($null -ne $mcl) { & $halt 'MANIFEST_CLOSE_FAILED' }
            }
        }
        if (-not $state.Aborted -and -not $state.Stopped) {
            # The only call to the mover: the same volume, pinned, through the handle, measured before and after.
            $mv = $null; $exType = $null
            try {
                if ($MoveTreeImpl) { $mv = & $MoveTreeImpl $c $entry 'payload' }
                else { $mv = [AgentTempManager.AtmMover]::MoveTree($c.Path, $c.Files, $c.Dirs, $c.Bytes, $c.NewestWriteTimeUtc.Ticks, $entry, 'payload', $null) }
                if ($null -eq $mv) { throw [InvalidOperationException]::new('MOVER_NO_RESULT') }
            } catch { $mv = $null; $exType = $_.Exception.GetBaseException().GetType().Name }
            $outcome = $(if ($null -ne $exType) { 'EXCEPTION' } elseif ($mv.Moved -and $mv.Verified) { 'COMPLETE' } elseif ($mv.Moved) { 'INTEGRITY_FAILED' } else { 'REFUSED' })
            $known = ($null -ne $mv)
            $row = [pscustomobject]@{ OpId = $opId; Path = $c.Path; EntryId = $state.EntryId; Outcome = $outcome; Moved = ($known -and [bool]$mv.Moved); Verified = ($known -and [bool]$mv.Verified)
                RenameStatus = $(if ($known) { $mv.RenameStatus } else { $null }); AbortReason = $(if ($known) { $mv.AbortReason } else { $null }); ExceptionType = $exType }
            $results.Add($row)
            $after = [ordered]@{ opId = $opId; outcome = $outcome; moved = $row.Moved; verified = $row.Verified
                filesAfter = $(if ($known) { $mv.FilesAfter } else { $null }); dirsAfter = $(if ($known) { $mv.DirsAfter } else { $null }); bytesAfter = $(if ($known) { $mv.BytesAfter } else { $null })
                digestPlanned = $(if ($known) { $mv.DigestPlanned } else { $null }); digestAfter = $(if ($known) { $mv.DigestAfter } else { $null })
                renameStatus = $row.RenameStatus; abortReason = $row.AbortReason; exceptionType = $exType }
            $man = [AgentTempManager.AtmCleanLog]::Pin($entry.ParentPath, $me.Sid)
            $mc = $(if ($null -ne $man.Error) { $man.Error } else { $man.OpenExisting('manifest.jsonl') })
            if ($null -eq $mc) { $mc = Write-AtmIsolationRecord -Log $man -State $ms -Schema $script:AtmQuarantineSchema -Type 'move-result' -Fields $after }
            $after['path'] = $c.Path; $after['entryId'] = $state.EntryId
            $lc = Write-AtmIsolationRecord -Log $log -State $ls -Schema $script:AtmIsolateLogSchema -Type 'move-result' -Fields $after
            if ($null -ne $lc) { & $logFail 'move-result' $lc; & $halt 'LOG_RESULT_FAILED' }
            elseif ($null -ne $mc) { & $halt 'MANIFEST_RESULT_FAILED' }
            elseif ($outcome -cne 'COMPLETE') { & $halt ('STOPPED_AFTER_' + $outcome) }
        }
        # run-end only while the log has not failed; neither a failed run-end nor a failed close replaces the main code.
        if ($logErrors.Count -eq 0) {
            $lc = Write-AtmIsolationRecord -Log $log -State $ls -Schema $script:AtmIsolateLogSchema -Type 'run-end' -Fields ([ordered]@{ results = $results.Count; complete = @($results | Where-Object { $_.Outcome -ceq 'COMPLETE' }).Count; stoppedBy = $(if ($state.Stopped) { $state.Stopped } else { $state.Aborted }); entryId = $state.EntryId })
            if ($null -ne $lc) { & $logFail 'run-end' $lc; if (-not $state.Aborted -and -not $state.Stopped) { & $halt 'LOG_END_FAILED' } }
        }
        if ($null -ne $man) { $mcl = $man.Close(); if ($null -ne $mcl -and -not $state.Aborted -and -not $state.Stopped) { & $halt 'MANIFEST_CLOSE_FAILED' } }
        $cc = $log.Close()
        if ($null -ne $cc) { & $logFail 'close' $cc; if (-not $state.Aborted -and -not $state.Stopped) { & $halt 'LOG_CLOSE_FAILED' } }
        return (& $finish)
    } finally {
        if ($null -ne $man) { try { $man.Dispose() } catch { $null = $_ } }
        if ($null -ne $entry) { try { $entry.Dispose() } catch { $null = $_ } }
        if ($null -ne $quar) { foreach ($h in @($quar.Session, $quar.Check)) { if ($null -ne $h) { try { $h.Dispose() } catch { $null = $_ } } } }
        if ($null -ne $log) { try { $log.Dispose() } catch { $null = $_ } }
    }
}

# ---------------------------------------------------------------------------------------------
# Quarantine management (phase P3b). list, inspect and verify only read: nothing is written, not even to a manifest
# (T-ISO-4). restore moves one entry back, past the isolation gate only.
# ---------------------------------------------------------------------------------------------
$script:AtmQuarantineEntryIdPattern = '^\d{8}T\d{6}Z-[0-9a-f]{8}$'

function Read-AtmQuarantineManifest {
    # The records of one entry's manifest, read with full sharing (never opened for writing) and checked (section 7.3):
    # JSON lines of atm.quarantine/1, recSeq consecutive from 1, every record carrying the folder's id, the first one an
    # 'entry'. Returns Records and Problem (MANIFEST_MISSING, MANIFEST_UNREADABLE or MANIFEST_INVALID).
    param([string]$EntryPath, [string]$Id)
    $out = [ordered]@{ Records = @(); Problem = $null }
    $f = Join-Path $EntryPath 'manifest.jsonl'
    if (-not [IO.File]::Exists($f)) { $out.Problem = 'MANIFEST_MISSING'; return [pscustomobject]$out }
    $txt = $null
    try {
        $fs = [IO.File]::Open($f, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        try { $txt = (New-Object IO.StreamReader($fs, (New-Object Text.UTF8Encoding($false, $true)))).ReadToEnd() } finally { $fs.Dispose() }
    } catch { $out.Problem = 'MANIFEST_UNREADABLE'; return [pscustomobject]$out }
    $recs = New-Object System.Collections.Generic.List[object]
    $n = 0
    foreach ($line in @($txt.Split([char]10) | Where-Object { $_ -ne '' })) {
        $n++
        try {
            $r = $line | ConvertFrom-Json
            if ([string]$r.schema -cne $script:AtmQuarantineSchema -or [int]$r.recSeq -ne $n -or [string]$r.id -cne $Id -or -not [string]$r.type) { throw 'record' }
        } catch { $out.Problem = 'MANIFEST_INVALID'; return [pscustomobject]$out }
        $recs.Add($r)
    }
    if ($recs.Count -eq 0 -or [string]$recs[0].type -cne 'entry' -or -not $txt.EndsWith("`n")) { $out.Problem = 'MANIFEST_INVALID'; return [pscustomobject]$out }
    $out.Records = $recs.ToArray()
    return [pscustomobject]$out
}

function Get-AtmRecordField {
    # One field of a manifest record, $null when the record does not carry it (a valid manifest may lack optional fields).
    param($Record, [string]$Name)
    if ($null -eq $Record) { return $null }
    $p = $Record.PSObject.Properties[$Name]
    return $(if ($null -ne $p) { $p.Value } else { $null })
}

function Get-AtmQuarantineEntryState {
    # The state derived from the records, in order (contract section 7.4): ISOLATED, INCOMPLETE (an intent without its
    # result; Pending says which), FAILED, RESTORED, PURGED; ABANDONED when the manifest is not this identity's. A purge
    # that the deleter refused before deleting anything leaves the entry ISOLATED; any other purge outcome but a complete,
    # verified one (part deleted, an exception, a removal not confirmed) makes it FAILED. IsolatedUtc: when the entry
    # first became ISOLATED (its complete move-result, or its reconciliation), the start of its retention.
    param($Records, [string]$OwnSid)
    $state = 'INCOMPLETE'; $pending = 'move'; $outcome = $null; $isolatedUtc = $null
    foreach ($r in @($Records)) {
        switch ([string]$r.type) {
            'move-intent' { $state = 'INCOMPLETE'; $pending = 'move' }
            'move-result' { $outcome = [string](Get-AtmRecordField $r 'outcome'); $pending = $null; $state = $(if ($outcome -ceq 'COMPLETE') { 'ISOLATED' } else { 'FAILED' }) }
            'reconcile' { if ([string](Get-AtmRecordField $r 'result') -ceq 'OK') { $state = 'ISOLATED'; $pending = $null } }
            'restore-intent' { $state = 'INCOMPLETE'; $pending = 'restore' }
            'restore-result' { $pending = $null; $outcome = [string](Get-AtmRecordField $r 'outcome'); $state = $(if ($outcome -ceq 'COMPLETE') { 'RESTORED' } elseif (Get-AtmRecordField $r 'moved') { 'FAILED' } else { 'ISOLATED' }) }
            'purge-intent' { $state = 'INCOMPLETE'; $pending = 'purge' }
            'purge-result' { $pending = $null; $outcome = [string](Get-AtmRecordField $r 'outcome'); $state = $(if ($outcome -ceq 'COMPLETE') { 'PURGED' } elseif ($outcome -ceq 'REFUSED') { 'ISOLATED' } else { 'FAILED' }) }
        }
        if ($state -ceq 'ISOLATED' -and $null -eq $isolatedUtc) { $u = Get-AtmRecordField $r 'utc'; if ($null -ne $u) { $isolatedUtc = New-Object DateTime ((ConvertTo-AtmUtcTicks $u), [DateTimeKind]::Utc) } }
    }
    $actor = [string](Get-AtmRecordField (Get-AtmRecordField $Records[0] 'actor') 'sid')
    if ($actor -cne $OwnSid) { $state = 'ABANDONED' }
    return [pscustomobject]@{ State = $state; Pending = $pending; LastOutcome = $outcome; ActorSid = $actor; IsolatedUtc = $isolatedUtc }
}

function Get-AtmQuarantineEntrySummary {
    # One entry folder: its manifest, derived state, the measurement its intent recorded and the one verified after the
    # move (no file names). A manifest that breaks section 7.3, or a payload incoherent with the last record (present
    # after a completed restore or purge), gives State ENTRY_MANIFEST_INVALID: reported only, never restored or purged.
    # Retention (section 10, J-ISO-6 (b)): an ISOLATED entry whose -RetentionDays have passed since it was isolated is
    # marked EXPIRED (ExpiresUtc says when); a mark only, nothing is done to it. -NowUtc: the clock of the caller.
    param([string]$Path, [string]$OwnSid, [int]$RetentionDays = $script:AtmQuarantineDefaultRetentionDays, $NowUtc = $null)
    $id = [IO.Path]::GetFileName($Path)
    $s = [ordered]@{ Id = $id; Path = $Path; State = 'UNRECOGNIZED'; Problem = $null; Pending = $null; LastOutcome = $null; ActorSid = $null; TargetKind = $null; OriginalPath = $null
        CreatedUtc = $null; Files = $null; Dirs = $null; Bytes = $null; NewestWriteUtc = $null; Verified = $null; PayloadPresent = $false; Records = @(); IsolatedUtc = $null; ExpiresUtc = $null }
    if ($id -cnotmatch $script:AtmQuarantineEntryIdPattern) { $s.Problem = 'NOT_AN_ENTRY'; return [pscustomobject]$s }
    $s.PayloadPresent = [IO.Directory]::Exists((Join-Path $Path 'payload'))
    $m = Read-AtmQuarantineManifest -EntryPath $Path -Id $id
    if ($null -ne $m.Problem) { $s.State = 'ENTRY_MANIFEST_INVALID'; $s.Problem = $m.Problem; return [pscustomobject]$s }
    $st = Get-AtmQuarantineEntryState -Records $m.Records -OwnSid $OwnSid
    $e0 = $m.Records[0]
    $s.State = $st.State; $s.Pending = $st.Pending; $s.LastOutcome = $st.LastOutcome; $s.ActorSid = $st.ActorSid
    $s.TargetKind = [string](Get-AtmRecordField $e0 'targetKind'); $s.OriginalPath = [string](Get-AtmRecordField $e0 'originalPath'); $s.CreatedUtc = Get-AtmRecordField $e0 'utc'
    $intent = @($m.Records | Where-Object { [string]$_.type -ceq 'move-intent' })
    if ($intent.Count -gt 0) {
        $i0 = $intent[$intent.Count - 1]
        if ($null -ne (Get-AtmRecordField $i0 'files')) { $s.Files = [long](Get-AtmRecordField $i0 'files'); $s.Dirs = [long](Get-AtmRecordField $i0 'dirs'); $s.Bytes = [long](Get-AtmRecordField $i0 'bytes') }
        $s.NewestWriteUtc = Get-AtmRecordField $i0 'newestWriteUtc'
    }
    $done = @($m.Records | Where-Object { [string]$_.type -ceq 'move-result' -and [string](Get-AtmRecordField $_ 'outcome') -ceq 'COMPLETE' })
    if ($done.Count -gt 0) {
        $d0 = $done[$done.Count - 1]
        $s.Verified = [pscustomobject]@{ Files = [long](Get-AtmRecordField $d0 'filesAfter'); Dirs = [long](Get-AtmRecordField $d0 'dirsAfter'); Bytes = [long](Get-AtmRecordField $d0 'bytesAfter'); Digest = [string](Get-AtmRecordField $d0 'digestAfter') }
    }
    $s.Records = @($m.Records | ForEach-Object {
            $oc = Get-AtmRecordField $_ 'outcome'; if ($null -eq $oc) { $oc = Get-AtmRecordField $_ 'result' }
            [pscustomobject]@{ Seq = [int]$_.recSeq; Type = [string]$_.type; Utc = (Get-AtmRecordField $_ 'utc'); Outcome = $(if ($null -ne $oc) { [string]$oc } else { $null }) } })
    if ($s.State -ceq 'RESTORED' -and $s.PayloadPresent) { $s.State = 'ENTRY_MANIFEST_INVALID'; $s.Problem = 'PAYLOAD_AFTER_RESTORE' }
    if ($s.State -ceq 'PURGED' -and $s.PayloadPresent) { $s.State = 'ENTRY_MANIFEST_INVALID'; $s.Problem = 'PAYLOAD_AFTER_PURGE' }
    $s.IsolatedUtc = $st.IsolatedUtc
    if ($s.State -ceq 'ISOLATED' -and $null -ne $st.IsolatedUtc) {
        $s.ExpiresUtc = $st.IsolatedUtc.AddDays($RetentionDays)
        $now = $(if ($null -ne $NowUtc) { ([datetime]$NowUtc).ToUniversalTime() } else { Get-AtmQuarantineNowUtc })
        if ($now -ge $s.ExpiresUtc) { $s.State = 'EXPIRED' }
    }
    return [pscustomobject]$s
}

function Get-AtmQuarantineList {
    <#
      quarantine list: read only. The entries of the quarantine root of the process user, each with its derived state;
      a folder that is not an entry, or is a reparse point, is listed as UNRECOGNIZED and never opened. -Policy: the
      effective policy (Get-AtmQuarantinePolicy; the default when not given), for the retention. Returns Root, Exists,
      RootProblem, Entries, Policy, and UsedBytes with QuotaReached when the policy sets a quota. A missing quarantine is
      not created.
    #>
    param([string]$Root = (Get-AtmQuarantineRootPath), [string]$OwnSid = (Get-AtmCurrentIdentity).Sid, $Policy = $null)
    if ($null -eq $Policy) { $Policy = Get-AtmQuarantinePolicy }
    $out = [ordered]@{ Root = $Root; Exists = $false; RootProblem = $null; Entries = @(); Policy = $Policy; UsedBytes = $null; QuotaReached = $false }
    if ($null -ne $Policy.QuotaBytes) {
        $out.UsedBytes = Get-AtmQuarantineUsage -Root $Root
        $out.QuotaReached = ($null -eq $out.UsedBytes -or [long]$out.UsedBytes -ge [long]$Policy.QuotaBytes)
    }
    if (-not $Root -or -not [IO.Directory]::Exists($Root)) { return [pscustomobject]$out }
    $out.Exists = $true
    if (((New-Object IO.DirectoryInfo $Root).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { $out.RootProblem = 'QUARANTINE_REPARSE_POINT'; return [pscustomobject]$out }
    $own = $OwnSid
    $now = Get-AtmQuarantineNowUtc
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($d in @((New-Object IO.DirectoryInfo $Root).GetDirectories() | Sort-Object Name)) {
        if (($d.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            $list.Add([pscustomobject]@{ Id = $d.Name; Path = $d.FullName; State = 'UNRECOGNIZED'; Problem = 'REPARSE_POINT'; Pending = $null; LastOutcome = $null; ActorSid = $null; TargetKind = $null; OriginalPath = $null
                    CreatedUtc = $null; Files = $null; Dirs = $null; Bytes = $null; NewestWriteUtc = $null; Verified = $null; PayloadPresent = $false; Records = @(); IsolatedUtc = $null; ExpiresUtc = $null })
            continue
        }
        $list.Add((Get-AtmQuarantineEntrySummary -Path $d.FullName -OwnSid $own -RetentionDays $Policy.RetentionDays -NowUtc $now))
    }
    $out.Entries = $list.ToArray()
    return [pscustomobject]$out
}

function Get-AtmQuarantineEntry {
    # quarantine inspect: read only. One entry by its id (the only input accepted: never a path, T-ISO-8). $null when
    # the id is not an entry id or no such entry exists. -Policy: as Get-AtmQuarantineList (the retention).
    param([string]$Id, [string]$Root = (Get-AtmQuarantineRootPath), [string]$OwnSid = (Get-AtmCurrentIdentity).Sid, $Policy = $null)
    if ($Id -cnotmatch $script:AtmQuarantineEntryIdPattern -or -not $Root) { return $null }
    $p = Join-Path $Root $Id
    if (-not [IO.Directory]::Exists($p) -or ((New-Object IO.DirectoryInfo $p).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $null }
    $days = $(if ($null -ne $Policy) { $Policy.RetentionDays } else { $script:AtmQuarantineDefaultRetentionDays })
    return (Get-AtmQuarantineEntrySummary -Path $p -OwnSid $OwnSid -RetentionDays $days)
}

function Get-AtmQuarantineNowUtc {
    # The clock of the retention: the system clock, or the suite's replacement (AtmQuarantineClock, test seam).
    if ($null -ne $script:AtmQuarantineClock) { return ([datetime](& $script:AtmQuarantineClock)).ToUniversalTime() }
    return [datetime]::UtcNow
}

function Get-AtmQuarantinePolicy {
    <#
      The effective quarantine policy (contract section 11.2), read only: config\quarantine.policy.json of the
      installation. Strict schema: one JSON object with schema = atm.quarantine-policy/1 and, optionally, retentionDays (a
      whole number of days, 1 to 3650), quotaBytes (a whole number of bytes, at least 1) and autoPurge (true or false);
      nothing else. A missing file is the default (30 days, no quota, autoPurge false). A file that cannot be read or
      breaks the schema counts as OFF, the same values, with the warning QUARANTINE_POLICY_INVALID. autoPurge = true
      turns the automatic purge on (phase P6a): only the entry point bin\agent-temp-autopurge.ps1 acts on it (run by the
      user's optional scheduled task, P6b, or by hand), within the limits of section 11.1, and it gives the warning
      AUTOPURGE_ON wherever the policy is shown.
      Returns RetentionDays, QuotaBytes ($null: no quota), AutoPurge, Source (DEFAULT, FILE, INVALID) and Warnings.
    #>
    param([string]$ConfigDir)
    $out = [ordered]@{ RetentionDays = $script:AtmQuarantineDefaultRetentionDays; QuotaBytes = $null; AutoPurge = $false; Source = 'DEFAULT'; Warnings = @() }
    if (-not $ConfigDir) { return [pscustomobject]$out }
    $f = Join-Path $ConfigDir $script:AtmQuarantinePolicyFile
    if (-not (Test-Path -LiteralPath $f)) { return [pscustomobject]$out }
    $doc = $null
    try {
        $fi = New-Object IO.FileInfo $f
        if (($fi.Attributes -band ([IO.FileAttributes]::ReparsePoint -bor [IO.FileAttributes]::Directory)) -ne 0 -or $fi.Length -gt 65536) { throw 'POLICY_SHAPE' }
        $txt = (New-Object Text.UTF8Encoding($false, $true)).GetString([IO.File]::ReadAllBytes($f)).TrimStart([char]0xFEFF)
        $doc = ConvertFrom-Json -InputObject $txt
    } catch { $doc = $null }
    $isInt = { param($v) ($v -is [int] -or $v -is [long]) }
    $ok = ($doc -is [System.Management.Automation.PSCustomObject])
    if ($ok) {
        $names = @($doc.PSObject.Properties | ForEach-Object { $_.Name })
        foreach ($n in $names) { if (@('schema', 'retentionDays', 'quotaBytes', 'autoPurge') -cnotcontains $n) { $ok = $false } }
        if (-not ($names -ccontains 'schema') -or -not ($doc.schema -is [string]) -or $doc.schema -cne $script:AtmQuarantinePolicySchema) { $ok = $false }
        if ($ok -and $names -ccontains 'retentionDays' -and -not ((& $isInt $doc.retentionDays) -and $doc.retentionDays -ge 1 -and $doc.retentionDays -le 3650)) { $ok = $false }
        if ($ok -and $names -ccontains 'quotaBytes' -and -not ((& $isInt $doc.quotaBytes) -and $doc.quotaBytes -ge 1)) { $ok = $false }
        if ($ok -and $names -ccontains 'autoPurge' -and -not ($doc.autoPurge -is [bool])) { $ok = $false }
    }
    if (-not $ok) { $out.Source = 'INVALID'; $out.Warnings = @('QUARANTINE_POLICY_INVALID'); return [pscustomobject]$out }
    $out.Source = 'FILE'
    if ($names -ccontains 'retentionDays') { $out.RetentionDays = [int]$doc.retentionDays }
    if ($names -ccontains 'quotaBytes') { $out.QuotaBytes = [long]$doc.quotaBytes }
    if ($names -ccontains 'autoPurge') { $out.AutoPurge = [bool]$doc.autoPurge }
    if ($out.AutoPurge) { $out.Warnings = @('AUTOPURGE_ON') }
    return [pscustomobject]$out
}

function Get-AtmQuarantineUsage {
    # The logical bytes held in the quarantine root now, measured read only by the native scanner (no names kept); 0 when
    # there is no quarantine, $null when the measurement is not complete.
    param([string]$Root)
    if (-not $Root -or -not [IO.Directory]::Exists($Root)) { return 0L }
    try { Initialize-AtmNative; $x = [AgentTempManager.AtmScanner]::ScanTree($Root, 3, 4096) } catch { return $null }
    if (-not $x.MeasurementComplete) { return $null }
    return [long]$x.Bytes
}

function Get-AtmQuarantineCapacityRefusal {
    <#
      Refusals of a NEW isolation of -Bytes (contract section 10), never a purge: QUARANTINE_QUOTA_REACHED when the policy
      sets a quota and the quarantine holds it already or would pass it (QUARANTINE_QUOTA_UNMEASURED when its usage cannot
      be measured); LOW_DISK_SPACE when the volume of the quarantine has less free space than the minimum fixed in code
      (the manifest and the log need room). -UsedBytes / -FreeBytes: the suite passes them to exercise the rule; otherwise
      both are measured, read only. Returned as plain output (callers wrap it in @()).
    #>
    param([string]$QuarantineRoot, [long]$Bytes, $Policy, $UsedBytes = $null, $FreeBytes = $null)
    if (-not $QuarantineRoot) { return @() }
    $why = New-Object System.Collections.Generic.List[string]
    if ($null -ne $Policy -and $null -ne $Policy.QuotaBytes) {
        $used = $(if ($null -ne $UsedBytes) { $UsedBytes } else { Get-AtmQuarantineUsage -Root $QuarantineRoot })
        if ($null -eq $used) { $why.Add('QUARANTINE_QUOTA_UNMEASURED') }
        elseif ([long]$used -ge [long]$Policy.QuotaBytes -or ([long]$used + $Bytes) -gt [long]$Policy.QuotaBytes) { $why.Add('QUARANTINE_QUOTA_REACHED') }
    }
    $free = $FreeBytes
    if ($null -eq $free) { try { $free = (New-Object IO.DriveInfo ([IO.Path]::GetPathRoot($QuarantineRoot))).AvailableFreeSpace } catch { $free = $null } }
    if ($null -eq $free -or [long]$free -lt $script:AtmQuarantineMinFreeBytes) { $why.Add('LOW_DISK_SPACE') }
    return $why.ToArray()
}

function ConvertTo-AtmUtcTicks {
    # A newestWriteUtc value of a manifest (an ISO 8601 string; PowerShell 7 may already have made it a DateTime).
    param($Value)
    if ($null -eq $Value -or '' -eq $Value) { return [long]-1 }
    if ($Value -is [datetime]) { return ([datetime]$Value).ToUniversalTime().Ticks }
    return ([datetime]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)).ToUniversalTime().Ticks
}

function Get-AtmQuarantinePayloadMeasure {
    # The payload measured the way the mover measures a tree (its MeasureTree: the same lines, order and SHA-256 of
    # the metadata), read only: names are enumerated, never opened, and kept only in memory. Error: REPARSE_POINT_FOUND,
    # ENUMERATION_FAILED or ROOT_TIME_UNREADABLE.
    param([string]$Root)
    $m = [ordered]@{ Files = 0L; Dirs = 0L; Bytes = 0L; Newest = 0L; Digest = $null; Error = $null }
    try { $m.Newest = (New-Object IO.DirectoryInfo $Root).LastWriteTimeUtc.Ticks } catch { $m.Error = 'ROOT_TIME_UNREADABLE'; return [pscustomobject]$m }
    $kept = [int]([IO.FileAttributes]::ReadOnly -bor [IO.FileAttributes]::Hidden -bor [IO.FileAttributes]::System -bor [IO.FileAttributes]::Directory)
    $lines = New-Object System.Collections.Generic.List[string]
    $dirs = New-Object System.Collections.Generic.List[string]
    $dirs.Add($Root)
    for ($k = 0; $k -lt $dirs.Count; $k++) {
        try {
            foreach ($fi in (New-Object IO.DirectoryInfo $dirs[$k]).EnumerateFileSystemInfos()) {
                $a = [int]$fi.Attributes
                if (($a -band [int][IO.FileAttributes]::ReparsePoint) -ne 0) { $m.Error = 'REPARSE_POINT_FOUND'; return [pscustomobject]$m }
                $wt = $fi.LastWriteTimeUtc.Ticks
                if ($wt -gt $m.Newest) { $m.Newest = $wt }
                $rel = $fi.FullName.Substring($Root.Length + 1)
                if (($a -band [int][IO.FileAttributes]::Directory) -ne 0) { $m.Dirs++; $dirs.Add($fi.FullName); $lines.Add("$rel`tD`t0`t$wt`t$($a -band $kept)") }
                else { $len = $fi.Length; $m.Files++; $m.Bytes += $len; $lines.Add("$rel`tF`t$len`t$wt`t$($a -band $kept)") }
            }
        } catch { $m.Error = 'ENUMERATION_FAILED'; return [pscustomobject]$m }
    }
    $arr = $lines.ToArray()
    [Array]::Sort($arr, [StringComparer]::Ordinal)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash((New-Object Text.UTF8Encoding($false)).GetBytes(($arr -join "`n"))) } finally { $sha.Dispose() }
    $m.Digest = [BitConverter]::ToString($h).Replace('-', '')
    return [pscustomobject]$m
}

function Test-AtmQuarantinePayload {
    # The payload measured now against the manifest: the statistics and metadata digest verified after the move
    # (move-result) when there is one, else the statistics of the intent (an INCOMPLETE entry). Result: OK, DIFFERS (with
    # the reasons), PAYLOAD_MISSING.
    param($Entry)
    $pp = Join-Path $Entry.Path 'payload'
    if (-not [IO.Directory]::Exists($pp) -or ((New-Object IO.DirectoryInfo $pp).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return [pscustomobject]@{ Result = 'PAYLOAD_MISSING'; Reason = $null } }
    $m = Get-AtmQuarantinePayloadMeasure -Root $pp
    if ($null -ne $m.Error) { return [pscustomobject]@{ Result = 'DIFFERS'; Reason = $m.Error } }
    $ref = $(if ($null -ne $Entry.Verified) { $Entry.Verified } else { [pscustomobject]@{ Files = $Entry.Files; Dirs = $Entry.Dirs; Bytes = $Entry.Bytes; Digest = $null } })
    $why = New-Object System.Collections.Generic.List[string]
    if ($m.Files -ne $ref.Files) { $why.Add("FILES $($m.Files)/$($ref.Files)") }
    if ($m.Dirs -ne $ref.Dirs) { $why.Add("DIRS $($m.Dirs)/$($ref.Dirs)") }
    if ($m.Bytes -ne $ref.Bytes) { $why.Add("BYTES $($m.Bytes)/$($ref.Bytes)") }
    if ($m.Newest -ne (ConvertTo-AtmUtcTicks $Entry.NewestWriteUtc)) { $why.Add('NEWEST_WRITE') }
    if ($ref.Digest -and -not [string]::Equals($m.Digest, $ref.Digest, [StringComparison]::Ordinal)) { $why.Add('META_DIGEST') }
    return [pscustomobject]@{ Result = $(if ($why.Count -eq 0) { 'OK' } else { 'DIFFERS' }); Reason = ($why -join '; ') }
}

function Test-AtmQuarantineEntry {
    <#
      quarantine verify: read only (T-ISO-4: nothing is written, not even to the manifest). Result: OK, DIFFERS,
      PAYLOAD_MISSING, ENTRY_MANIFEST_INVALID, NOT_VERIFIABLE (nothing to compare: FAILED, RESTORED, PURGED, no intent),
      ENTRY_NOT_FOUND. For an INCOMPLETE entry, Reconcilable says whether a restore would reconcile it (section 8.3:
      payload present and equal to the intent, original path absent, no purge pending); only the restore records it.
    #>
    param([string]$Id, [string]$OwnSid = (Get-AtmCurrentIdentity).Sid, $Policy = $null)
    $e = Get-AtmQuarantineEntry -Id $Id -OwnSid $OwnSid -Policy $Policy
    if ($null -eq $e) { return [pscustomobject]@{ Id = $Id; Result = 'ENTRY_NOT_FOUND'; Reason = $null; State = $null; Reconcilable = $null } }
    if ($e.State -ceq 'ENTRY_MANIFEST_INVALID') { return [pscustomobject]@{ Id = $Id; Result = 'ENTRY_MANIFEST_INVALID'; Reason = $e.Problem; State = $e.State; Reconcilable = $null } }
    if ($null -eq $e.Files -or $e.State -in @('FAILED', 'RESTORED', 'PURGED')) { return [pscustomobject]@{ Id = $Id; Result = 'NOT_VERIFIABLE'; Reason = $e.State; State = $e.State; Reconcilable = $null } }
    $t = Test-AtmQuarantinePayload -Entry $e
    $rec = $null
    if ($e.State -ceq 'INCOMPLETE') { $rec = ($t.Result -ceq 'OK' -and $e.Pending -cne 'purge' -and $e.OriginalPath -and -not (Test-Path -LiteralPath $e.OriginalPath)) }
    return [pscustomobject]@{ Id = $Id; Result = $t.Result; Reason = $t.Reason; State = $e.State; Reconcilable = $rec }
}

function Get-AtmRestorePlanId {
    # The plan id of a restore: its own prefix, the run, the entry, the destination and the measurement.
    param([string]$RunId, $Plan)
    $text = 'atm-restore-plan/1;' + $RunId + ';' + $Plan.Entry.Id + ';' + $Plan.Destination + ';' + (@($Plan.Entry.Files, $Plan.Entry.Dirs, $Plan.Entry.Bytes, (ConvertTo-AtmUtcTicks $Plan.Entry.NewestWriteUtc)) -join ',')
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)) } finally { $sha.Dispose() }
    return (-join @($h | ForEach-Object { $_.ToString('x2') }))
}

function Get-AtmRestorePlan {
    <#
      The restore plan of one entry, read only (contract section 8.3):
        * the entry exists, its manifest is valid and is this identity's; it is ISOLATED, or INCOMPLETE and reconcilable
          (Reconcile: payload present and equal to the intent, original absent; the restore records it first, T-ISO-5);
        * the payload measures as the manifest recorded (the verification of this run);
        * the destination's parent is the original's parent: a scope directory directly under an OK base of this
          identity, not shared; it passes gates 3 (chain, no reparse point) and 4 (owner and ACL of the parent and of
          the base); the same volume as the quarantine; nothing under it is RECENT or ACTIVE_EVIDENCE, and the runtime
          evidence (B2-1) refuses nothing there;
        * the original path is free. Otherwise (RESTORE_CONFLICT, with the counts of what exists, never names) the
          engine generates the alternative <name>.restored-<id8> next to it (T-ISO-8), which must be free too and needs
          its own phrase. Nothing is ever overwritten or merged.
      Returns Entry, Destination, DestinationParent, DestinationName, Conflict, ConflictFiles, ConflictDirs, Reconcile
      and Reasons (refusals).
    #>
    param([string]$Id, $Inventory, $RuntimeEvidence)
    $out = [ordered]@{ Entry = $null; Destination = $null; DestinationParent = $null; DestinationName = $null; Conflict = $false; ConflictFiles = $null; ConflictDirs = $null; Reconcile = $false; Reasons = @() }
    $why = New-Object System.Collections.Generic.List[string]
    $e = Get-AtmQuarantineEntry -Id $Id -OwnSid ([string]$Inventory.Identity.Sid)
    if ($null -eq $e) { $out.Reasons = @('ENTRY_NOT_FOUND'); return [pscustomobject]$out }
    $out.Entry = $e
    $ownSid = [string]$Inventory.Identity.Sid
    if ($e.State -ceq 'ENTRY_MANIFEST_INVALID') { $out.Reasons = @('ENTRY_MANIFEST_INVALID (' + $e.Problem + ')'); return [pscustomobject]$out }
    if ($e.State -ceq 'ABANDONED' -or [string]$e.ActorSid -cne $ownSid) { $why.Add($script:AtmIsolationOwnProfileOnly) }
    elseif ($e.State -ceq 'RESTORED') { $why.Add('ENTRY_ALREADY_RESTORED') }
    elseif ($e.State -ceq 'PURGED') { $why.Add('ENTRY_PURGED') }
    elseif ($e.State -ceq 'FAILED') { $why.Add('ENTRY_FAILED') }
    elseif ($e.State -ceq 'INCOMPLETE' -and $e.Pending -ceq 'purge') { $why.Add('ENTRY_INCOMPLETE (PURGE_PENDING)') }
    if ($why.Count -gt 0) { $out.Reasons = $why.ToArray(); return [pscustomobject]$out }
    if ($null -eq $e.Files) { $out.Reasons = @('ENTRY_INCOMPLETE (NO_INTENT)'); return [pscustomobject]$out }
    $t = Test-AtmQuarantinePayload -Entry $e
    if ($t.Result -cne 'OK') { $why.Add($(if ($e.State -ceq 'INCOMPLETE') { 'ENTRY_INCOMPLETE' } else { 'ENTRY_VERIFY_' + $t.Result }) + $(if ($t.Reason) { ' (' + $t.Reason + ')' } else { '' })) }
    $orig = [string]$e.OriginalPath
    if (-not $orig -or $null -ne (Test-AtmAllowListPathSyntax $orig)) { $why.Add('ORIGINAL_PATH_INVALID'); $out.Reasons = $why.ToArray(); return [pscustomobject]$out }
    $parent = [IO.Path]::GetDirectoryName($orig)
    $out.DestinationParent = $parent
    $base = @($Inventory.Bases | Where-Object { [string]$_.Sid -ceq $ownSid -and $_.Status -eq 'OK' -and -not $_.Shared -and [string]::Equals([IO.Path]::GetDirectoryName($parent), [string]$_.Path, [StringComparison]::OrdinalIgnoreCase) })
    if ($base.Count -ne 1) { $why.Add('RESTORE_PARENT_NOT_IN_OWN_BASE') }
    elseif (-not [IO.Directory]::Exists($parent)) { $why.Add('RESTORE_PARENT_MISSING') }
    else {
        $chain = Test-AtmPathChain $parent
        if ($chain.Status -ne 'OK') { $why.Add((Get-AtmText 'reason.chain' $chain.Status $chain.At)) }
        foreach ($dir in @($parent, [string]$base[0].Path)) { foreach ($pb in (Get-AtmAclProblems -Path $dir -OwnerSid $ownSid)) { $why.Add($pb) } }
        foreach ($v in @(Get-AtmOtherVolumeRefusal -Path $parent -QuarantinePath $e.Path)) { $why.Add($v) }
        # Gate 5 and B2-1 over the parent: what lives under it now (the agent may have recreated it).
        foreach ($sib in @($Inventory.Partitions | Where-Object { $_.Path -and [string]::Equals([IO.Path]::GetDirectoryName([string]$_.Path), $parent, [StringComparison]::OrdinalIgnoreCase) })) {
            $cls = [string](Get-AtmRecordField $sib 'Class'); if ($cls -in @('ACTIVE_EVIDENCE', 'RECENT')) { $why.Add('RESTORE_PARENT_' + $cls) }
            if ($null -ne $RuntimeEvidence -and -not $RuntimeEvidence.Failed) {
                $k = ([string]$sib.Path).ToLowerInvariant()
                if ($RuntimeEvidence.ByPath.ContainsKey($k)) { foreach ($r in @($RuntimeEvidence.ByPath[$k] | Where-Object { $_.Decision -ne 'ELIGIBLE' })) { $why.Add((Format-AtmRuntimeRefusal $r)) } }
            }
        }
        if ($null -eq $RuntimeEvidence -or $RuntimeEvidence.Failed) { $why.Add('RUNTIME_NOT_COLLECTED') }
    }
    $name = [IO.Path]::GetFileName($orig)
    if (Test-Path -LiteralPath $orig) {
        $out.Conflict = $true
        $x = [AgentTempManager.AtmScanner]::ScanTree($orig, 3, 4096)
        $out.ConflictFiles = [long]$x.Files; $out.ConflictDirs = [long]$x.Dirs
        $name = $name + '.restored-' + $e.Id.Substring($e.Id.Length - 8)
        if (Test-Path -LiteralPath (Join-Path $parent $name)) { $why.Add('RESTORE_CONFLICT (ALTERNATIVE_EXISTS)') }
    }
    $out.DestinationName = $name
    $out.Destination = Join-Path $parent $name
    $out.Reconcile = ($e.State -ceq 'INCOMPLETE')
    if ($out.Reconcile -and $out.Conflict) { $why.Add('ENTRY_INCOMPLETE (ORIGINAL_PRESENT)') }
    $out.Reasons = @($why | Select-Object -Unique)
    return [pscustomobject]$out
}

function Invoke-AtmRestore {
    <#
      quarantine restore -Entry <id> (CLI). With the isolation gate closed (every distributed copy) it shows the plan and
      stops (RESTAURACAO_REAL_DESABILITADA): nothing is asked, locked, logged or moved. Past the gate it runs
      Invoke-AtmRestoreCore under the clean lock (B8, the same name), like isolate.
    #>
    [CmdletBinding()]
    param(
        [string]$Id,
        [scriptblock]$PlanPresenter,
        [scriptblock]$ConfirmationReader,
        [hashtable]$InventoryArgs = @{},
        [string]$LogFile,
        [hashtable]$Interaction = @{},
        [scriptblock]$BeforeMoveHook,
        [scriptblock]$MoveTreeImpl
    )
    if (-not $script:AtmIsolationEnabled) { return (Invoke-AtmRestoreCore @PSBoundParameters) }
    # No closure: the body runs in this session state, where the engine's functions are, and finds $rstBound here.
    $rstBound = @{} + $PSBoundParameters
    $u = Invoke-AtmUnderSharedLock -Body { Invoke-AtmRestoreCore @rstBound }
    if (-not $u.Acquired) { return (Invoke-AtmRestoreCore @PSBoundParameters -LockRefusal ('CLEAN_LOCK_' + $u.Status) -LockReleaseError $u.ReleaseError) }
    $res = $u.Result
    if ($null -ne $u.ReleaseError -and $null -ne $res) {
        $res.LockReleaseError = $u.ReleaseError
        if (-not $res.Aborted -and -not $res.StoppedBy) { if (@($res.Results).Count -gt 0) { $res.StoppedBy = 'LOCK_RELEASE_FAILED' } else { $res.Aborted = 'LOCK_RELEASE_FAILED' } }
    }
    return $res
}

function Invoke-AtmRestoreCore {
    <#
      Fail-closed restore of ONE quarantine entry, called only by Invoke-AtmRestore.
        1. a fresh inventory, its runtime evidence and the plan (Get-AtmRestorePlan); its plan id (atm-restore-plan/1)
           and the plan through -PlanPresenter scriptblock(plan, inventory, planId). Gate closed: stop here.
      Past the gate:
        2. a reader, a NEW -LogFile (atm.isolatelog/1, outside the audited directories and the quarantine) and an
           interactive console observed by the engine are required; the log is created before any question;
        3. RESTAURAR <id8>, and for the alternative destination RESTAURAR <id8> EM DESTINO ALTERNATIVO as well;
        4. after -BeforeMoveHook (tests), the plan again (fresh inventory and evidence, the entry and its payload, the
           destination): any difference stops the run;
        5. an INCOMPLETE entry is reconciled first ('reconcile' in the manifest and in the log, T-ISO-5); then
           restore-intent in the manifest and in the log. Each manifest record reopens it (OpenExisting) and closes it:
           its pin would block the move;
        6. the mover (same volume, pinned, through the handle, measured before and after) from <entry>\payload to the
           destination, which never exists; restore-result in the manifest and in the log. Anything but a moved and
           verified tree stops the run (RESTORED_INTEGRITY_FAILED when moved but not verified); nothing is undone.
      -MoveTreeImpl: test seam (never passed by the CLI), scriptblock(plan, destinationSession, name).
    #>
    [CmdletBinding()]
    param(
        [string]$Id,
        [scriptblock]$PlanPresenter,
        [scriptblock]$ConfirmationReader,
        [hashtable]$InventoryArgs = @{},
        [string]$LogFile,
        [hashtable]$Interaction = @{},
        [scriptblock]$BeforeMoveHook,
        [scriptblock]$MoveTreeImpl,
        [string]$LockRefusal,
        [string]$LockReleaseError
    )
    $results = New-Object System.Collections.Generic.List[object]
    $logErrors = New-Object System.Collections.Generic.List[object]
    $state = @{ Aborted = $null; Stopped = $null; PlanId = $null; Phrases = @(); RunId = $null; LogCreated = $false; RefusedAt = $null; Plan = $null }
    $finish = {
        [pscustomobject]@{
            Id = $Id; Plan = $state.Plan; PlanId = $state.PlanId; Phrases = $state.Phrases; Aborted = $state.Aborted; StoppedBy = $state.Stopped; Results = $results.ToArray()
            RunId = $state.RunId; LogFile = $(if ($state.RunId) { $LogFile } else { $null }); LogCreated = $state.LogCreated; LogErrors = $logErrors.ToArray()
            LockReleaseError = $(if ($LockReleaseError) { $LockReleaseError } else { $null }); RefusedAt = $state.RefusedAt
        }
    }
    if ($LockRefusal) { $state.Aborted = $LockRefusal; return (& $finish) }
    if ($Id -cnotmatch $script:AtmQuarantineEntryIdPattern) { $state.Aborted = 'ENTRY_ID_INVALID'; return (& $finish) }
    if (-not $PlanPresenter) { $state.Aborted = 'SEM_APRESENTACAO'; return (& $finish) }
    $ia = @{} + $InventoryArgs
    $inv = Invoke-AtmInventory @ia
    $plan = Get-AtmRestorePlan -Id $Id -Inventory $inv -RuntimeEvidence (Get-AtmCleanRuntimeEvidence -Inventory $inv -InventoryArgs $ia)
    $state.Plan = $plan
    $runId = [guid]::NewGuid().ToString()
    if (@($plan.Reasons).Count -eq 0) {
        $state.PlanId = Get-AtmRestorePlanId -RunId $runId -Plan $plan
        $id8 = $Id.Substring($Id.Length - 8).ToUpperInvariant()
        $state.Phrases = @(@("RESTAURAR $id8") + $(if ($plan.Conflict) { @("RESTAURAR $id8 EM DESTINO ALTERNATIVO") } else { @() }))
    }
    & $PlanPresenter $plan $inv $state.PlanId
    if (@($plan.Reasons).Count -gt 0) { $state.Aborted = 'RESTAURACAO_RECUSADA'; return (& $finish) }
    if (-not $script:AtmIsolationEnabled) { $state.Aborted = 'RESTAURACAO_REAL_DESABILITADA'; return (& $finish) }

    # ---- past the isolation gate (the suite only, in its own process) ----
    if (-not $ConfirmationReader) { $state.Aborted = 'SEM_APRESENTACAO_OU_CONFIRMACAO'; return (& $finish) }
    if (-not $LogFile) { $state.Aborted = 'LOG_REQUIRED'; return (& $finish) }
    $qPath = Get-AtmQuarantineRootPath
    if ($LogFile.StartsWith($qPath.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { $state.Aborted = 'LOG_DESTINATION_NOT_ALLOWED'; return (& $finish) }
    $console = Get-AtmEngineConsoleObservation
    if (-not $console.Observed) { $state.Aborted = 'CONSOLE_NOT_OBSERVED'; return (& $finish) }
    $callerName = [string]$Interaction['Caller']
    $interactionRec = [ordered]@{ caller = $(if ($callerName -ceq 'CLI' -or $callerName -ceq 'TUI') { $callerName } else { 'DIRECT_CALL' }); consoleRequiredByCaller = ($Interaction['ConsoleRequired'] -eq $true)
        callerFieldsVerified = $false; interactiveConsoleObserved = $true; observedBy = $console.By; identifiesRespondent = $false }
    $state.RunId = $runId
    $me = Get-AtmCurrentIdentity
    $ls = @{ Id = $runId; Seq = 0 }
    $ms = @{ Id = $Id; Seq = @($plan.Entry.Records).Count }
    $opId = '{0}:1' -f $runId
    $halt = { param([string]$Code) if ($results.Count -gt 0) { $state.Stopped = $Code } else { $state.Aborted = $Code } }
    $logFail = { param([string]$Stage, [string]$Code) $logErrors.Add([pscustomobject]@{ Stage = $Stage; OpId = $null; Code = $Code }) }
    $entryPath = $plan.Entry.Path
    # One manifest record: the manifest reopened (OpenExisting, the same checks), written, flushed and closed.
    $writeManifest = {
        param([string]$Type, [System.Collections.IDictionary]$Fields)
        $mf = [AgentTempManager.AtmCleanLog]::Pin($entryPath, $me.Sid)
        try {
            $c = $(if ($null -ne $mf.Error) { $mf.Error } else { $mf.OpenExisting('manifest.jsonl') })
            if ($null -eq $c) { $c = Write-AtmIsolationRecord -Log $mf -State $ms -Schema $script:AtmQuarantineSchema -Type $Type -Fields $Fields }
            if ($null -eq $c) { $c = $mf.Close() }
            return $c
        } finally { $mf.Dispose() }
    }
    $log = $null; $dest = $null
    try {
        $opened = Open-AtmCleanLog -Path $LogFile -Inventory $inv -ProcessUserSid $me.Sid
        $state.LogCreated = [bool]$opened.Created
        if ($null -eq $opened.Log) { & $logFail 'open' $opened.Code; $state.Aborted = 'LOG_OPEN_FAILED'; return (& $finish) }
        $log = $opened.Log
        $lc = Write-AtmIsolationRecord -Log $log -State $ls -Schema $script:AtmIsolateLogSchema -Type 'run-start' -Fields ([ordered]@{ tool = $script:AtmVersion; operation = 'restore'; user = $inv.Identity.Name; sid = $inv.Identity.Sid
                elevated = [bool]$inv.Identity.IsAdmin; entryId = $Id; planId = $state.PlanId; destination = $plan.Destination; alternative = [bool]$plan.Conflict; reconcile = [bool]$plan.Reconcile })
        if ($null -ne $lc) { & $logFail 'run-start' $lc; $state.Aborted = 'LOG_WRITE_FAILED'; return (& $finish) }
        $refusal = $null
        $kinds = @('restore', 'alternative')
        for ($i = 0; $i -lt @($state.Phrases).Count -and $null -eq $refusal; $i++) {
            $ph = @($state.Phrases)[$i]
            $tp = Test-AtmTypedPhrase -Typed (& $ConfirmationReader $ph $kinds[$i] $plan.Destination @($ph)) -Phrases @($ph)
            if ($tp.Code) { $refusal = [pscustomobject]@{ Code = 'CONFIRMACAO_AUSENTE_OU_DIVERGENTE'; Step = $kinds[$i]; Path = $plan.Destination } }
        }
        $lc = Write-AtmIsolationRecord -Log $log -State $ls -Schema $script:AtmIsolateLogSchema -Type 'confirmation' -Fields ([ordered]@{ accepted = ($null -eq $refusal); planId = $state.PlanId; step = $(if ($refusal) { $refusal.Step } else { $null }); interaction = $interactionRec })
        if ($null -ne $refusal) { $state.RefusedAt = $refusal; $state.Aborted = $refusal.Code; if ($null -ne $lc) { & $logFail 'confirmation' $lc } }
        elseif ($null -ne $lc) { & $logFail 'confirmation' $lc; $state.Aborted = 'LOG_WRITE_FAILED' }
        if (-not $state.Aborted) {
            # The plan again, immediately before the move: the entry and its payload, the destination and its parent.
            if ($BeforeMoveHook) { & $BeforeMoveHook $plan }
            $iaRe = @{} + $InventoryArgs; $iaRe['NoProgress'] = $true
            $invRe = Invoke-AtmInventory @iaRe
            $re = Get-AtmRestorePlan -Id $Id -Inventory $invRe -RuntimeEvidence (Get-AtmCleanRuntimeEvidence -Inventory $invRe -InventoryArgs $iaRe)
            $same = (@($re.Reasons).Count -eq 0 -and [string]::Equals($re.Destination, $plan.Destination, [StringComparison]::Ordinal) -and $re.Conflict -eq $plan.Conflict -and $re.Reconcile -eq $plan.Reconcile -and @($re.Entry.Records).Count -eq @($plan.Entry.Records).Count)
            $lc = Write-AtmIsolationRecord -Log $log -State $ls -Schema $script:AtmIsolateLogSchema -Type 'plan-check' -Fields ([ordered]@{ planId = $state.PlanId; matched = $same; reasons = @($re.Reasons) })
            if ($null -ne $lc) { & $logFail 'plan-check' $lc; $state.Aborted = 'LOG_WRITE_FAILED' }
            elseif (-not $same) { $state.Aborted = 'REVALIDATION_REFUSED' }
        }
        $e = $plan.Entry
        if (-not $state.Aborted -and $plan.Reconcile) {
            # T-ISO-5: an INCOMPLETE entry whose payload measures as its intent and whose original is absent.
            $mc = & $writeManifest 'reconcile' ([ordered]@{ result = 'OK'; files = $e.Files; dirs = $e.Dirs; bytes = $e.Bytes; runId = $runId })
            if ($null -ne $mc) { $state.Aborted = 'MANIFEST_RECONCILE_FAILED' }
            else {
                $lc = Write-AtmIsolationRecord -Log $log -State $ls -Schema $script:AtmIsolateLogSchema -Type 'reconcile' -Fields ([ordered]@{ entryId = $Id; result = 'OK' })
                if ($null -ne $lc) { & $logFail 'reconcile' $lc; $state.Aborted = 'LOG_WRITE_FAILED' }
            }
        }
        if (-not $state.Aborted) {
            # The intent is written and flushed, in the manifest and in the log, BEFORE the mover; without both, no move.
            $mc = & $writeManifest 'restore-intent' ([ordered]@{ opId = $opId; runId = $runId; planId = $state.PlanId; destination = $plan.Destination; alternative = [bool]$plan.Conflict })
            if ($null -ne $mc) { $state.Aborted = 'MANIFEST_INTENT_FAILED' }
            else {
                $lc = Write-AtmIsolationRecord -Log $log -State $ls -Schema $script:AtmIsolateLogSchema -Type 'restore-intent' -Fields ([ordered]@{ opId = $opId; entryId = $Id; destination = $plan.Destination; files = $e.Files; dirs = $e.Dirs; bytes = $e.Bytes })
                if ($null -ne $lc) { & $logFail 'restore-intent' $lc; $state.Aborted = 'LOG_INTENT_FAILED' }
            }
        }
        if (-not $state.Aborted) {
            # The destination's parent pinned for the move (shared for reading and writing, never for deletion), then
            # the only call to the mover in a restore.
            $mv = $null; $exType = $null
            try {
                $dest = [AgentTempManager.AtmSafeCreate]::PinForMove($plan.DestinationParent)
                if (-not $dest.IsPinned) { throw [InvalidOperationException]::new('DESTINATION_PIN') }
                if ($MoveTreeImpl) { $mv = & $MoveTreeImpl $plan $dest $plan.DestinationName }
                else { $mv = [AgentTempManager.AtmMover]::MoveTree((Join-Path $entryPath 'payload'), $e.Files, $e.Dirs, $e.Bytes, (ConvertTo-AtmUtcTicks $e.NewestWriteUtc), $dest, $plan.DestinationName, $null) }
                if ($null -eq $mv) { throw [InvalidOperationException]::new('MOVER_NO_RESULT') }
            } catch { $mv = $null; $exType = $_.Exception.GetBaseException().GetType().Name }
            $outcome = $(if ($null -ne $exType) { 'EXCEPTION' } elseif ($mv.Moved -and $mv.Verified) { 'COMPLETE' } elseif ($mv.Moved) { 'INTEGRITY_FAILED' } else { 'REFUSED' })
            $known = ($null -ne $mv)
            $row = [pscustomobject]@{ OpId = $opId; Id = $Id; Destination = $plan.Destination; Outcome = $outcome; Moved = ($known -and [bool]$mv.Moved); Verified = ($known -and [bool]$mv.Verified)
                RenameStatus = $(if ($known) { $mv.RenameStatus } else { $null }); AbortReason = $(if ($known) { $mv.AbortReason } else { $null }); ExceptionType = $exType }
            $results.Add($row)
            if ($null -ne $dest) { $dest.Dispose(); $dest = $null }
            $after = [ordered]@{ opId = $opId; outcome = $outcome; moved = $row.Moved; verified = $row.Verified; destination = $plan.Destination
                filesAfter = $(if ($known) { $mv.FilesAfter } else { $null }); dirsAfter = $(if ($known) { $mv.DirsAfter } else { $null }); bytesAfter = $(if ($known) { $mv.BytesAfter } else { $null })
                digestPlanned = $(if ($known) { $mv.DigestPlanned } else { $null }); digestAfter = $(if ($known) { $mv.DigestAfter } else { $null })
                renameStatus = $row.RenameStatus; abortReason = $row.AbortReason; exceptionType = $exType }
            $mc = & $writeManifest 'restore-result' $after
            $after['entryId'] = $Id
            $lc = Write-AtmIsolationRecord -Log $log -State $ls -Schema $script:AtmIsolateLogSchema -Type 'restore-result' -Fields $after
            if ($null -ne $lc) { & $logFail 'restore-result' $lc; & $halt 'LOG_RESULT_FAILED' }
            elseif ($null -ne $mc) { & $halt 'MANIFEST_RESULT_FAILED' }
            elseif ($outcome -ceq 'INTEGRITY_FAILED') { & $halt 'RESTORED_INTEGRITY_FAILED' }
            elseif ($outcome -cne 'COMPLETE') { & $halt ('STOPPED_AFTER_' + $outcome) }
        }
        # run-end only while the log has not failed; neither a failed run-end nor a failed close replaces the main code.
        if ($logErrors.Count -eq 0) {
            $lc = Write-AtmIsolationRecord -Log $log -State $ls -Schema $script:AtmIsolateLogSchema -Type 'run-end' -Fields ([ordered]@{ results = $results.Count; complete = @($results | Where-Object { $_.Outcome -ceq 'COMPLETE' }).Count; stoppedBy = $(if ($state.Stopped) { $state.Stopped } else { $state.Aborted }); entryId = $Id })
            if ($null -ne $lc) { & $logFail 'run-end' $lc; if (-not $state.Aborted -and -not $state.Stopped) { & $halt 'LOG_END_FAILED' } }
        }
        $cc = $log.Close()
        if ($null -ne $cc) { & $logFail 'close' $cc; if (-not $state.Aborted -and -not $state.Stopped) { & $halt 'LOG_CLOSE_FAILED' } }
        return (& $finish)
    } finally {
        if ($null -ne $dest) { try { $dest.Dispose() } catch { $null = $_ } }
        if ($null -ne $log) { try { $log.Dispose() } catch { $null = $_ } }
    }
}

# ---------------------------------------------------------------------------------------------
# Purge (phase P4): one entry per run, from the launcher only, behind the purge gate of its own (J-ISO-1 (C)). The payload
# is purged by the same deleter as clean, given the measurement the manifest recorded; the entry folder and its manifest
# stay as the trail. Nothing here purges by itself: retention only marks EXPIRED and the quota only refuses isolations.
# ---------------------------------------------------------------------------------------------

function Get-AtmQuarantineReferenceRefusal {
    <#
      B2-1 extended to the quarantine (contract section 9): a process whose command line names the quarantine root, in its
      long or short form, refuses the purge. The parsing is that of Find-AtmReferences (slashes and case folded; the name
      followed by a separator or the end) and this run's own launcher chain is excluded, as in the inventory. Only the
      count is kept: no process name, command line or path. A failed process snapshot refuses too.
      Returned as plain output (callers wrap it in @()).
    #>
    param($Inventory, [string]$QuarantineRoot)
    $snap = $Inventory.Snapshot
    if ($null -eq $snap -or $snap.Failed) { return @('RUNTIME_NOT_COLLECTED (PROCESS_SNAPSHOT)') }
    $forms = @($QuarantineRoot.TrimEnd('\'))
    try { $sp = [AgentTempManager.AtmNative]::GetShortPath($QuarantineRoot); if ($sp) { $forms += $sp.TrimEnd('\') } } catch { $null = $_ }
    $forms = @($forms | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique)
    $self = @($Inventory.SelfPids)
    $hits = 0
    foreach ($proc in @($snap.Processes)) {
        if ($null -eq $proc -or -not $proc.CommandLine -or $self -contains $proc.Pid) { continue }
        $n = ([string]$proc.CommandLine).Replace('/', '\').ToLowerInvariant()
        while ($n.Contains('\\')) { $n = $n.Replace('\\', '\') }
        $hit = $false
        foreach ($f in $forms) {
            $i = $n.IndexOf($f, [StringComparison]::Ordinal)
            while ($i -ge 0 -and -not $hit) {
                $end = $i + $f.Length
                if ($end -ge $n.Length -or $n[$end] -eq '\' -or $script:AtmRefTerminators -contains $n[$end]) { $hit = $true }
                else { $i = $n.IndexOf($f, $end, [StringComparison]::Ordinal) }
            }
            if ($hit) { break }
        }
        if ($hit) { $hits++ }
    }
    if ($hits -gt 0) { return @("RUNTIME_QUARANTINE_REFERENCED ($hits)") }
    return @()
}

function Get-AtmPurgePlanId {
    # The plan id of a purge: its own prefix, the run, the entry and the measurement the deleter will be given.
    param([string]$RunId, $Plan)
    $text = 'atm-purge-plan/1;' + $RunId + ';' + $Plan.Entry.Id + ';' + (@($Plan.Files, $Plan.Dirs, $Plan.Bytes, $Plan.NewestTicks) -join ',')
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)) } finally { $sha.Dispose() }
    return (-join @($h | ForEach-Object { $_.ToString('x2') }))
}

function Get-AtmPurgePlan {
    <#
      The purge plan of one entry, read only (contract section 9). The entry itself refuses with PURGE_REFUSED_<reason>
      (never a weaker retry):
        * it must exist as an entry (a name that is not one, or a reparse point: UNRECOGNIZED), its manifest must be valid
          and this identity's (ABANDONED), and it must be ISOLATED or EXPIRED: INCOMPLETE, FAILED, RESTORED and PURGED
          refuse;
        * the verification of this run: the payload measures as the manifest recorded (DIFFERS, PAYLOAD_MISSING).
      Then the gates of the purge, with their own codes:
        * gate 3: the chain down to the payload (fixed drive, no reparse point); gate 4: owner and ACL of the quarantine
          root and of the entry (Get-AtmAclProblems: the owner is this identity, no other principal outside
          AtmTrustedWriterSids may write);
        * gate 8: the lock probe of the payload (share mode 0 on every file and folder);
        * B2-1: the runtime evidence of this inventory was collected, and no command line names the quarantine.
      Returns Entry, PayloadPath, Files, Dirs, Bytes, NewestTicks (the measurement given to the deleter), Uninspectable
      (processes whose command line could not be read, a count only) and Reasons.
    #>
    param([string]$Id, $Inventory, $RuntimeEvidence, $Policy = $null)
    $out = [ordered]@{ Entry = $null; PayloadPath = $null; Files = $null; Dirs = $null; Bytes = $null; NewestTicks = $null; Uninspectable = $null; Reasons = @() }
    $root = Get-AtmQuarantineRootPath
    $ownSid = [string]$Inventory.Identity.Sid
    $e = Get-AtmQuarantineEntry -Id $Id -Root $root -OwnSid $ownSid -Policy $Policy
    if ($null -eq $e) {
        $known = ($root -and $Id -cmatch $script:AtmQuarantineEntryIdPattern -and (Test-Path -LiteralPath (Join-Path $root $Id)))
        $out.Reasons = @($(if ($known) { 'PURGE_REFUSED_UNRECOGNIZED' } else { 'PURGE_REFUSED_ENTRY_NOT_FOUND' }))
        return [pscustomobject]$out
    }
    $out.Entry = $e
    if ($e.State -ceq 'ENTRY_MANIFEST_INVALID') { $out.Reasons = @('PURGE_REFUSED_ENTRY_MANIFEST_INVALID (' + $e.Problem + ')'); return [pscustomobject]$out }
    if ($e.State -ceq 'ABANDONED' -or [string]$e.ActorSid -cne $ownSid) { $out.Reasons = @('PURGE_REFUSED_ABANDONED'); return [pscustomobject]$out }
    if (@('ISOLATED', 'EXPIRED') -cnotcontains $e.State -or $null -eq $e.Files) { $out.Reasons = @('PURGE_REFUSED_' + $e.State + $(if ($e.Pending) { ' (' + $e.Pending + ')' } else { '' })); return [pscustomobject]$out }
    $t = Test-AtmQuarantinePayload -Entry $e
    if ($t.Result -cne 'OK') { $out.Reasons = @('PURGE_REFUSED_' + $t.Result + $(if ($t.Reason) { ' (' + $t.Reason + ')' } else { '' })); return [pscustomobject]$out }
    $pp = Join-Path $e.Path 'payload'
    $out.PayloadPath = $pp; $out.Files = [long]$e.Files; $out.Dirs = [long]$e.Dirs; $out.Bytes = [long]$e.Bytes; $out.NewestTicks = ConvertTo-AtmUtcTicks $e.NewestWriteUtc
    $why = New-Object System.Collections.Generic.List[string]
    $chain = Test-AtmPathChain $pp
    if ($chain.Status -ne 'OK') { $why.Add((Get-AtmText 'reason.chain' $chain.Status $chain.At)) }
    foreach ($dir in @($root, $e.Path)) { foreach ($pb in (Get-AtmAclProblems -Path $dir -OwnerSid $ownSid)) { $why.Add($pb) } }
    foreach ($lr in @((Get-AtmLockProbeReasons $pp).Reasons)) { $why.Add($lr) }
    if ($null -eq $RuntimeEvidence -or $RuntimeEvidence.Failed) { $why.Add('RUNTIME_NOT_COLLECTED') }
    foreach ($rr in @(Get-AtmQuarantineReferenceRefusal -Inventory $Inventory -QuarantineRoot $root)) { $why.Add($rr) }
    $u = Get-AtmUninspectableKeys -Inventory $Inventory
    $out.Uninspectable = @($u.Keys).Count + [int]$u.Unkeyed
    $out.Reasons = @($why | Select-Object -Unique)
    return [pscustomobject]$out
}

function Invoke-AtmPurge {
    <#
      quarantine purge -Entry <id> (CLI only). With the purge gate closed (every distributed copy) it shows the plan and
      stops (EXPURGO_REAL_DESABILITADO): nothing is asked, locked, logged or purged, and no space is freed. Only the purge
      gate is read: the isolation gate does not open it, and the deletion gate of clean is not involved. Past it, it runs
      Invoke-AtmPurgeCore under the clean lock (B8, the same name), like isolate and restore.
    #>
    [CmdletBinding()]
    param(
        [string]$Id,
        [scriptblock]$PlanPresenter,
        [scriptblock]$ConfirmationReader,
        [hashtable]$InventoryArgs = @{},
        [string]$LogFile,
        [hashtable]$Interaction = @{},
        [scriptblock]$BeforePurgeHook,
        [scriptblock]$PurgeTreeImpl
    )
    if (-not $script:AtmQuarantinePurgeEnabled) { return (Invoke-AtmPurgeCore @PSBoundParameters) }
    # No closure: the body runs in this session state, where the engine's functions are, and finds $purBound here.
    $purBound = @{} + $PSBoundParameters
    $u = Invoke-AtmUnderSharedLock -Body { Invoke-AtmPurgeCore @purBound }
    if (-not $u.Acquired) { return (Invoke-AtmPurgeCore @PSBoundParameters -LockRefusal ('CLEAN_LOCK_' + $u.Status) -LockReleaseError $u.ReleaseError) }
    $res = $u.Result
    if ($null -ne $u.ReleaseError -and $null -ne $res) {
        $res.LockReleaseError = $u.ReleaseError
        if (-not $res.Aborted -and -not $res.StoppedBy) { if (@($res.Results).Count -gt 0) { $res.StoppedBy = 'LOCK_RELEASE_FAILED' } else { $res.Aborted = 'LOCK_RELEASE_FAILED' } }
    }
    return $res
}

function Invoke-AtmPurgeCore {
    <#
      Fail-closed purge of ONE quarantine entry, called only by Invoke-AtmPurge.
        1. a fresh inventory, its runtime evidence, the policy and the plan (Get-AtmPurgePlan); its plan id
           (atm-purge-plan/1), the phrase EXPURGAR <id8> <files> ARQUIVOS and the plan through -PlanPresenter
           scriptblock(plan, inventory, planId, phrase). A refusal stops here (EXPURGO_RECUSADO); so does the purge gate
           when closed (EXPURGO_REAL_DESABILITADO).
      Past the purge gate:
        2. a reader, a NEW -LogFile (T1 writer, atm.purgelog/1, outside the audited directories and the quarantine) and an
           interactive console observed by the engine are required; the log is created before any question;
        3. the AUT-2 declarations of this purge (J-ISO-4 (a): those of the isolation do not count): the task finished, and
           the content needed is preserved or nothing in it needs to be kept; then the phrase. A refusal, a cancel or a
           wrong phrase stops the run; the declaration and the confirmation are written and flushed before anything else;
        4. after -BeforePurgeHook (tests), the plan again (a fresh inventory and evidence, the entry, its verification,
           every gate, the same measurement and records): any difference stops the run (REVALIDATION_REFUSED);
        5. and 6. Invoke-AtmPurgeDeletion, the path the automatic pass shares: purge-intent in the manifest (reopened
           with OpenExisting, then closed) and in the log, BEFORE the deleter; the only call to the deleter in this
           engine: DeleteTree(<entry>\payload, files, dirs, bytes, newest, $null) with the measurement of the manifest
           (a difference refuses before the first deletion); the absence of the payload confirmed; purge-result
           (automatic = false) in the manifest and in the log. The entry and its manifest stay as the trail (PURGED).
           Anything but a complete, verified purge stops the run (STOPPED_AFTER_<outcome>); nothing is retried.
      -PurgeTreeImpl / -BeforePurgeHook: test seams, never passed by the CLI; scriptblock(plan) that returns an object
      like AtmDeleteResult. Aborted: the deleter was never called. StoppedBy: it was called.
    #>
    [CmdletBinding()]
    param(
        [string]$Id,
        [scriptblock]$PlanPresenter,
        [scriptblock]$ConfirmationReader,
        [hashtable]$InventoryArgs = @{},
        [string]$LogFile,
        [hashtable]$Interaction = @{},
        [scriptblock]$BeforePurgeHook,
        [scriptblock]$PurgeTreeImpl,
        [string]$LockRefusal,
        [string]$LockReleaseError
    )
    $results = New-Object System.Collections.Generic.List[object]
    $logErrors = New-Object System.Collections.Generic.List[object]
    $state = @{ Aborted = $null; Stopped = $null; PlanId = $null; Phrase = $null; RunId = $null; LogCreated = $false; RefusedAt = $null; Plan = $null; Declaration = $null }
    $finish = {
        [pscustomobject]@{
            Id = $Id; Plan = $state.Plan; PlanId = $state.PlanId; Phrase = $state.Phrase; Aborted = $state.Aborted; StoppedBy = $state.Stopped; Results = $results.ToArray()
            RunId = $state.RunId; LogFile = $(if ($state.RunId) { $LogFile } else { $null }); LogCreated = $state.LogCreated; LogErrors = $logErrors.ToArray()
            LockReleaseError = $(if ($LockReleaseError) { $LockReleaseError } else { $null }); RefusedAt = $state.RefusedAt; Declaration = $state.Declaration
        }
    }
    if ($LockRefusal) { $state.Aborted = $LockRefusal; return (& $finish) }
    if ($Id -cnotmatch $script:AtmQuarantineEntryIdPattern) { $state.Aborted = 'ENTRY_ID_INVALID'; return (& $finish) }
    if (-not $PlanPresenter) { $state.Aborted = 'SEM_APRESENTACAO'; return (& $finish) }
    $ia = @{} + $InventoryArgs
    $policy = Get-AtmQuarantinePolicy -ConfigDir ([string]$InventoryArgs['ConfigDir'])
    $inv = Invoke-AtmInventory @ia
    $plan = Get-AtmPurgePlan -Id $Id -Inventory $inv -RuntimeEvidence (Get-AtmCleanRuntimeEvidence -Inventory $inv -InventoryArgs $ia) -Policy $policy
    $state.Plan = $plan
    $runId = [guid]::NewGuid().ToString()
    if (@($plan.Reasons).Count -eq 0) {
        $state.PlanId = Get-AtmPurgePlanId -RunId $runId -Plan $plan
        $state.Phrase = "EXPURGAR $($Id.Substring($Id.Length - 8).ToUpperInvariant()) $($plan.Files) ARQUIVOS"
    }
    & $PlanPresenter $plan $inv $state.PlanId $state.Phrase
    if (@($plan.Reasons).Count -gt 0) { $state.Aborted = 'EXPURGO_RECUSADO'; return (& $finish) }
    if (-not $script:AtmQuarantinePurgeEnabled) { $state.Aborted = 'EXPURGO_REAL_DESABILITADO'; return (& $finish) }

    # ---- past the purge gate (the suite only, in its own process) ----
    if (-not $ConfirmationReader) { $state.Aborted = 'SEM_APRESENTACAO_OU_CONFIRMACAO'; return (& $finish) }
    if (-not $LogFile) { $state.Aborted = 'LOG_REQUIRED'; return (& $finish) }
    $qPath = Get-AtmQuarantineRootPath
    if ($LogFile.StartsWith($qPath.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { $state.Aborted = 'LOG_DESTINATION_NOT_ALLOWED'; return (& $finish) }
    $console = Get-AtmEngineConsoleObservation
    if (-not $console.Observed) { $state.Aborted = 'CONSOLE_NOT_OBSERVED'; return (& $finish) }
    $callerName = [string]$Interaction['Caller']
    $interactionRec = [ordered]@{ caller = $(if ($callerName -ceq 'CLI') { $callerName } else { 'DIRECT_CALL' }); consoleRequiredByCaller = ($Interaction['ConsoleRequired'] -eq $true)
        callerFieldsVerified = $false; interactiveConsoleObserved = $true; observedBy = $console.By; identifiesRespondent = $false }
    $state.RunId = $runId
    $me = Get-AtmCurrentIdentity
    $ls = @{ Id = $runId; Seq = 0 }
    $opId = '{0}:1' -f $runId
    $halt = { param([string]$Code) if ($results.Count -gt 0) { $state.Stopped = $Code } else { $state.Aborted = $Code } }
    $logFail = { param([string]$Stage, [string]$Code) $logErrors.Add([pscustomobject]@{ Stage = $Stage; OpId = $null; Code = $Code }) }
    $e = $plan.Entry
    $log = $null
    try {
        $opened = Open-AtmCleanLog -Path $LogFile -Inventory $inv -ProcessUserSid $me.Sid
        $state.LogCreated = [bool]$opened.Created
        if ($null -eq $opened.Log) { & $logFail 'open' $opened.Code; $state.Aborted = 'LOG_OPEN_FAILED'; return (& $finish) }
        $log = $opened.Log
        $lc = Write-AtmIsolationRecord -Log $log -State $ls -Schema $script:AtmPurgeLogSchema -Type 'run-start' -Fields ([ordered]@{ tool = $script:AtmVersion; operation = 'purge'; user = $inv.Identity.Name; sid = $inv.Identity.Sid
                elevated = [bool]$inv.Identity.IsAdmin; entryId = $Id; planId = $state.PlanId; files = $plan.Files; dirs = $plan.Dirs; bytes = $plan.Bytes; uninspectableProcesses = $plan.Uninspectable })
        if ($null -ne $lc) { & $logFail 'run-start' $lc; $state.Aborted = 'LOG_WRITE_FAILED'; return (& $finish) }

        # AUT-2 for this purge (J-ISO-4 (a)): the task, the content decision, then the phrase bound to the entry.
        $refusal = $null
        $taskPhrase = Get-AtmText 'auth.phrase.task'
        $decisionMap = Get-AtmContentDecisions
        $choices = @($decisionMap.Keys)
        $dec = $null
        $tk = Test-AtmTypedPhrase -Typed (& $ConfirmationReader $taskPhrase 'task' $e.OriginalPath @($taskPhrase)) -Phrases @($taskPhrase)
        if ($tk.Code) { $refusal = [pscustomobject]@{ Code = 'DECLARATION_' + $tk.Code; Step = 'task'; Path = $e.OriginalPath } }
        if ($null -eq $refusal) {
            $cd = Test-AtmTypedPhrase -Typed (& $ConfirmationReader $choices[0] 'results' $e.OriginalPath $choices) -Phrases $choices
            if ($cd.Code) { $refusal = [pscustomobject]@{ Code = 'DECLARATION_' + $cd.Code; Step = 'results'; Path = $e.OriginalPath } } else { $dec = $decisionMap[$cd.Hit] }
        }
        if ($null -eq $refusal) {
            $fc = Test-AtmTypedPhrase -Typed (& $ConfirmationReader $state.Phrase 'purge' $Id @($state.Phrase)) -Phrases @($state.Phrase)
            if ($fc.Code) { $refusal = [pscustomobject]@{ Code = 'CONFIRMACAO_AUSENTE_OU_DIVERGENTE'; Step = 'purge'; Path = $Id } }
        }
        if ($null -ne $refusal) {
            $state.RefusedAt = $refusal
            $lc = Write-AtmIsolationRecord -Log $log -State $ls -Schema $script:AtmPurgeLogSchema -Type 'confirmation' -Fields ([ordered]@{ accepted = $false; planId = $state.PlanId; step = $refusal.Step; refusal = $refusal.Code; interaction = $interactionRec })
            if ($null -ne $lc) { & $logFail 'confirmation' $lc }
            $state.Aborted = $refusal.Code
        } else {
            $state.Declaration = [pscustomobject]@{ TaskCompleted = $true; ContentDecision = $dec; PreservationBasis = (Get-AtmPreservationBasis $dec) }
            $lc = Write-AtmIsolationRecord -Log $log -State $ls -Schema $script:AtmPurgeLogSchema -Type 'declaration' -Fields ([ordered]@{ entryId = $Id; declaredBy = 'OPERATOR'; taskCompleted = $true; contentDecision = $dec
                    preservation = [ordered]@{ basis = $state.Declaration.PreservationBasis; verifiedByTool = $false } })
            if ($null -eq $lc) { $lc = Write-AtmIsolationRecord -Log $log -State $ls -Schema $script:AtmPurgeLogSchema -Type 'confirmation' -Fields ([ordered]@{ accepted = $true; planId = $state.PlanId; entryId = $Id; interaction = $interactionRec; limitations = @($script:AtmCleanDeclarationLimitations) }) }
            if ($null -ne $lc) { & $logFail 'confirmation' $lc; $state.Aborted = 'LOG_WRITE_FAILED' }
        }
        if (-not $state.Aborted) {
            # The plan again after the questions: the entry, its verification and every gate, the same measurement.
            if ($BeforePurgeHook) { & $BeforePurgeHook $plan }
            $iaRe = @{} + $InventoryArgs; $iaRe['NoProgress'] = $true
            $invRe = Invoke-AtmInventory @iaRe
            $re = Get-AtmPurgePlan -Id $Id -Inventory $invRe -RuntimeEvidence (Get-AtmCleanRuntimeEvidence -Inventory $invRe -InventoryArgs $iaRe) -Policy $policy
            $same = (@($re.Reasons).Count -eq 0 -and $re.Files -eq $plan.Files -and $re.Dirs -eq $plan.Dirs -and $re.Bytes -eq $plan.Bytes -and $re.NewestTicks -eq $plan.NewestTicks -and @($re.Entry.Records).Count -eq @($e.Records).Count)
            $lc = Write-AtmIsolationRecord -Log $log -State $ls -Schema $script:AtmPurgeLogSchema -Type 'plan-check' -Fields ([ordered]@{ planId = $state.PlanId; matched = $same; reasons = @($re.Reasons) })
            if ($null -ne $lc) { & $logFail 'plan-check' $lc; $state.Aborted = 'LOG_WRITE_FAILED' }
            elseif (-not $same) { $state.Aborted = 'REVALIDATION_REFUSED' }
        }
        if (-not $state.Aborted) {
            # The intent, the deleter and the result: Invoke-AtmPurgeDeletion, the same path as the automatic pass.
            $pd = Invoke-AtmPurgeDeletion -Plan $plan -OpId $opId -RunId $runId -PlanId $state.PlanId -Log $log -LogState $ls -LogSchema $script:AtmPurgeLogSchema -Sid $me.Sid -PurgeTreeImpl $PurgeTreeImpl
            foreach ($le in @($pd.LogErrors)) { $logErrors.Add($le) }
            if ($null -ne $pd.Row) { $results.Add($pd.Row) }
            if ($pd.Aborted) { $state.Aborted = $pd.Aborted } elseif ($pd.Halt) { & $halt $pd.Halt }
        }
        # run-end only while the log has not failed; neither a failed run-end nor a failed close replaces the main code.
        if ($logErrors.Count -eq 0) {
            $lc = Write-AtmIsolationRecord -Log $log -State $ls -Schema $script:AtmPurgeLogSchema -Type 'run-end' -Fields ([ordered]@{ results = $results.Count; complete = @($results | Where-Object { $_.Outcome -ceq 'COMPLETE' }).Count; stoppedBy = $(if ($state.Stopped) { $state.Stopped } else { $state.Aborted }); entryId = $Id })
            if ($null -ne $lc) { & $logFail 'run-end' $lc; if (-not $state.Aborted -and -not $state.Stopped) { & $halt 'LOG_END_FAILED' } }
        }
        $cc = $log.Close()
        if ($null -ne $cc) { & $logFail 'close' $cc; if (-not $state.Aborted -and -not $state.Stopped) { & $halt 'LOG_CLOSE_FAILED' } }
        return (& $finish)
    } finally {
        if ($null -ne $log) { try { $log.Dispose() } catch { $null = $_ } }
    }
}

function Invoke-AtmPurgeDeletion {
    <#
      The purge of one planned entry, the path shared by the manual purge (Invoke-AtmPurgeCore) and the automatic pass
      (Invoke-AtmAutoPurgeCore); reached only past the purge gate, under the clean lock:
        1. purge-intent in the manifest (reopened with OpenExisting, then closed) and in the log, BEFORE the deleter;
        2. the only call to the deleter in this engine: DeleteTree(<entry>\payload, files, dirs, bytes, newest, $null)
           with the measurement of the manifest (a difference refuses before the first deletion); an exception leaves
           the payload's state unknown (none, part or all of it);
        3. the absence of the payload confirmed (never assumed); purge-result in the manifest and in the log.
      -Automatic: both records carry automatic = true and declaredBy = AUTOMATIC_POLICY (contract section 11.1);
      without it they are the manual purge's (automatic = false; declaredBy = OPERATOR in the manifest's intent).
      -PurgeTreeImpl: the manual purge's test seam. Returns Aborted (an intent was not written: the deleter was never
      called), Halt (the deleter was called and the run must stop: a result not written, or any outcome but COMPLETE),
      Row (the result) and LogErrors.
    #>
    param($Plan, [string]$OpId, [string]$RunId, [string]$PlanId, $Log, [hashtable]$LogState, [string]$LogSchema, [string]$Sid, [switch]$Automatic, [scriptblock]$PurgeTreeImpl)
    $out = [ordered]@{ Aborted = $null; Halt = $null; Row = $null; LogErrors = @() }
    $errs = New-Object System.Collections.Generic.List[object]
    $done = { $out.LogErrors = $errs.ToArray(); [pscustomobject]$out }
    $id = [string]$Plan.Entry.Id
    $entryPath = [string]$Plan.Entry.Path
    $ms = @{ Id = $id; Seq = @($Plan.Entry.Records).Count }
    $auto = [bool]$Automatic
    $by = $(if ($auto) { 'AUTOMATIC_POLICY' } else { 'OPERATOR' })
    # One manifest record: the manifest reopened (OpenExisting, the same checks), written, flushed and closed.
    $writeManifest = {
        param([string]$Type, [System.Collections.IDictionary]$Fields)
        $mf = [AgentTempManager.AtmCleanLog]::Pin($entryPath, $Sid)
        try {
            $c = $(if ($null -ne $mf.Error) { $mf.Error } else { $mf.OpenExisting('manifest.jsonl') })
            if ($null -eq $c) { $c = Write-AtmIsolationRecord -Log $mf -State $ms -Schema $script:AtmQuarantineSchema -Type $Type -Fields $Fields }
            if ($null -eq $c) { $c = $mf.Close() }
            return $c
        } finally { $mf.Dispose() }
    }
    # The intent is written and flushed, in the manifest and in the log, BEFORE the deleter; without both, no purge.
    $mc = & $writeManifest 'purge-intent' ([ordered]@{ opId = $OpId; runId = $RunId; planId = $PlanId; files = $Plan.Files; dirs = $Plan.Dirs; bytes = $Plan.Bytes; automatic = $auto; declaredBy = $by })
    if ($null -ne $mc) { $out.Aborted = 'MANIFEST_INTENT_FAILED'; return (& $done) }
    $li = [ordered]@{ opId = $OpId; entryId = $id; files = $Plan.Files; dirs = $Plan.Dirs; bytes = $Plan.Bytes; automatic = $auto }
    if ($auto) { $li['declaredBy'] = $by }
    $lc = Write-AtmIsolationRecord -Log $Log -State $LogState -Schema $LogSchema -Type 'purge-intent' -Fields $li
    if ($null -ne $lc) { $errs.Add([pscustomobject]@{ Stage = 'purge-intent'; OpId = $null; Code = $lc }); $out.Aborted = 'LOG_INTENT_FAILED'; return (& $done) }
    # The only call to the deleter: it pins the payload, plans it and compares the measurement of the manifest before
    # the first deletion.
    $d = $null; $exType = $null
    try {
        if ($PurgeTreeImpl) { $d = & $PurgeTreeImpl $Plan }
        else { $d = [AgentTempManager.AtmDeleter]::DeleteTree($Plan.PayloadPath, $Plan.Files, $Plan.Dirs, $Plan.Bytes, $Plan.NewestTicks, $null) }
        if ($null -eq $d) { throw [InvalidOperationException]::new('DELETER_NO_RESULT') }
    } catch { $d = $null; $exType = $_.Exception.GetBaseException().GetType().Name }
    # Only a confirmed absence verifies the purge; access denied or any other error: not verified, never assumed.
    $gone = $false; $vs = 'UNKNOWN'
    if ($null -eq $exType) {
        $pres = Get-AtmPathPresence $Plan.PayloadPath
        if ($pres -is [bool]) { $gone = -not $pres; $vs = $(if ($pres) { 'PRESENT' } else { 'GONE' }) }
    }
    $outcome = $(if ($null -ne $exType) { 'EXCEPTION' }
        elseif (-not $d.Completed) { $(if ([long]$d.FilesDeleted -gt 0 -or [long]$d.DirsDeleted -gt 0) { 'PARTIAL' } else { 'REFUSED' }) }
        elseif ($gone) { 'COMPLETE' }
        else { 'VERIFICATION_FAILED' })
    $known = ($null -ne $d)
    # The deleter's reason without the path it may carry: its code only (no file names in the records).
    $abort = $(if ($known -and $d.AbortReason) { ([regex]::Match([string]$d.AbortReason, '^[A-Z0-9_]+')).Value } else { $null })
    $row = [pscustomobject]@{ OpId = $OpId; Id = $id; Outcome = $outcome; Attempted = $(if ($known) { [bool]$d.Attempted } else { $null }); Completed = ($known -and [bool]$d.Completed); Verified = $gone; VerifiedState = $vs
        FilesDeleted = $(if ($known) { $d.FilesDeleted } else { $null }); DirsDeleted = $(if ($known) { $d.DirsDeleted } else { $null }); FilesPlanned = $(if ($known) { $d.FilesPlanned } else { $null })
        DirsPlanned = $(if ($known) { $d.DirsPlanned } else { $null }); AbortReason = $abort; ExceptionType = $exType; Bytes = $Plan.Bytes }
    $out.Row = $row
    $after = [ordered]@{ opId = $OpId; outcome = $outcome; filesDeleted = $row.FilesDeleted; dirsDeleted = $row.DirsDeleted; automatic = $auto; attempted = $row.Attempted; completed = $row.Completed
        filesPlanned = $row.FilesPlanned; dirsPlanned = $row.DirsPlanned; abortReason = $abort; verifiedGone = $(if ($vs -ceq 'UNKNOWN') { 'UNKNOWN' } else { $gone }); exceptionType = $exType }
    if ($auto) { $after['declaredBy'] = $by }
    $mc = & $writeManifest 'purge-result' $after
    $after['entryId'] = $id
    $lc = Write-AtmIsolationRecord -Log $Log -State $LogState -Schema $LogSchema -Type 'purge-result' -Fields $after
    if ($null -ne $lc) { $errs.Add([pscustomobject]@{ Stage = 'purge-result'; OpId = $null; Code = $lc }); $out.Halt = 'LOG_RESULT_FAILED' }
    elseif ($null -ne $mc) { $out.Halt = 'MANIFEST_RESULT_FAILED' }
    elseif ($outcome -cne 'COMPLETE') { $out.Halt = 'STOPPED_AFTER_' + $outcome }
    return (& $done)
}

# ---------------------------------------------------------------------------------------------
# Automatic purge (contract section 11, J-ISO-7 (ii), phase P6a): the pass behind bin\agent-temp-autopurge.ps1, its only
# caller. The pass runs only when that entry point is run: by the user's optional scheduled task (phase P6b, below) or by
# hand. It asks nothing (the
# administrator's policy is the authorization, ISO-D4) and is not a parameter of the interactive CLI.
# ---------------------------------------------------------------------------------------------

function Test-AtmAutoPurgeFutureDate {
    # FUTURE_DATE (contract section 11.3): the time in the entry's id, or in any record of its manifest, is after -NowUtc
    # (a clock set back, or records written with a clock ahead). A time that cannot be read is a doubt: $true too.
    param($Entry, [datetime]$NowUtc)
    $ticks = New-Object System.Collections.Generic.List[long]
    try {
        if ([string]$Entry.Id -cmatch $script:AtmQuarantineEntryIdPattern) {
            $ticks.Add([datetime]::ParseExact($Entry.Id.Substring(0, 16), 'yyyyMMdd\THHmmss\Z', [Globalization.CultureInfo]::InvariantCulture, ([Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal)).Ticks)
        }
        foreach ($r in @($Entry.Records)) { if ($null -ne $r.Utc -and '' -ne $r.Utc) { $ticks.Add((ConvertTo-AtmUtcTicks $r.Utc)) } }
    } catch { return $true }
    foreach ($t in $ticks) { if ($t -gt $NowUtc.ToUniversalTime().Ticks) { return $true } }
    return $false
}

function Open-AtmAutoPurgeLog {
    <#
      A NEW log for one pass: <parent of the quarantine root>\AutoPurgeLog\<yyyyMMddTHHmmssZ>-<8 hex>.jsonl, outside the
      quarantine, at a place fixed in code. A missing folder is created relative to its pinned parent
      (AtmSafeCreate.CreateNewDirectory: never an existing name, never through a reparse point, protected DACL of the
      new object only); then the T1 writer (Open-AtmCleanLog: the folder policy of AtmCleanLog.Pin, the audited
      directories rule, a new file). Returns Log, Path, Code and Created (a file was created; it is never removed).
    #>
    param([string]$QuarantineRoot, [string]$RunId, $Inventory, [string]$ProcessUserSid)
    $out = [ordered]@{ Log = $null; Path = $null; Code = $null; Created = $false }
    $parent = [IO.Path]::GetDirectoryName($QuarantineRoot)
    $dir = Join-Path $parent $script:AtmAutoPurgeLogFolder
    if (-not [IO.Directory]::Exists($dir)) {
        $pin = [AgentTempManager.AtmSafeCreate]::Pin($parent)
        try {
            if (-not $pin.IsPinned) { $out.Code = 'AUTOPURGE_LOG_PARENT_' + $pin.Error; return [pscustomobject]$out }
            $n = [AgentTempManager.AtmSafeCreate]::CreateNewDirectory($pin, $script:AtmAutoPurgeLogFolder, $ProcessUserSid)
            try { if ($null -ne $n.Error -and $n.Error -cne 'EXISTS') { $out.Code = 'AUTOPURGE_LOG_CREATE_' + $n.Error; return [pscustomobject]$out } } finally { $n.Dispose() }
        } finally { $pin.Dispose() }
    }
    $out.Path = Join-Path $dir ([datetime]::UtcNow.ToString('yyyyMMdd\THHmmss\Z', [Globalization.CultureInfo]::InvariantCulture) + '-' + $RunId.Substring(0, 8) + '.jsonl')
    $o = Open-AtmCleanLog -Path $out.Path -Inventory $Inventory -ProcessUserSid $ProcessUserSid
    $out.Log = $o.Log; $out.Code = $o.Code; $out.Created = [bool]$o.Created
    return [pscustomobject]$out
}

function Invoke-AtmAutoPurge {
    <#
      The automatic purge pass (contract section 11.1), called only by bin\agent-temp-autopurge.ps1: never by the
      interactive CLI or the TUI. It has no reader, phrase or console: nothing is ever answered for an operator.
        * autoPurge must be true in a valid policy (config\quarantine.policy.json under -InventoryArgs.ConfigDir);
          absent, invalid or off: nothing else is read or done (AUTOPURGE_OFF);
        * retentionDays below the minimum fixed in code: nothing expires automatically (AUTOPURGE_RETENTION_BELOW_MINIMUM);
        * the purge gate governs. Closed (every distributed copy): the pass only reports what it would purge
          (EXPURGO_REAL_DESABILITADO): no lock, no log, nothing purged. Past it, the clean lock (B8, the same name) is
          taken without waiting (busy: the pass ends with nothing purged and no log) and Invoke-AtmAutoPurgeCore runs
          under it.
      -BeforePurgeHook / -PurgeTreeImpl: the manual purge's test seams, never passed by the entry point.
    #>
    [CmdletBinding()]
    param([hashtable]$InventoryArgs = @{}, [scriptblock]$BeforePurgeHook, [scriptblock]$PurgeTreeImpl)
    $policy = Get-AtmQuarantinePolicy -ConfigDir ([string]$InventoryArgs['ConfigDir'])
    $empty = { param([string]$Code) [pscustomobject]@{ Policy = $policy; Aborted = $Code; StoppedBy = $null; Entries = @(); Results = @(); RunId = $null; LogFile = $null; LogCreated = $false; LogErrors = @(); LockReleaseError = $null } }
    if ($policy.Source -cne 'FILE' -or -not $policy.AutoPurge) { return (& $empty 'AUTOPURGE_OFF') }
    if ([int]$policy.RetentionDays -lt $script:AtmAutoPurgeMinRetentionDays) { return (& $empty 'AUTOPURGE_RETENTION_BELOW_MINIMUM') }
    if (-not $script:AtmQuarantinePurgeEnabled) { return (Invoke-AtmAutoPurgeCore -Policy $policy @PSBoundParameters) }
    # No closure: the body runs in this session state, where the engine's functions are, and finds $apBound here.
    $apBound = @{} + $PSBoundParameters
    $u = Invoke-AtmUnderSharedLock -Body { Invoke-AtmAutoPurgeCore -Policy $policy @apBound }
    if (-not $u.Acquired) { $r = & $empty ('CLEAN_LOCK_' + $u.Status); $r.LockReleaseError = $u.ReleaseError; return $r }
    $res = $u.Result
    # A failed release never replaces the main code; with none it makes the pass incomplete.
    if ($null -ne $u.ReleaseError -and $null -ne $res) {
        $res.LockReleaseError = $u.ReleaseError
        if (-not $res.Aborted -and -not $res.StoppedBy) { if (@($res.Results).Count -gt 0) { $res.StoppedBy = 'LOCK_RELEASE_FAILED' } else { $res.Aborted = 'LOCK_RELEASE_FAILED' } }
    }
    return $res
}

function Invoke-AtmAutoPurgeCore {
    <#
      The pass itself (contract section 11.1), called only by Invoke-AtmAutoPurge, which owns the lock past the gate.
        1. a fresh inventory, its runtime evidence and the quarantine of the process user (Get-AtmQuarantineList, with
           the retention of -Policy and the clock of the retention). A missing quarantine: nothing to do
           (QUARANTINE_ABSENT, no log); a quarantine that is a reparse point: refused (QUARANTINE_REPARSE_POINT);
        2. each entry, in order: a date after the clock skips it first (FUTURE_DATE); only an EXPIRED entry goes on
           (ABANDONED, INCOMPLETE, FAILED, UNRECOGNIZED, an invalid manifest, ISOLATED not yet expired, RESTORED or
           PURGED: skipped with its state, STATE_<state>); then the plan of the manual purge (Get-AtmPurgePlan: verify
           OK in this pass, gates 3, 4 and 8, B2-1 extended to the quarantine), and EXPIRED again in it. Any reason
           skips the entry; there is never a weaker retry;
        3. purge gate closed: the report only (WOULD_PURGE or SKIPPED, with the reasons) and EXPURGO_REAL_DESABILITADO.
      Past the gate (under the lock):
        4. a NEW log of the pass (Open-AtmAutoPurgeLog, atm.autopurgelog/1); run-start, then one skip record per skipped
           entry (its id and codes, never a path);
        5. for each candidate: after -BeforePurgeHook (tests), the plan again with a fresh inventory (the same
           measurement and records, still EXPIRED, every gate): a difference skips it (REVALIDATION_REFUSED). Then the
           path of the manual purge (Invoke-AtmPurgeDeletion, automatic): purge-intent and purge-result carry
           automatic = true and declaredBy = AUTOMATIC_POLICY in the manifest and in the log. An intent not written to
           the manifest, or a deleter that refused before deleting anything, skips the entry; any other outcome but
           COMPLETE, or a record of the log not written, stops the pass (the rest NOT_REACHED).
      Entries: Id, Decision (PURGED, WOULD_PURGE, SKIPPED, STOPPED, NOT_REACHED) and Reasons. Returns arrays only.
    #>
    [CmdletBinding()]
    param($Policy, [hashtable]$InventoryArgs = @{}, [scriptblock]$BeforePurgeHook, [scriptblock]$PurgeTreeImpl)
    $rows = New-Object System.Collections.Generic.List[object]
    $byId = @{}
    $results = New-Object System.Collections.Generic.List[object]
    $logErrors = New-Object System.Collections.Generic.List[object]
    $state = @{ Aborted = $null; Stopped = $null; RunId = $null; LogFile = $null; LogCreated = $false }
    $finish = {
        [pscustomobject]@{ Policy = $Policy; Aborted = $state.Aborted; StoppedBy = $state.Stopped; Entries = $rows.ToArray(); Results = $results.ToArray(); RunId = $state.RunId
            LogFile = $state.LogFile; LogCreated = $state.LogCreated; LogErrors = $logErrors.ToArray(); LockReleaseError = $null }
    }
    $ia = @{} + $InventoryArgs
    $inv = Invoke-AtmInventory @ia
    $rt = Get-AtmCleanRuntimeEvidence -Inventory $inv -InventoryArgs $ia
    $qRoot = Get-AtmQuarantineRootPath
    if (-not $qRoot) { $state.Aborted = 'QUARANTINE_PATH_INVALID'; return (& $finish) }
    $list = Get-AtmQuarantineList -Root $qRoot -OwnSid ([string]$inv.Identity.Sid) -Policy $Policy
    if ($list.RootProblem) { $state.Aborted = [string]$list.RootProblem; return (& $finish) }
    if (-not $list.Exists) { $state.Aborted = 'QUARANTINE_ABSENT'; return (& $finish) }
    $now = Get-AtmQuarantineNowUtc
    $cands = New-Object System.Collections.Generic.List[object]
    foreach ($en in @($list.Entries)) {
        $why = @()
        if (Test-AtmAutoPurgeFutureDate -Entry $en -NowUtc $now) { $why = @('FUTURE_DATE') }
        elseif ([string]$en.State -cne 'EXPIRED') { $why = @('STATE_' + $en.State + $(if ($en.Problem) { ' (' + $en.Problem + ')' } elseif ($en.Pending) { ' (' + $en.Pending + ')' } else { '' })) }
        else {
            $plan = Get-AtmPurgePlan -Id $en.Id -Inventory $inv -RuntimeEvidence $rt -Policy $Policy
            if (@($plan.Reasons).Count -gt 0) { $why = @($plan.Reasons) }
            elseif ($null -eq $plan.Entry -or [string]$plan.Entry.State -cne 'EXPIRED') { $why = @('STATE_' + $(if ($null -ne $plan.Entry) { $plan.Entry.State } else { 'UNKNOWN' })) }
            else { $cands.Add($plan) }
        }
        $row = [pscustomobject]@{ Id = [string]$en.Id; Decision = $(if (@($why).Count -gt 0) { 'SKIPPED' } else { 'CANDIDATE' }); Reasons = @($why) }
        $rows.Add($row); $byId[$row.Id] = $row
    }
    if (-not $script:AtmQuarantinePurgeEnabled) {
        foreach ($r in $rows) { if ($r.Decision -ceq 'CANDIDATE') { $r.Decision = 'WOULD_PURGE' } }
        $state.Aborted = 'EXPURGO_REAL_DESABILITADO'
        return (& $finish)
    }

    # ---- past the purge gate (the suite only, in its own process), under the clean lock ----
    $me = Get-AtmCurrentIdentity
    $runId = [guid]::NewGuid().ToString()
    $halt = { param([string]$Code) if ($results.Count -gt 0) { $state.Stopped = $Code } else { $state.Aborted = $Code } }
    $logFail = { param([string]$Stage, [string]$Code) $logErrors.Add([pscustomobject]@{ Stage = $Stage; OpId = $null; Code = $Code }) }
    $unreached = { foreach ($r in $rows) { if ($r.Decision -ceq 'CANDIDATE') { $r.Decision = 'NOT_REACHED' } } }
    $opened = Open-AtmAutoPurgeLog -QuarantineRoot $qRoot -RunId $runId -Inventory $inv -ProcessUserSid $me.Sid
    $state.LogCreated = [bool]$opened.Created
    if ($null -eq $opened.Log) { & $logFail 'open' $opened.Code; $state.Aborted = 'LOG_OPEN_FAILED'; & $unreached; return (& $finish) }
    $state.RunId = $runId; $state.LogFile = $opened.Path
    $log = $opened.Log
    $ls = @{ Id = $runId; Seq = 0 }
    $skipRec = { param($Row) $c = Write-AtmIsolationRecord -Log $log -State $ls -Schema $script:AtmAutoPurgeLogSchema -Type 'skip' -Fields ([ordered]@{ entryId = $Row.Id; reasons = @($Row.Reasons) }); if ($null -ne $c) { & $logFail 'skip' $c; & $halt 'LOG_WRITE_FAILED' } }
    try {
        $lc = Write-AtmIsolationRecord -Log $log -State $ls -Schema $script:AtmAutoPurgeLogSchema -Type 'run-start' -Fields ([ordered]@{ tool = $script:AtmVersion; operation = 'autopurge'; user = $inv.Identity.Name; sid = $inv.Identity.Sid
                elevated = [bool]$inv.Identity.IsAdmin; declaredBy = 'AUTOMATIC_POLICY'; retentionDays = $Policy.RetentionDays; minRetentionDays = $script:AtmAutoPurgeMinRetentionDays; clockUtc = $now.ToString('o')
                entries = $rows.Count; candidates = $cands.Count })
        if ($null -ne $lc) { & $logFail 'run-start' $lc; $state.Aborted = 'LOG_WRITE_FAILED' }
        foreach ($r in @($rows | Where-Object { $_.Decision -ceq 'SKIPPED' })) { if (-not $state.Aborted) { & $skipRec $r } }
        $n = 0
        foreach ($plan in $cands) {
            $row = $byId[[string]$plan.Entry.Id]
            if ($state.Aborted -or $state.Stopped) { $row.Decision = 'NOT_REACHED'; continue }
            $n++
            $opId = '{0}:{1}' -f $runId, $n
            # The plan again, immediately before the deleter: a fresh inventory and evidence, the entry, its verification,
            # every gate, the same measurement and records, still EXPIRED.
            if ($BeforePurgeHook) { & $BeforePurgeHook $plan }
            $iaRe = @{} + $InventoryArgs; $iaRe['NoProgress'] = $true
            $invRe = Invoke-AtmInventory @iaRe
            $re = Get-AtmPurgePlan -Id $plan.Entry.Id -Inventory $invRe -RuntimeEvidence (Get-AtmCleanRuntimeEvidence -Inventory $invRe -InventoryArgs $iaRe) -Policy $Policy
            $same = (@($re.Reasons).Count -eq 0 -and $null -ne $re.Entry -and [string]$re.Entry.State -ceq 'EXPIRED' -and $re.Files -eq $plan.Files -and $re.Dirs -eq $plan.Dirs -and $re.Bytes -eq $plan.Bytes -and
                $re.NewestTicks -eq $plan.NewestTicks -and @($re.Entry.Records).Count -eq @($plan.Entry.Records).Count)
            $lc = Write-AtmIsolationRecord -Log $log -State $ls -Schema $script:AtmAutoPurgeLogSchema -Type 'plan-check' -Fields ([ordered]@{ opId = $opId; entryId = $row.Id; matched = $same; reasons = @($re.Reasons) })
            if ($null -ne $lc) { & $logFail 'plan-check' $lc; & $halt 'LOG_WRITE_FAILED'; $row.Decision = 'NOT_REACHED'; continue }
            if (-not $same) { $row.Decision = 'SKIPPED'; $row.Reasons = @(@('REVALIDATION_REFUSED') + @($re.Reasons)); & $skipRec $row; continue }
            $pd = Invoke-AtmPurgeDeletion -Plan $plan -OpId $opId -RunId $runId -PlanId (Get-AtmPurgePlanId -RunId $runId -Plan $plan) -Log $log -LogState $ls -LogSchema $script:AtmAutoPurgeLogSchema -Sid $me.Sid -Automatic -PurgeTreeImpl $PurgeTreeImpl
            foreach ($le in @($pd.LogErrors)) { $logErrors.Add($le) }
            if ($pd.Aborted -ceq 'MANIFEST_INTENT_FAILED') { $row.Decision = 'SKIPPED'; $row.Reasons = @('MANIFEST_INTENT_FAILED'); & $skipRec $row; continue }
            if ($pd.Aborted) { $row.Decision = 'STOPPED'; $row.Reasons = @($pd.Aborted); & $halt $pd.Aborted; continue }
            $results.Add($pd.Row)
            if ($pd.Row.Outcome -ceq 'COMPLETE' -and -not $pd.Halt) { $row.Decision = 'PURGED'; continue }
            # A deleter that refused before deleting anything leaves the entry as it was: skipped, the pass goes on.
            if ($pd.Halt -ceq 'STOPPED_AFTER_REFUSED') { $row.Decision = 'SKIPPED'; $row.Reasons = @('DELETER_REFUSED' + $(if ($pd.Row.AbortReason) { ' (' + $pd.Row.AbortReason + ')' } else { '' })); continue }
            $row.Decision = 'STOPPED'; $row.Reasons = @($pd.Halt)
            & $halt $pd.Halt
        }
        # run-end only while the log has not failed; neither a failed run-end nor a failed close replaces the main code.
        if ($logErrors.Count -eq 0) {
            $lc = Write-AtmIsolationRecord -Log $log -State $ls -Schema $script:AtmAutoPurgeLogSchema -Type 'run-end' -Fields ([ordered]@{ results = $results.Count; purged = @($rows | Where-Object { $_.Decision -ceq 'PURGED' }).Count
                    skipped = @($rows | Where-Object { $_.Decision -ceq 'SKIPPED' }).Count; stoppedBy = $(if ($state.Stopped) { $state.Stopped } else { $state.Aborted }) })
            if ($null -ne $lc) { & $logFail 'run-end' $lc; if (-not $state.Aborted -and -not $state.Stopped) { & $halt 'LOG_END_FAILED' } }
        }
        $cc = $log.Close()
        if ($null -ne $cc) { & $logFail 'close' $cc; if (-not $state.Aborted -and -not $state.Stopped) { & $halt 'LOG_CLOSE_FAILED' } }
        return (& $finish)
    } finally {
        if ($null -ne $log) { try { $log.Dispose() } catch { $null = $_ } }
    }
}

# ------------------------------------------------------------------ the scheduled task of the automatic purge (P6b)
# The Task Scheduler is reached only through Connect-AtmTaskScheduler. It is changed only by Register-AtmAutoPurgeTask
# (quarantine schedule-autopurge) and Unregister-AtmAutoPurgeTask (quarantine unschedule-autopurge); everything else
# (version, quarantine list, the TUI) only reads the task's state.

function Get-AtmAutoPurgeTaskName {
    # The task name of a user: the prefix and the first 16 hex digits of the SHA-256 of the SID (UTF-8), never the SID.
    # The suite's name replaces it only in the test form.
    param([string]$Sid)
    if ($null -ne $script:AtmAutoPurgeTaskNameOverride) {
        if ([string]$script:AtmAutoPurgeTaskNameOverride -cnotmatch '^AutoPurgeTest-[0-9a-f]{8}$') { throw 'AUTOPURGE_TASK_TEST_NAME_INVALID' }
        return [string]$script:AtmAutoPurgeTaskNameOverride
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Sid)) } finally { $sha.Dispose() }
    return $script:AtmAutoPurgeTaskPrefix + (-join ($h[0..7] | ForEach-Object { $_.ToString('x2') }))
}

function Get-AtmAutoPurgeEntryPoint {
    # The entry point of this copy (bin next to lib): the only action a task of the product may have.
    return (Join-AtmPath (Split-Path $PSScriptRoot -Parent) 'bin\agent-temp-autopurge.ps1')
}

function Get-AtmAutoPurgeTaskAction {
    # The exact action (program and arguments), built only here for the definition and for every comparison: Windows
    # PowerShell 5.1 by its absolute path, as bin\agent-temp.cmd, with no profile, no input and a hidden window, and the
    # entry point with no arguments of its own.
    param([string]$EntryPoint)
    return [pscustomobject]@{
        Path      = (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe')
        Arguments = ('-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}"' -f $EntryPoint)
    }
}

function Get-AtmAutoPurgeTaskStart {
    # The first run: the next occurrence of the fixed hour at least one minute ahead, in local time without an offset (the
    # scheduler keeps the local hour across daylight-saving changes). Registering the task never starts a run.
    param([datetime]$Now = [datetime]::Now)
    $t = $Now.Date.AddHours($script:AtmAutoPurgeTaskHour)
    if ($t -le $Now.AddMinutes(1)) { $t = $t.AddDays(1) }
    return $t.ToString('yyyy-MM-ddTHH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
}

function Connect-AtmTaskScheduler {
    # The Task Scheduler of this machine, as the process user (its COM service object).
    $svc = New-Object -ComObject 'Schedule.Service'
    $svc.Connect()
    return $svc
}

function Get-AtmTaskSchedulerCode {
    # A scheduler error as a code (its HRESULT), never a message: TASK_SCHEDULER_0x<8 hex digits>.
    param($Exception)
    return ('TASK_SCHEDULER_0x{0:X8}' -f [int](Get-AtmInnerException $Exception).HResult)
}

function Test-AtmTaskNotFound {
    # The folder or the task does not exist (ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND); any other error is not absence.
    param($Exception)
    return (@(-2147024894, -2147024893) -contains [int](Get-AtmInnerException $Exception).HResult)
}

function Resolve-AtmTaskUserSid {
    # The SID of a task's user, given as a SID or as an account name; $null when it cannot be resolved (never a match).
    param([string]$UserId)
    if (-not $UserId) { return $null }
    try {
        if ($UserId -cmatch '^S-1-') { return (New-Object Security.Principal.SecurityIdentifier($UserId)).Value }
        return (New-Object Security.Principal.NTAccount($UserId)).Translate([Security.Principal.SecurityIdentifier]).Value
    } catch { return $null }
}

function Get-AtmAutoPurgeTaskObject {
    # The task of this name in the product's folder, read only (the folder is never created here): Folder and Task
    # ($null when absent), or Code when the scheduler cannot be read.
    param($Service, [string]$Name)
    $folder = $null
    try { $folder = $Service.GetFolder($script:AtmAutoPurgeTaskFolder) } catch {
        if (Test-AtmTaskNotFound $_.Exception) { return [pscustomobject]@{ Folder = $null; Task = $null; Code = $null } }
        return [pscustomobject]@{ Folder = $null; Task = $null; Code = (Get-AtmTaskSchedulerCode $_.Exception) }
    }
    $task = $null
    try { $task = $folder.GetTask($Name) } catch {
        if (Test-AtmTaskNotFound $_.Exception) { return [pscustomobject]@{ Folder = $folder; Task = $null; Code = $null } }
        return [pscustomobject]@{ Folder = $folder; Task = $null; Code = (Get-AtmTaskSchedulerCode $_.Exception) }
    }
    return [pscustomobject]@{ Folder = $folder; Task = $task; Code = $null }
}

function Test-AtmAutoPurgeTaskMatch {
    # Read only: the reasons a registered task is not exactly the product's task of this user (none: it is). Its path in
    # the product's folder; its user (the SID, or a name that resolves to it); interactive logon; limited run level; one
    # action, a program, exactly the action of Get-AtmAutoPurgeTaskAction, with no working directory.
    param($Task, [string]$Sid, [string]$Name, [string]$EntryPoint)
    $r = New-Object System.Collections.Generic.List[string]
    if (-not [string]::Equals([string]$Task.Path, ($script:AtmAutoPurgeTaskFolder + '\' + $Name), [StringComparison]::OrdinalIgnoreCase)) { $r.Add('TASK_PATH') }
    $td = $Task.Definition
    if ((Resolve-AtmTaskUserSid ([string]$td.Principal.UserId)) -cne $Sid) { $r.Add('TASK_USER') }
    if ([int]$td.Principal.LogonType -ne 3) { $r.Add('TASK_LOGON_TYPE') }
    if ([int]$td.Principal.RunLevel -ne 0) { $r.Add('TASK_RUN_LEVEL') }
    if ([int]$td.Actions.Count -ne 1) { $r.Add('TASK_ACTION_COUNT') }
    else {
        $a = $td.Actions.Item(1)
        if ([int]$a.Type -ne 0) { $r.Add('TASK_ACTION_TYPE') }
        else {
            $want = Get-AtmAutoPurgeTaskAction -EntryPoint $EntryPoint
            if (-not [string]::Equals([string]$a.Path, $want.Path, [StringComparison]::OrdinalIgnoreCase)) { $r.Add('TASK_ACTION_PATH') }
            if ([string]$a.Arguments -cne $want.Arguments) { $r.Add('TASK_ACTION_ARGUMENTS') }
            if ([string]$a.WorkingDirectory) { $r.Add('TASK_ACTION_DIRECTORY') }
        }
    }
    return $r.ToArray()
}

function Get-AtmAutoPurgeTaskState {
    # Read only: the product's task of the process user. State ABSENT, PRESENT (exactly the product's task, with the entry
    # point of this copy), DIVERGENT (Reasons) or UNREADABLE (Reasons: the code). TaskPath, Enabled, NextRunTime and
    # LastRunTime/LastResult (local times; $null when none). Never the SID or the account name.
    $me = Get-AtmCurrentIdentity
    $name = Get-AtmAutoPurgeTaskName -Sid $me.Sid
    $st = [ordered]@{ State = 'UNREADABLE'; TaskPath = ($script:AtmAutoPurgeTaskFolder + '\' + $name); Enabled = $null; NextRunTime = $null; LastRunTime = $null; LastResult = $null; Reasons = @() }
    try {
        $found = Get-AtmAutoPurgeTaskObject -Service (Connect-AtmTaskScheduler) -Name $name
        if ($found.Code) { $st.Reasons = @($found.Code) }
        elseif ($null -eq $found.Task) { $st.State = 'ABSENT' }
        else {
            $t = $found.Task
            $st.Reasons = @(Test-AtmAutoPurgeTaskMatch -Task $t -Sid $me.Sid -Name $name -EntryPoint (Get-AtmAutoPurgeEntryPoint))
            $st.State = $(if ($st.Reasons.Count -gt 0) { 'DIVERGENT' } else { 'PRESENT' })
            $st.Enabled = [bool]$t.Enabled
            # No next run: a date in 1899. Never run: SCHED_S_TASK_HAS_NOT_RUN (0x00041303), with a last run in 1999.
            $nr = [datetime]$t.NextRunTime; if ($nr.Year -gt 1900) { $st.NextRunTime = $nr }
            $lr = [datetime]$t.LastRunTime; if ([int]$t.LastTaskResult -ne 267011 -and $lr.Year -gt 1999) { $st.LastRunTime = $lr; $st.LastResult = ('0x{0:X8}' -f [int]$t.LastTaskResult) }
        }
    } catch { $st.State = 'UNREADABLE'; $st.Reasons = @(Get-AtmTaskSchedulerCode $_.Exception) }
    return [pscustomobject]$st
}

function New-AtmAutoPurgeTaskDefinition {
    # The definition of the task, not registered: the user's own token, interactive (no password), limited; daily at the
    # fixed hour with the random delay, a missed run at the next opportunity, also on battery (the defaults would never
    # start it on a laptop on battery), one instance at a time, stopped at the time limit; the single action.
    param($Service, [string]$Sid, [string]$EntryPoint, [datetime]$Now = [datetime]::Now)
    $td = $Service.NewTask(0)
    $td.RegistrationInfo.Author = 'Agent Temp Manager'
    $td.RegistrationInfo.Description = 'Agent Temp Manager: automatic purge of EXPIRED quarantine entries. It acts only with autoPurge = true in the policy of the installation.'
    $td.Principal.UserId = $Sid
    $td.Principal.LogonType = 3
    $td.Principal.RunLevel = 0
    $tr = $td.Triggers.Create(2)
    $tr.DaysInterval = 1
    $tr.StartBoundary = Get-AtmAutoPurgeTaskStart -Now $Now
    $tr.RandomDelay = $script:AtmAutoPurgeTaskRandomDelay
    $tr.Enabled = $true
    $s = $td.Settings
    $s.Enabled = $true
    $s.StartWhenAvailable = $true
    $s.DisallowStartIfOnBatteries = $false
    $s.StopIfGoingOnBatteries = $false
    $s.ExecutionTimeLimit = $script:AtmAutoPurgeTaskTimeLimit
    $s.MultipleInstances = 2
    $act = Get-AtmAutoPurgeTaskAction -EntryPoint $EntryPoint
    $a = $td.Actions.Create(0)
    $a.Path = $act.Path
    $a.Arguments = $act.Arguments
    return $td
}

function Register-AtmAutoPurgeTask {
    # The only registration (schedule-autopurge): the product's folder, created when missing, and the task of this user
    # with TASK_CREATE, so an existing task of the same name is never replaced (AUTOPURGE_TASK_EXISTS). The user is the
    # SID, the logon type interactive and the password none. Returns $null, or the code.
    param([string]$Sid, [string]$EntryPoint)
    try {
        $name = Get-AtmAutoPurgeTaskName -Sid $Sid
        $svc = Connect-AtmTaskScheduler
        $found = Get-AtmAutoPurgeTaskObject -Service $svc -Name $name
        if ($found.Code) { return $found.Code }
        if ($null -ne $found.Task) { return 'AUTOPURGE_TASK_EXISTS' }
        $folder = $found.Folder
        if ($null -eq $folder) {
            # Created by another process meanwhile (ERROR_ALREADY_EXISTS): that folder is used.
            try { $folder = $svc.GetFolder('\').CreateFolder($script:AtmAutoPurgeTaskFolder.TrimStart('\'), $null) } catch {
                if ([int](Get-AtmInnerException $_.Exception).HResult -ne -2147024713) { throw }
                $folder = $svc.GetFolder($script:AtmAutoPurgeTaskFolder)
            }
        }
        $td = New-AtmAutoPurgeTaskDefinition -Service $svc -Sid $Sid -EntryPoint $EntryPoint
        $null = $folder.RegisterTaskDefinition($name, $td, 2, $Sid, $null, 3, $null)
        return $null
    } catch {
        # Registered by another process meanwhile: TASK_CREATE refuses (ERROR_ALREADY_EXISTS or ERROR_FILE_EXISTS).
        if (@(-2147024713, -2147024816) -contains [int](Get-AtmInnerException $_.Exception).HResult) { return 'AUTOPURGE_TASK_EXISTS' }
        return (Get-AtmTaskSchedulerCode $_.Exception)
    }
}

function Unregister-AtmAutoPurgeTask {
    # The only removal (unschedule-autopurge): the task is read again just before and removed only when it is exactly the
    # product's task of this user (Test-AtmAutoPurgeTaskMatch); any divergence refuses with nothing touched
    # (AUTOPURGE_TASK_DIVERGENT). The folder stays. Returns $null, or the code.
    param([string]$Sid, [string]$EntryPoint)
    try {
        $name = Get-AtmAutoPurgeTaskName -Sid $Sid
        $found = Get-AtmAutoPurgeTaskObject -Service (Connect-AtmTaskScheduler) -Name $name
        if ($found.Code) { return $found.Code }
        if ($null -eq $found.Task) { return 'AUTOPURGE_TASK_ABSENT' }
        if (@(Test-AtmAutoPurgeTaskMatch -Task $found.Task -Sid $Sid -Name $name -EntryPoint $EntryPoint).Count -gt 0) { return 'AUTOPURGE_TASK_DIVERGENT' }
        $found.Folder.DeleteTask($name, 0)
        return $null
    } catch { return (Get-AtmTaskSchedulerCode $_.Exception) }
}

function Test-AtmAutoPurgeStandardToken {
    # schedule-autopurge runs only on a standard token: not an elevated administrator, not a full token, medium
    # integrity. Anything else, an unreadable token included, is refused: the task is always the user's own, never
    # elevated.
    $tok = $(if ($null -ne $script:AtmAutoPurgeElevationSource) { & $script:AtmAutoPurgeElevationSource } else { Get-AtmIdentityState })
    return ($tok.IsElevatedAdministrator -eq $false -and @('DEFAULT', 'LIMITED') -ccontains [string]$tok.ElevationType -and @('MEDIUM', 'MEDIUM_PLUS') -ccontains [string]$tok.IntegrityLevel)
}

function Invoke-AtmAutoPurgeSchedule {
    <#
      quarantine schedule-autopurge (J-ISO-7, complement of 2026-11-03). In order: a token that is not a standard one is
      refused (AUTOPURGE_TASK_REQUIRES_STANDARD_TOKEN), and so is a copy that is not installed
      (AUTOPURGE_TASK_NOT_INSTALLED); then the console, observed by the engine itself; a task that already exists, in any
      state, is refused and never replaced (AUTOPURGE_TASK_EXISTS). The plan is shown; with the policy not on, the
      warning that nothing happens until the administrator turns it on needs its own phrase; then the phrase AGENDAR
      EXPURGO AUTOMATICO. Only then the task is registered, and read back. Nothing is asked before the plan.
      Returns Operation, Aborted, Plan, Registered, Done and Task (the state read last).
    #>
    param([string]$ConfigDir, [switch]$Installed, [scriptblock]$PlanPresenter, [scriptblock]$ConfirmationReader)
    $st = [ordered]@{ Operation = 'schedule'; Aborted = $null; Plan = $null; Registered = $false; Done = $false; Task = $null }
    $end = { return [pscustomobject]$st }
    if (-not (Test-AtmAutoPurgeStandardToken)) { $st.Aborted = 'AUTOPURGE_TASK_REQUIRES_STANDARD_TOKEN'; return (& $end) }
    $ep = Get-AtmAutoPurgeEntryPoint
    if (-not $Installed -or -not [IO.File]::Exists($ep)) { $st.Aborted = 'AUTOPURGE_TASK_NOT_INSTALLED'; return (& $end) }
    if (-not $PlanPresenter -or -not $ConfirmationReader) { $st.Aborted = 'SEM_APRESENTACAO_OU_CONFIRMACAO'; return (& $end) }
    if (-not (Get-AtmEngineConsoleObservation).Observed) { $st.Aborted = 'CONSOLE_NOT_OBSERVED'; return (& $end) }
    $st.Task = Get-AtmAutoPurgeTaskState
    if ($st.Task.State -ceq 'UNREADABLE') { $st.Aborted = 'AUTOPURGE_TASK_UNREADABLE'; return (& $end) }
    if ($st.Task.State -cne 'ABSENT') { $st.Aborted = 'AUTOPURGE_TASK_EXISTS'; return (& $end) }
    $p = Get-AtmQuarantinePolicy -ConfigDir $ConfigDir
    $on = ($p.Source -ceq 'FILE' -and [bool]$p.AutoPurge)
    $act = Get-AtmAutoPurgeTaskAction -EntryPoint $ep
    $st.Plan = [pscustomobject]@{ TaskPath = $st.Task.TaskPath; Hour = $script:AtmAutoPurgeTaskHour; RandomDelay = $script:AtmAutoPurgeTaskRandomDelay; FirstRun = (Get-AtmAutoPurgeTaskStart)
        TimeLimit = $script:AtmAutoPurgeTaskTimeLimit; ActionPath = $act.Path; ActionArguments = $act.Arguments; PolicyOn = $on; Phrase = $script:AtmAutoPurgeSchedulePhrase
        OffPhrase = $(if ($on) { $null } else { $script:AtmAutoPurgeScheduleOffPhrase }) }
    & $PlanPresenter $st.Plan
    if (-not $on -and [string](& $ConfirmationReader $script:AtmAutoPurgeScheduleOffPhrase 'autopurge-off') -cne $script:AtmAutoPurgeScheduleOffPhrase) { $st.Aborted = 'AUTOPURGE_TASK_NOT_CONFIRMED'; return (& $end) }
    if ([string](& $ConfirmationReader $script:AtmAutoPurgeSchedulePhrase 'autopurge-schedule') -cne $script:AtmAutoPurgeSchedulePhrase) { $st.Aborted = 'AUTOPURGE_TASK_NOT_CONFIRMED'; return (& $end) }
    $code = Register-AtmAutoPurgeTask -Sid (Get-AtmCurrentIdentity).Sid -EntryPoint $ep
    if ($code) { $st.Aborted = $code; return (& $end) }
    $st.Registered = $true
    $st.Task = Get-AtmAutoPurgeTaskState
    if ($st.Task.State -cne 'PRESENT') { $st.Aborted = 'AUTOPURGE_TASK_NOT_VERIFIED' } else { $st.Done = $true }
    return (& $end)
}

function Invoke-AtmAutoPurgeUnschedule {
    <#
      quarantine unschedule-autopurge. The console, observed by the engine; then the task: absent
      (AUTOPURGE_TASK_ABSENT), unreadable, or divergent from the product's task of this user in any way
      (AUTOPURGE_TASK_DIVERGENT, with the reasons) is refused with nothing touched. The plan is shown, then the phrase
      DESAGENDAR EXPURGO AUTOMATICO; the task is checked again just before it is removed, and read back. The folder stays.
      Returns the shape of Invoke-AtmAutoPurgeSchedule.
    #>
    param([scriptblock]$PlanPresenter, [scriptblock]$ConfirmationReader)
    $st = [ordered]@{ Operation = 'unschedule'; Aborted = $null; Plan = $null; Registered = $false; Done = $false; Task = $null }
    $end = { return [pscustomobject]$st }
    if (-not $PlanPresenter -or -not $ConfirmationReader) { $st.Aborted = 'SEM_APRESENTACAO_OU_CONFIRMACAO'; return (& $end) }
    if (-not (Get-AtmEngineConsoleObservation).Observed) { $st.Aborted = 'CONSOLE_NOT_OBSERVED'; return (& $end) }
    $st.Task = Get-AtmAutoPurgeTaskState
    if ($st.Task.State -ceq 'ABSENT') { $st.Aborted = 'AUTOPURGE_TASK_ABSENT'; return (& $end) }
    if ($st.Task.State -ceq 'UNREADABLE') { $st.Aborted = 'AUTOPURGE_TASK_UNREADABLE'; return (& $end) }
    if ($st.Task.State -cne 'PRESENT') { $st.Aborted = 'AUTOPURGE_TASK_DIVERGENT'; return (& $end) }
    $ep = Get-AtmAutoPurgeEntryPoint
    $act = Get-AtmAutoPurgeTaskAction -EntryPoint $ep
    $st.Plan = [pscustomobject]@{ TaskPath = $st.Task.TaskPath; ActionPath = $act.Path; ActionArguments = $act.Arguments; Phrase = $script:AtmAutoPurgeUnschedulePhrase }
    & $PlanPresenter $st.Plan
    if ([string](& $ConfirmationReader $script:AtmAutoPurgeUnschedulePhrase 'autopurge-unschedule') -cne $script:AtmAutoPurgeUnschedulePhrase) { $st.Aborted = 'AUTOPURGE_TASK_NOT_CONFIRMED'; return (& $end) }
    $code = Unregister-AtmAutoPurgeTask -Sid (Get-AtmCurrentIdentity).Sid -EntryPoint $ep
    $st.Task = Get-AtmAutoPurgeTaskState
    if ($code) { $st.Aborted = $code; return (& $end) }
    if ($st.Task.State -cne 'ABSENT') { $st.Aborted = 'AUTOPURGE_TASK_NOT_VERIFIED' } else { $st.Done = $true }
    return (& $end)
}
