# AgentTempManager CLEAN ENGINE (fail-closed). Depends on Engine.Audit.ps1. No terminal output of its own:
# the plan is shown through a mandatory presenter callback and confirmation is read through a mandatory reader.
Set-StrictMode -Version 2.0

# RELEASE GATE (V0.1): real deletion is DISABLED. Invoke-AtmClean runs every gate and presents the exact plan,
# then stops without asking for confirmation. There is deliberately no switch, environment variable, config
# file or UI option to change this: enabling deletion requires a code change in this administrator-owned,
# manifest-verified file, released under a specific authorization. Only the automated test suite flips it,
# inside its own isolated sandbox.
$script:AtmRealDeletionEnabled = $false

# ---------------------------------------------------------------------------------------------
# Preview / clean gates
# ---------------------------------------------------------------------------------------------

function Test-AtmAllowListPathSyntax {
    # Returns $null when acceptable, otherwise a rejection code.
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return 'EMPTY' }
    if ($Path -ne $Path.Trim()) { return 'LEADING_OR_TRAILING_WHITESPACE' }
    if ($Path -match '[\x00-\x1f]') { return 'CONTROL_CHARS' }
    if ($Path -notmatch '^[A-Za-z]:\\') { return 'NOT_ABSOLUTE_LOCAL_PATH' }
    if ($Path.IndexOfAny([char[]]'*?"<>|') -ge 0) { return 'WILDCARD_OR_INVALID_CHARS' }
    if ($Path.Substring(2).Contains(':')) { return 'ALTERNATE_DATA_STREAM' }
    $body = $Path.Substring(3)
    if ($body.EndsWith('\')) { return 'TRAILING_SEPARATOR' }
    foreach ($seg in $body.Split('\')) {
        if ($seg -eq '') { return 'EMPTY_SEGMENT' }
        if ($seg -eq '.' -or $seg -eq '..') { return 'PATH_TRAVERSAL' }
        if ($seg.EndsWith('.') -or $seg.EndsWith(' ')) { return 'TRAILING_DOT_OR_SPACE' }
        if ($seg.Contains('~')) { return 'SHORT_NAME_NOT_ALLOWED' }
    }
    try { $full = [IO.Path]::GetFullPath($Path) } catch { return 'INVALID_PATH' }
    if (-not [string]::Equals($full, $Path, [StringComparison]::Ordinal)) { return 'NON_CANONICAL' }
    return $null
}

function Read-AtmAllowList {
    param([string]$File, [string[]]$Paths)
    $entries = New-Object System.Collections.Generic.List[object]
    if ($File) {
        $lines = [IO.File]::ReadAllLines($File, [Text.Encoding]::UTF8)
        $ln = 0
        foreach ($l in $lines) {
            $ln++
            $t = $l.TrimEnd("`r")
            if ($t.Trim() -eq '' -or $t.TrimStart().StartsWith('#')) { continue }
            $fp = $null; $pathPart = $t
            $bar = $t.IndexOf('|')
            if ($bar -ge 0) { $pathPart = $t.Substring(0, $bar); $fp = $t.Substring($bar + 1).Trim() }
            $entries.Add([pscustomobject]@{ Source = (Get-AtmText 'clean.line' $ln); Path = $pathPart; Fingerprint = $fp })
        }
    }
    foreach ($p in $Paths) { if ($p) { $entries.Add([pscustomobject]@{ Source = '-Path'; Path = $p; Fingerprint = $null }) } }
    return $entries.ToArray()
}

# Principals allowed to hold write-type rights on a session root and its scope/base besides the profile owner:
# SYSTEM, Administrators, TrustedInstaller, CREATOR OWNER, OWNER RIGHTS.
$script:AtmTrustedWriterSids = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464', 'S-1-3-0', 'S-1-3-4')

function Get-AtmAclProblems {
    # The directory must be owned by the profile SID and must not let any other non-administrative principal
    # write, delete or re-permission it (otherwise another account could stage content or swap entries).
    param([string]$Path, [string]$OwnerSid)
    $problems = New-Object System.Collections.Generic.List[string]
    try { $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop } catch { $problems.Add("ACL_ILEGIVEL: $Path"); return $problems.ToArray() }
    $owner = $null
    # Unreadable owner: reported as OWNER_ILEGIVEL below, which blocks.
    try { $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value } catch { $owner = $null }
    if (-not $owner) { $problems.Add("OWNER_ILEGIVEL: $Path") }
    elseif ($owner -ne $OwnerSid) { $problems.Add((Get-AtmText 'reason.ownerMismatch' $owner $Path)) }
    $writeMask = [Security.AccessControl.FileSystemRights]'WriteData, AppendData, WriteExtendedAttributes, WriteAttributes, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
    foreach ($ace in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        $sid = $ace.IdentityReference.Value
        if ($sid -eq $OwnerSid -or $script:AtmTrustedWriterSids -contains $sid) { continue }
        if (($ace.FileSystemRights -band $writeMask) -ne 0) { $problems.Add((Get-AtmText 'reason.thirdPartyWrite' $sid $Path)) }
    }
    return $problems.ToArray()
}

# B2-1: runtime evidence of the V0.2 collectors (Get-AtmRuntimeRefusals, Engine.Diagnose.ps1) as additional refusals.
# Test seam, single assignment: the suite replaces the service and virtualization sources (and may set a deadline) inside
# its own process so that no test depends on the runner's services or Hyper-V; the CLI and the TUI never set it.
$script:AtmRuntimeEvidenceSources = $null

function Get-AtmCleanRuntimeEvidence {
    # One run of the runtime collectors over an inventory already taken (the preview's, the plan's or one root's
    # revalidation inventory). Never reused for another inventory: a revalidation takes its own.
    param($Inventory, [hashtable]$InventoryArgs = @{})
    $a = @{ Inventory = $Inventory; InventoryArgs = $InventoryArgs }
    if ($null -ne $script:AtmRuntimeEvidenceSources) {
        foreach ($k in @('ServiceSource', 'VirtualizationSource', 'ProcessSource', 'DeadlineSeconds', 'Providers')) { if ($script:AtmRuntimeEvidenceSources.ContainsKey($k)) { $a[$k] = $script:AtmRuntimeEvidenceSources[$k] } }
    }
    return (Get-AtmRuntimeRefusals @a)
}

function Format-AtmRuntimeRefusal {
    # Text of one runtime refusal: its code, what it means, and where it comes from (never "unused" or "safe").
    param($Refusal)
    # Invariant culture: in a custom format ':' is the culture's time separator, so the text would vary by culture.
    $when = $(if ($null -ne $Refusal.ObservedUtc) { ([datetime]$Refusal.ObservedUtc).ToString('yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) + 'Z' } else { '-' })
    $detail = $(if ($Refusal.Detail) { ' - ' + $Refusal.Detail } else { '' })
    return (Get-AtmText 'runtime.reason' $Refusal.Code (Get-AtmText ('runtime.code.' + $Refusal.Code)) $(if ($Refusal.Collector) { $Refusal.Collector } else { '-' }) $(if ($Refusal.Relation) { $Refusal.Relation } else { '-' }) (Get-AtmText ('runtime.nature.' + $Refusal.Nature)) $(if ($Refusal.Coverage) { $Refusal.Coverage } else { '-' }) $when $detail)
}

function Test-AtmCandidate {
    <#
      Gates applied (in order) to one inventoried partition. Returns Category:
        BLOCKED | INVESTIGATE | ELIGIBLE, plus Reasons, Requirements and RuntimeReasons.
      ELIGIBLE means "technically eligible for a human decision"; clean re-runs this immediately before deleting.
      -RuntimeEvidence (B2-1, Get-AtmCleanRuntimeEvidence): after every gate below, its refusals for this partition are
      added: the category can only stay or become stricter (BLOCKED > INVESTIGATE > ELIGIBLE), the reasons already
      found stay first and in order, and the class of the partition is never changed. No refusal is not evidence of
      non-use. Preview and clean always pass it; without it (direct calls) only the gates below apply.
    #>
    [CmdletBinding()]
    param($Partition, $Inventory, [switch]$IncludeOtherUsers, [switch]$SkipLockProbe, [switch]$ForClean, $RuntimeEvidence = $null)
    $g = Get-AtmCandidateGate -Partition $Partition -Inventory $Inventory -IncludeOtherUsers:$IncludeOtherUsers -SkipLockProbe:$SkipLockProbe -ForClean:$ForClean
    $refs = @()
    if ($null -ne $RuntimeEvidence) {
        $k = ([string]$Partition.Path).ToLowerInvariant()
        if ($RuntimeEvidence.Failed) { $refs = @(New-AtmRuntimeRefusal -Code 'RUNTIME_NOT_COLLECTED' -Decision 'INVESTIGATE' -Collector 'runtime' -Evidence ([string]$RuntimeEvidence.Failed) -Relation 'COVERAGE' -Nature 'COVERAGE' -ObservedUtc $RuntimeEvidence.StartedUtc -Coverage 'FAILED') }
        elseif ($RuntimeEvidence.ByPath.ContainsKey($k)) { $refs = @($RuntimeEvidence.ByPath[$k]) }
        else { $refs = @(New-AtmRuntimeRefusal -Code 'RUNTIME_NOT_COLLECTED' -Decision 'INVESTIGATE' -Collector 'runtime' -Evidence 'PARTITION_NOT_IN_RUN' -Relation 'COVERAGE' -Nature 'COVERAGE' -ObservedUtc $RuntimeEvidence.StartedUtc -Coverage 'NOT_OBSERVABLE') }
    }
    $rank = @{ 'ELIGIBLE' = 0; 'INVESTIGATE' = 1; 'BLOCKED' = 2 }
    $cat = $g.Category
    foreach ($r in $refs) { if ($rank[$r.Decision] -gt $rank[$cat]) { $cat = $r.Decision } }
    return [pscustomobject]@{ Category = $cat; Reasons = @(@($g.Reasons) + @($refs | ForEach-Object { Format-AtmRuntimeRefusal $_ })); Requirements = $g.Requirements; Probe = $g.Probe; RuntimeReasons = $refs
        ProcessCoverageGate = $g.ProcessCoverageGate }
}

function Get-AtmCandidateGate {
    # The V0.1 gates of Test-AtmCandidate (unchanged), in order.
    [CmdletBinding()]
    param($Partition, $Inventory, [switch]$IncludeOtherUsers, [switch]$SkipLockProbe, [switch]$ForClean)
    $p = $Partition
    $reasons = New-Object System.Collections.Generic.List[string]
    $reqs = New-Object System.Collections.Generic.List[string]
    $probe = $null
    $id = $Inventory.Identity

    # ProcessCoverageGate: what happened to the B1 gate in THIS evaluation (data only; no gate changes): NOT_EVALUATED
    # when an earlier gate returned first, otherwise BLOCKED or PASSED.
    if ($p.Class -in @('ACTIVE_EVIDENCE', 'RECENT')) { $reasons.Add((Get-AtmText 'reason.class' $p.Class)) }
    foreach ($f in $p.Flags) { if ($script:AtmHardFlags -contains $f) { $reasons.Add($f) } }
    if ($reasons.Count -gt 0) { return [pscustomobject]@{ Category = 'BLOCKED'; Reasons = $reasons.ToArray(); Requirements = @(); Probe = $null; ProcessCoverageGate = 'NOT_EVALUATED' } }

    $soft = @($p.Flags | Where-Object { $script:AtmSoftFlags -contains $_ })
    if ($soft.Count -gt 0 -or $p.Class -ne 'ORPHAN_SUSPECTED') {
        foreach ($s in $soft) { $reasons.Add($s) }
        if ($p.Class -ne 'ORPHAN_SUSPECTED') { $reasons.Add((Get-AtmText 'reason.class' $p.Class)) }
        return [pscustomobject]@{ Category = 'INVESTIGATE'; Reasons = $reasons.ToArray(); Requirements = @(); Probe = $null; ProcessCoverageGate = 'NOT_EVALUATED' }
    }

    # Ownership / authorization
    if ($p.Sid -ne $id.Sid) {
        if (-not $id.IsAdmin) { $reasons.Add('OUTRO_USUARIO_EXIGE_ADMINISTRADOR_ELEVADO') }
        elseif (-not $IncludeOtherUsers) {
            if ($ForClean) { $reasons.Add('OUTRO_USUARIO_EXIGE_-IncludeOtherUsers') } else { $reqs.Add((Get-AtmText 'req.includeOthers')) }
        }
    }
    # Ownership and ACL of the root, its scope directory and the base (not only the root).
    foreach ($dir in @($p.Path, [IO.Path]::GetDirectoryName($p.Path), $p.BasePath)) {
        foreach ($pb in (Get-AtmAclProblems -Path $dir -OwnerSid $p.Sid)) { $reasons.Add($pb) }
    }

    # Path structure: root -> slug -> base -> temp, no reparse anywhere in the chain
    $chain = Test-AtmPathChain $p.Path
    if ($chain.Status -ne 'OK') { $reasons.Add((Get-AtmText 'reason.chain' $chain.Status $chain.At)) }
    $parent = [IO.Path]::GetDirectoryName($p.Path)
    $grand = [IO.Path]::GetDirectoryName($parent)
    if (-not [string]::Equals($grand, $p.BasePath, [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals([IO.Path]::GetFileName($parent), $p.Slug, [StringComparison]::OrdinalIgnoreCase)) { $reasons.Add('ESTRUTURA_PAI_INVALIDA') }
    $forbidden = @($p.ProfilePath, $p.TempPath, $p.BasePath, $parent, $p.Path.Substring(0, 3))
    foreach ($fb in $forbidden) { if ($fb -and [string]::Equals($fb.TrimEnd('\'), $p.Path, [StringComparison]::OrdinalIgnoreCase)) { $reasons.Add('CAMINHO_E_RAIZ_PROTEGIDA') } }

    # Incomplete process coverage is a HARD block, for everyone, with no override: a process we cannot inspect
    # (another account's service or automation, an elevated session, a protected process) could be using the path.
    if (-not $Inventory.ProcessCoverageComplete) {
        if ($Inventory.Snapshot.Failed) { $reasons.Add('COBERTURA_DE_PROCESSOS_INCOMPLETA (' + (Get-AtmText 'reason.coverageFailed') + ')') }
        elseif (-not $id.IsAdmin) { $reasons.Add('COBERTURA_DE_PROCESSOS_INCOMPLETA (' + (Get-AtmText 'reason.coverageNonAdmin' $Inventory.Snapshot.Uninspectable) + ')') }
        else { $reasons.Add('COBERTURA_DE_PROCESSOS_INCOMPLETA (' + (Get-AtmText 'reason.coverageAdmin' $Inventory.Snapshot.Uninspectable) + ')') }
    }

    if ($reasons.Count -eq 0 -and -not $SkipLockProbe) {
        $probe = [AgentTempManager.AtmLockProbe]::ProbeTree($p.Path, $script:AtmMaxSamples)
        if (-not $probe.Ok) {
            if ($probe.InUse -gt 0) { $reasons.Add('EM_USO: ' + (Get-AtmText 'reason.inUse' $probe.InUse)) }
            if ($probe.Denied -gt 0) { $reasons.Add('ACESSO_NEGADO_PARA_EXCLUSAO: ' + (Get-AtmText 'reason.items' $probe.Denied)) }
            if ($probe.ReparsePoints -gt 0) { $reasons.Add('REPARSE_POINT_NA_SONDAGEM') }
            if ($probe.Errors -gt 0 -or -not $probe.Complete) { $reasons.Add('SONDAGEM_INCOMPLETA') }
        }
    }
    $cat = $(if ($reasons.Count -gt 0) { 'BLOCKED' } else { 'ELIGIBLE' })
    # Reached here: the B1 gate above was evaluated; its result is the condition it tested.
    return [pscustomobject]@{ Category = $cat; Reasons = $reasons.ToArray(); Requirements = $reqs.ToArray(); Probe = $probe; ProcessCoverageGate = $(if (-not $Inventory.ProcessCoverageComplete) { 'BLOCKED' } else { 'PASSED' }) }
}

function Invoke-AtmPreview {
    # B2-1: one runtime collection for the whole preview (never one per partition); each row carries it (Runtime) so the
    # report can show, once, what was not observed for any partition. -InventoryArgs: the arguments of -Inventory.
    param($Inventory, [switch]$IncludeOtherUsers, [hashtable]$InventoryArgs = @{})
    $rt = Get-AtmCleanRuntimeEvidence -Inventory $Inventory -InventoryArgs $InventoryArgs
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($p in $Inventory.Partitions) {
        if ($p.Kind -eq 'NotScanned') { continue }
        $g = Test-AtmCandidate -Partition $p -Inventory $Inventory -IncludeOtherUsers:$IncludeOtherUsers -RuntimeEvidence $rt
        $rows.Add([pscustomobject]@{ Partition = $p; Gate = $g; Runtime = $rt })
    }
    return $rows.ToArray()
}

# T1 (F-04): the clean log. A NEW file per run (never an existing name, never appended to), created relative to the
# pinned folder and written only through the handle kept for the run (AtmCleanLog in Native.cs): JSON Lines, UTF-8
# without BOM, one record per line, each one flushed before the next step. Required whenever real deletion is enabled;
# with the release gate closed (every shipped copy) it is neither required, created nor opened. One record per root:
# the log never lists the files of a tree, and nothing can be undone from it.
$script:AtmCleanLogSchema = 'atm.cleanlog/1'

function Open-AtmCleanLog {
    <#
      Pins the folder of -Path (folder policy of AtmCleanLog.Pin), applies the audited-directories rule inside the pinned
      window and creates the file. Returns Log (open) or Code, and Created: a file was created and may remain after a
      refusal; it is never removed.
    #>
    param([string]$Path, $Inventory, [string]$ProcessUserSid)
    $out = [ordered]@{ Log = $null; Code = $null; Created = $false }
    if (Test-AtmAllowListPathSyntax $Path) { $out.Code = 'LOG_DESTINATION_NOT_ALLOWED'; return [pscustomobject]$out }
    $log = [AgentTempManager.AtmCleanLog]::Pin([IO.Path]::GetDirectoryName($Path), $ProcessUserSid)
    $keep = $false
    try {
        if ($null -ne $log.Error) { $out.Code = 'LOG_PIN_' + $log.Error; return [pscustomobject]$out }
        if (-not (Test-AtmOutputPathOutsideBases -Path $Path -Inventory $Inventory)) { $out.Code = 'LOG_DESTINATION_NOT_ALLOWED'; return [pscustomobject]$out }
        $code = $log.Create([IO.Path]::GetFileName($Path))
        $out.Created = [bool]$log.Created
        if ($null -ne $code) { $out.Code = 'LOG_CREATE_' + $code; return [pscustomobject]$out }
        $out.Log = $log
        $keep = $true
        return [pscustomobject]$out
    } finally { if (-not $keep) { $log.Dispose() } }
}

function Write-AtmCleanLogRecord {
    # One record: one JSON line, written and flushed by -Log. Returns $null, or the code of the failure.
    param($Log, [hashtable]$State, [string]$Type, [System.Collections.IDictionary]$Fields = @{})
    $State.RecSeq++
    $rec = [ordered]@{ schema = $script:AtmCleanLogSchema; type = $Type; runId = $State.RunId; recSeq = $State.RecSeq; utc = [datetime]::UtcNow.ToString('o') }
    foreach ($k in $Fields.Keys) { $rec[$k] = $Fields[$k] }
    $line = $null
    try { $line = ConvertTo-Json -InputObject $rec -Compress -Depth 5 } catch { return 'LOG_RECORD_INVALID' }
    try { return $Log.AppendLine($line) } catch { return ('LOG_WRITE_' + $_.Exception.GetBaseException().GetType().Name) }
}

# B8: machine-wide mutual exclusion of clean runs past the release gate (AtmCleanLock in Native.cs). Fixed name, never
# changed between versions (copies of different versions stay mutually exclusive). Only the test suite replaces it, with
# a Global\AgentTempManager.Test.<hex> name inside its own process; the CLI and the TUI never do.
$script:AtmCleanLockName = 'Global\AgentTempManager.Clean'

# AUT-2: past the release gate a clean run needs an interactive console observed by the engine itself
# (Test-AtmDiscardConsoleObserved). Test seam, single assignment: the suite, which has no console, replaces the
# observation inside its own process; the CLI and the TUI never set it. It is read only past the release gate.
$script:AtmCleanConsoleSource = $null

function Invoke-AtmClean {
    <#
      Entry point of clean (CLI and TUI). With the release gate closed (every distributed copy) it runs the plan-only flow
      of Invoke-AtmCleanCore unchanged and never touches the lock. Past the gate it first takes the clean lock without
      waiting, before any inventory, and holds it through the plan, the confirmation and the deletions; it is released
      last, after the log is closed. A refusal (CLEAN_LOCK_BUSY, _DENIED, _TYPE_MISMATCH, _POLICY_*, _NESTED,
      _NAME_INVALID, _ERROR_*) starts nothing: no inventory, plan or log. CLEAN_LOCK_ABANDONED: the previous holder ended
      without releasing it (a run may have been interrupted); the ownership received is released and this run stops
      before any inventory; a new attempt starts from scratch. A failed release never replaces the main code; with none it
      makes the run incomplete (LOCK_RELEASE_FAILED). Parameters: as Invoke-AtmCleanCore.
    #>
    [CmdletBinding()]
    param(
        [object[]]$Entries,
        [switch]$IncludeOtherUsers,
        [scriptblock]$PlanPresenter,
        [scriptblock]$ConfirmationReader,
        [hashtable]$InventoryArgs = @{},
        [scriptblock]$BeforeDeleteHook,
        [string]$LogFile,
        [scriptblock]$DeleteTreeImpl,
        [scriptblock]$PathPresenceImpl,
        $LogWriter,
        [hashtable]$Interaction = @{}
    )
    if (-not $script:AtmRealDeletionEnabled) { return (Invoke-AtmCleanCore @PSBoundParameters) }
    $lock = [AgentTempManager.AtmCleanLock]::TryAcquire($script:AtmCleanLockName)
    if (-not $lock.Acquired) { return (Invoke-AtmCleanCore @PSBoundParameters -RefusedBy ('CLEAN_LOCK_' + $lock.Status) -LockReleaseError $lock.ReleaseError) }
    $res = $null
    try {
        $res = Invoke-AtmCleanCore @PSBoundParameters
        return $res
    } finally {
        # The same object the caller receives: a release failure is added to it, never replacing the main code.
        $rc = $lock.Release()
        if ($null -ne $rc -and $null -ne $res) {
            $res.LockReleaseError = $rc
            if (-not $res.Aborted -and -not $res.StoppedBy) { if (@($res.Deleted).Count -gt 0) { $res.StoppedBy = 'LOCK_RELEASE_FAILED' } else { $res.Aborted = 'LOCK_RELEASE_FAILED' } }
        }
    }
}

function Invoke-AtmCleanCore {
    <#
      Fail-closed assisted deletion, called only by Invoke-AtmClean (which owns the B8 lock). The engine owns every safety
      decision; callers only provide:
        -PlanPresenter      scriptblock(verified, rejected, inventory) that MUST display the exact plan
                            (including "NADA FOI APAGADO AINDA"). Without it nothing proceeds.
        -ConfirmationReader scriptblock(phrase, kind, path, choices) returning the text typed by the operator. Every
                            phrase is generated here; anything but an exact ordinal match aborts. Past the release
                            gate (AUT-2) it is asked, for each root of the executable set (path shown): kind 'task'
                            (the task finished) and kind 'results' (choices: results preserved, or nothing needed,
                            with the AUT-1 meanings); then once kind 'confirm' for the whole set, a phrase bound to
                            the plan id and the exact number of roots. With the gate closed it is never called.
        -Interaction        what the caller reports: Caller ('CLI', 'TUI'; anything else is a direct call) and
                            ConsoleRequired. Recorded as reported; the console itself is observed by the engine.
        -LogFile            T1: a NEW file outside the audited directories. Required once real deletion is enabled
                            (LOG_REQUIRED otherwise); with the release gate closed it is neither required, created nor
                            opened, and the plan-only flow is unchanged.
      -InventoryArgs is splatted into every Invoke-AtmInventory call (tests / CLI self markers).
      -DeleteTreeImpl, -PathPresenceImpl and -LogWriter are test seams, never passed by the CLI: a stand-in deleter (it
      deletes nothing), a stand-in presence check and an object with AppendLine/Close/Dispose. They are reached only past
      the release gate, so they cannot make a run with the gate closed delete or log anything.
      Aborted: the run ended before any call to the deleter. StoppedBy: it ended after at least one call; anything but a
      complete, verified deletion (a refusal, a partial deletion, an exception, a verification that is not conclusive),
      a log failure or (AUT-2) a revalidation refusal after the confirmation (REVALIDATION_REFUSED) stops the run before
      the next root; nothing is undone. StoppedAtOpId names the root that stopped it; NotAttempted lists the later roots,
      never revalidated nor processed. LogErrors lists every log failure (Stage, OpId, Code) without
      replacing the main code. -RefusedBy and -LockReleaseError (from Invoke-AtmClean only): the lock was not acquired;
      the result is returned at once with that code, before anything else.
      Returns arrays only (no live collections).
    #>
    [CmdletBinding()]
    param(
        [object[]]$Entries,
        [switch]$IncludeOtherUsers,
        [scriptblock]$PlanPresenter,
        [scriptblock]$ConfirmationReader,
        [hashtable]$InventoryArgs = @{},
        [scriptblock]$BeforeDeleteHook,
        [string]$LogFile,
        [scriptblock]$DeleteTreeImpl,
        [scriptblock]$PathPresenceImpl,
        $LogWriter,
        [hashtable]$Interaction = @{},
        [string]$RefusedBy,
        [string]$LockReleaseError
    )
    $rejected = New-Object System.Collections.Generic.List[object]
    $verified = New-Object System.Collections.Generic.List[object]
    $deleted = New-Object System.Collections.Generic.List[object]
    $skipped = New-Object System.Collections.Generic.List[object]
    $logErrors = New-Object System.Collections.Generic.List[object]
    $declarations = New-Object System.Collections.Generic.List[object]
    $notAttempted = New-Object System.Collections.Generic.List[object]
    $state = @{ Confirmed = $false; Aborted = $null; Stopped = $null; Post = $null; Phrase = $null; RunId = $null; RecSeq = 0; LogCreated = $false; PlanId = $null; RefusedAt = $null; StopOpId = $null }
    $finish = {
        [pscustomobject]@{
            Requested = @($Entries).Count; Rejected = $rejected.ToArray(); Verified = $verified.ToArray(); Phrase = $state.Phrase; PlanId = $state.PlanId
            Declarations = $declarations.ToArray(); RefusedAt = $state.RefusedAt; StoppedAtOpId = $state.StopOpId; NotAttempted = $notAttempted.ToArray()
            Confirmed = $state.Confirmed; Deleted = $deleted.ToArray(); Skipped = $skipped.ToArray(); PostInventory = $state.Post; Aborted = $state.Aborted
            StoppedBy = $state.Stopped; RunId = $state.RunId; LogFile = $(if ($state.RunId) { $LogFile } else { $null }); LogCreated = $state.LogCreated
            LogErrors = $logErrors.ToArray(); LockReleaseError = $(if ($LockReleaseError) { $LockReleaseError } else { $null })
        }
    }
    if ($RefusedBy) { $state.Aborted = $RefusedBy; return (& $finish) }
    if (@($Entries).Count -eq 0) { $state.Aborted = 'ALLOWLIST_VAZIA'; return (& $finish) }
    if (-not $PlanPresenter -or -not $ConfirmationReader) { $state.Aborted = 'SEM_APRESENTACAO_OU_CONFIRMACAO'; return (& $finish) }

    # 1-14: syntactic gates, then a full fresh inventory with activity checks.
    $syntaxOk = New-Object System.Collections.Generic.List[object]
    foreach ($e in $Entries) {
        $why = Test-AtmAllowListPathSyntax $e.Path
        if ($why) { $rejected.Add([pscustomobject]@{ Path = $e.Path; Source = $e.Source; Reasons = @($why) }) } else { $syntaxOk.Add($e) }
    }
    $seen = @{}
    $ia = @{} + $InventoryArgs
    $inv = Invoke-AtmInventory @ia
    # B2-1: one runtime collection for the plan, attached to the inventory the presenter receives (run notices).
    $rt = Get-AtmCleanRuntimeEvidence -Inventory $inv -InventoryArgs $ia
    $inv | Add-Member -NotePropertyName RuntimeEvidence -NotePropertyValue $rt
    foreach ($e in $syntaxOk) {
        $k = $e.Path.ToLowerInvariant()
        if ($seen.ContainsKey($k)) { $rejected.Add([pscustomobject]@{ Path = $e.Path; Source = $e.Source; Reasons = @('DUPLICADO_NA_ALLOWLIST') }); continue }
        $seen[$k] = $true
        $m = @($inv.Partitions | Where-Object { [string]::Equals($_.Path, $e.Path, [StringComparison]::OrdinalIgnoreCase) -and $_.Kind -ne 'BaseLooseFiles' })
        if ($m.Count -ne 1) { $rejected.Add([pscustomobject]@{ Path = $e.Path; Source = $e.Source; Reasons = @('FORA_DAS_ROOTS_PERMITIDAS (' + (Get-AtmText 'reason.notRoot') + ')') }); continue }
        $p = $m[0]
        if (-not [string]::Equals($p.Path, $e.Path, [StringComparison]::Ordinal)) { $rejected.Add([pscustomobject]@{ Path = $e.Path; Source = $e.Source; Reasons = @('CAIXA_DIVERGENTE (' + (Get-AtmText 'reason.useExactly' $p.Path) + ')') }); continue }
        $g = Test-AtmCandidate -Partition $p -Inventory $inv -IncludeOtherUsers:$IncludeOtherUsers -ForClean -RuntimeEvidence $rt
        $reasons = @($g.Reasons)
        if ($e.Fingerprint -and $e.Fingerprint -ne $p.Fingerprint) { $reasons += "ALTERADO_DESDE_O_PREVIEW (fingerprint $($e.Fingerprint) -> $($p.Fingerprint))" }
        if ($g.Category -ne 'ELIGIBLE' -or $reasons.Count -gt 0) { $rejected.Add([pscustomobject]@{ Path = $e.Path; Source = $e.Source; Reasons = $reasons }); continue }
        $verified.Add($p)
    }
    if ($verified.Count -eq 0) { $state.Aborted = 'NENHUM_CAMINHO_ELEGIVEL'; return (& $finish) }

    # 15-17: exact plan + "NADA FOI APAGADO AINDA" (presenter) + typed confirmation (reader).
    $state.Phrase = "APAGAR $($verified.Count) CAMINHOS"
    & $PlanPresenter $verified.ToArray() $rejected.ToArray() $inv
    if (-not $script:AtmRealDeletionEnabled) {
        # V0.1 release gate: plan only. The confirmation reader is never invoked.
        $state.Aborted = 'EXCLUSAO_REAL_DESABILITADA_V0_1'
        return (& $finish)
    }
    # T1: past the release gate every run is logged in a new file, created and started before the confirmation, so the
    # operator never confirms a run that cannot be recorded.
    if (-not $LogFile -and $null -eq $LogWriter) { $state.Aborted = 'LOG_REQUIRED'; return (& $finish) }
    # AUT-2: an interactive console observed by the engine in this run (never proof that a person answers).
    $consoleBy = $(if ($null -ne $script:AtmCleanConsoleSource) { 'TEST_SEAM' } else { 'ENGINE_CONSOLE_CHECK' })
    $consoleObserved = $(if ($null -ne $script:AtmCleanConsoleSource) { [bool](& $script:AtmCleanConsoleSource) } else { [bool](Test-AtmDiscardConsoleObserved) })
    if (-not $consoleObserved) { $state.Aborted = 'CONSOLE_NOT_OBSERVED'; return (& $finish) }
    $callerName = [string]$Interaction['Caller']
    $interactionRec = [ordered]@{ caller = $(if ($callerName -ceq 'CLI' -or $callerName -ceq 'TUI') { $callerName } else { 'DIRECT_CALL' }); consoleRequiredByCaller = ($Interaction['ConsoleRequired'] -eq $true)
        callerFieldsVerified = $false; interactiveConsoleObserved = $true; observedBy = $consoleBy; identifiesRespondent = $false }
    $state.RunId = [guid]::NewGuid().ToString()
    # The first failure of a run: before any call to the deleter it is an abort, after one it is a stop.
    $halt = { param([string]$Code) if ($deleted.Count -gt 0) { $state.Stopped = $Code } else { $state.Aborted = $Code } }
    $logFail = { param([string]$Stage, [string]$OpId, [string]$Code) $logErrors.Add([pscustomobject]@{ Stage = $Stage; OpId = $OpId; Code = $Code }) }
    $log = $LogWriter
    try {
        if ($null -eq $log) {
            $opened = Open-AtmCleanLog -Path $LogFile -Inventory $inv -ProcessUserSid (Get-AtmCurrentIdentity).Sid
            $state.LogCreated = [bool]$opened.Created
            if ($null -eq $opened.Log) { & $logFail 'open' $null $opened.Code; $state.Aborted = 'LOG_OPEN_FAILED'; return (& $finish) }
            $log = $opened.Log
        }
        $plan = New-Object System.Collections.Generic.List[object]
        foreach ($p in $verified) { $plan.Add([pscustomobject]@{ OpId = ('{0}:{1}' -f $state.RunId, ($plan.Count + 1)); Part = $p }) }
        # AUT-2: the plan id identifies the exact executable set presented (paths and their statistics); the final phrase
        # carries it and the exact number of roots.
        $state.PlanId = Get-AtmCleanPlanId -RunId $state.RunId -Parts @($plan | ForEach-Object { $_.Part })
        $state.Phrase = "APAGAR $($plan.Count) CAMINHOS $($state.PlanId.Substring(0, 8).ToUpperInvariant())"
        $lc = Write-AtmCleanLogRecord -Log $log -State $state -Type 'run-start' -Fields ([ordered]@{ tool = $script:AtmVersion; user = $inv.Identity.Name; sid = $inv.Identity.Sid; elevated = [bool]$inv.Identity.IsAdmin; planned = $plan.Count; planId = $state.PlanId })
        $stage = 'run-start'
        if ($null -eq $lc) {
            $stage = 'plan'
            foreach ($item in $plan) {
                $p = $item.Part
                $lc = Write-AtmCleanLogRecord -Log $log -State $state -Type 'plan' -Fields ([ordered]@{ opId = $item.OpId; path = $p.Path; fingerprint = $p.Fingerprint; files = $p.Files; dirs = $p.Dirs; bytes = $p.Bytes
                        newestWriteUtc = $(if ($p.NewestWriteTimeUtc) { ([datetime]$p.NewestWriteTimeUtc).ToUniversalTime().ToString('o') } else { $null }) })
                if ($null -ne $lc) { break }
            }
        }
        if ($null -ne $lc) { & $logFail $stage $null $lc; $state.Aborted = 'LOG_WRITE_FAILED'; return (& $finish) }

        # AUT-2: for each root of the executable set (path shown), the task and the content decision (AUT-1 meanings);
        # then one confirmation for the whole set. Any refusal, cancellation or wrong phrase aborts the run before any
        # deletion. Declarations never replace the revalidation below.
        $refusal = $null
        $taskPhrase = Get-AtmText 'auth.phrase.task'
        $decisionMap = Get-AtmContentDecisions
        $choices = @($decisionMap.Keys)
        foreach ($item in $plan) {
            $p = $item.Part
            $t = Test-AtmTypedPhrase -Typed (& $ConfirmationReader $taskPhrase 'task' $p.Path @($taskPhrase)) -Phrases @($taskPhrase)
            if ($t.Code) { $refusal = [pscustomobject]@{ Code = 'DECLARATION_' + $t.Code; Step = 'task'; OpId = $item.OpId; Path = $p.Path }; break }
            $cd = Test-AtmTypedPhrase -Typed (& $ConfirmationReader $choices[0] 'results' $p.Path $choices) -Phrases $choices
            if ($cd.Code) { $refusal = [pscustomobject]@{ Code = 'DECLARATION_' + $cd.Code; Step = 'results'; OpId = $item.OpId; Path = $p.Path }; break }
            $dec = $decisionMap[$cd.Hit]
            $declarations.Add([pscustomobject]@{ OpId = $item.OpId; Path = $p.Path; Fingerprint = $p.Fingerprint; TaskCompleted = $true; ContentDecision = $dec; PreservationBasis = (Get-AtmPreservationBasis $dec) })
        }
        if ($null -eq $refusal) {
            $fc = Test-AtmTypedPhrase -Typed (& $ConfirmationReader $state.Phrase 'confirm' $null @($state.Phrase)) -Phrases @($state.Phrase)
            if ($fc.Code) { $refusal = [pscustomobject]@{ Code = 'CONFIRMACAO_AUSENTE_OU_DIVERGENTE'; Step = 'confirm'; OpId = $null; Path = $null } }
        }
        if ($null -ne $refusal) {
            # Nothing was recorded as declared: the answers given before the refusal are not kept in the result either.
            $declarations.Clear()
            $state.RefusedAt = $refusal
            $lc = Write-AtmCleanLogRecord -Log $log -State $state -Type 'confirmation' -Fields ([ordered]@{ accepted = $false; planId = $state.PlanId; step = $refusal.Step; opId = $refusal.OpId; refusal = $refusal.Code; interaction = $interactionRec })
            if ($null -ne $lc) { & $logFail 'confirmation' $null $lc }
            $state.Aborted = $refusal.Code
        } else {
            # The declarations and the confirmation are written and flushed before any intent.
            $lc = $null; $stage = 'declaration'
            foreach ($dcl in $declarations) {
                $lc = Write-AtmCleanLogRecord -Log $log -State $state -Type 'declaration' -Fields ([ordered]@{ opId = $dcl.OpId; path = $dcl.Path; fingerprint = $dcl.Fingerprint; declaredBy = 'OPERATOR'
                        taskCompleted = $true; contentDecision = $dcl.ContentDecision; preservation = [ordered]@{ basis = $dcl.PreservationBasis; verifiedByTool = $false } })
                if ($null -ne $lc) { break }
            }
            if ($null -eq $lc) {
                $stage = 'confirmation'
                $lc = Write-AtmCleanLogRecord -Log $log -State $state -Type 'confirmation' -Fields ([ordered]@{ accepted = $true; planId = $state.PlanId; roots = $plan.Count; interaction = $interactionRec; limitations = @($script:AtmCleanDeclarationLimitations) })
            }
            if ($null -ne $lc) { & $logFail $stage $null $lc; $state.Aborted = 'LOG_WRITE_FAILED' }
            else {
                $state.Confirmed = $true
                # The executable set must not have changed while the operator answered: a fresh inventory, the same gates
                # and fresh runtime evidence, root by root against the plan. Nothing is reduced, extended or updated under
                # the old confirmation; a difference stops the run and a new presentation is needed. Statistics only: a
                # write that keeps every statistic is not seen here either.
                $iaChk = @{} + $InventoryArgs
                $iaChk['NoProgress'] = $true
                $invChk = Invoke-AtmInventory @iaChk
                $rtChk = Get-AtmCleanRuntimeEvidence -Inventory $invChk -InventoryArgs $iaChk
                $changed = New-Object System.Collections.Generic.List[string]
                foreach ($item in $plan) {
                    $m3 = @($invChk.Partitions | Where-Object { [string]::Equals($_.Path, $item.Part.Path, [StringComparison]::Ordinal) -and $_.Kind -ne 'NotScanned' -and $_.Kind -ne 'BaseLooseFiles' })
                    if ($m3.Count -ne 1) { $changed.Add($item.OpId); continue }
                    if ((Get-AtmCleanPlanItemKey $m3[0]) -cne (Get-AtmCleanPlanItemKey $item.Part)) { $changed.Add($item.OpId); continue }
                    $g3 = Test-AtmCandidate -Partition $m3[0] -Inventory $invChk -IncludeOtherUsers:$IncludeOtherUsers -ForClean -RuntimeEvidence $rtChk
                    if ($g3.Category -ne 'ELIGIBLE') { $changed.Add($item.OpId) }
                }
                $lc = Write-AtmCleanLogRecord -Log $log -State $state -Type 'plan-check' -Fields ([ordered]@{ planId = $state.PlanId; matched = ($changed.Count -eq 0); changed = @($changed) })
                if ($null -ne $lc) { & $logFail 'plan-check' $null $lc; $state.Aborted = 'LOG_WRITE_FAILED' }
                elseif ($changed.Count -gt 0) { $state.Aborted = 'PLAN_CHANGED_BEFORE_EXECUTION' }
            }
        }
        if (-not $state.Aborted) {
            # 18-19: per-path revalidation immediately before deleting; only still-eligible paths are deleted.
            foreach ($item in $plan) {
                $p = $item.Part
                if ($BeforeDeleteHook) { & $BeforeDeleteHook $p }
                $args2 = @{} + $InventoryArgs
                $args2['OnlyRootPath'] = $p.Path
                $args2['NoProgress'] = $true
                $re = Invoke-AtmInventory @args2
                # B2-1: fresh runtime evidence for this root, never the plan's (evidence may appear in between).
                $rtRe = Get-AtmCleanRuntimeEvidence -Inventory $re -InventoryArgs $args2
                $cur = @($re.Partitions | Where-Object { [string]::Equals($_.Path, $p.Path, [StringComparison]::OrdinalIgnoreCase) -and $_.Kind -ne 'NotScanned' -and $_.Kind -ne 'BaseLooseFiles' })
                $why = @()
                if ($cur.Count -ne 1) { $why += 'DESAPARECEU_OU_AMBIGUO_NA_REVALIDACAO' }
                else {
                    $c = $cur[0]
                    if ($c.Fingerprint -ne $p.Fingerprint) { $why += "ALTERADO_APOS_CONFIRMACAO (fingerprint $($p.Fingerprint) -> $($c.Fingerprint))" }
                    $g = Test-AtmCandidate -Partition $c -Inventory $re -IncludeOtherUsers:$IncludeOtherUsers -ForClean -RuntimeEvidence $rtRe
                    if ($g.Category -ne 'ELIGIBLE') { $why += $g.Reasons }
                }
                if ($why.Count -gt 0) {
                    # AUT-2 (maintainer's decision): a revalidation refusal after the confirmation stops the run before
                    # this root and every later one. Not atomic and no rollback: earlier roots may already be deleted.
                    $skipped.Add([pscustomobject]@{ OpId = $item.OpId; Path = $p.Path; Reasons = $why })
                    $state.StopOpId = $item.OpId
                    $lc = Write-AtmCleanLogRecord -Log $log -State $state -Type 'skip' -Fields ([ordered]@{ opId = $item.OpId; path = $p.Path; reasons = @($why) })
                    if ($null -ne $lc) { & $logFail 'skip' $item.OpId $lc; & $halt 'LOG_WRITE_FAILED'; break }
                    & $halt 'REVALIDATION_REFUSED'
                    break
                }
                # The intent is written and flushed BEFORE the deleter is called; without it that root is never started.
                $lc = Write-AtmCleanLogRecord -Log $log -State $state -Type 'intent' -Fields ([ordered]@{ opId = $item.OpId; path = $c.Path; fingerprint = $c.Fingerprint; files = $c.Files; dirs = $c.Dirs; bytes = $c.Bytes })
                if ($null -ne $lc) { $state.StopOpId = $item.OpId; & $logFail 'intent' $item.OpId $lc; & $halt 'LOG_INTENT_FAILED'; break }
                # The deleter re-checks, under its own handle pins, that the tree still matches what was just validated.
                # An exception leaves the state of that root unknown: none, part or all of it may have been deleted.
                $d = $null; $exType = $null
                try {
                    if ($DeleteTreeImpl) { $d = & $DeleteTreeImpl $c }
                    else { $d = [AgentTempManager.AtmDeleter]::DeleteTree($c.Path, $c.Files, $c.Dirs, $c.Bytes, $c.NewestWriteTimeUtc.Ticks, $null) }
                    if ($null -eq $d) { throw [InvalidOperationException]::new('DELETER_NO_RESULT') }
                } catch { $d = $null; $exType = $_.Exception.GetBaseException().GetType().Name }
                # Only a confirmed absence verifies the removal; access denied or any other error: not verified, never assumed.
                $gone = $false; $vs = 'UNKNOWN'
                if ($null -eq $exType) {
                    $pres = $(if ($PathPresenceImpl) { & $PathPresenceImpl $p.Path } else { Get-AtmPathPresence $p.Path })
                    if ($pres -is [bool]) { $gone = -not $pres; $vs = $(if ($pres) { 'PRESENT' } else { 'GONE' }) }
                }
                # REFUSED: nothing deleted (the deleter's own counts). PARTIAL: some entries deleted, not all.
                # VERIFICATION_FAILED: the deleter completed but the absence could not be confirmed.
                $outcome = $(if ($null -ne $exType) { 'EXCEPTION' }
                    elseif (-not $d.Completed) { $(if ([long]$d.FilesDeleted -gt 0 -or [long]$d.DirsDeleted -gt 0) { 'PARTIAL' } else { 'REFUSED' }) }
                    elseif ($gone) { 'COMPLETE' }
                    else { 'VERIFICATION_FAILED' })
                $known = ($null -ne $d)
                $row = [pscustomobject]@{ OpId = $item.OpId; Path = $p.Path; Bytes = $p.Bytes; Outcome = $outcome; Completed = ($known -and [bool]$d.Completed); Verified = $gone; VerifiedState = $vs
                    Attempted = $(if ($known) { [bool]$d.Attempted } else { $null }); FilesDeleted = $(if ($known) { $d.FilesDeleted } else { $null }); DirsDeleted = $(if ($known) { $d.DirsDeleted } else { $null })
                    FilesPlanned = $(if ($known) { $d.FilesPlanned } else { $null }); DirsPlanned = $(if ($known) { $d.DirsPlanned } else { $null })
                    AbortReason = $(if ($known) { $d.AbortReason } else { $null }); FailedAt = $(if ($known) { $d.FailedAt } else { $null }); ExceptionType = $exType }
                $deleted.Add($row)
                $lc = Write-AtmCleanLogRecord -Log $log -State $state -Type 'result' -Fields ([ordered]@{ opId = $row.OpId; path = $row.Path; outcome = $outcome; attempted = $row.Attempted; completed = $row.Completed
                        filesDeleted = $row.FilesDeleted; dirsDeleted = $row.DirsDeleted; filesPlanned = $row.FilesPlanned; dirsPlanned = $row.DirsPlanned; abortReason = $row.AbortReason; failedAt = $row.FailedAt
                        verifiedGone = $(if ($vs -ceq 'UNKNOWN') { 'UNKNOWN' } else { $gone }); exceptionType = $exType })
                if ($null -ne $lc) { $state.StopOpId = $item.OpId; & $logFail 'result' $row.OpId $lc; & $halt 'LOG_RESULT_FAILED'; break }
                # Anything but a complete, verified deletion stops the run before the next root.
                if ($outcome -cne 'COMPLETE') { $state.StopOpId = $item.OpId; & $halt ('STOPPED_AFTER_' + $outcome); break }
            }
            # The roots after the one that stopped the run were never revalidated nor processed.
            if ($state.StopOpId) {
                $at = -1; for ($i = 0; $i -lt $plan.Count; $i++) { if ($plan[$i].OpId -ceq $state.StopOpId) { $at = $i } }
                for ($i = $at + 1; $i -lt $plan.Count; $i++) { $notAttempted.Add([pscustomobject]@{ OpId = $plan[$i].OpId; Path = $plan[$i].Part.Path }) }
            }

            # 20: post-clean read-only audit.
            $post = @{} + $InventoryArgs
            $post['NoProgress'] = $true
            $state.Post = Invoke-AtmInventory @post
        }
        # run-end only while the log has not failed (after a failure it writes nothing more). Neither a failed run-end
        # nor a failed close replaces the main code; with none, they make the run incomplete.
        if ($logErrors.Count -eq 0) {
            $lc = Write-AtmCleanLogRecord -Log $log -State $state -Type 'run-end' -Fields ([ordered]@{ results = $deleted.Count; complete = @($deleted | Where-Object { $_.Outcome -ceq 'COMPLETE' }).Count; skipped = $skipped.Count; stoppedBy = $(if ($state.Stopped) { $state.Stopped } else { $state.Aborted })
                    stoppedAtOpId = $state.StopOpId; notAttempted = @($notAttempted | ForEach-Object { $_.OpId }) })
            if ($null -ne $lc) { & $logFail 'run-end' $null $lc; if (-not $state.Aborted -and -not $state.Stopped) { & $halt 'LOG_END_FAILED' } }
        }
        $cc = $log.Close()
        if ($null -ne $cc) { & $logFail 'close' $null $cc; if (-not $state.Aborted -and -not $state.Stopped) { & $halt 'LOG_CLOSE_FAILED' } }
        return (& $finish)
    } finally { if ($null -ne $log) { try { $log.Dispose() } catch { $null = $_ } } }
}

# ---------------------------------------------------------------------------------------------
# AUT-1 (V0.3): the operator's discard authorization of ONE root, bound to a plan just presented. It records the
# operator's declarations (the task finished; the content needed is preserved, or nothing in it needs to be kept; the
# content shown may be discarded); it is not a credential: nothing in the product reads it, it makes nothing eligible,
# and a future run would still need a current confirmation and its own revalidation. The technical result (B1, RECENT
# and every other gate) is shown and recorded apart from the declarations: a root can be authorized by the operator and
# stay technically blocked. The association root -> session is the provider's naming convention (root name = session
# id), corroborated by a readable transcript of the same id; the task is the operator's declaration, never a fact read
# from the records. Recording succeeded only when the command says so (line written, flushed and the file closed); a
# line, complete or not, can remain in a file after a failure, so neither the line nor the file is proof of a recording.
# ---------------------------------------------------------------------------------------------
$script:AtmDiscardAuthSchema = 'atm.discard-authorization/2'
$script:AtmDiscardDescriptionMax = 200
# Basis of the preservation statement. TOOL_VERIFIED is reserved for a verification performed by the product itself;
# no such verifier exists, so it is never emitted (only the operator's two declarations below are).
$script:AtmPreservationBases = @('OPERATOR_DECLARED', 'NOTHING_NEEDED_DISCARD_ACCEPTED', 'TOOL_VERIFIED')
# What the record cannot guarantee, recorded with it (codes; text in the message catalog).
$script:AtmDiscardLimitations = @('ASSOCIATION_BY_NAME_CONVENTION', 'TASK_DECLARED_BY_OPERATOR', 'PRESERVATION_NOT_VERIFIED_BY_TOOL', 'STATISTICS_NOT_CONTENT',
    'READ_ONLY_USE_NOT_OBSERVED', 'NO_EVIDENCE_IS_NOT_NON_USE', 'RECORD_ALTERABLE_BY_SAME_IDENTITY', 'RECORD_LINE_MAY_REMAIN_AFTER_FAILURE',
    'NOT_A_DELETION_CREDENTIAL', 'PROCESS_IDENTITY_IS_NOT_THE_RESPONDENT', 'CALLER_AND_REQUIREMENT_REPORTED_BY_CALLER', 'INTERACTIVE_CONSOLE_IS_NOT_PROOF_OF_PRESENCE')

# AUT-2: the limits recorded with a clean run's confirmation (same codes and texts as AUT-1).
$script:AtmCleanDeclarationLimitations = @('TASK_DECLARED_BY_OPERATOR', 'PRESERVATION_NOT_VERIFIED_BY_TOOL', 'STATISTICS_NOT_CONTENT', 'READ_ONLY_USE_NOT_OBSERVED',
    'NO_EVIDENCE_IS_NOT_NON_USE', 'PROCESS_IDENTITY_IS_NOT_THE_RESPONDENT', 'CALLER_AND_REQUIREMENT_REPORTED_BY_CALLER', 'INTERACTIVE_CONSOLE_IS_NOT_PROOF_OF_PRESENCE')

function Get-AtmContentDecisions {
    # The two content declarations (phrase -> decision), shared by authorize (AUT-1) and clean (AUT-2): the content
    # needed is preserved outside the root, or nothing in it needs to be kept. Neither is verified by the product.
    return [ordered]@{ (Get-AtmText 'auth.phrase.results') = 'RESULTS_PRESERVED'; (Get-AtmText 'auth.phrase.nothingNeeded') = 'NOTHING_NEEDED' }
}

function Get-AtmPreservationBasis {
    # The basis recorded for a content decision; never TOOL_VERIFIED (no verifier exists).
    param([string]$Decision)
    if ($Decision -ceq 'NOTHING_NEEDED') { return 'NOTHING_NEEDED_DISCARD_ACCEPTED' }
    return 'OPERATOR_DECLARED'
}

function Test-AtmTypedPhrase {
    # Code $null with Hit = the phrase matched exactly (ordinal); CANCELLED for $null, '' or a non-string; DECLINED for
    # anything else. No trimming or case folding.
    param($Typed, [string[]]$Phrases)
    if (-not ($Typed -is [string]) -or $Typed -eq '') { return [pscustomobject]@{ Code = 'CANCELLED'; Hit = $null } }
    $hit = @($Phrases | Where-Object { [string]::Equals($Typed, $_, [StringComparison]::Ordinal) })
    if ($hit.Count -ne 1) { return [pscustomobject]@{ Code = 'DECLINED'; Hit = $null } }
    return [pscustomobject]@{ Code = $null; Hit = $hit[0] }
}

function Get-AtmCleanPlanItemKey {
    # One root of a clean plan as compared before execution: path and the statistics behind its fingerprint.
    param($Part)
    $nw = $(if ($Part.NewestWriteTimeUtc) { [string]([datetime]$Part.NewestWriteTimeUtc).ToUniversalTime().Ticks } else { '' })
    return ((@([string]$Part.Path, [string]$Part.Fingerprint, [string]$Part.Files, [string]$Part.Dirs, [string]$Part.Bytes, $nw) | ForEach-Object { '{0}:{1}' -f $_.Length, $_ }) -join ';')
}

function Get-AtmCleanPlanId {
    # Identifies the exact executable set presented in a run: SHA-256 over the run id and every root's key, in plan order.
    param([string]$RunId, $Parts)
    $text = 'atm-clean-plan/1;' + $RunId + ';' + ((@($Parts) | ForEach-Object { Get-AtmCleanPlanItemKey $_ }) -join '|')
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)) } finally { $sha.Dispose() }
    return (-join @($h | ForEach-Object { $_.ToString('x2') }))
}

function Test-AtmDiscardConsoleObserved {
    # The engine's own observation, in this call, of an interactive console (console host, input and output not
    # redirected, a real console window). It says nothing about who answered.
    try {
        if ($Host.Name -ne 'ConsoleHost') { return $false }
        if ([Console]::IsInputRedirected -or [Console]::IsOutputRedirected) { return $false }
        $null = [Console]::WindowWidth
        return $true
    } catch { return $false }
}
function Get-AtmDiscardReasonSignature {
    <#
      Stable, semantic form of the technical justification shown to the operator, for the revalidation: a new collection
      that says the same thing gives the same signature; new evidence or a changed justification gives another one.
        * V0.1 gate reasons as given (principal, path and status are part of the reason), except the counts that vary
          between collections: process coverage keeps only its code (its state is below), and the lock probe's
          in-use and access-denied reasons keep only their codes;
        * each runtime refusal as code|decision|collector|evidence|relation|nature|coverage|sources, list fields sorted:
          sources are the process keys (pid@creationTicksUtc) the evidence comes from, stable for the same process, so
          another process behind the same code is a different signature. Never its time, nor its detail text
          (localized). A refusal whose collector gives no process key (coverage gaps, an unverified session) is compared
          by its other fields only;
        * the process coverage state (COMPLETE, INCOMPLETE, FAILED), not its counts, and what the B1 gate did
          (NOT_EVALUATED, BLOCKED, PASSED).
      The class, flags, association, session registry and statistics are compared on their own.
    #>
    param($Gate, $Inventory)
    $sorted = { param([string]$s) (@($s -split ',' | Where-Object { $_ } | Sort-Object -Unique) -join ',') }
    $all = @($Gate.Reasons); $rt = @($Gate.RuntimeReasons)
    $v01 = $(if ($all.Count -gt $rt.Count) { @($all[0..($all.Count - $rt.Count - 1)]) } else { @() })
    $sig = New-Object System.Collections.Generic.List[string]
    foreach ($r in $v01) {
        $t = [string]$r
        if ($t.StartsWith('COBERTURA_DE_PROCESSOS_INCOMPLETA', [StringComparison]::Ordinal)) { $t = 'COBERTURA_DE_PROCESSOS_INCOMPLETA' }
        elseif ($t -cmatch '^(EM_USO|ACESSO_NEGADO_PARA_EXCLUSAO):') { $t = $Matches[1] }
        $sig.Add('GATE:' + $t)
    }
    foreach ($x in $rt) {
        $src = $(if ($x.PSObject.Properties['Sources']) { (@($x.Sources) | Where-Object { $_ } | Sort-Object -Unique) -join ',' } else { '' })
        $sig.Add('RUNTIME:' + (@([string]$x.Code, [string]$x.Decision, (& $sorted ([string]$x.Collector)), (& $sorted ([string]$x.Evidence)), (& $sorted ([string]$x.Relation)), [string]$x.Nature, [string]$x.Coverage, $src) -join '|'))
    }
    $sig.Add('COVERAGE:' + $(if ($Inventory.Snapshot.Failed) { 'FAILED' } elseif ($Inventory.ProcessCoverageComplete) { 'COMPLETE' } else { 'INCOMPLETE' }))
    $sig.Add('B1_GATE:' + [string]$Gate.ProcessCoverageGate)
    return , @($sig | Sort-Object -Unique)
}

function Get-AtmDiscardPresentation {
    <#
      What the operator is shown for one root, read-only: identity, observed facts (statistics and fingerprint), age as
      information, the association, the technical result of every gate with the runtime evidence, and the limits.
      Returns Refused (a code, with Detail) or the presentation with a new PlanId.
    #>
    param([string]$Path, [hashtable]$InventoryArgs = @{})
    $refuse = { param([string]$Code, $Detail) [pscustomobject]@{ Refused = $Code; Detail = $Detail } }
    $why = Test-AtmAllowListPathSyntax $Path
    if ($why) { return (& $refuse 'AUTH_PATH_INVALID' $why) }
    $ia = @{} + $InventoryArgs
    $inv = Invoke-AtmInventory @ia
    $m = @($inv.Partitions | Where-Object { [string]::Equals($_.Path, $Path, [StringComparison]::OrdinalIgnoreCase) -and $_.Kind -ne 'BaseLooseFiles' })
    if ($m.Count -ne 1) { return (& $refuse 'AUTH_NOT_A_ROOT' $null) }
    $p = $m[0]
    if (-not [string]::Equals($p.Path, $Path, [StringComparison]::Ordinal)) { return (& $refuse 'AUTH_PATH_CASE_MISMATCH' $p.Path) }
    if ($p.Kind -ne 'SessionRoot') { return (& $refuse 'AUTH_NOT_SESSION_ROOT' $p.Kind) }
    if ([string]$p.Sid -cne [string]$inv.Identity.Sid) { return (& $refuse 'AUTH_OTHER_USER' $null) }
    $rt = Get-AtmCleanRuntimeEvidence -Inventory $inv -InventoryArgs $ia
    $g = Test-AtmCandidate -Partition $p -Inventory $inv -ForClean -RuntimeEvidence $rt
    # Association: corroborated only by a readable transcript of the same id; the same session id under another scope
    # is ambiguous; anything else is unknown (never presented as proved).
    $same = @($inv.Partitions | Where-Object { $_.Kind -eq 'SessionRoot' -and [string]::Equals($_.Name, $p.Name, [StringComparison]::OrdinalIgnoreCase) })
    $tlw = $p.TranscriptLastWriteUtc
    $assoc = $(if ($same.Count -gt 1) { 'AMBIGUOUS' } elseif (@($p.Flags) -contains 'TRANSCRIPTS_UNREADABLE') { 'UNKNOWN' } elseif ($null -ne $tlw) { 'NAME_CONVENTION_CORROBORATED' } else { 'UNKNOWN' })
    $now = [datetime]::UtcNow
    return [pscustomobject]@{
        Refused = $null; Detail = $null; PlanId = [guid]::NewGuid().ToString(); PresentedUtc = $now
        Partition = $p; Inventory = $inv; Runtime = $rt; Gate = $g
        Association = [pscustomobject]@{ Kind = $assoc; SessionId = [string]$p.Name; TranscriptLastWriteUtc = $tlw; SameIdElsewhere = ($same.Count - 1) }
        SessionRegistry = $p.Session
        Facts = [pscustomobject]@{ Files = [long]$p.Files; Dirs = [long]$p.Dirs; Bytes = [long]$p.Bytes; NewestWriteUtc = $p.NewestWriteTimeUtc; CreationUtc = $p.CreationTimeUtc; Fingerprint = $p.Fingerprint
            AgeHours = $(if ($p.NewestWriteTimeUtc) { [Math]::Round(($inv.NowUtc - $p.NewestWriteTimeUtc).TotalHours, 1) } else { $null }); Class = $p.Class; Flags = @($p.Flags) }
        Technical = [pscustomobject]@{ Category = $g.Category; Reasons = @($g.Reasons); RuntimeCodes = @(@($g.RuntimeReasons) | ForEach-Object { $_.Code } | Sort-Object -Unique)
            # B1 apart: the coverage observed by this inventory, and what the B1 gate did in this evaluation
            # (NOT_EVALUATED when an earlier gate returned first: never an approval of B1).
            ProcessCoverage = [pscustomobject]@{ Observed = $(if ($inv.Snapshot.Failed) { 'FAILED' } elseif ($inv.ProcessCoverageComplete) { 'COMPLETE' } else { 'INCOMPLETE' }); Gate = [string]$g.ProcessCoverageGate }
            RecentBlock = ($p.Class -eq 'RECENT')
            ReasonSignature = (Get-AtmDiscardReasonSignature -Gate $g -Inventory $inv) }
        Limitations = @($script:AtmDiscardLimitations)
    }
}

function Compare-AtmDiscardPresentation {
    # The facts a later presentation must still match for the operator's answers to apply to it. A difference means the
    # plan changed; equal statistics never prove equal content nor non-use (a write that keeps every statistic, and any
    # read-only use, are not seen). The justification is compared in its semantic form (Get-AtmDiscardReasonSignature),
    # never as formatted text or collection times, so an equivalent new collection does not refuse by itself.
    param($Before, $After)
    $d = New-Object System.Collections.Generic.List[string]
    $pb = $Before.Partition; $pa = $After.Partition
    if (-not [string]::Equals($pb.Path, $pa.Path, [StringComparison]::Ordinal)) { $d.Add('PATH') }
    foreach ($k in @('Kind', 'Sid', 'Provider', 'Name', 'Fingerprint', 'Class')) { if ([string]$pb.$k -cne [string]$pa.$k) { $d.Add($k.ToUpperInvariant()) } }
    foreach ($k in @('Files', 'Dirs', 'Bytes')) { if ([long]$pb.$k -ne [long]$pa.$k) { $d.Add($k.ToUpperInvariant()) } }
    foreach ($k in @('NewestWriteTimeUtc', 'CreationTimeUtc')) { if ([string]$pb.$k -cne [string]$pa.$k) { $d.Add($k.ToUpperInvariant()) } }
    if ((@($pb.Flags) -join ',') -cne (@($pa.Flags) -join ',')) { $d.Add('FLAGS') }
    if ([string]$Before.Association.Kind -cne [string]$After.Association.Kind -or [string]$Before.Association.TranscriptLastWriteUtc -cne [string]$After.Association.TranscriptLastWriteUtc) { $d.Add('ASSOCIATION') }
    if ([string]$Before.SessionRegistry -cne [string]$After.SessionRegistry) { $d.Add('SESSION_REGISTRY') }
    if ([string]$Before.Technical.Category -cne [string]$After.Technical.Category -or (@($Before.Technical.RuntimeCodes) -join ',') -cne (@($After.Technical.RuntimeCodes) -join ',')) { $d.Add('TECHNICAL_RESULT') }
    if ((@($Before.Technical.ReasonSignature) -join "`n") -cne (@($After.Technical.ReasonSignature) -join "`n")) { $d.Add('TECHNICAL_REASONS') }
    return $d.ToArray()
}

function Invoke-AtmDiscardAuthorization {
    <#
      Records the operator's discard authorization of one root, bound to the plan just presented. Callers provide:
        -Presenter   scriptblock(presentation) that MUST show it (facts, association, technical result, limits).
        -Reader      scriptblock(kind, phrase) returning what the operator typed; kind is task and discard (one exact
                     phrase each), results (phrase = the two accepted phrases: preserved, or nothing needed) or
                     description (optional free text). $null or '' cancels.
        -RecordFile  a NEW file outside the audited directories, created by the pinned writer (AtmCleanLog: new file
                     only, protected DACL, an unsafe folder is refused and never changed).
        -Interaction what the caller reports: Caller ('CLI'; anything else is a direct call) and ConsoleRequired
                     (the caller requires an interactive console). Recorded as reported, never verified. The console
                     itself is observed by the engine in this call (Test-AtmDiscardConsoleObserved); a caller that
                     requires one when none is observed is refused before any question (AUTH_CONSOLE_NOT_OBSERVED).
      The CLI calls it only from an interactive console (redirected input never records an acceptance); even so that is
      not proof that a person answered. Before writing, the root is presented again and must still match: any detected
      change refuses this plan (AUTH_PLAN_CHANGED) and a new presentation is needed. No record is written unless every
      declaration is confirmed and the plan still matches. Accepted is true only when the line was written and flushed
      and the file closed without error; after a failure past the creation the file stays as it is (RecordState
      INCOMPLETE_OR_UNDETERMINED: it may hold no line, part of one, or a complete one) and is never reopened or removed.
      Nothing is deleted and no gate result changes.
    #>
    param([string]$Path, [hashtable]$InventoryArgs = @{}, [string]$RecordFile, [scriptblock]$Presenter, [scriptblock]$Reader, [hashtable]$Interaction = @{})
    $res = [ordered]@{ Accepted = $false; Refused = $null; Detail = $null; Step = $null; PlanId = $null; AuthorizationId = $null; RecordFile = $null; RecordCreated = $false
        RecordState = 'NOT_CREATED'; ContentDecision = $null; Changes = @(); Presentation = $null }
    $done = { [pscustomobject]$res }
    if (-not $Presenter -or -not $Reader) { $res.Refused = 'AUTH_NO_PRESENTER_OR_READER'; return (& $done) }
    if (-not $RecordFile) { $res.Refused = 'AUTH_RECORD_REQUIRED'; return (& $done) }
    # Interaction: the caller and its requirement as reported; the console as observed by the engine in this call.
    $isCli = ([string]$Interaction['Caller'] -ceq 'CLI')
    $required = ($isCli -and $Interaction['ConsoleRequired'] -eq $true)
    $observed = [bool](Test-AtmDiscardConsoleObserved)
    if ($required -and -not $observed) { $res.Refused = 'AUTH_CONSOLE_NOT_OBSERVED'; return (& $done) }
    $pres = Get-AtmDiscardPresentation -Path $Path -InventoryArgs $InventoryArgs
    if ($pres.Refused) { $res.Refused = $pres.Refused; $res.Detail = $pres.Detail; return (& $done) }
    $res.Presentation = $pres; $res.PlanId = $pres.PlanId
    # The destination is checked before any question (it is checked again, pinned, when the record is created).
    if (-not (Test-AtmOutputPathOutsideBases -Path $RecordFile -Inventory $pres.Inventory -MustNotExist)) { $res.Refused = 'AUTH_RECORD_DESTINATION_REFUSED'; return (& $done) }
    $pin = [AgentTempManager.AtmCleanLog]::Pin([IO.Path]::GetDirectoryName($RecordFile), (Get-AtmCurrentIdentity).Sid)
    try { $pinErr = $pin.Error } finally { $pin.Dispose() }
    if ($null -ne $pinErr) { $res.Refused = 'AUTH_RECORD_DESTINATION_REFUSED'; $res.Detail = $pinErr; return (& $done) }
    & $Presenter $pres
    if ($pres.Association.Kind -cne 'NAME_CONVENTION_CORROBORATED') { $res.Refused = 'AUTH_ASSOCIATION_' + $pres.Association.Kind; return (& $done) }
    $short = $pres.PlanId.Substring(0, 8).ToUpperInvariant()
    # The content decision has two declarations, each with its own phrase: the content needed is preserved outside the
    # root (OPERATOR_DECLARED), or nothing in it needs to be kept (NOTHING_NEEDED_DISCARD_ACCEPTED). Neither is verified
    # by the product, and neither says that the root is unused.
    $decisions = Get-AtmContentDecisions
    $decision = $null
    foreach ($step in @(@('task', @(Get-AtmText 'auth.phrase.task')), @('results', @($decisions.Keys)), @('discard', @(Get-AtmText 'auth.phrase.discard' $short)))) {
        $phrases = @($step[1])
        $typed = & $Reader $step[0] $(if ($phrases.Count -eq 1) { $phrases[0] } else { $phrases })
        $tp = Test-AtmTypedPhrase -Typed $typed -Phrases $phrases
        if ($tp.Code) { $res.Refused = 'AUTH_' + $tp.Code; $res.Step = $step[0]; return (& $done) }
        if ($step[0] -ceq 'results') { $decision = $decisions[$tp.Hit] }
    }
    $res.ContentDecision = $decision
    # Optional free text, kept as data only: control characters replaced, length capped.
    $descRaw = & $Reader 'description' $null
    $desc = $(if ($descRaw -is [string] -and $descRaw.Trim() -ne '') { $t = [regex]::Replace($descRaw.Trim(), '[\x00-\x1f\x7f-\x9f]', '?'); if ($t.Length -gt $script:AtmDiscardDescriptionMax) { $t.Substring(0, $script:AtmDiscardDescriptionMax) } else { $t } } else { $null })
    # The plan must still match: presented again, compared fact by fact.
    $again = Get-AtmDiscardPresentation -Path $Path -InventoryArgs $InventoryArgs
    if ($again.Refused) { $res.Refused = 'AUTH_PLAN_CHANGED'; $res.Detail = $again.Refused; return (& $done) }
    $diff = @(Compare-AtmDiscardPresentation -Before $pres -After $again)
    if ($diff.Count -gt 0) { $res.Refused = 'AUTH_PLAN_CHANGED'; $res.Changes = $diff; return (& $done) }
    $p = $pres.Partition; $idn = $pres.Inventory.Identity
    $iso = { param($v) if ($null -ne $v) { ([datetime]$v).ToUniversalTime().ToString('o') } else { $null } }
    $authId = [guid]::NewGuid().ToString()
    $basis = Get-AtmPreservationBasis $decision
    $rec = [ordered]@{
        schema = $script:AtmDiscardAuthSchema; authorizationId = $authId; planId = $pres.PlanId; tool = $script:AtmVersion
        presentedUtc = (& $iso $pres.PresentedUtc); revalidatedUtc = (& $iso $again.PresentedUtc); composedUtc = (& $iso ([datetime]::UtcNow))
        processIdentity = [ordered]@{ name = $idn.Name; sid = $idn.Sid; elevated = [bool]$idn.IsAdmin; identifiesRespondent = $false }
        # Caller and requirement as reported by the caller (not verified); the console as observed by the engine in this
        # call. Never a statement about who answered.
        interaction = [ordered]@{ caller = $(if ($isCli) { 'CLI' } else { 'DIRECT_CALL' }); consoleRequiredByCaller = $required; callerFieldsVerified = $false
            interactiveConsoleObserved = $observed; observedBy = 'ENGINE_CONSOLE_CHECK' }
        root = [ordered]@{ path = $p.Path; provider = $p.Provider; profileSid = $p.Sid; sessionId = [string]$p.Name; kind = $p.Kind }
        association = [ordered]@{ kind = $pres.Association.Kind; transcriptLastWriteUtc = (& $iso $pres.Association.TranscriptLastWriteUtc); basis = 'ROOT_NAME_EQUALS_SESSION_ID' }
        presented = [ordered]@{ files = $pres.Facts.Files; dirs = $pres.Facts.Dirs; bytes = $pres.Facts.Bytes; newestWriteUtc = (& $iso $pres.Facts.NewestWriteUtc); creationUtc = (& $iso $pres.Facts.CreationUtc)
            fingerprint = $pres.Facts.Fingerprint; ageHours = $pres.Facts.AgeHours; class = $pres.Facts.Class; flags = @($pres.Facts.Flags); sessionRegistry = $pres.SessionRegistry }
        technical = [ordered]@{ category = $pres.Technical.Category; runtimeCodes = @($pres.Technical.RuntimeCodes); processCoverage = [ordered]@{ observed = $pres.Technical.ProcessCoverage.Observed; gate = $pres.Technical.ProcessCoverage.Gate }; recentBlock = $pres.Technical.RecentBlock
            reasonSignature = @($pres.Technical.ReasonSignature); reasons = @($pres.Technical.Reasons) }
        # Received from the operator: every phrase was typed as required. A declaration, not an observed fact, not a
        # recording result and not a permission.
        declarations = [ordered]@{ declaredBy = 'OPERATOR'; status = 'ALL_PHRASES_TYPED'; taskCompleted = $true; contentDecision = $decision; discardAuthorized = $true; taskDescription = $desc }
        preservation = [ordered]@{ basis = $basis; verifiedByTool = $false; evidence = $null }
        revalidation = [ordered]@{ planRevalidated = $true; compared = 'STATISTICS_FINGERPRINT_AND_SEMANTIC_REASONS' }
        limitations = @($pres.Limitations)
    }
    if ($script:AtmPreservationBases -cnotcontains $rec.preservation.basis -or $rec.preservation.basis -ceq $script:AtmPreservationBases[2]) { throw (Get-AtmText 'err.diagFinding' 'preservation basis') }
    $line = ConvertTo-Json -InputObject $rec -Compress -Depth 6
    $res.RecordFile = $RecordFile
    $opened = Open-AtmCleanLog -Path $RecordFile -Inventory $again.Inventory -ProcessUserSid (Get-AtmCurrentIdentity).Sid
    $res.RecordCreated = [bool]$opened.Created
    if ($res.RecordCreated) { $res.RecordState = 'INCOMPLETE_OR_UNDETERMINED' }
    if ($null -eq $opened.Log) { $res.Refused = 'AUTH_RECORD_FAILED'; $res.Detail = $opened.Code; return (& $done) }
    try {
        $wc = $opened.Log.AppendLine($line)
        if ($null -ne $wc) { $res.Refused = 'AUTH_RECORD_FAILED'; $res.Detail = $wc; return (& $done) }
        $cc = $opened.Log.Close()
        if ($null -ne $cc) { $res.Refused = 'AUTH_RECORD_FAILED'; $res.Detail = $cc; return (& $done) }
    } finally { $opened.Log.Dispose() }
    $res.RecordState = 'COMPLETE'; $res.Accepted = $true; $res.AuthorizationId = $authId
    return (& $done)
}

function Test-AtmOutputPathOutsideBases {
    # Report/log destinations: absolute, canonical, parent chain free of reparse points (so the lexical check
    # cannot be redirected into an audited tree), outside every base; optionally must not exist yet.
    param([string]$Path, $Inventory, [switch]$MustNotExist)
    if (Test-AtmAllowListPathSyntax $Path) { return $false }
    $full = [IO.Path]::GetFullPath($Path)
    $parent = [IO.Path]::GetDirectoryName($full)
    if (-not $parent -or (Test-AtmPathChain $parent).Status -ne 'OK') { return $false }
    if ($MustNotExist -and (Test-Path -LiteralPath $full)) { return $false }
    foreach ($b in $Inventory.Bases) {
        if ($full.StartsWith($b.Path + '\', [StringComparison]::OrdinalIgnoreCase) -or [string]::Equals($full, $b.Path, [StringComparison]::OrdinalIgnoreCase)) { return $false }
    }
    return $true
}
