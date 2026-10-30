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
    return [pscustomobject]@{ Category = $cat; Reasons = @(@($g.Reasons) + @($refs | ForEach-Object { Format-AtmRuntimeRefusal $_ })); Requirements = $g.Requirements; Probe = $g.Probe; RuntimeReasons = $refs }
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

    if ($p.Class -in @('ACTIVE_EVIDENCE', 'RECENT')) { $reasons.Add((Get-AtmText 'reason.class' $p.Class)) }
    foreach ($f in $p.Flags) { if ($script:AtmHardFlags -contains $f) { $reasons.Add($f) } }
    if ($reasons.Count -gt 0) { return [pscustomobject]@{ Category = 'BLOCKED'; Reasons = $reasons.ToArray(); Requirements = @(); Probe = $null } }

    $soft = @($p.Flags | Where-Object { $script:AtmSoftFlags -contains $_ })
    if ($soft.Count -gt 0 -or $p.Class -ne 'ORPHAN_SUSPECTED') {
        foreach ($s in $soft) { $reasons.Add($s) }
        if ($p.Class -ne 'ORPHAN_SUSPECTED') { $reasons.Add((Get-AtmText 'reason.class' $p.Class)) }
        return [pscustomobject]@{ Category = 'INVESTIGATE'; Reasons = $reasons.ToArray(); Requirements = @(); Probe = $null }
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
    return [pscustomobject]@{ Category = $cat; Reasons = $reasons.ToArray(); Requirements = $reqs.ToArray(); Probe = $probe }
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
        $LogWriter
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
        -ConfirmationReader scriptblock(phrase) returning the text typed by the operator. The phrase is
                            generated here; anything but an exact ordinal match aborts.
        -LogFile            T1: a NEW file outside the audited directories. Required once real deletion is enabled
                            (LOG_REQUIRED otherwise); with the release gate closed it is neither required, created nor
                            opened, and the plan-only flow is unchanged.
      -InventoryArgs is splatted into every Invoke-AtmInventory call (tests / CLI self markers).
      -DeleteTreeImpl, -PathPresenceImpl and -LogWriter are test seams, never passed by the CLI: a stand-in deleter (it
      deletes nothing), a stand-in presence check and an object with AppendLine/Close/Dispose. They are reached only past
      the release gate, so they cannot make a run with the gate closed delete or log anything.
      Aborted: the run ended before any call to the deleter. StoppedBy: it ended after at least one call; anything but a
      complete, verified deletion (a refusal, a partial deletion, an exception, a verification that is not conclusive) or
      a log failure stops the run before the next root. LogErrors lists every log failure (Stage, OpId, Code) without
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
        [string]$RefusedBy,
        [string]$LockReleaseError
    )
    $rejected = New-Object System.Collections.Generic.List[object]
    $verified = New-Object System.Collections.Generic.List[object]
    $deleted = New-Object System.Collections.Generic.List[object]
    $skipped = New-Object System.Collections.Generic.List[object]
    $logErrors = New-Object System.Collections.Generic.List[object]
    $state = @{ Confirmed = $false; Aborted = $null; Stopped = $null; Post = $null; Phrase = $null; RunId = $null; RecSeq = 0; LogCreated = $false }
    $finish = {
        [pscustomobject]@{
            Requested = @($Entries).Count; Rejected = $rejected.ToArray(); Verified = $verified.ToArray(); Phrase = $state.Phrase
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
        $lc = Write-AtmCleanLogRecord -Log $log -State $state -Type 'run-start' -Fields ([ordered]@{ tool = $script:AtmVersion; user = $inv.Identity.Name; sid = $inv.Identity.Sid; elevated = [bool]$inv.Identity.IsAdmin; planned = $plan.Count })
        $stage = 'run-start'
        if ($null -eq $lc) {
            $stage = 'plan'
            foreach ($item in $plan) {
                $p = $item.Part
                $lc = Write-AtmCleanLogRecord -Log $log -State $state -Type 'plan' -Fields ([ordered]@{ opId = $item.OpId; path = $p.Path; fingerprint = $p.Fingerprint; files = $p.Files; dirs = $p.Dirs; bytes = $p.Bytes })
                if ($null -ne $lc) { break }
            }
        }
        if ($null -ne $lc) { & $logFail $stage $null $lc; $state.Aborted = 'LOG_WRITE_FAILED'; return (& $finish) }

        $typed = & $ConfirmationReader $state.Phrase
        $accepted = (($typed -is [string]) -and [string]::Equals($typed, $state.Phrase, [StringComparison]::Ordinal))
        $lc = Write-AtmCleanLogRecord -Log $log -State $state -Type 'confirmation' -Fields ([ordered]@{ accepted = $accepted })
        if ($null -ne $lc) { & $logFail 'confirmation' $null $lc }
        if (-not $accepted) { $state.Aborted = 'CONFIRMACAO_AUSENTE_OU_DIVERGENTE' }
        elseif ($null -ne $lc) { $state.Aborted = 'LOG_WRITE_FAILED' }
        else {
            $state.Confirmed = $true
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
                    $skipped.Add([pscustomobject]@{ Path = $p.Path; Reasons = $why })
                    $lc = Write-AtmCleanLogRecord -Log $log -State $state -Type 'skip' -Fields ([ordered]@{ opId = $item.OpId; path = $p.Path; reasons = @($why) })
                    if ($null -ne $lc) { & $logFail 'skip' $item.OpId $lc; & $halt 'LOG_WRITE_FAILED'; break }
                    continue
                }
                # The intent is written and flushed BEFORE the deleter is called; without it that root is never started.
                $lc = Write-AtmCleanLogRecord -Log $log -State $state -Type 'intent' -Fields ([ordered]@{ opId = $item.OpId; path = $c.Path; fingerprint = $c.Fingerprint; files = $c.Files; dirs = $c.Dirs; bytes = $c.Bytes })
                if ($null -ne $lc) { & $logFail 'intent' $item.OpId $lc; & $halt 'LOG_INTENT_FAILED'; break }
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
                if ($null -ne $lc) { & $logFail 'result' $row.OpId $lc; & $halt 'LOG_RESULT_FAILED'; break }
                # Anything but a complete, verified deletion stops the run before the next root.
                if ($outcome -cne 'COMPLETE') { & $halt ('STOPPED_AFTER_' + $outcome); break }
            }

            # 20: post-clean read-only audit.
            $post = @{} + $InventoryArgs
            $post['NoProgress'] = $true
            $state.Post = Invoke-AtmInventory @post
        }
        # run-end only while the log has not failed (after a failure it writes nothing more). Neither a failed run-end
        # nor a failed close replaces the main code; with none, they make the run incomplete.
        if ($logErrors.Count -eq 0) {
            $lc = Write-AtmCleanLogRecord -Log $log -State $state -Type 'run-end' -Fields ([ordered]@{ results = $deleted.Count; complete = @($deleted | Where-Object { $_.Outcome -ceq 'COMPLETE' }).Count; skipped = $skipped.Count; stoppedBy = $(if ($state.Stopped) { $state.Stopped } else { $state.Aborted }) })
            if ($null -ne $lc) { & $logFail 'run-end' $null $lc; if (-not $state.Aborted -and -not $state.Stopped) { & $halt 'LOG_END_FAILED' } }
        }
        $cc = $log.Close()
        if ($null -ne $cc) { & $logFail 'close' $null $cc; if (-not $state.Aborted -and -not $state.Stopped) { & $halt 'LOG_CLOSE_FAILED' } }
        return (& $finish)
    } finally { if ($null -ne $log) { try { $log.Dispose() } catch { $null = $_ } } }
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
