# AgentTempManager ISOLATION ENGINE (0.3.x, docs/adr/ADR-0013; phase P3a: isolate one session root per run). Depends on
# Engine.Audit.ps1 and Engine.Clean.ps1, whose gates, plan check, revalidation, lock and log writer it reuses unchanged.
# No terminal output of its own: the plan is shown through a mandatory presenter callback and the confirmation is read
# through a mandatory reader. With the isolation gate closed (every distributed copy) it stops after the plan: it asks
# nothing, takes no lock, opens no log, creates no quarantine and moves nothing.
Set-StrictMode -Version 2.0

# ISOLATION GATE (0.3.x): real isolation is DISABLED. Invoke-AtmIsolate applies the target rule and every gate and
# presents the exact plan, then stops. There is deliberately no switch, environment variable, config file or UI option to
# change this: enabling isolation requires a code change in this administrator-owned, manifest-verified file, released
# under a specific authorization. Only the automated test suite flips it, inside its own process.
$script:AtmIsolationEnabled = $false

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
           -AcceptB1ResidualRisk; RECENT blocks (J-ISO-3 (a)); a fingerprint given with a path must still match;
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
        if (-not $okRisk -and ($g.Category -ne 'ELIGIBLE' -or $reasons.Count -gt 0)) { $rejected.Add([pscustomobject]@{ Path = $e.Path; Source = $e.Source; Reasons = $reasons }); continue }
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
            $m3 = @($invChk.Partitions | Where-Object { [string]::Equals($_.Path, $p.Path, [StringComparison]::Ordinal) -and $_.Kind -ne 'NotScanned' -and $_.Kind -ne 'BaseLooseFiles' })
            $changed = ($m3.Count -ne 1)
            if (-not $changed) { $changed = ((Get-AtmCleanPlanItemKey $m3[0]) -cne (Get-AtmCleanPlanItemKey $p)) }
            if (-not $changed) { $changed = (@(Get-AtmCleanGateRefusal -Gate (Test-AtmCandidate -Partition $m3[0] -Inventory $invChk -ForClean -RuntimeEvidence $rtChk -AcceptB1ResidualRisk:$acceptRisk) -Risk $risk).Count -gt 0) }
            $lc = Write-AtmIsolationRecord -Log $log -State $ls -Schema $script:AtmIsolateLogSchema -Type 'plan-check' -Fields ([ordered]@{ planId = $state.PlanId; matched = (-not $changed) })
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
    # result; Pending says which), FAILED, RESTORED; ABANDONED when the manifest is not this identity's.
    param($Records, [string]$OwnSid)
    $state = 'INCOMPLETE'; $pending = 'move'; $outcome = $null
    foreach ($r in @($Records)) {
        switch ([string]$r.type) {
            'move-intent' { $state = 'INCOMPLETE'; $pending = 'move' }
            'move-result' { $outcome = [string](Get-AtmRecordField $r 'outcome'); $pending = $null; $state = $(if ($outcome -ceq 'COMPLETE') { 'ISOLATED' } else { 'FAILED' }) }
            'reconcile' { if ([string](Get-AtmRecordField $r 'result') -ceq 'OK') { $state = 'ISOLATED'; $pending = $null } }
            'restore-intent' { $state = 'INCOMPLETE'; $pending = 'restore' }
            'restore-result' { $pending = $null; $outcome = [string](Get-AtmRecordField $r 'outcome'); $state = $(if ($outcome -ceq 'COMPLETE') { 'RESTORED' } elseif (Get-AtmRecordField $r 'moved') { 'FAILED' } else { 'ISOLATED' }) }
        }
    }
    $actor = [string](Get-AtmRecordField (Get-AtmRecordField $Records[0] 'actor') 'sid')
    if ($actor -cne $OwnSid) { $state = 'ABANDONED' }
    return [pscustomobject]@{ State = $state; Pending = $pending; LastOutcome = $outcome; ActorSid = $actor }
}

function Get-AtmQuarantineEntrySummary {
    # One entry folder: its manifest, derived state, the measurement its intent recorded and the one verified after the
    # move (no file names). A manifest that breaks section 7.3, or a payload incoherent with the last record (present
    # after a completed restore), gives State ENTRY_MANIFEST_INVALID: reported only, never restored.
    param([string]$Path, [string]$OwnSid)
    $id = [IO.Path]::GetFileName($Path)
    $s = [ordered]@{ Id = $id; Path = $Path; State = 'UNRECOGNIZED'; Problem = $null; Pending = $null; LastOutcome = $null; ActorSid = $null; TargetKind = $null; OriginalPath = $null
        CreatedUtc = $null; Files = $null; Dirs = $null; Bytes = $null; NewestWriteUtc = $null; Verified = $null; PayloadPresent = $false; Records = @() }
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
    return [pscustomobject]$s
}

function Get-AtmQuarantineList {
    <#
      quarantine list: read only. The entries of the quarantine root of the process user, each with its derived state;
      a folder that is not an entry, or is a reparse point, is listed as UNRECOGNIZED and never opened. Returns Root,
      Exists, RootProblem and Entries. A missing quarantine is not created.
    #>
    param([string]$Root = (Get-AtmQuarantineRootPath), [string]$OwnSid = (Get-AtmCurrentIdentity).Sid)
    $out = [ordered]@{ Root = $Root; Exists = $false; RootProblem = $null; Entries = @() }
    if (-not $Root -or -not [IO.Directory]::Exists($Root)) { return [pscustomobject]$out }
    $out.Exists = $true
    if (((New-Object IO.DirectoryInfo $Root).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { $out.RootProblem = 'QUARANTINE_REPARSE_POINT'; return [pscustomobject]$out }
    $own = $OwnSid
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($d in @((New-Object IO.DirectoryInfo $Root).GetDirectories() | Sort-Object Name)) {
        if (($d.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            $list.Add([pscustomobject]@{ Id = $d.Name; Path = $d.FullName; State = 'UNRECOGNIZED'; Problem = 'REPARSE_POINT'; Pending = $null; LastOutcome = $null; ActorSid = $null; TargetKind = $null; OriginalPath = $null
                    CreatedUtc = $null; Files = $null; Dirs = $null; Bytes = $null; NewestWriteUtc = $null; Verified = $null; PayloadPresent = $false; Records = @() })
            continue
        }
        $list.Add((Get-AtmQuarantineEntrySummary -Path $d.FullName -OwnSid $own))
    }
    $out.Entries = $list.ToArray()
    return [pscustomobject]$out
}

function Get-AtmQuarantineEntry {
    # quarantine inspect: read only. One entry by its id (the only input accepted: never a path, T-ISO-8). $null when
    # the id is not an entry id or no such entry exists.
    param([string]$Id, [string]$Root = (Get-AtmQuarantineRootPath), [string]$OwnSid = (Get-AtmCurrentIdentity).Sid)
    if ($Id -cnotmatch $script:AtmQuarantineEntryIdPattern -or -not $Root) { return $null }
    $p = Join-Path $Root $Id
    if (-not [IO.Directory]::Exists($p) -or ((New-Object IO.DirectoryInfo $p).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $null }
    return (Get-AtmQuarantineEntrySummary -Path $p -OwnSid $OwnSid)
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
      PAYLOAD_MISSING, ENTRY_MANIFEST_INVALID, NOT_VERIFIABLE (nothing to compare: FAILED, RESTORED, no intent),
      ENTRY_NOT_FOUND. For an INCOMPLETE entry, Reconcilable says whether a restore would reconcile it (section 8.3:
      payload present and equal to the intent, original path absent); only the restore records it.
    #>
    param([string]$Id, [string]$OwnSid = (Get-AtmCurrentIdentity).Sid)
    $e = Get-AtmQuarantineEntry -Id $Id -OwnSid $OwnSid
    if ($null -eq $e) { return [pscustomobject]@{ Id = $Id; Result = 'ENTRY_NOT_FOUND'; Reason = $null; State = $null; Reconcilable = $null } }
    if ($e.State -ceq 'ENTRY_MANIFEST_INVALID') { return [pscustomobject]@{ Id = $Id; Result = 'ENTRY_MANIFEST_INVALID'; Reason = $e.Problem; State = $e.State; Reconcilable = $null } }
    if ($null -eq $e.Files -or $e.State -ceq 'FAILED' -or $e.State -ceq 'RESTORED') { return [pscustomobject]@{ Id = $Id; Result = 'NOT_VERIFIABLE'; Reason = $e.State; State = $e.State; Reconcilable = $null } }
    $t = Test-AtmQuarantinePayload -Entry $e
    $rec = $null
    if ($e.State -ceq 'INCOMPLETE') { $rec = ($t.Result -ceq 'OK' -and $e.OriginalPath -and -not (Test-Path -LiteralPath $e.OriginalPath)) }
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
    elseif ($e.State -ceq 'FAILED') { $why.Add('ENTRY_FAILED') }
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
        if (-not [string]::Equals([IO.Path]::GetPathRoot($parent), [IO.Path]::GetPathRoot($e.Path), [StringComparison]::OrdinalIgnoreCase)) { $why.Add('MOVE_OTHER_VOLUME') }
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
