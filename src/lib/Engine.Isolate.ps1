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
