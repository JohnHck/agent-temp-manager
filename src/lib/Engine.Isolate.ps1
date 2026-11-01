# AgentTempManager ISOLATION ENGINE (0.3.x, docs/adr/ADR-0013; phase P2: plan only). Depends on Engine.Audit.ps1 and
# Engine.Clean.ps1, whose gates it reuses unchanged. No terminal output of its own: the plan is shown through a mandatory
# presenter callback. Nothing in this file moves, creates or removes anything: with the isolation gate closed (every
# distributed copy) it stops after the plan, and past the gate the move itself is a later phase (P3), so it stops there
# too. It asks nothing, takes no lock, opens no log and creates no quarantine.
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

function Invoke-AtmIsolate {
    <#
      Entry point of isolate (CLI). Plan only in this phase:
        1. syntax of every exact path (the clean allowlist rules), duplicates refused;
        2. a fresh inventory and one runtime collection (B2-1) for the plan;
        3. the 0.3.x target rule (Get-AtmIsolationTarget), then the same gates as clean (Test-AtmCandidate -ForClean, lock
           probe included): ELIGIBLE, or the B1 restricted exception per root (J-ISO-2 (b)) only past the gate with
           -AcceptB1ResidualRisk, exactly as clean; RECENT blocks (J-ISO-3 (a)); a fingerprint given with a path must still
           match;
        4. the plan id of the exact set (Get-AtmCleanPlanId) and the plan through -PlanPresenter;
        5. with the isolation gate closed: stop (ISOLAMENTO_REAL_DESABILITADO). Past the gate: stop as well
           (ISOLAMENTO_ALEM_DA_TRAVA_NAO_IMPLEMENTADO); the confirmed, locked and logged move is phase P3.
      -PlanPresenter scriptblock(verified, rejected, inventory, planId) that MUST display the exact plan. There is no
      confirmation reader: nothing is asked. Returns arrays only.
    #>
    [CmdletBinding()]
    param(
        [object[]]$Entries,
        [scriptblock]$PlanPresenter,
        [hashtable]$InventoryArgs = @{},
        [switch]$AcceptB1ResidualRisk
    )
    $rejected = New-Object System.Collections.Generic.List[object]
    $verified = New-Object System.Collections.Generic.List[object]
    $state = @{ Aborted = $null; PlanId = $null }
    $finish = { [pscustomobject]@{ Requested = @($Entries).Count; Rejected = $rejected.ToArray(); Verified = $verified.ToArray(); PlanId = $state.PlanId; Aborted = $state.Aborted } }
    if (@($Entries).Count -eq 0) { $state.Aborted = 'ALLOWLIST_VAZIA'; return (& $finish) }
    if (-not $PlanPresenter) { $state.Aborted = 'SEM_APRESENTACAO'; return (& $finish) }

    $syntaxOk = New-Object System.Collections.Generic.List[object]
    foreach ($e in $Entries) {
        $why = Test-AtmAllowListPathSyntax $e.Path
        if ($why) { $rejected.Add([pscustomobject]@{ Path = $e.Path; Source = $e.Source; Reasons = @($why) }) } else { $syntaxOk.Add($e) }
    }
    # B1 restricted exception: considered only past the isolation gate, as clean considers it only past the deletion gate.
    $acceptRisk = ([bool]$AcceptB1ResidualRisk -and $script:AtmIsolationEnabled)
    $riskKeys = New-Object System.Collections.Generic.List[string]
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
        if ($okRisk) { foreach ($rk in @($g.B1Risk.Keys)) { $riskKeys.Add($rk) } }
    }
    if ($verified.Count -eq 0) { $state.Aborted = 'NENHUM_CAMINHO_ISOLAVEL'; return (& $finish) }

    # The plan id identifies the exact set presented (paths and their statistics, and accepted process identities).
    $state.PlanId = Get-AtmCleanPlanId -RunId ([guid]::NewGuid().ToString()) -Parts $verified.ToArray() -RiskKeys @($riskKeys | Sort-Object -Unique)
    & $PlanPresenter $verified.ToArray() $rejected.ToArray() $inv $state.PlanId
    if (-not $script:AtmIsolationEnabled) { $state.Aborted = 'ISOLAMENTO_REAL_DESABILITADO'; return (& $finish) }
    # Past the gate (the suite only, in its own process): the confirmation, the lock, the log, the quarantine and the
    # move are phase P3. Until then the run stops here, after the plan, with nothing changed (fail closed).
    $state.Aborted = 'ISOLAMENTO_ALEM_DA_TRAVA_NAO_IMPLEMENTADO'
    return (& $finish)
}
