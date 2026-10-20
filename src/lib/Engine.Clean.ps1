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

function Test-AtmCandidate {
    <#
      Gates applied (in order) to one inventoried partition. Returns Category:
        BLOCKED | INVESTIGATE | ELIGIBLE, plus Reasons and Requirements.
      ELIGIBLE means "technically eligible for a human decision"; clean re-runs this immediately before deleting.
    #>
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
    param($Inventory, [switch]$IncludeOtherUsers)
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($p in $Inventory.Partitions) {
        if ($p.Kind -eq 'NotScanned') { continue }
        $g = Test-AtmCandidate -Partition $p -Inventory $Inventory -IncludeOtherUsers:$IncludeOtherUsers
        $rows.Add([pscustomobject]@{ Partition = $p; Gate = $g })
    }
    return $rows.ToArray()
}

function Invoke-AtmClean {
    <#
      Fail-closed assisted deletion. The engine owns every safety decision; callers only provide:
        -PlanPresenter      scriptblock(verified, rejected, inventory) that MUST display the exact plan
                            (including "NADA FOI APAGADO AINDA"). Without it nothing proceeds.
        -ConfirmationReader scriptblock(phrase) returning the text typed by the operator. The phrase is
                            generated here; anything but an exact ordinal match aborts.
      -InventoryArgs is splatted into every Invoke-AtmInventory call (tests / CLI self markers).
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
        [string]$LogFile
    )
    $rejected = New-Object System.Collections.Generic.List[object]
    $verified = New-Object System.Collections.Generic.List[object]
    $deleted = New-Object System.Collections.Generic.List[object]
    $skipped = New-Object System.Collections.Generic.List[object]
    $state = @{ Confirmed = $false; Aborted = $null; Post = $null; Phrase = $null }
    $finish = {
        [pscustomobject]@{
            Requested = @($Entries).Count; Rejected = $rejected.ToArray(); Verified = $verified.ToArray(); Phrase = $state.Phrase
            Confirmed = $state.Confirmed; Deleted = $deleted.ToArray(); Skipped = $skipped.ToArray(); PostInventory = $state.Post; Aborted = $state.Aborted
        }
    }
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
    foreach ($e in $syntaxOk) {
        $k = $e.Path.ToLowerInvariant()
        if ($seen.ContainsKey($k)) { $rejected.Add([pscustomobject]@{ Path = $e.Path; Source = $e.Source; Reasons = @('DUPLICADO_NA_ALLOWLIST') }); continue }
        $seen[$k] = $true
        $m = @($inv.Partitions | Where-Object { [string]::Equals($_.Path, $e.Path, [StringComparison]::OrdinalIgnoreCase) -and $_.Kind -ne 'BaseLooseFiles' })
        if ($m.Count -ne 1) { $rejected.Add([pscustomobject]@{ Path = $e.Path; Source = $e.Source; Reasons = @('FORA_DAS_ROOTS_PERMITIDAS (' + (Get-AtmText 'reason.notRoot') + ')') }); continue }
        $p = $m[0]
        if (-not [string]::Equals($p.Path, $e.Path, [StringComparison]::Ordinal)) { $rejected.Add([pscustomobject]@{ Path = $e.Path; Source = $e.Source; Reasons = @('CAIXA_DIVERGENTE (' + (Get-AtmText 'reason.useExactly' $p.Path) + ')') }); continue }
        $g = Test-AtmCandidate -Partition $p -Inventory $inv -IncludeOtherUsers:$IncludeOtherUsers -ForClean
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
    $typed = & $ConfirmationReader $state.Phrase
    if (-not ($typed -is [string]) -or -not [string]::Equals($typed, $state.Phrase, [StringComparison]::Ordinal)) {
        $state.Aborted = 'CONFIRMACAO_AUSENTE_OU_DIVERGENTE'
        return (& $finish)
    }
    $state.Confirmed = $true

    # 18-19: per-path revalidation immediately before deleting; only still-eligible paths are deleted.
    foreach ($p in $verified) {
        if ($BeforeDeleteHook) { & $BeforeDeleteHook $p }
        $args2 = @{} + $InventoryArgs
        $args2['OnlyRootPath'] = $p.Path
        $args2['NoProgress'] = $true
        $re = Invoke-AtmInventory @args2
        $cur = @($re.Partitions | Where-Object { [string]::Equals($_.Path, $p.Path, [StringComparison]::OrdinalIgnoreCase) -and $_.Kind -ne 'NotScanned' -and $_.Kind -ne 'BaseLooseFiles' })
        $why = @()
        if ($cur.Count -ne 1) { $why += 'DESAPARECEU_OU_AMBIGUO_NA_REVALIDACAO' }
        else {
            $c = $cur[0]
            if ($c.Fingerprint -ne $p.Fingerprint) { $why += "ALTERADO_APOS_CONFIRMACAO (fingerprint $($p.Fingerprint) -> $($c.Fingerprint))" }
            $g = Test-AtmCandidate -Partition $c -Inventory $re -IncludeOtherUsers:$IncludeOtherUsers -ForClean
            if ($g.Category -ne 'ELIGIBLE') { $why += $g.Reasons }
        }
        if ($why.Count -gt 0) { $skipped.Add([pscustomobject]@{ Path = $p.Path; Reasons = $why }); continue }
        # The deleter re-checks, under its own handle pins, that the tree still matches what was just validated.
        $d = [AgentTempManager.AtmDeleter]::DeleteTree($c.Path, $c.Files, $c.Dirs, $c.Bytes, $c.NewestWriteTimeUtc.Ticks, $null)
        $gone = $false
        # Any other error: removal is not verified (Verified = false), never assumed.
        try { [void][IO.File]::GetAttributes($p.Path) } catch [IO.FileNotFoundException] { $gone = $true } catch [IO.DirectoryNotFoundException] { $gone = $true } catch { $gone = $false }
        $deleted.Add([pscustomobject]@{ Path = $p.Path; Bytes = $p.Bytes; Completed = $d.Completed; Verified = $gone; FilesDeleted = $d.FilesDeleted; DirsDeleted = $d.DirsDeleted; FilesPlanned = $d.FilesPlanned; DirsPlanned = $d.DirsPlanned; AbortReason = $d.AbortReason; FailedAt = $d.FailedAt })
        if ($LogFile) {
            $rec = [ordered]@{ utc = [datetime]::UtcNow.ToString('o'); user = $inv.Identity.Name; path = $p.Path; bytes = $p.Bytes; fingerprint = $p.Fingerprint; completed = $d.Completed; verifiedGone = $gone; abort = $d.AbortReason }
            Add-Content -LiteralPath $LogFile -Value ($rec | ConvertTo-Json -Compress) -Encoding UTF8
        }
    }

    # 20: post-clean read-only audit.
    $post = @{} + $InventoryArgs
    $post['NoProgress'] = $true
    $state.Post = Invoke-AtmInventory @post
    return (& $finish)
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
