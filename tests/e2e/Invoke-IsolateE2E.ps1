<#
.SYNOPSIS
  0.3.x ISO-P5a: the REAL isolation, restore and purge, end to end, on roots this script plants itself, on a DISPOSABLE
  machine only (CI).
.DESCRIPTION
  CI-only harness, never shipped (tools\Build-Release.ps1 leaves it out of the release archive and refuses an archive
  that contains it; the install e2e checks that it is absent from the package). It loads the INSTALLED engine into its
  own process and opens the isolation gate and the purge gate there only, in memory, like tests\Run-Tests.ps1 does for
  its sandbox: the installed files, the package and the sources keep the single assignment of every gate to $false
  (the six installed gates and the SHA-256 of every installed file are checked before and after). The deletion gate of
  clean is never opened. It uses the real mover (AtmMover), the real deleter of the purge (AtmDeleter), the T1 logs in
  real files, the real manifests, the real B8 lock name and the real revalidation; only the console observation is the
  existing test seam (AtmCleanConsoleSource, logged as TEST_SEAM): every confirmation is AUTOMATED by this script and
  is never a human acceptance.
  Containment: everything it can hand to isolate is under a run root it creates atomically in this run (refused if the
  name exists), with a protected DACL, and each planted root carries this run's nonce; every entry is checked against
  both before isolate is called and again by the plan presenter, before any question. Restore destinations are checked
  to be under this run's base, and purge only takes entries this run created. Real roots of the machine are never
  entries. The quarantine is the real one of the account (%LOCALAPPDATA%\AgentTempManager\Q); its entries stay there as
  the trail (restored and purged entries keep their manifest). Recency is SIMULATED: the write times of the planted
  roots and transcripts are set back (recorded as recencySimulated with the shift); RECENT itself (72 h) is unchanged.
  Each case has a scope of its own, so that the restore's check of the destination's siblings sees only that case.
  Leg A: a non-elevated standard user (B1 restricted exception, -AcceptB1ResidualRisk). Leg B: the elevated runner
  account (ELIGIBLE only if the process coverage measured here is complete; otherwise NOT_TESTED, never forced).
  Writes ONLY a summary (codes, counts, labels; no path, account name or SID) to -SummaryFile; the raw T1 logs stay in
  the run root and the manifests in the quarantine, never uploaded. Exit code = number of failed cases (NOT_TESTED is
  neither a pass nor a failure).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('A', 'B')][string]$Leg,
    [Parameter(Mandatory)][string]$InstallDir,
    [Parameter(Mandatory)][string]$SummaryFile,
    [Parameter(Mandatory)][string]$WorkDir,
    [switch]$DisposableMachine
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# Accident guard only (these variables can be set by anyone): the containment is the run root and the nonce below.
if (-not $DisposableMachine -and -not ($env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -eq 'github-hosted')) {
    throw 'Recusado: este teste move e expurga de verdade raizes que ele mesmo planta; so roda em maquina descartavel (runner do GitHub) ou com -DisposableMachine.'
}

$me = [Security.Principal.WindowsIdentity]::GetCurrent()
$mySid = $me.User.Value
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($me)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$shellExe = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
$nonce = [guid]::NewGuid().ToString('N')
$runRoot = Join-Path $env:SystemDrive ('ATM-E2E-ISO-' + $Leg + '-' + $nonce.Substring(0, 12))
$shiftHours = 120
# One scope (slug) per case: the restore refuses when a sibling of its destination is RECENT or ACTIVE_EVIDENCE.
$labels = @('free', 'conflict', 'purge')
$ctx = @{ Roots = @{}; Logs = (New-Object System.Collections.Generic.List[string]); EnvSet = @{}; Eligible = $false; EntryIds = (New-Object System.Collections.Generic.List[string]); Iso = @{}; Purged = $false; ConflictTouched = $false }
$summary = [ordered]@{
    schema = 'atm.e2e-isolate/1'; phase = 'ISO-P5a'; leg = $Leg; startedUtc = [datetime]::UtcNow.ToString('o')
    shell = "$($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)"; arch = $env:PROCESSOR_ARCHITECTURE
    elevated = [bool]$isAdmin; confirmation = 'AUTOMATED_BY_HARNESS (console: TEST_SEAM); not a human acceptance'
    recencySimulated = $true; recencyShiftHours = $shiftHours; recentHoursInProduct = $null
    processCoverage = [ordered]@{ complete = $null; uninspectable = $null }; quarantine = [ordered]@{ existedBefore = $null; entriesCreated = 0 }
    cases = [ordered]@{}
}
[void][IO.Directory]::CreateDirectory($WorkDir)

function Protect-Text([string]$Text) {
    # Defense in depth before the artifact sanitizer: no SID, run root, profile, temp, account or machine name.
    if (-not $Text) { return $Text }
    $t = [regex]::Replace($Text, 'S-1-5-21-[0-9-]+', '<sid>')
    foreach ($pair in @(@($runRoot, '<run-root>'), @($WorkDir, '<work>'), @($InstallDir, '<install>'), @([IO.Path]::GetTempPath().TrimEnd('\'), '<temp>'), @($env:LOCALAPPDATA, '<localappdata>'), @($env:USERPROFILE, '<profile>'), @($env:USERNAME, '<account>'), @($env:COMPUTERNAME, '<machine>'))) {
        if ($pair[0] -and $pair[0].Length -ge 3) { $t = [regex]::Replace($t, [regex]::Escape($pair[0]), $pair[1], 'IgnoreCase') }
    }
    return $t
}
$script:notTested = $false
function Case([string]$Id, [scriptblock]$Body) {
    $script:notTested = $false
    try {
        $d = & $Body
        $status = $(if ($script:notTested) { 'NOT_TESTED' } else { 'PASS' })
        $summary.cases[$Id] = [ordered]@{ status = $status; detail = (Protect-Text "$d") }
    } catch { $summary.cases[$Id] = [ordered]@{ status = 'FAIL'; detail = (Protect-Text $_.Exception.Message) } }
    $s = $summary.cases[$Id]
    [Console]::Out.WriteLine(("[{0}] ISO-{1} {2} {3}" -f $s.status, $Leg, $Id, $s.detail))
}
function Assert([bool]$Cond, [string]$Msg) { if (-not $Cond) { throw $Msg } }
function NotTested([string]$Why) { $script:notTested = $true; return $Why }
function Get-Codes($Reasons) { return ((@($Reasons | ForEach-Object { ([string]$_ -split '[\s:(]')[0] })) -join ',') }
# The refusal codes of a restore or purge plan (no plan when the run stopped before it: StrictMode refuses $null.Reasons).
function Get-PlanCodes($Res) { if ($null -ne $Res.Plan) { return (Get-Codes $Res.Plan.Reasons) } else { return '-' } }

function Get-FileSha([string]$Path) {
    $s = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
    try { $h = [Security.Cryptography.SHA256]::Create(); try { return ([BitConverter]::ToString($h.ComputeHash($s))).Replace('-', '') } finally { $h.Dispose() } } finally { $s.Dispose() }
}
function Get-Snapshot([string]$Root, [long]$HashMax, [int]$MaxEntries = 200000) {
    # Relative path -> D (directory), R (reparse point, never traversed), F|length|write ticks|SHA-256 ('-' above
    # HashMax, 'UNREADABLE' when it cannot be opened), X (directory not enumerable). A missing root is an empty map.
    $map = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase)
    if (-not [IO.Directory]::Exists($Root)) { return $map }
    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($Root)
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        $relDir = $dir.Substring($Root.Length).TrimStart('\')
        $items = $null
        try { $items = (New-Object IO.DirectoryInfo($dir)).GetFileSystemInfos() } catch { $map[$relDir + '\*'] = 'X'; continue }
        foreach ($i in $items) {
            if ($map.Count -ge $MaxEntries) { throw 'SNAPSHOT_TOO_LARGE' }
            $rel = $i.FullName.Substring($Root.Length).TrimStart('\')
            if (($i.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { $map[$rel] = 'R'; continue }
            if (($i.Attributes -band [IO.FileAttributes]::Directory) -ne 0) { $map[$rel] = 'D'; $stack.Push($i.FullName); continue }
            $sha = '-'
            if ($i.Length -le $HashMax) { try { $sha = Get-FileSha $i.FullName } catch { $sha = 'UNREADABLE' } }
            $map[$rel] = 'F|{0}|{1}|{2}' -f $i.Length, $i.LastWriteTimeUtc.Ticks, $sha
        }
    }
    return $map
}
function Compare-Snapshot($Before, $After) {
    $r = [ordered]@{ Removed = (New-Object System.Collections.Generic.List[string]); Added = (New-Object System.Collections.Generic.List[string]); Changed = (New-Object System.Collections.Generic.List[string]) }
    foreach ($k in $Before.Keys) { if (-not $After.ContainsKey($k)) { $r.Removed.Add($k) } elseif ($After[$k] -cne $Before[$k]) { $r.Changed.Add($k) } }
    foreach ($k in $After.Keys) { if (-not $Before.ContainsKey($k)) { $r.Added.Add($k) } }
    return $r
}
function Get-DiffCount($D) { return ($D.Removed.Count + $D.Added.Count + $D.Changed.Count) }
function Test-Under([string]$Rel, [string]$Prefix) { return ([string]::Equals($Rel, $Prefix, [StringComparison]::OrdinalIgnoreCase) -or $Rel.StartsWith($Prefix + '\', [StringComparison]::OrdinalIgnoreCase)) }

# The six gates of the installation: each a single assignment to $false in its installed file.
$gateFiles = [ordered]@{ AtmRealDeletionEnabled = 'lib\Engine.Clean.ps1'; AtmWorktreeDiagnosticsEnabled = 'lib\Engine.Diagnose.ps1'; AtmHandleDiagnosticsEnabled = 'lib\Engine.Diagnose.ps1'; AtmDiagnoseExportEnabled = 'lib\Report.ps1'; AtmIsolationEnabled = 'lib\Engine.Isolate.ps1'; AtmQuarantinePurgeEnabled = 'lib\Engine.Isolate.ps1' }
function Get-InstalledGateProblems {
    return @(foreach ($g in $gateFiles.Keys) {
            $t = [IO.File]::ReadAllText((Join-Path $InstallDir $gateFiles[$g]))
            if (-not ([regex]::Matches($t, ('\$script:' + $g + '\s*=')).Count -eq 1 -and $t -match ('(?m)^\$script:' + $g + ' = \$false\r?$'))) { $g }
        })
}
function Invoke-InstalledVerify {
    $null = & (Join-Path $env:SystemRoot 'System32\cmd.exe') /c "`"$(Join-Path $InstallDir 'bin\agent-temp.cmd')`" verify" 2>&1
    return $LASTEXITCODE
}

# ---------------------------------------------------------------------------------------------- before loading
Case 'identity' {
    if ($Leg -eq 'A') { Assert (-not $isAdmin) 'perna A exige token nao elevado (usuario padrao)' } else { Assert $isAdmin 'perna B exige a conta elevada do runner' }
    $(if ($isAdmin) { 'elevated administrator' } else { 'standard user, not elevated' })
}
Case 'installed-before' {
    $bad = Get-InstalledGateProblems
    Assert ($bad.Count -eq 0) "travas instaladas que nao sao uma unica atribuicao `$false: $($bad -join ',')"
    $v = Invoke-InstalledVerify
    Assert ($v -eq 0) "agent-temp verify exit $v"
    $ctx.InstallBefore = Get-Snapshot $InstallDir ([long]::MaxValue)
    "verify 0; six installed gates `$false (single assignment each); $($ctx.InstallBefore.Count) installed entries hashed"
}
if ($summary.cases['identity'].status -ne 'PASS' -or $summary.cases['installed-before'].status -ne 'PASS') {
    [IO.File]::WriteAllText($SummaryFile, ($summary | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
    exit 1
}

# The installed engine, in the order of the CLI (agent-temp.ps1). The native library is loaded by the engine only if its
# SHA-256 matches the installed manifest.
$lib = Join-Path $InstallDir 'lib'
. (Join-Path $lib 'Engine.Audit.ps1')
Set-AtmLanguage -Requested 'en-US'
foreach ($pf in @(Get-ChildItem -LiteralPath (Join-Path $InstallDir 'providers') -Filter '*.ps1' -File | Sort-Object Name)) { . $pf.FullName }
. (Join-Path $lib 'Engine.Clean.ps1')
. (Join-Path $lib 'Engine.Isolate.ps1')
. (Join-Path $lib 'Engine.Diagnose.ps1')
$loaded = [ordered]@{ AtmIsolationEnabled = $script:AtmIsolationEnabled; AtmQuarantinePurgeEnabled = $script:AtmQuarantinePurgeEnabled; AtmRealDeletionEnabled = $script:AtmRealDeletionEnabled }
# In memory, in this process only (the installed files are unchanged; checked again at the end). The deletion gate of
# clean stays closed: the purge reads only its own gate.
$script:AtmIsolationEnabled = $true
$script:AtmQuarantinePurgeEnabled = $true
$script:AtmCleanConsoleSource = { $true }
$summary.recentHoursInProduct = $script:AtmRecentHours
$ia = @{ SelfMarkers = @((Join-Path $InstallDir 'agent-temp.ps1'), (Join-Path $InstallDir 'bin\agent-temp.cmd')); ConfigDir = (Join-Path $InstallDir 'config'); NoProgress = $true }
$qRoot = Get-AtmQuarantineRootPath
$qArea = $(if ($qRoot) { [IO.Path]::GetDirectoryName($qRoot) } else { $null })

function Assert-Entry([string]$Path) {
    # Containment: canonical, under this run's base, the nonce of this run, no reparse point in the chain.
    Assert ([string]::Equals([IO.Path]::GetFullPath($Path), $Path, [StringComparison]::Ordinal)) 'entrada nao canonica'
    Assert ($Path.StartsWith($ctx.Base + '\', [StringComparison]::OrdinalIgnoreCase)) 'entrada fora da base desta execucao'
    $nf = Join-Path $Path 'ATM-E2E-NONCE.txt'
    Assert ((Test-Path -LiteralPath $nf -PathType Leaf) -and [IO.File]::ReadAllText($nf) -ceq $nonce) 'entrada sem o nonce desta execucao'
    Assert-NoReparseChain $Path
}
function Assert-NoReparseChain([string]$Path) {
    $p = $Path
    while ($p.Length -gt $runRoot.Length) {
        Assert (([IO.File]::GetAttributes($p) -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'reparse point na cadeia da entrada'
        $p = [IO.Path]::GetDirectoryName($p)
    }
}
# Presenters: they print nothing (anything they returned would reach the engine's output). Each re-checks containment
# BEFORE any question or move: a throw here ends the run with nothing moved or purged.
$isoPresenter = { param($verified, $rejected, $inventory, $planId) foreach ($v in @($verified)) { Assert-Entry ([string]$v.Path) } }
$rstPresenter = {
    param($plan, $inventory, $planId)
    if ($null -ne $plan.Destination -and -not ([string]$plan.Destination).StartsWith($ctx.Base + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'destino da restauracao fora da base desta execucao' }
}
$purPresenter = {
    param($plan, $inventory, $planId, $phrase)
    if ($null -ne $plan.Entry -and -not $ctx.EntryIds.Contains([string]$plan.Entry.Id)) { throw 'entrada da quarentena nao criada nesta execucao' }
}

function New-Operator {
    # Automated answers: the exact phrase generated by the engine for every step (risk, confirm, restore, alternative,
    # task, purge); for the content decision of the purge the last choice (nothing needed: the content is synthetic).
    $st = @{ Calls = (New-Object System.Collections.Generic.List[string]) }
    $st.Reader = {
        param($phrase, $kind, $rootPath, $choices, $info)
        $st.Calls.Add([string]$kind)
        if ($kind -ceq 'results') { $c = @($choices); return [string]$c[$c.Count - 1] }
        return [string]$phrase
    }.GetNewClosure()
    return $st
}
function Read-E2ELog([string]$Path) {
    $t = (New-Object Text.UTF8Encoding($false, $true)).GetString([IO.File]::ReadAllBytes($Path))
    return @($t.Split([char]10) | Where-Object { $_ -ne '' } | ForEach-Object { $_ | ConvertFrom-Json })
}
function Get-Types($Records) { return ((@($Records | ForEach-Object { $_.type })) -join ',') }
function Assert-Sequence($Records, [string]$Id, [string]$What) {
    for ($i = 0; $i -lt @($Records).Count; $i++) { Assert ([int]$Records[$i].recSeq -eq $i + 1) "$What`: recSeq fora de ordem" }
    Assert (@($Records | Where-Object { [string]$_.id -cne $Id }).Count -eq 0) "$What`: id divergente"
}
function New-E2ELogPath([string]$Name) { $ctx.Logs.Add($Name); return (Join-Path $ctx.LogDir $Name) }
$interaction = @{ Caller = 'E2E'; ConsoleRequired = $true }

function Invoke-E2EIsolate([string[]]$Paths, [string]$LogName, [switch]$NoRisk, [scriptblock]$Hook) {
    $entries = @(foreach ($p in $Paths) { [pscustomobject]@{ Source = 'e2e-iso'; Path = $p; Fingerprint = $null } })
    $op = New-Operator
    $a = @{ Entries = $entries; PlanPresenter = $isoPresenter; ConfirmationReader = $op.Reader; InventoryArgs = $ia; LogFile = (New-E2ELogPath $LogName); Interaction = $interaction }
    if ($Leg -eq 'A' -and -not $NoRisk) { $a['AcceptB1ResidualRisk'] = $true }
    if ($Hook) { $a['BeforeMoveHook'] = $Hook }
    $res = Invoke-AtmIsolate @a
    return [pscustomobject]@{ Res = $res; Log = $a.LogFile; Calls = $op.Calls }
}
function Invoke-E2EIsolateChurn([string]$Label, [string]$LogBase, [scriptblock]$Hook) {
    # Up to 3 complete, fresh runs. PLAN_CHANGED_BEFORE_EXECUTION and REVALIDATION_REFUSED are the engine's fail-closed
    # refusals when the set changed after the plan (with the B1 exception: a process identity not inspectable that was
    # not in the plan); nothing is moved then. Each refusal is explained by comparing the identities recorded in the
    # log's plan record with a fresh inventory; Exhausted means every attempt was refused.
    $path = $ctx.Roots[$Label].Path
    Assert-Entry $path
    $churn = New-Object System.Collections.Generic.List[object]
    for ($n = 1; $n -le 3; $n++) {
        $c = Invoke-E2EIsolate -Paths @($path) -LogName "$LogBase-$n.jsonl" -Hook $Hook
        if ($c.Res.Aborted -cne 'PLAN_CHANGED_BEFORE_EXECUTION' -and $c.Res.Aborted -cne 'REVALIDATION_REFUSED') {
            return [pscustomobject]@{ Res = $c.Res; Log = $c.Log; Calls = $c.Calls; Attempts = $n; Churn = $churn.ToArray(); Exhausted = $false }
        }
        Assert (@($c.Res.Results).Count -eq 0 -and $null -eq $c.Res.EntryId -and (Test-Path -LiteralPath $path)) 'algo movido numa execucao recusada antes do mover'
        $recs = Read-E2ELog $c.Log
        $planKeys = @($recs | Where-Object { $_.type -ceq 'plan' } | ForEach-Object { @($_.uninspectableKeys) } | Where-Object { $_ })
        $skip = (@($recs | Where-Object { $_.type -ceq 'skip' } | ForEach-Object { Get-Codes $_.reasons }) -join ';')
        $nowKeys = @((Get-AtmUninspectableKeys (Invoke-AtmInventory @ia)).Keys)
        $churn.Add([pscustomobject]@{ Attempt = $n; Code = [string]$c.Res.Aborted; Skip = $skip; NewIdentities = @($nowKeys | Where-Object { $planKeys -notcontains $_ }).Count; PlanIdentities = $planKeys.Count })
    }
    return [pscustomobject]@{ Res = $null; Log = $null; Calls = $null; Attempts = 3; Churn = $churn.ToArray(); Exhausted = $true }
}
function Get-ChurnText($Churn) { return ((@($Churn | ForEach-Object { "attempt $($_.Attempt): $($_.Code)$(if ($_.Skip) { ' [' + $_.Skip + ']' }), $($_.NewIdentities) new uninspectable process identities (plan had $($_.PlanIdentities))" })) -join '; ') }
function Resolve-Exhausted($C) {
    # Every attempt refused before the mover: NOT_TESTED only when each refusal is explained by new identities observed
    # (process churn on this runner); otherwise the refusal is unexplained and the case fails.
    $txt = Get-ChurnText $C.Churn
    if (@($C.Churn | Where-Object { $_.NewIdentities -eq 0 }).Count -eq 0) { return (NotTested "fail-closed refusal in all 3 attempts, nothing moved; $txt") }
    throw "recusa antes do mover sem nova identidade observada: $txt"
}
function Get-AttemptText($C) { return "attempts $($C.Attempts)$(if ($C.Attempts -gt 1) { ' (' + (Get-ChurnText $C.Churn) + ')' })" }

function Assert-Isolated($C, [string]$Label) {
    # One root isolated by the real mover: the result, the entry in the quarantine, the T1 log and the manifest read
    # from their files, the derived state; the original path gone and the payload carrying this run's nonce.
    $r = $C.Res
    $root = $ctx.Roots[$Label]
    # Any entry this run created is attributed to it first (the quarantine snapshot allows only those), even if it stopped.
    if ($r.EntryId) { $ctx.EntryIds.Add([string]$r.EntryId); $summary.quarantine.entriesCreated = $ctx.EntryIds.Count }
    Assert (-not $r.Aborted -and -not $r.StoppedBy) "Aborted=$($r.Aborted) StoppedBy=$($r.StoppedBy) rejected=$(@($r.Rejected | ForEach-Object { Get-Codes $_.Reasons }) -join ';')"
    Assert (@($r.Results).Count -eq 1 -and $r.Results[0].Outcome -ceq 'COMPLETE' -and $r.Results[0].Moved -eq $true -and $r.Results[0].Verified -eq $true) "resultado: $(@($r.Results | ForEach-Object { $_.Outcome }) -join ',')"
    Assert ([string]$r.EntryId -cmatch '^\d{8}T\d{6}Z-[0-9a-f]{8}$') 'id da entrada fora do formato'
    Assert ([string]::Equals([string]$r.EntryPath, (Join-Path $qRoot $r.EntryId), [StringComparison]::OrdinalIgnoreCase)) 'entrada fora da quarentena do usuario'
    Assert (-not (Test-Path -LiteralPath $root.Path)) 'caminho original ainda existe'
    $pay = Join-Path $r.EntryPath 'payload'
    Assert ([IO.File]::ReadAllText((Join-Path $pay 'ATM-E2E-NONCE.txt')) -ceq $nonce) 'payload sem o nonce desta execucao'
    $recs = Read-E2ELog $C.Log
    $types = Get-Types $recs
    Assert ($types -ceq 'run-start,plan,confirmation,plan-check,move-intent,move-result,run-end') "sequencia do log: $types"
    Assert-Sequence $recs $r.RunId 'log'
    $conf = $recs[2]
    Assert ($conf.accepted -eq $true -and $conf.planId -ceq $r.PlanId -and $r.PlanId -match '^[0-9a-f]{64}$') 'confirmacao sem o planId completo'
    Assert ($conf.interaction.observedBy -ceq 'TEST_SEAM' -and $conf.interaction.caller -ceq 'DIRECT_CALL' -and $conf.interaction.identifiesRespondent -eq $false) 'interacao registrada diferente de TEST_SEAM/DIRECT_CALL'
    $cat = $(if ($Leg -eq 'A') { 'ELIGIBLE_WITH_DECLARED_RISK' } else { 'ELIGIBLE' })
    Assert ($recs[1].category -ceq $cat -and [bool]$recs[0].b1Exception -eq ($Leg -eq 'A') -and [bool]$conf.b1ResidualRiskAccepted -eq ($Leg -eq 'A')) "categoria/excecao B1 no log: $($recs[1].category)"
    Assert ($recs[3].matched -eq $true -and $recs[4].entryId -ceq $r.EntryId -and $recs[5].outcome -ceq 'COMPLETE' -and $recs[5].verified -eq $true) 'plan-check/move-intent/move-result divergentes'
    Assert ($recs[6].complete -eq 1 -and $recs[6].entryId -ceq $r.EntryId) 'run-end divergente'
    $man = Read-E2ELog (Join-Path $r.EntryPath 'manifest.jsonl')
    $mt = Get-Types $man
    Assert ($mt -ceq 'entry,move-intent,move-result') "manifesto: $mt"
    Assert-Sequence $man $r.EntryId 'manifesto'
    Assert ($man[0].targetKind -ceq 'SessionRoot' -and [string]::Equals([string]$man[0].originalPath, $root.Path, [StringComparison]::Ordinal) -and $man[0].planId -ceq $r.PlanId -and $man[0].runId -ceq $r.RunId -and [string]$man[0].actor.sid -ceq $mySid) 'registro entry divergente'
    Assert ($man[2].outcome -ceq 'COMPLETE' -and [long]$man[2].filesAfter -eq [long]$man[1].files -and [long]$man[2].bytesAfter -eq [long]$man[1].bytes) 'move-result do manifesto divergente da intencao'
    $e = Get-AtmQuarantineEntry -Id $r.EntryId
    Assert ($null -ne $e -and $e.State -ceq 'ISOLATED' -and $e.PayloadPresent) "estado derivado: $(if ($e) { $e.State })"
    $ctx.Iso[$Label] = [string]$r.EntryId
    return "mover COMPLETE, verified; entry in the user's quarantine, original path gone, payload with this run's nonce; log: $types; manifest: $mt; state ISOLATED"
}

$lockHelper = Join-Path $WorkDir 'lock-helper.ps1'
[IO.File]::WriteAllText($lockHelper, @'
param([string]$Dll, [string]$Out)
# B8 evidence from ANOTHER process: try the product lock once (never waits) and release it at once.
Add-Type -Path $Dll
$l = [AgentTempManager.AtmCleanLock]::TryAcquire('Global\AgentTempManager.Clean')
[IO.File]::WriteAllText($Out, [string]$l.Status)
if ($l.Acquired) { $rc = $l.Release(); if ($null -ne $rc) { [IO.File]::AppendAllText($Out, '|RELEASE_' + $rc) } }
'@)
function Invoke-LockProbe([string]$Tag) {
    $out = Join-Path $WorkDir "lock-$Tag.txt"
    $null = & $shellExe -NoProfile -ExecutionPolicy Bypass -File $lockHelper -Dll (Join-Path $lib 'AgentTempManager.Native.dll') -Out $out 2>&1
    if (Test-Path -LiteralPath $out) { return [IO.File]::ReadAllText($out) } else { return 'NO_OUTPUT' }
}
function Set-SimulatedOld([string[]]$Files, [string[]]$Dirs) {
    $old = [datetime]::UtcNow.AddHours(-$shiftHours)
    foreach ($f in $Files) { [IO.File]::SetLastWriteTimeUtc($f, $old); [IO.File]::SetCreationTimeUtc($f, $old) }
    foreach ($d in $Dirs) { [IO.Directory]::SetLastWriteTimeUtc($d, $old); [IO.Directory]::SetCreationTimeUtc($d, $old) }
}
function Set-AccountOwner([string]$Path) {
    # Leg B: items created elevated are owned by Administrators; the profile's own roots are owned by the account.
    foreach ($it in @(@(Get-Item -LiteralPath $Path -Force) + @(Get-ChildItem -LiteralPath $Path -Recurse -Force))) { $a = Get-Acl -LiteralPath $it.FullName; $a.SetOwner($me.User); Set-Acl -LiteralPath $it.FullName -AclObject $a }
}

# ---------------------------------------------------------------------------------------------- plant
Case 'gates-in-memory' {
    Assert ($loaded.AtmIsolationEnabled -eq $false -and $loaded.AtmQuarantinePurgeEnabled -eq $false -and $loaded.AtmRealDeletionEnabled -eq $false) 'trava carregada da instalacao nao era $false'
    Assert ($script:AtmRealDeletionEnabled -eq $false) 'trava de exclusao aberta neste processo'
    'loaded closed from the installation; isolation and purge gates opened in this process memory only; deletion gate of clean left closed'
}
Case 'quarantine-precondition' {
    Assert ([bool]$qRoot) 'quarentena sem caminho'
    Assert ([IO.Directory]::Exists([Environment]::GetFolderPath('LocalApplicationData'))) 'LocalAppData do usuario ausente'
    Assert (-not $qRoot.StartsWith($runRoot + '\', [StringComparison]::OrdinalIgnoreCase)) 'quarentena dentro da raiz de execucao'
    $summary.quarantine.existedBefore = [IO.Directory]::Exists($qRoot)
    Assert ([string]::Equals([IO.Path]::GetPathRoot($qRoot), [IO.Path]::GetPathRoot($runRoot), [StringComparison]::OrdinalIgnoreCase)) 'quarentena em outro volume que a raiz de execucao (MOVE_OTHER_VOLUME)'
    $ctx.QBefore = Get-Snapshot $qArea ([long]::MaxValue)
    "the account's own quarantine (LocalAppData), same volume as the run root; existed before: $($summary.quarantine.existedBefore); $($ctx.QBefore.Count) entries in its area before"
}
Case 'run-root' {
    # Created atomically with a protected DACL (owner and full control: this account; SYSTEM and Administrators), refused
    # if the name exists; checked after creation (owner, protection, entries, not a reparse point).
    Assert (-not (Test-Path -LiteralPath $runRoot)) 'RUN_ROOT_EXISTS'
    $ds = New-Object Security.AccessControl.DirectorySecurity
    $ds.SetSecurityDescriptorSddlForm("O:$($mySid)D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;$mySid)")
    if ($PSVersionTable.PSEdition -eq 'Core') { $ext = 'System.IO.FileSystemAclExtensions' -as [type]; $null = $ext::CreateDirectory($ds, $runRoot) } else { $null = [IO.Directory]::CreateDirectory($runRoot, $ds) }
    $acl = Get-Acl -LiteralPath $runRoot
    Assert ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq $mySid) 'dono da raiz de execucao divergente'
    Assert $acl.AreAccessRulesProtected 'DACL da raiz de execucao nao protegida'
    foreach ($r in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) { Assert (@('S-1-5-18', 'S-1-5-32-544', $mySid) -contains $r.IdentityReference.Value) 'entrada inesperada na DACL da raiz de execucao' }
    Assert (([IO.File]::GetAttributes($runRoot) -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'raiz de execucao e reparse point'
    $ctx.Tmp = Join-Path $runRoot 'tmpdir'; $ctx.Cfg = Join-Path $runRoot 'config'; $ctx.LogDir = Join-Path $runRoot 'log'
    foreach ($d in @($ctx.Tmp, $ctx.Cfg, $ctx.LogDir)) { [void][IO.Directory]::CreateDirectory($d) }
    $ctx.Base = Join-Path $ctx.Tmp 'claude'
    'created atomically, protected DACL (owner, SYSTEM, Administrators), refused if present'
}
Case 'plant' {
    Assert ($null -ne $ctx['Base']) 'raiz de execucao indisponivel'
    # <TMPDIR>\claude\<slug>\<session id> + transcript <config>\projects\<slug>\<id>.jsonl, synthetic content and the nonce.
    # One slug per case; every root and transcript set back by $shiftHours hours (SIMULATION, declared).
    foreach ($label in $labels) {
        $slug = 'C--atm-e2e-iso-' + $label
        $id = [guid]::NewGuid().ToString()
        $root = Join-Path $ctx.Base "$slug\$id"
        [void][IO.Directory]::CreateDirectory((Join-Path $root 'scratchpad\nested'))
        [IO.File]::WriteAllText((Join-Path $root 'scratchpad\SYNTHETIC.txt'), "synthetic ISO-P5 fixture ($label)`n")
        [IO.File]::WriteAllText((Join-Path $root 'scratchpad\nested\SYNTHETIC-2.txt'), "second synthetic file ($label)`n")
        [IO.File]::WriteAllText((Join-Path $root 'ATM-E2E-NONCE.txt'), $nonce)
        $pj = Join-Path $ctx.Cfg "projects\$slug"; [void][IO.Directory]::CreateDirectory($pj)
        $tr = Join-Path $pj "$id.jsonl"
        [IO.File]::WriteAllText($tr, ('{"type":"ai-title","aiTitle":"SYNTHETIC","sessionId":"' + $id + '"}' + "`n"))
        $ctx.Roots[$label] = [pscustomobject]@{ Label = $label; Id = $id; Slug = $slug; Scope = (Join-Path $ctx.Base $slug); Path = $root; Transcript = $tr }
    }
    if ($isAdmin) { Set-AccountOwner $ctx.Tmp }
    # A pause so that the directory times are settled, then the SIMULATION.
    Start-Sleep -Seconds 2
    foreach ($label in $labels) {
        $r = $ctx.Roots[$label]
        Set-SimulatedOld -Files @((Join-Path $r.Path 'scratchpad\SYNTHETIC.txt'), (Join-Path $r.Path 'scratchpad\nested\SYNTHETIC-2.txt'), (Join-Path $r.Path 'ATM-E2E-NONCE.txt'), $r.Transcript) -Dirs @((Join-Path $r.Path 'scratchpad\nested'), (Join-Path $r.Path 'scratchpad'), $r.Path)
    }
    # Real discovery: the variables in this account's user environment (HKCU\Environment) and in this process, as Claude
    # Code would see them; removed again at the end if still the values set here.
    $k = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
    try {
        foreach ($pair in @(@('CLAUDE_CODE_TMPDIR', $ctx.Tmp), @('CLAUDE_CONFIG_DIR', $ctx.Cfg))) {
            $prev = $k.GetValue($pair[0], $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $ctx.EnvSet[$pair[0]] = [pscustomobject]@{ Value = $pair[1]; Previous = $prev }
            $k.SetValue($pair[0], $pair[1], [Microsoft.Win32.RegistryValueKind]::String)
            [Environment]::SetEnvironmentVariable($pair[0], $pair[1], 'Process')
        }
    } finally { $k.Close() }
    "$($labels.Count) roots, one scope each (set back ${shiftHours}h = SIMULATION), 3 files each, transcripts; user environment set"
}
Case 'discovery' {
    Assert ($ctx.Roots.Count -eq $labels.Count) 'plantio indisponivel'
    $inv = Invoke-AtmInventory @ia
    $b = @($inv.Bases | Where-Object { [string]::Equals($_.Path, $ctx.Base, [StringComparison]::OrdinalIgnoreCase) })
    Assert ($b.Count -eq 1) "base plantada descoberta $($b.Count) vez(es) pelo caminho normal"
    Assert (-not [bool]$b[0].Shared) 'base plantada compartilhada'
    Assert ([bool]$inv.Identity.IsAdmin -eq [bool]$isAdmin) 'identidade do produto diverge do token'
    foreach ($label in $labels) {
        $m = @($inv.Partitions | Where-Object { $_.Kind -ne 'BaseLooseFiles' -and [string]::Equals($_.Path, $ctx.Roots[$label].Path, [StringComparison]::OrdinalIgnoreCase) })
        Assert ($m.Count -eq 1) "raiz $label nao inventariada"
        $ctx.Roots[$label].Path = $m[0].Path
        Assert ($m[0].Sid -eq $mySid) "raiz $label atribuida a outro perfil"
    }
    $acl = @(foreach ($d in @(@($ctx.Base) + @($labels | ForEach-Object { $ctx.Roots[$_].Scope }))) { @(Get-AtmAclProblems -Path $d -OwnerSid $mySid) })
    Assert ($acl.Count -eq 0) "ACL da base plantada com problemas: $(Get-Codes $acl)"
    $summary.processCoverage = [ordered]@{ complete = [bool]$inv.ProcessCoverageComplete; uninspectable = [int]$inv.Snapshot.Uninspectable }
    $rows = @(Invoke-AtmPreview -Inventory $inv -InventoryArgs $ia)
    $cats = @(foreach ($label in $labels) {
            $r = @($rows | Where-Object { $_.Partition.Kind -ne 'BaseLooseFiles' -and [string]::Equals($_.Partition.Path, $ctx.Roots[$label].Path, [StringComparison]::OrdinalIgnoreCase) })[0]
            [pscustomobject]@{ Label = $label; Category = [string]$r.Gate.Category; Class = [string]$r.Partition.Class; Reasons = (Get-Codes $r.Gate.Reasons) }
        })
    $want = $(if ($Leg -eq 'A') { 'ELIGIBLE_WITH_DECLARED_RISK' } else { 'ELIGIBLE' })
    $got = (@($cats | ForEach-Object { "$($_.Label)=$($_.Category)/$($_.Class)$(if ($_.Reasons) { ' [' + $_.Reasons + ']' })" }) -join '; ')
    $cov = "process coverage complete=$($summary.processCoverage.complete), uninspectable=$($summary.processCoverage.uninspectable)"
    if (@($cats | Where-Object { $_.Category -cne $want }).Count -eq 0) { $ctx.Eligible = $true; return "base found via the user environment (source $($b[0].Source)), not shared; $($labels.Count) roots of this account, ACL clean; expected $want`: $got; $cov" }
    if ($Leg -eq 'B' -and -not $summary.processCoverage.complete) { return (NotTested "elevated coverage measured incomplete: ELIGIBLE unreachable, never forced; $got; $cov") }
    throw "categoria das raizes diferente de $($want): $got; $cov"
}
$needEligible = { if (-not $ctx.Eligible) { NotTested $(if ($Leg -eq 'B') { 'leg B: the measured process coverage is not complete (discovery); isolation only with complete coverage, never forced' } else { 'no planted root reached the expected category (discovery)' }) } }

# ---------------------------------------------------------------------------------------------- snapshots before the runs
if ($null -ne $ctx['LogDir'] -and $ctx.Roots.Count -eq $labels.Count) {
    $ctx.RunBefore = Get-Snapshot $runRoot ([long]::MaxValue)
    foreach ($label in $labels) { $ctx.Roots[$label] | Add-Member -NotePropertyName Tree -NotePropertyValue (Get-Snapshot $ctx.Roots[$label].Path ([long]::MaxValue)) }
    try { $ctx.TempBefore = Get-Snapshot ([IO.Path]::GetTempPath().TrimEnd('\')) 1MB } catch { $ctx.TempBefore = $null }
}
function Assert-QuarantineUnchanged([string]$What) {
    Assert ($null -ne $ctx['QBefore']) 'sem fotografia da quarentena'
    $d = Compare-Snapshot $ctx.QBefore (Get-Snapshot $qArea ([long]::MaxValue))
    $bad = @(@(@($d.Removed) + @($d.Changed) + @($d.Added)) | Where-Object { $k = $_; @($ctx.EntryIds | Where-Object { Test-Under $k ('Q\' + $_) }).Count -eq 0 -and $k -ine 'Q' })
    Assert ($bad.Count -eq 0) "$What`: $($bad.Count) mudanca(s) na area da quarentena fora das entradas desta execucao"
}

# ---------------------------------------------------------------------------------------------- refusals (J-ISO-9 a)
Case 'ISO-refuse-whole-base' {
    Assert ($null -ne $ctx['Base'] -and $ctx.Roots.Count -eq $labels.Count) 'plantio indisponivel'
    Assert ([string]::Equals([IO.Path]::GetFullPath($ctx.Base), $ctx.Base, [StringComparison]::Ordinal) -and $ctx.Base.StartsWith($runRoot + '\', [StringComparison]::OrdinalIgnoreCase)) 'base fora da raiz de execucao'
    Assert-NoReparseChain $ctx.Base
    $c = Invoke-E2EIsolate -Paths @($ctx.Base) -LogName 'ISO-refuse-base.jsonl'
    Assert ($c.Res.Aborted -ceq 'NENHUM_CAMINHO_ISOLAVEL') "Aborted=$($c.Res.Aborted)"
    $codes = Get-Codes $c.Res.Rejected[0].Reasons
    Assert ($codes -match 'ISOLAMENTO_BASE_NAO_LIBERADA_0_3X') "razoes: $codes"
    Assert (-not $c.Res.LogCreated -and -not (Test-Path -LiteralPath $c.Log) -and $c.Calls.Count -eq 0) 'log criado ou pergunta feita'
    foreach ($label in $labels) { Assert (Test-Path -LiteralPath $ctx.Roots[$label].Path) "raiz $label ausente" }
    Assert-QuarantineUnchanged 'base'
    "the whole base: NENHUM_CAMINHO_ISOLAVEL ($codes)$(if ($Leg -eq 'A') { ' even with -AcceptB1ResidualRisk' }); no question, no log, every root intact, quarantine unchanged"
}
Case 'ISO-refuse-scope' {
    Assert ($ctx.Roots.Count -eq $labels.Count) 'plantio indisponivel'
    $scope = $ctx.Roots['purge'].Scope
    Assert ([string]::Equals([IO.Path]::GetDirectoryName($scope), $ctx.Base, [StringComparison]::OrdinalIgnoreCase)) 'escopo fora da base desta execucao'
    Assert-NoReparseChain $scope
    $c = Invoke-E2EIsolate -Paths @($scope) -LogName 'ISO-refuse-scope.jsonl'
    Assert ($c.Res.Aborted -ceq 'NENHUM_CAMINHO_ISOLAVEL') "Aborted=$($c.Res.Aborted)"
    $codes = Get-Codes $c.Res.Rejected[0].Reasons
    Assert ($codes -match 'ISOLAMENTO_ESCOPO_NAO_LIBERADO_0_3X') "razoes: $codes"
    Assert (-not $c.Res.LogCreated -and -not (Test-Path -LiteralPath $c.Log) -and $c.Calls.Count -eq 0) 'log criado ou pergunta feita'
    Assert (Test-Path -LiteralPath $ctx.Roots['purge'].Path) 'raiz do escopo ausente'
    Assert-QuarantineUnchanged 'escopo'
    "a scope directory: NENHUM_CAMINHO_ISOLAVEL ($codes)$(if ($Leg -eq 'A') { ' even with -AcceptB1ResidualRisk' }); no question, no log, root intact, quarantine unchanged"
}
Case 'ISO-no-risk-switch' {
    if ($Leg -ne 'A') { return (NotTested 'leg A only (B1 restricted exception)') }
    $nt = & $needEligible; if ($nt) { return $nt }
    Assert-Entry $ctx.Roots['free'].Path
    $c = Invoke-E2EIsolate -Paths @($ctx.Roots['free'].Path) -LogName 'ISO-no-risk.jsonl' -NoRisk
    Assert ($c.Res.Aborted -ceq 'NENHUM_CAMINHO_ISOLAVEL') "Aborted=$($c.Res.Aborted)"
    $codes = Get-Codes $c.Res.Rejected[0].Reasons
    Assert ($codes -match 'COBERTURA_DE_PROCESSOS_INCOMPLETA') "razoes: $codes"
    Assert (-not (Test-Path -LiteralPath $c.Log) -and (Test-Path -LiteralPath $ctx.Roots['free'].Path)) 'log criado ou raiz movida'
    Assert-QuarantineUnchanged 'sem -AcceptB1ResidualRisk'
    "without -AcceptB1ResidualRisk: rejected by B1 ($codes), NENHUM_CAMINHO_ISOLAVEL, no log, quarantine unchanged"
}

# ---------------------------------------------------------------------------------------------- isolate, restore, purge
Case 'ISO-isolate-session-root' {
    $nt = & $needEligible; if ($nt) { return $nt }
    # B8 from another process while the run holds the lock (between the plan check and the revalidation), and after it.
    # No GetNewClosure: the hook runs inside the engine's call chain and needs this script's functions (dynamic scope).
    $isoProbe = @{ Status = $null }
    $hook = { param($part) if ($null -eq $isoProbe.Status) { $isoProbe.Status = Invoke-LockProbe 'during-isolate' } }
    $c = Invoke-E2EIsolateChurn -Label 'free' -LogBase 'ISO-isolate' -Hook $hook
    if ($c.Exhausted) { return (Resolve-Exhausted $c) }
    $txt = Assert-Isolated $c 'free'
    $calls = ($c.Calls -join ',')
    Assert ($calls -ceq $(if ($Leg -eq 'A') { 'risk,confirm' } else { 'confirm' })) "perguntas: $calls"
    Assert ($isoProbe.Status -ceq 'BUSY') "lock durante a execucao: $($isoProbe.Status), esperado BUSY"
    $after = Invoke-LockProbe 'after-isolate'
    Assert ($after -ceq 'ACQUIRED') "lock depois da execucao: $after, esperado ACQUIRED (liberado)"
    $how = $(if ($Leg -eq 'A') { 'B1 exception: the risk phrase, then ISOLAR 1 CAMINHOS <plan>' } else { 'ELIGIBLE: ISOLAR 1 CAMINHOS <plan>' })
    "$how; $txt; questions $calls; B8: BUSY from another process during the run, ACQUIRED after it; $(Get-AttemptText $c)"
}
Case 'ISO-restore-free-destination' {
    $nt = & $needEligible; if ($nt) { return $nt }
    if (-not $ctx.Iso.ContainsKey('free')) { return (NotTested 'no entry isolated by ISO-isolate-session-root') }
    $id = $ctx.Iso['free']; $root = $ctx.Roots['free']
    $op = New-Operator
    $res = Invoke-AtmRestore -Id $id -PlanPresenter $rstPresenter -ConfirmationReader $op.Reader -InventoryArgs $ia -LogFile (New-E2ELogPath 'ISO-restore-free.jsonl') -Interaction $interaction
    Assert (-not $res.Aborted -and -not $res.StoppedBy) "Aborted=$($res.Aborted) StoppedBy=$($res.StoppedBy) razoes=$(Get-PlanCodes $res)"
    Assert ($res.Plan.Conflict -eq $false -and $res.Plan.Reconcile -eq $false -and [string]::Equals([string]$res.Plan.Destination, $root.Path, [StringComparison]::Ordinal)) 'plano: destino diferente do original livre'
    Assert (@($res.Results).Count -eq 1 -and $res.Results[0].Outcome -ceq 'COMPLETE' -and $res.Results[0].Verified -eq $true) "resultado: $(@($res.Results | ForEach-Object { $_.Outcome }) -join ',')"
    Assert (($op.Calls -join ',') -ceq 'restore') "perguntas: $($op.Calls -join ',')"
    $d = Compare-Snapshot $root.Tree (Get-Snapshot $root.Path ([long]::MaxValue))
    Assert ((Get-DiffCount $d) -eq 0) "arvore restaurada diferente da original: $($d.Removed.Count) ausentes, $($d.Added.Count) novas, $($d.Changed.Count) alteradas"
    $recs = Read-E2ELog $res.LogFile
    $types = Get-Types $recs
    Assert ($types -ceq 'run-start,confirmation,plan-check,restore-intent,restore-result,run-end') "sequencia do log: $types"
    Assert-Sequence $recs $res.RunId 'log'
    Assert ($recs[0].operation -ceq 'restore' -and $recs[0].alternative -eq $false -and $recs[1].accepted -eq $true -and $recs[2].matched -eq $true -and $recs[4].outcome -ceq 'COMPLETE' -and $recs[4].verified -eq $true) 'registros do log divergentes'
    $e = Get-AtmQuarantineEntry -Id $id
    $man = Read-E2ELog (Join-Path $e.Path 'manifest.jsonl')
    $mt = Get-Types $man
    Assert ($mt -ceq 'entry,move-intent,move-result,restore-intent,restore-result') "manifesto: $mt"
    Assert-Sequence $man $id 'manifesto'
    Assert ($e.State -ceq 'RESTORED' -and -not $e.PayloadPresent) "estado derivado: $($e.State), payload $($e.PayloadPresent)"
    "RESTAURAR <id8>: mover COMPLETE, verified, back at the free original path; restored tree identical by SHA-256, size and write time; log: $types; manifest: $mt; state RESTORED, the entry kept as the trail"
}
Case 'ISO-restore-conflict-alternative' {
    $nt = & $needEligible; if ($nt) { return $nt }
    $c = Invoke-E2EIsolateChurn -Label 'conflict' -LogBase 'ISO-isolate-conflict'
    if ($c.Exhausted) { return (Resolve-Exhausted $c) }
    $null = Assert-Isolated $c 'conflict'
    $id = $ctx.Iso['conflict']; $root = $ctx.Roots['conflict']
    # The original path taken again (as an agent would recreate it): this run's nonce, other content, set back too.
    $ctx.ConflictTouched = $true
    [void][IO.Directory]::CreateDirectory((Join-Path $root.Path 'scratchpad'))
    [IO.File]::WriteAllText((Join-Path $root.Path 'scratchpad\RECREATED.txt'), "recreated after the isolation`n")
    [IO.File]::WriteAllText((Join-Path $root.Path 'ATM-E2E-NONCE.txt'), $nonce)
    if ($isAdmin) { Set-AccountOwner $root.Path }
    Start-Sleep -Seconds 2
    Set-SimulatedOld -Files @((Join-Path $root.Path 'scratchpad\RECREATED.txt'), (Join-Path $root.Path 'ATM-E2E-NONCE.txt')) -Dirs @((Join-Path $root.Path 'scratchpad'), $root.Path)
    $recreated = Get-Snapshot $root.Path ([long]::MaxValue)
    $altName = [IO.Path]::GetFileName($root.Path) + '.restored-' + $id.Substring($id.Length - 8)
    $alt = Join-Path $root.Scope $altName
    Assert (-not (Test-Path -LiteralPath $alt)) 'destino alternativo ja existe'
    $op = New-Operator
    $res = Invoke-AtmRestore -Id $id -PlanPresenter $rstPresenter -ConfirmationReader $op.Reader -InventoryArgs $ia -LogFile (New-E2ELogPath 'ISO-restore-conflict.jsonl') -Interaction $interaction
    Assert (-not $res.Aborted -and -not $res.StoppedBy) "Aborted=$($res.Aborted) StoppedBy=$($res.StoppedBy) razoes=$(Get-PlanCodes $res)"
    Assert ($res.Plan.Conflict -eq $true -and [string]$res.Plan.DestinationName -ceq $altName -and [string]::Equals([string]$res.Plan.Destination, $alt, [StringComparison]::Ordinal)) "plano: conflito $($res.Plan.Conflict), destino alternativo divergente"
    Assert (@($res.Phrases).Count -eq 2 -and ($op.Calls -join ',') -ceq 'restore,alternative' -and [string]$res.Phrases[1] -match ' EM DESTINO ALTERNATIVO$') "frases: $(@($res.Phrases).Count), perguntas $($op.Calls -join ',')"
    Assert (@($res.Results).Count -eq 1 -and $res.Results[0].Outcome -ceq 'COMPLETE' -and $res.Results[0].Verified -eq $true) "resultado: $(@($res.Results | ForEach-Object { $_.Outcome }) -join ',')"
    $dr = Compare-Snapshot $recreated (Get-Snapshot $root.Path ([long]::MaxValue))
    Assert ((Get-DiffCount $dr) -eq 0) 'caminho recriado alterado: nada pode ser sobrescrito nem mesclado'
    $da = Compare-Snapshot $root.Tree (Get-Snapshot $alt ([long]::MaxValue))
    Assert ((Get-DiffCount $da) -eq 0) "arvore restaurada no destino alternativo diferente da original: $($da.Removed.Count)/$($da.Added.Count)/$($da.Changed.Count)"
    $recs = Read-E2ELog $res.LogFile
    $types = Get-Types $recs
    Assert ($types -ceq 'run-start,confirmation,plan-check,restore-intent,restore-result,run-end' -and $recs[0].alternative -eq $true -and $recs[4].outcome -ceq 'COMPLETE') "log: $types"
    Assert-Sequence $recs $res.RunId 'log'
    $e = Get-AtmQuarantineEntry -Id $id
    Assert ($e.State -ceq 'RESTORED' -and -not $e.PayloadPresent) "estado derivado: $($e.State)"
    "original path recreated after the isolation: RESTORE conflict, the engine's alternative <name>.restored-<id8> with its own phrase (questions restore,alternative); the recreated path unchanged by SHA-256 (nothing overwritten or merged); restored tree identical; log: $types; state RESTORED; $(Get-AttemptText $c)"
}
Case 'ISO-purge-one-entry' {
    $nt = & $needEligible; if ($nt) { return $nt }
    $c = Invoke-E2EIsolateChurn -Label 'purge' -LogBase 'ISO-isolate-purge'
    if ($c.Exhausted) { return (Resolve-Exhausted $c) }
    $null = Assert-Isolated $c 'purge'
    $id = $ctx.Iso['purge']
    $ep = Join-Path $qRoot $id
    $op = New-Operator
    $res = Invoke-AtmPurge -Id $id -PlanPresenter $purPresenter -ConfirmationReader $op.Reader -InventoryArgs $ia -LogFile (New-E2ELogPath 'ISO-purge.jsonl') -Interaction $interaction
    Assert (-not $res.Aborted -and -not $res.StoppedBy) "Aborted=$($res.Aborted) StoppedBy=$($res.StoppedBy) razoes=$(Get-PlanCodes $res)"
    Assert ([long]$res.Plan.Files -eq 3) "arquivos no plano do expurgo: $($res.Plan.Files), esperado 3"
    Assert ($res.Phrase -ceq ('EXPURGAR ' + $id.Substring($id.Length - 8).ToUpperInvariant() + ' 3 ARQUIVOS') -and ($op.Calls -join ',') -ceq 'task,results,purge') "frase/perguntas: $($op.Calls -join ',')"
    Assert (@($res.Results).Count -eq 1 -and $res.Results[0].Outcome -ceq 'COMPLETE' -and $res.Results[0].Verified -eq $true) "resultado: $(@($res.Results | ForEach-Object { $_.Outcome }) -join ',')"
    Assert (-not (Test-Path -LiteralPath (Join-Path $ep 'payload')) -and (Test-Path -LiteralPath (Join-Path $ep 'manifest.jsonl'))) 'payload presente ou manifesto ausente'
    $ctx.Purged = $true
    $recs = Read-E2ELog $res.LogFile
    $types = Get-Types $recs
    Assert ($types -ceq 'run-start,declaration,confirmation,plan-check,purge-intent,purge-result,run-end') "sequencia do log: $types"
    Assert-Sequence $recs $res.RunId 'log'
    Assert ($recs[0].operation -ceq 'purge' -and $recs[3].matched -eq $true -and $recs[5].outcome -ceq 'COMPLETE' -and $recs[5].automatic -eq $false -and $recs[5].verifiedGone -eq $true) 'registros do log divergentes'
    $man = Read-E2ELog (Join-Path $ep 'manifest.jsonl')
    $mt = Get-Types $man
    Assert ($mt -ceq 'entry,move-intent,move-result,purge-intent,purge-result') "manifesto: $mt"
    Assert-Sequence $man $id 'manifesto'
    $e = Get-AtmQuarantineEntry -Id $id
    Assert ($e.State -ceq 'PURGED') "estado derivado: $($e.State)"
    Assert (-not (Test-Path -LiteralPath $ctx.Roots['purge'].Path)) 'raiz original reapareceu'
    "EXPURGAR <id8> 3 ARQUIVOS after the purge's own declarations (task,results,purge): the real deleter COMPLETE, verified gone; the entry and its manifest kept as the trail; log: $types; manifest: $mt; state PURGED; $(Get-AttemptText $c)"
}

# ---------------------------------------------------------------------------------------------- snapshots after the runs
Case 'snapshot-run-root' {
    if ($null -eq $ctx['RunBefore']) { return (NotTested 'no snapshot before the runs') }
    $d = Compare-Snapshot $ctx.RunBefore (Get-Snapshot $runRoot ([long]::MaxValue))
    $purgeRel = $ctx.Roots['purge'].Path.Substring($runRoot.Length).TrimStart('\')
    $conflictScopeRel = $ctx.Roots['conflict'].Scope.Substring($runRoot.Length).TrimStart('\')
    $allowed = {
        param([string]$k, [string]$kind)
        if ($ctx.ConflictTouched -and (Test-Under $k $conflictScopeRel)) { return $true }
        # The purge root left the run root when it was isolated (purged or not afterwards).
        if ($kind -ceq 'Removed' -and $ctx.Iso.ContainsKey('purge') -and (Test-Under $k $purgeRel)) { return $true }
        if ($kind -ceq 'Added' -and $ctx.Logs.Contains($(if ($k.StartsWith('log\', [StringComparison]::OrdinalIgnoreCase)) { $k.Substring(4) } else { '' }))) { return $true }
        return $false
    }
    $bad = @(@($d.Removed | Where-Object { -not (& $allowed $_ 'Removed') }) + @($d.Added | Where-Object { -not (& $allowed $_ 'Added') }) + @($d.Changed | Where-Object { -not (& $allowed $_ 'Changed') }))
    Assert ($bad.Count -eq 0) "raiz de execucao: $($bad.Count) diferenca(s) fora do alvo [$((@($bad | Select-Object -First 3)) -join '; ')]"
    "run root: only the purged root ($(@($d.Removed).Count) removed), the conflict scope (recreated path and alternative) and this run's logs ($(@($d.Added).Count) added) differ; the restored root, the transcripts and the rest identical"
}
Case 'snapshot-quarantine' {
    Assert-QuarantineUnchanged 'fim'
    $d = Compare-Snapshot $ctx.QBefore (Get-Snapshot $qArea ([long]::MaxValue))
    foreach ($id in $ctx.EntryIds) { Assert (Test-Path -LiteralPath (Join-Path (Join-Path $qRoot $id) 'manifest.jsonl')) 'entrada desta execucao sem manifesto' }
    "quarantine area: only this run's $($ctx.EntryIds.Count) entries added ($(@($d.Added).Count) items), 0 removed or changed outside them; every entry keeps its manifest"
}
Case 'temp-pre-existing' {
    # Other processes of the runner may write in the temp folder: a difference there is reported, not attributed.
    if ($null -eq $ctx['TempBefore']) { return (NotTested 'temp snapshot unavailable') }
    $t = Compare-Snapshot $ctx.TempBefore (Get-Snapshot ([IO.Path]::GetTempPath().TrimEnd('\')) 1MB)
    if ($t.Removed.Count -eq 0 -and $t.Changed.Count -eq 0) { return "no pre-existing temp entry removed or changed ($($t.Added.Count) added by the shells)" }
    NotTested "inconclusive: $($t.Removed.Count) pre-existing entries removed and $($t.Changed.Count) changed in the account's temp folder, not attributable (other processes write there)"
}

# ---------------------------------------------------------------------------------------------- after
Case 'installed-after' {
    Assert ($loaded.AtmIsolationEnabled -eq $false -and $loaded.AtmQuarantinePurgeEnabled -eq $false -and $loaded.AtmRealDeletionEnabled -eq $false) 'trava carregada da instalacao nao era $false'
    Assert ($script:AtmRealDeletionEnabled -eq $false) 'trava de exclusao aberta neste processo'
    $bad = Get-InstalledGateProblems
    Assert ($bad.Count -eq 0) "travas instaladas alteradas: $($bad -join ',')"
    $v = Invoke-InstalledVerify
    Assert ($v -eq 0) "agent-temp verify exit $v"
    $d = Compare-Snapshot $ctx.InstallBefore (Get-Snapshot $InstallDir ([long]::MaxValue))
    Assert ((Get-DiffCount $d) -eq 0) "instalacao alterada: $($d.Removed.Count) removidos, $($d.Added.Count) adicionados, $($d.Changed.Count) alterados"
    'installed files identical by SHA-256 to before the runs; verify 0; six installed gates still $false (isolation and purge opened only in this process memory)'
}
# The variables set in the user environment are taken out again (or restored) if they still hold the values set here.
try {
    $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
    if ($null -ne $k) {
        try {
            foreach ($n in @($ctx.EnvSet.Keys)) {
                $e = $ctx.EnvSet[$n]
                if ([string]$k.GetValue($n, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) -ceq $e.Value) {
                    if ($null -eq $e.Previous) { $k.DeleteValue($n) } else { $k.SetValue($n, $e.Previous, [Microsoft.Win32.RegistryValueKind]::ExpandString) }
                }
            }
        } finally { $k.Close() }
    }
} catch { $summary.envRestoreError = $_.Exception.GetType().Name }

$summary.finishedUtc = [datetime]::UtcNow.ToString('o')
$failed = @($summary.cases.Values | Where-Object { $_.status -eq 'FAIL' }).Count
$summary.failed = $failed
$summary.notTested = @($summary.cases.Values | Where-Object { $_.status -eq 'NOT_TESTED' }).Count
$summary.passed = @($summary.cases.Values | Where-Object { $_.status -eq 'PASS' }).Count
[IO.File]::WriteAllText($SummaryFile, ($summary | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
[Console]::Out.WriteLine(("ISO-{0}: {1} PASS / {2} FAIL / {3} NOT_TESTED | {4} | elevated {5}" -f $Leg, $summary.passed, $failed, $summary.notTested, $summary.shell, $summary.elevated))
exit $failed
