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
  ISO-P5b (adversarial cases and scale): the section 6.1 measurement (the installed mover on trees of the run root, outside
  the base); a file held open by a helper process of this harness, before the plan and between the revalidation and the
  mover; a process that ends by itself after move-intent (this script started again as a CHILD, Environment.Exit, never a
  forced termination) and the restore that reconciles the entry; clean and isolate contending for the lock in both orders
  (BUSY); a junction swapped in for the root between the revalidation and the mover; a root on a second fixed volume;
  200,000 files with the time measured (-Heavy, one x64 job). The windows inside the flow use the engine's existing mover
  seam (-MoveTreeImpl) with a wrapper that calls the REAL mover with exactly the engine's arguments, plus the attack (no
  new seam in the product). The clean that contends for the lock runs in a child that opens the deletion gate in its own
  memory only and answers a wrong final phrase by design: it never deletes.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('A', 'B')][string]$Leg,
    [Parameter(Mandatory)][string]$InstallDir,
    [Parameter(Mandatory)][string]$SummaryFile,
    [Parameter(Mandatory)][string]$WorkDir,
    [switch]$DisposableMachine,
    # ISO-P5b: 200,000 files in one root (one x64 job of the matrix only); without it that case is NOT_TESTED.
    [switch]$Heavy,
    # ISO-P5b child modes (this script started again by itself; no case runs): K isolates -ChildRoot and ends by itself
    # right after the real mover, before move-result; CleanTry runs one clean of -ChildRoot (the lock is expected busy);
    # CleanHold runs one clean of -ChildRoot that holds the lock at its final phrase until -ChildRelease, then answers a
    # wrong phrase (never deletes). One line is written to -ChildOut.
    [ValidateSet('', 'K', 'CleanTry', 'CleanHold')][string]$ChildMode = '',
    [string]$ChildRoot,
    [string]$ChildLog,
    [string]$ChildOut,
    [string]$ChildReady,
    [string]$ChildRelease
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# Accident guard only (these variables can be set by anyone): the containment is the run root and the nonce below.
if (-not $DisposableMachine -and -not ($env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -eq 'github-hosted')) {
    throw 'Recusado: este teste move e expurga de verdade raizes que ele mesmo planta; so roda em maquina descartavel (runner do GitHub) ou com -DisposableMachine.'
}

# ISO-P5b: the 200,000-file case must end well inside the job's limit (the steps after this harness still need to run).
$harnessClock = [Diagnostics.Stopwatch]::StartNew()
$heavyDeadline = [TimeSpan]::FromMinutes(35)
$me = [Security.Principal.WindowsIdentity]::GetCurrent()
$mySid = $me.User.Value
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($me)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$shellExe = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
$nonce = [guid]::NewGuid().ToString('N')
$runRoot = Join-Path $env:SystemDrive ('ATM-E2E-ISO-' + $Leg + '-' + $nonce.Substring(0, 12))
$shiftHours = 120
# One scope (slug) per case: the restore refuses when a sibling of its destination is RECENT or ACTIVE_EVIDENCE.
$labels = @('free', 'conflict', 'purge', 'openA', 'openB', 'interrupt', 'conc', 'xclean', 'jswap')
# Touched: scopes (relative to the run root) that a case changes on purpose and checks itself; Skip: folders the run-root
# snapshot does not enter (the 200,000 files); ExtraBases: a base planted outside the run root (the second volume).
$ctx = @{ Roots = @{}; Logs = (New-Object System.Collections.Generic.List[string]); EnvSet = @{}; Eligible = $false; EntryIds = (New-Object System.Collections.Generic.List[string]); Iso = @{}
    Touched = (New-Object System.Collections.Generic.List[string]); Skip = (New-Object System.Collections.Generic.List[string]); QSkip = (New-Object System.Collections.Generic.List[string])
    ExtraBases = (New-Object System.Collections.Generic.List[object]) }
$summary = [ordered]@{
    schema = 'atm.e2e-isolate/1'; phase = 'ISO-P5a+P5b'; leg = $Leg; startedUtc = [datetime]::UtcNow.ToString('o')
    shell = "$($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)"; arch = $env:PROCESSOR_ARCHITECTURE
    elevated = [bool]$isAdmin; confirmation = 'AUTOMATED_BY_HARNESS (console: TEST_SEAM); not a human acceptance'
    recencySimulated = $true; recencyShiftHours = $shiftHours; recentHoursInProduct = $null
    processCoverage = [ordered]@{ complete = $null; uninspectable = $null }; quarantine = [ordered]@{ existedBefore = $null; entriesCreated = 0 }
    section61 = $null; secondVolume = $null; heavy = $null
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
    if ($ChildMode) { return }
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
function Get-Snapshot([string]$Root, [long]$HashMax, [int]$MaxEntries = 200000, [string[]]$Skip = @()) {
    # Relative path -> D (directory), R (reparse point, never traversed), F|length|write ticks|SHA-256 ('-' above
    # HashMax, 'UNREADABLE' when it cannot be opened), X (directory not enumerable). A missing root is an empty map. A
    # folder in -Skip is recorded as D and not entered.
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
            if (($i.Attributes -band [IO.FileAttributes]::Directory) -ne 0) {
                $map[$rel] = 'D'
                if (@($Skip | Where-Object { [string]::Equals($_, $i.FullName, [StringComparison]::OrdinalIgnoreCase) }).Count -eq 0) { $stack.Push($i.FullName) }
                continue
            }
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
    $bad = @(Get-InstalledGateProblems)
    Assert ($bad.Count -eq 0) "travas instaladas que nao sao uma unica atribuicao `$false: $($bad -join ',')"
    $v = Invoke-InstalledVerify
    Assert ($v -eq 0) "agent-temp verify exit $v"
    $ctx.InstallBefore = Get-Snapshot $InstallDir ([long]::MaxValue)
    "verify 0; six installed gates `$false (single assignment each); $($ctx.InstallBefore.Count) installed entries hashed"
}
if (-not $ChildMode -and ($summary.cases['identity'].status -ne 'PASS' -or $summary.cases['installed-before'].status -ne 'PASS')) {
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
    # Containment: canonical, under a base of this run (the run root's, or one planted in this run on another volume),
    # the nonce of this run, no reparse point in the chain.
    Assert ([string]::Equals([IO.Path]::GetFullPath($Path), $Path, [StringComparison]::Ordinal)) 'entrada nao canonica'
    $b = @(@(@{ Base = $ctx['Base']; Top = $runRoot }) + @($ctx.ExtraBases) | Where-Object { $_.Base -and $Path.StartsWith($_.Base + '\', [StringComparison]::OrdinalIgnoreCase) })
    Assert ($b.Count -eq 1) 'entrada fora da base desta execucao'
    $nf = Join-Path $Path 'ATM-E2E-NONCE.txt'
    Assert ((Test-Path -LiteralPath $nf -PathType Leaf) -and [IO.File]::ReadAllText($nf) -ceq $nonce) 'entrada sem o nonce desta execucao'
    Assert-NoReparseChain $Path $b[0].Top
}
function Assert-NoReparseChain([string]$Path, [string]$Top = $runRoot) {
    $p = $Path
    while ($p.Length -gt $Top.Length) {
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

function Add-EntryId([string]$Id) {
    # Any entry this run created is attributed to it (the quarantine snapshot allows only those), even if its run stopped.
    if ($Id -and -not $ctx.EntryIds.Contains($Id)) { $ctx.EntryIds.Add($Id); $summary.quarantine.entriesCreated = $ctx.EntryIds.Count }
}
function Invoke-E2EIsolate([string[]]$Paths, [string]$LogName, [switch]$NoRisk, [scriptblock]$Hook, $Operator, [scriptblock]$MoveImpl) {
    $entries = @(foreach ($p in $Paths) { [pscustomobject]@{ Source = 'e2e-iso'; Path = $p; Fingerprint = $null } })
    $op = $(if ($Operator) { $Operator } else { New-Operator })
    $a = @{ Entries = $entries; PlanPresenter = $isoPresenter; ConfirmationReader = $op.Reader; InventoryArgs = $ia; LogFile = (New-E2ELogPath $LogName); Interaction = $interaction }
    if ($Leg -eq 'A' -and -not $NoRisk) { $a['AcceptB1ResidualRisk'] = $true }
    if ($Hook) { $a['BeforeMoveHook'] = $Hook }
    # The engine's existing mover seam: a wrapper that calls the REAL mover with the engine's own arguments (ISO-P5b).
    if ($MoveImpl) { $a['MoveTreeImpl'] = $MoveImpl }
    $res = Invoke-AtmIsolate @a
    Add-EntryId ([string]$res.EntryId)
    return [pscustomobject]@{ Res = $res; Log = $a.LogFile; Calls = $op.Calls }
}
function Invoke-E2EIsolateChurn([string]$Label, [string]$LogBase, [scriptblock]$Hook, [scriptblock]$MoveImpl) {
    # Up to 3 complete, fresh runs. PLAN_CHANGED_BEFORE_EXECUTION and REVALIDATION_REFUSED are the engine's fail-closed
    # refusals when the set changed after the plan (with the B1 exception: a process identity not inspectable that was
    # not in the plan); nothing is moved then. Each refusal is explained by comparing the identities recorded in the
    # log's plan record with a fresh inventory; Exhausted means every attempt was refused.
    $path = $ctx.Roots[$Label].Path
    Assert-Entry $path
    $churn = New-Object System.Collections.Generic.List[object]
    for ($n = 1; $n -le 3; $n++) {
        $c = Invoke-E2EIsolate -Paths @($path) -LogName "$LogBase-$n.jsonl" -Hook $Hook -MoveImpl $MoveImpl
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
# A child (ISO-P5b) never rewrites the helpers the parent may be running.
if (-not $ChildMode) { [IO.File]::WriteAllText($lockHelper, @'
param([string]$Dll, [string]$Out)
# B8 evidence from ANOTHER process: try the product lock once (never waits) and release it at once.
Add-Type -Path $Dll
$l = [AgentTempManager.AtmCleanLock]::TryAcquire('Global\AgentTempManager.Clean')
[IO.File]::WriteAllText($Out, [string]$l.Status)
if ($l.Acquired) { $rc = $l.Release(); if ($null -ne $rc) { [IO.File]::AppendAllText($Out, '|RELEASE_' + $rc) } }
'@) }
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

# ---------------------------------------------------------------------------------------------- ISO-P5b helpers
# A file held open by ANOTHER process of this harness: the path is handed over in a request file (never on the command
# line, so the runtime evidence does not see it as a reference); it ends by itself on a release file or a deadline.
$holdHelper = Join-Path $WorkDir 'hold-helper.ps1'
if (-not $ChildMode) { [IO.File]::WriteAllText($holdHelper, @'
param([string]$Request, [string]$Share, [string]$Ready, [string]$Release)
$path = [IO.File]::ReadAllText($Request)
$sh = $(if ($Share -eq 'None') { [IO.FileShare]::None } else { [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete })
$h = [IO.File]::Open($path, 'Open', 'Read', $sh)
try { [IO.File]::WriteAllText($Ready, '1'); $n = 0; while (-not (Test-Path -LiteralPath $Release) -and $n -lt 1800) { Start-Sleep -Milliseconds 100; $n++ } } finally { $h.Dispose() }
'@) }
function Start-HoldProcess([string]$File, [string]$Share, [string]$Tag) {
    $req = Join-Path $WorkDir "hold-$Tag.request"; $ready = Join-Path $WorkDir "hold-$Tag.ready"; $release = Join-Path $WorkDir "hold-$Tag.release"
    [IO.File]::WriteAllText($req, $File)
    $psi = New-Object Diagnostics.ProcessStartInfo($shellExe, ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Request "{1}" -Share {2} -Ready "{3}" -Release "{4}"' -f $holdHelper, $req, $Share, $ready, $release))
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true; $psi.WorkingDirectory = $WorkDir
    $p = [Diagnostics.Process]::Start($psi)
    $n = 0; while (-not (Test-Path -LiteralPath $ready) -and -not $p.HasExited -and $n -lt 600) { Start-Sleep -Milliseconds 100; $n++ }
    return [pscustomobject]@{ Process = $p; Ready = (Test-Path -LiteralPath $ready); Release = $release }
}
function Stop-HoldProcess($H) {
    # The helper releases the file and ends by itself (never terminated).
    [IO.File]::WriteAllText($H.Release, '1')
    if (-not $H.Process.WaitForExit(120000)) { throw 'processo auxiliar nao terminou (nunca encerrado a forca)' }
}
function New-RefusedMoveStub([string]$Reason) {
    # What the wrapper hands back when its attack could not be set up: the real mover is NOT called then.
    return [pscustomobject]@{ Moved = $false; Verified = $false; RenameStatus = $null; AbortReason = $Reason; FilesAfter = $null; DirsAfter = $null; BytesAfter = $null; DigestPlanned = $null; DigestAfter = $null }
}
function Start-IsoChild([string]$Mode, [string]$Root, [string]$LogName) {
    # This script again, as a child of the same account (real lock name); it ends by itself and is never terminated.
    $tag = [IO.Path]::GetFileNameWithoutExtension($LogName)
    $k = [pscustomobject]@{ Out = (Join-Path $WorkDir "child-$tag.txt"); Ready = (Join-Path $WorkDir "child-$tag.ready"); Release = (Join-Path $WorkDir "child-$tag.release"); Log = (New-E2ELogPath $LogName); Process = $null; So = $null; Se = $null }
    $argLine = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Leg {1} -InstallDir "{2}" -SummaryFile "{3}" -WorkDir "{4}" -DisposableMachine -ChildMode {5} -ChildRoot "{6}" -ChildLog "{7}" -ChildOut "{8}" -ChildReady "{9}" -ChildRelease "{10}"' -f $PSCommandPath, $Leg, $InstallDir, (Join-Path $WorkDir "child-summary-$tag.json"), $WorkDir, $Mode, $Root, $k.Log, $k.Out, $k.Ready, $k.Release
    $psi = New-Object Diagnostics.ProcessStartInfo($shellExe, $argLine)
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true; $psi.WorkingDirectory = $WorkDir
    $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
    $k.Process = [Diagnostics.Process]::Start($psi)
    $k.So = $k.Process.StandardOutput.ReadToEndAsync(); $k.Se = $k.Process.StandardError.ReadToEndAsync()
    return $k
}
function Wait-IsoChild($K) {
    if (-not $K.Process.WaitForExit(900000)) { throw 'processo filho nao terminou em 15 min (nunca encerrado a forca)' }
    $K.Process.WaitForExit()
    $text = ([string]$K.So.Result + ' ' + [string]$K.Se.Result) -replace '\s+', ' '
    return [pscustomobject]@{ Exit = $K.Process.ExitCode; Out = $(if (Test-Path -LiteralPath $K.Out) { [IO.File]::ReadAllText($K.Out) } else { $null }); Log = $K.Log
        Tail = $(if ($text.Length -gt 400) { $text.Substring($text.Length - 400) } else { $text.Trim() }) }
}
function Invoke-IsoChild {
    # Child mode: one run of its own on -ChildRoot (the parent checked the entry before starting it), then one line.
    $calls = @{ Presenter = 0 }
    $op = New-Operator
    $entries = @([pscustomobject]@{ Source = 'e2e-iso-child'; Path = $ChildRoot; Fingerprint = $null })
    if ($ChildMode -ceq 'K') {
        # The REAL mover with the engine's own arguments, then this process ends by itself before move-result
        # (Environment.Exit: never a forced termination); the lock and the log are left as an interrupted run leaves them.
        $kMove = {
            param($c, $entrySession, $name)
            $m = [AgentTempManager.AtmMover]::MoveTree($c.Path, $c.Files, $c.Dirs, $c.Bytes, $c.NewestWriteTimeUtc.Ticks, $entrySession, $name, $null)
            [IO.File]::WriteAllText($ChildOut, ('EXITED|{0}|{1}|{2}' -f [IO.Path]::GetFileName([string]$entrySession.ParentPath), [bool]$m.Moved, [bool]$m.Verified))
            [Environment]::Exit(7)
        }
        $pres = { param($verified, $rejected, $inventory, $planId) $calls.Presenter++ }.GetNewClosure()
        $a = @{ Entries = $entries; PlanPresenter = $pres; ConfirmationReader = $op.Reader; InventoryArgs = $ia; LogFile = $ChildLog; Interaction = $interaction; MoveTreeImpl = $kMove }
        if ($Leg -eq 'A') { $a['AcceptB1ResidualRisk'] = $true }
        $res = Invoke-AtmIsolate @a
    } else {
        # The deletion gate of clean, opened in THIS child's memory only, so that clean reaches the lock; the final phrase
        # is always wrong (CleanHold) or never asked (CleanTry: the lock is expected busy): nothing is deleted.
        $script:AtmRealDeletionEnabled = $true
        $holdInner = $op.Reader
        $reader = $op.Reader
        if ($ChildMode -ceq 'CleanHold') {
            $reader = {
                param($phrase, $kind, $rootPath, $choices, $info)
                if ($kind -ceq 'confirm') {
                    [IO.File]::WriteAllText($ChildReady, '1')
                    $n = 0; while (-not (Test-Path -LiteralPath $ChildRelease) -and $n -lt 3000) { Start-Sleep -Milliseconds 100; $n++ }
                    return 'APAGAR 1 CAMINHOS ZZZZZZZZ'
                }
                & $holdInner $phrase $kind $rootPath $choices $info
            }
        }
        $pres = { param($verified, $rejected, $inventory) $calls.Presenter++ }.GetNewClosure()
        $a = @{ Entries = $entries; PlanPresenter = $pres; ConfirmationReader = $reader; InventoryArgs = $ia; LogFile = $ChildLog; Interaction = $interaction }
        if ($Leg -eq 'A') { $a['AcceptB1ResidualRisk'] = $true }
        $res = Invoke-AtmClean @a
    }
    [IO.File]::WriteAllText($ChildOut, ('NOT_EXITED|{0}|{1}|{2}|{3}' -f $res.Aborted, $res.StoppedBy, $calls.Presenter, [bool]$res.LogCreated))
}
if ($ChildMode) {
    if (-not $ChildRoot -or -not $ChildLog -or -not $ChildOut) { throw 'modo filho sem raiz, log ou saida' }
    # Clean and isolate take the lock before any inventory: the installed library is loaded here first, by the engine's
    # own loader (only if its SHA-256 matches the manifest).
    Initialize-AtmNative -LibDir $lib
    Invoke-IsoChild
    exit 0
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
    # ISO-P5b: the target of the junction swapped in for a root (outside the base, never a planted root).
    $ctx.Sentinel = Join-Path $runRoot 'sentinel-jswap'
    [void][IO.Directory]::CreateDirectory($ctx.Sentinel)
    [IO.File]::WriteAllText((Join-Path $ctx.Sentinel 'keep.txt'), "sentinel: never moved`n")
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
    "$($labels.Count) roots, one scope each (set back ${shiftHours}h = SIMULATION), 3 files each, transcripts; a sentinel outside the base; user environment set"
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

Case 'measure-6.1-rename-open-handle' {
    # Contract section 6.1, in this harness's summary (both legs; no gate involved): the installed mover on trees of this
    # run root (outside the base, never an entry), into a destination pinned by AtmSafeCreate: nothing open, a file open
    # exclusively, a file open with full sharing, and a process (ending by itself) whose working directory is inside.
    Assert ($null -ne $ctx['LogDir']) 'raiz de execucao indisponivel'
    $m = Join-Path $runRoot 'm61'
    [void][IO.Directory]::CreateDirectory((Join-Path $m 'q'))
    $q = [AgentTempManager.AtmSafeCreate]::Pin((Join-Path $m 'q'))
    $out = New-Object System.Collections.Generic.List[string]
    try {
        if (-not $q.IsPinned) { return (NotTested "destination not pinned on this image: $($q.Error)") }
        $e = [AgentTempManager.AtmSafeCreate]::CreateNewDirectory($q, 'e', $mySid)
        try {
            if (-not $e.IsPinned) { return (NotTested "destination not created on this image: $($e.Error)") }
            $n = 0
            foreach ($case in @('none', 'file-exclusive', 'file-shared', 'cwd')) {
                $n++
                $r = Join-Path $m "t$n\root"
                [void][IO.Directory]::CreateDirectory((Join-Path $r 'd')); [IO.File]::WriteAllText((Join-Path $r 'd\f.txt'), 'x'); [IO.File]::WriteAllText((Join-Path $r 'g.txt'), 'yy')
                # NTFS updates directory times lazily after recent creations: scan until two scans agree (10 s at most).
                $s = $null; $prev = $null
                for ($i = 0; $i -lt 20 -and $null -eq $s; $i++) {
                    Start-Sleep -Milliseconds 500
                    $cur = [AgentTempManager.AtmScanner]::ScanTree($r, 3, 4096)
                    if ($null -ne $prev -and $cur.Files -eq $prev.Files -and $cur.Dirs -eq $prev.Dirs -and $cur.Bytes -eq $prev.Bytes -and $cur.NewestWriteTimeUtc -eq $prev.NewestWriteTimeUtc) { $s = $cur }
                    $prev = $cur
                }
                if ($null -eq $s) { $s = $prev }
                $h = $null; $p = $null
                if ($case -eq 'file-exclusive') { $h = [IO.File]::Open((Join-Path $r 'd\f.txt'), 'Open', 'ReadWrite', 'None') }
                if ($case -eq 'file-shared') { $h = [IO.File]::Open((Join-Path $r 'd\f.txt'), 'Open', 'Read', ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)) }
                if ($case -eq 'cwd') {
                    $psi = New-Object Diagnostics.ProcessStartInfo($shellExe, '-NoProfile -NonInteractive -Command Start-Sleep -Seconds 8')
                    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true; $psi.WorkingDirectory = (Join-Path $r 'd')
                    $p = [Diagnostics.Process]::Start($psi); Start-Sleep -Milliseconds 2000
                }
                try { $mv = [AgentTempManager.AtmMover]::MoveTree($r, $s.Files, $s.Dirs, $s.Bytes, $s.NewestWriteTimeUtc.Ticks, $e, "p$n", $null) }
                finally {
                    if ($null -ne $h) { $h.Dispose() }
                    # The helper ends by itself (never terminated).
                    if ($null -ne $p -and -not $p.WaitForExit(60000)) { throw 'processo com diretorio de trabalho na arvore nao terminou' }
                }
                $state = $(if ($mv.Moved -and $mv.Verified) { 'MOVED_VERIFIED' } elseif ([string]$mv.AbortReason -like 'PLAN_DIFFERS*') { 'NOT_TESTED_PLAN_DIFFERS' } elseif ($mv.Moved) { 'MOVED_' + ([regex]::Match([string]$mv.AbortReason, '^[A-Z0-9_]+')).Value } elseif ([IO.File]::Exists((Join-Path $r 'd\f.txt'))) { ([regex]::Match([string]$mv.AbortReason, '^[A-Z0-9_]+')).Value + '_SOURCE_INTACT' } else { ([regex]::Match([string]$mv.AbortReason, '^[A-Z0-9_]+')).Value + '_SOURCE_MISSING' })
                $out.Add("$case=$state")
            }
        } finally { $e.Dispose() }
    } finally { $q.Dispose() }
    $line = $out -join '|'
    $summary.section61 = $line
    Assert ($out[0] -match '^none=(MOVED_VERIFIED|NOT_TESTED_PLAN_DIFFERS)$') "mover: $line"
    foreach ($x in $out[1..3]) { Assert ($x -match '=(MOVED_VERIFIED|[A-Z_]+_SOURCE_INTACT|NOT_TESTED_PLAN_DIFFERS)$') "resultado: $x" }
    if ($line -match 'NOT_TESTED_PLAN_DIFFERS') { return (NotTested "a tree kept changing under the scan: $line") }
    "$((Get-CimInstance -ClassName Win32_OperatingSystem -Property Caption).Caption) $env:PROCESSOR_ARCHITECTURE`: $line"
}

# ---------------------------------------------------------------------------------------------- snapshots before the runs
if ($null -ne $ctx['LogDir'] -and $ctx.Roots.Count -eq $labels.Count) {
    $ctx.RunBefore = Get-Snapshot $runRoot ([long]::MaxValue)
    foreach ($label in $labels) { $ctx.Roots[$label] | Add-Member -NotePropertyName Tree -NotePropertyValue (Get-Snapshot $ctx.Roots[$label].Path ([long]::MaxValue)) }
    try { $ctx.TempBefore = Get-Snapshot ([IO.Path]::GetTempPath().TrimEnd('\')) 1MB } catch { $ctx.TempBefore = $null }
}
function Assert-QuarantineUnchanged([string]$What) {
    Assert ($null -ne $ctx['QBefore']) 'sem fotografia da quarentena'
    $d = Compare-Snapshot $ctx.QBefore (Get-Snapshot $qArea ([long]::MaxValue) -Skip @($ctx.QSkip))
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
    $ctx.Touched.Add($root.Scope.Substring($runRoot.Length).TrimStart('\'))
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

# ---------------------------------------------------------------------------------------------- ISO-P5b
function Assert-StoppedRefused($C, [string]$Label, [string]$What) {
    # A run stopped by the real mover's refusal: one result REFUSED, nothing moved, the log and the manifest read back,
    # the entry FAILED with no payload, the root identical by SHA-256, size and write time. Returns the mover's code.
    $r = $C.Res
    Assert ($r.StoppedBy -ceq 'STOPPED_AFTER_REFUSED' -and @($r.Results).Count -eq 1 -and $r.Results[0].Outcome -ceq 'REFUSED' -and $r.Results[0].Moved -eq $false) "$What`: Aborted=$($r.Aborted) StoppedBy=$($r.StoppedBy) resultado=$(@($r.Results | ForEach-Object { $_.Outcome }) -join ',')"
    $code = ([regex]::Match([string]$r.Results[0].AbortReason, '^[A-Z0-9_]+')).Value
    $recs = Read-E2ELog $C.Log
    $types = Get-Types $recs
    Assert ($types -ceq 'run-start,plan,confirmation,plan-check,move-intent,move-result,run-end' -and $recs[5].outcome -ceq 'REFUSED' -and $recs[6].stoppedBy -ceq 'STOPPED_AFTER_REFUSED') "$What`: log $types"
    $man = Read-E2ELog (Join-Path $r.EntryPath 'manifest.jsonl')
    $mt = Get-Types $man
    Assert ($mt -ceq 'entry,move-intent,move-result' -and $man[2].outcome -ceq 'REFUSED') "$What`: manifesto $mt"
    $e = Get-AtmQuarantineEntry -Id $r.EntryId
    Assert ($null -ne $e -and $e.State -ceq 'FAILED' -and -not $e.PayloadPresent) "$What`: estado $(if ($e) { $e.State })"
    return [pscustomobject]@{ Code = $code; Types = $types; Manifest = $mt }
}
function Assert-TreeSame([string]$Path, $Tree, [string]$What) {
    $d = Compare-Snapshot $Tree (Get-Snapshot $Path ([long]::MaxValue))
    Assert ((Get-DiffCount $d) -eq 0) "$What`: arvore alterada ($($d.Removed.Count) ausentes, $($d.Added.Count) novas, $($d.Changed.Count) alteradas)"
}

Case 'ISO-open-file-before-plan' {
    if ($Leg -eq 'B') { return (NotTested 'leg B: B1 (coverage measured incomplete) refuses before the in-use probe, so the probe is not observable in this leg; never forced') }
    $nt = & $needEligible; if ($nt) { return $nt }
    $root = $ctx.Roots['openA']
    Assert-Entry $root.Path
    $f = Join-Path $root.Path 'scratchpad\SYNTHETIC.txt'
    $h = Start-HoldProcess $f 'None' 'openA'
    $c = $null
    try {
        Assert $h.Ready 'processo auxiliar nao abriu o arquivo'
        $probe = Get-Codes @((Get-AtmLockProbeReasons $root.Path).Reasons)
        Assert ($probe -match 'EM_USO') "sondagem direta sem EM_USO: $probe"
        $c = Invoke-E2EIsolate -Paths @($root.Path) -LogName 'ISO-openA.jsonl'
    } finally { Stop-HoldProcess $h }
    Assert ($c.Res.Aborted -ceq 'NENHUM_CAMINHO_ISOLAVEL' -and $c.Calls.Count -eq 0 -and -not (Test-Path -LiteralPath $c.Log)) "Aborted=$($c.Res.Aborted)"
    $codes = Get-Codes $c.Res.Rejected[0].Reasons
    Assert ($codes -match 'COBERTURA_DE_PROCESSOS_INCOMPLETA') "razoes: $codes"
    Assert-TreeSame $root.Path $root.Tree 'raiz'
    Assert-QuarantineUnchanged 'arquivo aberto antes do plano'
    "a file held (no sharing) by another process of the harness before the plan: the in-use probe sees it (EM_USO) and removes the B1 exception (F6), so the root is refused ($codes), NENHUM_CAMINHO_ISOLAVEL; no question, no log, root and quarantine unchanged"
}
Case 'ISO-open-file-in-move-window' {
    $nt = & $needEligible; if ($nt) { return $nt }
    $root = $ctx.Roots['openB']
    # Between the revalidation and the mover: another process of the harness opens a file of the root with full sharing,
    # then the REAL mover runs with the engine's own arguments (section 6.1: the rename is refused, the source intact).
    $isoHold = @{ H = $null; File = (Join-Path $root.Path 'scratchpad\SYNTHETIC.txt'); Ready = $false }
    $mvImpl = {
        param($c, $entrySession, $name)
        $isoHold.H = Start-HoldProcess $isoHold.File 'Full' 'openB'
        $isoHold.Ready = [bool]$isoHold.H.Ready
        if (-not $isoHold.Ready) { New-RefusedMoveStub 'E2E_ATTACK_NOT_APPLIED' }
        else { [AgentTempManager.AtmMover]::MoveTree($c.Path, $c.Files, $c.Dirs, $c.Bytes, $c.NewestWriteTimeUtc.Ticks, $entrySession, $name, $null) }
    }
    try { $c = Invoke-E2EIsolateChurn -Label 'openB' -LogBase 'ISO-openB' -MoveImpl $mvImpl } finally { if ($null -ne $isoHold.H) { Stop-HoldProcess $isoHold.H } }
    if ($c.Exhausted) { return (Resolve-Exhausted $c) }
    Assert $isoHold.Ready 'ataque nao aplicado: o processo auxiliar nao abriu o arquivo'
    $s = Assert-StoppedRefused $c 'openB' 'mover'
    Assert-TreeSame $root.Path $root.Tree 'raiz'
    "a file held open (full sharing) by another process of the harness between the revalidation and the real mover: the mover refused ($($s.Code)), nothing moved, STOPPED_AFTER_REFUSED; log $($s.Types); manifest $($s.Manifest); entry FAILED with no payload; root identical; $(Get-AttemptText $c)"
}
Case 'ISO-interrupt-after-move-intent' {
    $nt = & $needEligible; if ($nt) { return $nt }
    $root = $ctx.Roots['interrupt']
    Assert-Entry $root.Path
    # A child of the same account isolates the root and ends by itself right after the real mover, before move-result.
    $ctx.Touched.Add($root.Scope.Substring($runRoot.Length).TrimStart('\'))
    $tries = New-Object System.Collections.Generic.List[string]
    $k = $null
    for ($n = 1; $n -le 3 -and $null -eq $k; $n++) {
        $w = Wait-IsoChild (Start-IsoChild 'K' $root.Path "ISO-interrupt-$n.jsonl")
        if ($w.Exit -eq 7) { $k = $w; break }
        Assert ($w.Exit -eq 0 -and $w.Out -and ($w.Out -cmatch '^NOT_EXITED\|(PLAN_CHANGED_BEFORE_EXECUTION|REVALIDATION_REFUSED)\|')) "filho saiu com $($w.Exit): $($w.Out) [$($w.Tail)]"
        $tries.Add(($w.Out -split '\|')[1])
    }
    if ($null -eq $k) { return (NotTested "the child was refused before the mover in all 3 attempts (process churn): $($tries -join ', ')") }
    $p = @($k.Out -split '\|')
    Assert ($p.Count -eq 4 -and $p[0] -ceq 'EXITED' -and $p[2] -ceq 'True' -and $p[3] -ceq 'True') "saida do filho: $($k.Out)"
    $id = $p[1]
    Assert ($id -cmatch '^\d{8}T\d{6}Z-[0-9a-f]{8}$') 'id da entrada do filho fora do formato'
    Add-EntryId $id
    $lt = Get-Types (Read-E2ELog $k.Log)
    Assert ($lt -ceq 'run-start,plan,confirmation,plan-check,move-intent') "o log do filho deve terminar no move-intent: $lt"
    $e = Get-AtmQuarantineEntry -Id $id
    Assert ($null -ne $e -and $e.State -ceq 'INCOMPLETE' -and $e.Pending -ceq 'move' -and $e.PayloadPresent -and -not (Test-Path -LiteralPath $root.Path)) "entrada: $(if ($e) { $e.State + '/' + $e.Pending })"
    $mt0 = Get-Types (Read-E2ELog (Join-Path $e.Path 'manifest.jsonl'))
    Assert ($mt0 -ceq 'entry,move-intent') "manifesto antes da reconciliacao: $mt0"
    # The restore reconciles the entry first (T-ISO-5). A lock left abandoned by the child is reported once by the engine.
    $abandoned = $false
    $op = New-Operator
    $res = Invoke-AtmRestore -Id $id -PlanPresenter $rstPresenter -ConfirmationReader $op.Reader -InventoryArgs $ia -LogFile (New-E2ELogPath 'ISO-interrupt-restore.jsonl') -Interaction $interaction
    if ($res.Aborted -ceq 'CLEAN_LOCK_ABANDONED') {
        $abandoned = $true
        $op = New-Operator
        $res = Invoke-AtmRestore -Id $id -PlanPresenter $rstPresenter -ConfirmationReader $op.Reader -InventoryArgs $ia -LogFile (New-E2ELogPath 'ISO-interrupt-restore-2.jsonl') -Interaction $interaction
    }
    Assert (-not $res.Aborted -and -not $res.StoppedBy) "Aborted=$($res.Aborted) StoppedBy=$($res.StoppedBy) razoes=$(Get-PlanCodes $res)"
    Assert ($res.Plan.Reconcile -eq $true -and $res.Plan.Conflict -eq $false -and @($res.Results).Count -eq 1 -and $res.Results[0].Outcome -ceq 'COMPLETE' -and $res.Results[0].Verified -eq $true) 'restauracao sem reconciliacao ou incompleta'
    $types = Get-Types (Read-E2ELog $res.LogFile)
    Assert ($types -ceq 'run-start,confirmation,plan-check,reconcile,restore-intent,restore-result,run-end') "log da restauracao: $types"
    $e2 = Get-AtmQuarantineEntry -Id $id
    $mt = Get-Types (Read-E2ELog (Join-Path $e2.Path 'manifest.jsonl'))
    Assert ($mt -ceq 'entry,move-intent,reconcile,restore-intent,restore-result' -and $e2.State -ceq 'RESTORED' -and -not $e2.PayloadPresent) "manifesto: $mt; estado $($e2.State)"
    Assert-TreeSame $root.Path $root.Tree 'raiz restaurada'
    "a child ended by itself right after the real mover (exit 7, never terminated): log ends at move-intent, manifest $mt0, entry INCOMPLETE (move) with the payload present and the original absent; the restore reconciled it first (T-ISO-5$(if ($abandoned) { '; the lock left abandoned by the child reported once as CLEAN_LOCK_ABANDONED' })): log $types, manifest $mt, RESTORED, tree identical$(if ($tries.Count) { '; earlier attempts: ' + ($tries -join ', ') })"
}
Case 'ISO-concurrency-isolate-holds-clean-busy' {
    $nt = & $needEligible; if ($nt) { return $nt }
    $conc = $ctx.Roots['conc']; $xc = $ctx.Roots['xclean']
    Assert-Entry $conc.Path; Assert-Entry $xc.Path
    # This process isolates and holds the lock through its questions; at the final phrase a child runs a complete clean
    # (its own deletion gate opened in its memory) and must be refused at once. Then a wrong phrase: nothing is moved.
    $isoConc = @{ Child = $null }
    $concInner = (New-Operator).Reader
    $concOp = @{ Calls = (New-Object System.Collections.Generic.List[string]) }
    $concOp.Reader = {
        param($phrase, $kind, $rootPath, $choices, $info)
        $concOp.Calls.Add([string]$kind)
        if ($kind -ceq 'confirm') {
            if ($null -eq $isoConc.Child) { $isoConc.Child = Wait-IsoChild (Start-IsoChild 'CleanTry' $xc.Path 'ISO-X1-clean.jsonl') }
            return 'ISOLAR 1 CAMINHOS ZZZZZZZZ'
        }
        & $concInner $phrase $kind $rootPath $choices $info
    }
    $c = Invoke-E2EIsolate -Paths @($conc.Path) -LogName 'ISO-X1-isolate.jsonl' -Operator $concOp
    Assert ($null -ne $isoConc.Child) 'a limpeza concorrente nao foi iniciada'
    $k = $isoConc.Child
    Assert ($k.Exit -eq 0 -and $k.Out -ceq 'NOT_EXITED|CLEAN_LOCK_BUSY||0|False' -and -not (Test-Path -LiteralPath $k.Log)) "limpeza concorrente: exit $($k.Exit), $($k.Out) [$($k.Tail)]"
    Assert ($c.Res.Aborted -ceq 'CONFIRMACAO_AUSENTE_OU_DIVERGENTE' -and @($c.Res.Results).Count -eq 0 -and $null -eq $c.Res.EntryId) "isolamento: $($c.Res.Aborted)"
    $types = Get-Types (Read-E2ELog $c.Log)
    Assert ($types -ceq 'run-start,plan,confirmation,run-end') "log do isolamento: $types"
    Assert-TreeSame $conc.Path $conc.Tree 'raiz do isolamento'
    Assert-TreeSame $xc.Path $xc.Tree 'raiz da limpeza'
    "isolate holding the lock at its final phrase; a complete clean of another root in a child (deletion gate open in its memory only): CLEAN_LOCK_BUSY at once (presenter never called, no log, nothing deleted); the isolation then given a wrong phrase stopped (log $types); both roots identical"
}
Case 'ISO-concurrency-clean-holds-isolate-busy' {
    $nt = & $needEligible; if ($nt) { return $nt }
    $conc = $ctx.Roots['conc']; $xc = $ctx.Roots['xclean']
    Assert-Entry $conc.Path; Assert-Entry $xc.Path
    # A child runs a clean (its own deletion gate opened in its memory) that holds the lock at its final phrase until
    # released, then answers a wrong phrase: it never deletes. Meanwhile this process tries to isolate another root.
    $k = Start-IsoChild 'CleanHold' $xc.Path 'ISO-X2-clean.jsonl'
    $c = $null
    try {
        $n = 0; while (-not (Test-Path -LiteralPath $k.Ready) -and -not $k.Process.HasExited -and $n -lt 6000) { Start-Sleep -Milliseconds 100; $n++ }
        if (Test-Path -LiteralPath $k.Ready) { $c = Invoke-E2EIsolate -Paths @($conc.Path) -LogName 'ISO-X2-isolate.jsonl' }
    } finally { [IO.File]::WriteAllText($k.Release, '1') }
    $w = Wait-IsoChild $k
    Assert ($null -ne $c) "a limpeza do filho nao chegou a frase final: exit $($w.Exit), $($w.Out) [$($w.Tail)]"
    Assert ($c.Res.Aborted -ceq 'CLEAN_LOCK_BUSY' -and -not $c.Res.LogCreated -and -not (Test-Path -LiteralPath $c.Log) -and $c.Calls.Count -eq 0) "isolamento: Aborted=$($c.Res.Aborted) log=$($c.Res.LogCreated)"
    Assert ($w.Exit -eq 0 -and $w.Out -cmatch '^NOT_EXITED\|CONFIRMACAO_AUSENTE_OU_DIVERGENTE\|') "limpeza do filho: exit $($w.Exit), $($w.Out) [$($w.Tail)]"
    $recs = Read-E2ELog $w.Log
    $types = Get-Types $recs
    Assert (@($recs | Where-Object { $_.type -ceq 'intent' }).Count -eq 0 -and @($recs | Where-Object { $_.type -ceq 'confirmation' -and $_.accepted -eq $false }).Count -eq 1 -and $recs[-1].type -ceq 'run-end') "log da limpeza: $types"
    Assert-TreeSame $conc.Path $conc.Tree 'raiz do isolamento'
    Assert-TreeSame $xc.Path $xc.Tree 'raiz da limpeza'
    Assert-QuarantineUnchanged 'concorrencia'
    "a clean in a child holding the lock at its final phrase: isolate refused CLEAN_LOCK_BUSY at once (no inventory, no question, no log, no entry); the clean then given a wrong phrase stopped without deleting (log $types, 0 intents); both roots identical"
}
Case 'ISO-second-volume' {
    $nt = & $needEligible; if ($nt) { return $nt }
    $sys = [IO.Path]::GetPathRoot($runRoot)
    $vols = @([IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq [IO.DriveType]::Fixed -and $_.IsReady -and -not [string]::Equals($_.Name, $sys, [StringComparison]::OrdinalIgnoreCase) })
    if ($vols.Count -eq 0) { $summary.secondVolume = 'NONE'; return (NotTested 'no second fixed volume on this runner') }
    $vr = Join-Path $vols[0].Name ('ATM-E2E-ISO2-' + $Leg + '-' + $nonce.Substring(0, 12))
    Assert (-not (Test-Path -LiteralPath $vr)) 'RUN_ROOT_EXISTS (segundo volume)'
    $ds = New-Object Security.AccessControl.DirectorySecurity
    $ds.SetSecurityDescriptorSddlForm("O:$($mySid)D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;$mySid)")
    try { if ($PSVersionTable.PSEdition -eq 'Core') { $ext = 'System.IO.FileSystemAclExtensions' -as [type]; $null = $ext::CreateDirectory($ds, $vr) } else { $null = [IO.Directory]::CreateDirectory($vr, $ds) } }
    catch { $summary.secondVolume = 'NOT_WRITABLE'; return (NotTested "measured: this account cannot create a folder at the root of the second fixed volume ($($_.Exception.GetType().Name))") }
    $summary.secondVolume = 'PRESENT'
    $tmp2 = Join-Path $vr 'tmpdir'; $base2 = Join-Path $tmp2 'claude'
    $slug = 'C--atm-e2e-iso-vol'; $id = [guid]::NewGuid().ToString()
    $rp = Join-Path $base2 "$slug\$id"
    [void][IO.Directory]::CreateDirectory((Join-Path $rp 'scratchpad'))
    [IO.File]::WriteAllText((Join-Path $rp 'scratchpad\SYNTHETIC.txt'), "synthetic ISO-P5b fixture (second volume)`n")
    [IO.File]::WriteAllText((Join-Path $rp 'ATM-E2E-NONCE.txt'), $nonce)
    $pj = Join-Path $ctx.Cfg "projects\$slug"; [void][IO.Directory]::CreateDirectory($pj)
    $ctx.Touched.Add($pj.Substring($runRoot.Length).TrimStart('\'))
    $tr = Join-Path $pj "$id.jsonl"
    [IO.File]::WriteAllText($tr, ('{"type":"ai-title","aiTitle":"SYNTHETIC","sessionId":"' + $id + '"}' + "`n"))
    if ($isAdmin) { Set-AccountOwner $tmp2 }
    Start-Sleep -Seconds 2
    Set-SimulatedOld -Files @((Join-Path $rp 'scratchpad\SYNTHETIC.txt'), (Join-Path $rp 'ATM-E2E-NONCE.txt'), $tr) -Dirs @((Join-Path $rp 'scratchpad'), $rp)
    $ctx.ExtraBases.Add(@{ Base = $base2; Top = $vr })
    $ctx.Roots['vol'] = [pscustomobject]@{ Label = 'vol'; Id = $id; Slug = $slug; Scope = (Join-Path $base2 $slug); Path = $rp; Transcript = $tr; Tree = (Get-Snapshot $rp ([long]::MaxValue)) }
    $volBefore = Get-Snapshot $vr ([long]::MaxValue)
    # The base of this run moved to the second volume for this case only (user environment and process), then back.
    $k = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
    try { $k.SetValue('CLAUDE_CODE_TMPDIR', $tmp2, [Microsoft.Win32.RegistryValueKind]::String) } finally { $k.Close() }
    [Environment]::SetEnvironmentVariable('CLAUDE_CODE_TMPDIR', $tmp2, 'Process')
    try {
        $inv = Invoke-AtmInventory @ia
        $m = @($inv.Partitions | Where-Object { $_.Kind -ne 'BaseLooseFiles' -and [string]::Equals($_.Path, $rp, [StringComparison]::OrdinalIgnoreCase) })
        if ($m.Count -ne 1) { return (NotTested "the root on the second volume was not inventoried through the user environment ($($m.Count))") }
        $ctx.Roots['vol'].Path = $m[0].Path
        $c = Invoke-E2EIsolateChurn -Label 'vol' -LogBase 'ISO-vol'
    } finally {
        $k = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
        try { $k.SetValue('CLAUDE_CODE_TMPDIR', $ctx.Tmp, [Microsoft.Win32.RegistryValueKind]::String) } finally { $k.Close() }
        [Environment]::SetEnvironmentVariable('CLAUDE_CODE_TMPDIR', $ctx.Tmp, 'Process')
    }
    if ($c.Exhausted) { return (Resolve-Exhausted $c) }
    $r = $c.Res
    Assert (Test-Path -LiteralPath $rp) 'raiz do segundo volume ausente'
    Assert-TreeSame $rp $ctx.Roots['vol'].Tree 'raiz do segundo volume'
    $dv = Compare-Snapshot $volBefore (Get-Snapshot $vr ([long]::MaxValue))
    Assert ((Get-DiffCount $dv) -eq 0) "segundo volume alterado: $(Get-DiffCount $dv)"
    if ($r.Aborted -ceq 'NENHUM_CAMINHO_ISOLAVEL') {
        $codes = Get-Codes $r.Rejected[0].Reasons
        $summary.secondVolume = 'REFUSED_AT_PLAN'
        if ($codes -match 'VOLUME') { return "a root on another fixed volume than the quarantine: refused at the plan ($codes); nothing created or moved" }
        return (NotTested "the root on the second volume did not reach the volume rule; refused at the plan for other reasons: $codes")
    }
    $s = Assert-StoppedRefused $c 'vol' 'segundo volume'
    Assert ($s.Code -match 'OTHER_VOLUME') "recusa do mover: $($s.Code)"
    $summary.secondVolume = 'REFUSED_BY_MOVER'
    "a root on another fixed volume than the quarantine: the plan does not refuse it (the target rule and the gates accept it); the real mover refused it ($($s.Code)) after move-intent, nothing moved; entry FAILED with no payload, log $($s.Types); the root and the second volume identical. Finding: contract section 4 lists a base on another volume as not isolable; the refusal happens at the mover, not at the plan; $(Get-AttemptText $c)"
}
Case 'ISO-junction-swapped-in-window' {
    $nt = & $needEligible; if ($nt) { return $nt }
    $root = $ctx.Roots['jswap']
    $sentBefore = Get-Snapshot $ctx.Sentinel ([long]::MaxValue)
    $ctx.Touched.Add($root.Scope.Substring($runRoot.Length).TrimStart('\'))
    # Between the revalidation and the mover: the root is renamed aside and a junction to a sentinel outside the base takes
    # its name; then the REAL mover runs with the engine's own arguments.
    $isoSwap = @{ Status = $null; Aside = ($root.Path + '-aside'); Sentinel = $ctx.Sentinel }
    $mvImpl = {
        param($c, $entrySession, $name)
        try {
            [IO.Directory]::Move($c.Path, $isoSwap.Aside)
            $null = & (Join-Path $env:SystemRoot 'System32\cmd.exe') /c mklink /J "$($c.Path)" "$($isoSwap.Sentinel)" 2>&1
            $isoSwap.Status = $(if ((Test-Path -LiteralPath $c.Path) -and ([IO.File]::GetAttributes($c.Path) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { 'SWAPPED' } else { 'JUNCTION_NOT_CREATED' })
        } catch { $isoSwap.Status = 'SWAP_' + $_.Exception.GetType().Name }
        if ($isoSwap.Status -cne 'SWAPPED') { New-RefusedMoveStub 'E2E_ATTACK_NOT_APPLIED' }
        else { [AgentTempManager.AtmMover]::MoveTree($c.Path, $c.Files, $c.Dirs, $c.Bytes, $c.NewestWriteTimeUtc.Ticks, $entrySession, $name, $null) }
    }
    $c = Invoke-E2EIsolateChurn -Label 'jswap' -LogBase 'ISO-jswap' -MoveImpl $mvImpl
    if ($c.Exhausted) { return (Resolve-Exhausted $c) }
    Assert ($isoSwap.Status -ceq 'SWAPPED') "ataque nao aplicado: $($isoSwap.Status)"
    $s = Assert-StoppedRefused $c 'jswap' 'juncao'
    Assert ((([IO.File]::GetAttributes($root.Path)) -band [IO.FileAttributes]::ReparsePoint) -ne 0) 'a juncao saiu do lugar'
    Assert-TreeSame $isoSwap.Aside $root.Tree 'raiz renomeada'
    $ds = Compare-Snapshot $sentBefore (Get-Snapshot $ctx.Sentinel ([long]::MaxValue))
    Assert ((Get-DiffCount $ds) -eq 0) 'sentinela alterada'
    "the root swapped for a junction to a sentinel outside the base between the revalidation and the real mover: the mover refused ($($s.Code)), nothing moved through the junction; STOPPED_AFTER_REFUSED, log $($s.Types); entry FAILED with no payload; the sentinel, the junction and the root (renamed aside) unchanged; $(Get-AttemptText $c)"
}
Case 'ISO-200k-files' {
    if (-not $Heavy) { return (NotTested 'scale runs in one x64 job of the matrix only (windows-2025, installer pwsh, leg A); not this one') }
    if ($env:PROCESSOR_ARCHITECTURE -ne 'AMD64') { return (NotTested 'scale runs on x64 only') }
    $nt = & $needEligible; if ($nt) { return $nt }
    # Planted after the run-root snapshot, last of all the cases (every later inventory would scan it), in a scope the
    # snapshot does not enter. 200 folders of 1,000 one-byte files, then the nonce; times set back (SIMULATION).
    $slug = 'C--atm-e2e-iso-heavy'; $id = [guid]::NewGuid().ToString()
    $scope = Join-Path $ctx.Base $slug; $rp = Join-Path $scope $id
    $ctx.Skip.Add($scope)
    $ctx.Touched.Add($scope.Substring($runRoot.Length).TrimStart('\'))
    # Time budget (the round: "if it fits the job's limit, else NAO_TESTADO with the partial measurement"): everything
    # below must end before $heavyDeadline after this harness started; each engine call starts only if its projection
    # (from the measured inventory of this root) fits. One attempt only: churn here is NAO_TESTADO with the timings.
    $left = { $heavyDeadline - $harnessClock.Elapsed }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $one = [byte[]]@(120)
    $made = 0
    for ($d = 0; $d -lt 200 -and (& $left) -gt [TimeSpan]::FromMinutes(12); $d++) {
        $dir = Join-Path $rp ('d{0:D3}' -f $d)
        [void][IO.Directory]::CreateDirectory($dir)
        for ($f = 0; $f -lt 1000; $f++) { [IO.File]::WriteAllBytes((Join-Path $dir ('f{0:D4}.bin' -f $f)), $one); $made++ }
    }
    [IO.File]::WriteAllText((Join-Path $rp 'ATM-E2E-NONCE.txt'), $nonce)
    $summary.heavy = [ordered]@{ planned = 200000; files = $made; plantSeconds = $null; inventorySeconds = $null; isolateSeconds = $null; restoreSeconds = $null }
    if ($made -lt 200000) { $summary.heavy.plantSeconds = [math]::Round($sw.Elapsed.TotalSeconds, 1); return (NotTested "partial measurement: $made files planted in $($summary.heavy.plantSeconds) s before the time budget of the job ran short; the isolation was not started") }
    $pj = Join-Path $ctx.Cfg "projects\$slug"; [void][IO.Directory]::CreateDirectory($pj)
    $ctx.Touched.Add($pj.Substring($runRoot.Length).TrimStart('\'))
    $tr = Join-Path $pj "$id.jsonl"
    [IO.File]::WriteAllText($tr, ('{"type":"ai-title","aiTitle":"SYNTHETIC","sessionId":"' + $id + '"}' + "`n"))
    Start-Sleep -Seconds 2
    $old = [datetime]::UtcNow.AddHours(-$shiftHours)
    $timed = 0
    foreach ($fi in (New-Object IO.DirectoryInfo $rp).EnumerateFiles('*', [IO.SearchOption]::AllDirectories)) {
        if (($timed % 10000) -eq 0 -and (& $left) -lt [TimeSpan]::FromMinutes(10)) { break }
        [IO.File]::SetLastWriteTimeUtc($fi.FullName, $old); $timed++
    }
    $summary.heavy.plantSeconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    if ($timed -lt 200001) { return (NotTested "partial measurement: 200,001 files planted, $timed write times set back in $($summary.heavy.plantSeconds) s before the time budget of the job ran short; the isolation was not started") }
    foreach ($di in (New-Object IO.DirectoryInfo $rp).EnumerateDirectories('*', [IO.SearchOption]::TopDirectoryOnly)) { [IO.Directory]::SetLastWriteTimeUtc($di.FullName, $old) }
    [IO.Directory]::SetLastWriteTimeUtc($rp, $old); [IO.File]::SetLastWriteTimeUtc($tr, $old)
    $ctx.Roots['heavy'] = [pscustomobject]@{ Label = 'heavy'; Id = $id; Slug = $slug; Scope = $scope; Path = $rp; Transcript = $tr; Tree = $null }
    $one1 = @{} + $ia; $one1['OnlyRootPath'] = $rp
    $sw.Restart()
    $p0 = @((Invoke-AtmInventory @one1).Partitions | Where-Object { [string]::Equals($_.Path, $rp, [StringComparison]::OrdinalIgnoreCase) -and $_.Kind -ne 'BaseLooseFiles' })
    $inv = $sw.Elapsed
    $summary.heavy.inventorySeconds = [math]::Round($inv.TotalSeconds, 1)
    Assert ($p0.Count -eq 1 -and [long]$p0[0].Files -eq 200001) "raiz pesada inventariada: $(@($p0 | ForEach-Object { [string]$_.Kind + '/' + [string]$_.Files }) -join ',')"
    $ctx.Roots['heavy'].Path = $p0[0].Path
    $st0 = '{0}/{1}/{2}/{3}' -f $p0[0].Files, $p0[0].Dirs, $p0[0].Bytes, ([datetime]$p0[0].NewestWriteTimeUtc).ToUniversalTime().Ticks
    $timings = { "plant $($summary.heavy.plantSeconds) s, one inventory of the root $($summary.heavy.inventorySeconds) s, isolate $($summary.heavy.isolateSeconds) s, restore $($summary.heavy.restoreSeconds) s" }
    # Isolate: about 3 inventories and 3 in-use probes of the base, the move and its two measurements.
    if ((& $left) -lt [TimeSpan]::FromTicks($inv.Ticks * 8)) { return (NotTested "partial measurement: $(& $timings); the isolation projected past the time budget of the job, not started") }
    Assert-Entry $rp
    $sw.Restart()
    $c = Invoke-E2EIsolate -Paths @($rp) -LogName 'ISO-heavy.jsonl'
    $summary.heavy.isolateSeconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    # The quarantine snapshot does not enter the 200,000 files if they stay in the entry (no restore, or a failed one).
    if ($c.Res.EntryId) { $ctx.QSkip.Add((Join-Path (Join-Path $qRoot $c.Res.EntryId) 'payload')) }
    if (@('PLAN_CHANGED_BEFORE_EXECUTION', 'REVALIDATION_REFUSED') -ccontains [string]$c.Res.Aborted) { return (NotTested "refused before the mover by process churn of the runner ($($c.Res.Aborted)), one attempt only for this case; $(& $timings)") }
    $null = Assert-Isolated ([pscustomobject]@{ Res = $c.Res; Log = $c.Log; Calls = $c.Calls; Attempts = 1; Churn = @(); Exhausted = $false }) 'heavy'
    $mi = @(Read-E2ELog $c.Log | Where-Object { $_.type -ceq 'move-result' })[0]
    Assert ([long]$mi.filesAfter -eq 200001) "move-result: $($mi.filesAfter) arquivos"
    $hid = $ctx.Iso['heavy']
    # Restore: about 2 inventories of the base, the verification of the payload, the move and its two measurements.
    if ((& $left) -lt [TimeSpan]::FromTicks($inv.Ticks * 6)) { return (NotTested "partial measurement: isolated (COMPLETE, 200,001 files verified); $(& $timings); the restore projected past the time budget of the job, not started (the entry stays ISOLATED in the VM's quarantine)") }
    $op = New-Operator
    $sw.Restart()
    $res = Invoke-AtmRestore -Id $hid -PlanPresenter $rstPresenter -ConfirmationReader $op.Reader -InventoryArgs $ia -LogFile (New-E2ELogPath 'ISO-heavy-restore.jsonl') -Interaction $interaction
    $summary.heavy.restoreSeconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    Assert (-not $res.Aborted -and -not $res.StoppedBy -and @($res.Results).Count -eq 1 -and $res.Results[0].Outcome -ceq 'COMPLETE') "restauracao: $($res.Aborted) $($res.StoppedBy) razoes=$(Get-PlanCodes $res)"
    $p1 = @((Invoke-AtmInventory @one1).Partitions | Where-Object { [string]::Equals($_.Path, $rp, [StringComparison]::OrdinalIgnoreCase) -and $_.Kind -ne 'BaseLooseFiles' })
    $st1 = $(if ($p1.Count -eq 1) { '{0}/{1}/{2}/{3}' -f $p1[0].Files, $p1[0].Dirs, $p1[0].Bytes, ([datetime]$p1[0].NewestWriteTimeUtc).ToUniversalTime().Ticks } else { 'MISSING' })
    Assert ($st1 -ceq $st0) "estatisticas antes $st0, depois $st1"
    "200,001 files (200 folders): planted and set back in $($summary.heavy.plantSeconds) s; one inventory of the root $($summary.heavy.inventorySeconds) s; isolated by the real mover in $($summary.heavy.isolateSeconds) s (plan, plan check, revalidation, move; move-result 200,001 files verified); restored in $($summary.heavy.restoreSeconds) s (COMPLETE); files, folders, bytes and newest write time identical before and after"
}

# ---------------------------------------------------------------------------------------------- snapshots after the runs
Case 'snapshot-run-root' {
    if ($null -eq $ctx['RunBefore']) { return (NotTested 'no snapshot before the runs') }
    $d = Compare-Snapshot $ctx.RunBefore (Get-Snapshot $runRoot ([long]::MaxValue) -Skip @($ctx.Skip))
    $purgeRel = $ctx.Roots['purge'].Path.Substring($runRoot.Length).TrimStart('\')
    $allowed = {
        param([string]$k, [string]$kind)
        # Scopes a case changed on purpose and checked itself (conflict, interruption, junction, scale, their transcripts).
        if (@($ctx.Touched | Where-Object { Test-Under $k $_ }).Count -gt 0) { return $true }
        # The purge root left the run root when it was isolated (purged or not afterwards).
        if ($kind -ceq 'Removed' -and $ctx.Iso.ContainsKey('purge') -and (Test-Under $k $purgeRel)) { return $true }
        if ($kind -ceq 'Added' -and $ctx.Logs.Contains($(if ($k.StartsWith('log\', [StringComparison]::OrdinalIgnoreCase)) { $k.Substring(4) } else { '' }))) { return $true }
        return $false
    }
    $bad = @(@($d.Removed | Where-Object { -not (& $allowed $_ 'Removed') }) + @($d.Added | Where-Object { -not (& $allowed $_ 'Added') }) + @($d.Changed | Where-Object { -not (& $allowed $_ 'Changed') }))
    Assert ($bad.Count -eq 0) "raiz de execucao: $($bad.Count) diferenca(s) fora do alvo [$((@($bad | Select-Object -First 3)) -join '; ')]"
    "run root: only the purged root ($(@($d.Removed).Count) removed), the scopes the cases changed and checked themselves ($($ctx.Touched.Count)) and this run's logs ($(@($d.Added).Count) added) differ; the restored roots, the held and contended roots, the sentinel, the transcripts and the rest identical"
}
Case 'snapshot-quarantine' {
    Assert-QuarantineUnchanged 'fim'
    $d = Compare-Snapshot $ctx.QBefore (Get-Snapshot $qArea ([long]::MaxValue) -Skip @($ctx.QSkip))
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
    $bad = @(Get-InstalledGateProblems)
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
