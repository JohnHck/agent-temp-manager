<#
.SYNOPSIS
  V0.3 V2: the REAL clean, end to end, on roots this script plants itself, on a DISPOSABLE machine only (CI).
.DESCRIPTION
  CI-only harness, never shipped (tools\Build-Release.ps1 leaves it out of the release archive and refuses an archive
  that contains it). It loads the INSTALLED engine into its own process and opens the deletion gate there only, in
  memory, like tests\Run-Tests.ps1 does for its sandbox: the installed files, the package and the sources keep the single
  assignment of the deletion gate to $false (checked here by hash before and after). It uses the real deleter
  (AtmDeleter), the T1 log in a real file, the real B8 lock name and the real revalidation; only the console observation
  is the existing test seam (AtmCleanConsoleSource, logged as TEST_SEAM): every confirmation is AUTOMATED by this script
  and is never a human acceptance.
  Containment: everything it can hand to clean is under a run root it creates atomically in this run (refused if the
  name exists), with a protected DACL, and each planted root carries this run's nonce; every entry is checked against
  both before clean is called. Real roots of the machine are never entries. Recency is SIMULATED: the write times of the
  planted "old" roots and transcripts are set back (recorded as recencySimulated with the shift); RECENT itself
  (72 h) is unchanged.
  Leg A: a non-elevated standard user (B1 restricted exception, ELIGIBLE_WITH_DECLARED_RISK). Leg B: the elevated
  runner account (ELIGIBLE only if the process coverage measured here is complete; otherwise NOT_TESTED, never forced).
  Writes ONLY a summary (codes, counts, labels; no path, account name or SID) to -SummaryFile; the raw T1 logs stay in
  the run root and are never uploaded. Exit code = number of failed cases (NOT_TESTED is neither a pass nor a failure).
  V0.3 V3, phase V3a (cases V3-*): reparse points and links, and files and folders in use, attacked in each window of the
  flow on more roots planted the same way. The windows inside the deleter use the REAL deleter through a wrapper passed
  to the engine's existing deleter test seam, with the engine's own arguments plus an attack (no new seam in the product).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('A', 'B')][string]$Leg,
    [Parameter(Mandatory)][string]$InstallDir,
    [Parameter(Mandatory)][string]$SummaryFile,
    [Parameter(Mandatory)][string]$WorkDir,
    [switch]$DisposableMachine,
    # V3b (P2, P3): a folder watched by the e2e (another account), which starts a short, self-ending process of its own
    # when this script asks; leg A only. Without it those cases are NOT_TESTED.
    [string]$SignalDir,
    # V3c (K1, K3, X1): this script started again by itself as a CHILD that runs one clean of its own on -ChildRoot and
    # writes one line to -ChildOut: K1 exits by itself inside the real deleter (after pinning), K3 right after it, X1
    # contends for the lock the parent holds. In this mode no case runs.
    [ValidateSet('', 'K1', 'K3', 'X1')][string]$ChildMode = '',
    [string]$ChildRoot,
    [string]$ChildLog,
    [string]$ChildOut
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# Accident guard only (these variables can be set by anyone): the containment is the run root and the nonce below.
if (-not $DisposableMachine -and -not ($env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -eq 'github-hosted')) {
    throw 'Recusado: este teste apaga de verdade raizes que ele mesmo planta; so roda em maquina descartavel (runner do GitHub) ou com -DisposableMachine.'
}

$me = [Security.Principal.WindowsIdentity]::GetCurrent()
$mySid = $me.User.Value
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($me)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$shellExe = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
$nonce = [guid]::NewGuid().ToString('N')
$runRoot = Join-Path $env:SystemDrive ('ATM-E2E-V2-' + $Leg + '-' + $nonce.Substring(0, 12))
$shiftHours = 120
$slug = 'C--atm-e2e-v2'
$ctx = @{ Roots = @{}; Logs = (New-Object System.Collections.Generic.List[string]); Changed = (New-Object System.Collections.Generic.List[string]); Eligible = $false; EnvSet = @{} }
$summary = [ordered]@{
    schema = 'atm.e2e-clean-v2/1'; leg = $Leg; startedUtc = [datetime]::UtcNow.ToString('o')
    shell = "$($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)"; arch = $env:PROCESSOR_ARCHITECTURE
    elevated = [bool]$isAdmin; confirmation = 'AUTOMATED_BY_HARNESS (console: TEST_SEAM); not a human acceptance'
    recencySimulated = $true; recencyShiftHours = $shiftHours; recentHoursInProduct = $null
    processCoverage = $null; cases = [ordered]@{}
}
[void][IO.Directory]::CreateDirectory($WorkDir)

function Protect-Text([string]$Text) {
    # Defense in depth before the artifact sanitizer: no SID, run root, profile, temp, account or machine name.
    if (-not $Text) { return $Text }
    $t = [regex]::Replace($Text, 'S-1-5-21-[0-9-]+', '<sid>')
    foreach ($pair in @(@($runRoot, '<run-root>'), @($WorkDir, '<work>'), @($InstallDir, '<install>'), @([IO.Path]::GetTempPath().TrimEnd('\'), '<temp>'), @($env:USERPROFILE, '<profile>'), @($env:USERNAME, '<account>'), @($env:COMPUTERNAME, '<machine>'))) {
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
    [Console]::Out.WriteLine(("[{0}] V2-{1} {2} {3}" -f $s.status, $Leg, $Id, $s.detail))
}
function Assert([bool]$Cond, [string]$Msg) { if (-not $Cond) { throw $Msg } }
function NotTested([string]$Why) { $script:notTested = $true; return $Why }
function Get-Codes($Reasons) { return ((@($Reasons | ForEach-Object { ([string]$_ -split '[\s:(]')[0] })) -join ',') }

function Get-FileSha([string]$Path) {
    $s = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
    try { $h = [Security.Cryptography.SHA256]::Create(); try { return ([BitConverter]::ToString($h.ComputeHash($s))).Replace('-', '') } finally { $h.Dispose() } } finally { $s.Dispose() }
}
function Get-Snapshot([string]$Root, [long]$HashMax, [int]$MaxEntries = 200000) {
    # Relative path -> D (directory), R (reparse point, never traversed), F|length|write ticks|SHA-256 ('-' above
    # HashMax, 'UNREADABLE' when it cannot be opened), X (directory not enumerable).
    $map = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase)
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
function Test-Under([string]$Rel, [string]$Prefix) { return ([string]::Equals($Rel, $Prefix, [StringComparison]::OrdinalIgnoreCase) -or $Rel.StartsWith($Prefix + '\', [StringComparison]::OrdinalIgnoreCase)) }

function Test-InstalledGate {
    $t = [IO.File]::ReadAllText((Join-Path $InstallDir 'lib\Engine.Clean.ps1'))
    $g = 'AtmRealDeletionEnabled'
    return ([regex]::Matches($t, ('\$script:' + $g + '\s*=')).Count -eq 1 -and $t -match ('(?m)^\$script:' + $g + ' = \$false\r?$'))
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
Case 'P1-installed-before' {
    Assert (Test-InstalledGate) 'trava instalada nao e uma unica atribuicao $false'
    $v = Invoke-InstalledVerify
    Assert ($v -eq 0) "agent-temp verify exit $v"
    $ctx.InstallBefore = Get-Snapshot $InstallDir ([long]::MaxValue)
    "verify 0; installed gate `$false (single assignment); $($ctx.InstallBefore.Count) installed entries hashed"
}
if (-not $ChildMode -and ($summary.cases['identity'].status -ne 'PASS' -or $summary.cases['P1-installed-before'].status -ne 'PASS')) {
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
. (Join-Path $lib 'Engine.Diagnose.ps1')
$loadedGate = $script:AtmRealDeletionEnabled
# In memory, in this process only (the installed file is unchanged; checked again at the end).
$script:AtmRealDeletionEnabled = $true
$script:AtmCleanConsoleSource = { $true }
$summary.recentHoursInProduct = $script:AtmRecentHours
$ia = @{ SelfMarkers = @((Join-Path $InstallDir 'agent-temp.ps1'), (Join-Path $InstallDir 'bin\agent-temp.cmd')); ConfigDir = (Join-Path $InstallDir 'config'); NoProgress = $true }
# Empty body: anything it returned would reach Invoke-AtmClean's output (the engine does not capture the presenter).
$presenter = { param($verified, $rejected, $inventory) }

function New-Operator([string]$Final) {
    # Automated answers: the exact phrase generated by the engine for task, risk and confirmation; for the content
    # decision the last choice (nothing needed: the planted content is synthetic). -Final replaces the final phrase.
    $st = @{ Calls = (New-Object System.Collections.Generic.List[string]); Final = $Final }
    $st.Reader = {
        param($phrase, $kind, $rootPath, $choices, $info)
        $st.Calls.Add([string]$kind)
        if ($kind -ceq 'results') { $c = @($choices); return [string]$c[$c.Count - 1] }
        if ($kind -ceq 'confirm' -and $st.Final) { return $st.Final }
        return [string]$phrase
    }.GetNewClosure()
    return $st
}
function Assert-Entry([string]$Path) {
    # Containment (V2 contract, B): canonical, under this run's base, the nonce of this run, no reparse point in the chain.
    Assert ([string]::Equals([IO.Path]::GetFullPath($Path), $Path, [StringComparison]::Ordinal)) 'entrada nao canonica'
    Assert ($Path.StartsWith($ctx.Base + '\', [StringComparison]::OrdinalIgnoreCase)) 'entrada fora da base desta execucao'
    $nf = Join-Path $Path 'ATM-E2E-NONCE.txt'
    Assert ((Test-Path -LiteralPath $nf -PathType Leaf) -and [IO.File]::ReadAllText($nf) -ceq $nonce) 'entrada sem o nonce desta execucao'
    $p = $Path
    while ($p.Length -gt $runRoot.Length) {
        Assert (([IO.File]::GetAttributes($p) -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'reparse point na cadeia da entrada'
        $p = [IO.Path]::GetDirectoryName($p)
    }
}
function Invoke-E2EClean([string[]]$Labels, [string]$LogName, [switch]$Risk, $Operator, [scriptblock]$Hook) {
    $entries = @(foreach ($l in $Labels) { $p = $ctx.Roots[$l].Path; Assert-Entry $p; [pscustomobject]@{ Source = 'e2e-v2'; Path = $p; Fingerprint = $null } })
    $log = Join-Path $ctx.LogDir $LogName
    $ctx.Logs.Add($LogName)
    if (-not $Operator) { $Operator = New-Operator }
    $a = @{ Entries = $entries; PlanPresenter = $presenter; ConfirmationReader = $Operator.Reader; InventoryArgs = $ia; LogFile = $log; Interaction = @{ Caller = 'E2E'; ConsoleRequired = $true } }
    if ($Risk) { $a['AcceptB1ResidualRisk'] = $true }
    if ($Hook) { $a['BeforeDeleteHook'] = $Hook }
    $res = Invoke-AtmClean @a
    return [pscustomobject]@{ Res = $res; Log = $log }
}
function Invoke-E2ECleanChurn([string[]]$Labels, [string]$LogBase, [switch]$Risk, [scriptblock]$Hook) {
    # Up to 3 complete, fresh runs. PLAN_CHANGED_BEFORE_EXECUTION is the engine's fail-closed refusal when the executable
    # set changed after the plan (with the B1 exception: a process identity not inspectable that was not in the plan).
    # Nothing is deleted then. Each refusal is explained by comparing the identities recorded in the log's plan record
    # with a fresh inventory; Exhausted means every attempt was refused.
    $churn = New-Object System.Collections.Generic.List[object]
    for ($n = 1; $n -le 3; $n++) {
        $c = Invoke-E2EClean -Labels $Labels -LogName "$LogBase-$n.jsonl" -Risk:$Risk -Hook $Hook
        # Also a revalidation refusal before any deletion that is NOT the change declared by the case (same nature).
        $undeclared = ($c.Res.Aborted -ceq 'REVALIDATION_REFUSED' -and -not ((@($c.Res.Skipped | ForEach-Object { Get-Codes $_.Reasons }) -join ';') -match 'ALTERADO_APOS_CONFIRMACAO'))
        if ($c.Res.Aborted -cne 'PLAN_CHANGED_BEFORE_EXECUTION' -and -not $undeclared) {
            return [pscustomobject]@{ Res = $c.Res; Log = $c.Log; Attempts = $n; Churn = $churn.ToArray(); Exhausted = $false }
        }
        Assert (@($c.Res.Deleted).Count -eq 0) 'algo apagado numa execucao recusada antes da execucao'
        $planKeys = @(Read-E2ELog $c.Log | Where-Object { $_.type -ceq 'plan' } | ForEach-Object { @($_.uninspectableKeys) } | Where-Object { $_ })
        $nowKeys = @((Get-AtmUninspectableKeys (Invoke-AtmInventory @ia)).Keys)
        $churn.Add([pscustomobject]@{ Attempt = $n; Code = [string]$c.Res.Aborted; NewIdentities = @($nowKeys | Where-Object { $planKeys -notcontains $_ }).Count; PlanIdentities = $planKeys.Count })
    }
    return [pscustomobject]@{ Res = $null; Log = $null; Attempts = 3; Churn = $churn.ToArray(); Exhausted = $true }
}
function Get-ChurnText($Churn) { return ((@($Churn | ForEach-Object { "attempt $($_.Attempt): $($_.Code), $($_.NewIdentities) new uninspectable process identities (plan had $($_.PlanIdentities))" })) -join '; ') }
function Resolve-Exhausted($C) {
    # Every attempt refused before any deletion: NOT_TESTED only when each refusal is explained by new identities
    # observed (process churn on this runner); otherwise the refusal is unexplained and the case fails.
    $txt = Get-ChurnText $C.Churn
    if (@($C.Churn | Where-Object { $_.NewIdentities -eq 0 }).Count -eq 0) { return (NotTested "fail-closed refusal in all 3 attempts, nothing deleted; $txt") }
    throw "recusa antes da execucao sem nova identidade observada: $txt"
}
function Read-E2ELog([string]$Path) {
    $t = (New-Object Text.UTF8Encoding($false, $true)).GetString([IO.File]::ReadAllBytes($Path))
    return @($t.Split([char]10) | Where-Object { $_ -ne '' } | ForEach-Object { $_ | ConvertFrom-Json })
}
function Get-Types($Records) { return ((@($Records | ForEach-Object { $_.type })) -join ',') }
$lockHelper = Join-Path $WorkDir 'lock-helper.ps1'
[IO.File]::WriteAllText($lockHelper, @'
param([string]$Dll, [string]$Mode, [string]$Out, [string]$Ready, [string]$Release)
# B8 evidence from ANOTHER process: try the product lock (never waits). Mode hold: keep it until the release file.
Add-Type -Path $Dll
$l = [AgentTempManager.AtmCleanLock]::TryAcquire('Global\AgentTempManager.Clean')
[IO.File]::WriteAllText($Out, [string]$l.Status)
if ($l.Acquired) {
    if ($Mode -eq 'hold') { [IO.File]::WriteAllText($Ready, '1'); $n = 0; while (-not (Test-Path -LiteralPath $Release) -and $n -lt 1800) { Start-Sleep -Milliseconds 100; $n++ } }
    $rc = $l.Release(); if ($null -ne $rc) { [IO.File]::AppendAllText($Out, '|RELEASE_' + $rc) }
}
'@)
function Invoke-LockProbe([string]$Tag) {
    $out = Join-Path $WorkDir "lock-$Tag.txt"
    $null = & $shellExe -NoProfile -ExecutionPolicy Bypass -File $lockHelper -Dll (Join-Path $lib 'AgentTempManager.Native.dll') -Mode probe -Out $out -Ready 'none' -Release 'none' 2>&1
    if (Test-Path -LiteralPath $out) { return [IO.File]::ReadAllText($out) } else { return 'NO_OUTPUT' }
}

# ---------------------------------------------------------------------------------------------- plant
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
    foreach ($label in @('old1', 'old2', 'oldSentinel', 'new')) {
        $id = [guid]::NewGuid().ToString()
        $root = Join-Path $ctx.Base "$slug\$id"
        [void][IO.Directory]::CreateDirectory((Join-Path $root 'scratchpad'))
        [IO.File]::WriteAllText((Join-Path $root 'scratchpad\SYNTHETIC.txt'), "synthetic V2 fixture ($label)`n")
        [IO.File]::WriteAllText((Join-Path $root 'ATM-E2E-NONCE.txt'), $nonce)
        $pj = Join-Path $ctx.Cfg "projects\$slug"; [void][IO.Directory]::CreateDirectory($pj)
        $tr = Join-Path $pj "$id.jsonl"
        [IO.File]::WriteAllText($tr, ('{"type":"ai-title","aiTitle":"SYNTHETIC","sessionId":"' + $id + '"}' + "`n"))
        $ctx.Roots[$label] = [pscustomobject]@{ Label = $label; Id = $id; Path = $root; Transcript = $tr }
    }
    [IO.File]::WriteAllText((Join-Path $ctx.Base 'loose-sentinel.txt'), "sentinel`n")
    # Leg B: items created elevated are owned by Administrators; the profile's own roots are owned by the account.
    if ($isAdmin) {
        foreach ($it in @(@(Get-Item -LiteralPath $ctx.Tmp -Force) + @(Get-ChildItem -LiteralPath $ctx.Tmp -Recurse -Force))) { $a = Get-Acl -LiteralPath $it.FullName; $a.SetOwner($me.User); Set-Acl -LiteralPath $it.FullName -AclObject $a }
    }
    # SIMULATION (declared): the "old" roots and their transcripts are set back by $shiftHours hours, after a pause so
    # that the directory times are settled; the new root keeps its real times.
    Start-Sleep -Seconds 2
    $old = [datetime]::UtcNow.AddHours(-$shiftHours)
    foreach ($label in @('old1', 'old2', 'oldSentinel')) {
        $r = $ctx.Roots[$label]
        foreach ($f in @((Join-Path $r.Path 'scratchpad\SYNTHETIC.txt'), (Join-Path $r.Path 'ATM-E2E-NONCE.txt'), $r.Transcript)) { [IO.File]::SetLastWriteTimeUtc($f, $old); [IO.File]::SetCreationTimeUtc($f, $old) }
        foreach ($d in @((Join-Path $r.Path 'scratchpad'), $r.Path)) { [IO.Directory]::SetLastWriteTimeUtc($d, $old); [IO.Directory]::SetCreationTimeUtc($d, $old) }
    }
    # D3: real discovery. The variables in this account's user environment (HKCU\Environment = HKU\<SID>\Environment)
    # and in this process, as Claude Code would see them; removed again at the end if still the values set here.
    $k = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
    try {
        foreach ($pair in @(@('CLAUDE_CODE_TMPDIR', $ctx.Tmp), @('CLAUDE_CONFIG_DIR', $ctx.Cfg))) {
            $prev = $k.GetValue($pair[0], $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $ctx.EnvSet[$pair[0]] = [pscustomobject]@{ Value = $pair[1]; Previous = $prev }
            $k.SetValue($pair[0], $pair[1], [Microsoft.Win32.RegistryValueKind]::String)
            [Environment]::SetEnvironmentVariable($pair[0], $pair[1], 'Process')
        }
    } finally { $k.Close() }
    "4 roots (old1, old2, oldSentinel: set back ${shiftHours}h = SIMULATION; new: real times), 1 loose file, transcripts; user environment set"
}
Case 'discovery' {
    Assert ($ctx.Roots.Count -eq 4) 'plantio indisponivel'
    $inv = Invoke-AtmInventory @ia
    $ctx.Inv = $inv
    $b = @($inv.Bases | Where-Object { [string]::Equals($_.Path, $ctx.Base, [StringComparison]::OrdinalIgnoreCase) })
    Assert ($b.Count -eq 1) "base plantada descoberta $($b.Count) vez(es) pelo caminho normal"
    Assert (-not [bool]$b[0].Shared) 'base plantada compartilhada'
    Assert ([bool]$inv.Identity.IsAdmin -eq [bool]$isAdmin) 'identidade do produto diverge do token'
    foreach ($label in @('old1', 'old2', 'oldSentinel', 'new')) {
        $m = @($inv.Partitions | Where-Object { $_.Kind -ne 'BaseLooseFiles' -and [string]::Equals($_.Path, $ctx.Roots[$label].Path, [StringComparison]::OrdinalIgnoreCase) })
        Assert ($m.Count -eq 1) "raiz $label nao inventariada"
        $ctx.Roots[$label].Path = $m[0].Path
        Assert ($m[0].Sid -eq $mySid) "raiz $label atribuida a outro perfil"
    }
    $acl = @(foreach ($d in @($ctx.Base, (Join-Path $ctx.Base $slug), $ctx.Roots['old1'].Path, $ctx.Roots['old2'].Path)) { @(Get-AtmAclProblems -Path $d -OwnerSid $mySid) })
    Assert ($acl.Count -eq 0) "ACL da base plantada com problemas: $(Get-Codes $acl)"
    $summary.processCoverage = [ordered]@{ complete = [bool]$inv.ProcessCoverageComplete; uninspectable = [int]$inv.Snapshot.Uninspectable }
    "base found via the user environment (source $($b[0].Source)); 4 roots of this account; ACL clean (base, scope, roots); process coverage complete=$([bool]$inv.ProcessCoverageComplete), uninspectable=$([int]$inv.Snapshot.Uninspectable)"
}
Case 'P2-preview' {
    Assert ($null -ne $ctx['Inv']) 'inventario indisponivel'
    $rows = @(Invoke-AtmPreview -Inventory $ctx.Inv -InventoryArgs $ia)
    $cat = @{}
    foreach ($label in @('old1', 'old2', 'oldSentinel', 'new')) {
        $r = @($rows | Where-Object { $_.Partition.Kind -ne 'BaseLooseFiles' -and [string]::Equals($_.Partition.Path, $ctx.Roots[$label].Path, [StringComparison]::OrdinalIgnoreCase) })[0]
        $cat[$label] = [pscustomobject]@{ Category = [string]$r.Gate.Category; Class = [string]$r.Partition.Class; Reasons = (Get-Codes $r.Gate.Reasons) }
    }
    Assert ($cat['new'].Category -eq 'BLOCKED' -and $cat['new'].Class -eq 'RECENT') "raiz nova: $($cat['new'].Category)/$($cat['new'].Class), esperado BLOCKED/RECENT"
    $want = $(if ($Leg -eq 'A') { 'ELIGIBLE_WITH_DECLARED_RISK' } else { 'ELIGIBLE' })
    $got = "old1=$($cat['old1'].Category)/$($cat['old1'].Class) [$($cat['old1'].Reasons)]; old2=$($cat['old2'].Category); oldSentinel=$($cat['oldSentinel'].Category); new=BLOCKED/RECENT"
    if ($cat['old1'].Category -eq $want -and $cat['old2'].Category -eq $want) { $ctx.Eligible = $true; return "expected $want for the old roots: $got" }
    if ($Leg -eq 'B' -and -not $summary.processCoverage.complete) { return (NotTested "elevated coverage measured incomplete ($($summary.processCoverage.uninspectable) uninspectable): ELIGIBLE unreachable, never forced; $got") }
    throw "categoria das raizes antigas diferente de $($want): $got"
}

# ---------------------------------------------------------------------------------------------- runs
$ctx.ExistingLog = 'P3e-existing.jsonl'
if ($ctx.Roots.Count -eq 4) {
    [IO.File]::WriteAllText((Join-Path $ctx.LogDir $ctx.ExistingLog), "pre-existing`n")
    $ctx.ExistingLogSha = Get-FileSha (Join-Path $ctx.LogDir $ctx.ExistingLog)
    $ctx.RunBefore = Get-Snapshot $runRoot ([long]::MaxValue)
    try { $ctx.TempBefore = Get-Snapshot ([IO.Path]::GetTempPath().TrimEnd('\')) 1MB } catch { $ctx.TempBefore = $null }
}
$needEligible = { if (-not $ctx.Eligible) { NotTested 'no planted root reached the expected category (P2-preview)' } }

Case 'P3f-lock-busy' {
    $nt = & $needEligible; if ($nt) { return $nt }
    $out = Join-Path $WorkDir 'lock-hold.txt'; $ready = Join-Path $WorkDir 'lock-hold.ready'; $release = Join-Path $WorkDir 'lock-hold.release'
    $psi = New-Object Diagnostics.ProcessStartInfo($shellExe, ('-NoProfile -ExecutionPolicy Bypass -File "{0}" -Dll "{1}" -Mode hold -Out "{2}" -Ready "{3}" -Release "{4}"' -f $lockHelper, (Join-Path $lib 'AgentTempManager.Native.dll'), $out, $ready, $release))
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $h = [Diagnostics.Process]::Start($psi)
    try {
        $n = 0; while (-not (Test-Path -LiteralPath $ready) -and -not $h.HasExited -and $n -lt 1200) { Start-Sleep -Milliseconds 100; $n++ }
        Assert (Test-Path -LiteralPath $ready) "outro processo nao tomou o lock: $(if (Test-Path $out) { [IO.File]::ReadAllText($out) })"
        $c = Invoke-E2EClean -Labels @('old1') -LogName 'P3f.jsonl' -Risk:($Leg -eq 'A')
    } finally { [IO.File]::WriteAllText($release, '1'); if (-not $h.WaitForExit(60000)) { $h.Kill() } }
    Assert ($c.Res.Aborted -ceq 'CLEAN_LOCK_BUSY') "Aborted=$($c.Res.Aborted), esperado CLEAN_LOCK_BUSY"
    Assert (-not $c.Res.LogCreated -and -not (Test-Path -LiteralPath $c.Log)) 'log criado com o lock ocupado'
    Assert (@($c.Res.Deleted).Count -eq 0 -and (Test-Path -LiteralPath $ctx.Roots['old1'].Path)) 'algo foi apagado'
    'another process holds Global\AgentTempManager.Clean: CLEAN_LOCK_BUSY, no inventory, no log, nothing deleted'
}
Case 'P3e-log-exists' {
    $nt = & $needEligible; if ($nt) { return $nt }
    $c = Invoke-E2EClean -Labels @('old1') -LogName $ctx.ExistingLog -Risk:($Leg -eq 'A')
    Assert ($c.Res.Aborted -ceq 'LOG_OPEN_FAILED') "Aborted=$($c.Res.Aborted), esperado LOG_OPEN_FAILED"
    Assert (@($c.Res.LogErrors | Where-Object { $_.Code -ceq 'LOG_CREATE_EXISTS' }).Count -eq 1) "LogErrors=$(@($c.Res.LogErrors | ForEach-Object { $_.Code }) -join ',')"
    Assert ((Get-FileSha $c.Log) -ceq $ctx.ExistingLogSha) 'arquivo de log existente alterado'
    Assert (@($c.Res.Deleted).Count -eq 0 -and (Test-Path -LiteralPath $ctx.Roots['old1'].Path)) 'algo foi apagado'
    'existing log file: LOG_OPEN_FAILED (LOG_CREATE_EXISTS), file unchanged, nothing deleted'
}
Case 'P3b-no-risk-switch' {
    if ($Leg -ne 'A') { return (NotTested 'leg A only (B1 restricted exception)') }
    $nt = & $needEligible; if ($nt) { return $nt }
    $c = Invoke-E2EClean -Labels @('old1') -LogName 'P3b.jsonl'
    Assert ($c.Res.Aborted -ceq 'NENHUM_CAMINHO_ELEGIVEL') "Aborted=$($c.Res.Aborted)"
    Assert ((Get-Codes $c.Res.Rejected[0].Reasons) -match 'COBERTURA_DE_PROCESSOS_INCOMPLETA') "razoes: $(Get-Codes $c.Res.Rejected[0].Reasons)"
    Assert (-not (Test-Path -LiteralPath $c.Log) -and (Test-Path -LiteralPath $ctx.Roots['old1'].Path)) 'log criado ou raiz apagada'
    'without -AcceptB1ResidualRisk: rejected by B1 (COBERTURA_DE_PROCESSOS_INCOMPLETA), NENHUM_CAMINHO_ELEGIVEL, no log'
}
Case 'P3d-recent' {
    $c = Invoke-E2EClean -Labels @('new') -LogName 'P3d.jsonl' -Risk:($Leg -eq 'A')
    Assert ($c.Res.Aborted -ceq 'NENHUM_CAMINHO_ELEGIVEL') "Aborted=$($c.Res.Aborted)"
    Assert (@($c.Res.Rejected[0].Reasons | Where-Object { "$_" -match 'RECENT' }).Count -gt 0) "sem RECENT: $(Get-Codes $c.Res.Rejected[0].Reasons)"
    Assert ((Test-Path -LiteralPath $ctx.Roots['new'].Path) -and -not (Test-Path -LiteralPath $c.Log)) 'raiz nova apagada ou log criado'
    'new root (real times): rejected RECENT, NENHUM_CAMINHO_ELEGIVEL, no log'
}
Case 'P3c-b1-limit' {
    if ($Leg -ne 'A') { return (NotTested 'leg A only (B1 restricted exception limit)') }
    $nt = & $needEligible; if ($nt) { return $nt }
    $c = Invoke-E2EClean -Labels @('old1', 'old2') -LogName 'P3c.jsonl' -Risk
    Assert ($c.Res.Aborted -ceq 'B1_EXCEPTION_LIMIT_EXCEEDED') "Aborted=$($c.Res.Aborted)"
    Assert (-not (Test-Path -LiteralPath $c.Log) -and (Test-Path -LiteralPath $ctx.Roots['old1'].Path) -and (Test-Path -LiteralPath $ctx.Roots['old2'].Path)) 'log criado ou raiz apagada'
    'two roots under the exception: B1_EXCEPTION_LIMIT_EXCEEDED before any question, no log'
}
Case 'P3a-wrong-phrase' {
    $nt = & $needEligible; if ($nt) { return $nt }
    $op = New-Operator -Final 'APAGAR 1 CAMINHOS ZZZZZZZZ'
    $c = Invoke-E2EClean -Labels @('old1') -LogName 'P3a.jsonl' -Risk:($Leg -eq 'A') -Operator $op
    Assert ($c.Res.Aborted -ceq 'CONFIRMACAO_AUSENTE_OU_DIVERGENTE') "Aborted=$($c.Res.Aborted)"
    $recs = Read-E2ELog $c.Log
    $conf = @($recs | Where-Object { $_.type -ceq 'confirmation' })
    Assert ($conf.Count -eq 1 -and $conf[0].accepted -eq $false -and $conf[0].step -ceq 'confirm') "confirmacao no log: $(Get-Types $recs)"
    Assert (@($recs | Where-Object { $_.type -ceq 'intent' }).Count -eq 0 -and $recs[-1].type -ceq 'run-end') "registros: $(Get-Types $recs)"
    Assert (@($c.Res.Deleted).Count -eq 0 -and (Test-Path -LiteralPath $ctx.Roots['old1'].Path)) 'algo foi apagado'
    "wrong final phrase: CONFIRMACAO_AUSENTE_OU_DIVERGENTE; log read from file: $(Get-Types $recs); nothing deleted"
}
Case 'P8-revalidation-refused' {
    $nt = & $needEligible; if ($nt) { return $nt }
    # After the confirmation and the plan check, before the revalidation of the changed root: a new file in it.
    # No GetNewClosure: the hook runs inside the engine's call chain and needs this script's functions (dynamic scope);
    # its variable names are not used by the engine.
    $v2ChangeRoot = $ctx.Roots['old2'].Path
    $v2Probe = @{ Status = $null }
    $hook = {
        param($part)
        if ([string]::Equals($part.Path, $v2ChangeRoot, [StringComparison]::OrdinalIgnoreCase)) { [IO.File]::WriteAllText((Join-Path $part.Path 'ATM-E2E-CHANGED.txt'), "changed after the confirmation`n") }
        elseif ($null -eq $v2Probe.Status) { $v2Probe.Status = Invoke-LockProbe 'during-P8' }
    }
    $changeRoot = $v2ChangeRoot; $probe = $v2Probe
    $ctx.Changed.Add('old2')
    if ($Leg -eq 'A') {
        # One root per run under the exception: the changed root alone; nothing is deleted.
        $c = Invoke-E2ECleanChurn -Labels @('old2') -LogBase 'P8' -Risk -Hook $hook
        if ($c.Exhausted) { return (Resolve-Exhausted $c) }
        Assert ($c.Res.Aborted -ceq 'REVALIDATION_REFUSED' -and -not $c.Res.StoppedBy) "Aborted=$($c.Res.Aborted) StoppedBy=$($c.Res.StoppedBy)"
        Assert (@($c.Res.Deleted).Count -eq 0) 'deleter chamado para a raiz alterada'
    } else {
        # Two ELIGIBLE roots: the first is deleted by the real deleter, the changed second one stops the run.
        $c = Invoke-E2ECleanChurn -Labels @('old1', 'old2') -LogBase 'P8' -Hook $hook
        if ($c.Exhausted) { return (Resolve-Exhausted $c) }
        Assert ($c.Res.StoppedBy -ceq 'REVALIDATION_REFUSED') "StoppedBy=$($c.Res.StoppedBy) Aborted=$($c.Res.Aborted)"
        Assert (@($c.Res.Deleted).Count -eq 1 -and $c.Res.Deleted[0].Outcome -ceq 'COMPLETE' -and $c.Res.Deleted[0].Verified -eq $true) "primeira raiz: $(@($c.Res.Deleted | ForEach-Object { $_.Outcome }) -join ',')"
        Assert (-not (Test-Path -LiteralPath $ctx.Roots['old1'].Path)) 'primeira raiz ainda existe'
        Assert ($probe.Status -ceq 'BUSY') "lock durante a execucao: $($probe.Status), esperado BUSY"
        $ctx.Deleted = @('old1')
    }
    Assert ($c.Res.StoppedAtOpId -ceq ($c.Res.RunId + ':' + $(if ($Leg -eq 'A') { 1 } else { 2 }))) "StoppedAtOpId=$($c.Res.StoppedAtOpId)"
    Assert (@($c.Res.Skipped).Count -eq 1 -and (Get-Codes $c.Res.Skipped[0].Reasons) -match 'ALTERADO_APOS_CONFIRMACAO') "skipped: $(@($c.Res.Skipped | ForEach-Object { Get-Codes $_.Reasons }) -join ';')"
    Assert ((Test-Path -LiteralPath $changeRoot) -and (Test-Path -LiteralPath (Join-Path $changeRoot 'scratchpad\SYNTHETIC.txt'))) 'raiz alterada apagada'
    $recs = Read-E2ELog $c.Log
    $pc = @($recs | Where-Object { $_.type -ceq 'plan-check' })
    Assert ($pc.Count -eq 1 -and $pc[0].matched -eq $true) "plan-check: $(Get-Types $recs)"
    $skip = @($recs | Where-Object { $_.type -ceq 'skip' })
    Assert ($skip.Count -eq 1 -and $recs[-1].type -ceq 'run-end' -and $recs[-1].stoppedBy -ceq 'REVALIDATION_REFUSED') "registros: $(Get-Types $recs)"
    Assert (@($recs | Where-Object { $_.type -ceq 'intent' }).Count -eq $(if ($Leg -eq 'A') { 0 } else { 1 })) "intents: $(Get-Types $recs)"
    "change between the confirmation and the deletion: REVALIDATION_REFUSED (ALTERADO_APOS_CONFIRMACAO), changed root intact; log: $(Get-Types $recs); attempts $($c.Attempts)$(if ($c.Attempts -gt 1) { ' (' + (Get-ChurnText $c.Churn) + ')' })" + $(if ($Leg -eq 'B') { '; first root deleted by the real deleter (COMPLETE, verified); lock BUSY from another process during the run' } else { '' })
}
Case 'P4-P7-real-deletion' {
    $nt = & $needEligible; if ($nt) { return $nt }
    if ($Leg -eq 'B') { return (NotTested 'leg B: the real deletion, its log and the lock are proved inside P8 (two ELIGIBLE roots)') }
    $v2Probe = @{ Status = $null }
    $hook = { param($part) if ($null -eq $v2Probe.Status) { $v2Probe.Status = Invoke-LockProbe 'during-P4' } }
    $probe = $v2Probe
    $c = Invoke-E2ECleanChurn -Labels @('old1') -LogBase 'P4' -Risk -Hook $hook
    if ($c.Exhausted) { return (Resolve-Exhausted $c) }
    Assert (-not $c.Res.Aborted -and -not $c.Res.StoppedBy) "Aborted=$($c.Res.Aborted) StoppedBy=$($c.Res.StoppedBy) rejected=$(@($c.Res.Rejected | ForEach-Object { Get-Codes $_.Reasons }) -join ';') skipped=$(@($c.Res.Skipped | ForEach-Object { Get-Codes $_.Reasons }) -join ';')"
    Assert (@($c.Res.Deleted).Count -eq 1 -and $c.Res.Deleted[0].Outcome -ceq 'COMPLETE' -and $c.Res.Deleted[0].Verified -eq $true) "resultado: $(@($c.Res.Deleted | ForEach-Object { $_.Outcome }) -join ',')"
    Assert (-not (Test-Path -LiteralPath $ctx.Roots['old1'].Path)) 'raiz ainda existe'
    $ctx.Deleted = @('old1')
    Assert ($probe.Status -ceq 'BUSY') "lock durante a execucao: $($probe.Status), esperado BUSY"
    $after = Invoke-LockProbe 'after-P4'
    Assert ($after -ceq 'ACQUIRED') "lock depois da execucao: $after, esperado ACQUIRED (liberado)"
    $recs = Read-E2ELog $c.Log
    $types = Get-Types $recs
    Assert ($types -ceq 'run-start,plan,declaration,confirmation,plan-check,intent,result,run-end') "sequencia do log: $types"
    Assert (@($recs | Where-Object { $_.runId -cne $c.Res.RunId }).Count -eq 0) 'runId divergente no log'
    for ($i = 0; $i -lt $recs.Count; $i++) { Assert ([int]$recs[$i].recSeq -eq $i + 1) 'recSeq fora de ordem' }
    $conf = $recs[3]
    Assert ($conf.accepted -eq $true -and $conf.planId -ceq $c.Res.PlanId -and $c.Res.PlanId -match '^[0-9a-f]{64}$') 'confirmacao sem o planId completo'
    Assert ($conf.interaction.observedBy -ceq 'TEST_SEAM' -and $conf.interaction.caller -ceq 'DIRECT_CALL' -and $conf.interaction.identifiesRespondent -eq $false) 'interacao registrada diferente de TEST_SEAM/DIRECT_CALL'
    Assert ($recs[1].category -ceq 'ELIGIBLE_WITH_DECLARED_RISK' -and $recs[2].b1ResidualRiskAccepted -eq $true -and $recs[0].b1Exception -eq $true) 'excecao B1 nao registrada no plano/declaracao'
    Assert ($recs[4].matched -eq $true -and $recs[5].opId -ceq ($c.Res.RunId + ':1') -and $recs[6].outcome -ceq 'COMPLETE' -and $recs[6].verifiedGone -eq $true) 'plan-check/intent/result divergentes'
    Assert ($recs[7].complete -eq 1 -and $recs[7].results -eq 1) 'run-end divergente'
    "real deleter: COMPLETE, verified gone; T1 log read from file: $types (confirmation TEST_SEAM/DIRECT_CALL, planId SHA-256); B8: BUSY from another process during the run, ACQUIRED after it; revalidation passed (plan-check matched); attempts $($c.Attempts)$(if ($c.Attempts -gt 1) { ' (' + (Get-ChurnText $c.Churn) + ')' })"
}
Case 'P9-snapshot' {
    if ($null -eq $ctx['RunBefore']) { return (NotTested 'no snapshot before the runs') }
    $after = Get-Snapshot $runRoot ([long]::MaxValue)
    $d = Compare-Snapshot $ctx.RunBefore $after
    $deletedRel = @(foreach ($l in @($ctx['Deleted'] | Where-Object { $_ })) { $ctx.Roots[$l].Path.Substring($runRoot.Length).TrimStart('\') })
    $badRemoved = @($d.Removed | Where-Object { $k = $_; @($deletedRel | Where-Object { Test-Under $k $_ }).Count -eq 0 })
    $allowedAdded = @(@($ctx.Logs | ForEach-Object { 'log\' + $_ }) + @($ctx.Changed | ForEach-Object { $ctx.Roots[$_].Path.Substring($runRoot.Length).TrimStart('\') + '\ATM-E2E-CHANGED.txt' }))
    $badAdded = @($d.Added | Where-Object { $allowedAdded -notcontains $_ })
    $missing = @($deletedRel | Where-Object { $r = $_; @($d.Removed | Where-Object { $_ -ieq $r }).Count -ne 1 })
    Assert ($badRemoved.Count -eq 0 -and $badAdded.Count -eq 0 -and $d.Changed.Count -eq 0 -and $missing.Count -eq 0) "run root: removido fora do esperado $($badRemoved.Count), adicionado fora do esperado $($badAdded.Count), alterado $($d.Changed.Count), raiz apagada ausente da diferenca $($missing.Count)"
    $tempNote = 'temp not snapshotted'
    if ($null -ne $ctx['TempBefore']) {
        $t = Compare-Snapshot $ctx.TempBefore (Get-Snapshot ([IO.Path]::GetTempPath().TrimEnd('\')) 1MB)
        $tempNote = "temp: $($t.Removed.Count) pre-existing removed, $($t.Changed.Count) changed, $($t.Added.Count) added"
        $ctx.TempDiff = $t
    }
    "run root: only the deleted root(s) ($($d.Removed.Count) entries), the logs and the declared change differ ($($d.Added.Count) added, 0 changed); $tempNote"
}
Case 'P9-temp-pre-existing' {
    # Other processes of the runner may write in the temp folder: a difference there is reported, not attributed.
    if ($null -eq $ctx['TempDiff']) { return (NotTested 'temp snapshot unavailable') }
    $t = $ctx.TempDiff
    if ($t.Removed.Count -eq 0 -and $t.Changed.Count -eq 0) { return "no pre-existing temp entry removed or changed ($($t.Added.Count) added by the shells)" }
    NotTested "inconclusive: $($t.Removed.Count) pre-existing entries removed and $($t.Changed.Count) changed in the account's temp folder, not attributable (other processes write there)"
}

# ---------------------------------------------------------------------------------------------- V3a
# V0.3 V3, phase V3a (contract CONTRATO-V3-ADVERSARIAIS, sections 4.1 and 4.2): reparse points and links, and files and
# folders in use, against the same installed engine, real lock, real T1 log file, real revalidation and runtime evidence.
# Each attack runs in one window of the flow: before the plan; between the plan and the final confirmation (this
# script's confirmation reader); between the confirmation and the revalidation (-BeforeDeleteHook); between the
# revalidation and the deleter, and inside the deleter once everything is pinned (the wrapper below). Every case asserts
# its own code per leg (F6: in leg A a refusal of the lock probe, an ACL or runtime evidence removes the B1 exception
# and shows as B1 itself or B1_EXCEPTION_NO_LONGER_APPLIES), the records read from the log file, the number of intents
# (= calls to the deleter) and that nothing outside the planned root and the declared attack changed. Sentinels and link
# targets live in this run root, outside the base. Leg A runs one root per clean (B1 exception); leg B reaches the
# deleter only with ELIGIBLE (complete coverage measured), otherwise those cases are NOT_TESTED, never forced.
$v3 = @{ Ready = $false; Roots = @{}; Sentinels = @{}; Adversarial = @{}; SnapBefore = $null; NativeError = $null; Symlink = @{}; R2 = $null; R3 = $null; HardLink = $null
    S1Run = $null; S1Root = $null; S1Error = $null; K1Exited = $false; K3Exited = $false }
$v3Slug = 'C--atm-e2e-v3'
$v3s = @{ Calls = 0; Before = $null; During = $null; After = $null; Attacked = $false }
$v3NativeSrc = @'
using System; using System.Runtime.InteropServices; using Microsoft.Win32.SafeHandles; using System.Text;
public static class AtmE2EV3Native {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern SafeFileHandle CreateFileW(string n, uint a, uint s, IntPtr sa, uint c, uint f, IntPtr t);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(SafeFileHandle h, uint code, byte[] inb, int inl, IntPtr outb, int outl, out int ret, IntPtr ov);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern byte CreateSymbolicLinkW(string link, string target, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CreateHardLinkW(string link, string existing, IntPtr sa);
    public static string CreateHardLink(string link, string existing) {
        return CreateHardLinkW(link, existing, IntPtr.Zero) ? "OK" : "FAIL " + Marshal.GetLastWin32Error();
    }
    // FSCTL_SET_REPARSE_POINT through a handle opened with FILE_WRITE_ATTRIBUTES only (share modes do not stop it).
    static string Set(string dir, byte[] b) {
        using (SafeFileHandle h = CreateFileW(dir, 0x100, 7, IntPtr.Zero, 3, 0x02000000u | 0x00200000u, IntPtr.Zero)) {
            if (h.IsInvalid) return "OPEN_FAIL " + Marshal.GetLastWin32Error();
            int r; bool ok = DeviceIoControl(h, 0x000900A4, b, b.Length, IntPtr.Zero, 0, out r, IntPtr.Zero);
            return ok ? "SET_OK" : "SET_FAIL " + Marshal.GetLastWin32Error();
        }
    }
    // Junction (mount point) on an existing EMPTY folder.
    public static string SetJunction(string dir, string target) {
        byte[] s = Encoding.Unicode.GetBytes("\\??\\" + target); byte[] p = Encoding.Unicode.GetBytes(target);
        int dataLen = 8 + s.Length + 2 + p.Length + 2; byte[] b = new byte[8 + dataLen];
        BitConverter.GetBytes(0xA0000003u).CopyTo(b, 0); BitConverter.GetBytes((ushort)dataLen).CopyTo(b, 4);
        BitConverter.GetBytes((ushort)0).CopyTo(b, 8); BitConverter.GetBytes((ushort)s.Length).CopyTo(b, 10);
        BitConverter.GetBytes((ushort)(s.Length + 2)).CopyTo(b, 12); BitConverter.GetBytes((ushort)p.Length).CopyTo(b, 14);
        s.CopyTo(b, 16); p.CopyTo(b, 16 + s.Length + 2);
        return Set(dir, b);
    }
    // Absolute directory symbolic link on an existing EMPTY folder (needs the symbolic link privilege).
    public static string SetDirSymlink(string dir, string target) {
        byte[] s = Encoding.Unicode.GetBytes("\\??\\" + target); byte[] p = Encoding.Unicode.GetBytes(target);
        int dataLen = 12 + s.Length + p.Length; byte[] b = new byte[8 + dataLen];
        BitConverter.GetBytes(0xA000000Cu).CopyTo(b, 0); BitConverter.GetBytes((ushort)dataLen).CopyTo(b, 4);
        BitConverter.GetBytes((ushort)0).CopyTo(b, 8); BitConverter.GetBytes((ushort)s.Length).CopyTo(b, 10);
        BitConverter.GetBytes((ushort)s.Length).CopyTo(b, 12); BitConverter.GetBytes((ushort)p.Length).CopyTo(b, 14);
        BitConverter.GetBytes(0u).CopyTo(b, 16); s.CopyTo(b, 20); p.CopyTo(b, 20 + s.Length);
        return Set(dir, b);
    }
    // SYMBOLIC_LINK_FLAG_DIRECTORY (1) | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE (2: developer mode only).
    public static string CreateSymlink(string link, string target, bool isDir) {
        return CreateSymbolicLinkW(link, target, (isDir ? 1u : 0u) | 2u) != 0 ? "OK" : "FAIL " + Marshal.GetLastWin32Error();
    }
    // No data access (FILE_READ_ATTRIBUTES) and full sharing: the kind of handle the lock probe cannot see.
    public static SafeFileHandle OpenAttributesOnly(string path, bool isDir) {
        return CreateFileW(path, 0x80, 7, IntPtr.Zero, 3, isDir ? 0x02000000u : 0u, IntPtr.Zero);
    }
}
'@
try { if (-not ('AtmE2EV3Native' -as [type])) { Add-Type -TypeDefinition $v3NativeSrc } } catch { $v3.NativeError = $_.Exception.GetType().Name }

# J1 (auditor's choice, no new seam in the product): the REAL deleter, called by this wrapper through the engine's existing
# deleter test seam with exactly the arguments of the engine's single call (a static test of the suite compares them),
# plus the attack of the case: Before = between the revalidation and the deleter; During = afterPinning (everything
# pinned and planned, before the first deletion); After = the deleter returned, before the engine checks the absence.
$v3Deleter = {
    param($c)
    $v3s.Calls++
    if ($null -ne $v3s.Before) { $v3s.Attacked = $true; & $v3s.Before $c }
    if ($null -ne $v3s.During) { $v3s.Attacked = $true }
    $v3After = $v3s.During
    $v3r = [AgentTempManager.AtmDeleter]::DeleteTree($c.Path, $c.Files, $c.Dirs, $c.Bytes, $c.NewestWriteTimeUtc.Ticks, $v3After)
    if ($null -ne $v3s.After) { & $v3s.After $c $v3r }
    return $v3r
}
function Get-V3Snap { return (Get-Snapshot $runRoot ([long]::MaxValue)) }
function Assert-V3Only($Before, [string[]]$Allowed, [string]$LogPrefix) {
    # Nothing outside the planned root(s), the declared attack paths and this case's own log files may differ.
    $d = Compare-Snapshot $Before (Get-V3Snap)
    $bad = @(@(@($d.Removed) + @($d.Added) + @($d.Changed)) | Where-Object { $k = $_; -not ($LogPrefix -and $k.StartsWith('log\' + $LogPrefix, [StringComparison]::OrdinalIgnoreCase)) -and @($Allowed | Where-Object { $_ -and (Test-Under $k $_) }).Count -eq 0 })
    Assert ($bad.Count -eq 0) "mudanca fora do plano e do ataque declarado: $($bad.Count) entrada(s) [$((@($bad | Select-Object -First 3)) -join '; ')]"
    return "run root: $($d.Removed.Count) removed, $($d.Added.Count) added, $($d.Changed.Count) changed, all inside the planned root or the declared attack"
}
function Get-V3Rel([string]$Path) { return $Path.Substring($runRoot.Length).TrimStart('\') }
function New-V3Sentinel([string]$Label) {
    $s = Join-Path $runRoot "v3-sentinel\$Label"
    [void][IO.Directory]::CreateDirectory((Join-Path $s 'deep'))
    [IO.File]::WriteAllText((Join-Path $s 'keep.txt'), "sentinel $Label`n"); [IO.File]::WriteAllText((Join-Path $s 'deep\deep.txt'), "deep sentinel $Label`n")
    $v3.Sentinels[$Label] = $s
    return $s
}
function New-V3Root([string]$Label, [string]$Slug = $v3Slug) {
    # <base>\<slug>\<session id>: the nonce, a.txt at the top, sub\z.txt (the last file the deleter reaches: the
    # enumeration is breadth first) and an empty folder; a synthetic transcript of the same id.
    $id = [guid]::NewGuid().ToString()
    $root = Join-Path $ctx.Base "$Slug\$id"
    foreach ($d in @((Join-Path $root 'sub'), (Join-Path $root 'empty'))) { [void][IO.Directory]::CreateDirectory($d) }
    [IO.File]::WriteAllText((Join-Path $root 'ATM-E2E-NONCE.txt'), $nonce)
    [IO.File]::WriteAllText((Join-Path $root 'a.txt'), "synthetic V3 fixture ($Label)`n")
    [IO.File]::WriteAllText((Join-Path $root 'sub\z.txt'), "synthetic V3 fixture ($Label), last file of the tree`n")
    $pj = Join-Path $ctx.Cfg "projects\$Slug"; [void][IO.Directory]::CreateDirectory($pj)
    $tr = Join-Path $pj "$id.jsonl"
    [IO.File]::WriteAllText($tr, ('{"type":"ai-title","aiTitle":"SYNTHETIC","sessionId":"' + $id + '"}' + "`n"))
    $v3.Roots[$Label] = [pscustomobject]@{ Label = $Label; Id = $id; Path = $root; Transcript = $tr; Slug = $Slug }
}
function Switch-V3ToJunction([string]$Path, [string]$Target) {
    # The attack on a name: the directory is moved aside (<name>-moved) and a junction takes its name, pointing to
    # $Target (the moved directory itself when $Target is empty). Returns the moved path.
    $moved = $Path + '-moved'
    [IO.Directory]::Move($Path, $moved)
    [void][IO.Directory]::CreateDirectory($Path)
    $st = [AtmE2EV3Native]::SetJunction($Path, $(if ($Target) { $Target } else { $moved }))
    if ($st -cne 'SET_OK') { throw "juncao nao criada: $st" }
    return $moved
}
function Assert-V3Entry([string]$Path) {
    if ($v3.S1Root -and [string]::Equals($Path, $v3.S1Root, [StringComparison]::Ordinal)) {
        # S1: the root this run planted under %WINDIR%\Temp: canonical, the nonce, no reparse point up to its run folder.
        Assert ([string]::Equals([IO.Path]::GetFullPath($Path), $Path, [StringComparison]::Ordinal)) 'entrada nao canonica'
        Assert ([IO.File]::ReadAllText((Join-Path $Path 'ATM-E2E-NONCE.txt')) -ceq $nonce) 'entrada sem o nonce desta execucao'
        for ($p = $Path; $p.Length -ge $v3.S1Run.Length; $p = [IO.Path]::GetDirectoryName($p)) { Assert (([IO.File]::GetAttributes($p) -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'reparse point na cadeia da entrada' }
        return
    }
    if ($v3.Adversarial.ContainsKey($Path)) {
        # An entry that is itself an attack (a link created by this run): canonical, under this run's base, its target
        # a sentinel created in this run root.
        Assert ([string]::Equals([IO.Path]::GetFullPath($Path), $Path, [StringComparison]::Ordinal)) 'entrada nao canonica'
        Assert ($Path.StartsWith($ctx.Base + '\', [StringComparison]::OrdinalIgnoreCase)) 'entrada fora da base desta execucao'
        Assert ($v3.Adversarial[$Path].StartsWith($runRoot + '\', [StringComparison]::OrdinalIgnoreCase)) 'alvo do link fora da raiz desta execucao'
        return
    }
    Assert-Entry $Path
}
function Invoke-V3Clean([string[]]$Paths, [string]$LogName, $Operator, [scriptblock]$Hook, [hashtable]$Fingerprints = @{}, [switch]$Gone) {
    # -Gone (K3): the entry is a root of this run that no longer exists (nothing left to delete): canonical, under the
    # base, absent.
    $entries = @(foreach ($v3p in $Paths) {
            if ($Gone) { Assert ([string]::Equals([IO.Path]::GetFullPath($v3p), $v3p, [StringComparison]::Ordinal) -and $v3p.StartsWith($ctx.Base + '\', [StringComparison]::OrdinalIgnoreCase) -and -not (Test-Path -LiteralPath $v3p)) 'entrada ausente fora da base ou ainda presente' }
            else { Assert-V3Entry $v3p }
            [pscustomobject]@{ Source = 'e2e-v3'; Path = $v3p; Fingerprint = $Fingerprints[$v3p] } })
    $log = Join-Path $ctx.LogDir $LogName
    if (-not $Operator) { $Operator = New-Operator }
    $a = @{ Entries = $entries; PlanPresenter = $presenter; ConfirmationReader = $Operator.Reader; InventoryArgs = $ia; LogFile = $log; Interaction = @{ Caller = 'E2E'; ConsoleRequired = $true }; DeleteTreeImpl = $v3Deleter }
    if ($Leg -eq 'A') { $a['AcceptB1ResidualRisk'] = $true }
    if ($Hook) { $a['BeforeDeleteHook'] = $Hook }
    $v3s.Calls = 0
    $res = Invoke-AtmClean @a
    return [pscustomobject]@{ Res = $res; Log = $log; Calls = $v3s.Calls }
}
function Invoke-V3Churn([string[]]$Paths, [string]$LogBase, $Operator, [scriptblock]$Hook) {
    # As Invoke-E2ECleanChurn (V2): a refusal before any call to the deleter AND before the attack ran (process churn of
    # the runner: PLAN_CHANGED_BEFORE_EXECUTION or a revalidation refusal) is retried, up to 3 complete, fresh runs, and
    # explained by the identities recorded in the plan. Once the attack ran, the result is final.
    $churn = New-Object System.Collections.Generic.List[object]
    for ($n = 1; $n -le 3; $n++) {
        $v3s.Attacked = $false
        $r = Invoke-V3Clean -Paths $Paths -LogName "$LogBase-$n.jsonl" -Operator $Operator -Hook $Hook
        $retry = (-not $v3s.Attacked -and $r.Calls -eq 0 -and @($r.Res.Deleted).Count -eq 0 -and @('PLAN_CHANGED_BEFORE_EXECUTION', 'REVALIDATION_REFUSED') -ccontains [string]$r.Res.Aborted)
        if (-not $retry) { return [pscustomobject]@{ Res = $r.Res; Log = $r.Log; Calls = $r.Calls; Attempts = $n; Churn = $churn.ToArray(); Exhausted = $false } }
        $planKeys = @(Read-E2ELog $r.Log | Where-Object { $_.type -ceq 'plan' } | ForEach-Object { @($_.uninspectableKeys) } | Where-Object { $_ })
        $nowKeys = @((Get-AtmUninspectableKeys (Invoke-AtmInventory @ia)).Keys)
        $churn.Add([pscustomobject]@{ Attempt = $n; Code = [string]$r.Res.Aborted; NewIdentities = @($nowKeys | Where-Object { $planKeys -notcontains $_ }).Count; PlanIdentities = $planKeys.Count })
    }
    return [pscustomobject]@{ Res = $null; Log = $null; Calls = 0; Attempts = 3; Churn = $churn.ToArray(); Exhausted = $true }
}
function Get-V3LogTypes([string]$Log) { if (Test-Path -LiteralPath $Log) { return (Get-Types (Read-E2ELog $Log)) }; return '<no log>' }
function Get-V3Intents([string]$Log) { if (Test-Path -LiteralPath $Log) { return @(Read-E2ELog $Log | Where-Object { $_.type -ceq 'intent' }).Count }; return 0 }
function Get-V3Attempts($C) { if ($C.Attempts -gt 1) { return "; attempts $($C.Attempts) ($(Get-ChurnText $C.Churn))" }; return '' }
function Assert-V3PlanRefused($C, [string]$Code) {
    # Refused while planning: no log file, no question, no call to the deleter.
    Assert ($C.Res.Aborted -ceq 'NENHUM_CAMINHO_ELEGIVEL') "Aborted=$($C.Res.Aborted) StoppedBy=$($C.Res.StoppedBy), esperado NENHUM_CAMINHO_ELEGIVEL"
    Assert (@($C.Res.Rejected).Count -eq 1) "rejeitadas: $(@($C.Res.Rejected).Count)"
    $codes = Get-Codes @($C.Res.Rejected[0].Reasons)
    Assert ($codes -match $Code) "motivos: $codes, esperado $Code"
    Assert (-not $C.Res.LogCreated -and -not (Test-Path -LiteralPath $C.Log) -and $C.Calls -eq 0 -and @($C.Res.Deleted).Count -eq 0) 'log criado ou deleter chamado numa recusa do plano'
    return $codes
}
function Assert-V3Stopped($C, [string]$Outcome, [string]$Reason, [string]$FailedAt) {
    # The real deleter was called once and its outcome stopped the run; the result is in the log file.
    Assert ($null -eq $C.Res.Aborted -and $C.Res.StoppedBy -ceq ('STOPPED_AFTER_' + $Outcome)) "Aborted=$($C.Res.Aborted) StoppedBy=$($C.Res.StoppedBy), esperado STOPPED_AFTER_$Outcome"
    $row = @($C.Res.Deleted)
    Assert ($row.Count -eq 1 -and $row[0].Outcome -ceq $Outcome) "desfecho: $(@($row | ForEach-Object { $_.Outcome }) -join ',')"
    if ($Reason) { Assert ([string]$row[0].AbortReason -like ($Reason + '*')) "AbortReason=$([string]$row[0].AbortReason -replace ':.*$', ''), esperado $Reason" }
    if ($FailedAt) { Assert ([string]::Equals([string]$row[0].FailedAt, $FailedAt, [StringComparison]::OrdinalIgnoreCase)) "FailedAt divergente ($(if ($row[0].FailedAt) { Split-Path -Leaf ([string]$row[0].FailedAt) }))" }
    $types = Get-V3LogTypes $C.Log
    Assert ($types -ceq 'run-start,plan,declaration,confirmation,plan-check,intent,result,run-end') "registros: $types"
    $recs = Read-E2ELog $C.Log
    $res = @($recs | Where-Object { $_.type -ceq 'result' })[0]
    Assert ($res.outcome -ceq $Outcome -and [string]$res.abortReason -ceq [string]$row[0].AbortReason -and [string]$res.failedAt -ceq [string]$row[0].FailedAt) 'result do log diferente do resultado'
    Assert ($recs[-1].stoppedBy -ceq ('STOPPED_AFTER_' + $Outcome)) "run-end: $($recs[-1].stoppedBy)"
    Assert ($C.Calls -eq 1 -and (Get-V3Intents $C.Log) -eq 1) "chamadas ao deleter $($C.Calls), intents $(Get-V3Intents $C.Log)"
    return $row[0]
}
$v3NeedPlant = { if (-not $v3.Ready) { NotTested 'V3 plant unavailable' } }
$v3NeedExec = {
    if (-not $v3.Ready) { return (NotTested 'V3 plant unavailable') }
    if (-not $ctx.Eligible) {
        if ($Leg -eq 'B') { return (NotTested "leg B: ELIGIBLE unreachable (process coverage measured incomplete, $(if ($null -ne $summary.processCoverage) { $summary.processCoverage.uninspectable }) uninspectable): the root never reaches the deleter; never forced") }
        return (NotTested 'no planted root reached the expected category (P2-preview)')
    }
}
$v3ProbeHidden = {
    # F6: with B1 refusing first (coverage incomplete) the V0.1 gate never reaches the lock probe; elevated, there is no
    # B1 exception either, so EM_USO is not observable in leg B unless the coverage is complete.
    if (-not $v3.Ready) { return (NotTested 'V3 plant unavailable') }
    if ($Leg -eq 'B' -and ($null -eq $summary.processCoverage -or -not $summary.processCoverage.complete)) { return (NotTested 'leg B: B1 (coverage measured incomplete) refuses before the lock probe, so EM_USO is not observable in this leg; never forced') }
}

function Invoke-V3Child {
    # V3c child (a fresh process of the same account): one clean of its own on -ChildRoot, with the real lock name, the
    # real deleter (the same wrapper) and its own log file; the parent checked the entry before starting it. K1 and K3
    # end the process by itself (Environment.Exit: never a forced termination), so the lock is left abandoned and the
    # log ends at the intent. When it does not exit, it writes its outcome for the parent.
    $calls = @{ Presenter = 0 }
    $pres = { param($verified, $rejected, $inventory) $calls.Presenter++ }.GetNewClosure()
    if ($ChildMode -ceq 'K1') { $v3s.During = [Action[string]]({ param($root) [Environment]::Exit(7) }) }
    if ($ChildMode -ceq 'K3') { $v3s.After = { param($c, $res) [Environment]::Exit(8) } }
    $op = New-Operator
    $a = @{ Entries = @([pscustomobject]@{ Source = 'e2e-v3-child'; Path = $ChildRoot; Fingerprint = $null }); PlanPresenter = $pres; ConfirmationReader = $op.Reader; InventoryArgs = $ia; LogFile = $ChildLog; Interaction = @{ Caller = 'E2E'; ConsoleRequired = $true }; DeleteTreeImpl = $v3Deleter }
    if ($Leg -eq 'A') { $a['AcceptB1ResidualRisk'] = $true }
    $res = Invoke-AtmClean @a
    [IO.File]::WriteAllText($ChildOut, ('NOT_EXITED|{0}|{1}|{2}|{3}' -f $res.Aborted, $res.StoppedBy, $calls.Presenter, [bool]$res.LogCreated))
}
if ($ChildMode) {
    if (-not $ChildRoot -or -not $ChildLog -or -not $ChildOut) { throw 'modo filho sem raiz, log ou saida' }
    Invoke-V3Child
    exit 0
}

Case 'V3-plant' {
    Assert ($null -ne $ctx['Base'] -and (Test-Path -LiteralPath $ctx.Base)) 'base plantada indisponivel'
    Assert ($null -eq $v3.NativeError) "auxiliar nativo do teste nao compilou: $($v3.NativeError)"
    # V3a roots, then V3b (new entries, changes, ACL and processes after the plan).
    foreach ($l in @('U1', 'U3', 'U4', 'U5', 'U6', 'U7', 'U8', 'U9', 'R1', 'R4', 'R5', 'R6', 'R7', 'R8', 'R9', 'R11', 'R12', 'R13',
            'N1', 'N2', 'N4', 'N5', 'N6', 'N8', 'A1', 'A2', 'A3', 'A4', 'P1', 'P2', 'P3',
            'O2', 'O3', 'L2', 'K1', 'K3', 'X1', 'X3', 'S2')) { New-V3Root $l }
    New-V3Root 'R10' 'C--atm-e2e-v3-anc'
    # Leg B: items created elevated are owned by Administrators; the profile's own roots are owned by the account.
    if ($isAdmin) {
        foreach ($sd in @((Join-Path $ctx.Base $v3Slug), (Join-Path $ctx.Base 'C--atm-e2e-v3-anc'))) {
            foreach ($it in @(@(Get-Item -LiteralPath $sd -Force) + @(Get-ChildItem -LiteralPath $sd -Recurse -Force))) { $a = Get-Acl -LiteralPath $it.FullName; $a.SetOwner($me.User); Set-Acl -LiteralPath $it.FullName -AclObject $a }
        }
    }
    # SIMULATION (declared, as V2): files and folders of every V3 root and its transcript set back, before any link
    # exists (a time change is never applied through a link).
    Start-Sleep -Seconds 2
    $old = [datetime]::UtcNow.AddHours(-$shiftHours)
    foreach ($r in @($v3.Roots.Values)) {
        $items = @(Get-ChildItem -LiteralPath $r.Path -Recurse -Force)
        foreach ($f in @($items | Where-Object { -not $_.PSIsContainer })) { [IO.File]::SetLastWriteTimeUtc($f.FullName, $old); [IO.File]::SetCreationTimeUtc($f.FullName, $old) }
        foreach ($d in @(@($items | Where-Object { $_.PSIsContainer } | Sort-Object { $_.FullName.Length } -Descending | ForEach-Object { $_.FullName }) + @($r.Path))) { [IO.Directory]::SetLastWriteTimeUtc($d, $old); [IO.Directory]::SetCreationTimeUtc($d, $old) }
        [IO.File]::SetLastWriteTimeUtc($r.Transcript, $old); [IO.File]::SetCreationTimeUtc($r.Transcript, $old)
    }
    foreach ($l in @('R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7', 'R8', 'R9', 'R12', 'R13')) { $null = New-V3Sentinel $l }
    # Attacks already in place before the plan.
    # R1: a junction inside a root (sub\link -> sentinel).
    $r1 = $v3.Roots['R1'].Path
    [void][IO.Directory]::CreateDirectory((Join-Path $r1 'sub\link'))
    $st = [AtmE2EV3Native]::SetJunction((Join-Path $r1 'sub\link'), $v3.Sentinels['R1'])
    Assert ($st -ceq 'SET_OK') "R1: juncao nao criada: $st"
    # R2: an entry that is itself a junction named as a session root (-> sentinel).
    $v3.R2 = Join-Path $ctx.Base "$v3Slug\$([guid]::NewGuid())"
    [void][IO.Directory]::CreateDirectory($v3.R2)
    $st = [AtmE2EV3Native]::SetJunction($v3.R2, $v3.Sentinels['R2'])
    Assert ($st -ceq 'SET_OK') "R2: juncao nao criada: $st"
    $v3.Adversarial[$v3.R2] = $v3.Sentinels['R2']
    # R3: a scope folder that is a junction to a sentinel holding a session root of the same shape.
    $r3id = [guid]::NewGuid().ToString()
    [void][IO.Directory]::CreateDirectory((Join-Path $v3.Sentinels['R3'] "$r3id\sub"))
    [IO.File]::WriteAllText((Join-Path $v3.Sentinels['R3'] "$r3id\ATM-E2E-NONCE.txt"), $nonce)
    $jscope = Join-Path $ctx.Base 'C--atm-e2e-v3-jscope'
    [void][IO.Directory]::CreateDirectory($jscope)
    $st = [AtmE2EV3Native]::SetJunction($jscope, $v3.Sentinels['R3'])
    Assert ($st -ceq 'SET_OK') "R3: juncao nao criada: $st"
    $v3.R3 = Join-Path $jscope $r3id
    $v3.Adversarial[$v3.R3] = $v3.Sentinels['R3']
    # R4, R5: a directory and a file symbolic link inside a root (privilege permitting; measured).
    $v3.Symlink['R4'] = [AtmE2EV3Native]::CreateSymlink((Join-Path $v3.Roots['R4'].Path 'sub\symdir'), $v3.Sentinels['R4'], $true)
    $v3.Symlink['R5'] = [AtmE2EV3Native]::CreateSymlink((Join-Path $v3.Roots['R5'].Path 'sub\symfile.txt'), (Join-Path $v3.Sentinels['R5'] 'keep.txt'), $false)
    # N8 (V3b): a hard link inside a root to a sentinel file outside it. The sentinel's times are set back first (the
    # link shares them), and the folder that received the new name too.
    $n8 = New-V3Sentinel 'N8'
    foreach ($f in @((Join-Path $n8 'keep.txt'), (Join-Path $n8 'deep\deep.txt'))) { [IO.File]::SetLastWriteTimeUtc($f, $old); [IO.File]::SetCreationTimeUtc($f, $old) }
    $v3.HardLink = [AtmE2EV3Native]::CreateHardLink((Join-Path $v3.Roots['N8'].Path 'sub\link.txt'), (Join-Path $n8 'keep.txt'))
    [IO.Directory]::SetLastWriteTimeUtc((Join-Path $v3.Roots['N8'].Path 'sub'), $old)
    # S1 (V3c): a base under %WINDIR%\Temp (shared by every account), with one root of the same shape and its transcript;
    # outside this run root, created in this run only (the name carries the nonce). Measured: a standard user may create it.
    try {
        $v3.S1Run = Join-Path $env:SystemRoot ('Temp\ATM-E2E-V3-' + $nonce.Substring(0, 12))
        Assert (-not (Test-Path -LiteralPath $v3.S1Run)) 'S1_RUN_EXISTS'
        $s1id = [guid]::NewGuid().ToString()
        $v3.S1Root = Join-Path $v3.S1Run "claude\$v3Slug\$s1id"
        [void][IO.Directory]::CreateDirectory((Join-Path $v3.S1Root 'sub'))
        [IO.File]::WriteAllText((Join-Path $v3.S1Root 'ATM-E2E-NONCE.txt'), $nonce)
        [IO.File]::WriteAllText((Join-Path $v3.S1Root 'sub\z.txt'), "synthetic V3 fixture (S1)`n")
        $tr = Join-Path $ctx.Cfg "projects\$v3Slug\$s1id.jsonl"
        [IO.File]::WriteAllText($tr, ('{"type":"ai-title","aiTitle":"SYNTHETIC","sessionId":"' + $s1id + '"}' + "`n"))
        foreach ($f in @((Join-Path $v3.S1Root 'ATM-E2E-NONCE.txt'), (Join-Path $v3.S1Root 'sub\z.txt'), $tr)) { [IO.File]::SetLastWriteTimeUtc($f, $old) }
        foreach ($d in @((Join-Path $v3.S1Root 'sub'), $v3.S1Root)) { [IO.Directory]::SetLastWriteTimeUtc($d, $old) }
    } catch { $v3.S1Error = $_.Exception.GetType().Name; $v3.S1Root = $null }
    $v3.SnapBefore = Get-V3Snap
    $v3.Ready = $true
    "$($v3.Roots.Count) roots (times set back ${shiftHours}h = SIMULATION), $($v3.Sentinels.Count) sentinels outside the base; junctions R1, R2, R3 in place; symbolic links R4 $($v3.Symlink['R4']), R5 $($v3.Symlink['R5']); hard link N8 $($v3.HardLink)"
}

# ---- 4.2 files and folders in use
function Invoke-V3PlanLock([string]$Id, [IO.FileShare]$Share) {
    $nt = & $v3ProbeHidden; if ($nt) { return $nt }
    $r = $v3.Roots['U1'].Path
    $before = Get-V3Snap
    $h = [IO.File]::Open((Join-Path $r 'a.txt'), 'Open', 'Read', $Share)
    try {
        # The lock probe itself sees the handle (the attack is in place); the plan is then made.
        $probe = Get-Codes @((Get-AtmLockProbeReasons $r).Reasons)
        Assert ($probe -match 'EM_USO') "sondagem direta sem EM_USO: $probe"
        $preview = ''
        if ($Leg -eq 'A') {
            # Preview never opens real roots (no probe): it still shows the exception, only clean refuses it.
            $pr = @(Invoke-AtmPreview -Inventory (Invoke-AtmInventory @ia) -InventoryArgs $ia | Where-Object { [string]::Equals($_.Partition.Path, $r, [StringComparison]::OrdinalIgnoreCase) })
            Assert ($pr.Count -eq 1 -and [string]$pr[0].Gate.Category -ceq 'ELIGIBLE_WITH_DECLARED_RISK') "preview: $(@($pr | ForEach-Object { $_.Gate.Category }) -join ',')"
            $preview = '; preview (no probe) still ELIGIBLE_WITH_DECLARED_RISK'
        }
        $c = Invoke-V3Clean -Paths @($r) -LogName "V3-$Id.jsonl"
    } finally { $h.Dispose() }
    $codes = Assert-V3PlanRefused $c $(if ($Leg -eq 'A') { 'COBERTURA_DE_PROCESSOS_INCOMPLETA' } else { 'EM_USO' })
    if ($Leg -eq 'A') { Assert ($codes -notmatch 'EM_USO') "perna A: EM_USO nao deveria aparecer (F6): $codes" }
    $inv = Assert-V3Only $before @() "V3-$Id"
    "file held ($Share) before the plan: lock probe EM_USO; clean NENHUM_CAMINHO_ELEGIVEL with $codes$(if ($Leg -eq 'A') { ' (B1 itself: the probe removed the exception, F6)' })$preview; no log, 0 intents; $inv"
}
Case 'V3-U1-held-no-share-delete-before-plan' { Invoke-V3PlanLock 'U1' ([IO.FileShare]::None) }
Case 'V3-U2-held-share-delete-before-plan' { Invoke-V3PlanLock 'U2' ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete) }
Case 'V3-U3-held-before-revalidation' {
    $nt = & $v3NeedExec; if ($nt) { return $nt }
    $r = $v3.Roots['U3'].Path
    $before = Get-V3Snap
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($share in @([IO.FileShare]::None, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))) {
        $v3Hold = @{ H = $null; Probe = $null; Share = $share }
        $hook = { param($part) if ($null -eq $v3Hold.H) { $v3s.Attacked = $true; $v3Hold.H = [IO.File]::Open((Join-Path $part.Path 'a.txt'), 'Open', 'Read', $v3Hold.Share); $v3Hold.Probe = Get-Codes @((Get-AtmLockProbeReasons $part.Path).Reasons) } }
        try { $c = Invoke-V3Churn -Paths @($r) -LogBase "V3-U3-$([int]$share)" -Hook $hook } finally { if ($null -ne $v3Hold.H) { $v3Hold.H.Dispose() } }
        if ($c.Exhausted) { return (Resolve-Exhausted $c) }
        Assert ($v3Hold.Probe -match 'EM_USO') "ataque nao confirmado pela sondagem: $($v3Hold.Probe)"
        Assert ($c.Res.Aborted -ceq 'REVALIDATION_REFUSED' -and @($c.Res.Skipped).Count -eq 1) "Aborted=$($c.Res.Aborted) StoppedBy=$($c.Res.StoppedBy)"
        $codes = Get-Codes $c.Res.Skipped[0].Reasons
        Assert ($codes -match $(if ($Leg -eq 'A') { 'B1_EXCEPTION_NO_LONGER_APPLIES' } else { 'EM_USO' })) "motivos da revalidacao: $codes"
        $types = Get-V3LogTypes $c.Log
        Assert ($types -ceq 'run-start,plan,declaration,confirmation,plan-check,skip,run-end' -and $c.Calls -eq 0) "registros: $types; chamadas $($c.Calls)"
        $out.Add("$($share): REVALIDATION_REFUSED ($codes)$(Get-V3Attempts $c)")
    }
    $inv = Assert-V3Only $before @() 'V3-U3-'
    "file held between the confirmation and the revalidation (probe EM_USO): $($out -join '; '); log run-start..plan-check,skip,run-end, 0 intents; $inv"
}
function Invoke-V3DuringLock([string]$Id, [string]$Label, [IO.FileShare]$Share) {
    $nt = & $v3NeedExec; if ($nt) { return $nt }
    $r = $v3.Roots[$Label].Path
    $z = Join-Path $r 'sub\z.txt'
    $zSha = Get-FileSha $z
    $top = @(Get-ChildItem -LiteralPath $r -File -Force).Count
    $before = Get-V3Snap
    $v3Hold = @{ H = $null; Err = $null }
    $v3Share = $Share
    $v3s.During = [Action[string]]({ param($root) try { $v3Hold.H = [IO.File]::Open($z, 'Open', 'Read', $v3Share) } catch { $v3Hold.Err = $_.Exception.GetType().Name } }.GetNewClosure())
    try { $c = Invoke-V3Churn -Paths @($r) -LogBase "V3-$Id" } finally { $v3s.During = $null; if ($null -ne $v3Hold.H) { $v3Hold.H.Dispose() } }
    if ($c.Exhausted) { return (Resolve-Exhausted $c) }
    Assert ($null -eq $v3Hold.Err) "ataque nao aplicado: $($v3Hold.Err)"
    $row = Assert-V3Stopped $c 'PARTIAL' 'DELETE_FILE_REFUSED: IN_USE' $z
    Assert ([long]$row.FilesDeleted -eq $top -and (Test-Path -LiteralPath $z) -and (Get-FileSha $z) -ceq $zSha) "FilesDeleted=$($row.FilesDeleted) (esperado $top); arquivo em uso preservado"
    $inv = Assert-V3Only $before @((Get-V3Rel $r)) "V3-$Id"
    "file held ($Share) inside the deleter, after pinning: PARTIAL, DELETE_FILE_REFUSED: IN_USE at sub\z.txt, $($row.FilesDeleted) files deleted before it, the held file intact; STOPPED_AFTER_PARTIAL; log ...intent,result,run-end, 1 intent$(Get-V3Attempts $c); $inv"
}
Case 'V3-U4-held-no-share-delete-in-deleter' { Invoke-V3DuringLock 'U4' 'U4' ([IO.FileShare]::None) }
Case 'V3-U5-held-share-delete-in-deleter' { Invoke-V3DuringLock 'U5' 'U5' ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete) }
Case 'V3-U6-attributes-only-handle-in-deleter' {
    # NOVO-MED: a handle without data access and full sharing (invisible to the lock probe) on the last file. Accepted:
    # PARTIAL (DELETE_DIR_FAILED at sub: the deleted file stays pending while the handle is open) or COMPLETE.
    $nt = & $v3NeedExec; if ($nt) { return $nt }
    $r = $v3.Roots['U6'].Path
    $z = Join-Path $r 'sub\z.txt'
    $before = Get-V3Snap
    $v3Hold = @{ H = $null; Err = $null }
    $v3s.During = [Action[string]]({ param($root) $h = [AtmE2EV3Native]::OpenAttributesOnly($z, $false); if ($h.IsInvalid) { $v3Hold.Err = 'OPEN_FAILED'; $h.Dispose() } else { $v3Hold.H = $h } }.GetNewClosure())
    $v3s.After = { param($c, $res) if ($null -ne $v3Hold.H) { $v3Hold.H.Dispose(); $v3Hold.H = $null } }
    try { $c = Invoke-V3Churn -Paths @($r) -LogBase 'V3-U6' } finally { $v3s.During = $null; $v3s.After = $null; if ($null -ne $v3Hold.H) { $v3Hold.H.Dispose() } }
    if ($c.Exhausted) { return (Resolve-Exhausted $c) }
    if ($null -ne $v3Hold.Err) { return (NotTested "the attributes-only handle could not be opened ($($v3Hold.Err)); outcome $(@($c.Res.Deleted | ForEach-Object { $_.Outcome }) -join ',')") }
    $row = @($c.Res.Deleted)
    Assert ($row.Count -eq 1) "desfechos: $($row.Count)"
    if ($row[0].Outcome -ceq 'PARTIAL') { $null = Assert-V3Stopped $c 'PARTIAL' 'DELETE_DIR_FAILED' (Join-Path $r 'sub'); $m = "PARTIAL, DELETE_DIR_FAILED at sub ($($row[0].AbortReason -replace '^.*(WIN32_\d+).*$', '$1')): the deleted file stayed pending while the handle was open" }
    elseif ($row[0].Outcome -ceq 'COMPLETE') { Assert ($null -eq $c.Res.StoppedBy -and $row[0].Verified -eq $true) 'COMPLETE sem verificacao'; $m = 'COMPLETE, verified' }
    else { throw "desfecho fora do conjunto aceito {PARTIAL com DELETE_DIR_FAILED, COMPLETE}: $($row[0].Outcome) $([string]$row[0].AbortReason -replace ':.*$', '')" }
    $inv = Assert-V3Only $before @((Get-V3Rel $r)) 'V3-U6'
    "MEASURED: a handle with no data access and full sharing on the last file, opened after pinning: $m$(Get-V3Attempts $c); $inv"
}
Case 'V3-U7-attributes-only-handle-on-root' {
    # NOVO-MED: the same kind of handle on the root folder, kept open until the engine checked the absence. Accepted:
    # VERIFICATION_FAILED (the folder pending deletion is not confirmed gone) or COMPLETE.
    $nt = & $v3NeedExec; if ($nt) { return $nt }
    $r = $v3.Roots['U7'].Path
    $before = Get-V3Snap
    $v3Hold = @{ H = $null; Err = $null }
    $v3s.During = [Action[string]]({ param($root) $h = [AtmE2EV3Native]::OpenAttributesOnly($root, $true); if ($h.IsInvalid) { $v3Hold.Err = 'OPEN_FAILED'; $h.Dispose() } else { $v3Hold.H = $h } }.GetNewClosure())
    try { $c = Invoke-V3Churn -Paths @($r) -LogBase 'V3-U7' } finally { $v3s.During = $null; if ($null -ne $v3Hold.H) { $v3Hold.H.Dispose() } }
    if ($c.Exhausted) { return (Resolve-Exhausted $c) }
    if ($null -ne $v3Hold.Err) { return (NotTested "the attributes-only handle on the root could not be opened ($($v3Hold.Err))") }
    $row = @($c.Res.Deleted)
    Assert ($row.Count -eq 1) "desfechos: $($row.Count)"
    if ($row[0].Outcome -ceq 'VERIFICATION_FAILED') {
        $null = Assert-V3Stopped $c 'VERIFICATION_FAILED' $null $null
        Assert ($row[0].Completed -eq $true -and $row[0].Verified -eq $false) 'VERIFICATION_FAILED sem Completed'
        $m = "VERIFICATION_FAILED (state $($row[0].VerifiedState)): the deleter completed, the absence was not confirmed while the handle was open"
    } elseif ($row[0].Outcome -ceq 'COMPLETE') { Assert ($null -eq $c.Res.StoppedBy -and $row[0].Verified -eq $true) 'COMPLETE sem verificacao'; $m = 'COMPLETE, verified' }
    else { throw "desfecho fora do conjunto aceito {VERIFICATION_FAILED, COMPLETE}: $($row[0].Outcome) $([string]$row[0].AbortReason -replace ':.*$', '')" }
    $inv = Assert-V3Only $before @((Get-V3Rel $r)) 'V3-U7'
    "MEASURED: a handle with no data access and full sharing on the root folder, opened after pinning: $m$(Get-V3Attempts $c); $inv"
}
Case 'V3-U8-working-directory-before-plan' {
    $nt = & $v3ProbeHidden; if ($nt) { return $nt }
    $r = $v3.Roots['U8'].Path
    $before = Get-V3Snap
    # A process of this account with its working directory inside the root; it ends by itself (never terminated).
    $psi = New-Object Diagnostics.ProcessStartInfo($shellExe, '-NoProfile -NonInteractive -Command Start-Sleep -Seconds 20')
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true; $psi.WorkingDirectory = (Join-Path $r 'sub')
    $hp = [Diagnostics.Process]::Start($psi)
    Start-Sleep -Milliseconds 1500
    Assert (-not $hp.HasExited) 'processo auxiliar terminou antes do plano'
    $probe = Get-Codes @((Get-AtmLockProbeReasons $r).Reasons)
    Assert ($probe -match 'EM_USO') "sondagem direta sem EM_USO: $probe"
    $c = Invoke-V3Clean -Paths @($r) -LogName 'V3-U8.jsonl'
    $codes = Assert-V3PlanRefused $c $(if ($Leg -eq 'A') { 'COBERTURA_DE_PROCESSOS_INCOMPLETA' } else { 'EM_USO' })
    $inv = Assert-V3Only $before @() 'V3-U8'
    "process of this account with its working directory in the root (probe EM_USO): clean NENHUM_CAMINHO_ELEGIVEL with $codes$(if ($Leg -eq 'A') { ' (B1 itself, F6)' }); no log, 0 intents; the process ends by itself; $inv"
}
Case 'V3-U9-enter-pinned-folder-in-deleter' {
    # NOVO-MED: a process of this account started with its working directory in a pinned folder, after pinning.
    # Accepted: the start refused and COMPLETE; or started and the run stopped (PARTIAL), never outside the root.
    $nt = & $v3NeedExec; if ($nt) { return $nt }
    $r = $v3.Roots['U9'].Path
    $before = Get-V3Snap
    $v3Start = @{ Status = $null }
    $v3Exe = $shellExe; $v3Wd = Join-Path $r 'sub'
    $v3s.During = [Action[string]]({
        param($root)
        try {
            $psi = New-Object Diagnostics.ProcessStartInfo($v3Exe, '-NoProfile -NonInteractive -Command Start-Sleep -Seconds 15')
            $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true; $psi.WorkingDirectory = $v3Wd
            $null = [Diagnostics.Process]::Start($psi); $v3Start.Status = 'STARTED'
        } catch { $v3Start.Status = 'REFUSED_' + $_.Exception.GetBaseException().GetType().Name }
    }.GetNewClosure())
    try { $c = Invoke-V3Churn -Paths @($r) -LogBase 'V3-U9' } finally { $v3s.During = $null }
    if ($c.Exhausted) { return (Resolve-Exhausted $c) }
    $row = @($c.Res.Deleted)
    Assert ($row.Count -eq 1 -and $null -ne $v3Start.Status) "desfechos: $($row.Count); inicio: $($v3Start.Status)"
    if ($v3Start.Status -ceq 'STARTED') { Assert ($row[0].Outcome -ceq 'PARTIAL' -or $row[0].Outcome -ceq 'COMPLETE') "iniciado e desfecho fora do conjunto aceito: $($row[0].Outcome)" }
    else { Assert ($row[0].Outcome -ceq 'COMPLETE' -and $row[0].Verified -eq $true) "inicio recusado e desfecho $($row[0].Outcome), esperado COMPLETE" }
    $inv = Assert-V3Only $before @((Get-V3Rel $r)) 'V3-U9'
    "MEASURED: process start with its working directory in a pinned folder: $($v3Start.Status); outcome $($row[0].Outcome)$(if ($row[0].AbortReason) { ' (' + ([string]$row[0].AbortReason -replace ':.*$', '') + ')' })$(Get-V3Attempts $c); $inv"
}

# ---- 4.1 reparse points, links and the root swapped by a link
Case 'V3-R11-rename-pinned-in-deleter' {
    $nt = & $v3NeedExec; if ($nt) { return $nt }
    $r = $v3.Roots['R11'].Path
    $before = Get-V3Snap
    $v3Ren = @{ Results = (New-Object System.Collections.Generic.List[string]) }
    $v3Targets = @((Join-Path $r 'sub'), $r, (Join-Path $ctx.Base $v3Slug), $ctx.Base)
    $v3Exe = $shellExe
    $v3Cmd = "try { Rename-Item -LiteralPath '$($r.Replace("'", "''"))' -NewName 'v3-taken' -ErrorAction Stop; exit 0 } catch { exit 3 }"
    $v3s.During = [Action[string]]({
        param($root)
        foreach ($t in $v3Targets) { try { [IO.Directory]::Move($t, $t + '-v3moved'); $v3Ren.Results.Add('MOVED') } catch { $v3Ren.Results.Add('REFUSED') } }
        $psi = New-Object Diagnostics.ProcessStartInfo($v3Exe, ('-NoProfile -NonInteractive -Command "' + $v3Cmd + '"'))
        $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
        $p = [Diagnostics.Process]::Start($psi)
        if ($p.WaitForExit(60000)) { $v3Ren.Results.Add($(if ($p.ExitCode -eq 3) { 'REFUSED' } else { 'CHILD_EXIT_' + $p.ExitCode })) } else { $v3Ren.Results.Add('CHILD_TIMEOUT') }
    }.GetNewClosure())
    try { $c = Invoke-V3Churn -Paths @($r) -LogBase 'V3-R11' } finally { $v3s.During = $null }
    if ($c.Exhausted) { return (Resolve-Exhausted $c) }
    Assert (($v3Ren.Results -join ',') -ceq 'REFUSED,REFUSED,REFUSED,REFUSED,REFUSED') "renomeacoes durante a exclusao: $($v3Ren.Results -join ',')"
    Assert (-not $c.Res.Aborted -and -not $c.Res.StoppedBy -and @($c.Res.Deleted).Count -eq 1 -and $c.Res.Deleted[0].Outcome -ceq 'COMPLETE' -and $c.Res.Deleted[0].Verified -eq $true) "resultado: $($c.Res.Aborted) $($c.Res.StoppedBy) $(@($c.Res.Deleted | ForEach-Object { $_.Outcome }) -join ',')"
    $types = Get-V3LogTypes $c.Log
    Assert ($types -ceq 'run-start,plan,declaration,confirmation,plan-check,intent,result,run-end' -and $c.Calls -eq 1) "registros: $types"
    $inv = Assert-V3Only $before @((Get-V3Rel $r)) 'V3-R11'
    "inside the deleter: renaming sub, the root, the scope and the base (this process) and the root (another process of this account) all refused; COMPLETE, verified; log $types$(Get-V3Attempts $c); $inv"
}
function Invoke-V3InPlaceLink([string]$Id, [switch]$Symlink) {
    # A pinned empty folder turned into a link IN PLACE by another handle (FSCTL; share modes do not stop it, F-10/M-1).
    $nt = & $v3NeedExec; if ($nt) { return $nt }
    $r = $v3.Roots[$Id].Path
    $before = Get-V3Snap
    $v3J = @{ Set = $null }
    $v3Empty = Join-Path $r 'empty'; $v3Target = $v3.Sentinels[$Id]; $v3Sym = [bool]$Symlink
    $v3s.During = [Action[string]]({ param($root) try { $v3J.Set = $(if ($v3Sym) { [AtmE2EV3Native]::SetDirSymlink($v3Empty, $v3Target) } else { [AtmE2EV3Native]::SetJunction($v3Empty, $v3Target) }) } catch { $v3J.Set = 'THROW_' + $_.Exception.GetType().Name } }.GetNewClosure())
    try { $c = Invoke-V3Churn -Paths @($r) -LogBase "V3-$Id" } finally { $v3s.During = $null }
    if ($c.Exhausted) { return (Resolve-Exhausted $c) }
    if ($v3J.Set -cne 'SET_OK') {
        Assert (@($c.Res.Deleted).Count -eq 1 -and $c.Res.Deleted[0].Outcome -ceq 'COMPLETE') "link nao gravado ($($v3J.Set)) e desfecho $(@($c.Res.Deleted | ForEach-Object { $_.Outcome }) -join ',')"
        $null = Assert-V3Only $before @((Get-V3Rel $r)) "V3-$Id"
        return (NotTested "the $(if ($Symlink) { 'symbolic link' } else { 'junction' }) could not be set by this account ($($v3J.Set -replace ' .*$', '')); the deletion then completed normally; covered by the suite on its own fixtures")
    }
    $row = Assert-V3Stopped $c 'PARTIAL' 'PINNED_DIR_CHANGED' $v3Empty
    $inv = Assert-V3Only $before @((Get-V3Rel $r)) "V3-$Id"
    "inside the deleter, the empty pinned folder turned into a $(if ($Symlink) { 'directory symbolic link' } else { 'junction' }) to a sentinel: PINNED_DIR_CHANGED at it, PARTIAL ($($row.FilesDeleted) files deleted before), sentinel never traversed; log ...intent,result,run-end$(Get-V3Attempts $c); $inv"
}
Case 'V3-R12-junction-in-place-in-deleter' { Invoke-V3InPlaceLink 'R12' }
Case 'V3-R13-symlink-in-place-in-deleter' { Invoke-V3InPlaceLink 'R13' -Symlink }
Case 'V3-R9-root-swapped-before-deleter' {
    $nt = & $v3NeedExec; if ($nt) { return $nt }
    $r = $v3.Roots['R9'].Path
    $before = Get-V3Snap
    $v3Swap = @{ Moved = $null }
    $v3SwapTarget = $v3.Sentinels['R9']
    $v3s.Before = { param($c) $v3Swap.Moved = Switch-V3ToJunction $c.Path $v3SwapTarget }
    try { $c = Invoke-V3Churn -Paths @($r) -LogBase 'V3-R9' } finally { $v3s.Before = $null }
    if ($c.Exhausted) { return (Resolve-Exhausted $c) }
    $row = Assert-V3Stopped $c 'REFUSED' 'ROOT_REPARSE_POINT' $null
    Assert ($row.Attempted -eq $false -and [long]$row.FilesDeleted -eq 0) "Attempted=$($row.Attempted) FilesDeleted=$($row.FilesDeleted)"
    Assert ((Test-Path -LiteralPath (Join-Path $v3Swap.Moved 'sub\z.txt')) -and (Test-Path -LiteralPath (Join-Path $v3Swap.Moved 'a.txt'))) 'raiz original movida incompleta'
    $inv = Assert-V3Only $before @((Get-V3Rel $r), (Get-V3Rel $v3Swap.Moved)) 'V3-R9'
    "between the revalidation and the deleter, the root replaced by a junction to a sentinel: ROOT_REPARSE_POINT, REFUSED, nothing attempted; STOPPED_AFTER_REFUSED$(Get-V3Attempts $c); $inv"
}
Case 'V3-R10-scope-swapped-before-deleter' {
    $nt = & $v3NeedExec; if ($nt) { return $nt }
    $r = $v3.Roots['R10'].Path
    $before = Get-V3Snap
    $v3Swap = @{ Moved = $null }
    $v3Scope = [IO.Path]::GetDirectoryName($r)
    # The scope replaced by a junction to its own moved content: the same tree, reached through a link.
    $v3s.Before = { param($c) $v3Swap.Moved = Switch-V3ToJunction $v3Scope $null }
    try { $c = Invoke-V3Churn -Paths @($r) -LogBase 'V3-R10' } finally { $v3s.Before = $null }
    if ($c.Exhausted) { return (Resolve-Exhausted $c) }
    $row = Assert-V3Stopped $c 'REFUSED' 'ANCESTOR_REPARSE_POINT' $null
    Assert ($row.Attempted -eq $false -and [long]$row.FilesDeleted -eq 0) "Attempted=$($row.Attempted) FilesDeleted=$($row.FilesDeleted)"
    Assert (Test-Path -LiteralPath (Join-Path $v3Swap.Moved "$(Split-Path -Leaf $r)\sub\z.txt")) 'arvore movida incompleta'
    $inv = Assert-V3Only $before @((Get-V3Rel $v3Scope), (Get-V3Rel $v3Swap.Moved)) 'V3-R10'
    "between the revalidation and the deleter, the scope replaced by a junction to the same content: ANCESTOR_REPARSE_POINT, REFUSED, nothing attempted$(Get-V3Attempts $c); $inv"
}
Case 'V3-R8-root-swapped-before-revalidation' {
    $nt = & $v3NeedExec; if ($nt) { return $nt }
    $r = $v3.Roots['R8'].Path
    $before = Get-V3Snap
    $v3Swap = @{ Moved = $null }
    $v3SwapTarget = $v3.Sentinels['R8']
    $hook = { param($part) if ($null -eq $v3Swap.Moved) { $v3s.Attacked = $true; $v3Swap.Moved = Switch-V3ToJunction $part.Path $v3SwapTarget } }
    $c = Invoke-V3Churn -Paths @($r) -LogBase 'V3-R8' -Hook $hook
    if ($c.Exhausted) { return (Resolve-Exhausted $c) }
    Assert ($c.Res.Aborted -ceq 'REVALIDATION_REFUSED' -and @($c.Res.Skipped).Count -eq 1) "Aborted=$($c.Res.Aborted) StoppedBy=$($c.Res.StoppedBy)"
    $codes = Get-Codes $c.Res.Skipped[0].Reasons
    Assert ($codes -match 'ALTERADO_APOS_CONFIRMACAO' -and ($Leg -ne 'A' -or $codes -match 'B1_EXCEPTION_NO_LONGER_APPLIES')) "motivos da revalidacao: $codes"
    $types = Get-V3LogTypes $c.Log
    Assert ($types -ceq 'run-start,plan,declaration,confirmation,plan-check,skip,run-end' -and $c.Calls -eq 0) "registros: $types; chamadas $($c.Calls)"
    $inv = Assert-V3Only $before @((Get-V3Rel $r), (Get-V3Rel $v3Swap.Moved)) 'V3-R8'
    "between the confirmation and the revalidation, the root replaced by a junction: REVALIDATION_REFUSED ($codes), 0 intents; log $types$(Get-V3Attempts $c); $inv"
}
Case 'V3-R7-root-swapped-before-final-confirmation' {
    $nt = & $v3NeedExec; if ($nt) { return $nt }
    $r = $v3.Roots['R7'].Path
    $before = Get-V3Snap
    $v3Swap = @{ Moved = $null }
    $v3SwapTarget = $v3.Sentinels['R7']; $v3SwapRoot = $r
    $v3Inner = (New-Operator).Reader
    # The harness's own confirmation reader swaps the root right before answering the final phrase.
    $op = @{ Reader = { param($phrase, $kind, $rootPath, $choices, $info) if ($kind -ceq 'confirm' -and $null -eq $v3Swap.Moved) { $v3s.Attacked = $true; $v3Swap.Moved = Switch-V3ToJunction $v3SwapRoot $v3SwapTarget }; & $v3Inner $phrase $kind $rootPath $choices $info } }
    $c = Invoke-V3Churn -Paths @($r) -LogBase 'V3-R7' -Operator $op
    if ($c.Exhausted) { return (Resolve-Exhausted $c) }
    Assert ($null -ne $v3Swap.Moved) 'a confirmacao final nao foi pedida'
    Assert ($c.Res.Aborted -ceq 'PLAN_CHANGED_BEFORE_EXECUTION' -and $c.Calls -eq 0 -and @($c.Res.Deleted).Count -eq 0) "Aborted=$($c.Res.Aborted) chamadas $($c.Calls)"
    $recs = Read-E2ELog $c.Log
    $types = Get-Types $recs
    $pc = @($recs | Where-Object { $_.type -ceq 'plan-check' })
    Assert ($types -ceq 'run-start,plan,declaration,confirmation,plan-check,run-end' -and $pc[0].matched -eq $false -and @($pc[0].changed).Count -eq 1) "registros: $types"
    $inv = Assert-V3Only $before @((Get-V3Rel $r), (Get-V3Rel $v3Swap.Moved)) 'V3-R7'
    "between the plan and the final confirmation, the root replaced by a junction: PLAN_CHANGED_BEFORE_EXECUTION (plan-check matched=false, the root listed), 0 intents; log $types; $inv"
}
Case 'V3-R6-root-swapped-after-preview' {
    $nt = & $v3NeedPlant; if ($nt) { return $nt }
    $r = $v3.Roots['R6'].Path
    $before = Get-V3Snap
    $fp = @((Invoke-AtmInventory @ia).Partitions | Where-Object { [string]::Equals($_.Path, $r, [StringComparison]::OrdinalIgnoreCase) })[0].Fingerprint
    $moved = Switch-V3ToJunction $r $v3.Sentinels['R6']
    $v3.Adversarial[$r] = $v3.Sentinels['R6']
    $c = Invoke-V3Clean -Paths @($r) -LogName 'V3-R6.jsonl' -Fingerprints @{ $r = $fp }
    $codes = Assert-V3PlanRefused $c 'REPARSE_POINT'
    Assert ($codes -match 'ALTERADO_DESDE_O_PREVIEW') "motivos: $codes"
    $inv = Assert-V3Only $before @((Get-V3Rel $r), (Get-V3Rel $moved)) 'V3-R6'
    "root replaced by a junction between the preview and clean (preview fingerprint given): NENHUM_CAMINHO_ELEGIVEL with $codes; no log, 0 intents; $inv"
}
Case 'V3-R1-junction-inside-before-plan' {
    $nt = & $v3NeedPlant; if ($nt) { return $nt }
    $before = Get-V3Snap
    $c = Invoke-V3Clean -Paths @($v3.Roots['R1'].Path) -LogName 'V3-R1.jsonl'
    $codes = Assert-V3PlanRefused $c 'REPARSE_POINT'
    $inv = Assert-V3Only $before @() 'V3-R1'
    "junction inside the root before the plan: NENHUM_CAMINHO_ELEGIVEL with $codes (both legs: a hard flag, before B1); no log, 0 intents; $inv"
}
Case 'V3-R2-root-is-junction' {
    $nt = & $v3NeedPlant; if ($nt) { return $nt }
    $before = Get-V3Snap
    $c = Invoke-V3Clean -Paths @($v3.R2) -LogName 'V3-R2.jsonl'
    $codes = Assert-V3PlanRefused $c 'REPARSE_POINT'
    $inv = Assert-V3Only $before @() 'V3-R2'
    "entry that is a junction named as a session root: NENHUM_CAMINHO_ELEGIVEL with $codes; target never traversed; no log, 0 intents; $inv"
}
Case 'V3-R3-scope-is-junction' {
    $nt = & $v3NeedPlant; if ($nt) { return $nt }
    $before = Get-V3Snap
    $c = Invoke-V3Clean -Paths @($v3.R3) -LogName 'V3-R3.jsonl'
    $codes = Assert-V3PlanRefused $c 'FORA_DAS_ROOTS_PERMITIDAS'
    $inv = Assert-V3Only $before @() 'V3-R3'
    "session root reached through a scope folder that is a junction: never inventoried, NENHUM_CAMINHO_ELEGIVEL with $codes; no log, 0 intents; $inv"
}
function Invoke-V3SymlinkInside([string]$Id, [string]$Kind) {
    $nt = & $v3NeedPlant; if ($nt) { return $nt }
    if ($v3.Symlink[$Id] -cne 'OK') { return (NotTested "a $Kind symbolic link could not be created by this account ($($v3.Symlink[$Id])): no symbolic link privilege (a standard user without developer mode)") }
    $before = Get-V3Snap
    $c = Invoke-V3Clean -Paths @($v3.Roots[$Id].Path) -LogName "V3-$Id.jsonl"
    $codes = Assert-V3PlanRefused $c 'REPARSE_POINT'
    $inv = Assert-V3Only $before @() "V3-$Id"
    "$Kind symbolic link inside the root before the plan: NENHUM_CAMINHO_ELEGIVEL with $codes; no log, 0 intents; $inv"
}
Case 'V3-R4-directory-symlink-inside-before-plan' { Invoke-V3SymlinkInside 'R4' 'directory' }
Case 'V3-R5-file-symlink-inside-before-plan' { Invoke-V3SymlinkInside 'R5' 'file' }
# ---------------------------------------------------------------------------------------------- V3b
# V0.3 V3, phase V3b (contract sections 4.3 and 4.4): a new entry, a change, a third-party ACL and a new process after
# the plan, in each window. N3 (a new file between the confirmation and the revalidation) is V2's P8. ACL changes are
# fixtures only (J4): an explicit ACE on a root this run planted, never on a folder of the machine or the profile. The
# processes are short and end by themselves; none is ever terminated.
function Grant-V3ThirdPartyWrite([string]$Path) {
    # Fixture only (J4): one explicit, non-inherited ACE giving BUILTIN\Users modify on a root of this run.
    Assert ($Path.StartsWith((Join-Path $ctx.Base $v3Slug) + '\', [StringComparison]::OrdinalIgnoreCase) -and [IO.File]::ReadAllText((Join-Path $Path 'ATM-E2E-NONCE.txt')) -ceq $nonce) 'ACE fora de uma raiz plantada nesta execucao'
    $acl = Get-Acl -LiteralPath $Path
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')), 'Modify', 'None', 'None', 'Allow')))
    Set-Acl -LiteralPath $Path -AclObject $acl
    return (Get-Codes @(Get-AtmAclProblems -Path $Path -OwnerSid $mySid))
}
function Request-V3OtherAccountProcess([string]$Tag) {
    # Asks the e2e (another account) to start a short process of its own and waits for its confirmation; returns the
    # confirmation text or $null.
    [IO.File]::WriteAllText((Join-Path $SignalDir "go-$Tag.txt"), $nonce)
    $ack = Join-Path $SignalDir "ack-$Tag.txt"
    for ($i = 0; $i -lt 200 -and -not (Test-Path -LiteralPath $ack); $i++) { Start-Sleep -Milliseconds 100 }
    if (-not (Test-Path -LiteralPath $ack)) { return $null }
    Start-Sleep -Milliseconds 1500
    return [IO.File]::ReadAllText($ack).Trim()
}
$v3NeedSignal = {
    if ($Leg -ne 'A') { return (NotTested 'leg A only: a process of another account is not inspectable only for a non-elevated token (B1 exception)') }
    if (-not $SignalDir -or -not (Test-Path -LiteralPath $SignalDir)) { return (NotTested 'no signal folder from the e2e (another account cannot be asked to start a process)') }
}

# ---- 4.3 new entry and change after the plan
Case 'V3-N1-new-file-after-preview' {
    $nt = & $v3NeedPlant; if ($nt) { return $nt }
    $r = $v3.Roots['N1'].Path
    $before = Get-V3Snap
    $fp = @((Invoke-AtmInventory @ia).Partitions | Where-Object { [string]::Equals($_.Path, $r, [StringComparison]::OrdinalIgnoreCase) })[0].Fingerprint
    # A new file whose time is set back too: only the fingerprint tells it apart (not RECENT).
    $nf = Join-Path $r 'sub\new-after-preview.txt'
    [IO.File]::WriteAllText($nf, "new after the preview`n"); [IO.File]::SetLastWriteTimeUtc($nf, [datetime]::UtcNow.AddHours(-$shiftHours))
    $c = Invoke-V3Clean -Paths @($r) -LogName 'V3-N1.jsonl' -Fingerprints @{ $r = $fp }
    $codes = Assert-V3PlanRefused $c 'ALTERADO_DESDE_O_PREVIEW'
    Assert (Test-Path -LiteralPath $nf) 'arquivo novo apagado'
    $inv = Assert-V3Only $before @((Get-V3Rel $r)) 'V3-N1'
    "a file added between the preview and clean (preview fingerprint given): NENHUM_CAMINHO_ELEGIVEL with $codes (both legs); no log, 0 intents; $inv"
}
Case 'V3-N2-new-file-before-final-confirmation' {
    $nt = & $v3NeedExec; if ($nt) { return $nt }
    $r = $v3.Roots['N2'].Path
    $before = Get-V3Snap
    $v3New = @{ Path = (Join-Path $r 'sub\new-before-confirmation.txt'); Done = $false }
    $v3Inner = (New-Operator).Reader
    $op = @{ Reader = { param($phrase, $kind, $rootPath, $choices, $info) if ($kind -ceq 'confirm' -and -not $v3New.Done) { $v3New.Done = $true; $v3s.Attacked = $true; [IO.File]::WriteAllText($v3New.Path, "new before the final confirmation`n") }; & $v3Inner $phrase $kind $rootPath $choices $info } }
    $c = Invoke-V3Churn -Paths @($r) -LogBase 'V3-N2' -Operator $op
    if ($c.Exhausted) { return (Resolve-Exhausted $c) }
    Assert ($v3New.Done) 'a confirmacao final nao foi pedida'
    Assert ($c.Res.Aborted -ceq 'PLAN_CHANGED_BEFORE_EXECUTION' -and $c.Calls -eq 0 -and @($c.Res.Deleted).Count -eq 0) "Aborted=$($c.Res.Aborted) chamadas $($c.Calls)"
    $recs = Read-E2ELog $c.Log; $types = Get-Types $recs
    $pc = @($recs | Where-Object { $_.type -ceq 'plan-check' })
    Assert ($types -ceq 'run-start,plan,declaration,confirmation,plan-check,run-end' -and $pc[0].matched -eq $false -and @($pc[0].changed).Count -eq 1) "registros: $types"
    Assert (Test-Path -LiteralPath $v3New.Path) 'arquivo novo apagado'
    $inv = Assert-V3Only $before @((Get-V3Rel $r)) 'V3-N2'
    "a file added between the plan and the final confirmation: PLAN_CHANGED_BEFORE_EXECUTION (plan-check matched=false), 0 intents, the new file intact; log $types; $inv"
}
Case 'V3-N4-new-file-before-deleter' {
    $nt = & $v3NeedExec; if ($nt) { return $nt }
    $r = $v3.Roots['N4'].Path
    $before = Get-V3Snap
    $v3New = Join-Path $r 'sub\new-before-deleter.txt'
    $v3s.Before = { param($c) [IO.File]::WriteAllText($v3New, "new between the revalidation and the deleter`n") }
    try { $c = Invoke-V3Churn -Paths @($r) -LogBase 'V3-N4' } finally { $v3s.Before = $null }
    if ($c.Exhausted) { return (Resolve-Exhausted $c) }
    $row = Assert-V3Stopped $c 'REFUSED' 'PLAN_DIFFERS_FROM_VALIDATED_MEASUREMENT' $null
    Assert ($row.Attempted -eq $false -and [long]$row.FilesDeleted -eq 0 -and (Test-Path -LiteralPath $v3New) -and (Test-Path -LiteralPath (Join-Path $r 'sub\z.txt'))) "Attempted=$($row.Attempted) FilesDeleted=$($row.FilesDeleted); arvore intacta"
    $inv = Assert-V3Only $before @((Get-V3Rel $r)) 'V3-N4'
    "a file added between the revalidation and the deleter: PLAN_DIFFERS_FROM_VALIDATED_MEASUREMENT, REFUSED, nothing attempted, tree intact; STOPPED_AFTER_REFUSED, 1 intent$(Get-V3Attempts $c); $inv"
}
Case 'V3-N5-new-file-in-pinned-folder' {
    # NOVO-MED. Accepted: the file created and the run stops (DELETE_DIR_FAILED at sub, PARTIAL) with it intact; or the
    # creation refused by the pin and COMPLETE. Never: the new file deleted.
    $nt = & $v3NeedExec; if ($nt) { return $nt }
    $r = $v3.Roots['N5'].Path
    $before = Get-V3Snap
    $v3New = @{ Path = (Join-Path $r 'sub\new-in-deleter.txt'); Status = $null }
    $v3s.During = [Action[string]]({ param($root) try { [IO.File]::WriteAllText($v3New.Path, "new inside the deleter`n"); $v3New.Status = 'CREATED' } catch { $v3New.Status = 'REFUSED_' + $_.Exception.GetType().Name } }.GetNewClosure())
    try { $c = Invoke-V3Churn -Paths @($r) -LogBase 'V3-N5' } finally { $v3s.During = $null }
    if ($c.Exhausted) { return (Resolve-Exhausted $c) }
    $row = @($c.Res.Deleted)
    Assert ($row.Count -eq 1 -and $null -ne $v3New.Status) "desfechos $($row.Count); criacao $($v3New.Status)"
    if ($v3New.Status -ceq 'CREATED') {
        $null = Assert-V3Stopped $c 'PARTIAL' 'DELETE_DIR_FAILED' (Join-Path $r 'sub')
        Assert (Test-Path -LiteralPath $v3New.Path) 'arquivo criado depois da fixacao foi apagado'
        $m = "the file was created; PARTIAL, DELETE_DIR_FAILED at sub, the new file intact"
    } else {
        Assert ($row[0].Outcome -ceq 'COMPLETE' -and $row[0].Verified -eq $true) "criacao recusada e desfecho $($row[0].Outcome)"
        $m = "creation refused ($($v3New.Status)); COMPLETE"
    }
    $inv = Assert-V3Only $before @((Get-V3Rel $r)) 'V3-N5'
    "MEASURED: a file created in a pinned folder inside the deleter: $m$(Get-V3Attempts $c); $inv"
}
Case 'V3-N6-planned-file-changed-in-deleter' {
    $nt = & $v3NeedExec; if ($nt) { return $nt }
    $r = $v3.Roots['N6'].Path
    $z = Join-Path $r 'sub\z.txt'
    $top = @(Get-ChildItem -LiteralPath $r -File -Force).Count
    $before = Get-V3Snap
    $v3Chg = @{ Err = $null }
    $v3s.During = [Action[string]]({ param($root) try { [IO.File]::SetLastWriteTimeUtc($z, [datetime]::UtcNow.AddMinutes(-1)) } catch { $v3Chg.Err = $_.Exception.GetType().Name } }.GetNewClosure())
    try { $c = Invoke-V3Churn -Paths @($r) -LogBase 'V3-N6' } finally { $v3s.During = $null }
    if ($c.Exhausted) { return (Resolve-Exhausted $c) }
    Assert ($null -eq $v3Chg.Err) "ataque nao aplicado: $($v3Chg.Err)"
    $row = Assert-V3Stopped $c 'PARTIAL' 'FILE_CHANGED_AFTER_PLANNING' $z
    Assert ([long]$row.FilesDeleted -eq $top -and (Test-Path -LiteralPath $z)) "FilesDeleted=$($row.FilesDeleted) (esperado $top); arquivo alterado preservado"
    $inv = Assert-V3Only $before @((Get-V3Rel $r)) 'V3-N6'
    "a planned file changed inside the deleter, after pinning: FILE_CHANGED_AFTER_PLANNING at sub\z.txt, PARTIAL ($($row.FilesDeleted) files deleted before), the changed file intact$(Get-V3Attempts $c); $inv"
}
Case 'V3-N7-write-keeping-statistics' {
    NotTested 'by design: a write that keeps every statistic (size, write time, count) does not change the fingerprint, the plan check nor the deleter''s checks; a declared limit (no content hash), never provoked here'
}
Case 'V3-N8-hard-link-to-outside' {
    $nt = & $v3NeedExec; if ($nt) { return $nt }
    if ($v3.HardLink -cne 'OK') { return (NotTested "the hard link could not be created ($($v3.HardLink))") }
    $r = $v3.Roots['N8'].Path
    $keep = Join-Path $v3.Sentinels['N8'] 'keep.txt'
    $keepSha = Get-FileSha $keep
    $before = Get-V3Snap
    $c = Invoke-V3Churn -Paths @($r) -LogBase 'V3-N8'
    if ($c.Exhausted) { return (Resolve-Exhausted $c) }
    Assert (-not $c.Res.Aborted -and -not $c.Res.StoppedBy -and @($c.Res.Deleted).Count -eq 1 -and $c.Res.Deleted[0].Outcome -ceq 'COMPLETE' -and $c.Res.Deleted[0].Verified -eq $true) "resultado: $($c.Res.Aborted) $($c.Res.StoppedBy) $(@($c.Res.Deleted | ForEach-Object { $_.Outcome }) -join ',')"
    Assert ((Test-Path -LiteralPath $keep) -and (Get-FileSha $keep) -ceq $keepSha) 'sentinela ligada por hard link alterada ou apagada'
    $types = Get-V3LogTypes $c.Log
    Assert ($types -ceq 'run-start,plan,declaration,confirmation,plan-check,intent,result,run-end' -and $c.Calls -eq 1) "registros: $types"
    $inv = Assert-V3Only $before @((Get-V3Rel $r)) 'V3-N8'
    "a hard link inside the root to a sentinel outside it: COMPLETE, only the name inside the root removed, the sentinel intact (same SHA-256); the deleter does not check the link count (recorded); log $types$(Get-V3Attempts $c); $inv"
}

# ---- 4.3 third-party ACL after the plan (fixture ACE, J4)
Case 'V3-A1-third-party-acl-after-preview' {
    $nt = & $v3NeedPlant; if ($nt) { return $nt }
    $r = $v3.Roots['A1'].Path
    $before = Get-V3Snap
    $acl = Grant-V3ThirdPartyWrite $r
    Assert ($acl -match 'ESCRITA_CONCEDIDA_A_TERCEIROS') "ACE nao reconhecida pelo produto: $acl"
    $c = Invoke-V3Clean -Paths @($r) -LogName 'V3-A1.jsonl'
    # The ACL gate runs before B1 in the V0.1 gate (not cut short as the lock probe is): visible in both legs.
    $codes = Assert-V3PlanRefused $c 'ESCRITA_CONCEDIDA_A_TERCEIROS'
    $inv = Assert-V3Only $before @() 'V3-A1'
    "write granted to a third party on the root before clean: NENHUM_CAMINHO_ELEGIVEL with $codes (both legs: the ACL gate is evaluated before B1); no log, 0 intents; $inv"
}
Case 'V3-A2-third-party-acl-before-final-confirmation' {
    $nt = & $v3NeedExec; if ($nt) { return $nt }
    $r = $v3.Roots['A2'].Path
    $before = Get-V3Snap
    $v3Acl = @{ Codes = $null; Root = $r }
    $v3Inner = (New-Operator).Reader
    $op = @{ Reader = { param($phrase, $kind, $rootPath, $choices, $info) if ($kind -ceq 'confirm' -and $null -eq $v3Acl.Codes) { $v3s.Attacked = $true; $v3Acl.Codes = Grant-V3ThirdPartyWrite $v3Acl.Root }; & $v3Inner $phrase $kind $rootPath $choices $info } }
    $c = Invoke-V3Churn -Paths @($r) -LogBase 'V3-A2' -Operator $op
    if ($c.Exhausted) { return (Resolve-Exhausted $c) }
    Assert ($v3Acl.Codes -match 'ESCRITA_CONCEDIDA_A_TERCEIROS') "ACE nao aplicada antes da confirmacao: $($v3Acl.Codes)"
    Assert ($c.Res.Aborted -ceq 'PLAN_CHANGED_BEFORE_EXECUTION' -and $c.Calls -eq 0 -and @($c.Res.Deleted).Count -eq 0) "Aborted=$($c.Res.Aborted) chamadas $($c.Calls)"
    $recs = Read-E2ELog $c.Log; $types = Get-Types $recs
    $pc = @($recs | Where-Object { $_.type -ceq 'plan-check' })
    Assert ($types -ceq 'run-start,plan,declaration,confirmation,plan-check,run-end' -and $pc[0].matched -eq $false) "registros: $types"
    $inv = Assert-V3Only $before @() 'V3-A2'
    "write granted to a third party between the plan and the final confirmation (statistics unchanged): PLAN_CHANGED_BEFORE_EXECUTION by the gate, 0 intents; log $types; $inv"
}
Case 'V3-A3-third-party-acl-before-revalidation' {
    $nt = & $v3NeedExec; if ($nt) { return $nt }
    $r = $v3.Roots['A3'].Path
    $before = Get-V3Snap
    $v3Acl = @{ Codes = $null }
    $hook = { param($part) if ($null -eq $v3Acl.Codes) { $v3s.Attacked = $true; $v3Acl.Codes = Grant-V3ThirdPartyWrite $part.Path } }
    $c = Invoke-V3Churn -Paths @($r) -LogBase 'V3-A3' -Hook $hook
    if ($c.Exhausted) { return (Resolve-Exhausted $c) }
    Assert ($c.Res.Aborted -ceq 'REVALIDATION_REFUSED' -and @($c.Res.Skipped).Count -eq 1 -and $c.Calls -eq 0) "Aborted=$($c.Res.Aborted) chamadas $($c.Calls)"
    $codes = Get-Codes $c.Res.Skipped[0].Reasons
    Assert ($codes -match 'ESCRITA_CONCEDIDA_A_TERCEIROS' -and ($Leg -ne 'A' -or $codes -match 'B1_EXCEPTION_NO_LONGER_APPLIES')) "motivos da revalidacao: $codes"
    $types = Get-V3LogTypes $c.Log
    Assert ($types -ceq 'run-start,plan,declaration,confirmation,plan-check,skip,run-end') "registros: $types"
    $inv = Assert-V3Only $before @() 'V3-A3'
    "write granted to a third party between the confirmation and the revalidation: REVALIDATION_REFUSED ($codes), 0 intents; log $types$(Get-V3Attempts $c); $inv"
}
Case 'V3-A4-third-party-acl-in-deleter' {
    # Proof of a limit: the deleter does not read the ACL again once everything is pinned. Accepted: the ACE applied
    # and COMPLETE (the limit), or the ACE refused while pinned and COMPLETE.
    $nt = & $v3NeedExec; if ($nt) { return $nt }
    $r = $v3.Roots['A4'].Path
    $before = Get-V3Snap
    $v3Acl = @{ Status = $null }
    $v3s.During = [Action[string]]({
        param($root)
        try {
            $a = Get-Acl -LiteralPath $root
            $a.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')), 'Modify', 'None', 'None', 'Allow')))
            Set-Acl -LiteralPath $root -AclObject $a
            $v3Acl.Status = $(if (@((Get-Acl -LiteralPath $root).GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference.Value -ceq 'S-1-5-32-545' }).Count -gt 0) { 'APPLIED' } else { 'NOT_PRESENT' })
        } catch { $v3Acl.Status = 'REFUSED_' + $_.Exception.GetType().Name }
    }.GetNewClosure())
    try { $c = Invoke-V3Churn -Paths @($r) -LogBase 'V3-A4' } finally { $v3s.During = $null }
    if ($c.Exhausted) { return (Resolve-Exhausted $c) }
    Assert ($null -ne $v3Acl.Status) 'ataque nao executado'
    Assert (-not $c.Res.Aborted -and -not $c.Res.StoppedBy -and @($c.Res.Deleted).Count -eq 1 -and $c.Res.Deleted[0].Outcome -ceq 'COMPLETE' -and $c.Res.Deleted[0].Verified -eq $true) "resultado: $($c.Res.Aborted) $($c.Res.StoppedBy) $(@($c.Res.Deleted | ForEach-Object { $_.Outcome }) -join ',')"
    $inv = Assert-V3Only $before @((Get-V3Rel $r)) 'V3-A4'
    "MEASURED: write granted to a third party inside the deleter, after pinning: ACE $($v3Acl.Status); COMPLETE (the deleter does not read the ACL again once pinned: a declared limit)$(Get-V3Attempts $c); $inv"
}

# ---- 4.4 processes after the plan
Case 'V3-P1-referencing-process-before-revalidation' {
    $nt = & $v3NeedExec; if ($nt) { return $nt }
    $r = $v3.Roots['P1'].Path
    $before = Get-V3Snap
    # A process of this account (inspectable) whose command line names the root; it ends by itself.
    # The path is the last word of the command line (a comment for the shell), so the reference resolves to the root.
    $v3Proc = @{ Started = $false; Exe = $shellExe; Arg = ("-NoProfile -NonInteractive -Command `"Start-Sleep -Seconds 25 # " + $r + "`"") }
    $hook = {
        param($part)
        if (-not $v3Proc.Started) {
            $v3s.Attacked = $true
            $psi = New-Object Diagnostics.ProcessStartInfo($v3Proc.Exe, $v3Proc.Arg)
            $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
            $null = [Diagnostics.Process]::Start($psi); $v3Proc.Started = $true
            Start-Sleep -Milliseconds 1500
        }
    }
    $c = Invoke-V3Churn -Paths @($r) -LogBase 'V3-P1' -Hook $hook
    if ($c.Exhausted) { return (Resolve-Exhausted $c) }
    Assert ($c.Res.Aborted -ceq 'REVALIDATION_REFUSED' -and @($c.Res.Skipped).Count -eq 1 -and $c.Calls -eq 0) "Aborted=$($c.Res.Aborted) chamadas $($c.Calls)"
    $raw = (@($c.Res.Skipped[0].Reasons) -join ' ')
    Assert ($raw -match 'ACTIVE_EVIDENCE|RUNTIME_USE_OBSERVED') "motivos da revalidacao: $(Get-Codes $c.Res.Skipped[0].Reasons)"
    Assert ($Leg -ne 'A' -or $raw -match 'B1_EXCEPTION_NO_LONGER_APPLIES') "perna A sem B1_EXCEPTION_NO_LONGER_APPLIES: $(Get-Codes $c.Res.Skipped[0].Reasons)"
    $types = Get-V3LogTypes $c.Log
    Assert ($types -ceq 'run-start,plan,declaration,confirmation,plan-check,skip,run-end') "registros: $types"
    $inv = Assert-V3Only $before @() 'V3-P1'
    $ev = @([regex]::Matches($raw, 'ACTIVE_EVIDENCE|RUNTIME_USE_OBSERVED') | ForEach-Object { $_.Value } | Sort-Object -Unique) -join ','
    "a process of this account naming the root started between the confirmation and the revalidation: REVALIDATION_REFUSED ($ev$(if ($Leg -eq 'A') { ', B1_EXCEPTION_NO_LONGER_APPLIES' })), 0 intents; the process ends by itself; log $types; $inv"
}
Case 'V3-P2-other-account-process-before-revalidation' {
    $nt = & $v3NeedExec; if ($nt) { return $nt }
    $nt = & $v3NeedSignal; if ($nt) { return $nt }
    $r = $v3.Roots['P2'].Path
    $before = Get-V3Snap
    $v3Sig = @{ Ack = $null; Asked = $false }
    $hook = { param($part) if (-not $v3Sig.Asked) { $v3Sig.Asked = $true; $v3s.Attacked = $true; $v3Sig.Ack = Request-V3OtherAccountProcess 'P2' } }
    $c = Invoke-V3Churn -Paths @($r) -LogBase 'V3-P2' -Hook $hook
    if ($c.Exhausted) { return (Resolve-Exhausted $c) }
    if ($v3Sig.Ack -cne 'STARTED') { return (NotTested "the e2e did not confirm a process of another account ($($v3Sig.Ack)); outcome $($c.Res.Aborted)") }
    Assert ($c.Res.Aborted -ceq 'REVALIDATION_REFUSED' -and @($c.Res.Skipped).Count -eq 1 -and $c.Calls -eq 0) "Aborted=$($c.Res.Aborted) chamadas $($c.Calls)"
    $codes = Get-Codes $c.Res.Skipped[0].Reasons
    Assert ($codes -match 'B1_EXCEPTION_NEW_UNINSPECTABLE_PROCESS') "motivos da revalidacao: $codes"
    $types = Get-V3LogTypes $c.Log
    Assert ($types -ceq 'run-start,plan,declaration,confirmation,plan-check,skip,run-end') "registros: $types"
    $inv = Assert-V3Only $before @() 'V3-P2'
    "a process of another account (not inspectable here) started between the confirmation and the revalidation: REVALIDATION_REFUSED ($codes), 0 intents; it ends by itself; log $types; $inv"
}
Case 'V3-P3-other-account-process-before-final-confirmation' {
    $nt = & $v3NeedExec; if ($nt) { return $nt }
    $nt = & $v3NeedSignal; if ($nt) { return $nt }
    $r = $v3.Roots['P3'].Path
    $before = Get-V3Snap
    $v3Sig = @{ Ack = $null; Asked = $false }
    $v3Inner = (New-Operator).Reader
    $op = @{ Reader = { param($phrase, $kind, $rootPath, $choices, $info) if ($kind -ceq 'confirm' -and -not $v3Sig.Asked) { $v3Sig.Asked = $true; $v3s.Attacked = $true; $v3Sig.Ack = Request-V3OtherAccountProcess 'P3' }; & $v3Inner $phrase $kind $rootPath $choices $info } }
    $c = Invoke-V3Churn -Paths @($r) -LogBase 'V3-P3' -Operator $op
    if ($c.Exhausted) { return (Resolve-Exhausted $c) }
    if ($v3Sig.Ack -cne 'STARTED') { return (NotTested "the e2e did not confirm a process of another account ($($v3Sig.Ack)); outcome $($c.Res.Aborted)") }
    Assert ($c.Res.Aborted -ceq 'PLAN_CHANGED_BEFORE_EXECUTION' -and $c.Calls -eq 0 -and @($c.Res.Deleted).Count -eq 0) "Aborted=$($c.Res.Aborted) chamadas $($c.Calls)"
    $recs = Read-E2ELog $c.Log; $types = Get-Types $recs
    Assert ($types -ceq 'run-start,plan,declaration,confirmation,plan-check,run-end' -and @($recs | Where-Object { $_.type -ceq 'plan-check' })[0].matched -eq $false) "registros: $types"
    $inv = Assert-V3Only $before @() 'V3-P3'
    "a process of another account started between the plan and the final confirmation: PLAN_CHANGED_BEFORE_EXECUTION (a new identity not inspectable), 0 intents; it ends by itself; log $types; $inv"
}

# ---------------------------------------------------------------------------------------------- V3c
# V0.3 V3, phase V3c (contract sections 4.5 and 4.6): outcomes of the real deleter, the log, a process that ends inside
# a run, concurrency and shared bases. A child is this script started again in child mode (same account, real lock
# name): it ends by itself (Environment.Exit) and is never terminated; the parent waits for it with a deadline.
function Invoke-V3ChildRun([string]$Mode, [string]$Root, [string]$LogName) {
    $out = Join-Path $WorkDir "child-$LogName.txt"
    $log = Join-Path $ctx.LogDir $LogName
    $argLine = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Leg {1} -InstallDir "{2}" -SummaryFile "{3}" -WorkDir "{4}" -DisposableMachine -ChildMode {5} -ChildRoot "{6}" -ChildLog "{7}" -ChildOut "{8}"' -f $PSCommandPath, $Leg, $InstallDir, (Join-Path $WorkDir "child-summary-$LogName.json"), $WorkDir, $Mode, $Root, $log, $out
    $psi = New-Object Diagnostics.ProcessStartInfo($shellExe, $argLine)
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $p = [Diagnostics.Process]::Start($psi)
    if (-not $p.WaitForExit(600000)) { throw 'processo filho nao terminou em 10 min (nunca encerrado a forca)' }
    return [pscustomobject]@{ Exit = $p.ExitCode; Out = $(if (Test-Path -LiteralPath $out) { [IO.File]::ReadAllText($out) } else { $null }); Log = $log }
}
function Invoke-V3ChildExit([string]$Mode, [string]$Label, [int]$ExpectedExit) {
    # Up to 3 children: a child that did not exit was refused before the deleter by process churn of the runner (it
    # ran to the end and released the lock); any other outcome fails.
    $r = $v3.Roots[$Label].Path
    Assert-V3Entry $r
    $tries = New-Object System.Collections.Generic.List[string]
    for ($n = 1; $n -le 3; $n++) {
        $k = Invoke-V3ChildRun $Mode $r "V3-$Label-$n.jsonl"
        if ($k.Exit -eq $ExpectedExit) { return [pscustomobject]@{ Exited = $true; Run = $k; Tries = $tries.ToArray() } }
        Assert ($k.Exit -eq 0 -and $k.Out -and ($k.Out -cmatch '^NOT_EXITED\|(PLAN_CHANGED_BEFORE_EXECUTION|REVALIDATION_REFUSED)\|')) "filho saiu com $($k.Exit): $($k.Out)"
        $tries.Add(($k.Out -split '\|')[1])
    }
    return [pscustomobject]@{ Exited = $false; Run = $null; Tries = $tries.ToArray() }
}

# ---- 4.5 outcomes of the real deleter
Case 'V3-O1-partial-with-real-deleter' {
    # PARTIAL with the real deleter is produced by U4, U5, N6 and R12 in this run (each asserts it); this case collects them.
    $ids = @('V3-U4-held-no-share-delete-in-deleter', 'V3-U5-held-share-delete-in-deleter', 'V3-N6-planned-file-changed-in-deleter', 'V3-R12-junction-in-place-in-deleter')
    $st = @($ids | ForEach-Object { if ($summary.cases.Contains($_)) { [string]$summary.cases[$_].status } else { 'MISSING' } })
    $passed = @($st | Where-Object { $_ -ceq 'PASS' }).Count
    Assert (@($st | Where-Object { $_ -ceq 'FAIL' -or $_ -ceq 'MISSING' }).Count -eq 0) "casos de PARTIAL: $($st -join ',')"
    if ($passed -eq 0) { return (NotTested "no PARTIAL case reached the deleter in this leg ($($st -join ','))") }
    "PARTIAL with the real deleter, STOPPED_AFTER_PARTIAL, proved by $passed of U4, U5, N6, R12 in this run ($($st -join ',')); the stop before a next root needs two ELIGIBLE roots (leg B), not reached while its coverage is incomplete"
}
Case 'V3-O2-verification-failed-with-real-deleter' {
    $nt = & $v3NeedExec; if ($nt) { return $nt }
    $r = $v3.Roots['O2'].Path
    $before = Get-V3Snap
    # Declared provocation of the harness: the real deletion completes, then the root folder is created again before the
    # engine checks the absence.
    $v3s.After = { param($c, $res) [void][IO.Directory]::CreateDirectory($c.Path) }
    try { $c = Invoke-V3Churn -Paths @($r) -LogBase 'V3-O2' } finally { $v3s.After = $null }
    if ($c.Exhausted) { return (Resolve-Exhausted $c) }
    $row = Assert-V3Stopped $c 'VERIFICATION_FAILED' $null $null
    Assert ($row.Completed -eq $true -and $row.Verified -eq $false -and $row.VerifiedState -ceq 'PRESENT') "Completed=$($row.Completed) Verified=$($row.Verified) Estado=$($row.VerifiedState)"
    Assert ((@(Read-E2ELog $c.Log | Where-Object { $_.type -ceq 'result' })[0].verifiedGone) -eq $false) 'verifiedGone no log diferente de false'
    $inv = Assert-V3Only $before @((Get-V3Rel $r)) 'V3-O2'
    "the real deleter completed and the root folder was created again before the check (declared provocation): VERIFICATION_FAILED (PRESENT), STOPPED_AFTER_VERIFICATION_FAILED, result verifiedGone=false$(Get-V3Attempts $c); $inv"
}
Case 'V3-O3-exception-after-real-deleter' {
    $nt = & $v3NeedExec; if ($nt) { return $nt }
    $r = $v3.Roots['O3'].Path
    $before = Get-V3Snap
    # Declared: tests the engine's handling of an exception from the deleter call (the real deletion has run).
    $v3s.After = { param($c, $res) throw [IO.IOException]::new('V3 O3: declared exception after the real deletion') }
    try { $c = Invoke-V3Churn -Paths @($r) -LogBase 'V3-O3' } finally { $v3s.After = $null }
    if ($c.Exhausted) { return (Resolve-Exhausted $c) }
    $row = Assert-V3Stopped $c 'EXCEPTION' $null $null
    Assert ($row.ExceptionType -ceq 'IOException' -and $null -eq $row.Attempted -and $null -eq $row.FilesDeleted -and $row.VerifiedState -ceq 'UNKNOWN') "excecao: tipo $($row.ExceptionType), estado $($row.VerifiedState)"
    $res = @(Read-E2ELog $c.Log | Where-Object { $_.type -ceq 'result' })[0]
    Assert ([string]$res.verifiedGone -ceq 'UNKNOWN' -and $res.exceptionType -ceq 'IOException') 'log sem UNKNOWN/IOException'
    $inv = Assert-V3Only $before @((Get-V3Rel $r)) 'V3-O3'
    "an exception from the deleter call after the real deletion (declared): EXCEPTION, outcome unknown (verifiedGone UNKNOWN, IOException recorded, counts not presumed), STOPPED_AFTER_EXCEPTION$(Get-V3Attempts $c); $inv"
}
Case 'V3-O4-internal-exception-of-the-deleter' {
    NotTested 'no deterministic trigger: the deleter turns its failures into AbortReason codes (it does not throw); the engine path for an exception is O3 and the suite'
}

# ---- 4.5 log
Case 'V3-L1-log-write-failure-mid-run' {
    NotTested 'J3: no size-limited volume on the runner; changing the log ACL mid-run does not fail an open handle; the engine path is covered by the suite with a stand-in writer (each stage)'
}
Case 'V3-L2-log-folder-pinned-during-run' {
    $nt = & $v3NeedExec; if ($nt) { return $nt }
    $r = $v3.Roots['L2'].Path
    $before = Get-V3Snap
    $v3Ren = @{ Status = $null }
    $hook = { param($part) if ($null -eq $v3Ren.Status) { $v3s.Attacked = $true; try { [IO.Directory]::Move($ctx.LogDir, $ctx.LogDir + '-v3moved'); $v3Ren.Status = 'MOVED' } catch { $v3Ren.Status = 'REFUSED' } } }
    $c = Invoke-V3Churn -Paths @($r) -LogBase 'V3-L2' -Hook $hook
    if ($c.Exhausted) { return (Resolve-Exhausted $c) }
    Assert ($v3Ren.Status -ceq 'REFUSED') "pasta do log durante a execucao: $($v3Ren.Status)"
    Assert (-not $c.Res.Aborted -and -not $c.Res.StoppedBy -and @($c.Res.Deleted).Count -eq 1 -and $c.Res.Deleted[0].Outcome -ceq 'COMPLETE') "resultado: $($c.Res.Aborted) $($c.Res.StoppedBy)"
    $types = Get-V3LogTypes $c.Log
    Assert ($types -ceq 'run-start,plan,declaration,confirmation,plan-check,intent,result,run-end') "registros: $types"
    $inv = Assert-V3Only $before @((Get-V3Rel $r)) 'V3-L2'
    "renaming the log folder during the run refused (pinned while the log is open); the log is complete and in place ($types); COMPLETE$(Get-V3Attempts $c); $inv"
}

# ---- 4.5 a process that ends inside a run, and the abandoned lock (real name, disposable machine only)
Case 'V3-K1-exit-after-intent' {
    $nt = & $v3NeedExec; if ($nt) { return $nt }
    $r = $v3.Roots['K1'].Path
    $before = Get-V3Snap
    $k = Invoke-V3ChildExit 'K1' 'K1' 7
    if (-not $k.Exited) { return (NotTested "the child was refused before the deleter in all 3 attempts (process churn): $($k.Tries -join ', ')") }
    $v3.K1Exited = $true
    $types = Get-V3LogTypes $k.Run.Log
    Assert ($types -ceq 'run-start,plan,declaration,confirmation,plan-check,intent') "o log deve terminar no intent: $types"
    Assert ((Test-Path -LiteralPath (Join-Path $r 'a.txt')) -and (Test-Path -LiteralPath (Join-Path $r 'sub\z.txt'))) 'raiz alterada: a saida foi antes da primeira exclusao'
    $inv = Assert-V3Only $before @() 'V3-K1-'
    "a child (real lock) ended by itself inside the real deleter, after pinning (exit 7, never terminated): the log ends at the intent (no result, no run-end: outcome unknown), the root intact$(if ($k.Tries.Count) { '; earlier attempts: ' + ($k.Tries -join ', ') }); $inv"
}
Case 'V3-K2-abandoned-lock-after-exit' {
    if (-not $v3.K1Exited) { return (NotTested 'K1 did not leave the lock abandoned') }
    $r = $v3.Roots['K1'].Path
    $before = Get-V3Snap
    $c = Invoke-V3Clean -Paths @($r) -LogName 'V3-K2-abandoned.jsonl'
    Assert ($c.Res.Aborted -ceq 'CLEAN_LOCK_ABANDONED' -and -not $c.Res.LogCreated -and -not (Test-Path -LiteralPath $c.Log) -and $c.Calls -eq 0 -and @($c.Res.Verified).Count -eq 0) "Aborted=$($c.Res.Aborted) log=$($c.Res.LogCreated) chamadas=$($c.Calls)"
    $n = Invoke-V3Churn -Paths @($r) -LogBase 'V3-K2-next'
    if ($n.Exhausted) { return (Resolve-Exhausted $n) }
    Assert (-not $n.Res.Aborted -and -not $n.Res.StoppedBy -and @($n.Res.Deleted).Count -eq 1 -and $n.Res.Deleted[0].Outcome -ceq 'COMPLETE' -and $n.Res.Deleted[0].Verified -eq $true) "execucao seguinte: $($n.Res.Aborted) $($n.Res.StoppedBy)"
    $inv = Assert-V3Only $before @((Get-V3Rel $r)) 'V3-K2-'
    "the next clean after the exit: CLEAN_LOCK_ABANDONED (no inventory, no log, no deleter; ownership released); the following one acquired the lock, planned the root again and deleted it (COMPLETE)$(Get-V3Attempts $n); $inv"
}
Case 'V3-K3-exit-after-real-deletion' {
    $nt = & $v3NeedExec; if ($nt) { return $nt }
    $r = $v3.Roots['K3'].Path
    $before = Get-V3Snap
    $k = Invoke-V3ChildExit 'K3' 'K3' 8
    if (-not $k.Exited) { return (NotTested "the child was refused before the deleter in all 3 attempts (process churn): $($k.Tries -join ', ')") }
    $types = Get-V3LogTypes $k.Run.Log
    Assert ($types -ceq 'run-start,plan,declaration,confirmation,plan-check,intent' -and -not (Test-Path -LiteralPath $r)) "log $types; raiz presente: $(Test-Path -LiteralPath $r)"
    $c = Invoke-V3Clean -Paths @($r) -LogName 'V3-K3-abandoned.jsonl' -Gone
    Assert ($c.Res.Aborted -ceq 'CLEAN_LOCK_ABANDONED' -and -not (Test-Path -LiteralPath $c.Log)) "depois da saida: $($c.Res.Aborted)"
    $c2 = Invoke-V3Clean -Paths @($r) -LogName 'V3-K3-after.jsonl' -Gone
    $codes = Assert-V3PlanRefused $c2 'FORA_DAS_ROOTS_PERMITIDAS'
    $inv = Assert-V3Only $before @((Get-V3Rel $r)) 'V3-K3-'
    "a child ended by itself right after the real deletion, before the result (exit 8): the log ends at the intent and the root is gone (the outcome is known only by looking); next clean CLEAN_LOCK_ABANDONED, then the entry no longer exists: NENHUM_CAMINHO_ELEGIVEL ($codes); $inv"
}
Case 'V3-K4-exit-mid-tree' {
    NotTested 'J2: no per-file hook in the native deletion loop and no forced termination; an exit after the intent (K1) and after the deletion (K3) are proved'
}

# ---- 4.6 concurrency and shared bases
Case 'V3-X1-second-clean-while-first-holds-lock' {
    $nt = & $v3NeedExec; if ($nt) { return $nt }
    $r = $v3.Roots['X1'].Path
    $before = Get-V3Snap
    $v3X = @{ Child = $null; Root = $r }
    $v3Inner = (New-Operator).Reader
    # The first clean (this process) holds the lock through its questions; at the final phrase a second, complete clean
    # of the same root runs in a child process and must be refused at once.
    $op = @{ Reader = { param($phrase, $kind, $rootPath, $choices, $info) if ($kind -ceq 'confirm' -and $null -eq $v3X.Child) { $v3s.Attacked = $true; $v3X.Child = Invoke-V3ChildRun 'X1' $v3X.Root 'V3-X1-child.jsonl' }; & $v3Inner $phrase $kind $rootPath $choices $info } }
    $c = Invoke-V3Churn -Paths @($r) -LogBase 'V3-X1' -Operator $op
    if ($c.Exhausted) { return (Resolve-Exhausted $c) }
    Assert ($null -ne $v3X.Child) 'a segunda execucao nao foi iniciada'
    $k = $v3X.Child
    Assert ($k.Exit -eq 0 -and $k.Out -ceq 'NOT_EXITED|CLEAN_LOCK_BUSY||0|False' -and -not (Test-Path -LiteralPath $k.Log)) "segunda execucao: exit $($k.Exit), $($k.Out)"
    if (@('PLAN_CHANGED_BEFORE_EXECUTION', 'REVALIDATION_REFUSED') -ccontains [string]$c.Res.Aborted) { return (NotTested "the second clean was refused CLEAN_LOCK_BUSY (no presenter, no log), but the first one was then refused by process churn of the runner ($($c.Res.Aborted)), nothing deleted") }
    Assert (-not $c.Res.Aborted -and -not $c.Res.StoppedBy -and @($c.Res.Deleted).Count -eq 1 -and $c.Res.Deleted[0].Outcome -ceq 'COMPLETE') "primeira execucao: $($c.Res.Aborted) $($c.Res.StoppedBy)"
    $inv = Assert-V3Only $before @((Get-V3Rel $r)) 'V3-X1'
    "a second complete clean of the same root (another process, same account) while the first held the lock: CLEAN_LOCK_BUSY at once (presenter never called, no log, no deleter); the first went on and deleted the root once (COMPLETE); $inv"
}
Case 'V3-X3-other-object-with-the-lock-name' {
    $nt = & $v3NeedPlant; if ($nt) { return $nt }
    $r = $v3.Roots['X3'].Path
    $before = Get-V3Snap
    # Squatting with another type of object under the real name, on this disposable machine only.
    $ev = New-Object Threading.EventWaitHandle($false, [Threading.EventResetMode]::ManualReset, 'Global\AgentTempManager.Clean')
    try { $c = Invoke-V3Clean -Paths @($r) -LogName 'V3-X3.jsonl' } finally { $ev.Dispose() }
    Assert ($c.Res.Aborted -ceq 'CLEAN_LOCK_TYPE_MISMATCH' -and -not (Test-Path -LiteralPath $c.Log) -and $c.Calls -eq 0 -and @($c.Res.Verified).Count -eq 0) "Aborted=$($c.Res.Aborted)"
    $inv = Assert-V3Only $before @() 'V3-X3'
    "an event created under the real lock name: CLEAN_LOCK_TYPE_MISMATCH before any inventory, no log, no deleter (both legs); $inv"
}
function Set-V3TmpDir([string]$Value) {
    # The variable as V2 sets it (this account's user environment and this process); restored by the caller.
    $k = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
    try { $k.SetValue('CLAUDE_CODE_TMPDIR', $Value, [Microsoft.Win32.RegistryValueKind]::String) } finally { $k.Close() }
    [Environment]::SetEnvironmentVariable('CLAUDE_CODE_TMPDIR', $Value, 'Process')
}
Case 'V3-S1-base-under-windows-temp' {
    $nt = & $v3NeedPlant; if ($nt) { return $nt }
    if (-not $v3.S1Root) { return (NotTested "the base under the Windows temp folder could not be created by this account ($($v3.S1Error))") }
    $before = Get-V3Snap
    Set-V3TmpDir $v3.S1Run
    try {
        $inv = Invoke-AtmInventory @ia
        $b = @($inv.Bases | Where-Object { [string]::Equals($_.Path, (Join-Path $v3.S1Run 'claude'), [StringComparison]::OrdinalIgnoreCase) })
        Assert ($b.Count -eq 1 -and [bool]$b[0].Shared) "base sob o Temp do Windows: encontrada $($b.Count), compartilhada $(if ($b.Count) { $b[0].Shared })"
        $c = Invoke-V3Clean -Paths @($v3.S1Root) -LogName 'V3-S1.jsonl'
    } finally { Set-V3TmpDir $ctx.Tmp }
    $codes = Assert-V3PlanRefused $c 'SHARED_TEMP'
    Assert (Test-Path -LiteralPath (Join-Path $v3.S1Root 'sub\z.txt')) 'raiz sob o Temp do Windows alterada'
    $inv2 = Assert-V3Only $before @() 'V3-S1'
    "a base under the Windows temp folder (writable by every account), found through the user environment: marked shared, NENHUM_CAMINHO_ELEGIVEL with $codes (both legs); no log, 0 intents, the root intact; the variable restored; $inv2"
}
Case 'V3-S2-base-shared-by-two-profiles' {
    # NOVO-MED (leg B, elevated: reads the other accounts' environment): the disposable test account's environment pointed at
    # this account's base. Only when that account's hive is loaded and its environment readable; otherwise measured as
    # NOT_TESTED. The value is set only if absent and taken out again.
    $nt = & $v3NeedPlant; if ($nt) { return $nt }
    if ($Leg -ne 'B') { return (NotTested 'leg B only: a standard user does not read the environment of other accounts') }
    $inv = Invoke-AtmInventory @ia
    $other = @($inv.Profiles | Where-Object { [string]$_.Sid -cne $mySid -and [string]$_.Sid -like 'S-1-5-21-*' -and (Split-Path -Leaf ([string]$_.ProfilePath)) -like 'atme2e*' })
    if ($other.Count -ne 1) { return (NotTested "the disposable test account was not found among the profiles ($($other.Count))") }
    $o = $other[0]
    if (-not $o.Loaded -or [string]$o.EnvStatus -cne 'OK') { return (NotTested "measured: the test account's registry hive is $(if ($o.Loaded) { 'loaded' } else { 'not loaded' }) and its environment $([string]$o.EnvStatus): its base cannot be read, so a shared base cannot be seen through it") }
    $k = [Microsoft.Win32.Registry]::Users.OpenSubKey(([string]$o.Sid + '\Environment'), $true)
    if ($null -eq $k) { return (NotTested 'the test account environment key cannot be opened for writing') }
    $set = $false
    try {
        if ($null -ne $k.GetValue('CLAUDE_CODE_TMPDIR', $null)) { return (NotTested 'the test account already has CLAUDE_CODE_TMPDIR; left unchanged') }
        $k.SetValue('CLAUDE_CODE_TMPDIR', $ctx.Tmp, [Microsoft.Win32.RegistryValueKind]::String); $set = $true
        $before = Get-V3Snap
        $c = Invoke-V3Clean -Paths @($v3.Roots['S2'].Path) -LogName 'V3-S2.jsonl'
    } finally { if ($set) { $k.DeleteValue('CLAUDE_CODE_TMPDIR') }; $k.Close() }
    $codes = Assert-V3PlanRefused $c 'SHARED_TEMP'
    $inv2 = Assert-V3Only $before @() 'V3-S2'
    "the same base claimed by the disposable test account's environment: SHARED_TEMP, NENHUM_CAMINHO_ELEGIVEL ($codes); the value taken out again; $inv2"
}

Case 'V3-snapshot' {
    # Over the whole V3a phase: only the V3 scopes and the V3 logs may differ; sentinels, link targets, the V2 roots,
    # the transcripts and the rest of the run root are unchanged.
    if ($null -eq $v3.SnapBefore) { return (NotTested 'no V3 snapshot before the runs') }
    $d = Compare-Snapshot $v3.SnapBefore (Get-V3Snap)
    $bad = @(@(@($d.Removed) + @($d.Added) + @($d.Changed)) | Where-Object { -not ($_.StartsWith('tmpdir\claude\' + $v3Slug, [StringComparison]::OrdinalIgnoreCase) -or $_.StartsWith('log\V3-', [StringComparison]::OrdinalIgnoreCase)) })
    Assert ($bad.Count -eq 0) "mudanca fora das areas da V3: $($bad.Count) [$((@($bad | Select-Object -First 3)) -join '; ')]"
    $sent = @(@($d.Removed) + @($d.Added) + @($d.Changed) | Where-Object { $_.StartsWith('v3-sentinel', [StringComparison]::OrdinalIgnoreCase) })
    Assert ($sent.Count -eq 0) 'sentinela alterada'
    "V3a phase: $($d.Removed.Count) removed, $($d.Added.Count) added, $($d.Changed.Count) changed, all inside the V3 scopes and logs; $($v3.Sentinels.Count) sentinels and every link target unchanged"
}

# ---------------------------------------------------------------------------------------------- after
Case 'P1-installed-after' {
    Assert ($loadedGate -eq $false) 'trava carregada da instalacao nao era $false'
    Assert (Test-InstalledGate) 'trava instalada alterada'
    $v = Invoke-InstalledVerify
    Assert ($v -eq 0) "agent-temp verify exit $v"
    $d = Compare-Snapshot $ctx.InstallBefore (Get-Snapshot $InstallDir ([long]::MaxValue))
    Assert ($d.Removed.Count -eq 0 -and $d.Added.Count -eq 0 -and $d.Changed.Count -eq 0) "instalacao alterada: $($d.Removed.Count) removidos, $($d.Added.Count) adicionados, $($d.Changed.Count) alterados"
    'installed files identical by SHA-256 to before the runs; verify 0; installed gate still $false (opened only in this process memory)'
}
# The variables set in the user environment are removed again (or restored) if they still hold the values set here.
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
$v3Cases = @($summary.cases.Keys | Where-Object { $_.StartsWith('V3-') } | ForEach-Object { $summary.cases[$_] })
$summary.v3 = [ordered]@{ phase = 'V3a+V3b+V3c'; passed = @($v3Cases | Where-Object { $_.status -eq 'PASS' }).Count; failed = @($v3Cases | Where-Object { $_.status -eq 'FAIL' }).Count; notTested = @($v3Cases | Where-Object { $_.status -eq 'NOT_TESTED' }).Count }
[IO.File]::WriteAllText($SummaryFile, ($summary | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
[Console]::Out.WriteLine(("V2-{0}: {1} PASS / {2} FAIL / {3} NOT_TESTED | {4} | elevated {5}" -f $Leg, $summary.passed, $failed, $summary.notTested, $summary.shell, $summary.elevated))
exit $failed
