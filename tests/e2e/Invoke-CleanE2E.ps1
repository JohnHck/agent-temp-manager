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
if ($summary.cases['identity'].status -ne 'PASS' -or $summary.cases['P1-installed-before'].status -ne 'PASS') {
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
[IO.File]::WriteAllText($SummaryFile, ($summary | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
[Console]::Out.WriteLine(("V2-{0}: {1} PASS / {2} FAIL / {3} NOT_TESTED | {4} | elevated {5}" -f $Leg, $summary.passed, $failed, $summary.notTested, $summary.shell, $summary.elevated))
exit $failed
