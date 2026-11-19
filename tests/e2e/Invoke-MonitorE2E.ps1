<#
.SYNOPSIS
  V0.5 M3b (ADR-0017 section 6, row M3): the REAL Task Scheduler for the collector's task, end to end, with a test task
  name, on a DISPOSABLE machine only (CI): register, read back, run once, remove, read back absent.
.DESCRIPTION
  CI-only harness, never shipped (tools\Build-Release.ps1 leaves it out of the release archive and refuses an archive
  that contains it; the install e2e checks that it is absent from the package). Two legs, run in this order by the
  install e2e, each against the INSTALLED copy:
    A (the install e2e's temporary standard user, launched with Start-Process -Credential; no new account mechanism):
      the token is a standard one; the engine registers the user's own task under this run's test name with the
      installed entry point and the default interval; the read-back is PRESENT (that user, interactive logon, limited run
      level, no password, the exact action, PT6H, a next run in the future); a second registration is refused
      (MONITOR_TASK_EXISTS); the task is run once and waited for (a short declared timeout): the expected last result is
      3 (the installed gate is closed) and no history folder is created; the test task is removed by this script, by its
      exact name; the read-back is ABSENT.
    B (the elevated runner account): monitor enable, with the gate open in this process memory, refuses with
      MONITOR_TASK_REQUIRES_STANDARD_TOKEN before any plan or phrase, and nothing is registered (ABSENT); then a test task
      of this account (optional proof of the exit code 3, run with the limited token of run level 0), removed the same
      way.
    Both legs: the installed CLI's monitor enable, as a process, exits 3 (MONITORING_GATE_CLOSED) and the product's task
      folder lists the same tasks before and after.
  Containment: each leg loads the INSTALLED engine into its own process and opens the monitoring gate there only, in
  memory (the nine installed gates and the SHA-256 of every installed file are checked before and after). The only seam
  set is the engine's test task name, MonitorTest-<8 random hex digits> of this run. Every touch of the scheduler goes
  through a wrapper of this script whose first statement is Assert-TestName (the exact form and this run's name). The
  product removes no task until M4: Remove-TestTask is this script's only removal, of the test name only. The product's
  task folder stays. The logon type, the account and the password are never changed or given: if the scheduler does not
  start the interactive task (no interactive session), the run is NOT_TESTED with the state and the code.
  Writes ONLY a summary (booleans, codes, counts, labels; no SID, account name, path or machine name) to -SummaryFile.
  Exit code = number of failed cases (NOT_TESTED is neither a pass nor a failure).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('A', 'B')][string]$Leg,
    [Parameter(Mandatory)][string]$InstallDir,
    [Parameter(Mandatory)][string]$SummaryFile,
    [switch]$DisposableMachine
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# Accident guard only (these variables can be set by anyone): the containment is the test name and the wrappers.
if (-not $DisposableMachine -and -not ($env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -eq 'github-hosted')) {
    throw 'Recusado: este teste registra, roda e remove uma tarefa agendada de verdade; so roda em maquina descartavel (runner do GitHub) ou com -DisposableMachine.'
}

$me = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($me)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
# This run's test task name: the exact form the engine accepts for its override.
$script:testName = 'MonitorTest-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
# The run once: polled every half second for at most this many seconds. The task's own trigger starts at least 61
# seconds after its registration, so a result read within this window comes from the run of this script.
$runWaitSeconds = 45
$summary = [ordered]@{
    schema = 'atm.e2e-monitor/1'; phase = 'V05-M3b'; leg = $Leg; startedUtc = [datetime]::UtcNow.ToString('o')
    shell = "$($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)"; arch = $env:PROCESSOR_ARCHITECTURE
    elevated = [bool]$isAdmin
    account = $(if ($Leg -eq 'A') { 'the install e2e temporary standard user (launched by the install e2e)' } else { 'the elevated runner account' })
    gate = 'opened in this process memory only, after the installed engine is loaded; the installed copy stays closed'
    seam = 'only the engine test task name (MonitorTest-<8 random hex digits> of this run)'
    runWaitSeconds = $runWaitSeconds
    token = [ordered]@{}; runOnce = [ordered]@{}; cli = [ordered]@{}; cleanup = $null
    cases = [ordered]@{}
}

function Protect-Text([string]$Text) {
    # Defense in depth before the artifact sanitizer: no SID, install path, profile, temp, account or machine name.
    if (-not $Text) { return $Text }
    $t = [regex]::Replace($Text, 'S-1-5-21-[0-9-]+', '<sid>')
    foreach ($pair in @(@($InstallDir, '<install>'), @([IO.Path]::GetTempPath().TrimEnd('\'), '<temp>'), @($env:LOCALAPPDATA, '<localappdata>'), @($env:USERPROFILE, '<profile>'),
            @($env:USERNAME, '<account>'), @($env:COMPUTERNAME, '<machine>'))) {
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
    [Console]::Out.WriteLine(("[{0}] MON-{1} {2} {3}" -f $s.status, $Leg, $Id, $s.detail))
}
function Assert([bool]$Cond, [string]$Msg) { if (-not $Cond) { throw $Msg } }
function NotTested([string]$Why) { $script:notTested = $true; return $Why }
function Write-Summary {
    $summary.finishedUtc = [datetime]::UtcNow.ToString('o')
    $summary.failed = @($summary.cases.Values | Where-Object { $_.status -eq 'FAIL' }).Count
    $summary.notTested = @($summary.cases.Values | Where-Object { $_.status -eq 'NOT_TESTED' }).Count
    $summary.passed = @($summary.cases.Values | Where-Object { $_.status -eq 'PASS' }).Count
    [IO.File]::WriteAllText($SummaryFile, ($summary | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
    [Console]::Out.WriteLine(("MON-{0}: {1} PASS / {2} FAIL / {3} NOT_TESTED | {4} | elevated {5}" -f $Leg, $summary.passed, $summary.failed, $summary.notTested, $summary.shell, $summary.elevated))
    return $summary.failed
}

# ---------------------------------------------------------------------------------------------- the installation
# The nine gates of the installation: each a single assignment to $false in its installed file.
$gateFiles = [ordered]@{ AtmRealDeletionEnabled = 'lib\Engine.Clean.ps1'; AtmWorktreeDiagnosticsEnabled = 'lib\Engine.Diagnose.ps1'; AtmHandleDiagnosticsEnabled = 'lib\Engine.Diagnose.ps1'; AtmDiagnoseExportEnabled = 'lib\Report.ps1'; AtmIsolationEnabled = 'lib\Engine.Isolate.ps1'; AtmQuarantinePurgeEnabled = 'lib\Engine.Isolate.ps1'; AtmGuiEnabled = 'lib\Gui.ps1'; AtmRecoveryEnabled = 'lib\Engine.Recover.ps1'; AtmMonitoringEnabled = 'lib\Engine.Monitor.ps1' }
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
function Get-FileSha([string]$Path) {
    $s = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
    try { $h = [Security.Cryptography.SHA256]::Create(); try { return ([BitConverter]::ToString($h.ComputeHash($s))).Replace('-', '') } finally { $h.Dispose() } } finally { $s.Dispose() }
}
function Get-InstallSnapshot {
    # Relative path -> SHA-256 of every installed file (directories as D).
    $map = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($i in @(Get-ChildItem -LiteralPath $InstallDir -Recurse -Force)) {
        $rel = $i.FullName.Substring($InstallDir.Length).TrimStart('\')
        if ($i.PSIsContainer) { $map[$rel] = 'D' } else { $map[$rel] = 'F|' + $i.Length + '|' + (Get-FileSha $i.FullName) }
    }
    return $map
}
$ctx = @{}

Case 'identity' {
    if ($Leg -eq 'A') { Assert (-not $isAdmin) 'perna A exige token nao elevado (usuario padrao)' } else { Assert $isAdmin 'perna B exige a conta elevada do runner' }
    $(if ($isAdmin) { 'elevated administrator' } else { 'standard user, not elevated' })
}
Case 'installed-before' {
    $bad = @(Get-InstalledGateProblems)
    Assert ($bad.Count -eq 0) "travas instaladas que nao sao uma unica atribuicao `$false: $($bad -join ',')"
    $v = Invoke-InstalledVerify
    Assert ($v -eq 0) "agent-temp verify exit $v"
    $ctx.InstallBefore = Get-InstallSnapshot
    "verify 0; nine installed gates `$false (single assignment each); $($ctx.InstallBefore.Count) installed entries hashed"
}
if ($summary.cases['identity'].status -ne 'PASS' -or $summary.cases['installed-before'].status -ne 'PASS') { exit ([Math]::Max(1, (Write-Summary))) }

# The installed engine, in the order of the CLI (agent-temp.ps1), up to the monitoring engine. The native types are not
# loaded: the task functions do not use them.
$lib = Join-Path $InstallDir 'lib'
. (Join-Path $lib 'Engine.Audit.ps1')
Set-AtmLanguage -Requested 'en-US'
foreach ($pf in @(Get-ChildItem -LiteralPath (Join-Path $InstallDir 'providers') -Filter '*.ps1' -File | Sort-Object Name)) { . $pf.FullName }
. (Join-Path $lib 'Engine.Clean.ps1')
. (Join-Path $lib 'Engine.Isolate.ps1')
. (Join-Path $lib 'Engine.Diagnose.ps1')
. (Join-Path $lib 'Engine.Monitor.ps1')
# The gates of the files loaded here (Report.ps1, Gui.ps1 and Engine.Recover.ps1 are not loaded: their gates are checked
# in the installed files only).
$loadedGates = @($gateFiles.Keys | Where-Object { @('lib\Engine.Clean.ps1', 'lib\Engine.Isolate.ps1', 'lib\Engine.Diagnose.ps1', 'lib\Engine.Monitor.ps1') -contains $gateFiles[$_] })
$loaded = [ordered]@{}
foreach ($g in $loadedGates) { $loaded[$g] = (Get-Variable -Name $g -Scope Script -ValueOnly) }
$loadedOverride = $script:AtmMonitorTaskNameOverride
# In memory, in this process only (the installed files are unchanged; checked again at the end). No other gate is opened;
# no other seam of the engine is set.
$script:AtmMonitoringEnabled = $true
$script:AtmMonitorTaskNameOverride = $script:testName

# ---------------------------------------------------------------------------------------------- the scheduler wrappers
# Every touch of the scheduler goes through one of these functions, and each one checks the test name first: the exact
# form, and this run's name as the engine's override (so the engine names the test task, never the product's).
function Assert-TestName {
    Assert ([string]$script:testName -cmatch '^MonitorTest-[0-9a-f]{8}\z' -and [string]$script:AtmMonitorTaskNameOverride -ceq [string]$script:testName) 'GUARD: nome de tarefa que nao e o nome de teste desta execucao'
}
function Get-TestTask {
    # The test task in the product's folder, read only: Folder and Task ($null when absent), or Code.
    Assert-TestName
    return (Get-AtmMonitorTaskObject -Service (Connect-AtmTaskScheduler) -Name $script:testName)
}
function Get-TestState {
    Assert-TestName
    return (Get-AtmMonitorTaskState)
}
function Invoke-TestRegister([string]$Sid, [string]$EntryPoint) {
    Assert-TestName
    return (Register-AtmMonitorTask -Sid $Sid -EntryPoint $EntryPoint -IntervalHours 6)
}
function Invoke-TestEnable([scriptblock]$Presenter, [scriptblock]$Reader) {
    Assert-TestName
    return (Invoke-AtmMonitorEnable -IntervalHours 6 -Installed -PlanPresenter $Presenter -ConfirmationReader $Reader)
}
function Invoke-TestTaskRun {
    # One run of the test task, as registered (no parameter). The second form is used only when the first is refused by
    # the COM binder of this shell (nothing was started then).
    Assert-TestName
    $o = Get-TestTask
    Assert ($null -ne $o.Task -and [string]$o.Task.Name -ceq $script:testName) 'GUARD: tarefa de teste ausente ou com outro nome'
    try { $null = $o.Task.Run($null); return 'null' } catch {
        # The binder of this shell (an argument it cannot convert: exactly MethodException, not an invocation error) or
        # DISP_E_TYPEMISMATCH / DISP_E_BADVARTYPE; any other error is the scheduler's answer and is rethrown.
        $hr = [int](Get-AtmInnerException $_.Exception).HResult
        if (@(-2147352571, -2147352568) -notcontains $hr -and $_.Exception.GetType().FullName -cne 'System.Management.Automation.MethodException') { throw }
    }
    $null = $o.Task.Run([string]'')
    return 'empty-string'
}
function Remove-TestTask {
    # The only removal of this script: the test task, by its exact name, in the product's folder (the folder stays).
    # Returns '' when it is absent afterwards (removed, or never there), or the scheduler code.
    Assert-TestName
    $o = Get-TestTask
    if ($o.Code) { return $o.Code }
    if ($null -eq $o.Task) { return '' }
    Assert ([string]$o.Task.Name -ceq $script:testName) 'GUARD: tarefa com outro nome'
    try { $o.Folder.DeleteTask($script:testName, 0) } catch { return (Get-AtmTaskSchedulerCode $_.Exception) }
    return ''
}
function Get-TestFolderListing {
    # The tasks this account sees in the product's folder, as a count and a hash of their names (never the names).
    Assert-TestName
    $svc = Connect-AtmTaskScheduler
    $f = $null
    try { $f = $svc.GetFolder($script:AtmMonitorTaskFolder) } catch {
        if (Test-AtmTaskNotFound $_.Exception) { return [pscustomobject]@{ Present = $false; Count = 0; Hash = '' } }
        throw
    }
    $names = @(@(foreach ($t in @($f.GetTasks(1))) { [string]$t.Name }) | Sort-Object)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $h = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($names -join "`n")))).Replace('-', '') } finally { $sha.Dispose() }
    return [pscustomobject]@{ Present = $true; Count = $names.Count; Hash = $h }
}
function Invoke-TestCliEnable {
    # The installed CLI's monitor enable, as a new process, in the non-interactive form of the other checks (cmd /c).
    Assert-TestName
    $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try {
        $out = @(& (Join-Path $env:SystemRoot 'System32\cmd.exe') /c "`"$(Join-Path $InstallDir 'bin\agent-temp.cmd')`" monitor enable -Lang en-US" 2>&1 | ForEach-Object { "$_" })
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $eap }
    return [pscustomobject]@{ Exit = $code; Text = ($out -join "`n") }
}

# ---------------------------------------------------------------------------------------------- shared steps
function Get-FolderPresence([string]$Path) {
    if (-not $Path) { return 'UNKNOWN' }
    if ([IO.Directory]::Exists($Path)) { return 'PRESENT' }
    if ([IO.File]::Exists($Path)) { return 'FILE' }
    return 'ABSENT'
}
function Get-TaskStartBoundary($Task) {
    try { return [datetime]::Parse([string]$Task.Definition.Triggers.Item(1).StartBoundary, [Globalization.CultureInfo]::InvariantCulture) } catch { return $null }
}
function Assert-ReadBack([string]$Sid, [string]$EntryPoint) {
    # The engine's read-back, then the raw task: field by field.
    $st = Get-TestState
    Assert ([string]$st.State -ceq 'PRESENT' -and @($st.Reasons).Count -eq 0) "releitura $($st.State) [$(@($st.Reasons) -join ',')]"
    Assert ($st.IntervalHours -eq 6 -and $st.Enabled -eq $true -and $st.GateOpen -eq $true) "releitura: intervalo $($st.IntervalHours), habilitada $($st.Enabled), trava $($st.GateOpen)"
    Assert ($null -ne $st.NextRunTime -and [datetime]$st.NextRunTime -gt [datetime]::Now) 'releitura: proximo disparo ausente ou no passado'
    $o = Get-TestTask
    Assert ($null -eq $o.Code -and $null -ne $o.Task) "tarefa ilegivel ($($o.Code))"
    $t = $o.Task; $td = $t.Definition
    $r = [ordered]@{
        userIsSelf    = ((Resolve-AtmTaskUserSid ([string]$td.Principal.UserId)) -ceq $Sid)
        logonType     = [int]$td.Principal.LogonType
        runLevel      = [int]$td.Principal.RunLevel
        noPassword    = -not ([string]$t.Xml).Contains('<Password>')
        matchReasons  = @(Test-AtmMonitorTaskMatch -Task $t -Sid $Sid -Name $script:testName -EntryPoint $EntryPoint).Count
        interval      = [string]$td.Triggers.Item(1).Repetition.Interval
        hidden        = ([string]$td.Actions.Item(1).Arguments).Contains('-WindowStyle Hidden')
        nextRunFuture = ([datetime]$t.NextRunTime -gt [datetime]::Now)
        neverRun      = ([int]$t.LastTaskResult -eq 267011)
    }
    $summary.readBack = $r
    Assert ($r.userIsSelf -and $r.logonType -eq 3 -and $r.runLevel -eq 0 -and $r.noPassword -and $r.matchReasons -eq 0 -and $r.interval -ceq 'PT6H' -and $r.hidden -and $r.nextRunFuture) "tarefa lida: $(($r.Keys | ForEach-Object { $_ + '=' + $r[$_] }) -join ', ')"
    return "PRESENT, no reasons; this account, logon 3 (interactive), run level 0 (limited), no <Password> in the XML, the exact action of the installed entry point (with -WindowStyle Hidden), PT6H, next run in the future, never run yet: $($r.neverRun)"
}
function Invoke-RunOnce {
    # Runs the test task once and waits for its end (at most $runWaitSeconds). PASS: last result 3 and the history
    # folder unchanged. A result that is a scheduler status or HRESULT (the task not started, refused or still queued) is
    # NOT_TESTED with the state and the code: the logon type, the account and the password are never changed.
    $folder = Get-AtmMonitorFolder
    $before = Get-FolderPresence $folder
    $o = Get-TestTask
    $boundary = Get-TaskStartBoundary $o.Task
    $ro = $summary.runOnce
    $ro.folderBefore = $before
    $runAt = [datetime]::Now
    $ro.runArgument = $null; $ro.runCode = $null
    try { $ro.runArgument = Invoke-TestTaskRun } catch {
        if ([string]$_.Exception.Message -clike 'GUARD:*') { throw }
        $ro.runCode = Get-AtmTaskSchedulerCode $_.Exception
    }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $state = $null; $last = $null; $lastRun = $null; $finished = $false
    if (-not $ro.runCode) {
        while ($true) {
            $c = Get-TestTask
            if ($null -ne $c.Task) {
                $state = [int]$c.Task.State; $last = [int]$c.Task.LastTaskResult; $lastRun = [datetime]$c.Task.LastRunTime
                # Not finished: running (0x41301), never run (0x41303) or queued (0x41325), or the state running or queued.
                if (@(267009, 267011, 267045) -notcontains $last -and @(2, 4) -notcontains $state) { $finished = $true; break }
            }
            if ($sw.Elapsed.TotalSeconds -ge $runWaitSeconds) { break }
            Start-Sleep -Milliseconds 500
        }
    }
    $sw.Stop()
    $after = Get-FolderPresence $folder
    $ro.finished = $finished
    $ro.seconds = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
    $ro.state = $state
    $ro.lastResult = $(if ($null -ne $last) { '0x{0:X8}' -f $last } else { $null })
    $ro.lastRunAfterRun = $(if ($null -ne $lastRun) { $lastRun -ge $runAt.AddSeconds(-2) } else { $null })
    $ro.beforeOwnTrigger = $(if ($null -ne $boundary) { [datetime]::Now -lt $boundary } else { $null })
    $ro.folderAfter = $after
    Assert ($after -ceq $before) "pasta do historico mudou ($before -> $after)"
    if ($ro.runCode) { return (NotTested "the scheduler refused the run: $($ro.runCode); history folder $before before and after") }
    if (-not $finished) { return (NotTested "not finished within $runWaitSeconds s: state $state, last result $($ro.lastResult) (the scheduler did not start the interactive task, or it stayed queued); history folder $before before and after") }
    if ($last -eq 3) {
        Assert ($ro.lastRunAfterRun -eq $true) 'resultado 3 sem execucao depois do Run'
        return "ran once (Run with $($ro.runArgument)) and ended in $($ro.seconds) s: last result 3 (the installed gate is closed), state $state, before the task's own trigger: $($ro.beforeOwnTrigger); history folder $before before and after"
    }
    if ($last -ge 0 -and $last -le 255) { throw "a tarefa rodou e saiu com $last (esperado 3): defeito do produto a reportar" }
    return (NotTested "ended without a run of the entry point: state $state, last result $($ro.lastResult) (a scheduler status, not an exit code); history folder $before before and after")
}
$windowNote = 'the action read back carries -WindowStyle Hidden (exact action, ADR-0017 section 8); whether a console window appeared is not observable from this process: the entry point ends at the gate check within seconds, and this script does not trace or capture windows'

Case 'loaded' {
    foreach ($g in $loadedGates) { Assert ($loaded[$g] -eq $false) "trava $g carregada da instalacao nao era `$false" }
    foreach ($g in @($loadedGates | Where-Object { $_ -cne 'AtmMonitoringEnabled' })) { Assert ((Get-Variable -Name $g -Scope Script -ValueOnly) -eq $false) "trava $g aberta neste processo" }
    Assert ($null -eq $loadedOverride) 'nome de teste da instalacao nao era $null'
    "the $($loadedGates.Count) gates of the loaded engine files loaded closed from the installation (and the test name seam `$null); monitoring opened in this process memory only; the others still closed"
}
if ($summary.cases['loaded'].status -ne 'PASS') { exit ([Math]::Max(1, (Write-Summary))) }

Case 'cli-gate-closed' {
    # The installed copy, from outside: its own gate decides (the CLI names the product's task, not this run's).
    $l0 = Get-TestFolderListing
    $r = Invoke-TestCliEnable
    $l1 = Get-TestFolderListing
    $summary.cli = [ordered]@{ exit = $r.Exit; gateClosed = $r.Text.Contains('NOTHING WAS SCHEDULED: MONITORING_GATE_CLOSED'); noPhrase = -not $r.Text.Contains('ATIVAR MONITORAMENTO'); listingUnchanged = ($l0.Present -eq $l1.Present -and $l0.Count -eq $l1.Count -and $l0.Hash -ceq $l1.Hash); tasksSeen = $l1.Count }
    Assert ($r.Exit -eq 3 -and $summary.cli.gateClosed -and $summary.cli.noPhrase) "monitor enable exit $($r.Exit), MONITORING_GATE_CLOSED $($summary.cli.gateClosed), sem frase $($summary.cli.noPhrase)"
    Assert $summary.cli.listingUnchanged "pasta de tarefas mudou ($($l0.Count) -> $($l1.Count))"
    "the installed agent-temp monitor enable (cmd /c, -Lang en-US) exited 3 with MONITORING_GATE_CLOSED, no phrase asked; the product's task folder lists the same $($l1.Count) task(s) before and after (folder present: $($l1.Present))"
}
Case 'token' {
    $id = Get-AtmIdentityState
    $summary.token = [ordered]@{ isElevatedAdministrator = $id.IsElevatedAdministrator; elevationType = [string]$id.ElevationType; integrityLevel = [string]$id.IntegrityLevel; sessionId = $id.SessionId }
    $std = [bool](Test-AtmMonitorStandardToken)
    $summary.token.standard = $std
    if ($Leg -eq 'A') { Assert ($std -and $id.IsElevatedAdministrator -eq $false) "token padrao $std ($($id.ElevationType), $($id.IntegrityLevel))" }
    else { Assert (-not $std -and $id.IsElevatedAdministrator -eq $true -and @('HIGH', 'SYSTEM') -ccontains [string]$id.IntegrityLevel) "token elevado legivel: padrao $std, administrador elevado $($id.IsElevatedAdministrator), $($id.IntegrityLevel)" }
    "Test-AtmMonitorStandardToken $std; elevated administrator $($id.IsElevatedAdministrator), elevation type $($id.ElevationType), integrity $($id.IntegrityLevel)"
}

# ============================================================================================== the own task (A; B optional)
function Invoke-OwnTaskCycle([string]$Prefix) {
    # Register (the engine, this account's SID, the installed entry point, 6 h), read back, the duplicate, run once,
    # remove (this script, the test name), read back absent.
    $sid = (Get-AtmMonitorIdentity).Sid
    $ep = Get-AtmMonitorEntryPoint
    Case "$Prefix-absent-before" {
        $st = Get-TestState
        Assert ([string]$st.State -ceq 'ABSENT') "estado antes $($st.State) [$(@($st.Reasons) -join ',')]"
        'ABSENT (this run''s test name)'
    }
    Case "$Prefix-register" {
        Assert ($summary.cases["$Prefix-absent-before"].status -eq 'PASS') 'estado antes nao era ABSENT'
        Assert ([IO.File]::Exists($ep) -and $ep.StartsWith((Join-Path $InstallDir 'bin') + '\', [StringComparison]::OrdinalIgnoreCase)) 'ponto de entrada fora da instalacao'
        $code = Invoke-TestRegister $sid $ep
        Assert ($null -eq $code) "registro devolveu $code"
        $ctx.Registered = $true
        'Register-' + 'AtmMonitorTask returned $null (this account, the installed entry point, 6 h)'
    }
    if (-not $ctx.ContainsKey('Registered')) { return }
    Case "$Prefix-read-back" { Assert-ReadBack $sid $ep }
    Case "$Prefix-duplicate" {
        $code = Invoke-TestRegister $sid $ep
        Assert ([string]$code -ceq 'MONITOR_TASK_EXISTS') "segundo registro devolveu $code"
        'a second registration: MONITOR_TASK_EXISTS (never replaced)'
    }
    Case "$Prefix-run-once" { Invoke-RunOnce }
    Case "$Prefix-window" { NotTested $windowNote }
    Case "$Prefix-remove" {
        $code = Remove-TestTask
        Assert ($code -ceq '') "remocao devolveu $code"
        'the test task removed by this script, by its exact name (the product removes no task until M4)'
    }
    Case "$Prefix-absent-after" {
        $st = Get-TestState
        Assert ([string]$st.State -ceq 'ABSENT') "estado depois $($st.State) [$(@($st.Reasons) -join ',')]"
        $o = Get-TestTask
        Assert ($null -eq $o.Code -and $null -ne $o.Folder) "pasta do produto ausente ou ilegivel ($($o.Code))"
        'ABSENT; the product''s task folder stays'
    }
}

# ============================================================================================== leg A (standard user)
if ($Leg -eq 'A') {
    Invoke-OwnTaskCycle 'A'
}

# ============================================================================================== leg B (elevated)
if ($Leg -eq 'B') {
    Case 'B-enable-refused' {
        $calls = @{ Presenter = 0; Reader = 0 }
        $pr = { param($plan) $null = $plan; $calls.Presenter++ }.GetNewClosure()
        $rd = { param($phrase, $kind) $null = $phrase; $null = $kind; $calls.Reader++; return '' }.GetNewClosure()
        $res = Invoke-TestEnable $pr $rd
        Assert ([string]$res.Aborted -ceq 'MONITOR_TASK_REQUIRES_STANDARD_TOKEN') "enable parou em $($res.Aborted)"
        Assert (-not $res.Registered -and -not $res.Done -and $null -eq $res.Plan -and $null -eq $res.Task) 'enable registrou, montou plano ou leu a tarefa'
        Assert ($calls.Presenter -eq 0 -and $calls.Reader -eq 0) "plano ou frase alcancados ($($calls.Presenter), $($calls.Reader))"
        'monitor enable (gate open in this process memory): MONITOR_TASK_REQUIRES_STANDARD_TOKEN; no plan shown, no phrase asked, nothing registered'
    }
    Case 'B-absent-after-enable' {
        $st = Get-TestState
        Assert ([string]$st.State -ceq 'ABSENT') "estado $($st.State) [$(@($st.Reasons) -join ',')]"
        'ABSENT (this run''s test name)'
    }
    # Optional: this account's own test task, to prove the exit code 3 on a runner where the scheduler starts it (the
    # elevated runner account; the task runs with the limited token of run level 0).
    Invoke-OwnTaskCycle 'B-own'
}

# ---------------------------------------------------------------------------------------------- after
# A test task left by a failure is removed here, by its test name only.
try { $summary.cleanup = $(if ((Remove-TestTask) -ceq '') { 'absent' } else { 'code' }) } catch { $summary.cleanup = 'error' }
Case 'installed-after' {
    foreach ($g in $loadedGates) { Assert ($loaded[$g] -eq $false) "trava $g carregada da instalacao nao era `$false" }
    foreach ($g in @($loadedGates | Where-Object { $_ -cne 'AtmMonitoringEnabled' })) { Assert ((Get-Variable -Name $g -Scope Script -ValueOnly) -eq $false) "trava $g aberta neste processo" }
    $bad = @(Get-InstalledGateProblems)
    Assert ($bad.Count -eq 0) "travas instaladas alteradas: $($bad -join ',')"
    $v = Invoke-InstalledVerify
    Assert ($v -eq 0) "agent-temp verify exit $v"
    $after = Get-InstallSnapshot
    $diff = @(@($ctx.InstallBefore.Keys | Where-Object { -not $after.ContainsKey($_) -or $after[$_] -cne $ctx.InstallBefore[$_] }) + @($after.Keys | Where-Object { -not $ctx.InstallBefore.ContainsKey($_) }))
    Assert ($diff.Count -eq 0) "instalacao alterada: $($diff.Count) entrada(s)"
    Assert ($summary.cleanup -ceq 'absent') "tarefa de teste restante: $($summary.cleanup)"
    'installed files identical by SHA-256 to before the runs; verify 0; nine installed gates still $false (monitoring opened only in this process memory); no test task left'
}
exit (Write-Summary)
