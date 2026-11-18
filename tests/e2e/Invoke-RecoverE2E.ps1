<#
.SYNOPSIS
  V0.4 R6 (ADR-0016): the REAL REC-SVC-START and its undo (R2 and R3), end to end, on services this script creates itself,
  on a DISPOSABLE machine only (CI).
.DESCRIPTION
  CI-only harness, never shipped (tools\Build-Release.ps1 leaves it out of the release archive and refuses an archive
  that contains it; the install e2e checks that it is absent from the package). Three modes, run in this order by the
  install e2e:
    Setup (elevated): creates a run root atomically (refused if the name exists) with a protected DACL, compiles in it an
      inert service executable (always through Windows PowerShell 5.1 Add-Type, whatever the installer's shell), and
      creates seven services named AtmRecE2E-<nonce>-<key>, each checked absent first, start mode manual (one disabled),
      the default account (LocalSystem). It writes their names to a file in that root, readable (never writable) by the
      account of leg A.
    A (a non-elevated standard user): reads the names from that file and checks the prefix, the nonce and the executable.
      A real start is expected to reach the seam and get ACCESS_DENIED (the service's default security descriptor is
      never changed); whatever the runner gives is recorded.
    B (the elevated runner account): a real start and its real undo; the refusals before the seam; the dependencies; the
      undo of leg A's log (provenance across legs); then the final stop of every own service that is not STOPPED, by
      exact name checked as its own. The services stay registered (the runner is discarded); none is removed.
  Containment: legs A and B load the INSTALLED engine into their own process and open the recovery gate there only, in
  memory (the eight installed gates and the SHA-256 of every installed file are checked before and after). The test
  provider is an in-memory object passed through -Providers that declares only this run's services. The real default
  seams are reached only through the guard wrappers ($recStartGuard, $recStopGuard), passed as -ServiceControlImpl and
  -ServiceStopImpl: each checks the name against this run's list, counts the call and calls the default seam with exactly
  the engine's argument; any other name throws. The log's intent record says TEST_SEAM because a seam is passed. Every
  service control of this script (sc.exe) goes through Invoke-OwnSc, which checks the name first. The console
  observation is the existing test seam (AtmCleanConsoleSource, logged as TEST_SEAM): every confirmation is AUTOMATED by
  this script and is never a human acceptance.
  Writes ONLY a summary (codes, counts, labels; no path, account name or SID) to -SummaryFile; the raw recovery logs stay
  in each leg's run root and are never uploaded. Exit code = number of failed cases (NOT_TESTED is neither a pass nor a
  failure).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Setup', 'A', 'B')][string]$Leg,
    [Parameter(Mandatory)][string]$InstallDir,
    [Parameter(Mandatory)][string]$SummaryFile,
    [Parameter(Mandatory)][string]$WorkDir,
    [switch]$DisposableMachine,
    # Setup: where the path of the service root is written for the next steps, and the account of leg A (a read-only ACE).
    [string]$StateFile,
    [string]$ReaderAccount,
    # Legs A and B: the service root that Setup created.
    [string]$ServiceRoot
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# Accident guard only (these variables can be set by anyone): the containment is the run root, the nonce and the guard.
if (-not $DisposableMachine -and -not ($env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -eq 'github-hosted')) {
    throw 'Recusado: este teste cria servicos e os inicia e para de verdade; so roda em maquina descartavel (runner do GitHub) ou com -DisposableMachine.'
}

$me = [Security.Principal.WindowsIdentity]::GetCurrent()
$mySid = $me.User.Value
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($me)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$prefix = 'AtmRecE2E'
# The seven services: one started and undone in leg B (and refused to leg A), one never declared, one declared with
# another executable, one disabled, one already running, and a dependency pair (y depends on x).
$keys = @('start', 'undecl', 'mism', 'dis', 'run', 'x', 'y')
$script:own = $null
$runRoot = $null
$n12 = $null
$ctx = @{ Logs = (New-Object System.Collections.Generic.List[string]) }
$summary = [ordered]@{
    schema = 'atm.e2e-recover/1'; phase = 'V04-R6'; leg = $Leg; startedUtc = [datetime]::UtcNow.ToString('o')
    shell = "$($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)"; arch = $env:PROCESSOR_ARCHITECTURE
    elevated = [bool]$isAdmin; confirmation = 'AUTOMATED_BY_HARNESS (console: TEST_SEAM); not a human acceptance'
    legOrder = 'Setup (elevated), then A (standard user), then B (elevated, ends with the final stop)'
    seam = 'the DEFAULT seams behind the guard wrappers (the log records TEST_SEAM because a seam is passed)'
    serviceCompile = $null; seamCalls = [ordered]@{ start = 0; stop = 0; refusedByGuard = 0 }; dependency = [ordered]@{}
    cases = [ordered]@{}
}
[void][IO.Directory]::CreateDirectory($WorkDir)

function Protect-Text([string]$Text) {
    # Defense in depth before the artifact sanitizer: no SID, root, profile, temp, account or machine name.
    if (-not $Text) { return $Text }
    $t = [regex]::Replace($Text, 'S-1-5-21-[0-9-]+', '<sid>')
    foreach ($pair in @(@($runRoot, '<run-root>'), @($ServiceRoot, '<service-root>'), @($WorkDir, '<work>'), @($InstallDir, '<install>'), @([IO.Path]::GetTempPath().TrimEnd('\'), '<temp>'),
            @($env:LOCALAPPDATA, '<localappdata>'), @($env:USERPROFILE, '<profile>'), @($ReaderAccount, '<account>'), @($env:USERNAME, '<account>'), @($env:COMPUTERNAME, '<machine>'), @($n12, '<nonce>'))) {
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
    [Console]::Out.WriteLine(("[{0}] REC-{1} {2} {3}" -f $s.status, $Leg, $Id, $s.detail))
}
function Assert([bool]$Cond, [string]$Msg) { if (-not $Cond) { throw $Msg } }
function NotTested([string]$Why) { $script:notTested = $true; return $Why }
function Write-Summary {
    $summary.seamCalls.start = $script:recGuard.Start; $summary.seamCalls.stop = $script:recGuard.Stop; $summary.seamCalls.refusedByGuard = $script:recGuard.Refused
    $summary.finishedUtc = [datetime]::UtcNow.ToString('o')
    $summary.failed = @($summary.cases.Values | Where-Object { $_.status -eq 'FAIL' }).Count
    $summary.notTested = @($summary.cases.Values | Where-Object { $_.status -eq 'NOT_TESTED' }).Count
    $summary.passed = @($summary.cases.Values | Where-Object { $_.status -eq 'PASS' }).Count
    [IO.File]::WriteAllText($SummaryFile, ($summary | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
    [Console]::Out.WriteLine(("REC-{0}: {1} PASS / {2} FAIL / {3} NOT_TESTED | {4} | elevated {5}" -f $Leg, $summary.passed, $summary.failed, $summary.notTested, $summary.shell, $summary.elevated))
    return $summary.failed
}

# ---------------------------------------------------------------------------------------------- this run's services
function Assert-OwnName([string]$Name) {
    # Containment: one of the seven names of this run, spelled exactly (prefix, nonce, key).
    Assert ($null -ne $script:own -and $script:own.Names -ccontains $Name -and $Name.StartsWith($script:own.Prefix, [StringComparison]::Ordinal)) 'GUARD: nome que nao e um servico desta execucao'
}
function Invoke-OwnSc {
    # The only service control of this script outside the engine: sc.exe, for one of this run's names only.
    param([ValidateSet('query', 'qc', 'create', 'start', 'stop')][string]$Verb, [string]$Name, [string[]]$Extra = @())
    Assert-OwnName $Name
    $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try {
        $out = @(& (Join-Path $env:SystemRoot 'System32\sc.exe') $Verb $Name @Extra 2>&1 | ForEach-Object { "$_" })
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $eap }
    return [pscustomobject]@{ Exit = $code; Text = ($out -join ' ') }
}
function Get-OwnService([string]$Name) {
    Assert-OwnName $Name
    $r = @(Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + $Name + "'") -Property Name, State, StartMode, StartName, PathName -ErrorAction Stop)
    if ($r.Count -ne 1) { return $null }
    return $r[0]
}
function Get-OwnState([string]$Name) {
    $s = Get-OwnService $Name
    if ($null -eq $s) { return 'ABSENT' }
    return [string]$s.State
}
function Wait-OwnState([string]$Name, [string]$Want, [int]$Seconds = 30) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $Seconds) {
        if ((Get-OwnState $Name) -ceq $Want) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return ((Get-OwnState $Name) -ceq $Want)
}
function Set-OwnList([string]$Nonce, [string]$Root) {
    $short = $Nonce.Substring(0, 12)
    $byKey = [ordered]@{}
    foreach ($k in $keys) { $byKey[$k] = 'AtmRecE2E-' + $short + '-' + $k }
    $script:own = [pscustomobject]@{ Prefix = ($prefix + '-' + $short + '-'); Nonce = $Nonce; Short = $short; ByKey = $byKey; Names = [string[]]@($byKey.Values)
        Root = $Root; Image = ('AtmRecE2E-' + $short + '.exe'); ImagePath = (Join-Path $Root ('AtmRecE2E-' + $short + '.exe')) }
}
function Get-FileSha([string]$Path) {
    $s = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
    try { $h = [Security.Cryptography.SHA256]::Create(); try { return ([BitConverter]::ToString($h.ComputeHash($s))).Replace('-', '') } finally { $h.Dispose() } } finally { $s.Dispose() }
}
function New-RunRoot([string]$Path, [string]$ReaderSid) {
    # Created atomically with a protected DACL (owner and full control: this account; SYSTEM and Administrators; and, for
    # the service root only, read and execute for leg A's account), refused if the name exists; checked after creation.
    Assert (-not (Test-Path -LiteralPath $Path)) 'RUN_ROOT_EXISTS'
    $sddl = "O:$($mySid)D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;$mySid)"
    if ($ReaderSid) { $sddl += "(A;OICI;0x1200a9;;;$ReaderSid)" }
    $ds = New-Object Security.AccessControl.DirectorySecurity
    $ds.SetSecurityDescriptorSddlForm($sddl)
    if ($PSVersionTable.PSEdition -eq 'Core') { $ext = 'System.IO.FileSystemAclExtensions' -as [type]; $null = $ext::CreateDirectory($ds, $Path) } else { $null = [IO.Directory]::CreateDirectory($Path, $ds) }
    $acl = Get-Acl -LiteralPath $Path
    Assert ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq $mySid) 'dono da raiz de execucao divergente'
    Assert $acl.AreAccessRulesProtected 'DACL da raiz de execucao nao protegida'
    $allowed = @('S-1-5-18', 'S-1-5-32-544', $mySid); if ($ReaderSid) { $allowed += $ReaderSid }
    foreach ($r in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) { Assert ($allowed -contains $r.IdentityReference.Value) 'entrada inesperada na DACL da raiz de execucao' }
    Assert (([IO.File]::GetAttributes($Path) -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'raiz de execucao e reparse point'
}

# The guard wrappers: the ONLY places where the default seams appear. Each checks the name against this run's list, counts
# the call and calls the default seam with exactly the engine's argument; any other name throws (the engine records the
# outcome EXCEPTION and the case fails). No closure: they run in this script's session state, where the engine is loaded.
$script:recGuard = @{ Start = 0; Stop = 0; Refused = 0 }
$recStartGuard = {
    param($Name)
    if (-not ($Name -is [string]) -or $null -eq $script:own -or $script:own.Names -cnotcontains $Name) { $script:recGuard.Refused++; throw 'GUARD_NAME_NOT_OWN' }
    $script:recGuard.Start++
    Invoke-AtmRecoverServiceStartDefault -Name $Name
}
$recStopGuard = {
    param($Name)
    if (-not ($Name -is [string]) -or $null -eq $script:own -or $script:own.Names -cnotcontains $Name) { $script:recGuard.Refused++; throw 'GUARD_NAME_NOT_OWN' }
    $script:recGuard.Stop++
    Invoke-AtmRecoverServiceStopDefault -Name $Name
}

# ============================================================================================== Setup (elevated)
if ($Leg -eq 'Setup') {
    Case 'identity' { Assert $isAdmin 'o Setup exige a conta elevada do runner'; 'elevated administrator' }
    Case 'service-root' {
        Assert ($summary.cases['identity'].status -eq 'PASS') 'sem identidade elevada'
        $nonce = [guid]::NewGuid().ToString('N')
        $n12 = $nonce.Substring(0, 12); $script:n12 = $n12
        $root = Join-Path $env:SystemDrive ('ATM-E2E-REC-S-' + $n12)
        $readerSid = $null
        if ($ReaderAccount) { $readerSid = (New-Object Security.Principal.NTAccount($ReaderAccount)).Translate([Security.Principal.SecurityIdentifier]).Value }
        Assert ($readerSid -ne $mySid) 'conta de leitura igual a conta do Setup'
        New-RunRoot $root $readerSid
        $script:runRoot = $root
        Set-OwnList $nonce $root
        [void][IO.Directory]::CreateDirectory((Join-Path $root 'build\tmp'))
        "created atomically, protected DACL (owner, SYSTEM, Administrators$(if ($readerSid) { '; read and execute for the account of leg A' })), refused if present"
    }
    Case 'compile' {
        Assert ($null -ne $script:own) 'raiz dos servicos indisponivel'
        # An inert service: it answers start and stop only (no pause, no shutdown, no power or session events), writes no
        # event log (AutoLog false), opens no file, socket or process. One executable serves every own service.
        $cs = @'
using System.ServiceProcess;
public sealed class AtmRecE2EService : ServiceBase
{
    public AtmRecE2EService()
    {
        ServiceName = "AtmRecE2E";
        AutoLog = false;
        CanStop = true;
        CanPauseAndContinue = false;
        CanShutdown = false;
        CanHandlePowerEvent = false;
        CanHandleSessionChangeEvent = false;
    }
    public static void Main()
    {
        ServiceBase.Run(new AtmRecE2EService());
    }
}
'@
        $compiler = @'
param([string]$Source, [string]$Output)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.ServiceProcess
$ref = [System.ServiceProcess.ServiceBase].Assembly.Location
Add-Type -TypeDefinition ([IO.File]::ReadAllText($Source)) -ReferencedAssemblies @($ref) -OutputAssembly $Output -OutputType ConsoleApplication
'@
        $build = Join-Path $script:own.Root 'build'
        $src = Join-Path $build 'AtmRecE2EService.cs'
        $cps = Join-Path $build 'compile.ps1'
        [IO.File]::WriteAllText($src, $cs, (New-Object Text.UTF8Encoding($false)))
        [IO.File]::WriteAllText($cps, $compiler, (New-Object Text.UTF8Encoding($false)))
        # Always Windows PowerShell 5.1 (System32), whatever the installer's shell; its compiler's temp files stay in the root.
        $ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $oldTemp = $env:TEMP; $oldTmp = $env:TMP
        $env:TEMP = Join-Path $build 'tmp'; $env:TMP = $env:TEMP
        try {
            $p = Start-Process -FilePath $ps51 -ArgumentList ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $cps + '" -Source "' + $src + '" -Output "' + $script:own.ImagePath + '"') -Wait -PassThru -NoNewWindow `
                -RedirectStandardOutput (Join-Path $build 'compile-out.txt') -RedirectStandardError (Join-Path $build 'compile-err.txt')
        } finally { $env:TEMP = $oldTemp; $env:TMP = $oldTmp }
        Assert ($p.ExitCode -eq 0 -and [IO.File]::Exists($script:own.ImagePath)) "compilacao falhou (exit $($p.ExitCode)): $([IO.File]::ReadAllText((Join-Path $build 'compile-err.txt')))"
        Assert ($script:own.ImagePath -notmatch '\s') 'caminho do executavel com espaco'
        $script:own | Add-Member -NotePropertyName ImageSha256 -NotePropertyValue (Get-FileSha $script:own.ImagePath)
        $summary.serviceCompile = 'Windows PowerShell 5.1 (System32) Add-Type -OutputAssembly -OutputType ConsoleApplication, referencing System.ServiceProcess; the same in every job, whatever the installer shell'
        "inert ServiceBase executable compiled in the service root ($((New-Object IO.FileInfo($script:own.ImagePath)).Length) bytes)"
    }
    Case 'services-created' {
        Assert ($null -ne $script:own -and $script:own.PSObject.Properties['ImageSha256']) 'executavel indisponivel'
        foreach ($k in $keys) {
            $n = $script:own.ByKey[$k]
            $q = Invoke-OwnSc 'query' $n
            Assert ($q.Exit -eq 1060 -and $null -eq (Get-OwnService $n)) "servico $k ja existe ou consulta inesperada (exit $($q.Exit))"
        }
        foreach ($k in $keys) {
            $n = $script:own.ByKey[$k]
            $extra = @('binPath=', $script:own.ImagePath, 'start=', $(if ($k -ceq 'dis') { 'disabled' } else { 'demand' }))
            if ($k -ceq 'y') { $extra += @('depend=', $script:own.ByKey['x']) }
            $c = Invoke-OwnSc 'create' $n $extra
            Assert ($c.Exit -eq 0) "criacao de $k falhou (exit $($c.Exit)): $($c.Text)"
        }
        foreach ($k in $keys) {
            $s = Get-OwnService $script:own.ByKey[$k]
            Assert ($null -ne $s) "servico $k ausente depois da criacao"
            Assert ([string]$s.State -ceq 'Stopped') "servico $k nao esta parado ($($s.State))"
            Assert ([string]$s.StartMode -ceq $(if ($k -ceq 'dis') { 'Disabled' } else { 'Manual' })) "modo de inicio de $k`: $($s.StartMode)"
            Assert ([string]$s.StartName -ceq 'LocalSystem') "conta de $k nao e a padrao (LocalSystem)"
            Assert ([string]::Equals(([string]$s.PathName).Trim('"'), $script:own.ImagePath, [StringComparison]::OrdinalIgnoreCase)) "executavel de $k divergente"
        }
        $qc = Invoke-OwnSc 'qc' $script:own.ByKey['y']
        Assert ($qc.Exit -eq 0 -and $qc.Text.Contains($script:own.ByKey['x'])) 'y nao depende de x'
        "7 services created by exact name (each absent first): STOPPED, manual (dis: disabled), LocalSystem, the generated executable; y depends on x"
    }
    Case 'names-file' {
        Assert ($summary.cases['services-created'].status -eq 'PASS') 'servicos indisponiveis'
        $doc = [ordered]@{ schema = 'atm.e2e-recover-names/1'; prefix = $prefix; nonce = $script:own.Nonce; image = $script:own.Image; imageSha256 = $script:own.ImageSha256; services = $script:own.ByKey }
        $nf = Join-Path $script:own.Root 'services.json'
        [IO.File]::WriteAllText($nf, ($doc | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding($false)))
        Assert ((([IO.File]::ReadAllText($nf)) | ConvertFrom-Json).nonce -ceq $script:own.Nonce) 'arquivo de nomes ilegivel'
        if ($StateFile) { [IO.File]::WriteAllText($StateFile, $script:own.Root, (New-Object Text.UTF8Encoding($false))) }
        'names, nonce, executable name and SHA-256 written to the service root (read only for leg A)'
    }
    exit (Write-Summary)
}

# ============================================================================================== legs A and B
# The eight gates of the installation: each a single assignment to $false in its installed file.
$gateFiles = [ordered]@{ AtmRealDeletionEnabled = 'lib\Engine.Clean.ps1'; AtmWorktreeDiagnosticsEnabled = 'lib\Engine.Diagnose.ps1'; AtmHandleDiagnosticsEnabled = 'lib\Engine.Diagnose.ps1'; AtmDiagnoseExportEnabled = 'lib\Report.ps1'; AtmIsolationEnabled = 'lib\Engine.Isolate.ps1'; AtmQuarantinePurgeEnabled = 'lib\Engine.Isolate.ps1'; AtmGuiEnabled = 'lib\Gui.ps1'; AtmRecoveryEnabled = 'lib\Engine.Recover.ps1' }
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
function Get-InstallSnapshot {
    # Relative path -> SHA-256 of every installed file (directories as D).
    $map = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($i in @(Get-ChildItem -LiteralPath $InstallDir -Recurse -Force)) {
        $rel = $i.FullName.Substring($InstallDir.Length).TrimStart('\')
        if ($i.PSIsContainer) { $map[$rel] = 'D' } else { $map[$rel] = 'F|' + $i.Length + '|' + (Get-FileSha $i.FullName) }
    }
    return $map
}

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
    "verify 0; eight installed gates `$false (single assignment each); $($ctx.InstallBefore.Count) installed entries hashed"
}
Case 'service-root' {
    # The names come only from the file Setup wrote in its protected root: the root's name, the nonce, every name (prefix,
    # nonce, key), the executable's name and SHA-256, and each service's account and executable, checked before any call.
    Assert ([string]$ServiceRoot -cmatch '^[A-Za-z]:\\ATM-E2E-REC-S-[0-9a-f]{12}$' -and [string]::Equals([IO.Path]::GetPathRoot($ServiceRoot), $env:SystemDrive + '\', [StringComparison]::OrdinalIgnoreCase)) 'raiz dos servicos invalida'
    Assert ([IO.Directory]::Exists($ServiceRoot) -and ([IO.File]::GetAttributes($ServiceRoot) -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'raiz dos servicos ausente ou reparse point'
    $acl = Get-Acl -LiteralPath $ServiceRoot
    Assert $acl.AreAccessRulesProtected 'DACL da raiz dos servicos nao protegida'
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($Leg -eq 'B') { Assert ($owner -eq $mySid) 'raiz dos servicos nao criada por esta conta' } else { Assert ($owner -ne $mySid) 'raiz dos servicos de propriedade da perna A' }
    $short = $ServiceRoot.Substring($ServiceRoot.Length - 12)
    $script:n12 = $short
    $nf = Join-Path $ServiceRoot 'services.json'
    Assert (([IO.File]::GetAttributes($nf) -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'arquivo de nomes e reparse point'
    $doc = [IO.File]::ReadAllText($nf) | ConvertFrom-Json
    Assert ([string]$doc.schema -ceq 'atm.e2e-recover-names/1' -and [string]$doc.prefix -ceq $prefix -and [string]$doc.nonce -cmatch '^[0-9a-f]{32}$' -and ([string]$doc.nonce).Substring(0, 12) -ceq $short) 'arquivo de nomes: esquema, prefixo ou nonce divergente'
    Set-OwnList ([string]$doc.nonce) $ServiceRoot
    foreach ($k in $keys) { Assert ([string]$doc.services.$k -ceq $script:own.ByKey[$k]) "arquivo de nomes: nome de $k divergente" }
    Assert ([string]$doc.image -ceq $script:own.Image -and [IO.File]::Exists($script:own.ImagePath) -and (Get-FileSha $script:own.ImagePath) -ceq [string]$doc.imageSha256) 'executavel divergente do arquivo de nomes'
    if ($Leg -eq 'A') {
        # Read only for leg A: opening the names file for writing is refused (nothing is written).
        $denied = $false
        try { $w = [IO.File]::Open($nf, 'Open', 'Write', 'ReadWrite'); $w.Dispose() } catch { $denied = ($_.Exception.GetBaseException() -is [UnauthorizedAccessException]) }
        Assert $denied 'arquivo de nomes gravavel pela perna A'
    }
    foreach ($k in $keys) {
        $s = Get-OwnService $script:own.ByKey[$k]
        Assert ($null -ne $s -and [string]$s.StartName -ceq 'LocalSystem' -and [string]::Equals(([string]$s.PathName).Trim('"'), $script:own.ImagePath, [StringComparison]::OrdinalIgnoreCase)) "servico $k ausente ou nao e desta execucao"
    }
    "7 own names read from the protected service root (prefix, nonce and executable checked$(if ($Leg -eq 'A') { '; the file is not writable by this account' }))"
}
if ($summary.cases['identity'].status -ne 'PASS' -or $summary.cases['installed-before'].status -ne 'PASS' -or $summary.cases['service-root'].status -ne 'PASS') { exit ([Math]::Max(1, (Write-Summary))) }

# The installed engine, in the order of the CLI (agent-temp.ps1). The native library is loaded by the engine only if its
# SHA-256 matches the installed manifest.
$lib = Join-Path $InstallDir 'lib'
. (Join-Path $lib 'Engine.Audit.ps1')
Set-AtmLanguage -Requested 'en-US'
foreach ($pf in @(Get-ChildItem -LiteralPath (Join-Path $InstallDir 'providers') -Filter '*.ps1' -File | Sort-Object Name)) { . $pf.FullName }
. (Join-Path $lib 'Engine.Clean.ps1')
. (Join-Path $lib 'Engine.Isolate.ps1')
. (Join-Path $lib 'Engine.Diagnose.ps1')
. (Join-Path $lib 'Engine.Recover.ps1')
# The gates of the files loaded here (Report.ps1 and Gui.ps1 are not loaded: their gates are checked in the installed
# files only).
$loadedGates = @($gateFiles.Keys | Where-Object { @('lib\Engine.Clean.ps1', 'lib\Engine.Isolate.ps1', 'lib\Engine.Diagnose.ps1', 'lib\Engine.Recover.ps1') -contains $gateFiles[$_] })
$loaded = [ordered]@{}
foreach ($g in $loadedGates) { $loaded[$g] = (Get-Variable -Name $g -Scope Script -ValueOnly) }
# In memory, in this process only (the installed files are unchanged; checked again at the end). No other gate is opened.
$script:AtmRecoveryEnabled = $true
$script:AtmCleanConsoleSource = { $true }
$ia = @{ SelfMarkers = @((Join-Path $InstallDir 'agent-temp.ps1'), (Join-Path $InstallDir 'bin\agent-temp.cmd')); ConfigDir = (Join-Path $InstallDir 'config'); NoProgress = $true }
$interaction = @{ Caller = 'E2E'; ConsoleRequired = $true }

Case 'loaded' {
    foreach ($g in $loadedGates) { Assert ($loaded[$g] -eq $false) "trava $g carregada da instalacao nao era `$false" }
    foreach ($g in @($loadedGates | Where-Object { $_ -cne 'AtmRecoveryEnabled' })) { Assert ((Get-Variable -Name $g -Scope Script -ValueOnly) -eq $false) "trava $g aberta neste processo" }
    "the $($loadedGates.Count) gates of the loaded engine files loaded closed from the installation; recovery opened in this process memory only; the others still closed"
}
Case 'run-root' {
    $script:runRoot = Join-Path $env:SystemDrive ('ATM-E2E-REC-' + $Leg + '-' + $script:own.Short)
    New-RunRoot $script:runRoot $null
    $ctx.LogDir = Join-Path $script:runRoot 'log'
    [void][IO.Directory]::CreateDirectory($ctx.LogDir)
    'created atomically, protected DACL (owner, SYSTEM, Administrators), refused if present; the logs stay here'
}
if ($summary.cases['run-root'].status -ne 'PASS' -or $summary.cases['loaded'].status -ne 'PASS') { exit ([Math]::Max(1, (Write-Summary))) }

function New-RecProvider {
    # The in-memory test provider: contract v2, runtime only, declaring only services of this run (checked by name).
    param([string[]]$Keys, [hashtable]$ImageOverride = @{})
    $hints = @(foreach ($k in $Keys) {
            $n = $script:own.ByKey[$k]
            Assert-OwnName $n
            [pscustomobject]@{ Name = $n; Role = $null; ExpectedImage = $(if ($ImageOverride.ContainsKey($k)) { [string]$ImageOverride[$k] } else { $script:own.Image }) }
        })
    $get = { $hints }.GetNewClosure()
    return [pscustomobject]@{ Id = 'e2e-recover'; DisplayName = 'E2E recover (CI only, in memory)'; ContractVersion = 2; Capabilities = @('runtime')
        GetProcessMatchers = { @() }; GetServiceHints = $get; GetVirtualizationHints = { @() } }
}
function New-Operator {
    # Automated answers: the exact phrase generated by the engine.
    $st = @{ Calls = (New-Object System.Collections.Generic.List[string]) }
    $st.Reader = {
        param($phrase, $kind, $rootPath, $choices)
        $st.Calls.Add([string]$kind)
        return [string]$phrase
    }.GetNewClosure()
    return $st
}
function Read-E2ELog([string]$Path) {
    $t = (New-Object Text.UTF8Encoding($false, $true)).GetString([IO.File]::ReadAllBytes($Path))
    return @($t.Split([char]10) | Where-Object { $_ -ne '' } | ForEach-Object { $_ | ConvertFrom-Json })
}
function Get-Types($Records) { return ((@($Records | ForEach-Object { $_.type })) -join ',') }
function New-E2ELogPath([string]$Name) { $ctx.Logs.Add($Name); return (Join-Path $ctx.LogDir $Name) }
# The presenter prints nothing (anything it returned would reach the engine's output); it re-checks the target first.
$script:recPresented = $null
$recPresenter = { param($plan) Assert-OwnName ([string]$plan.Target); $script:recPresented = $plan }

function Invoke-E2ERecStart([string]$Key, $Providers, [string]$LogName) {
    # One real REC-SVC-START, with the reference plan of recover plan (the same functions, a collection just before).
    $name = $script:own.ByKey[$Key]
    Assert-OwnName $name
    $cimBefore = Get-OwnState $name
    $ref = Get-AtmRecoverPlan -Collection (Get-AtmRecoverCollection -Providers $Providers) -Operation 'REC-SVC-START' -Service $name
    $op = New-Operator
    $log = New-E2ELogPath $LogName
    $s0 = $script:recGuard.Start
    $script:recPresented = $null
    Assert-OwnName $name
    $res = Invoke-AtmRecover -Operation 'REC-SVC-START' -Service $name -PlanPresenter $recPresenter -ConfirmationReader $op.Reader -InventoryArgs $ia -LogFile $log -Interaction $interaction -Providers $Providers -ServiceControlImpl $recStartGuard
    return [pscustomobject]@{ Res = $res; Ref = $ref; Log = $log; SeamCalls = ($script:recGuard.Start - $s0); Presented = $script:recPresented; Calls = $op.Calls; CimBefore = $cimBefore; CimAfter = (Get-OwnState $name) }
}
function Invoke-E2ERecUndo([string]$Key, $Providers, [string]$SourceLog, [string]$RunId, [string]$LogName) {
    # One real undo of one run's log, with the reference inverse plan (the same functions, a collection just before).
    $name = $script:own.ByKey[$Key]
    Assert-OwnName $name
    $cimBefore = Get-OwnState $name
    $src = Read-AtmRecoverRunLog -Path $SourceLog -RunId $RunId
    $ref = Get-AtmRecoverUndoPlan -Collection $(if ($null -eq $src.Code) { Get-AtmRecoverCollection -Providers $Providers } else { $null }) -Source $src
    $op = New-Operator
    $log = New-E2ELogPath $LogName
    $s0 = $script:recGuard.Stop
    $script:recPresented = $null
    Assert-OwnName $name
    $res = Invoke-AtmRecoverUndo -SourceLog $SourceLog -RunId $RunId -PlanPresenter $recPresenter -ConfirmationReader $op.Reader -InventoryArgs $ia -LogFile $log -Interaction $interaction -Providers $Providers -ServiceStopImpl $recStopGuard
    return [pscustomobject]@{ Res = $res; Ref = $ref; Log = $log; SeamCalls = ($script:recGuard.Stop - $s0); Presented = $script:recPresented; Calls = $op.Calls; CimBefore = $cimBefore; CimAfter = (Get-OwnState $name) }
}
function Get-RecCodes($Codes) { $c = @($Codes); if ($c.Count -eq 0) { return '-' }; return ($c -join ',') }
function Get-DiffFields($Diff) { return @(@($Diff) | ForEach-Object { [string]$_.field }) }
# The fields a start or a stop of an inert service may change: its state, the fault signals that follow it, and the
# 'name|STATE' labels of its dependencies (x's state, read in y's capture).
$stateFields = @('State', 'ExitCode', 'ServiceSpecificExitCode', 'CheckPoint', 'WaitHint', 'AcceptStop', 'Condition', 'DependsOn', 'Dependents')
function Assert-Completed($R, [string]$Seam, [string]$Want, [string]$What) {
    # A real run past the seam: the reference plan offered and equal to the presented one (plan id and codes), one call
    # through the guard to the default seam with OK, the outcome COMPLETE, the end state (engine and CIM), the expected
    # diff, and the log: every record of a run in order, confirmed, matched, intent TEST_SEAM.
    $res = $R.Res
    Assert ($R.Ref.Offered -and @($R.Ref.Codes).Count -eq 0) "$What`: plano de referencia recusado ($(Get-RecCodes $R.Ref.Codes))"
    Assert ($null -ne $R.Presented -and [string]$R.Presented.PlanId -ceq [string]$R.Ref.PlanId -and (Get-RecCodes $R.Presented.Codes) -ceq (Get-RecCodes $R.Ref.Codes)) "$What`: plano apresentado diferente do de referencia"
    Assert (-not $res.Aborted -and -not $res.StoppedBy) "$What`: parou em $($res.Aborted)$($res.StoppedBy) ($(Get-RecCodes $res.RefusalCodes); revalidacao $(Get-RecCodes $res.RevalidationCodes))"
    Assert ($R.SeamCalls -eq 1 -and $res.SeamCalled -and [string]$res.SeamCode -ceq 'OK') "$What`: seam $($R.SeamCalls) chamada(s), codigo $($res.SeamCode) $($res.ExceptionType)"
    Assert ([string]$res.Outcome -ceq 'COMPLETE' -and $null -ne $res.After -and [string]$res.After.State -ceq $Want) "$What`: resultado $($res.Outcome), depois $(if ($null -ne $res.After) { $res.After.State })"
    Assert ($R.CimAfter -ceq $(if ($Want -ceq 'RUNNING') { 'Running' } else { 'Stopped' })) "$What`: CIM depois $($R.CimAfter)"
    $f = @(Get-DiffFields $res.Diff)
    Assert ($f -ccontains 'State' -and @($f | Where-Object { $stateFields -cnotcontains $_ }).Count -eq 0) "$What`: diff inesperado ($($f -join ','))"
    $recs = @(Read-E2ELog $res.LogFile)
    Assert ((Get-Types $recs) -ceq 'run-start,plan,before,confirmation,plan-check,intent,result,after,run-end') "$What`: registros do log $(Get-Types $recs)"
    $intent = @($recs | Where-Object { $_.type -eq 'intent' })[0]
    Assert ([string]$intent.seam -ceq $Seam) "$What`: intent seam $($intent.seam)"
    return "seam OK through the guard (1 call), $($res.Outcome), after $($res.After.State); diff $($f -join ','); plan id equal to recover plan's; log: 9 records, intent seam $Seam"
}
function Assert-RefusedBeforeSeam($R, [string]$Aborted, [string]$Code, [string]$What, [string]$Counter = 'Start') {
    # A refusal before anything is asked: the code the reference plan gives, no seam call, no log, no state change.
    $res = $R.Res
    Assert ([string]$res.Aborted -ceq $Aborted) "$What`: parou em '$($res.Aborted)', esperado $Aborted"
    Assert (@($res.RefusalCodes) -ccontains $Code) "$What`: codigos $(Get-RecCodes $res.RefusalCodes), esperado $Code"
    Assert ((Get-RecCodes $res.RefusalCodes) -ceq (Get-RecCodes $R.Ref.Codes)) "$What`: codigos $(Get-RecCodes $res.RefusalCodes) diferentes do plano de referencia $(Get-RecCodes $R.Ref.Codes)"
    Assert ($R.SeamCalls -eq 0 -and -not $res.SeamCalled -and $R.Calls.Count -eq 0) "$What`: seam ou pergunta alcancados"
    Assert (-not $res.LogCreated -and -not (Test-Path -LiteralPath $R.Log)) "$What`: log criado"
    Assert ($R.CimAfter -ceq $R.CimBefore) "$What`: estado mudou ($($R.CimBefore) -> $($R.CimAfter))"
    return "$Aborted [$(Get-RecCodes $res.RefusalCodes)] (the same codes as recover plan); 0 $($Counter.ToLowerInvariant()) seam calls, nothing asked, no log; state $($R.CimAfter) unchanged"
}
function Get-LogRunId([string]$Path) { return [string]@(Read-E2ELog $Path)[0].runId }

# ============================================================================================== leg A (standard user)
if ($Leg -eq 'A') {
    Case 'A-start-standard-user' {
        $p = New-RecProvider @('start')
        $r = Invoke-E2ERecStart 'start' $p 'REC-A-start.jsonl'
        $res = $r.Res
        Assert ($r.CimBefore -ceq 'Stopped') "servico nao estava parado ($($r.CimBefore))"
        if ($res.LogCreated) { $ctx.ALog = $r.Log; $ctx.ARunId = [string]$res.RunId; $ctx.AOutcome = [string]$res.Outcome }
        # Nothing may change, whatever the runner gives.
        Assert ($r.CimAfter -ceq 'Stopped' -and @($res.Diff).Count -eq 0) "estado mudou ($($r.CimBefore) -> $($r.CimAfter); diff $(@($res.Diff).Count))"
        if ($res.SeamCalled -and [string]$res.SeamCode -ceq 'ACCESS_DENIED') {
            Assert ($r.SeamCalls -eq 1 -and [string]$res.Outcome -ceq 'REFUSED') "seam $($r.SeamCalls) chamada(s), resultado $($res.Outcome)"
            Assert ([string]$r.Presented.PlanId -ceq [string]$r.Ref.PlanId -and [string]$r.Ref.Elevation -ceq 'NEEDS_ELEVATION') "plano apresentado ou elevacao divergente ($($r.Ref.Elevation))"
            $recs = @(Read-E2ELog $res.LogFile)
            Assert ((Get-Types $recs) -ceq 'run-start,plan,before,confirmation,plan-check,intent,result,after,run-end') "registros do log $(Get-Types $recs)"
            return "plan offered (elevation NEEDS_ELEVATION; plan id equal to recover plan's); the real seam through the guard (1 call) gave ACCESS_DENIED (Win32 5), outcome REFUSED; STOPPED before and after, empty diff; log: 9 records"
        }
        NotTested "the runner gave: stopped at $($res.Aborted) [$(Get-RecCodes $res.RefusalCodes)]; seam called $($res.SeamCalled) ($($r.SeamCalls)) code $($res.SeamCode) $($res.ExceptionType); outcome $($res.Outcome); nothing changed (STOPPED, empty diff)"
    }
    Case 'A-undo-own-refused-log' {
        if (-not $ctx.ContainsKey('ALog')) { return (NotTested 'no log of the start: the run stopped before it') }
        $r = Invoke-E2ERecUndo 'start' (New-RecProvider @('start')) $ctx.ALog $ctx.ARunId 'REC-A-undo-own.jsonl'
        $res = $r.Res
        Assert ([string]$res.Aborted -ceq 'UNDO_SOURCE_REFUSED' -and (Get-RecCodes $res.RefusalCodes) -ceq (Get-RecCodes $r.Ref.Codes)) "parou em $($res.Aborted) [$(Get-RecCodes $res.RefusalCodes)], referencia [$(Get-RecCodes $r.Ref.Codes)]"
        Assert ($r.SeamCalls -eq 0 -and -not $res.SeamCalled -and $r.Calls.Count -eq 0 -and -not $res.LogCreated -and $r.CimAfter -ceq 'Stopped') 'seam, pergunta ou log alcancados'
        "UNDO_SOURCE_REFUSED [$(Get-RecCodes $res.RefusalCodes)] (its own log, outcome $($ctx.AOutcome)); 0 stop seam calls, nothing asked, no log"
    }
    Case 'A-provenance-cross-leg' {
        NotTested 'leg A runs before leg B (Setup, A, B), so no log of leg B exists yet; leg B undoes the log of leg A instead (B-provenance-cross-leg)'
    }
    Case 'A-b8-integrity-levels' {
        NotTested 'optional, not done: no new seam; the install e2e step v3-x2-lock-across-identities already holds and tries the real B8 lock across the standard user and the elevated account'
    }
}

# ============================================================================================== leg B (elevated)
if ($Leg -eq 'B') {
    Case 'B-start' {
        $r = Invoke-E2ERecStart 'start' (New-RecProvider @('start')) 'REC-B-start.jsonl'
        Assert ($r.CimBefore -ceq 'Stopped') "servico nao estava parado ($($r.CimBefore))"
        $d = Assert-Completed $r 'TEST_SEAM' 'RUNNING' 'inicio'
        $ctx.StartLog = $r.Log; $ctx.StartRunId = [string]$r.Res.RunId
        $d
    }
    Case 'B-undo' {
        if (-not $ctx.ContainsKey('StartLog')) { throw 'sem o log do inicio' }
        $r = Invoke-E2ERecUndo 'start' (New-RecProvider @('start')) $ctx.StartLog $ctx.StartRunId 'REC-B-undo.jsonl'
        Assert-Completed $r 'TEST_SEAM' 'STOPPED' 'undo'
    }
    Case 'B-refuse-not-declared' {
        Assert-RefusedBeforeSeam (Invoke-E2ERecStart 'undecl' (New-RecProvider @('start')) 'REC-B-undecl.jsonl') 'RECOVERY_REFUSED' 'RECOVERY_NOT_DECLARED' 'nao declarado'
    }
    Case 'B-refuse-image-mismatch' {
        Assert-RefusedBeforeSeam (Invoke-E2ERecStart 'mism' (New-RecProvider @('mism') @{ mism = 'AtmRecE2E-other.exe' }) 'REC-B-mism.jsonl') 'RECOVERY_REFUSED' 'RECOVERY_IMAGE_MISMATCH' 'imagem divergente'
    }
    Case 'B-refuse-disabled' {
        Assert-RefusedBeforeSeam (Invoke-E2ERecStart 'dis' (New-RecProvider @('dis')) 'REC-B-dis.jsonl') 'RECOVERY_REFUSED' 'RECOVERY_START_MODE_DISABLED' 'desativado'
    }
    Case 'B-refuse-running' {
        # Started by this script (sc.exe, own name), refused by the engine, stopped again by this script.
        $n = $script:own.ByKey['run']
        $s = Invoke-OwnSc 'start' $n
        Assert ($s.Exit -eq 0 -and (Wait-OwnState $n 'Running')) "inicio pelo harness falhou (exit $($s.Exit))"
        try { $d = Assert-RefusedBeforeSeam (Invoke-E2ERecStart 'run' (New-RecProvider @('run')) 'REC-B-run.jsonl') 'RECOVERY_REFUSED' 'RECOVERY_NOT_STOPPED' 'ja em execucao' }
        finally { $t = Invoke-OwnSc 'stop' $n; $null = $t; $stopped = Wait-OwnState $n 'Stopped' }
        Assert $stopped 'parada pelo harness falhou'
        "$d; started and stopped again by this script (Invoke-OwnSc, own name)"
    }
    Case 'B-dep-undeclared' {
        Assert-RefusedBeforeSeam (Invoke-E2ERecStart 'y' (New-RecProvider @('y')) 'REC-B-dep-undecl.jsonl') 'RECOVERY_REFUSED' 'RECOVERY_DEPENDENCY_STOPPED' 'dependencia parada nao declarada'
    }
    Case 'B-dep-start-y-x-stopped' {
        $x = $script:own.ByKey['x']
        Assert ((Get-OwnState $x) -ceq 'Stopped') 'x nao estava parado'
        $r = Invoke-E2ERecStart 'y' (New-RecProvider @('x', 'y')) 'REC-B-dep-y1.jsonl'
        $stoppedDep = @($r.Ref.DeclaredDependencyStopped)
        $d = Assert-Completed $r 'TEST_SEAM' 'RUNNING' 'inicio de y'
        $xAfter = Get-OwnState $x
        $summary.dependency.declaredDependencyStoppedInPlan = ($stoppedDep -ccontains $x)
        $summary.dependency.scmStartedX = ($xAfter -ceq 'Running')
        $summary.dependency.xAfterStartOfY = $xAfter
        $ctx.Y1Log = $r.Log; $ctx.Y1RunId = [string]$r.Res.RunId
        "$d; x STOPPED and declared (the plan shows it as a stopped declared dependency: $($stoppedDep -ccontains $x)); measured: x is $xAfter after the start of y (the SCM started it: $($xAfter -ceq 'Running'))"
    }
    Case 'B-dep-undo-y' {
        if (-not $ctx.ContainsKey('Y1Log')) { throw 'sem o log do inicio de y' }
        $r = Invoke-E2ERecUndo 'y' (New-RecProvider @('x', 'y')) $ctx.Y1Log $ctx.Y1RunId 'REC-B-dep-y1-undo.jsonl'
        $d = Assert-Completed $r 'TEST_SEAM' 'STOPPED' 'undo de y'
        $xAfter = Get-OwnState $script:own.ByKey['x']
        $summary.dependency.xAfterUndoOfY = $xAfter
        "$d; measured: x is $xAfter after the undo of y (the undo stops y only, never its dependency)"
    }
    Case 'B-dep-start-x' {
        # For a start run of x itself: x is first stopped by this script if the SCM started it (sc.exe, own name).
        $x = $script:own.ByKey['x']
        Assert ((Get-OwnState $script:own.ByKey['y']) -ceq 'Stopped') 'y nao estava parado'
        $pre = ''
        if ((Get-OwnState $x) -cne 'Stopped') { $t = Invoke-OwnSc 'stop' $x; Assert ($t.Exit -eq 0 -and (Wait-OwnState $x 'Stopped')) "parada de x pelo harness falhou (exit $($t.Exit))"; $pre = 'x first stopped by this script (Invoke-OwnSc, own name); ' }
        $r = Invoke-E2ERecStart 'x' (New-RecProvider @('x', 'y')) 'REC-B-dep-x.jsonl'
        $d = Assert-Completed $r 'TEST_SEAM' 'RUNNING' 'inicio de x'
        $ctx.XLog = $r.Log; $ctx.XRunId = [string]$r.Res.RunId
        "$pre$d"
    }
    Case 'B-dep-start-y-x-running' {
        if (-not $ctx.ContainsKey('XLog')) { throw 'sem o log do inicio de x' }
        $r = Invoke-E2ERecStart 'y' (New-RecProvider @('x', 'y')) 'REC-B-dep-y2.jsonl'
        $d = Assert-Completed $r 'TEST_SEAM' 'RUNNING' 'inicio de y com x em execucao'
        $ctx.Y2Log = $r.Log; $ctx.Y2RunId = [string]$r.Res.RunId
        $d
    }
    Case 'B-dep-undo-x-y-running' {
        # R3's own criterion refuses before the seam: a dependent that is not STOPPED (UNDO_DEPENDENT_ACTIVE).
        if (-not $ctx.ContainsKey('Y2Log')) { throw 'sem o log do inicio de y' }
        Assert ((Get-OwnState $script:own.ByKey['y']) -ceq 'Running') 'y nao esta em execucao'
        $r = Invoke-E2ERecUndo 'x' (New-RecProvider @('x', 'y')) $ctx.XLog $ctx.XRunId 'REC-B-dep-x-undo-refused.jsonl'
        $res = $r.Res
        Assert ([string]$res.Aborted -ceq 'UNDO_REFUSED' -and @($res.RefusalCodes) -ccontains 'UNDO_DEPENDENT_ACTIVE') "parou em $($res.Aborted) [$(Get-RecCodes $res.RefusalCodes)]"
        Assert ((Get-RecCodes $res.RefusalCodes) -ceq (Get-RecCodes $r.Ref.Codes)) "codigos diferentes do plano inverso de referencia [$(Get-RecCodes $r.Ref.Codes)]"
        Assert ($r.SeamCalls -eq 0 -and -not $res.SeamCalled -and $r.Calls.Count -eq 0 -and -not $res.LogCreated) 'seam, pergunta ou log alcancados'
        Assert ($r.CimAfter -ceq 'Running' -and (Get-OwnState $script:own.ByKey['y']) -ceq 'Running') 'x ou y mudou'
        $summary.dependency.undoOfXWithYRunning = "UNDO_REFUSED [$(Get-RecCodes $res.RefusalCodes)]"
        "UNDO_REFUSED [$(Get-RecCodes $res.RefusalCodes)] before anything is asked (the same codes as the inverse plan); 0 stop seam calls; x and y still RUNNING (no cascade)"
    }
    Case 'B-dep-seam-dependent-services-running' {
        NotTested 'the stop seam is never reached with a running dependent: R3 refuses first (UNDO_DEPENDENT_ACTIVE, read from the capture, B-dep-undo-x-y-running), so the seam code DEPENDENT_SERVICES_RUNNING cannot be produced through the engine; calling the wrapper directly would not be the engine'
    }
    Case 'B-dep-undo-y-2' {
        if (-not $ctx.ContainsKey('Y2Log')) { throw 'sem o log do inicio de y' }
        Assert-Completed (Invoke-E2ERecUndo 'y' (New-RecProvider @('x', 'y')) $ctx.Y2Log $ctx.Y2RunId 'REC-B-dep-y2-undo.jsonl') 'TEST_SEAM' 'STOPPED' 'undo de y'
    }
    Case 'B-dep-undo-x' {
        if (-not $ctx.ContainsKey('XLog')) { throw 'sem o log do inicio de x' }
        Assert-Completed (Invoke-E2ERecUndo 'x' (New-RecProvider @('x', 'y')) $ctx.XLog $ctx.XRunId 'REC-B-dep-x-undo.jsonl') 'TEST_SEAM' 'STOPPED' 'undo de x'
    }
    Case 'B-provenance-cross-leg' {
        # The log leg A wrote (its own root, owned by the standard user): readable here (Administrators), refused by the
        # provenance check before its content is read.
        $aLog = Join-Path (Join-Path $env:SystemDrive ('ATM-E2E-REC-A-' + $script:own.Short)) 'log\REC-A-start.jsonl'
        if (-not [IO.File]::Exists($aLog)) { return (NotTested 'no log of leg A (leg A did not run, or stopped before its log)') }
        $r = Invoke-E2ERecUndo 'start' (New-RecProvider @('start')) $aLog (Get-LogRunId $aLog) 'REC-B-undo-leg-A-log.jsonl'
        $res = $r.Res
        Assert ([string]$res.Aborted -ceq 'UNDO_SOURCE_REFUSED' -and (Get-RecCodes $res.RefusalCodes) -ceq (Get-RecCodes $r.Ref.Codes)) "parou em $($res.Aborted) [$(Get-RecCodes $res.RefusalCodes)], referencia [$(Get-RecCodes $r.Ref.Codes)]"
        Assert (@($res.RefusalCodes) -ccontains 'UNDO_SOURCE_PROVENANCE') "codigos $(Get-RecCodes $res.RefusalCodes), esperado UNDO_SOURCE_PROVENANCE (o dono do log e a conta da perna A)"
        Assert ($r.SeamCalls -eq 0 -and -not $res.SeamCalled -and $r.Calls.Count -eq 0 -and -not $res.LogCreated) 'seam, pergunta ou log alcancados'
        "the undo of the log leg A created: UNDO_SOURCE_REFUSED [$(Get-RecCodes $res.RefusalCodes)]; 0 stop seam calls, nothing asked, no log"
    }
    Case 'B-final-stop' {
        # Every own service ends STOPPED: any that is not is stopped by this script, by exact name checked as its own
        # (dependents first). None is removed.
        $byScript = New-Object System.Collections.Generic.List[string]
        foreach ($k in @('y', 'run', 'x', 'start', 'mism', 'dis', 'undecl')) {
            $n = $script:own.ByKey[$k]
            $s = Get-OwnService $n
            Assert ($null -ne $s -and [string]::Equals(([string]$s.PathName).Trim('"'), $script:own.ImagePath, [StringComparison]::OrdinalIgnoreCase)) "servico $k ausente ou nao e desta execucao"
            if ([string]$s.State -cne 'Stopped') { $t = Invoke-OwnSc 'stop' $n; $null = $t; $byScript.Add($k); $null = Wait-OwnState $n 'Stopped' }
        }
        $notStopped = @($keys | Where-Object { (Get-OwnState $script:own.ByKey[$_]) -cne 'Stopped' })
        $summary.dependency.stoppedByHarnessAtEnd = $byScript.ToArray()
        Assert ($notStopped.Count -eq 0) "servicos nao parados no fim: $($notStopped -join ',')"
        "all 7 own services STOPPED; stopped by this script at the end: $(if ($byScript.Count) { $byScript -join ',' } else { 'none' }); none removed (left registered)"
    }
}

# ---------------------------------------------------------------------------------------------- after
Case 'installed-after' {
    foreach ($g in $loadedGates) { Assert ($loaded[$g] -eq $false) "trava $g carregada da instalacao nao era `$false" }
    foreach ($g in @($loadedGates | Where-Object { $_ -cne 'AtmRecoveryEnabled' })) { Assert ((Get-Variable -Name $g -Scope Script -ValueOnly) -eq $false) "trava $g aberta neste processo" }
    $bad = @(Get-InstalledGateProblems)
    Assert ($bad.Count -eq 0) "travas instaladas alteradas: $($bad -join ',')"
    $v = Invoke-InstalledVerify
    Assert ($v -eq 0) "agent-temp verify exit $v"
    $after = Get-InstallSnapshot
    $diff = @(@($ctx.InstallBefore.Keys | Where-Object { -not $after.ContainsKey($_) -or $after[$_] -cne $ctx.InstallBefore[$_] }) + @($after.Keys | Where-Object { -not $ctx.InstallBefore.ContainsKey($_) }))
    Assert ($diff.Count -eq 0) "instalacao alterada: $($diff.Count) entrada(s)"
    Assert ($script:recGuard.Refused -eq 0) "o envoltorio recusou $($script:recGuard.Refused) nome(s)"
    'installed files identical by SHA-256 to before the runs; verify 0; eight installed gates still $false (recovery opened only in this process memory); the guard refused no name'
}
exit (Write-Summary)
