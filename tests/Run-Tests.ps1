<#
  AgentTempManager automated tests. Self-contained (no Pester), runs on Windows PowerShell 5.1 and PowerShell 7.
  Every destructive operation runs ONLY inside an isolated sandbox created by this script under
  %TEMP%\atm-tests-<random> (outside every real <TEMP>\claude base). Real Claude Code temp files are never
  written; tests that touch the real machine are read-only.
  Usage: powershell -NoProfile -ExecutionPolicy Bypass -File tests\Run-Tests.ps1 [-SkipHeavy] [-ReportFile <path>]
         [-Only '<Area> :: <name pattern>', ...] [-Except '<Area> :: <name pattern>', ...]
  -Only (FINAL-A-S): runs only the cases whose "<Area> :: <name>" matches one of the wildcard patterns. -Except
  (FINAL-B): leaves out the cases that match one of its patterns. Every setup step outside the cases still runs; a case
  left out is neither run nor counted (never a PASS), the summary says it is a subset and names each case left out by
  -Except, and a pattern (of either list) that matches no case is a FAIL.
#>
param([switch]$SkipHeavy, [string]$ReportFile, [int]$HeavyFiles = 200000, [string[]]$Only = @(), [string[]]$Except = @())

$ErrorActionPreference = 'Stop'
# Native and child-process output (Git, the CLI, which writes UTF-8) is decoded as UTF-8, like the CLI itself does:
# with a redirected console the code page is the OEM one (850 on pt-BR Windows) and a non-ASCII profile path or text
# would be misread (P5-B, local FAIL matrix). Process-level only; restored at the end.
$prevOutputEncoding = $null
try { $prevOutputEncoding = [Console]::OutputEncoding; [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { $null = $_ }
# Assertions on rendered text are written for pt-BR; dedicated i18n tests switch languages explicitly.
$env:ATM_LANG = 'pt-BR'
$testsDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$srcDir = Join-Path (Split-Path -Parent $testsDir) 'src'
. (Join-Path $srcDir 'lib\Engine.Audit.ps1')
. (Join-Path $srcDir 'providers\ClaudeCode.ps1')
. (Join-Path $srcDir 'lib\Engine.Clean.ps1')
. (Join-Path $srcDir 'lib\Engine.Diagnose.ps1')
. (Join-Path $srcDir 'lib\Report.ps1')
. (Join-Path $srcDir 'lib\Tui.ps1')
. (Join-Path (Split-Path -Parent $testsDir) 'install\InstallCommon.ps1')
Initialize-AtmNative -LibDir (Join-Path $srcDir 'lib')
$cfgDir = Join-Path $srcDir 'config'
# The shipped release gate disables real deletion. The suite enables it ONLY inside this process so that the
# deletion path can be exercised against the isolated sandbox; dedicated tests restore and verify the default.
$shippedDeletionGate = $script:AtmRealDeletionEnabled
$script:AtmRealDeletionEnabled = $true

$me = Get-AtmCurrentIdentity
$results = New-Object System.Collections.Generic.List[object]
$cleanupActions = New-Object System.Collections.Generic.List[scriptblock]
$sandbox = Get-AtmNormalizedPath (Join-Path ([IO.Path]::GetTempPath()) ('atm-tests-' + [guid]::NewGuid().ToString('N').Substring(0, 8)))
[void][IO.Directory]::CreateDirectory($sandbox)
# The NTFS owner that new files actually get on this machine: the user SID for a standard account, the
# Administrators group on an elevated Windows Server runner (CI). Test profiles and the test identity use it, so the
# engine's owner gate (owner == profile SID) is exercised identically everywhere.
$testOwnerSid = (Get-Acl -LiteralPath $sandbox).GetOwner([Security.Principal.SecurityIdentifier]).Value

function Get-SandboxAclTargetProblems {
    # The only directory whose ACL the suite may replace: a freshly created, empty, plain (non-reparse) directory named
    # atm-tests-<8 hex> directly inside the canonical temporary root, with no reparse point on any ancestor.
    param([string]$Path, [string]$TempRoot)
    $problems = New-Object System.Collections.Generic.List[string]
    $root = Get-AtmNormalizedPath $TempRoot
    $canon = Get-AtmNormalizedPath $Path
    if (-not $root -or -not $canon) { $problems.Add('caminho nao normalizavel'); return $problems.ToArray() }
    if (-not [string]::Equals([IO.Path]::GetDirectoryName($canon), $root.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) { $problems.Add('fora da raiz temporaria de testes') }
    if ([IO.Path]::GetFileName($canon) -cnotmatch '^atm-tests-[0-9a-f]{8}$') { $problems.Add('nome inesperado') }
    if (-not [IO.Directory]::Exists($canon)) { $problems.Add('inexistente'); return $problems.ToArray() }
    $d = New-Object IO.DirectoryInfo($canon)
    while ($d) {
        if (($d.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { $problems.Add("reparse point: $($d.FullName)") }
        $d = $d.Parent
    }
    if (@([IO.Directory]::EnumerateFileSystemEntries($canon)).Count -ne 0) { $problems.Add('nao vazio') }
    return $problems.ToArray()
}

function Get-SandboxAclResultProblems {
    # Expected result: protected DACL (nothing inherited from ancestors), owner = test owner, and exactly two explicit
    # allow entries, FullControl for SYSTEM and Administrators, inherited by subdirectories and files.
    param([string]$Path, [string]$OwnerSid)
    $problems = New-Object System.Collections.Generic.List[string]
    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) { $problems.Add('heranca ainda ativa') }
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $OwnerSid) { $problems.Add('owner inesperado') }
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    $sids = @($rules | ForEach-Object { $_.IdentityReference.Value } | Sort-Object)
    if (($sids -join ',') -ne 'S-1-5-18,S-1-5-32-544') { $problems.Add("entradas inesperadas: $($sids -join ',')") }
    foreach ($r in $rules) {
        if ($r.IsInherited -or $r.AccessControlType -ne 'Allow' -or $r.FileSystemRights -ne 'FullControl' -or
            $r.InheritanceFlags -ne ([Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit')) { $problems.Add("entrada inesperada: $($r.IdentityReference.Value)") }
    }
    return $problems.ToArray()
}

function Set-SandboxSingleOwnerAcl {
    # The whole DACL is replaced by an exact descriptor (protected; SYSTEM and Administrators, full control, inherited
    # by subfolders and files). Only the access section is written; the owner is unchanged. icacls is not used here:
    # its /inheritance:r was observed to copy the inherited entries instead of removing them.
    param([string]$Path)
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetSecurityDescriptorSddlForm('D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)', [Security.AccessControl.AccessControlSections]::Access)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

if ($testOwnerSid -ne $me.Sid) {
    # Elevated session (CI runner): new files are owned by Administrators while the sandbox inherits an allow ACE for
    # the user SID, which the engine rightly reports as a third-party writer. The sandbox (and only it, after the guard
    # above) gets the ACL of a single-owner profile: SYSTEM + Administrators. Ancestors are never touched.
    $bad = @(Get-SandboxAclTargetProblems -Path $sandbox -TempRoot ([IO.Path]::GetTempPath()))
    if ($bad.Count) { throw "sandbox recusado para ajuste de ACL: $($bad -join '; ')" }
    $parentSddl = (Get-Acl -LiteralPath ([IO.Path]::GetDirectoryName($sandbox))).Sddl
    Set-SandboxSingleOwnerAcl -Path $sandbox
    $bad = @(Get-SandboxAclResultProblems -Path $sandbox -OwnerSid $testOwnerSid)
    if ($bad.Count) { throw "ACL do sandbox diferente do esperado: $($bad -join '; ')" }
    if ((Get-Acl -LiteralPath ([IO.Path]::GetDirectoryName($sandbox))).Sddl -ne $parentSddl) { throw 'ACL da raiz temporaria foi alterada' }
    $script:sandboxAclAdjusted = $true
} else { $script:sandboxAclAdjusted = $false }
$testIdentity = [pscustomobject]@{ Sid = $testOwnerSid; Name = $me.Name; IsAdmin = $me.IsAdmin }
$nowFuture = [datetime]::UtcNow.AddDays(10)      # everything created now looks 10 days old
$uni = 'Usu' + [char]0x00E1 + 'rio Teste ' + [char]0x00E7 + ' ' + [char]0x65E5 + [char]0x672C

function Assert-True { param($Cond, [string]$Msg) if (-not $Cond) { throw "ASSERT: $Msg" } }
function Assert-Eq { param($A, $B, [string]$Msg) if ($A -ne $B) { throw "ASSERT: $Msg (esperado '$B', obtido '$A')" } }

$script:notSelected = 0
$script:onlyHits = @{}
$script:exceptHits = @{}
$script:excludedNames = New-Object System.Collections.Generic.List[string]
# FINAL-B (artifact privacy): case details reach the console and the report with this machine's identifiers replaced
# by placeholders (<temp>, <profile>, <account>, <machine>, <sid>...); the structure of each message is kept.
. (Join-Path (Split-Path -Parent $testsDir) 'tools\AtmArtifactSanitizer.ps1')
$script:safeIds = Get-AtmArtifactIdentifiers
function Test-Case {
    param([string]$Area, [string]$Name, [scriptblock]$Body)
    if ($Only.Count -gt 0) {
        $sel = @($Only | Where-Object { ('{0} :: {1}' -f $Area, $Name) -like $_ })
        if ($sel.Count -eq 0) { $script:notSelected++; return }
        foreach ($o in $sel) { $script:onlyHits[$o] = $true }
    }
    if ($Except.Count -gt 0) {
        $ex = @($Except | Where-Object { ('{0} :: {1}' -f $Area, $Name) -like $_ })
        if ($ex.Count -gt 0) { foreach ($o in $ex) { $script:exceptHits[$o] = $true }; $script:notSelected++; $script:excludedNames.Add(('{0} :: {1}' -f $Area, $Name)); return }
    }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $status = 'PASS'; $msg = ''
    $script:caseNote = $null; $script:caseSkipped = $false
    try { $null = & $Body 6>$null } catch { $status = 'FAIL'; $msg = $_.Exception.Message + ' @' + $_.InvocationInfo.ScriptLineNumber }
    if ($status -eq 'PASS' -and $script:caseSkipped) { $status = 'NAO_TESTADO' }
    if (-not $msg -and $script:caseNote) { $msg = $script:caseNote }
    $msg = ConvertTo-AtmArtifactSafeText -Text $msg -Identifiers $script:safeIds
    $sw.Stop()
    $results.Add([pscustomobject]@{ Area = $Area; Test = $Name; Result = $status; Ms = $sw.ElapsedMilliseconds; Detail = $msg })
    $color = $(if ($status -eq 'PASS') { 'Green' } elseif ($status -eq 'NAO_TESTADO') { 'Yellow' } else { 'Red' })
    Write-Host ("[{0}] {1} :: {2} ({3} ms) {4}" -f $status, $Area, $Name, $sw.ElapsedMilliseconds, $msg) -ForegroundColor $color
}

# FINAL-B-S: a child process of the suite runs inside its own Job Object (AgentTempManager.AtmJobRunner, the Git
# runner's executor): the job is created and its limits set and read back before the process exists, the process is
# created inside it (never started outside and associated later), cmd.exe by its absolute path, the environment given
# explicitly. On the deadline, or when a member still holds the output pipes after the child ended, only the job's
# members are terminated (TerminateJobObject; KILL_ON_JOB_CLOSE when the job closes). No PID is ever looked up and no
# process outside the job can be signalled. Bound: the deadline plus the runner's fixed waits (at most about 22.5 s:
# 10 s for the child after termination, 2.5 s for the pipes, 10 s for the readers after the job is terminated); bytes
# kept per stream are capped (truncation declared). A runner failure is a sanitized CHILD_RUNNER_<code>, raised
# before anything runs when the job or the process could not be set up.
function ConvertFrom-AtmTestJobResult {
    param($Result)
    if (-not $Result.Started) { throw ('CHILD_RUNNER_' + $(if ($Result.Error -cmatch '^[A-Z_]+$') { $Result.Error } else { 'NOT_STARTED' })) }
    if ($Result.TimedOut -and -not $Result.JobTerminated) { throw 'CHILD_RUNNER_JOB_TERMINATE_FAILED' }
    $truncated = ($Result.OutputTruncated -or $Result.ErrorTruncated)
    if ($Result.TimedOut) { $text = 'CHILD_TIMEOUT' }
    else {
        $raw = [Text.Encoding]::UTF8.GetString($Result.Output) + "`n" + [Text.Encoding]::UTF8.GetString($Result.ErrorOutput)
        $text = (@($raw -split "`r?`n" | Where-Object { $_ -ne '' }) -join ' ')
    }
    if ($truncated) { $text += ' [SAIDA_TRUNCADA]' }
    [pscustomobject]@{ Exit = $(if ($Result.TimedOut) { $null } else { $Result.ExitCode }); TimedOut = [bool]$Result.TimedOut; Text = $text; Ms = [long]$Result.ElapsedMs; Truncated = [bool]$truncated; JobTerminated = [bool]$Result.JobTerminated }
}
function Invoke-AtmTestChild {
    param([string]$CommandLine, [int]$TimeoutSec = 180, [hashtable]$Environment = $null, [int]$MaxOutputBytes = 4194304, [int]$ActiveProcessLimit = 64)
    $cmdExe = Join-Path $env:SystemRoot 'System32\cmd.exe'
    # -Environment: the child gets exactly these variables; otherwise this process's environment.
    $map = $Environment
    if ($null -eq $map) { $map = @{}; foreach ($k in [Environment]::GetEnvironmentVariables().Keys) { $map[[string]$k] = [Environment]::GetEnvironmentVariable([string]$k) } }
    $pairs = [string[]]@($map.Keys | Where-Object { $null -ne $map[$_] -and -not ([string]$_).StartsWith('=') } | Sort-Object | ForEach-Object { '{0}={1}' -f $_, $map[$_] })
    # The working directory the previous Process.Start children inherited (an empty string is refused by CreateProcess).
    $wd = [Environment]::CurrentDirectory
    try { $r = [AgentTempManager.AtmJobRunner]::Run($cmdExe, ('cmd.exe /s /c "' + $CommandLine + '"'), $wd, $pairs, [int]($TimeoutSec * 1000), $MaxOutputBytes, [long]2147483648, $ActiveProcessLimit) }
    catch { throw ('CHILD_RUNNER_' + $(if ($_.Exception.GetBaseException() -is [ArgumentOutOfRangeException]) { 'INVALID_LIMITS' } else { 'EXCEPTION' })) }
    return (ConvertFrom-AtmTestJobResult -Result $r)
}

# Test-only FSCTL helper (FINAL-A M-1, FINAL-B F-10): turns an existing empty folder into a junction through another
# handle opened with FILE_WRITE_ATTRIBUTES. Used on sandbox fixtures only.
function Initialize-AtmTestReparse {
    if (-not ('AtmTestReparse' -as [type])) {
        Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices; using Microsoft.Win32.SafeHandles; using System.Text;
public static class AtmTestReparse {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern SafeFileHandle CreateFileW(string n, uint a, uint s, IntPtr sa, uint c, uint f, IntPtr t);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool DeviceIoControl(SafeFileHandle h, uint code, byte[] inb, int inl, IntPtr outb, int outl, out int ret, IntPtr ov);
  // Test-only: sets a mount-point (junction) reparse point on an existing empty folder, opened with FILE_WRITE_ATTRIBUTES.
  public static string SetJunction(string dir, string target) {
using (SafeFileHandle h = CreateFileW(dir, 0x100, 7, IntPtr.Zero, 3, 0x02000000 | 0x00200000, IntPtr.Zero)) {
  if (h.IsInvalid) return "OPEN_FAIL " + Marshal.GetLastWin32Error();
  byte[] s = Encoding.Unicode.GetBytes("\\??\\" + target); byte[] p = Encoding.Unicode.GetBytes(target);
  int dataLen = 8 + s.Length + 2 + p.Length + 2; byte[] b = new byte[8 + dataLen];
  BitConverter.GetBytes(0xA0000003u).CopyTo(b, 0); BitConverter.GetBytes((ushort)dataLen).CopyTo(b, 4);
  BitConverter.GetBytes((ushort)0).CopyTo(b, 8); BitConverter.GetBytes((ushort)s.Length).CopyTo(b, 10);
  BitConverter.GetBytes((ushort)(s.Length + 2)).CopyTo(b, 12); BitConverter.GetBytes((ushort)p.Length).CopyTo(b, 14);
  s.CopyTo(b, 16); p.CopyTo(b, 16 + s.Length + 2);
  int r; bool ok = DeviceIoControl(h, 0x000900A4, b, b.Length, IntPtr.Zero, 0, out r, IntPtr.Zero);
  return ok ? "SET_OK" : "SET_FAIL " + Marshal.GetLastWin32Error();
}
  }
}
'@
    }
}

$script:profileCounter = 0
function New-TestProfile {
    param([string]$Name, [string]$Sid = $testOwnerSid, [switch]$NoConfig)
    $script:profileCounter++
    $root = Join-Path $sandbox ("Users{0}\{1}" -f $script:profileCounter, $Name)
    $temp = Join-Path $root 'AppData\Local\Temp'
    [void][IO.Directory]::CreateDirectory((Join-Path $temp 'claude'))
    $cfg = Join-Path $root '.claude'
    if (-not $NoConfig) { [void][IO.Directory]::CreateDirectory((Join-Path $cfg 'sessions')); [void][IO.Directory]::CreateDirectory((Join-Path $cfg 'projects')) }
    [pscustomobject]@{
        Sid = $Sid; UserName = "TEST\$Name"; ProfilePath = $root; Loaded = $true; Special = $false; Origin = 'Test'; EnvStatus = 'OK'
        TempCandidates = @([pscustomobject]@{ TempPath = $temp; Source = 'test' }); EnvValues = @{}; EnvKnown = $true; Notes = @()
    }
}

function Get-Base { param([Alias('Profile')]$ProfileInfo) return (Join-Path $ProfileInfo.TempCandidates[0].TempPath 'claude') }

function New-TestRoot {
    param([Alias('Profile')]$ProfileInfo, [string]$Slug = 'C--work-proj', [string]$Uuid = ([guid]::NewGuid().ToString()), [hashtable]$Files = @{ 'a.txt' = 100; 'sub\b.bin' = 2048 })
    $p = Join-Path (Join-Path (Get-Base $ProfileInfo) $Slug) $Uuid
    [void][IO.Directory]::CreateDirectory($p)
    foreach ($k in $Files.Keys) {
        $f = Join-Path $p $k
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($f))
        [IO.File]::WriteAllBytes($f, (New-Object byte[] ([int]$Files[$k])))
    }
    return $p
}

function New-Procs {
    # Fully inspectable synthetic process list (coverage complete).
    param([object[]]$Extra = @())
    $l = @([pscustomobject]@{ ProcessId = 1; Name = 'idle.exe'; ParentProcessId = 0; CommandLine = 'idle.exe'; CreationDate = (Get-Date).AddHours(-1) })
    return @($l + $Extra)
}

function Inv {
    param([object[]]$Profiles, $Procs = (New-Procs), $Identity = $testIdentity, [string]$OnlyRootPath)
    $a = Get-InvArgs -Profiles $Profiles -Procs $Procs -Identity $Identity
    if ($OnlyRootPath) { $a['OnlyRootPath'] = $OnlyRootPath }
    return Invoke-AtmInventory @a
}

function Get-InvArgs {
    param([object[]]$Profiles, $Procs = (New-Procs), $Identity = $testIdentity)
    $a = @{ ProfilesOverride = $Profiles; NowUtc = $nowFuture; IdentityOverride = $Identity; NoProgress = $true; ConfigDir = $cfgDir }
    if ($null -ne $Procs) { $a['ProcessesOverride'] = $Procs }
    return $a
}

function Find-Part { param($Inv, [string]$Path) return @($Inv.Partitions | Where-Object { [string]::Equals($_.Path, $Path, [StringComparison]::OrdinalIgnoreCase) -and $_.Kind -ne 'BaseLooseFiles' })[0] }

function Get-StableTreeListing {
    # NTFS updates directory timestamps lazily after recent creations: wait until the listing is stable.
    param([string]$Path)
    $a = Get-TreeListing $Path
    for ($w = 0; $w -lt 20; $w++) { Start-Sleep -Milliseconds 500; $b = Get-TreeListing $Path; if ($b -eq $a) { break }; $a = $b }
    return $a
}

function Get-TreeListing {
    param([string]$Path)
    $out = New-Object System.Collections.Generic.List[string]
    $stack = New-Object System.Collections.Generic.Stack[string]; $stack.Push($Path)
    while ($stack.Count -gt 0) {
        $d = $stack.Pop()
        foreach ($e in (New-Object IO.DirectoryInfo($d)).GetFileSystemInfos()) {
            $len = $(if ($e -is [IO.FileInfo]) { $e.Length } else { -1 })
            $out.Add(('{0}|{1}|{2}|{3}' -f $e.FullName, $len, $e.LastWriteTimeUtc.Ticks, [int]$e.Attributes))
            if (($e.Attributes -band [IO.FileAttributes]::Directory) -and -not ($e.Attributes -band [IO.FileAttributes]::ReparsePoint)) { $stack.Push($e.FullName) }
        }
    }
    return (($out | Sort-Object) -join "`n")
}

function New-Junction {
    param([string]$Link, [string]$Target)
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Link))
    $o = cmd /c mklink /J "`"$Link`"" "`"$Target`"" 2>&1
    if (-not [IO.Directory]::Exists($Link)) { throw "mklink falhou: $o" }
    $cleanupActions.Add([scriptblock]::Create("try { [IO.Directory]::Delete('$($Link.Replace("'", "''"))', `$false) } catch { }"))
}

function Confirm-Correct { param($phrase) return $phrase }
$presenter = { param($v, $r, $i) Show-AtmCleanPlan -Verified $v -Rejected $r -Inventory $i }

Write-Host "PowerShell $($PSVersionTable.PSVersion) | sandbox: $sandbox | usuario: $($me.Name) | admin: $($me.IsAdmin)" -ForegroundColor Cyan

try {
    # ------------------------------------------------------------------ basic / empty
    Test-Case 'Colecoes vazias' 'Inventario sem perfis' {
        $i = Inv -Profiles @()
        Assert-Eq @($i.Partitions).Count 0 'sem particoes'
        Assert-Eq @($i.Bases).Count 0 'sem bases'
        Show-AtmAudit -Inventory $i
    }
    Test-Case 'Colecoes vazias' 'Perfil sem base claude e lista de processos vazia' {
        $p = New-TestProfile 'vazio'
        [IO.Directory]::Delete((Get-Base $p))
        $i = Inv -Profiles @($p) -Procs @()
        Assert-Eq @($i.Partitions).Count 0 'sem particoes'
        Assert-Eq $i.ProfileBaseStatus[$p.Sid + '|' + $p.ProfilePath][0].Status 'NOT_FOUND' 'base inexistente'
        Assert-Eq $i.Snapshot.Total 0 'processos vazios'
        Show-AtmAudit -Inventory $i
        $rows = Invoke-AtmPreview -Inventory $i
        Show-AtmPreview -Inventory $i -Rows $rows
    }
    Test-Case 'Colecoes vazias' 'Base claude vazia' {
        $p = New-TestProfile 'basevazia'
        $i = Inv -Profiles @($p)
        Assert-Eq @($i.Partitions).Count 0 'sem particoes'
        Assert-Eq @($i.Bases)[0].Status 'OK' 'base auditada'
    }

    # ------------------------------------------------------------------ unicode / spaces
    Test-Case 'Unicode e espacos' 'Perfil e arquivos com espacos/Unicode' {
        $p = New-TestProfile $uni
        $r = New-TestRoot -ProfileInfo $p -Files @{ ('arquivo com espa' + [char]0x00E7 + 'o ' + [char]0x00E3 + '.txt') = 10; ('pasta ' + [char]0x65E5 + '\x y.bin') = 20 }
        $i = Inv -Profiles @($p)
        $x = Find-Part $i $r
        Assert-True $x 'particao encontrada'
        Assert-Eq $x.Files 2 'arquivos'
        Assert-Eq $x.Bytes 30 'bytes'
        Assert-True $x.MeasurementComplete 'medicao completa'
        Assert-Eq $x.Class 'ORPHAN_SUSPECTED' 'classe'
        Show-AtmAudit -Inventory $i
    }

    # ------------------------------------------------------------------ classification
    Test-Case 'Classificacao' 'RECENT por NewestWriteTime < 72h' {
        $p = New-TestProfile 'recent'
        $r = New-TestRoot -ProfileInfo $p
        [IO.File]::SetLastWriteTimeUtc((Join-Path $r 'sub\b.bin'), $nowFuture.AddHours(-1))
        $x = Find-Part (Inv -Profiles @($p)) $r
        Assert-Eq $x.Class 'RECENT' 'classe'
    }
    Test-Case 'Classificacao' 'Idade > 72h sem evidencias = ORPHAN_SUSPECTED (somente informativo)' {
        $p = New-TestProfile 'old'
        $r = New-TestRoot -ProfileInfo $p
        $i = Inv -Profiles @($p)
        Assert-Eq (Find-Part $i $r).Class 'ORPHAN_SUSPECTED' 'classe'
    }
    Test-Case 'Classificacao' 'Relogio adiantado (CLOCK_SKEW) bloqueia' {
        $p = New-TestProfile 'skew'
        $r = New-TestRoot -ProfileInfo $p
        [IO.File]::SetLastWriteTimeUtc((Join-Path $r 'a.txt'), $nowFuture.AddDays(1))
        $i = Inv -Profiles @($p)
        $x = Find-Part $i $r
        Assert-True ($x.Flags -contains 'CLOCK_SKEW') 'flag'
        Assert-Eq $x.Class 'RECENT' 'classe conservadora'
    }
    Test-Case 'Classificacao' 'Arquivos soltos, diretorio nao-UUID e slug invalido nunca sao roots de sessao' {
        $p = New-TestProfile 'loose'
        $b = Get-Base $p
        $null = New-TestRoot -ProfileInfo $p
        [IO.File]::WriteAllText((Join-Path $b 'solto.json'), '{}')
        [void][IO.Directory]::CreateDirectory((Join-Path $b 'C--work-proj\nao-e-uuid'))
        [IO.File]::WriteAllText((Join-Path $b 'C--work-proj\arquivo.txt'), 'x')
        [void][IO.Directory]::CreateDirectory((Join-Path $b ('slug invalido ' + [char]0x00E7 + '\' + [guid]::NewGuid())))
        $i = Inv -Profiles @($p)
        $loose = @($i.Partitions | Where-Object Kind -eq 'BaseLooseFiles')
        Assert-Eq $loose.Count 1 'uma particao de arquivos soltos'
        Assert-True ($loose[0].Flags -contains 'NOT_SESSION_ROOT') 'soltos bloqueados'
        Assert-True (@($i.Partitions | Where-Object { $_.Kind -eq 'UnrecognizedDir' -and $_.Flags -contains 'NOT_SESSION_ROOT' }).Count -eq 1) 'nao-uuid bloqueado'
        Assert-True (@($i.Partitions | Where-Object { $_.Kind -eq 'LooseFile' }).Count -eq 1) 'arquivo no slug'
        Assert-True (@($i.Partitions | Where-Object { $_.Flags -contains 'UNRECOGNIZED_SLUG' }).Count -eq 1) 'slug invalido'
        $rows = Invoke-AtmPreview -Inventory $i
        Assert-True (@($rows | Where-Object { $_.Partition.Kind -ne 'SessionRoot' -and $_.Gate.Category -ne 'BLOCKED' }).Count -eq 0) 'nao-raizes bloqueadas'
    }
    Test-Case 'Classificacao' 'Base com estrutura nao reconhecida bloqueia tudo' {
        $p = New-TestProfile 'weird'
        [void][IO.Directory]::CreateDirectory((Join-Path (Get-Base $p) 'qualquer coisa\outra'))
        $i = Inv -Profiles @($p)
        Assert-True (@($i.Partitions | Where-Object { -not ($_.Flags -contains 'BASE_STRUCTURE_UNRECOGNIZED') }).Count -eq 0) 'todas marcadas'
    }
    Test-Case 'Classificacao' 'TEMP compartilhado entre perfis (SHARED_TEMP)' {
        $p1 = New-TestProfile 'shareA'
        $p2 = New-TestProfile 'shareB' -Sid 'S-1-5-21-1-2-3-777'
        $p2.TempCandidates = $p1.TempCandidates
        $r = New-TestRoot -ProfileInfo $p1
        $i = Inv -Profiles @($p1, $p2)
        Assert-True ((Find-Part $i $r).Flags -contains 'SHARED_TEMP') 'flag'
        Assert-Eq @($i.Partitions).Count 1 'sem duplicar particoes'
    }

    # ------------------------------------------------------------------ partitions
    Test-Case 'Particoes exclusivas' 'Soma das particoes = total independente, sem duplicidade' {
        $p = New-TestProfile 'sum'
        1..5 | ForEach-Object { $null = New-TestRoot -ProfileInfo $p -Slug ('C--p' + ($_ % 2)) -Files @{ 'x.bin' = (1000 * $_); 'd\y.bin' = 7; 'd\e\z.bin' = 3 } }
        [IO.File]::WriteAllBytes((Join-Path (Get-Base $p) 'loose.bin'), (New-Object byte[] 555))
        [IO.File]::WriteAllBytes((Join-Path (Get-Base $p) 'C--p0\loose2.bin'), (New-Object byte[] 66))
        $i = Inv -Profiles @($p)
        $files = @(Get-ChildItem -LiteralPath (Get-Base $p) -Recurse -File -Force)
        $indep = 0L; foreach ($f in $files) { $indep += $f.Length }
        Assert-Eq (Get-AtmSum $i.Partitions 'Bytes') $indep 'bytes'
        Assert-Eq (Get-AtmSum $i.Partitions 'Files') $files.Count 'arquivos'
        $paths = @($i.Partitions | ForEach-Object { $_.Path + '|' + $_.Kind })
        Assert-Eq ($paths | Select-Object -Unique).Count $paths.Count 'particoes unicas'
        $x = @($i.Partitions | Where-Object Kind -eq 'SessionRoot')[0]
        Assert-Eq $x.Dirs 2 'dirs descendentes'
        Assert-Eq $x.DirectChildren 2 'filhos diretos'
        Assert-True ($x.AllocatedBytesEstimate -ge $x.Bytes) 'alocado >= logico'
    }

    # ------------------------------------------------------------------ errors / permissions
    Test-Case 'Permissoes' 'Diretorio inacessivel dentro da root -> erro, medicao incompleta, BLOQUEADO' {
        $p = New-TestProfile 'denied'
        $r = New-TestRoot -ProfileInfo $p -Files @{ 'a.txt' = 1; 'secreto\b.txt' = 2 }
        $d = Join-Path $r 'secreto'
        $null = icacls $d /deny "*$($me.Sid):(OI)(CI)(RD)" 2>&1
        $cleanupActions.Add([scriptblock]::Create("icacls '$d' /remove:d '*$($me.Sid)' | Out-Null"))
        $i = Inv -Profiles @($p)
        $x = Find-Part $i $r
        Assert-True ($x.ErrorCount -gt 0) 'erro registrado'
        Assert-True (-not $x.MeasurementComplete) 'incompleta'
        Assert-True ($x.Flags -contains 'MEASUREMENT_INCOMPLETE' -and $x.Flags -contains 'READ_ERRORS') 'flags'
        Assert-Eq (Test-AtmCandidate -Partition $x -Inventory $i).Category 'BLOCKED' 'bloqueado'
        $c = Invoke-AtmClean -Entries @([pscustomobject]@{ Source = 't'; Path = $r; Fingerprint = $null }) -PlanPresenter $presenter -ConfirmationReader ${function:Confirm-Correct} -InventoryArgs (Get-InvArgs -Profiles @($p))
        Assert-Eq $c.Aborted 'NENHUM_CAMINHO_ELEGIVEL' 'clean recusa'
        Assert-True ([IO.Directory]::Exists($r)) 'preservado'
    }
    Test-Case 'Permissoes' 'Base inacessivel -> perfil com cobertura incompleta' {
        $p = New-TestProfile 'basedenied'
        $b = Get-Base $p
        $null = New-TestRoot -ProfileInfo $p
        $null = icacls $b /deny "*$($me.Sid):(RD)" 2>&1
        $cleanupActions.Add([scriptblock]::Create("icacls '$b' /remove:d '*$($me.Sid)' | Out-Null"))
        $i = Inv -Profiles @($p)
        Assert-True (@($i.Bases)[0].Status -in @('ENUMERATION_FAILED', 'INACCESSIBLE')) "status $(@($i.Bases)[0].Status)"
        Assert-True (-not $i.CoverageComplete) 'cobertura incompleta'
        Assert-Eq @($i.InaccessibleProfiles).Count 1 'perfil listado como inacessivel'
        Show-AtmAudit -Inventory $i
    }
    Test-Case 'Permissoes' 'Sem permissao de exclusao (deny DE/DC) -> sondagem ACCESS_DENIED, BLOQUEADO' {
        $p = New-TestProfile 'nodelete'
        $r = New-TestRoot -ProfileInfo $p -Files @{ 'a.txt' = 5 }
        $f = Join-Path $r 'a.txt'
        $null = icacls $f /deny "*$($me.Sid):(DE)" 2>&1
        $null = icacls $r /deny "*$($me.Sid):(DC)" 2>&1
        $cleanupActions.Add([scriptblock]::Create("icacls '$f' /remove:d '*$($me.Sid)' | Out-Null; icacls '$r' /remove:d '*$($me.Sid)' | Out-Null"))
        $i = Inv -Profiles @($p)
        $g = Test-AtmCandidate -Partition (Find-Part $i $r) -Inventory $i
        Assert-Eq $g.Category 'BLOCKED' 'bloqueado'
        Assert-True (($g.Reasons -join ' ') -match 'ACESSO_NEGADO') "motivo: $($g.Reasons -join ';')"
        Assert-True ([IO.File]::Exists($f)) 'arquivo intacto'
    }
    Test-Case 'Permissoes' 'Arquivo somente leitura (protegido) bloqueia; sem -Force' {
        $p = New-TestProfile 'readonly'
        $r = New-TestRoot -ProfileInfo $p
        $f = Join-Path $r 'a.txt'
        [IO.File]::SetAttributes($f, [IO.FileAttributes]::ReadOnly)
        $cleanupActions.Add([scriptblock]::Create("try { [IO.File]::SetAttributes('$f', 'Normal') } catch { }"))
        $i = Inv -Profiles @($p)
        $x = Find-Part $i $r
        Assert-True ($x.Flags -contains 'PROTECTED_FILES') 'flag'
        $d = [AgentTempManager.AtmDeleter]::DeleteTree($r)
        Assert-True (-not $d.Attempted) 'deleter aborta antes de excluir'
        Assert-True ($d.AbortReason -like 'PROTECTED_FILE_FOUND*') $d.AbortReason
        Assert-True ([IO.File]::Exists((Join-Path $r 'sub\b.bin'))) 'nada excluido'
    }
    Test-Case 'Permissoes' 'Outro usuario: nao-admin BLOQUEADO; admin exige -IncludeOtherUsers' {
        $p = New-TestProfile 'otheruser'
        $r = New-TestRoot -ProfileInfo $p
        $fakeMe = [pscustomobject]@{ Sid = 'S-1-5-21-9-9-9-1000'; Name = 'TEST\outro'; IsAdmin = $false }
        $i = Inv -Profiles @($p) -Identity $fakeMe
        $g = Test-AtmCandidate -Partition (Find-Part $i $r) -Inventory $i
        Assert-True ($g.Reasons -contains 'OUTRO_USUARIO_EXIGE_ADMINISTRADOR_ELEVADO') ($g.Reasons -join ';')
        $fakeAdmin = [pscustomobject]@{ Sid = 'S-1-5-21-9-9-9-1000'; Name = 'TEST\admin'; IsAdmin = $true }
        $c = Invoke-AtmClean -Entries @([pscustomobject]@{ Source = 't'; Path = $r; Fingerprint = $null }) -PlanPresenter $presenter -ConfirmationReader ${function:Confirm-Correct} -InventoryArgs (Get-InvArgs -Profiles @($p) -Identity $fakeAdmin)
        Assert-Eq $c.Aborted 'NENHUM_CAMINHO_ELEGIVEL' 'sem -IncludeOtherUsers'
        Assert-True ((@($c.Rejected)[0].Reasons -join ' ') -match 'IncludeOtherUsers') 'motivo'
        Assert-True ([IO.Directory]::Exists($r)) 'preservado'
    }
    Test-Case 'Permissoes' 'Owner NTFS diferente do SID do perfil -> OWNER_DIVERGENTE' {
        $p = New-TestProfile 'owner' -Sid 'S-1-5-21-1-2-3-4444'
        $r = New-TestRoot -ProfileInfo $p
        $ident = [pscustomobject]@{ Sid = 'S-1-5-21-1-2-3-4444'; Name = 'TEST\owner'; IsAdmin = $false }
        $i = Inv -Profiles @($p) -Identity $ident
        $g = Test-AtmCandidate -Partition (Find-Part $i $r) -Inventory $i
        Assert-True (($g.Reasons -join ' ') -match 'OWNER_DIVERGENTE') ($g.Reasons -join ';')
    }

    # ------------------------------------------------------------------ processes / sessions / references
    Test-Case 'Processos' 'Cobertura de processos incompleta bloqueia SEMPRE (nao-admin e admin), sem override' {
        $p = New-TestProfile 'procgap'
        $r = New-TestRoot -ProfileInfo $p
        $procs = New-Procs -Extra @([pscustomobject]@{ ProcessId = 900; Name = 'svc.exe'; ParentProcessId = 1; CommandLine = $null; CreationDate = (Get-Date) })
        $i = Inv -Profiles @($p) -Procs $procs
        Assert-Eq $i.Snapshot.Uninspectable 1 'registrado'
        Assert-True (-not $i.ProcessCoverageComplete) 'cobertura incompleta'
        Assert-Eq (Find-Part $i $r).Class 'ORPHAN_SUSPECTED' 'continua so suspeito'
        Assert-Eq (Test-AtmCandidate -Partition (Find-Part $i $r) -Inventory $i).Category 'BLOCKED' 'preview: bloqueado'
        $c = Invoke-AtmClean -Entries @([pscustomobject]@{ Source = 't'; Path = $r; Fingerprint = $null }) -PlanPresenter $presenter -ConfirmationReader ${function:Confirm-Correct} -InventoryArgs (Get-InvArgs -Profiles @($p) -Procs $procs)
        Assert-Eq $c.Aborted 'NENHUM_CAMINHO_ELEGIVEL' 'nao-admin bloqueado'
        Assert-True ((@($c.Rejected)[0].Reasons -join ' ') -match 'COBERTURA_DE_PROCESSOS_INCOMPLETA') 'motivo'
        $adm = [pscustomobject]@{ Sid = $testOwnerSid; Name = $me.Name; IsAdmin = $true }
        $c2 = Invoke-AtmClean -Entries @([pscustomobject]@{ Source = 't'; Path = $r; Fingerprint = $null }) -PlanPresenter $presenter -ConfirmationReader ${function:Confirm-Correct} -InventoryArgs (Get-InvArgs -Profiles @($p) -Procs $procs -Identity $adm)
        Assert-Eq $c2.Aborted 'NENHUM_CAMINHO_ELEGIVEL' 'admin tambem bloqueado'
        $threw = $false; try { $null = Invoke-AtmClean -Entries @() -AcceptProcessCoverageGap } catch { $threw = $true }
        Assert-True $threw 'switch -AcceptProcessCoverageGap nao existe mais no motor'
        foreach ($f in @(Get-ChildItem -LiteralPath $srcDir -Recurse -File)) { Assert-True (-not ([IO.File]::ReadAllText($f.FullName).Contains('AcceptProcessCoverageGap'))) "$($f.Name) ainda referencia o switch" }
        Assert-True ([IO.Directory]::Exists($r)) 'preservado'
    }
    Test-Case 'Processos' 'Falha na coleta de processos nunca presume ausencia' {
        $p = New-TestProfile 'procfail'
        $r = New-TestRoot -ProfileInfo $p
        $i = Inv -Profiles @($p)
        $i.Snapshot.Failed = $true
        $x = Find-Part $i $r
        Set-AtmClassification -Partition $x -Base @($i.Bases)[0] -Registry ([pscustomobject]@{ Readable = $true; Unparseable = 0; Entries = @() }) -Snapshot $i.Snapshot -NowUtc $nowFuture -StartUtc ([datetime]::UtcNow)
        Assert-True ($x.Flags -contains 'PROCESS_SNAPSHOT_FAILED') 'flag'
        Assert-Eq $x.Class 'LIVENESS_UNKNOWN' 'classe'
    }
    Test-Case 'Referencias' 'Referencia direta em linha de comando -> ACTIVE_EVIDENCE (sem expor a linha)' {
        $p = New-TestProfile 'ref'
        $r = New-TestRoot -ProfileInfo $p
        $procs = New-Procs -Extra @([pscustomobject]@{ ProcessId = 501; Name = 'node.exe'; ParentProcessId = 1; CommandLine = "node.exe --token=SEGREDO `"$r\sub\b.bin`""; CreationDate = (Get-Date) })
        $i = Inv -Profiles @($p) -Procs $procs
        $x = Find-Part $i $r
        Assert-Eq $x.Class 'ACTIVE_EVIDENCE' 'classe'
        Assert-True (($x.Evidence -join ' ') -notmatch 'SEGREDO') 'linha de comando nao exposta'
        Assert-Eq (Test-AtmCandidate -Partition $x -Inventory $i).Category 'BLOCKED' 'bloqueado'
    }
    Test-Case 'Referencias' 'Referencia com barras normais e caixa diferente' {
        $p = New-TestProfile 'refslash'
        $r = New-TestRoot -ProfileInfo $p
        $procs = New-Procs -Extra @([pscustomobject]@{ ProcessId = 502; Name = 'bash.exe'; ParentProcessId = 1; CommandLine = ('bash -c cd ' + $r.ToUpperInvariant().Replace('\', '/') + '/x'); CreationDate = (Get-Date) })
        Assert-Eq (Find-Part (Inv -Profiles @($p) -Procs $procs) $r).Class 'ACTIVE_EVIDENCE' 'classe'
    }
    Test-Case 'Referencias' 'Referencia so ao ancestral (projeto/base) NAO comprova atividade dos filhos' {
        $p = New-TestProfile 'anc'
        $r1 = New-TestRoot -ProfileInfo $p -Slug 'C--a'
        $r2 = New-TestRoot -ProfileInfo $p -Slug 'C--b'
        $slugDir = [IO.Path]::GetDirectoryName($r1)
        $procs = New-Procs -Extra @([pscustomobject]@{ ProcessId = 503; Name = 'x.exe'; ParentProcessId = 1; CommandLine = "x.exe `"$slugDir`""; CreationDate = (Get-Date) })
        $i = Inv -Profiles @($p) -Procs $procs
        $a = Find-Part $i $r1; $b = Find-Part $i $r2
        Assert-True ($a.Class -ne 'ACTIVE_EVIDENCE') 'ancestral nao e prova'
        Assert-True ($a.Flags -contains 'ANCESTOR_REFERENCE') 'mas e registrada'
        Assert-Eq (Test-AtmCandidate -Partition $a -Inventory $i).Category 'INVESTIGATE' 'exige investigacao'
        Assert-Eq $b.Class 'ORPHAN_SUSPECTED' ('outro projeto nao afetado: ' + ($b.Flags -join ','))
        $procs2 = New-Procs -Extra @([pscustomobject]@{ ProcessId = 504; Name = 'y.exe'; ParentProcessId = 1; CommandLine = "y.exe $(Get-Base $p)"; CreationDate = (Get-Date) })
        $i2 = Inv -Profiles @($p) -Procs $procs2
        Assert-True (@($i2.Partitions | Where-Object { -not ($_.Flags -contains 'ANCESTOR_REFERENCE') }).Count -eq 0) 'base referenciada afeta todos'
    }
    Test-Case 'Referencias' 'Referencia ambigua (nome curto/curinga) nao e descartada' {
        $p = New-TestProfile 'amb'
        $r = New-TestRoot -ProfileInfo $p -Slug 'C--longo-projeto'
        $procs = New-Procs -Extra @([pscustomobject]@{ ProcessId = 505; Name = 'z.exe'; ParentProcessId = 1; CommandLine = "z.exe $(Get-Base $p)\C--LON~1\x"; CreationDate = (Get-Date) })
        $x = Find-Part (Inv -Profiles @($p) -Procs $procs) $r
        Assert-True ($x.Flags -contains 'AMBIGUOUS_REFERENCE') 'ambigua'
    }
    Test-Case 'Referencias' 'Exclusao da propria cadeia de execucao (shim) do indice de referencias' {
        $ct = [datetime]::UtcNow.AddHours(-1)
        $snap = [pscustomobject]@{ Failed = $false; Processes = @(
                [pscustomobject]@{ Pid = 100; ParentPid = 50; CommandLine = 'powershell -File C:\PF\CTM\agent-temp.ps1 clean -Path X'; Name = 'powershell.exe'; CreationUtc = $ct.AddSeconds(2) }
                [pscustomobject]@{ Pid = 50; ParentPid = 10; CommandLine = 'cmd /c "C:\PF\CTM\bin\agent-temp.cmd" clean -Path X'; Name = 'cmd.exe'; CreationUtc = $ct.AddSeconds(1) }
                [pscustomobject]@{ Pid = 10; ParentPid = 1; CommandLine = 'pwsh.exe'; Name = 'pwsh.exe'; CreationUtc = $ct }) }
        $s = @(Get-AtmSelfChainPids -Snapshot $snap -SelfPid 100 -Markers @('C:\PF\CTM\agent-temp.ps1', 'C:\PF\CTM\bin\agent-temp.cmd'))
        Assert-Eq ($s -join ',') '100,50' 'cadeia'
        # FINAL-A review (L-3): an unknown creation time stops the chain (the launcher stays a reference: the safe side).
        $snap.Processes[1].CreationUtc = $null
        Assert-Eq (@(Get-AtmSelfChainPids -Snapshot $snap -SelfPid 100 -Markers @('C:\PF\CTM\agent-temp.ps1', 'C:\PF\CTM\bin\agent-temp.cmd')) -join ',') '100' 'horario de criacao desconhecido: cadeia interrompida'
    }
    Test-Case 'Processos reais' 'Processo real referenciando a root e detectado (CIM, passagem unica)' {
        $p = New-TestProfile 'realproc'
        $r = New-TestRoot -ProfileInfo $p
        $sp = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList @('-NoProfile', '-Command', "Start-Sleep 60; '$r\sub'") -PassThru -WindowStyle Hidden
        $cleanupActions.Add([scriptblock]::Create("Stop-Process -Id $($sp.Id) -ErrorAction SilentlyContinue"))
        Start-Sleep -Milliseconds 1500
        $a = Get-InvArgs -Profiles @($p) -Procs $null
        $a.Remove('ProcessesOverride')
        $i = Invoke-AtmInventory @a
        $x = Find-Part $i $r
        Stop-Process -Id $sp.Id -ErrorAction SilentlyContinue
        Assert-Eq $x.Class 'ACTIVE_EVIDENCE' "classe (refs: $($x.DirectRefs -join ';'))"
        Assert-True (($x.DirectRefs -join ' ') -match "PID $($sp.Id)") 'pid correto'
    }
    Test-Case 'Sessoes simultaneas' 'Registro de sessoes vivas em dois perfis -> ACTIVE_EVIDENCE' {
        $created = (Get-Date).AddMinutes(-30)
        $ft = $created.ToUniversalTime().ToFileTimeUtc()
        $pa = New-TestProfile 'sessA'; $pb = New-TestProfile 'sessB'
        $ra = New-TestRoot -ProfileInfo $pa; $rb = New-TestRoot -ProfileInfo $pb
        $ua = Split-Path $ra -Leaf; $ub = Split-Path $rb -Leaf
        [IO.File]::WriteAllText((Join-Path (Join-Path $pa.ProfilePath '.claude') 'sessions\4242.json'), "{`"pid`":4242,`"sessionId`":`"$ua`",`"procStart`":`"$ft`"}")
        [IO.File]::WriteAllText((Join-Path (Join-Path $pb.ProfilePath '.claude') 'sessions\4343.json'), "{`"pid`":4343,`"sessionId`":`"$ub`",`"procStart`":`"$ft`"}")
        [IO.File]::WriteAllText((Join-Path (Join-Path $pb.ProfilePath '.claude') 'sessions\4343.key'), 'NUNCA-LIDO')
        $procs = New-Procs -Extra @(
            [pscustomobject]@{ ProcessId = 4242; Name = 'claude.exe'; ParentProcessId = 1; CommandLine = 'claude'; CreationDate = $created },
            [pscustomobject]@{ ProcessId = 4343; Name = 'claude.exe'; ParentProcessId = 1; CommandLine = 'claude'; CreationDate = $created })
        $i = Inv -Profiles @($pa, $pb) -Procs $procs
        Assert-Eq (Find-Part $i $ra).Class 'ACTIVE_EVIDENCE' 'A ativo'
        Assert-Eq (Find-Part $i $rb).Class 'ACTIVE_EVIDENCE' 'B ativo'
    }
    Test-Case 'Sessoes simultaneas' 'PID reutilizado, PID sem horario e registro corrompido' {
        $p = New-TestProfile 'sessX'
        $r1 = New-TestRoot -ProfileInfo $p; $r2 = New-TestRoot -ProfileInfo $p
        $u1 = Split-Path $r1 -Leaf; $u2 = Split-Path $r2 -Leaf
        $ft = (Get-Date).AddDays(-3).ToUniversalTime().ToFileTimeUtc()
        [IO.File]::WriteAllText((Join-Path (Join-Path $p.ProfilePath '.claude') 'sessions\700.json'), "{`"pid`":700,`"sessionId`":`"$u1`",`"procStart`":`"$ft`"}")
        [IO.File]::WriteAllText((Join-Path (Join-Path $p.ProfilePath '.claude') 'sessions\701.json'), "{`"pid`":701,`"sessionId`":`"$u2`"}")
        $procs = New-Procs -Extra @(
            [pscustomobject]@{ ProcessId = 700; Name = 'other.exe'; ParentProcessId = 1; CommandLine = 'other'; CreationDate = (Get-Date) },
            [pscustomobject]@{ ProcessId = 701; Name = 'claude.exe'; ParentProcessId = 1; CommandLine = 'claude'; CreationDate = (Get-Date) })
        $i = Inv -Profiles @($p) -Procs $procs
        Assert-Eq (Find-Part $i $r1).Class 'ORPHAN_SUSPECTED' ('pid reutilizado nao e atividade: ' + ((Find-Part $i $r1).Flags -join ','))
        Assert-True ((Find-Part $i $r2).Flags -contains 'SESSION_PID_ALIVE_UNVERIFIED') 'pid vivo sem horario -> investigar'
        [IO.File]::WriteAllText((Join-Path (Join-Path $p.ProfilePath '.claude') 'sessions\702.json'), '{corrompido')
        $i2 = Inv -Profiles @($p) -Procs $procs
        Assert-True ((Find-Part $i2 $r1).Flags -contains 'SESSION_REGISTRY_ENTRY_UNPARSEABLE') 'corrompido afeta o perfil'
    }
    Test-Case 'Sessoes simultaneas' 'Transcricao recente da sessao exige investigacao' {
        $p = New-TestProfile 'transcript'
        $r = New-TestRoot -ProfileInfo $p -Slug 'C--t'
        $u = Split-Path $r -Leaf
        $tdir = Join-Path (Join-Path $p.ProfilePath '.claude') 'projects\C--t'
        [void][IO.Directory]::CreateDirectory($tdir)
        $tf = Join-Path $tdir "$u.jsonl"
        [IO.File]::WriteAllText($tf, '{}')
        [IO.File]::SetLastWriteTimeUtc($tf, $nowFuture.AddHours(-2))
        $x = Find-Part (Inv -Profiles @($p)) $r
        Assert-True ($x.Flags -contains 'TRANSCRIPT_RECENT') 'flag'
        Assert-Eq $x.Class 'LIVENESS_UNKNOWN' 'classe'
    }
    Test-Case 'Perfis nao carregados' 'Perfil nao carregado/env desconhecido -> CONFIG_DIR_UNKNOWN (investigar)' {
        $p = New-TestProfile 'unloaded'
        $p.Loaded = $false; $p.EnvStatus = 'NOT_LOADED'; $p.EnvKnown = $false
        $r = New-TestRoot -ProfileInfo $p
        $i = Inv -Profiles @($p)
        $x = Find-Part $i $r
        Assert-True ($x.Flags -contains 'CONFIG_DIR_UNKNOWN') 'flag'
        Assert-Eq (Test-AtmCandidate -Partition $x -Inventory $i).Category 'INVESTIGATE' 'categoria'
    }

    # ------------------------------------------------------------------ reparse points
    Test-Case 'Reparse points' 'Junction como root nao e atravessada; alvo intacto' {
        $p = New-TestProfile 'jroot'
        $target = Join-Path $sandbox 'alvo-jroot'; [void][IO.Directory]::CreateDirectory($target); [IO.File]::WriteAllText((Join-Path $target 'canario.txt'), 'vivo')
        $link = Join-Path (Get-Base $p) ('C--j\' + [guid]::NewGuid())
        New-Junction -Link $link -Target $target
        $i = Inv -Profiles @($p)
        $x = @($i.Partitions | Where-Object { $_.Path -eq $link })[0]
        Assert-Eq $x.Kind 'ReparsePoint' 'tipo'
        Assert-Eq $x.Files 0 'conteudo do alvo nao contado'
        $c = Invoke-AtmClean -Entries @([pscustomobject]@{ Source = 't'; Path = $link; Fingerprint = $null }) -PlanPresenter $presenter -ConfirmationReader ${function:Confirm-Correct} -InventoryArgs (Get-InvArgs -Profiles @($p))
        Assert-Eq $c.Aborted 'NENHUM_CAMINHO_ELEGIVEL' 'recusado'
        Assert-True ([IO.File]::Exists((Join-Path $target 'canario.txt'))) 'alvo intacto'
    }
    Test-Case 'Reparse points' 'Junction dentro da root: contada, nao atravessada, bloqueia; deleter aborta sem excluir' {
        $p = New-TestProfile 'jinside'
        $r = New-TestRoot -ProfileInfo $p
        $target = Join-Path $sandbox 'alvo-jinside'; [void][IO.Directory]::CreateDirectory($target); [IO.File]::WriteAllText((Join-Path $target 'canario.txt'), 'vivo')
        New-Junction -Link (Join-Path $r 'sub\link') -Target $target
        $i = Inv -Profiles @($p)
        $x = Find-Part $i $r
        Assert-Eq $x.ReparsePoints 1 'contada'
        Assert-Eq $x.Files 2 'alvo nao contado'
        Assert-True ($x.Flags -contains 'REPARSE_POINT') 'flag'
        Assert-Eq (Test-AtmCandidate -Partition $x -Inventory $i).Category 'BLOCKED' 'bloqueado'
        $d = [AgentTempManager.AtmDeleter]::DeleteTree($r)
        Assert-True (-not $d.Attempted) 'nada tentado'
        Assert-True ([IO.File]::Exists((Join-Path $r 'a.txt'))) 'root intacta'
        Assert-True ([IO.File]::Exists((Join-Path $target 'canario.txt'))) 'alvo intacto'
        $pr = [AgentTempManager.AtmLockProbe]::ProbeTree($r, 5)
        Assert-True (-not $pr.Ok -and $pr.ReparsePoints -eq 1) 'sondagem recusa'
    }
    Test-Case 'Reparse points' 'Reparse point em ancestral (TEMP e junction): base nao auditada' {
        $p = New-TestProfile 'janc'
        $realTemp = Join-Path $sandbox 'temp-real-janc'
        [void][IO.Directory]::CreateDirectory((Join-Path $realTemp ('claude\C--x\' + [guid]::NewGuid())))
        $temp = $p.TempCandidates[0].TempPath
        [IO.Directory]::Delete((Join-Path $temp 'claude')); [IO.Directory]::Delete($temp)
        New-Junction -Link $temp -Target $realTemp
        $i = Inv -Profiles @($p)
        Assert-Eq @($i.Bases)[0].Status 'REPARSE_IN_PATH' 'status'
        Assert-Eq @($i.Partitions).Count 0 'nada inventariado'
        Assert-Eq (Test-AtmPathChain (Join-Path $temp 'claude')).Status 'REPARSE_IN_PATH' 'cadeia'
    }
    Test-Case 'Reparse points' 'Symlink de diretorio (se permitido) tambem e bloqueado' {
        $p = New-TestProfile 'symlink'
        $r = New-TestRoot -ProfileInfo $p
        $target = Join-Path $sandbox 'alvo-sym'; [void][IO.Directory]::CreateDirectory($target)
        # No symlink privilege: the case is reported as NAO_TESTADO below.
        try { $null = cmd /c mklink /D "`"$(Join-Path $r 'sym')`"" "`"$target`"" 2>&1 } catch { $null = $_ }
        if (-not [IO.Directory]::Exists((Join-Path $r 'sym'))) { $script:caseSkipped = $true; $script:caseNote = 'symlink exige privilegio (SeCreateSymbolicLink) ou modo desenvolvedor; reparse coberto por junctions'; return }
        $cleanupActions.Add([scriptblock]::Create("try { [IO.Directory]::Delete('$(Join-Path $r 'sym')', `$false) } catch { }"))
        Assert-True ((Find-Part (Inv -Profiles @($p)) $r).Flags -contains 'REPARSE_POINT') 'flag'
    }

    # ------------------------------------------------------------------ locks / in use
    Test-Case 'Arquivos em uso' 'Arquivo aberto (FileShare.None e ReadWrite|Delete) -> EM_USO, preservado' {
        $p = New-TestProfile 'locked'
        $r = New-TestRoot -ProfileInfo $p
        $i = Inv -Profiles @($p)
        foreach ($share in @([IO.FileShare]::None, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))) {
            $fs = [IO.File]::Open((Join-Path $r 'a.txt'), 'Open', 'Read', $share)
            try {
                $g = Test-AtmCandidate -Partition (Find-Part $i $r) -Inventory $i
                Assert-Eq $g.Category 'BLOCKED' "bloqueado ($share)"
                Assert-True (($g.Reasons -join ' ') -match 'EM_USO') "motivo ($share): $($g.Reasons -join ';')"
                $c = Invoke-AtmClean -Entries @([pscustomobject]@{ Source = 't'; Path = $r; Fingerprint = $null }) -PlanPresenter $presenter -ConfirmationReader ${function:Confirm-Correct} -InventoryArgs (Get-InvArgs -Profiles @($p))
                Assert-Eq $c.Aborted 'NENHUM_CAMINHO_ELEGIVEL' 'clean recusa'
            } finally { $fs.Dispose() }
        }
        Assert-True ([IO.File]::Exists((Join-Path $r 'a.txt'))) 'preservado'
    }
    Test-Case 'Arquivos em uso' 'Processo com diretorio corrente dentro da root -> EM_USO' {
        $p = New-TestProfile 'cwd'
        $r = New-TestRoot -ProfileInfo $p
        $sp = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep 60') -WorkingDirectory (Join-Path $r 'sub') -PassThru -WindowStyle Hidden
        $cleanupActions.Add([scriptblock]::Create("Stop-Process -Id $($sp.Id) -ErrorAction SilentlyContinue"))
        Start-Sleep -Milliseconds 1500
        $pr = [AgentTempManager.AtmLockProbe]::ProbeTree($r, 5)
        Stop-Process -Id $sp.Id -ErrorAction SilentlyContinue
        Assert-True ($pr.InUse -ge 1) "diretorio em uso detectado ($($pr.Samples -join ';'))"
    }

    # ------------------------------------------------------------------ allowlist / traversal
    Test-Case 'Path traversal' 'Entradas maliciosas ou nao canonicas sao rejeitadas' {
        $p = New-TestProfile 'trav'
        $r = New-TestRoot -ProfileInfo $p
        $b = Get-Base $p
        $bad = @{
            "$b\C--work-proj\..\C--work-proj\$(Split-Path $r -Leaf)" = 'PATH_TRAVERSAL'
            'relativo\x'                       = 'NOT_ABSOLUTE_LOCAL_PATH'
            '\\servidor\share\x'               = 'NOT_ABSOLUTE_LOCAL_PATH'
            "\\?\$r"                           = 'NOT_ABSOLUTE_LOCAL_PATH'
            "$b\*"                             = 'WILDCARD_OR_INVALID_CHARS'
            "$r`:stream"                       = 'ALTERNATE_DATA_STREAM'
            "$r\"                              = 'TRAILING_SEPARATOR'
            "$r."                              = 'TRAILING_DOT_OR_SPACE'
            'C:\Users\EXAMPL~1\x'              = 'SHORT_NAME_NOT_ALLOWED'
            " $r"                              = 'LEADING_OR_TRAILING_WHITESPACE'
            ($r -replace '\\', '\\')           = 'EMPTY_SEGMENT'
        }
        foreach ($k in $bad.Keys) { Assert-Eq (Test-AtmAllowListPathSyntax $k) $bad[$k] "entrada '$k'" }
        Assert-Eq (Test-AtmAllowListPathSyntax $r) $null 'caminho valido aceito'
    }
    Test-Case 'Path traversal' 'Perfil, TEMP, base, projeto e raiz do disco nunca sao aceitos' {
        $p = New-TestProfile 'roots'
        $r = New-TestRoot -ProfileInfo $p
        $b = Get-Base $p
        $targets = @($p.ProfilePath, $p.TempCandidates[0].TempPath, $b, [IO.Path]::GetDirectoryName($r), 'C:\', $sandbox)
        $entries = @($targets | ForEach-Object { [pscustomobject]@{ Source = 't'; Path = $_; Fingerprint = $null } })
        $c = Invoke-AtmClean -Entries $entries -PlanPresenter $presenter -ConfirmationReader ${function:Confirm-Correct} -InventoryArgs (Get-InvArgs -Profiles @($p))
        Assert-Eq $c.Aborted 'NENHUM_CAMINHO_ELEGIVEL' 'tudo recusado'
        Assert-Eq @($c.Rejected).Count $targets.Count 'todos recusados'
        Assert-True ([IO.Directory]::Exists($r)) 'preservado'
    }
    Test-Case 'Allowlist' 'Leitura de allowlist UTF-8 com comentarios, fingerprint e Unicode' {
        $f = Join-Path $sandbox 'allow.txt'
        $u = "C:\x\" + $uni
        [IO.File]::WriteAllText($f, "# comentario`r`n`r`n$u|ABCDEF`r`nC:\y\z`r`n", (New-Object Text.UTF8Encoding($true)))
        $e = @(Read-AtmAllowList -File $f -Paths @('C:\w'))
        Assert-Eq $e.Count 3 'entradas'
        Assert-Eq $e[0].Path $u 'unicode preservado'
        Assert-Eq $e[0].Fingerprint 'ABCDEF' 'fingerprint'
        Assert-Eq $e[2].Source '-Path' 'origem'
    }

    # ------------------------------------------------------------------ clean flow
    Test-Case 'Clean' 'Sem confirmacao ou confirmacao divergente: nada e apagado' {
        $p = New-TestProfile 'noconfirm'
        $r = New-TestRoot -ProfileInfo $p
        $e = @([pscustomobject]@{ Source = 't'; Path = $r; Fingerprint = $null })
        foreach ($reader in @({ param($x) $null }, { param($x) '' }, { param($x) $x.ToLowerInvariant() }, { param($x) "$x " }, { param($x) 'sim' })) {
            $c = Invoke-AtmClean -Entries $e -PlanPresenter $presenter -ConfirmationReader $reader -InventoryArgs (Get-InvArgs -Profiles @($p))
            Assert-Eq $c.Aborted 'CONFIRMACAO_AUSENTE_OU_DIVERGENTE' 'abortado'
            Assert-Eq @($c.Deleted).Count 0 'nada excluido'
        }
        $c = Invoke-AtmClean -Entries $e -InventoryArgs (Get-InvArgs -Profiles @($p))
        Assert-Eq $c.Aborted 'SEM_APRESENTACAO_OU_CONFIRMACAO' 'sem leitor/apresentador'
        $c = Invoke-AtmClean -Entries $e -ConfirmationReader ${function:Confirm-Correct} -InventoryArgs (Get-InvArgs -Profiles @($p))
        Assert-Eq $c.Aborted 'SEM_APRESENTACAO_OU_CONFIRMACAO' 'sem apresentador do plano'
        Assert-True ([IO.Directory]::Exists($r)) 'preservado'
    }
    Test-Case 'Clean' 'Allowlist vazia e caminho fora da allowlist preservado' {
        $c = Invoke-AtmClean -Entries @() -PlanPresenter $presenter -ConfirmationReader ${function:Confirm-Correct}
        Assert-Eq $c.Aborted 'ALLOWLIST_VAZIA' 'vazia'
        $p = New-TestProfile 'outside'
        $r1 = New-TestRoot -ProfileInfo $p; $r2 = New-TestRoot -ProfileInfo $p
        $before = Get-StableTreeListing $r2
        $c = Invoke-AtmClean -Entries @([pscustomobject]@{ Source = 't'; Path = $r1; Fingerprint = $null }) -PlanPresenter $presenter -ConfirmationReader ${function:Confirm-Correct} -InventoryArgs (Get-InvArgs -Profiles @($p))
        Assert-Eq @($c.Deleted | Where-Object { $_.Completed -and $_.Verified }).Count 1 'somente r1'
        Assert-True (-not [IO.Directory]::Exists($r1)) 'r1 excluido'
        Assert-Eq (Get-TreeListing $r2) $before 'r2 (fora da allowlist) intacto'
        Assert-True ([IO.Directory]::Exists([IO.Path]::GetDirectoryName($r1))) 'diretorio do projeto preservado'
        Assert-True ($null -ne $c.PostInventory) 'auditoria posterior executada'
    }
    Test-Case 'Clean' 'Alteracao entre preview e clean (fingerprint) -> recusado' {
        $p = New-TestProfile 'changed'
        $r = New-TestRoot -ProfileInfo $p
        $fp = (Find-Part (Inv -Profiles @($p)) $r).Fingerprint
        [IO.File]::WriteAllBytes((Join-Path $r 'novo.bin'), (New-Object byte[] 3))
        [IO.File]::SetLastWriteTimeUtc((Join-Path $r 'novo.bin'), [datetime]::UtcNow.AddDays(-5))
        $c = Invoke-AtmClean -Entries @([pscustomobject]@{ Source = 't'; Path = $r; Fingerprint = $fp }) -PlanPresenter $presenter -ConfirmationReader ${function:Confirm-Correct} -InventoryArgs (Get-InvArgs -Profiles @($p))
        Assert-Eq $c.Aborted 'NENHUM_CAMINHO_ELEGIVEL' 'recusado'
        Assert-True ((@($c.Rejected)[0].Reasons -join ' ') -match 'ALTERADO_DESDE_O_PREVIEW') 'motivo'
        Assert-True ([IO.Directory]::Exists($r)) 'preservado'
    }
    Test-Case 'Clean' 'Alteracao apos a confirmacao (antes da exclusao) -> preservado na revalidacao' {
        $p = New-TestProfile 'toctou'
        $r = New-TestRoot -ProfileInfo $p
        $hook = { param($part) [IO.File]::WriteAllBytes((Join-Path $part.Path 'apareceu.bin'), (New-Object byte[] 9)) }
        $c = Invoke-AtmClean -Entries @([pscustomobject]@{ Source = 't'; Path = $r; Fingerprint = $null }) -PlanPresenter $presenter -ConfirmationReader ${function:Confirm-Correct} -InventoryArgs (Get-InvArgs -Profiles @($p)) -BeforeDeleteHook $hook
        Assert-Eq @($c.Deleted).Count 0 'nada excluido'
        Assert-Eq @($c.Skipped).Count 1 'preservado'
        Assert-True ([IO.File]::Exists((Join-Path $r 'apareceu.bin'))) 'arquivo novo intacto'
    }
    Test-Case 'Clean' 'Root removida entre preview e clean / durante a revalidacao' {
        $p = New-TestProfile 'vanish'
        $r = New-TestRoot -ProfileInfo $p
        $hook = { param($part) [AgentTempManager.AtmDeleter]::DeleteTree($part.Path) | Out-Null }
        $c = Invoke-AtmClean -Entries @([pscustomobject]@{ Source = 't'; Path = $r; Fingerprint = $null }) -PlanPresenter $presenter -ConfirmationReader ${function:Confirm-Correct} -InventoryArgs (Get-InvArgs -Profiles @($p)) -BeforeDeleteHook $hook
        Assert-Eq @($c.Skipped).Count 1 'tratado como desaparecido'
        $c2 = Invoke-AtmClean -Entries @([pscustomobject]@{ Source = 't'; Path = $r; Fingerprint = $null }) -PlanPresenter $presenter -ConfirmationReader ${function:Confirm-Correct} -InventoryArgs (Get-InvArgs -Profiles @($p))
        Assert-Eq $c2.Aborted 'NENHUM_CAMINHO_ELEGIVEL' 'inexistente recusado'
        $s = [AgentTempManager.AtmScanner]::ScanTree($r, 3, 4096)
        Assert-True (-not $s.Exists) 'scanner tolera remocao'
    }
    Test-Case 'Clean' 'Caixa divergente e duplicados na allowlist sao recusados' {
        $p = New-TestProfile 'case'
        $r = New-TestRoot -ProfileInfo $p
        $c = Invoke-AtmClean -Entries @([pscustomobject]@{ Source = 't'; Path = $r.ToUpperInvariant().Replace('C:\', 'C:\'); Fingerprint = $null }) -PlanPresenter $presenter -ConfirmationReader ${function:Confirm-Correct} -InventoryArgs (Get-InvArgs -Profiles @($p))
        Assert-Eq $c.Aborted 'NENHUM_CAMINHO_ELEGIVEL' 'caixa'
        $c2 = Invoke-AtmClean -Entries @([pscustomobject]@{ Source = 'a'; Path = $r; Fingerprint = $null }, [pscustomobject]@{ Source = 'b'; Path = $r; Fingerprint = $null }) -PlanPresenter $presenter -ConfirmationReader { param($x) 'nao' } -InventoryArgs (Get-InvArgs -Profiles @($p))
        Assert-True (@($c2.Rejected | Where-Object { $_.Reasons -contains 'DUPLICADO_NA_ALLOWLIST' }).Count -eq 1) 'duplicado'
        Assert-True ([IO.Directory]::Exists($r)) 'preservado'
    }
    Test-Case 'Clean' 'Classes ACTIVE/RECENT/UNKNOWN nunca entram no plano' {
        $p = New-TestProfile 'classes'
        $ra = New-TestRoot -ProfileInfo $p; $rr = New-TestRoot -ProfileInfo $p; $ru = New-TestRoot -ProfileInfo $p
        [IO.File]::SetLastWriteTimeUtc((Join-Path $rr 'a.txt'), $nowFuture.AddHours(-3))
        $procs = New-Procs -Extra @(
            [pscustomobject]@{ ProcessId = 801; Name = 'n.exe'; ParentProcessId = 1; CommandLine = "n $ra"; CreationDate = (Get-Date) },
            [pscustomobject]@{ ProcessId = 802; Name = 'n.exe'; ParentProcessId = 1; CommandLine = "n $([IO.Path]::GetDirectoryName($ru))"; CreationDate = (Get-Date) })
        $e = @($ra, $rr, $ru | ForEach-Object { [pscustomobject]@{ Source = 't'; Path = $_; Fingerprint = $null } })
        $c = Invoke-AtmClean -Entries $e -PlanPresenter $presenter -ConfirmationReader ${function:Confirm-Correct} -InventoryArgs (Get-InvArgs -Profiles @($p) -Procs $procs)
        Assert-Eq $c.Aborted 'NENHUM_CAMINHO_ELEGIVEL' 'nenhum elegivel'
        Assert-True ([IO.Directory]::Exists($ra) -and [IO.Directory]::Exists($rr) -and [IO.Directory]::Exists($ru)) 'todos preservados'
    }

    # ------------------------------------------------------------------ read-only guarantee
    Test-Case 'Somente leitura' 'audit + preview nao alteram nada no sandbox' {
        $p = New-TestProfile 'ro'
        1..3 | ForEach-Object { $null = New-TestRoot -ProfileInfo $p }
        # NTFS updates directory timestamps lazily after recent creations: wait until the tree is stable.
        $before = Get-TreeListing $p.ProfilePath
        for ($w = 0; $w -lt 20; $w++) { Start-Sleep -Milliseconds 500; $again = Get-TreeListing $p.ProfilePath; if ($again -eq $before) { break }; $before = $again }
        $i = Inv -Profiles @($p)
        Show-AtmAudit -Inventory $i
        $rows = Invoke-AtmPreview -Inventory $i
        Show-AtmPreview -Inventory $i -Rows $rows
        $after = Get-TreeListing $p.ProfilePath
        $diff = @(Compare-Object ($before -split "`n") ($after -split "`n") | ForEach-Object { $_.SideIndicator + ' ' + ($_.InputObject -replace '^.*\\(Users\d+)', '$1') })
        Assert-Eq $diff.Count 0 ('listagem identica (nomes, tamanhos, mtime, atributos): ' + ($diff -join ' ; '))
        Assert-Eq @($rows | Where-Object { $_.Gate.Category -eq 'ELIGIBLE' }).Count 3 'elegiveis para revisao'
    }

    # ------------------------------------------------------------------ real machine (read-only)
    Test-Case 'Maquina real (somente leitura)' 'Descoberta de perfis pelo Windows (ProfileList, Public, Default, reparse)' {
        $script:AtmDiscoveryNotes = New-Object System.Collections.Generic.List[string]
        $ps = @(Get-AtmProfiles -Identity $me)
        $mine = @($ps | Where-Object { $_.Sid -eq $me.Sid })
        Assert-Eq $mine.Count 1 'perfil atual por SID'
        Assert-True (@($ps | Where-Object { $_.Sid -eq 'S-1-5-18' }).Count -eq 1) 'SYSTEM'
        $pub = @($ps | Where-Object { $_.Sid -eq 'SHARED-PUBLIC' })
        Assert-Eq $pub.Count 1 'Public como compartilhado, sem SID proprio'
        Assert-True (@($ps | Where-Object { $_.ProfilePath -like '*\Public' -and $_.Sid -like 'S-1-5-21-*' }).Count -eq 0) 'Public nao e perfil de usuario'
        Assert-True (@($script:AtmDiscoveryNotes | Where-Object { $_ -like '*reparse*' }).Count -ge 1) 'junctions/symlinks registrados, nao atravessados'
        foreach ($x in $ps) { Write-Host ("   {0,-48} {1,-30} {2}" -f $x.Sid, $x.UserName, $x.ProfilePath) }
    }
    Test-Case 'Maquina real (somente leitura)' 'Inventario real completo nao falha e reporta cobertura' {
        $i = Invoke-AtmInventory -NoProgress -ConfigDir $cfgDir
        Assert-True (@($i.Profiles).Count -ge 2) 'perfis'
        Assert-True ($i.Snapshot.Total -gt 0) 'processos coletados'
        if (-not $me.IsAdmin) { Assert-True (-not $i.CoverageComplete) 'sem elevacao a cobertura e declarada incompleta' }
        $own = @($i.Partitions | Where-Object { $_.Class -eq 'ACTIVE_EVIDENCE' })
        Write-Host ("   particoes={0} ativas={1} bytes={2} inacessiveis={3}" -f @($i.Partitions).Count, $own.Count, (Get-AtmSum $i.Partitions 'Bytes'), (@($i.InaccessibleProfiles | ForEach-Object { $_.UserName }) -join ','))
    }

    # ------------------------------------------------------------------ security review regressions
    Test-Case 'Revisao de seguranca' 'H1: troca por junction durante a exclusao e impossivel (cadeia fixada por handle)' {
        $p = New-TestProfile 'pin'
        $r = New-TestRoot -ProfileInfo $p -Files @{ 'sub\alvo.txt' = 5; 'a.txt' = 1 }
        $victim = Join-Path $sandbox 'vitima-pin'; [void][IO.Directory]::CreateDirectory($victim); [IO.File]::WriteAllText((Join-Path $victim 'alvo.txt'), 'vivo')
        $slugDir = [IO.Path]::GetDirectoryName($r)
        # Control: without pinning the same renames succeed (so the assertion below proves the pin, not something else).
        [IO.Directory]::Move((Join-Path $r 'sub'), (Join-Path $r 'sub-c')); [IO.Directory]::Move((Join-Path $r 'sub-c'), (Join-Path $r 'sub'))
        [IO.Directory]::Move($slugDir, ($slugDir + '-c')); [IO.Directory]::Move(($slugDir + '-c'), $slugDir)
        $script:pinAttempts = @()
        $hook = [Action[string]]{
            param($root)
            foreach ($pair in @(@((Join-Path $root 'sub'), (Join-Path $root 'sub-movido')), @($slugDir, ($slugDir + '-movido')), @((Get-Base $p), ((Get-Base $p) + '-movido')))) {
                try { [IO.Directory]::Move($pair[0], $pair[1]); $script:pinAttempts += "RENOMEOU $($pair[0])" } catch { $script:pinAttempts += 'bloqueado' }
            }
        }
        $d = [AgentTempManager.AtmDeleter]::DeleteTree($r, $hook)
        Assert-Eq (@($script:pinAttempts | Where-Object { $_ -ne 'bloqueado' }) -join ';') '' 'nenhuma renomeacao possivel durante a exclusao'
        Assert-True $d.Completed "exclusao concluida ($($d.AbortReason))"
        Assert-True (-not [IO.Directory]::Exists($r)) 'root excluida'
        Assert-True ([IO.File]::Exists((Join-Path $victim 'alvo.txt'))) 'nada fora da arvore foi atingido'
        Assert-True ([IO.Directory]::Exists($slugDir)) 'ancestrais preservados'
    }
    Test-Case 'Revisao de seguranca' 'H1: redirecionamento ja existente no caminho e recusado pelo deleter' {
        $real = Join-Path $sandbox 'real-redir'; [void][IO.Directory]::CreateDirectory((Join-Path $real 'x')); [IO.File]::WriteAllText((Join-Path $real 'x\f.txt'), 'vivo')
        $link = Join-Path $sandbox 'link-redir'
        New-Junction -Link $link -Target $real
        $d = [AgentTempManager.AtmDeleter]::DeleteTree((Join-Path $link 'x'))
        Assert-True (-not $d.Attempted) "recusado: $($d.AbortReason)"
        Assert-True ($d.AbortReason -match 'REPARSE|REDIRECTED') $d.AbortReason
        Assert-True ([IO.File]::Exists((Join-Path $real 'x\f.txt'))) 'alvo intacto'
    }
    Test-Case 'Revisao de seguranca' 'M1: base/projeto com escrita concedida a terceiros bloqueia; %WINDIR%\Temp e compartilhado' {
        $p = New-TestProfile 'aclbase'
        $r = New-TestRoot -ProfileInfo $p
        $b = Get-Base $p
        $null = icacls $b /grant '*S-1-5-32-545:(OI)(CI)(M)' 2>&1
        $i = Inv -Profiles @($p)
        $g = Test-AtmCandidate -Partition (Find-Part $i $r) -Inventory $i
        Assert-Eq $g.Category 'BLOCKED' 'bloqueado'
        Assert-True (($g.Reasons -join ' ') -match 'ESCRITA_CONCEDIDA_A_TERCEIROS') ($g.Reasons -join ';')
        $ps = New-TestProfile 'wintemp'
        $ps.TempCandidates = @([pscustomobject]@{ TempPath = (Join-Path $env:SystemRoot 'Temp'); Source = 'test' })
        $i2 = Inv -Profiles @($ps)
        Assert-True (@($i2.Bases)[0].Shared) 'Windows\Temp marcado como compartilhado'
    }
    Test-Case 'Revisao de seguranca' 'M2: procStart em formato inesperado nunca vira "sessao encerrada"' {
        $p = New-TestProfile 'procstart'
        $r = New-TestRoot -ProfileInfo $p
        $u = Split-Path $r -Leaf
        $ms = [long]([datetime]::UtcNow - [datetime]'1970-01-01').TotalMilliseconds
        [IO.File]::WriteAllText((Join-Path (Join-Path $p.ProfilePath '.claude') 'sessions\910.json'), "{`"pid`":910,`"sessionId`":`"$u`",`"procStart`":`"$ms`"}")
        $procs = New-Procs -Extra @([pscustomobject]@{ ProcessId = 910; Name = 'claude.exe'; ParentProcessId = 1; CommandLine = 'claude'; CreationDate = (Get-Date) })
        $x = Find-Part (Inv -Profiles @($p) -Procs $procs) $r
        Assert-True ($x.Flags -contains 'SESSION_PID_ALIVE_UNVERIFIED') ($x.Flags -join ',')
        Assert-True ($x.Class -ne 'ORPHAN_SUSPECTED') 'nao suspeito de orfao'
    }
    Test-Case 'Revisao de seguranca' 'L1/L2/L4: drill-down e saidas validados; tokens de linha de comando nao sao exibidos' {
        $p = New-TestProfile 'lows'
        $r = New-TestRoot -ProfileInfo $p -Slug 'C--longo-projeto'
        $procs = New-Procs -Extra @([pscustomobject]@{ ProcessId = 920; Name = 'z.exe'; ParentProcessId = 1; CommandLine = "z.exe $(Get-Base $p)\C--LON~1\SEGREDO-TOKEN"; CreationDate = (Get-Date) })
        $i = Inv -Profiles @($p) -Procs $procs
        $x = Find-Part $i $r
        Assert-True (($x.AmbiguousRefs -join ' ') -notmatch 'LON~1|SEGREDO') 'sem fragmentos da linha de comando'
        $out = (Show-AtmPathDetail -Inventory $i -Path ((Get-Base $p) + '\..\..\..\..') 6>&1 | Out-String)
        Assert-True ($out -match 'recusado') 'drill-down com .. recusado'
        $existing = Join-Path $sandbox 'ja-existe.json'; [IO.File]::WriteAllText($existing, '{}')
        Assert-True (-not (Test-AtmOutputPathOutsideBases -Path $existing -Inventory $i -MustNotExist)) 'nao sobrescreve'
        Assert-True (-not (Test-AtmOutputPathOutsideBases -Path (Join-Path (Get-Base $p) 'out.json') -Inventory $i)) 'dentro da base recusado'
        Assert-True (-not (Test-AtmOutputPathOutsideBases -Path ((Get-Base $p) + '\..\x.json') -Inventory $i)) 'caminho nao canonico recusado'
        Assert-True (Test-AtmOutputPathOutsideBases -Path (Join-Path $sandbox 'novo.json') -Inventory $i -MustNotExist) 'caminho valido aceito'
    }

    # ------------------------------------------------------------------ final gate V0.1
    Test-Case 'Gate V0.1' 'Versao distribuida: exclusao real DESABILITADA; clean so valida e mostra o plano' {
        Assert-Eq $shippedDeletionGate $false 'Engine.Clean.ps1 distribuido com $script:AtmRealDeletionEnabled = $false'
        $clean = [IO.File]::ReadAllText((Join-Path $srcDir 'lib\Engine.Clean.ps1'))
        Assert-Eq ([regex]::Matches($clean, '\$script:AtmRealDeletionEnabled\s*=').Count) 1 'uma unica atribuicao (a constante)'
        Assert-True ($clean -match '\$script:AtmRealDeletionEnabled = \$false') 'constante = $false'
        foreach ($f in @(Get-ChildItem -LiteralPath $srcDir -Recurse -File | Where-Object { $_.Name -ne 'Engine.Clean.ps1' })) {
            Assert-True (-not ([regex]::IsMatch([IO.File]::ReadAllText($f.FullName), 'AtmRealDeletionEnabled\s*='))) "$($f.Name) nao pode alterar a trava"
        }
        $p = New-TestProfile 'gate01'
        $r = New-TestRoot -ProfileInfo $p
        $before = Get-StableTreeListing $r
        $script:readerCalled = $false
        $script:AtmRealDeletionEnabled = $false
        try {
            $c = Invoke-AtmClean -Entries @([pscustomobject]@{ Source = 't'; Path = $r; Fingerprint = $null }) -PlanPresenter $presenter -ConfirmationReader { param($x) $script:readerCalled = $true; $x } -InventoryArgs (Get-InvArgs -Profiles @($p))
        } finally { $script:AtmRealDeletionEnabled = $true }
        Assert-Eq $c.Aborted 'EXCLUSAO_REAL_DESABILITADA_V0_1' 'abortado pela trava'
        Assert-Eq @($c.Verified).Count 1 'plano validado e exibido'
        Assert-True (-not $script:readerCalled) 'confirmacao nunca solicitada'
        Assert-Eq @($c.Deleted).Count 0 'nada excluido'
        Assert-Eq (Get-StableTreeListing $r) $before 'root intacta'
    }
    Test-Case 'Gate V0.1' 'TOCTOU: plano fixado diferente da medicao validada -> nada e excluido' {
        $p = New-TestProfile 'planmismatch'
        $r = New-TestRoot -ProfileInfo $p
        $s = [AgentTempManager.AtmScanner]::ScanTree($r, 3, 4096)
        $d = [AgentTempManager.AtmDeleter]::DeleteTree($r, $s.Files + 1, $s.Dirs, $s.Bytes, $s.NewestWriteTimeUtc.Ticks, $null)
        Assert-True (-not $d.Attempted) 'nao tentou'
        Assert-True ($d.AbortReason -like 'PLAN_DIFFERS_FROM_VALIDATED_MEASUREMENT*') $d.AbortReason
        Assert-True ([IO.File]::Exists((Join-Path $r 'a.txt'))) 'intacto'
        $s = [AgentTempManager.AtmScanner]::ScanTree($r, 3, 4096)
        $hook = [Action[string]]{ param($root) foreach ($f in [IO.Directory]::GetFiles($root, '*', 'AllDirectories')) { [IO.File]::SetLastWriteTimeUtc($f, [datetime]::UtcNow.AddMinutes(-1)) } }
        $d = [AgentTempManager.AtmDeleter]::DeleteTree($r, $s.Files, $s.Dirs, $s.Bytes, $s.NewestWriteTimeUtc.Ticks, $hook)
        Assert-Eq $d.AbortReason 'FILE_CHANGED_AFTER_PLANNING' 'arquivo alterado apos o plano'
        Assert-Eq $d.FilesDeleted 0 'nenhum arquivo excluido'
        $s = [AgentTempManager.AtmScanner]::ScanTree($r, 3, 4096)
        $d = [AgentTempManager.AtmDeleter]::DeleteTree($r, $s.Files, $s.Dirs, $s.Bytes, $s.NewestWriteTimeUtc.Ticks, $null)
        Assert-True $d.Completed "medicao identica: excluido no sandbox ($($d.AbortReason))"
    }
    Test-Case 'Gate V0.1' 'H1 entre processos: outro processo nao consegue renomear root, projeto ou base durante a exclusao' {
        $p = New-TestProfile 'pinxproc'
        $r = New-TestRoot -ProfileInfo $p -Files @{ 'sub\x.txt' = 3 }
        $slugDir = [IO.Path]::GetDirectoryName($r)
        $script:xprocResults = @()
        $hook = [Action[string]]{
            param($root)
            foreach ($target in @((Join-Path $root 'sub'), $root, $slugDir, (Get-Base $p))) {
                $cmd = "try { Rename-Item -LiteralPath '$($target.Replace("'", "''"))' -NewName 'tomado' -ErrorAction Stop; exit 0 } catch { exit 3 }"
                $pr = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList @('-NoProfile', '-Command', $cmd) -Wait -PassThru -WindowStyle Hidden
                $script:xprocResults += $pr.ExitCode
            }
        }
        $d = [AgentTempManager.AtmDeleter]::DeleteTree($r, $hook)
        Assert-Eq ($script:xprocResults -join ',') '3,3,3,3' 'todas as renomeacoes externas falharam'
        Assert-True $d.Completed "exclusao concluida ($($d.AbortReason))"
        Assert-True ([IO.Directory]::Exists($slugDir)) 'projeto preservado'
    }
    Test-Case 'Gate V0.1' 'Referencias com ":" ou "." colados e nomes nao resolvidos nunca sao ignorados' {
        $p = New-TestProfile 'refterm'
        $r = New-TestRoot -ProfileInfo $p -Slug 'C--proj'
        $r2 = New-TestRoot -ProfileInfo $p -Slug 'C--proj'
        $other = New-TestRoot -ProfileInfo $p -Slug 'C--outro'
        foreach ($cl in @("docker run -v $($r):/work img", "tool --dir=$r.", "x `"$r`".bak")) {
            $procs = New-Procs -Extra @([pscustomobject]@{ ProcessId = 930; Name = 't.exe'; ParentProcessId = 1; CommandLine = $cl; CreationDate = (Get-Date) })
            Assert-Eq (Find-Part (Inv -Profiles @($p) -Procs $procs) $r).Class 'ACTIVE_EVIDENCE' "referencia detectada em: $($cl.Substring(0, 12))..."
        }
        $procs = New-Procs -Extra @([pscustomobject]@{ ProcessId = 931; Name = 't.exe'; ParentProcessId = 1; CommandLine = "t $($r)sufixo\x"; CreationDate = (Get-Date) })
        $i = Inv -Profiles @($p) -Procs $procs
        Assert-True ((Find-Part $i $r2).Flags -contains 'AMBIGUOUS_REFERENCE') 'nome nao resolvido marca todo o projeto'
        Assert-Eq (Test-AtmCandidate -Partition (Find-Part $i $r) -Inventory $i).Category 'INVESTIGATE' 'exige investigacao'
        Assert-Eq (Find-Part $i $other).Class 'ORPHAN_SUSPECTED' 'outro projeto nao afetado'
        $procs = New-Procs -Extra @([pscustomobject]@{ ProcessId = 932; Name = 't.exe'; ParentProcessId = 1; CommandLine = "t $(Get-Base $p)\C--naoexiste\y"; CreationDate = (Get-Date) })
        Assert-True ((Find-Part (Inv -Profiles @($p) -Procs $procs) $other).Flags -contains 'AMBIGUOUS_REFERENCE') 'nao resolvido sob a base marca a base inteira'
    }
    Test-Case 'Gate V0.1' 'Diretorio fixado nao pode ser aberto para escrita (conversao em junction impossivel)' {
        if (-not ('AtmTestOpen' -as [type])) {
            Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; using Microsoft.Win32.SafeHandles; public static class AtmTestOpen { [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern SafeFileHandle CreateFileW(string n, uint a, uint s, IntPtr sa, uint d, uint f, IntPtr t); public static int TryOpenDirForWrite(string p) { using (SafeFileHandle h = CreateFileW(p, 0x0002 | 0x0100, 7, IntPtr.Zero, 3, 0x02000000 | 0x00200000, IntPtr.Zero)) { return h.IsInvalid ? Marshal.GetLastWin32Error() : 0; } } }'
        }
        $p = New-TestProfile 'pinwrite'
        $r = New-TestRoot -ProfileInfo $p -Files @{ 'a.txt' = 1 }
        [void][IO.Directory]::CreateDirectory((Join-Path $r 'vazio'))
        Assert-Eq ([AtmTestOpen]::TryOpenDirForWrite((Join-Path $r 'vazio'))) 0 'controle: sem fixacao a abertura para escrita funciona'
        $script:pinWrite = -1
        $d = [AgentTempManager.AtmDeleter]::DeleteTree($r, [Action[string]]{ param($root) $script:pinWrite = [AtmTestOpen]::TryOpenDirForWrite((Join-Path $root 'vazio')) })
        Assert-Eq $script:pinWrite 32 'durante a exclusao: violacao de compartilhamento (32)'
        Assert-True $d.Completed "exclusao concluida ($($d.AbortReason))"
    }
    Test-Case 'Gate V0.1' 'Preview sempre exibe o motivo do bloqueio, mesmo com evidencias longas' {
        $p = New-TestProfile 'whyshown'
        $r = New-TestRoot -ProfileInfo $p
        $extra = @(1..40 | ForEach-Object { [pscustomobject]@{ ProcessId = 1000 + $_; Name = ('processo-com-nome-longo-' + $_ + '.exe'); ParentProcessId = 1; CommandLine = "x `"$r\sub`""; CreationDate = (Get-Date) } })
        $i = Inv -Profiles @($p) -Procs (New-Procs -Extra $extra)
        $rows = Invoke-AtmPreview -Inventory $i
        $out = (@(Show-AtmPreview -Inventory $i -Rows $rows 6>&1 | ForEach-Object { [string]$_.MessageData }) -join "`n")
        Assert-True ($out -match [regex]::Escape("[BLOCKED] $r")) 'caminho exibido'
        Assert-True ($out -match 'motivo: classe ACTIVE_EVIDENCE') 'motivo exibido'
        Assert-True ($out -match 'PID 1040') 'evidencias exibidas por completo'
    }
    Test-Case 'Gate V0.1' 'Nenhum script do produto altera politica de execucao' {
        $repo = Split-Path -Parent $testsDir
        foreach ($f in @(Get-ChildItem -LiteralPath $repo -Recurse -File -Include '*.ps1', '*.cmd' | Where-Object { $_.FullName -notmatch '\\(tests|\.git|dist)\\' })) {
            Assert-True (-not ([IO.File]::ReadAllText($f.FullName) -match 'Set-ExecutionPolicy')) "$($f.Name) altera politica"
        }
        $cmdTxt = [IO.File]::ReadAllText((Join-Path $srcDir 'bin\agent-temp.cmd'))
        Assert-True ($cmdTxt -match '-ExecutionPolicy Bypass -File') 'politica apenas no escopo do processo filho'
    }

    # ------------------------------------------------------------------ TUI (headless) and layering
    function New-Key { param([string]$Key, [char]$Char = [char]0) return New-Object ConsoleKeyInfo($Char, [ConsoleKey]$Key, $false, $false, $false) }
    function Invoke-HeadlessTui {
        param([object[]]$Keys, [hashtable]$InvArgs, [string[]]$Lines = @(), [switch]$Ascii, [int]$W = 120, [int]$H = 30, [scriptblock]$DiagRunner = $null)
        $script:tuiKeys = New-Object System.Collections.Generic.Queue[object]; foreach ($k in $Keys) { $script:tuiKeys.Enqueue($k) }
        $script:tuiLines = New-Object System.Collections.Generic.Queue[string]; foreach ($l in $Lines) { $script:tuiLines.Enqueue($l) }
        $script:tuiFrames = New-Object System.Collections.Generic.List[string]
        $ks = { if ($script:tuiKeys.Count -gt 0) { $script:tuiKeys.Dequeue() } else { $null } }
        $lr = { param($p) if ($script:tuiLines.Count -gt 0) { $script:tuiLines.Dequeue() } else { '' } }
        $rd = { param($frame) $script:tuiFrames.Add((($frame | ForEach-Object { ($_ | ForEach-Object { $_.Text }) -join '' }) -join "`n")) }
        $tuiArgs = @{ InventoryArgs = $InvArgs; KeySource = $ks; Renderer = $rd; LineReader = $lr; Ascii = $Ascii; Width = $W; Height = $H }
        if ($null -ne $DiagRunner) { $tuiArgs['DiagnoseRunner'] = $DiagRunner; $tuiArgs['DiagnoseArgs'] = @{} }
        $st = Start-AtmTui @tuiArgs
        return [pscustomobject]@{ State = $st; Frames = $script:tuiFrames.ToArray() }
    }
    Test-Case 'TUI' 'Navegacao headless: dashboard, usuarios, roots, detalhe, classes, erros, preview, ajuda' {
        $p = New-TestProfile 'tui'
        $r1 = New-TestRoot -ProfileInfo $p; $r2 = New-TestRoot -ProfileInfo $p
        [IO.File]::SetLastWriteTimeUtc((Join-Path $r2 'a.txt'), $nowFuture.AddHours(-1))
        $ia = Get-InvArgs -Profiles @($p)
        $keys = @((New-Key 'D1' '1'), (New-Key 'Escape'), (New-Key 'D2' '2'), (New-Key 'Enter'), (New-Key 'Enter'), (New-Key 'Escape'), (New-Key 'Escape'), (New-Key 'Escape'),
            (New-Key 'D6' '6'), (New-Key 'Escape'), (New-Key 'D8' '8'), (New-Key 'Escape'), (New-Key 'D9' '9'), (New-Key 'PageDown'), (New-Key 'Escape'), (New-Key 'P' 'p'), (New-Key 'DownArrow'), (New-Key 'Enter'), (New-Key 'Escape'), (New-Key 'Escape'),
            (New-Key 'H' 'h'), (New-Key 'Escape'), (New-Key 'D3' '3'), (New-Key 'Enter'), (New-Key 'Escape'), (New-Key 'Escape'), (New-Key 'Q' 'q'))
        $o = Invoke-HeadlessTui -Keys $keys -InvArgs $ia -H 40
        $all = $o.Frames -join "`n=====`n"
        foreach ($s in @((Get-AtmText 'menu.dashboard'), (Get-AtmText 'dash.profiles'), (Get-AtmText 'menu.users'), (Get-AtmText 'tui.detailOf' '').Trim(), 'RECENT', (Get-AtmText 'menu.blockedTitle'), (Get-AtmText 'menu.errorsTitle'), 'Preview', 'ELIGIBLE', (Get-AtmText 'menu.help'), (Get-AtmText 'menu.projects'), 'ORPHAN_SUSPECTED', (Get-AtmText 'det.fingerprint'))) { Assert-True ($all.Contains($s)) "tela contem '$s'" }
        Assert-True ($all.Contains((Split-Path $r1 -Leaf))) 'root listada'
        foreach ($f in $o.Frames) { foreach ($ln in ($f -split "`n")) { Assert-True ($ln.Length -le 120) "linha excede largura: $($ln.Length)" } }
        Assert-True ([IO.Directory]::Exists($r1) -and [IO.Directory]::Exists($r2)) 'TUI nao alterou nada'
    }
    Test-Case 'TUI' 'Fallback ASCII e terminal estreito (60x20)' {
        $p = New-TestProfile 'tuiascii'
        $null = New-TestRoot -ProfileInfo $p
        $o = Invoke-HeadlessTui -Keys @((New-Key 'D1' '1'), (New-Key 'Escape'), (New-Key 'D4' '4'), (New-Key 'Q' 'q')) -InvArgs (Get-InvArgs -Profiles @($p)) -Ascii -W 60 -H 20
        $all = $o.Frames -join "`n"
        Assert-True ($all -match '^[\x09\x0A\x20-\x7E]*$') 'somente ASCII imprimivel'
        foreach ($f in $o.Frames) { foreach ($ln in ($f -split "`n")) { Assert-True ($ln.Length -le 60) 'largura' } }
    }
    Test-Case 'TUI' 'Limpeza pela TUI usa o motor: allowlist, plano, frase; cancelamentos nao apagam' {
        # Both prompt flows, whatever the session: an administrator is also asked whether to include other users
        # (answered with an empty line = no), which shifts every later answer by one line.
        foreach ($asAdmin in @($false, $true)) {
            $p = New-TestProfile ('tuiclean' + [int]$asAdmin)
            $r = New-TestRoot -ProfileInfo $p
            $ia = Get-InvArgs -Profiles @($p) -Identity ([pscustomobject]@{ Sid = $testOwnerSid; Name = $me.Name; IsAdmin = $asAdmin })
            $others = @(if ($asAdmin) { '' })
            $o = Invoke-HeadlessTui -Keys @((New-Key 'L' 'l'), (New-Key 'Q' 'q')) -InvArgs $ia -Lines @('', '', '')
            Assert-True ([IO.Directory]::Exists($r)) "cancelado: preservado (admin=$asAdmin)"
            $o = Invoke-HeadlessTui -Keys @((New-Key 'L' 'l'), (New-Key 'Q' 'q')) -InvArgs $ia -Lines (@('', $r) + $others + @('APAGAR 1 caminhos', ''))
            Assert-True ([IO.Directory]::Exists($r)) "frase errada: preservado (admin=$asAdmin)"
            Assert-Eq $o.State.LastClean.Aborted 'CONFIRMACAO_AUSENTE_OU_DIVERGENTE' "motor abortou (admin=$asAdmin)"
            $o = Invoke-HeadlessTui -Keys @((New-Key 'L' 'l'), (New-Key 'Q' 'q')) -InvArgs $ia -Lines (@('', "$(Get-Base $p)") + $others + @(''))
            Assert-Eq $o.State.LastClean.Aborted 'NENHUM_CAMINHO_ELEGIVEL' "base recusada pelo motor (admin=$asAdmin)"
            $o = Invoke-HeadlessTui -Keys @((New-Key 'L' 'l'), (New-Key 'Q' 'q')) -InvArgs $ia -Lines (@('', $r) + $others + @('APAGAR 1 CAMINHOS', ''))
            Assert-True (-not [IO.Directory]::Exists($r)) "confirmado: excluido pelo motor (admin=$asAdmin)"
            Assert-True ($null -ne $o.State.LastClean.PostInventory) "auditoria posterior (admin=$asAdmin)"
        }
    }
    Test-Case 'Camadas' 'TUI e relatorio nunca chamam APIs de exclusao; motor de auditoria nao exclui nem imprime' {
        $lib = Join-Path $srcDir 'lib'
        foreach ($f in @('Tui.ps1', 'Report.ps1')) {
            $txt = [IO.File]::ReadAllText((Join-Path $lib $f))
            foreach ($pat in @('AtmDeleter', 'DeleteTree', 'Remove-Item', '::Delete(', '.Delete(', 'rd /s', 'rmdir', 'del ')) { Assert-True (-not $txt.Contains($pat)) "$f contem '$pat'" }
        }
        $audit = [IO.File]::ReadAllText((Join-Path $lib 'Engine.Audit.ps1'))
        foreach ($pat in @('AtmDeleter', 'DeleteTree', 'Remove-Item', 'Write-Host', 'Write-Progress', 'Read-Host')) { Assert-True (-not $audit.Contains($pat)) "Engine.Audit contem '$pat'" }
        $clean = [IO.File]::ReadAllText((Join-Path $lib 'Engine.Clean.ps1'))
        foreach ($pat in @('Write-Host', 'Read-Host', 'Remove-Item', '-Force')) { Assert-True (-not $clean.Contains($pat)) "Engine.Clean contem '$pat'" }
        Assert-Eq ([regex]::Matches($clean, 'AtmDeleter\]::DeleteTree').Count) 1 'um unico ponto de exclusao, apos revalidacao'
    }
    Test-Case 'Gate V0.1' 'FINAL-B F-10: motor de exclusao contra arvore descartavel do harness - pasta vazia pinada convertida em juncao dentro da janela (FSCTL) recusada, alvo sentinela intacto; juncao presente antes do inicio, ancestral juncao e renomeacao de pasta pinada recusados sem nada apagado fora da arvore; trava distribuida fechada' {
        # Native engine only (AtmDeleter), on a tree the harness creates; every junction points to a sentinel folder INSIDE
        # the sandbox, so even a defect could only touch sandbox content. The distributed gate is never opened here.
        # The harness opens the gate in memory for its sandbox (top of this file); the distributed copy keeps it closed.
        $gateSrc = [IO.File]::ReadAllText((Join-Path $srcDir 'lib\Engine.Clean.ps1'))
        $gateClosed = { [regex]::Matches($gateSrc, '\$script:AtmRealDeletionEnabled\s*=').Count -eq 1 -and $gateSrc -match '(?m)^\$script:AtmRealDeletionEnabled = \$false\r?$' }
        Assert-True (& $gateClosed) 'trava distribuida fechada (atribuicao unica $false em Engine.Clean.ps1)'
        Initialize-AtmTestReparse
        $f10 = [AgentTempManager.AtmNative]::GetLongPath((New-Item -ItemType Directory -Path (Join-Path $sandbox 'f10')).FullName)
        $sent = Join-Path $f10 'sentinel'
        foreach ($d in @($sent, (Join-Path $sent 'deep'))) { [void][IO.Directory]::CreateDirectory($d) }
        [IO.File]::WriteAllText((Join-Path $sent 'keep.txt'), 'keep'); [IO.File]::WriteAllText((Join-Path $sent 'deep\deep.txt'), 'deep')
        $snap = { @(Get-ChildItem -LiteralPath $sent -Recurse -Force | ForEach-Object { $_.FullName.Substring($sent.Length) + '|' + $(if ($_.PSIsContainer) { 'd' } else { [IO.File]::ReadAllText($_.FullName) }) } | Sort-Object) -join ';' }
        $before = & $snap
        $newTree = { param([string]$Name) $t = Join-Path $f10 $Name; foreach ($d in @($t, (Join-Path $t 'empty'), (Join-Path $t 'sub'))) { [void][IO.Directory]::CreateDirectory($d) }; [IO.File]::WriteAllText((Join-Path $t 'top.txt'), 't'); [IO.File]::WriteAllText((Join-Path $t 'sub\file.txt'), 'f'); $t }
        # 1. Inside the window: everything pinned and planned, then another handle turns the empty pinned folder into a
        #    junction (share modes do not stop it: M-1). The bottom-up re-check must refuse it; the target is never traversed.
        $t1 = & $newTree 'tree1'
        $st = @{ Set = $null }
        $hook = [Action[string]]({ param($root) $st.Set = [AtmTestReparse]::SetJunction((Join-Path $root 'empty'), $sent) }.GetNewClosure())
        $r1 = [AgentTempManager.AtmDeleter]::DeleteTree($t1, $hook)
        Assert-Eq $st.Set 'SET_OK' 'juncao gravada na pasta pinada por outro handle (limite documentado)'
        Assert-True (-not $r1.Completed -and [string]$r1.AbortReason -like 'PINNED_DIR_CHANGED*') "exclusao recusada na reverificacao ($($r1.AbortReason))"
        Assert-Eq (& $snap) $before 'alvo sentinela intacto (nada apagado nem atravessado)'
        $lnk = Join-Path $t1 'empty'
        if ((Test-Path -LiteralPath $lnk) -and (([IO.File]::GetAttributes($lnk) -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { [IO.Directory]::Delete($lnk, $false) }
        # 2. A junction already in the tree when the deletion starts: refused while planning, nothing deleted.
        $t2 = & $newTree 'tree2'
        [IO.Directory]::Delete((Join-Path $t2 'empty'), $false)
        $o = & cmd.exe /c "mklink /J `"$(Join-Path $t2 'empty')`" `"$sent`"" 2>&1; Assert-Eq $LASTEXITCODE 0 "juncao de fixture criada ($o)"
        $r2 = [AgentTempManager.AtmDeleter]::DeleteTree($t2)
        Assert-True (-not $r2.Attempted -and $r2.FilesDeleted -eq 0 -and [string]$r2.AbortReason -like 'REPARSE_POINT_FOUND*') "juncao antes do inicio: recusada sem apagar ($($r2.AbortReason))"
        Assert-True ((Test-Path -LiteralPath (Join-Path $t2 'top.txt')) -and (& $snap) -eq $before) 'arvore e sentinela intactas'
        [IO.Directory]::Delete((Join-Path $t2 'empty'), $false)
        # 3. An ancestor that is a junction: refused before anything is pinned.
        $t3 = & $newTree 'tree3'
        $via = Join-Path $f10 'via'
        $o = & cmd.exe /c "mklink /J `"$via`" `"$t3`"" 2>&1; Assert-Eq $LASTEXITCODE 0 "juncao ancestral de fixture criada ($o)"
        $r3 = [AgentTempManager.AtmDeleter]::DeleteTree((Join-Path $via 'sub'))
        Assert-True (-not $r3.Attempted -and [string]$r3.AbortReason -like 'ANCESTOR_REPARSE_POINT*') "ancestral juncao: recusado ($($r3.AbortReason))"
        Assert-True (Test-Path -LiteralPath (Join-Path $t3 'sub\file.txt')) 'nada apagado pelo caminho com juncao'
        [IO.Directory]::Delete($via, $false)
        # 4. A pinned folder cannot be renamed during the window (its identity cannot change under the engine).
        $t4 = & $newTree 'tree4'
        $mv = @{ Threw = $false }
        $hook4 = [Action[string]]({ param($root) try { [IO.Directory]::Move((Join-Path $root 'sub'), (Join-Path $root 'sub-moved')) } catch { $mv.Threw = $true } }.GetNewClosure())
        $r4 = [AgentTempManager.AtmDeleter]::DeleteTree($t4, $hook4)
        Assert-True ($mv.Threw -and -not (Test-Path -LiteralPath (Join-Path $t4 'sub-moved'))) 'renomear pasta pinada durante a janela: recusado pelo sistema'
        Assert-True ($r4.Completed -and -not (Test-Path -LiteralPath $t4)) "arvore descartavel inteira apagada pelo motor depois da tentativa ($($r4.AbortReason))"
        Assert-Eq (& $snap) $before 'sentinela intacta ao final'
        $gateSrc = [IO.File]::ReadAllText((Join-Path $srcDir 'lib\Engine.Clean.ps1'))
        Assert-True (& $gateClosed) 'trava distribuida fechada ao final'
        $script:caseNote = "janela: $($r1.AbortReason -replace ':.*$', ''); antes do inicio: $($r2.AbortReason -replace ':.*$', ''); ancestral: $($r3.AbortReason -replace ':.*$', '')"
    }
    Test-Case 'Gate V0.1' 'FINAL-B F-10: verificacao do caminho final por handle - arvore alcancada por uma unidade subst recusada (PATH_REDIRECTED), nada apagado' {
        $real = Join-Path $sandbox 'f10-subst'
        foreach ($d in @($real, (Join-Path $real 'tree5\sub'))) { [void][IO.Directory]::CreateDirectory($d) }
        [IO.File]::WriteAllText((Join-Path $real 'tree5\sub\file.txt'), 'f')
        $sl = $null; foreach ($l in [char[]]'QRSTUVWXYZ') { if (-not (Test-Path "$($l):\")) { $sl = $l; break } }
        if (-not $sl) { $script:caseSkipped = $true; $script:caseNote = 'nenhuma letra de unidade livre'; return }
        $null = cmd /c subst "$($sl):" "`"$real`"" 2>&1
        try {
            if (-not (Test-Path "$($sl):\tree5")) { $script:caseSkipped = $true; $script:caseNote = 'subst indisponivel'; return }
            $r = [AgentTempManager.AtmDeleter]::DeleteTree("$($sl):\tree5")
            Assert-True (-not $r.Attempted -and $r.FilesDeleted -eq 0 -and [string]$r.AbortReason -like '*PATH_REDIRECTED*') "caminho final diferente do pedido: recusado ($($r.AbortReason -replace ':.*$', ''))"
            Assert-True (Test-Path -LiteralPath (Join-Path $real 'tree5\sub\file.txt')) 'nada apagado'
            $script:caseNote = "unidade subst: $($r.AbortReason -replace ':.*$', '')"
        } finally { $null = cmd /c subst "$($sl):" /d 2>&1 }
    }
    Test-Case 'Privacidade' 'Scanner detecta dados pessoais plantados e aceita apenas os valores ficticios do projeto' {
        $scan = Join-Path (Split-Path -Parent $testsDir) 'tools\Test-AtmPrivacy.ps1'
        $d = Join-Path $sandbox 'privacy-probe'; [void][IO.Directory]::CreateDirectory($d)
        $fakeSid = 'S-1-5-21-' + '111111111-222222222-333333333-1001'
        $fakeMail = 'maria.silva' + '@' + 'exemplo-real.com.br'
        $fakePath = 'C:' + '\Users\' + 'MariaSilva\AppData'
        $fakeTok = 'sk-ant-' + 'api03-AbCdEfGhIjKlMnOp'
        $fakeHost = 'DESKTOP-' + 'Q1W2E3R'
        [IO.File]::WriteAllText((Join-Path $d 'vazamento.md'), "$fakeSid`n$fakeMail`n$fakePath`n$fakeTok`n$fakeHost`nSEGREDO-PRIVADO-XYZ`n")
        [IO.File]::WriteAllText((Join-Path $d 'ficticio.md'), "C:\Users\alice\AppData S-1-5-21-1-2-3-777 S-1-5-21-9-9-9-1000 C:\Users\EXAMPL~1\x noreply@anthropic.com")
        $f = @(& $scan -Path $d -ExtraNeedles @('SEGREDO-PRIVADO-XYZ'))
        foreach ($k in @('SID', 'EMAIL', 'USER_PATH', 'TOKEN', 'MACHINE', 'PRIVATE_IDENTIFIER')) { Assert-True (@($f | Where-Object { $_.Kind -eq $k -and $_.File -eq 'vazamento.md' }).Count -ge 1) "detecta $k" }
        Assert-Eq @($f | Where-Object { $_.File -eq 'ficticio.md' }).Count 0 'valores ficticios aceitos'
        Assert-True (@($f | Where-Object { $_.Excerpt -match 'MariaSilva|111111111|exemplo-real' }).Count -eq 0) 'achados nao reproduzem o dado'
    }
    Test-Case 'Privacidade' 'FINAL-A-S: identificador da maquina igual a uma palavra do produto nao e procurado (com aviso); nome que apenas contem a palavra e identificador explicito continuam detectados' {
        $scan = Join-Path (Split-Path -Parent $testsDir) 'tools\Test-AtmPrivacy.ps1'
        $d = Join-Path $sandbox 'privacy-words'; [void][IO.Directory]::CreateDirectory($d)
        [IO.File]::WriteAllText((Join-Path $d 'produto.md'), "The installer verifies the manifest; TrustedInstaller keeps its access.`n")
        $joined = 'installer' + '-maria-p'
        [IO.File]::WriteAllText((Join-Path $d 'nome.md'), "account $joined`n")
        $savedUser = $env:USERNAME
        try {
            # The same filter runs for every needle taken from the machine (environment, SID, ProfileList).
            $env:USERNAME = 'Installer'
            $wv = $null
            $f = @(& $scan -Path $d -WarningVariable wv -WarningAction SilentlyContinue)
            Assert-Eq @($f | Where-Object { $_.Kind -eq 'PRIVATE_IDENTIFIER' -and $_.File -eq 'produto.md' }).Count 0 'palavra do produto vinda da maquina: texto do produto aceito'
            Assert-True (@($wv | Where-Object { [string]$_ -match "from USERNAME equals the product word 'installer'" }).Count -eq 1) 'aviso visivel com a origem e a palavra (nunca silencioso)'
            $env:USERNAME = $joined
            $wv = $null
            $f = @(& $scan -Path $d -WarningVariable wv -WarningAction SilentlyContinue)
            Assert-True (@($f | Where-Object { $_.Kind -eq 'PRIVATE_IDENTIFIER' -and $_.File -eq 'nome.md' }).Count -ge 1 -and @($wv | Where-Object { [string]$_ -match 'from USERNAME equals the product word' }).Count -eq 0) 'nome que apenas contem a palavra: detectado, sem aviso dessa origem (outra origem desta maquina pode avisar)'
        } finally { $env:USERNAME = $savedUser }
        $f = @(& $scan -Path $d -ExtraNeedles @('installer') -WarningAction SilentlyContinue)
        Assert-True (@($f | Where-Object { $_.Kind -eq 'PRIVATE_IDENTIFIER' -and $_.File -eq 'produto.md' }).Count -ge 1) 'identificador explicito igual a palavra: sempre procurado'
        $src = [IO.File]::ReadAllText($scan)
        Assert-True ($src.Contains("`$machineNeedles.Add(@('ProfileList', `$leaf))") -and $src.Contains("`$productWords = @('installer')") -and -not $src.Contains("`$needles.Add(`$leaf)")) 'ProfileList passa pelo mesmo filtro; lista com uma unica palavra'
    }
    Test-Case 'Privacidade' 'FINAL-B: artefatos de CI - identificadores desta maquina trocados por marcadores antes do envio; varredura falha fechada (achado, scanner ausente); arquivo compactado varrido e nunca alterado; relatorio sem nome de conta' {
        $tool = Join-Path (Split-Path -Parent $testsDir) 'tools\Protect-AtmArtifact.ps1'
        $shell = (Get-Process -Id $PID).Path
        $run = { param([string]$ArgLine) Invoke-AtmTestChild -CommandLine ("`"$shell`" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$tool`" " + $ArgLine) -TimeoutSec 180 }
        $d = Join-Path $sandbox 'artifact-ok'; [void][IO.Directory]::CreateDirectory($d)
        $fakeSid = 'S-1-5-21-' + '111111111-222222222-333333333-1001'
        $rep = Join-Path $d 'report.json'
        $raw = '{ "detail": "' + ($sandbox + '\x.txt').Replace('\', '\\') + '", "who": "' + $env:USERNAME + '", "machine": "' + $env:COMPUTERNAME + '", "sid": "' + $fakeSid + '", "test": "S-1-5-21-1-2-3-777", "home": "' + $env:USERPROFILE + '" }'
        [IO.File]::WriteAllText($rep, $raw)
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zsrc = Join-Path $sandbox 'artifact-zip-src'; [void][IO.Directory]::CreateDirectory($zsrc); [IO.File]::WriteAllText((Join-Path $zsrc 'a.txt'), 'clean')
        $zip = Join-Path $d 'pkg.zip'; [IO.Compression.ZipFile]::CreateFromDirectory($zsrc, $zip)
        $zh = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
        $r = & $run ("-Path `"$d`"")
        Assert-Eq $r.Exit 0 "artefato limpo depois da troca: exit 0 ($($r.Text))"
        $after = [IO.File]::ReadAllText($rep)
        foreach ($x in @($env:USERNAME, $env:COMPUTERNAME, $fakeSid, $env:USERPROFILE, $env:USERPROFILE.Replace('\', '\\'))) { Assert-True ($after.IndexOf($x, [StringComparison]::OrdinalIgnoreCase) -lt 0) 'identificador desta maquina trocado no artefato' }
        # The account may also be a profile folder name of this machine: either placeholder replaces it.
        Assert-True ($after.Contains('<temp>') -and ($after.Contains('<account>') -or $after.Contains('<profile-name>')) -and $after.Contains('<sid>') -and $after.Contains('S-1-5-21-1-2-3-777') -and $after.Contains('<profile>')) "marcadores no lugar; SID ficticio do projeto mantido ($after)"
        Assert-Eq (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash $zh 'arquivo compactado nunca alterado'
        Assert-True ($r.Text -match '1 archive\(s\)') "arquivo compactado varrido ($($r.Text))"
        # A value the sanitizer does not know (an address) is still found by the scanner: exit 1, location only.
        $d2 = Join-Path $sandbox 'artifact-leak'; [void][IO.Directory]::CreateDirectory($d2)
        $mail = 'maria.silva' + '@' + 'exemplo-real.com.br'
        [IO.File]::WriteAllText((Join-Path $d2 'out.txt'), "contato $mail")
        $r = & $run ("-Path `"$d2`"")
        Assert-Eq $r.Exit 1 "achado: exit 1 ($($r.Text))"
        Assert-True ($r.Text -match 'FINDING out\.txt:1 EMAIL' -and $r.Text -notmatch 'maria|exemplo-real') 'achado por arquivo, linha e tipo, sem o valor'
        # The scan cannot be trusted: exit 2 (fail closed), never a silent pass.
        $r = & $run ("-Path `"$d`" -Scanner `"$(Join-Path $sandbox 'nao-existe.ps1')`"")
        Assert-Eq $r.Exit 2 "scanner ausente: exit 2 ($($r.Text))"
        # The suite's own details and report: placeholders, no account name.
        Assert-True ((ConvertTo-AtmArtifactSafeText -Text "$sandbox\y" -Identifiers $script:safeIds).StartsWith('<temp>')) 'detalhe dos casos: sandbox sob <temp>'
        $self = [IO.File]::ReadAllText((Join-Path $testsDir 'Run-Tests.ps1'))
        Assert-True ($self.Contains("accountKind = `$(if (`$me.IsAdmin)") -and -not $self.Contains('user = ' + '$me.Name')) 'relatorio: tipo de conta, sem nome'
    }
    Test-Case 'Privacidade' 'Identidade Git: autor, committer e trailers; noreply aceito; pessoal detectado sem expor o endereco' {
        if (-not (Get-Command git -ErrorAction SilentlyContinue)) { $script:caseSkipped = $true; $script:caseNote = 'git indisponivel'; return }
        $tool = Join-Path (Split-Path -Parent $testsDir) 'tools\Test-AtmCommitIdentity.ps1'
        $shell = (Get-Process -Id $PID).Path
        $g = Join-Path $sandbox 'identity-repo'; [void][IO.Directory]::CreateDirectory($g)
        # Fictitious addresses, assembled at run time so the privacy scanner never sees them in the source.
        $personal = 'maria.teste' + '@' + 'exemplo-pessoal.com.br'
        $other = 'joao.contrib' + '@' + 'exemplo-pessoal.com.br'
        $noreply = '1234567+alice-dev' + '@' + 'users.noreply.github.com'
        $botMail = '49699333+dependabot[bot]' + '@' + 'users.noreply.github.com'
        $webflow = 'noreply' + '@' + 'github.com'
        $ghSupport = 'support' + '@' + 'github.com'
        $assistant = 'noreply' + '@' + 'anthropic.com'
        $saved = @{}; foreach ($v in @('GIT_CONFIG_GLOBAL', 'GIT_CONFIG_NOSYSTEM', 'GIT_AUTHOR_NAME', 'GIT_AUTHOR_EMAIL', 'GIT_COMMITTER_NAME', 'GIT_COMMITTER_EMAIL')) { $saved[$v] = [Environment]::GetEnvironmentVariable($v) }
        $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        try {
            # Isolated from the user's and the system's Git configuration (no hooks, signing or identity leak in).
            $env:GIT_CONFIG_GLOBAL = Join-Path $g 'empty.gitconfig'; [IO.File]::WriteAllText($env:GIT_CONFIG_GLOBAL, '')
            $env:GIT_CONFIG_NOSYSTEM = '1'
            & git -C $g init -q 2>&1 | Out-Null
            function New-IdCommit([string]$Author, [string]$Committer, [string[]]$Trailers = @()) {
                $env:GIT_AUTHOR_NAME = 'Autor'; $env:GIT_AUTHOR_EMAIL = $Author
                $env:GIT_COMMITTER_NAME = 'Committer'; $env:GIT_COMMITTER_EMAIL = $Committer
                $msg = @('-m', 'teste'); if ($Trailers.Count) { $msg += @('-m', ($Trailers -join "`n")) }
                & git -C $g commit -q --allow-empty @msg 2>&1 | Out-Null
                Assert-Eq $LASTEXITCODE 0 'commit de teste'
                return (& git -C $g rev-parse HEAD).Trim()
            }
            function Invoke-IdTool([string[]]$ToolArgs) {
                $out = @(& $shell -NoProfile -ExecutionPolicy Bypass -File $tool -RepoDir $g @ToolArgs 2>&1 | ForEach-Object { "$_" })
                return [pscustomobject]@{ Code = $LASTEXITCODE; Text = ($out -join "`n") }
            }
            $c0 = New-IdCommit $noreply $noreply @("Co-authored-by: Assistente <$assistant>")
            $c1 = New-IdCommit $botMail $webflow @("Signed-off-by: dependabot[bot] <$ghSupport>")
            $r = Invoke-IdTool @('-All')
            Assert-Eq $r.Code 0 "noreply, bot, web-flow e trailers organizacionais aceitos: $($r.Text)"

            $c2 = New-IdCommit $personal $noreply
            $c3 = New-IdCommit $noreply $personal                       # what a GitHub merge did in the incident
            $c4 = New-IdCommit $noreply $noreply @("Co-authored-by: Joao <$other>", "Signed-off-by: Maria <$personal>")
            $c5 = New-IdCommit $assistant $noreply                       # trailer-only address used as author
            $r = Invoke-IdTool @('-All')
            Assert-Eq $r.Code 1 'achados geram codigo 1'
            foreach ($exp in @("$($c2.Substring(0, 12)) author", "$($c3.Substring(0, 12)) committer", "$($c4.Substring(0, 12)) Co-authored-by", "$($c4.Substring(0, 12)) Signed-off-by", "$($c5.Substring(0, 12)) author")) {
                Assert-True ($r.Text -match [regex]::Escape($exp)) "detecta $exp"
            }
            Assert-True ($r.Text -match 'achados: 5') "cinco achados: $($r.Text)"
            foreach ($secret in @($personal, $other, 'maria.teste', 'joao.contrib', 'exemplo-pessoal')) { Assert-True (-not $r.Text.Contains($secret)) 'endereco nunca aparece completo' }
            Assert-True ($r.Text -match 'm\*\*\*@e\*\*\*') 'endereco mascarado'

            $r = Invoke-IdTool @('-Range', "$c1..$c2")
            Assert-Eq $r.Code 1 'faixa com um commit pessoal'
            Assert-True ($r.Text -match 'commits verificados: 1 ') 'a faixa limita os commits verificados'
            $r = Invoke-IdTool @('-Range', "$c0..$c1")
            Assert-Eq $r.Code 0 'faixa limpa'
            $r = Invoke-IdTool @('-Commit', $c3)
            Assert-Eq $r.Code 1 'commit unico (push) com committer pessoal'

            $al = Join-Path $sandbox 'identity-allowlist.txt'
            [IO.File]::WriteAllText($al, "# teste`nemail:$($personal.ToUpperInvariant())`nemail:$other`ncommit:$c5`n")
            $r = Invoke-IdTool @('-All', '-AllowListFile', $al)
            Assert-Eq $r.Code 0 "allow-list: e-mails publicados por decisao e commit aceito ($($r.Text))"
            Assert-True ($r.Text -match 'excecoes aceitas: 1') 'commit aceito contabilizado'
            [IO.File]::WriteAllText($al, "email:nao-e-um-endereco`n")
            $r = Invoke-IdTool @('-All', '-AllowListFile', $al)
            Assert-Eq $r.Code 2 'linha invalida na allow-list e erro (nao aceita tudo)'
            $r = Invoke-IdTool @('-All', '-Commit', $c0)
            Assert-Eq $r.Code 2 'parametros conflitantes'
            $r = Invoke-IdTool @('-Range', 'ref-inexistente..HEAD')
            Assert-Eq $r.Code 2 'faixa invalida e erro, nunca "limpo"'
        } finally {
            $ErrorActionPreference = $eap
            foreach ($v in $saved.Keys) { [Environment]::SetEnvironmentVariable($v, $saved[$v]) }
        }
    }
    Test-Case 'Privacidade' 'Repositorio (arquivos de trabalho e index Git) sem dados pessoais, da maquina ou privados' {
        $repo = Split-Path -Parent $testsDir
        $scan = Join-Path $repo 'tools\Test-AtmPrivacy.ps1'
        $copy = Join-Path $sandbox 'publishable'
        foreach ($rel in @('src', 'install', 'docs', 'tests', 'tools', '.github')) { if (Test-Path (Join-Path $repo $rel)) { Copy-AtmTree -From (Join-Path $repo $rel) -To (Join-Path $copy $rel) } }
        # '.git' is a file (pointer to the main repository) in a linked worktree; it is never published.
        foreach ($f in @(Get-ChildItem -LiteralPath $repo -File -Force | Where-Object { $_.Name -ne '.git' })) { Copy-Item -LiteralPath $f.FullName -Destination $copy }
        $pw = $null
        $hits = @(& $scan -Path $copy -NeedlesFile $env:ATM_PRIVATE_NEEDLES -WarningVariable pw -WarningAction SilentlyContinue)
        # A weaker scan stays visible in the result (source and product word only, never a name of this machine).
        if (@($pw).Count -gt 0) { $script:caseNote = 'avisos do scanner: ' + ((@($pw) | ForEach-Object { [string]$_ } | Sort-Object -Unique) -join ' | ') }
        Assert-Eq $hits.Count 0 (($hits | ForEach-Object { "$($_.File):$($_.Line) $($_.Kind)" }) -join '; ')
        if ((Get-Command git -ErrorAction SilentlyContinue) -and (Test-Path (Join-Path $repo '.git'))) {
            $idx = Join-Path $sandbox 'git-index'
            $ErrorActionPreference = 'Continue'
            foreach ($p in @(& git -C $repo ls-files 2>$null)) {
                $dst = Join-Path $idx ($p.Replace('/', '\'))
                [void][IO.Directory]::CreateDirectory((Split-Path -Parent $dst))
                $blob = (& git -C $repo show ":$p" 2>$null) -join "`n"
                [IO.File]::WriteAllText($dst, [string]$blob)
            }
            if (Test-Path $idx) {
                $h2 = @(& $scan -Path $idx -NeedlesFile $env:ATM_PRIVATE_NEEDLES)
                Assert-Eq $h2.Count 0 ('index Git: ' + (($h2 | ForEach-Object { "$($_.File):$($_.Line) $($_.Kind)" }) -join '; '))
            }
            $ignored = @(& git -C $repo status --short --ignored 2>$null | Where-Object { $_ -like '!!*' } | ForEach-Object { $_.Substring(3) })
            foreach ($i in $ignored) { Assert-True ($i -in @('dist/')) "arquivo ignorado inesperado: $i" }
        }
    }
    Test-Case 'Configuracao' 'Regras locais opcionais; sem regra nem evidencia o projeto e "nao identificado"' {
        $cd = Join-Path $sandbox 'cfg'; [void][IO.Directory]::CreateDirectory($cd)
        Copy-Item (Join-Path $cfgDir 'projects.json') $cd
        $cfg0 = Get-AtmConfig -ConfigDir $cd
        Assert-Eq @($cfg0.projects).Count 0 'sem projects.local.json: nenhuma regra (generico)'
        $prov = (Get-AtmProviders)[0]
        $u = Resolve-AtmProject -Slug 'C--Users-x-src-beta' -ProfilePath 'C:\Users\x' -Config $cfg0 -Provider $prov
        Assert-Eq $u.Name (Get-AtmText 'project.unknown') 'nao identificado'
        Assert-True (-not $u.Identified) 'flag'
        Assert-True ((Get-AtmText 'project.unknown') -match '^Projeto n.o identificado$') 'texto padrao pt-BR'
        [IO.File]::WriteAllText((Join-Path $cd 'projects.local.json'), '{"projects":[{"name":"Alpha","pattern":"alpha-?svc"}]}')
        $cfg = Get-AtmConfig -ConfigDir $cd
        Assert-Eq (Resolve-AtmProject -Slug 'C--Users-x-src-alpha-svc' -ProfilePath 'C:\Users\x' -Config $cfg -Provider $prov).Name 'Alpha' 'regra local'
        Assert-Eq (Resolve-AtmProject -Slug 'C--Users-x' -ProfilePath 'C:\Users\x' -Config $cfg -Provider $prov).Name (Get-AtmText 'project.home') 'home'
        $ev = @{ 'c--src-gamma' = 'gamma' }
        $g = Resolve-AtmProject -Slug 'C--src-gamma' -ProfilePath 'C:\Users\x' -Config $cfg -Provider $prov -EvidenceNames $ev
        Assert-True ($g.Identified -and $g.Name -eq 'gamma' -and $g.Source -eq (Get-AtmText 'project.srcSession')) 'evidencia de sessao'
    }

    # ------------------------------------------------------------------ i18n (pt-BR / en-US)
    Test-Case 'I18n' 'Catalogo: paridade de chaves, mesmos placeholders e nenhuma chave usada sem traducao' {
        $en = $script:AtmMessages['en-US']; $pt = $script:AtmMessages['pt-BR']
        Assert-Eq @($en.Keys | Where-Object { -not $pt.ContainsKey($_) }).Count 0 'chaves so em en-US'
        Assert-Eq @($pt.Keys | Where-Object { -not $en.ContainsKey($_) }).Count 0 'chaves so em pt-BR'
        foreach ($k in $en.Keys) {
            $a = @([regex]::Matches($en[$k], '\{(\d+)') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique) -join ','
            $b = @([regex]::Matches($pt[$k], '\{(\d+)') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique) -join ','
            Assert-Eq $b $a "placeholders de '$k'"
        }
        $repo = Split-Path -Parent $testsDir
        $used = @(Get-ChildItem (Join-Path $repo 'src'), (Join-Path $repo 'install') -Recurse -Filter '*.ps1' | Select-String -Pattern "Get-AtmText\s+'([^']+)'" -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
        $missing = @($used | Where-Object { -not $en.ContainsKey($_) })
        Assert-Eq $missing.Count 0 ('chaves usadas sem entrada: ' + ($missing -join ','))
        foreach ($code in @('AUDITADO', 'AUDITADO_PARCIAL', 'TEMP_NAO_VERIFICAVEL', 'INACESSIVEL', 'NAO_AUDITADO_REPARSE', 'NAO_AUDITADO_UNIDADE', 'SEM_TEMP_CLAUDE')) { Assert-True $en.ContainsKey("status.$code") "status.$code" }
        foreach ($m in @('dll', 'memory')) { Assert-True $en.ContainsKey("native.$m") "native.$m" }
    }
    Test-Case 'I18n' 'Resolucao de idioma e fallback seguro (desconhecido -> en-US; chave ausente -> [chave]; formato invalido nao lanca)' {
        try {
            Set-AtmLanguage -Requested 'en-US'; Assert-Eq (Get-AtmLanguage) 'en-US' 'explicito en-US'
            Set-AtmLanguage -Requested 'pt-br'; Assert-Eq (Get-AtmLanguage) 'pt-BR' 'explicito pt (qualquer caixa)'
            Set-AtmLanguage -Requested 'pt-PT'; Assert-Eq (Get-AtmLanguage) 'pt-BR' 'pt-* -> pt-BR'
            Set-AtmLanguage -Requested 'xx-YY'; Assert-Eq (Get-AtmLanguage) 'en-US' 'desconhecido -> en-US'
            Set-AtmLanguage -Requested 'de-DE'; Assert-Eq (Get-AtmLanguage) 'en-US' 'nao suportado -> en-US'
            $old = $env:ATM_LANG; $env:ATM_LANG = 'en-US'; Set-AtmLanguage; Assert-Eq (Get-AtmLanguage) 'en-US' 'ATM_LANG'; $env:ATM_LANG = $old
            Assert-Eq (Get-AtmText 'chave.que.nao.existe') '[chave.que.nao.existe]' 'chave ausente'
            Assert-True ((Get-AtmText 'audit.total') -match '\{0\}') 'sem argumentos: modelo intacto, sem excecao'
            $script:AtmMessages['pt-BR'].Remove('preview.done'); Set-AtmLanguage -Requested 'pt-BR'
            Assert-True ((Get-AtmText 'preview.done') -match '^PREVIEW: nothing') 'chave ausente em pt-BR cai para en-US'
        } finally {
            . (Join-Path $srcDir 'lib\I18n.ps1')
            Set-AtmLanguage -Requested 'pt-BR'
        }
    }
    Test-Case 'I18n' 'en-US: auditoria, preview, plano de limpeza e TUI totalmente em ingles; codigos do motor identicos' {
        $p = New-TestProfile 'idioma'
        $r = New-TestRoot -ProfileInfo $p
        [IO.File]::SetLastWriteTimeUtc((Join-Path $r 'a.txt'), $nowFuture.AddHours(-1))
        $r2 = New-TestRoot -ProfileInfo $p
        try {
            Set-AtmLanguage -Requested 'pt-BR'
            $iPt = Inv -Profiles @($p)
            Set-AtmLanguage -Requested 'en-US'
            $iEn = Inv -Profiles @($p)
            foreach ($x in @($r, $r2)) {
                Assert-Eq (Find-Part $iEn $x).Class (Find-Part $iPt $x).Class 'classe identica'
                Assert-Eq ((Find-Part $iEn $x).Flags -join ',') ((Find-Part $iPt $x).Flags -join ',') 'flags identicas'
            }
            $gPt = Invoke-AtmPreview -Inventory $iPt; $gEn = Invoke-AtmPreview -Inventory $iEn
            Assert-Eq (@($gEn | ForEach-Object { $_.Gate.Category }) -join ',') (@($gPt | ForEach-Object { $_.Gate.Category }) -join ',') 'categorias identicas'
            $msg = { param($sb) (@(& $sb 6>&1 | ForEach-Object { [string]$_.MessageData }) -join "`n") }
            $audit = & $msg { Show-AtmAudit -Inventory $iEn }
            $prev = & $msg { Show-AtmPreview -Inventory $iEn -Rows $gEn }
            $plan = & $msg { Show-AtmCleanPlan -Verified @() -Rejected @() -Inventory $iEn }
            foreach ($s in @('GENERAL SUMMARY', 'SUMMARY BY USER / SID', 'FINAL SUMMARY', 'Read-only mode')) { Assert-True ($audit.Contains($s)) "audit en: $s" }
            foreach ($s in @('BLOCKED PATHS', 'TECHNICALLY ELIGIBLE', 'reason:', 'nothing was deleted')) { Assert-True ($prev.Contains($s)) "preview en: $s" }
            Assert-True ($plan.Contains('NOTHING HAS BEEN DELETED YET')) 'plano en'
            foreach ($pt in @('RESUMO', 'NADA FOI APAGADO', 'Partições', 'Usuário', 'motivo:', 'nenhum item')) { Assert-True (-not ($audit + $prev + $plan).Contains($pt)) "sem pt-BR no en-US: $pt" }
            $o = Invoke-HeadlessTui -Keys @((New-Key 'D1' '1'), (New-Key 'Escape'), (New-Key 'D2' '2'), (New-Key 'Escape'), (New-Key 'H' 'h'), (New-Key 'Escape'), (New-Key 'Q' 'q')) -InvArgs (Get-InvArgs -Profiles @($p))
            $all = $o.Frames -join "`n"
            foreach ($s in @('Main menu', 'Users / SIDs', 'Profiles', 'Space', 'Navigation:', 'Q quit')) { Assert-True ($all.Contains($s)) "TUI en: $s" }
            foreach ($pt in @('Menu principal', 'Usuários', 'Espaço', 'Sair')) { Assert-True (-not $all.Contains($pt)) "TUI sem pt-BR: $pt" }
        } finally { Set-AtmLanguage -Requested 'pt-BR' }
    }
    Test-Case 'I18n' 'ASCII: acentos transliterados (pt-BR) e nada fora do ASCII imprimivel' {
        Assert-Eq (ConvertTo-AtmAscii ('Usu' + [char]0x00E1 + 'rio ' + [char]0x00E7 + [char]0x00E3 + ' ' + [char]0x540D)) 'Usuario ca ?' 'transliteracao'
        $p = New-TestProfile ('Jos' + [char]0x00E9)
        $null = New-TestRoot -ProfileInfo $p
        $o = Invoke-HeadlessTui -Keys @((New-Key 'D1' '1'), (New-Key 'Escape'), (New-Key 'D2' '2'), (New-Key 'Q' 'q')) -InvArgs (Get-InvArgs -Profiles @($p)) -Ascii -W 140 -H 30
        $all = $o.Frames -join "`n"
        Assert-True ($all -match '^[\x09\x0A\x20-\x7E]*$') 'somente ASCII'
        Assert-True ($all.Contains('Usuarios / SIDs') -and $all.Contains('Jose')) 'texto pt-BR legivel sem acentos'
    }
    Test-Case 'I18n' 'CLI: -Lang en-US, ATM_LANG e idioma invalido (fallback en-US)' {
        $cmd = Join-Path $srcDir 'bin\agent-temp.cmd'
        $out = (& cmd.exe /c "`"$cmd`" version -Lang en-US" 2>&1) -join ' '
        Assert-True ($out -match 'language: en-US' -and $out -match 'real deletion: DISABLED') "en-US: $out"
        $out = (& cmd.exe /c "`"$cmd`" version -Lang pt-BR" 2>&1) -join ' '
        Assert-True ($out -match 'idioma: pt-BR' -and $out -match 'limpeza real: DESABILITADA') "pt-BR: $out"
        $out = (& cmd.exe /c "`"$cmd`" version -Lang xx-YY" 2>&1) -join ' '
        Assert-True ($out -match 'language: en-US') "invalido -> en-US: $out"
        $old = $env:ATM_LANG; $env:ATM_LANG = 'en-US'
        try { $out = (& cmd.exe /c "`"$cmd`" help" 2>&1) -join ' ' } finally { $env:ATM_LANG = $old }
        Assert-True ($out -match 'Examples:' -and $out -match 'PLAN ONLY') "ATM_LANG=en-US: help em ingles"
        $out = (& cmd.exe /c "`"$cmd`" clean -Lang en-US" 2>&1) -join ' '
        Assert-True ($out -match 'NOTHING WAS DELETED') 'clean sem allowlist em ingles'
    }

    # ------------------------------------------------------------------ portability
    Test-Case 'Portabilidade' 'Windows com apenas um usuario' {
        $p = New-TestProfile 'unico'
        $null = New-TestRoot -ProfileInfo $p
        $i = Inv -Profiles @($p)
        Assert-Eq @($i.Profiles).Count 1 'um perfil'
        Assert-Eq (Get-AtmProfileStatusLabel -Inventory $i -ProfileInfo $p) 'AUDITADO' 'rotulo'
        Assert-True $i.CoverageComplete 'cobertura completa com processos inspecionaveis'
        Assert-Eq @($i.Partitions).Count 1 'uma particao'
        Show-AtmAudit -Inventory $i
    }
    Test-Case 'Portabilidade' 'Varios usuarios: auditado, inacessivel, hive nao carregado, sem Claude Code' {
        $pa = New-TestProfile 'multiA'; $ra = New-TestRoot -ProfileInfo $pa
        $pb = New-TestProfile 'multiB' -Sid 'S-1-5-21-1-2-3-4444'; $null = New-TestRoot -ProfileInfo $pb
        $bb = Get-Base $pb
        $null = icacls $bb /deny "*$($me.Sid):(RD)" 2>&1
        $cleanupActions.Add([scriptblock]::Create("icacls '$bb' /remove:d '*$($me.Sid)' | Out-Null"))
        $pc = New-TestProfile 'multiC'; [IO.Directory]::Delete((Get-Base $pc)); $pc.EnvStatus = 'NOT_LOADED'; $pc.Loaded = $false; $pc.EnvKnown = $false
        $pd = New-TestProfile 'multiD' -NoConfig; [IO.Directory]::Delete((Get-Base $pd))
        $i = Inv -Profiles @($pa, $pb, $pc, $pd)
        Assert-Eq (Get-AtmProfileStatusLabel -Inventory $i -ProfileInfo $pa) 'AUDITADO' 'A auditado'
        Assert-Eq (Get-AtmProfileStatusLabel -Inventory $i -ProfileInfo $pb) 'INACESSIVEL' 'B inacessivel'
        Assert-Eq (Get-AtmProfileStatusLabel -Inventory $i -ProfileInfo $pc) 'TEMP_NAO_VERIFICAVEL' 'C: ausencia no local padrao nao prova nada'
        Assert-Eq (Get-AtmProfileStatusLabel -Inventory $i -ProfileInfo $pd) 'SEM_TEMP_CLAUDE' 'D: sem Claude Code'
        Assert-True (-not $i.CoverageComplete) 'cobertura incompleta declarada'
        Assert-True (@($i.UnverifiedTempProfiles) -contains $pc) 'C listado como nao verificavel'
        Assert-True (@($i.Partitions | Where-Object { $_.Sid -ne $pa.Sid -or $_.ProfilePath -ne $pa.ProfilePath }).Count -eq 0) 'nenhuma particao atribuida ao perfil errado'
        Assert-Eq (Find-Part $i $ra).Class 'ORPHAN_SUSPECTED' 'A classificado normalmente'
        Show-AtmAudit -Inventory $i
    }
    Test-Case 'Portabilidade' 'Perfil em outra unidade (letra de unidade virtual via subst)' {
        $letter = $null
        foreach ($l in [char[]]'QRSTUVWXYZ') { if (-not (Test-Path "$($l):\")) { $letter = $l; break } }
        if (-not $letter) { $script:caseSkipped = $true; $script:caseNote = 'nenhuma letra de unidade livre'; return }
        $real = Join-Path $sandbox 'outra-unidade'; [void][IO.Directory]::CreateDirectory($real)
        $o = cmd /c subst "$($letter):" "`"$real`"" 2>&1
        $cleanupActions.Add([scriptblock]::Create("cmd /c subst $($letter): /D | Out-Null"))
        if (-not (Test-Path "$($letter):\")) { $script:caseSkipped = $true; $script:caseNote = "subst indisponivel: $o"; return }
        try {
            $root = "$($letter):\Perfis\Dona Carla"
            $temp = Join-Path $root 'Temp Redirecionado'
            [void][IO.Directory]::CreateDirectory((Join-Path $temp 'claude'))
            [void][IO.Directory]::CreateDirectory((Join-Path $root '.claude\sessions'))
            $p = [pscustomobject]@{ Sid = $testOwnerSid; UserName = 'TEST\carla'; ProfilePath = $root; Loaded = $true; Special = $false; Origin = 'Test'; EnvStatus = 'OK'
                TempCandidates = @([pscustomobject]@{ TempPath = $temp; Source = 'test' }); EnvValues = @{}; EnvKnown = $true; Notes = @() }
            $r = Join-Path $temp ('claude\' + "$($letter)--Perfis-Dona-Carla\" + [guid]::NewGuid())
            [void][IO.Directory]::CreateDirectory($r); [IO.File]::WriteAllBytes((Join-Path $r 'f.bin'), (New-Object byte[] 11))
            $i = Inv -Profiles @($p)
            $b = @($i.Bases)[0]
            $script:caseNote = "unidade $($letter): status da base = $($b.Status)"
            if ($b.Status -eq 'OK') {
                $x = Find-Part $i $r
                Assert-True ($x -and $x.Path.StartsWith("$($letter):\")) 'particao na outra unidade'
                Assert-Eq $x.Bytes 11 'medida'
                Assert-Eq $x.Project $i.Partitions[0].Project 'projeto resolvido sem assumir C:'
                $d = [AgentTempManager.AtmDeleter]::DeleteTree($r)
                Assert-True (-not $d.Attempted -and $d.AbortReason -match 'REDIRECTED') "unidade virtual: exclusao recusada (fail-closed): $($d.AbortReason)"
                Assert-True ([IO.File]::Exists((Join-Path $r 'f.bin'))) 'nada excluido'
            } else {
                Assert-True ($b.Status -eq 'UNSUPPORTED_DRIVE') "status explicito: $($b.Status)"
            }
        } finally { cmd /c subst "$($letter):" /D | Out-Null }
    }
    Test-Case 'Portabilidade' 'Nenhuma instalacao do Claude Code; TEMP vazio; root de sessao vazia' {
        $p = New-TestProfile 'semclaude' -NoConfig
        [IO.Directory]::Delete((Get-Base $p))
        $i = Inv -Profiles @($p)
        Assert-Eq @($i.Partitions).Count 0 'nada inventariado'
        Assert-Eq @($i.InaccessibleProfiles).Count 0 'ausencia legitima nao e erro'
        Assert-Eq (Get-AtmProfileStatusLabel -Inventory $i -ProfileInfo $p) 'SEM_TEMP_CLAUDE' 'rotulo'
        $p2 = New-TestProfile 'tempvazio'
        $i2 = Inv -Profiles @($p2)
        Assert-Eq @($i2.Partitions).Count 0 'TEMP\claude vazio'
        $r = Join-Path (Join-Path (Get-Base $p2) 'C--x') ([guid]::NewGuid().ToString())
        [void][IO.Directory]::CreateDirectory($r)
        $x = Find-Part (Inv -Profiles @($p2)) $r
        Assert-True ($x.Files -eq 0 -and $x.MeasurementComplete -and $x.Class -eq 'ORPHAN_SUSPECTED') 'root vazia medida e classificada (somente informativo)'
    }
    Test-Case 'Portabilidade' 'Projetos: nao identificado por padrao; identificado pelo diretorio de trabalho da sessao; colisao nao identifica' {
        $p = New-TestProfile 'projetos'
        $cfgRoot = Join-Path $p.ProfilePath '.claude'
        $r1 = New-TestRoot -ProfileInfo $p -Slug 'D--src-gamma'; $r2 = New-TestRoot -ProfileInfo $p -Slug 'D--src-gamma'
        $r3 = New-TestRoot -ProfileInfo $p -Slug 'C--src-delta'; $r4 = New-TestRoot -ProfileInfo $p -Slug 'C--src-delta'
        $r5 = New-TestRoot -ProfileInfo $p -Slug 'C--a-b'
        $u1 = Split-Path $r1 -Leaf; $u4 = Split-Path $r4 -Leaf; $u5 = Split-Path $r5 -Leaf
        [IO.File]::WriteAllText((Join-Path $cfgRoot 'sessions\61.json'), ('{"pid":61,"sessionId":"' + $u1 + '","cwd":"D:\\src\\gamma"}'))
        [IO.File]::WriteAllText((Join-Path $cfgRoot 'sessions\62.json'), ('{"pid":62,"sessionId":"' + $u4 + '","cwd":"C:\\outro\\lugar"}'))
        [IO.File]::WriteAllText((Join-Path $cfgRoot 'sessions\63.json'), ('{"pid":63,"sessionId":"' + $u5 + '","cwd":"C:\\a-b"}'))
        [IO.File]::WriteAllText((Join-Path $cfgRoot 'sessions\64.json'), ('{"pid":64,"sessionId":"' + [guid]::NewGuid() + '","cwd":"C:\\a b"}'))
        $i = Inv -Profiles @($p)
        $unknown = Get-AtmText 'project.unknown'
        Assert-True ((Find-Part $i $r1).Project -eq 'gamma' -and (Find-Part $i $r1).ProjectIdentified) 'identificado pela sessao'
        Assert-Eq (Find-Part $i $r2).Project 'gamma' 'mesmo escopo: identificado'
        Assert-Eq (Find-Part $i $r3).Project $unknown 'cwd de outro escopo nao identifica'
        Assert-Eq (Find-Part $i $r5).Project $unknown 'colisao de slug (C:\a-b e C:\a b) nao identifica'
        $out = (@(Show-AtmAudit -Inventory $i 6>&1 | ForEach-Object { [string]$_.MessageData }) -join "`n")
        Assert-True ($out -match 'C--src-delta' -and $out -match 'C--a-b') 'nao identificados agrupados por escopo, sem fundir'
    }
    Test-Case 'Portabilidade' 'Nomes Unicode, espacos e especiais (apostrofo, &, #, parenteses) em perfil e instalacao' {
        $name = "O'Brien & Co (Ltda) #1 " + [char]0x00E7 + [char]0x00E3 + [char]0x00E9 + ' ' + [char]0x540D + [char]0x524D
        $p = New-TestProfile $name
        $r = New-TestRoot -ProfileInfo $p -Files @{ ("arq '&' #1 " + [char]0x00E7 + '.txt') = 3 }
        $i = Inv -Profiles @($p)
        $x = Find-Part $i $r
        Assert-True ($x -and $x.Files -eq 1 -and $x.Bytes -eq 3) 'medido'
        $c = Invoke-AtmClean -Entries @([pscustomobject]@{ Source = 't'; Path = $r; Fingerprint = $null }) -PlanPresenter $presenter -ConfirmationReader ${function:Confirm-Correct} -InventoryArgs (Get-InvArgs -Profiles @($p))
        Assert-True (@($c.Deleted | Where-Object { $_.Completed -and $_.Verified }).Count -eq 1) 'motor de exclusao (sandbox) funciona com o nome'
        $inst = Join-Path $sandbox "PF O'Neil & Co (x) #1\AgentTempManager"
        [void][IO.Directory]::CreateDirectory((Split-Path -Parent $inst))
        $null = Install-AtmProduct -SourceDir $srcDir -InstallDir $inst -TrustSid $me.Sid -SkipPath -SourceWithoutManifest
        Assert-True (Test-Path (Join-Path $inst 'lib\AgentTempManager.Native.dll')) 'DLL compilada em caminho com apostrofo'
        Assert-True (-not (Test-Path (Join-Path $inst 'config\projects.local.json'))) 'instalado sem configuracao pessoal'
        $out = & cmd.exe /c "`"$(Join-Path $inst 'bin\agent-temp.cmd')`" version" 2>&1
        Assert-Eq $LASTEXITCODE 0 "launcher funciona no caminho especial: $out"
        Uninstall-AtmProduct -InstallDir $inst | Out-Null
        Assert-True (-not (Test-Path $inst)) 'desinstalado'
    }
    Test-Case 'Portabilidade' 'TEMP do registro de cada perfil: redirecionado, outra unidade, variaveis do proprio perfil' {
        $vol = @{ LOCALAPPDATA = 'E:\Perfis\bea\AppData\Local' }
        Assert-Eq (Expand-AtmProfileValue -Value '%USERPROFILE%\AppData\Local\Temp' -ProfilePath 'E:\Perfis\bea' -Volatile @{}) 'E:\Perfis\bea\AppData\Local\Temp' 'USERPROFILE do proprio perfil'
        Assert-Eq (Expand-AtmProfileValue -Value '%LOCALAPPDATA%\Temp' -ProfilePath 'E:\Perfis\bea' -Volatile $vol) 'E:\Perfis\bea\AppData\Local\Temp' 'LOCALAPPDATA volatil'
        Assert-Eq (Expand-AtmProfileValue -Value 'D:\Temp' -ProfilePath 'E:\Perfis\bea' -Volatile @{}) 'D:\Temp' 'TEMP absoluto em outra unidade'
        Assert-Eq (Expand-AtmProfileValue -Value '%VARIAVEL_INEXISTENTE%\x' -ProfilePath 'E:\Perfis\bea' -Volatile @{}) $null 'variavel nao resolvivel: nao inventa caminho'
        Assert-True ((Expand-AtmProfileValue -Value '%USERPROFILE%\T' -ProfilePath 'E:\Perfis\bea' -Volatile @{}) -notmatch [regex]::Escape($env:USERPROFILE)) 'nunca usa o perfil de quem executa'
    }

    # ------------------------------------------------------------------ provider contract
    Test-Case 'Providers' 'Registro valida o contrato (membros, Id, TempSubdir)' {
        $base = (Get-AtmProviders)[0]
        $bad1 = [pscustomobject]@{ Id = 'x' }
        $threw = $false; try { Register-AtmProvider $bad1 } catch { $threw = $true }
        Assert-True $threw 'membros ausentes recusados'
        $bad2 = $base.PSObject.Copy(); $bad2.Id = 'Bad Id'
        $threw = $false; try { Register-AtmProvider $bad2 } catch { $threw = $true }
        Assert-True $threw 'Id invalido recusado'
        $bad3 = $base.PSObject.Copy(); $bad3.Id = 'bad3'; $bad3.TempSubdir = '..\fora'
        $threw = $false; try { Register-AtmProvider $bad3 } catch { $threw = $true }
        Assert-True $threw 'TempSubdir com traversal recusado'
        Assert-Eq @(Get-AtmProviders).Count 1 'V1: somente Claude Code registrado'
        Assert-Eq (Get-AtmProviders)[0].Id 'claude-code' 'id'
    }
    Test-Case 'Providers' 'Provider ficticio (somente teste) usa o mesmo motor, gates e particoes' {
        $p = New-TestProfile 'multi'
        $rc = New-TestRoot -ProfileInfo $p
        $fakeRoot = Join-Path $p.TempCandidates[0].TempPath ('fake-agent\scope1\run-0001')
        [void][IO.Directory]::CreateDirectory($fakeRoot); [IO.File]::WriteAllBytes((Join-Path $fakeRoot 'x.bin'), (New-Object byte[] 42))
        $claude = (Get-AtmProviders)[0]
        $fake = [pscustomobject]@{
            Id = 'fake-agent'; DisplayName = 'Fake'; TempSubdir = 'fake-agent'; ScopePattern = '^scope\d+$'; RootPattern = '^run-\d{4}$'; EnvVarNames = @()
            # Written as a third-party provider would be before the ProfileInfo rename: the old parameter name
            # $Profile must keep working, because the engine passes provider arguments by position. Built from text
            # so the analyser does not report the deliberate use of the automatic-variable name.
            GetExtraTempDirs = [scriptblock]::Create('param($Profile) if ($null -eq $Profile.Sid) { throw "perfil nao recebido" }; @()')
            GetConfigDirs = [scriptblock]::Create('param($Profile) [pscustomobject]@{ Dirs = @(); Known = ($null -ne $Profile -and [bool]$Profile.Sid) }')
            GetSessionEvidence = [scriptblock]::Create('param($Profile, $Snapshot) [pscustomobject]@{ Readable = [bool]$Profile.Sid; Unparseable = 0; Entries = @() }')
            GetActivityEvidence = [scriptblock]::Create('param($Profile, $Scope, $RootName) if ($null -eq $Profile.Sid) { throw "perfil nao recebido" }; [pscustomobject]@{ Readable = $true; LastWriteUtc = $null }')
            GetProjectKey = { param($Scope, $ProfilePath) [pscustomobject]@{ IsHome = $false; Key = $Scope } }
        }
        $a = Get-InvArgs -Profiles @($p)
        $a['Providers'] = @($claude, $fake)
        $i = Invoke-AtmInventory @a
        $x = Find-Part $i $fakeRoot
        Assert-Eq $x.Provider 'fake-agent' 'provider'
        Assert-Eq $x.Kind 'SessionRoot' 'root reconhecida pelo padrao do provider'
        Assert-Eq $x.Class 'ORPHAN_SUSPECTED' 'classe pelo motor comum'
        Assert-Eq (Find-Part $i $rc).Provider 'claude-code' 'claude intacto'
        Assert-Eq (Get-AtmSum $i.Partitions 'Bytes') (42 + 2148) 'particoes exclusivas entre providers'
        Assert-Eq (Test-AtmCandidate -Partition $x -Inventory $i).Category 'ELIGIBLE' 'mesmos gates'
        Assert-True (-not ((@($x.Flags) -join ' ') -match 'CONFIG_DIR_UNKNOWN')) 'provider com o nome antigo do parametro ($Profile) recebe o perfil'
        # Named calls with the old parameter name keep working through the alias.
        Assert-Eq (Get-AtmClaudeConfigDirs -Profile $p).Known (Get-AtmClaudeConfigDirs -ProfileInfo $p).Known 'alias -Profile'
        Assert-Eq @(Get-AtmProviders).Count 1 'provider de teste nao foi registrado globalmente'
    }

    # ------------------------------------------------------------------ installer helpers + global shim (no elevation, sandbox only)
    . (Join-Path (Split-Path -Parent $testsDir) 'install\InstallCommon.ps1')
    Test-Case 'Instalacao' 'Copia + manifesto + verify; adulteracao detectada; shim e codigos de saida' {
        $inst = Join-Path $sandbox 'PF\AgentTempManager'
        [void][IO.Directory]::CreateDirectory($inst)
        Copy-AtmTree -From $srcDir -To $inst
        New-AtmNativeAssembly -Root $inst
        Write-AtmManifest -Root $inst -Version (Get-AtmSourceVersion -SourceDir $srcDir)
        $cmd = Join-Path $inst 'bin\agent-temp.cmd'
        $out = & cmd.exe /c "`"$cmd`" verify" 2>&1; Assert-Eq $LASTEXITCODE 0 "verify integro: $out"
        $out = & cmd.exe /c "`"$cmd`" version" 2>&1; Assert-Eq $LASTEXITCODE 0 'version'
        Assert-True (($out -join ' ') -match 'agent-temp \d+\.\d+\.\d+') 'texto da versao'
        Assert-True (($out -join ' ') -match 'DLL pr.-compilada') "DLL verificada carregada (5.1): $out"
        $pw = Join-Path $PSHOME 'pwsh.exe'
        if (-not (Test-Path $pw)) { $pw = $env:ATM_PWSH }
        if ($pw -and (Test-Path $pw)) { $out7 = & $pw -NoProfile -ExecutionPolicy Bypass -File (Join-Path $inst 'agent-temp.ps1') version 2>&1; Assert-Eq $LASTEXITCODE 0 "PS7 carrega a DLL: $out7"; Assert-True (($out7 -join ' ') -match 'DLL pr.-compilada') 'modo dll no PS7' }
        $out = & cmd.exe /c "`"$cmd`" clean" 2>&1; Assert-Eq $LASTEXITCODE 2 'clean sem allowlist recusa (exit 2)'
        Assert-True (($out -join ' ') -match 'NADA FOI APAGADO') 'mensagem'
        $out = & cmd.exe /c "`"$cmd`" clean -AllowListFile `"$sandbox\nao-existe.txt`"" 2>&1; Assert-Eq $LASTEXITCODE 2 'allowlist inexistente (exit 2)'
        $out = & cmd.exe /c "`"$cmd`"" 2>&1; Assert-Eq $LASTEXITCODE 6 'TUI recusa console nao interativo (exit 6)'
        $out = & cmd.exe /c "`"$cmd`" comando-invalido" 2>&1; Assert-Eq $LASTEXITCODE 1 'comando invalido (exit 1)'
        Add-Content -LiteralPath (Join-Path $inst 'lib\Engine.Clean.ps1') -Value '# adulterado'
        $out = & cmd.exe /c "`"$cmd`" verify" 2>&1; Assert-Eq $LASTEXITCODE 5 'adulteracao detectada (exit 5)'
        [IO.File]::AppendAllText((Join-Path $inst 'lib\AgentTempManager.Native.dll'), 'x')
        $out = & cmd.exe /c "`"$cmd`" version" 2>&1; Assert-Eq $LASTEXITCODE 5 'DLL adulterada: execucao recusada na verificacao de integridade (exit 5)'
    }
    Test-Case 'Instalacao' 'Arquivos obrigatorios (R-B3): Engine.Diagnose.ps1 exigido na origem; ausente recusado antes de copiar; adulterado ou removido detectado pelo manifesto' {
        Assert-True ($script:AtmRequiredFiles -contains 'lib\Engine.Diagnose.ps1') 'motor de diagnostico na lista de obrigatorios'
        foreach ($rel in $script:AtmRequiredFiles) { Assert-True (Test-Path -LiteralPath (Join-Path $srcDir $rel) -PathType Leaf) "obrigatorio presente na origem: $rel" }
        # Every library the launcher loads is required (a missing one would only fail at run time).
        $launcher = [IO.File]::ReadAllText((Join-Path $srcDir 'agent-temp.ps1'))
        $loaded = @([regex]::Matches($launcher, "Join-Path \`$here '(lib\\[^']+\.ps1)'") | ForEach-Object { $_.Groups[1].Value })
        Assert-True ($loaded.Count -ge 5 -and $loaded -contains 'lib\Engine.Diagnose.ps1') "bibliotecas carregadas pelo lancador: $($loaded -join ', ')"
        foreach ($rel in $loaded) { Assert-True ($script:AtmRequiredFiles -contains $rel) "carregado pelo lancador e obrigatorio: $rel" }
        # Source without the file: refused at the first step, nothing created.
        $srcM = Join-Path $sandbox 'src-sem-diagnose'
        [void][IO.Directory]::CreateDirectory($srcM)
        Copy-AtmTree -From $srcDir -To $srcM
        [IO.File]::Delete((Join-Path $srcM 'lib\Engine.Diagnose.ps1'))
        $instM = Join-Path $sandbox 'PF6\AgentTempManager'
        $msg = $null; try { $null = Install-AtmProduct -SourceDir $srcM -InstallDir $instM -TrustSid $me.Sid -SkipPath -SourceWithoutManifest } catch { $msg = $_.Exception.Message }
        Assert-True ($null -ne $msg -and $msg -match 'Engine\.Diagnose\.ps1') "origem sem o motor de diagnostico recusada: $msg"
        Assert-True (-not (Test-Path -LiteralPath (Split-Path -Parent $instM))) 'nada criado no destino'
        # Release source (with manifest): missing or altered file refused.
        $rel = Join-Path $sandbox 'release-diag'
        [void][IO.Directory]::CreateDirectory($rel)
        Copy-AtmTree -From $srcDir -To $rel
        Write-AtmManifest -Root $rel -Version (Get-AtmSourceVersion -SourceDir $rel)
        $m = Get-Content -LiteralPath (Join-Path $rel 'manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        Assert-True (@($m.files | Where-Object { $_.path -eq 'lib\Engine.Diagnose.ps1' -and $_.sha256 -match '^[0-9A-F]{64}$' }).Count -eq 1) 'manifesto lista o motor de diagnostico com SHA-256'
        Test-AtmSourceIntegrity -SourceDir $rel
        $diag = Join-Path $rel 'lib\Engine.Diagnose.ps1'
        $orig = [IO.File]::ReadAllBytes($diag)
        Add-Content -LiteralPath $diag -Value '#x'
        $threw = $false; try { Test-AtmSourceIntegrity -SourceDir $rel } catch { $threw = ($_.Exception.Message -match 'hash divergente') }
        Assert-True $threw 'motor de diagnostico alterado na origem recusado'
        [IO.File]::Delete($diag)
        $threw = $false; try { Test-AtmSourceIntegrity -SourceDir $rel } catch { $threw = $true }
        Assert-True $threw 'motor de diagnostico ausente da origem com manifesto recusado'
        [IO.File]::WriteAllBytes($diag, $orig)
        Test-AtmSourceIntegrity -SourceDir $rel
        # Installed copy: verify and every command refuse an altered or removed file.
        $inst = Join-Path $sandbox 'PF7\AgentTempManager'
        [void][IO.Directory]::CreateDirectory($inst)
        Copy-AtmTree -From $srcDir -To $inst
        New-AtmNativeAssembly -Root $inst
        Write-AtmManifest -Root $inst -Version (Get-AtmSourceVersion -SourceDir $srcDir)
        $cmd = Join-Path $inst 'bin\agent-temp.cmd'
        $out = & cmd.exe /c "`"$cmd`" verify" 2>&1; Assert-Eq $LASTEXITCODE 0 "verify integro: $out"
        $idiag = Join-Path $inst 'lib\Engine.Diagnose.ps1'
        $iorig = [IO.File]::ReadAllBytes($idiag)
        Add-Content -LiteralPath $idiag -Value '# adulterado'
        $out = & cmd.exe /c "`"$cmd`" verify" 2>&1; Assert-Eq $LASTEXITCODE 5 'motor de diagnostico adulterado: verify (exit 5)'
        $out = & cmd.exe /c "`"$cmd`" diagnose -DeadlineSeconds 0" 2>&1; Assert-Eq $LASTEXITCODE 5 'motor de diagnostico adulterado: execucao recusada (exit 5)'
        [IO.File]::Delete($idiag)
        # Removed: verify (R-B5 test below) and every other command refuse it before loading any code.
        $out = & cmd.exe /c "`"$cmd`" verify" 2>&1; Assert-Eq $LASTEXITCODE 5 'motor de diagnostico removido: verify (exit 5)'
        $out = & cmd.exe /c "`"$cmd`" version" 2>&1; Assert-Eq $LASTEXITCODE 5 'motor de diagnostico removido: execucao recusada (exit 5)'
        Assert-True (($out -join ' ') -match 'ausente: lib\\engine\.diagnose\.ps1') "motivo: ausente ($out)"
        [IO.File]::WriteAllBytes($idiag, $iorig)
        $out = & cmd.exe /c "`"$cmd`" verify" 2>&1; Assert-Eq $LASTEXITCODE 0 "restaurado: verify integro ($out)"
    }
    # R-B5 payloads: harmless only. The marker line appends to a file next to the altered code (relative to it, so the
    # path stays ASCII); the shadow answers the manifest's own hash for every file, which forged verify before R-B5.
    $rb5Mark = { param([string]$Up) "[IO.File]::AppendAllText((Join-Path `$PSScriptRoot '$Up\atm-marker.txt'), 'executed;')" }
    $rb5Shadow = @'
function global:Get-FileHash { param([string]$LiteralPath, [string]$Algorithm)
    $root = Split-Path -Parent $PSScriptRoot
    $e = @((Get-Content -LiteralPath (Join-Path $root 'manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json).files | Where-Object { (Join-Path $root $_.path) -eq $LiteralPath })
    [pscustomobject]@{ Hash = $(if ($e.Count -gt 0) { $e[0].sha256 } else { '' }) } }
'@
    # FINAL-B: each CLI call is a bounded child process (Invoke-AtmTestChild); its duration is recorded per verb, and a
    # call that does not finish fails the case with a sanitized code (verb and call number) instead of hanging the run.
    $script:rb5Calls = New-Object System.Collections.Generic.List[object]
    function Invoke-Rb5Cli {
        param([string]$Cmd, [string]$Arguments)
        $r = Invoke-AtmTestChild -CommandLine ("`"$Cmd`" $Arguments") -TimeoutSec 180
        $verb = @(([string]$Arguments).Trim() -split ' ')[0]
        $script:rb5Calls.Add([pscustomobject]@{ Verb = $verb; Ms = $r.Ms })
        if ($r.TimedOut) { throw ('CHILD_TIMEOUT: {0}, chamada {1}, limite 180 s' -f $verb, $script:rb5Calls.Count) }
        [pscustomobject]@{ Exit = $r.Exit; Text = $r.Text }
    }
    function Format-Rb5Calls {
        $c = $script:rb5Calls.ToArray()
        if ($c.Count -eq 0) { return 'nenhuma chamada do CLI' }
        $max = @($c | Sort-Object Ms -Descending)[0]
        '{0} chamadas do CLI: media {1} ms, maxima {2} ms ({3}), total {4} s' -f $c.Count, [math]::Round((($c | Measure-Object Ms -Average).Average)), $max.Ms, $max.Verb, [math]::Round((($c | Measure-Object Ms -Sum).Sum) / 1000)
    }
    Test-Case 'Instalacao' 'FINAL-B F-13 (estatico): instalador, produto e ferramentas de evidencia nunca acham um programa do sistema por busca no PATH (cmd, whoami, icacls, reg, subst, powershell...)' {
        $root = Split-Path -Parent $testsDir
        $files = @(Get-ChildItem -LiteralPath (Join-Path $root 'install'), $srcDir -Recurse -File -Filter '*.ps1') + @(Get-Item -LiteralPath (Join-Path $root 'tools\privilege-matrix\Invoke-PrivilegeProbe.ps1'))
        $names = '(whoami|cmd|icacls|takeown|reg|subst|fsutil|powershell|pwsh|schtasks|net|sc|tasklist|taskkill)(\.exe)?'
        # A name where a command starts (line start, ';', '{', '(', '=', '|', '&'), Start-Process and Process.Start with a name.
        $rx = @("(^|[;{(=|&])\s*$names(\s|`$)", "Start-Process\s+(-FilePath\s+)?['""]?$names['""\s]", "Process\]::Start\(\s*['""]$names['""]")
        $probe = { param([string]$Line) @($rx | Where-Object { $Line -match $_ }).Count -gt 0 }
        foreach ($bad in @('cmd /c dir', '    $o = & cmd.exe /c x', 'Start-Process powershell -ArgumentList x', "[Diagnostics.Process]::Start('cmd.exe', 'x')", '$x = whoami.exe /groups | Out-Null')) { Assert-True (& $probe $bad) "padrao detecta: $bad" }
        foreach ($ok in @('$o = & $cmdExe /c x', '& (Join-Path $env:SystemRoot ''System32\cmd.exe'') /c x', 'Write-Host cmd-like text')) { Assert-True (-not (& $probe $ok)) "padrao aceita: $ok" }
        foreach ($f in $files) {
            # Code only: comment-based help (<# ... #>, usage examples) and line comments are left out.
            $code = [regex]::Replace([IO.File]::ReadAllText($f.FullName), '(?s)<#.*?#>', '')
            $hits = @(($code -split "`r?`n") | Where-Object { $l = $_; $l -notmatch '^\s*#' -and @($rx | Where-Object { $l -match $_ }).Count -gt 0 })
            Assert-Eq $hits.Count 0 "$($f.Name): programa do sistema chamado pelo nome ($($hits -join ' | '))"
        }
        $ic = [IO.File]::ReadAllText((Join-Path $root 'install\InstallCommon.ps1'))
        Assert-True ($ic.Contains("`$cmdExe = Join-Path `$env:SystemRoot 'System32\cmd.exe'")) 'verificacao pos-instalacao usa o cmd.exe do System32'
    }
    Test-Case 'Instalacao' 'FINAL-B: arquivo adicional nao listado fora de providers (lib e raiz da instalacao) - comportamento registrado; codigo plantado nunca executa' {
        $inst = Join-Path $sandbox 'PF-extra\AgentTempManager'
        [void][IO.Directory]::CreateDirectory($inst)
        Copy-AtmTree -From $srcDir -To $inst
        New-AtmNativeAssembly -Root $inst
        Write-AtmManifest -Root $inst -Version (Get-AtmSourceVersion -SourceDir $srcDir)
        $cmd = Join-Path $inst 'bin\agent-temp.cmd'
        $marker = Join-Path $inst 'atm-extra-marker.txt'
        $code = "[IO.File]::WriteAllText('$($marker.Replace("'", "''"))', 'x')"
        $seen = New-Object System.Collections.Generic.List[string]
        foreach ($rel in @('lib\Extra.ps1', 'Extra.ps1', 'lib\Extra.txt')) {
            $f = Join-Path $inst $rel
            [IO.File]::WriteAllText($f, $code)
            try {
                foreach ($a in @('verify', 'version', 'diagnose -DeadlineSeconds 0')) {
                    $r = Invoke-AtmTestChild -CommandLine ("`"$cmd`" $a") -TimeoutSec 180
                    Assert-True (-not $r.TimedOut) "$rel / $($a): terminou"
                    Assert-True (-not (Test-Path -LiteralPath $marker)) "$rel / $($a): codigo plantado nunca executado"
                    $seen.Add(('{0} {1}={2}' -f $rel, @($a -split ' ')[0], $r.Exit))
                }
            } finally { [IO.File]::Move($f, "$f.aside") }
        }
        $script:caseNote = 'codigos de saida: ' + ($seen -join '; ')
    }
    Test-Case 'Executor' 'FINAL-B-S: processos de teste dentro de Job Object - saida normal e extensa (truncamento declarado), prazo, descendente que segura o pipe ou excede o prazo encerrado so como membro do job; sentinela externa criada pelo harness intacta; falhas do executor com codigo seguro; nenhum PID usado para encerrar' {
        $ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $dir = Join-Path $sandbox 'executor'; [void][IO.Directory]::CreateDirectory($dir)
        # Child scripts use .NET calls only (no cmdlet), so a Windows PowerShell 5.1 child starts fast on every runner.
        $write = { param([string]$Name, [string[]]$Lines) $f = Join-Path $dir $Name; [IO.File]::WriteAllLines($f, $Lines, (New-Object Text.UTF8Encoding($true))); $f }
        $q = { param([string]$P) $P.Replace("'", "''") }
        $ps = { param([string]$Script) "`"$ps51`" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Script`"" }
        # 1. Normal end.
        $r = Invoke-AtmTestChild -CommandLine 'exit 7' -TimeoutSec 60
        Assert-True ($r.Exit -eq 7 -and -not $r.TimedOut -and -not $r.Truncated -and -not $r.JobTerminated) "saida normal: exit 7 ($($r.Text))"
        # 2-3. Long stdout and stderr: everything is read (the child never blocks), only the cap is kept, truncation declared.
        $big = & $write 'big.ps1' @('[Console]::Out.Write((''o'' * 300000)); [Console]::Error.Write((''e'' * 300000)); exit 0')
        $r = Invoke-AtmTestChild -CommandLine (& $ps $big) -TimeoutSec 120 -MaxOutputBytes 65536
        Assert-True ($r.Exit -eq 0 -and $r.Truncated -and $r.Text.EndsWith('[SAIDA_TRUNCADA]') -and $r.Text.Length -lt (2 * 65536 + 100)) "saidas extensas: truncamento declarado, no maximo o limite por fluxo (tamanho $($r.Text.Length))"
        # 4. A child past the deadline: CHILD_TIMEOUT, the job terminated, within the deadline plus the runner's fixed waits.
        $slp = & $write 'sleep.ps1' @('[Threading.Thread]::Sleep(120000)')
        $r = Invoke-AtmTestChild -CommandLine (& $ps $slp) -TimeoutSec 3
        Assert-True ($r.TimedOut -and $r.JobTerminated -and $null -eq $r.Exit -and $r.Text -ceq 'CHILD_TIMEOUT' -and $r.Ms -ge 2900 -and $r.Ms -lt 28000) "prazo: CHILD_TIMEOUT, job encerrado em $($r.Ms) ms"
        # 5-9. Descendants. A sentinel OUTSIDE any job of this suite, created by the harness a moment before, must stay alive.
        $flag = Join-Path $dir 'sentinel-stop.txt'
        $sentScript = & $write 'sentinel.ps1' @(('$sw = [Diagnostics.Stopwatch]::StartNew(); while (-not [IO.File]::Exists(''{0}'') -and $sw.ElapsedMilliseconds -lt 180000) {{ [Threading.Thread]::Sleep(200) }}' -f (& $q $flag)))
        $psi = New-Object Diagnostics.ProcessStartInfo($ps51, ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f $sentScript))
        $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
        $sentinel = [Diagnostics.Process]::Start($psi)
        try {
            $gone = {
                param([string]$Info)
                if (-not [IO.File]::Exists($Info)) { return 'sem registro' }
                $parts = [IO.File]::ReadAllText($Info).Split('|')
                # Read-only check of the descendant's own record (PID and creation time written by itself): never used to signal anything.
                try { $p = [Diagnostics.Process]::GetProcessById([int]$parts[0]); $alive = (-not $p.HasExited -and $p.StartTime.ToUniversalTime().Ticks -eq [long]$parts[1]); $p.Dispose() } catch { $alive = $false }
                $(if ($alive) { 'VIVO' } else { 'encerrado' })
            }
            foreach ($mode in @('pipe', 'hang')) {
                $info = Join-Path $dir "grandchild-$mode.txt"
                $gc = & $write "grandchild-$mode.ps1" @('$p = [Diagnostics.Process]::GetCurrentProcess()', ('[IO.File]::WriteAllText(''{0}'', (''{{0}}|{{1}}'' -f $p.Id, $p.StartTime.ToUniversalTime().Ticks))' -f (& $q $info)), '[Threading.Thread]::Sleep(120000)')
                $main = & $write "main-$mode.ps1" @(
                    ('$psi = New-Object Diagnostics.ProcessStartInfo(''{0}'', ''-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{1}"'')' -f (& $q $ps51), (& $q $gc)),
                    '$psi.UseShellExecute = $false; $null = [Diagnostics.Process]::Start($psi)',
                    ('$sw = [Diagnostics.Stopwatch]::StartNew(); while (-not [IO.File]::Exists(''{0}'') -and $sw.ElapsedMilliseconds -lt 90000) {{ [Threading.Thread]::Sleep(100) }}' -f (& $q $info)),
                    $(if ($mode -eq 'hang') { '[Threading.Thread]::Sleep(120000)' } else { 'exit 0' }))
                $r = Invoke-AtmTestChild -CommandLine (& $ps $main) -TimeoutSec $(if ($mode -eq 'hang') { 15 } else { 120 })
                if ($mode -eq 'pipe') { Assert-True ($r.Exit -eq 0 -and -not $r.TimedOut -and $r.JobTerminated) "descendente segurando o pipe depois da saida do filho: membros do job encerrados (exit $($r.Exit), $($r.Ms) ms)" }
                else { Assert-True ($r.TimedOut -and $r.JobTerminated) "filho e descendente alem do prazo: job encerrado ($($r.Ms) ms)" }
                Assert-Eq (& $gone $info) 'encerrado' "descendente ($mode) encerrado como membro do job"
            }
            Assert-True (-not $sentinel.HasExited) 'sentinela externa ao job, criada logo antes: intacta'
        } finally {
            [IO.File]::WriteAllText($flag, 'stop')
            # The sentinel ends by itself on the flag; it is never signalled.
            $null = $sentinel.WaitForExit(60000)
        }
        Assert-True $sentinel.HasExited 'sentinela terminou sozinha ao ver o marcador'
        $sentinel.Dispose()
        # 10-13, 16. Runner failures: a sanitized code, raised before anything runs; never a PID search.
        $threw = $null; try { $null = Invoke-AtmTestChild -CommandLine 'exit 0' -ActiveProcessLimit 0 } catch { $threw = [string]$_.Exception.Message }
        Assert-Eq $threw 'CHILD_RUNNER_INVALID_LIMITS' 'limites invalidos: recusado antes de executar'
        $threw = $null; try { $null = ConvertFrom-AtmTestJobResult -Result ([AgentTempManager.AtmJobRunner]::Run((Join-Path $dir 'nao-existe.exe'), 'nao-existe.exe', $dir, [string[]]@("SystemRoot=$env:SystemRoot"), 5000, 4096, [long]67108864, 4)) } catch { $threw = [string]$_.Exception.Message }
        Assert-Eq $threw 'CHILD_RUNNER_CREATE_PROCESS_FAILED' 'processo que nao inicia dentro do job: codigo seguro'
        foreach ($c in @('JOB_CREATE_FAILED', 'JOB_LIMITS_FAILED', 'JOB_LIMITS_MISMATCH', 'ATTRIBUTES_FAILED', 'PIPE_FAILED')) {
            $threw = $null; try { $null = ConvertFrom-AtmTestJobResult -Result ([pscustomobject]@{ Started = $false; Error = $c }) } catch { $threw = [string]$_.Exception.Message }
            Assert-Eq $threw "CHILD_RUNNER_$c" "falha do executor ($c): codigo seguro, nada executado"
        }
        $threw = $null; try { $null = ConvertFrom-AtmTestJobResult -Result ([pscustomobject]@{ Started = $false; Error = 'C:\caminho com detalhes' }) } catch { $threw = [string]$_.Exception.Message }
        Assert-Eq $threw 'CHILD_RUNNER_NOT_STARTED' 'motivo fora do padrao nunca vira mensagem (sanitizado)'
        $threw = $null; try { $null = ConvertFrom-AtmTestJobResult -Result ([pscustomobject]@{ Started = $true; TimedOut = $true; JobTerminated = $false; OutputTruncated = $false; ErrorTruncated = $false }) } catch { $threw = [string]$_.Exception.Message }
        Assert-Eq $threw 'CHILD_RUNNER_JOB_TERMINATE_FAILED' 'encerramento do job que falha: FAIL com codigo, sem busca de PID'
        # 10, 17. No process identity is ever used to stop anything: the executor has no PID lookup, enumeration or kill.
        $exec = (Get-Command Invoke-AtmTestChild).ScriptBlock.ToString() + (Get-Command ConvertFrom-AtmTestJobResult).ScriptBlock.ToString()
        foreach ($pat in @('Kill(', 'Stop-Process', 'taskkill', 'Win32_Process', 'Get-CimInstance', 'GetProcessById', 'ProcessId', 'TerminateProcess', '.Terminate(')) { Assert-True (-not $exec.Contains($pat)) "executor sem '$pat'" }
        Assert-True (-not (Test-Path Function:\Stop-AtmTestChildTree)) 'encerramento por PID heuristico removido'
        $script:caseNote = 'prazo 3 s encerrado; descendentes encerrados como membros do job; sentinela externa intacta'
    }
    Test-Case 'Ambiente' 'FINAL-B: custo de processos filhos por camada - cmd, Windows PowerShell 5.1, lancador instalado (fixture) e o mesmo com ambiente minimo; somente medicao, tempos e nomes de variaveis' {
        # Diagnostic for the ARM64 PowerShell 7 slowness (R-B5 verify: about 20 s per CLI call there, 0.5 s with Windows
        # PowerShell 5.1 as the parent). The launcher always starts Windows PowerShell 5.1 and the native DLL is always
        # compiled by a Windows PowerShell 5.1 child (New-AtmNativeAssembly), so the layers below locate the cost.
        $inst = Join-Path $sandbox 'PF-probe\AgentTempManager'
        [void][IO.Directory]::CreateDirectory($inst)
        Copy-AtmTree -From $srcDir -To $inst
        New-AtmNativeAssembly -Root $inst
        Write-AtmManifest -Root $inst -Version (Get-AtmSourceVersion -SourceDir $srcDir)
        $cmd = Join-Path $inst 'bin\agent-temp.cmd'
        $ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $minimal = @{}
        foreach ($n in @('SystemRoot', 'windir', 'SystemDrive', 'ComSpec', 'PATHEXT', 'TEMP', 'TMP', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA', 'HOMEDRIVE', 'HOMEPATH', 'USERNAME', 'USERDOMAIN', 'COMPUTERNAME', 'PROCESSOR_ARCHITECTURE', 'NUMBER_OF_PROCESSORS', 'OS', 'ProgramData', 'ProgramFiles', 'ProgramFiles(x86)', 'CommonProgramFiles', 'ATM_LANG')) { $minimal[$n] = [Environment]::GetEnvironmentVariable($n) }
        $minimal['PATH'] = (@('System32', 'System32\Wbem', 'System32\WindowsPowerShell\v1.0') | ForEach-Object { Join-Path $env:SystemRoot $_ }) -join ';'
        $layers = [ordered]@{
            'cmd'                        = @("exit 0", $null, 0)
            'powershell 5.1'             = @("`"$ps51`" -NoProfile -NonInteractive -Command exit 0", $null, 0)
            'lancador version'           = @("`"$cmd`" version", $null, 0)
            'lancador version, ambiente minimo' = @("`"$cmd`" version", $minimal, 0)
        }
        $notes = New-Object System.Collections.Generic.List[string]
        foreach ($k in $layers.Keys) {
            $ms = New-Object System.Collections.Generic.List[long]
            for ($i = 0; $i -lt 3; $i++) {
                $r = Invoke-AtmTestChild -CommandLine $layers[$k][0] -Environment $layers[$k][1] -TimeoutSec 180
                Assert-True (-not $r.TimedOut) "$($k): terminou dentro do limite"
                Assert-Eq $r.Exit $layers[$k][2] "$($k): codigo de saida ($($r.Text))"
                $ms.Add($r.Ms)
            }
            $notes.Add(('{0} {1} ms' -f $k, @($ms | Sort-Object)[1]))
        }
        # Where the launcher's time goes: the same loading sequence, step by step, timed inside a Windows PowerShell 5.1
        # child (module path pinned as the launcher pins it), with the inherited environment and with the minimal one.
        $steps = @('lib\Engine.Audit.ps1', 'lib\I18n.ps1', 'lib\Engine.Clean.ps1', 'lib\Engine.Diagnose.ps1', 'lib\Report.ps1', 'lib\Tui.ps1', 'providers\ClaudeCode.ps1')
        $probe = Join-Path $sandbox 'probe-load.ps1'
        $body = @('$t = [Diagnostics.Stopwatch]::StartNew(); $o = New-Object System.Collections.Generic.List[string]', '$ErrorActionPreference = ''Stop''')
        $body += ('$sha = [Security.Cryptography.SHA256]::Create(); foreach ($f in [IO.Directory]::GetFiles(''{0}'', ''*'', ''AllDirectories'')) {{ $s = [IO.File]::OpenRead($f); try {{ $null = $sha.ComputeHash($s) }} finally {{ $s.Dispose() }} }}; $o.Add(''hashes '' + $t.ElapsedMilliseconds)' -f $inst.Replace("'", "''"))
        foreach ($st in $steps) { $body += ('. ''{0}''; $o.Add(''{1} '' + $t.ElapsedMilliseconds)' -f (Join-Path $inst $st).Replace("'", "''"), (Split-Path -Leaf $st)) }
        $body += '[Console]::Out.Write(''LOAD['' + ($o -join '','') + '']'')'
        # With a BOM: Windows PowerShell 5.1 reads a script without one in the ANSI code page (non-ASCII paths).
        [IO.File]::WriteAllLines($probe, $body, (New-Object Text.UTF8Encoding($true)))
        $pinned = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules'
        $inherit = @{}; foreach ($k in [Environment]::GetEnvironmentVariables().Keys) { $inherit[[string]$k] = [Environment]::GetEnvironmentVariable([string]$k) }
        $inherit['PSModulePath'] = $pinned
        $min2 = $minimal.Clone(); $min2['PSModulePath'] = $pinned
        foreach ($e in @(@('herdado', $inherit), @('minimo', $min2))) {
            $r = Invoke-AtmTestChild -CommandLine ("`"$ps51`" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$probe`"") -Environment $e[1] -TimeoutSec 180
            Assert-True (-not $r.TimedOut -and $r.Text -match 'LOAD\[([^\]]*)\]') "carga passo a passo ($($e[0])): concluida ($($r.Text))"
            $notes.Add(('carga {0} (ms acumulados): {1}' -f $e[0], $Matches[1]))
        }
        # Second round (CI showed the whole cost in the first step, the file hashes): the hash step split in parts, and
        # which inherited variables, added to the minimal environment, make it fast (bisection; names only, never values).
        $hp = Join-Path $sandbox 'probe-hash.ps1'
        $hb = @('$t = [Diagnostics.Stopwatch]::StartNew(); $o = New-Object System.Collections.Generic.List[string]; $o.Add(''inicio '' + $t.ElapsedMilliseconds)',
            '$sha = [Security.Cryptography.SHA256]::Create(); $o.Add(''sha256 '' + $t.ElapsedMilliseconds)',
            ('$f = [IO.Directory]::GetFiles(''{0}'', ''*'', ''AllDirectories''); $o.Add(''lista '' + $t.ElapsedMilliseconds)' -f $inst.Replace("'", "''")),
            '$s = [IO.File]::OpenRead($f[0]); try { $null = $sha.ComputeHash($s) } finally { $s.Dispose() }; $o.Add(''primeiro '' + $t.ElapsedMilliseconds)',
            'foreach ($x in $f) { $s = [IO.File]::OpenRead($x); try { $null = $sha.ComputeHash($s) } finally { $s.Dispose() } }; $o.Add(''todos '' + $t.ElapsedMilliseconds)',
            '[Console]::Out.Write(''HASH['' + ($o -join '','') + '']'')')
        [IO.File]::WriteAllLines($hp, $hb, (New-Object Text.UTF8Encoding($true)))
        $hashRun = {
            param([hashtable]$Env)
            $r = Invoke-AtmTestChild -CommandLine ("`"$ps51`" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$hp`"") -Environment $Env -TimeoutSec 120
            if ($r.TimedOut -or $r.Text -notmatch 'HASH\[([^\]]*)\]') { return [pscustomobject]@{ Ms = 999999; Parts = 'sem resultado' } }
            $parts = $Matches[1]
            [pscustomobject]@{ Ms = [long](($parts -split ',')[-1] -split ' ')[-1]; Parts = $parts }
        }
        $hm = & $hashRun $min2; $hi = & $hashRun $inherit
        $notes.Add(('hash em partes (ms acumulados) minimo: {0}; herdado: {1}' -f $hm.Parts, $hi.Parts))
        # Rounds 3 and 4 (bisection: PSModuleAnalysisCachePath; a private cache for the child did not help) are recorded in
        # release/V0.2-FINAL-B-VALIDATION.md, section C; only the measurements above stay in every run.
        $script:caseNote = 'mediana de 3: ' + ($notes -join '; ')
    }
    Test-Case 'Instalacao' 'R-B5 verify: nenhum codigo carregado antes da verificacao; biblioteca removida, adulterada ou que sombreia Get-FileHash e provider plantado nunca executam nem forjam sucesso; manifesto invalido ou ausente recusado' {
        $script:rb5Calls.Clear()
        $inst = Join-Path $sandbox 'PF8\AgentTempManager'
        [void][IO.Directory]::CreateDirectory($inst)
        Copy-AtmTree -From $srcDir -To $inst
        New-AtmNativeAssembly -Root $inst
        Write-AtmManifest -Root $inst -Version (Get-AtmSourceVersion -SourceDir $srcDir)
        $cmd = Join-Path $inst 'bin\agent-temp.cmd'
        $marker = Join-Path $inst 'atm-marker.txt'
        $r = Invoke-Rb5Cli $cmd 'verify'; Assert-Eq $r.Exit 0 "verify integro ($($r.Text))"
        Assert-True ($r.Text -match 'Vers.o \d+\.\d+\.\d+; 0 arquivo') "resumo localizado quando tudo confere ($($r.Text))"
        $mark = & $rb5Mark '..'
        foreach ($t in @('lib\Engine.Audit.ps1', 'lib\I18n.ps1', 'lib\Engine.Clean.ps1', 'lib\Engine.Diagnose.ps1', 'lib\Report.ps1', 'lib\Tui.ps1', 'providers\ClaudeCode.ps1')) {
            $fp = Join-Path $inst $t
            $orig = [IO.File]::ReadAllBytes($fp)
            [IO.File]::Move($fp, "$fp.aside")
            $r = Invoke-Rb5Cli $cmd 'verify'
            Assert-Eq $r.Exit 5 "$t removido: verify recusa com exit 5, nao erro do PowerShell ($($r.Text))"
            Assert-True ($r.Text -match ('FAIL\s+' + [regex]::Escape($t))) "$t removido: listado como FAIL"
            foreach ($a in @('version', 'diagnose -DeadlineSeconds 0')) { $r = Invoke-Rb5Cli $cmd $a; Assert-Eq $r.Exit 5 "$t removido: $a recusado (exit 5)" }
            [IO.File]::Move("$fp.aside", $fp)
            foreach ($payload in @($mark, ($mark + "`r`n" + $rb5Shadow))) {
                [IO.File]::WriteAllBytes($fp, $orig)
                [IO.File]::AppendAllText($fp, "`r`n$payload`r`n")
                $r = Invoke-Rb5Cli $cmd 'verify'
                Assert-Eq $r.Exit 5 "$t adulterado: verify recusa, sem sucesso forjado ($($r.Text))"
                Assert-True ($r.Text -match ('FAIL\s+' + [regex]::Escape($t))) "$t adulterado: listado como FAIL ($($r.Text))"
                Assert-True (-not (Test-Path -LiteralPath $marker)) "$t adulterado: nenhum codigo executado por verify"
                foreach ($a in @('version', 'help', 'diagnose -DeadlineSeconds 0')) {
                    $r = Invoke-Rb5Cli $cmd $a
                    Assert-Eq $r.Exit 5 "$t adulterado: $a recusado (exit 5)"
                    Assert-True (-not (Test-Path -LiteralPath $marker)) "$t adulterado: nenhum codigo executado por $a"
                }
            }
            [IO.File]::WriteAllBytes($fp, $orig)
        }
        # Planted provider: verify reports it, as every other command refuses it.
        $planted = Join-Path $inst 'providers\Plantado.ps1'
        [IO.File]::WriteAllText($planted, $mark)
        $r = Invoke-Rb5Cli $cmd 'verify'
        Assert-Eq $r.Exit 5 "provider plantado: verify recusa ($($r.Text))"
        Assert-True ($r.Text -match 'FAIL\s+providers\\Plantado\.ps1') 'provider plantado listado como FAIL'
        $r = Invoke-Rb5Cli $cmd 'version'; Assert-Eq $r.Exit 5 'provider plantado: version recusado'
        Assert-True (-not (Test-Path -LiteralPath $marker)) 'provider plantado nunca executou'
        [IO.File]::Move($planted, (Join-Path $inst 'Plantado.ps1.aside'))
        $r = Invoke-Rb5Cli $cmd 'verify'; Assert-Eq $r.Exit 0 "restaurado ($($r.Text))"
        # Hidden attribute (not an ACL): a hidden unlisted provider is still refused; a hidden listed one is still loaded,
        # never silently left out of the provider set.
        [IO.File]::WriteAllText($planted, $mark)
        [IO.File]::SetAttributes($planted, [IO.FileAttributes]::Hidden)
        foreach ($a in @('verify', 'version')) {
            $r = Invoke-Rb5Cli $cmd $a
            Assert-Eq $r.Exit 5 "provider plantado oculto: $a recusado ($($r.Text))"
            Assert-True (-not (Test-Path -LiteralPath $marker)) "provider plantado oculto nunca executou ($a)"
        }
        [IO.File]::SetAttributes($planted, [IO.FileAttributes]::Normal)
        [IO.File]::Move($planted, (Join-Path $inst 'Plantado-oculto.ps1.aside'))
        $claude = Join-Path $inst 'providers\ClaudeCode.ps1'
        [IO.File]::SetAttributes($claude, [IO.FileAttributes]::Hidden)
        $r = Invoke-Rb5Cli $cmd 'verify'; Assert-Eq $r.Exit 0 "provider listado oculto: integro ($($r.Text))"
        $r = Invoke-Rb5Cli $cmd 'version'
        Assert-True ($r.Exit -eq 0 -and $r.Text -match 'providers: Claude Code') "provider listado oculto: carregado, conjunto completo ($($r.Text))"
        [IO.File]::SetAttributes($claude, [IO.FileAttributes]::Normal)
        # Invalid manifest: explicit refusal (exit 5) for verify and every other command; an unlisted library is never loaded.
        $mfp = Join-Path $inst 'manifest.json'
        $mfOrig = [IO.File]::ReadAllBytes($mfp)
        $m = [IO.File]::ReadAllText($mfp) | ConvertFrom-Json
        $files = @($m.files)
        $hex = ('A' * 64)
        $report = Join-Path $inst 'lib\Report.ps1'
        $reportOrig = [IO.File]::ReadAllBytes($report)
        $cases = [ordered]@{
            'malformado'            = '{ "files": [ '
            'sem lista de arquivos' = ([pscustomobject]@{ product = $m.product; version = $m.version } | ConvertTo-Json)
            'lista vazia'           = ([pscustomobject]@{ product = $m.product; version = $m.version; files = @() } | ConvertTo-Json)
            'biblioteca fora'       = ([pscustomobject]@{ product = $m.product; version = $m.version; files = @($files | Where-Object { $_.path -ne 'lib\Report.ps1' }) } | ConvertTo-Json -Depth 4)
            'entrada duplicada'     = ([pscustomobject]@{ product = $m.product; version = $m.version; files = @($files + $files[0]) } | ConvertTo-Json -Depth 4)
            'caminho com ..'        = ([pscustomobject]@{ product = $m.product; version = $m.version; files = @($files + [pscustomobject]@{ path = '..\fora.ps1'; sha256 = $hex; bytes = 1 }) } | ConvertTo-Json -Depth 4)
            'caminho absoluto'      = ([pscustomobject]@{ product = $m.product; version = $m.version; files = @($files + [pscustomobject]@{ path = 'C:\Windows\win.ini'; sha256 = $hex; bytes = 1 }) } | ConvertTo-Json -Depth 4)
            'sha256 invalido'       = ([pscustomobject]@{ product = $m.product; version = $m.version; files = @(@($files | Select-Object -Skip 1) + [pscustomobject]@{ path = $files[0].path; sha256 = 'zz'; bytes = 1 }) } | ConvertTo-Json -Depth 4)
        }
        foreach ($c in $cases.Keys) {
            [IO.File]::WriteAllText($mfp, $cases[$c], (New-Object Text.UTF8Encoding($false)))
            if ($c -eq 'biblioteca fora') { [IO.File]::AppendAllText($report, "`r`n$mark`r`n") }
            foreach ($a in @('verify', 'version', 'help')) {
                $r = Invoke-Rb5Cli $cmd $a
                Assert-Eq $r.Exit 5 "manifesto $($c): $a recusado com exit 5 ($($r.Text))"
                Assert-True (-not (Test-Path -LiteralPath $marker)) "manifesto $($c): nenhum codigo executado por $a"
            }
            [IO.File]::WriteAllBytes($report, $reportOrig)
        }
        [IO.File]::WriteAllBytes($mfp, $mfOrig)
        # Unreadable files and directories: exit 5, nothing loaded, reasons by relative name only (no absolute path, no
        # exception text). The manifest is rewritten to match a library carrying the marker, so any code loaded after
        # the failure would leave it. Files are made unreadable by an exclusive handle of this process (no ACL change).
        [IO.File]::AppendAllText($report, "`r`n$mark`r`n")
        Write-AtmManifest -Root $inst -Version (Get-AtmSourceVersion -SourceDir $srcDir)
        $readCases = [ordered]@{
            'diretorio de providers ausente'   = @{ Kind = 'move'; Target = 'providers'; Fail = 'providers' }
            'diretorio de providers quebrado'  = @{ Kind = 'junction'; Target = 'providers'; Fail = 'providers' }
            'biblioteca ilegivel'              = @{ Kind = 'lock'; Target = 'lib\Engine.Clean.ps1'; Fail = 'lib\Engine.Clean.ps1' }
            'provider ilegivel'                = @{ Kind = 'lock'; Target = 'providers\ClaudeCode.ps1'; Fail = 'providers\ClaudeCode.ps1' }
            'manifesto ilegivel'               = @{ Kind = 'lock'; Target = 'manifest.json'; Fail = 'manifest.json' }
        }
        foreach ($c in $readCases.Keys) {
            $rc = $readCases[$c]
            $tp = Join-Path $inst $rc.Target
            $lock = $null
            if ($rc.Kind -eq 'lock') { $lock = [IO.File]::Open($tp, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None) }
            else {
                [IO.Directory]::Move($tp, "$tp.aside")
                if ($rc.Kind -eq 'junction') { $o = & cmd.exe /c "mklink /J `"$tp`" `"$tp.nao-existe`"" 2>&1; Assert-Eq $LASTEXITCODE 0 "juncao para destino inexistente criada ($o)" }
            }
            try {
                foreach ($a in @('verify', 'version', 'help', 'diagnose -DeadlineSeconds 0')) {
                    $r = Invoke-Rb5Cli $cmd $a
                    Assert-Eq $r.Exit 5 "$($c): $a recusado com exit 5, nao erro do PowerShell ($($r.Text))"
                    Assert-True (-not (Test-Path -LiteralPath $marker)) "$($c): nenhum codigo executado por $a"
                    Assert-True ($r.Text -notmatch '[A-Za-z]:\\' -and $r.Text -notmatch 'Exception') "$($c): motivo sem caminho absoluto nem texto de excecao ($($r.Text))"
                }
                $r = Invoke-Rb5Cli $cmd 'verify'
                Assert-True ($r.Text -match ('FAIL\s+' + [regex]::Escape($rc.Fail))) "$($c): listado como FAIL ($($r.Text))"
            } finally {
                if ($null -ne $lock) { $lock.Dispose() }
                if ($rc.Kind -eq 'junction') { [IO.Directory]::Move($tp, "$tp.juncao") }
                if ($rc.Kind -ne 'lock') { [IO.Directory]::Move("$tp.aside", $tp) }
            }
        }
        [IO.File]::WriteAllBytes($report, $reportOrig)
        [IO.File]::WriteAllBytes($mfp, $mfOrig)
        $r = Invoke-Rb5Cli $cmd 'verify'; Assert-Eq $r.Exit 0 "restaurado apos os casos de leitura ($($r.Text))"
        # Installed copy (install-state.json) without a manifest: refused, never loaded as a source checkout.
        $state = Join-Path $inst 'install-state.json'
        [IO.File]::WriteAllText($state, '{ "product": "Agent Temp Manager", "version": "0.1.0" }')
        $r = Invoke-Rb5Cli $cmd 'verify'; Assert-Eq $r.Exit 0 "instalacao com estado e manifesto integros ($($r.Text))"
        [IO.File]::Move($mfp, "$mfp.aside")
        [IO.File]::AppendAllText($report, "`r`n$mark`r`n")
        foreach ($a in @('verify', 'version', 'help')) {
            $r = Invoke-Rb5Cli $cmd $a
            Assert-Eq $r.Exit 5 "instalacao sem manifesto: $a recusado com exit 5 ($($r.Text))"
            Assert-True (-not (Test-Path -LiteralPath $marker)) "instalacao sem manifesto: nenhum codigo executado por $a"
        }
        [IO.File]::WriteAllBytes($report, $reportOrig)
        # Source checkout (neither file): verify keeps exit 4 and loads nothing; the other commands load as before.
        [IO.File]::Move($state, "$state.aside")
        $r = Invoke-Rb5Cli $cmd 'verify'; Assert-Eq $r.Exit 4 "origem sem manifesto: verify exit 4 ($($r.Text))"
        $r = Invoke-Rb5Cli $cmd 'help'; Assert-Eq $r.Exit 0 "origem sem manifesto: help carrega como antes ($($r.Text))"
        [IO.File]::Move("$mfp.aside", $mfp)
        $r = Invoke-Rb5Cli $cmd 'verify'; Assert-Eq $r.Exit 0 "restaurado ($($r.Text))"
        Assert-True (-not (Test-Path -LiteralPath $marker)) 'nenhum marcador em todo o teste'
        $script:caseNote = Format-Rb5Calls
    }
    Test-Case 'Instalacao' 'R-B5 bootstrap: I18n.ps1 do pacote so executa depois de verificado (Install, Uninstall, Restore; -SourceDir diferente; Get-FileHash sombreado; pacote sem manifesto so com autorizacao explicita)' {
        $repoDir = Split-Path -Parent $testsDir
        $pkg = Join-Path $sandbox 'pkg-rb5'
        foreach ($d in @('src', 'install')) { $t = Join-Path $pkg $d; [void][IO.Directory]::CreateDirectory($t); Copy-AtmTree -From (Join-Path $repoDir $d) -To $t }
        $ver = Get-AtmSourceVersion -SourceDir $srcDir
        Write-AtmManifest -Root (Join-Path $pkg 'src') -Version $ver
        $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $common = Join-Path $pkg 'install\InstallCommon.ps1'
        $marker = Join-Path $pkg 'atm-marker.txt'
        $i18n = Join-Path $pkg 'src\lib\I18n.ps1'
        $i18nOrig = [IO.File]::ReadAllBytes($i18n)
        $pkgReport = Join-Path $pkg 'src\lib\Report.ps1'
        $pkgReportOrig = [IO.File]::ReadAllBytes($pkgReport)
        # Child process: the caller's variables, then the package's InstallCommon, then a source check.
        $probe = Join-Path $sandbox 'rb5-probe.ps1'
        [IO.File]::WriteAllText($probe, @'
param([string]$Common, [string]$Source, [switch]$Trust, [string]$InstallDir)
$ErrorActionPreference = 'Stop'
if ($Trust) { $script:AtmCatalogTrustUnverified = $true }
if ($InstallDir) { $script:AtmCatalogInstallDir = $InstallDir }
. $Common
'CATALOG=' + (Get-AtmText 'inst.incomplete') + ' NOMANIFEST=' + (Get-AtmText 'inst.noManifest')
try { Test-AtmSourceIntegrity -SourceDir $Source; 'INTEGRITY=OK' } catch { 'INTEGRITY=REFUSED ' + $_.Exception.Message }
'@)
        $probeRun = { param([string]$Source, [string[]]$Extra = @()) $ErrorActionPreference = 'Continue'; $o = & $ps -NoProfile -ExecutionPolicy Bypass -File $probe -Common $common -Source $Source @Extra 2>&1; (@($o | ForEach-Object { "$_" }) -join ' ') }
        $t = & $probeRun (Join-Path $pkg 'src')
        Assert-True ($t -match 'CATALOG=Origem incompleta' -and $t -match 'INTEGRITY=OK') "pacote integro: catalogo verificado carregado, origem aceita ($t)"
        # Altered catalog (harmless marker + Get-FileHash shadow) and altered library: refused, catalog never executed.
        [IO.File]::AppendAllText($i18n, "`r`n$(& $rb5Mark '..\..')`r`n$rb5Shadow`r`n")
        [IO.File]::AppendAllText($pkgReport, "`r`n# altered`r`n")
        $t = & $probeRun (Join-Path $pkg 'src')
        Assert-True ($t -match 'INTEGRITY=REFUSED') "catalogo e biblioteca adulterados: origem recusada, sem sucesso forjado ($t)"
        Assert-True (-not (Test-Path -LiteralPath $marker)) "I18n.ps1 adulterado nao executou antes da validacao ($t)"
        Assert-True ($t -notmatch 'CATALOG=\[') "recusa legivel sem o catalogo ($t)"
        # The three administrative scripts. Not elevated: they stop at the elevation check. Elevated (CI): at the source
        # check or the missing installation. Either way the altered catalog never runs and nothing is installed.
        $target = Join-Path $sandbox 'PF9\AgentTempManager'
        foreach ($s in @(@{ N = 'Install-AgentTempManager.ps1'; X = @('-SkipPath') }, @{ N = 'Uninstall-AgentTempManager.ps1'; X = @() }, @{ N = 'Restore-AgentTempManagerPrevious.ps1'; X = @() })) {
            $sa = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $pkg "install\$($s.N)"), '-InstallDir', $target) + $s.X
            $ErrorActionPreference = 'Continue'; $o = & $ps @sa 2>&1; $code = $LASTEXITCODE; $ErrorActionPreference = 'Stop'
            Assert-True ($code -ne 0) "$($s.N) com pacote adulterado nao conclui ($o)"
            Assert-True (-not (Test-Path -LiteralPath $marker)) "$($s.N): I18n.ps1 adulterado nao executou"
            Assert-True (-not (Test-Path -LiteralPath $target)) "$($s.N): nada instalado"
        }
        [IO.File]::WriteAllBytes($i18n, $i18nOrig)
        [IO.File]::WriteAllBytes($pkgReport, $pkgReportOrig)
        # A different -SourceDir: the bootstrap loads only the package's verified catalog; the other source is checked.
        $other = Join-Path $sandbox 'other-src'
        [void][IO.Directory]::CreateDirectory($other)
        Copy-AtmTree -From $srcDir -To $other
        Write-AtmManifest -Root $other -Version $ver
        $otherMarker = Join-Path $sandbox 'atm-marker.txt'
        [IO.File]::AppendAllText((Join-Path $other 'lib\I18n.ps1'), "`r`n$(& $rb5Mark '..\..')`r`n")
        $t = & $probeRun $other
        Assert-True ($t -match 'CATALOG=Origem incompleta' -and $t -match 'INTEGRITY=REFUSED') "outra origem adulterada recusada com o catalogo verificado do pacote ($t)"
        Assert-True (-not (Test-Path -LiteralPath $otherMarker)) 'I18n.ps1 da outra origem nao executou'
        $ErrorActionPreference = 'Continue'; $o = & $ps -NoProfile -ExecutionPolicy Bypass -File (Join-Path $pkg 'install\Install-AgentTempManager.ps1') -SourceDir $other -InstallDir $target -SkipPath 2>&1; $code = $LASTEXITCODE; $ErrorActionPreference = 'Stop'
        Assert-True ($code -ne 0 -and -not (Test-Path -LiteralPath $target)) "instalador com -SourceDir adulterado nao instala ($o)"
        Assert-True (-not (Test-Path -LiteralPath $otherMarker)) 'instalador: I18n.ps1 da outra origem nao executou'
        # Uninstall/rollback: the installed copy's catalog, verified against its own manifest, when the package has none.
        $instCopy = Join-Path $sandbox 'PF11\AgentTempManager'
        [void][IO.Directory]::CreateDirectory($instCopy)
        Copy-AtmTree -From $srcDir -To $instCopy
        Write-AtmManifest -Root $instCopy -Version $ver
        # Package without a manifest (git checkout): its catalog is code that nothing verified.
        [IO.File]::Move((Join-Path $pkg 'src\manifest.json'), (Join-Path $pkg 'src\manifest.json.aside'))
        $t = & $probeRun (Join-Path $pkg 'src')
        Assert-True ($t -notmatch 'CATALOG=Origem incompleta' -and $t -notmatch 'CATALOG=\[') "sem manifesto e sem autorizacao: catalogo nao carregado, textos internos legiveis ($t)"
        Assert-True ($t -match 'INTEGRITY=REFUSED .*SourceWithoutManifest') "sem manifesto: recusa orienta -SourceWithoutManifest ($t)"
        $t = & $probeRun (Join-Path $pkg 'src') @('-Trust')
        Assert-True ($t -match 'CATALOG=Origem incompleta') "sem manifesto, com autorizacao explicita: catalogo carregado ($t)"
        $t = & $probeRun (Join-Path $pkg 'src') @('-InstallDir', $instCopy)
        Assert-True ($t -match 'CATALOG=Origem incompleta') "sem manifesto no pacote: catalogo da instalacao verificado carregado ($t)"
        [IO.File]::AppendAllText((Join-Path $instCopy 'lib\I18n.ps1'), "`r`n$(& $rb5Mark '..')`r`n")
        $t = & $probeRun (Join-Path $pkg 'src') @('-InstallDir', $instCopy)
        Assert-True ($t -notmatch 'CATALOG=Origem incompleta') "catalogo da instalacao adulterado nao carregado ($t)"
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $instCopy 'atm-marker.txt'))) 'catalogo da instalacao adulterado nao executou'
        [IO.File]::AppendAllText($i18n, "`r`n$(& $rb5Mark '..\..')`r`n")
        $t = & $probeRun (Join-Path $pkg 'src')
        Assert-True (-not (Test-Path -LiteralPath $marker)) "sem manifesto e sem autorizacao: I18n.ps1 do pacote nao executou ($t)"
        [IO.File]::WriteAllBytes($i18n, $i18nOrig)
        [IO.File]::Move((Join-Path $pkg 'src\manifest.json.aside'), (Join-Path $pkg 'src\manifest.json'))
    }
    Test-Case 'Instalacao' 'R-B5 rollback: .previous adulterado recusado antes da troca; instalacao atual e .previous preservados; rollback integro conclui' {
        $cur = Join-Path $sandbox 'PF10\AgentTempManager'
        $prev = "$cur.previous"
        $ver = Get-AtmSourceVersion -SourceDir $srcDir
        $stateJson = '{ "product": "Agent Temp Manager", "version": "' + $ver + '", "pathAddedByInstaller": false }'
        [void][IO.Directory]::CreateDirectory($cur)
        Copy-AtmTree -From $srcDir -To $cur
        New-AtmNativeAssembly -Root $cur
        Write-AtmManifest -Root $cur -Version $ver
        [IO.File]::WriteAllText((Join-Path $cur 'install-state.json'), $stateJson)
        [void][IO.Directory]::CreateDirectory($prev)
        Copy-AtmTree -From $cur -To $prev
        Write-AtmManifest -Root $prev -Version $ver
        [IO.File]::WriteAllText((Join-Path $prev 'install-state.json'), $stateJson)
        $prevReport = Join-Path $prev 'lib\Report.ps1'
        $prevReportOrig = [IO.File]::ReadAllBytes($prevReport)
        [IO.File]::AppendAllText($prevReport, "`r`n$(& $rb5Mark '..')`r`n")
        $msg = $null; try { $null = Restore-AtmPrevious -InstallDir $cur } catch { $msg = $_.Exception.Message }
        Assert-True ($null -ne $msg) 'rollback para uma copia adulterada recusado'
        $r = Invoke-Rb5Cli (Join-Path $cur 'bin\agent-temp.cmd') 'verify'
        Assert-Eq $r.Exit 0 "instalacao atual preservada e integra ($msg / $($r.Text))"
        Assert-True ((Test-Path -LiteralPath $prev) -and ([IO.File]::ReadAllBytes($prevReport).Length -gt $prevReportOrig.Length)) '.previous preservado como estava'
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $cur 'atm-marker.txt')) -and -not (Test-Path -LiteralPath (Join-Path $prev 'atm-marker.txt'))) 'codigo da copia adulterada nunca executou'
        Assert-Eq @(Get-ChildItem -LiteralPath (Split-Path -Parent $cur) -Directory -Filter 'AgentTempManager.staging-*').Count 0 'nenhum diretorio intermediario deixado'
        [IO.File]::WriteAllBytes($prevReport, $prevReportOrig)
        # The restored copy fails its verify after the swap: both copies go back, nothing is deleted.
        $script:rb5UndoMsg = $null
        & {
            function Invoke-AtmVerifyInstalled { param([string]$InstallDir) [pscustomobject]@{ Ok = $false; Output = 'simulated failure' } }
            try { $null = Restore-AtmPrevious -InstallDir $cur } catch { $script:rb5UndoMsg = $_.Exception.Message }
        }
        $msg = $script:rb5UndoMsg
        Assert-True ($null -ne $msg -and $msg -match 'simulated failure') "verify apos a troca falhou: rollback desfeito ($msg)"
        $r = Invoke-Rb5Cli (Join-Path $cur 'bin\agent-temp.cmd') 'verify'; Assert-Eq $r.Exit 0 "instalacao atual de volta e integra ($($r.Text))"
        Assert-True ((Test-Path -LiteralPath $prev) -and ([Convert]::ToBase64String([IO.File]::ReadAllBytes($prevReport)) -eq [Convert]::ToBase64String($prevReportOrig))) '.previous de volta, inalterado'
        Assert-Eq @(Get-ChildItem -LiteralPath (Split-Path -Parent $cur) -Directory -Filter 'AgentTempManager.staging-*').Count 0 'nenhum diretorio intermediario deixado (desfeito)'
        # The verify throws instead of failing: the same undo. Each copy is tagged in install-state.json (outside the
        # integrity check) to tell them apart.
        $pf10 = Split-Path -Parent $cur
        $tagOf = { param([string]$Dir) [string](Get-Content -LiteralPath (Join-Path $Dir 'install-state.json') -Raw | ConvertFrom-Json).tag }
        [IO.File]::WriteAllText((Join-Path $cur 'install-state.json'), $stateJson.Replace(' }', ', "tag": "atual" }'))
        [IO.File]::WriteAllText((Join-Path $prev 'install-state.json'), $stateJson.Replace(' }', ', "tag": "anterior" }'))
        $script:rb5UndoMsg = $null
        & {
            function Invoke-AtmVerifyInstalled { param([string]$InstallDir) throw 'simulated exception' }
            try { $null = Restore-AtmPrevious -InstallDir $cur } catch { $script:rb5UndoMsg = $_.Exception.Message }
        }
        $msg = $script:rb5UndoMsg
        Assert-True ($null -ne $msg -and $msg -match 'simulated exception' -and $msg -match 'voltaram para onde estavam') "verify lancou excecao apos a troca: rollback desfeito ($msg)"
        Assert-True ((& $tagOf $cur) -eq 'atual' -and (& $tagOf $prev) -eq 'anterior') 'excecao: instalacao atual e .previous de volta as posicoes originais'
        Assert-True ([Convert]::ToBase64String([IO.File]::ReadAllBytes($prevReport)) -eq [Convert]::ToBase64String($prevReportOrig)) 'excecao: .previous inalterado'
        $r = Invoke-Rb5Cli (Join-Path $cur 'bin\agent-temp.cmd') 'verify'; Assert-Eq $r.Exit 0 "excecao: instalacao atual integra ($($r.Text))"
        Assert-Eq @(Get-ChildItem -LiteralPath $pf10 -Directory -Filter 'AgentTempManager.staging-*').Count 0 'excecao: nenhum diretorio intermediario deixado'
        # The undo itself fails (an open file blocks a rename, no ACL change): nothing more is moved or deleted and the
        # error says where each copy is. 'restaurada' blocks the first undo step, 'retirada' the second.
        foreach ($which in @('restaurada', 'retirada')) {
            $script:rb5LockWhich = $which; $script:rb5Lock = $null; $script:rb5UndoMsg = $null
            & {
                function Invoke-AtmVerifyInstalled {
                    param([string]$InstallDir)
                    $dir = $InstallDir
                    if ($script:rb5LockWhich -eq 'retirada') { $dir = @(Get-ChildItem -LiteralPath (Split-Path -Parent $InstallDir) -Directory -Filter 'AgentTempManager.recovery-*')[0].FullName }
                    $script:rb5Lock = [IO.File]::Open((Join-Path $dir 'agent-temp.ps1'), [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
                    throw 'simulated exception'
                }
                try { $null = Restore-AtmPrevious -InstallDir $cur } catch { $script:rb5UndoMsg = $_.Exception.Message }
            }
            if ($null -ne $script:rb5Lock) { $script:rb5Lock.Dispose() }
            $msg = $script:rb5UndoMsg
            $staging = @(Get-ChildItem -LiteralPath $pf10 -Directory -Filter 'AgentTempManager.recovery-*')
            Assert-Eq $staging.Count 1 "desfazer falhou ($which): a copia que estava em uso ficou num diretorio de recuperacao (R-B6: nunca varrido pela desinstalacao), nao foi apagada ($msg)"
            Assert-True ($staging.Count -eq 1 -and (& $tagOf $staging[0].FullName) -eq 'atual') "desfazer falhou ($which): copia em uso preservada"
            $prevAt = $(if ($which -eq 'restaurada') { $cur } else { $prev })
            Assert-True ((Test-Path -LiteralPath (Join-Path $prevAt 'install-state.json')) -and (& $tagOf $prevAt) -eq 'anterior') "desfazer falhou ($which): versao anterior preservada em $prevAt"
            Assert-True ($null -ne $msg -and $msg -match 'simulated exception' -and $msg -match 'Nada foi apagado' -and
                $staging.Count -eq 1 -and $msg.Contains($staging[0].FullName) -and $msg.Contains($prevAt)) "desfazer falhou ($which): erro claro com a posicao de cada copia ($msg)"
            if ($which -eq 'retirada') { Assert-True (-not (Test-Path -LiteralPath $cur)) 'desfazer falhou (retirada): nada foi colocado no lugar da instalacao' }
            Assert-True ((Test-Path -LiteralPath "$cur.transaction.json") -and $msg.Contains("$cur.transaction.json")) "desfazer falhou ($which): recuperacao pendente registrada e informada (R-B6)"
            foreach ($copy in @($staging[0].FullName, $prevAt)) {
                $ok = $true; try { Test-AtmSourceIntegrity -SourceDir $copy -InstalledCopy } catch { $ok = $false }
                Assert-True $ok "desfazer falhou ($which): copia preservada integra (manifesto, SHA-256, conjunto exato): $copy"
            }
            # Manual recovery by rename only, as the message instructs, then the pending marker is removed.
            if ($which -eq 'restaurada') { Rename-Item -LiteralPath $cur -NewName (Split-Path -Leaf $prev) }
            Rename-Item -LiteralPath $staging[0].FullName -NewName (Split-Path -Leaf $cur)
            if (Test-Path -LiteralPath "$cur.transaction.json") { [IO.File]::Delete("$cur.transaction.json") }
            Assert-True ((& $tagOf $cur) -eq 'atual' -and (& $tagOf $prev) -eq 'anterior') "recuperacao manual ($which): posicoes originais"
            $r = Invoke-Rb5Cli (Join-Path $cur 'bin\agent-temp.cmd') 'verify'; Assert-Eq $r.Exit 0 "recuperacao manual ($which): instalacao atual integra ($($r.Text))"
        }
        Assert-Eq (Restore-AtmPrevious -InstallDir $cur) $ver 'rollback integro conclui'
        Assert-True (-not (Test-Path -LiteralPath $prev)) '.previous consumido pelo rollback'
        $r = Invoke-Rb5Cli (Join-Path $cur 'bin\agent-temp.cmd') 'verify'; Assert-Eq $r.Exit 0 "versao restaurada integra ($($r.Text))"
        # Update from an altered release source: refused at the source check, the current installation untouched.
        $relSrc = Join-Path $sandbox 'release-rb5'
        [void][IO.Directory]::CreateDirectory($relSrc)
        Copy-AtmTree -From $srcDir -To $relSrc
        Write-AtmManifest -Root $relSrc -Version $ver
        [IO.File]::AppendAllText((Join-Path $relSrc 'lib\Report.ps1'), "`r`n$(& $rb5Mark '..')`r`n")
        $msg = $null; try { $null = Install-AtmProduct -SourceDir $relSrc -InstallDir $cur -Update -TrustSid $me.Sid -SkipPath } catch { $msg = $_.Exception.Message }
        Assert-True ($null -ne $msg -and $msg -match 'hash divergente') "atualizacao com origem adulterada recusada ($msg)"
        Assert-True (-not (Test-Path -LiteralPath $prev)) 'nenhuma .previous criada pela atualizacao recusada'
        Assert-Eq @(Get-ChildItem -LiteralPath (Split-Path -Parent $cur) -Directory -Filter 'AgentTempManager.staging-*').Count 0 'nenhum diretorio intermediario (atualizacao recusada)'
        $r = Invoke-Rb5Cli (Join-Path $cur 'bin\agent-temp.cmd') 'verify'; Assert-Eq $r.Exit 0 "instalacao atual intacta apos atualizacao recusada ($($r.Text))"
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $relSrc 'atm-marker.txt')) -and -not (Test-Path -LiteralPath (Join-Path $cur 'atm-marker.txt'))) 'codigo da origem adulterada nunca executou'
    }
    # R-B6: an update never destroys the only intact installation. Each copy is tagged in install-state.json (outside
    # the integrity check) to tell them apart; the test PATH key is compared before and after every failure.
    $rb6Tag = { param([string]$Dir)
        $f = Join-Path $Dir 'install-state.json'
        if (-not (Test-Path -LiteralPath $f)) { return '(ausente)' }
        $s = Get-Content -LiteralPath $f -Raw | ConvertFrom-Json
        if ($s.PSObject.Properties['tag']) { [string]$s.tag } else { '' } }
    $rb6SetTag = { param([string]$Dir, [string]$Tag)
        $f = Join-Path $Dir 'install-state.json'
        $s = Get-Content -LiteralPath $f -Raw | ConvertFrom-Json
        $s | Add-Member -NotePropertyName tag -NotePropertyValue $Tag -Force
        [IO.File]::WriteAllText($f, ($s | ConvertTo-Json), (New-Object Text.UTF8Encoding($false))) }
    $rb6Leftovers = { param([string]$Inst) (@(@(Get-ChildItem -LiteralPath (Split-Path -Parent $Inst) -Directory | Where-Object { $_.Name -match '^AgentTempManager\.(staging|recovery)-' } | ForEach-Object { $_.Name }) + @(if (Test-Path -LiteralPath "$Inst.transaction.json") { 'transaction.json' })) -join ',') }
    # Integrity of a preserved copy: manifest, SHA-256 and exact file set, checked in this process (no code run).
    $rb6Intact = { param([string]$Dir) try { Test-AtmSourceIntegrity -SourceDir $Dir -InstalledCopy; $true } catch { $false } }
    # Pending recovery only: recovery directories and the transaction marker (intermediate staging copies ignored).
    $rb6Pending = { param([string]$Inst) (@(@(Get-ChildItem -LiteralPath (Split-Path -Parent $Inst) -Directory | Where-Object { $_.Name -match '^AgentTempManager\.recovery-' } | ForEach-Object { $_.Name }) + @(if (Test-Path -LiteralPath "$Inst.transaction.json") { 'transaction.json' })) -join ',') }
    Test-Case 'Instalacao' 'R-B6 atualizacao: falha ou excecao apos a troca devolve a instalacao e a .previous; recuperacao que falha nao apaga nada; copias de recuperacao bloqueiam novas operacoes e sobrevivem a desinstalacao' {
        $testKey = 'Software\AgentTempManagerTest\EnvB6'
        $cleanupActions.Add({ try { [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree('Software\AgentTempManagerTest', $false) } catch { $null = $_ } })
        $k = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($testKey)
        $k.SetValue('Path', '%SystemRoot%\system32;C:\Outro\Bin', [Microsoft.Win32.RegistryValueKind]::ExpandString); $k.Close()
        $pathSnap = { $pk = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($testKey); try { [string]$pk.GetValueKind('Path') + '|' + [string]$pk.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) } finally { $pk.Close() } }
        $inst = Join-Path $sandbox 'PF12\AgentTempManager'
        $prev = "$inst.previous"
        $pf12 = Split-Path -Parent $inst
        [void][IO.Directory]::CreateDirectory($pf12)
        $cmd = Join-Path $inst 'bin\agent-temp.cmd'
        $inArgs = @{ SourceDir = $srcDir; InstallDir = $inst; TrustSid = $me.Sid; TestPathKey = $testKey; SourceWithoutManifest = $true }
        $null = Install-AtmProduct @inArgs
        & $rb6SetTag $inst 'v1'
        $path0 = & $pathSnap
        # Intact update, no .previous yet: the installed version becomes .previous.
        $null = Install-AtmProduct @inArgs -Update
        Assert-True ((& $rb6Tag $inst) -eq '' -and (& $rb6Tag $prev) -eq 'v1') 'atualizacao integra: nova versao instalada, a anterior em .previous'
        Assert-Eq (Invoke-Rb5Cli $cmd 'verify').Exit 0 'atualizacao integra: verify'
        Assert-Eq (& $pathSnap) $path0 'atualizacao integra: PATH inalterado'
        Assert-Eq (& $rb6Leftovers $inst) '' 'atualizacao integra: nenhum diretorio intermediario ou de recuperacao'
        & $rb6SetTag $inst 'v2'
        # Altered release source: refused before anything moves.
        $relSrc = Join-Path $sandbox 'release-rb6'
        [void][IO.Directory]::CreateDirectory($relSrc)
        Copy-AtmTree -From $srcDir -To $relSrc
        Write-AtmManifest -Root $relSrc -Version (Get-AtmSourceVersion -SourceDir $srcDir)
        [IO.File]::AppendAllText((Join-Path $relSrc 'lib\Report.ps1'), "`r`n# altered`r`n")
        $msg = $null; try { $null = Install-AtmProduct -SourceDir $relSrc -InstallDir $inst -Update -TrustSid $me.Sid -TestPathKey $testKey } catch { $msg = $_.Exception.Message }
        Assert-True ($null -ne $msg -and $msg -match 'hash divergente') "origem adulterada recusada ($msg)"
        Assert-True ((& $rb6Tag $inst) -eq 'v2' -and (& $rb6Tag $prev) -eq 'v1') 'origem adulterada: instalacao e .previous intactas'
        Assert-Eq (& $pathSnap) $path0 'origem adulterada: PATH inalterado'
        Assert-Eq (& $rb6Leftovers $inst) '' 'origem adulterada: nenhum diretorio intermediario ou de recuperacao'
        # The post-swap verify fails or throws, with a .previous present and the PATH entry missing (so this run adds it):
        # the installed version and the older .previous go back, the PATH entry this run added is removed again.
        $script:rb6Real = ${function:Invoke-AtmVerifyInstalled}
        $script:rb6Inst = $inst
        foreach ($mode in @('falha', 'excecao')) {
            $script:rb6Mode = $mode; $script:rb6Msg = $null
            $null = Remove-AtmMachinePath -Dir (Join-Path $inst 'bin') -TestKeyPath $testKey
            $pathBefore = & $pathSnap
            & {
                function Invoke-AtmVerifyInstalled {
                    param([string]$InstallDir)
                    if (-not [string]::Equals($InstallDir.TrimEnd('\'), $script:rb6Inst, [StringComparison]::OrdinalIgnoreCase)) { return (& $script:rb6Real -InstallDir $InstallDir) }
                    if ($script:rb6Mode -eq 'falha') { return [pscustomobject]@{ Ok = $false; Output = 'simulated failure' } }
                    throw 'simulated exception'
                }
                try { $null = Install-AtmProduct @inArgs -Update } catch { $script:rb6Msg = $_.Exception.Message }
            }
            $msg = $script:rb6Msg
            Assert-True ($null -ne $msg -and $msg -match 'simulated (failure|exception)') "verify apos a troca ($mode): atualizacao recusada ($msg)"
            Assert-Eq (& $rb6Tag $inst) 'v2' "verify apos a troca ($mode): versao instalada de volta ($msg)"
            Assert-Eq (& $rb6Tag $prev) 'v1' "verify apos a troca ($mode): .previous antiga preservada"
            Assert-Eq (Invoke-Rb5Cli $cmd 'verify').Exit 0 "verify apos a troca ($mode): instalacao integra"
            Assert-Eq (& $pathSnap) $pathBefore "verify apos a troca ($mode): PATH como antes da atualizacao"
            Assert-Eq (& $rb6Leftovers $inst) '' "verify apos a troca ($mode): nenhum diretorio intermediario ou de recuperacao"
            $null = Add-AtmMachinePath -Dir (Join-Path $inst 'bin') -TestKeyPath $testKey
        }
        # Intact update with a .previous present: the older one is discarded only after the new version verified.
        $null = Install-AtmProduct @inArgs -Update
        Assert-True ((& $rb6Tag $inst) -eq '' -and (& $rb6Tag $prev) -eq 'v2') 'atualizacao integra com .previous: a antiga descartada so depois do verify'
        Assert-Eq (& $rb6Leftovers $inst) '' 'atualizacao integra com .previous: nenhum diretorio intermediario ou de recuperacao'
        Assert-Eq (& $pathSnap) $path0 'atualizacao integra com .previous: PATH'
        & $rb6SetTag $inst 'v3'
        # Putting the copies back fails too (an open file blocks a rename; no ACL change): nothing is deleted, the error
        # names where each copy is, and further updates and rollbacks are refused until it is resolved by hand.
        # 'nova' blocks the first undo step (the failed new copy), 'antiga' the last (the older .previous).
        foreach ($which in @('nova', 'antiga')) {
            $script:rb6Which = $which; $script:rb6Lock = $null; $script:rb6Msg = $null
            & {
                function Invoke-AtmVerifyInstalled {
                    param([string]$InstallDir)
                    if (-not [string]::Equals($InstallDir.TrimEnd('\'), $script:rb6Inst, [StringComparison]::OrdinalIgnoreCase)) { return (& $script:rb6Real -InstallDir $InstallDir) }
                    $dir = $InstallDir
                    if ($script:rb6Which -eq 'antiga') { $dir = @(Get-ChildItem -LiteralPath (Split-Path -Parent $InstallDir) -Directory -Filter 'AgentTempManager.recovery-*')[0].FullName }
                    $script:rb6Lock = [IO.File]::Open((Join-Path $dir 'agent-temp.ps1'), [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
                    throw 'simulated exception'
                }
                try { $null = Install-AtmProduct @inArgs -Update } catch { $script:rb6Msg = $_.Exception.Message }
            }
            try {
                $msg = $script:rb6Msg
                $rec = @(Get-ChildItem -LiteralPath $pf12 -Directory -Filter 'AgentTempManager.recovery-*')
                # (staging-0000000a: the failed copy that the manual recovery of the 'nova' case set aside)
                $stg = @(Get-ChildItem -LiteralPath $pf12 -Directory -Filter 'AgentTempManager.staging-*' | Where-Object { $_.Name -ne 'AgentTempManager.staging-0000000a' })
                Assert-True ($null -ne $msg -and $msg -match 'simulated exception' -and $msg -match 'Nada foi apagado') "recuperacao falhou ($which): erro claro ($msg)"
                Assert-Eq $rec.Count 1 "recuperacao falhou ($which): .previous antiga guardada num diretorio de recuperacao"
                Assert-True ((& $rb6Tag $rec[0].FullName) -eq 'v2' -and $msg.Contains($rec[0].FullName)) "recuperacao falhou ($which): posicao da .previous antiga informada"
                if ($which -eq 'nova') {
                    Assert-True ((& $rb6Tag $prev) -eq 'v3' -and (& $rb6Tag $inst) -eq '' -and $msg.Contains($prev)) "recuperacao falhou (nova): versao instalada preservada em .previous ($msg)"
                } else {
                    Assert-True ((& $rb6Tag $inst) -eq 'v3' -and -not (Test-Path -LiteralPath $prev)) 'recuperacao falhou (antiga): versao instalada de volta; nada no lugar da .previous'
                    Assert-True ($stg.Count -eq 1 -and $msg.Contains($stg[0].FullName)) "recuperacao falhou (antiga): nova versao com falha guardada, nao apagada ($msg)"
                }
                $g = $null; try { $null = Install-AtmProduct @inArgs -Update } catch { $g = $_.Exception.Message }
                Assert-True ($null -ne $g -and $g.Contains($rec[0].FullName)) "recuperacao falhou ($which): nova atualizacao recusada enquanto ha copia de recuperacao ($g)"
                $g = $null; try { $null = Restore-AtmPrevious -InstallDir $inst } catch { $g = $_.Exception.Message }
                Assert-True ($null -ne $g -and $g.Contains($rec[0].FullName)) "recuperacao falhou ($which): rollback recusado enquanto ha copia de recuperacao ($g)"
                $pathHeld = & $pathSnap
                $g = $null; try { $null = Uninstall-AtmProduct -InstallDir $inst -TestPathKey $testKey } catch { $g = $_.Exception.Message }
                Assert-True ($null -ne $g -and $g.Contains($rec[0].FullName) -and $g -match 'Nao desinstale') "recuperacao falhou ($which): desinstalacao recusada ($g)"
                Assert-Eq @(Get-ChildItem -LiteralPath $pf12 -Directory -Filter 'AgentTempManager.recovery-*').Count 1 "recuperacao falhou ($which): recusas nao mexeram em nada"
                Assert-True ((& $rb6Tag $rec[0].FullName) -eq 'v2') "recuperacao falhou ($which): copia de recuperacao intacta apos as recusas"
                if ($which -eq 'nova') { Assert-True ((& $rb6Tag $prev) -eq 'v3' -and (& $rb6Tag $inst) -eq '') 'recuperacao falhou (nova): instalacao e .previous intactas apos as recusas' }
                else { Assert-True ((& $rb6Tag $inst) -eq 'v3' -and $stg.Count -eq 1 -and (Test-Path -LiteralPath $stg[0].FullName)) 'recuperacao falhou (antiga): instalacao e copia nova intactas apos as recusas' }
                Assert-Eq (& $pathSnap) $pathHeld "recuperacao falhou ($which): PATH intacto apos as recusas"
                Assert-True ((Test-Path -LiteralPath "$inst.transaction.json") -and $msg.Contains("$inst.transaction.json")) "recuperacao falhou ($which): transacao pendente registrada e informada"
            } finally { if ($null -ne $script:rb6Lock) { $script:rb6Lock.Dispose() } }
            $kept = @($rec[0].FullName, $(if ($which -eq 'nova') { $prev } else { $inst }), $(if ($which -eq 'nova') { $inst } else { $stg[0].FullName }))
            foreach ($copy in $kept) { Assert-True (& $rb6Intact $copy) "recuperacao falhou ($which): copia preservada integra (manifesto, SHA-256, conjunto exato): $copy" }
            # Manual recovery by rename only, as the message instructs, then the pending marker is removed.
            if ($which -eq 'nova') {
                Rename-Item -LiteralPath $inst -NewName 'AgentTempManager.staging-0000000a'
                Rename-Item -LiteralPath $prev -NewName (Split-Path -Leaf $inst)
            }
            Rename-Item -LiteralPath $rec[0].FullName -NewName (Split-Path -Leaf $prev)
            if (Test-Path -LiteralPath "$inst.transaction.json") { [IO.File]::Delete("$inst.transaction.json") }
            Assert-True ((& $rb6Tag $inst) -eq 'v3' -and (& $rb6Tag $prev) -eq 'v2') "recuperacao manual ($which): posicoes originais"
            Assert-Eq (Invoke-Rb5Cli $cmd 'verify').Exit 0 "recuperacao manual ($which): instalacao integra"
        }
        # Interrupted between renames (no installation, a .previous): -Update refuses and names it; nothing is changed.
        Rename-Item -LiteralPath $inst -NewName 'AgentTempManager.staging-0000000d'
        $g = $null; try { $null = Install-AtmProduct @inArgs -Update } catch { $g = $_.Exception.Message }
        Assert-True ($null -ne $g -and $g.Contains($prev)) "sem instalacao e com .previous: -Update recusado e aponta a .previous ($g)"
        Assert-True ((& $rb6Tag $prev) -eq 'v2' -and -not (Test-Path -LiteralPath $inst)) 'sem instalacao e com .previous: nada alterado'
        Rename-Item -LiteralPath (Join-Path $pf12 'AgentTempManager.staging-0000000d') -NewName (Split-Path -Leaf $inst)
        # A recovery copy pending: uninstall refuses before changing anything (PATH, product directories, sweeps).
        Rename-Item -LiteralPath $prev -NewName 'AgentTempManager.recovery-0000000c'
        $rc = Join-Path $pf12 'AgentTempManager.recovery-0000000c'
        $stgBefore = (@(Get-ChildItem -LiteralPath $pf12 -Directory -Filter 'AgentTempManager.staging-*' | ForEach-Object { $_.Name }) -join ',')
        $pathBefore = & $pathSnap
        $g = $null; try { $null = Uninstall-AtmProduct -InstallDir $inst -TestPathKey $testKey } catch { $g = $_.Exception.Message }
        Assert-True ($null -ne $g -and $g.Contains($rc) -and $g -match 'Nao desinstale') "desinstalacao recusada com recuperacao pendente ($g)"
        Assert-True ((& $rb6Tag $inst) -eq 'v3' -and (& $rb6Tag $rc) -eq 'v2') 'desinstalacao recusada: instalacao e copia de recuperacao intactas'
        Assert-Eq (Invoke-Rb5Cli $cmd 'verify').Exit 0 'desinstalacao recusada: instalacao integra'
        Assert-Eq (& $pathSnap) $pathBefore 'desinstalacao recusada: PATH intacto'
        Assert-Eq (@(Get-ChildItem -LiteralPath $pf12 -Directory -Filter 'AgentTempManager.staging-*' | ForEach-Object { $_.Name }) -join ',') $stgBefore 'desinstalacao recusada: nada varrido'
        # Resolved by hand: the normal uninstall works.
        Rename-Item -LiteralPath $rc -NewName (Split-Path -Leaf $prev)
        $null = Uninstall-AtmProduct -InstallDir $inst -TestPathKey $testKey
        Assert-True (-not (Test-Path -LiteralPath $inst) -and -not (Test-Path -LiteralPath $prev)) 'desinstalacao normal: produto e .previous removidos'
        Assert-Eq (& $rb6Leftovers $inst) '' 'desinstalacao normal: intermediarios varridos, nada pendente'
        Assert-Eq (& $pathSnap) 'ExpandString|%SystemRoot%\system32;C:\Outro\Bin' 'desinstalacao normal: PATH como antes da instalacao'
    }
    Test-Case 'Instalacao' 'R-B6 rollback: falha na troca e na sua reversao nao apaga nada e informa a posicao de cada copia' {
        $cur = Join-Path $sandbox 'PF13\AgentTempManager'
        $prev = "$cur.previous"
        $pf13 = Split-Path -Parent $cur
        $ver = Get-AtmSourceVersion -SourceDir $srcDir
        foreach ($d in @(@{ P = $cur; T = 'atual' }, @{ P = $prev; T = 'anterior' })) {
            [void][IO.Directory]::CreateDirectory($d.P)
            Copy-AtmTree -From $srcDir -To $d.P
            New-AtmNativeAssembly -Root $d.P
            Write-AtmManifest -Root $d.P -Version $ver
            [IO.File]::WriteAllText((Join-Path $d.P 'install-state.json'), '{ "product": "Agent Temp Manager", "version": "' + $ver + '", "pathAddedByInstaller": false, "tag": "' + $d.T + '" }')
        }
        # Renames are counted: call 1 retires the current copy, call 2 swaps .previous in, call 3 reverts call 1.
        # 'troca e reversao' fails calls 2 and 3; 'troca' fails only call 2.
        foreach ($case in @('troca e reversao', 'troca')) {
            $script:rb6N = 0; $script:rb6Fail = $(if ($case -eq 'troca') { @(2) } else { @(2, 3) }); $script:rb6Msg = $null
            & {
                function Rename-Item {
                    param([string]$LiteralPath, [string]$NewName)
                    $script:rb6N++
                    if ($script:rb6Fail -contains $script:rb6N) { throw 'simulated rename failure' }
                    Microsoft.PowerShell.Management\Rename-Item -LiteralPath $LiteralPath -NewName $NewName
                }
                try { $null = Restore-AtmPrevious -InstallDir $cur } catch { $script:rb6Msg = $_.Exception.Message }
            }
            $msg = $script:rb6Msg
            $rec = @(Get-ChildItem -LiteralPath $pf13 -Directory -Filter 'AgentTempManager.recovery-*')
            if ($case -eq 'troca e reversao') {
                # The swap and its reversal fail: the current copy stays in a recovery directory, nothing deleted.
                Assert-True ($null -ne $msg -and $msg -match 'simulated rename failure' -and $msg -match 'Nada foi apagado') "troca e reversao falharam: erro claro ($msg)"
                Assert-True ($rec.Count -eq 1 -and (& $rb6Tag $rec[0].FullName) -eq 'atual' -and $msg.Contains($rec[0].FullName)) "troca e reversao falharam: copia em uso preservada e informada ($msg)"
                Assert-True ((& $rb6Tag $prev) -eq 'anterior' -and $msg.Contains($prev) -and -not (Test-Path -LiteralPath $cur)) 'troca e reversao falharam: .previous preservada e informada'
                Assert-True ((Test-Path -LiteralPath "$cur.transaction.json") -and $msg.Contains("$cur.transaction.json") -and $msg -match 'Nao desinstale') "troca e reversao falharam: transacao pendente registrada e informada ($msg)"
                $g = $null; try { $null = Uninstall-AtmProduct -InstallDir $cur } catch { $g = $_.Exception.Message }
                Assert-True ($null -ne $g -and $g.Contains("$cur.transaction.json")) "troca e reversao falharam: desinstalacao recusada ($g)"
                Assert-True ((& $rb6Tag $rec[0].FullName) -eq 'atual' -and (& $rb6Tag $prev) -eq 'anterior') 'troca e reversao falharam: copias intactas apos a recusa'
                foreach ($copy in @($rec[0].FullName, $prev)) { Assert-True (& $rb6Intact $copy) "troca e reversao falharam: copia preservada integra (manifesto, SHA-256, conjunto exato): $copy" }
                Microsoft.PowerShell.Management\Rename-Item -LiteralPath $rec[0].FullName -NewName (Split-Path -Leaf $cur)
                [IO.File]::Delete("$cur.transaction.json")
            } else {
                # Only the swap fails: reverted, nothing left behind.
                Assert-True ($null -ne $msg -and $msg -match 'simulated rename failure') "troca falhou: erro ($msg)"
                Assert-Eq $rec.Count 0 'troca falhou: revertida, nenhuma copia de recuperacao'
                Assert-True (-not (Test-Path -LiteralPath "$cur.transaction.json")) 'troca falhou: revertida, nada pendente'
            }
            Assert-True ((& $rb6Tag $cur) -eq 'atual' -and (& $rb6Tag $prev) -eq 'anterior') "falha ($case): posicoes originais"
        }
        Assert-Eq (Restore-AtmPrevious -InstallDir $cur) $ver 'rollback integro conclui'
        Assert-True ((& $rb6Tag $cur) -eq 'anterior' -and -not (Test-Path -LiteralPath $prev)) 'rollback integro: versao anterior em uso'
        Assert-Eq (& $rb6Leftovers $cur) '' 'rollback integro: nenhum diretorio intermediario ou de recuperacao'
    }
    Test-Case 'Instalacao' 'R-B6 primeira atualizacao (sem .previous): sucesso; falha recuperada; reversao que falha deixa a transacao pendente e update, rollback e desinstalacao recusam sem apagar a versao integra' {
        $testKey = 'Software\AgentTempManagerTest\EnvB6b'
        $cleanupActions.Add({ try { [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree('Software\AgentTempManagerTest', $false) } catch { $null = $_ } })
        $k = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($testKey)
        $k.SetValue('Path', '%SystemRoot%\system32;C:\Outro\Bin', [Microsoft.Win32.RegistryValueKind]::ExpandString); $k.Close()
        $pathSnap = { $pk = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($testKey); try { [string]$pk.GetValueKind('Path') + '|' + [string]$pk.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) } finally { $pk.Close() } }
        $inst = Join-Path $sandbox 'PF14\AgentTempManager'
        $prev = "$inst.previous"
        $marker = "$inst.transaction.json"
        $pf14 = Split-Path -Parent $inst
        [void][IO.Directory]::CreateDirectory($pf14)
        $cmd = Join-Path $inst 'bin\agent-temp.cmd'
        $inArgs = @{ SourceDir = $srcDir; InstallDir = $inst; TrustSid = $me.Sid; TestPathKey = $testKey; SourceWithoutManifest = $true }
        $null = Install-AtmProduct @inArgs
        $path0 = & $pathSnap
        $script:rb6Real = ${function:Invoke-AtmVerifyInstalled}
        $script:rb6Inst = $inst
        # The installed version gets a tag and every .previous is set aside first, so each update below starts with none.
        $script:rb6Aside = 0
        $noPrevious = { param([string]$Tag)
            if (Test-Path -LiteralPath $prev) { $script:rb6Aside++; Rename-Item -LiteralPath $prev -NewName ('AgentTempManager.staging-1000000' + $script:rb6Aside) }
            & $rb6SetTag $inst $Tag }
        $refusals = { param([string]$Label)
            # Update, rollback and uninstall all refuse while the transaction is pending, and name the marker.
            $g = $null; try { $null = Install-AtmProduct @inArgs -Update } catch { $g = $_.Exception.Message }
            Assert-True ($null -ne $g -and $g.Contains($marker) -and $g -match 'Nao desinstale') "$($Label): atualizacao recusada com a transacao pendente ($g)"
            $g = $null; try { $null = Restore-AtmPrevious -InstallDir $inst } catch { $g = $_.Exception.Message }
            Assert-True ($null -ne $g -and $g.Contains($marker)) "$($Label): rollback recusado ($g)"
            $g = $null; try { $null = Uninstall-AtmProduct -InstallDir $inst -TestPathKey $testKey } catch { $g = $_.Exception.Message }
            Assert-True ($null -ne $g -and $g.Contains($marker)) "$($Label): desinstalacao recusada ($g)" }
        # 1. First update, no .previous: success, nothing pending.
        & $noPrevious 'v1'
        $null = Install-AtmProduct @inArgs -Update
        Assert-True ((& $rb6Tag $inst) -eq '' -and (& $rb6Tag $prev) -eq 'v1') 'primeira atualizacao: nova versao instalada, a anterior em .previous'
        Assert-Eq (& $rb6Pending $inst) '' 'primeira atualizacao: nada pendente'
        Assert-Eq (Invoke-Rb5Cli $cmd 'verify').Exit 0 'primeira atualizacao: verify'
        # 2. First update, verify fails: recovered, nothing pending, no .previous invented.
        & $noPrevious 'v2'
        $script:rb6Mode = 'falha'; $script:rb6Msg = $null
        & {
            function Invoke-AtmVerifyInstalled {
                param([string]$InstallDir)
                if (-not [string]::Equals($InstallDir.TrimEnd('\'), $script:rb6Inst, [StringComparison]::OrdinalIgnoreCase)) { return (& $script:rb6Real -InstallDir $InstallDir) }
                return [pscustomobject]@{ Ok = $false; Output = 'simulated failure' }
            }
            try { $null = Install-AtmProduct @inArgs -Update } catch { $script:rb6Msg = $_.Exception.Message }
        }
        Assert-True ($null -ne $script:rb6Msg -and $script:rb6Msg -match 'simulated failure') "primeira atualizacao, verify falha: recusada ($($script:rb6Msg))"
        Assert-True ((& $rb6Tag $inst) -eq 'v2' -and -not (Test-Path -LiteralPath $prev)) 'primeira atualizacao, verify falha: versao instalada de volta, sem .previous'
        Assert-Eq (& $rb6Pending $inst) '' 'primeira atualizacao, verify falha: nada pendente'
        Assert-Eq (& $pathSnap) $path0 'primeira atualizacao, verify falha: PATH inalterado'
        Assert-Eq (Invoke-Rb5Cli $cmd 'verify').Exit 0 'primeira atualizacao, verify falha: instalacao integra'
        # 3-4. First update, the reversal fails at its first step (the failed copy cannot be moved out) or at the next
        # (the installed copy cannot be moved back). No recovery directory exists here: the transaction marker is what
        # keeps the state pending.
        foreach ($which in @('primeiro passo', 'passo seguinte')) {
            $script:rb6Which = $which; $script:rb6Lock = $null; $script:rb6Msg = $null
            # Intermediate copies that exist before this run (set aside by this test), to find the one it leaves.
            $stgBefore = @(Get-ChildItem -LiteralPath $pf14 -Directory -Filter 'AgentTempManager.staging-*' | ForEach-Object { $_.Name })
            & {
                function Invoke-AtmVerifyInstalled {
                    param([string]$InstallDir)
                    if (-not [string]::Equals($InstallDir.TrimEnd('\'), $script:rb6Inst, [StringComparison]::OrdinalIgnoreCase)) { return (& $script:rb6Real -InstallDir $InstallDir) }
                    $dir = $(if ($script:rb6Which -eq 'primeiro passo') { $InstallDir } else { "$InstallDir.previous" })
                    $script:rb6Lock = [IO.File]::Open((Join-Path $dir 'agent-temp.ps1'), [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
                    throw 'simulated exception'
                }
                try { $null = Install-AtmProduct @inArgs -Update } catch { $script:rb6Msg = $_.Exception.Message }
            }
            try {
                $msg = $script:rb6Msg
                Assert-True ($null -ne $msg -and $msg -match 'simulated exception' -and $msg -match 'Nada foi apagado' -and $msg -match 'Nao desinstale') "reversao falhou ($which): erro claro ($msg)"
                Assert-True ((Test-Path -LiteralPath $marker) -and $msg.Contains($marker)) "reversao falhou ($which): transacao pendente registrada e informada"
                Assert-True ((& $rb6Tag $prev) -eq 'v2' -and $msg.Contains($prev)) "reversao falhou ($which): versao integra preservada em .previous e informada"
                if ($which -eq 'primeiro passo') {
                    Assert-True ((& $rb6Tag $inst) -eq '' -and $msg.Contains($inst)) 'reversao falhou (primeiro passo): nova versao com falha no lugar, informada'
                } else {
                    $failed = @(Get-ChildItem -LiteralPath $pf14 -Directory -Filter 'AgentTempManager.staging-*' | Where-Object { $stgBefore -notcontains $_.Name })
                    Assert-True (-not (Test-Path -LiteralPath $inst) -and $failed.Count -eq 1 -and $msg.Contains($failed[0].FullName)) "reversao falhou (passo seguinte): nova versao guardada, nao apagada, informada ($msg)"
                }
                $pathHeld = & $pathSnap
                & $refusals "reversao falhou ($which)"
                Assert-True ((& $rb6Tag $prev) -eq 'v2' -and (Test-Path -LiteralPath $marker)) "reversao falhou ($which): versao integra e marcador intactos apos as recusas"
                Assert-Eq (& $pathSnap) $pathHeld "reversao falhou ($which): PATH intacto apos as recusas"
            } finally { if ($null -ne $script:rb6Lock) { $script:rb6Lock.Dispose() } }
            $kept = @($prev, $(if ($which -eq 'primeiro passo') { $inst } else { $failed[0].FullName }))
            foreach ($copy in $kept) { Assert-True (& $rb6Intact $copy) "reversao falhou ($which): copia preservada integra (manifesto, SHA-256, conjunto exato): $copy" }
            # Manual recovery by rename only, then the marker is removed; the installation can be updated again.
            if ($which -eq 'primeiro passo') { Rename-Item -LiteralPath $inst -NewName 'AgentTempManager.staging-2000000a' }
            Rename-Item -LiteralPath $prev -NewName (Split-Path -Leaf $inst)
            [IO.File]::Delete($marker)
            Assert-True ((& $rb6Tag $inst) -eq 'v2' -and (& $rb6Pending $inst) -eq '') "recuperacao manual ($which): versao integra de volta, nada pendente"
            Assert-Eq (Invoke-Rb5Cli $cmd 'verify').Exit 0 "recuperacao manual ($which): instalacao integra"
            $null = Install-AtmProduct @inArgs -Update
            Assert-True ((& $rb6Tag $prev) -eq 'v2' -and (& $rb6Pending $inst) -eq '') "recuperacao manual ($which): atualizar volta a funcionar"
            & $noPrevious 'v2'
        }
        # The normal uninstall still works and sweeps only intermediate copies.
        $null = Uninstall-AtmProduct -InstallDir $inst -TestPathKey $testKey
        Assert-True (-not (Test-Path -LiteralPath $inst) -and (& $rb6Leftovers $inst) -eq '') 'desinstalacao normal apos as recuperacoes'
        Assert-Eq (& $pathSnap) 'ExpandString|%SystemRoot%\system32;C:\Outro\Bin' 'desinstalacao normal: PATH como antes da instalacao'
    }
    Test-Case 'Instalacao' 'R-B6 mensagens de recuperacao nao dependem do catalogo: com um catalogo sem as chaves de recuperacao (como o da V0.1) trazem motivo, posicoes, estado pendente e a orientacao de nao desinstalar' {
        $repoDir = Split-Path -Parent $testsDir
        # A package without a manifest (git checkout): uninstall and rollback load the installed copy's catalog.
        $pkg = Join-Path $sandbox 'pkg-rb6'
        foreach ($d in @('src', 'install')) { $t = Join-Path $pkg $d; [void][IO.Directory]::CreateDirectory($t); Copy-AtmTree -From (Join-Path $repoDir $d) -To $t }
        $cur = Join-Path $sandbox 'PF15\AgentTempManager'
        $prev = "$cur.previous"
        $pf15 = Split-Path -Parent $cur
        $ver = Get-AtmSourceVersion -SourceDir $srcDir
        $recKeys = "'inst\.(rollbackUndoFailed|rollbackVerifyFailed|updateRestored|updateUndoFailed|recoveryPending|recoveryLeftover|recoveryKept|interruptedPrevious|stagingVerifyFailed|previousIntegrity)'"
        foreach ($d in @(@{ P = $cur; T = 'atual' }, @{ P = $prev; T = 'anterior' })) {
            [void][IO.Directory]::CreateDirectory($d.P)
            Copy-AtmTree -From $srcDir -To $d.P
            # The installed catalog without any recovery key, as V0.1's (verified: the manifest is written after it).
            $i18n = Join-Path $d.P 'lib\I18n.ps1'
            $old = @([IO.File]::ReadAllText($i18n) -split "`r`n" | Where-Object { $_ -notmatch $recKeys }) -join "`r`n"
            [IO.File]::WriteAllText($i18n, $old, (New-Object Text.UTF8Encoding($true)))
            Write-AtmManifest -Root $d.P -Version $ver
            [IO.File]::WriteAllText((Join-Path $d.P 'install-state.json'), '{ "product": "Agent Temp Manager", "version": "' + $ver + '", "pathAddedByInstaller": false, "tag": "' + $d.T + '" }')
        }
        $cleanupActions.Add({ try { [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree('Software\AgentTempManagerTest', $false) } catch { $null = $_ } })
        $probe = Join-Path $sandbox 'rb6-probe.ps1'
        [IO.File]::WriteAllText($probe, @'
param([string]$Common, [string]$InstallDir, [string]$Source, [string]$Mode)
$ErrorActionPreference = 'Stop'
$script:AtmCatalogInstallDir = $InstallDir
. $Common
'CATALOG=' + (Get-AtmText 'inst.noPrevious' 'x') + ' RECOVERYKEY=' + (Get-AtmText 'inst.recoveryPending' 'x')
$script:n = 0
function Rename-Item { param([string]$LiteralPath, [string]$NewName) $script:n++; if ($Mode -eq 'undo' -and $script:n -ge 2) { throw 'simulated rename failure' }; Microsoft.PowerShell.Management\Rename-Item -LiteralPath $LiteralPath -NewName $NewName }
foreach ($op in $(if ($Mode -eq 'undo') { @('restore') } else { @('uninstall', 'restore', 'update') })) {
    try {
        switch ($op) {
            'uninstall' { $null = Uninstall-AtmProduct -InstallDir $InstallDir -TestPathKey 'Software\AgentTempManagerTest\EnvB6c' }
            'restore' { $null = Restore-AtmPrevious -InstallDir $InstallDir }
            'update' { $null = Install-AtmProduct -SourceDir $Source -InstallDir $InstallDir -Update -SkipPath -SourceWithoutManifest -TrustSid 'S-1-5-32-544' }
        }
        "MSG[$op]=(none)"
    } catch { "MSG[$op]=" + $_.Exception.Message }
}
'@)
        $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $runProbe = { param([string]$Mode) $ErrorActionPreference = 'Continue'; $o = & $ps -NoProfile -ExecutionPolicy Bypass -File $probe -Common (Join-Path $pkg 'install\InstallCommon.ps1') -InstallDir $cur -Source (Join-Path $pkg 'src') -Mode $Mode 2>&1; @($o | ForEach-Object { "$_" }) }
        # Pending recovery (a recovery directory): the three operations refuse with a complete built-in message.
        $rc = "$cur.recovery-0000000e"
        [void][IO.Directory]::CreateDirectory($rc)
        $out = & $runProbe 'guard'
        $txt = $out -join ' '
        Assert-True ($txt -match 'CATALOG=Nenhuma' -and $txt -match 'RECOVERYKEY=\[inst\.recoveryPending\]') "catalogo antigo carregado e sem as chaves de recuperacao ($txt)"
        foreach ($op in @('uninstall', 'restore', 'update')) {
            $line = @($out | Where-Object { $_.StartsWith("MSG[$op]=") }) -join ' '
            Assert-True ($line.Contains($rc) -and $line -match 'pendente' -and $line -match 'pending' -and $line -match 'Nao desinstale' -and $line -notmatch '\[inst\.') "$($op): mensagem completa sem depender do catalogo ($line)"
        }
        Assert-True ((& $rb6Tag $cur) -eq 'atual' -and (& $rb6Tag $prev) -eq 'anterior' -and (Test-Path -LiteralPath $rc)) 'recusas com catalogo antigo: nada alterado'
        # A rollback whose swap and reversal fail: the message names every copy and the pending marker.
        Rename-Item -LiteralPath $rc -NewName 'AgentTempManager.staging-0000000e'
        $out = & $runProbe 'undo'
        $line = @($out | Where-Object { $_.StartsWith('MSG[restore]=') }) -join ' '
        $retired = @(Get-ChildItem -LiteralPath $pf15 -Directory -Filter 'AgentTempManager.recovery-*')
        Assert-True ($retired.Count -eq 1 -and $line.Contains($retired[0].FullName) -and $line.Contains($prev) -and $line.Contains("$cur.transaction.json")) "rollback que nao reverte: posicoes e marcador na mensagem ($line)"
        Assert-True ($line -match 'simulated rename failure' -and $line -match 'Nada foi apagado' -and $line -match 'Nao desinstale' -and $line -notmatch '\[inst\.') "rollback que nao reverte: motivo e orientacao sem o catalogo ($line)"
        Assert-True ($retired.Count -eq 1 -and (& $rb6Tag $retired[0].FullName) -eq 'atual' -and (& $rb6Tag $prev) -eq 'anterior') 'rollback que nao reverte: copias preservadas'
    }
    # R-B6 concurrency between independent processes. A holder process runs one administrative operation and stops at a
    # gate: when it gets there it writes <gate>.ready and waits until the test writes <gate>.go (no timing guesses).
    # 'staging' stops while the new copy is staged (before any marker), 'integrity' at the rollback's check of
    # .previous (before any marker), 'remove' at the uninstall's first removal, 'postswap' at the verify after the swap.
    $rb6Ps = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $rb6Common = Join-Path (Split-Path -Parent $testsDir) 'install\InstallCommon.ps1'
    $rb6HolderScript = Join-Path $sandbox 'rb6-holder.ps1'
    [IO.File]::WriteAllText($rb6HolderScript, @'
param([string]$Common, [string]$Op, [string]$Source, [string]$InstallDir, [string]$TestPathKey, [string]$TrustSid, [string]$Hold, [string]$Gate, [switch]$Throw)
$ErrorActionPreference = 'Stop'
$script:AtmCatalogTrustUnverified = $true
. $Common
$script:target = [IO.Path]::GetFullPath($InstallDir).TrimEnd('\')
$script:origNative = ${function:New-AtmNativeAssembly}
$script:origVerify = ${function:Invoke-AtmVerifyInstalled}
$script:origIntegrity = ${function:Test-AtmSourceIntegrity}
$script:origRemove = ${function:Remove-AtmOwnTree}
$script:held = $false
function Wait-Gate {
    if ($script:held) { return }
    $script:held = $true
    [IO.File]::WriteAllText("$Gate.ready", [string]$PID)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while (-not (Test-Path -LiteralPath "$Gate.go")) { if ($sw.Elapsed.TotalSeconds -gt 300) { throw 'gate timeout' }; Start-Sleep -Milliseconds 50 }
    if ($Throw) { throw 'simulated exception in the holder' }
}
switch ($Hold) {
    'staging' { function New-AtmNativeAssembly { param([string]$Root) Wait-Gate; & $script:origNative -Root $Root } }
    'postswap' { function Invoke-AtmVerifyInstalled { param([string]$InstallDir) if ([string]::Equals($InstallDir.TrimEnd('\'), $script:target, [StringComparison]::OrdinalIgnoreCase)) { Wait-Gate }; & $script:origVerify -InstallDir $InstallDir } }
    'integrity' { function Test-AtmSourceIntegrity { param([string]$SourceDir, [switch]$AllowNoManifest, [switch]$InstalledCopy) Wait-Gate; & $script:origIntegrity @PSBoundParameters } }
    'remove' { function Remove-AtmOwnTree { param([string]$Path, [string]$InstallDir) Wait-Gate; & $script:origRemove @PSBoundParameters } }
}
$result = 'RESULT=OK'
try {
    switch ($Op) {
        'install' { $null = Install-AtmProduct -SourceDir $Source -InstallDir $InstallDir -TrustSid $TrustSid -TestPathKey $TestPathKey -SourceWithoutManifest }
        'update' { $null = Install-AtmProduct -SourceDir $Source -InstallDir $InstallDir -Update -TrustSid $TrustSid -TestPathKey $TestPathKey -SourceWithoutManifest }
        'rollback' { $null = Restore-AtmPrevious -InstallDir $InstallDir }
        'uninstall' { $null = Uninstall-AtmProduct -InstallDir $InstallDir -TestPathKey $TestPathKey }
    }
} catch { $result = 'RESULT=ERROR ' + $_.Exception.Message }
[IO.File]::WriteAllText("$Gate.result", $result)
'@)
    $rb6StartHolder = { param([string]$Op, [string]$InstallDir, [string]$Hold, [string]$TestPathKey = 'Software\AgentTempManagerTest\EnvB6h', [switch]$Throw)
        $gate = Join-Path $sandbox ('gate-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        $psi = New-Object Diagnostics.ProcessStartInfo
        $psi.FileName = $rb6Ps
        $psi.Arguments = ('-NoProfile -ExecutionPolicy Bypass -File "{0}" -Common "{1}" -Op {2} -Source "{3}" -InstallDir "{4}" -TestPathKey "{5}" -TrustSid {6} -Hold {7} -Gate "{8}"' -f $rb6HolderScript, $rb6Common, $Op, $srcDir, $InstallDir, $TestPathKey, $me.Sid, $Hold, $gate) + $(if ($Throw) { ' -Throw' } else { '' })
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $p = [Diagnostics.Process]::Start($psi)
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while (-not (Test-Path -LiteralPath "$gate.ready") -and -not $p.HasExited -and $sw.Elapsed.TotalSeconds -lt 240) { Start-Sleep -Milliseconds 50 }
        [pscustomobject]@{ Process = $p; Gate = $gate; Ready = (Test-Path -LiteralPath "$gate.ready") } }
    $rb6Result = { param($H) if (Test-Path -LiteralPath "$($H.Gate).result") { [IO.File]::ReadAllText("$($H.Gate).result") } else { '(no result)' } }
    $rb6Release = { param($H)
        [IO.File]::WriteAllText("$($H.Gate).go", 'go')
        if (-not $H.Process.WaitForExit(240000)) { $H.Process.Kill(); [void]$H.Process.WaitForExit(30000) }
        & $rb6Result $H }
    $rb6Stop = { param($H) if ($null -ne $H -and -not $H.Process.HasExited) { $H.Process.Kill(); [void]$H.Process.WaitForExit(30000) } }
    $rb6LockGone = { param([string]$Inst)
        # The OS closes the holder's handle when its process ends; the lock file is delete-on-close.
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while ((Test-Path -LiteralPath "$Inst.lock") -and $sw.Elapsed.TotalSeconds -lt 20) { Start-Sleep -Milliseconds 100 }
        -not (Test-Path -LiteralPath "$Inst.lock") }
    $rb6Build = { param([string]$Cur)
        # A current installation ('atual') and its .previous ('anterior'), built without Install-AtmProduct (no parent
        # ACL requirement, so this runs on any machine).
        $ver = Get-AtmSourceVersion -SourceDir $srcDir
        foreach ($d in @(@{ P = $Cur; T = 'atual' }, @{ P = "$Cur.previous"; T = 'anterior' })) {
            [void][IO.Directory]::CreateDirectory($d.P)
            Copy-AtmTree -From $srcDir -To $d.P
            New-AtmNativeAssembly -Root $d.P
            Write-AtmManifest -Root $d.P -Version $ver
            [IO.File]::WriteAllText((Join-Path $d.P 'install-state.json'), '{ "product": "Agent Temp Manager", "version": "' + $ver + '", "pathAddedByInstaller": false, "tag": "' + $d.T + '" }')
        } }
    Test-Case 'Instalacao' 'R-B6 concorrencia entre processos (rollback e desinstalacao): uma operacao por destino; a concorrente recusa sem alterar nada; destinos distintos nao se bloqueiam; excecao e encerramento abrupto liberam o bloqueio e preservam a evidencia' {
        $holders = @()
        try {
            # 1. A rollback held before its marker exists: uninstall and rollback from this process refuse, nothing moves.
            $cur = Join-Path $sandbox 'PF16\AgentTempManager'
            & $rb6Build $cur
            $h = & $rb6StartHolder 'rollback' $cur 'integrity'; $holders += $h
            Assert-True $h.Ready "rollback detentor chegou ao portao ($(& $rb6Result $h))"
            foreach ($op in @('uninstall', 'rollback')) {
                $g = $null
                try { if ($op -eq 'uninstall') { $null = Uninstall-AtmProduct -InstallDir $cur } else { $null = Restore-AtmPrevious -InstallDir $cur } } catch { $g = $_.Exception.Message }
                Assert-True ($null -ne $g -and $g.Contains("$cur.lock") -and $g -match 'Nada foi alterado') "rollback em andamento: $op concorrente recusado ($g)"
            }
            Assert-True (Test-Path -LiteralPath "$cur.lock") 'bloqueio da operacao presente enquanto o rollback roda'
            Assert-True ((& $rb6Tag $cur) -eq 'atual' -and (& $rb6Tag "$cur.previous") -eq 'anterior' -and (& $rb6Leftovers $cur) -eq '') 'rollback em andamento: recusas nao alteraram nada'
            # 2. A different destination is not blocked.
            $other = Join-Path $sandbox 'PF17\AgentTempManager'
            & $rb6Build $other
            Assert-Eq (Restore-AtmPrevious -InstallDir $other) (Get-AtmSourceVersion -SourceDir $srcDir) 'destino distinto: rollback concluido enquanto o outro destino esta bloqueado'
            Assert-True ((& $rb6Tag $other) -eq 'anterior' -and (& $rb6Leftovers $other) -eq '') 'destino distinto: rollback integro'
            $r = & $rb6Release $h
            Assert-Eq $r 'RESULT=OK' 'rollback detentor concluiu depois de liberado'
            Assert-True ((& $rb6Tag $cur) -eq 'anterior' -and (& $rb6Leftovers $cur) -eq '' -and (& $rb6LockGone $cur)) 'rollback detentor: concluido, nada pendente, bloqueio liberado'
            # 3. An uninstall held at its first removal: a rollback from this process refuses.
            $cur = Join-Path $sandbox 'PF18\AgentTempManager'
            & $rb6Build $cur
            $h = & $rb6StartHolder 'uninstall' $cur 'remove'; $holders += $h
            Assert-True $h.Ready "desinstalacao detentora chegou ao portao ($(& $rb6Result $h))"
            $g = $null; try { $null = Restore-AtmPrevious -InstallDir $cur } catch { $g = $_.Exception.Message }
            Assert-True ($null -ne $g -and $g.Contains("$cur.lock")) "desinstalacao em andamento: rollback concorrente recusado ($g)"
            Assert-True ((& $rb6Tag $cur) -eq 'atual' -and (& $rb6Tag "$cur.previous") -eq 'anterior') 'desinstalacao em andamento: rollback recusado nao moveu nada'
            Assert-Eq (& $rb6Release $h) 'RESULT=OK' 'desinstalacao detentora concluiu'
            Assert-True (-not (Test-Path -LiteralPath $cur) -and (& $rb6LockGone $cur)) 'desinstalacao detentora: produto removido, bloqueio liberado'
            # 4. An exception in the holder releases the lock; nothing was moved; the next operation runs.
            $cur = Join-Path $sandbox 'PF19\AgentTempManager'
            & $rb6Build $cur
            $h = & $rb6StartHolder 'rollback' $cur 'integrity' -Throw; $holders += $h
            Assert-True $h.Ready 'rollback detentor (excecao) chegou ao portao'
            $r = & $rb6Release $h
            Assert-True ($r -match '^RESULT=ERROR .*simulated exception in the holder') "excecao no detentor relatada ($r)"
            Assert-True ((& $rb6LockGone $cur) -and (& $rb6Tag $cur) -eq 'atual' -and (& $rb6Tag "$cur.previous") -eq 'anterior' -and (& $rb6Leftovers $cur) -eq '') 'excecao no detentor: bloqueio liberado, nada movido, nada pendente'
            Assert-Eq (Restore-AtmPrevious -InstallDir $cur) (Get-AtmSourceVersion -SourceDir $srcDir) 'excecao no detentor: operacao seguinte executa'
            # In this process too: an operation that throws after taking the lock releases it.
            $g = $null; try { $null = Restore-AtmPrevious -InstallDir $cur } catch { $g = $_.Exception.Message }
            Assert-True ($null -ne $g -and -not (Test-Path -LiteralPath "$cur.lock") -and $script:AtmLockDepth -eq 0) "excecao neste processo: bloqueio liberado ($g)"
            # 5. The holder is killed after the swap (marker written): the lock goes with the process, the marker stays,
            # every later operation refuses and nothing intact is lost.
            $cur = Join-Path $sandbox 'PF20\AgentTempManager'
            & $rb6Build $cur
            $h = & $rb6StartHolder 'rollback' $cur 'postswap'; $holders += $h
            Assert-True $h.Ready "rollback detentor chegou ao portao apos a troca ($(& $rb6Result $h))"
            $h.Process.Kill(); [void]$h.Process.WaitForExit(30000)
            Assert-True (& $rb6LockGone $cur) 'encerramento abrupto: bloqueio liberado com o processo'
            $rec = @(Get-ChildItem -LiteralPath (Split-Path -Parent $cur) -Directory -Filter 'AgentTempManager.recovery-*')
            Assert-True ((Test-Path -LiteralPath "$cur.transaction.json") -and $rec.Count -eq 1) 'encerramento abrupto: marcador e copia retirada preservados'
            foreach ($op in @('uninstall', 'rollback')) {
                $g = $null
                try { if ($op -eq 'uninstall') { $null = Uninstall-AtmProduct -InstallDir $cur } else { $null = Restore-AtmPrevious -InstallDir $cur } } catch { $g = $_.Exception.Message }
                Assert-True ($null -ne $g -and $g.Contains("$cur.transaction.json") -and $g -match 'Nao desinstale') "encerramento abrupto: $op posterior recusado pela recuperacao pendente ($g)"
            }
            Assert-True ((& $rb6Tag $cur) -eq 'anterior' -and (& $rb6Tag $rec[0].FullName) -eq 'atual' -and (& $rb6Intact $cur) -and (& $rb6Intact $rec[0].FullName)) 'encerramento abrupto: as duas copias integras onde estavam'
            Rename-Item -LiteralPath $cur -NewName (Split-Path -Leaf "$cur.previous")
            Rename-Item -LiteralPath $rec[0].FullName -NewName (Split-Path -Leaf $cur)
            [IO.File]::Delete("$cur.transaction.json")
            Assert-Eq (Invoke-Rb5Cli (Join-Path $cur 'bin\agent-temp.cmd') 'verify').Exit 0 'encerramento abrupto: recuperacao manual, instalacao integra'
            # 6. The marker of another transaction is never overwritten nor removed.
            $m = "$cur.transaction.json"
            [IO.File]::WriteAllText($m, '{ "id": "outra-transacao", "operation": "update" }')
            $threw = $false; try { Write-AtmTransaction -InstallDir $cur -Id 'esta' -Operation 'rollback' -State 'started' -Copies @{} -New } catch { $threw = $true }
            Assert-True ($threw -and [IO.File]::ReadAllText($m).Contains('outra-transacao')) 'marcador de outra transacao nao sobrescrito'
            Clear-AtmTransaction -InstallDir $cur -Id 'esta' 3> $null
            Assert-True ([IO.File]::ReadAllText($m).Contains('outra-transacao')) 'marcador de outra transacao nao removido'
            [IO.File]::Delete($m)
        } finally { foreach ($x in $holders) { & $rb6Stop $x } }
    }
    Test-Case 'Instalacao' 'R-B6 concorrencia entre processos (instalacao e atualizacao): update+update, update+rollback, update+desinstalacao e instalacao+instalacao recusam a segunda; destinos distintos seguem; excecao e encerramento abrupto do detentor nao destroem a instalacao integra' {
        $testKey = 'Software\AgentTempManagerTest\EnvB6h'
        $cleanupActions.Add({ try { [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree('Software\AgentTempManagerTest', $false) } catch { $null = $_ } })
        $k = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($testKey)
        $k.SetValue('Path', '%SystemRoot%\system32;C:\Outro\Bin', [Microsoft.Win32.RegistryValueKind]::ExpandString); $k.Close()
        $pathSnap = { $pk = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($testKey); try { [string]$pk.GetValueKind('Path') + '|' + [string]$pk.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) } finally { $pk.Close() } }
        $inst = Join-Path $sandbox 'PF21\AgentTempManager'
        $prev = "$inst.previous"
        [void][IO.Directory]::CreateDirectory((Split-Path -Parent $inst))
        $inArgs = @{ SourceDir = $srcDir; InstallDir = $inst; TrustSid = $me.Sid; TestPathKey = $testKey; SourceWithoutManifest = $true }
        $null = Install-AtmProduct @inArgs
        $null = Install-AtmProduct @inArgs -Update
        & $rb6SetTag $inst 'v2'; & $rb6SetTag $prev 'v1'
        $path0 = & $pathSnap
        $holders = @()
        try {
            # 1. An update held while staging (before any marker): update, rollback and uninstall refuse.
            $h = & $rb6StartHolder 'update' $inst 'staging' $testKey; $holders += $h
            Assert-True $h.Ready "atualizacao detentora chegou ao portao ($(& $rb6Result $h))"
            foreach ($op in @('update', 'rollback', 'uninstall')) {
                $g = $null
                try {
                    switch ($op) {
                        'update' { $null = Install-AtmProduct @inArgs -Update }
                        'rollback' { $null = Restore-AtmPrevious -InstallDir $inst }
                        'uninstall' { $null = Uninstall-AtmProduct -InstallDir $inst -TestPathKey $testKey }
                    }
                } catch { $g = $_.Exception.Message }
                Assert-True ($null -ne $g -and $g.Contains("$inst.lock") -and $g -match 'Nada foi alterado') "atualizacao em andamento: $op concorrente recusado ($g)"
                Assert-True ((& $rb6Tag $inst) -eq 'v2' -and (& $rb6Tag $prev) -eq 'v1' -and (& $rb6Pending $inst) -eq '' -and (& $pathSnap) -eq $path0) "atualizacao em andamento: $op recusado nao alterou instalacao, .previous nem PATH"
            }
            # 2. A different destination is not blocked: a first installation there completes meanwhile.
            $other = Join-Path $sandbox 'PF22\AgentTempManager'
            [void][IO.Directory]::CreateDirectory((Split-Path -Parent $other))
            $null = Install-AtmProduct -SourceDir $srcDir -InstallDir $other -TrustSid $me.Sid -SkipPath -SourceWithoutManifest
            Assert-Eq (Invoke-Rb5Cli (Join-Path $other 'bin\agent-temp.cmd') 'verify').Exit 0 'destino distinto: instalado enquanto o outro destino esta bloqueado'
            Assert-Eq (& $rb6Release $h) 'RESULT=OK' 'atualizacao detentora concluiu depois de liberada'
            Assert-True ((& $rb6Tag $inst) -eq '' -and (& $rb6Tag $prev) -eq 'v2' -and (& $rb6Pending $inst) -eq '' -and (& $rb6LockGone $inst)) 'atualizacao detentora: concluida, nada pendente, bloqueio liberado'
            & $rb6SetTag $inst 'v3'
            # 3. Two first installations on the same destination: the second refuses.
            $fresh = Join-Path $sandbox 'PF23\AgentTempManager'
            [void][IO.Directory]::CreateDirectory((Split-Path -Parent $fresh))
            $h = & $rb6StartHolder 'install' $fresh 'staging' $testKey; $holders += $h
            Assert-True $h.Ready "instalacao detentora chegou ao portao ($(& $rb6Result $h))"
            $g = $null; try { $null = Install-AtmProduct -SourceDir $srcDir -InstallDir $fresh -TrustSid $me.Sid -SkipPath -SourceWithoutManifest } catch { $g = $_.Exception.Message }
            Assert-True ($null -ne $g -and $g.Contains("$fresh.lock")) "instalacao em andamento: segunda instalacao no mesmo destino recusada ($g)"
            Assert-True (-not (Test-Path -LiteralPath $fresh)) 'instalacao em andamento: a recusada nao criou o destino'
            Assert-Eq (& $rb6Release $h) 'RESULT=OK' 'instalacao detentora concluiu'
            Assert-Eq (Invoke-Rb5Cli (Join-Path $fresh 'bin\agent-temp.cmd') 'verify').Exit 0 'instalacao detentora: instalacao integra'
            # (that installation added its own bin to the test PATH key: the reference for the cases below)
            $path0 = & $pathSnap
            # 4. An exception in an update holder: lock released, installation and .previous intact, next update runs.
            $h = & $rb6StartHolder 'update' $inst 'staging' $testKey -Throw; $holders += $h
            Assert-True $h.Ready 'atualizacao detentora (excecao) chegou ao portao'
            $r = & $rb6Release $h
            Assert-True ($r -match '^RESULT=ERROR .*simulated exception in the holder') "excecao no detentor relatada ($r)"
            Assert-True (& $rb6LockGone $inst) 'excecao no detentor: bloqueio liberado'
            Assert-True ((& $rb6Tag $inst) -eq 'v3' -and (& $rb6Tag $prev) -eq 'v2') "excecao no detentor: instalacao e .previous intactas ($(& $rb6Tag $inst) / $(& $rb6Tag $prev))"
            Assert-Eq (& $rb6Leftovers $inst) '' 'excecao no detentor: nada pendente nem intermediario'
            Assert-Eq (& $pathSnap) $path0 'excecao no detentor: PATH intacto'
            # 5. An update holder killed after the swap (marker written): the lock goes with the process; the marker, the
            # installed copy (now .previous) and the older .previous (recovery) stay; every later operation refuses.
            $h = & $rb6StartHolder 'update' $inst 'postswap' $testKey; $holders += $h
            Assert-True $h.Ready "atualizacao detentora chegou ao portao apos a troca ($(& $rb6Result $h))"
            $h.Process.Kill(); [void]$h.Process.WaitForExit(30000)
            Assert-True (& $rb6LockGone $inst) 'encerramento abrupto: bloqueio liberado com o processo'
            $rec = @(Get-ChildItem -LiteralPath (Split-Path -Parent $inst) -Directory -Filter 'AgentTempManager.recovery-*')
            Assert-True ((Test-Path -LiteralPath "$inst.transaction.json") -and $rec.Count -eq 1) 'encerramento abrupto: marcador e .previous antiga preservados'
            foreach ($op in @('update', 'rollback', 'uninstall')) {
                $g = $null
                try {
                    switch ($op) {
                        'update' { $null = Install-AtmProduct @inArgs -Update }
                        'rollback' { $null = Restore-AtmPrevious -InstallDir $inst }
                        'uninstall' { $null = Uninstall-AtmProduct -InstallDir $inst -TestPathKey $testKey }
                    }
                } catch { $g = $_.Exception.Message }
                Assert-True ($null -ne $g -and $g.Contains("$inst.transaction.json") -and $g -match 'Nao desinstale') "encerramento abrupto: $op posterior recusado ($g)"
            }
            Assert-True ((& $rb6Tag $prev) -eq 'v3' -and (& $rb6Tag $rec[0].FullName) -eq 'v2' -and (& $rb6Intact $prev) -and (& $rb6Intact $rec[0].FullName) -and (& $rb6Intact $inst)) 'encerramento abrupto: instalada (v3), .previous antiga (v2) e nova integras, nada apagado'
            Assert-Eq (& $pathSnap) $path0 'encerramento abrupto: PATH intacto'
            # Manual recovery by rename only, then the marker; the installation updates again.
            Rename-Item -LiteralPath $inst -NewName 'AgentTempManager.staging-3000000a'
            Rename-Item -LiteralPath $prev -NewName (Split-Path -Leaf $inst)
            Rename-Item -LiteralPath $rec[0].FullName -NewName (Split-Path -Leaf $prev)
            [IO.File]::Delete("$inst.transaction.json")
            Assert-True ((& $rb6Tag $inst) -eq 'v3' -and (& $rb6Tag $prev) -eq 'v2') 'recuperacao manual: posicoes originais'
            $null = Install-AtmProduct @inArgs -Update
            Assert-True ((& $rb6Tag $prev) -eq 'v3' -and (& $rb6Pending $inst) -eq '' -and (& $rb6LockGone $inst)) 'recuperacao manual: atualizar volta a funcionar'
        } finally { foreach ($x in $holders) { & $rb6Stop $x } }
    }
    Test-Case 'Instalacao' 'Auditoria de ACL: escrita por Users/Everyone e detectada; Program Files padrao e aceito' {
        $d = Join-Path $sandbox 'aclcheck'; [void][IO.Directory]::CreateDirectory($d); [IO.File]::WriteAllText((Join-Path $d 'x.ps1'), '#')
        # The scenario needs an ordinary-user write entry; in an elevated session the sandbox only grants SYSTEM and
        # Administrators, so the entry is granted explicitly (redundant, and harmless, for a standard account).
        $o = icacls $d /grant "*$($me.Sid):(OI)(CI)(M)" 2>&1
        Assert-Eq $LASTEXITCODE 0 "ACE do usuario comum concedida: $o"
        Assert-True (Test-AtmInstallAcl -Path $d -AlsoTrustSid $me.Sid).Ok 'diretorio privado ok'
        Assert-True (-not (Test-AtmInstallAcl -Path $d).Ok) 'sem confiar no usuario: owner/ACE do usuario comum detectados'
        $o = icacls $d /grant '*S-1-5-32-545:(OI)(CI)(M)' 2>&1
        $r = Test-AtmInstallAcl -Path $d -AlsoTrustSid $me.Sid
        Assert-True (-not $r.Ok) 'Users com Modify detectado'
        $acl = Get-Acl -LiteralPath $env:ProgramFiles
        $bad = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object { $_.AccessControlType -eq 'Allow' -and $script:AtmUntrustedSids -contains $_.IdentityReference.Value -and (($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]'WriteData, AppendData, Delete, ChangePermissions, TakeOwnership') -ne 0) -and -not ($_.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) })
        Assert-Eq $bad.Count 0 'Program Files nao concede escrita a usuarios comuns (heranca segura)'
        Assert-True ([bool](Get-Command Remove-AtmOwnTree)) 'helper'
        $threw = $false; try { Remove-AtmOwnTree -Path $sandbox -InstallDir (Join-Path $sandbox 'PF\AgentTempManager') } catch { $threw = $true }
        Assert-True $threw 'remocao recusa diretorio que nao e do produto'
    }
    Test-Case 'Instalacao' 'Instalador e desinstalador recusam execucao sem elevacao (nenhuma elevacao silenciosa)' {
        if ($me.IsAdmin) { $script:caseSkipped = $true; $script:caseNote = 'sessao elevada: teste de recusa sem elevacao nao aplicavel'; return }
        $inst = Join-Path (Split-Path -Parent $testsDir) 'install'
        $ErrorActionPreference = 'Continue'   # native stderr must not throw here
        $o = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $inst 'Install-AgentTempManager.ps1') -InstallDir (Join-Path $sandbox 'nunca') 2>&1
        Assert-True ($LASTEXITCODE -ne 0) 'instalador falha'
        Assert-True (($o -join ' ') -match 'Administrador') 'mensagem clara'
        Assert-True (-not (Test-Path (Join-Path $sandbox 'nunca'))) 'nada criado'
        $o = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $inst 'Uninstall-AgentTempManager.ps1') -InstallDir (Join-Path $sandbox 'nunca') 2>&1
        Assert-True ($LASTEXITCODE -ne 0) 'desinstalador falha'
    }

    Test-Case 'Instalacao' 'Ponta a ponta no sandbox: instalar, PATH (REG_EXPAND_SZ), atualizar, rollback, desinstalar' {
        $testKey = 'Software\AgentTempManagerTest\Env'
        # Best-effort cleanup of the test registry key.
        $cleanupActions.Add({ try { [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree('Software\AgentTempManagerTest', $false) } catch { $null = $_ } })
        $k = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($testKey)
        $k.SetValue('Path', '%SystemRoot%\system32;C:\Outro\Bin', [Microsoft.Win32.RegistryValueKind]::ExpandString); $k.Close()
        $inst = Join-Path $sandbox 'PF2\AgentTempManager'
        [void][IO.Directory]::CreateDirectory((Split-Path -Parent $inst))
        $r1 = Install-AtmProduct -SourceDir $srcDir -InstallDir $inst -TrustSid $me.Sid -TestPathKey $testKey -SourceWithoutManifest
        Assert-Eq $r1.Version (Get-AtmSourceVersion -SourceDir $srcDir) 'versao'
        Assert-True $r1.PathAdded 'PATH adicionado'
        $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($testKey)
        $raw = [string]$k.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames); $kind = $k.GetValueKind('Path'); $k.Close()
        Assert-Eq ([string]$kind) 'ExpandString' 'tipo REG_EXPAND_SZ preservado'
        Assert-True ($raw.StartsWith('%SystemRoot%\system32;C:\Outro\Bin;')) "entradas existentes e variaveis preservadas: $raw"
        Assert-True ($raw.EndsWith((Join-Path $inst 'bin'))) 'bin adicionado'
        Assert-True (-not (Add-AtmMachinePath -Dir (Join-Path $inst 'bin') -TestKeyPath $testKey)) 'idempotente'
        Assert-True (Test-Path (Join-Path $inst 'lib\AgentTempManager.Native.dll')) 'DLL compilada no destino'
        Assert-True (-not (Test-Path (Join-Path $inst '.build-tmp'))) 'temporarios de compilacao removidos'
        $threw = $false; try { $null = Install-AtmProduct -SourceDir $srcDir -InstallDir $inst -TrustSid $me.Sid -TestPathKey $testKey -SourceWithoutManifest } catch { $threw = $true }
        Assert-True $threw 'reinstalar sem -Update e recusado'
        Add-Content -LiteralPath (Join-Path $inst 'install-state.json') -Value ' ' -NoNewline
        $marker = (Get-Item (Join-Path $inst 'manifest.json')).LastWriteTimeUtc
        $r2 = Install-AtmProduct -SourceDir $srcDir -InstallDir $inst -Update -TrustSid $me.Sid -TestPathKey $testKey -SourceWithoutManifest
        Assert-True $r2.PreviousKept 'versao anterior mantida'
        Assert-True (-not $r2.PathAdded) 'PATH nao duplicado na atualizacao'
        $v = Restore-AtmPrevious -InstallDir $inst
        Assert-Eq $v $r1.Version 'rollback restaurou e verificou'
        Assert-Eq (Get-Item (Join-Path $inst 'manifest.json')).LastWriteTimeUtc $marker 'arquivos da versao anterior'
        Assert-Eq @(Get-ChildItem -LiteralPath (Split-Path -Parent $inst) -Directory -Filter 'AgentTempManager.staging-*').Count 0 'sem staging residual'
        $removed = Uninstall-AtmProduct -InstallDir $inst -TestPathKey $testKey
        Assert-True $removed 'PATH removido'
        Assert-True (-not (Test-Path $inst) -and -not (Test-Path "$inst.previous")) 'diretorios do produto removidos'
        $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($testKey)
        Assert-Eq ([string]$k.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)) '%SystemRoot%\system32;C:\Outro\Bin' 'demais entradas intactas'
        Assert-Eq ([string]$k.GetValueKind('Path')) 'ExpandString' 'tipo intacto'
        $k.Close()
    }

    Test-Case 'Instalacao' 'Origem verificada contra o manifesto do release; provider plantado e recusado (instalacao e execucao)' {
        $rel = Join-Path $sandbox 'release-src'
        [void][IO.Directory]::CreateDirectory($rel)
        Copy-AtmTree -From $srcDir -To $rel
        Write-AtmManifest -Root $rel -Version (Get-AtmSourceVersion -SourceDir $rel)
        Test-AtmSourceIntegrity -SourceDir $rel
        $short = [AgentTempManager.AtmNative]::GetShortPath($rel)
        if ($short -and $short -ne $rel) { Test-AtmSourceIntegrity -SourceDir $short.TrimEnd('\') }   # 8.3 form of the same source
        $out = & cmd.exe /c "`"$(Join-Path $rel 'bin\agent-temp.cmd')`" version" 2>&1
        Assert-Eq $LASTEXITCODE 0 "release extraido roda sem instalar ($out)"
        Assert-True (($out -join ' ') -match 'compilado em mem.ria') 'release extraido compila em memoria'
        [IO.File]::WriteAllText((Join-Path $rel 'providers\Plantado.ps1'), 'Write-Host pwned')
        $threw = $false; try { Test-AtmSourceIntegrity -SourceDir $rel } catch { $threw = ($_.Exception.Message -match 'fora do manifesto') }
        Assert-True $threw 'arquivo extra na origem recusado'
        [IO.File]::Delete((Join-Path $rel 'providers\Plantado.ps1'))
        Add-Content -LiteralPath (Join-Path $rel 'lib\Report.ps1') -Value '#x'
        $threw = $false; try { Test-AtmSourceIntegrity -SourceDir $rel } catch { $threw = ($_.Exception.Message -match 'hash divergente') }
        Assert-True $threw 'arquivo alterado na origem recusado'
        $threw = $false; try { Test-AtmSourceIntegrity -SourceDir $srcDir } catch { $threw = $true }
        Assert-True $threw 'origem sem manifesto exige -SourceWithoutManifest'
        # Runtime: an installed copy refuses to run with an unlisted provider.
        $inst = Join-Path $sandbox 'PF3\AgentTempManager'
        [void][IO.Directory]::CreateDirectory((Split-Path -Parent $inst))
        $null = Install-AtmProduct -SourceDir $srcDir -InstallDir $inst -TrustSid $me.Sid -SkipPath -SourceWithoutManifest
        $cmd = Join-Path $inst 'bin\agent-temp.cmd'
        $out = & cmd.exe /c "`"$cmd`" version" 2>&1; Assert-Eq $LASTEXITCODE 0 "instalado integro ($out)"
        [IO.File]::WriteAllText((Join-Path $inst 'providers\Plantado.ps1'), 'Write-Host pwned')
        $out = & cmd.exe /c "`"$cmd`" version" 2>&1
        Assert-Eq $LASTEXITCODE 5 'provider fora do manifesto: execucao recusada'
        Assert-True (($out -join ' ') -match 'provider fora do manifesto') 'motivo'
        Assert-True (($out -join ' ') -notmatch 'pwned') 'codigo plantado nunca executou'
        [IO.File]::Delete((Join-Path $inst 'providers\Plantado.ps1'))
        [IO.File]::Delete((Join-Path $inst 'lib\AgentTempManager.Native.dll'))
        $out = & cmd.exe /c "`"$cmd`" version" 2>&1; Assert-Eq $LASTEXITCODE 5 'DLL ausente na instalacao: recusado'
        Uninstall-AtmProduct -InstallDir $inst | Out-Null
    }
    Test-Case 'Instalacao' 'Diretorio pai gravavel por usuarios comuns e recusado; PATH pre-existente nunca e removido' {
        $parent = Join-Path $sandbox 'PF4'
        [void][IO.Directory]::CreateDirectory($parent)
        $null = icacls $parent /grant '*S-1-5-32-545:(OI)(CI)(M)' 2>&1
        $threw = $false; try { $null = Install-AtmProduct -SourceDir $srcDir -InstallDir (Join-Path $parent 'AgentTempManager') -TrustSid $me.Sid -SkipPath -SourceWithoutManifest } catch { $threw = ($_.Exception.Message -match 'pai inseguro') }
        Assert-True $threw 'pai inseguro recusado'
        Assert-True (-not (Test-Path (Join-Path $parent 'AgentTempManager'))) 'nada instalado'
        $testKey = 'Software\AgentTempManagerTest\Env2'
        # Best-effort cleanup of the test registry key.
        $cleanupActions.Add({ try { [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree('Software\AgentTempManagerTest', $false) } catch { $null = $_ } })
        $inst = Join-Path $sandbox 'PF5\AgentTempManager'
        [void][IO.Directory]::CreateDirectory((Split-Path -Parent $inst))
        $k = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($testKey)
        $k.SetValue('Path', "C:\A;$(Join-Path $inst 'bin')", [Microsoft.Win32.RegistryValueKind]::ExpandString); $k.Close()
        $r1 = Install-AtmProduct -SourceDir $srcDir -InstallDir $inst -TrustSid $me.Sid -TestPathKey $testKey -SourceWithoutManifest
        Assert-True (-not $r1.PathAdded) 'entrada ja existia: nao adicionada'
        $removed = Uninstall-AtmProduct -InstallDir $inst -TestPathKey $testKey
        Assert-True (-not $removed) 'entrada pre-existente nao removida'
        $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($testKey)
        Assert-True (([string]$k.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)).Contains((Join-Path $inst 'bin'))) 'PATH intacto'
        $k.Close()
    }

    Test-Case 'Instalacao' 'Operacoes administrativas usam TEMP privado (heranca admin-only) e o removem ao final' {
        $inst = Join-Path $sandbox 'PF6\AgentTempManager'
        [void][IO.Directory]::CreateDirectory((Split-Path -Parent $inst))
        $oldTemp = $env:TEMP
        $st = Enter-AtmPrivateTemp -InstallDir $inst
        try {
            Assert-True ($env:TEMP -eq $st.Dir -and $env:TMP -eq $st.Dir) 'TEMP/TMP redirecionados'
            Assert-True ($st.Dir -match '\\AgentTempManager\.staging-[0-9a-f]{8}$') 'nome aceito por Remove-AtmOwnTree'
            Assert-True ([IO.Path]::GetDirectoryName($st.Dir) -eq (Split-Path -Parent $inst)) 'ao lado do destino (mesma ACL do pai)'
            [IO.File]::WriteAllText((Join-Path $env:TEMP 'intermediario.tmp'), 'x')
        } finally { Exit-AtmPrivateTemp -State $st -InstallDir $inst }
        Assert-Eq $env:TEMP $oldTemp 'TEMP restaurado'
        Assert-True (-not (Test-Path $st.Dir)) 'TEMP privado removido'
        $instDir = Join-Path (Split-Path -Parent $testsDir) 'install'
        foreach ($w in @('Install-AgentTempManager.ps1', 'Uninstall-AgentTempManager.ps1', 'Restore-AgentTempManagerPrevious.ps1')) {
            $txt = [IO.File]::ReadAllText((Join-Path $instDir $w))
            $iEnter = $txt.IndexOf('Enter-AtmPrivateTemp'); $iElev = $txt.IndexOf('Assert-AtmElevated')
            $iOp = [regex]::Match($txt, '(Install-AtmProduct|Uninstall-AtmProduct|Restore-AtmPrevious) -').Index
            Assert-True ($iElev -ge 0 -and $iEnter -gt $iElev -and $iOp -gt $iEnter -and $txt.Contains('Exit-AtmPrivateTemp')) "${w}: elevacao -> TEMP privado -> operacao -> limpeza"
        }
    }

    Test-Case 'Ambiente de teste' 'Ajuste de ACL do sandbox (sessao elevada): somente o sandbox vazio e canonico; ACL resultante verificada' {
        $fakeRoot = Join-Path $sandbox 'acl-guard'
        $ok = Join-Path $fakeRoot 'atm-tests-0123abcd'; [void][IO.Directory]::CreateDirectory($ok)
        Assert-Eq @(Get-SandboxAclTargetProblems -Path $ok -TempRoot $fakeRoot).Count 0 'sandbox valido aceito'
        $full = Join-Path $fakeRoot 'atm-tests-1111aaaa'; [void][IO.Directory]::CreateDirectory($full); [IO.File]::WriteAllText((Join-Path $full 'f.txt'), 'x')
        Assert-True ((@(Get-SandboxAclTargetProblems -Path $full -TempRoot $fakeRoot) -join ';') -match 'nao vazio') 'nao vazio recusado'
        $odd = Join-Path $fakeRoot 'atm-tests-XYZ'; [void][IO.Directory]::CreateDirectory($odd)
        Assert-True ((@(Get-SandboxAclTargetProblems -Path $odd -TempRoot $fakeRoot) -join ';') -match 'nome inesperado') 'nome inesperado recusado'
        $deep = Join-Path $fakeRoot 'sub\atm-tests-2222bbbb'; [void][IO.Directory]::CreateDirectory($deep)
        Assert-True ((@(Get-SandboxAclTargetProblems -Path $deep -TempRoot $fakeRoot) -join ';') -match 'fora da raiz') 'fora da raiz recusado'
        $self = @(Get-SandboxAclTargetProblems -Path $fakeRoot -TempRoot $fakeRoot) -join ';'
        Assert-True ($self -match 'fora da raiz' -and $self -match 'nome inesperado') 'a propria raiz temporaria e recusada'
        $tgt = Join-Path $sandbox 'acl-guard-alvo'; [void][IO.Directory]::CreateDirectory($tgt)
        $jn = Join-Path $fakeRoot 'atm-tests-3333cccc'; New-Junction -Link $jn -Target $tgt
        Assert-True ((@(Get-SandboxAclTargetProblems -Path $jn -TempRoot $fakeRoot) -join ';') -match 'reparse point') 'junction recusada'
        $jroot = Join-Path $sandbox 'acl-guard-jroot'; New-Junction -Link $jroot -Target $fakeRoot
        Assert-True ((@(Get-SandboxAclTargetProblems -Path (Join-Path $jroot 'atm-tests-0123abcd') -TempRoot $jroot) -join ';') -match 'reparse point') 'ancestral reparse recusado'
        Assert-True (@(Get-SandboxAclTargetProblems -Path (Join-Path $fakeRoot 'atm-tests-4444dddd') -TempRoot $fakeRoot) -contains 'inexistente') 'inexistente recusado'
        # The result check rejects an ACL that still inherits from ancestors (the unadjusted case) ...
        $okOwner = (Get-Acl -LiteralPath $ok).GetOwner([Security.Principal.SecurityIdentifier]).Value
        Assert-True ((@(Get-SandboxAclResultProblems -Path $ok -OwnerSid $okOwner) -join ';') -match 'heranca ainda ativa') 'ACL herdada nao passa na verificacao'
        # ... and accepts exactly what the adjustment produces (applied here to a directory inside the sandbox, then
        # reset to inherited so the sandbox can be removed even without elevation).
        $cleanupActions.Add([scriptblock]::Create("icacls '$ok' /reset 2>&1 | Out-Null"))
        Set-SandboxSingleOwnerAcl -Path $ok
        $applied = @(Get-SandboxAclResultProblems -Path $ok -OwnerSid $okOwner)
        $null = icacls $ok /reset 2>&1
        Assert-Eq $applied.Count 0 "ACL aplicada = SYSTEM + Administradores, protegida ($($applied -join '; '))"
        Assert-Eq $LASTEXITCODE 0 'heranca restaurada'
        if ($script:sandboxAclAdjusted) {
            Assert-Eq @(Get-SandboxAclResultProblems -Path $sandbox -OwnerSid $testOwnerSid).Count 0 'ACL ajustada do sandbox = SYSTEM + Administradores'
            $script:caseNote = 'sessao elevada: ACL do sandbox ajustada e verificada'
        } else { $script:caseNote = 'sessao nao elevada: nenhum ajuste de ACL (owner = usuario)' }
    }

    Test-Case 'Ambiente de teste' 'Teste de instalacao real (e2e) recusa rodar fora de maquina descartavel e nao cria nada' {
        $e2e = Join-Path $testsDir 'e2e\Invoke-InstallE2E.ps1'
        $out = Join-Path $sandbox 'e2e-out'
        $shell = (Get-Process -Id $PID).Path
        # The runner markers are cleared in the child, so the refusal is verified in CI too.
        # Windows PowerShell 5.1 turns the child's stderr into a terminating error under 'Stop'; collect it instead.
        $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        try {
            $o = @(& $shell -NoProfile -ExecutionPolicy Bypass -Command "`$env:GITHUB_ACTIONS = ''; `$env:RUNNER_ENVIRONMENT = ''; & '$($e2e.Replace("'", "''"))' -OutDir '$($out.Replace("'", "''"))'" 2>&1 | ForEach-Object { "$_" })
            $code = $LASTEXITCODE
        } finally { $ErrorActionPreference = $eap }
        Assert-True ($code -ne 0) 'recusa com codigo de saida diferente de zero'
        Assert-True (($o -join ' ') -match 'Recusado') "mensagem de recusa: $($o -join ' ')"
        Assert-True (-not (Test-Path -LiteralPath $out)) 'nada criado'
    }

    Test-Case 'Analise estatica' 'Excecoes revisadas: justificadas, restritas e sem enfraquecer as regras impostas' {
        $root = Split-Path -Parent $testsDir
        $cfg = Import-PowerShellDataFile -LiteralPath (Join-Path $root 'tools\static-analysis-exceptions.psd1')
        $enforced = @($cfg.EnforcedRules)
        foreach ($r in @('PSAvoidUsingInvokeExpression', 'PSAvoidUsingPlainTextForPassword', 'PSAvoidUsingConvertToSecureStringWithPlainText', 'PSUsePSCredentialType', 'PSAvoidUsingUsernameAndPasswordParams', 'PSAvoidUsingBrokenHashAlgorithms', 'PSUseCompatibleSyntax', 'PSUseCompatibleCommands', 'PSUseCompatibleTypes', 'PSAvoidAssignmentToAutomaticVariable', 'PSAvoidUsingEmptyCatchBlock')) {
            Assert-True ($enforced -contains $r) "regra imposta: $r"
        }
        foreach ($e in @($cfg.Exceptions)) {
            Assert-True ([bool]$e['Rule'] -and @($e['Files']).Count -gt 0 -and ([string]$e['Justification']).Trim().Length -ge 20) "excecao completa: $($e['Rule'])"
            if ($enforced -contains $e['Rule']) { Assert-True ([bool]$e['Match']) "excecao de regra imposta restrita por Match: $($e['Rule'])" }
            foreach ($f in @($e['Files'])) { Assert-True (Test-Path -LiteralPath (Join-Path $root $f) -PathType Leaf) "arquivo da excecao existe: $f" }
            Assert-True (-not (@($e['Files']) | Where-Object { $_ -match '[*?]' })) 'sem curingas nos arquivos'
        }
        # The engines and the installer library are never exempt from the console-output rule.
        $wh = @($cfg.Exceptions | Where-Object { $_['Rule'] -eq 'PSAvoidUsingWriteHost' } | ForEach-Object { @($_['Files']) })
        foreach ($f in @('src/lib/Engine.Audit.ps1', 'src/lib/Engine.Clean.ps1', 'src/lib/I18n.ps1', 'src/providers/ClaudeCode.ps1', 'install/InstallCommon.ps1')) { Assert-True ($wh -notcontains $f) "sem excecao de Write-Host: $f" }
    }

    Test-Case 'Analise estatica' 'Assinaturas do PSScriptAnalyzer: excecao de catalogo restrita a um arquivo e hash; demais casos recusados' {
        . (Join-Path (Split-Path -Parent $testsDir) 'tools\StaticAnalysisSignature.ps1')
        # The allow-list itself is unchanged and the exception list stays one exact, complete entry.
        Assert-Eq (@($script:AtmAnalyzerAllowedSigners) -join '|') 'Microsoft Corporation|Microsoft 3rd Party Application Component|Json.NET (.NET Foundation)' 'allow-list global inalterada'
        Assert-True ($script:AtmAnalyzerAllowedSigners -notcontains 'Microsoft Windows') 'Microsoft Windows fora da allow-list global'
        $ex = @($script:AtmAnalyzerSignatureExceptions)
        Assert-Eq $ex.Count 1 'uma unica excecao'
        foreach ($e in $ex) {
            Assert-True ($e.Path -notmatch '[*?\\/]') "caminho exato, sem curinga: $($e.Path)"
            Assert-True ($e.Sha256 -cmatch '^[0-9A-F]{64}$') 'SHA-256 fixado'
            Assert-Eq $e.SignatureType 'Catalog' 'somente assinatura de catalogo'
            Assert-True ($script:AtmAnalyzerAllowedSigners -ccontains $e.EmbeddedSigner) 'certificado embutido de signatario permitido'
            Assert-True (([string]$e.Justification).Trim().Length -ge 20) 'justificativa'
        }
        $good = $ex[0]
        $catalog = [pscustomobject]@{ RelativePath = $good.Path; Sha256 = $good.Sha256; Status = 'Valid'; SignatureType = 'Catalog'; Signer = $good.Signer; EmbeddedSigner = $good.EmbeddedSigner }
        $v = Test-AtmAnalyzerSignature -Facts $catalog
        Assert-True ($v.Accepted -and $v.Exception -eq $good.Path) 'caso exato aceito pela excecao'
        $v = Test-AtmAnalyzerSignature -Facts ([pscustomobject]@{ RelativePath = 'x.dll'; Sha256 = ('0' * 64); Status = 'Valid'; SignatureType = 'Authenticode'; Signer = 'Microsoft Corporation'; EmbeddedSigner = 'Microsoft Corporation' })
        Assert-True ($v.Accepted -and $null -eq $v.Exception) 'signatario permitido aceito sem excecao'
        $negatives = [ordered]@{
            'status HashMismatch'                = @{ Status = 'HashMismatch' }
            'status NotSigned'                   = @{ Status = 'NotSigned' }
            'hash difere (adulterado ou versao)' = @{ Sha256 = ('A' * 64) }
            'outro arquivo com o mesmo hash'     = @{ RelativePath = 'Other.dll' }
            'mesmo nome em subpasta'             = @{ RelativePath = 'lib\Newtonsoft.Json.dll' }
            'outro signatario de catalogo'       = @{ Signer = 'Contoso' }
            'Microsoft Windows embutido'         = @{ SignatureType = 'Authenticode' }
            'tipo de assinatura ausente'         = @{ SignatureType = '' }
            'sem certificado embutido'           = @{ EmbeddedSigner = '' }
            'certificado embutido diferente'     = @{ EmbeddedSigner = 'Contoso' }
            'signatario em outra caixa'          = @{ Signer = 'microsoft windows' }
        }
        foreach ($n in $negatives.Keys) {
            $f = $catalog.PSObject.Copy()
            foreach ($k in $negatives[$n].Keys) { $f.$k = $negatives[$n][$k] }
            $v = Test-AtmAnalyzerSignature -Facts $f
            Assert-True (-not $v.Accepted) "recusado: $n ($($v.Reason))"
        }
        # Real facts of an unsigned file named like the excepted one: rejected.
        $fake = Join-Path $sandbox 'sig\Newtonsoft.Json.dll'; [void][IO.Directory]::CreateDirectory((Split-Path -Parent $fake))
        [IO.File]::WriteAllBytes($fake, [byte[]](1..64))
        $facts = Get-AtmAnalyzerSignatureInfo -Path $fake -RelativePath 'Newtonsoft.Json.dll'
        Assert-True ($facts.Status -ne 'Valid' -and $facts.EmbeddedSigner -eq '') "arquivo real sem assinatura: $($facts.Status)"
        Assert-True (-not (Test-AtmAnalyzerSignature -Facts $facts).Accepted) 'arquivo real falso recusado'
    }

    Test-Case 'Ambiente limpo' 'Gerador do Windows Sandbox: .wsb valido, rede desativada, release somente leitura; nada e iniciado' {
        $tools = Join-Path (Split-Path -Parent $testsDir) 'tools\clean-env'
        foreach ($f in @('New-CleanEnvSandbox.ps1', 'Invoke-CleanEnvTest.ps1')) { $tk = $null; $e = $null; [void][Management.Automation.Language.Parser]::ParseFile((Join-Path $tools $f), [ref]$tk, [ref]$e); Assert-Eq $e.Count 0 "$f sintaxe" }
        $rel = Join-Path $sandbox 'fake release & co'; [void][IO.Directory]::CreateDirectory($rel)
        $out = Join-Path $sandbox 'clean-env-out'
        & (Join-Path $tools 'New-CleanEnvSandbox.ps1') -ReleaseDir $rel -OutDir $out 6>$null
        $x = [xml][IO.File]::ReadAllText((Join-Path $out 'agent-temp-clean-env.wsb'))
        Assert-Eq $x.Configuration.Networking 'Disable' 'sem rede'
        $mf = @($x.Configuration.MappedFolders.MappedFolder)
        Assert-Eq $mf.Count 3 'tres pastas'
        Assert-True (@($mf | Where-Object { $_.SandboxFolder -eq 'C:\atm\release' -and $_.ReadOnly -eq 'true' -and $_.HostFolder -eq $rel }).Count -eq 1) 'release somente leitura (caminho com & preservado)'
        Assert-True ($x.Configuration.LogonCommand.Command -match 'Invoke-CleanEnvTest\.ps1') 'comando de logon'
        $txt = [IO.File]::ReadAllText((Join-Path $tools 'Invoke-CleanEnvTest.ps1'))
        Assert-True (-not ($txt -match 'Remove-Item|DeleteTree|Temp\\claude')) 'roteiro nao exclui temporarios'
        Assert-True ($txt -match "install\\Install-AgentTempManager\.ps1'\) \*>") 'instala sem -ProjectsFile'
    }

    # ------------------------------------------------------------------ V0.2 diagnose: model, identity, layering
    Test-Case 'Diagnose' 'Modelo: cobertura, evidencia e achado validam codigos e listas fechadas' {
        $c = New-AtmCoverage -Collector 'processes' -Status 'PARTIAL' -Reasons @('OTHER_ACCOUNT') -ElevationWouldHelp 'YES' -Observed 3 -Expected 5
        Assert-Eq $c.Status 'PARTIAL' 'status'
        Assert-Eq $c.Observed 3 'observados'
        $bad = @(
            { New-AtmCoverage -Collector 'Processes' -Status 'COMPLETE' },
            { New-AtmCoverage -Collector 'processes' -Status 'CLEAN' },
            { New-AtmCoverage -Collector 'processes' -Status 'DENIED' },
            { New-AtmCoverage -Collector 'processes' -Status 'DENIED' -Reasons @('access denied') },
            { New-AtmCoverage -Collector 'processes' -Status 'COMPLETE' -ElevationWouldHelp 'MAYBE' },
            { New-AtmCoverage -Collector 'processes' -Status 'complete' },
            { New-AtmCoverage -Collector 'processes' -Status 'COMPLETE' -ElevationWouldHelp 'yes' },
            { New-AtmFinding -Kind 'tempPartition' -Key 'x' -State 'UNKNOWN' },
            { New-AtmEvidence -Code 'bad code' -Source 'audit' -Collector 'inventory' },
            { New-AtmEvidence -Code 'AUDIT_FLAG' -Source 'Audit' -Collector 'inventory' },
            { New-AtmFinding -Kind 'File' -Key 'x' -State 'UNKNOWN' },
            { New-AtmFinding -Kind 'TempPartition' -Key '' -State 'UNKNOWN' },
            { New-AtmFinding -Kind 'TempPartition' -Key 'x' -State 'not a code' },
            { New-AtmFinding -Kind 'TempPartition' -Key 'x' -State 'UNKNOWN' -Coverage @('COMPLETE') })
        foreach ($b in $bad) {
            $threw = $false; try { $null = & $b } catch { $threw = $true }
            Assert-True $threw "recusado: $b"
        }
        $e = New-AtmEvidence -Code 'AUDIT_FLAG' -Source 'audit' -Collector 'inventory' -Detail (('x' * 600) + "`r`nlinha")
        Assert-True ($e.Detail.Length -le 512 -and $e.Detail -notmatch "[`r`n]") 'detalhe limitado e sem quebras de linha'
        Assert-Eq $e.ObservedUtc.Kind ([DateTimeKind]::Utc) 'horario em UTC'
        Assert-Eq (ConvertTo-AtmExceptionCode 'System.UnauthorizedAccessException') 'EXCEPTION_SYSTEMUNAUTHORIZEDACCESSEXCEPTION' 'codigo de excecao'
    }
    Test-Case 'Diagnose' 'Ausencia de evidencia nunca vira "sem dependencia": UNKNOWN sem cobertura conclusiva' {
        # Every kind that allows a "no dependency" state, with every coverage status (T-1).
        $exercised = @{}
        foreach ($kind in $script:AtmFindingKinds) {
            foreach ($state in @($script:AtmFindingStates[$kind] | Where-Object { $script:AtmNoDependencyStates -ccontains $_ })) {
                $exercised[$state] = $true
                foreach ($st in $script:AtmCoverageStatuses) {
                    $conclusive = $script:AtmConclusiveCoverage -ccontains $st
                    $reasons = $(if ($conclusive) { @() } else { @('TEST_REASON') })
                    $cov = @((New-AtmCoverage -Collector 'identity' -Status 'COMPLETE'), (New-AtmCoverage -Collector 'processes' -Status $st -Reasons $reasons))
                    $f = New-AtmFinding -Kind $kind -Key 'k' -State $state -Coverage $cov
                    Assert-Eq $f.State $(if ($conclusive) { $state } else { 'UNKNOWN' }) "$kind/$state com cobertura $st"
                    Assert-Eq $f.RequestedState $state 'estado pedido preservado'
                    if (-not $conclusive) { Assert-Eq (@($f.IncompleteCoverage) -join ',') 'processes' 'coletor incompleto listado' }
                }
                Assert-Eq (New-AtmFinding -Kind $kind -Key 'k' -State $state).State 'UNKNOWN' "$kind/$state sem nenhuma cobertura"
            }
        }
        foreach ($state in $script:AtmNoDependencyStates) { Assert-True $exercised.ContainsKey($state) "$state exercitado em algum tipo" }
        $f = New-AtmFinding -Kind 'TempPartition' -Key 'k' -State 'IN_USE' -Coverage @(New-AtmCoverage -Collector 'processes' -Status 'DENIED' -Reasons @('ACCESS_DENIED'))
        Assert-Eq $f.State 'IN_USE' 'evidencia positiva nao depende de cobertura completa'
    }
    Test-Case 'Diagnose' 'Estados fechados por tipo de achado (T-1): tabela coerente; desconhecido, de outro tipo ou em minusculas recusado; cobertura malformada recusada' {
        Assert-Eq (@($script:AtmFindingStates.Keys | Sort-Object) -join ',') (@($script:AtmFindingKinds | Sort-Object) -join ',') 'um item da tabela por tipo'
        $all = @{}
        foreach ($kind in $script:AtmFindingKinds) {
            $states = @($script:AtmFindingStates[$kind])
            Assert-True ($states -ccontains 'UNKNOWN') "$kind aceita UNKNOWN (destino do bloqueio)"
            foreach ($s in $states) { Assert-True ($s -cmatch $script:AtmCodePattern) "$kind/$s e um codigo"; $all[$s] = $true }
        }
        foreach ($s in $script:AtmNoDependencyStates) { Assert-True $all.ContainsKey($s) "$s pertence a algum tipo" }
        $cov = @(New-AtmCoverage -Collector 'processes' -Status 'COMPLETE')
        $refused = 0
        foreach ($kind in $script:AtmFindingKinds) {
            $own = @($script:AtmFindingStates[$kind])
            foreach ($s in $own) { Assert-Eq (New-AtmFinding -Kind $kind -Key 'k' -State $s -Coverage $cov).RequestedState $s "$kind aceita $s" }
            $other = @($all.Keys | Where-Object { $own -cnotcontains $_ })
            $bad = @($other) + @('CLEAN', 'FREE', 'UNUSED', 'DISPOSABLE', 'NOT_RUNNING') + @($own | ForEach-Object { $_.ToLowerInvariant() })
            foreach ($s in $bad) {
                $threw = $false; try { $null = New-AtmFinding -Kind $kind -Key 'k' -State $s -Coverage $cov } catch { $threw = $true }
                Assert-True $threw "$kind recusa $s"
                $refused++
            }
        }
        Assert-True ($refused -gt 40) "combinacoes negativas exercitadas: $refused"
        $badCov = @(
            [pscustomobject]@{ Status = 'COMPLETE' },
            [pscustomobject]@{ Collector = 'processes' },
            [pscustomobject]@{ Collector = 'processes'; Status = 'complete' },
            [pscustomobject]@{ Collector = 'processes'; Status = 'CLEAN' },
            [pscustomobject]@{ Collector = 'processes'; Status = $null },
            [pscustomobject]@{ Collector = 'Processes'; Status = 'COMPLETE' },
            [pscustomobject]@{ Collector = ''; Status = 'COMPLETE' },
            'COMPLETE')
        foreach ($state in @('IN_USE', 'NO_DEPENDENCY_OBSERVED', 'RUNTIME_NOT_DIAGNOSED')) {
            foreach ($c in $badCov) {
                $threw = $false; try { $null = New-AtmFinding -Kind 'TempPartition' -Key 'k' -State $state -Coverage @($c) } catch { $threw = $true }
                Assert-True $threw "cobertura malformada recusada ($state): $($c | Out-String)"
            }
        }
    }
    Test-Case 'Diagnose' 'Identidade: tipo de elevacao, integridade e falhas de leitura (fontes injetadas)' {
        $cases = @(
            @(1, 0x2000, $false, 'DEFAULT', 'MEDIUM'), @(2, 0x3000, $true, 'FULL', 'HIGH'), @(3, 0x2000, $false, 'LIMITED', 'MEDIUM'),
            @(1, 0x4000, $true, 'DEFAULT', 'SYSTEM'), @(3, 0x1000, $false, 'LIMITED', 'LOW'), @(1, 0x2100, $false, 'DEFAULT', 'MEDIUM_PLUS'),
            @(1, 0, $false, 'DEFAULT', 'UNTRUSTED'), @(1, 0x5000, $false, 'DEFAULT', 'PROTECTED'))
        foreach ($c in $cases) {
            $raw = [pscustomobject]@{ Name = 'TEST\alice'; Sid = 'S-1-5-21-1-2-3-1001'; IsAdmin = $c[2]; ElevationTypeRaw = $c[0]; IntegrityRid = $c[1]; SessionId = 1 }
            $s = Get-AtmIdentityState -Source ({ $raw }.GetNewClosure())
            Assert-Eq $s.ElevationType $c[3] "tipo $($c[0])"
            Assert-Eq $s.IntegrityLevel $c[4] "integridade $($c[1])"
            Assert-Eq $s.IsElevatedAdministrator $c[2] 'administrador elevado'
            Assert-Eq $s.Coverage.Status 'COMPLETE' 'cobertura completa'
            Assert-Eq $s.Coverage.ElevationWouldHelp 'NO' 'elevacao nao muda a leitura do proprio token'
        }
        $s = Get-AtmIdentityState -Source { [pscustomobject]@{ Name = 'TEST\alice'; Sid = 'S-1-5-21-1-2-3-1001'; IsAdmin = $false; ElevationTypeRaw = 0; IntegrityRid = -1; SessionId = 1 } }
        Assert-Eq $s.Coverage.Status 'PARTIAL' 'token ilegivel -> parcial'
        Assert-Eq (@($s.Coverage.Reasons) -join ',') 'TOKEN_ELEVATION_TYPE_UNREADABLE,TOKEN_INTEGRITY_UNREADABLE' 'motivos'
        Assert-Eq $s.ElevationType 'UNKNOWN' 'tipo desconhecido'
        $s = Get-AtmIdentityState -Source { throw (New-Object UnauthorizedAccessException('texto-que-nao-pode-aparecer')) }
        Assert-Eq $s.Coverage.Status 'FAILED' 'falha de leitura'
        Assert-Eq (@($s.Coverage.Reasons) -join ',') 'IDENTITY_UNREADABLE,EXCEPTION_UNAUTHORIZEDACCESSEXCEPTION' 'codigo do tipo da excecao, nunca a mensagem'
        Assert-True ($null -eq $s.Name -and $s.IntegrityLevel -eq 'UNKNOWN') 'nada inventado'
    }
    Test-Case 'Diagnose' 'Identidade real do processo (somente leitura): token consistente e igual a identidade da V0.1' {
        $s = Get-AtmIdentityState
        Assert-Eq $s.Sid $me.Sid 'SID'
        Assert-Eq $s.Name $me.Name 'nome'
        Assert-Eq $s.IsElevatedAdministrator $me.IsAdmin 'administrador elevado'
        Assert-Eq $s.Coverage.Status 'COMPLETE' 'token legivel'
        Assert-True ($s.ElevationType -ne 'UNKNOWN' -and $s.IntegrityLevel -ne 'UNKNOWN') 'tipo e integridade lidos'
        if ($s.IsElevatedAdministrator) { Assert-True (@('FULL', 'DEFAULT') -contains $s.ElevationType -and @('HIGH', 'SYSTEM') -contains $s.IntegrityLevel) "administrador elevado: $($s.ElevationType)/$($s.IntegrityLevel)" }
        if ($s.ElevationType -eq 'LIMITED') { Assert-True ((-not $s.IsElevatedAdministrator) -and @('LOW', 'MEDIUM', 'MEDIUM_PLUS') -contains $s.IntegrityLevel) 'token filtrado' }
        if ($s.ElevationType -eq 'FULL') { Assert-True (@('HIGH', 'SYSTEM') -contains $s.IntegrityLevel) 'token completo' }
        Assert-Eq $s.SessionId ([Diagnostics.Process]::GetCurrentProcess().SessionId) 'sessao'
        $script:caseNote = "$($s.ElevationType)/$($s.IntegrityLevel)"
    }
    Test-Case 'Diagnose' 'Processos (P1-B1): identidade pid@creationTicksUtc; linha invalida, PID duplicado, horario ausente/ilegivel/futuro e limite de linhas nunca viram identidade verificada' {
        $t0 = New-Object DateTime(2026, 1, 1, 8, 0, 0, [DateTimeKind]::Utc)
        $k = ConvertTo-AtmProcessKey -ProcessId 4321 -CreationUtc $t0
        Assert-Eq $k ('4321@' + $t0.Ticks) 'formato da chave'
        $back = ConvertFrom-AtmProcessKey $k
        Assert-True ($back.ProcessId -eq 4321 -and $back.CreationUtc -eq $t0 -and $back.CreationUtc.Kind -eq [DateTimeKind]::Utc) 'ida e volta da chave'
        Assert-Eq (ConvertTo-AtmProcessKey -ProcessId 0 -CreationUtc $t0) ('0@' + $t0.Ticks) 'PID 0'
        Assert-True ($null -eq (ConvertTo-AtmProcessKey -ProcessId 7 -CreationUtc $null)) 'sem horario de criacao, sem chave'
        foreach ($bad in @('', '4321', '4321@', '@1', '-1@5', '4321@-5', '4321@1.5', '4321 @5', '4294967296@5', ('1@' + ('9' * 19)), '4321@5x', '4321@5@6')) {
            Assert-True ($null -eq (ConvertFrom-AtmProcessKey $bad)) "chave invalida: '$bad'"
        }
        $rows = @(
            [pscustomobject]@{ ProcessId = 0; ParentProcessId = 0; Name = 'System Idle Process'; CreationDate = $t0 },
            [pscustomobject]@{ ProcessId = 4; ParentProcessId = 0; Name = 'System'; CreationDate = $t0 },
            @{ ProcessId = [uint32]100; ParentProcessId = 4; Name = 'app.exe'; CreationDate = '2026-01-01T09:00:00.1234567Z' },
            [pscustomobject]@{ ProcessId = 200; ParentProcessId = 100; Name = 'tool.exe'; CreationDate = $null },
            [pscustomobject]@{ ProcessId = 201; ParentProcessId = 100; Name = 'late.exe'; CreationDate = [datetime]::UtcNow.AddDays(3) },
            [pscustomobject]@{ ProcessId = 202; ParentProcessId = 100; Name = 'old.exe'; CreationDate = '1999-12-31T00:00:00Z' },
            [pscustomobject]@{ ProcessId = 203; ParentProcessId = 100; Name = 'garbled.exe'; CreationDate = 'yesterday' },
            [pscustomobject]@{ ProcessId = 300; ParentProcessId = 4; Name = 'first.exe'; CreationDate = $t0.AddMinutes(1) },
            [pscustomobject]@{ ProcessId = 300; ParentProcessId = 4; Name = 'second.exe'; CreationDate = $t0.AddMinutes(2) },
            [pscustomobject]@{ ProcessId = 400; ParentProcessId = 'x'; Name = "bad`nname.exe"; CreationDate = $t0 },
            [pscustomobject]@{ ProcessId = -1; ParentProcessId = 4; Name = 'negative.exe'; CreationDate = $t0 },
            [pscustomobject]@{ ProcessId = '12a'; ParentProcessId = 4; Name = 'text.exe'; CreationDate = $t0 },
            [pscustomobject]@{ ProcessId = 1.5; ParentProcessId = 4; Name = 'fraction.exe'; CreationDate = $t0 },
            [pscustomobject]@{ ProcessId = $true; ParentProcessId = 4; Name = 'bool.exe'; CreationDate = $t0 },
            [pscustomobject]@{ ProcessId = 4294967296; ParentProcessId = 4; Name = 'big.exe'; CreationDate = $t0 },
            [pscustomobject]@{ ParentProcessId = 4; Name = 'noid.exe'; CreationDate = $t0 },
            'not a row')
        $c = Get-AtmProcessCollection -Source ({ $rows }.GetNewClosure())
        Assert-Eq $c.Coverage.Collector 'process-snapshot' 'coletor'
        Assert-Eq $c.Coverage.Status 'PARTIAL' 'linhas com problemas -> parcial'
        Assert-Eq (@($c.Coverage.Reasons | Sort-Object) -join ',') 'CREATION_TIME_UNREADABLE,DUPLICATE_PID,MALFORMED_PROCESS_RECORDS,PARENT_ID_UNREADABLE,PROCESS_NAME_UNREADABLE' 'motivos'
        Assert-Eq $c.Coverage.ElevationWouldHelp 'UNKNOWN' 'elevacao: desconhecido'
        Assert-Eq $c.Coverage.Expected $rows.Count 'linhas recebidas'
        Assert-Eq $c.Coverage.Observed 4 'identidades verificadas'
        Assert-Eq $c.Coverage.BudgetMs 30000 'orcamento declarado'
        Assert-Eq (@($c.Processes).Count) 10 'linhas sem PID valido descartadas'
        foreach ($p in $c.Processes) {
            Assert-Eq (@($p.PSObject.Properties.Name) -join ',') 'Pid,ParentPid,Name,CreationUtc,Key,IdentityStatus,Resources' "propriedades de $($p.Pid)"
            Assert-True ($script:AtmProcessIdentityStatuses -ccontains $p.IdentityStatus) "estado de identidade fechado: $($p.IdentityStatus)"
            Assert-Eq ($null -ne $p.Key) ($p.IdentityStatus -ceq 'VERIFIED') "so identidade verificada tem chave ($($p.Pid))"
        }
        foreach ($id in @(0, 4, 100, 400)) { Assert-Eq $c.ByPid[[long]$id].IdentityStatus 'VERIFIED' "PID $id verificado" }
        Assert-Eq $c.ByPid[[long]100].CreationUtc.Ticks ([datetime]::Parse('2026-01-01T09:00:00.1234567Z', [Globalization.CultureInfo]::InvariantCulture).ToUniversalTime().Ticks) 'horario ISO preciso ao tick'
        Assert-Eq $c.ByPid[[long]100].Key ('100@' + $c.ByPid[[long]100].CreationUtc.Ticks) 'chave do PID 100'
        Assert-True ($null -eq $c.ByPid[[long]400].Name -and $null -eq $c.ByPid[[long]400].ParentPid) 'nome e pai ilegiveis ficam nulos'
        foreach ($id in @(200, 201, 202, 203)) {
            Assert-Eq $c.ByPid[[long]$id].IdentityStatus 'CREATION_TIME_UNKNOWN' "PID $id sem horario confiavel"
            Assert-True ($null -eq $c.ByPid[[long]$id].CreationUtc) "PID $id sem horario inventado"
        }
        Assert-True (-not $c.ByPid.ContainsKey([long]300)) 'PID duplicado fora do indice'
        Assert-Eq (@($c.Processes | Where-Object { $_.IdentityStatus -eq 'DUPLICATE_PID' }).Count) 2 'as duas linhas do PID duplicado marcadas'
        $ok = @($rows[0], $rows[1], $rows[2])
        $c = Get-AtmProcessCollection -Source ({ $ok }.GetNewClosure())
        Assert-True ($c.Coverage.Status -eq 'COMPLETE' -and @($c.Coverage.Reasons).Count -eq 0 -and $c.Coverage.ElevationWouldHelp -eq 'NO') 'linhas validas -> completa'
        Assert-True ($c.Coverage.Observed -eq 3 -and $c.Coverage.Expected -eq 3) 'contagens'
        $many = @(1..5 | ForEach-Object { [pscustomobject]@{ ProcessId = 1000 + $_; ParentProcessId = 4; Name = 'n.exe'; CreationDate = $t0.AddSeconds($_) } })
        $c = Get-AtmProcessCollection -Source ({ $many }.GetNewClosure()) -MaxRecords 3
        Assert-Eq $c.Coverage.Status 'PARTIAL' 'acima do limite -> parcial'
        Assert-Eq (@($c.Coverage.Reasons) -join ',') 'PROCESS_LIMIT_EXCEEDED' 'motivo do limite'
        Assert-True (@($c.Processes).Count -eq 3 -and $c.Coverage.Expected -eq 5 -and $c.Coverage.Observed -eq 3) 'linhas alem do limite nao lidas'
        foreach ($b in @({ Get-AtmProcessCollection -Source { $ok } -MaxRecords 0 }, { Get-AtmProcessCollection -Source { $ok } -TimeoutSec 0 })) {
            $threw = $false; try { $null = & $b } catch { $threw = $true }
            Assert-True $threw "parametro recusado: $b"
        }
    }
    Test-Case 'Diagnose' 'Processos (P1-B1): referencia por PID e horario de criacao; PID reutilizado; NOT_FOUND so com coleta completa; tolerancia limitada' {
        $t0 = New-Object DateTime(2026, 1, 1, 8, 0, 0, [DateTimeKind]::Utc)
        $t1 = $t0.AddHours(1)
        $base = @(
            [pscustomobject]@{ ProcessId = 4; ParentProcessId = 0; Name = 'System'; CreationDate = $t0 },
            [pscustomobject]@{ ProcessId = 100; ParentProcessId = 4; Name = 'app.exe'; CreationDate = $t1 })
        $full = Get-AtmProcessCollection -Source ({ $base }.GetNewClosure())
        Assert-Eq $full.Coverage.Status 'COMPLETE' 'coleta completa'
        $cases = @(
            @(100, $t1, 0, 'MATCH'), @('100', $t1, 0, 'MATCH'), @([int]100, $t1.ToString('o'), 0, 'MATCH'),
            @(100, $t1.AddTicks(1), 0, 'PID_REUSED'), @(100, $t1.AddMilliseconds(1), 1, 'MATCH'), @(100, $t1.AddMilliseconds(2), 1, 'PID_REUSED'),
            @(100, $t1.AddMilliseconds(-2000), 2000, 'MATCH'), @(100, $t0, 0, 'PID_REUSED'), @(100, $t1.AddDays(-1), 2000, 'PID_REUSED'),
            @(100, $null, 0, 'IDENTITY_UNVERIFIED'), @(100, 'garbage', 0, 'IDENTITY_UNVERIFIED'), @(100, [datetime]::UtcNow.AddDays(5), 0, 'IDENTITY_UNVERIFIED'),
            @(999, $t1, 0, 'NOT_FOUND'), @(-1, $t1, 0, 'IDENTITY_UNVERIFIED'), @('abc', $t1, 0, 'IDENTITY_UNVERIFIED'), @($null, $t1, 0, 'IDENTITY_UNVERIFIED'))
        foreach ($cs in $cases) {
            $r = Resolve-AtmProcessReference -Collection $full -ProcessId $cs[0] -CreationUtc $cs[1] -ToleranceMs $cs[2]
            Assert-Eq $r.Result $cs[3] "PID '$($cs[0])', horario '$($cs[1])', tolerancia $($cs[2])"
            Assert-True ($script:AtmProcessReferenceResults -ccontains $r.Result) 'resultado da lista fechada'
            Assert-Eq ($null -ne $r.Process) (@('MATCH', 'PID_REUSED') -ccontains $r.Result -or ($r.Result -eq 'IDENTITY_UNVERIFIED' -and $cs[0] -eq 100)) "processo devolvido so quando o PID foi coletado ($($cs[0]))"
        }
        $partial = Get-AtmProcessCollection -Source ({ @($base) + @([pscustomobject]@{ ProcessId = 'x'; CreationDate = $t0 }) }.GetNewClosure())
        Assert-Eq $partial.Coverage.Status 'PARTIAL' 'coleta parcial'
        Assert-Eq (Resolve-AtmProcessReference -Collection $partial -ProcessId 999 -CreationUtc $t1).Result 'IDENTITY_UNVERIFIED' 'ausente em coleta parcial nao e NOT_FOUND'
        Assert-Eq (Resolve-AtmProcessReference -Collection $partial -ProcessId 100 -CreationUtc $t1).Result 'MATCH' 'presente em coleta parcial ainda casa'
        $odd = Get-AtmProcessCollection -Source ({ @($base) + @([pscustomobject]@{ ProcessId = 300; ParentProcessId = 4; Name = 'a.exe'; CreationDate = $t0 }, [pscustomobject]@{ ProcessId = 300; ParentProcessId = 4; Name = 'b.exe'; CreationDate = $t1 }, [pscustomobject]@{ ProcessId = 200; ParentProcessId = 4; Name = 'c.exe'; CreationDate = $null }) }.GetNewClosure())
        Assert-True ($odd.Coverage.Status -eq 'PARTIAL' -and $odd.ByPid[[long]200].IdentityStatus -eq 'CREATION_TIME_UNKNOWN' -and $odd.Duplicates.ContainsKey([long]300)) 'coleta lida (nao falha): duplicado e sem horario'
        foreach ($t in @($t0, $t1)) { Assert-Eq (Resolve-AtmProcessReference -Collection $odd -ProcessId 300 -CreationUtc $t).Result 'IDENTITY_UNVERIFIED' 'PID duplicado nunca casa' }
        Assert-Eq (Resolve-AtmProcessReference -Collection $odd -ProcessId 200 -CreationUtc $t0).Result 'IDENTITY_UNVERIFIED' 'PID coletado sem horario nao casa'
        Assert-Eq (Resolve-AtmProcessReference -Collection $null -ProcessId 100 -CreationUtc $t1).Result 'IDENTITY_UNVERIFIED' 'sem coleta'
        foreach ($tol in @(-1, 2001)) {
            $threw = $false; try { $null = Resolve-AtmProcessReference -Collection $full -ProcessId 100 -CreationUtc $t1 -ToleranceMs $tol } catch { $threw = $true }
            Assert-True $threw "tolerancia $tol recusada"
        }
        # Reference results and identity statuses are not finding states (T-1); IDENTITY_UNVERIFIED is also a Process state
        # since P1-B4-b (a candidate without a verified identity), with its own tests.
        foreach ($s in @(@($script:AtmProcessReferenceResults) + @($script:AtmProcessIdentityStatuses) | Where-Object { $_ -cne 'IDENTITY_UNVERIFIED' })) {
            $threw = $false; try { $null = New-AtmFinding -Kind 'Process' -Key 'k' -State $s -Coverage @($full.Coverage) } catch { $threw = $true }
            Assert-True $threw "$s nao e estado de achado"
        }
    }
    Test-Case 'Diagnose' 'Processos (P1-B1): falha, resposta vazia, tempo esgotado e prazo nunca viram "nenhum processo"; excecao so pelo tipo' {
        $t0 = New-Object DateTime(2026, 1, 1, 8, 0, 0, [DateTimeKind]::Utc)
        $flag = @{ Called = $false }
        $cases = @(
            @{ Name = 'excecao'; Args = @{ Source = { throw (New-Object UnauthorizedAccessException('texto-que-nao-pode-aparecer')) } }; Status = 'FAILED'; Reasons = 'PROCESS_SNAPSHOT_FAILED,EXCEPTION_UNAUTHORIZEDACCESSEXCEPTION' },
            @{ Name = 'nulo'; Args = @{ Source = { $null } }; Status = 'FAILED'; Reasons = 'PROCESS_SNAPSHOT_EMPTY' },
            @{ Name = 'vazio'; Args = @{ Source = { @() } }; Status = 'FAILED'; Reasons = 'PROCESS_SNAPSHOT_EMPTY' },
            @{ Name = 'so nulos'; Args = @{ Source = { @($null, $null) } }; Status = 'FAILED'; Reasons = 'PROCESS_SNAPSHOT_EMPTY' },
            @{ Name = 'tempo esgotado'; Args = @{ TimeoutSec = 1; Source = { Start-Sleep -Milliseconds 1100; throw (New-Object TimeoutException('texto-que-nao-pode-aparecer')) } }; Status = 'TIMEOUT'; Reasons = 'PROCESS_SNAPSHOT_TIMEOUT,EXCEPTION_TIMEOUTEXCEPTION' },
            @{ Name = 'prazo'; Args = @{ Deadline = [datetime]::UtcNow; Source = ({ $flag.Called = $true; @([pscustomobject]@{ ProcessId = 4; ParentProcessId = 0; Name = 'System'; CreationDate = $t0 }) }.GetNewClosure()) }; Status = 'TIMEOUT'; Reasons = 'DEADLINE_EXCEEDED' })
        foreach ($cs in $cases) {
            $a = $cs.Args
            $c = Get-AtmProcessCollection @a
            Assert-Eq $c.Coverage.Status $cs.Status "$($cs.Name): status"
            Assert-Eq (@($c.Coverage.Reasons) -join ',') $cs.Reasons "$($cs.Name): motivos"
            Assert-True ($c.Failed -and @($c.Processes).Count -eq 0 -and $c.ByPid.Count -eq 0) "$($cs.Name): nada inventado"
            Assert-True (-not ($c | ConvertTo-Json -Depth 6).Contains('texto-que-nao-pode-aparecer')) "$($cs.Name): mensagem da excecao nunca guardada"
            foreach ($id in @(4, 999)) { Assert-Eq (Resolve-AtmProcessReference -Collection $c -ProcessId $id -CreationUtc $t0).Result 'IDENTITY_UNVERIFIED' "$($cs.Name): PID $id nao verificavel, nunca NOT_FOUND" }
        }
        Assert-True (-not $flag.Called) 'prazo esgotado: a fonte nem e chamada'
    }
    Test-Case 'Diagnose' 'Processos reais (somente leitura, P1-B1): o proprio processo identificado por PID e horario de criacao; sem linha de comando nem caminho' {
        Assert-Eq ($script:AtmProcessCimProperties -join ',') 'ProcessId,ParentProcessId,Name,CreationDate,KernelModeTime,UserModeTime,WorkingSetSize,PrivatePageCount,HandleCount,ReadTransferCount,WriteTransferCount,OtherTransferCount' 'propriedades pedidas ao CIM'
        $fn = ${function:Get-AtmProcessRaw}.ToString()
        foreach ($pat in @('CommandLine', 'ExecutablePath', 'Get-Process', 'Invoke-CimMethod')) { Assert-True (-not $fn.Contains($pat)) "coletor bruto contem '$pat'" }
        $c = Get-AtmProcessCollection
        Assert-True (@('COMPLETE', 'PARTIAL') -ccontains $c.Coverage.Status) "coleta real: $($c.Coverage.Status) $(@($c.Coverage.Reasons) -join ',')"
        Assert-True ($c.Coverage.Observed -gt 0 -and $c.Coverage.ElapsedMs -le $c.Coverage.BudgetMs) 'processos observados dentro do orcamento'
        foreach ($p in $c.Processes) { Assert-Eq (@($p.PSObject.Properties.Name) -join ',') 'Pid,ParentPid,Name,CreationUtc,Key,IdentityStatus,Resources' 'nenhuma outra propriedade guardada'; Assert-Eq (@($p.Resources.PSObject.Properties.Name) -join ',') 'KernelTime100ns,UserTime100ns,WorkingSetBytes,PrivateBytes,HandleCount,ReadTransferBytes,WriteTransferBytes,OtherTransferBytes' 'contadores guardados' }
        $self = [Diagnostics.Process]::GetCurrentProcess()
        # Process.StartTime (100 ns) and CIM CreationDate (1 us) are different sources: a bounded tolerance.
        $r = Resolve-AtmProcessReference -Collection $c -ProcessId $self.Id -CreationUtc $self.StartTime.ToUniversalTime() -ToleranceMs 1000
        Assert-Eq $r.Result 'MATCH' 'proprio processo identificado'
        Assert-Eq $r.Process.Key (ConvertTo-AtmProcessKey -ProcessId $self.Id -CreationUtc $r.Process.CreationUtc) 'chave pid@creationTicksUtc'
        Assert-Eq (Resolve-AtmProcessReference -Collection $c -ProcessId $self.Id -CreationUtc $self.StartTime.ToUniversalTime().AddMinutes(-10) -ToleranceMs 1000).Result 'PID_REUSED' 'mesmo PID com outro horario nunca e o mesmo processo'
        $script:caseNote = "$($c.Coverage.Status), $($c.Coverage.Observed)/$($c.Coverage.Expected), $($c.Coverage.ElapsedMs) ms"
    }
    Test-Case 'Diagnose' 'Arvores de processos (P1-B2): vinculo com pai so verificado por identidade e horario; PID reutilizado e pai encerrado cortam a cadeia; limites e ciclos' {
        $t0 = New-Object DateTime(2026, 1, 1, 8, 0, 0, [DateTimeKind]::Utc)
        function New-Row { param($Id, $Parent, $Created) [pscustomobject]@{ ProcessId = $Id; ParentProcessId = $Parent; Name = "p$Id.exe"; CreationDate = $Created } }
        $rows = @((New-Row 0 0 $t0), (New-Row 4 0 $t0), (New-Row 100 4 $t0.AddMinutes(1)), (New-Row 110 100 $t0.AddMinutes(2)), (New-Row 120 100 $t0.AddMinutes(2)),
            (New-Row 111 110 $t0.AddMinutes(3)), (New-Row 200 999 $t0.AddMinutes(5)), (New-Row 300 100 $t0.AddSeconds(30)))
        $c = Get-AtmProcessCollection -Source ({ $rows }.GetNewClosure())
        Assert-Eq $c.Coverage.Status 'COMPLETE' 'coleta completa'
        $expect = @{ 0 = 'ROOT'; 4 = 'VERIFIED'; 100 = 'VERIFIED'; 110 = 'VERIFIED'; 111 = 'VERIFIED'; 120 = 'VERIFIED'; 200 = 'PARENT_EXITED_OR_REUSED'; 300 = 'PARENT_EXITED_OR_REUSED' }
        foreach ($id in $expect.Keys) {
            $l = Get-AtmProcessParentLink -Collection $c -Process $c.ByPid[[long]$id]
            Assert-Eq $l.Result $expect[$id] "vinculo do PID $id"
            Assert-Eq ($null -ne $l.Parent) ($l.Result -ceq 'VERIFIED') "pai devolvido so quando verificado ($id)"
            Assert-True ($script:AtmParentLinkResults -ccontains $l.Result) 'resultado da lista fechada'
        }
        $k = { param($id) $c.ByPid[[long]$id].Key }
        $tr = Get-AtmProcessTree -Collection $c -RootKey (& $k 100)
        Assert-Eq ($tr.Members -join ',') ((@(100, 110, 120, 111) | ForEach-Object { & $k $_ }) -join ',') 'descendentes verificados, raiz primeiro, em largura'
        Assert-True ($tr.Complete -and @($tr.Reasons).Count -eq 0) 'arvore completa'
        Assert-True ($tr.Members -cnotcontains (& $k 300)) 'processo mais antigo que o "pai" nao e descendente (PID do pai reutilizado)'
        Assert-Eq (@((Get-AtmProcessTree -Collection $c -RootKey (& $k 4)).Members).Count) 5 'arvore a partir do System'
        foreach ($bad in @(('100@' + $t0.Ticks), '100', '', 'x@y', ('999@' + $t0.Ticks))) {
            $t = Get-AtmProcessTree -Collection $c -RootKey $bad
            Assert-True (-not $t.Complete -and @($t.Members).Count -eq 0 -and (@($t.Reasons) -join ',') -eq 'ROOT_NOT_VERIFIED') "raiz nao verificada: '$bad'"
        }
        $odd = @($rows) + @((New-Row 130 100 $null), (New-Row 140 100 $t0.AddMinutes(4)), (New-Row 140 100 $t0.AddMinutes(6)), (New-Row 150 888 $t0.AddMinutes(4)), [pscustomobject]@{ ProcessId = 'x' })
        $o = Get-AtmProcessCollection -Source ({ $odd }.GetNewClosure())
        Assert-Eq $o.Coverage.Status 'PARTIAL' 'coleta parcial'
        $t = Get-AtmProcessTree -Collection $o -RootKey (& $k 100)
        Assert-Eq (@($t.Reasons | Sort-Object) -join ',') 'COLLECTION_INCOMPLETE,UNVERIFIED_CHILD_LINKS' 'filhos sem horario ou com PID duplicado deixam a arvore incompleta'
        Assert-Eq (@($t.Members).Count) 4 'so membros verificados'
        Assert-Eq (Get-AtmProcessParentLink -Collection $o -Process $o.ByPid[[long]150]).Result 'UNVERIFIED' 'pai ausente em coleta parcial: nao verificado, nunca "encerrado"'
        Assert-Eq (Get-AtmProcessParentLink -Collection $o -Process $o.ByPid[[long]130]).Result 'UNVERIFIED' 'filho sem horario'
        Assert-Eq (Get-AtmProcessParentLink -Collection $o -Process @($o.Processes | Where-Object { $_.Pid -eq 140 })[0]).Result 'UNVERIFIED' 'filho com PID duplicado'
        $dupRows = @((New-Row 4 0 $t0), (New-Row 50 4 $t0), (New-Row 50 4 $t0.AddMinutes(1)), (New-Row 60 50 $t0.AddMinutes(2)))
        $dupParent = Get-AtmProcessCollection -Source ({ $dupRows }.GetNewClosure())
        Assert-Eq $dupParent.ByPid[[long]60].IdentityStatus 'VERIFIED' 'filho do PID duplicado verificado'
        Assert-Eq (Get-AtmProcessParentLink -Collection $dupParent -Process $dupParent.ByPid[[long]60]).Result 'UNVERIFIED' 'pai com PID duplicado'
        Assert-Eq (Get-AtmProcessParentLink -Collection $null -Process $c.ByPid[[long]110]).Result 'UNVERIFIED' 'sem coleta'
        $t = Get-AtmProcessTree -Collection $c -RootKey (& $k 100) -MaxMembers 2
        Assert-True (@($t.Members).Count -eq 2 -and (@($t.Reasons) -join ',') -eq 'TREE_LIMIT_EXCEEDED' -and -not $t.Complete) 'limite de membros'
        $t = Get-AtmProcessTree -Collection $c -RootKey (& $k 100) -MaxDepth 1
        Assert-True (@($t.Members).Count -eq 3 -and (@($t.Reasons) -join ',') -eq 'TREE_LIMIT_EXCEEDED') 'limite de profundidade com mais a ler'
        $t = Get-AtmProcessTree -Collection $c -RootKey (& $k 100) -MaxDepth 2
        Assert-True (@($t.Members).Count -eq 4 -and $t.Complete) 'profundidade suficiente: completa'
        foreach ($b in @({ Get-AtmProcessTree -Collection $c -RootKey 'x' -MaxMembers 0 }, { Get-AtmProcessTree -Collection $c -RootKey 'x' -MaxDepth 0 })) {
            $threw = $false; try { $null = & $b } catch { $threw = $true }
            Assert-True $threw "limite recusado: $b"
        }
        $cycRows = @((New-Row 500 501 $t0), (New-Row 501 500 $t0))
        $cyc = Get-AtmProcessCollection -Source ({ $cycRows }.GetNewClosure())
        Assert-Eq $cyc.Coverage.Status 'COMPLETE' 'coleta do ciclo'
        $t = Get-AtmProcessTree -Collection $cyc -RootKey $cyc.ByPid[[long]500].Key
        Assert-Eq (@($t.Members).Count) 2 'ciclo termina'
        # Scale: 2,000 processes, five levels; linear in the number of processes.
        $big = New-Object System.Collections.Generic.List[object]
        $big.Add((New-Row 10 4 $t0))
        $n = 11
        $lvl = @(10)
        for ($d = 1; $d -le 5; $d++) {
            $nl = @()
            foreach ($par in $lvl) { for ($i = 0; $i -lt 5 -and $n -lt 2010; $i++) { $big.Add((New-Row $n $par $t0.AddMinutes($d))); $nl += $n; $n++ } }
            $lvl = $nl
        }
        while ($n -lt 2010) { $big.Add((New-Row $n 10 $t0.AddMinutes(9))); $n++ }
        $bigArr = $big.ToArray()
        $bc = Get-AtmProcessCollection -Source ({ $bigArr }.GetNewClosure())
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $t = Get-AtmProcessTree -Collection $bc -RootKey $bc.ByPid[[long]10].Key
        $sw.Stop()
        Assert-True ($t.Complete -and @($t.Members).Count -eq 2000) "2.000 membros: $(@($t.Members).Count)"
        Assert-True ($sw.Elapsed.TotalSeconds -lt 30) "tempo limitado: $([int]$sw.Elapsed.TotalMilliseconds) ms"
        $script:caseNote = "2.000 membros em $([int]$sw.Elapsed.TotalMilliseconds) ms"
    }
    Test-Case 'Diagnose' 'Processos encerrados durante a coleta e exclusao do proprio diagnostico (P1-B2): EXITED_DURING_RUN so com prova; SELF so verificado; nada desconhecido e escondido' {
        $t0 = New-Object DateTime(2026, 1, 1, 8, 0, 0, [DateTimeKind]::Utc)
        function New-Row { param($Id, $Parent, $Created) [pscustomobject]@{ ProcessId = $Id; ParentProcessId = $Parent; Name = "p$Id.exe"; CreationDate = $Created } }
        $first = @((New-Row 4 0 $t0), (New-Row 100 4 $t0.AddMinutes(1)), (New-Row 110 100 $t0.AddMinutes(2)), (New-Row 120 100 $t0.AddMinutes(2)), (New-Row 130 100 $null))
        $a = Get-AtmProcessCollection -Source ({ $first }.GetNewClosure())
        $secondRows = @((New-Row 4 0 $t0), (New-Row 100 4 $t0.AddMinutes(1)), (New-Row 120 100 $t0.AddMinutes(7)))
        $b = Get-AtmProcessCollection -Source ({ $secondRows }.GetNewClosure())
        Assert-Eq $b.Coverage.Status 'COMPLETE' 'segunda coleta completa'
        $cmp = Compare-AtmProcessCollections -First $a -Second $b
        Assert-Eq $cmp[$a.ByPid[[long]100].Key] 'PRESENT' 'mesmo processo nas duas coletas'
        Assert-Eq $cmp[$a.ByPid[[long]110].Key] 'EXITED_DURING_RUN' 'ausente de coleta completa'
        Assert-Eq $cmp[$a.ByPid[[long]120].Key] 'EXITED_DURING_RUN' 'PID reutilizado por outro processo'
        Assert-Eq $cmp[$a.ByPid[[long]4].Key] 'PRESENT' 'System presente'
        Assert-Eq $cmp.Count 4 'so identidades verificadas sao comparadas (sem o PID sem horario)'
        foreach ($v in $cmp.Values) { Assert-True ($script:AtmProcessRunStates -ccontains $v) 'estado da lista fechada' }
        $partialRows = @($secondRows) + @([pscustomobject]@{ ProcessId = 'x' }, (New-Row 110 100 $null))
        $p = Get-AtmProcessCollection -Source ({ $partialRows }.GetNewClosure())
        Assert-Eq $p.Coverage.Status 'PARTIAL' 'coleta parcial com PID sem horario'
        $cmp = Compare-AtmProcessCollections -First $a -Second $p
        Assert-Eq $cmp[$a.ByPid[[long]110].Key] 'UNVERIFIED' 'PID presente sem horario: nao verificavel'
        $p2Rows = @((New-Row 4 0 $t0), [pscustomobject]@{ ProcessId = 'x' })
        $p2 = Get-AtmProcessCollection -Source ({ $p2Rows }.GetNewClosure())
        Assert-Eq $p2.Coverage.Status 'PARTIAL' 'segunda coleta parcial'
        $cmp = Compare-AtmProcessCollections -First $a -Second $p2
        Assert-Eq $cmp[$a.ByPid[[long]110].Key] 'UNVERIFIED' 'ausente de coleta parcial: nunca "encerrado"'
        $f = Get-AtmProcessCollection -Source { throw (New-Object InvalidOperationException('x')) }
        $cmp = Compare-AtmProcessCollections -First $a -Second $f
        Assert-True (@($cmp.Values | Where-Object { $_ -ne 'UNVERIFIED' }).Count -eq 0 -and $cmp.Count -eq 4) 'segunda coleta falhou: tudo nao verificado'
        Assert-Eq (Compare-AtmProcessCollections -First $f -Second $a).Count 0 'primeira coleta falhou: nada comparado'

        $selfT = $t0.AddMinutes(3)
        $rows = @((New-Row 4 0 $t0), (New-Row 100 4 $t0.AddMinutes(1)), (New-Row 120 100 $t0.AddMinutes(2)), (New-Row 150 100 $selfT),
            (New-Row 151 150 $t0.AddMinutes(4)), (New-Row 152 151 $t0.AddMinutes(5)), (New-Row 160 150 $t0.AddMinutes(1)))
        $c = Get-AtmProcessCollection -Source ({ $rows }.GetNewClosure())
        Assert-Eq $c.Coverage.Status 'COMPLETE' 'coleta do proprio diagnostico'
        $k = { param($id) $c.ByPid[[long]$id].Key }
        # Launchers come from the V0.1 CIM snapshot (same resolution); this process from Process.StartTime (100 ns,
        # truncated to 1 us before the exact comparison).
        $launcher =[pscustomobject]@{ Pid = 100; CreationUtc = $t0.AddMinutes(1) }
        $s = Get-AtmSelfProcessKeys -Collection $c -SelfPid 150 -SelfCreationUtc $selfT.AddTicks(7) -LauncherReferences @($launcher)
        Assert-Eq (@($s.Keys | Sort-Object) -join ',') (@(100, 150, 151, 152 | ForEach-Object { & $k $_ } | Sort-Object) -join ',') 'proprio processo, filhos verificados e lancador verificado'
        Assert-Eq @($s.Unverified).Count 0 'nada pendente'
        Assert-True ($s.Keys -cnotcontains (& $k 120) -and $s.Keys -cnotcontains (& $k 4)) 'outros filhos do lancador e o sistema nao sao do diagnostico'
        Assert-True ($s.Keys -cnotcontains (& $k 160)) 'processo anterior que so reutiliza o PID nao e filho'
        $refs = @(
            @{ Ref = [pscustomobject]@{ Pid = 120; CreationUtc = $t0.AddMinutes(2) }; Result = 'NOT_AN_ANCESTOR' },
            @{ Ref = [pscustomobject]@{ Pid = 100; CreationUtc = $t0.AddMinutes(9) }; Result = 'PID_REUSED' },
            @{ Ref = @{ Pid = 999; CreationUtc = $t0 }; Result = 'NOT_FOUND' },
            @{ Ref = 'not a reference'; Result = 'IDENTITY_UNVERIFIED' })
        foreach ($r in $refs) {
            $s = Get-AtmSelfProcessKeys -Collection $c -SelfPid 150 -SelfCreationUtc $selfT -LauncherReferences @($r.Ref)
            Assert-Eq (@($s.Unverified | ForEach-Object { $_.Result }) -join ',') $r.Result "lancador: $($r.Result)"
            Assert-Eq (@($s.Keys | Sort-Object) -join ',') (@(150, 151, 152 | ForEach-Object { & $k $_ } | Sort-Object) -join ',') "lancador nao verificado nao e excluido ($($r.Result))"
        }
        Assert-Eq @((Get-AtmSelfProcessKeys -Collection $c -SelfPid 150 -SelfCreationUtc $selfT -LauncherReferences @([pscustomobject]@{ Pid = 150; CreationUtc = $selfT })).Unverified).Count 0 'o proprio processo como lancador e ignorado'
        foreach ($cs in @(@(150, $selfT.AddMinutes(10), 'PID_REUSED'), @(777, $selfT, 'NOT_FOUND'))) {
            $s = Get-AtmSelfProcessKeys -Collection $c -SelfPid $cs[0] -SelfCreationUtc $cs[1] -LauncherReferences @($launcher)
            Assert-True (@($s.Keys).Count -eq 0 -and @($s.Unverified)[0].Result -eq $cs[2]) "proprio processo nao verificado ($($cs[2])): nada excluido"
        }
        # SELF is a Process state since P1-B4-b (Get-AtmAgentRuntimeFindings); link results and run states are not.
        foreach ($st in @($script:AtmParentLinkResults) + @($script:AtmProcessRunStates)) {
            $threw = $false; try { $null = New-AtmFinding -Kind 'Process' -Key 'k' -State $st -Coverage @($c.Coverage) } catch { $threw = $true }
            Assert-True $threw "$st nao e estado de achado (T-1)"
        }
        # Real, read-only: this process is marked SELF only where the CIM resolution is proven on this machine; two
        # collections agree on it.
        $r1 = Get-AtmProcessCollection
        $s = Get-AtmSelfProcessKeys -Collection $r1
        $st = [Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().Ticks
        $mine = Resolve-AtmProcessReference -Collection $r1 -ProcessId $PID -CreationUtc ([Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime()) -ToleranceMs 1000
        Assert-Eq $mine.Result 'MATCH' 'proprio processo coletado'
        $proven = ($mine.Process.CreationUtc.Ticks % 10 -eq 0 -and $mine.Process.CreationUtc.Ticks -eq ($st - ($st % 10)))
        if ($proven) { Assert-True ($s.Keys -ccontains $mine.Process.Key -and @($s.Unverified).Count -eq 0) 'proprio processo real marcado como SELF' }
        else { Assert-True (@($s.Keys).Count -eq 0 -and @($s.Unverified).Count -eq 1) 'precisao nao comprovada: nada marcado como SELF' }
        $r2 = Get-AtmProcessCollection
        Assert-Eq (Compare-AtmProcessCollections -First $r1 -Second $r2)[$mine.Process.Key] 'PRESENT' 'proprio processo presente nas duas coletas reais'
    }
    Test-Case 'Diagnose' 'SELF sem tolerancia (R-B1): igual na precisao do CIM; 1 us de diferenca, PID reutilizado na janela antiga ou referencia aproximada nunca marcam SELF; resolucao incompativel nao verificada' {
        $t0 = New-Object DateTime(2026, 1, 1, 8, 0, 0, [DateTimeKind]::Utc)
        function New-Row { param($Id, $Parent, $Created) [pscustomobject]@{ ProcessId = $Id; ParentProcessId = $Parent; Name = "p$Id.exe"; CreationDate = $Created } }
        $selfT = $t0.AddMinutes(3).AddTicks(1234560)   # on the CIM resolution (1 us = 10 ticks)
        $launchT = $t0.AddMinutes(1)
        $rows = @((New-Row 4 0 $t0), (New-Row 100 4 $launchT), (New-Row 120 100 $t0.AddMinutes(2)), (New-Row 150 100 $selfT), (New-Row 151 150 $t0.AddMinutes(4)))
        $c = Get-AtmProcessCollection -Source ({ $rows }.GetNewClosure())
        Assert-Eq $c.Coverage.Status 'COMPLETE' 'coleta completa'
        $k = { param($id) $c.ByPid[[long]$id].Key }
        $launcher = [pscustomobject]@{ Pid = 100; CreationUtc = $launchT }
        $selfKeys = (@(100, 150, 151 | ForEach-Object { & $k $_ } | Sort-Object) -join ',')
        # Same process: the 100 ns time truncates to the collected microsecond.
        foreach ($ticks in @(0, 1, 9)) {
            $s = Get-AtmSelfProcessKeys -Collection $c -SelfPid 150 -SelfCreationUtc $selfT.AddTicks($ticks) -LauncherReferences @($launcher)
            Assert-Eq (@($s.Keys | Sort-Object) -join ',') $selfKeys "mesmo processo (+$ticks x 100 ns): SELF, filhos e lancador"
            Assert-True ($s.Keys -cnotcontains (& $k 120) -and $s.Keys -cnotcontains (& $k 4) -and @($s.Unverified).Count -eq 0) "irmao do lancador e sistema nao excluidos (+$ticks)"
        }
        # A different microsecond, either side, is another process.
        foreach ($ticks in @(10, -1, -10)) {
            $s = Get-AtmSelfProcessKeys -Collection $c -SelfPid 150 -SelfCreationUtc $selfT.AddTicks($ticks) -LauncherReferences @($launcher)
            Assert-True (@($s.Keys).Count -eq 0 -and (@($s.Unverified | ForEach-Object { $_.Result }) -join ',') -eq 'PID_REUSED') "horario diferente em 1 us ($ticks x 100 ns): nada marcado como SELF"
        }
        # PID reused inside the former 1 s window: the old tolerance would have matched, SELF does not.
        foreach ($ms in @(1, 500, 999)) {
            $old = Resolve-AtmProcessReference -Collection $c -ProcessId 150 -CreationUtc $selfT.AddMilliseconds($ms) -ToleranceMs 1000
            Assert-True ($old.Result -eq 'MATCH' -and $old.Approximate) "tolerancia de 1 s casaria ($ms ms) e e marcada como aproximada"
            $s = Get-AtmSelfProcessKeys -Collection $c -SelfPid 150 -SelfCreationUtc $selfT.AddMilliseconds($ms) -LauncherReferences @($launcher)
            Assert-True (@($s.Keys).Count -eq 0) "PID reutilizado $ms ms depois: o outro processo nao e escondido como SELF"
        }
        # External reference inside the 2 s tolerance: never enough for SELF.
        $ext = [pscustomobject]@{ Pid = 100; CreationUtc = $launchT.AddMilliseconds(1500) }
        $r = Resolve-AtmProcessReference -Collection $c -ProcessId 100 -CreationUtc $ext.CreationUtc -ToleranceMs 2000
        Assert-True ($r.Result -eq 'MATCH' -and $r.Approximate) 'referencia externa casa so de forma aproximada'
        $s = Get-AtmSelfProcessKeys -Collection $c -SelfPid 150 -SelfCreationUtc $selfT -LauncherReferences @($ext)
        Assert-True ($s.Keys -cnotcontains (& $k 100) -and (@($s.Unverified | ForEach-Object { $_.Result }) -join ',') -eq 'PID_REUSED') 'lancador aproximado nao e excluido'
        Assert-True (-not (Get-Command Get-AtmSelfProcessKeys).Parameters.ContainsKey('ToleranceMs')) 'SELF nao aceita tolerancia'
        Assert-True (-not ${function:Get-AtmSelfProcessKeys}.ToString().Contains('-ToleranceMs')) 'SELF nunca chama a comparacao com tolerancia'
        $threw = $false; try { $null = Resolve-AtmProcessReference -Collection $c -ProcessId 150 -CreationUtc $selfT -ToleranceMs 5 -CimPrecision } catch { $threw = $true }
        Assert-True $threw 'precisao do CIM e tolerancia sao exclusivas'
        $exact = Resolve-AtmProcessReference -Collection $c -ProcessId 150 -CreationUtc $selfT
        Assert-True ($exact.Result -eq 'MATCH' -and -not $exact.Approximate) 'mesma fonte: exata, nao aproximada'
        # Missing, invalid or incompatible time: not verified, nothing excluded.
        foreach ($bad in @('garbage', '', [datetime]::UtcNow.AddDays(5), '1999-01-01T00:00:00Z')) {
            $s = Get-AtmSelfProcessKeys -Collection $c -SelfPid 150 -SelfCreationUtc $bad -LauncherReferences @($launcher)
            Assert-True (@($s.Keys).Count -eq 0 -and (@($s.Unverified | ForEach-Object { $_.Result }) -join ',') -eq 'IDENTITY_UNVERIFIED') "horario '$bad': nao verificado"
        }
        $offRows = @((New-Row 4 0 $t0), (New-Row 100 4 $launchT.AddTicks(3)), (New-Row 150 100 $selfT.AddTicks(3)), (New-Row 151 150 $t0.AddMinutes(4)))
        $off = Get-AtmProcessCollection -Source ({ $offRows }.GetNewClosure())
        Assert-Eq $off.Coverage.Status 'COMPLETE' 'coleta lida'
        $s = Get-AtmSelfProcessKeys -Collection $off -SelfPid 150 -SelfCreationUtc $selfT.AddTicks(3)
        Assert-True (@($s.Keys).Count -eq 0 -and (@($s.Unverified | ForEach-Object { $_.Result }) -join ',') -eq 'IDENTITY_UNVERIFIED') 'horario coletado fora da resolucao do CIM: nao verificado, mesmo igual'
        $s = Get-AtmSelfProcessKeys -Collection $c -SelfPid 150 -SelfCreationUtc $selfT -LauncherReferences @([pscustomobject]@{ Pid = 100; CreationUtc = $launchT })
        Assert-Eq @($s.Unverified).Count 0 'controle: lancador exato verificado'
        $s2 = Get-AtmSelfProcessKeys -Collection $off -SelfPid 151 -SelfCreationUtc $t0.AddMinutes(4) -LauncherReferences @([pscustomobject]@{ Pid = 100; CreationUtc = $launchT.AddTicks(3) })
        Assert-True ($s2.Keys -cnotcontains $off.ByPid[[long]100].Key -and @($s2.Unverified | ForEach-Object { $_.Result }) -ccontains 'IDENTITY_UNVERIFIED') 'lancador fora da resolucao: nao verificado'
        # Real, read-only evidence of the CIM resolution on this machine; recorded, not assumed.
        # Processes of this session only (start times of other accounts' processes are not readable without elevation).
        $col = Get-AtmProcessCollection
        $session = [Diagnostics.Process]::GetCurrentProcess().SessionId
        $cmp = 0; $trunc = 0; $other = 0
        foreach ($pr in @([Diagnostics.Process]::GetProcesses() | Where-Object { $_.SessionId -eq $session } | Select-Object -First 300)) {
            $stp = $null
            try { $stp = $pr.StartTime.ToUniversalTime().Ticks } catch { continue }
            $p = $col.ByPid[[long]$pr.Id]
            if ($null -eq $p -or $p.IdentityStatus -ne 'VERIFIED') { continue }
            $cmp++
            if ($p.CreationUtc.Ticks -eq ($stp - ($stp % 10))) { $trunc++ } else { $other++ }
        }
        $script:caseNote = "CIM x StartTime: $trunc de $cmp iguais apos truncar a 1 us, $other diferentes (processos encerrados ou reutilizados entre as leituras contam aqui)"
        Assert-True ($cmp -gt 0) 'horarios comparados'
    }
    Test-Case 'Diagnose' 'Recursos (P1-B3): contadores lidos como inteiros; ilegivel vira nulo com cobertura PARTIAL, nunca 0; cobertura da identidade nao muda' {
        $t0 = New-Object DateTime(2026, 1, 1, 8, 0, 0, [DateTimeKind]::Utc)
        function New-RRow { param($Id, $Parent, $Created, $K = 10, $U = 20, $Ws = 4096, $Priv = 8192, $H = 7, $R = 1, $W = 2, $O = 3)
            [pscustomobject]@{ ProcessId = $Id; ParentProcessId = $Parent; Name = "p$Id.exe"; CreationDate = $Created; KernelModeTime = $K; UserModeTime = $U; WorkingSetSize = $Ws; PrivatePageCount = $Priv; HandleCount = $H; ReadTransferCount = $R; WriteTransferCount = $W; OtherTransferCount = $O } }
        $rows = @((New-RRow 0 0 $t0 -K ([uint64]25781994218750) -U ([uint64]0) -H ([uint32]0)), (New-RRow 4 0 $t0),
            (New-RRow 200 4 $t0.AddMinutes(1) -Ws 'abc' -Priv (-5) -H $null -R 1.5 -W $true -O ([uint64]::MaxValue)),
            [pscustomobject]@{ ProcessId = 300; ParentProcessId = 4; Name = 'old.exe'; CreationDate = $t0.AddMinutes(2) })
        $c = Get-AtmProcessCollection -Source ({ $rows }.GetNewClosure())
        Assert-Eq $c.Coverage.Status 'COMPLETE' 'identidade completa mesmo com contadores ilegiveis'
        Assert-Eq $c.ResourceCoverage.Collector 'process-resources' 'coletor de recursos'
        Assert-Eq $c.ResourceCoverage.Status 'PARTIAL' 'contadores ilegiveis -> parcial'
        Assert-Eq (@($c.ResourceCoverage.Reasons) -join ',') 'RESOURCE_COUNTERS_UNREADABLE' 'motivo'
        Assert-True ($c.ResourceCoverage.Observed -eq 2 -and $c.ResourceCoverage.Expected -eq 4) 'contagens dos recursos'
        $idle = $c.ByPid[[long]0].Resources
        Assert-True ($idle.KernelTime100ns -eq 25781994218750 -and $idle.UserTime100ns -eq 0 -and $idle.HandleCount -eq 0) 'zero informado pela fonte e mantido como 0'
        Assert-True ($idle.UserTime100ns -is [long] -and $idle.HandleCount -is [long]) 'inteiros de 64 bits'
        $bad = $c.ByPid[[long]200].Resources
        foreach ($n in @('WorkingSetBytes', 'PrivateBytes', 'HandleCount', 'ReadTransferBytes', 'WriteTransferBytes', 'OtherTransferBytes')) { Assert-True ($null -eq $bad.$n) "$n ilegivel e nulo, nunca 0" }
        Assert-True ($bad.KernelTime100ns -eq 10 -and $bad.UserTime100ns -eq 20) 'contadores legiveis da mesma linha mantidos'
        foreach ($n in @($c.ByPid[[long]300].Resources.PSObject.Properties.Name)) { Assert-True ($null -eq $c.ByPid[[long]300].Resources.$n) "linha sem contadores: $n nulo" }
        Assert-True ($null -eq (Get-AtmProcessCpuTime $c.ByPid[[long]300]) -and (Get-AtmProcessCpuTime $c.ByPid[[long]4]) -eq 30) 'tempo de CPU so com os dois contadores'
        $okRows = @($rows[0], $rows[1])
        $c = Get-AtmProcessCollection -Source ({ $okRows }.GetNewClosure())
        Assert-True ($c.ResourceCoverage.Status -eq 'COMPLETE' -and $c.ResourceCoverage.ElevationWouldHelp -eq 'NO' -and @($c.ResourceCoverage.Reasons).Count -eq 0) 'todos os contadores lidos -> completa'
        $c = Get-AtmProcessCollection -Source ({ $okRows }.GetNewClosure()) -MaxRecords 1
        Assert-Eq (@($c.ResourceCoverage.Reasons) -join ',') 'PROCESS_ROWS_NOT_READ' 'limite de linhas: recursos parciais'
        $malRows = @($okRows) + @([pscustomobject]@{ ProcessId = 'x' })
        $c = Get-AtmProcessCollection -Source ({ $malRows }.GetNewClosure())
        Assert-Eq (@($c.ResourceCoverage.Reasons) -join ',') 'PROCESS_ROWS_NOT_READ' 'linha invalida: recursos parciais'
        $f = Get-AtmProcessCollection -Source { throw (New-Object InvalidOperationException('texto-que-nao-pode-aparecer')) }
        Assert-True ($f.ResourceCoverage.Status -eq 'FAILED' -and $f.ResourceCoverage.Collector -eq 'process-resources') 'falha da coleta: recursos FAILED'
        $d = Get-AtmProcessCollection -Source { $okRows } -Deadline ([datetime]::UtcNow)
        Assert-True ($d.ResourceCoverage.Status -eq 'TIMEOUT' -and (@($d.ResourceCoverage.Reasons) -join ',') -eq 'DEADLINE_EXCEEDED') 'prazo: recursos TIMEOUT'
    }
    Test-Case 'Diagnose' 'CPU (P1-B3): porcentagem entre duas amostras sobre intervalo declarado e processadores logicos; ilegivel, contador que diminui ou identidade incerta nunca viram 0' {
        $t0 = New-Object DateTime(2026, 1, 1, 8, 0, 0, [DateTimeKind]::Utc)
        function New-RRow { param($Id, $Created, $K, $U)
            [pscustomobject]@{ ProcessId = $Id; ParentProcessId = 4; Name = "p$Id.exe"; CreationDate = $Created; KernelModeTime = $K; UserModeTime = $U; WorkingSetSize = 1; PrivatePageCount = 1; HandleCount = 1; ReadTransferCount = 1; WriteTransferCount = 1; OtherTransferCount = 1 } }
        $r1 = @((New-RRow 100 $t0 10000000 10000000), (New-RRow 110 $t0 0 0), (New-RRow 120 $t0 1000000 $null), (New-RRow 130 $t0 5 5), (New-RRow 140 $t0 5 5), (New-RRow 150 $t0 900 900))
        $r2 = @((New-RRow 100 $t0 15000000 15000000), (New-RRow 110 $t0 1000000 1000000), (New-RRow 120 $t0 2000000 $null), (New-RRow 140 $t0.AddMinutes(1) 5 5), (New-RRow 150 $t0 100 100))
        $a = Get-AtmProcessCollection -Source ({ $r1 }.GetNewClosure())
        $b = Get-AtmProcessCollection -Source ({ $r2 }.GetNewClosure())
        $m = Measure-AtmProcessCpu -First $a -Second $b -LogicalProcessors 4 -ElapsedMs 1000
        $key = { param($id) $a.ByPid[[long]$id].Key }
        Assert-Eq $m.ByKey[(& $key 100)] 25 '1 s de CPU em 1 s com 4 processadores logicos = 25%'
        Assert-Eq $m.ByKey[(& $key 110)] 5 '0,2 s em 1 s com 4 processadores = 5%'
        Assert-True ($m.ByKey.ContainsKey((& $key 120)) -and $null -eq $m.ByKey[(& $key 120)]) 'contador ilegivel: nulo'
        Assert-True ($null -eq $m.ByKey[(& $key 150)]) 'contador que diminui: nulo'
        Assert-Eq $m.Exited 2 'encerrado e PID reutilizado nao tem porcentagem'
        Assert-True ($m.IntervalMs -eq 1000 -and $m.LogicalProcessors -eq 4) 'intervalo e processadores declarados'
        Assert-Eq $m.Coverage.Collector 'process-cpu' 'coletor'
        Assert-Eq $m.Coverage.Status 'PARTIAL' 'parcial'
        Assert-Eq (@($m.Coverage.Reasons | Sort-Object) -join ',') 'CPU_COUNTER_DECREASED,CPU_COUNTERS_UNREADABLE' 'motivos'
        Assert-True ($m.Coverage.Observed -eq 2 -and $m.Coverage.Expected -eq 4) 'contagens'
        $clean1 = @($r1[0], $r1[1]); $clean2 = @($r2[0], $r2[1])
        $m = Measure-AtmProcessCpu -First (Get-AtmProcessCollection -Source ({ $clean1 }.GetNewClosure())) -Second (Get-AtmProcessCollection -Source ({ $clean2 }.GetNewClosure())) -LogicalProcessors 1 -ElapsedMs 2000
        Assert-True ($m.Coverage.Status -eq 'COMPLETE' -and $m.ByKey[(& $key 100)] -eq 50) 'completa; 1 s em 2 s com 1 processador = 50%'
        $partial2 = @($clean2) + @([pscustomobject]@{ ProcessId = 'x' })
        $m = Measure-AtmProcessCpu -First (Get-AtmProcessCollection -Source ({ $r1 }.GetNewClosure())) -Second (Get-AtmProcessCollection -Source ({ $partial2 }.GetNewClosure())) -LogicalProcessors 4 -ElapsedMs 1000
        Assert-True (@($m.Coverage.Reasons) -ccontains 'CPU_SAMPLE_INCOMPLETE' -and @($m.Coverage.Reasons) -ccontains 'CPU_SAMPLE_IDENTITY_UNVERIFIED') 'segunda amostra parcial: ausentes nao verificados'
        Assert-Eq $m.Exited 0 'ausente de amostra parcial nunca e encerrado'
        $fail = Get-AtmProcessCollection -Source { throw (New-Object InvalidOperationException('x')) }
        $late = Get-AtmProcessCollection -Source { $r2 } -Deadline ([datetime]::UtcNow)
        foreach ($cs in @(@($fail, $b, 'FAILED', 'CPU_SAMPLE_UNAVAILABLE'), @($a, $null, 'FAILED', 'CPU_SAMPLE_UNAVAILABLE'), @($a, $late, 'TIMEOUT', 'CPU_SAMPLE_TIMEOUT'))) {
            $m = Measure-AtmProcessCpu -First $cs[0] -Second $cs[1] -ElapsedMs 1000
            Assert-True ($m.Coverage.Status -eq $cs[2] -and (@($m.Coverage.Reasons) -join ',') -eq $cs[3] -and $m.ByKey.Count -eq 0) "sem amostra: $($cs[3])"
        }
        $m = Measure-AtmProcessCpu -First $a -Second $b -ElapsedMs 0
        Assert-True ($m.Coverage.Status -eq 'FAILED' -and (@($m.Coverage.Reasons) -join ',') -eq 'CPU_INTERVAL_INVALID' -and $m.ByKey.Count -eq 0) 'intervalo invalido'
        $threw = $false; try { $null = Measure-AtmProcessCpu -First $a -Second $b -LogicalProcessors 0 } catch { $threw = $true }
        Assert-True $threw 'zero processadores recusado'
        foreach ($iv in @(99, 5001)) {
            $threw = $false; try { $null = Invoke-AtmProcessCpuSampling -Source { $r1 } -IntervalMs $iv } catch { $threw = $true }
            Assert-True $threw "intervalo $iv ms recusado (100 a 5000)"
        }
        $seq = @{ N = 0 }
        $s = Invoke-AtmProcessCpuSampling -Source ({ $seq.N++; if ($seq.N -eq 1) { $r1 } else { $r2 } }.GetNewClosure()) -IntervalMs 100 -LogicalProcessors 4
        Assert-True ($seq.N -eq 2 -and $null -ne $s.Second -and $s.Cpu.IntervalMs -ge 90) "duas amostras com o intervalo medido: $($s.Cpu.IntervalMs) ms"
        Assert-True ($s.Cpu.ByKey[(& $key 100)] -gt 0) 'porcentagem calculada com o intervalo medido'
        $seq.N = 0
        $s = Invoke-AtmProcessCpuSampling -Source ({ $seq.N++; $r1 }.GetNewClosure()) -IntervalMs 1000 -Deadline ([datetime]::UtcNow.AddMilliseconds(500))
        Assert-True ($seq.N -eq 1 -and $null -eq $s.Second -and $s.Cpu.Coverage.Status -eq 'TIMEOUT' -and (@($s.Cpu.Coverage.Reasons) -join ',') -eq 'DEADLINE_EXCEEDED') 'prazo antes do fim do intervalo: so a primeira amostra'
        Assert-Eq (Get-AtmProcessCpuTime $s.First.ByPid[[long]100]) 20000000 'tempo de CPU acumulado da primeira amostra disponivel'
        $seq.N = 0
        $s = Invoke-AtmProcessCpuSampling -Source ({ $seq.N++; throw (New-Object InvalidOperationException('x')) }.GetNewClosure()) -IntervalMs 1000
        Assert-True ($seq.N -eq 1 -and $null -eq $s.Second -and $s.Cpu.Coverage.Status -eq 'FAILED') 'primeira amostra falhou: sem espera nem segunda amostra'
    }
    Test-Case 'Diagnose' 'Recursos por arvore verificada (P1-B3): soma dos membros; ilegivel, arvore incompleta ou CPU nao amostrada deixam a soma parcial; PID reutilizado nao soma' {
        $t0 = New-Object DateTime(2026, 1, 1, 8, 0, 0, [DateTimeKind]::Utc)
        function New-RRow { param($Id, $Parent, $Created, $K, $H = 10)
            [pscustomobject]@{ ProcessId = $Id; ParentProcessId = $Parent; Name = "p$Id.exe"; CreationDate = $Created; KernelModeTime = $K; UserModeTime = 0; WorkingSetSize = 1000 * $Id; PrivatePageCount = 2000; HandleCount = $H; ReadTransferCount = 1; WriteTransferCount = 2; OtherTransferCount = 3 } }
        $r1 = @((New-RRow 4 0 $t0 1), (New-RRow 100 4 $t0.AddMinutes(1) 1000), (New-RRow 110 100 $t0.AddMinutes(2) 1000), (New-RRow 120 100 $t0.AddMinutes(2) 1000),
            (New-RRow 111 110 $t0.AddMinutes(3) 1000), (New-RRow 300 100 $t0.AddSeconds(30) 999999 -H 50000))
        $r2 = @($r1 | ForEach-Object { $x = $_.PSObject.Copy(); $x.KernelModeTime = $_.KernelModeTime + 2500000; $x })
        $a = Get-AtmProcessCollection -Source ({ $r1 }.GetNewClosure())
        $b = Get-AtmProcessCollection -Source ({ $r2 }.GetNewClosure())
        $cpu = Measure-AtmProcessCpu -First $a -Second $b -LogicalProcessors 1 -ElapsedMs 1000
        $root = $a.ByPid[[long]100].Key
        $tree = Get-AtmProcessTree -Collection $a -RootKey $root
        $res = Get-AtmProcessTreeResources -Collection $a -Tree $tree -Cpu $cpu
        Assert-True ($res.Complete -and @($res.Reasons).Count -eq 0 -and $res.Members -eq 4) 'arvore completa com todos os contadores'
        Assert-Eq $res.Counters.WorkingSetBytes.Sum (1000 * (100 + 110 + 120 + 111)) 'working set somado dos membros'
        Assert-Eq $res.Counters.HandleCount.Sum 40 'handles: o processo que so reutiliza o PID nao soma'
        Assert-Eq $res.Counters.CpuTime100ns.Sum 4000 'tempo de CPU somado'
        Assert-Eq $res.Counters.CpuPercent.Sum 100 'porcentagem da arvore: 4 x 25%'
        Assert-Eq (@($res.Counters.PSObject.Properties.Name) -join ',') ((@($script:AtmTreeCounters) + @('CpuPercent')) -join ',') 'contadores da lista fechada'
        Assert-True ($cpu.Coverage.Status -eq 'COMPLETE' -and $res.Counters.CpuPercent.Complete -and @($res.Counters.PSObject.Properties | Where-Object { -not $_.Value.Complete }).Count -eq 0) 'controle positivo: CPU completa, todos os contadores completos'
        $res = Get-AtmProcessTreeResources -Collection $a -Tree $tree
        Assert-True (-not $res.Complete -and (@($res.Reasons) -join ',') -eq 'CPU_NOT_SAMPLED' -and $null -eq $res.Counters.CpuPercent.Sum -and $res.Counters.CpuTime100ns.Complete) 'sem amostra de CPU: so o tempo acumulado'
        Assert-True (-not $res.Counters.CpuPercent.Complete -and $res.Counters.CpuPercent.Known -eq 0) 'sem amostra de CPU: porcentagem incompleta'
        foreach ($n in $script:AtmTreeCounters) { Assert-True $res.Counters.$n.Complete "sem amostra de CPU: $n continua completo" }
        # Second sample PARTIAL because of a row outside the tree; every member still has a percentage.
        $outside = @($r2) + @([pscustomobject]@{ ProcessId = 900; ParentProcessId = 4; Name = 'p900.exe'; CreationDate = $null; KernelModeTime = 1; UserModeTime = 1; WorkingSetSize = 1; PrivatePageCount = 1; HandleCount = 1; ReadTransferCount = 1; WriteTransferCount = 1; OtherTransferCount = 1 })
        $bp = Get-AtmProcessCollection -Source ({ $outside }.GetNewClosure())
        Assert-True ($a.Coverage.Status -eq 'COMPLETE' -and $bp.Coverage.Status -eq 'PARTIAL') 'primeira completa, segunda parcial'
        $cpuP = Measure-AtmProcessCpu -First $a -Second $bp -LogicalProcessors 1 -ElapsedMs 1000
        Assert-Eq $cpuP.Coverage.Status 'PARTIAL' 'amostra de CPU parcial'
        Assert-True (@($tree.Members | Where-Object { $null -eq $cpuP.ByKey[$_] }).Count -eq 0) 'todos os membros da arvore com porcentagem'
        $res = Get-AtmProcessTreeResources -Collection $a -Tree $tree -Cpu $cpuP
        Assert-True ($res.Counters.CpuPercent.Sum -eq 100 -and $res.Counters.CpuPercent.Known -eq 4) 'soma disponivel preservada como evidencia parcial'
        Assert-True (-not $res.Counters.CpuPercent.Complete) 'amostra de CPU parcial: CpuPercent nunca completo'
        Assert-True (-not $res.Complete -and (@($res.Reasons) -join ',') -eq 'CPU_SAMPLE_INCOMPLETE') 'arvore incompleta com o motivo da CPU'
        foreach ($n in $script:AtmTreeCounters) { Assert-True $res.Counters.$n.Complete "amostra de CPU parcial: $n continua completo" }
        # CPU unreadable for one member in the second sample.
        $noUser = @($r2 | ForEach-Object { $x = $_.PSObject.Copy(); if ($x.ProcessId -eq 110) { $x.UserModeTime = $null }; $x })
        $cpuU = Measure-AtmProcessCpu -First $a -Second (Get-AtmProcessCollection -Source ({ $noUser }.GetNewClosure())) -LogicalProcessors 1 -ElapsedMs 1000
        $res = Get-AtmProcessTreeResources -Collection $a -Tree $tree -Cpu $cpuU
        Assert-True ($cpuU.Coverage.Status -eq 'PARTIAL' -and $res.Counters.CpuPercent.Sum -eq 75 -and $res.Counters.CpuPercent.Known -eq 3 -and -not $res.Counters.CpuPercent.Complete) 'CPU ilegivel de um membro: soma parcial, nunca 0'
        Assert-True (-not $res.Complete -and @($res.Reasons) -ccontains 'CPU_SAMPLE_INCOMPLETE' -and $res.Counters.CpuTime100ns.Complete) 'CPU ilegivel: arvore incompleta; tempo acumulado da coleta indicada completo'
        $holeRows = @($r1 | ForEach-Object { $x = $_.PSObject.Copy(); if ($x.ProcessId -eq 120) { $x.HandleCount = $null }; $x })
        $h = Get-AtmProcessCollection -Source ({ $holeRows }.GetNewClosure())
        $res = Get-AtmProcessTreeResources -Collection $h -Tree (Get-AtmProcessTree -Collection $h -RootKey $root) -Cpu $cpu
        Assert-True ($res.Counters.HandleCount.Sum -eq 30 -and $res.Counters.HandleCount.Known -eq 3 -and -not $res.Counters.HandleCount.Complete) 'contador ilegivel: soma parcial (limite inferior), nunca 0'
        Assert-True (-not $res.Complete -and @($res.Reasons) -ccontains 'COUNTERS_UNREADABLE' -and $res.Counters.WorkingSetBytes.Complete) 'so o contador afetado fica incompleto'
        $res = Get-AtmProcessTreeResources -Collection $a -Tree (Get-AtmProcessTree -Collection $a -RootKey $root -MaxMembers 2) -Cpu $cpu
        Assert-True (-not $res.Complete -and @($res.Reasons) -ccontains 'TREE_INCOMPLETE' -and @($res.Counters.PSObject.Properties | Where-Object { $_.Value.Complete }).Count -eq 0) 'arvore incompleta: nenhuma soma completa'
        $res = Get-AtmProcessTreeResources -Collection $a -Tree (Get-AtmProcessTree -Collection $a -RootKey ('100@' + $t0.Ticks)) -Cpu $cpu
        Assert-True ($res.Members -eq 0 -and -not $res.Complete -and @($res.Counters.PSObject.Properties | Where-Object { $null -ne $_.Value.Sum }).Count -eq 0) 'raiz nao verificada: somas nulas'
        $res = Get-AtmProcessTreeResources -Collection $b -Tree $tree -Cpu $cpu
        Assert-True ($res.Complete -and $res.Counters.CpuTime100ns.Sum -eq 10004000) 'membros procurados pela chave na coleta indicada'
        # Real, read-only: this process sampled twice; its counters and percentage are read, never invented.
        $s = Invoke-AtmProcessCpuSampling -IntervalMs 200
        $mine = Resolve-AtmProcessReference -Collection $s.First -ProcessId $PID -CreationUtc ([Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime()) -ToleranceMs 1000
        Assert-Eq $mine.Result 'MATCH' 'proprio processo'
        foreach ($n in @($mine.Process.Resources.PSObject.Properties.Name)) { Assert-True ($null -ne $mine.Process.Resources.$n) "proprio processo: $n lido" }
        Assert-True ($null -ne $s.Cpu.ByKey[$mine.Process.Key] -and $s.Cpu.ByKey[$mine.Process.Key] -ge 0 -and $s.Cpu.IntervalMs -ge 180) "porcentagem real: $($s.Cpu.ByKey[$mine.Process.Key]) em $([int]$s.Cpu.IntervalMs) ms"
        $own = Get-AtmProcessTreeResources -Collection $s.First -Tree (Get-AtmProcessTree -Collection $s.First -RootKey $mine.Process.Key) -Cpu $s.Cpu
        Assert-True ($own.Members -ge 1 -and $own.Counters.WorkingSetBytes.Sum -gt 0) 'arvore do proprio processo'
        $unread = @($s.First.Processes | Where-Object { $p = $_; @($p.Resources.PSObject.Properties | Where-Object { $null -eq $_.Value }).Count -gt 0 }).Count
        $script:caseNote = "recursos $($s.First.ResourceCoverage.Status) ($unread com contador ilegivel de $(@($s.First.Processes).Count)), CPU $($s.Cpu.Coverage.Status), admin=$($me.IsAdmin)"
    }
    # A pure v1 copy of a provider: Claude Code is v2 since P1-B4-b, and the V0.1 contract tests keep a v1 subject.
    function ConvertTo-AtmTestV1Provider {
        param($Provider)
        $c = $Provider.PSObject.Copy()
        foreach ($n in @('ContractVersion', 'Capabilities', 'GetProcessMatchers', 'GetServiceHints', 'GetVirtualizationHints', 'GetWorktreeHints')) { if ($c.PSObject.Properties[$n]) { $c.PSObject.Properties.Remove($n) } }
        return $c
    }
    # P1-B4-b fixtures: process rows on the CIM resolution (whole seconds), with every counter unless left out.
    $b4T0 = New-Object DateTime(2026, 10, 20, 10, 0, 0, [DateTimeKind]::Utc)
    $b4Row = { param([long]$ProcessId, [long]$Parent, [string]$Name, $Created, [string[]]$Without = @())
        $o = [ordered]@{ ProcessId = $ProcessId; ParentProcessId = $Parent; Name = $Name; CreationDate = $Created }
        foreach ($c in @('KernelModeTime', 'UserModeTime', 'WorkingSetSize', 'PrivatePageCount', 'HandleCount', 'ReadTransferCount', 'WriteTransferCount', 'OtherTransferCount')) { $o[$c] = $(if ($Without -contains $c) { $null } else { [long]1000 }) }
        [pscustomobject]$o }
    $b4Hints = { param([string]$ProviderId, $Matchers, [string]$Status = 'COMPLETE')
        $cov = $(if ($Status -eq 'COMPLETE') { New-AtmCoverage -Collector ('provider-' + $ProviderId) -Status 'COMPLETE' } else { New-AtmCoverage -Collector ('provider-' + $ProviderId) -Status $Status -Reasons @('HINT_FAILED_PROCESS_MATCHERS') })
        [pscustomobject]@{ ProviderId = $ProviderId; ProcessMatchers = @($Matchers); ServiceHints = @(); VirtualizationHints = @(); Coverage = $cov } }
    $b4Key = { param([long]$ProcessId, $Created) ConvertTo-AtmProcessKey -ProcessId $ProcessId -CreationUtc $Created }
    # Session keys are keyed pseudonyms (P1-B4-c, ADR-0010): a fixed test key, passed to the engine-level runtime calls
    # below and to Invoke-AtmDiagnose where a key is computed; these fixtures carry no profile.
    $testPseudonymKey = [byte[]](1..32)
    $b4Pz = New-AtmPseudonymizer -Key $testPseudonymKey
    $b4SKey = { param([string]$Provider, [string]$SessionId) ConvertTo-AtmSessionKey -Pseudonymizer $b4Pz -Provider $Provider -ProfileSid '' -ProfilePath '' -SessionId $SessionId }
    $b4PKey = { param([string]$Path) ConvertTo-AtmPartitionKey -Pseudonymizer $b4Pz -Provider 'claude-code' -Path $Path }
    $b4State = { param($Result, [string]$Key) $f = @($Result.Findings | Where-Object { $_.Key -ceq $Key }); if ($f.Count -eq 1) { $f[0].State } elseif ($f.Count -eq 0) { '(none)' } else { "(x$($f.Count))" } }
    Test-Case 'Diagnose' 'Estados de ausencia (P1-B4-b): SESSION_PROCESS_NOT_FOUND so com cobertura conclusiva; sem cobertura ou com qualquer status nao conclusivo vira UNKNOWN' {
        $exercised = @{}
        foreach ($kind in $script:AtmFindingKinds) {
            foreach ($state in @($script:AtmFindingStates[$kind] | Where-Object { $script:AtmAbsenceStates -ccontains $_ })) {
                $exercised[$state] = $true
                foreach ($st in $script:AtmCoverageStatuses) {
                    $conclusive = $script:AtmConclusiveCoverage -ccontains $st
                    $cov = @((New-AtmCoverage -Collector 'sessions-x' -Status 'COMPLETE'), (New-AtmCoverage -Collector 'process-snapshot' -Status $st -Reasons $(if ($conclusive) { @() } else { @('TEST_REASON') })))
                    $f = New-AtmFinding -Kind $kind -Key 'k' -State $state -Coverage $cov
                    Assert-Eq $f.State $(if ($conclusive) { $state } else { 'UNKNOWN' }) "$kind/$state com cobertura $st"
                    Assert-Eq $f.RequestedState $state 'estado pedido preservado'
                }
                Assert-Eq (New-AtmFinding -Kind $kind -Key 'k' -State $state).State 'UNKNOWN' "$kind/$state sem nenhuma cobertura"
            }
        }
        foreach ($state in $script:AtmAbsenceStates) { Assert-True $exercised.ContainsKey($state) "$state pertence a algum tipo" }
        Assert-Eq (@($script:AtmFindingStates['Process']) -join ',') 'SELF,AGENT_PROCESS,AGENT_DESCENDANT,IDENTITY_UNVERIFIED,UNKNOWN' 'estados de Process'
        Assert-Eq (@($script:AtmFindingStates['AgentSession']) -join ',') 'LIVE,PID_REUSED,IDENTITY_UNVERIFIED,SESSION_PROCESS_NOT_FOUND,UNKNOWN' 'estados de AgentSession'
        foreach ($s in @('ENDED', 'NOT_RUNNING', 'DEAD', 'TERMINATED', 'RELEASED', 'FREE', 'SAFE_TO_DELETE')) {
            foreach ($kind in @('Process', 'AgentSession')) { $threw = $false; try { $null = New-AtmFinding -Kind $kind -Key 'k' -State $s -Coverage @(New-AtmCoverage -Collector 'process-snapshot' -Status 'COMPLETE') } catch { $threw = $true }; Assert-True $threw "$kind recusa $s" }
        }
    }
    Test-Case 'Diagnose' 'Identidade de sessao (P1-B4-b): LIVE so com identidade exata na precisao do CIM; diferenca dentro da antiga tolerancia, sem horario, horario fora da resolucao, PID duplicado ou coleta parcial ficam inconclusivos; ausencia so com coleta COMPLETE' {
        $rows = @((& $b4Row 4 0 'System' $b4T0.AddHours(-1)), (& $b4Row 500 4 'claude.exe' $b4T0), (& $b4Row 501 4 'odd.exe' $b4T0.AddTicks(3)), (& $b4Row 503 4 'a.exe' $b4T0), (& $b4Row 503 4 'b.exe' $b4T0.AddSeconds(1)))
        $c = Get-AtmProcessCollection -Source ({ $rows }.GetNewClosure())
        $cases = [ordered]@{
            'exato'                 = @(500, $b4T0, 'LIVE', 'IDENTITY_EXACT')
            '+9 ticks (truncado)'   = @(500, $b4T0.AddTicks(9), 'LIVE', 'IDENTITY_EXACT')
            '-1 tick'               = @(500, $b4T0.AddTicks(-1), 'IDENTITY_UNVERIFIED', 'CREATION_TIME_PRECISION_MISMATCH')
            '+10 ticks (1 us)'      = @(500, $b4T0.AddTicks(10), 'IDENTITY_UNVERIFIED', 'CREATION_TIME_PRECISION_MISMATCH')
            'PID reutilizado em 1s' = @(500, $b4T0.AddSeconds(1), 'IDENTITY_UNVERIFIED', 'CREATION_TIME_PRECISION_MISMATCH')
            'PID reutilizado em 3s' = @(500, $b4T0.AddSeconds(3), 'PID_REUSED', 'CREATION_TIME_DIFFERS')
            'sem horario'           = @(500, $null, 'IDENTITY_UNVERIFIED', 'SESSION_START_UNKNOWN')
            'horario invalido'      = @(500, 'ontem', 'IDENTITY_UNVERIFIED', 'SESSION_START_UNKNOWN')
            'fora da resolucao'     = @(501, $b4T0.AddTicks(3), 'IDENTITY_UNVERIFIED', 'CREATION_TIME_OFF_RESOLUTION')
            'PID duplicado'         = @(503, $b4T0, 'IDENTITY_UNVERIFIED', 'DUPLICATE_PID')
        }
        # (The duplicate PID makes this collection PARTIAL; absence is tested below with its own collections.)
        foreach ($n in $cases.Keys) {
            $v = $cases[$n]
            $r = Resolve-AtmSessionProcess -Collection $c -ProcessId $v[0] -StartUtc $v[1]
            Assert-True ($r.State -ceq $v[2] -and $r.Reason -ceq $v[3]) "$($n): $($r.State)/$($r.Reason) (esperado $($v[2])/$($v[3]))"
        }
        $completeRows = @((& $b4Row 4 0 'System' $b4T0.AddHours(-1)), (& $b4Row 500 4 'claude.exe' $b4T0), (& $b4Row 502 4 'x.exe' $b4T0))
        $complete = Get-AtmProcessCollection -Source ({ $completeRows }.GetNewClosure())
        Assert-Eq $complete.Coverage.Status 'COMPLETE' 'coleta completa'
        $r = Resolve-AtmSessionProcess -Collection $complete -ProcessId 7777 -StartUtc $b4T0
        Assert-True ($r.State -ceq 'SESSION_PROCESS_NOT_FOUND' -and $r.Reason -ceq 'PID_NOT_IN_COMPLETE_SNAPSHOT') "ausente com coleta COMPLETE: $($r.State)"
        $partialRows = @((& $b4Row 4 0 'System' $b4T0.AddHours(-1)), (& $b4Row 500 4 'claude.exe' $b4T0), (& $b4Row 510 4 'nodate.exe' $null))
        $partial = Get-AtmProcessCollection -Source ({ $partialRows }.GetNewClosure())
        Assert-Eq $partial.Coverage.Status 'PARTIAL' 'coleta parcial'
        $r = Resolve-AtmSessionProcess -Collection $partial -ProcessId 7777 -StartUtc $b4T0
        Assert-True ($r.State -ceq 'UNKNOWN' -and $r.Reason -ceq 'PROCESS_SNAPSHOT_INCOMPLETE') "ausente com coleta PARTIAL nunca vira ausencia: $($r.State)"
        $r = Resolve-AtmSessionProcess -Collection $partial -ProcessId 510 -StartUtc $b4T0
        Assert-True ($r.State -ceq 'IDENTITY_UNVERIFIED' -and $r.Reason -ceq 'PROCESS_CREATION_TIME_UNKNOWN') "processo sem horario de criacao: $($r.State)"
        $failed = Get-AtmProcessCollection -Source { throw (New-Object System.InvalidOperationException 'x') }
        $r = Resolve-AtmSessionProcess -Collection $failed -ProcessId 500 -StartUtc $b4T0
        Assert-True ($r.State -ceq 'UNKNOWN' -and $r.Reason -ceq 'PROCESS_SNAPSHOT_UNAVAILABLE') "coleta com falha: $($r.State)"
        # The V0.1 rule (2 s tolerance) is unchanged for the audit; the same session is only inconclusive for V0.2.
        $p = New-TestProfile 'b4sess'
        $ft = $b4T0.AddSeconds(1).ToFileTimeUtc()
        [IO.File]::WriteAllText((Join-Path (Join-Path $p.ProfilePath '.claude') 'sessions\500.json'), "{`"pid`":500,`"sessionId`":`"11111111-2222-3333-4444-555555555555`",`"procStart`":`"$ft`"}")
        $legacy = [pscustomobject]@{ Failed = $false; Processes = @([pscustomobject]@{ Pid = 500; Name = 'claude.exe'; ParentPid = 4; CommandLine = $null; CreationUtc = $b4T0 }) }
        $reg = Get-AtmClaudeSessionEvidence -ProfileInfo $p -Snapshot $legacy
        Assert-Eq @($reg.Entries).Count 1 'uma sessao'
        Assert-Eq $reg.Entries[0].State 'LIVE' 'regra V0.1 inalterada: 1 s de diferenca ainda e LIVE para a auditoria'
        Assert-Eq $reg.Entries[0].StartUtc $b4T0.AddSeconds(1) 'StartUtc: o procStart registrado (FILETIME, 100 ns)'
        $r = Resolve-AtmSessionProcess -Collection $complete -ProcessId $reg.Entries[0].Pid -StartUtc $reg.Entries[0].StartUtc
        Assert-Eq $r.State 'IDENTITY_UNVERIFIED' 'V0.2: a mesma sessao nao e LIVE sem identidade exata'
    }
    Test-Case 'Diagnose' 'Processos de agentes (P1-B4-b): matcher positivo e negativo, marcador indisponivel, sessoes, referencias de caminho, descendentes so por vinculo verificado, SELF acima de tudo; nada sensivel no resultado' {
        $rows = @(
            (& $b4Row 4 0 'System' $b4T0.AddHours(-1)),
            (& $b4Row 1000 4 'explorer.exe' $b4T0.AddMinutes(-30)),
            (& $b4Row 2000 1000 'claude.exe' $b4T0),
            (& $b4Row 2001 2000 'bash.exe' $b4T0.AddMinutes(1) -Without @('HandleCount')),
            (& $b4Row 2002 2001 'node.exe' $b4T0.AddMinutes(2)),
            (& $b4Row 2003 2000 'git.exe' $b4T0.AddMinutes(-1)),
            (& $b4Row 2500 2000 'cmd.exe' $b4T0.AddMinutes(4)),
            (& $b4Row 2501 2500 'sibling.exe' $b4T0.AddMinutes(4).AddSeconds(30)),
            (& $b4Row 2700 2000 'tool.exe' $b4T0.AddMinutes(6)),
            (& $b4Row 3000 2500 'powershell.exe' $b4T0.AddMinutes(5)),
            (& $b4Row 3001 3000 'conhost.exe' $b4T0.AddMinutes(5).AddSeconds(1)),
            (& $b4Row 5000 1000 'helper.exe' $b4T0.AddMinutes(10)),
            (& $b4Row 5001 1000 'other.exe' $b4T0.AddMinutes(11)),
            (& $b4Row 6000 1000 'fakeagent.exe' $b4T0.AddMinutes(12)),
            (& $b4Row 6001 1000 'fakeagent.exe' $b4T0.AddMinutes(13)),
            (& $b4Row 6002 1000 'fakeagent.exe' $b4T0.AddMinutes(14)))
        $c = Get-AtmProcessCollection -Source ({ $rows }.GetNewClosure())
        Assert-Eq $c.Coverage.Status 'COMPLETE' 'coleta completa'
        $k = @{}; foreach ($r in $rows) { $k[[int]$r.ProcessId] = & $b4Key $r.ProcessId $r.CreationDate }
        $marker = '--fake-agent-marker-SECRET'
        $hints = @((& $b4Hints 'claude-code' @([pscustomobject]@{ ImageName = 'claude.exe'; CommandLineMarker = $null })), (& $b4Hints 'fake-agent' @([pscustomobject]@{ ImageName = 'fakeagent.exe'; CommandLineMarker = $marker })))
        $entries = @(
            [pscustomobject]@{ SessionId = 's1'; Pid = 2000; State = 'LIVE'; StartUtc = $b4T0.AddTicks(5) },
            [pscustomobject]@{ SessionId = 's2'; Pid = 2001; State = 'LIVE'; StartUtc = $b4T0.AddMinutes(1).AddSeconds(1) },
            [pscustomobject]@{ SessionId = 's3'; Pid = 7777; State = 'DEAD'; StartUtc = $b4T0 },
            [pscustomobject]@{ SessionId = 's4'; Pid = 1000; State = 'PID_REUSED'; StartUtc = $b4T0.AddDays(-1) },
            [pscustomobject]@{ SessionId = 's5'; Pid = 2000; State = 'LIVE_UNVERIFIED'; StartUtc = $null })
        $regs = @([pscustomobject]@{ ProviderId = 'claude-code'; Registry = [pscustomobject]@{ Readable = $true; Unparseable = 0; Entries = $entries }; Error = $null })
        $legacy = [pscustomobject]@{ Failed = $false; Processes = @(
                [pscustomobject]@{ Pid = 5000; Name = 'helper.exe'; ParentPid = 1000; CommandLine = 'helper.exe C:\Users\alice\AppData\Local\Temp\claude\proj\uuid\script.sh'; CreationUtc = $b4T0.AddMinutes(10) },
                [pscustomobject]@{ Pid = 5001; Name = 'other.exe'; ParentPid = 1000; CommandLine = 'other.exe'; CreationUtc = $b4T0.AddHours(-5) },
                [pscustomobject]@{ Pid = 6000; Name = 'fakeagent.exe'; ParentPid = 1000; CommandLine = "fakeagent.exe $marker C:\secret\path"; CreationUtc = $b4T0.AddMinutes(12) },
                [pscustomobject]@{ Pid = 6001; Name = 'fakeagent.exe'; ParentPid = 1000; CommandLine = 'fakeagent.exe --other'; CreationUtc = $b4T0.AddMinutes(13) },
                [pscustomobject]@{ Pid = 6002; Name = 'fakeagent.exe'; ParentPid = 1000; CommandLine = $null; CreationUtc = $b4T0.AddMinutes(14) }) }
        $parts = @([pscustomobject]@{ Provider = 'claude-code'; DirectRefs = @('PID 5000 (helper.exe)'); AncestorRefs = @('PID 5001 (other.exe) -> projeto') })
        # SELF through the R-B1 rules: this process (3000), its launcher (2500, a verified ancestor) and its own child; a
        # launcher reference whose PID was reused (2700 recorded with another time) is not excluded.
        $self = Get-AtmSelfProcessKeys -Collection $c -SelfPid 3000 -SelfCreationUtc $b4T0.AddMinutes(5) -LauncherReferences @([pscustomobject]@{ Pid = 2500; CreationUtc = $b4T0.AddMinutes(4) }, [pscustomobject]@{ Pid = 2700; CreationUtc = $b4T0.AddMinutes(7) })
        Assert-Eq (@($self.Keys | Sort-Object) -join ',') ((@($k[2500], $k[3000], $k[3001]) | Sort-Object) -join ',') 'SELF: o proprio processo, o launcher verificado e o filho proprio'
        Assert-True (@($self.Unverified | Where-Object { $_.Pid -eq 2700 -and $_.Result -eq 'PID_REUSED' }).Count -eq 1) 'launcher com PID reutilizado nao verificado'
        $invCov = @(New-AtmCoverage -Collector 'inventory' -Status 'COMPLETE')
        $res = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $c -ProviderHints $hints -SessionRegistries $regs -LegacySnapshot $legacy -Partitions $parts -InventoryCoverage $invCov -SelfKeys $self
        $expect = [ordered]@{
            2000 = 'AGENT_PROCESS'; 2001 = 'AGENT_DESCENDANT'; 2002 = 'AGENT_DESCENDANT'; 2003 = '(none)'; 3000 = 'SELF'; 3001 = 'SELF'
            2500 = 'SELF'; 2501 = 'AGENT_DESCENDANT'; 2700 = 'AGENT_DESCENDANT'
            5000 = 'AGENT_PROCESS'; 5001 = '(none)'; 6000 = 'AGENT_PROCESS'; 6001 = '(none)'; 6002 = 'UNKNOWN'; 1000 = '(none)'; 4 = '(none)'
        }
        foreach ($e in $expect.GetEnumerator()) { Assert-Eq (& $b4State $res $k[[int]$e.Key]) $e.Value "processo $($e.Key)" }
        $f2000 = @($res.Findings | Where-Object { $_.Key -ceq $k[2000] })[0]
        Assert-Eq (@($f2000.Evidence | ForEach-Object { $_.Code } | Sort-Object) -join ',') 'PROCESS_MATCHER_IMAGE,SESSION_PROCESS_MATCH' 'claude.exe: matcher e sessao como evidencia'
        Assert-Eq $f2000.Provider 'claude-code' 'provider do processo'
        Assert-Eq (@($f2000.Coverage | ForEach-Object { $_.Collector }) -join ',') 'process-snapshot,agent-processes,provider-claude-code,sessions-claude-code' 'cobertura das fontes da evidencia'
        Assert-Eq (@(@($res.Findings | Where-Object { $_.Key -ceq $k[2002] })[0].Coverage | ForEach-Object { $_.Collector }) -join ',') 'process-snapshot,agent-processes,provider-claude-code,sessions-claude-code' 'descendente herda a cobertura da raiz'
        Assert-Eq (@(@($res.Findings | Where-Object { $_.Key -ceq $k[5000] })[0].Coverage | ForEach-Object { $_.Collector }) -join ',') 'process-snapshot,agent-processes,inventory' 'referencia de caminho depende do inventario'
        Assert-True (@($res.Findings | ForEach-Object { $_.Evidence } | Where-Object { @('process-matcher', 'session-registry', 'path-reference', 'diagnose') -cnotcontains $_.Source }).Count -eq 0) 'fontes de evidencia sao codigos fixos'
        Assert-Eq (@($res.Findings | Where-Object { $_.Key -ceq $k[2002] })[0].Evidence[0].Detail) $k[2000] 'descendente aponta a raiz verificada'
        Assert-Eq (@($res.Findings | Where-Object { $_.Key -ceq $k[5000] })[0].Evidence[0].Code) 'PATH_REFERENCE' 'referencia de caminho com identidade exata'
        Assert-Eq (@($res.Findings | Where-Object { $_.Key -ceq $k[6000] })[0].Evidence[0].Code) 'PROCESS_MATCHER_MARKER' 'marcador confirmado em memoria'
        Assert-Eq (@($res.Findings | Where-Object { $_.Key -ceq $k[6002] })[0].Evidence[0].Code) 'COMMAND_LINE_MARKER_UNAVAILABLE' 'marcador indisponivel: inconclusivo, nunca negativo'
        $sess = [ordered]@{ 's1' = 'LIVE'; 's2' = 'IDENTITY_UNVERIFIED'; 's3' = 'SESSION_PROCESS_NOT_FOUND'; 's4' = 'PID_REUSED'; 's5' = 'IDENTITY_UNVERIFIED' }
        foreach ($s in $sess.Keys) { Assert-Eq (& $b4State $res (& $b4SKey 'claude-code' $s)) $sess[$s] "sessao $s" }
        $ac = @($res.Coverage | Where-Object { $_.Collector -eq 'agent-processes' })[0]
        Assert-Eq $ac.Status 'PARTIAL' 'cobertura de processos de agentes parcial (marcador indisponivel, referencia nao verificada)'
        Assert-Eq (@($ac.Reasons | Sort-Object) -join ',') 'COMMAND_LINE_MARKER_UNAVAILABLE,PATH_REFERENCE_UNVERIFIED' 'motivos'
        Assert-Eq @($res.Coverage | Where-Object { $_.Collector -eq 'sessions-claude-code' })[0].Status 'COMPLETE' 'registro de sessoes completo'
        # Resources per agent tree: partial counters stay partial (never 0), and so does an unsampled CPU.
        $t = @($res.Trees | Where-Object { $_.RootKey -ceq $k[2000] })[0]
        $treeExpected = @($k[2000], $k[2001], $k[2002], $k[2500], $k[2501], $k[2700], $k[3000], $k[3001]) | Sort-Object
        Assert-Eq (@($t.Tree.Members | Sort-Object) -join ',') ($treeExpected -join ',') 'arvore verificada da raiz (sem o git criado antes do pai)'
        Assert-True (-not $t.Resources.Complete -and -not $t.Resources.Counters.HandleCount.Complete -and $t.Resources.Counters.HandleCount.Known -eq ($treeExpected.Count - 1)) 'contador ilegivel deixa a soma parcial'
        $rc = @($res.Coverage | Where-Object { $_.Collector -eq 'agent-resources' })[0]
        Assert-True ($rc.Status -eq 'PARTIAL' -and $rc.Reasons -contains 'COUNTERS_UNREADABLE' -and $rc.Reasons -contains 'CPU_NOT_SAMPLED') "recursos parciais: $($rc.Reasons -join ',')"
        # Nothing sensitive leaves the engine: no command line, marker, path or argument.
        $json = (@{ F = $res.Findings; C = $res.Coverage; T = $res.Trees } | ConvertTo-Json -Depth 10)
        foreach ($s in @($marker, 'SECRET', 'secret\\path', 'alice', 'AppData', 'script.sh', '--other', 'C:\\')) { Assert-True (-not $json.Contains($s)) "nada sensivel no resultado: $s" }
        foreach ($f in @($res.Findings | Where-Object { $_.Kind -eq 'Process' })) { Assert-True ($null -ne (ConvertFrom-AtmProcessKey $f.Key)) "processo com identidade verificada: $($f.Key)" }
    }
    Test-Case 'Diagnose' 'Processos de agentes (P1-B4-b): identidade incerta, coleta parcial ou com falha, provider sem agente instalado, falha de leitura do provider e de dicas nunca viram ausencia confirmada' {
        $claude = @(& $b4Hints 'claude-code' @([pscustomobject]@{ ImageName = 'claude.exe'; CommandLineMarker = $null }))
        $emptyReg = @([pscustomobject]@{ ProviderId = 'claude-code'; Registry = [pscustomobject]@{ Readable = $true; Unparseable = 0; Entries = @() }; Error = $null })
        # Unverified identity (no creation time): pid:<n>, IDENTITY_UNVERIFIED; the collection is PARTIAL, so a session
        # whose PID is absent is UNKNOWN, never SESSION_PROCESS_NOT_FOUND.
        $rows = @((& $b4Row 4 0 'System' $b4T0.AddHours(-1)), (& $b4Row 4000 4 'claude.exe' $null))
        $c = Get-AtmProcessCollection -Source ({ $rows }.GetNewClosure())
        $regs = @([pscustomobject]@{ ProviderId = 'claude-code'; Registry = [pscustomobject]@{ Readable = $true; Unparseable = 0; Entries = @([pscustomobject]@{ SessionId = 's3'; Pid = 7777; StartUtc = $b4T0 }) }; Error = $null })
        $res = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $c -ProviderHints $claude -SessionRegistries $regs
        Assert-Eq (& $b4State $res 'pid:4000') 'IDENTITY_UNVERIFIED' 'processo sem horario: identidade nao verificada'
        Assert-True ($null -eq (ConvertFrom-AtmProcessKey 'pid:4000')) 'pid:<n> nunca e uma chave de identidade'
        Assert-Eq (& $b4State $res (& $b4SKey 'claude-code' 's3')) 'UNKNOWN' 'PID ausente em coleta PARTIAL: UNKNOWN'
        $ac = @($res.Coverage | Where-Object { $_.Collector -eq 'agent-processes' })[0]
        Assert-True ($ac.Status -eq 'PARTIAL' -and $ac.Reasons -contains 'PROCESS_SNAPSHOT_INCOMPLETE' -and $ac.Reasons -contains 'IDENTITY_UNVERIFIED_CANDIDATES') "cobertura parcial: $($ac.Reasons -join ',')"
        # Failed collection: no process finding at all, sessions UNKNOWN, coverage FAILED.
        $failed = Get-AtmProcessCollection -Source { throw (New-Object System.UnauthorizedAccessException 'x') }
        $res = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $failed -ProviderHints $claude -SessionRegistries $regs
        Assert-Eq @($res.Findings | Where-Object { $_.Kind -eq 'Process' }).Count 0 'coleta com falha: nenhum processo afirmado'
        Assert-Eq (& $b4State $res (& $b4SKey 'claude-code' 's3')) 'UNKNOWN' 'coleta com falha: sessao UNKNOWN'
        Assert-Eq @($res.Coverage | Where-Object { $_.Collector -eq 'agent-processes' })[0].Status 'FAILED' 'cobertura FAILED'
        # Agent not installed: no process, empty registry. Nothing is claimed about the agent; coverage is conclusive
        # only because the collection is COMPLETE, and no finding says "not running".
        $noneRows = @((& $b4Row 4 0 'System' $b4T0.AddHours(-1)), (& $b4Row 100 4 'app.exe' $b4T0))
        $none = Get-AtmProcessCollection -Source ({ $noneRows }.GetNewClosure())
        $res = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $none -ProviderHints $claude -SessionRegistries $emptyReg
        Assert-Eq @($res.Findings).Count 0 'sem agente: nenhum achado'
        Assert-Eq @($res.Coverage | Where-Object { $_.Collector -eq 'agent-processes' })[0].Status 'COMPLETE' 'sem agente: coleta completa sem candidatos'
        Assert-Eq @($res.Coverage | Where-Object { $_.Collector -eq 'sessions-claude-code' })[0].Status 'COMPLETE' 'sem agente: registro vazio'
        # The real provider without the agent installed (no config directory): readable, no entries.
        $np = New-TestProfile 'b4none' -NoConfig
        $nr = Get-AtmClaudeSessionEvidence -ProfileInfo $np -Snapshot ([pscustomobject]@{ Failed = $false; Processes = @() })
        Assert-True ($nr.Readable -and @($nr.Entries).Count -eq 0) 'Claude Code nao instalado: registro legivel e vazio'
        # Provider read failures: an exception or an unreadable registry is FAILED, never an empty registry.
        $bad = @(
            [pscustomobject]@{ ProviderId = 'claude-code'; Registry = $null; Error = 'IOException' },
            [pscustomobject]@{ ProviderId = 'fake-agent'; Registry = [pscustomobject]@{ Readable = $false; Unparseable = 0; Entries = @() }; Error = $null },
            [pscustomobject]@{ ProviderId = 'fake-two'; Registry = [pscustomobject]@{ Readable = $true; Unparseable = 2; Entries = @() }; Error = $null },
            [pscustomobject]@{ ProviderId = 'Bad Id'; Registry = $null; Error = $null })
        $res = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $none -ProviderHints $claude -SessionRegistries $bad
        $sc = @{}; foreach ($cv in $res.Coverage) { $sc[$cv.Collector] = $cv }
        Assert-True ($sc['sessions-claude-code'].Status -eq 'FAILED' -and $sc['sessions-claude-code'].Reasons -contains 'EXCEPTION_IOEXCEPTION') 'excecao do provider: FAILED com o tipo'
        Assert-True ($sc['sessions-fake-agent'].Status -eq 'FAILED' -and $sc['sessions-fake-agent'].Reasons -contains 'SESSION_REGISTRY_UNREADABLE') 'registro ilegivel: FAILED'
        Assert-True ($sc['sessions-fake-two'].Status -eq 'PARTIAL' -and $sc['sessions-fake-two'].Reasons -contains 'SESSION_ENTRIES_UNPARSEABLE') 'entradas ilegiveis: PARTIAL'
        Assert-Eq $sc['sessions-invalid'].Status 'FAILED' 'provider invalido isolado'
        # A V0.1 provider with an upper-case Id (accepted by V0.1): its registry and path references are read; the real Id
        # stays in the finding, the collector name is lower case.
        $legacyUp = [pscustomobject]@{ Failed = $false; Processes = @([pscustomobject]@{ Pid = 100; Name = 'app.exe'; ParentPid = 4; CommandLine = $null; CreationUtc = $b4T0 }) }
        $partsUp = @([pscustomobject]@{ Provider = 'Fake-Upper-V1'; DirectRefs = @('PID 100 (app.exe)'); AncestorRefs = @() })
        $regUp = @([pscustomobject]@{ ProviderId = 'Fake-Upper-V1'; Registry = [pscustomobject]@{ Readable = $true; Unparseable = 0; Entries = @([pscustomobject]@{ SessionId = 'u1'; Pid = 100; StartUtc = $b4T0 }) }; Error = $null })
        $res = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $none -SessionRegistries $regUp -LegacySnapshot $legacyUp -Partitions $partsUp
        Assert-Eq (& $b4State $res (& $b4Key 100 $b4T0)) 'AGENT_PROCESS' 'provider v1 com Id em maiusculas: referencia e sessao lidas'
        Assert-Eq @($res.Findings | Where-Object { $_.Key -ceq (& $b4Key 100 $b4T0) })[0].Provider 'Fake-Upper-V1' 'Id real no achado'
        Assert-Eq @($res.Coverage | Where-Object { $_.Collector -eq 'sessions-fake-upper-v1' })[0].Status 'COMPLETE' 'coletor em minusculas'
        Assert-Eq (& $b4State $res (& $b4SKey 'Fake-Upper-V1' 'u1')) 'LIVE' 'sessao do provider v1'
        # The same PID twice in the V0.1 snapshot: the reference cannot be attributed (never guessed).
        $legacyDup = [pscustomobject]@{ Failed = $false; Processes = @($legacyUp.Processes[0], [pscustomobject]@{ Pid = 100; Name = 'app.exe'; ParentPid = 4; CommandLine = $null; CreationUtc = $b4T0.AddHours(-2) }) }
        $res = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $none -LegacySnapshot $legacyDup -Partitions $partsUp
        Assert-True ((& $b4State $res (& $b4Key 100 $b4T0)) -eq '(none)' -and @($res.Coverage | Where-Object { $_.Collector -eq 'agent-processes' })[0].Reasons -contains 'PATH_REFERENCE_UNVERIFIED') 'PID duplicado na V0.1: referencia nao atribuida'
        # A runtime provider with service hints only: no process was searched, so the agent coverage is not observable.
        $svcOnly = [pscustomobject]@{ ProviderId = 'fake-svc'; ProcessMatchers = @(); ServiceHints = @([pscustomobject]@{ Name = 'FakeSvc'; Role = $null }); VirtualizationHints = @(); Coverage = (New-AtmCoverage -Collector 'provider-fake-svc' -Status 'COMPLETE') }
        $res = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $none -ProviderHints @($svcOnly)
        Assert-Eq @($res.Coverage | Where-Object { $_.Collector -eq 'agent-processes' })[0].Status 'NOT_OBSERVABLE' 'sem matcher de processo: NOT_OBSERVABLE, nunca COMPLETE'
        # A hint member that throws (provider coverage FAILED) keeps the agent coverage below COMPLETE.
        $throwing = [pscustomobject]@{ Id = 'fake-throw'; DisplayName = 'F'; ContractVersion = 2; Capabilities = @('runtime'); GetProcessMatchers = { throw (New-Object System.IO.IOException 'x') } }
        $th = Get-AtmProviderRuntimeHints $throwing
        Assert-Eq $th.Coverage.Status 'FAILED' 'dica com excecao: FAILED'
        $res = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $none -ProviderHints @($th)
        $ac = @($res.Coverage | Where-Object { $_.Collector -eq 'agent-processes' })[0]
        Assert-True ($ac.Status -ne 'COMPLETE' -and $ac.Status -ne 'NOT_PRESENT' -and $ac.Reasons -contains 'PROVIDER_HINTS_INCOMPLETE') "dica com excecao nunca vira ausencia confirmada: $($ac.Status)"
        # No runtime source at all: not observable, never "no agent".
        $res = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $none
        Assert-True (@($res.Coverage | Where-Object { $_.Collector -eq 'agent-processes' })[0].Status -eq 'NOT_OBSERVABLE') 'sem fontes de runtime: NOT_OBSERVABLE'
        # A v1 provider has no runtime hints, and a runtime-only fictional provider takes part like any other.
        Assert-True ($null -eq (Get-AtmProviderRuntimeHints (ConvertTo-AtmTestV1Provider (Get-AtmProviders)[0]))) 'provider v1: sem dicas'
        $rtOnly = [pscustomobject]@{ Id = 'fake-runtime'; DisplayName = 'F'; ContractVersion = 2; Capabilities = @('runtime'); GetProcessMatchers = { @([pscustomobject]@{ ImageName = 'app.exe' }) } }
        $res = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $none -ProviderHints @(Get-AtmProviderRuntimeHints $rtOnly)
        Assert-Eq (& $b4State $res (& $b4Key 100 $b4T0)) 'AGENT_PROCESS' 'provider somente runtime ficticio'
        $threw = $false; try { $null = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $null } catch { $threw = $true }
        Assert-True $threw 'sem coleta: recusado'
    }
    Test-Case 'Diagnose' 'Cobertura de sessoes (P1-B4-b): um registro de sessoes FAILED ou PARTIAL impede agent-processes COMPLETE; evidencias positivas ficam, lacunas nunca viram ausencia' {
        $claude = @(& $b4Hints 'claude-code' @([pscustomobject]@{ ImageName = 'claude.exe'; CommandLineMarker = $null }))
        $rows = @((& $b4Row 4 0 'System' $b4T0.AddHours(-1)), (& $b4Row 200 4 'claude.exe' $b4T0), (& $b4Row 201 200 'bash.exe' $b4T0.AddMinutes(1)))
        $c = Get-AtmProcessCollection -Source ({ $rows }.GetNewClosure())
        $partialRows = @($rows) + @(& $b4Row 210 4 'nodate.exe' $null)
        $cp = Get-AtmProcessCollection -Source ({ $partialRows }.GetNewClosure())
        Assert-True ($c.Coverage.Status -eq 'COMPLETE' -and $cp.Coverage.Status -eq 'PARTIAL') 'coletas completa e parcial'
        $live = [pscustomobject]@{ SessionId = 's1'; Pid = 200; StartUtc = $b4T0 }
        $gone = [pscustomobject]@{ SessionId = 's9'; Pid = 7777; StartUtc = $b4T0 }
        $reg = { param($Readable, $Unparseable, $Entries, $Err) @([pscustomobject]@{ ProviderId = 'claude-code'; Registry = $(if ($Err) { $null } else { [pscustomobject]@{ Readable = $Readable; Unparseable = $Unparseable; Entries = @($Entries) } }); Error = $Err }) }
        $svcOnly = [pscustomobject]@{ ProviderId = 'fake-svc'; ProcessMatchers = @(); ServiceHints = @([pscustomobject]@{ Name = 'FakeSvc'; Role = $null }); VirtualizationHints = @(); Coverage = (New-AtmCoverage -Collector 'provider-fake-svc' -Status 'COMPLETE') }
        # Name = (collection, hints, registries, agent-processes status, required reason, sessions status, 200 state, s9 state)
        $cases = [ordered]@{
            'registro completo com sessao valida' = @($c, $claude, (& $reg $true 0 @($live, $gone) $null), 'COMPLETE', $null, 'COMPLETE', 'AGENT_PROCESS', 'SESSION_PROCESS_NOT_FOUND')
            'registro completo e vazio'           = @($c, $claude, (& $reg $true 0 @() $null), 'COMPLETE', $null, 'COMPLETE', 'AGENT_PROCESS', '(none)')
            'registro FAILED por excecao'         = @($c, $claude, (& $reg $true 0 @() 'IOException'), 'PARTIAL', 'SESSION_REGISTRY_INCOMPLETE', 'FAILED', 'AGENT_PROCESS', '(none)')
            'registro PARTIAL (entradas ilegiveis)' = @($c, $claude, (& $reg $true 2 @($live, $gone) $null), 'PARTIAL', 'SESSION_REGISTRY_INCOMPLETE', 'PARTIAL', 'AGENT_PROCESS', 'UNKNOWN')
            'registro nao legivel'                = @($c, $claude, (& $reg $false 0 @() $null), 'PARTIAL', 'SESSION_REGISTRY_INCOMPLETE', 'FAILED', 'AGENT_PROCESS', '(none)')
            'snapshot parcial'                    = @($cp, $claude, (& $reg $true 0 @($live, $gone) $null), 'PARTIAL', 'PROCESS_SNAPSHOT_INCOMPLETE', 'COMPLETE', 'AGENT_PROCESS', 'UNKNOWN')
            'hints sem fonte de sessao'           = @($c, $claude, @(), 'COMPLETE', $null, '(none)', 'AGENT_PROCESS', '(none)')
            'somente servico'                     = @($c, @($svcOnly), @(), 'NOT_OBSERVABLE', 'NO_RUNTIME_EVIDENCE_SOURCE', '(none)', '(none)', '(none)')
            'somente servico, registro FAILED'    = @($c, @($svcOnly), (& $reg $true 0 @() 'IOException'), 'PARTIAL', 'SESSION_REGISTRY_INCOMPLETE', 'FAILED', '(none)', '(none)')
        }
        foreach ($n in $cases.Keys) {
            $v = $cases[$n]
            $res = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $v[0] -ProviderHints $v[1] -SessionRegistries $v[2]
            $ac = @($res.Coverage | Where-Object { $_.Collector -eq 'agent-processes' })[0]
            $sc = @($res.Coverage | Where-Object { $_.Collector -eq 'sessions-claude-code' })
            Assert-Eq $ac.Status $v[3] "$($n): agent-processes"
            if ($v[4]) { Assert-True (@($ac.Reasons) -ccontains $v[4]) "$($n): motivo $($v[4]) em $(@($ac.Reasons) -join ',')" }
            else { Assert-Eq @($ac.Reasons).Count 0 "$($n): sem motivos" }
            Assert-Eq $(if ($sc.Count -eq 1) { $sc[0].Status } else { '(none)' }) $v[5] "$($n): sessions-claude-code"
            Assert-Eq (& $b4State $res (& $b4Key 200 $b4T0)) $v[6] "$($n): evidencia positiva do processo 200 preservada"
            Assert-Eq (& $b4State $res (& $b4SKey 'claude-code' 's9')) $v[7] "$($n): sessao com PID ausente"
            foreach ($f in @($res.Findings | Where-Object { $_.Kind -eq 'Process' })) { Assert-True (@($f.Coverage | Where-Object { $_.Collector -eq 'agent-processes' })[0].Status -eq $ac.Status) "$($n): achado carrega a cobertura agent-processes" }
        }
        # The V0.1 audit reading of the same registry is untouched: the session State still comes from the V0.1 rule.
        $p = New-TestProfile 'b4cov'
        [IO.File]::WriteAllText((Join-Path (Join-Path $p.ProfilePath '.claude') 'sessions\200.json'), "{`"pid`":200,`"sessionId`":`"11111111-2222-3333-4444-555555555555`",`"procStart`":`"$($b4T0.ToFileTimeUtc())`"}")
        [IO.File]::WriteAllText((Join-Path (Join-Path $p.ProfilePath '.claude') 'sessions\bad.json'), 'not json')
        $v01 = Get-AtmClaudeSessionEvidence -ProfileInfo $p -Snapshot ([pscustomobject]@{ Failed = $false; Processes = @([pscustomobject]@{ Pid = 200; Name = 'claude.exe'; ParentPid = 4; CommandLine = $null; CreationUtc = $b4T0 }) })
        Assert-True ($v01.Readable -and $v01.Unparseable -eq 1 -and @($v01.Entries).Count -eq 1 -and $v01.Entries[0].State -eq 'LIVE') 'auditoria V0.1: mesma leitura e mesmo estado'
    }
    Test-Case 'Diagnose' 'Varios providers no mesmo PID (P1-B4-b): um achado por processo, provider so com atribuicao unica, ambiguidade explicita, resultado independente da ordem' {
        $rows = @(
            (& $b4Row 4 0 'System' $b4T0.AddHours(-1)),
            (& $b4Row 1000 4 'explorer.exe' $b4T0.AddMinutes(-30)),
            (& $b4Row 200 1000 'claude.exe' $b4T0),
            (& $b4Row 201 200 'bash.exe' $b4T0.AddMinutes(1)),
            (& $b4Row 300 1000 'shared.exe' $b4T0.AddMinutes(2)),
            (& $b4Row 301 300 'child.exe' $b4T0.AddMinutes(3)),
            (& $b4Row 400 1000 'helper.exe' $b4T0.AddMinutes(4)),
            (& $b4Row 450 1000 'tool.exe' $b4T0.AddMinutes(5)),
            (& $b4Row 500 1000 'nodate.exe' $null),
            (& $b4Row 600 1000 'markeragent.exe' $b4T0.AddMinutes(6)))
        $c = Get-AtmProcessCollection -Source ({ $rows }.GetNewClosure())
        $k = @{}; foreach ($r in $rows) { if ($null -ne $r.CreationDate) { $k[[int]$r.ProcessId] = & $b4Key $r.ProcessId $r.CreationDate } }
        $hints = @(
            (& $b4Hints 'claude-code' @([pscustomobject]@{ ImageName = 'claude.exe'; CommandLineMarker = $null })),
            (& $b4Hints 'fake-a' @([pscustomobject]@{ ImageName = 'shared.exe'; CommandLineMarker = $null })),
            (& $b4Hints 'fake-b' @([pscustomobject]@{ ImageName = 'shared.exe'; CommandLineMarker = $null }, [pscustomobject]@{ ImageName = 'markeragent.exe'; CommandLineMarker = '--fake-marker' })))
        # PID 600 appears twice in the V0.1 snapshot (one entry with the exact ticks and the marker): ambiguous, so the
        # marker is never checked against it.
        $legacy = [pscustomobject]@{ Failed = $false; Processes = @(
                [pscustomobject]@{ Pid = 400; Name = 'helper.exe'; ParentPid = 1000; CommandLine = 'helper.exe'; CreationUtc = $b4T0.AddMinutes(4) },
                [pscustomobject]@{ Pid = 450; Name = 'tool.exe'; ParentPid = 1000; CommandLine = 'tool.exe'; CreationUtc = $b4T0.AddMinutes(5) },
                [pscustomobject]@{ Pid = 500; Name = 'nodate.exe'; ParentPid = 1000; CommandLine = 'nodate.exe'; CreationUtc = $b4T0.AddMinutes(7) },
                [pscustomobject]@{ Pid = 600; Name = 'markeragent.exe'; ParentPid = 1000; CommandLine = 'markeragent.exe --fake-marker'; CreationUtc = $b4T0.AddMinutes(6) },
                [pscustomobject]@{ Pid = 600; Name = 'markeragent.exe'; ParentPid = 1000; CommandLine = 'markeragent.exe'; CreationUtc = $b4T0.AddMinutes(-9) }) }
        $parts = @(
            [pscustomobject]@{ Provider = 'claude-code'; DirectRefs = @('PID 400 (helper.exe)', 'PID 450 (tool.exe)'); AncestorRefs = @() },
            [pscustomobject]@{ Provider = 'claude-code'; DirectRefs = @('PID 450 (tool.exe)'); AncestorRefs = @('PID 500 (nodate.exe) -> projeto') },
            [pscustomobject]@{ Provider = 'fake-a'; DirectRefs = @(); AncestorRefs = @('PID 400 (helper.exe) -> projeto') },
            [pscustomobject]@{ Provider = 'fake-b'; DirectRefs = @('PID 500 (nodate.exe)'); AncestorRefs = @() })
        $regs = @([pscustomobject]@{ ProviderId = 'claude-code'; Registry = [pscustomobject]@{ Readable = $true; Unparseable = 0; Entries = @([pscustomobject]@{ SessionId = 's1'; Pid = 200; StartUtc = $b4T0 }) }; Error = $null })
        $invCov = @(New-AtmCoverage -Collector 'inventory' -Status 'COMPLETE')
        $res = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $c -ProviderHints $hints -SessionRegistries $regs -LegacySnapshot $legacy -Partitions $parts -InventoryCoverage $invCov
        $one = { param([string]$Key) $f = @($res.Findings | Where-Object { $_.Key -ceq $Key }); Assert-Eq $f.Count 1 "um achado por processo: $Key"; $f[0] }
        $amb = { param($F) @($F.Evidence | Where-Object { $_.Code -ceq 'PROVIDER_ATTRIBUTION_AMBIGUOUS' } | ForEach-Object { $_.Detail }) -join ';' }
        # One PID, one provider (matcher and session of the same provider): attributed, no ambiguity; its descendant too.
        $f = & $one $k[200]
        Assert-True ($f.State -eq 'AGENT_PROCESS' -and $f.Provider -ceq 'claude-code' -and (& $amb $f) -eq '') 'um PID e um provider'
        $f = & $one $k[201]
        Assert-True ($f.State -eq 'AGENT_DESCENDANT' -and $f.Provider -ceq 'claude-code') 'descendente do provider unico'
        # One PID referenced by partitions of two providers: agent-related, provider not chosen, ambiguity stated.
        $f = & $one $k[400]
        Assert-True ($f.State -eq 'AGENT_PROCESS' -and $null -eq $f.Provider -and (& $amb $f) -ceq 'claude-code,fake-a') "PID de dois providers: $($f.Provider) / $(& $amb $f)"
        Assert-Eq @($f.Evidence | Where-Object { $_.Code -ceq 'PATH_REFERENCE' }).Count 1 'uma evidencia de referencia, nao duplicada'
        # Two partitions of the same provider: one provider, one evidence item.
        $f = & $one $k[450]
        Assert-True ($f.State -eq 'AGENT_PROCESS' -and $f.Provider -ceq 'claude-code' -and (& $amb $f) -eq '' -and @($f.Evidence).Count -eq 1) 'duas particoes do mesmo provider'
        # Two providers whose matchers match the same process; its descendant inherits the ambiguity.
        $f = & $one $k[300]
        Assert-True ($f.State -eq 'AGENT_PROCESS' -and $null -eq $f.Provider -and (& $amb $f) -ceq 'fake-a,fake-b' -and @($f.Evidence | Where-Object { $_.Code -ceq 'PROCESS_MATCHER_IMAGE' }).Count -eq 1) 'dois matchers no mesmo processo'
        Assert-Eq (@($f.Coverage | ForEach-Object { $_.Collector }) -join ',') 'process-snapshot,agent-processes,provider-fake-a,provider-fake-b' 'cobertura das duas fontes'
        $f = & $one $k[301]
        Assert-True ($f.State -eq 'AGENT_DESCENDANT' -and $null -eq $f.Provider -and (& $amb $f) -ceq 'fake-a,fake-b') 'descendente de raiz ambigua'
        # A path reference with an uncertain identity (no creation time) referenced by two providers: unverified, unattributed.
        $f = & $one 'pid:500'
        Assert-True ($f.State -eq 'IDENTITY_UNVERIFIED' -and $null -eq $f.Provider -and (& $amb $f) -ceq 'claude-code,fake-b') 'referencia com identidade incerta'
        # Duplicate PID in the V0.1 snapshot: the marker is not checked (inconclusive), never confirmed by the ambiguous entry.
        Assert-True ($null -eq (Get-AtmLegacyCommandLine -LegacySnapshot $legacy -Process $c.ByPid[[long]600])) 'linha de comando com PID duplicado na V0.1: nao usada'
        Assert-True ($null -ne (Get-AtmLegacyCommandLine -LegacySnapshot $legacy -Process $c.ByPid[[long]450])) 'PID unico com ticks exatos: usada'
        $sameTicks = [pscustomobject]@{ Failed = $false; Processes = @($legacy.Processes[1], $legacy.Processes[1]) }
        Assert-True ($null -eq (Get-AtmLegacyCommandLine -LegacySnapshot $sameTicks -Process $c.ByPid[[long]450])) 'mesmo PID e mesmos ticks duas vezes: nao usada'
        $f = & $one $k[600]
        Assert-True ($f.State -eq 'UNKNOWN' -and @($f.Evidence | Where-Object { $_.Code -ceq 'COMMAND_LINE_MARKER_UNAVAILABLE' }).Count -eq 1) 'marcador com PID duplicado: inconclusivo'
        # The order of providers, registries, partitions and references does not change the result.
        $sig = { param($R)
            $fs = @($R.Findings | ForEach-Object { '{0}|{1}|{2}|{3}|{4}|{5}' -f $_.Kind, $_.Key, $_.State, $_.Provider, (@($_.Evidence | ForEach-Object { "$($_.Code)/$($_.Source)/$($_.Collector)/$($_.Detail)" }) -join '+'), (@($_.Coverage | ForEach-Object { "$($_.Collector)=$($_.Status)" }) -join '+') })
            $cs = @($R.Coverage | ForEach-Object { '{0}={1}:{2}' -f $_.Collector, $_.Status, (@($_.Reasons | Sort-Object) -join '+') } | Sort-Object)
            $ts = @($R.Trees | ForEach-Object { '{0}|{1}|{2}' -f $_.RootKey, $_.Provider, (@($_.Tree.Members | Sort-Object) -join '+') })
            (@($fs) + '#' + @($cs) + '#' + @($ts)) -join "`n" }
        $revParts = @($parts[3..0] | ForEach-Object { [pscustomobject]@{ Provider = $_.Provider; DirectRefs = @($_.DirectRefs[($_.DirectRefs.Count - 1)..0] | Where-Object { $_ }); AncestorRefs = @($_.AncestorRefs) } })
        $res2 = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $c -ProviderHints @($hints[2..0]) -SessionRegistries $regs -LegacySnapshot $legacy -Partitions $revParts -InventoryCoverage $invCov
        Assert-Eq (& $sig $res2) (& $sig $res) 'ordem invertida: mesmo resultado (achados, evidencias, cobertura, arvores)'
        $ac = @($res.Coverage | Where-Object { $_.Collector -eq 'agent-processes' })[0]
        Assert-True ($ac.Status -eq 'PARTIAL' -and @($ac.Reasons) -ccontains 'IDENTITY_UNVERIFIED_CANDIDATES' -and @($ac.Reasons) -ccontains 'COMMAND_LINE_MARKER_UNAVAILABLE') "cobertura reflete as lacunas: $(@($ac.Reasons) -join ',')"
        $json = (@{ F = $res.Findings; C = $res.Coverage } | ConvertTo-Json -Depth 10)
        Assert-True (-not $json.Contains('--fake-marker')) 'marcador nunca no resultado'
    }
    $diagIdUser = { [pscustomobject]@{ Name = 'TEST\alice'; Sid = 'S-1-5-21-1-2-3-1001'; IsAdmin = $false; ElevationTypeRaw = 3; IntegrityRid = 0x2000; SessionId = 1 } }
    $diagIdAdmin = { [pscustomobject]@{ Name = 'TEST\admin'; Sid = 'S-1-5-21-1-2-3-500'; IsAdmin = $true; ElevationTypeRaw = 2; IntegrityRid = 0x3000; SessionId = 1 } }
    # P1-B4-c fixtures: one agent tree with a nested claude.exe, this run (SELF) under it, and the V0.1 rows of the
    # same processes (same PID and time; every command line readable, one with a planted marker).
    $b4cMarker = 'ATM' + 'PLANTED' + 'B4C'
    $b4cRows = @(
        (& $b4Row 4 0 'System' $b4T0.AddHours(-1)),
        (& $b4Row 1000 4 'explorer.exe' $b4T0.AddMinutes(-30)),
        (& $b4Row 200 1000 'claude.exe' $b4T0),
        (& $b4Row 201 200 'bash.exe' $b4T0.AddMinutes(1)),
        (& $b4Row 202 200 'claude.exe' $b4T0.AddMinutes(2)),
        (& $b4Row 203 202 'node.exe' $b4T0.AddMinutes(3)),
        (& $b4Row 3000 201 'powershell.exe' $b4T0.AddMinutes(5)),
        (& $b4Row 3001 3000 'conhost.exe' $b4T0.AddMinutes(5).AddSeconds(1)))
    $b4cLegacy = @($b4cRows | ForEach-Object { [pscustomobject]@{ ProcessId = $_.ProcessId; Name = $_.Name; ParentProcessId = $_.ParentProcessId; CommandLine = $(if ($_.ProcessId -eq 202) { "claude.exe --resume $b4cMarker" } else { [string]$_.Name }); CreationDate = $_.CreationDate } })
    $b4cSession = { param($ProfileInfo, [int]$ProcessId, [string]$SessionId, $Start)
        [IO.File]::WriteAllText((Join-Path (Join-Path $ProfileInfo.ProfilePath '.claude') "sessions\$ProcessId.json"), "{`"pid`":$ProcessId,`"sessionId`":`"$SessionId`",`"procStart`":`"$(([datetime]$Start).ToFileTimeUtc())`"}") }
    Test-Case 'Diagnose' 'Runtime integrado (P1-B4-c): processos, sessoes por perfil, SELF, arvores aninhadas contadas uma vez, cobertura, JSON nos dois idiomas e relatorio; SessionId nunca exportado nas chaves de sessao' {
        $sid = [guid]::NewGuid().ToString()
        $p1 = New-TestProfile 'b4c1'; $p2 = New-TestProfile 'b4c2'
        # The same UUID is a session id and a temporary root (as Claude Code does): the partition path carries it.
        $root = New-TestRoot -ProfileInfo $p1 -Uuid $sid
        & $b4cSession $p1 200 $sid $b4T0
        & $b4cSession $p2 7777 $sid $b4T0
        $rows = $b4cRows
        $src = { $rows }.GetNewClosure()
        $run = { param($Key) Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p1, $p2) -Procs $b4cLegacy) -IdentitySource $diagIdUser -Providers @((Get-AtmProviders)[0]) -ProcessSource $src -SelfPid 3000 -SelfCreationUtc $b4T0.AddMinutes(5) -PseudonymKey $Key }
        $d = & $run $testPseudonymKey
        $k = @{}; foreach ($r in $b4cRows) { $k[[int]$r.ProcessId] = & $b4Key $r.ProcessId $r.CreationDate }
        $cs = @{}; foreach ($c in $d.Coverage) { $cs[$c.Collector] = $c }
        foreach ($c in @('process-snapshot', 'sessions-claude-code', 'agent-processes', 'agent-resources')) { Assert-Eq $cs[$c].Status 'COMPLETE' "$c completo: $(@($cs[$c].Reasons) -join ',')" }
        Assert-Eq @($d.Coverage | Where-Object { $_.Collector -like 'sessions-*' }).Count 1 'um registro de sessoes por provider (dois perfis)'
        # P1-C: working directories are not observed and open files are a sample, so a diagnose is never complete.
        Assert-True (-not $d.CoverageComplete -and (@($d.Coverage | Where-Object { $script:AtmConclusiveCoverage -cnotcontains $_.Status } | Where-Object { $_.Collector -notlike 'virtual*' } | ForEach-Object { $_.Collector } | Sort-Object) -join ',') -eq 'handles,process-cwd,service-properties,services,worktree-discovery') 'cobertura incompleta so por diretorios de trabalho, arquivos abertos (trava), servicos (nenhum declarado) e worktrees (trava); virtualizacao depende da maquina'
        $expect = @{ 200 = 'AGENT_PROCESS'; 202 = 'AGENT_PROCESS'; 201 = 'AGENT_DESCENDANT'; 203 = 'AGENT_DESCENDANT'; 3000 = 'SELF'; 3001 = 'SELF'; 1000 = '(none)'; 4 = '(none)' }
        foreach ($e in $expect.GetEnumerator()) { Assert-Eq (& $b4State $d $k[[int]$e.Key]) $e.Value "processo $($e.Key)" }
        # Sessions: one key per profile for the same session id; LIVE (exact identity) and absent from a complete collection.
        $k1 = ConvertTo-AtmSessionKey -Pseudonymizer $b4Pz -Provider 'claude-code' -ProfileSid $p1.Sid -ProfilePath $p1.ProfilePath -SessionId $sid
        $k2 = ConvertTo-AtmSessionKey -Pseudonymizer $b4Pz -Provider 'claude-code' -ProfileSid $p2.Sid -ProfilePath $p2.ProfilePath -SessionId $sid
        Assert-True ($k1 -cmatch '^claude-code/s-[0-9a-f]{32}$' -and $k1 -cne $k2) "chaves pseudonimas distintas por perfil: $k1 / $k2"
        Assert-Eq (& $b4State $d $k1) 'LIVE' 'sessao viva do perfil 1'
        Assert-Eq (& $b4State $d $k2) 'SESSION_PROCESS_NOT_FOUND' 'mesma sessao no perfil 2: PID ausente de coleta completa'
        # Totals over the union: 200, 201, 202, 203 once each (the trees of 200 and 202 overlap); SELF excluded.
        $t = $d.AgentResources
        Assert-True ($t.Processes -eq 4 -and $t.Complete -and $t.Counters.WorkingSetBytes.Sum -eq 4000 -and $t.Counters.WorkingSetBytes.Complete) "totais da uniao: $($t.Processes) processos, $($t.Counters.WorkingSetBytes.Sum) bytes, $(@($t.Reasons) -join ',')"
        Assert-True ($t.Counters.CpuPercent.Complete -and $t.Counters.CpuPercent.Sum -eq 0 -and $t.CpuIntervalMs -ge 400) "CPU amostrada (~500 ms): $($t.CpuIntervalMs) ms"
        $naive = 0; foreach ($tree in @($d.Findings | Where-Object { $_.State -eq 'AGENT_PROCESS' })) { $naive += @(Get-AtmProcessTree -Collection (Get-AtmProcessCollection -Source $src) -RootKey $tree.Key).Members.Count }
        Assert-True ($naive -gt $t.Processes) "arvores sobrepostas somariam $naive, a uniao conta $($t.Processes)"
        # Order: temporary partitions first (V0.1 order), then runtime findings by Kind and Key (ordinal).
        $kinds = @($d.Findings | ForEach-Object { $_.Kind })
        $firstRt = [array]::IndexOf($kinds, 'AgentSession')
        Assert-True ($firstRt -gt 0 -and @($kinds[0..($firstRt - 1)] | Where-Object { $_ -ne 'TempPartition' }).Count -eq 0) 'particoes antes dos achados de runtime'
        $rt = @($d.Findings | Where-Object { $_.Kind -ne 'TempPartition' } | ForEach-Object { $_.Kind + [char]1 + $_.Key })
        $sorted = [string[]]@($rt); [Array]::Sort($sorted, [StringComparer]::Ordinal)
        Assert-Eq ($rt -join '|') ($sorted -join '|') 'runtime ordenado por Kind e Key'
        # Same session, same profile: the same key in another run with the same operator key; another key without it.
        $d2 = & $run $testPseudonymKey
        Assert-Eq (& $b4State $d2 $k1) 'LIVE' 'mesma chave entre execucoes com o mesmo arquivo de chave'
        $d3 = & $run $null
        Assert-True ((& $b4State $d3 $k1) -eq '(none)' -and @($d3.Findings | Where-Object { $_.Kind -eq 'AgentSession' -and $_.State -eq 'LIVE' }).Count -eq 1) 'sem arquivo de chave: outra chave (efemera), mesmo estado'
        # JSON: identical in both languages; agentResources; the session id is in no runtime finding.
        $old = Get-AtmLanguage
        try { Set-AtmLanguage -Requested 'en-US'; $en = ConvertTo-AtmDiagnoseJson -Result $d; $txt = (Show-AtmDiagnose -Result $d 6>&1 | Out-String); Set-AtmLanguage -Requested 'pt-BR'; $pt = ConvertTo-AtmDiagnoseJson -Result $d; $txtPt = (Show-AtmDiagnose -Result $d 6>&1 | Out-String) } finally { Set-AtmLanguage -Requested $old }
        Assert-Eq ($en -replace '"language":\s*"[^"]*"', '') ($pt -replace '"language":\s*"[^"]*"', '') 'JSON identico nos dois idiomas (exceto language)'
        $j = $en | ConvertFrom-Json
        Assert-True ($j.agentResources.collected -and $j.agentResources.processes -eq 4 -and $j.agentResources.counters.workingSetBytes.sum -eq 4000 -and $j.agentResources.counters.cpuPercent.complete) 'agentResources no JSON'
        $rtJson = (@($j.findings | Where-Object { $_.kind -ne 'TempPartition' }) | ConvertTo-Json -Depth 8)
        Assert-True (-not $rtJson.Contains($sid)) 'SessionId original nunca nos achados de runtime'
        Assert-True (@($j.findings | Where-Object { $_.kind -eq 'AgentSession' -and $_.key -notmatch '^claude-code/s-[0-9a-f]{32}$' }).Count -eq 0) 'chaves de sessao pseudonimas'
        # P1-B4-d (ADR-0010): the partition named after the session is a keyed pseudonym; the session id and the paths
        # are nowhere in the export.
        Assert-True (@($j.findings | Where-Object { $_.kind -eq 'TempPartition' }).Count -ge 1 -and @($j.findings | Where-Object { $_.kind -eq 'TempPartition' -and $_.key -cnotmatch '^claude-code/p-[0-9a-f]{32}$' }).Count -eq 0) 'particoes com chave pseudonima'
        Assert-True (@($j.findings | Where-Object { $_.kind -eq 'TempPartition' -and $_.key -ceq (& $b4PKey $root) }).Count -eq 1) 'particao da sessao pela chave calculada'
        foreach ($x in @($sid, $root, $p1.ProfilePath, $p2.ProfilePath)) { Assert-True (-not $en.Contains($x) -and -not $en.Contains($x.Replace('\', '\\'))) 'nenhum id de sessao nem caminho no JSON' }
        foreach ($x in @($en, $txt, $txtPt)) { Assert-True (-not $x.Contains($b4cMarker)) 'marcador plantado nunca exportado'; Assert-True (-not $x.Contains('--resume')) 'argumentos nunca exportados' }
        foreach ($x in @($txt, $txtPt)) { Assert-True (-not $x.Contains($sid)) 'SessionId original nunca no relatorio' }
        Assert-True ($txt.Contains('AGENT RUNTIME') -and $txt.Contains('provider claude-code: 4 agent process(es)') -and $txt.Contains('processes counted: 4')) 'relatorio en-US: secao, atribuicao e totais'
        $flat = $txt -replace '\s+', ' '
        Assert-True ($flat.Contains('it never means that no other agent exists') -and $flat.Contains('No runtime classification frees, authorizes or blocks the deletion')) 'relatorio: escopo dos matchers e nenhuma autorizacao de exclusao'
        Assert-True ($txtPt.Contains('RUNTIME DE AGENTES') -and -not $txt.Contains('RUNTIME DE AGENTES')) 'relatorio nos dois idiomas'
        Assert-True ($txt.Contains('SESSION_PROCESS_MATCH: process of a live session')) 'legenda das evidencias'
        # A v1 provider (same session registry shape) next to the v2 one: its sessions are read too; the process both
        # name is agent-related with an ambiguous attribution, one finding.
        $v1 = ConvertTo-AtmTestV1Provider (Get-AtmProviders)[0]; $v1.Id = 'Fake-Upper-V1'; $v1.TempSubdir = 'fake-upper'
        $dv = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p1, $p2) -Procs $b4cLegacy) -IdentitySource $diagIdUser -Providers @((Get-AtmProviders)[0], $v1) -ProcessSource $src -SelfPid 3000 -SelfCreationUtc $b4T0.AddMinutes(5) -CpuSampleMs 0 -PseudonymKey $testPseudonymKey
        $f200 = @($dv.Findings | Where-Object { $_.Key -ceq $k[200] })
        Assert-True ($f200.Count -eq 1 -and $f200[0].State -eq 'AGENT_PROCESS' -and $null -eq $f200[0].Provider -and @($f200[0].Evidence | Where-Object { $_.Code -eq 'PROVIDER_ATTRIBUTION_AMBIGUOUS' -and $_.Detail -ceq 'Fake-Upper-V1,claude-code' }).Count -eq 1) 'providers v1 e v2 no mesmo processo: um achado, ambiguo'
        Assert-Eq (@($dv.Coverage | Where-Object { $_.Collector -like 'sessions-*' } | ForEach-Object { $_.Collector }) -join ',') 'sessions-claude-code,sessions-fake-upper-v1' 'um registro por provider, em ordem'
        Assert-True (-not $dv.AgentResources.Complete -and @($dv.AgentResources.Reasons) -contains 'CPU_NOT_SAMPLED' -and $null -eq $dv.AgentResources.Counters.CpuPercent.Sum) 'CPU nao amostrada: parcial, nunca 0'
    }
    Test-Case 'Diagnose' 'Sessoes (P1-B4-c): perfis agregados num registro por provider, colisao de chave e entradas conflitantes ficam UNKNOWN sem sobrescrever, evidencia positiva mantida, ordem das entradas irrelevante' {
        # GetNewClosure captures only local variables: the shared rows are copied into one first.
        $rows = $b4cRows
        $c = Get-AtmProcessCollection -Source ({ $rows }.GetNewClosure())
        $claude = @(& $b4Hints 'claude-code' @([pscustomobject]@{ ImageName = 'claude.exe'; CommandLineMarker = $null }))
        $reg = { param($Sid, $Path, $Entries, $Readable = $true, $Unparseable = 0) [pscustomobject]@{ ProviderId = 'claude-code'; Registry = [pscustomobject]@{ Readable = $Readable; Unparseable = $Unparseable; Entries = @($Entries) }; Error = $null; ProfileSid = $Sid; ProfilePath = $Path } }
        $e = { param($Session, $ProcessId, $Start) [pscustomobject]@{ SessionId = $Session; Pid = $ProcessId; StartUtc = $Start } }
        $okA = & $reg 'S-1-5-21-9' 'D:\profiles\a' @((& $e 'AAA' 200 $b4T0))
        $okB = & $reg 'S-1-5-21-9' 'D:\profiles\b' @((& $e 'AAA' 7777 $b4T0))
        $bad = & $reg 'S-1-5-21-9' 'D:\profiles\c' @() $false
        $sk = @{ a = (ConvertTo-AtmSessionKey -Pseudonymizer $b4Pz -Provider 'claude-code' -ProfileSid 'S-1-5-21-9' -ProfilePath 'D:\profiles\a' -SessionId 'aaa'); b = (ConvertTo-AtmSessionKey -Pseudonymizer $b4Pz -Provider 'claude-code' -ProfileSid 'S-1-5-21-9' -ProfilePath 'D:\profiles\b\' -SessionId ' AAA ') }
        Assert-True ($sk.a -cne $sk.b) 'mesmo SessionId e SID, perfis diferentes: chaves diferentes'
        Assert-Eq (ConvertTo-AtmSessionKey -Pseudonymizer $b4Pz -Provider 'Claude-Code' -ProfileSid 'S-1-5-21-9' -ProfilePath 'D:\PROFILES\A\' -SessionId 'AAA') $sk.a 'normalizacao: caixa, separador final e espacos'
        Assert-True ((ConvertTo-AtmSessionKey -Pseudonymizer $b4Pz -Provider 'claude-code' -ProfileSid 'S-1-5-21-9a' -ProfilePath 'D:\profiles\a' -SessionId 'aaa') -cne (ConvertTo-AtmSessionKey -Pseudonymizer $b4Pz -Provider 'claude-code' -ProfileSid 'S-1-5-21-9' -ProfilePath 'aD:\profiles\a' -SessionId 'aaa')) 'campos com separacao inequivoca'
        $res = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $c -ProviderHints $claude -SessionRegistries @($okA, $okB, $bad)
        $rc = @($res.Coverage | Where-Object { $_.Collector -eq 'sessions-claude-code' })
        Assert-True ($rc.Count -eq 1 -and $rc[0].Status -eq 'PARTIAL' -and @($rc[0].Reasons) -contains 'SESSION_REGISTRY_UNREADABLE' -and $rc[0].Observed -eq 2) "um perfil ilegivel de tres: PARTIAL ($($rc[0].Status) $(@($rc[0].Reasons) -join ','))"
        Assert-True ((& $b4State $res $sk.a) -eq 'LIVE' -and (& $b4State $res $sk.b) -eq 'UNKNOWN') 'registro parcial: ausencia vira UNKNOWN, LIVE mantido'
        $res = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $c -ProviderHints $claude -SessionRegistries @($bad, (& $reg 'S-1-5-21-9' 'D:\profiles\d' @() $true 0 | ForEach-Object { $_.Registry = $null; $_.Error = 'IOException'; $_ }))
        Assert-Eq @($res.Coverage | Where-Object { $_.Collector -eq 'sessions-claude-code' })[0].Status 'FAILED' 'todos os perfis falharam: FAILED'
        $deadlineItem = [pscustomobject]@{ ProviderId = 'claude-code'; Registry = $null; Error = $null; Reason = 'DEADLINE_EXCEEDED'; ProfileSid = 'S-1-5-21-9'; ProfilePath = 'D:\profiles\e' }
        $res = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $c -ProviderHints $claude -SessionRegistries @($okA, $deadlineItem)
        $rc = @($res.Coverage | Where-Object { $_.Collector -eq 'sessions-claude-code' })[0]
        Assert-True ($rc.Status -eq 'PARTIAL' -and @($rc.Reasons) -contains 'DEADLINE_EXCEEDED') 'perfil nao lido por prazo: PARTIAL'
        # A forced collision (test key function): never an overwritten finding; one UNKNOWN finding with the reason;
        # the process proven by the LIVE entry stays agent-related.
        $same = { param($Provider, $ProfileSid, $ProfilePath, $SessionId) 'claude-code/s-' + ('0' * 32) }
        $res = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $c -ProviderHints $claude -SessionRegistries @($okA, $okB) -SessionKeyFunction $same
        $f = @($res.Findings | Where-Object { $_.Kind -eq 'AgentSession' })
        Assert-True ($f.Count -eq 1 -and $f[0].State -eq 'UNKNOWN' -and @($f[0].Evidence | Where-Object { $_.Code -eq 'SESSION_KEY_COLLISION' }).Count -eq 1) 'colisao: um achado UNKNOWN com a evidencia'
        $rc = @($res.Coverage | Where-Object { $_.Collector -eq 'sessions-claude-code' })[0]
        Assert-True ($rc.Status -eq 'PARTIAL' -and @($rc.Reasons) -contains 'SESSION_KEY_COLLISION') 'colisao registrada na cobertura'
        Assert-Eq (& $b4State $res (& $b4Key 200 $b4T0)) 'AGENT_PROCESS' 'evidencia positiva mantida na colisao'
        # One session listed with two PIDs in the same profile: conflict, UNKNOWN.
        $conf = & $reg 'S-1-5-21-9' 'D:\profiles\a' @((& $e 'BBB' 200 $b4T0), (& $e 'BBB' 201 $b4T0.AddMinutes(1)))
        $res = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $c -ProviderHints $claude -SessionRegistries @($conf)
        $kb = ConvertTo-AtmSessionKey -Pseudonymizer $b4Pz -Provider 'claude-code' -ProfileSid 'S-1-5-21-9' -ProfilePath 'D:\profiles\a' -SessionId 'bbb'
        Assert-True ((& $b4State $res $kb) -eq 'UNKNOWN' -and @(@($res.Findings | Where-Object { $_.Key -ceq $kb })[0].Evidence | Where-Object { $_.Code -eq 'SESSION_ENTRIES_CONFLICT' }).Count -eq 1) 'entradas conflitantes: UNKNOWN'
        $dup = & $reg 'S-1-5-21-9' 'D:\profiles\a' @((& $e 'CCC' 200 $b4T0), (& $e 'CCC' 200 $b4T0))
        $res = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $c -ProviderHints $claude -SessionRegistries @($dup)
        Assert-Eq @($res.Coverage | Where-Object { $_.Collector -eq 'sessions-claude-code' })[0].Status 'COMPLETE' 'entrada repetida identica lida uma vez'
        # The order of registries, entries and SELF keys does not change the literal result.
        $self = Get-AtmSelfProcessKeys -Collection $c -SelfPid 3000 -SelfCreationUtc $b4T0.AddMinutes(5)
        $selfRev = [pscustomobject]@{ Keys = @($self.Keys[($self.Keys.Count - 1)..0]); Unverified = @() }
        $two = & $reg 'S-1-5-21-9' 'D:\profiles\a' @((& $e 'AAA' 200 $b4T0), (& $e 'DDD' 202 $b4T0.AddMinutes(2)))
        $twoRev = & $reg 'S-1-5-21-9' 'D:\profiles\a' @((& $e 'DDD' 202 $b4T0.AddMinutes(2)), (& $e 'AAA' 200 $b4T0))
        $sig = { param($R) (@($R.Findings | ForEach-Object { '{0}|{1}|{2}|{3}|{4}' -f $_.Kind, $_.Key, $_.State, $_.Provider, (@($_.Evidence | ForEach-Object { $_.Code + '/' + $_.Detail }) -join '+') }) + @($R.Coverage | ForEach-Object { $_.Collector + '=' + $_.Status })) -join "`n" }
        $r1 = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $c -ProviderHints $claude -SessionRegistries @($two, $okB) -SelfKeys $self
        $r2 = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $c -ProviderHints $claude -SessionRegistries @($okB, $twoRev) -SelfKeys $selfRev
        Assert-Eq (& $sig $r2) (& $sig $r1) 'ordem de registros, entradas e SELF: resultado literal identico'
        # Reasons in coverage records: the same literal order whatever the order of providers and profiles (D6).
        $mixRows = @($b4cRows) + @((& $b4Row 9998 4 'nodate.exe' $null))
        $cm = Get-AtmProcessCollection -Source ({ $mixRows }.GetNewClosure())
        $ha = & $b4Hints 'fake-a' @([pscustomobject]@{ ImageName = 'node.exe'; CommandLineMarker = '--x' })
        $hb = & $b4Hints 'fake-b' @([pscustomobject]@{ ImageName = 'nodate.exe'; CommandLineMarker = $null })
        $ra = & $reg 'S-1-5-21-9' 'D:\profiles\a' @() $false
        $rb = [pscustomobject]@{ ProviderId = 'claude-code'; Registry = $null; Error = 'IOException'; ProfileSid = 'S-1-5-21-9'; ProfilePath = 'D:\profiles\b' }
        $rcv = { param($R) @($R.Coverage | ForEach-Object { $_.Collector + '=' + $_.Status + ':' + (@($_.Reasons) -join '+') }) + @('totals:' + (@($R.Totals.Reasons) -join '+')) -join "`n" }
        $m1 = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $cm -ProviderHints @($ha, $hb) -SessionRegistries @($ra, $rb)
        $m2 = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $cm -ProviderHints @($hb, $ha) -SessionRegistries @($rb, $ra)
        Assert-True (@(@($m1.Coverage | Where-Object { $_.Collector -eq 'agent-processes' })[0].Reasons).Count -ge 3 -and @(@($m1.Coverage | Where-Object { $_.Collector -eq 'sessions-claude-code' })[0].Reasons).Count -ge 3) 'varios motivos nos registros comparados'
        Assert-Eq (& $rcv $m2) (& $rcv $m1) 'motivos na mesma ordem literal com providers e perfis invertidos'
    }
    Test-Case 'Diagnose' 'Saida durante a execucao e recursos (P1-B4-c): evidencia so entre duas coletas completas; CPU sem segunda amostra ou com prazo insuficiente fica parcial; zero processos so com cobertura conclusiva' {
        # GetNewClosure captures only local variables: the shared rows are copied into one first.
        $rows = $b4cRows
        $c = Get-AtmProcessCollection -Source ({ $rows }.GetNewClosure())
        $claude = @(& $b4Hints 'claude-code' @([pscustomobject]@{ ImageName = 'claude.exe'; CommandLineMarker = $null }))
        $regs = @([pscustomobject]@{ ProviderId = 'claude-code'; Registry = [pscustomobject]@{ Readable = $true; Unparseable = 0; Entries = @([pscustomobject]@{ SessionId = 'x1'; Pid = 202; StartUtc = $b4T0.AddMinutes(2) }) }; Error = $null })
        $exitedRows = @($b4cRows | Where-Object { $_.ProcessId -ne 203 -and $_.ProcessId -ne 202 })
        $second = Get-AtmProcessCollection -Source ({ $exitedRows }.GetNewClosure())
        Assert-Eq $second.Coverage.Status 'COMPLETE' 'segunda coleta completa'
        $cpu = Measure-AtmProcessCpu -First $c -Second $second -ElapsedMs 500
        $res = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $c -Second $second -ProviderHints $claude -SessionRegistries $regs -Cpu $cpu
        $hasExit = { param($Key) @(@($res.Findings | Where-Object { $_.Key -ceq $Key })[0].Evidence | Where-Object { $_.Code -eq 'PROCESS_EXITED_DURING_RUN' }).Count -eq 1 }
        Assert-True ((& $hasExit (& $b4Key 203 $b4T0.AddMinutes(3))) -and (& $hasExit (& $b4Key 202 $b4T0.AddMinutes(2)))) 'processos encerrados entre coletas completas: evidencia de saida'
        Assert-True (-not (& $hasExit (& $b4Key 200 $b4T0))) 'processo presente: sem evidencia de saida'
        Assert-True (& $hasExit (& $b4SKey 'claude-code' 'x1')) 'sessao viva cujo processo encerrou: evidencia desatualizada'
        Assert-Eq (& $b4State $res (& $b4Key 203 $b4T0.AddMinutes(3))) 'AGENT_DESCENDANT' 'estado mantido (evidencia, nao estado novo)'
        $t = $res.Totals
        Assert-True (-not $t.Complete -and @($t.Reasons) -contains 'CPU_PROCESS_EXITED' -and $t.Counters.CpuPercent.Known -eq ($t.Processes - 2) -and $t.Counters.WorkingSetBytes.Complete) "CPU sem os encerrados: parcial ($(@($t.Reasons) -join ','); conhecidos $($t.Counters.CpuPercent.Known) de $($t.Processes); WS completo $($t.Counters.WorkingSetBytes.Complete); agent-processes $(@($res.Coverage | Where-Object { $_.Collector -eq 'agent-processes' })[0].Status))"
        # A reused PID in a PARTIAL second collection proves nothing: no exit evidence.
        $reusedRows = @($b4cRows | Where-Object { $_.ProcessId -ne 203 }) + @((& $b4Row 203 202 'node.exe' $b4T0.AddMinutes(9)), (& $b4Row 9999 4 'nodate.exe' $null))
        $partial = Get-AtmProcessCollection -Source ({ $reusedRows }.GetNewClosure())
        Assert-Eq $partial.Coverage.Status 'PARTIAL' 'segunda coleta parcial'
        $res = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $c -Second $partial -ProviderHints $claude
        Assert-Eq @($res.Findings | ForEach-Object { $_.Evidence } | Where-Object { $_.Code -eq 'PROCESS_EXITED_DURING_RUN' }).Count 0 'PID reutilizado em coleta parcial: nenhuma saida concluida'
        # CPU: no second sample, and a deadline too short for the interval.
        $res = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $c -ProviderHints $claude
        Assert-True (-not $res.Totals.Complete -and @($res.Totals.Reasons) -contains 'CPU_NOT_SAMPLED' -and $null -eq $res.Totals.Counters.CpuPercent.Sum -and $res.Totals.Counters.HandleCount.Sum -eq (1000 * $res.Totals.Processes)) 'sem segunda amostra: CPU nula, demais contadores somados'
        $rowsT = $b4cRows
        $sample = Invoke-AtmProcessCpuSampling -Source ({ $rowsT }.GetNewClosure()) -IntervalMs 500 -Deadline ([datetime]::UtcNow.AddMilliseconds(200))
        Assert-True ($null -eq $sample.Second -and $sample.Cpu.Coverage.Status -eq 'TIMEOUT') 'prazo insuficiente: so a primeira coleta'
        $res = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $sample.First -Second $sample.Second -ProviderHints $claude -Cpu $sample.Cpu
        Assert-True (@($res.Totals.Reasons) -contains 'CPU_NOT_SAMPLED' -and @($res.Totals.Reasons) -contains 'DEADLINE_EXCEEDED' -and $null -eq $res.Totals.CpuIntervalMs) "prazo insuficiente: $(@($res.Totals.Reasons) -join ',')"
        $rc = @($res.Coverage | Where-Object { $_.Collector -eq 'agent-resources' })[0]
        Assert-True ($rc.Status -eq 'PARTIAL' -and @($rc.Reasons) -contains 'CPU_NOT_SAMPLED') 'agent-resources parcial'
        # No agent process: 0 only with a conclusive discovery; otherwise null.
        $noAgent = @($b4cRows | Where-Object { $_.Name -ne 'claude.exe' })
        $cn = Get-AtmProcessCollection -Source ({ $noAgent }.GetNewClosure())
        $res = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $cn -ProviderHints $claude
        Assert-True ($res.Totals.Processes -eq 0 -and $res.Totals.Complete -and $res.Totals.Counters.WorkingSetBytes.Sum -eq 0 -and $res.Totals.Counters.CpuPercent.Sum -eq 0) 'nenhum processo identificado com cobertura conclusiva: 0'
        $res = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $cn -ProviderHints @(& $b4Hints 'claude-code' @([pscustomobject]@{ ImageName = 'claude.exe'; CommandLineMarker = $null }) 'FAILED')
        Assert-True ($res.Totals.Processes -eq 0 -and -not $res.Totals.Complete -and $null -eq $res.Totals.Counters.WorkingSetBytes.Sum -and @($res.Totals.Reasons) -contains 'AGENT_PROCESSES_INCOMPLETE') 'nenhum processo com descoberta inconclusiva: nulo, nunca 0'
        # Failed collection: every runtime collector still has exactly one record.
        $failed = Get-AtmProcessCollection -Source { throw (New-Object System.InvalidOperationException 'x') }
        $res = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $failed -ProviderHints $claude -SessionRegistries $regs
        Assert-Eq (@($res.Coverage | ForEach-Object { $_.Collector + '=' + $_.Status }) -join ',') 'sessions-claude-code=COMPLETE,agent-processes=FAILED,agent-resources=FAILED' 'coleta com falha: um registro por coletor'
        Assert-True ($null -eq $res.Totals.Counters.WorkingSetBytes.Sum) 'coleta com falha: totais nulos'
    }
    Test-Case 'Diagnose' 'Prazo (P1-B4-c): prazo zero deixa todos os coletores de runtime TIMEOUT e agentResources nao coletado; prazo curto nunca vira COMPLETE nem 0' {
        $p = New-TestProfile 'b4cdl'
        $null = New-TestRoot -ProfileInfo $p
        $rows = $b4cRows
        $d = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p) -Procs $b4cLegacy) -IdentitySource $diagIdUser -Providers @((Get-AtmProviders)[0]) -ProcessSource ({ $rows }.GetNewClosure()) -DeadlineSeconds 0
        foreach ($c in @('process-snapshot', 'sessions-claude-code', 'agent-processes', 'agent-resources')) {
            $x = @($d.Coverage | Where-Object { $_.Collector -eq $c })
            Assert-True ($x.Count -eq 1 -and $x[0].Status -eq 'TIMEOUT' -and @($x[0].Reasons) -contains 'DEADLINE_EXCEEDED') "$c TIMEOUT"
        }
        Assert-True ($null -eq $d.AgentResources -and @($d.Findings).Count -eq 0) 'nada inventado'
        $j = (ConvertTo-AtmDiagnoseJson -Result $d) | ConvertFrom-Json
        Assert-True ($j.agentResources.collected -eq $false -and $null -eq $j.agentResources.processes -and $null -eq $j.agentResources.counters) 'agentResources nao coletado: nulo, nunca 0'
        $txt = (Show-AtmDiagnose -Result $d 6>&1 | Out-String)
        Assert-True ($txt.Contains((Get-AtmText 'diag.runtimeNotRun'))) 'relatorio: runtime nao observado'
        # A short deadline with a long CPU interval: either the runtime is TIMEOUT or the CPU was not sampled.
        $d = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p) -Procs $b4cLegacy) -IdentitySource $diagIdUser -Providers @((Get-AtmProviders)[0]) -ProcessSource ({ $rows }.GetNewClosure()) -DeadlineSeconds 2 -CpuSampleMs 5000
        $rc = @($d.Coverage | Where-Object { $_.Collector -eq 'agent-resources' })[0]
        Assert-True ($rc.Status -eq 'TIMEOUT' -or ($rc.Status -eq 'PARTIAL' -and @($rc.Reasons) -contains 'CPU_NOT_SAMPLED')) "prazo curto: agent-resources $($rc.Status) $(@($rc.Reasons) -join ',')"
        Assert-True (-not $d.CoverageComplete) 'prazo curto: cobertura incompleta'
        if ($null -ne $d.AgentResources) { Assert-True ($null -eq $d.AgentResources.Counters.CpuPercent.Sum) 'CPU nula, nunca 0' }
        $threw = $false; try { $null = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p)) -IdentitySource $diagIdUser -CpuSampleMs 50 } catch { $threw = $true }
        Assert-True $threw 'intervalo de CPU fora dos limites recusado'
    }
    Test-Case 'I18n' 'Runtime de agentes (P1-B4-c): todo estado, motivo e evidencia tem texto nos dois idiomas; os codigos emitidos estao nas listas' {
        foreach ($l in @('en-US', 'pt-BR')) {
            foreach ($kind in @('Process', 'AgentSession')) { foreach ($st in @($script:AtmFindingStates[$kind])) { Assert-True $script:AtmMessages[$l].ContainsKey("state.$kind.$st") "state.$kind.$st ($l)" } }
            foreach ($x in $script:AtmRuntimeReasonCodes) { Assert-True $script:AtmMessages[$l].ContainsKey("reason.$x") "reason.$x ($l)" }
            foreach ($x in $script:AtmRuntimeEvidenceCodes) { Assert-True $script:AtmMessages[$l].ContainsKey("evidence.$x") "evidence.$x ($l)" }
            foreach ($n in @($script:AtmTreeCounters) + @('CpuPercent')) { Assert-True $script:AtmMessages[$l].ContainsKey("diag.res.$n") "diag.res.$n ($l)" }
        }
        # Codes emitted by the runtime collectors in varied scenarios are all in the lists (or EXCEPTION_<TYPE>).
        $claude = @(& $b4Hints 'claude-code' @([pscustomobject]@{ ImageName = 'claude.exe'; CommandLineMarker = $null }) 'FAILED')
        $marker = @(& $b4Hints 'fake-agent' @([pscustomobject]@{ ImageName = 'node.exe'; CommandLineMarker = '--x' }))
        $partialRows = @($b4cRows) + @((& $b4Row 9999 4 'nodate.exe' $null), (& $b4Row 9998 4 'claude.exe' $null))
        $cp = Get-AtmProcessCollection -Source ({ $partialRows }.GetNewClosure())
        $failed = Get-AtmProcessCollection -Source { throw (New-Object System.IO.IOException 'x') }
        $regs = @([pscustomobject]@{ ProviderId = 'claude-code'; Registry = $null; Error = 'IOException' }, [pscustomobject]@{ ProviderId = 'Bad Id'; Registry = $null; Error = $null },
            [pscustomobject]@{ ProviderId = 'fake-agent'; Registry = [pscustomobject]@{ Readable = $true; Unparseable = 1; Entries = @() }; Error = $null })
        $parts = @([pscustomobject]@{ Provider = 'claude-code'; DirectRefs = @('PID 4242 (gone.exe)'); AncestorRefs = @() })
        $emitted = New-Object System.Collections.Generic.List[string]
        foreach ($res in @((Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $cp -ProviderHints @($claude + $marker) -SessionRegistries $regs -Partitions $parts),
                (Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $failed -ProviderHints $claude -SessionRegistries $regs),
                (Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $cp -Partitions $parts -LegacySnapshot ([pscustomobject]@{ Failed = $false; Processes = @() })),
                (Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $cp))) {
            foreach ($cv in @($res.Coverage) + @($cp.Coverage, $failed.Coverage)) { foreach ($x in @($cv.Reasons)) { $emitted.Add([string]$x) } }
            foreach ($x in @($res.Totals.Reasons)) { $emitted.Add([string]$x) }
            foreach ($f in @($res.Findings)) { foreach ($ev in @($f.Evidence)) { Assert-True ($script:AtmRuntimeEvidenceCodes -ccontains $ev.Code) "evidencia emitida com texto: $($ev.Code)" } }
        }
        foreach ($x in @($emitted | Select-Object -Unique)) { Assert-True ($x -like 'EXCEPTION_*' -or $script:AtmRuntimeReasonCodes -ccontains $x) "motivo emitido com texto: $x" }
    }
    # P1-B4-d fixtures: a key file of the operator in the sandbox (random bytes) with the ACL an operator would give it:
    # no inheritance, only the current user, SYSTEM and Administrators (the inherited TEMP ACL may grant other accounts).
    $b4dKeyFile = { param([string]$Name, [int]$Size = 32)
        $f = Join-Path $sandbox $Name
        $b = New-Object byte[] $Size
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create(); try { $rng.GetBytes($b) } finally { $rng.Dispose() }
        [IO.File]::WriteAllBytes($f, $b)
        # icacls writes only the DACL (Set-Acl would also write the SACL, which needs a privilege).
        $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $null = & icacls.exe $f /inheritance:r /grant:r "*$($me):(F)" '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' 2>&1
        return $f }
    Test-Case 'Privacidade' 'Pseudonimos (P1-B4-d): chave efemera por padrao, arquivo de chave do operador para correlacao, nenhum caminho nem id de sessao exportado, chave nunca no resultado' {
        $sid = [guid]::NewGuid().ToString()
        $p = New-TestProfile 'b4dps'
        $root = New-TestRoot -ProfileInfo $p -Uuid $sid
        $other = New-TestRoot -ProfileInfo $p
        & $b4cSession $p 200 $sid $b4T0
        $rows = $b4cRows
        $src = { $rows }.GetNewClosure()
        $run = { param($Key) Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p) -Procs $b4cLegacy) -IdentitySource $diagIdUser -Providers @((Get-AtmProviders)[0]) -ProcessSource $src -SelfPid 3000 -SelfCreationUtc $b4T0.AddMinutes(5) -CpuSampleMs 0 -PseudonymKey $Key }
        $keysOf = { param($D, [string]$Kind) @($D.Findings | Where-Object { $_.Kind -eq $Kind } | ForEach-Object { $_.Key } | Sort-Object) -join ',' }
        # Ephemeral (default): no correlation between runs for partitions and sessions; process keys stay comparable.
        $e1 = & $run $null; $e2 = & $run $null
        Assert-True ($e1.Pseudonymization.KeySource -eq 'EPHEMERAL' -and $null -eq $e1.Pseudonymization.KeyId -and $e1.Pseudonymization.Scheme -eq 'HMAC-SHA256-128/1') 'chave efemera por padrao, sem id'
        $pk1 = @($e1.Findings | Where-Object { $_.Kind -eq 'TempPartition' } | ForEach-Object { $_.Key }); $pk2 = @($e2.Findings | Where-Object { $_.Kind -eq 'TempPartition' } | ForEach-Object { $_.Key })
        Assert-True ($pk1.Count -eq 2 -and @($pk1 | Where-Object { $pk2 -ccontains $_ }).Count -eq 0) 'particoes: chaves diferentes entre execucoes sem arquivo de chave'
        Assert-True ((& $keysOf $e1 'AgentSession') -cne (& $keysOf $e2 'AgentSession')) 'sessoes: chaves diferentes entre execucoes sem arquivo de chave'
        Assert-Eq (& $keysOf $e2 'Process') (& $keysOf $e1 'Process') 'chaves de processo continuam comparaveis (nao sao pseudonimos)'
        # Operator key file: the same file gives the same keys and key id; another file gives others.
        $kf1 = & $b4dKeyFile 'b4d-key1.bin'; $kf2 = & $b4dKeyFile 'b4d-key2.bin'
        $r1 = Read-AtmPseudonymKeyFile -Path $kf1; $r2 = Read-AtmPseudonymKeyFile -Path $kf2
        Assert-True ($null -ne $r1.Key -and $null -eq $r1.Reason -and $null -ne $r2.Key) "arquivos de chave lidos: $($r1.Reason) $($r2.Reason)"
        $keyBytes = [byte[]]$r1.Key.Clone()
        $o1 = & $run $r1.Key; $o2 = & $run $r1.Key; $o3 = & $run $r2.Key
        Assert-True ($o1.Pseudonymization.KeySource -eq 'OPERATOR_KEY_FILE' -and $o1.Pseudonymization.KeyId -cmatch '^[0-9a-f]{32}$' -and $o1.Pseudonymization.KeyId -ceq $o2.Pseudonymization.KeyId -and $o1.Pseudonymization.KeyId -cne $o3.Pseudonymization.KeyId) 'id da chave: igual com o mesmo arquivo, diferente com outro'
        foreach ($kind in @('TempPartition', 'AgentSession')) {
            Assert-Eq (& $keysOf $o2 $kind) (& $keysOf $o1 $kind) "$($kind): mesmas chaves com o mesmo arquivo de chave"
            Assert-True ((& $keysOf $o3 $kind) -cne (& $keysOf $o1 $kind)) "$($kind): outras chaves com outro arquivo"
        }
        Assert-True ($r1.Key.Length -eq $keyBytes.Length -and @(0..($keyBytes.Length - 1) | Where-Object { $r1.Key[$_] -ne $keyBytes[$_] }).Count -eq 0) 'a chave do chamador nao e alterada pelo diagnostico'
        Assert-True (@($o1.Findings | Where-Object { $_.Kind -eq 'TempPartition' -and $_.Key -cnotmatch '^claude-code/p-[0-9a-f]{32}$' }).Count -eq 0 -and @($o1.Findings | Where-Object { $_.Kind -eq 'AgentSession' -and $_.Key -cnotmatch '^claude-code/s-[0-9a-f]{32}$' }).Count -eq 0) 'formato das chaves'
        # Nothing protected in the export, the report or the whole in-memory result: session id, paths, root names,
        # the key (hex, base64), the key file path.
        $old = Get-AtmLanguage
        try { Set-AtmLanguage -Requested 'en-US'; $json = ConvertTo-AtmDiagnoseJson -Result $o1; $txt = (Show-AtmDiagnose -Result $o1 6>&1 | Out-String) } finally { Set-AtmLanguage -Requested $old }
        $mem = ($o1 | Select-Object * -ExcludeProperty Inventory | ConvertTo-Json -Depth 12)
        $hex = -join @($keyBytes | ForEach-Object { $_.ToString('x2') }); $b64 = [Convert]::ToBase64String($keyBytes)
        $needles = @($sid, $root, $other, (Split-Path -Leaf $other), $p.ProfilePath, $hex, $hex.ToUpperInvariant(), $b64, $kf1)
        foreach ($x in @($json, $txt, $mem)) { foreach ($n in $needles) { Assert-True (-not $x.Contains($n) -and -not $x.Contains($n.Replace('\', '\\'))) 'nada protegido nas saidas nem no resultado em memoria' } }
        Assert-Eq (@($o1.Pseudonymization.PSObject.Properties.Name) -join ',') 'Scheme,KeySource,KeyId' 'resultado leva so esquema, origem e id da chave'
        Assert-True ($txt.Contains('operator key file, key id ' + $o1.Pseudonymization.KeyId)) 'relatorio: origem da chave'
        $te = (Show-AtmDiagnose -Result $e1 6>&1 | Out-String) -replace '\s+', ' '
        Assert-True ($te.Contains('one-run key') -or $te.Contains('chave de uma execu')) 'relatorio: chave efemera'
        # The pseudonymizer: closed means disposed and cleared; the key id uses its own domain.
        $z = New-AtmPseudonymizer -Key $keyBytes
        $kid = $z.KeyId
        Assert-True ($kid -cne (Get-AtmPseudonym -Pseudonymizer $z -Domain 'atm-session/2' -Fields @()) -and $kid -cne (Get-AtmPseudonym -Pseudonymizer $z -Domain 'atm-partition/1' -Fields @())) 'id da chave em dominio proprio'
        $buf = $z.Buffer
        Close-AtmPseudonymizer $z
        Assert-True ($null -eq $z.Hmac -and $null -eq $z.Buffer -and @($buf | Where-Object { $_ -ne 0 }).Count -eq 0) 'pseudonimizador fechado: HMAC descartado, copia da chave zerada'
        $threw = $false; try { $null = New-AtmPseudonymizer -Key ([byte[]](1..31)) } catch { $threw = $true }
        Assert-True $threw 'chave curta recusada'
        # The engine alone, without a pseudonymizer, uses an ephemeral key for that call only.
        $cr = Get-AtmProcessCollection -Source $src
        $reg1 = @([pscustomobject]@{ ProviderId = 'claude-code'; Registry = [pscustomobject]@{ Readable = $true; Unparseable = 0; Entries = @([pscustomobject]@{ SessionId = 'e1'; Pid = 200; StartUtc = $b4T0 }) }; Error = $null })
        $ka = @((Get-AtmAgentRuntimeFindings -Collection $cr -SessionRegistries $reg1).Findings | Where-Object { $_.Kind -eq 'AgentSession' } | ForEach-Object { $_.Key })
        $kb = @((Get-AtmAgentRuntimeFindings -Collection $cr -SessionRegistries $reg1).Findings | Where-Object { $_.Kind -eq 'AgentSession' } | ForEach-Object { $_.Key })
        Assert-True ($ka.Count -eq 1 -and $kb.Count -eq 1 -and $ka[0] -cne $kb[0]) 'motor sem pseudonimizador: chave efemera por chamada'
    }
    Test-Case 'Privacidade' 'Reconstrucao adversarial (P1-B4-d): a partir do proprio export, nenhuma chave de sessao ou particao e recalculada (formula sem chave, chaves derivadas dos campos exportados, chave vazia ou zerada)' {
        $sid = [guid]::NewGuid().ToString()
        $p = New-TestProfile 'b4dadv'
        $root = New-TestRoot -ProfileInfo $p -Uuid $sid
        & $b4cSession $p 200 $sid $b4T0
        $rows = $b4cRows
        $kf = & $b4dKeyFile 'b4d-adv.bin'
        $kr = Read-AtmPseudonymKeyFile -Path $kf
        $d = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p) -Procs $b4cLegacy) -IdentitySource $diagIdUser -Providers @((Get-AtmProviders)[0]) -ProcessSource ({ $rows }.GetNewClosure()) -CpuSampleMs 0 -PseudonymKey $kr.Key
        $j = (ConvertTo-AtmDiagnoseJson -Result $d) | ConvertFrom-Json
        $exported = @($j.findings | Where-Object { $_.kind -eq 'TempPartition' -or $_.kind -eq 'AgentSession' } | ForEach-Object { $_.key })
        Assert-True ($exported.Count -ge 2) 'chaves de particao e sessao exportadas'
        # The attacker knows the raw inputs (worst case: session id and paths leaked elsewhere) and every exported field.
        $cands = New-Object System.Collections.Generic.List[string]
        # 1. The P1-B4-c unkeyed formula (SHA-256 over the same fields).
        $sha = { param([string[]]$Fields) $sb = New-Object System.Text.StringBuilder; foreach ($f in $Fields) { [void]$sb.Append($f.Length).Append(':').Append($f).Append(';') }; $h = [Security.Cryptography.SHA256]::Create(); try { -join @($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($sb.ToString()))[0..15] | ForEach-Object { $_.ToString('x2') }) } finally { $h.Dispose() } }
        $sessFields = @('claude-code', [string]$p.Sid, $p.ProfilePath.TrimEnd('\').ToLowerInvariant(), $sid.ToLowerInvariant())
        $partFields = @('claude-code', $root.TrimEnd('\').ToLowerInvariant())
        $cands.Add('claude-code/s-' + (& $sha (@('atm-session/1') + $sessFields))); $cands.Add('claude-code/s-' + (& $sha (@('atm-session/2') + $sessFields)))
        $cands.Add('claude-code/p-' + (& $sha (@('atm-partition/1') + $partFields)))
        # 2. HMAC keys an attacker could build from the export: machine, SID, user, key id, schema, scheme, empty, zeros.
        $guesses = @($j.machine, $j.identity.sid, $j.identity.user, $j.pseudonymization.keyId, $j.schemaVersion, $j.pseudonymization.scheme, '') | Where-Object { $null -ne $_ }
        $keys = @($guesses | ForEach-Object { , [Text.Encoding]::UTF8.GetBytes([string]$_) }) + @(, (New-Object byte[] 32))
        foreach ($k in $keys) {
            $h = New-Object Security.Cryptography.HMACSHA256 (, [byte[]]$k)
            try {
                $z = [pscustomobject]@{ Hmac = $h }
                $cands.Add('claude-code/s-' + (Get-AtmPseudonym -Pseudonymizer $z -Domain 'atm-session/2' -Fields $sessFields))
                $cands.Add('claude-code/p-' + (Get-AtmPseudonym -Pseudonymizer $z -Domain 'atm-partition/1' -Fields $partFields))
            } finally { $h.Dispose() }
        }
        Assert-True ($cands.Count -ge 19) "candidatos testados: $($cands.Count)"
        Assert-Eq @($cands | Where-Object { $exported -ccontains $_ }).Count 0 'nenhum pseudonimo recalculado a partir do export'
        # Control: with the real key the same computation does match (the attack above is meaningful).
        $zr = New-AtmPseudonymizer -Key $kr.Key
        try { Assert-True ($exported -ccontains ('claude-code/p-' + (Get-AtmPseudonym -Pseudonymizer $zr -Domain 'atm-partition/1' -Fields $partFields))) 'controle: com a chave real o pseudonimo confere' } finally { Close-AtmPseudonymizer $zr }
    }
    Test-Case 'Privacidade' 'Arquivo de chave do operador (P1-B4-d): caminho relativo, ausente, pasta, tamanho invalido e ACL aberta recusados sem expor caminho nem conteudo; CLI falha fechada' {
        $ok = & $b4dKeyFile 'b4d-ok.bin'
        Assert-True ($null -ne (Read-AtmPseudonymKeyFile -Path $ok).Key) 'arquivo valido'
        $cases = [ordered]@{
            'b4d-relative.bin'                 = 'PSEUDONYM_KEY_PATH_INVALID'
            ($ok.Substring(0, 2) + 'b4d-ok.bin') = 'PSEUDONYM_KEY_PATH_INVALID'
            ($ok.Substring(2))                 = 'PSEUDONYM_KEY_PATH_INVALID'
            (Join-Path $sandbox 'b4d-none.bin') = 'PSEUDONYM_KEY_NOT_FOUND'
            $sandbox                           = 'PSEUDONYM_KEY_NOT_A_FILE'
            (& $b4dKeyFile 'b4d-short.bin' 31) = 'PSEUDONYM_KEY_SIZE_INVALID'
            (& $b4dKeyFile 'b4d-long.bin' 4097) = 'PSEUDONYM_KEY_SIZE_INVALID'
        }
        foreach ($c in $cases.GetEnumerator()) { $r = Read-AtmPseudonymKeyFile -Path $c.Key; Assert-True ($null -eq $r.Key -and $r.Reason -eq $c.Value) "$($c.Value): $($r.Reason)" }
        # Another account may read or change the file: refused, generic rights included (sandbox files only).
        $grant = { param([string]$Name, [string]$Grant) $f = & $b4dKeyFile $Name; $null = & icacls.exe $f /grant $Grant 2>&1; return $f }
        $open = & $grant 'b4d-open.bin' '*S-1-1-0:(R)'
        Assert-Eq (Read-AtmPseudonymKeyFile -Path $open).Reason 'PSEUDONYM_KEY_ACL_TOO_OPEN' 'legivel por Everyone: recusado'
        Assert-Eq (Read-AtmPseudonymKeyFile -Path (& $grant 'b4d-inter.bin' '*S-1-5-4:(RX)')).Reason 'PSEUDONYM_KEY_ACL_TOO_OPEN' 'legivel por INTERACTIVE: recusado'
        Assert-Eq (Read-AtmPseudonymKeyFile -Path (& $grant 'b4d-write.bin' '*S-1-5-32-545:(W)')).Reason 'PSEUDONYM_KEY_ACL_TOO_OPEN' 'gravavel por Users: recusado'
        $gen = & $b4dKeyFile 'b4d-generic.bin'
        $null = & icacls.exe $gen /grant '*S-1-1-0:(GR)' 2>&1
        $genAce = @((Get-Acl -LiteralPath $gen).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference.Value -eq 'S-1-1-0' })
        Assert-True ($genAce.Count -ge 1) 'ACE de leitura generica aplicada'
        Assert-Eq (Read-AtmPseudonymKeyFile -Path $gen).Reason 'PSEUDONYM_KEY_ACL_TOO_OPEN' 'leitura generica (GR) por Everyone: recusado'
        # The diagnose progress line never carries the inventory's messages (they name temporary bases).
        $launcher = [IO.File]::ReadAllText((Join-Path $srcDir 'agent-temp.ps1'))
        Assert-True ($launcher -match 'diagInvArgs\[''ProgressCallback''\] = \{ param\(\$pct, \$msg\)[^\r\n]*-Status \(Get-AtmText ''cli\.diagProgressStatus''\)' -and $launcher -match '\$diagArgs = @\{ InventoryArgs = \$diagInvArgs \}') 'progresso do diagnose sem caminhos'
        # CLI: refused before running (exit 2), the code is shown, the path and the content are not.
        $cmd = Join-Path $srcDir 'bin\agent-temp.cmd'
        $out = (& cmd.exe /c "`"$cmd`" diagnose -DeadlineSeconds 0 -NoProgress -Lang en-US -PseudonymKeyFile `"$open`"" 2>&1) -join "`n"
        Assert-Eq $LASTEXITCODE 2 'CLI: arquivo de chave recusado, codigo 2'
        Assert-True ($out.Contains('PSEUDONYM_KEY_ACL_TOO_OPEN') -and -not $out.Contains($open) -and -not $out.Contains('b4d-open') -and -not $out.Contains('COVERAGE BY COLLECTOR')) 'CLI: so o codigo; nada executado'
        $out = (& cmd.exe /c "`"$cmd`" diagnose -DeadlineSeconds 0 -NoProgress -Lang en-US -PseudonymKeyFile `"$ok`"" 2>&1) -join "`n"
        Assert-True ($LASTEXITCODE -eq 0 -and $out -match 'operator key file, key id [0-9a-f]{32}' -and -not $out.Contains($ok)) 'CLI: arquivo valido aceito, id da chave mostrado'
        $out = (& cmd.exe /c "`"$cmd`" help -Lang en-US" 2>&1) -join "`n"
        Assert-True ($out.Contains('-PseudonymKeyFile')) 'ajuda mostra -PseudonymKeyFile'
    }
    Test-Case 'Diagnose' 'Colisao de chave de particao (P1-B4-d): duas particoes com a mesma chave viram um achado UNKNOWN, nada sobrescrito, ordem pelo pseudonimo (D-8)' {
        $parts = @(
            [pscustomobject]@{ Provider = 'claude-code'; Path = 'D:\t\a'; Kind = 'SessionRoot'; Class = 'OLD'; Flags = @() },
            [pscustomobject]@{ Provider = 'claude-code'; Path = 'D:\t\b'; Kind = 'SessionRoot'; Class = 'ACTIVE_EVIDENCE'; Flags = @('X') },
            [pscustomobject]@{ Provider = 'claude-code'; Path = 'D:\t\c'; Kind = 'SessionRoot'; Class = 'OLD'; Flags = @() },
            [pscustomobject]@{ Provider = 'claude-code'; Path = 'D:\t\n'; Kind = 'NotScanned'; Class = 'OLD'; Flags = @() })
        $inv = @(New-AtmCoverage -Collector 'inventory' -Status 'COMPLETE')
        $f = @(Get-AtmPartitionFindings -Partitions $parts -InventoryCoverage $inv -Pseudonymizer $b4Pz)
        Assert-True ($f.Count -eq 3 -and @($f | Where-Object { $_.State -eq 'RUNTIME_NOT_DIAGNOSED' }).Count -eq 3) 'sem colisao: um achado por particao medida'
        $expected = [string[]]@(@('D:\t\a', 'D:\t\b', 'D:\t\c') | ForEach-Object { ConvertTo-AtmPartitionKey -Pseudonymizer $b4Pz -Provider 'claude-code' -Path $_ }); [Array]::Sort($expected, [StringComparer]::Ordinal)
        Assert-Eq (@($f | ForEach-Object { $_.Key }) -join ',') ($expected -join ',') 'ordem ordinal pelo pseudonimo (D-8)'
        $clash = { param($Provider, $Path) if ($Path -like '*\c') { 'claude-code/p-' + ('1' * 32) } else { 'claude-code/p-' + ('0' * 32) } }
        $f = @(Get-AtmPartitionFindings -Partitions $parts -InventoryCoverage $inv -Pseudonymizer $b4Pz -KeyFunction $clash)
        Assert-True ($f.Count -eq 2 -and $f[0].State -eq 'UNKNOWN' -and @($f[0].Evidence | Where-Object { $_.Code -eq 'PARTITION_KEY_COLLISION' -and $_.Detail -eq '2' }).Count -eq 1 -and @($f[0].Evidence | Where-Object { $_.Code -eq 'AUDIT_CLASS' }).Count -eq 0) 'colisao: um achado UNKNOWN, sem a classe de nenhuma das duas'
        Assert-True ($f[1].State -eq 'RUNTIME_NOT_DIAGNOSED' -and $f[1].Key -ceq ('claude-code/p-' + ('1' * 32))) 'particao sem colisao inalterada'
        # Reversed input: the same collision and the same order.
        $fr = @(Get-AtmPartitionFindings -Partitions @($parts[($parts.Count - 1)..0]) -InventoryCoverage $inv -Pseudonymizer $b4Pz -KeyFunction $clash)
        Assert-Eq (@($fr | ForEach-Object { $_.Key + '=' + $_.State }) -join ',') (@($f | ForEach-Object { $_.Key + '=' + $_.State }) -join ',') 'colisao com entrada invertida: mesmo resultado'
    }
    Test-Case 'Privacidade' 'Ordem das particoes (P1-B4-d, D-8): enumeracao invertida da a mesma saida literal; mesma chave, mesma ordem; outra chave, ordem ordinal dos novos pseudonimos; nenhum campo devolve a ordem das pastas; V0.1 inalterada' {
        $mk = { param([string]$Leaf, [string]$Class, [string[]]$Flags) [pscustomobject]@{ Provider = 'claude-code'; Path = "D:\t\$Leaf"; Kind = 'SessionRoot'; Class = $Class; Flags = @($Flags) } }
        $parts = @((& $mk 'a1' 'OLD' @()), (& $mk 'b2' 'ACTIVE_EVIDENCE' @('X')), (& $mk 'c3' 'OLD' @('Y', 'Z')), (& $mk 'd4' 'RECENT' @()), (& $mk 'e5' 'OLD' @()))
        $inv = @(New-AtmCoverage -Collector 'inventory' -Status 'COMPLETE')
        $sig = { param($F) @($F | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.Key, $_.State, $_.Provider, (@($_.Evidence | ForEach-Object { $_.Code + '/' + $_.Detail }) -join '+') }) -join "`n" }
        $f1 = @(Get-AtmPartitionFindings -Partitions $parts -InventoryCoverage $inv -Pseudonymizer $b4Pz)
        $f2 = @(Get-AtmPartitionFindings -Partitions @($parts[($parts.Count - 1)..0]) -InventoryCoverage $inv -Pseudonymizer $b4Pz)
        Assert-Eq (& $sig $f2) (& $sig $f1) 'enumeracao invertida, mesma chave: saida literal identica'
        $f3 = @(Get-AtmPartitionFindings -Partitions $parts -InventoryCoverage $inv -Pseudonymizer $b4Pz)
        Assert-Eq (& $sig $f3) (& $sig $f1) 'mesma chave reutilizada: pseudonimos e ordem identicos'
        $keys1 = [string[]]@($f1 | ForEach-Object { $_.Key }); $sorted1 = [string[]]$keys1.Clone(); [Array]::Sort($sorted1, [StringComparer]::Ordinal)
        Assert-Eq ($keys1 -join ',') ($sorted1 -join ',') 'ordem ordinal pela chave'
        $other = New-AtmPseudonymizer -Key ([byte[]](101..132))
        try {
            $f4 = @(Get-AtmPartitionFindings -Partitions $parts -InventoryCoverage $inv -Pseudonymizer $other)
            $keys4 = [string[]]@($f4 | ForEach-Object { $_.Key }); $sorted4 = [string[]]$keys4.Clone(); [Array]::Sort($sorted4, [StringComparer]::Ordinal)
            Assert-True (@($keys4 | Where-Object { $keys1 -ccontains $_ }).Count -eq 0 -and ($keys4 -join ',') -ceq ($sorted4 -join ',')) 'outra chave: pseudonimos recalculados, ordem ordinal'
            $byPath = @{}; foreach ($pt in $parts) { $byPath[(ConvertTo-AtmPartitionKey -Pseudonymizer $other -Provider 'claude-code' -Path $pt.Path)] = $pt.Class }
            Assert-True (@($f4 | Where-Object { @($_.Evidence | Where-Object { $_.Code -eq 'AUDIT_CLASS' })[0].Detail -cne $byPath[$_.Key] }).Count -eq 0) 'cada achado continua com a classe da sua particao'
        } finally { Close-AtmPseudonymizer $other }
        # No field gives the enumeration order back: one observation time for every partition finding.
        Assert-Eq @($f1 | ForEach-Object { $_.Evidence } | ForEach-Object { $_.ObservedUtc.Ticks } | Select-Object -Unique).Count 1 'mesmo horario de observacao em todas as particoes'
        # Integrated: roots created in a known order; the export lists them by pseudonym; the report lists none; the V0.1
        # inventory carried by the result keeps its own order.
        $p = New-TestProfile 'b4dord'
        $roots = @(1..4 | ForEach-Object { New-TestRoot -ProfileInfo $p -Uuid ('0000000' + $_ + '-0000-0000-0000-000000000000') })
        $rows = $b4cRows
        $d = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p) -Procs $b4cLegacy) -IdentitySource $diagIdUser -Providers @((Get-AtmProviders)[0]) -ProcessSource ({ $rows }.GetNewClosure()) -CpuSampleMs 0 -PseudonymKey $testPseudonymKey
        $j = (ConvertTo-AtmDiagnoseJson -Result $d) | ConvertFrom-Json
        $pk = [string[]]@($j.findings | Where-Object { $_.kind -eq 'TempPartition' } | ForEach-Object { $_.key }); $pks = [string[]]$pk.Clone(); [Array]::Sort($pks, [StringComparer]::Ordinal)
        Assert-True ($pk.Count -eq 4 -and ($pk -join ',') -ceq ($pks -join ',')) 'JSON: particoes em ordem ordinal'
        Assert-Eq ((@($pk) | Sort-Object) -join ',') ((@($roots | ForEach-Object { & $b4PKey $_ }) | Sort-Object) -join ',') 'JSON: exatamente as particoes criadas, pelos seus pseudonimos'
        Assert-Eq @($j.findings | Where-Object { $_.kind -eq 'TempPartition' } | ForEach-Object { $_.evidence } | ForEach-Object { $_.observedUtc } | Select-Object -Unique).Count 1 'JSON: um horario de observacao para as particoes'
        $txt = (Show-AtmDiagnose -Result $d 6>&1 | Out-String)
        Assert-True (-not ($txt -match '/p-[0-9a-f]{32}')) 'relatorio nao lista particoes individualmente'
        $invOrder = @($d.Inventory.Partitions | Where-Object { $_.Kind -ne 'NotScanned' -and $_.Kind -ne 'BaseLooseFiles' } | ForEach-Object { $_.Path })
        $fresh = Inv -Profiles @($p) -Procs $b4cLegacy
        Assert-Eq ($invOrder -join '|') (@($fresh.Partitions | Where-Object { $_.Kind -ne 'NotScanned' -and $_.Kind -ne 'BaseLooseFiles' } | ForEach-Object { $_.Path }) -join '|') 'inventario V0.1 com a sua propria ordem (nao alterado pelo diagnostico)'
    }
    Test-Case 'Diagnose' 'Identidade real (somente leitura, P1-B4-b): o snapshot da V0.1 e a coleta da P1-B1 dao ao proprio processo o mesmo horario de criacao em ticks' {
        $legacy = Get-AtmProcessSnapshot
        $c = Get-AtmProcessCollection
        $lp = @($legacy.Processes | Where-Object { $_.Pid -eq $PID })
        $cp = $(if ($c.ByPid.ContainsKey([long]$PID)) { $c.ByPid[[long]$PID] } else { $null })
        Assert-True ($lp.Count -eq 1 -and $null -ne $cp -and $null -ne $lp[0].CreationUtc -and $cp.IdentityStatus -eq 'VERIFIED') 'proprio processo nas duas coletas'
        Assert-Eq $lp[0].CreationUtc.ToUniversalTime().Ticks $cp.CreationUtc.Ticks 'mesmos ticks (marcadores e referencias dependem disso)'
        Assert-True ($null -ne (Get-AtmLegacyCommandLine -LegacySnapshot $legacy -Process $cp)) 'linha de comando do proprio processo correlacionada em memoria (nao exibida)'
    }
    Test-Case 'Diagnose' 'CLI version mostra identidade, tipo de elevacao e integridade (PRIV-10) nos dois idiomas' {
        $cmd = Join-Path $srcDir 'bin\agent-temp.cmd'
        $out = (& cmd.exe /c "`"$cmd`" version -Lang en-US" 2>&1) -join "`n"
        Assert-True ($out -match 'identity: .+ \| elevated administrator: (yes|no) \| elevation type: (DEFAULT|FULL|LIMITED) \| integrity: [A-Z_]+ \| session: \d+') 'en-US: linha de identidade'
        Assert-True ($out -match 'real deletion: DISABLED' -and $out -match 'language: en-US') 'linhas existentes preservadas'
        $out = (& cmd.exe /c "`"$cmd`" version -Lang pt-BR" 2>&1) -join "`n"
        Assert-True ($out -match 'identidade: .+ \| administrador elevado: (sim|n.{1,3}o) \| tipo de eleva.{1,6}o: (DEFAULT|FULL|LIMITED) \| integridade: [A-Z_]+') 'pt-BR: linha de identidade'
    }
    Test-Case 'Providers' 'Contrato v2: v1 inalterado; provider somente runtime registra sem membros de temporarios; validacao de versao, capacidades e membros' {
        $real = Get-AtmProviderContract (Get-AtmProviders)[0]
        Assert-Eq $real.Version 2 'Claude Code v2 (P1-B4-b)'
        Assert-Eq (@($real.Capabilities) -join ',') 'temp,runtime' 'Claude Code: temp e runtime'
        $claude = ConvertTo-AtmTestV1Provider (Get-AtmProviders)[0]
        $c = Get-AtmProviderContract $claude
        Assert-Eq $c.Version 1 'copia v1 continua v1'
        Assert-Eq (@($c.Capabilities) -join ',') 'temp' 'v1 = temp'
        $rt = [pscustomobject]@{ Id = 'fake-runtime'; DisplayName = 'Fake runtime'; ContractVersion = 2; Capabilities = @('runtime'); GetServiceHints = { @([pscustomobject]@{ Name = 'FakeAgentService'; Role = 'vm-host' }) } }
        try {
            Register-AtmProvider $rt
            Assert-Eq @(Get-AtmProviders).Count 2 'registrado'
            Assert-Eq (@(Get-AtmProviderCapabilities $rt) -join ',') 'runtime' 'capacidade runtime'
        } finally {
            for ($k = $script:AtmProviders.Count - 1; $k -ge 0; $k--) { if ($script:AtmProviders[$k].Id -eq 'fake-runtime') { $script:AtmProviders.RemoveAt($k) } }
        }
        Assert-Eq @(Get-AtmProviders).Count 1 'registro de teste removido'
        $both = $claude.PSObject.Copy(); $both.Id = 'fake-both'
        $both | Add-Member -NotePropertyName ContractVersion -NotePropertyValue 2
        $both | Add-Member -NotePropertyName Capabilities -NotePropertyValue @('temp', 'runtime')
        $both | Add-Member -NotePropertyName GetProcessMatchers -NotePropertyValue { @() }
        $threw = $false; try { Register-AtmProvider $both } catch { $threw = $true }
        try { Assert-True (-not $threw) 'v2 com temp e runtime aceito' } finally { for ($k = $script:AtmProviders.Count - 1; $k -ge 0; $k--) { if ($script:AtmProviders[$k].Id -eq 'fake-both') { $script:AtmProviders.RemoveAt($k) } } }
        $bad = @(
            [pscustomobject]@{ Id = 'b1'; DisplayName = 'B'; ContractVersion = 3; Capabilities = @('runtime') },
            [pscustomobject]@{ Id = 'b2'; DisplayName = 'B'; ContractVersion = 2; Capabilities = @() },
            [pscustomobject]@{ Id = 'b3'; DisplayName = 'B'; ContractVersion = 2; Capabilities = @('Runtime') },
            [pscustomobject]@{ Id = 'b4'; DisplayName = 'B'; ContractVersion = 2; Capabilities = @('runtime', 'runtime') },
            [pscustomobject]@{ Id = 'b5'; DisplayName = 'B'; ContractVersion = 2; Capabilities = @('gui') },
            [pscustomobject]@{ Id = 'b6'; DisplayName = 'B'; ContractVersion = 2; Capabilities = @('temp') },
            [pscustomobject]@{ Id = 'b7'; DisplayName = 'B'; ContractVersion = 2; Capabilities = @('runtime'); GetServiceHints = 'FakeAgentService' },
            [pscustomobject]@{ Id = 'B8'; DisplayName = 'B'; ContractVersion = 2; Capabilities = @('runtime') },
            [pscustomobject]@{ Id = 'b9'; ContractVersion = 2; Capabilities = @('runtime') })
        foreach ($b in $bad) {
            $threw = $false; try { Register-AtmProvider $b } catch { $threw = $true }
            Assert-True $threw "recusado: $($b.Id)"
        }
        # Full v1 compatibility: the V0.1 Id check (case-insensitive) is unchanged for providers without ContractVersion.
        $v1up = $claude.PSObject.Copy(); $v1up.Id = 'Fake-Upper-V1'
        try {
            Register-AtmProvider $v1up
            Assert-True (@(Get-AtmProviders | Where-Object { $_.Id -eq 'Fake-Upper-V1' }).Count -eq 1) 'v1 com Id em maiusculas continua aceito (como na V0.1)'
        } finally { for ($k = $script:AtmProviders.Count - 1; $k -ge 0; $k--) { if ($script:AtmProviders[$k].Id -eq 'Fake-Upper-V1') { $script:AtmProviders.RemoveAt($k) } } }
        $v1rt = $claude.PSObject.Copy(); $v1rt.Id = 'b10'; $v1rt | Add-Member -NotePropertyName GetServiceHints -NotePropertyValue { @() }
        $threw = $false; try { Register-AtmProvider $v1rt } catch { $threw = $true }
        Assert-True $threw 'membro de runtime sem a capacidade runtime recusado (v1)'
        Assert-Eq @(Get-AtmProviders).Count 1 'nenhum provider invalido registrado'
    }
    Test-Case 'Providers' 'Inventario ignora provider somente runtime (override -Providers sem registro); nenhum perfil sem agente quebra' {
        $p = New-TestProfile 'v2inv'
        $rc = New-TestRoot -ProfileInfo $p
        $rt = [pscustomobject]@{ Id = 'fake-runtime'; DisplayName = 'Fake runtime'; ContractVersion = 2; Capabilities = @('runtime') }
        $a = Get-InvArgs -Profiles @($p)
        $a['Providers'] = @((Get-AtmProviders)[0], $rt)
        $i = Invoke-AtmInventory @a
        Assert-Eq (@($i.Providers | ForEach-Object { $_.Id }) -join ',') 'claude-code' 'somente providers temp no inventario'
        Assert-Eq @($i.Partitions | Where-Object { $_.Provider -eq 'fake-runtime' }).Count 0 'nenhuma particao do runtime'
        Assert-Eq (Find-Part $i $rc).Provider 'claude-code' 'claude intacto'
        $a['Providers'] = @($rt)
        $threw = $false; try { $null = Invoke-AtmInventory @a } catch { $threw = $true }
        Assert-True $threw 'sem provider temp: erro explicito (nao inventario vazio)'
    }
    Test-Case 'Providers' 'Dicas de runtime: validas, ausentes, malformadas e com excecao (cobertura FAILED, nunca "nada em execucao")' {
        Assert-True ($null -eq (Get-AtmProviderRuntimeHints (ConvertTo-AtmTestV1Provider (Get-AtmProviders)[0]))) 'v1 sem runtime: nenhuma leitura'
        # Claude Code (v2): its process matcher, validated like any provider's.
        $ch = Get-AtmProviderRuntimeHints (Get-AtmProviders)[0]
        Assert-True ($ch.Coverage.Status -eq 'COMPLETE' -and @($ch.ProcessMatchers).Count -eq 1 -and $ch.ProcessMatchers[0].ImageName -eq 'claude.exe' -and $null -eq $ch.ProcessMatchers[0].CommandLineMarker) 'Claude Code: claude.exe sem marcador'
        $ok = [pscustomobject]@{ Id = 'fake-runtime'; DisplayName = 'F'; ContractVersion = 2; Capabilities = @('runtime')
            GetProcessMatchers = { @([pscustomobject]@{ ImageName = 'fake-agent.exe'; CommandLineMarker = '--fake-agent' }, @{ ImageName = 'fake-helper.exe' }) }
            GetServiceHints = { @([pscustomobject]@{ Name = 'FakeAgentService'; Role = 'vm-host' }) }
            GetVirtualizationHints = { @([pscustomobject]@{ Kind = 'ServiceOwner'; Value = 'FakeAgentService' }) } }
        $h = Get-AtmProviderRuntimeHints $ok
        Assert-Eq $h.Coverage.Collector 'provider-fake-runtime' 'coletor por provider'
        Assert-Eq $h.Coverage.Status 'COMPLETE' 'completo'
        Assert-Eq @($h.ProcessMatchers).Count 2 'matchers (objeto e hashtable)'
        Assert-True ($null -eq $h.ProcessMatchers[1].CommandLineMarker) 'marcador opcional ausente = $null'
        Assert-Eq $h.ServiceHints[0].Name 'FakeAgentService' 'servico'
        $none = [pscustomobject]@{ Id = 'fake-none'; DisplayName = 'F'; ContractVersion = 2; Capabilities = @('runtime') }
        $h = Get-AtmProviderRuntimeHints $none
        Assert-Eq $h.Coverage.Status 'COMPLETE' 'sem membros: completo, sem dicas'
        Assert-Eq (@($h.ProcessMatchers).Count + @($h.ServiceHints).Count + @($h.VirtualizationHints).Count) 0 'nenhuma dica'
        $badCases = @(
            @({ @([pscustomobject]@{ ImageName = 'C:\x\fake.exe' }) }, 'HINT_MALFORMED_PROCESS_MATCHERS'),
            @({ @([pscustomobject]@{ ImageName = 'fake.dll' }) }, 'HINT_MALFORMED_PROCESS_MATCHERS'),
            @({ @([pscustomobject]@{ ImageName = 'fake.exe'; CommandLineMarker = ('x' * 300) }) }, 'HINT_MALFORMED_PROCESS_MATCHERS'),
            @({ @(1..300 | ForEach-Object { [pscustomobject]@{ ImageName = "f$_.exe" } }) }, 'HINT_MALFORMED_PROCESS_MATCHERS'),
            @({ throw (New-Object InvalidOperationException('texto-que-nao-pode-aparecer')) }, 'HINT_FAILED_PROCESS_MATCHERS'))
        foreach ($bc in $badCases) {
            $pv = [pscustomobject]@{ Id = 'fake-bad'; DisplayName = 'F'; ContractVersion = 2; Capabilities = @('runtime'); GetProcessMatchers = $bc[0]
                GetServiceHints = { @([pscustomobject]@{ Name = 'FakeAgentService' }) } }
            $h = Get-AtmProviderRuntimeHints $pv
            Assert-Eq $h.Coverage.Status 'FAILED' "falha: $($bc[1])"
            Assert-True (@($h.Coverage.Reasons) -contains $bc[1]) "motivo $($bc[1]): $(@($h.Coverage.Reasons) -join ',')"
            Assert-Eq @($h.ProcessMatchers).Count 0 'membro invalido descartado inteiro'
            Assert-Eq @($h.ServiceHints).Count 1 'membros validos mantidos'
            Assert-True (-not ((@($h.Coverage.Reasons) -join ' ') -match 'texto-que')) 'mensagem da excecao nunca registrada'
        }
        $pv = [pscustomobject]@{ Id = 'fake-bad'; DisplayName = 'F'; ContractVersion = 2; Capabilities = @('runtime'); GetServiceHints = { @([pscustomobject]@{ Name = 'Bad|Name' }) }; GetVirtualizationHints = { @(@{ Kind = 'vmname'; Value = 'x' }) } }
        $h = Get-AtmProviderRuntimeHints $pv
        Assert-Eq (@($h.Coverage.Reasons) -join ',') 'HINT_MALFORMED_SERVICE_HINTS,HINT_MALFORMED_VIRTUALIZATION_HINTS' 'servico e virtualizacao malformados'
    }
    Test-Case 'Diagnose' 'Invoke-AtmDiagnose (fontes injetadas): identidade, providers, inventario e cobertura de processos/perfis; achados das particoes' {
        $p = New-TestProfile 'diag'
        $r1 = New-TestRoot -ProfileInfo $p
        $d = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p)) -IdentitySource $diagIdUser -PseudonymKey $testPseudonymKey
        Assert-Eq $d.SchemaVersion 'atm.diagnose/2' 'schema'
        Assert-Eq (@($d.Coverage | ForEach-Object { $_.Collector }) -join ',') 'identity,provider-claude-code,inventory,processes,temp-profiles,profile-discovery,process-snapshot,sessions-claude-code,agent-processes,agent-resources,services,service-properties,virtualization-platform,virtual-machines,virtualization-processes,worktree-discovery,process-cwd,handles,dependency-graph' 'coletores (Claude Code v2: dicas de runtime lidas; runtime de agentes da P1-B4-c; P2-A; P2-B; P1-C; P4-B: descoberta de perfis e grafo; P5-A: worktrees nao observadas com a trava fechada)'
        foreach ($c in @($d.Coverage | Where-Object { $_.Collector -ne 'process-cwd' -and $_.Collector -ne 'handles' -and $_.Collector -ne 'worktree-discovery' -and $_.Collector -notlike 'service*' -and $_.Collector -notlike 'virtual*' })) { Assert-Eq $c.Status 'COMPLETE' "$($c.Collector) completo" }
        $hc = @($d.Coverage | Where-Object { $_.Collector -eq 'handles' })[0]; $wc = @($d.Coverage | Where-Object { $_.Collector -eq 'process-cwd' })[0]
        $sv = @($d.Coverage | Where-Object { $_.Collector -like 'service*' })
        Assert-True ($sv.Count -eq 2 -and @($sv | Where-Object { $_.Status -ceq 'NOT_OBSERVABLE' -and @($_.Reasons) -ccontains 'SERVICE_HINTS_NONE' }).Count -eq 2) 'P2-A: nenhum servico declarado pelo Claude Code: servicos NOT_OBSERVABLE, nunca ausencia'
        Assert-True ($hc.Status -eq 'NOT_OBSERVABLE' -and (@($hc.Reasons) -join ',') -eq 'HANDLE_SECURITY_GATE_CLOSED' -and $wc.Status -eq 'NOT_OBSERVABLE' -and @($wc.Reasons) -contains 'WORKING_DIRECTORY_DEFERRED' -and -not $d.CoverageComplete) 'P1-C-S: arquivos abertos nao observados (trava fechada), diretorios de trabalho nao observados; cobertura nunca completa'
        Assert-True ($null -eq @($d.Coverage | Where-Object { $_.Collector -eq 'inventory' })[0].BudgetMs) 'inventario V0.1 sem orcamento declarado (nao interrompivel)'
        $f = @($d.Findings | Where-Object { $_.Key -ceq (& $b4PKey $r1) })
        Assert-Eq $f.Count 1 'achado da particao (pela chave pseudonima)'
        Assert-Eq $f[0].State 'UNKNOWN' 'estado (P4-B: pelo grafo; arquivos abertos e diretorios de trabalho nao observaveis, nunca livre)'
        Assert-Eq $f[0].Provider 'claude-code' 'provider'
        Assert-Eq (@($f[0].Evidence | Where-Object { $_.Code -eq 'AUDIT_CLASS' })[0].Detail) (Find-Part $d.Inventory $r1).Class 'classe da auditoria como evidencia'
        Assert-Eq (@($f[0].Coverage | ForEach-Object { $_.Collector }) -join ',') 'inventory,processes,temp-profiles,dependency-graph,process-snapshot,handles,process-cwd' 'cobertura do achado (P4-B: as do inventario, a do grafo e as dos coletores relevantes)'
        $procs = New-Procs -Extra @([pscustomobject]@{ ProcessId = 4242; Name = 'other.exe'; ParentProcessId = 1; CommandLine = $null; CreationDate = (Get-Date).AddHours(-1) })
        $d = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p) -Procs $procs) -IdentitySource $diagIdUser
        $pc = @($d.Coverage | Where-Object { $_.Collector -eq 'processes' })[0]
        Assert-True ($pc.Status -eq 'PARTIAL' -and $pc.ElevationWouldHelp -eq 'YES' -and $pc.Observed -eq 1 -and $pc.Expected -eq 2) "processos parciais: $($pc.Status)/$($pc.ElevationWouldHelp)/$($pc.Observed)/$($pc.Expected)"
        Assert-True (-not $d.CoverageComplete) 'cobertura incompleta'
        $d = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p) -Procs $procs) -IdentitySource $diagIdAdmin
        Assert-Eq (@($d.Coverage | Where-Object { $_.Collector -eq 'processes' })[0].ElevationWouldHelp) 'NO' 'administrador elevado: processos protegidos continuam invisiveis'
    }
    Test-Case 'Diagnose' 'Coerencia de cobertura (T-3): inventario incompleto nunca aparece completo no resultado, no JSON nem no relatorio' {
        # Each row builds a real sandbox inventory; nothing is mocked except the process snapshot failure.
        $rows = @(
            @{ Name = 'controle'; Collector = $null; Status = 'COMPLETE'; Reason = $null },
            @{ Name = 'snapshot'; Collector = 'processes'; Status = 'FAILED'; Reason = 'PROCESS_SNAPSHOT_FAILED' },
            @{ Name = 'uninspectable'; Collector = 'processes'; Status = 'PARTIAL'; Reason = 'UNINSPECTABLE_PROCESSES' },
            @{ Name = 'inaccessible'; Collector = 'temp-profiles'; Status = 'PARTIAL'; Reason = 'PROFILES_INACCESSIBLE' },
            @{ Name = 'unverified'; Collector = 'temp-profiles'; Status = 'PARTIAL'; Reason = 'TEMP_LOCATION_UNVERIFIED' })
        $origSnapshot = ${function:Get-AtmProcessSnapshot}
        foreach ($row in $rows) {
            $n = $row.Name
            $procs = New-Procs
            $p = New-TestProfile ('diagcoh' + $n)
            $r = New-TestRoot -ProfileInfo $p
            # A second TEMP location that cannot be read (invalid name): the profile is inaccessible without any ACL change.
            if ($n -eq 'inaccessible') { $p.TempCandidates = @($p.TempCandidates) + @([pscustomobject]@{ TempPath = (Join-Path $p.ProfilePath 'Temp|ilegivel'); Source = 'test' }) }
            if ($n -eq 'uninspectable') { $procs = New-Procs -Extra @([pscustomobject]@{ ProcessId = 4243; Name = 'other.exe'; ParentProcessId = 1; CommandLine = $null; CreationDate = (Get-Date).AddHours(-1) }) }
            if ($n -eq 'unverified') { $p.Loaded = $false; $p.EnvStatus = 'NOT_LOADED'; $p.EnvKnown = $false }
            if ($n -eq 'snapshot') { ${function:script:Get-AtmProcessSnapshot} = { param($Override) [pscustomobject]([ordered]@{ Failed = $true; Error = 'x'; Processes = @(); Total = 0; Readable = 0; Uninspectable = 0; UninspectableByName = @{} }) } }
            try { $d = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p) -Procs $procs) -IdentitySource $diagIdUser -Providers @((Get-AtmProviders)[0]) -PseudonymKey $testPseudonymKey }
            finally { ${function:script:Get-AtmProcessSnapshot} = $origSnapshot }
            $control = ($n -eq 'controle')
            Assert-Eq ([bool]$d.Inventory.CoverageComplete) $control ("$n`: Inventory.CoverageComplete (bases $(@($d.Inventory.Bases | ForEach-Object { $_.Status }) -join ','); registros legiveis $(@($d.Inventory.Registries.Values | ForEach-Object { $_.Readable }) -join ','))")
            # P1-C: process-cwd (deferred) and handles (a sample) are never complete; apart from them the control is complete.
            # P5-A: worktree-discovery (closed gate) is always NOT_OBSERVABLE too.
            $incomplete = @($d.Coverage | Where-Object { $script:AtmConclusiveCoverage -cnotcontains $_.Status -and $_.Collector -ne 'process-cwd' -and $_.Collector -ne 'handles' -and $_.Collector -ne 'worktree-discovery' -and $_.Collector -notlike 'service*' -and $_.Collector -notlike 'virtual*' })
            Assert-True (-not $d.CoverageComplete -and (($incomplete.Count -eq 0) -eq $control)) "$n`: diagnose incompleto; fora de process-cwd/handles, completo so no controle ($(@($incomplete | ForEach-Object { $_.Collector }) -join ','))"
            if (-not $control) {
                $c = @($d.Coverage | Where-Object { $_.Collector -eq $row.Collector })[0]
                Assert-True ($c.Status -ceq $row.Status -and @($c.Reasons) -ccontains $row.Reason) "$n`: $($row.Collector) $($row.Status) $($row.Reason) (obtido $($c.Status) $(@($c.Reasons) -join ','))"
                $f = @($d.Findings | Where-Object { $_.Key -ceq (& $b4PKey $r) })
                Assert-Eq $f.Count 1 "$n`: achado da particao"
                Assert-True (@($f[0].IncompleteCoverage) -ccontains $row.Collector) "$n`: achado lista $($row.Collector) como incompleto"
                if ($n -eq 'inaccessible') { Assert-Eq @($d.Inventory.InaccessibleProfiles).Count 1 'perfil inacessivel no inventario' }
                if ($n -eq 'unverified') { Assert-Eq @($d.Inventory.UnverifiedTempProfiles).Count 1 'TEMP nao verificavel no inventario' }
            } else {
                foreach ($c in @($d.Coverage | Where-Object { $_.Collector -ne 'process-cwd' -and $_.Collector -ne 'handles' -and $_.Collector -ne 'worktree-discovery' -and $_.Collector -notlike 'service*' -and $_.Collector -notlike 'virtual*' })) { Assert-Eq $c.Status 'COMPLETE' "controle: $($c.Collector) completo" }
            }
            $j = (ConvertTo-AtmDiagnoseJson -Result $d) | ConvertFrom-Json
            Assert-Eq ([bool]$j.coverageComplete) $false "$n`: JSON coverageComplete (P1-C: nunca completo)"
            Assert-Eq ([bool]$j.inventory.coverageComplete) $control "$n`: JSON inventory.coverageComplete"
            if (-not $control) { Assert-True (@($j.coverage | Where-Object { $_.collector -ceq $row.Collector -and $_.status -ceq $row.Status -and @($_.reasons) -ccontains $row.Reason }).Count -eq 1) "$n`: JSON com o mesmo codigo" }
            $old = Get-AtmLanguage
            try { Set-AtmLanguage -Requested 'en-US'; $txt = (Show-AtmDiagnose -Result $d 6>&1 | Out-String) } finally { Set-AtmLanguage -Requested $old }
            $yes = $txt.Contains('Complete coverage: YES'); $no = $txt.Contains('Complete coverage: NO')
            Assert-True (-not $yes -and $no) "$n`: relatorio (YES=$yes NO=$no; P1-C: nunca completo)"
            if (-not $control) { Assert-True ($txt.Contains($row.Reason)) "$n`: relatorio mostra $($row.Reason)" }
        }
    }
    Test-Case 'Diagnose' 'Prazo e falhas: TIMEOUT/FAILED, nunca COMPLETE; provider invalido isolado; nada e inventado' {
        $p = New-TestProfile 'diagdl'
        $null = New-TestRoot -ProfileInfo $p
        $d = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p)) -IdentitySource $diagIdUser -DeadlineSeconds 0
        foreach ($c in @('inventory', 'processes', 'temp-profiles')) {
            $x = @($d.Coverage | Where-Object { $_.Collector -eq $c })[0]
            Assert-True ($x.Status -eq 'TIMEOUT' -and @($x.Reasons) -contains 'DEADLINE_EXCEEDED') "$c TIMEOUT"
        }
        Assert-Eq @($d.Findings).Count 0 'nenhum achado inventado'
        Assert-True ($null -eq $d.Inventory -and -not $d.CoverageComplete) 'sem inventario e cobertura incompleta'
        Assert-Eq @($d.Coverage | Where-Object { $_.Collector -eq 'identity' })[0].Status 'COMPLETE' 'identidade sempre lida'
        $a = Get-InvArgs -Profiles @($p)
        $a['ConfigDir'] = (Join-Path $sandbox 'config-inexistente')
        $d = Invoke-AtmDiagnose -InventoryArgs $a -IdentitySource $diagIdUser
        $x = @($d.Coverage | Where-Object { $_.Collector -eq 'inventory' })[0]
        Assert-True ($x.Status -eq 'FAILED' -and @($x.Reasons) -contains 'INVENTORY_FAILED') 'falha do inventario'
        Assert-Eq @($x.Reasons | Where-Object { $_ -like 'EXCEPTION_*' }).Count 1 'somente o tipo da excecao'
        Assert-Eq @($d.Coverage | Where-Object { $_.Collector -eq 'processes' })[0].Status 'FAILED' 'processos desconhecidos'
        $badProv = [pscustomobject]@{ Id = 'fake-bad'; DisplayName = 'B'; ContractVersion = 9 }
        $rt = [pscustomobject]@{ Id = 'fake-runtime'; DisplayName = 'F'; ContractVersion = 2; Capabilities = @('runtime'); GetServiceHints = { @([pscustomobject]@{ Name = 'FakeAgentService' }) } }
        $d = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p)) -IdentitySource $diagIdUser -Providers @((Get-AtmProviders)[0], $badProv, $rt) -ServiceSource { param($Names) @() }
        Assert-Eq @($d.Coverage | Where-Object { $_.Collector -eq 'provider-fake-bad' })[0].Status 'FAILED' 'contrato invalido isolado'
        Assert-Eq @($d.Coverage | Where-Object { $_.Collector -eq 'provider-fake-runtime' })[0].Status 'COMPLETE' 'dicas de runtime lidas'
        Assert-Eq @($d.Coverage | Where-Object { $_.Collector -eq 'inventory' })[0].Status 'COMPLETE' 'inventario segue com o provider temp'
        Assert-Eq (@($d.Providers | ForEach-Object { $_.Id }) -join ',') 'claude-code,fake-runtime' 'somente providers validos'
        $threw = $false; try { $null = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p)) -IdentitySource $diagIdUser -DeadlineSeconds -1 } catch { $threw = $true }
        Assert-True $threw 'prazo negativo recusado'
        # Full v1 compatibility in diagnose too: a v1 provider with an upper-case Id (accepted by V0.1) takes part.
        $v1up = ConvertTo-AtmTestV1Provider (Get-AtmProviders)[0]; $v1up.Id = 'Fake-Upper-V1'; $v1up.TempSubdir = 'fake-upper'
        $d = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p)) -IdentitySource $diagIdUser -Providers @((Get-AtmProviders)[0], $v1up)
        Assert-True (@($d.Providers | Where-Object { $_.Id -eq 'Fake-Upper-V1' -and $_.ContractVersion -eq 1 }).Count -eq 1) 'v1 com Id em maiusculas listado'
        Assert-Eq @($d.Coverage | Where-Object { $_.Status -eq 'FAILED' }).Count 0 'nenhuma cobertura FAILED por causa do Id'
        Assert-True ((@($d.Inventory.Providers | ForEach-Object { $_.Id }) -join ',') -eq 'claude-code,Fake-Upper-V1') 'inventario usa os dois providers temp'
    }
    Test-Case 'Somente leitura' 'diagnose nao altera nada no sandbox (nomes, tamanhos, mtime, atributos)' {
        $p = New-TestProfile 'diagro'
        1..2 | ForEach-Object { $null = New-TestRoot -ProfileInfo $p }
        $before = Get-TreeListing $p.ProfilePath
        for ($w = 0; $w -lt 20; $w++) { Start-Sleep -Milliseconds 500; $again = Get-TreeListing $p.ProfilePath; if ($again -eq $before) { break }; $before = $again }
        $d = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p)) -IdentitySource $diagIdUser
        $null = ConvertTo-AtmDiagnoseJson -Result $d
        $null = Show-AtmDiagnose -Result $d 6>&1
        $after = Get-TreeListing $p.ProfilePath
        $diff = @(Compare-Object ($before -split "`n") ($after -split "`n") | ForEach-Object { $_.SideIndicator + ' ' + ($_.InputObject -replace '^.*\\(Users\d+)', '$1') })
        Assert-Eq $diff.Count 0 ('listagem identica: ' + ($diff -join ' ; '))
        Assert-Eq @($d.Findings | Where-Object { $_.Kind -cne 'VirtualizationPlatform' -and $_.Kind -cne 'VirtualMachine' }).Count 2 'duas particoes diagnosticadas (virtualizacao depende da maquina)'
    }
    Test-Case 'Diagnose' 'JSON atm.diagnose/2: campos iguais ao documento do schema; identico nos dois idiomas (exceto language); horarios ISO UTC; listas sempre arrays' {
        $p = New-TestProfile 'diagjson'
        $null = New-TestRoot -ProfileInfo $p
        $d = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p)) -IdentitySource $diagIdUser
        $old = Get-AtmLanguage
        try { Set-AtmLanguage -Requested 'en-US'; $en = ConvertTo-AtmDiagnoseJson -Result $d; Set-AtmLanguage -Requested 'pt-BR'; $pt = ConvertTo-AtmDiagnoseJson -Result $d } finally { Set-AtmLanguage -Requested $old }
        Assert-Eq ($en -replace '"language":\s*"[^"]*"', '') ($pt -replace '"language":\s*"[^"]*"', '') 'identico exceto language'
        $j = $en | ConvertFrom-Json
        $doc = [IO.File]::ReadAllLines((Join-Path (Split-Path -Parent $testsDir) 'docs\DIAGNOSE-SCHEMA.md'))
        $sections = @{}; $cur = $null
        foreach ($l in $doc) {
            if ($l -match '^## (.+)$') { $cur = $Matches[1].Trim(); $sections[$cur] = New-Object System.Collections.Generic.List[string]; continue }
            if ($cur -and $l -match '^\| `([A-Za-z][A-Za-z0-9]*)` \|') { $sections[$cur].Add($Matches[1]) }
        }
        $objects = [ordered]@{ 'Top level' = $j; 'identity' = $j.identity; 'providers[]' = $j.providers[0]; 'coverage[]' = $j.coverage[0]; 'findings[]' = $j.findings[0]; 'findings[].evidence[]' = $j.findings[0].evidence[0]; 'inventory' = $j.inventory
            'agentResources' = $j.agentResources; 'agentResources.counters' = $j.agentResources.counters; 'agentResources.counters.*' = $j.agentResources.counters.cpuTime100ns; 'pseudonymization' = $j.pseudonymization
            'graph' = $j.graph; 'graph.nodes[]' = $j.graph.nodes[0]; 'graph.summaries[]' = $j.graph.summaries[0]; 'graph.coverage' = $j.graph.coverage }
        foreach ($k in $objects.Keys) {
            Assert-True $sections.ContainsKey($k) "secao '$k' no documento do schema"
            Assert-Eq (@($objects[$k].PSObject.Properties.Name | Sort-Object) -join ',') (@($sections[$k] | Sort-Object) -join ',') "campos de '$k'"
        }
        Assert-Eq $j.schemaVersion 'atm.diagnose/2' 'versao'
        foreach ($name in @('startedUtc', 'finishedUtc', 'deadlineUtc', 'observedUtc')) {
            $ms = @([regex]::Matches($en, '"' + $name + '":\s*"([^"]*)"'))
            Assert-True ($ms.Count -ge 1) "$name presente"
            foreach ($m in $ms) { Assert-True ($m.Groups[1].Value -match '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z$') "$name ISO UTC: $($m.Groups[1].Value)" }
        }
        Assert-Eq ([regex]::Matches($en, '"reasons":\s*\[').Count) (@($j.coverage).Count + 1 + 1 + @($j.graph.summaries).Count) 'reasons sempre array (inclusive vazio): coverage[], agentResources, graph.coverage e graph.summaries[]'
        Assert-Eq ([regex]::Matches($en, '"capabilities":\s*\[').Count) @($j.providers).Count 'capabilities sempre array'
        $d0 = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p)) -IdentitySource $diagIdUser -DeadlineSeconds 0
        $j0 = (ConvertTo-AtmDiagnoseJson -Result $d0) | ConvertFrom-Json
        Assert-True ($j0.inventory.collected -eq $false -and $null -eq $j0.inventory.partitions) 'inventario nao coletado: null, nunca 0'
        Assert-Eq (@($j0.inventory.PSObject.Properties.Name | Sort-Object) -join ',') (@($sections['inventory'] | Sort-Object) -join ',') 'mesmos campos sem inventario'
    }
    Test-Case 'Privacidade' 'Diagnose: relatorio e JSON sem linhas de comando, argumentos ou mensagens de excecao plantados' {
        $p = New-TestProfile 'diagpriv'
        $r1 = New-TestRoot -ProfileInfo $p
        $marker = 'ATM' + 'PLANTED' + 'CMDLINE'
        $boom = 'ATM' + 'PLANTED' + 'EXCEPTION'
        $procs = New-Procs -Extra @([pscustomobject]@{ ProcessId = 777; Name = 'fake-agent.exe'; ParentProcessId = 1; CommandLine = "fake-agent.exe --secret $marker `"$r1`""; CreationDate = (Get-Date).AddHours(-1) })
        $rt = [pscustomobject]@{ Id = 'fake-runtime'; DisplayName = 'F'; ContractVersion = 2; Capabilities = @('runtime'); GetProcessMatchers = ([scriptblock]::Create("throw '$boom'")) }
        $d = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p) -Procs $procs) -IdentitySource $diagIdUser -Providers @((Get-AtmProviders)[0], $rt) -PseudonymKey $testPseudonymKey
        Assert-Eq (@(@($d.Findings | Where-Object { $_.Key -ceq (& $b4PKey $r1) })[0].Evidence | Where-Object { $_.Code -eq 'AUDIT_CLASS' })[0].Detail) 'ACTIVE_EVIDENCE' 'referencia direta considerada (classe da auditoria)'
        Assert-True (@(@($d.Coverage | Where-Object { $_.Collector -eq 'provider-fake-runtime' })[0].Reasons) -contains 'HINT_FAILED_PROCESS_MATCHERS') 'falha do provider registrada por codigo'
        $json = ConvertTo-AtmDiagnoseJson -Result $d
        $txt = (Show-AtmDiagnose -Result $d 6>&1 | Out-String)
        foreach ($s in @($json, $txt)) {
            Assert-True (-not $s.Contains($marker)) 'linha de comando nunca exportada'
            Assert-True (-not $s.Contains('--secret')) 'argumentos nunca exportados'
            Assert-True (-not $s.Contains($boom)) 'mensagem de excecao nunca exportada'
        }
    }
    Test-Case 'Diagnose' 'CLI diagnose com prazo 0 (nenhum temporario real e lido): codigo 0 e cobertura TIMEOUT; exportacao recusada pela trava (codigo 10, EXPORT_SECURITY_GATE_CLOSED); ajuda' {
        $cmd = Join-Path $srcDir 'bin\agent-temp.cmd'
        $out = (& cmd.exe /c "`"$cmd`" diagnose -DeadlineSeconds 0 -NoProgress -Lang en-US" 2>&1) -join "`n"
        Assert-Eq $LASTEXITCODE 0 'cobertura parcial nao e erro'
        Assert-True ($out -match 'inventory\s+TIMEOUT' -and $out -match 'DEADLINE_EXCEEDED' -and $out -match 'Complete coverage: NO') 'cobertura TIMEOUT relatada'
        Assert-True ($out -match 'identity\s+COMPLETE' -and $out -match 'elevation type: (DEFAULT|FULL|LIMITED)') 'identidade lida no CLI'
        $target = Join-Path $sandbox 'diag-export.json'
        $out = (& cmd.exe /c "`"$cmd`" diagnose -DeadlineSeconds 0 -NoProgress -Lang en-US -ExportJson `"$target`"" 2>&1) -join "`n"
        Assert-Eq $LASTEXITCODE 10 'exportacao recusada'
        Assert-True ($out -match 'ExportJson refused' -and $out.Contains('EXPORT_SECURITY_GATE_CLOSED') -and $out -match 'No deletion was performed') 'mensagem de recusa (trava fechada; a recusa sem inventario e coberta com a trava aberta no harness)'
        Assert-True (-not (Test-Path -LiteralPath $target)) 'nenhum arquivo criado'
        $out = (& cmd.exe /c "`"$cmd`" help -Lang en-US" 2>&1) -join "`n"
        Assert-True ($out -match 'agent-temp diagnose' -and $out -match '-DeadlineSeconds') 'ajuda'
    }
    Test-Case 'I18n' 'Diagnose: todo status de cobertura tem texto nos dois idiomas; relatorio en-US sem texto pt-BR' {
        foreach ($st in $script:AtmCoverageStatuses) { foreach ($l in @('en-US', 'pt-BR')) { Assert-True $script:AtmMessages[$l].ContainsKey("coverage.$st") "coverage.$st ($l)" } }
        $p = New-TestProfile 'diagi18n'
        $null = New-TestRoot -ProfileInfo $p
        $d = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p)) -IdentitySource $diagIdUser
        $old = Get-AtmLanguage
        try { Set-AtmLanguage -Requested 'en-US'; $txt = (Show-AtmDiagnose -Result $d 6>&1 | Out-String) } finally { Set-AtmLanguage -Requested $old }
        foreach ($w in @('Cobertura', 'somente leitura', 'Coletor', 'ACHADOS', 'RESUMO')) { Assert-True (-not $txt.Contains($w)) "en-US sem '$w'" }
        Assert-True ($txt.Contains('COVERAGE BY COLLECTOR') -and $txt.Contains('TEMPORARY PARTITIONS AND WORKTREES') -and $txt.Contains('GRAPH')) 'en-US e codigos (estado das particoes pelo grafo, P4-B)'
    }
    # ------------------------------------------------------------------ Git runner (P3-A, ADR-0006, D-4)
    # Fixtures are built with raw Git in the sandbox only: isolated configuration (no global or system file), hooks and
    # signing off, discovery bounded at the fixture root, and the top level checked before any change. The runner
    # under test never gets anything but read-only, allow-listed commands.
    $gitRoot = Join-Path $sandbox 'git'
    [void][IO.Directory]::CreateDirectory($gitRoot)
    $gitCfg = Join-Path $gitRoot 'gitconfig'
    [IO.File]::WriteAllText($gitCfg, '')
    $testGit = Resolve-AtmGitExecutable
    # P3-B0: repository commands need the worktree diagnostics gate (opened only here, in the suite's process, and always
    # closed again) and a preflight of the working directory.
    $gitOpen = { param([scriptblock]$Body) $script:AtmWorktreeDiagnosticsEnabled = $true; try { & $Body } finally { $script:AtmWorktreeDiagnosticsEnabled = $false } }
    $gitRun = { param([string[]]$GitArgs, [string]$Dir, [int]$TimeoutMs = 10000) Invoke-AtmGitCommand -Git $testGit -Arguments $GitArgs -WorkingDirectory $Dir -Preflight (Get-AtmGitPreflight -Target $Dir) -TimeoutMs $TimeoutMs }
    $gitSkip = { if ($testGit.Status -ne 'COMPLETE') { $script:caseSkipped = $true; $script:caseNote = "Git indisponivel: $($testGit.Reason)"; return $true }; return $false }
    $setEnvVar = { param([string]$Name, $Value) if ($null -eq $Value) { [Environment]::SetEnvironmentVariable($Name, [NullString]::Value) } else { [Environment]::SetEnvironmentVariable($Name, [string]$Value) } }
    # Raw Git for fixtures and counter-proofs (never the runner): returns Code and Out. -ExtraEnv adds variables for one
    # call (a counter-proof with HOME, for example).
    $gitFxOut = { param([string]$Dir, [string[]]$GitArgs, [string]$Expect, [hashtable]$ExtraEnv = @{})
        # Identity, hooks and signing through the environment (independent of how each shell passes native arguments).
        $fxEnv = [ordered]@{ GIT_CONFIG_GLOBAL = $gitCfg; GIT_CONFIG_NOSYSTEM = '1'; GIT_CEILING_DIRECTORIES = $gitRoot; GIT_DIR = $null; GIT_WORK_TREE = $null
            GIT_AUTHOR_NAME = 'atm'; GIT_AUTHOR_EMAIL = 'atm@fixture'; GIT_COMMITTER_NAME = 'atm'; GIT_COMMITTER_EMAIL = 'atm@fixture'
            GIT_CONFIG_COUNT = '2'; GIT_CONFIG_KEY_0 = 'core.hooksPath'; GIT_CONFIG_VALUE_0 = 'NUL'; GIT_CONFIG_KEY_1 = 'commit.gpgsign'; GIT_CONFIG_VALUE_1 = 'false' }
        foreach ($k in $ExtraEnv.Keys) { $fxEnv[$k] = $ExtraEnv[$k] }
        $saved = @{}; foreach ($k in $fxEnv.Keys) { $saved[$k] = [Environment]::GetEnvironmentVariable($k) }
        try {
            foreach ($k in $fxEnv.Keys) { & $setEnvVar $k $fxEnv[$k] }
            if ($Expect) {
                $top = (& $testGit.Path -C $Dir rev-parse --show-toplevel 2>$null | Out-String).Trim().Replace('/', '\')
                if (-not [string]::Equals((Get-AtmNormalizedPath $top), (Get-AtmNormalizedPath $Expect), [StringComparison]::OrdinalIgnoreCase)) { throw "fixture fora do sandbox: $top" }
            }
            # Git writes warnings to stderr: only the exit code decides (sandbox fixture, so its text may be shown).
            $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
            try { $o = @(& $testGit.Path -C $Dir @GitArgs 2>&1 | ForEach-Object { "$_" }) } finally { $ErrorActionPreference = $eap }
            return [pscustomobject]@{ Code = $LASTEXITCODE; Out = (@($o) -join "`n") }
        } finally { foreach ($k in $saved.Keys) { & $setEnvVar $k $saved[$k] } }
    }
    $gitFx = { param([string]$Dir, [string[]]$GitArgs, [string]$Expect)
        $res = & $gitFxOut $Dir $GitArgs $Expect
        if ($res.Code -ne 0) { throw "git de fixture falhou: $($GitArgs[0]) ($($res.Code)): $($res.Out.Substring(0, [Math]::Min(300, $res.Out.Length)))" }
    }
    # Listing of a tree: name, size, last-write time read from the item itself (an enumeration can return stale directory
    # times) and SHA-256 of every file, .git and its index included.
    $gitSnap = { param([string]$Root)
        @(Get-ChildItem -LiteralPath $Root -Recurse -Force | Sort-Object FullName | ForEach-Object {
                $f = $_.FullName
                if ($_.PSIsContainer) { '{0}|d|{1}' -f $f.Substring($Root.Length), [IO.Directory]::GetLastWriteTimeUtc($f).Ticks }
                else { '{0}|{1}|{2}|{3}' -f $f.Substring($Root.Length), (New-Object IO.FileInfo($f)).Length, [IO.File]::GetLastWriteTimeUtc($f).Ticks, (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash } }) -join "`n" }
    $gitNewFixture = { param([string]$Name)
        $base = Join-Path $gitRoot $Name
        $repo = Join-Path $base 'repo'; $wt = Join-Path $base 'wt'
        [void][IO.Directory]::CreateDirectory($repo)
        & $gitFx $repo @('init', '-q', '-b', 'main') $null
        & $gitFx $repo @('rev-parse', '--git-dir') $repo
        [IO.File]::WriteAllText((Join-Path $repo 'a.txt'), "a`n"); [void][IO.Directory]::CreateDirectory((Join-Path $repo 'sub')); [IO.File]::WriteAllText((Join-Path $repo 'sub\b.txt'), "b`n")
        & $gitFx $repo @('add', 'a.txt', 'sub/b.txt') $repo
        & $gitFx $repo @('commit', '-q', '-m', 'one') $repo
        & $gitFx $repo @('worktree', 'add', '-q', $wt, '-b', 'wt') $repo
        [IO.File]::WriteAllText((Join-Path $repo 'a.txt'), "a2`n")
        [IO.File]::WriteAllText((Join-Path $repo 'c.txt'), "c`n"); & $gitFx $repo @('add', 'c.txt') $repo
        [IO.File]::WriteAllText((Join-Path $repo 'u.txt'), "u`n"); [IO.File]::WriteAllText((Join-Path $wt 'w.txt'), "w`n")
        [void][IO.Directory]::CreateDirectory((Join-Path $repo 'plain\deeper'))
        return [pscustomobject]@{ Base = $base; Repo = $repo; Worktree = $wt } }
    # P3-E: a repository (real Git fixture, one commit) with -Worktrees linked worktrees and -Refs remote-tracking refs,
    # written as files only (administrative entries, .git files, loose refs), every worktree a child of one partition.
    $scaleFixture = { param([string]$Name, [int]$Worktrees, [int]$Refs)
        $base = Join-Path $gitRoot $Name
        $repo = Join-Path $base 'repo'; $part = Join-Path $base 'part'
        foreach ($d in @($repo, $part)) { [void][IO.Directory]::CreateDirectory($d) }
        & $gitFx $repo @('init', '-q', '-b', 'main') $null
        [IO.File]::WriteAllText((Join-Path $repo 'a.txt'), "a`n"); & $gitFx $repo @('add', 'a.txt') $repo; & $gitFx $repo @('commit', '-q', '-m', 'one') $repo
        $head = (& $gitFxOut $repo @('rev-parse', 'HEAD') $repo).Out.Trim()
        $gd = Join-Path $repo '.git'
        $rr = Join-Path $gd 'refs\remotes\origin'; [void][IO.Directory]::CreateDirectory($rr)
        for ($i = 0; $i -lt $Refs; $i++) { [IO.File]::WriteAllText((Join-Path $rr ('b' + $i)), "$head`n") }
        for ($i = 0; $i -lt $Worktrees; $i++) {
            $n = 'wt' + $i; $wt = Join-Path $part $n; $ad = Join-Path $gd ('worktrees\' + $n)
            foreach ($d in @($wt, $ad)) { [void][IO.Directory]::CreateDirectory($d) }
            [IO.File]::WriteAllText((Join-Path $wt '.git'), "gitdir: $ad`n")
            [IO.File]::WriteAllText((Join-Path $ad 'gitdir'), (Join-Path $wt '.git') + "`n")
            [IO.File]::WriteAllText((Join-Path $ad 'HEAD'), "ref: refs/heads/main`n")
            [IO.File]::WriteAllText((Join-Path $ad 'commondir'), "../..`n")
        }
        return [pscustomobject]@{ Repo = $repo; Part = $part; Partitions = @([pscustomobject]@{ Path = $part; Kind = 'SessionRoot' }) }
    }
    $gitAllowed = @(
        @('--version'), @('rev-parse', '--show-toplevel', '--git-dir', '--git-common-dir', '--is-inside-work-tree'), @('worktree', 'list', '--porcelain', '-z'),
        @('status', '--porcelain=v2', '-z', '--branch', '--untracked-files=all'), @('status', '--porcelain=v2', '-z', '--ignored=matching', '--show-stash'),
        @('for-each-ref', '--format=%(refname)%00%(objectname)', 'refs/heads', 'refs/remotes'), @('rev-list', '--count', 'HEAD', '--not', '--remotes'),
        @('config', '--name-only', '--get-regexp', '^core\.'), @('cat-file', '-e', 'HEAD'))
    Test-Case 'Git' 'Executor Git (P3-A): git.exe so de entradas absolutas do PATH; relativo, .cmd e ausente nunca executados; local gravavel por usuarios recusado quando elevado' {
        if (& $gitSkip) { return }
        Assert-True ([IO.Path]::IsPathRooted($testGit.Path) -and $testGit.Path -match '\\git\.exe$' -and $null -ne $testGit.Version) "git resolvido: $($testGit.Version)"
        if ($env:GITHUB_ACTIONS -eq 'true') { Assert-Eq (Resolve-AtmGitExecutable).Status 'COMPLETE' 'CI (elevado): local do Git confiavel pela regra do instalador' }
        $script:AtmGitInvocationLog = New-Object System.Collections.Generic.List[object]
        try {
            $rel = Join-Path $gitRoot 'rel'; [void][IO.Directory]::CreateDirectory($rel); [IO.File]::WriteAllText((Join-Path $rel 'git.exe'), 'not a program')
            $cmdDir = Join-Path $gitRoot 'cmdonly'; [void][IO.Directory]::CreateDirectory($cmdDir); [IO.File]::WriteAllText((Join-Path $cmdDir 'git.cmd'), '@echo planted')
            $r = Resolve-AtmGitExecutable -PathVariable ('rel;.\rel;' + [IO.Path]::GetFileName($rel) + ';"' + $cmdDir + '";' + (Join-Path $gitRoot 'missing'))
            Assert-True ($r.Status -eq 'UNAVAILABLE' -and $r.Reason -eq 'GIT_NOT_FOUND' -and $null -eq $r.Path) "relativo, .cmd e ausente: $($r.Reason)"
            Assert-Eq $script:AtmGitInvocationLog.Count 0 'nada executado'
            $u = Invoke-AtmGitCommand -Git $null -Arguments @('--version') -WorkingDirectory $gitRoot
            Assert-True ($u.Status -eq 'UNAVAILABLE' -and $u.Reason -eq 'GIT_NOT_FOUND' -and $script:AtmGitInvocationLog.Count -eq 0) 'sem Git: UNAVAILABLE, nada executado'
            $open = Join-Path $gitRoot 'open'; [void][IO.Directory]::CreateDirectory($open); [IO.File]::WriteAllText((Join-Path $open 'git.exe'), 'not a program')
            $null = & icacls.exe $open /grant '*S-1-5-32-545:(OI)(CI)(M)' 2>&1
            $r = Resolve-AtmGitExecutable -PathVariable $open -Elevated $true
            Assert-True ($r.Status -eq 'UNAVAILABLE' -and $r.Reason -eq 'GIT_LOCATION_NOT_TRUSTED' -and $script:AtmGitInvocationLog.Count -eq 0) "elevado e local gravavel por Users: $($r.Reason), nada executado"
            $r = Resolve-AtmGitExecutable -PathVariable $open -Elevated $false
            Assert-True ($r.Status -eq 'UNAVAILABLE' -and $r.Reason -eq 'GIT_VERSION_UNREADABLE') "nao elevado, arquivo que nao e programa: $($r.Reason)"
            Assert-True ($script:AtmGitInvocationLog.Count -eq 1 -and ($script:AtmGitInvocationLog[0].Arguments -join ' ') -match ' --version$') 'so o --version foi tentado'
        } finally { $script:AtmGitInvocationLog = $null }
    }
    Test-Case 'Git' 'Executor Git (P3-A): allow-list e diretorio de trabalho recusados antes de qualquer processo; formas permitidas aceitas' {
        foreach ($a in $gitAllowed) { Assert-True ($null -eq (Test-AtmGitArguments -Arguments $a)) "permitido: $($a -join ' ')" }
        $refused = @(
            @('fetch'), @('pull'), @('push'), @('prune'), @('gc'), @('maintenance', 'run'), @('repack'), @('checkout', 'main'), @('switch', 'main'), @('restore', 'a.txt'), @('reset', '--hard'),
            @('clean', '-fdx'), @('stash'), @('worktree', 'add', 'x'), @('worktree', 'remove', 'x'), @('worktree', 'prune'), @('worktree', 'move', 'a', 'b'), @('worktree', 'repair'), @('worktree', 'lock', 'x'),
            @('update-index', '--refresh'), @('reflog', 'expire'), @('commit-graph', 'write'), @('-c', 'core.fsmonitor=x', 'status', '--porcelain=v2', '-z'), @('--exec-path=x', '--version'), @('-C', 'x', 'status'),
            @('status'), @('status', '--porcelain=v2'), @('status', '--porcelain=v2', '-z', '--untracked-cache'), @('config', '--get', 'user.name'), @('config', '--name-only', '--get-regexp'),
            @('config', '--list'), @('rev-parse', '--git-path', 'x'), @('rev-parse'), @('rev-list', '--objects', 'HEAD'), @('cat-file', '-p', 'HEAD'), @('cat-file', '-e', '^HEAD'),
            @('for-each-ref', '--format=%(refname) x'), @('rev-parse', 'HEAD extra'), @('rev-parse', 'HEAD"'), @('--version', 'x'), @())
        $script:AtmGitInvocationLog = New-Object System.Collections.Generic.List[object]
        try {
            foreach ($a in $refused) {
                $code = Test-AtmGitArguments -Arguments $a
                Assert-True ($code -eq 'GIT_VERB_NOT_ALLOWED' -or $code -eq 'GIT_ARGUMENT_REFUSED') "recusado: [$($a -join ' ')] -> $code"
                $r = Invoke-AtmGitCommand -Git ([pscustomobject]@{ Path = 'C:\nao\existe\git.exe' }) -Arguments $a -WorkingDirectory $gitRoot
                Assert-True ($r.Status -eq 'REFUSED' -and $r.Reason -eq $code) "runner recusa: [$($a -join ' ')]"
            }
            foreach ($wd in @('relativo', 'C:', (Join-Path $gitRoot 'nao-existe'), $gitCfg, '')) {
                $r = Invoke-AtmGitCommand -Git ([pscustomobject]@{ Path = 'C:\nao\existe\git.exe' }) -Arguments @('--version') -WorkingDirectory $wd
                Assert-True ($r.Status -eq 'REFUSED' -and $r.Reason -eq 'GIT_WORKDIR_INVALID') "diretorio de trabalho invalido recusado: '$wd'"
            }
            Assert-Eq $script:AtmGitInvocationLog.Count 0 'nenhum processo iniciado por um pedido recusado'
        } finally { $script:AtmGitInvocationLog = $null }
    }
    Test-Case 'Git' 'Executor Git (P3-A): somente leitura em repositorio e worktree descartaveis (nomes, tamanhos, horarios, SHA-256, .git\index, diretorios); opcoes globais; ambiente sanitizado; teto de descoberta com caminho curto' {
        if (& $gitSkip) { return }
        $fx = & $gitNewFixture 'ro'
        # A repository-configured fsmonitor hook that would leave a marker if Git ran it.
        $marker = Join-Path $fx.Base 'fsmonitor-ran.txt'
        $hook = Join-Path $fx.Base 'fsmon.sh'
        [IO.File]::WriteAllText($hook, "#!/bin/sh`necho ran > '" + $marker.Replace('\', '/') + "'`n")
        & $gitFx $fx.Repo @('config', 'core.fsmonitor', $hook.Replace('\', '/')) $fx.Repo
        Start-Sleep -Milliseconds 1100
        $before = & $gitSnap $fx.Base
        $script:AtmGitInvocationLog = New-Object System.Collections.Generic.List[object]
        $script:AtmWorktreeDiagnosticsEnabled = $true
        try {
            foreach ($a in $gitAllowed) {
                foreach ($wd in @($fx.Repo, $fx.Worktree)) {
                    $r = & $gitRun $a $wd
                    Assert-True ($r.Status -eq 'COMPLETE' -and $r.ExitCode -eq 0) "[$($a -join ' ')] em $(Split-Path -Leaf $wd): $($r.Status) $($r.Reason)"
                }
            }
            $st = & $gitRun @('status', '--porcelain=v2', '-z', '--untracked-files=all') $fx.Repo
            $recs = @($st.Output.Split([char]0) | Where-Object { $_ })
            Assert-True (@($recs | Where-Object { $_ -like '1 .M *a.txt' }).Count -eq 1 -and @($recs | Where-Object { $_ -like '1 A. *c.txt' }).Count -eq 1 -and @($recs | Where-Object { $_ -ceq '? u.txt' }).Count -eq 1) "status v2 le a fixture: $(@($recs) -join ' | ')"
            $wl = & $gitRun @('worktree', 'list', '--porcelain', '-z') $fx.Repo
            Assert-Eq @($wl.Output.Split([char]0) | Where-Object { $_ -like 'worktree *' }).Count 2 'worktree list: repositorio e worktree'
            Start-Sleep -Milliseconds 300
            $after = & $gitSnap $fx.Base
            $diff = @(Compare-Object ($before -split "`n") ($after -split "`n") | ForEach-Object { $_.SideIndicator + ($_.InputObject -replace '\|[0-9A-F]{64}$', '') })
            Assert-Eq $diff.Count 0 ('nada alterado no repositorio nem na worktree: ' + ($diff -join ' ; '))
            Assert-True (-not (Test-Path -LiteralPath $marker)) 'hook fsmonitor do repositorio nao executado (core.fsmonitor=false)'
            Assert-True (-not (Test-Path -LiteralPath (Join-Path $fx.Repo '.git\index.lock'))) 'nenhum index.lock'
            foreach ($v in $script:AtmGitInvocationLog) {
                $args0 = [string[]]$v.Arguments
                Assert-Eq (($args0 | Select-Object -First $script:AtmGitGlobalArguments.Count) -join ' ') ($script:AtmGitGlobalArguments -join ' ') 'opcoes globais em toda chamada'
                Assert-True ($null -eq (Test-AtmGitArguments -Arguments @($args0 | Select-Object -Skip $script:AtmGitGlobalArguments.Count))) "vetor registrado permitido: $($args0 -join ' ')"
            }
            $ga = $script:AtmGitGlobalArguments -join ' '
            Assert-True ($ga -match '--no-optional-locks' -and $ga -match 'core\.fsmonitor=false' -and $ga -match 'protocol\.allow=never') 'sem locks opcionais, sem fsmonitor, protocolos recusados por padrao'
            foreach ($proto in @('file', 'git', 'ssh', 'http', 'https', 'ext')) { Assert-True ($ga -match "protocol\.$proto\.allow=never") "protocolo $proto recusado por nome (a configuracao do repositorio nao o reativa)" }
            Assert-True ($ga -match 'core\.excludesFile=NUL' -and $ga -match 'core\.attributesFile=NUL') 'arquivos globais de exclusao e atributos nunca lidos'
        } finally { $script:AtmGitInvocationLog = $null; $script:AtmWorktreeDiagnosticsEnabled = $false }
        # Environment: inherited GIT_* never reach the child; locale C; ceiling.
        $saved = @{}; foreach ($k in 'GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_CONFIG_PARAMETERS', 'GIT_CONFIG_COUNT', 'GIT_CONFIG_KEY_0', 'GIT_CONFIG_VALUE_0') { $saved[$k] = [Environment]::GetEnvironmentVariable($k) }
        try {
            $env:GIT_DIR = (Join-Path $gitRoot 'bogus'); $env:GIT_WORK_TREE = $gitRoot; $env:GIT_INDEX_FILE = (Join-Path $gitRoot 'bogus-index'); $env:GIT_CONFIG_PARAMETERS = "'core.bare=true'"
            $env:GIT_CONFIG_COUNT = '1'; $env:GIT_CONFIG_KEY_0 = 'core.worktree'; $env:GIT_CONFIG_VALUE_0 = $gitRoot
            $envList = Get-AtmGitEnvironment -Ceiling 'C:\x'
            Assert-True (@($envList | Where-Object { $_ -match '^GIT_(DIR|WORK_TREE|INDEX_FILE|CONFIG_PARAMETERS|CONFIG_COUNT|CONFIG_KEY_0|CONFIG_VALUE_0)=' }).Count -eq 0) 'GIT_* herdados removidos'
            foreach ($kv in @('GIT_OPTIONAL_LOCKS=0', 'GIT_TERMINAL_PROMPT=0', 'GCM_INTERACTIVE=never', 'GIT_ASKPASS=', 'SSH_ASKPASS=', 'GIT_NO_LAZY_FETCH=1', 'GIT_DISCOVERY_ACROSS_FILESYSTEM=0', 'GIT_CEILING_DIRECTORIES=C:\x', 'LC_ALL=C', 'LANG=C')) { Assert-True ($envList -contains $kv) "ambiente: $kv" }
            $r = & $gitOpen { & $gitRun @('rev-parse', '--show-toplevel') $fx.Repo }
            Assert-True ($r.Status -eq 'COMPLETE' -and [string]::Equals((Get-AtmNormalizedPath $r.Output.Trim().Replace('/', '\')), (Get-AtmNormalizedPath $fx.Repo), [StringComparison]::OrdinalIgnoreCase)) "variaveis GIT_* do chamador ignoradas: $($r.Status)"
        } finally { foreach ($k in $saved.Keys) { & $setEnvVar $k $saved[$k] } }
        $iso = Get-AtmGitEnvironment -Ceiling 'C:\x' -IsolatedHome 'C:\iso\none'
        foreach ($kv in @('GIT_CONFIG_GLOBAL=NUL', 'GIT_CONFIG_NOSYSTEM=1', 'GIT_ATTR_NOSYSTEM=1', 'HOME=C:\iso\none', 'USERPROFILE=C:\iso\none', 'XDG_CONFIG_HOME=C:\iso\none')) { Assert-True ($iso -contains $kv) "configuracao isolada: $kv" }
        # A junction in the working directory path is refused (Git would work from the resolved directory, above the ceiling).
        $jn = Join-Path $fx.Base 'junction-to-plain'
        $null = & cmd.exe /c mklink /J "$jn" "$(Join-Path $fx.Repo 'plain\deeper')" 2>&1
        if (Test-Path -LiteralPath $jn) {
            $r = & $gitOpen { Invoke-AtmGitCommand -Git $testGit -Arguments @('rev-parse', '--show-toplevel') -WorkingDirectory $jn -Preflight (Get-AtmGitPreflight -Target $jn) }
            Assert-True ($r.Status -eq 'REFUSED' -and $r.Reason -eq 'GIT_WORKDIR_REPARSE_OR_UNREADABLE') "juncao no caminho recusada: $($r.Reason)"
            Assert-Eq (Get-AtmGitPreflight -Target $jn).Reason 'GIT_REF_PATH_REPARSE' 'preflight recusa a juncao'
        } else { Assert-True $false 'juncao de teste nao criada' }
        # Ceiling: a plain directory inside the repository is not attributed to it, also through its 8.3 name.
        $plain = Join-Path $fx.Repo 'plain\deeper'
        foreach ($wd in @($plain, [AgentTempManager.AtmNative]::GetShortPath($plain))) {
            $pf = Get-AtmGitPreflight -Target $wd
            Assert-True ($pf.Status -eq 'NOT_A_REPOSITORY') "preflight: diretorio comum dentro do repositorio nao e repositorio ($wd)"
            $r = & $gitOpen { Invoke-AtmGitCommand -Git $testGit -Arguments @('rev-parse', '--show-toplevel') -WorkingDirectory $wd -Preflight $pf }
            Assert-True ($r.Status -eq 'REFUSED' -and $r.Reason -eq 'GIT_PREFLIGHT_REQUIRED') "sem repositorio, o Git nao roda: $($r.Reason)"
            # The ceiling itself, observed with Git through the same job, options and environment.
            $wdn = Get-AtmNormalizedPath $wd
            $j = Invoke-AtmBoundedProcess -Executable $testGit.Path -CommandLine ('"' + $testGit.Path + '" ' + (@($script:AtmGitGlobalArguments) + @('rev-parse', '--show-toplevel') -join ' ')) -WorkingDirectory $wdn -Environment (Get-AtmGitEnvironment -Ceiling (Get-AtmNormalizedPath ([IO.Path]::GetDirectoryName($wdn))) -IsolatedHome $testGit.IsolatedHome) -TimeoutMs 10000 -MaxOutputBytes 65536 -JobMemoryBytes 1GB -ActiveProcessLimit 8
            Assert-True ($j.ExitCode -ne 0 -and ([Text.Encoding]::UTF8.GetString($j.ErrorOutput)) -match 'not a git repository') "teto de descoberta observado no Git ($wd)"
        }
        # Control for the fsmonitor marker (raw Git, after the read-only checks): whether this Git runs the hook at all.
        & $gitFx $fx.Repo @('status', '--porcelain') $fx.Repo
        $script:caseNote = $(if (Test-Path -LiteralPath $marker) { 'controle: o Git sem as opcoes do executor roda o hook fsmonitor' } else { 'controle: este Git nao rodou o hook fsmonitor (teste do marcador sem contraprova)' })
    }
    Test-Case 'Git' 'Executor Git (P3-A, D-4): prazo encerra so o job proprio (filho e neto), sem index.lock e sem afetar processo preexistente; limites de memoria, processos e saida' {
        if (& $gitSkip) { return }
        $fx = & $gitNewFixture 'to'
        Start-Sleep -Milliseconds 1100
        $before = & $gitSnap $fx.Base
        $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        # A process outside the job, started before the runs; it ends by itself.
        $sentinel = [Diagnostics.Process]::Start((New-Object Diagnostics.ProcessStartInfo($ps, '-NoProfile -Command Start-Sleep 40') -Property @{ UseShellExecute = $false; CreateNoWindow = $true }))
        $sentStart = $sentinel.StartTime
        $r = & $gitOpen { & $gitRun @('status', '--porcelain=v2', '-z', '--untracked-files=all') $fx.Repo 0 }
        Assert-True ($r.Status -eq 'TIMEOUT' -and $r.Reason -eq 'GIT_TIMEOUT' -and $null -eq $r.Output) "prazo 0: $($r.Status)"
        Start-Sleep -Milliseconds 500
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $fx.Repo '.git\index.lock'))) 'nenhum index.lock depois do prazo'
        $diff = @(Compare-Object ($before -split "`n") ((& $gitSnap $fx.Base) -split "`n"))
        Assert-Eq $diff.Count 0 'repositorio intacto depois do encerramento por prazo'
        # Child and grandchild in the job; the deadline terminates the job, both end; the sentinel lives.
        $envList = Get-AtmGitEnvironment -Ceiling $gitRoot
        $script = '$g = Start-Process -FilePath powershell.exe -ArgumentList ''-NoProfile -Command Start-Sleep 60'' -PassThru -WindowStyle Hidden; [Console]::Out.WriteLine(''{0}|{1}'' -f $g.Id, $g.StartTime.ToUniversalTime().Ticks); [Console]::Out.Flush(); Start-Sleep 60'
        $j = Invoke-AtmBoundedProcess -Executable $ps -CommandLine ('"powershell.exe" -NoProfile -Command "' + $script.Replace('"', '\"') + '"') -WorkingDirectory $gitRoot -Environment $envList -TimeoutMs 20000 -MaxOutputBytes 4096 -JobMemoryBytes 1GB -ActiveProcessLimit 8
        $runStart = [datetime]::Now.AddSeconds(-25)
        $parts = ([Text.Encoding]::ASCII.GetString($j.Output).Trim()).Split('|')
        Assert-True ($j.Started -and $j.TimedOut -and $j.JobTerminated -and $j.TotalProcesses -ge 3) "job encerrado no prazo com filho e neto: total $($j.TotalProcesses), saida '$($parts -join '|')', stderr '$(([Text.Encoding]::UTF8.GetString($j.ErrorOutput)).Trim())'"
        Start-Sleep -Milliseconds 800
        # No process the job's child started is still alive (the child itself is gone too).
        $kids = @(Get-CimInstance Win32_Process -Filter "ParentProcessId = $($j.ProcessId)" -ErrorAction SilentlyContinue | Where-Object { $_.CreationDate -ge $runStart -and $_.ProcessId -ne $PID })
        Assert-True ($kids.Count -eq 0 -and $null -eq (Get-Process -Id $j.ProcessId -ErrorAction SilentlyContinue | Where-Object { $_.StartTime -ge $runStart })) "filho e neto (dentro do job) encerrados: $($kids.Count) restantes"
        if ($parts.Count -eq 2) { $gp = Get-Process -Id ([int]$parts[0]) -ErrorAction SilentlyContinue; Assert-True ($null -eq $gp -or $gp.StartTime.ToUniversalTime().Ticks -ne [long]$parts[1]) 'neto (PID e horario impressos pelo filho) encerrado' }
        $sp = Get-Process -Id $sentinel.Id -ErrorAction SilentlyContinue
        Assert-True ($null -ne $sp -and $sp.StartTime -eq $sentStart) 'processo preexistente fora do job continua vivo'
        # Limits read back from the job and their effect (non-Git children).
        $j = Invoke-AtmBoundedProcess -Executable $ps -CommandLine '"powershell.exe" -NoProfile -Command "try { $p = Start-Process cmd.exe -ArgumentList ''/c exit 0'' -PassThru -Wait -WindowStyle Hidden; exit 0 } catch { exit 7 }"' -WorkingDirectory $gitRoot -Environment $envList -TimeoutMs 30000 -MaxOutputBytes 4096 -JobMemoryBytes 1GB -ActiveProcessLimit 1
        Assert-True ($j.ActiveProcessLimit -eq 1 -and $j.ExitCode -eq 7) "limite de 1 processo: o filho nao cria outro (saida $($j.ExitCode))"
        $j = Invoke-AtmBoundedProcess -Executable $ps -CommandLine '"powershell.exe" -NoProfile -Command "[Console]::Out.Write((''x'' * 300000))"' -WorkingDirectory $gitRoot -Environment $envList -TimeoutMs 30000 -MaxOutputBytes 65536 -JobMemoryBytes 1GB -ActiveProcessLimit 8
        Assert-True ($j.ExitCode -eq 0 -and $j.Output.Length -eq 65536 -and $j.OutputTruncated) "saida limitada: $($j.Output.Length) bytes, truncada $($j.OutputTruncated)"
        $alloc = '"powershell.exe" -NoProfile -Command "try { $b = New-Object byte[] 1500000000 -ErrorAction Stop; $b[0] = 1; exit 0 } catch { exit 9 }"'
        $j = Invoke-AtmBoundedProcess -Executable $ps -CommandLine $alloc -WorkingDirectory $gitRoot -Environment $envList -TimeoutMs 60000 -MaxOutputBytes 4096 -JobMemoryBytes 400MB -ActiveProcessLimit 8
        Assert-True ($j.JobMemoryLimit -eq 400MB -and $j.ExitCode -eq 9) "limite de memoria do job (lido de volta $($j.JobMemoryLimit)): alocacao de 1,5 GB recusada (saida $($j.ExitCode), esperado 9)"
        $j = Invoke-AtmBoundedProcess -Executable $ps -CommandLine $alloc -WorkingDirectory $gitRoot -Environment $envList -TimeoutMs 60000 -MaxOutputBytes 4096 -JobMemoryBytes 3GB -ActiveProcessLimit 8
        Assert-True ($j.JobMemoryLimit -eq 3GB -and $j.ExitCode -eq 0) "contraprova: com limite de 3 GB a mesma alocacao funciona (saida $($j.ExitCode))"
        $threw = $false; try { $null = Invoke-AtmBoundedProcess -Executable $ps -CommandLine 'x' -WorkingDirectory $gitRoot -Environment $envList -TimeoutMs 1000 -MaxOutputBytes 0 -JobMemoryBytes 1GB -ActiveProcessLimit 1 } catch { $threw = $true }
        Assert-True $threw 'limites invalidos recusados'
        foreach ($bad in @(@(-1, 4096, 1GB, 1), @(1000, 0, 1GB, 1), @(1000, 4096, -1, 1), @(1000, 4096, 1GB, 0))) {
            $threw = $false; try { $null = [AgentTempManager.AtmJobRunner]::Run($ps, '"powershell.exe" -NoProfile -Command exit', $gitRoot, $envList, $bad[0], $bad[1], [long]$bad[2], $bad[3]) } catch { $threw = $true }
            Assert-True $threw "executor nativo recusa limites invalidos ($($bad -join ','))"
        }
        $script:caseNote = "sentinela PID $($sentinel.Id) termina sozinho"
    }
    # ------------------------------------------------------------------ P3-B0: security preconnect gate
    $uncHost = 'atm-unc-probe.invalid'
    $gitSpy = { param([scriptblock]$Body) $script:AtmGitInvocationLog = New-Object System.Collections.Generic.List[object]; try { & $Body; return $script:AtmGitInvocationLog.Count } finally { $script:AtmGitInvocationLog = $null } }
    Test-Case 'Git' 'P3-B0: resolvedor de caminhos referenciados recusa rede, expansoes e formas de dispositivo antes de qualquer acesso; parser de configuracao estrito' {
        $base = Join-Path $gitRoot 'resolver'; [void][IO.Directory]::CreateDirectory((Join-Path $base 'sub'))
        $refused = [ordered]@{
            ('\\' + $uncHost + '\s\x') = 'GIT_REF_PATH_NETWORK'; ('//' + $uncHost + '/s/x') = 'GIT_REF_PATH_NETWORK'; ('\\?\UNC\' + $uncHost + '\s') = 'GIT_REF_PATH_NETWORK'; '\\.\pipe\x' = 'GIT_REF_PATH_NETWORK'
            ('/\' + $uncHost + '\s') = 'GIT_REF_PATH_NETWORK'; ('\/' + $uncHost + '/s') = 'GIT_REF_PATH_NETWORK'; ('file://' + $uncHost + '/s') = 'GIT_REF_PATH_NETWORK'; 'file:x' = 'GIT_REF_PATH_NETWORK'; ('https://' + $uncHost + '/x') = 'GIT_REF_PATH_NETWORK'
            '~/x' = 'GIT_REF_PATH_EXPANSION'; '%(prefix)/x' = 'GIT_REF_PATH_EXPANSION'; '$HOME/x' = 'GIT_REF_PATH_EXPANSION'; '%USERPROFILE%\x' = 'GIT_REF_PATH_EXPANSION'
            'C:x' = 'GIT_REF_PATH_INVALID'; 'C:' = 'GIT_REF_PATH_INVALID'; ($base + '\a:ads') = 'GIT_REF_PATH_INVALID'; '\rooted\no-drive' = 'GIT_REF_PATH_INVALID'; 'sub\na*me' = 'GIT_REF_PATH_INVALID'; '' = 'GIT_REF_PATH_INVALID'
        }
        foreach ($c in $refused.GetEnumerator()) { $r = Resolve-AtmGitReferencedPath -Value $c.Key -BaseDir $base; Assert-True ($r.Status -eq 'REFUSED' -and $r.Reason -eq $c.Value -and $null -eq $r.Path) "recusado [$($c.Key)]: $($r.Reason)" }
        $r = Resolve-AtmGitReferencedPath -Value 'sub\..\sub' -BaseDir $base
        Assert-True ($r.Status -eq 'OK' -and $r.Path -ceq (Join-Path $base 'sub')) 'relativo resolvido sem acesso fora da base'
        Assert-Eq (Resolve-AtmGitReferencedPath -Value 'nope' -BaseDir $base).Status 'MISSING' 'local inexistente: MISSING'
        $unused = $null
        foreach ($l in [char[]]'BDEFGHIJKLMNOPQRSTUVWXYZ') { if (-not (Test-Path -LiteralPath "$($l):\")) { $unused = $l; break } }
        if ($unused) { Assert-Eq (Resolve-AtmGitReferencedPath -Value "$($unused):\x" -BaseDir $base).Reason 'GIT_REF_PATH_NETWORK' 'unidade inexistente ou de rede (nao fixa) recusada' }
        $jn = Join-Path $base 'jn'; $null = & cmd.exe /c mklink /J "$jn" "$(Join-Path $base 'sub')" 2>&1
        Assert-Eq (Resolve-AtmGitReferencedPath -Value 'jn\x' -BaseDir $base).Reason 'GIT_REF_PATH_REPARSE' 'reparse point no caminho recusado'
        # Strict configuration parser.
        $ok = Read-AtmGitConfigText -Text "# c`n[core]`n`trepositoryformatversion = 0`n`tbare`n[remote `"origin`"]`n`turl = `"https://example.invalid/x`" ; c`n[a.b]`n`tk = `"x\\y\`"z`"`n"
        Assert-True ($null -eq $ok.Error -and @($ok.Entries).Count -eq 4 -and @($ok.Entries | Where-Object { $_.Section -eq 'core' -and $_.Key -eq 'bare' -and $_.Value -eq 'true' }).Count -eq 1 -and @($ok.Entries | Where-Object { $_.Key -eq 'k' -and $_.Value -ceq 'x\y"z' }).Count -eq 1) 'configuracao valida lida e decodificada'
        foreach ($bad in @("[core]`n`tworktree = a \`n`tb", "[core]`n`tk = `"open", "[core]`n`tk = a\q", "k = v", "[core`n", "[core] junk`n", "[sec `"sub`" x]", "[core]`n`t= v")) {
            Assert-Eq (Read-AtmGitConfigText -Text $bad).Error 'GIT_CONFIG_UNPARSEABLE' "linha nao entendida recusa o arquivo: $($bad.Replace("`n", '|'))"
        }
        $inc = Read-AtmGitConfigText -Text "[INCLUDE]`n`tpath = x"
        Assert-Eq (Get-AtmGitConfigFindings -Entries $inc.Entries -BaseDir $base).Refuse 'GIT_PREFLIGHT_INCLUDE' '[INCLUDE] em maiusculas tambem e include'
        $inc = Read-AtmGitConfigText -Text "[includeIf `"onbranch:x`"]`n`tpath = x"
        Assert-Eq (Get-AtmGitConfigFindings -Entries $inc.Entries -BaseDir $base).Refuse 'GIT_PREFLIGHT_INCLUDE' 'includeIf em qualquer forma'
        $esc = Read-AtmGitConfigText -Text ("[core]`n`texcludesFile = \\\\" + $uncHost + "\\s\\x")
        Assert-Eq (Get-AtmGitConfigFindings -Entries $esc.Entries -BaseDir $base).Refuse 'GIT_PREFLIGHT_CONFIG_PATH' 'caminho UNC escrito com escapes decodificado e recusado'
        # A value on a drive that is not fixed, in any key (stand-in: an unassigned letter; a real mapped drive is not used).
        $freeL = @([char[]]'ZYXWVUTSRQPONMLKJIHG' | Where-Object { (New-Object IO.DriveInfo([string]$_)).DriveType -eq [IO.DriveType]::NoRootDirectory })
        if ($freeL.Count -gt 0) {
            $mapped = Read-AtmGitConfigText -Text ("[mailmap]`n`tfile = " + $freeL[0] + ":/share/mailmap")
            Assert-Eq (Get-AtmGitConfigFindings -Entries $mapped.Entries -BaseDir $base).Refuse 'GIT_PREFLIGHT_CONFIG_NETWORK' 'valor em unidade nao fixa recusado em qualquer chave'
        }
        $sysL = $env:SystemDrive.Substring(0, 1)
        $fixed = Read-AtmGitConfigText -Text ("[mailmap]`n`tfile = " + $sysL + ":/x/mailmap")
        Assert-Eq (Get-AtmGitConfigFindings -Entries $fixed.Entries -BaseDir $base).Refuse $null 'valor em unidade fixa fora das chaves de caminho permitido'
    }
    Test-Case 'Git' 'P3-B0: cada vetor que leva o Git para fora do repositorio e provado com caminho local (contraprova) e recusado com caminho de rede antes de qualquer processo (espiao: zero)' {
        if (& $gitSkip) { return }
        $out = Join-Path $gitRoot 'outside'; [void][IO.Directory]::CreateDirectory($out)
        $incFile = Join-Path $out 'inc.cfg'; [IO.File]::WriteAllText($incFile, "[atm]`n`tprobe = from-include`n")
        $refusedRun = { param([string]$Dir) & $gitSpy { $null = & $gitOpen { Invoke-AtmGitCommand -Git $testGit -Arguments @('rev-parse', '--show-toplevel') -WorkingDirectory $Dir -Preflight (Get-AtmGitPreflight -Target $Dir) } } }
        # include and includeIf: Git reads configuration from outside the repository.
        $fx = & $gitNewFixture 'v-inc'
        & $gitFx $fx.Repo @('config', '--add', 'include.path', $incFile.Replace('\', '/')) $fx.Repo
        Assert-Eq (& $gitFxOut $fx.Repo @('config', '--get', 'atm.probe') $fx.Repo).Out.Trim() 'from-include' 'contraprova: o Git le o include local'
        $pf = Get-AtmGitPreflight -Target $fx.Repo
        Assert-True ($pf.Status -eq 'REFUSED' -and $pf.Reason -eq 'GIT_PREFLIGHT_INCLUDE') "include recusado: $($pf.Reason)"
        Assert-Eq (& $refusedRun $fx.Repo) 0 'include: nenhum processo Git'
        $fx = & $gitNewFixture 'v-incif'
        & $gitFx $fx.Repo @('config', '--add', ('includeIf.gitdir/i:' + (Get-AtmNormalizedPath $fx.Repo).Replace('\', '/') + '/.path'), $incFile.Replace('\', '/')) $fx.Repo
        Assert-Eq (& $gitFxOut $fx.Repo @('config', '--get', 'atm.probe') $fx.Repo).Out.Trim() 'from-include' 'contraprova: o Git le o includeIf local'
        Assert-Eq (Get-AtmGitPreflight -Target $fx.Repo).Reason 'GIT_PREFLIGHT_INCLUDE' 'includeIf recusado'
        # Alternates: Git reads objects from another directory.
        $fxA = & $gitNewFixture 'v-alt-src'
        $oid = (& $gitFxOut $fxA.Repo @('rev-parse', 'HEAD') $fxA.Repo).Out.Trim()
        $fx = & $gitNewFixture 'v-alt'
        $altFile = Join-Path $fx.Repo '.git\objects\info\alternates'
        [IO.File]::WriteAllText($altFile, (Join-Path $fxA.Repo '.git\objects') + "`n")
        Assert-Eq (& $gitFxOut $fx.Repo @('cat-file', '-e', $oid) $fx.Repo).Code 0 'contraprova: o Git le objetos do alternate local'
        $pf = Get-AtmGitPreflight -Target $fx.Repo
        Assert-True ($pf.Status -eq 'OK' -and $pf.Alternates -eq 1) 'alternate local permitido e contado'
        [IO.File]::WriteAllText($altFile, "\\$uncHost\share\objects`n")
        Assert-Eq (Get-AtmGitPreflight -Target $fx.Repo).Reason 'GIT_PREFLIGHT_ALTERNATE_NETWORK' 'alternate de rede recusado'
        Assert-Eq (& $refusedRun $fx.Repo) 0 'alternate de rede: nenhum processo Git'
        [IO.File]::WriteAllText($altFile, (Join-Path $fxA.Repo '.git\objects') + "`n")
        [IO.File]::WriteAllText((Join-Path $fxA.Repo '.git\objects\info\alternates'), "//$uncHost/share/objects`n")
        Assert-Eq (Get-AtmGitPreflight -Target $fx.Repo).Reason 'GIT_PREFLIGHT_ALTERNATE_NETWORK' 'alternate de rede num alternate (encadeado) recusado'
        # gitdir: a .git file sends Git to another directory.
        $fxG = & $gitNewFixture 'v-gitdir'
        $redir = Join-Path $out 'redir'; [void][IO.Directory]::CreateDirectory($redir)
        [IO.File]::WriteAllText((Join-Path $redir '.git'), 'gitdir: ' + (Join-Path $fxG.Repo '.git') + "`n")
        $gd = (& $gitFxOut $redir @('rev-parse', '--absolute-git-dir') $null).Out.Trim().Replace('/', '\')
        Assert-True ([string]::Equals((Get-AtmNormalizedPath $gd), (Get-AtmNormalizedPath (Join-Path $fxG.Repo '.git')), [StringComparison]::OrdinalIgnoreCase)) "contraprova: o arquivo .git leva o Git a outro diretorio ($gd)"
        Assert-Eq (Get-AtmGitPreflight -Target $redir).Status 'OK' 'gitdir local permitido'
        $redirU = Join-Path $out 'redir-unc'; [void][IO.Directory]::CreateDirectory($redirU)
        [IO.File]::WriteAllText((Join-Path $redirU '.git'), "gitdir: \\$uncHost\share\repo.git`n")
        Assert-Eq (Get-AtmGitPreflight -Target $redirU).Reason 'GIT_PREFLIGHT_GITDIR_NETWORK' 'gitdir de rede recusado'
        Assert-Eq (& $refusedRun $redirU) 0 'gitdir de rede: nenhum processo Git'
        # commondir of a worktree's administrative directory.
        $admin = Join-Path $fxG.Repo '.git\worktrees\fake'; [void][IO.Directory]::CreateDirectory($admin)
        [IO.File]::WriteAllText((Join-Path $admin 'commondir'), "//$uncHost/share/common`n")
        $wtFake = Join-Path $out 'wt-fake'; [void][IO.Directory]::CreateDirectory($wtFake)
        [IO.File]::WriteAllText((Join-Path $wtFake '.git'), "gitdir: $admin`n")
        Assert-Eq (Get-AtmGitPreflight -Target $wtFake).Reason 'GIT_PREFLIGHT_COMMONDIR_NETWORK' 'commondir de rede recusado'
        # Administrative gitdir: `worktree list` stats it.
        $fx = & $gitNewFixture 'v-admin'
        $ad = Join-Path $fx.Repo '.git\worktrees\gone'; [void][IO.Directory]::CreateDirectory($ad)
        [IO.File]::WriteAllText((Join-Path $ad 'gitdir'), (Join-Path $out 'missing-wt\.git') + "`n"); [IO.File]::WriteAllText((Join-Path $ad 'HEAD'), "ref: refs/heads/main`n")
        Assert-True ((& $gitFxOut $fx.Repo @('worktree', 'list', '--porcelain') $fx.Repo).Out -match 'prunable') 'contraprova: worktree list consulta o gitdir administrativo (prunable)'
        $pf = Get-AtmGitPreflight -Target $fx.Repo
        Assert-True ($pf.Status -eq 'OK' -and @($pf.AdminEntries | Where-Object { $_.Name -eq 'gone' -and $_.Gitdir.Status -eq 'MISSING' }).Count -eq 1) 'gitdir administrativo local ausente: MISSING (evidencia, nao recusa)'
        [IO.File]::WriteAllText((Join-Path $ad 'gitdir'), "\\$uncHost\share\wt\.git`n")
        Assert-Eq (Get-AtmGitPreflight -Target $fx.Repo).Reason 'GIT_PREFLIGHT_ADMIN_NETWORK' 'gitdir administrativo de rede recusado (o repositorio inteiro)'
        Assert-Eq (& $refusedRun $fx.Repo) 0 'gitdir administrativo de rede: nenhum processo Git'
        # Path-valued configuration and an unparseable file.
        $fx = & $gitNewFixture 'v-cfg'
        $alt = Join-Path $out 'other-tree'; [void][IO.Directory]::CreateDirectory($alt)
        & $gitFx $fx.Repo @('config', 'core.worktree', $alt.Replace('\', '/')) $fx.Repo
        $tl = (& $gitFxOut $fx.Repo @('rev-parse', '--show-toplevel') $null).Out.Trim().Replace('/', '\')
        Assert-True ([string]::Equals((Get-AtmNormalizedPath $tl), (Get-AtmNormalizedPath $alt), [StringComparison]::OrdinalIgnoreCase)) 'contraprova: core.worktree leva o Git a outro diretorio'
        Assert-Eq (Get-AtmGitPreflight -Target $fx.Repo).Reason 'GIT_PREFLIGHT_CORE_WORKTREE' 'core.worktree recusado mesmo local (o Git o resolve a partir do diretorio Git)'
        Assert-Eq (& $refusedRun $fx.Repo) 0 'core.worktree: nenhum processo Git'
        & $gitFx $fx.Repo @('config', '--unset', 'core.worktree') $null
        $cfgFile = Join-Path $fx.Repo '.git\config'
        foreach ($c in @(@("[core]`n`tworktree = \\\\$uncHost\\share", 'GIT_PREFLIGHT_CORE_WORKTREE'), @("[core]`n`tworktree = ../lnk", 'GIT_PREFLIGHT_CORE_WORKTREE'), @("[core]`n`thooksPath = \\\\$uncHost\\hooks", 'GIT_PREFLIGHT_CONFIG_PATH'), @("[core]`n`texcludesFile = //$uncHost/s/ignore", 'GIT_PREFLIGHT_CONFIG_PATH'), @("[core]`n`tattributesFile = ~/attr", 'GIT_PREFLIGHT_CONFIG_PATH'),
                @("[atm]`n`tsomething = \\\\$uncHost\\x", 'GIT_PREFLIGHT_CONFIG_NETWORK'), @("[core]`n`tbroken = a \`n`tb", 'GIT_CONFIG_UNPARSEABLE'))) {
            $orig = [IO.File]::ReadAllText($cfgFile)
            [IO.File]::WriteAllText($cfgFile, $orig + "`n" + $c[0] + "`n")
            Assert-Eq (Get-AtmGitPreflight -Target $fx.Repo).Reason $c[1] "configuracao recusada: $($c[1])"
            [IO.File]::WriteAllText($cfgFile, $orig)
        }
        # Bare fallback: when <dir>\.git is not a Git directory, Git reads <dir> itself as a bare repository (its config
        # included). Proved locally, then refused.
        $bareX = Join-Path $out 'bare-fallback'
        foreach ($d in @('.git', 'objects', 'refs')) { [void][IO.Directory]::CreateDirectory((Join-Path $bareX $d)) }
        [IO.File]::WriteAllText((Join-Path $bareX 'HEAD'), "ref: refs/heads/main`n"); [IO.File]::WriteAllText((Join-Path $bareX 'config'), "[atm]`n`tprobe = from-target-config`n")
        Assert-Eq (& $gitFxOut $bareX @('config', '--get', 'atm.probe') $null).Out.Trim() 'from-target-config' 'contraprova: o Git le o proprio alvo como repositorio bare'
        Assert-Eq (Get-AtmGitPreflight -Target $bareX).Reason 'GIT_PREFLIGHT_TARGET_IS_GITDIR' 'alvo com HEAD recusado'
        Assert-Eq (& $refusedRun $bareX) 0 'alvo bare: nenhum processo Git'
        $badHead = Join-Path $out 'bad-head'
        foreach ($d in @('.git\objects', '.git\refs')) { [void][IO.Directory]::CreateDirectory((Join-Path $badHead $d)) }
        [IO.File]::WriteAllText((Join-Path $badHead '.git\HEAD'), "garbage`n")
        Assert-Eq (Get-AtmGitPreflight -Target $badHead).Reason 'GIT_PREFLIGHT_GITDIR_INVALID' 'diretorio .git sem HEAD valido recusado'
        $noObj = Join-Path $out 'no-objects'; [void][IO.Directory]::CreateDirectory((Join-Path $noObj '.git\refs'))
        [IO.File]::WriteAllText((Join-Path $noObj '.git\HEAD'), "ref: refs/heads/main`n")
        Assert-Eq (Get-AtmGitPreflight -Target $noObj).Reason 'GIT_PREFLIGHT_GITDIR_INVALID' 'diretorio .git sem objects recusado'
        # A relative hooks path (Husky) is not read by the allowed commands: allowed.
        $orig = [IO.File]::ReadAllText($cfgFile)
        [IO.File]::WriteAllText($cfgFile, $orig + "`n[core]`n`thooksPath = .husky/_`n")
        Assert-Eq (Get-AtmGitPreflight -Target $fx.Repo).Status 'OK' 'core.hooksPath relativo permitido'
        [IO.File]::WriteAllText($cfgFile, $orig + "`n[url `"https://example.invalid/`"]`n`tinsteadOf = g:`n")
        Assert-Eq (Get-AtmGitPreflight -Target $fx.Repo).Status 'OK' 'valor com letra e dois pontos que nao e caminho permitido'
        [IO.File]::WriteAllText($cfgFile, $orig)
        # Paths stored in Git files are taken exactly as Git reads them: blanks Git would keep are refused.
        $ws = Join-Path $out 'gitfile-ws'; [void][IO.Directory]::CreateDirectory($ws)
        [IO.File]::WriteAllText((Join-Path $ws '.git'), 'gitdir:  ' + (Join-Path $fxG.Repo '.git') + "`n")
        Assert-Eq (Get-AtmGitPreflight -Target $ws).Reason 'GIT_PREFLIGHT_GITFILE_INVALID' 'gitfile com espaco extra recusado'
        [IO.File]::WriteAllText((Join-Path $ws '.git'), 'gitdir: ' + (Join-Path $fxG.Repo '.git') + "`r`n")
        Assert-Eq (Get-AtmGitPreflight -Target $ws).Status 'OK' 'gitfile com CRLF final aceito (como o Git)'
        [IO.File]::WriteAllText((Join-Path $admin 'commondir'), " ..\..`n")
        Assert-Eq (Get-AtmGitPreflight -Target $wtFake).Reason 'GIT_PREFLIGHT_COMMONDIR_INVALID' 'commondir com espaco inicial recusado'
        # Links where `worktree list` reads: a lock of an administrative entry, a loose ref.
        $lockTarget = Join-Path $out 'lock-target'; [void][IO.Directory]::CreateDirectory($lockTarget)
        $fxL = & $gitNewFixture 'v-link-lock'
        & $gitFx $fxL.Repo @('worktree', 'add', '-q', (Join-Path $out 'wt-link-lock'), '-b', 'links') $fxL.Repo
        Assert-Eq (Get-AtmGitPreflight -Target $fxL.Repo).Status 'OK' 'antes do link: permitido'
        New-Junction -Link (Join-Path $fxL.Repo '.git\worktrees\wt-link-lock\locked') -Target $lockTarget
        Assert-Eq (Get-AtmGitPreflight -Target $fxL.Repo).Reason 'GIT_PREFLIGHT_ADMIN_REPARSE' 'trava administrativa como link recusada'
        Assert-Eq (& $refusedRun $fxL.Repo) 0 'trava como link: nenhum processo Git'
        $fxR = & $gitNewFixture 'v-link-ref'
        New-Junction -Link (Join-Path $fxR.Repo '.git\refs\heads\linked') -Target $lockTarget
        Assert-Eq (Get-AtmGitPreflight -Target $fxR.Repo).Reason 'GIT_PREFLIGHT_REFS_REPARSE' 'ref como link recusada'
        Assert-Eq (& $refusedRun $fxR.Repo) 0 'ref como link: nenhum processo Git'
        # Reserved device names never reach the file system.
        foreach ($v in @('C:\x\COM1', 'C:\x\nul.txt', 'AUX', 'C:\x\LPT9\y', 'C:\x\conout')) { Assert-Eq (Resolve-AtmGitReferencedPath -Value $v -BaseDir $out).Reason 'GIT_REF_PATH_INVALID' "nome de dispositivo recusado: $v" }
        # A forged preflight is not enough: the runner takes its own.
        $forged = [pscustomobject]@{ Status = 'OK'; WorkTree = (Get-AtmNormalizedPath $bareX); GitDir = (Join-Path $bareX '.git'); CommonDir = (Join-Path $bareX '.git'); StatusAllowed = $true }
        $n = & $gitSpy { $script:fr = & $gitOpen { Invoke-AtmGitCommand -Git $testGit -Arguments @('rev-parse', '--show-toplevel') -WorkingDirectory $bareX -Preflight $forged } }
        Assert-True ($n -eq 0 -and $script:fr.Reason -eq 'GIT_PREFLIGHT_REQUIRED') "pre-verificacao forjada recusada sem processo: $($script:fr.Reason)"
        # A PATH entry on a drive that is not fixed is skipped before any file-system call.
        $free = @([char[]]'ZYXWVUTSRQPONMLKJIHG' | Where-Object { (New-Object IO.DriveInfo([string]$_)).DriveType -eq [IO.DriveType]::NoRootDirectory })
        if ($free.Count -gt 0) { Assert-Eq (Resolve-AtmGitExecutable -PathVariable ("$($free[0]):\Git\cmd") -Elevated $false).Reason 'GIT_NOT_FOUND' 'entrada do PATH em unidade nao fixa ignorada' }
        $script:caseNote = 'host UNC de teste em .invalid; nenhum valor de rede chega a uma chamada de sistema de arquivos'
    }
    Test-Case 'Git' 'P3-B0: configuracao isolada (so opcoes de linha de comando) e D-3 (filtro do repositorio bloqueia status; atributo sem driver e filtro global nao executam), com contraprovas' {
        if (& $gitSkip) { return }
        # One observation: with the runner environment, Git sees only command-line configuration.
        $plain = Join-Path $gitRoot 'iso-plain'; [void][IO.Directory]::CreateDirectory($plain)
        $fakeHome = Join-Path $gitRoot 'fake-home'; [void][IO.Directory]::CreateDirectory($fakeHome)
        $marker = Join-Path $gitRoot 'filter-ran.txt'
        $evil = "echo ran > '" + $marker.Replace('\', '/') + "' && cat"
        [IO.File]::WriteAllText((Join-Path $fakeHome '.gitconfig'), "[atm]`n`tprobe = from-home`n[filter `"evil`"]`n`tclean = $evil`n")
        $line = '"' + $testGit.Path + '" ' + ((@($script:AtmGitGlobalArguments) + @('config', '--list', '--show-origin')) -join ' ')
        $saved = @{ HOME = $env:HOME; USERPROFILE = $env:USERPROFILE }
        try {
            & $setEnvVar 'HOME' $fakeHome; & $setEnvVar 'USERPROFILE' $fakeHome
            $iso = Invoke-AtmBoundedProcess -Executable $testGit.Path -CommandLine $line -WorkingDirectory $plain -Environment (Get-AtmGitEnvironment -Ceiling $gitRoot -IsolatedHome $testGit.IsolatedHome) -TimeoutMs 10000 -MaxOutputBytes 65536 -JobMemoryBytes 1GB -ActiveProcessLimit 8
            $origins = @(([Text.Encoding]::UTF8.GetString($iso.Output)).Split("`n") | Where-Object { $_ } | ForEach-Object { ($_ -split "`t")[0] } | Select-Object -Unique)
            Assert-True ($iso.ExitCode -eq 0 -and $origins.Count -ge 1 -and @($origins | Where-Object { $_ -ne 'command line:' }).Count -eq 0) "isolada: so 'command line:' ($($origins -join ', '))"
            # Control: the caller's environment without any GIT_* variable (none left over by other tests), HOME on the fake home.
            $ctl = @([Environment]::GetEnvironmentVariables().GetEnumerator() | Where-Object { -not ([string]$_.Key).StartsWith('GIT_', [StringComparison]::OrdinalIgnoreCase) -and @('HOME', 'USERPROFILE') -notcontains [string]$_.Key } | ForEach-Object { "$($_.Key)=$($_.Value)" }) + @("HOME=$fakeHome", "USERPROFILE=$fakeHome")
            $raw = Invoke-AtmBoundedProcess -Executable $testGit.Path -CommandLine ('"' + $testGit.Path + '" config --list --show-origin') -WorkingDirectory $plain -Environment $ctl -TimeoutMs 10000 -MaxOutputBytes 65536 -JobMemoryBytes 1GB -ActiveProcessLimit 8
            $rawText = [Text.Encoding]::UTF8.GetString($raw.Output)
            Assert-True ($rawText -match 'file:' -and $rawText -match 'from-home') 'contraprova: sem isolamento o Git le arquivos de configuracao (inclusive o HOME)'
        } finally { foreach ($k in $saved.Keys) { & $setEnvVar $k $saved[$k] } }
        # D-3 (a): a filter driver configured in the repository blocks status; raw Git runs it.
        $fx = & $gitNewFixture 'd3-repo'
        [IO.File]::WriteAllText((Join-Path $fx.Repo '.gitattributes'), "a.txt filter=evil`n")
        & $gitFx $fx.Repo @('config', 'filter.evil.clean', $evil) $fx.Repo
        $pf = Get-AtmGitPreflight -Target $fx.Repo
        Assert-True ($pf.Status -eq 'OK' -and -not $pf.StatusAllowed -and $pf.StatusBlock -eq 'D3_FILTER_DRIVER') "filtro no repositorio bloqueia status: $($pf.StatusBlock)"
        $n = & $gitSpy { $r = & $gitOpen { Invoke-AtmGitCommand -Git $testGit -Arguments @('status', '--porcelain=v2', '-z') -WorkingDirectory $fx.Repo -Preflight $pf }; Assert-Eq $r.Reason 'GIT_STATUS_PRECONDITION' 'status recusado sem as precondicoes D-3' }
        Assert-Eq $n 0 'status bloqueado: nenhum processo Git'
        $r = & $gitOpen { & $gitRun @('rev-parse', '--show-toplevel') $fx.Repo }
        Assert-Eq $r.Status 'COMPLETE' 'outros comandos seguem permitidos'
        Assert-True (-not (Test-Path -LiteralPath $marker)) 'filtro nao executado pelo executor'
        Start-Sleep -Milliseconds 1100; [IO.File]::WriteAllText((Join-Path $fx.Repo 'a.txt'), "a`n")
        $null = & $gitFxOut $fx.Repo @('status', '--porcelain') $fx.Repo
        Assert-True (Test-Path -LiteralPath $marker) 'contraprova: o Git sem as protecoes executa o filtro do repositorio'
        # D-3 (b): an attribute without a configured driver, and (c) a driver in a global file under HOME: status runs, nothing executes.
        $marker2 = Join-Path $gitRoot 'filter-ran-2.txt'
        $evil2 = "echo ran > '" + $marker2.Replace('\', '/') + "' && cat"
        [IO.File]::WriteAllText((Join-Path $fakeHome '.gitconfig'), "[filter `"evil`"]`n`tclean = $evil2`n")
        $fx = & $gitNewFixture 'd3-attr'
        [IO.File]::WriteAllText((Join-Path $fx.Repo '.gitattributes'), "a.txt filter=evil`n")
        Start-Sleep -Milliseconds 1100; [IO.File]::WriteAllText((Join-Path $fx.Repo 'a.txt'), "a`n")
        $saved = @{ HOME = $env:HOME; USERPROFILE = $env:USERPROFILE }
        try {
            & $setEnvVar 'HOME' $fakeHome; & $setEnvVar 'USERPROFILE' $fakeHome
            $pf = Get-AtmGitPreflight -Target $fx.Repo
            Assert-True ($pf.Status -eq 'OK' -and $pf.StatusAllowed) 'sem driver no repositorio: status permitido'
            $r = & $gitOpen { Invoke-AtmGitCommand -Git $testGit -Arguments @('status', '--porcelain=v2', '-z') -WorkingDirectory $fx.Repo -Preflight $pf }
            Assert-True ($r.Status -eq 'COMPLETE' -and -not (Test-Path -LiteralPath $marker2)) "status executado; atributo sem driver e driver global ignorados: $($r.Status)"
            $null = & $gitFxOut $fx.Repo @('status', '--porcelain') $fx.Repo @{ GIT_CONFIG_GLOBAL = $null; HOME = $fakeHome }
            Assert-True (Test-Path -LiteralPath $marker2) 'contraprova: o Git com o HOME do usuario executa o filtro global'
        } finally { foreach ($k in $saved.Keys) { & $setEnvVar $k $saved[$k] } }
        # Submodules block status too.
        $fx = & $gitNewFixture 'd3-sub'
        [IO.File]::WriteAllText((Join-Path $fx.Repo '.gitmodules'), "[submodule `"x`"]`n`tpath = x`n`turl = ./x`n")
        Assert-Eq (Get-AtmGitPreflight -Target $fx.Repo).StatusBlock 'D3_SUBMODULES' '.gitmodules bloqueia status'
    }
    Test-Case 'Git' 'P3-B0: sem rede e sem lazy fetch em clone parcial (contraprova: o Git sem as protecoes tenta buscar o objeto); versao minima 2.45.0' {
        if (& $gitSkip) { return }
        Assert-True ($testGit.Version -ge $script:AtmGitMinimumVersion -and $script:AtmGitMinimumVersion -eq [version]'2.45.0') "Git $($testGit.Version) atende a versao minima $($script:AtmGitMinimumVersion)"
        Assert-True ([version]'2.44.9' -lt $script:AtmGitMinimumVersion) 'versao anterior seria GIT_VERSION_TOO_OLD'
        $fxS = & $gitNewFixture 'lazy-server'
        [IO.File]::WriteAllText((Join-Path $fxS.Repo 'big.txt'), ('x' * 5000)); & $gitFx $fxS.Repo @('add', 'big.txt') $fxS.Repo; & $gitFx $fxS.Repo @('commit', '-q', '-m', 'big') $fxS.Repo
        $client = Join-Path $gitRoot 'lazy-client'
        $srcUrl = 'file:///' + $fxS.Repo.Replace('\', '/')
        # The filter is honoured only when the serving repository allows it.
        & $gitFx $fxS.Repo @('config', 'uploadpack.allowFilter', 'true') $fxS.Repo
        $res = & $gitFxOut $gitRoot @('-c', 'protocol.file.allow=always', 'clone', '-q', '--no-checkout', '--filter=blob:none', $srcUrl, $client) $null
        Assert-Eq $res.Code 0 "clone parcial da fixture: $($res.Out)"
        $missing = @((& $gitFxOut $client @('rev-list', '--objects', '--missing=print', 'HEAD') $client).Out.Split("`n") | Where-Object { $_ -match '^\?[0-9a-f]{40}' } | ForEach-Object { $_.Substring(1, 40) })
        Assert-True ($missing.Count -ge 1) "blob ausente no clone parcial ($($missing.Count))"
        # The promisor now points to a local path that does not exist.
        & $gitFx $client @('config', 'remote.origin.url', ('file:///' + (Join-Path $gitRoot 'no-such-server').Replace('\', '/'))) $client
        Start-Sleep -Milliseconds 1100
        $before = & $gitSnap $client
        $pf = Get-AtmGitPreflight -Target $client
        Assert-Eq $pf.Status 'OK' 'clone parcial passa no preflight (o promissor nunca e contatado)'
        $r = & $gitOpen { Invoke-AtmGitCommand -Git $testGit -Arguments @('cat-file', '-e', $missing[0]) -WorkingDirectory $client -Preflight $pf }
        Assert-True ($r.Status -eq 'FAILED') "objeto ausente nao buscado: $($r.Status)"
        $wdn = Get-AtmNormalizedPath $client
        $j = Invoke-AtmBoundedProcess -Executable $testGit.Path -CommandLine ('"' + $testGit.Path + '" ' + ((@($script:AtmGitGlobalArguments) + @('cat-file', '-e', $missing[0])) -join ' ')) -WorkingDirectory $wdn -Environment (Get-AtmGitEnvironment -Ceiling (Get-AtmNormalizedPath $gitRoot) -IsolatedHome $testGit.IsolatedHome) -TimeoutMs 10000 -MaxOutputBytes 65536 -JobMemoryBytes 1GB -ActiveProcessLimit 8
        $err = [Text.Encoding]::UTF8.GetString($j.ErrorOutput)
        # cat-file -e is silent: with lazy fetching disabled it only fails, and never names the promisor.
        Assert-True ($j.ExitCode -ne 0 -and $err -notmatch 'no-such-server|does not appear') "lazy fetch desativado e promissor nunca contatado (saida $($j.ExitCode)): $($err.Trim())"
        $envNoLazy = @(Get-AtmGitEnvironment -Ceiling (Get-AtmNormalizedPath $gitRoot) -IsolatedHome $testGit.IsolatedHome | Where-Object { $_ -notmatch '^GIT_NO_LAZY_FETCH=' })
        $j = Invoke-AtmBoundedProcess -Executable $testGit.Path -CommandLine ('"' + $testGit.Path + '" ' + ((@($script:AtmGitGlobalArguments) + @('cat-file', '-e', $missing[0])) -join ' ')) -WorkingDirectory $wdn -Environment $envNoLazy -TimeoutMs 10000 -MaxOutputBytes 65536 -JobMemoryBytes 1GB -ActiveProcessLimit 8
        $err2 = [Text.Encoding]::UTF8.GetString($j.ErrorOutput)
        Assert-True ($j.ExitCode -ne 0 -and $err2 -match "transport 'file' not allowed") "segunda camada: mesmo sem GIT_NO_LAZY_FETCH o transporte e recusado ($($err2.Trim()))"
        Assert-Eq (@(Compare-Object ($before -split "`n") ((& $gitSnap $client) -split "`n")).Count) 0 'nenhum objeto novo no clone'
        $raw = & $gitFxOut $client @('-c', 'protocol.file.allow=always', 'cat-file', '-e', $missing[0]) $null
        Assert-True ($raw.Code -ne 0 -and $raw.Out -match 'no-such-server|does not appear|not a git repository|could not read') "contraprova: o Git sem as protecoes tenta buscar no promissor ($($raw.Out.Trim().Split("`n")[0]))"
    }
    Test-Case 'Git' 'P3-B0: trava de diagnostico de worktrees fechada por padrao; cadeia elevada (launcher, programa efetivo e diretorios) verificada' {
        if (& $gitSkip) { return }
        Assert-Eq $script:AtmWorktreeDiagnosticsEnabled $false 'trava fechada fora dos testes'
        $diag = [IO.File]::ReadAllText((Join-Path $srcDir 'lib\Engine.Diagnose.ps1'))
        Assert-Eq ([regex]::Matches($diag, '\$script:AtmWorktreeDiagnosticsEnabled\s*=').Count) 1 'uma unica atribuicao da trava no motor'
        Assert-True ($diag -match '\$script:AtmWorktreeDiagnosticsEnabled = \$false') 'a trava distribuida e $false'
        $others = @(Get-ChildItem -LiteralPath $srcDir -Recurse -File -Filter '*.ps1' | Where-Object { $_.Name -ne 'Engine.Diagnose.ps1' -and ([IO.File]::ReadAllText($_.FullName)) -match 'AtmWorktreeDiagnosticsEnabled\s*=' })
        Assert-Eq $others.Count 0 'nenhum outro arquivo altera a trava'
        $fx = & $gitNewFixture 'gate'
        $n = & $gitSpy { $r = Invoke-AtmGitCommand -Git $testGit -Arguments @('rev-parse', '--show-toplevel') -WorkingDirectory $fx.Repo -Preflight (Get-AtmGitPreflight -Target $fx.Repo); Assert-Eq $r.Reason 'GIT_EXECUTION_GATE_CLOSED' 'trava fechada: comando no repositorio recusado' }
        Assert-Eq $n 0 'trava fechada: nenhum processo'
        Assert-Eq (Invoke-AtmGitCommand -Git $testGit -Arguments @('--version') -WorkingDirectory ([IO.Path]::GetDirectoryName($testGit.Path))).Status 'COMPLETE' 'so --version roda com a trava fechada'
        Assert-True ($null -ne $testGit.EffectivePath -and [IO.File]::Exists($testGit.EffectivePath) -and $null -ne $testGit.IsolatedHome -and -not [IO.Directory]::Exists($testGit.IsolatedHome)) "programa efetivo identificado ($([IO.Path]::GetFileName([IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName($testGit.EffectivePath))))); HOME isolado inexistente"
        # Git for Windows layout in the sandbox: launcher and effective program are found; elevated, the chain is refused.
        $fg = Join-Path $gitRoot 'fakegit'
        foreach ($d in @('cmd', 'mingw64\bin')) { [void][IO.Directory]::CreateDirectory((Join-Path $fg $d)) }
        [IO.File]::WriteAllText((Join-Path $fg 'cmd\git.exe'), 'not a program'); [IO.File]::WriteAllText((Join-Path $fg 'mingw64\bin\git.exe'), 'not a program')
        $n = & $gitSpy { $r = Resolve-AtmGitExecutable -PathVariable (Join-Path $fg 'cmd') -Elevated $true; Assert-Eq $r.Reason 'GIT_LOCATION_NOT_TRUSTED' 'elevado: cadeia nao confiavel recusada' }
        Assert-Eq $n 0 'elevado e nao confiavel: nada executado'
        $r = Resolve-AtmGitExecutable -PathVariable (Join-Path $fg 'cmd') -Elevated $false
        Assert-True ($r.Reason -eq 'GIT_VERSION_UNREADABLE' -and $r.Path -eq (Get-AtmNormalizedPath (Join-Path $fg 'cmd\git.exe'))) 'layout reconhecido (versao ilegivel: arquivo que nao e programa)'
        if ($env:GITHUB_ACTIONS -eq 'true') { Assert-Eq (Resolve-AtmGitExecutable -Elevated $true).Status 'COMPLETE' 'CI elevado: launcher, programa efetivo, bibliotecas e diretorios confiaveis' }
    }
    Test-Case 'Git' 'P3-B: descoberta limitada as fontes (particoes e caminhos explicitos), deduplicada, registro pelas entradas administrativas e confirmado pelo Git, orfao so com nao encontrado positivo, pseudonimos e somente leitura' {
        if (& $gitSkip) { return }
        $base = Join-Path $gitRoot 'disc'
        $partA = Join-Path $base 'partA'; $partB = Join-Path $base 'partB'
        foreach ($d in @($partA, $partB)) { [void][IO.Directory]::CreateDirectory($d) }
        # Repository R (main + locked worktree + worktree whose directory was removed) under partition A, reached again
        # through an explicit path deep inside it; repository Q is the partition B root itself; S sits next to the
        # partitions and is never named.
        $R = Join-Path $partA 'proj'; [void][IO.Directory]::CreateDirectory($R)
        & $gitFx $R @('init', '-q', '-b', 'main') $null
        [IO.File]::WriteAllText((Join-Path $R 'a.txt'), "a`n"); & $gitFx $R @('add', 'a.txt') $R; & $gitFx $R @('commit', '-q', '-m', 'one') $R
        $wtL = Join-Path $base 'wt-locked'; & $gitFx $R @('worktree', 'add', '-q', $wtL, '-b', 'locked') $R; & $gitFx $R @('worktree', 'lock', '--reason', 'keep', $wtL) $R
        $ad = Join-Path $R '.git\worktrees\ghost'; [void][IO.Directory]::CreateDirectory($ad)
        [IO.File]::WriteAllText((Join-Path $ad 'gitdir'), (Join-Path $base 'ghost-wt\.git') + "`n"); [IO.File]::WriteAllText((Join-Path $ad 'HEAD'), "ref: refs/heads/main`n")
        [void][IO.Directory]::CreateDirectory((Join-Path $R 'deep\deeper'))
        & $gitFx $partB @('init', '-q', '-b', 'main') $null
        $S = Join-Path $base 'stranger'; [void][IO.Directory]::CreateDirectory($S); & $gitFx $S @('init', '-q', '-b', 'main') $null
        [IO.File]::WriteAllText((Join-Path $S 's.txt'), "s`n"); & $gitFx $S @('add', 's.txt') $S; & $gitFx $S @('commit', '-q', '-m', 's') $S
        $sWt = Join-Path $partA 'stranger-wt'; & $gitFx $S @('worktree', 'add', '-q', $sWt, '-b', 'swt') $S
        # A worktree directory whose administrative entry does not exist (positive not found) under partition A, and one
        # whose .git points to a network path (refused, never an orphan).
        $orph = Join-Path $partA 'orphan'; [void][IO.Directory]::CreateDirectory($orph)
        [IO.File]::WriteAllText((Join-Path $orph '.git'), 'gitdir: ' + (Join-Path $R '.git\worktrees\deleted-entry') + "`n")
        $netw = Join-Path $partA 'net-wt'; [void][IO.Directory]::CreateDirectory($netw)
        [IO.File]::WriteAllText((Join-Path $netw '.git'), "gitdir: \\$uncHost\share\x`n")
        $parts = @([pscustomobject]@{ Path = $partA; Kind = 'SessionRoot' }, [pscustomobject]@{ Path = $partB; Kind = 'SessionRoot' }, [pscustomobject]@{ Path = $S; Kind = 'NotScanned' })
        $pz = New-AtmPseudonymizer -Key $testPseudonymKey
        try {
            $closed = Get-AtmWorktreeDiscovery -Partitions $parts -Pseudonymizer $pz
            Assert-True (@($closed.Findings).Count -eq 0 -and $closed.Coverage[0].Status -eq 'NOT_OBSERVABLE' -and @($closed.Coverage[0].Reasons) -contains 'WORKTREE_DIAGNOSTICS_GATE_CLOSED') 'trava fechada: nada lido, nao observavel'
            Start-Sleep -Milliseconds 1100
            $before = & $gitSnap $base
            $script:AtmGitInvocationLog = New-Object System.Collections.Generic.List[object]
            $script:AtmWorktreeDiagnosticsEnabled = $true
            try { $res = Get-AtmWorktreeDiscovery -Partitions $parts -RepositoryPaths @((Join-Path $R 'deep\deeper'), 'relative\x') -Git $testGit -Pseudonymizer $pz; $log = $script:AtmGitInvocationLog.ToArray() }
            finally { $script:AtmWorktreeDiagnosticsEnabled = $false; $script:AtmGitInvocationLog = $null }
            Start-Sleep -Milliseconds 300
            Assert-Eq (@(Compare-Object ($before -split "`n") ((& $gitSnap $base) -split "`n")).Count) 0 'descoberta e confirmacao pelo Git nao alteram nada'
            $repos = @($res.Findings | Where-Object { $_.Kind -eq 'Repository' }); $wts = @($res.Findings | Where-Object { $_.Kind -eq 'Worktree' })
            $kR = 'git/r-' + (Get-AtmPseudonym -Pseudonymizer $pz -Domain 'atm-repository/1' -Fields @((Get-AtmNormalizedPath (Join-Path $R '.git')).ToLowerInvariant()))
            $fR = @($repos | Where-Object { $_.Key -ceq $kR })
            Assert-True ($fR.Count -eq 1 -and $fR[0].State -eq 'UNKNOWN') 'repositorio R: um achado (particao e caminho explicito deduplicados)'
            Assert-Eq (@($fR[0].Evidence | Where-Object { $_.Code -eq 'REPOSITORY_DISCOVERED' } | ForEach-Object { $_.Detail } | Sort-Object) -join ',') 'EXPLICIT,PARTITION' 'fontes registradas'
            Assert-True (@($fR[0].Evidence | Where-Object { $_.Code -eq 'REPOSITORY_CONFIRMED_BY_GIT' }).Count -eq 1) 'confirmado pelo Git (rev-parse)'
            $wk = { param($d) 'git/w-' + (Get-AtmPseudonym -Pseudonymizer $pz -Domain 'atm-worktree/1' -Fields @((Get-AtmNormalizedPath $d).ToLowerInvariant())) }
            $codes = { param($k) @(@($wts | Where-Object { $_.Key -ceq $k })[0].Evidence | ForEach-Object { $_.Code }) }
            Assert-True ((& $codes (& $wk $R)) -contains 'WORKTREE_MAIN' -and (& $codes (& $wk $R)) -contains 'LOCAL_WORK_NONE_OBSERVED') 'worktree principal registrada; trabalho local observado (nenhum)'
            Assert-True ((& $codes (& $wk $wtL)) -contains 'WORKTREE_LOCKED' -and (& $codes (& $wk $wtL)) -contains 'WORKTREE_REGISTERED') 'worktree trancada'
            Assert-True ((& $codes (& $wk (Join-Path $base 'ghost-wt'))) -contains 'WORKTREE_DIRECTORY_MISSING' -and (& $codes (& $wk (Join-Path $base 'ghost-wt'))) -contains 'LOCAL_WORK_UNKNOWN') 'entrada administrativa sem diretorio: ausente (nao orfa), trabalho local desconhecido'
            $fo = @($wts | Where-Object { $_.Key -ceq (& $wk $orph) })
            Assert-True ($fo.Count -eq 1 -and $fo[0].State -eq 'APPARENT_ORPHAN' -and @($fo[0].Evidence | ForEach-Object { $_.Code }) -contains 'LOCAL_WORK_UNKNOWN') 'orfa aparente so com entrada administrativa positivamente ausente, trabalho local desconhecido'
            Assert-Eq @($wts | Where-Object { $_.State -eq 'APPARENT_ORPHAN' }).Count 1 'nenhum outro orfao (a de rede e recusada, nao orfa)'
            Assert-True (@($repos | Where-Object { @($_.Evidence | Where-Object { $_.Code -eq 'REPOSITORY_PREFLIGHT_REFUSED' -and $_.Detail -eq 'GIT_PREFLIGHT_GITDIR_NETWORK' }).Count -eq 1 }).Count -eq 1) 'gitdir de rede: recusado antes do Git'
            Assert-Eq @($repos | Where-Object { @($_.Evidence | Where-Object { $_.Code -eq 'REPOSITORY_DISCOVERED' }).Count -gt 0 }).Count 3 'repositorios R, Q (raiz da particao B) e S (so pela worktree na particao A)'
            $kS = 'git/r-' + (Get-AtmPseudonym -Pseudonymizer $pz -Domain 'atm-repository/1' -Fields @((Get-AtmNormalizedPath (Join-Path $S '.git')).ToLowerInvariant()))
            $fS = @($repos | Where-Object { $_.Key -ceq $kS })
            Assert-True ($fS.Count -eq 1 -and @($fS[0].Evidence | Where-Object { $_.Code -eq 'GIT_NOT_RUN' -and $_.Detail -eq 'REPOSITORY_OUTSIDE_SOURCES' }).Count -eq 1 -and @($fS[0].Evidence | Where-Object { $_.Code -eq 'REPOSITORY_CONFIRMED_BY_GIT' }).Count -eq 0) 'repositorio alcancado so por gitdir: registrado pelos arquivos, sem Git'
            Assert-True ((& $codes (& $wk $sWt)) -contains 'WORKTREE_REGISTERED') 'worktree de S na particao registrada'
            Assert-True (@($wts | ForEach-Object { @($_.Evidence | Where-Object { $_.Code -eq 'LOCAL_WORK_UNKNOWN' -or $_.Code -eq 'LOCAL_WORK_NONE_OBSERVED' }).Count } | Where-Object { $_ -ne 1 }).Count -eq 0 -and @($res.Findings | Where-Object { $_.State -eq 'CLEAN_AND_PUBLISHED_UNKNOWN' }).Count -eq 0) 'toda worktree declara trabalho local desconhecido ou nenhum observado; nada limpo/publicado'
            Assert-True ((& $codes (& $wk $wtL)) -contains 'LOCAL_WORK_UNKNOWN' -and @(@($wts | Where-Object { $_.Key -ceq (& $wk $wtL) })[0].Evidence | Where-Object { $_.Detail -eq 'WORKTREE_OUTSIDE_SOURCES' }).Count -eq 1) 'worktree fora das fontes: trabalho local nao observado'
            $sN = Get-AtmNormalizedPath $S
            Assert-Eq @($log | Where-Object { [string]::Equals($_.WorkingDirectory, $sN, [StringComparison]::OrdinalIgnoreCase) }).Count 0 'repositorio nunca citado nunca recebe o Git (espiao)'
            Assert-Eq @($log | Where-Object { $_.WorkingDirectory -like "*net-wt*" -or $_.WorkingDirectory -like "*orphan*" -or $_.WorkingDirectory -like "*wt-locked*" }).Count 0 'alvos recusados, orfaos e worktrees fora das fontes nunca recebem o Git'
            $dc = @($res.Coverage | Where-Object { $_.Collector -eq 'worktree-discovery' })[0]
            Assert-True ($dc.Status -eq 'PARTIAL' -and @($dc.Reasons) -contains 'DISCOVERY_BOUNDED' -and @($dc.Reasons) -contains 'EXPLICIT_PATH_INVALID' -and @($dc.Reasons) -contains 'PREFLIGHT_REFUSED_TARGETS') "cobertura limitada: $(@($dc.Reasons) -join ',')"
            Assert-Eq @($res.Coverage | Where-Object { $_.Collector -eq 'git' })[0].Status 'COMPLETE' 'chamadas ao Git completas'
            Assert-True (@($res.Findings | Where-Object { $_.Key -cnotmatch '^git/[rwt]-[0-9a-f]{32}$' }).Count -eq 0) 'chaves pseudonimas'
            $json = (@{ F = $res.Findings; C = $res.Coverage } | ConvertTo-Json -Depth 8)
            foreach ($x in @($base, $R, $wtL, (Split-Path -Leaf $R), 'locked', 'keep', $uncHost)) { Assert-True (-not $json.Contains($x) -and -not $json.Contains($x.Replace('\', '\\'))) "nada sensivel nos achados: $(Split-Path -Leaf $x)" }
            # Caps and the upward walk limit.
            $script:AtmWorktreeDiagnosticsEnabled = $true
            try {
                $one = Get-AtmWorktreeDiscovery -Partitions $parts -Git $testGit -Pseudonymizer $pz -MaxRepositories 1
                $walk = Get-AtmWorktreeDiscovery -RepositoryPaths @((Join-Path $R 'deep\deeper')) -Git $null -Pseudonymizer $pz -MaxWalkLevels 1
                $capC = Get-AtmWorktreeDiscovery -Partitions $parts -Git $null -Pseudonymizer $pz -MaxCandidates 2
            } finally { $script:AtmWorktreeDiagnosticsEnabled = $false }
            Assert-True (@($one.Coverage[0].Reasons) -contains 'REPOSITORY_LIMIT' -and @($one.Findings | Where-Object { $_.Kind -eq 'Repository' -and @($_.Evidence | Where-Object { $_.Code -eq 'REPOSITORY_DISCOVERED' }).Count -gt 0 }).Count -eq 1) 'limite de repositorios: PARTIAL'
            Assert-True (@($walk.Coverage[0].Reasons) -contains 'WALK_LIMIT' -and @($walk.Findings).Count -eq 0) 'limite de subida: PARTIAL, nada inventado'
            Assert-True (@($capC.Coverage[0].Reasons) -contains 'CANDIDATE_LIMIT') 'limite de diretorios examinados (recusados incluidos): PARTIAL'
            Assert-True (@($walk.Coverage | Where-Object { $_.Collector -eq 'git' })[0].Status -eq 'UNAVAILABLE') 'sem Git: cobertura git indisponivel'
            # Integrated: closed gate leaves diagnose unchanged; open gate adds the two collectors.
            $p = New-TestProfile 'disc-int'
            $null = New-TestRoot -ProfileInfo $p
            $rows = $b4cRows
            $d0 = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p) -Procs $b4cLegacy) -IdentitySource $diagIdUser -Providers @((Get-AtmProviders)[0]) -ProcessSource ({ $rows }.GetNewClosure()) -CpuSampleMs 0 -PseudonymKey $testPseudonymKey
            # P5-A: with the gate closed the discovery is reported as not observed (never read as "no worktrees"); Git never runs.
            Assert-True (@($d0.Coverage | Where-Object { $_.Collector -eq 'git' }).Count -eq 0 -and (@($d0.Coverage | Where-Object { $_.Collector -eq 'worktree-discovery' } | ForEach-Object { $_.Status + ':' + (@($_.Reasons) -join ',') }) -join ';') -ceq 'NOT_OBSERVABLE:WORKTREE_DIAGNOSTICS_GATE_CLOSED') 'trava fechada: worktrees nao observadas (trava), nenhum coletor git'
            $d1 = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p) -Procs $b4cLegacy) -IdentitySource $diagIdUser -Providers @((Get-AtmProviders)[0]) -ProcessSource ({ $rows }.GetNewClosure()) -CpuSampleMs 0 -PseudonymKey $testPseudonymKey -RepositoryPaths @($R)
            Assert-True (@($d1.Coverage | Where-Object { $_.Collector -eq 'worktree-discovery' -and $_.Status -eq 'NOT_OBSERVABLE' }).Count -eq 1) 'trava fechada com lista explicita: nao observavel'
            $script:AtmWorktreeDiagnosticsEnabled = $true
            try { $d2 = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p) -Procs $b4cLegacy) -IdentitySource $diagIdUser -Providers @((Get-AtmProviders)[0]) -ProcessSource ({ $rows }.GetNewClosure()) -CpuSampleMs 0 -PseudonymKey $testPseudonymKey -RepositoryPaths @($R) }
            finally { $script:AtmWorktreeDiagnosticsEnabled = $false }
            Assert-True (@($d2.Findings | Where-Object { $_.Key -ceq $kR }).Count -eq 1 -and @($d2.Coverage | Where-Object { $_.Collector -eq 'git' }).Count -eq 1 -and -not $d2.CoverageComplete) 'trava aberta: repositorio no diagnose; descoberta limitada deixa a cobertura incompleta'
            $txt = (Show-AtmDiagnose -Result $d2 6>&1 | Out-String) -replace '\s+', ' '
            Assert-True ($txt.Contains((Get-AtmText 'diag.wtTitle')) -and $txt.Contains((Get-AtmText 'diag.wtNoDelete'))) 'relatorio: secao de worktrees, sem nada descartavel'
            Assert-True (-not $txt.Contains($R) -and -not (ConvertTo-AtmDiagnoseJson -Result $d2).Contains($R.Replace('\', '\\'))) 'relatorio e JSON sem caminhos de repositorio'
        } finally { Close-AtmPseudonymizer $pz }
    }
    Test-Case 'Git' 'P3-C0: travas de leitura impedem alterar, substituir ou renomear o que a pre-verificacao validou durante a chamada; GIT_COMMON_DIR fixado; vetores por ausencia provados e registrados como abertos' {
        if (& $gitSkip) { return }
        $fx = & $gitNewFixture 'c0-pin'
        $pf = Get-AtmGitPreflight -Target $fx.Repo
        Assert-True ($pf.Status -eq 'OK' -and @($pf.PinPaths) -contains (Join-Path $fx.Repo '.git\config') -and @($pf.PinPaths) -contains (Join-Path $fx.Repo '.git\HEAD')) 'pre-verificacao lista config e HEAD para travar'
        $other = & $gitNewFixture 'c0-other'
        $otherBlob = (& $gitFxOut $other.Repo @('rev-parse', 'HEAD:a.txt') $other.Repo).Out.Trim()
        $pins = Open-AtmGitReadPins -Paths @($pf.PinPaths)
        try {
            Assert-True ($null -eq $pins.Error -and @($pins.Handles).Count -eq @($pf.PinPaths).Count) 'todas as travas abertas'
            $try = { param([scriptblock]$B) try { & $B; return 'SUCCEEDED' } catch { return 'BLOCKED' } }
            Assert-Eq (& $try { [IO.File]::AppendAllText((Join-Path $fx.Repo '.git\config'), "[include]`n`tpath = x`n") }) 'BLOCKED' 'include acrescentado durante a chamada: bloqueado'
            Assert-Eq (& $try { [IO.File]::Copy((Join-Path $other.Repo '.git\config'), (Join-Path $fx.Repo '.git\config'), $true) }) 'BLOCKED' 'config substituido: bloqueado'
            Assert-Eq (& $try { [IO.File]::Copy((Join-Path $other.Repo '.git\HEAD'), (Join-Path $fx.Repo '.git\HEAD'), $true) }) 'BLOCKED' 'HEAD substituido: bloqueado'
            Assert-Eq (& $try { [IO.Directory]::Move((Join-Path $fx.Repo '.git'), (Join-Path $fx.Repo '.git-moved')) }) 'BLOCKED' '.git renomeado: bloqueado'
            Assert-Eq (& $try { [IO.Directory]::Move($fx.Repo, $fx.Repo + '-moved') }) 'BLOCKED' 'repositorio renomeado: bloqueado'
            Assert-Eq (& $try { [IO.Directory]::Move((Join-Path $fx.Repo '.git\objects'), (Join-Path $fx.Repo '.git\objects-moved')) }) 'BLOCKED' 'objects renomeado (para trocar por uma juncao): bloqueado'
            Assert-Eq (& $try { [IO.Directory]::Move((Join-Path $fx.Repo '.git\refs'), (Join-Path $fx.Repo '.git\refs-moved')) }) 'BLOCKED' 'refs renomeado: bloqueado'
            # Other processes' index and ref updates are not blocked (only the pinned files are).
            [IO.File]::WriteAllText((Join-Path $fx.Repo '.git\refs\heads\main.lock'), (Get-Content -LiteralPath (Join-Path $fx.Repo '.git\refs\heads\main') -Raw))
            Assert-Eq (& $try { [IO.File]::Replace((Join-Path $fx.Repo '.git\refs\heads\main.lock'), (Join-Path $fx.Repo '.git\refs\heads\main'), [NullString]::Value) }) 'SUCCEEDED' 'atualizacao de ref por outro processo nao e bloqueada'
            # Open (recorded, not resolved): a file that did not exist cannot be pinned. Proved locally: alternates created
            # during the call are followed by Git.
            Assert-Eq (& $try { [IO.File]::WriteAllText((Join-Path $fx.Repo '.git\objects\info\alternates'), (Join-Path $other.Repo '.git\objects') + "`n") }) 'SUCCEEDED' 'aberto: alternates criado durante a chamada nao e impedido'
            Assert-Eq (& $gitFxOut $fx.Repo @('cat-file', '-e', $otherBlob) $fx.Repo).Code 0 'aberto (contraprova local): o Git segue o alternates criado depois'
        } finally { foreach ($h in @($pins.Handles)) { $h.Dispose() } }
        # Someone holding a validated file open for writing: refused, no process.
        $fxB = & $gitNewFixture 'c0-busy'
        $pfB = Get-AtmGitPreflight -Target $fxB.Repo
        $fs = [IO.File]::Open((Join-Path $fxB.Repo '.git\config'), [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
        try { $n = & $gitSpy { $script:c0r = & $gitOpen { Invoke-AtmGitCommand -Git $testGit -Arguments @('rev-parse', '--show-toplevel') -WorkingDirectory $fxB.Repo -Preflight $pfB } } }
        finally { $fs.Dispose() }
        Assert-True ($n -eq 0 -and $script:c0r.Reason -eq 'GIT_PIN_BUSY') "config aberto para escrita: recusado sem processo ($($script:c0r.Reason))"
        # A commondir planted after the caller's preflight: the fresh preflight under the pins sees it; Git never runs.
        $pfW = Get-AtmGitPreflight -Target $fxB.Worktree
        $admW = Join-Path $fxB.Repo '.git\worktrees\wt'
        [IO.File]::WriteAllText((Join-Path $other.Repo '.git\config'), [IO.File]::ReadAllText((Join-Path $other.Repo '.git\config')) + "[atm]`n`tprobe = from-other`n")
        Assert-Eq (& $gitFxOut $fxB.Worktree @('config', '--get', 'atm.probe') $null).Out.Trim() '' 'antes: sem a sonda'
        [IO.File]::WriteAllText((Join-Path $admW 'commondir'), (Join-Path $other.Repo '.git') + "`n")
        Assert-Eq (& $gitFxOut $fxB.Worktree @('config', '--get', 'atm.probe') $null).Out.Trim() 'from-other' 'contraprova: o Git segue o commondir plantado'
        Assert-Eq (& $gitFxOut $fxB.Worktree @('config', '--get', 'atm.probe') $null @{ GIT_COMMON_DIR = (Join-Path $fxB.Repo '.git') }).Out.Trim() '' 'GIT_COMMON_DIR fixado: o commondir plantado nao e lido'
        $n = & $gitSpy { $script:c0w = & $gitOpen { Invoke-AtmGitCommand -Git $testGit -Arguments @('rev-parse', '--show-toplevel') -WorkingDirectory $fxB.Worktree -Preflight $pfW } }
        Assert-True ($n -eq 0 -and $script:c0w.Reason -eq 'GIT_PREFLIGHT_REQUIRED') "commondir plantado apos a pre-verificacao: recusado sem processo ($($script:c0w.Reason))"
        Assert-True (@(Get-AtmGitEnvironment -Ceiling $gitRoot -IsolatedHome 'C:\x' -CommonDir (Join-Path $fxB.Repo '.git')) -contains ('GIT_COMMON_DIR=' + (Join-Path $fxB.Repo '.git'))) 'ambiente do Git com GIT_COMMON_DIR da pre-verificacao'
        # Open (recorded, not resolved): status follows a .git file dropped in the work tree (untracked scan).
        $fxN = & $gitNewFixture 'c0-nested'
        $nest = Join-Path $fxN.Repo 'nested'; [void][IO.Directory]::CreateDirectory($nest)
        [IO.File]::WriteAllText((Join-Path $nest '.git'), 'gitdir: ' + (Join-Path $gitRoot 'c0-missing') + "`n")
        $o1 = (& $gitFxOut $fxN.Repo @('--no-optional-locks', 'status', '--porcelain=v2', '-uall') $fxN.Repo).Out
        [IO.File]::WriteAllText((Join-Path $nest '.git'), 'gitdir: ' + (Join-Path $other.Repo '.git') + "`n")
        $o2 = (& $gitFxOut $fxN.Repo @('--no-optional-locks', 'status', '--porcelain=v2', '-uall') $fxN.Repo).Out
        Assert-True ($o1 -ne $o2) 'aberto (contraprova local): o status resolve o alvo de um arquivo .git aninhado na work tree'
        # The pinned window covers the whole Git process.
        $fxT = & $gitNewFixture 'c0-time'
        $rt = & $gitOpen { & $gitRun @('rev-parse', '--show-toplevel') $fxT.Repo }
        Assert-True ($rt.Status -eq 'COMPLETE' -and $rt.PinnedMs -ge $rt.ElapsedMs) "travas durante toda a chamada (travado $($rt.PinnedMs) ms, Git $($rt.ElapsedMs) ms)"
        $script:caseNote = 'vetores por ausencia (alternates criado, .git aninhado, entradas administrativas novas) provados localmente e registrados como abertos'
    }
    Test-Case 'Git' 'P3-C: trabalho local (preparado, nao preparado, nao rastreado, ignorado, conflitos, operacoes, stash) por fixtures; cobertura por fato; somente leitura; nenhum estado limpo' {
        if (& $gitSkip) { return }
        $lwBase = Join-Path $gitRoot 'lwp'
        $plain = { param([string]$Name) $d = Join-Path $lwBase $Name; [void][IO.Directory]::CreateDirectory($d); & $gitFx $d @('init', '-q', '-b', 'main') $null; [IO.File]::WriteAllText((Join-Path $d 'a.txt'), "1`n"); & $gitFx $d @('add', 'a.txt') $d; & $gitFx $d @('commit', '-q', '-m', 'base') $d; return $d }
        $edit = { param([string]$D, [string]$V, [string]$M) [IO.File]::WriteAllText((Join-Path $D 'a.txt'), "$V`n"); & $gitFx $D @('commit', '-q', '-a', '-m', $M) $D }
        $fx = & $gitNewFixture 'lw'
        [IO.File]::AppendAllText((Join-Path $fx.Repo '.git\info\exclude'), "build/`n"); [void][IO.Directory]::CreateDirectory((Join-Path $fx.Repo 'build')); [IO.File]::WriteAllText((Join-Path $fx.Repo 'build\out.bin'), 'x')
        $merge = & $plain 'merge'; & $gitFx $merge @('checkout', '-q', '-b', 'x') $merge; & $edit $merge '2' 'x'; & $gitFx $merge @('checkout', '-q', 'main') $merge; & $edit $merge '3' 'main'
        $null = & $gitFxOut $merge @('merge', '-q', '--no-edit', 'x') $merge
        $rebase = & $plain 'rebase'; & $gitFx $rebase @('checkout', '-q', '-b', 'y') $rebase; & $edit $rebase '2' 'y'; & $gitFx $rebase @('checkout', '-q', 'main') $rebase; & $edit $rebase '3' 'main'; & $gitFx $rebase @('checkout', '-q', 'y') $rebase
        $null = & $gitFxOut $rebase @('rebase', 'main') $rebase
        $pick = & $plain 'pick'; & $gitFx $pick @('checkout', '-q', '-b', 'z') $pick; & $edit $pick '2' 'z'; $zc = (& $gitFxOut $pick @('rev-parse', 'HEAD') $pick).Out.Trim(); & $gitFx $pick @('checkout', '-q', 'main') $pick; & $edit $pick '3' 'main'
        $null = & $gitFxOut $pick @('cherry-pick', $zc) $pick
        $revert = & $plain 'revert'; & $edit $revert '2' 'c1'; $c1 = (& $gitFxOut $revert @('rev-parse', 'HEAD') $revert).Out.Trim(); & $edit $revert '3' 'c2'
        $null = & $gitFxOut $revert @('revert', '--no-edit', $c1) $revert
        $bisect = & $plain 'bisect'; & $gitFx $bisect @('bisect', 'start') $bisect
        $stash = & $plain 'stash'; [IO.File]::WriteAllText((Join-Path $stash 'a.txt'), "9`n"); & $gitFx $stash @('stash', 'push', '-q', '-m', 'keep') $stash
        $clean = & $plain 'clean'
        $submod = & $plain 'submod'; [IO.File]::WriteAllText((Join-Path $submod '.gitmodules'), "[submodule `"s`"]`n`tpath = s`n`turl = ./s`n")
        $all = @($fx.Repo, $merge, $rebase, $pick, $revert, $bisect, $stash, $clean, $submod)
        $pz = New-AtmPseudonymizer -Key $testPseudonymKey
        try {
            Start-Sleep -Milliseconds 1100
            $snapA = & $gitSnap (Join-Path $gitRoot 'lw'); $snapB = & $gitSnap $lwBase
            $script:AtmGitInvocationLog = New-Object System.Collections.Generic.List[object]
            $script:AtmWorktreeDiagnosticsEnabled = $true
            try { $res = Get-AtmWorktreeDiscovery -RepositoryPaths $all -Git $testGit -Pseudonymizer $pz; $log = $script:AtmGitInvocationLog.ToArray() }
            finally { $script:AtmWorktreeDiagnosticsEnabled = $false; $script:AtmGitInvocationLog = $null }
            Start-Sleep -Milliseconds 300
            Assert-Eq (@(Compare-Object ($snapA -split "`n") ((& $gitSnap (Join-Path $gitRoot 'lw')) -split "`n")).Count + @(Compare-Object ($snapB -split "`n") ((& $gitSnap $lwBase) -split "`n")).Count) 0 'trabalho local lido sem alterar nada (.git e index incluidos)'
            $wk = { param($d) 'git/w-' + (Get-AtmPseudonym -Pseudonymizer $pz -Domain 'atm-worktree/1' -Fields @((Get-AtmNormalizedPath $d).ToLowerInvariant())) }
            $f = { param($d) @($res.Findings | Where-Object { $_.Kind -eq 'Worktree' -and $_.Key -ceq (& $wk $d) })[0] }
            $ev = { param($d, [string]$c) @((& $f $d).Evidence | Where-Object { $_.Code -ceq $c } | ForEach-Object { [string]$_.Detail }) }
            Assert-True ((& $f $fx.Repo).State -eq 'LOCAL_WORK' -and @(& $ev $fx.Repo 'STAGED').Count -eq 1 -and @(& $ev $fx.Repo 'UNSTAGED').Count -eq 1 -and @(& $ev $fx.Repo 'UNTRACKED').Count -eq 1 -and @(& $ev $fx.Repo 'IGNORED').Count -eq 1) 'preparado, nao preparado, nao rastreado e ignorado: LOCAL_WORK'
            Assert-True ((& $f $fx.Worktree).State -eq 'UNKNOWN' -and @(& $ev $fx.Worktree 'LOCAL_WORK_UNKNOWN') -contains 'WORKTREE_OUTSIDE_SOURCES') 'worktree vinculada nao citada: desconhecida'
            Assert-True (@(& $ev $merge 'OPERATION_IN_PROGRESS') -contains 'MERGE' -and @(& $ev $merge 'CONFLICTS').Count -eq 1 -and (& $f $merge).State -eq 'LOCAL_WORK') 'merge em andamento com conflito'
            Assert-True (@(& $ev $rebase 'OPERATION_IN_PROGRESS') -contains 'REBASE') 'rebase em andamento'
            Assert-True (@(& $ev $pick 'OPERATION_IN_PROGRESS') -contains 'CHERRY_PICK') 'cherry-pick em andamento'
            Assert-True (@(& $ev $revert 'OPERATION_IN_PROGRESS') -contains 'REVERT') 'revert em andamento'
            Assert-True (@(& $ev $bisect 'OPERATION_IN_PROGRESS') -contains 'BISECT' -and (& $f $bisect).State -eq 'LOCAL_WORK') 'bisect em andamento'
            $kStash = 'git/r-' + (Get-AtmPseudonym -Pseudonymizer $pz -Domain 'atm-repository/1' -Fields @((Get-AtmNormalizedPath (Join-Path $stash '.git')).ToLowerInvariant()))
            Assert-True (@(@($res.Findings | Where-Object { $_.Key -ceq $kStash })[0].Evidence | Where-Object { $_.Code -ceq 'STASHES_IN_REPOSITORY' -and $_.Detail -eq '1' }).Count -eq 1) 'stash contado no repositorio'
            Assert-True (@(& $ev $stash 'STASH_MENTIONS_BRANCH') -contains '1' -and (& $f $stash).State -eq 'LOCAL_WORK') 'stash atribuido a worktree pelo branch'
            Assert-True ((& $f $clean).State -eq 'UNKNOWN' -and @(& $ev $clean 'LOCAL_WORK_NONE_OBSERVED').Count -eq 1 -and @(& $ev $clean 'NO_REMOTE_TRACKING_REFS').Count -eq 1) 'sem trabalho local observado e sem referencias remotas: desconhecido (ausencia de referencias nao prova nao publicacao)'
            Assert-True (@(& $ev $submod 'SUBMODULES') -contains 'DECLARED' -and @(& $ev $submod 'LOCAL_WORK_NOT_OBSERVED') -contains 'D3_SUBMODULES' -and @(& $ev $submod 'LOCAL_WORK_UNKNOWN').Count -eq 1) 'submodulos declarados: status nao executado, trabalho local desconhecido'
            Assert-Eq @($res.Findings | Where-Object { $_.State -eq 'CLEAN_AND_PUBLISHED_UNKNOWN' }).Count 0 'nenhum estado limpo e publicado'
            $stc = @($res.Coverage | Where-Object { $_.Collector -eq 'local-work-status' })[0]
            Assert-True ($stc.Status -eq 'PARTIAL' -and @($stc.Reasons) -contains 'D3_SUBMODULES' -and @($stc.Reasons) -contains 'HIDDEN_ENTRIES_NOT_OBSERVED' -and $stc.Expected -eq 9 -and $stc.Observed -eq 8) "cobertura do status nunca completa (gitlinks, assume-unchanged, skip-worktree): $($stc.Status) $($stc.Observed)/$($stc.Expected)"
            Assert-Eq @($res.Coverage | Where-Object { $_.Collector -eq 'local-work-files' })[0].Status 'COMPLETE' 'cobertura dos arquivos completa'
            $st = @($log | Where-Object { $_.Arguments -ccontains 'status' })
            Assert-True ($st.Count -eq 8 -and @($st | Where-Object { $_.Arguments -cnotcontains '--ignore-submodules=all' -or $_.Pins -lt 2 }).Count -eq 0) "status sempre sem submodulos e com travas ($($st.Count))"
            Assert-Eq @($st | Where-Object { [string]::Equals($_.WorkingDirectory, (Get-AtmNormalizedPath $submod), [StringComparison]::OrdinalIgnoreCase) }).Count 0 'status nunca roda com submodulos declarados'
            $json = (@{ F = $res.Findings; C = $res.Coverage } | ConvertTo-Json -Depth 8)
            foreach ($x in @($lwBase, 'build', 'out.bin', 'keep', 'u.txt', 'c.txt')) { Assert-True (-not $json.Contains($x) -and -not $json.Contains($x.Replace('\', '\\'))) "nada sensivel nos achados: $(Split-Path -Leaf $x)" }
            # A stash that cannot be attributed (detached HEAD) and a stash ref without its log are never "none".
            $det = & $plain 'stash-detached'; [IO.File]::WriteAllText((Join-Path $det 'a.txt'), "8`n"); & $gitFx $det @('stash', 'push', '-q') $det; & $gitFx $det @('checkout', '-q', '--detach') $det
            $nolog = & $plain 'stash-nolog'; & $gitFx $nolog @('update-ref', 'refs/stash', 'HEAD') $nolog
            $script:AtmWorktreeDiagnosticsEnabled = $true
            try { $res2 = Get-AtmWorktreeDiscovery -RepositoryPaths @($det, $nolog) -Git $testGit -Pseudonymizer $pz }
            finally { $script:AtmWorktreeDiagnosticsEnabled = $false }
            $f2 = { param($d) @($res2.Findings | Where-Object { $_.Kind -eq 'Worktree' -and $_.Key -ceq (& $wk $d) })[0] }
            Assert-True (@((& $f2 $det).Evidence | Where-Object { $_.Code -eq 'LOCAL_WORK_NOT_OBSERVED' -and $_.Detail -eq 'STASH_NOT_ATTRIBUTABLE' }).Count -eq 1 -and @((& $f2 $det).Evidence | Where-Object { $_.Code -eq 'LOCAL_WORK_NONE_OBSERVED' }).Count -eq 0) 'HEAD destacado com stash no repositorio: nao atribuivel, nunca "nenhum"'
            Assert-True (@((& $f2 $nolog).Evidence | Where-Object { $_.Code -eq 'LOCAL_WORK_UNKNOWN' }).Count -eq 1 -and @((& $f2 $nolog).Evidence | Where-Object { $_.Code -eq 'LOCAL_WORK_NONE_OBSERVED' }).Count -eq 0) 'ref de stash sem log: trabalho local desconhecido'
            Assert-True (@($res2.Coverage | Where-Object { $_.Collector -eq 'local-work-files' })[0].Status -eq 'PARTIAL') 'cobertura dos arquivos parcial'
            $closed = Get-AtmWorktreeLocalWork -WorkTree $clean -Git $testGit
            Assert-True ($closed.StatusCoverage.Status -eq 'NOT_OBSERVABLE' -and $closed.StatusCoverage.Reason -eq 'WORKTREE_DIAGNOSTICS_GATE_CLOSED' -and @($closed.Evidence).Count -eq 0) 'trava fechada: nada lido'
        } finally { Close-AtmPseudonymizer $pz }
    }
    Test-Case 'Git' 'P3-D: publicacao so por arquivos (sem Git): sem referencias remotas, ponta igual a remota, alcancabilidade nao lida, destacado, sem commits, packed-refs; nada publicado comprovado; somente leitura e sem processos' {
        if (& $gitSkip) { return }
        $pb = Join-Path $gitRoot 'pub'
        $mk = { param([string]$Name) $d = Join-Path $pb $Name; [void][IO.Directory]::CreateDirectory($d); & $gitFx $d @('init', '-q', '-b', 'main') $null; [IO.File]::WriteAllText((Join-Path $d 'a.txt'), "1`n"); & $gitFx $d @('add', 'a.txt') $d; & $gitFx $d @('commit', '-q', '-m', 'base') $d; return $d }
        $next = { param([string]$D, [string]$V) [IO.File]::WriteAllText((Join-Path $D 'a.txt'), "$V`n"); & $gitFx $D @('commit', '-q', '-a', '-m', $V) $D }
        $none = & $mk 'no-remote'
        $equal = & $mk 'equal'; & $gitFx $equal @('update-ref', 'refs/remotes/origin/main', 'HEAD') $equal; & $gitFx $equal @('config', 'branch.main.remote', 'origin') $equal; & $gitFx $equal @('config', 'branch.main.merge', 'refs/heads/main') $equal
        $ahead = & $mk 'ahead'; & $gitFx $ahead @('update-ref', 'refs/remotes/origin/main', 'HEAD') $ahead; & $next $ahead '2'
        $packed = & $mk 'packed'; & $gitFx $packed @('update-ref', 'refs/remotes/origin/main', 'HEAD') $packed; & $gitFx $packed @('pack-refs', '--all') $packed
        $detRef = & $mk 'detached-ref'; & $gitFx $detRef @('update-ref', 'refs/remotes/origin/main', 'HEAD') $detRef; & $gitFx $detRef @('checkout', '-q', '--detach') $detRef
        $detNew = & $mk 'detached-new'; & $gitFx $detNew @('update-ref', 'refs/remotes/origin/main', 'HEAD') $detNew; & $gitFx $detNew @('checkout', '-q', '--detach') $detNew; & $next $detNew '2'
        $unborn = Join-Path $pb 'unborn'; [void][IO.Directory]::CreateDirectory($unborn); & $gitFx $unborn @('init', '-q', '-b', 'main') $null
        $reftab = & $mk 'reftable-marked'; [IO.File]::AppendAllText((Join-Path $reftab '.git\config'), "[extensions]`n`trefStorage = reftable`n")
        # A symbolic branch (HEAD -> alias -> main): no tip claimed.
        $symb = & $mk 'symbolic'; [IO.File]::WriteAllText((Join-Path $symb '.git\refs\heads\alias'), "ref: refs/heads/main`n"); [IO.File]::WriteAllText((Join-Path $symb '.git\HEAD'), "ref: refs/heads/alias`n")
        # A stale packed peeled id (tag recreated loose): the old commit is no longer referenced by it.
        $stale = & $mk 'stale-peel'; $oldC = (& $gitFxOut $stale @('rev-parse', 'HEAD') $stale).Out.Trim(); & $gitFx $stale @('tag', '-a', 'v1', '-m', 'one') $stale; & $gitFx $stale @('pack-refs', '--all') $stale
        & $next $stale '2'; & $gitFx $stale @('tag', '-f', '-a', 'v1', '-m', 'two') $stale; & $gitFx $stale @('update-ref', 'refs/remotes/origin/main', 'HEAD') $stale; & $gitFx $stale @('checkout', '-q', $oldC) $stale
        # Upstream in config.worktree (extensions.worktreeConfig).
        $wtc = & $mk 'worktree-config'; & $gitFx $wtc @('update-ref', 'refs/remotes/origin/main', 'HEAD') $wtc; & $gitFx $wtc @('config', 'extensions.worktreeConfig', 'true') $wtc; & $gitFx $wtc @('config', '--worktree', 'branch.main.merge', 'refs/heads/main') $wtc
        # A name starting with a dot under refs/remotes is not a reference (Git ignores it).
        $dot = & $mk 'dot-name'; $dotId = (& $gitFxOut $dot @('rev-parse', 'HEAD') $dot).Out.Trim(); [void][IO.Directory]::CreateDirectory((Join-Path $dot '.git\refs\remotes')); [IO.File]::WriteAllText((Join-Path $dot '.git\refs\remotes\.hidden'), "$dotId`n")
        # A: pushed to a local fixture server (file path, no network), then the remote-tracking reference removed.
        $server = Join-Path $pb 'server.git'; [void][IO.Directory]::CreateDirectory($server); & $gitFx $server @('init', '-q', '--bare') $null
        $pushed = & $mk 'pushed'; & $gitFx $pushed @('remote', 'add', 'origin', $server) $pushed; & $gitFx $pushed @('push', '-q', 'origin', 'main') $pushed
        Assert-True ([IO.File]::Exists((Join-Path $pushed '.git\refs\remotes\origin\main'))) 'fixture: o push criou a referencia remota'
        & $gitFx $pushed @('update-ref', '-d', 'refs/remotes/origin/main') $pushed
        # B: remote configured, no remote-tracking reference.
        $remoteOnly = & $mk 'remote-only'; & $gitFx $remoteOnly @('remote', 'add', 'origin', $server) $remoteOnly
        # D: detached, no remote-tracking reference, a new commit.
        $detNoRemote = & $mk 'detached-no-remote'; & $gitFx $detNoRemote @('checkout', '-q', '--detach') $detNoRemote; & $next $detNoRemote '2'
        $all = @($none, $equal, $ahead, $packed, $detRef, $detNew, $unborn, $reftab, $symb, $stale, $wtc, $dot, $pushed, $remoteOnly, $detNoRemote)
        $pz = New-AtmPseudonymizer -Key $testPseudonymKey
        try {
            Start-Sleep -Milliseconds 1100
            $before = & $gitSnap $pb
            $script:AtmGitInvocationLog = New-Object System.Collections.Generic.List[object]
            $script:AtmWorktreeDiagnosticsEnabled = $true
            try { $res = Get-AtmWorktreeDiscovery -RepositoryPaths $all -Git $null -Pseudonymizer $pz; $log = $script:AtmGitInvocationLog.ToArray() }
            finally { $script:AtmWorktreeDiagnosticsEnabled = $false; $script:AtmGitInvocationLog = $null }
            Start-Sleep -Milliseconds 300
            Assert-Eq (@(Compare-Object ($before -split "`n") ((& $gitSnap $pb) -split "`n")).Count) 0 'publicacao lida sem alterar referencias nem conteudo'
            Assert-Eq $log.Count 0 'nenhum processo Git (somente arquivos)'
            $wk = { param($d) 'git/w-' + (Get-AtmPseudonym -Pseudonymizer $pz -Domain 'atm-worktree/1' -Fields @((Get-AtmNormalizedPath $d).ToLowerInvariant())) }
            $f = { param($d) @($res.Findings | Where-Object { $_.Kind -eq 'Worktree' -and $_.Key -ceq (& $wk $d) })[0] }
            $ev = { param($d, [string]$c) @((& $f $d).Evidence | Where-Object { $_.Code -ceq $c } | ForEach-Object { [string]$_.Detail }) }
            # Absence of remote-tracking references is never proof that the commits were never published (A-D).
            foreach ($c in @(@($none, 'C: sem remote configurado'), @($pushed, 'A: enviado a um servidor de fixture, referencias remotas removidas depois'), @($remoteOnly, 'B: remote configurado sem referencias remotas'), @($detNoRemote, 'D: destacado sem referencias remotas'))) {
                Assert-True ((& $f $c[0]).State -eq 'UNKNOWN' -and @(& $ev $c[0] 'NO_REMOTE_TRACKING_REFS').Count -eq 1 -and @(& $ev $c[0] 'PUBLICATION_UNKNOWN') -contains 'NO_REMOTE_TRACKING_REFS') "$($c[1]): publicacao desconhecida, nunca nao publicado"
            }
            Assert-True (@(& $ev $detNoRemote 'COMMITS_ONLY_IN_THIS_WORKTREE_POSSIBLE').Count -eq 1) 'D: commit destacado novo: possivelmente so nesta worktree (risco, nao prova)'
            Assert-Eq @($res.Findings | Where-Object { $_.State -eq 'UNPUBLISHED_COMMITS' }).Count 0 'nenhum estado UNPUBLISHED_COMMITS inferido de arquivos'
            Assert-True ((& $f $equal).State -eq 'UNKNOWN' -and @(& $ev $equal 'PUBLICATION_UNVERIFIED') -contains 'HEAD_TIP_ON_REMOTE_TRACKING' -and @(& $ev $equal 'UPSTREAM_CONFIGURED').Count -eq 1) 'ponta igual a remota: publicacao NAO verificada (nunca publicada), estado desconhecido'
            Assert-True ((& $f $ahead).State -eq 'UNKNOWN' -and @(& $ev $ahead 'PUBLICATION_UNKNOWN') -contains 'REACHABILITY_NOT_READ' -and @(& $ev $ahead 'NO_UPSTREAM').Count -eq 1) 'a frente da remota: alcancabilidade nao lida, desconhecido (nunca publicado)'
            Assert-True (@(& $ev $packed 'PUBLICATION_UNVERIFIED') -contains 'HEAD_TIP_ON_REMOTE_TRACKING') 'referencias compactadas lidas'
            Assert-True (@(& $ev $detRef 'HEAD_STATE') -contains 'DETACHED' -and @(& $ev $detRef 'DETACHED_TIP_REFERENCED').Count -eq 1) 'destacado na ponta de uma referencia'
            Assert-True (@(& $ev $detNew 'COMMITS_ONLY_IN_THIS_WORKTREE_POSSIBLE').Count -eq 1 -and @(& $ev $detNew 'PUBLICATION_UNKNOWN').Count -eq 1) 'destacado com commit novo: possivelmente so nesta worktree'
            Assert-True ((& $f $unborn).State -eq 'UNKNOWN' -and @(& $ev $unborn 'PUBLICATION_NOT_OBSERVED') -contains 'HEAD_BRANCH_NOT_FOUND' -and @(& $ev $unborn 'COMMITS_NOT_ON_REMOTE_TRACKING').Count -eq 0) 'branch sem ponta (sem commits, movido ou simbolico): nada afirmado'
            Assert-True ((& $f $symb).State -eq 'UNKNOWN' -and @(& $ev $symb 'PUBLICATION_NOT_OBSERVED') -contains 'HEAD_BRANCH_NOT_FOUND') 'branch simbolico: nada afirmado'
            Assert-True (@(& $ev $stale 'COMMITS_ONLY_IN_THIS_WORKTREE_POSSIBLE').Count -eq 1 -and @(& $ev $stale 'DETACHED_TIP_REFERENCED').Count -eq 0) 'id descascado obsoleto (tag recriada solta) nao conta como referencia'
            Assert-True (@(& $ev $wtc 'UPSTREAM_CONFIGURED').Count -eq 1 -and @(& $ev $wtc 'NO_UPSTREAM').Count -eq 0) 'upstream em config.worktree reconhecido (nunca "sem upstream" falso)'
            Assert-True ((& $f $dot).State -eq 'UNKNOWN' -and @(& $ev $dot 'NO_REMOTE_TRACKING_REFS').Count -eq 1) 'nome iniciado por ponto ignorado como o Git ignora'
            Assert-True (@(& $ev $equal 'LOCAL_WORK_UNKNOWN').Count -eq 1) 'sem Git: trabalho local desconhecido sempre declarado'
            Assert-True ((& $f $reftab).State -eq 'UNKNOWN' -and @(& $ev $reftab 'PUBLICATION_NOT_OBSERVED') -contains 'REF_STORE_UNSUPPORTED') 'reftable: nao suportado, desconhecido (nunca nao publicado)'
            Assert-True (@($res.Findings | Where-Object { @($_.Evidence | Where-Object { $_.Code -match 'PUBLISHED$' -and $_.Code -notmatch 'UNPUBLISHED' }).Count -gt 0 }).Count -eq 0 -and @($res.Findings | Where-Object { $_.State -eq 'CLEAN_AND_PUBLISHED_UNKNOWN' }).Count -eq 0) 'nenhum codigo ou estado de publicado'
            $pc = @($res.Coverage | Where-Object { $_.Collector -eq 'publication-files' })[0]
            Assert-True ($pc.Status -eq 'PARTIAL' -and @($pc.Reasons) -contains 'REF_STORE_UNSUPPORTED' -and @($pc.Reasons) -contains 'HEAD_BRANCH_NOT_FOUND' -and $pc.Expected -eq 15) "cobertura de publicacao: $($pc.Status) $($pc.Observed)/$($pc.Expected)"
            $json = (@{ F = $res.Findings; C = $res.Coverage } | ConvertTo-Json -Depth 8)
            foreach ($x in @($pb, 'origin', 'refs/heads', 'refs/remotes', 'main')) { Assert-True (-not $json.Contains($x) -and -not $json.Contains($x.Replace('\', '\\'))) "nada sensivel nos achados: $(Split-Path -Leaf $x)" }
        } finally { Close-AtmPseudonymizer $pz }
    }
    Test-Case 'Git' 'P3-D: leitura direta concorrente e formatos (leitor injetado): mudanca entre passadas, linha desconhecida, trait desconhecido, sem quebra final, arquivo bloqueado; falha nunca vira ausencia; leitura compartilhada nao bloqueia outros processos' {
        if (& $gitSkip) { return }
        $pb = Join-Path $gitRoot 'pubfmt'
        $d = Join-Path $pb 'r'; [void][IO.Directory]::CreateDirectory($d); & $gitFx $d @('init', '-q', '-b', 'main') $null
        [IO.File]::WriteAllText((Join-Path $d 'a.txt'), "1`n"); & $gitFx $d @('add', 'a.txt') $d; & $gitFx $d @('commit', '-q', '-m', 'base') $d
        $cd = Join-Path $d '.git'
        $base = Get-AtmGitRefStore -CommonDir $cd
        Assert-True ($base.Status -eq 'COMPLETE' -and $base.RemoteCount -eq 0 -and $base.Local.ContainsKey('main')) 'referencias lidas: um branch, nenhuma remota'
        # The second pass sees a remote-tracking ref that the first did not: unstable, never "no remote".
        $script:pdN = 0
        $reader = { param([string]$P, [int]$Max) $t = Read-AtmGitSmallFile -Path $P -MaxBytes $Max; if ($P.EndsWith('packed-refs')) { $script:pdN++; if ($script:pdN -ge 2) { $t = $t + ('0' * 40) + " refs/remotes/origin/main`n" } }; return $t }
        & $gitFx $d @('pack-refs', '--all') $d
        $u = Get-AtmGitRefStore -CommonDir $cd -ReadFile $reader
        Assert-True ($u.Status -eq 'UNSTABLE' -and $u.Reason -eq 'REF_STORE_UNSTABLE') "mudanca entre as passadas: instavel ($($u.Status))"
        $pr = Join-Path $cd 'packed-refs'
        $orig = [IO.File]::ReadAllText($pr)
        foreach ($c in @(@(($orig + "garbage line`n"), 'FAILED'), @(("# pack-refs with: peeled future-trait`n" + $orig), 'UNSUPPORTED'), @($orig.TrimEnd("`n"), 'FAILED'))) {
            [IO.File]::WriteAllText($pr, $c[0])
            Assert-Eq (Get-AtmGitRefStore -CommonDir $cd).Status $c[1] "packed-refs: $($c[1])"
        }
        [IO.File]::WriteAllText($pr, $orig)
        $lock = [IO.File]::Open($pr, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
        try { $bl = Get-AtmGitRefStore -CommonDir $cd } finally { $lock.Dispose() }
        Assert-True ($bl.Status -eq 'FAILED' -and $bl.RemoteCount -eq 0) 'packed-refs bloqueado: falha (nunca "sem remotas")'
        # E: unreadable or unstable references: never even the absence observation.
        foreach ($st in @(@($bl, 'ilegivel'), @($u, 'instavel'))) {
            $pub = Get-AtmWorktreePublication -GitDir $cd -RefStore $st[0] -CommonDir $cd
            Assert-True (@($pub.Evidence | Where-Object { $_.Code -eq 'PUBLICATION_NOT_OBSERVED' }).Count -eq 1 -and @($pub.Evidence | Where-Object { $_.Code -eq 'NO_REMOTE_TRACKING_REFS' }).Count -eq 0) "E: referencias $($st[1]): publicacao nao observada, nenhuma ausencia afirmada"
        }
        # Shared reads never block another process's rename over the file; a non-shared read would (counter-proof).
        $target = Join-Path $pb 'shared.txt'; [IO.File]::WriteAllText($target, "old`n")
        $try = { param([scriptblock]$B) try { & $B; return 'SUCCEEDED' } catch { return 'BLOCKED' } }
        $sh = New-AtmGitSharedReadStream -Path $target
        try { [IO.File]::WriteAllText((Join-Path $pb 'shared.new'), "new`n"); $r1 = & $try { [IO.File]::Replace((Join-Path $pb 'shared.new'), $target, [NullString]::Value) } } finally { $sh.Dispose() }
        Assert-Eq $r1 'SUCCEEDED' 'leitura compartilhada aberta: outro processo substitui o arquivo'
        $ns = [IO.File]::Open($target, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try { [IO.File]::WriteAllText((Join-Path $pb 'shared.new2'), "new2`n"); $r2 = & $try { [IO.File]::Replace((Join-Path $pb 'shared.new2'), $target, [NullString]::Value) } } finally { $ns.Dispose() }
        Assert-Eq $r2 'BLOCKED' 'contraprova: leitura sem compartilhamento bloquearia a substituicao'
        # Raw bytes as Git reads them: a UTF-16 HEAD is not a branch; packed names differing only in case stay distinct.
        $u16 = Join-Path $pb 'utf16-gitdir'; [void][IO.Directory]::CreateDirectory($u16); [IO.File]::WriteAllText((Join-Path $u16 'HEAD'), "ref: refs/heads/main`n", [Text.Encoding]::Unicode)
        Assert-Eq (Read-AtmGitHead -GitDir $u16).Kind 'UNREADABLE' 'HEAD em UTF-16: ilegivel (como para o Git)'
        $idA = ('a' * 40); $idB = ('b' * 40)
        [IO.File]::WriteAllText($pr, $orig + "$idA refs/heads/Foo`n$idB refs/heads/foo`n")
        $cs = Get-AtmGitRefStore -CommonDir $cd
        Assert-True ($cs.Status -eq 'COMPLETE' -and $cs.Local['Foo'] -ceq $idA -and $cs.Local['foo'] -ceq $idB) 'branches que diferem so na caixa: distintos'
        [IO.File]::WriteAllText($pr, $orig)
        # A shared read never follows a reparse point: a junction is refused on the handle.
        $jn = Join-Path $pb 'jn'; New-Junction -Link $jn -Target $pb
        $thrown = $false; try { $x = New-AtmGitSharedReadStream -Path $jn; $x.Dispose() } catch { $thrown = $true }
        Assert-True ($thrown -and $null -eq (Read-AtmGitSmallFile -Path $jn)) 'leitura compartilhada recusa reparse point'
        # NOT RESOLVED (recorded): an ANCESTOR directory replaced between the path check and the open redirects the read.
        # Only the final component is opened without following a reparse point. Local junction only (never a network path).
        $real = Join-Path $pb 'anc-real'; $evil = Join-Path $pb 'anc-evil'
        foreach ($x in @((Join-Path $real 'anc'), (Join-Path $evil 'anc'))) { [void][IO.Directory]::CreateDirectory($x) }
        [IO.File]::WriteAllText((Join-Path $real 'anc\ref'), "real`n"); [IO.File]::WriteAllText((Join-Path $evil 'anc\ref'), "redirected`n")
        $chk = Resolve-AtmGitReferencedPath -Value 'anc\ref' -BaseDir $real
        Assert-Eq $chk.Status 'OK' 'caminho validado'
        [IO.Directory]::Move((Join-Path $real 'anc'), (Join-Path $real 'anc-old'))
        New-Junction -Link (Join-Path $real 'anc') -Target (Join-Path $evil 'anc')
        Assert-Eq ((Read-AtmGitSmallFile -Path $chk.Path) -replace "`n", '') 'redirected' 'NAO RESOLVIDO (provado): ancestral trocado depois da validacao redireciona a leitura (juncao local)'
        Assert-Eq (Resolve-AtmGitReferencedPath -Value 'anc\ref' -BaseDir $real).Reason 'GIT_REF_PATH_REPARSE' 'uma nova validacao detecta a troca (protecao so no momento da checagem)'
        # HEAD through the resolver: a directory (junction) named HEAD is never read as a branch.
        $fakeGd = Join-Path $pb 'fake-gitdir'; [void][IO.Directory]::CreateDirectory($fakeGd)
        New-Junction -Link (Join-Path $fakeGd 'HEAD') -Target $pb
        Assert-Eq (Read-AtmGitHead -GitDir $fakeGd).Kind 'UNREADABLE' 'HEAD como juncao: ilegivel'
        $sa = Get-AtmWorktreeStashAttribution -GitDir $fakeGd -Stash ([pscustomobject]@{ Status = 'COMPLETE'; Count = 1; Branches = @('main') })
        Assert-True ($sa.Code -eq 'STASH_NOT_ATTRIBUTABLE' -and -not $sa.Complete) 'stash com HEAD ilegivel: nao atribuivel'
        # rev-parse no longer asks the common directory (Git would only repeat GIT_COMMON_DIR).
        $pz = New-AtmPseudonymizer -Key $testPseudonymKey
        try {
            $script:AtmGitInvocationLog = New-Object System.Collections.Generic.List[object]
            $script:AtmWorktreeDiagnosticsEnabled = $true
            try { $null = Get-AtmWorktreeDiscovery -RepositoryPaths @($d) -Git $testGit -Pseudonymizer $pz; $log = $script:AtmGitInvocationLog.ToArray() }
            finally { $script:AtmWorktreeDiagnosticsEnabled = $false; $script:AtmGitInvocationLog = $null }
        } finally { Close-AtmPseudonymizer $pz }
        $rp = @($log | Where-Object { $_.Arguments -ccontains 'rev-parse' })
        Assert-True ($rp.Count -eq 1 -and $rp[0].Arguments -cnotcontains '--git-common-dir' -and $rp[0].Arguments -ccontains '--show-toplevel') 'rev-parse sem --git-common-dir'
    }
    Test-Case 'Git' 'P3-E: escala - a parte comum da pre-verificacao e lida uma vez por repositorio (cache por impressao digital), sem repeticao O(W x R); limites, ordem deterministica, privacidade e memoria' {
        if (& $gitSkip) { return }
        $big = & $scaleFixture 'scale-big' 300 2000
        $small = & $scaleFixture 'scale-small' 20 300
        $pz = New-AtmPseudonymizer -Key $testPseudonymKey
        try {
            $script:AtmWorktreeDiagnosticsEnabled = $true
            try {
                # Before (no cache) and after (cache) on the small repository: same findings, far less work.
                $u = Get-AtmWorktreeDiscovery -Partitions $small.Partitions -Git $null -Pseudonymizer $pz -NoPreflightCache
                $c = Get-AtmWorktreeDiscovery -Partitions $small.Partitions -Git $null -Pseudonymizer $pz
                # Large repository: 300 worktrees, 2,000 references.
                [GC]::Collect(); $m0 = [GC]::GetTotalMemory($true)
                $sw = [Diagnostics.Stopwatch]::StartNew()
                $b = Get-AtmWorktreeDiscovery -Partitions $big.Partitions -Git $null -Pseudonymizer $pz
                $sw.Stop(); $m1 = [GC]::GetTotalMemory($false)
                $b2 = Get-AtmWorktreeDiscovery -Partitions $big.Partitions -Git $null -Pseudonymizer $pz
                # Limits give PARTIAL with their reason, never a silent cut.
                $capC = Get-AtmWorktreeDiscovery -Partitions $big.Partitions -Git $null -Pseudonymizer $pz -MaxCandidates 50
                $capB = Get-AtmWorktreeDiscovery -Partitions $big.Partitions -Git $null -Pseudonymizer $pz -MaxBytesRead 2000
                $capD = Get-AtmWorktreeDiscovery -Partitions $big.Partitions -Git $null -Pseudonymizer $pz -Deadline ([datetime]::UtcNow.AddSeconds(-1))
            } finally { $script:AtmWorktreeDiagnosticsEnabled = $false }
            $sig = { param($r) (@($r.Findings | ForEach-Object { $_.Kind + '|' + $_.Key + '|' + $_.State + '|' + (@($_.Evidence | ForEach-Object { $_.Code + '=' + $_.Detail }) -join ',') }) -join "`n") }
            Assert-Eq (& $sig $c) (& $sig $u) 'mesmos achados com e sem cache'
            Assert-True ($u.Stats.CommonPreflights -ge 20 -and $c.Stats.CommonPreflights -eq 1 -and $c.Stats.CommonCacheHits -ge 19) "parte comum: sem cache $($u.Stats.CommonPreflights), com cache $($c.Stats.CommonPreflights) (acertos $($c.Stats.CommonCacheHits))"
            Assert-True ($u.Stats.RefEntriesWalked -ge 20 * 300 -and $c.Stats.RefEntriesWalked -lt 2 * 310) "entradas de referencia percorridas: sem cache $($u.Stats.RefEntriesWalked), com cache $($c.Stats.RefEntriesWalked)"
            Assert-True ($b.Stats.CommonPreflights -eq 1 -and $b.Stats.RefStoreReads -eq 1 -and $b.Stats.RefEntriesWalked -lt 2100) "300 worktrees, 2000 referencias: parte comum 1x, referencias 1x por repositorio ($($b.Stats.RefEntriesWalked) entradas)"
            Assert-Eq @($b.Findings | Where-Object { $_.Kind -eq 'Worktree' -and @($_.Evidence | Where-Object { $_.Code -eq 'WORKTREE_REGISTERED' }).Count -eq 1 }).Count 300 'todas as 300 worktrees registradas'
            Assert-Eq (& $sig $b2) (& $sig $b) 'ordem e conteudo deterministicos entre execucoes'
            Assert-True ((($m1 - $m0) / 1MB) -lt 200) ("memoria gerenciada controlada ({0:N1} MB)" -f (($m1 - $m0) / 1MB))
            Assert-True (@($capC.Coverage[0].Reasons) -contains 'CANDIDATE_LIMIT' -and @($capB.Coverage[0].Reasons) -contains 'READ_BUDGET' -and @($capD.Coverage[0].Reasons) -contains 'DEADLINE_EXCEEDED') 'limites de candidatos, bytes e prazo: PARTIAL com o motivo'
            Assert-True (@($capC.Findings | Where-Object { $_.State -eq 'CLEAN_AND_PUBLISHED_UNKNOWN' }).Count -eq 0) 'um corte nunca vira limpo'
            $nx = @($capB.Findings | Where-Object { $_.Kind -eq 'Repository' -and @($_.Evidence | Where-Object { $_.Code -eq 'REPOSITORY_NOT_EXAMINED' -and $_.Detail -eq 'READ_BUDGET' }).Count -eq 1 })
            Assert-True ($nx.Count -eq 1 -and @($capB.Findings | Where-Object { $_.Kind -eq 'Worktree' -and @($_.Evidence | Where-Object { $_.Code -eq 'LOCAL_WORK_UNKNOWN' -and $_.Detail -eq 'READ_BUDGET' }).Count -eq 1 }).Count -ge 1) 'orcamento de leitura: repositorio descoberto mantido e marcado como nao examinado (nunca descartado)'
            $json = (@{ F = $b.Findings; C = $b.Coverage } | ConvertTo-Json -Depth 8)
            foreach ($x in @($big.Repo, $big.Part, 'wt17', 'origin')) { Assert-True (-not $json.Contains($x) -and -not $json.Contains($x.Replace('\', '\\'))) "nada sensivel nos achados: $(Split-Path -Leaf $x)" }
            $script:caseNote = ("300 worktrees/2000 refs: {0:N1}s, {1} arquivos, {2:N0} KB lidos; 20 worktrees/300 refs: parte comum {3} -> {4}, entradas {5} -> {6}" -f $sw.Elapsed.TotalSeconds, $b.Stats.FilesRead, ($b.Stats.BytesRead / 1KB), $u.Stats.CommonPreflights, $c.Stats.CommonPreflights, $u.Stats.RefEntriesWalked, $c.Stats.RefEntriesWalked)
        } finally { Close-AtmPseudonymizer $pz }
    }
    Test-Case 'Git' 'P3-E: o cache nao reutiliza conclusoes apos mudancas detectaveis; a pre-verificacao do executor nunca usa cache; referencias novas sao vistas' {
        if (& $gitSkip) { return }
        $fx = & $scaleFixture 'scale-inval' 3 5
        $wt0 = Join-Path $fx.Part 'wt0'; $wt1 = Join-Path $fx.Part 'wt1'; $wt2 = Join-Path $fx.Part 'wt2'
        Reset-AtmScaleStats
        $cache = @{}
        $p0 = Get-AtmGitPreflight -Target $wt0 -Cache $cache
        $p1 = Get-AtmGitPreflight -Target $wt1 -Cache $cache
        Assert-True ($p0.Status -eq 'OK' -and $p1.Status -eq 'OK' -and $script:AtmScaleStats.CommonPreflights -eq 1 -and $script:AtmScaleStats.CommonCacheHits -eq 1) 'sem mudanca: parte comum reutilizada'
        Start-Sleep -Milliseconds 50
        [IO.File]::AppendAllText((Join-Path $fx.Repo '.git\config'), "[include]`n`tpath = x`n")
        $p2 = Get-AtmGitPreflight -Target $wt2 -Cache $cache
        Assert-True ($script:AtmScaleStats.CommonCacheInvalidations -eq 1 -and $script:AtmScaleStats.CommonPreflights -eq 2 -and $p2.Reason -eq 'GIT_PREFLIGHT_INCLUDE') 'config alterado: cache invalidado, include recusado'
        # A reference added later is seen by the reference store (never cached).
        $before = Get-AtmGitRefStore -CommonDir (Join-Path $fx.Repo '.git')
        $id = (& $gitFxOut $fx.Repo @('rev-parse', 'HEAD') $fx.Repo).Out.Trim()
        [IO.File]::WriteAllText((Join-Path $fx.Repo '.git\refs\remotes\origin\late'), "$id`n")
        $after = Get-AtmGitRefStore -CommonDir (Join-Path $fx.Repo '.git')
        Assert-Eq ($after.RemoteCount - $before.RemoteCount) 1 'referencia nova vista pela leitura de referencias'
        # The runner takes its own uncached preflight: a cached OK never lets Git run on a changed repository.
        $n = & $gitSpy { $script:p3eR = & $gitOpen { Invoke-AtmGitCommand -Git $testGit -Arguments @('rev-parse', '--show-toplevel') -WorkingDirectory $wt0 -Preflight $p0 } }
        Assert-True ($n -eq 0 -and $script:p3eR.Reason -eq 'GIT_PREFLIGHT_REQUIRED') "executor: pre-verificacao propria recusa o repositorio alterado ($($script:p3eR.Reason))"
        # A change in a chained alternates file invalidates the cached part too.
        $alt = & $scaleFixture 'scale-alt' 2 1
        $other = & $gitNewFixture 'scale-alt-other'
        $otherObj = Join-Path $other.Repo '.git\objects'
        [IO.File]::WriteAllText((Join-Path $alt.Repo '.git\objects\info\alternates'), "$otherObj`n")
        Reset-AtmScaleStats
        $c2 = @{}
        $null = Get-AtmGitPreflight -Target (Join-Path $alt.Part 'wt0') -Cache $c2
        Start-Sleep -Milliseconds 50
        [IO.File]::WriteAllText((Join-Path $otherObj 'info\alternates'), "\\$uncHost\share\objects`n")
        $pa = Get-AtmGitPreflight -Target (Join-Path $alt.Part 'wt1') -Cache $c2
        Assert-True ($script:AtmScaleStats.CommonCacheInvalidations -eq 1 -and $pa.Reason -eq 'GIT_PREFLIGHT_ALTERNATE_NETWORK') "alternates encadeado alterado: cache invalidado, rede recusada ($($pa.Reason))"
        $body = [IO.File]::ReadAllText((Join-Path $srcDir 'lib\Engine.Diagnose.ps1'))
        $inv = $body.Substring($body.IndexOf('function Invoke-AtmGitCommand'), 6000)
        Assert-True ($inv.Contains('$fresh = Get-AtmGitPreflight -Target $wd') -and -not $inv.Contains('-Cache')) 'executor nunca passa cache'
    }
    Test-Case 'Git' 'P3-E: verificacao de cadeia nativa do diagnostico tem o mesmo resultado de Test-AtmPathChain (arquivo, ausente, ausente no meio, componente arquivo, juncao, unidade nao fixa, raiz, invalido)' {
        $pb = Join-Path $gitRoot 'chain-parity'; [void][IO.Directory]::CreateDirectory((Join-Path $pb 'd'))
        [IO.File]::WriteAllText((Join-Path $pb 'd\f.txt'), 'x')
        New-Junction -Link (Join-Path $pb 'j') -Target (Join-Path $pb 'd')
        $free = @([char[]]'ZYXWVUTSRQPONMLKJIHG' | Where-Object { (New-Object IO.DriveInfo([string]$_)).DriveType -eq [IO.DriveType]::NoRootDirectory })
        $cases = @((Join-Path $pb 'd\f.txt'), (Join-Path $pb 'd\missing.txt'), (Join-Path $pb 'nope\f.txt'), (Join-Path $pb 'd\f.txt\below'), (Join-Path $pb 'j\f.txt'), $env:SystemDrive + '\', 'relative\x', '')
        if ($free.Count -gt 0) { $cases += ($free[0] + ':\x') }
        # Too long for the plain API: refused, never "not found" (which some callers accept as absent).
        Assert-Eq (Test-AtmGitPathChain ($env:SystemDrive + '\' + ('a' * 270))).Status 'INACCESSIBLE' 'caminho longo: recusado, nunca ausente'
        foreach ($c in $cases) {
            $a = Test-AtmPathChain $c; $b = Test-AtmGitPathChain $c
            Assert-True ($a.Status -ceq $b.Status) "paridade [$($c.Replace($pb, '<fx>'))]: $($a.Status) / $($b.Status)"
        }
    }
    Test-Case 'Diagnose' 'P3-C: contagem de status porcelain v2 por fonte injetada (renomeacao, conflito, submodulo, ignorado); registro irreconhecivel nunca vira zero' {
        $z = [char]0
        $t = "# branch.oid abc$z" + "1 M. N... 100644 100644 100644 h1 h2 a b.txt$z" + "1 .M N... 100644 100644 100644 h1 h2 c.txt$z" + "2 R. N... 100644 100644 100644 h1 h2 R100 new name$z" + "old name$z" +
            "u UU N... 100644 100644 100644 100644 h1 h2 h3 d.txt$z" + "? x y$z" + "! build/$z" + "1 .M S.M. 160000 160000 160000 h1 h2 sub$z"
        $c = ConvertFrom-AtmGitStatusV2 -Text $t
        Assert-True ($null -eq $c.Error -and $c.Staged -eq 2 -and $c.Unstaged -eq 2 -and $c.Untracked -eq 1 -and $c.Ignored -eq 1 -and $c.Conflicts -eq 1 -and $c.Submodules -eq 1) "contagens: $($c.Staged)/$($c.Unstaged)/$($c.Untracked)/$($c.Ignored)/$($c.Conflicts)/$($c.Submodules)"
        Assert-Eq (ConvertFrom-AtmGitStatusV2 -Text '').Staged 0 'vazio: nada'
        foreach ($bad in @("1 M. N...$z", "Z foo$z", "2 R. N... 100644 100644 100644 h1 h2 R100 new", "1 MM. N... 100644 100644 100644 h1 h2 x$z", "u UU N... 1 2 3$z")) { Assert-Eq (ConvertFrom-AtmGitStatusV2 -Text $bad).Error 'GIT_STATUS_UNPARSEABLE' "irreconhecivel: $($bad.Replace([string]$z, '\0'))" }
    }
    # ------------------------------------------------------------------ P1-C (D-2 Restart Manager; D-1 deferred)
    # Helper processes are started by the tests themselves, hold sandbox files only, and are stopped through their own
    # Process object (bound to their handle). No other process is opened, signalled or stopped.
    $rmHolder = { param([string]$File, [int]$Seconds = 25)
        $cmd = "`$f = [IO.File]::Open('$File', 'Open', 'Read', 'ReadWrite'); Start-Sleep -Seconds $Seconds; `$f.Dispose()"
        $c = Start-Process -FilePath (Join-Path $PSHOME $(if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' })) -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', $cmd) -PassThru -WindowStyle Hidden
        # Ready when Restart Manager sees the file held (bounded wait).
        for ($i = 0; $i -lt 60; $i++) { $h = $null; $null = [AgentTempManager.AtmRestartManager]::Query([string[]]@($File), 8, [ref]$h); if (@($h | Where-Object { $_.Split('|')[0] -eq [string]$c.Id }).Count -gt 0) { break }; Start-Sleep -Milliseconds 250 }
        return $c }
    $rmRow = { param($Proc) [pscustomobject]@{ ProcessId = $Proc.Id; ParentProcessId = $PID; Name = 'helper.exe'; CreationDate = (New-Object DateTime(($Proc.StartTime.ToUniversalTime().Ticks - ($Proc.StartTime.ToUniversalTime().Ticks % 10)), [DateTimeKind]::Utc)); KernelModeTime = 0; UserModeTime = 0; WorkingSetSize = 0; PrivatePageCount = 0; HandleCount = 0; ReadTransferCount = 0; WriteTransferCount = 0; OtherTransferCount = 0 } }
    Test-Case 'Processos' 'P1-C D-2: Restart Manager lista o processo auxiliar que mantem um arquivo de fixture aberto, com PID e inicio verificaveis; arquivo sem handle nao lista nada; conteudo e processo intactos' {
        $d = Join-Path $sandbox 'rm-basic'; [void][IO.Directory]::CreateDirectory($d)
        $held = Join-Path $d 'held.txt'; $free = Join-Path $d 'free.txt'
        [IO.File]::WriteAllText($held, "held`n"); [IO.File]::WriteAllText($free, "free`n")
        $before = (Get-FileHash -LiteralPath $held).Hash + (Get-FileHash -LiteralPath $free).Hash
        $c = & $rmHolder $held
        try {
            $h = $null; $st = [AgentTempManager.AtmRestartManager]::Query([string[]]@($held), 8, [ref]$h)
            $mine = @($h | Where-Object { $_.Split('|')[0] -eq [string]$c.Id })
            Assert-True ($st -eq 'OK' -and $mine.Count -eq 1) "arquivo mantido aberto: processo auxiliar listado ($st)"
            Assert-Eq ([long]$mine[0].Split('|')[1]) $c.StartTime.ToUniversalTime().Ticks 'inicio do processo igual ao do sistema (100 ns)'
            $h2 = $null; Assert-True (([AgentTempManager.AtmRestartManager]::Query([string[]]@($free), 8, [ref]$h2)) -eq 'OK' -and @($h2).Count -eq 0) 'arquivo sem handle: nenhum processo'
            Assert-True (-not $c.HasExited) 'processo auxiliar segue ativo depois das consultas'
        } finally { if (-not $c.HasExited) { $c.Kill() }; $c.WaitForExit(10000) | Out-Null }
        Assert-Eq ((Get-FileHash -LiteralPath $held).Hash + (Get-FileHash -LiteralPath $free).Hash) $before 'conteudo dos arquivos intacto'
        # Sessions are always ended: more sequential queries than Restart Manager's concurrent-session limit all succeed.
        $ok = 0; for ($i = 0; $i -lt 70; $i++) { $hx = $null; if (([AgentTempManager.AtmRestartManager]::Query([string[]]@($free), 4, [ref]$hx)) -eq 'OK') { $ok++ } }
        Assert-Eq $ok 70 'sessoes sempre encerradas (70 consultas seguidas)'
        $hx = $null; Assert-Eq ([AgentTempManager.AtmRestartManager]::Query([string[]]@(), 4, [ref]$hx)) 'OK' 'nenhum arquivo: nada consultado'
    }
    Test-Case 'Processos' 'P1-C D-2: coletor handles - identidade verificada pelo snapshot, nao verificada, proprio processo excluido, processo encerrado, limites, falha de registro, prazo; nunca COMPLETE' {
        # P1-C-S: the gate is opened for this harness fixture only and closed again, even on error.
        $script:AtmHandleDiagnosticsEnabled = $true
        try {
        $d = Join-Path $sandbox 'rm-coll'; [void][IO.Directory]::CreateDirectory($d)
        $held = Join-Path $d 'held.txt'; [IO.File]::WriteAllText($held, "x`n")
        $c = & $rmHolder $held
        try {
            # GetNewClosure copies only this scope's variables: the row is built here, not inside the closure.
            $helperRow = & $rmRow $c
            $coll = Get-AtmProcessCollection -Source ({ @($helperRow) }.GetNewClosure())
            $node = [pscustomobject]@{ Key = 'claude-code/p-test'; Files = @($held); Capped = $false; Error = $null }
            $r = Get-AtmHandleEvidence -Nodes @($node) -Collection $coll
            $ev = @($r.Evidence['claude-code/p-test'])
            $key = ConvertTo-AtmProcessKey -ProcessId $c.Id -CreationUtc (& $rmRow $c).CreationDate
            Assert-True (@($ev | Where-Object { $_.Code -eq 'FILE_HELD_OPEN' -and $_.Detail -eq $key }).Count -eq 1) "processo verificado pelo snapshot: FILE_HELD_OPEN com a chave ($(@($ev | ForEach-Object { $_.Code }) -join ','))"
            Assert-True ($r.Coverage.Status -eq 'PARTIAL' -and @($r.Coverage.Reasons) -contains 'HANDLES_SAMPLED') 'cobertura sempre PARTIAL (amostra)'
            $r2 = Get-AtmHandleEvidence -Nodes @($node) -Collection (Get-AtmProcessCollection -Source { @([pscustomobject]@{ ProcessId = 999999; ParentProcessId = 1; Name = 'x'; CreationDate = [datetime]::UtcNow.AddDays(-1) }) })
            Assert-True (@($r2.Evidence['claude-code/p-test'] | Where-Object { $_.Code -eq 'FILE_HELD_OPEN_UNVERIFIED' -and $_.Detail -eq ('pid:' + $c.Id) }).Count -eq 1 -and @($r2.Coverage.Reasons) -contains 'HANDLE_IDENTITY_UNVERIFIED') 'fora do snapshot: identidade nao verificada'
            $r3 = Get-AtmHandleEvidence -Nodes @($node) -Collection $coll -SelfKeys @{ $key = $true }
            Assert-True (-not $r3.Evidence.ContainsKey('claude-code/p-test')) 'processo do proprio ATM nunca reportado (nada anexado)'
        } finally { if (-not $c.HasExited) { $c.Kill() }; $c.WaitForExit(10000) | Out-Null }
        # Exited: the same file is no longer held.
        $node = [pscustomobject]@{ Key = 'k'; Files = @($held); Capped = $false; Error = $null }
        $r4 = Get-AtmHandleEvidence -Nodes @($node) -Collection $null
        Assert-True ((-not $r4.Evidence.ContainsKey('k')) -and @($r4.Coverage.Reasons) -contains 'PROCESS_SNAPSHOT_UNAVAILABLE') 'processo encerrado: nada listado; sem snapshot declarado'
        # Injected queries: limits, failures, deadline.
        $n2 = @([pscustomobject]@{ Key = 'a'; Files = @('C:\x\1', 'C:\x\2'); Capped = $true; Error = $null }, [pscustomobject]@{ Key = 'b'; Files = @('C:\x\3'); Capped = $false; Error = $null })
        $okQ = { param($Files, $Max) [pscustomobject]@{ Status = 'OK'; Holders = @() } }
        $capF = Get-AtmHandleEvidence -Nodes $n2 -Query $okQ -MaxFilesPerRun 1
        Assert-True (@($capF.Coverage.Reasons) -contains 'HANDLE_FILES_CAPPED') 'limite de arquivos por execucao e por item'
        $capS = Get-AtmHandleEvidence -Nodes $n2 -Query $okQ -MaxSessions 1
        Assert-True (@($capS.Coverage.Reasons) -contains 'HANDLE_SESSION_LIMIT' -and $capS.Coverage.Observed -eq 1) 'limite de sessoes'
        $capH = Get-AtmHandleEvidence -Nodes $n2 -Query { param($Files, $Max) [pscustomobject]@{ Status = 'PARTIAL'; Holders = @() } }
        Assert-True (@($capH.Coverage.Reasons) -contains 'HANDLE_HOLDERS_CAPPED' -and @($capH.Evidence['a'] | Where-Object { $_.Code -eq 'FILE_HELD_OPEN_UNVERIFIED' -and $_.Detail -eq 'HOLDERS_CAPPED' }).Count -eq 1) 'mais processos do que o limite: item marcado como mantido aberto, nunca livre'
        $dup = Get-AtmHandleEvidence -Nodes @([pscustomobject]@{ Key = 'z'; Files = @('C:\x\1'); Capped = $false; Error = $null }, [pscustomobject]@{ Key = 'z'; Files = @('C:\x\2'); Capped = $false; Error = $null }) -Query $okQ
        Assert-Eq $dup.Coverage.Expected 1 'chave repetida: um so item'
        $fail = Get-AtmHandleEvidence -Nodes $n2 -Query { param($Files, $Max) [pscustomobject]@{ Status = 'FAILED_REGISTER_5'; Holders = @('1|1') } }
        Assert-True (@($fail.Coverage.Reasons) -contains 'HANDLE_QUERY_FAILED' -and $fail.Evidence.Count -eq 0) 'erro no registro: nenhuma evidencia, nunca "livre"'
        $thr = Get-AtmHandleEvidence -Nodes $n2 -Query { param($Files, $Max) throw 'boom' }
        Assert-True (@($thr.Coverage.Reasons) -contains 'HANDLE_QUERY_FAILED') 'excecao na consulta: falha declarada'
        $dl = Get-AtmHandleEvidence -Nodes $n2 -Query $okQ -Deadline ([datetime]::UtcNow.AddSeconds(-1))
        Assert-True (@($dl.Coverage.Reasons) -contains 'DEADLINE_EXCEEDED' -and $dl.Coverage.Observed -eq 0) 'prazo: nada consultado depois dele'
        Assert-Eq (Get-AtmHandleEvidence -Nodes @()).Coverage.Status 'NOT_OBSERVABLE' 'sem itens: nao observavel'
        # Observation time (P1-C-S): one instant for the whole batch, the start of the batch (= coverage StartedUtc),
        # even when the queries of the nodes run at different times.
        $slowQ = { param($Files, $Max) Start-Sleep -Milliseconds 30; [pscustomobject]@{ Status = 'OK'; Holders = @('424242|' + [datetime]::UtcNow.AddMinutes(-5).Ticks) } }
        $tb = Get-AtmHandleEvidence -Nodes $n2 -Query $slowQ
        $tt = @(@($tb.Evidence['a']) + @($tb.Evidence['b']) | ForEach-Object { $_.ObservedUtc.Ticks } | Select-Object -Unique)
        Assert-True ($tt.Count -eq 1 -and $tt[0] -eq $tb.Coverage.StartedUtc.Ticks -and $tb.Coverage.ElapsedMs -ge 40) "horario do lote: um so, igual ao inicio da cobertura handles ($($tt.Count) valores)"
        Assert-True (@((Get-Command Get-AtmHandleEvidence).Parameters.Keys) -notcontains 'ObservedUtc') 'horario de outra coleta nao pode ser imposto ao lote'
        } finally { $script:AtmHandleDiagnosticsEnabled = $false }
    }
    Test-Case 'Processos' 'P1-C D-2: amostra de arquivos por item (nunca recursiva, sem reparse point, limitada) e integracao ao diagnose sem caminhos; estado da particao inalterado; diretorios de trabalho nao observados' {
        # P1-C-S: the gate is opened for this harness fixture only and closed again, even on error.
        $script:AtmHandleDiagnosticsEnabled = $true
        try {
        $d = Join-Path $sandbox 'rm-sample'; [void][IO.Directory]::CreateDirectory((Join-Path $d 'sub'))
        foreach ($n in @('a.txt', 'b.txt', 'c.txt')) { [IO.File]::WriteAllText((Join-Path $d $n), 'x') }
        $od = Join-Path $sandbox 'rm-office'; [void][IO.Directory]::CreateDirectory($od); [IO.File]::WriteAllText((Join-Path $od '~$doc.docx'), 'x')
        Assert-Eq @((Get-AtmHandleSampleFiles -Dir $od).Files | Where-Object { $_ -like '*~$doc.docx' }).Count 1 'arquivo de dono do Office (~$) entra na amostra'
        [IO.File]::WriteAllText((Join-Path $d 'sub\deep.txt'), 'x')
        $smp = Get-AtmHandleSampleFiles -Dir $d -Max 2
        Assert-True (@($smp.Files).Count -eq 2 -and $smp.Capped -and @($smp.Files | Where-Object { $_ -like '*deep*' }).Count -eq 0) 'amostra limitada e nao recursiva'
        Assert-Eq (Get-AtmHandleSampleFiles -Dir '\\atm-unc-probe.invalid\share').Error 'HANDLE_NODE_UNREADABLE' 'item de rede recusado antes de listar'
        $p = New-TestProfile 'p1c-int'
        $root = New-TestRoot -ProfileInfo $p
        $marker = 'p1c-secret-name'
        [IO.File]::WriteAllText((Join-Path $root "$marker.txt"), 'x')
        $hq = { param($Files, $Max) [pscustomobject]@{ Status = 'OK'; Holders = @('424242|' + [datetime]::UtcNow.AddMinutes(-5).Ticks) } }
        $res = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p)) -IdentitySource $diagIdUser -ProcessSource { @([pscustomobject]@{ ProcessId = 1; ParentProcessId = 0; Name = 'x'; CreationDate = [datetime]::UtcNow.AddDays(-1) }) } -CpuSampleMs 0 -PseudonymKey $testPseudonymKey -HandleQuery $hq
        $tp = @($res.Findings | Where-Object { $_.Kind -eq 'TempPartition' })
        Assert-True ($tp.Count -ge 1 -and @($tp | Where-Object { @($_.Evidence | Where-Object { $_.Code -eq 'FILE_HELD_OPEN_UNVERIFIED' -and $_.Detail -eq 'pid:424242' }).Count -eq 1 }).Count -ge 1) 'evidencia de arquivo aberto na particao (identidade nao verificada)'
        Assert-True (@($tp | Where-Object { $_.State -ceq 'NO_DEPENDENCY_OBSERVED' -or $_.State -ceq 'RUNTIME_NOT_DIAGNOSED' -or ($_.State -ceq 'IN_USE' -and @($_.Evidence | Where-Object { $_.Code -ceq 'GRAPH_SOURCE_DIRECT' }).Count -eq 0) }).Count -eq 0) 'particao nunca livre nem sem diagnostico; IN_USE so com fonte direta (P4-B)'
        $json = ConvertTo-AtmDiagnoseJson -Result $res
        foreach ($x in @($marker, $root, $root.Replace('\', '\\'))) { Assert-True (-not $json.Contains($x)) "JSON sem caminho nem nome de arquivo: $(Split-Path -Leaf $x)" }
        $txt = (Show-AtmDiagnose -Result $res 6>&1 | Out-String)
        Assert-True ($txt.Contains((Get-AtmText 'diag.hTitle')) -and $txt.Contains((Get-AtmText 'diag.hCwd')) -and -not $txt.Contains($marker) -and -not $txt.Contains($root)) 'relatorio: secao de arquivos abertos, sem caminhos'
        Assert-True (@($res.Coverage | Where-Object { $_.Collector -eq 'process-cwd' -and $_.Status -eq 'NOT_OBSERVABLE' }).Count -eq 1) 'diretorios de trabalho: NOT_OBSERVABLE (D-1 adiado)'
        # Observation time (P1-C-S): handle evidence carries the start of the handle batch (its coverage StartedUtc);
        # the partition evidence keeps its own single time (D-8); neither gives the enumeration order back.
        $hcov = @($res.Coverage | Where-Object { $_.Collector -eq 'handles' })[0]
        $hT = @($tp | ForEach-Object { @($_.Evidence) } | Where-Object { $_.Collector -ceq 'handles' } | ForEach-Object { $_.ObservedUtc.Ticks } | Select-Object -Unique)
        $pT = @($tp | ForEach-Object { @($_.Evidence) } | Where-Object { $_.Collector -cne 'handles' } | ForEach-Object { $_.ObservedUtc.Ticks } | Select-Object -Unique)
        Assert-True ($hT.Count -eq 1 -and $hT[0] -eq $hcov.StartedUtc.Ticks -and $pT.Count -eq 1 -and $hT[0] -ge $pT[0]) "horarios: lote handles = inicio da sua cobertura; particoes com um horario proprio ($($hT.Count)/$($pT.Count))"
        $jo = $json | ConvertFrom-Json
        $jh = @($jo.findings | Where-Object { $_.kind -eq 'TempPartition' } | ForEach-Object { @($_.evidence) } | Where-Object { $_.collector -eq 'handles' } | ForEach-Object { [string]$_.observedUtc } | Select-Object -Unique)
        Assert-Eq $jh.Count 1 'JSON: um horario de observacao para as evidencias de arquivos abertos'
        } finally { $script:AtmHandleDiagnosticsEnabled = $false }
    }
    Test-Case 'Processos' 'P1-C-S: trava de arquivos abertos fechada por padrao - diagnose sem listar arquivos nem chamar o Restart Manager; coletor direto recusado; NOT_OBSERVABLE; sem caminhos; estados inalterados' {
        Assert-Eq $script:AtmHandleDiagnosticsEnabled $false 'trava fechada fora dos testes'
        $diag = [IO.File]::ReadAllText((Join-Path $srcDir 'lib\Engine.Diagnose.ps1'))
        Assert-Eq ([regex]::Matches($diag, '\$script:AtmHandleDiagnosticsEnabled\s*=').Count) 1 'uma unica atribuicao da trava no motor'
        Assert-True ($diag -match '(?m)^\$script:AtmHandleDiagnosticsEnabled = \$false\r?$') 'a trava distribuida e $false (linha inteira)'
        # Every other mention of the gate in the engine only reads it (no Set-Variable/New-Variable, no environment).
        $gateUses = @([regex]::Matches($diag, '(?m)^.*AtmHandleDiagnosticsEnabled.*$') | ForEach-Object { $_.Value.Trim() } | Where-Object { $_ -notmatch '^#' -and $_ -cne '$script:AtmHandleDiagnosticsEnabled = $false' })
        Assert-True ($gateUses.Count -ge 4 -and @($gateUses | Where-Object { $_ -notmatch '^(if|elseif) \((-not )?\$script:AtmHandleDiagnosticsEnabled\) \{' -and $_ -notmatch '^\} ?elseif' }).Count -eq 0 -and -not ($diag -match '(?i)(Set|New)-Variable[^\r\n]*AtmHandleDiagnosticsEnabled')) "a trava so e lida no motor ($($gateUses.Count) leituras)"
        $srcAll = @(Get-ChildItem -LiteralPath $srcDir -Recurse -File | Where-Object { $_.Extension -in @('.ps1', '.psm1', '.psd1', '.cs', '.json', '.cmd', '.bat') } | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Text = [IO.File]::ReadAllText($_.FullName) } })
        Assert-Eq (@($srcAll | Where-Object { $_.Name -ne 'Engine.Diagnose.ps1' -and $_.Text.Contains('AtmHandleDiagnosticsEnabled') }).Count) 0 'nenhum outro arquivo (CLI, TUI, configuracao) menciona a trava: nenhuma opcao publica a abre'
        Assert-True (-not ($diag -match '\$env:[A-Za-z_]*Handle')) 'nenhuma variavel de ambiente abre a trava'
        # The only Restart Manager reference in PowerShell is inside the collector, after its gate check.
        $rmRefs = @($srcAll | Where-Object { $_.Name -like '*.ps1' -and $_.Text.Contains('[AgentTempManager.AtmRestartManager]') } | ForEach-Object { $_.Name })
        $he = $diag.Substring($diag.IndexOf('function Get-AtmHandleEvidence'), $diag.IndexOf('function Add-AtmFindingEvidence') - $diag.IndexOf('function Get-AtmHandleEvidence'))
        Assert-True (($rmRefs -join ',') -eq 'Engine.Diagnose.ps1' -and [regex]::Matches($diag, '\[AgentTempManager\.AtmRestartManager\]').Count -eq 1 -and $he.IndexOf('if (-not $script:AtmHandleDiagnosticsEnabled)') -gt 0 -and $he.IndexOf('[AgentTempManager.AtmRestartManager]') -gt $he.IndexOf('if (-not $script:AtmHandleDiagnosticsEnabled)')) 'Restart Manager so dentro do coletor, depois da trava'
        $smpFn = $diag.Substring($diag.IndexOf('function Get-AtmHandleSampleFiles'), $diag.IndexOf('function Get-AtmHandleEvidence') - $diag.IndexOf('function Get-AtmHandleSampleFiles'))
        Assert-True ($smpFn.IndexOf('if (-not $script:AtmHandleDiagnosticsEnabled)') -gt 0 -and $smpFn.IndexOf('EnumerateFiles') -gt $smpFn.IndexOf('if (-not $script:AtmHandleDiagnosticsEnabled)')) 'listagem de arquivos so depois da trava'
        $cli = [IO.File]::ReadAllText((Join-Path $srcDir 'agent-temp.ps1'))
        Assert-True (-not $cli.Contains('HandleQuery')) 'CLI nunca passa uma consulta de arquivos abertos'
        # D: direct calls with the gate closed are refused (even an injected query is never called).
        $calls = @{ N = 0 }
        $countQ = ({ param($Files, $Max) $calls.N++; [pscustomobject]@{ Status = 'OK'; Holders = @('424242|1') } }.GetNewClosure())
        $gd = Join-Path $sandbox 'rm-gate'; [void][IO.Directory]::CreateDirectory($gd); [IO.File]::WriteAllText((Join-Path $gd 'x.txt'), 'x')
        $direct = Get-AtmHandleEvidence -Nodes @([pscustomobject]@{ Key = 'k'; Files = @((Join-Path $gd 'x.txt')); Capped = $false; Error = $null }) -Query $countQ
        Assert-True ($calls.N -eq 0 -and $direct.Evidence.Count -eq 0 -and $direct.Coverage.Status -ceq 'NOT_OBSERVABLE' -and (@($direct.Coverage.Reasons) -join ',') -ceq 'HANDLE_SECURITY_GATE_CLOSED') 'coletor chamado diretamente com a trava fechada: recusado, nenhuma consulta'
        $ds = Get-AtmHandleSampleFiles -Dir $gd
        Assert-True (@($ds.Files).Count -eq 0 -and $ds.Error -ceq 'HANDLE_SECURITY_GATE_CLOSED') 'amostra chamada diretamente com a trava fechada: nada listado'
        # A/B/C/F/H: the diagnose with a file of the partition held by a harness helper: nothing listed, no Restart
        # Manager query (native or injected), NOT_OBSERVABLE, no held evidence, no path; the helper is the harness's own.
        $p = New-TestProfile 'p1cs-gate'
        $root = New-TestRoot -ProfileInfo $p
        $marker = 'p1cs-secret-name'
        $held = Join-Path $root "$marker.txt"; [IO.File]::WriteAllText($held, 'x')
        $diagArgs = @{ InventoryArgs = (Get-InvArgs -Profiles @($p)); IdentitySource = $diagIdUser; ProcessSource = { @([pscustomobject]@{ ProcessId = 1; ParentProcessId = 0; Name = 'x'; CreationDate = [datetime]::UtcNow.AddDays(-1) }) }; CpuSampleMs = 0; PseudonymKey = $testPseudonymKey }
        $c = & $rmHolder $held
        try {
            $script:AtmHandleInvocationLog = New-Object System.Collections.Generic.List[object]
            try {
                $closedNative = Invoke-AtmDiagnose @diagArgs
                $closedInjected = Invoke-AtmDiagnose @diagArgs -HandleQuery $countQ
                $log = $script:AtmHandleInvocationLog.ToArray()
            } finally { $script:AtmHandleInvocationLog = $null }
            Assert-True ($log.Count -eq 0 -and $calls.N -eq 0) "trava fechada: nenhuma listagem de arquivos e nenhuma consulta Restart Manager pelo diagnose ($($log.Count) registros)"
            Assert-True (-not $c.HasExited) 'processo auxiliar do proprio harness segue ativo'
        } finally { if (-not $c.HasExited) { $c.Kill() }; $c.WaitForExit(10000) | Out-Null }
        foreach ($r in @($closedNative, $closedInjected)) {
            $hc = @($r.Coverage | Where-Object { $_.Collector -eq 'handles' })
            Assert-True ($hc.Count -eq 1 -and $hc[0].Status -ceq 'NOT_OBSERVABLE' -and (@($hc[0].Reasons) -join ',') -ceq 'HANDLE_SECURITY_GATE_CLOSED' -and $hc[0].ElevationWouldHelp -ceq 'NO') 'handles NOT_OBSERVABLE (trava), nunca NOT_PRESENT nem COMPLETE'
            Assert-True (-not $r.CoverageComplete) 'cobertura do diagnose incompleta'
            Assert-Eq @($r.Findings | ForEach-Object { @($_.Evidence) } | Where-Object { $_.Collector -ceq 'handles' }).Count 0 'nenhuma evidencia de arquivos abertos anexada'
            # P4-B attaches the relevant coverage to partitions (why absence is not concluded): handles only as the closed gate.
            Assert-Eq @($r.Findings | ForEach-Object { @($_.Coverage) } | Where-Object { $_.Collector -ceq 'handles' -and ($_.Status -cne 'NOT_OBSERVABLE' -or (@($_.Reasons) -join ',') -cne 'HANDLE_SECURITY_GATE_CLOSED') }).Count 0 'cobertura handles nos achados so como a trava fechada (NOT_OBSERVABLE)'
        }
        # The spy sees the collector when the gate is open (the closed result above is the gate, not a missing spy).
        $script:AtmHandleDiagnosticsEnabled = $true
        $script:AtmHandleInvocationLog = New-Object System.Collections.Generic.List[object]
        try {
            $open = Invoke-AtmDiagnose @diagArgs -HandleQuery ({ param($Files, $Max) [pscustomobject]@{ Status = 'OK'; Holders = @() } })
            $openLog = $script:AtmHandleInvocationLog.ToArray()
        } finally { $script:AtmHandleInvocationLog = $null; $script:AtmHandleDiagnosticsEnabled = $false }
        Assert-True (@($openLog | Where-Object { $_.Op -eq 'LIST' }).Count -ge 1 -and @($openLog | Where-Object { $_.Op -eq 'QUERY' }).Count -ge 1) 'contraprova: com a trava aberta o espiao registra listagem e consulta'
        # I: no state changes because of missing evidence: the same states and evidence codes, closed or open with no holder.
        $sig = { param($R) @($R.Findings | Where-Object { $_.Kind -eq 'TempPartition' } | ForEach-Object { '{0}|{1}|{2}' -f $_.Key, $_.State, (@($_.Evidence | Where-Object { $_.Collector -cne 'handles' } | ForEach-Object { $_.Code + '/' + $_.Detail }) -join '+') }) -join "`n" }
        Assert-True ((& $sig $closedNative) -ceq (& $sig $open) -and @($open.Findings | Where-Object { $_.Kind -eq 'TempPartition' }).Count -ge 1) 'estados e evidencias das particoes iguais com a trava fechada e aberta sem processo'
        Assert-Eq @($open.Findings | ForEach-Object { @($_.Evidence) } | Where-Object { $_.Collector -ceq 'handles' }).Count 0 'sem processo: nada anexado (ausencia nao vira evidencia)'
        # H: JSON and report without paths or names; the report says "not observed", never a count of held items.
        $json = ConvertTo-AtmDiagnoseJson -Result $closedNative
        foreach ($x in @($marker, $root, $root.Replace('\', '\\'))) { Assert-True (-not $json.Contains($x)) "JSON sem caminho nem nome de arquivo: $(Split-Path -Leaf $x)" }
        Assert-True ($json.Contains('HANDLE_SECURITY_GATE_CLOSED')) 'JSON com o motivo da trava'
        # Messages joined as written (Out-String wraps long lines at the console width on PowerShell 5.1).
        $txt = (Show-AtmDiagnose -Result $closedNative 6>&1 | ForEach-Object { [string]$_ }) -join "`n"
        $lineHead = (Get-AtmText 'diag.hLine' 0 0).Split(':')[0]
        Assert-True ($txt.Contains((Get-AtmText 'diag.hGate')) -and -not $txt.Contains($lineHead) -and -not $txt.Contains((Get-AtmText 'diag.hSample')) -and -not $txt.Contains($marker) -and -not $txt.Contains($root)) 'relatorio: arquivos abertos nao observados (trava), sem contagem de itens livres, sem caminhos'
    }
    Test-Case 'Prototipo' 'ADR-0011 (estudo isolado, so codigo de teste): abertura relativa a raiz do volume com OBJ_DONT_REPARSE recusa reparse point em qualquer componente na propria abertura; caixa, 8.3, caminho longo, inexistente' {
        if (-not ('AgentTempManagerPrototype.AtmHandleRelativeOpen' -as [type])) { Add-Type -Path (Join-Path $testsDir 'prototypes\AtmHandleRelativeOpen.cs') }
        $T = [AgentTempManagerPrototype.AtmHandleRelativeOpen]
        $hex = { param([int]$v) '0x{0:X8}' -f $v }
        $d = Join-Path $sandbox 'proto-dr'
        foreach ($x in @('real\anc', 'evil\anc')) { [void][IO.Directory]::CreateDirectory((Join-Path $d $x)) }
        [IO.File]::WriteAllText((Join-Path $d 'real\anc\ref'), 'real'); [IO.File]::WriteAllText((Join-Path $d 'evil\anc\ref'), 'evil')
        $f = Join-Path $d 'real\anc\ref'
        Assert-Eq (& $hex $T::Open($f, $true)) '0x00000000' 'caminho limpo abre'
        Assert-Eq (& $hex $T::Open($f.ToUpperInvariant(), $true)) '0x00000000' 'diferenca de caixa: abre (OBJ_CASE_INSENSITIVE)'
        Assert-Eq (& $hex $T::Open((Join-Path $d 'real\anc\none'), $true)) '0xC0000034' 'inexistente: STATUS_OBJECT_NAME_NOT_FOUND'
        $short = [AgentTempManager.AtmNative]::GetShortPath($f)
        if ($short -and $short -ne $f) { Assert-Eq (& $hex $T::Open($short, $true)) '0x00000000' 'nome 8.3: abre' } else { $script:caseNote = 'nome 8.3 nao disponivel neste volume' }
        # Long path (> 260): created through the \\?\ prefix, opened by the prototype without it.
        $long = $d; while ($long.Length -lt 300) { $long = Join-Path $long ('l' * 40) }
        [void][IO.Directory]::CreateDirectory('\\?\' + $long); [IO.File]::WriteAllText('\\?\' + (Join-Path $long 'f'), 'x')
        Assert-Eq (& $hex $T::Open((Join-Path $long 'f'), $true)) '0x00000000' 'caminho longo: abre'
        # Ancestor replaced by a junction after the "check": refused at open; without the flag it is followed.
        [IO.Directory]::Move((Join-Path $d 'real\anc'), (Join-Path $d 'real\anc-old'))
        New-Junction -Link (Join-Path $d 'real\anc') -Target (Join-Path $d 'evil\anc')
        Assert-Eq (& $hex $T::Open($f, $false)) '0x00000000' 'contraprova: sem a flag a juncao ancestral e seguida'
        Assert-Eq (& $hex $T::Open($f, $true)) '0xC000050B' 'juncao em ancestral: STATUS_REPARSE_POINT_ENCOUNTERED'
        # Final component a junction (a directory link where a file was): refused too.
        New-Junction -Link (Join-Path $d 'real\last') -Target (Join-Path $d 'evil\anc')
        # A directory junction as the final component of a file open: refused (STATUS_FILE_IS_A_DIRECTORY comes first).
        Assert-True ((& $hex $T::Open((Join-Path $d 'real\last'), $true)) -in @('0xC000050B', '0xC00000BA')) "componente final juncao: recusado ($(& $hex $T::Open((Join-Path $d 'real\last'), $true)))"
        Assert-Eq $T::Open('\\atm-unc-probe.invalid\share\x', $true) -1 'caminho de rede: recusado antes de qualquer abertura'
        Assert-Eq $T::Open('relative\x', $true) -1 'caminho relativo: recusado'
    }
    # ------------------------------------------------------------------ P2-A (Windows services, ADR-0005)
    # Service rows and process rows are injected; no service is started, stopped or changed. Only the CI-runner case
    # queries the local service control manager (read-only) and compares states before and after.
    $svcT0 = [datetime]::UtcNow.AddMinutes(-30)
    $svcHints = { param([string]$Provider, [object[]]$Hints, [string]$Status = 'COMPLETE', [string[]]$Reasons = @())
        [pscustomobject]@{ ProviderId = $Provider; ProcessMatchers = @(); ServiceHints = @($Hints); VirtualizationHints = @(); Coverage = (New-AtmCoverage -Collector ('provider-' + $Provider) -Status $Status -Reasons $Reasons) } }
    $svcHint = { param([string]$Name, $Role = $null) [pscustomobject]@{ Name = $Name; Role = $Role } }
    $svcSys = "`"$env:SystemRoot\System32\svchost.exe`" -k test"
    # Adversarial profile path, built at run time so that no literal user path is in the repository.
    $svcUser = 'C:\' + 'Users\' + 'p2a-person'
    $svcRow = { param([string]$Name, $State = 'Running', $StartMode = 'Auto', $Delayed = $false, $StartName = 'LocalSystem', $ProcessId = 0, $PathName = $svcSys)
        [pscustomobject]@{ Name = $Name; State = $State; StartMode = $StartMode; DelayedAutoStart = $Delayed; StartName = $StartName; ProcessId = $ProcessId; PathName = $PathName } }
    $svcPRow = { param($ProcId, $Created) [pscustomobject]@{ ProcessId = $ProcId; ParentProcessId = 4; Name = 'svc.exe'; CreationDate = $Created } }
    $svcProcs = { param([object[]]$Rows) $pr = @($Rows); Get-AtmProcessCollection -Source ({ $pr }.GetNewClosure()) }
    $svcRun = { param($Hints, $Rows, $Collection, $Tq = $svcT0) $rr = @($Rows); $q = Invoke-AtmServiceQuery -ProviderHints @($Hints) -Source ({ param($Names) $rr }.GetNewClosure()) -NowUtc $Tq; Get-AtmServiceFindings -Query $q -Collection $Collection }
    # Always an array (one value is not unrolled into a string).
    $svcEv = { param($F, [string]$Code) return , @($F.Evidence | Where-Object { $_.Code -ceq $Code } | ForEach-Object { [string]$_.Detail }) }
    $svcByKey = { param($R) $m = @{}; foreach ($x in @($R.Findings)) { $m[$x.Key] = $x }; $m }
    $svcCov = { param($R, [string]$Collector) @($R.Coverage | Where-Object { $_.Collector -ceq $Collector })[0] }
    Test-Case 'Servicos' 'P2-A: servico declarado presente (em execucao, processo verificado), parado, nao listado (UNKNOWN); estados, tipo de inicio, inicio atrasado e tipos de conta' {
        $h = & $svcHints 'fake' @((& $svcHint 'FakeSvc' 'vm-host'), (& $svcHint 'GoneSvc'), (& $svcHint 'StopSvc'))
        $coll = & $svcProcs @((& $svcPRow 4 $svcT0.AddHours(-1)), (& $svcPRow 4321 $svcT0.AddMinutes(-10)))
        $r = & $svcRun $h @((& $svcRow 'FakeSvc' 'Running' 'Auto' $true 'NT SERVICE\FakeSvc' 4321), (& $svcRow 'StopSvc' 'Stopped' 'Manual' $false 'NT AUTHORITY\LocalService' 777)) $coll
        $f = & $svcByKey $r
        Assert-Eq (@($r.Findings | ForEach-Object { $_.Key }) -join ',') 'FakeSvc,GoneSvc,StopSvc' 'um achado por nome declarado, em ordem ordinal'
        Assert-True ($f['FakeSvc'].State -ceq 'RUNNING' -and $f['FakeSvc'].Provider -ceq 'fake' -and (& $svcEv $f['FakeSvc'] 'SERVICE_HINT')[0] -ceq 'fake:vm-host') 'presente, em execucao, com o provider e o papel declarados'
        Assert-Eq (& $svcEv $f['FakeSvc'] 'SERVICE_PROCESS_VERIFIED')[0] (ConvertTo-AtmProcessKey -ProcessId 4321 -CreationUtc $svcT0.AddMinutes(-10)) 'processo do servico verificado (criado antes da consulta, presente no snapshot posterior)'
        Assert-True ((& $svcEv $f['FakeSvc'] 'SERVICE_START_MODE')[0] -ceq 'AUTO' -and (& $svcEv $f['FakeSvc'] 'SERVICE_DELAYED_AUTO_START')[0] -ceq 'TRUE' -and (& $svcEv $f['FakeSvc'] 'SERVICE_ACCOUNT_KIND')[0] -ceq 'VIRTUAL' -and (& $svcEv $f['FakeSvc'] 'SERVICE_ACCOUNT').Count -eq 0 -and (& $svcEv $f['FakeSvc'] 'SERVICE_ACCOUNT_UNREADABLE').Count -eq 0) 'tipo de inicio, inicio atrasado; conta virtual so pelo tipo (ADR-0012), sem ser ilegivel'
        Assert-Eq (& $svcEv $f['FakeSvc'] 'SERVICE_EXECUTABLE')[0] "$env:SystemRoot\System32\svchost.exe" 'executavel com caminho completo (local conhecido), sem argumentos'
        Assert-True ($f['StopSvc'].State -ceq 'STOPPED' -and (& $svcEv $f['StopSvc'] 'SERVICE_PROCESS_VERIFIED').Count -eq 0 -and (& $svcEv $f['StopSvc'] 'SERVICE_PROCESS_UNVERIFIED')[0] -ceq 'SERVICE_NOT_RUNNING') 'parado: PID informado nunca vinculado'
        Assert-True ((& $svcEv $f['StopSvc'] 'SERVICE_START_MODE')[0] -ceq 'MANUAL' -and (& $svcEv $f['StopSvc'] 'SERVICE_DELAYED_AUTO_START')[0] -ceq 'FALSE' -and (& $svcEv $f['StopSvc'] 'SERVICE_ACCOUNT_KIND')[0] -ceq 'LOCAL_SERVICE' -and (& $svcEv $f['StopSvc'] 'SERVICE_ACCOUNT')[0] -ceq 'NT AUTHORITY\LocalService') 'manual, sem inicio atrasado, LocalService com identificador padrao'
        Assert-True ($f['GoneSvc'].State -ceq 'UNKNOWN' -and $f['GoneSvc'].RequestedState -ceq 'UNKNOWN' -and (& $svcEv $f['GoneSvc'] 'SERVICE_NOT_LISTED')[0] -ceq 'NOT_LISTED_FOR_ACCOUNT') 'nao listado: UNKNOWN (nem estado nem estado pedido NOT_PRESENT), observacao preservada'
        Assert-True ((& $svcCov $r 'services').Status -ceq 'PARTIAL' -and (& $svcCov $r 'services').Observed -eq 2 -and (& $svcCov $r 'services').Expected -eq 3 -and (& $svcCov $r 'service-properties').Status -ceq 'COMPLETE') 'coberturas: consulta PARTIAL (2 de 3 listados), propriedades dos listados completas'
        Assert-True (@((& $svcCov $r 'services').Reasons) -ccontains 'SERVICE_NOT_LISTED_FOR_ACCOUNT' -and (& $svcCov $r 'services').ElevationWouldHelp -ceq 'UNKNOWN') 'nome nao listado: declarado como nao listado para esta conta (outra conta poderia ver)'
        $all = & $svcRun (& $svcHints 'fake' @((& $svcHint 'FakeSvc'))) @((& $svcRow 'FakeSvc' 'Running' 'Auto' $true 'NT SERVICE\FakeSvc' 4321)) $coll
        Assert-True ((& $svcCov $all 'services').ElevationWouldHelp -ceq 'NO' -and @((& $svcCov $all 'services').Reasons).Count -eq 0) 'todos listados: sem motivo'
        # Every state and start mode the source can report; anything else is unreadable, never guessed.
        $names = @('S1', 'S2', 'S3', 'S4', 'S5', 'S6', 'S7')
        $h2 = & $svcHints 'fake' @($names | ForEach-Object { & $svcHint $_ })
        $rows2 = @((& $svcRow 'S1' 'Paused' 'Boot'), (& $svcRow 'S2' 'Start Pending' 'System'), (& $svcRow 'S3' 'Stop Pending' 'Disabled'), (& $svcRow 'S4' 'Continue Pending' 'Manual'), (& $svcRow 'S5' 'Pause Pending' 'Auto'), (& $svcRow 'S6' 'Unknown' 'Unknown'), (& $svcRow 'S7' 'running' 'auto'))
        $f2 = & $svcByKey (& $svcRun $h2 $rows2 $coll)
        Assert-Eq (@($names | ForEach-Object { $f2[$_].State }) -join ',') 'PAUSED,PENDING,PENDING,PENDING,PENDING,UNKNOWN,UNKNOWN' 'estados: pausado, pendentes; desconhecido e grafia inesperada ilegiveis'
        Assert-Eq (@($names | ForEach-Object { ((& $svcEv $f2[$_] 'SERVICE_START_MODE') + @('-'))[0] }) -join ',') 'BOOT,SYSTEM,DISABLED,MANUAL,AUTO,-,-' 'tipos de inicio; valor desconhecido ilegivel'
        # Accounts (ADR-0012): a standard identifier only for the three built-in service accounts; the kind for the rest.
        $upn = 'p2a-acct' + '@' + 'corp.example'
        foreach ($cs in @(@('LocalSystem', 'LOCAL_SYSTEM', 'LocalSystem'), @('NT AUTHORITY\SYSTEM', 'LOCAL_SYSTEM', 'LocalSystem'), @('localsystem', 'LOCAL_SYSTEM', 'LocalSystem'), @('NT AUTHORITY\LocalService', 'LOCAL_SERVICE', 'NT AUTHORITY\LocalService'), @('NT AUTHORITY\LOCAL SERVICE', 'LOCAL_SERVICE', 'NT AUTHORITY\LocalService'), @('NT AUTHORITY\NetworkService', 'NETWORK_SERVICE', 'NT AUTHORITY\NetworkService'),
                @('NT SERVICE\Agent', 'VIRTUAL', $null), @('NT AUTHORITY\Other', 'BUILTIN', $null), @('CORPDOM\svc-gmsa$', 'MANAGED', $null), @('.\p2a-acct', 'USER', $null), @('CORPDOM\p2a-acct', 'USER', $null), @($upn, 'USER', $null))) {
            $a = ConvertTo-AtmServiceAccount $cs[0]
            Assert-True ($a.Kind -ceq $cs[1] -and $a.Account -ceq $cs[2]) "conta '$($cs[1])': $($a.Kind) $($a.Account)"
        }
        Assert-True ($null -eq (ConvertTo-AtmServiceAccount $null) -and $null -eq (ConvertTo-AtmServiceAccount '') -and $null -eq (ConvertTo-AtmServiceAccount '   ') -and $null -eq (ConvertTo-AtmServiceAccount 5) -and $null -eq (ConvertTo-AtmServiceAccount ('a' * 300)) -and $null -eq (ConvertTo-AtmServiceAccount "a`tb")) 'conta ausente, vazia, longa, com controle ou de outro tipo: ilegivel'
        foreach ($m in @('\', '@', 'CORPDOM\', '\p2a-acct', 'CORPDOM\\p2a-acct', 'a@b@c', 'a\b\c', "p2a$([char]0x202E)acct")) { Assert-True ($null -eq (ConvertTo-AtmServiceAccount $m)) "conta malformada: ilegivel ($($m.Length) caracteres)" }
    }
    Test-Case 'Servicos' 'P2-A: propriedade ausente ou ilegivel vira null com service-properties PARTIAL (nunca 0 ou false); a consulta nao herda esses motivos' {
        $h = & $svcHints 'fake' @((& $svcHint 'OddSvc'), (& $svcHint 'GoneSvc'))
        $odd = [pscustomobject]@{ Name = 'OddSvc'; State = 'Running'; StartMode = $null; DelayedAutoStart = 'False'; StartName = $null; ProcessId = $null; PathName = $null }
        $r = & $svcRun $h @($odd) (& $svcProcs @((& $svcPRow 4 $svcT0.AddHours(-1))))
        $f = & $svcByKey $r
        foreach ($c in @('SERVICE_START_MODE_UNREADABLE', 'SERVICE_DELAYED_AUTO_START_UNREADABLE', 'SERVICE_ACCOUNT_UNREADABLE', 'SERVICE_EXECUTABLE_UNREADABLE')) { Assert-Eq (& $svcEv $f['OddSvc'] $c).Count 1 "$c" }
        Assert-True ((& $svcEv $f['OddSvc'] 'SERVICE_DELAYED_AUTO_START').Count -eq 0 -and (& $svcEv $f['OddSvc'] 'SERVICE_START_MODE').Count -eq 0) 'nenhum valor inventado (texto "False" nao vira false)'
        Assert-True ($f['OddSvc'].State -ceq 'RUNNING' -and (& $svcEv $f['OddSvc'] 'SERVICE_PROCESS_UNVERIFIED')[0] -ceq 'PID_NOT_REPORTED') 'em execucao sem PID: processo nao verificado'
        $pc = & $svcCov $r 'service-properties'
        Assert-True ($pc.Status -ceq 'PARTIAL' -and @($pc.Reasons) -ccontains 'SERVICE_PROPERTY_UNREADABLE' -and @($pc.Reasons) -ccontains 'SERVICE_PROCESS_UNVERIFIED' -and $pc.Observed -eq 0 -and $pc.Expected -eq 1) 'service-properties PARTIAL'
        Assert-True (@((& $svcCov $r 'services').Reasons) -cnotcontains 'SERVICE_PROPERTY_UNREADABLE' -and $f['GoneSvc'].State -ceq 'UNKNOWN') 'motivos de propriedades so em service-properties; nome nao listado UNKNOWN'
        $x = ConvertFrom-AtmServicePathName 12
        Assert-True ($null -eq $x.Path -and $null -eq $x.Name -and $x.Reason -ceq 'EXECUTABLE_UNREADABLE') 'PathName de outro tipo: ilegivel'
    }
    Test-Case 'Servicos' 'P2-A: consulta negada, com falha, tempo esgotado e prazo; nunca NOT_PRESENT; somente o tipo da excecao' {
        $h = & $svcHints 'fake' @((& $svcHint 'FakeSvc'), (& $svcHint 'GoneSvc'))
        $sx = 'S3cr3t-P2A-exc'
        $cases = [ordered]@{
            'negada (tipo)'    = @({ param($Names) throw (New-Object UnauthorizedAccessException("$svcUser --password=$sx")) }, 'DENIED', 'SERVICE_QUERY_DENIED')
            'negada (HRESULT)' = @({ param($Names) throw (New-Object Runtime.InteropServices.COMException("--token=$sx", -2147024891)) }, 'DENIED', 'SERVICE_QUERY_DENIED')
            'negada (WMI)'     = @({ param($Names) throw (New-Object Runtime.InteropServices.COMException("--token=$sx", -2147217405)) }, 'DENIED', 'SERVICE_QUERY_DENIED')
            'falha'            = @({ param($Names) throw (New-Object IO.IOException("$svcUser $sx")) }, 'FAILED', 'SERVICE_QUERY_FAILED')
        }
        foreach ($n in $cases.Keys) {
            $src = $cases[$n][0]
            $q = Invoke-AtmServiceQuery -ProviderHints @($h) -Source $src
            $r = Get-AtmServiceFindings -Query $q
            Assert-True ($q.Coverage.Status -ceq $cases[$n][1] -and @($q.Coverage.Reasons) -ccontains $cases[$n][2] -and @($q.Coverage.Reasons | Where-Object { $_ -like 'EXCEPTION_*' }).Count -eq 1) "$n`: $($q.Coverage.Status) $(@($q.Coverage.Reasons) -join ',')"
            Assert-True (@($r.Findings | Where-Object { $_.State -cne 'UNKNOWN' }).Count -eq 0 -and @($r.Findings | Where-Object { (& $svcEv $_ 'SERVICE_NOT_QUERIED').Count -ne 1 }).Count -eq 0) "$n`: todos UNKNOWN, nunca NOT_PRESENT"
            Assert-True ((& $svcCov $r 'service-properties').Status -ceq 'NOT_OBSERVABLE') "$n`: propriedades nao observadas"
            Assert-True (-not ((ConvertTo-Json -InputObject @($r.Coverage + @($r.Findings)) -Depth 6) -match 'S3cr3t|p2a-person|token')) "$n`: mensagem da excecao nunca guardada"
        }
        $q = Invoke-AtmServiceQuery -ProviderHints @($h) -TimeoutSec 1 -Source { param($Names) Start-Sleep -Milliseconds 1100; throw (New-Object TimeoutException('x')) }
        Assert-True ($q.Coverage.Status -ceq 'TIMEOUT' -and @($q.Coverage.Reasons) -ccontains 'SERVICE_QUERY_TIMEOUT' -and $q.Coverage.BudgetMs -eq 1000) 'falha depois do orcamento: TIMEOUT'
        $calls = @{ N = 0 }
        $q = Invoke-AtmServiceQuery -ProviderHints @($h) -Deadline ([datetime]::UtcNow.AddSeconds(-1)) -Source ({ param($Names) $calls.N++; @() }.GetNewClosure())
        $r = Get-AtmServiceFindings -Query $q
        Assert-True ($calls.N -eq 0 -and $q.Coverage.Status -ceq 'TIMEOUT' -and @($q.Coverage.Reasons) -ccontains 'DEADLINE_EXCEEDED' -and @($r.Findings | Where-Object { $_.State -cne 'UNKNOWN' }).Count -eq 0) 'prazo: nada consultado, nada ausente'
        Assert-Eq (Invoke-AtmServiceQuery -ProviderHints @() -Deadline ([datetime]::UtcNow.AddSeconds(-1))).Coverage.Status 'TIMEOUT' 'prazo antes das dicas: TIMEOUT, nunca "nenhum servico declarado"'
        $ni = Invoke-AtmServiceQuery -ProviderHints @() -HintsIncomplete
        Assert-True ($ni.Coverage.Status -ceq 'NOT_OBSERVABLE' -and @($ni.Coverage.Reasons) -ccontains 'SERVICE_HINTS_INCOMPLETE') 'provider nao lido: dicas incompletas declaradas'
        $txt = (Show-AtmDiagnoseServices -Result ([pscustomobject]@{ Coverage = @($ni.Coverage, (New-AtmCoverage -Collector 'service-properties' -Status 'NOT_OBSERVABLE' -Reasons @('SERVICE_HINTS_NONE'))); Findings = @() }) 6>&1 | ForEach-Object { [string]$_ }) -join "`n"
        Assert-True (-not $txt.Contains((Get-AtmText 'diag.svcNone'))) 'relatorio: com dicas incompletas nunca diz que nenhum provider declara servico'
    }
    Test-Case 'Servicos' 'P2-A-S: ausencia nunca concluida - inexistente, oculto por permissao (simulado), consulta vazia, um observado e um omitido, negada, parcial, nome semelhante, dicas incompletas; COMPLETE nunca com motivo; nenhum NOT_PRESENT' {
        # A simulated machine: Visible and Hidden exist; the source lists only what the account may query (as
        # EnumServicesStatusEx does). Missing does not exist. Hidden and Missing must give the same output.
        $machine = @{ 'VisibleSvc' = $true; 'HiddenSvc' = $false }
        $aclSource = ({ param($Names) foreach ($n in $Names) { if ($machine.ContainsKey($n) -and $machine[$n]) { [pscustomobject]@{ Name = $n; State = 'Stopped'; StartMode = 'Auto'; DelayedAutoStart = $false; StartName = 'LocalSystem'; ProcessId = 0; PathName = 'svc.exe' } } } }.GetNewClosure())
        $h = & $svcHints 'fake' @((& $svcHint 'VisibleSvc'), (& $svcHint 'HiddenSvc'), (& $svcHint 'MissingSvc'))
        $q = Invoke-AtmServiceQuery -ProviderHints @($h) -Source $aclSource
        $r = Get-AtmServiceFindings -Query $q
        $f = & $svcByKey $r
        $sig = { param($F) (@($F.Evidence | Where-Object { $_.Code -cne 'SERVICE_HINT' } | ForEach-Object { $_.Code + '=' + $_.Detail }) -join ';') + '|' + $F.State + '|' + $F.RequestedState }
        Assert-True ($f['VisibleSvc'].State -ceq 'STOPPED' -and $f['HiddenSvc'].State -ceq 'UNKNOWN' -and $f['MissingSvc'].State -ceq 'UNKNOWN') 'observado mantido; oculto e inexistente UNKNOWN'
        Assert-Eq (& $sig $f['HiddenSvc']) (& $sig $f['MissingSvc']) 'oculto por permissao e inexistente sao indistinguiveis: mesma saida, nenhuma prova de ausencia'
        Assert-True ($q.Coverage.Status -ceq 'PARTIAL' -and @($q.Coverage.Reasons) -ccontains 'SERVICE_NOT_LISTED_FOR_ACCOUNT' -and $q.Coverage.ElevationWouldHelp -ceq 'UNKNOWN' -and (& $svcCov $r 'service-properties').Status -ceq 'COMPLETE') 'consulta PARTIAL; propriedades do observado completas'
        $results = New-Object System.Collections.Generic.List[object]
        $results.Add($r)
        $results.Add((& $svcRun $h @() $null))
        $results.Add((Get-AtmServiceFindings -Query (Invoke-AtmServiceQuery -ProviderHints @($h) -Source { param($Names) throw (New-Object UnauthorizedAccessException('x')) })))
        $results.Add((& $svcRun $h @((& $svcRow 'VisibleSvc'), (& $svcRow 'OtherSvc')) $null))
        $results.Add((& $svcRun $h @((& $svcRow 'VisibleSvc2')) $null))
        $results.Add((& $svcRun @((& $svcHints 'broken' @() 'FAILED' @('HINT_FAILED_SERVICE_HINTS')), $h) @() $null))
        $q2 = Invoke-AtmServiceQuery -ProviderHints @($h) -HintsIncomplete -Source $aclSource
        $results.Add((Get-AtmServiceFindings -Query $q2))
        foreach ($x in $results) {
            Assert-Eq @($x.Findings | Where-Object { $_.State -ceq 'NOT_PRESENT' -or $_.RequestedState -ceq 'NOT_PRESENT' }).Count 0 'nenhum NOT_PRESENT, nem pedido'
            Assert-Eq @($x.Coverage | Where-Object { ($_.Status -ceq 'COMPLETE' -or $_.Status -ceq 'NOT_PRESENT') -and @($_.Reasons).Count -gt 0 }).Count 0 'nenhuma cobertura conclusiva com motivo'
            Assert-True (@($x.Findings | Where-Object { $_.Key -ceq 'MissingSvc' -and $_.State -cne 'UNKNOWN' }).Count -eq 0) 'nome nao observado sempre UNKNOWN'
        }
        Assert-True ($q2.Coverage.Status -ceq 'PARTIAL' -and @($q2.Coverage.Reasons) -ccontains 'SERVICE_HINTS_INCOMPLETE') 'dicas incompletas: PARTIAL'
        foreach ($st in @('COMPLETE', 'NOT_PRESENT')) {
            $threw = $false; try { $null = New-AtmCoverage -Collector 'services' -Status $st -Reasons @('SERVICE_NOT_LISTED_FOR_ACCOUNT') } catch { $threw = $true }
            Assert-True $threw "cobertura $st com motivo recusada pelo modelo"
        }
        Assert-Eq (New-AtmCoverage -Collector 'services' -Status 'COMPLETE').Status 'COMPLETE' 'COMPLETE sem motivo aceito'
    }
    Test-Case 'Servicos' 'P2-A: vinculo de PID so com identidade verificada no snapshot posterior; PID inexistente, reutilizado, duplicado, sem horario, snapshot indisponivel ou anterior a consulta ficam UNVERIFIED' {
        $tq = $svcT0
        $c = & $svcProcs @((& $svcPRow 4 $tq.AddHours(-1)), (& $svcPRow 100 $tq.AddMinutes(-1)), (& $svcPRow 200 $tq.AddMinutes(1)), (& $svcPRow 300 $tq.AddTicks(-5)), (& $svcPRow 400 $null), (& $svcPRow 500 $tq.AddHours(-2)), (& $svcPRow 500 $tq.AddHours(-3)))
        $cases = @(@(100, 'MATCH'), @(200, 'CREATED_AFTER_QUERY'), @(300, 'CREATED_AFTER_QUERY'), @(400, 'CREATION_TIME_UNKNOWN'), @(500, 'DUPLICATE_PID'), @(999, 'PROCESS_NOT_COLLECTED'), @(0, 'PID_NOT_REPORTED'), @($null, 'PID_NOT_REPORTED'), @('abc', 'PID_NOT_REPORTED'))
        foreach ($cs in $cases) { Assert-Eq (Resolve-AtmServiceProcess -Collection $c -ProcessId $cs[0] -QueryUtc $tq).Result $cs[1] "PID '$($cs[0])'" }
        $failed = Get-AtmProcessCollection -Source { throw (New-Object IO.IOException('x')) }
        Assert-Eq (Resolve-AtmServiceProcess -Collection $failed -ProcessId 100 -QueryUtc $tq).Result 'PROCESS_SNAPSHOT_UNAVAILABLE' 'snapshot com falha'
        Assert-Eq (Resolve-AtmServiceProcess -Collection $null -ProcessId 100 -QueryUtc $tq).Result 'PROCESS_SNAPSHOT_UNAVAILABLE' 'sem snapshot (runtime nao executado)'
        Assert-Eq (Resolve-AtmServiceProcess -Collection $c -ProcessId 100 -QueryUtc ([datetime]::UtcNow.AddHours(1))).Result 'SNAPSHOT_BEFORE_QUERY' 'snapshot anterior a consulta: nada provado'
        Assert-Eq (Resolve-AtmServiceProcess -Collection $c -ProcessId 100 -QueryUtc $tq -QueryEndUtc ([datetime]::UtcNow.AddHours(1))).Result 'SNAPSHOT_BEFORE_QUERY' 'snapshot iniciado antes do fim da consulta: nada provado'
        # In findings: an unverified link keeps the reported state and makes service-properties PARTIAL.
        $h = & $svcHints 'fake' @((& $svcHint 'ReusedSvc'))
        $r = & $svcRun $h @((& $svcRow 'ReusedSvc' 'Running' 'Auto' $false 'LocalSystem' 200)) $c
        $f = & $svcByKey $r
        Assert-True ($f['ReusedSvc'].State -ceq 'RUNNING' -and (& $svcEv $f['ReusedSvc'] 'SERVICE_PROCESS_UNVERIFIED')[0] -ceq 'CREATED_AFTER_QUERY' -and (& $svcEv $f['ReusedSvc'] 'SERVICE_PROCESS_VERIFIED').Count -eq 0) 'PID reutilizado: nunca vinculado'
        Assert-True ((& $svcCov $r 'service-properties').Status -ceq 'PARTIAL' -and @((& $svcCov $r 'service-properties').Reasons) -ccontains 'SERVICE_PROCESS_UNVERIFIED') 'vinculo nao verificado declarado'
    }
    Test-Case 'Servicos' 'FINAL-A-S: ordem entre o fim da consulta e o inicio do snapshot no relogio monotonico; relogio UTC grosso nao recusa um vinculo provado; snapshot anterior continua recusado; precisao de 1 us' {
        $tq = $svcT0
        $c = & $svcProcs @((& $svcPRow 4 $tq.AddHours(-1)), (& $svcPRow 100 $tq.AddMinutes(-1)), (& $svcPRow 600 $tq.AddTicks(-10)))
        Assert-True ($null -ne $c.StartedTimestamp -and $c.StartedTimestamp -is [long]) 'snapshot leva o instante monotonico do seu inicio'
        # Coarse UtcNow (Windows PowerShell 5.1): the snapshot's UTC start reads the same tick as the query start, while
        # the query end (start + Stopwatch elapsed) is later. Monotonic order: the snapshot started after the query ended.
        $coarseStart = [datetime]$c.CollectedUtc
        $coarseEnd = $coarseStart.AddMilliseconds(3)
        $before = [long]$c.StartedTimestamp - 1
        Assert-Eq (Resolve-AtmServiceProcess -Collection $c -ProcessId 100 -QueryUtc $coarseStart -QueryEndUtc $coarseEnd).Result 'SNAPSHOT_BEFORE_QUERY' 'ordem UTC mista (regra antiga): recusa falsa reproduzida'
        Assert-Eq (Resolve-AtmServiceProcess -Collection $c -ProcessId 100 -QueryUtc $coarseStart -QueryEndUtc $coarseEnd -QueryEndTimestamp $before).Result 'MATCH' 'ordem monotonica: vinculo provado aceito com relogio UTC grosso'
        Assert-Eq (Resolve-AtmServiceProcess -Collection $c -ProcessId 100 -QueryUtc $coarseStart -QueryEndUtc $coarseEnd -QueryEndTimestamp ([long]$c.StartedTimestamp)).Result 'MATCH' 'mesmo instante monotonico: aceito (o snapshot vem depois no programa)'
        # A UTC clock stepped forward never hides a snapshot taken before the query ended.
        Assert-Eq (Resolve-AtmServiceProcess -Collection $c -ProcessId 100 -QueryUtc $tq -QueryEndUtc $tq -QueryEndTimestamp ([long]$c.StartedTimestamp + 1)).Result 'SNAPSHOT_BEFORE_QUERY' 'snapshot iniciado antes do fim da consulta (monotonico), mesmo com UTC posterior'
        # Without a monotonic reading on either side the UTC order still applies (injected times, collections built by hand).
        $hand = [pscustomobject]@{ Failed = $false; CollectedUtc = $tq.AddMinutes(-5); ByPid = $c.ByPid; Duplicates = @{} }
        Assert-Eq (Resolve-AtmServiceProcess -Collection $hand -ProcessId 100 -QueryUtc $tq -QueryEndTimestamp $before).Result 'SNAPSHOT_BEFORE_QUERY' 'snapshot sem instante monotonico: ordem UTC'
        Assert-Eq (Resolve-AtmServiceProcess -Collection $c -ProcessId 100 -QueryUtc $tq -QueryEndUtc ([datetime]::UtcNow.AddHours(1))).Result 'SNAPSHOT_BEFORE_QUERY' 'consulta sem instante monotonico: ordem UTC'
        $q0 = Invoke-AtmServiceQuery -ProviderHints @((& $svcHints 'fake' @((& $svcHint 'ClockSvc')))) -Source { param($Names) @() } -NowUtc $tq
        Assert-True ($null -eq $q0.QueryEndTimestamp) 'tempo injetado: nenhum instante monotonico (os testes de ordem UTC seguem validos)'
        # Creation time: still compared with the UTC start (1 us resolution); a coarse start only refuses more.
        Assert-Eq (Resolve-AtmServiceProcess -Collection $c -ProcessId 600 -QueryUtc $tq -QueryEndTimestamp $before).Result 'MATCH' 'criado 1 us antes do inicio: aceito'
        Assert-Eq (Resolve-AtmServiceProcess -Collection $c -ProcessId 600 -QueryUtc $tq.AddTicks(-1) -QueryEndTimestamp $before).Result 'CREATED_AFTER_QUERY' 'criado a menos de 1 us do inicio: recusado'
        Assert-Eq (Resolve-AtmServiceProcess -Collection $c -ProcessId 100 -QueryUtc $tq.AddMinutes(-2) -QueryEndTimestamp $before).Result 'CREATED_AFTER_QUERY' 'criado depois do inicio, ordem monotonica correta: recusado'
        # The real sequence (query, then snapshot; injected rows, real clocks): every link proved by the monotonic order.
        # Recorded, never asserted: how many the old UTC order would have refused on this machine and shell.
        $rows = @((& $svcRow 'ClockSvc' 'Running' 'Auto' $false 'LocalSystem' 100))
        $prs = @((& $svcPRow 4 $tq.AddHours(-1)), (& $svcPRow 100 $tq.AddMinutes(-1)))
        $old = 0; $new = @{}
        for ($i = 0; $i -lt 100; $i++) {
            $q = Invoke-AtmServiceQuery -ProviderHints @((& $svcHints 'fake' @((& $svcHint 'ClockSvc')))) -Source ({ param($Names) $rows }.GetNewClosure())
            $cc = & $svcProcs $prs
            $n = (Resolve-AtmServiceProcess -Collection $cc -ProcessId 100 -QueryUtc $q.QueryUtc -QueryEndUtc $q.QueryEndUtc -QueryEndTimestamp $q.QueryEndTimestamp).Result
            $new[$n] = 1 + $(if ($new.ContainsKey($n)) { $new[$n] } else { 0 })
            if ((Resolve-AtmServiceProcess -Collection $cc -ProcessId 100 -QueryUtc $q.QueryUtc -QueryEndUtc $q.QueryEndUtc).Result -cne 'MATCH') { $old++ }
        }
        Assert-Eq (@($new.Keys) -join ',') 'MATCH' "sequencia real: todo vinculo provado ($(@($new.Keys | ForEach-Object { $_ + '=' + $new[$_] }) -join ','))"
        $g = New-Object System.Collections.Generic.List[long]; $a = [datetime]::UtcNow.Ticks; $sw = [Diagnostics.Stopwatch]::StartNew()
        while ($g.Count -lt 20 -and $sw.ElapsedMilliseconds -lt 2000) { $b = [datetime]::UtcNow.Ticks; if ($b -ne $a) { $g.Add($b - $a); $a = $b } }
        $gran = $(if ($g.Count -gt 0) { [math]::Round((($g | Measure-Object -Average).Average) / 10) } else { 'n/d' })
        $script:caseNote = "UtcNow: passo medio $gran us; ordem UTC antiga recusaria $old/100; ordem monotonica 0/100"
    }
    Test-Case 'Servicos' 'P2-A: dois providers com o mesmo servico, nenhum servico declarado, dicas incompletas, nomes semelhantes, limite de nomes, nome com aspas recusado' {
        $a = & $svcHints 'prov-a' @((& $svcHint 'SharedSvc'))
        $b = & $svcHints 'prov-b' @((& $svcHint 'sharedsvc' 'vm-host'))
        $r = & $svcRun @($a, $b) @((& $svcRow 'SharedSvc' 'Stopped' 'Manual')) $null
        Assert-True (@($r.Findings).Count -eq 1 -and $null -eq $r.Findings[0].Provider -and (& $svcEv $r.Findings[0] 'PROVIDER_ATTRIBUTION_AMBIGUOUS')[0] -ceq 'prov-a,prov-b' -and (& $svcEv $r.Findings[0] 'SERVICE_HINT').Count -eq 2) 'mesmo servico em dois providers: um achado, atribuicao ambigua, nunca escolhida'
        $calls = @{ N = 0 }
        $q = Invoke-AtmServiceQuery -ProviderHints @((& $svcHints 'none' @())) -Source ({ param($Names) $calls.N++; @() }.GetNewClosure())
        $r = Get-AtmServiceFindings -Query $q
        Assert-True ($calls.N -eq 0 -and $q.Coverage.Status -ceq 'NOT_OBSERVABLE' -and @($q.Coverage.Reasons) -ccontains 'SERVICE_HINTS_NONE' -and @($r.Findings).Count -eq 0 -and (& $svcCov $r 'service-properties').Status -ceq 'NOT_OBSERVABLE') 'nenhum servico declarado: nada consultado, NOT_OBSERVABLE, nunca "sem servicos"'
        $bad = & $svcHints 'broken' @() 'FAILED' @('HINT_FAILED_SERVICE_HINTS', 'EXCEPTION_IOEXCEPTION')
        $r = & $svcRun @($bad, (& $svcHints 'ok' @((& $svcHint 'GoneSvc')))) @() $null
        Assert-True ((& $svcCov $r 'services').Status -ceq 'PARTIAL' -and @((& $svcCov $r 'services').Reasons) -ccontains 'SERVICE_HINTS_INCOMPLETE' -and $r.Findings[0].State -ceq 'UNKNOWN') 'dicas de um provider ilegiveis: ausencia nunca confirmada'
        # Similar names are never linked: a returned name that was not asked for leaves the query incomplete.
        $h = & $svcHints 'fake' @((& $svcHint 'FakeAgentService'))
        $r = & $svcRun $h @((& $svcRow 'FakeAgentService2'), (& $svcRow 'FakeAgent Service')) $null
        Assert-True (@($r.Findings).Count -eq 1 -and $r.Findings[0].Key -ceq 'FakeAgentService' -and $r.Findings[0].State -ceq 'UNKNOWN' -and @((& $svcCov $r 'services').Reasons) -ccontains 'SERVICE_UNEXPECTED_ROW' -and (& $svcEv $r.Findings[0] 'SERVICE_STATE').Count -eq 0) 'nomes semelhantes: nunca associados; ausencia nao confirmada'
        $r = & $svcRun $h @() $null
        Assert-True ($r.Findings[0].State -ceq 'UNKNOWN' -and (& $svcCov $r 'services').Status -ceq 'PARTIAL' -and @((& $svcCov $r 'services').Reasons) -ccontains 'SERVICE_NOT_LISTED_FOR_ACCOUNT') 'sem linha para o nome exato: UNKNOWN, consulta PARTIAL'
        $r = & $svcRun $h @((& $svcRow 'FakeAgentService'), (& $svcRow 'fakeagentservice')) $null
        Assert-True ($r.Findings[0].State -ceq 'UNKNOWN' -and @((& $svcCov $r 'services').Reasons) -ccontains 'SERVICE_DUPLICATE_ROW') 'mesmo nome duas vezes: estado nao confiavel'
        $asked = @{ Names = $null }
        $q = Invoke-AtmServiceQuery -ProviderHints @((& $svcHints 'fake' @((& $svcHint 'A1'), (& $svcHint 'B2')))) -MaxNames 1 -Source ({ param($Names) $asked.Names = @($Names); @() }.GetNewClosure())
        $r = Get-AtmServiceFindings -Query $q
        $f = & $svcByKey $r
        Assert-True ((@($asked.Names) -join ',') -ceq 'A1' -and $q.Coverage.Status -ceq 'PARTIAL' -and @($q.Coverage.Reasons) -ccontains 'SERVICE_HINTS_CAPPED' -and $f['B2'].State -ceq 'UNKNOWN' -and (& $svcEv $f['B2'] 'SERVICE_NOT_QUERIED')[0] -ceq 'SERVICE_HINTS_CAPPED' -and $f['A1'].State -ceq 'UNKNOWN') 'limite de nomes: o resto nao e consultado; nenhuma ausencia confirmada com consulta parcial'
        $quote = [pscustomobject]@{ Id = 'fake-quote'; DisplayName = 'F'; ContractVersion = 2; Capabilities = @('runtime'); GetServiceHints = { @([pscustomobject]@{ Name = "a' OR Name='b" }) } }
        $qh = Get-AtmProviderRuntimeHints $quote
        Assert-True ($qh.Coverage.Status -ceq 'FAILED' -and @($qh.ServiceHints).Count -eq 0) 'nome com aspas recusado no contrato'
        $threw = $false; try { $null = Get-AtmServiceRaw -Names @("a' OR Name='b") -TimeoutSec 1 } catch { $threw = $true }
        Assert-True $threw 'nome com aspas recusado antes de montar o filtro'
    }
    Test-Case 'Servicos' 'P2-A: PathName com credenciais e argumentos sensiveis nunca aparece em evidencias, coberturas, JSON, relatorio ou erros; caminho completo so em local conhecido' {
        $pf = $env:ProgramFiles
        $cases = @(
            @("`"$svcUser\AppData\Local\agent\svc.exe`" --password=S3cr3t-P2A", $null, 'svc.exe', $null),
            @("$pf\Agent\svc.exe --token=tok-P2A-123 -k `"$svcUser\x`"", $null, $null, 'EXECUTABLE_UNPARSEABLE'),
            @("$svcUser\run.cmd /pw S3cr3t-P2A", $null, $null, 'EXECUTABLE_UNPARSEABLE'),
            @("`"$pf\..\Users\p2a-person\svc.exe`" -p S3cr3t-P2A", $null, 'svc.exe', $null),
            @("\??\$svcUser\drv.exe S3cr3t-P2A", $null, 'drv.exe', $null),
            @('%SystemRoot%\System32\svchost.exe -k tok-P2A-123', "$env:SystemRoot\System32\svchost.exe", 'svchost.exe', $null),
            @('%APPDATA%\agent\svc.exe tok-P2A-123', $null, $null, 'EXECUTABLE_UNPARSEABLE'),
            @('"unterminated --password=S3cr3t-P2A', $null, $null, 'EXECUTABLE_UNPARSEABLE'),
            @('svc.exe --password=S3cr3t-P2A', $null, 'svc.exe', $null),
            # Review P2-A: later ".exe" arguments, a whole command line inside the quotes, switches with '/', relative
            # segments with spaces or dots.
            @("$pf\App\run.cmd --password=hunter2 --log=out.exe", $null, $null, 'EXECUTABLE_UNPARSEABLE'),
            @("`"$pf\App\svc.exe --password=S3cr3t-P2A run.exe`"", $null, $null, 'EXECUTABLE_UNPARSEABLE'),
            @('C:\tools\launch.bat /pw S3cr3t-P2A other.exe', $null, $null, 'EXECUTABLE_UNPARSEABLE'),
            @('C:\tools\launch.bat pw S3cr3t-P2A other.exe', $null, $null, 'EXECUTABLE_UNPARSEABLE'),
            @("`"$env:SystemRoot\ ..\Users\x\x.exe`" -a", $null, 'x.exe', $null),
            @("$env:SystemRoot\...\Users\x\x.exe -a", $null, 'x.exe', $null),
            @("$env:SystemRoot\System32\..\..\Users\x\x.exe", $null, 'x.exe', $null),
            @('C:\tools\a:b.exe', $null, $null, 'EXECUTABLE_UNPARSEABLE'),
            # P2-A-S: quoted paths with spaces are read as text; network and device forms, unknown variables, relative
            # and malformed names; a misquoted line with two ".exe".
            @("`"$pf\Agent Dir\svc.exe`" --token=tok-P2A-123", "$pf\Agent Dir\svc.exe", 'svc.exe', $null),
            @("`"$svcUser\My Agent\svc.exe`" -x", $null, 'svc.exe', $null),
            @("`"$pf\App\svc.exe S3cr3t-P2A run.exe`"", $null, $null, 'EXECUTABLE_UNPARSEABLE'),
            @("$env:SystemRoot\System32\svchost.exe -k netsvcs", "$env:SystemRoot\System32\svchost.exe", 'svchost.exe', $null),
            @('\\atm-unc-probe.invalid\share\svc.exe -x', $null, $null, 'EXECUTABLE_UNPARSEABLE'),
            @('"\\atm-unc-probe.invalid\share\svc.exe"', $null, $null, 'EXECUTABLE_UNPARSEABLE'),
            @('\\.\pipe\svc.exe', $null, $null, 'EXECUTABLE_UNPARSEABLE'),
            @('\\?\C:\Windows\svc.exe', $null, $null, 'EXECUTABLE_UNPARSEABLE'),
            @('\??\UNC\atm-unc-probe.invalid\share\svc.exe', $null, $null, 'EXECUTABLE_UNPARSEABLE'),
            @('%P2A_UNKNOWN%\svc.exe -x', $null, $null, 'EXECUTABLE_UNPARSEABLE'),
            @('svc.exe', $null, 'svc.exe', $null),
            @('.exe', $null, $null, 'EXECUTABLE_UNPARSEABLE'),
            @('C:svc.exe', $null, $null, 'EXECUTABLE_UNPARSEABLE'),
            @('run.bat --x', $null, $null, 'EXECUTABLE_UNPARSEABLE'),
            # Review P2-A-S: switch-like text inside quotes, Unicode format and separator characters, splitting only on
            # space and tab, list separators.
            @("`"$pf\Agent\agent.cmd --token tok123 --run\svc.exe`" x", $null, $null, 'EXECUTABLE_UNPARSEABLE'),
            @("`"$pf\App$([char]0x202E)x\svc.exe`"", $null, $null, 'EXECUTABLE_UNPARSEABLE'),
            @("`"$pf\App$([char]0x2028)x\svc.exe`"", $null, $null, 'EXECUTABLE_UNPARSEABLE'),
            @("`"$pf\App$([char]0x00A0)x\svc.exe`"", $null, $null, 'EXECUTABLE_UNPARSEABLE'),
            @("$env:SystemRoot\System32\svc.exe$([char]0x0085)S3cr3t-P2A", $null, $null, 'EXECUTABLE_UNPARSEABLE'),
            @("$env:SystemRoot\System32\svc.exe$([char]0x00A0)S3cr3t-P2A", $null, $null, 'EXECUTABLE_UNPARSEABLE'),
            @("$env:SystemRoot\System32\svc.exe`t-k x", "$env:SystemRoot\System32\svc.exe", 'svc.exe', $null),
            @('C:\tools\svc.exe,S3cr3t-P2A.exe', $null, $null, 'EXECUTABLE_UNPARSEABLE'),
            @('C:\tools\svc.exe;S3cr3t-P2A.exe', $null, $null, 'EXECUTABLE_UNPARSEABLE'))
        for ($ci = 0; $ci -lt $cases.Count; $ci++) {
            $cs = $cases[$ci]
            $x = ConvertFrom-AtmServicePathName $cs[0]
            Assert-True ($x.Path -ceq $cs[1] -and $x.Name -ceq $cs[2] -and $x.Reason -ceq $cs[3]) "PathName $ci -> $($x.Path)|$($x.Name)|$($x.Reason)"
        }
        # P2-A-S: no file-system access while parsing. A spy on every path cmdlet, a path through a junction whose
        # target does not exist (read as text, never followed), a network path (refused at once, no connection), and
        # the parser's source holds no file-system API.
        $spy = @{ N = 0 }
        $bps = @(Set-PSBreakpoint -Command @('Test-Path', 'Get-Item', 'Get-ChildItem', 'Resolve-Path', 'Get-ItemProperty', 'Get-Acl', 'Get-Content', 'Convert-Path') -Action ({ $spy.N++ }.GetNewClosure()))
        try {
            $jd = Join-Path $sandbox 'p2as-jn'; [void][IO.Directory]::CreateDirectory($jd)
            New-Junction -Link (Join-Path $jd 'redirected') -Target (Join-Path $jd 'missing-target')
            $sw = [Diagnostics.Stopwatch]::StartNew()
            foreach ($cs in $cases) { $null = ConvertFrom-AtmServicePathName $cs[0] }
            $jx = ConvertFrom-AtmServicePathName ('"' + (Join-Path $jd 'redirected\deep\svc.exe') + '" -x')
            $ux = ConvertFrom-AtmServicePathName '\\atm-unc-probe.invalid\share\agent\svc.exe'
            $sw.Stop()
        } finally { $bps | Remove-PSBreakpoint }
        Assert-True ($spy.N -eq 0) "nenhuma chamada de caminho durante a interpretacao ($($spy.N))"
        Assert-True ($jx.Name -ceq 'svc.exe' -and $null -eq $jx.Path -and $ux.Reason -ceq 'EXECUTABLE_UNPARSEABLE' -and $sw.ElapsedMilliseconds -lt 2000) "juncao com alvo inexistente lida como texto; caminho de rede recusado sem conexao ($($sw.ElapsedMilliseconds) ms)"
        $diagSrc = [IO.File]::ReadAllText((Join-Path $srcDir 'lib\Engine.Diagnose.ps1'))
        $pfn = $diagSrc.Substring($diagSrc.IndexOf('function ConvertFrom-AtmServicePathName'), $diagSrc.IndexOf('function ConvertTo-AtmServiceAccount') - $diagSrc.IndexOf('function ConvertFrom-AtmServicePathName'))
        foreach ($api in @('IO.File', 'IO.Directory', 'FileInfo', 'DirectoryInfo', 'DriveInfo', 'GetFullPath', 'Exists', 'GetAttributes', 'Test-Path', 'Get-Item', 'Resolve-Path', 'FileExists', 'AtmNative', 'AtmPathCheck', 'Test-AtmGitPathChain')) { Assert-True (-not $pfn.Contains($api)) "interpretacao sem '$api'" }
        Assert-True (@((Get-Command ConvertFrom-AtmServicePathName).Parameters.Keys) -notcontains 'FileExists') 'sem parametro de verificacao de existencia'
        # Integrated: a runtime provider declaring the services; the rows carry secrets in PathName.
        $rt = [pscustomobject]@{ Id = 'fake-svc'; DisplayName = 'F'; ContractVersion = 2; Capabilities = @('runtime'); GetServiceHints = { @([pscustomobject]@{ Name = 'SecretSvc1' }, [pscustomobject]@{ Name = 'SecretSvc2' }, [pscustomobject]@{ Name = 'SecretSvc3' }) } }
        $upn = 'p2a-acct' + '@' + 'corp.example'
        $rows = @((& $svcRow 'SecretSvc1' 'Running' 'Auto' $false 'NT SERVICE\SecretSvc1' 4321 $cases[0][0]), (& $svcRow 'SecretSvc2' 'Running' 'Auto' $false 'CORPDOM\p2a-acct' 0 $cases[1][0]), (& $svcRow 'SecretSvc3' 'Stopped' 'Manual' $false $upn 0 $cases[2][0]))
        $p = New-TestProfile 'p2a-priv'
        $null = New-TestRoot -ProfileInfo $p
        $procRows = @([pscustomobject]@{ ProcessId = 4; ParentProcessId = 0; Name = 'System'; CreationDate = [datetime]::UtcNow.AddHours(-2) }, [pscustomobject]@{ ProcessId = 4321; ParentProcessId = 4; Name = 'svc.exe'; CreationDate = [datetime]::UtcNow.AddHours(-1) })
        $d = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p)) -IdentitySource $diagIdUser -Providers @((Get-AtmProviders)[0], $rt) -ProcessSource ({ $procRows }.GetNewClosure()) -CpuSampleMs 0 -PseudonymKey $testPseudonymKey -ServiceSource ({ param($Names) $rows }.GetNewClosure())
        $json = ConvertTo-AtmDiagnoseJson -Result $d
        $f0 = @($d.Findings | Where-Object { $_.Kind -ceq 'Service' -and $_.Key -ceq 'SecretSvc1' })[0]
        $txt = (Show-AtmDiagnose -Result $d 6>&1 | ForEach-Object { [string]$_ }) -join "`n"
        $all = $json + "`n" + $txt + "`n" + (@($d.Coverage | ForEach-Object { @($_.Reasons) }) -join ' ') + "`n" + (@($d.Findings | ForEach-Object { @($_.Evidence | ForEach-Object { [string]$_.Detail }) }) -join ' ')
        foreach ($sx in @('S3cr3t-P2A', 'tok-P2A-123', 'p2a-person', '--password', '--token', '/pw', 'run.cmd', 'p2a-acct', 'CORPDOM', 'corp.example', 'NT SERVICE')) { Assert-True (-not $all.Contains($sx)) "nenhum '$sx' na saida" }
        Assert-True ((& $svcEv $f0 'SERVICE_ACCOUNT_KIND')[0] -ceq 'VIRTUAL') 'tipo da conta preservado'
        $f = & $svcByKey ([pscustomobject]@{ Findings = @($d.Findings | Where-Object { $_.Kind -ceq 'Service' }) })
        Assert-True ((& $svcEv $f['SecretSvc2'] 'SERVICE_ACCOUNT_KIND')[0] -ceq 'USER' -and (& $svcEv $f['SecretSvc3'] 'SERVICE_ACCOUNT_KIND')[0] -ceq 'USER' -and (& $svcEv $f['SecretSvc2'] 'SERVICE_ACCOUNT').Count -eq 0 -and (& $svcEv $f['SecretSvc2'] 'SERVICE_ACCOUNT_UNREADABLE').Count -eq 0) 'conta de dominio e UPN: so o tipo USER, nunca ilegivel nem o nome'
        Assert-True ((& $svcEv $f['SecretSvc1'] 'SERVICE_EXECUTABLE_NAME')[0] -ceq 'svc.exe' -and (& $svcEv $f['SecretSvc2'] 'SERVICE_EXECUTABLE_UNREADABLE')[0] -ceq 'EXECUTABLE_UNPARSEABLE' -and (& $svcEv $f['SecretSvc3'] 'SERVICE_EXECUTABLE_UNREADABLE')[0] -ceq 'EXECUTABLE_UNPARSEABLE') 'fora de local conhecido so o nome; caminho com espacos inexistente e ilegivel so o codigo'
        Assert-True ($txt.Contains((Get-AtmText 'diag.svcTitle')) -and $txt.Contains('SecretSvc1') -and $txt.Contains((Get-AtmText 'diag.svcNoDelete'))) 'relatorio: secao de servicos'
    }
    Test-Case 'Servicos' 'P2-A: integracao ao diagnose - consulta antes do snapshot (processo verificado), coberturas, JSON e relatorio; sem servico declarado nada e consultado' {
        $p = New-TestProfile 'p2a-int'
        $null = New-TestRoot -ProfileInfo $p
        $rt = [pscustomobject]@{ Id = 'fake-svc'; DisplayName = 'F'; ContractVersion = 2; Capabilities = @('runtime'); GetServiceHints = { @([pscustomobject]@{ Name = 'LinkedSvc'; Role = 'vm-host' }, [pscustomobject]@{ Name = 'AbsentSvc' }) } }
        $procRows = @([pscustomobject]@{ ProcessId = 4; ParentProcessId = 0; Name = 'System'; CreationDate = [datetime]::UtcNow.AddHours(-2) }, [pscustomobject]@{ ProcessId = 6000; ParentProcessId = 4; Name = 'svc.exe'; CreationDate = [datetime]::UtcNow.AddHours(-1) })
        $rows = @(& $svcRow 'LinkedSvc' 'Running' 'Auto' $true 'LocalSystem' 6000)
        $d = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p)) -IdentitySource $diagIdUser -Providers @((Get-AtmProviders)[0], $rt) -ProcessSource ({ $procRows }.GetNewClosure()) -CpuSampleMs 0 -PseudonymKey $testPseudonymKey -ServiceSource ({ param($Names) $rows }.GetNewClosure())
        $cols = @($d.Coverage | ForEach-Object { $_.Collector })
        Assert-True ($cols.IndexOf('services') -eq $cols.IndexOf('agent-resources') + 1 -and $cols.IndexOf('service-properties') -eq $cols.IndexOf('services') + 1) "coberturas services e service-properties depois do runtime ($($cols -join ','))"
        $sf = @($d.Findings | Where-Object { $_.Kind -ceq 'Service' })
        $f = & $svcByKey ([pscustomobject]@{ Findings = $sf })
        Assert-True ($sf.Count -eq 2 -and $f['LinkedSvc'].State -ceq 'RUNNING' -and $f['AbsentSvc'].State -ceq 'UNKNOWN' -and $f['AbsentSvc'].RequestedState -ceq 'UNKNOWN') 'achados de servico no diagnose; nao listado UNKNOWN'
        Assert-True ((& $svcEv $f['LinkedSvc'] 'SERVICE_PROCESS_VERIFIED').Count -eq 1) 'consulta antes do snapshot do runtime: processo do servico verificado'
        Assert-True (@($d.Findings | Where-Object { $_.Kind -ceq 'TempPartition' -and ($_.State -ceq 'NO_DEPENDENCY_OBSERVED' -or $_.State -ceq 'RUNTIME_NOT_DIAGNOSED' -or ($_.State -ceq 'IN_USE' -and @($_.Evidence | Where-Object { $_.Code -ceq 'GRAPH_SOURCE_DIRECT' }).Count -eq 0)) }).Count -eq 0) 'servicos nao tornam particao livre (P4-B: estado so pelo grafo, IN_USE so com fonte direta)'
        $j = (ConvertTo-AtmDiagnoseJson -Result $d) | ConvertFrom-Json
        $js = @($j.findings | Where-Object { $_.kind -eq 'Service' })
        Assert-True ($js.Count -eq 2 -and @($j.coverage | Where-Object { $_.collector -eq 'services' -and $_.status -eq 'PARTIAL' -and @($_.reasons) -contains 'SERVICE_NOT_LISTED_FOR_ACCOUNT' }).Count -eq 1 -and @($js | Where-Object { $_.key -eq 'AbsentSvc' -and $_.state -eq 'UNKNOWN' -and $_.requestedState -eq 'UNKNOWN' }).Count -eq 1 -and @($js | Where-Object { $_.state -eq 'NOT_PRESENT' -or $_.requestedState -eq 'NOT_PRESENT' }).Count -eq 0) 'JSON: achados e cobertura de servicos; nenhum NOT_PRESENT'
        # Only Claude Code (no service declared): the source is never called.
        $calls = @{ N = 0 }
        $d2 = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p)) -IdentitySource $diagIdUser -Providers @((Get-AtmProviders)[0]) -ProcessSource ({ $procRows }.GetNewClosure()) -CpuSampleMs 0 -PseudonymKey $testPseudonymKey -ServiceSource ({ param($Names) $calls.N++; @() }.GetNewClosure())
        Assert-True ($calls.N -eq 0 -and @($d2.Findings | Where-Object { $_.Kind -ceq 'Service' }).Count -eq 0 -and @($d2.Coverage | Where-Object { $_.Collector -ceq 'services' -and $_.Status -ceq 'NOT_OBSERVABLE' }).Count -eq 1) 'sem servico declarado: nenhuma consulta'
        $txt = (Show-AtmDiagnose -Result $d2 6>&1 | ForEach-Object { [string]$_ }) -join "`n"
        Assert-True ($txt.Contains((Get-AtmText 'diag.svcNone'))) 'relatorio: nada verificado, nunca "sem servicos"'
        $d0 = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p)) -IdentitySource $diagIdUser -Providers @((Get-AtmProviders)[0], $rt) -DeadlineSeconds 0 -ServiceSource ({ param($Names) $calls.N++; @() }.GetNewClosure())
        Assert-True ($calls.N -eq 0 -and @($d0.Coverage | Where-Object { $_.Collector -ceq 'services' -and $_.Status -ceq 'TIMEOUT' }).Count -eq 1 -and @($d0.Findings | Where-Object { $_.Kind -ceq 'Service' -and $_.State -cne 'UNKNOWN' }).Count -eq 0) 'prazo 0: servicos TIMEOUT, nada consultado'
    }
    Test-Case 'Servicos' 'P2-A (estatico): nenhuma chamada que altere servicos, nenhum acesso remoto, uma unica consulta Win32_Service; PathName so na secao de servicos; CLI sem fonte injetada' {
        $diag = [IO.File]::ReadAllText((Join-Path $srcDir 'lib\Engine.Diagnose.ps1'))
        foreach ($pat in @('Start-Service', 'Stop-Service', 'Set-Service', 'Restart-Service', 'Suspend-Service', 'Resume-Service', 'New-Service', 'Remove-Service', 'Invoke-CimMethod', 'Invoke-WmiMethod', 'Get-WmiObject', 'Set-WmiInstance', 'Set-CimInstance', 'New-CimSession', '-CimSession', '-ComputerName', 'Invoke-Expression', 'sc.exe', 'Start-Process')) { Assert-True (-not $diag.Contains($pat)) "motor sem '$pat'" }
        Assert-True (-not ($diag -match '(?i)\b(StartService|StopService|PauseService|ResumeService|ChangeStartMode|UserControlService|ControlService)\b')) 'nenhum metodo de controle de servico'
        Assert-Eq ([regex]::Matches($diag, 'Get-CimInstance[^\r\n]*Win32_Service').Count) 2 'Win32_Service: a consulta dos nomes declarados e a leitura do vmms (P2-B, so estado)'
        $sec = $diag.IndexOf('# Windows services (P2-A'); $end = $diag.IndexOf('# Open-file evidence (D-2')
        $outside = @([regex]::Matches($diag, 'PathName') | Where-Object { $_.Index -lt $sec -or $_.Index -gt $end })
        Assert-True ($sec -gt 0 -and $end -gt $sec -and $outside.Count -eq 0) 'PathName so dentro da secao de servicos'
        $raw = $diag.Substring($diag.IndexOf('function Get-AtmServiceRaw'), $diag.IndexOf('function Test-AtmAccessDeniedException') - $diag.IndexOf('function Get-AtmServiceRaw'))
        Assert-True ($raw.Contains('Get-CimInstance -ClassName Win32_Service') -and $raw.Contains('-OperationTimeoutSec')) 'consulta local com tempo limite'
        foreach ($f in @('agent-temp.ps1', 'lib\Report.ps1', 'lib\Tui.ps1')) { $t = [IO.File]::ReadAllText((Join-Path $srcDir $f)); Assert-True (-not $t.Contains('ServiceSource') -and -not $t.Contains('PathName')) "$f sem fonte injetada nem PathName" }
        foreach ($l in @('en-US', 'pt-BR')) {
            foreach ($x in $script:AtmServiceReasonCodes) { Assert-True $script:AtmMessages[$l].ContainsKey("reason.$x") "reason.$x ($l)" }
            foreach ($x in $script:AtmServiceEvidenceCodes) { Assert-True $script:AtmMessages[$l].ContainsKey("evidence.$x") "evidence.$x ($l)" }
            foreach ($x in $script:AtmFindingStates['Service']) { Assert-True $script:AtmMessages[$l].ContainsKey("state.Service.$x") "state.Service.$x ($l)" }
        }
        Assert-True ($script:AtmAbsenceStates -ccontains 'NOT_PRESENT' -and $script:AtmFindingStates['Service'] -ccontains 'NOT_PRESENT') 'NOT_PRESENT segue no contrato fechado (capacidade futura) e exige cobertura conclusiva'
        $svcSec = $diag.Substring($sec, $end - $sec)
        Assert-True (-not ($svcSec -match "=\s*'NOT_PRESENT'|-State\s+'NOT_PRESENT'|'NOT_PRESENT'\s*\}")) 'o coletor de servicos nunca pede NOT_PRESENT'
        $nf = New-AtmFinding -Kind 'Service' -Key 'X' -State 'NOT_PRESENT' -Coverage @(New-AtmCoverage -Collector 'services' -Status 'PARTIAL' -Reasons @('SERVICE_UNEXPECTED_ROW'))
        Assert-Eq $nf.State 'UNKNOWN' 'ausencia com consulta parcial vira UNKNOWN'
    }
    Test-Case 'Servicos' 'P2-A (runner de CI, somente leitura): consulta real de EventLog, Winmgmt e um nome inexistente (UNKNOWN, consulta PARTIAL); estado e tipo de inicio identicos antes e depois; processo do Winmgmt verificado' {
        if ($env:GITHUB_ACTIONS -ne 'true') { $script:caseSkipped = $true; $script:caseNote = 'somente em runner de CI (consulta real, somente leitura)'; return }
        $snap = { (@(Get-CimInstance -ClassName Win32_Service -Filter "Name='EventLog' OR Name='Winmgmt'" -Property Name, State, StartMode -ErrorAction Stop | Sort-Object Name | ForEach-Object { '{0}/{1}/{2}' -f $_.Name, $_.State, $_.StartMode })) -join ',' }
        $before = & $snap
        $h = & $svcHints 'fake-ci' @((& $svcHint 'EventLog'), (& $svcHint 'Winmgmt'), (& $svcHint 'AtmNoSuchServiceP2A'))
        $q = Invoke-AtmServiceQuery -ProviderHints @($h)
        $coll = Get-AtmProcessCollection
        $r = Get-AtmServiceFindings -Query $q -Collection $coll
        $after = & $snap
        $f = & $svcByKey $r
        Assert-Eq $after $before 'estado e tipo de inicio identicos antes e depois'
        Assert-True ($q.Coverage.Status -ceq 'PARTIAL' -and (@($q.Coverage.Reasons) -join ',') -ceq 'SERVICE_NOT_LISTED_FOR_ACCOUNT' -and $f['EventLog'].State -ceq 'RUNNING' -and $f['Winmgmt'].State -ceq 'RUNNING' -and $f['AtmNoSuchServiceP2A'].State -ceq 'UNKNOWN') "consulta real: $($q.Coverage.Status), $(@($r.Findings | ForEach-Object { $_.Key + '=' + $_.State }) -join ',')"
        # Sanitized: link codes only (never a PID, a key or a time). The old UTC order (FINAL-A-S) is recorded for comparison.
        $wmOld = (Resolve-AtmServiceProcess -Collection $coll -ProcessId $q.Rows['Winmgmt'].ProcessId -QueryUtc $q.QueryUtc -QueryEndUtc $q.QueryEndUtc).Result
        Assert-Eq (& $svcEv $f['Winmgmt'] 'SERVICE_PROCESS_VERIFIED').Count 1 "Winmgmt: processo verificado (nao verificado: $((& $svcEv $f['Winmgmt'] 'SERVICE_PROCESS_UNVERIFIED') -join ','); ordem UTC antiga: $wmOld)"
        Assert-True ((& $svcEv $f['Winmgmt'] 'SERVICE_EXECUTABLE')[0] -like '*\svchost.exe' -and (& $svcEv $f['Winmgmt'] 'SERVICE_ACCOUNT_KIND')[0] -ceq 'LOCAL_SYSTEM') 'Winmgmt: svchost.exe em local conhecido, LocalSystem'
        $script:caseNote = "services $($q.Coverage.Status) em $($q.Coverage.ElapsedMs) ms; propriedades $((& $svcCov $r 'service-properties').Status) $(@((& $svcCov $r 'service-properties').Reasons) -join ','); Winmgmt pela ordem UTC antiga: $wmOld"
    }
    # ------------------------------------------------------------------ P2-B (virtualization, ADR-0005 rules 7-9)
    # CIM rows and process rows are injected; no VM is created, started or changed and no service is touched. Only the
    # CI-runner case runs the real read-only queries.
    $vT0 = [datetime]::UtcNow.AddMinutes(-30)
    $vG1 = '11111111-2222-3333-4444-555555555555'; $vG2 = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'; $vG3 = '99999999-8888-7777-6666-555555555555'
    $vHostRow = [pscustomobject]@{ Name = 'P2B-HOSTNAME'; Caption = 'Hosting Computer System'; Description = 'Microsoft Hosting Computer System'; ElementName = 'P2B-HOSTNAME'; EnabledState = 2; ProcessID = $null }
    $vVmRow = { param([string]$Guid, [string]$Element, $State = 2, $ProcId = 0) [pscustomobject]@{ Name = $Guid; Caption = 'Virtual Machine'; Description = 'Microsoft Virtual Computer System'; ElementName = $Element; EnabledState = $State; ProcessID = $ProcId } }
    $vBase = { param($Vms = @()) @{ Hypervisor = @([pscustomobject]@{ HypervisorPresent = $true }); NamespaceRoot = @([pscustomobject]@{ Name = 'virtualization' }); NamespaceV2 = @([pscustomobject]@{ Name = 'v2' }); Vmms = @([pscustomobject]@{ Name = 'vmms'; State = 'Running' }); Vms = @($Vms) } }
    # A source from a table: a value that is a scriptblock is invoked (to throw), anything else returned; calls counted.
    $vSrc = { param([hashtable]$T, [hashtable]$Calls = @{}) ({ param($Op) $Calls[$Op] = 1 + $(if ($Calls.ContainsKey($Op)) { $Calls[$Op] } else { 0 }); $v = $T[$Op]; if ($v -is [scriptblock]) { & $v } else { @($v) } }.GetNewClosure()) }
    $vPRow = { param($ProcId, $Parent, [string]$Name, $Created, $Ws = 1000) [pscustomobject]@{ ProcessId = $ProcId; ParentProcessId = $Parent; Name = $Name; CreationDate = $Created; KernelModeTime = 10; UserModeTime = 20; WorkingSetSize = $Ws; PrivatePageCount = 500; HandleCount = 1; ReadTransferCount = 0; WriteTransferCount = 0; OtherTransferCount = 0 } }
    $vColl = { param([object[]]$Rows) $vr = @($Rows); Get-AtmProcessCollection -Source ({ $vr }.GetNewClosure()) }
    $vRun = { param([hashtable]$T, $Collection, $Hints = @(), $Services = @()) $q = Invoke-AtmVirtualizationQuery -Source (& $vSrc $T) -NowUtc $vT0; Get-AtmVirtualizationFindings -Query $q -Collection $Collection -Pseudonymizer $b4Pz -ProviderHints @($Hints) -ServiceFindings @($Services) }
    $vEv = { param($F, [string]$Code) return , @($F.Evidence | Where-Object { $_.Code -ceq $Code } | ForEach-Object { [string]$_.Detail }) }
    $vPlat = { param($R) @($R.Findings | Where-Object { $_.Kind -ceq 'VirtualizationPlatform' })[0] }
    $vVms = { param($R) return , @($R.Findings | Where-Object { $_.Kind -ceq 'VirtualMachine' }) }
    $vCov = { param($R, [string]$Collector) @($R.Coverage | Where-Object { $_.Collector -ceq $Collector })[0] }
    $vKey = { param([string]$Guid) 'vm/v-' + (Get-AtmPseudonym -Pseudonymizer $b4Pz -Domain 'atm-virtual-machine/1' -Fields @($Guid.ToLowerInvariant())) }
    $vHints = { param([string]$Provider, [object[]]$VHints, [object[]]$SHints = @()) [pscustomobject]@{ ProviderId = $Provider; ProcessMatchers = @(); ServiceHints = @($SHints); VirtualizationHints = @($VHints); Coverage = (New-AtmCoverage -Collector ('provider-' + $Provider) -Status 'COMPLETE') } }
    Test-Case 'Virtualizacao' 'P2-B: plataforma presente, nao observavel, namespace indisponivel, acesso negado, falha; indicador de hipervisor so como evidencia; vmms parado nunca consultado (nenhuma consulta de VM)' {
        $coll = & $vColl @((& $vPRow 4 0 'System' $vT0.AddHours(-2)))
        $r = & $vRun (& $vBase) $coll
        $pf = & $vPlat $r
        Assert-True ($pf.State -ceq 'PRESENT' -and (& $vEv $pf 'VIRTUALIZATION_NAMESPACE_LISTED').Count -eq 1 -and (& $vEv $pf 'VMMS_SERVICE_STATE')[0] -ceq 'RUNNING' -and (& $vCov $r 'virtualization-platform').Status -ceq 'COMPLETE') 'plataforma presente (namespace e vmms listados)'
        $none = (& $vBase); $none.NamespaceRoot = @(); $none.Vmms = @()
        $r = & $vRun $none $coll
        Assert-True ((& $vPlat $r).State -ceq 'UNKNOWN' -and @((& $vCov $r 'virtualization-platform').Reasons) -ccontains 'PLATFORM_NOT_OBSERVED' -and (& $vCov $r 'virtualization-platform').Status -ceq 'PARTIAL' -and (& $vCov $r 'virtual-machines').Status -ceq 'NOT_OBSERVABLE') 'nada listado: UNKNOWN (nunca NOT_PRESENT), VMs nao observaveis'
        Assert-True ((& $vEv (& $vPlat $r) 'HYPERVISOR_PRESENT_FLAG')[0] -ceq 'TRUE' -and (& $vPlat $r).State -cne 'PRESENT') 'indicador de hipervisor sozinho nao torna a plataforma presente (verdadeiro tambem dentro de uma VM)'
        $inv = (& $vBase); $inv.NamespaceV2 = { throw (New-Object Runtime.InteropServices.COMException('x', -2147217394)) }; $inv.Vmms = @()
        $r = & $vRun $inv $coll
        Assert-True ((& $vEv (& $vPlat $r) 'VIRTUALIZATION_NAMESPACE_NOT_LISTED')[0] -ceq 'NOT_LISTED_FOR_ACCOUNT' -and (& $vPlat $r).State -ceq 'UNKNOWN') 'namespace invalido: nao listado, nunca falha nem ausencia'
        $den = (& $vBase); $den.NamespaceRoot = { throw (New-Object UnauthorizedAccessException('x')) }
        $r = & $vRun $den $coll
        Assert-True (@((& $vCov $r 'virtualization-platform').Reasons) -ccontains 'VIRTUALIZATION_NAMESPACE_DENIED' -and (& $vCov $r 'virtual-machines').Status -ceq 'NOT_OBSERVABLE' -and (& $vPlat $r).State -ceq 'PRESENT') 'namespace negado: declarado; vmms listado mantem a plataforma presente; VMs nao consultadas'
        $allDen = @{ Hypervisor = { throw (New-Object UnauthorizedAccessException('x')) }; NamespaceRoot = { throw (New-Object UnauthorizedAccessException('x')) }; Vmms = { throw (New-Object UnauthorizedAccessException('x')) } }
        Assert-Eq (Invoke-AtmVirtualizationQuery -Source (& $vSrc $allDen)).PlatformCoverage.Status 'DENIED' 'tudo negado: DENIED'
        $allFail = @{ Hypervisor = { throw (New-Object IO.IOException('x')) }; NamespaceRoot = { throw (New-Object IO.IOException('p2b-secret')) }; Vmms = { throw (New-Object UnauthorizedAccessException('x')) } }
        $qf = Invoke-AtmVirtualizationQuery -Source (& $vSrc $allFail)
        Assert-True ($qf.PlatformCoverage.Status -ceq 'FAILED' -and -not ((@($qf.PlatformCoverage.Reasons) -join ' ') -match 'p2b-secret')) 'falhas: FAILED, so o tipo da excecao'
        $calls = @{}
        $stopped = (& $vBase @((& $vVmRow $vG1 'X'))); $stopped.Vmms = @([pscustomobject]@{ Name = 'vmms'; State = 'Stopped' })
        $qs = Invoke-AtmVirtualizationQuery -Source (& $vSrc $stopped $calls)
        Assert-True (-not $calls.ContainsKey('Vms') -and (@($qs.VmCoverage.Reasons) -join ',') -ceq 'VMMS_NOT_RUNNING' -and $qs.VmCoverage.Status -ceq 'NOT_OBSERVABLE') 'vmms parado: nenhuma consulta de VM (uma consulta poderia iniciar o servico)'
        $calls2 = @{}; $nolist = (& $vBase @((& $vVmRow $vG1 'X'))); $nolist.NamespaceRoot = @()
        $null = Invoke-AtmVirtualizationQuery -Source (& $vSrc $nolist $calls2)
        Assert-True (-not $calls2.ContainsKey('Vms') -and -not $calls2.ContainsKey('NamespaceV2')) 'namespace nao listado: nenhuma conexao a root\virtualization\v2'
    }
    Test-Case 'Virtualizacao' 'P2-B: maquinas virtuais - existente, varias, consulta vazia (nunca ausencia), objeto do host, objeto sem identidade, estados documentados, limite, negada, falha; nomes e GUIDs nunca exportados' {
        $coll = & $vColl @((& $vPRow 4 0 'System' $vT0.AddHours(-2)))
        $rows = @($vHostRow, (& $vVmRow $vG1 'P2B-Secret-VM-Name' 2), (& $vVmRow $vG2 'Personal P2B VM' 3), (& $vVmRow $vG3 'Third' 32769))
        $r = & $vRun (& $vBase $rows) $coll
        $vms = & $vVms $r
        Assert-True ($vms.Count -eq 3 -and (& $vCov $r 'virtual-machines').Status -ceq 'COMPLETE' -and (& $vCov $r 'virtual-machines').Observed -eq 3) 'tres VMs; host deixado de fora'
        $byKey = @{}; foreach ($v in $vms) { $byKey[$v.Key] = $v }
        Assert-True ($byKey[(& $vKey $vG1)].State -ceq 'RUNNING' -and $byKey[(& $vKey $vG2)].State -ceq 'OFF' -and $byKey[(& $vKey $vG3)].State -ceq 'SAVED') 'estados documentados por chave pseudonima'
        $json = ConvertTo-Json -InputObject @($r.Findings + $r.Coverage) -Depth 6
        foreach ($x in @('P2B-Secret-VM-Name', 'Personal P2B VM', 'P2B-HOSTNAME', $vG1, $vG2.ToUpperInvariant(), $vG2)) { Assert-True (-not $json.Contains($x)) 'nenhum nome, host ou GUID exportado' }
        foreach ($cs in @(@(4, 'PENDING'), @(10, 'PENDING'), @(32768, 'PAUSED'), @(0, 'UNKNOWN'), @(9, 'UNKNOWN'), @(6, 'UNKNOWN'), @(32775, 'UNKNOWN'))) {
            $rr = & $vRun (& $vBase @((& $vVmRow $vG1 'X' $cs[0]))) $coll
            Assert-Eq (& $vVms $rr)[0].State $cs[1] "EnabledState $($cs[0])"
        }
        $rr = & $vRun (& $vBase @((& $vVmRow $vG1 'X' $null))) $coll
        Assert-True ((& $vVms $rr)[0].State -ceq 'UNKNOWN' -and (& $vEv (& $vVms $rr)[0] 'VM_STATE_UNREADABLE').Count -eq 1) 'estado ilegivel'
        $empty = & $vRun (& $vBase @($vHostRow)) $coll
        Assert-True ((& $vVms $empty).Count -eq 0 -and (& $vCov $empty 'virtual-machines').Status -ceq 'COMPLETE' -and @($empty.Findings | Where-Object { $_.State -ceq 'NOT_PRESENT' -or $_.RequestedState -ceq 'NOT_PRESENT' }).Count -eq 0) 'consulta sem VMs: nenhum achado, nenhuma ausencia'
        $amb = & $vRun (& $vBase @([pscustomobject]@{ Name = 'not-a-guid'; Caption = 'Virtual Machine'; Description = 'Microsoft Virtual Computer System'; ElementName = 'Y'; EnabledState = 2; ProcessID = 0 }, [pscustomobject]@{ Name = $vG1; Caption = 'Hosting Computer System'; Description = 'Microsoft Hosting Computer System'; ElementName = 'Z'; EnabledState = 2; ProcessID = 0 }, [pscustomobject]@{ Foo = 1 })) $coll
        Assert-True ((& $vVms $amb).Count -eq 0 -and (& $vCov $amb 'virtual-machines').Status -ceq 'PARTIAL' -and @((& $vCov $amb 'virtual-machines').Reasons) -ccontains 'VM_ROW_AMBIGUOUS' -and @((& $vCov $amb 'virtual-machines').Reasons) -ccontains 'VM_ROW_MALFORMED') 'objeto sem identidade de VM ou ambiguo: deixado de fora, nunca contado'
        $dup = & $vRun (& $vBase @((& $vVmRow $vG1 'A'), (& $vVmRow $vG1.ToUpperInvariant() 'B'))) $coll
        Assert-True ((& $vVms $dup).Count -eq 1 -and (& $vVms $dup)[0].State -ceq 'UNKNOWN' -and (& $vEv (& $vVms $dup)[0] 'VM_KEY_COLLISION').Count -eq 1) 'mesma chave duas vezes: UNKNOWN'
        $many = @(1..5 | ForEach-Object { & $vVmRow ('{0:D8}-0000-0000-0000-000000000000' -f $_) "vm$_" })
        $q = Invoke-AtmVirtualizationQuery -Source (& $vSrc (& $vBase $many)) -MaxObjects 3
        Assert-True (@($q.VmRows).Count -eq 3 -and $q.VmCoverage.Status -ceq 'PARTIAL' -and @($q.VmCoverage.Reasons) -ccontains 'VM_LIMIT_EXCEEDED') 'limite de objetos: PARTIAL'
        $den = (& $vBase); $den.Vms = { throw (New-Object UnauthorizedAccessException('x')) }
        $q = Invoke-AtmVirtualizationQuery -Source (& $vSrc $den)
        Assert-True ($q.VmCoverage.Status -ceq 'DENIED' -and $q.VmCoverage.ElevationWouldHelp -ceq 'YES' -and @($q.VmRows).Count -eq 0) 'VMs negadas: DENIED (elevacao ajudaria), nunca "nenhuma VM"'
        $fl = (& $vBase); $fl.Vms = { throw (New-Object IO.IOException('p2b-secret')) }
        $q = Invoke-AtmVirtualizationQuery -Source (& $vSrc $fl)
        Assert-True ($q.VmCoverage.Status -ceq 'FAILED' -and -not ((@($q.VmCoverage.Reasons) -join ' ') -match 'p2b-secret')) 'VMs com falha: FAILED, so o tipo'
        # Review P2-B.
        $q = Invoke-AtmVirtualizationQuery -Source (& $vSrc $den) -Elevated $true
        Assert-Eq $q.VmCoverage.ElevationWouldHelp 'UNKNOWN' 'administrador elevado negado: elevacao nao ajudaria com certeza'
        foreach ($bad in @(99999999999, '2', $true, -1)) {
            $rr = & $vRun (& $vBase @((& $vVmRow $vG1 'X' $bad))) $coll
            Assert-True ((& $vVms $rr)[0].State -ceq 'UNKNOWN') "EnabledState fora do tipo ou da faixa: UNKNOWN, nunca erro ($bad)"
        }
        $alt = & $vRun (& $vBase @([pscustomobject]@{ Name = $vG1; Caption = 'Virtual Machine'; Description = 'Microsoft Virtual Machine'; ElementName = 'A'; EnabledState = 2; ProcessID = 0 })) $coll
        Assert-Eq (& $vVms $alt).Count 1 'descricao "Microsoft Virtual Machine" tambem aceita'
        Assert-True ((& $vCov $dup 'virtual-machines').Status -ceq 'PARTIAL' -and @((& $vCov $dup 'virtual-machines').Reasons) -ccontains 'VM_KEY_COLLISION') 'colisao: cobertura de VMs PARTIAL'
        Assert-True ((& $vCov $rr 'virtual-machines').Status -ceq 'PARTIAL' -and @((& $vCov $rr 'virtual-machines').Reasons) -ccontains 'VM_PROPERTY_UNREADABLE') 'estado ilegivel: cobertura de VMs PARTIAL'
        $ord = & $vRun (& $vBase $rows) $coll
        $sig = @($ord.Findings | ForEach-Object { $_.Kind + '|' + $_.Key }); $srt = [string[]]$sig.Clone(); [Array]::Sort($srt, [StringComparer]::Ordinal)
        Assert-Eq ($sig -join ',') ($srt -join ',') 'ordem ordinal por Kind e Key (VMs antes da plataforma)'
        $uv = (& $vBase); $uv.Vmms = @([pscustomobject]@{ Name = 'vmms'; State = 'Weird' })
        $q = Invoke-AtmVirtualizationQuery -Source (& $vSrc $uv)
        Assert-True ($q.PlatformCoverage.Status -ceq 'PARTIAL' -and @($q.PlatformCoverage.Reasons) -ccontains 'VMMS_STATE_UNREADABLE' -and (@($q.VmCoverage.Reasons) -join ',') -ceq 'VMMS_STATE_UNREADABLE') 'estado do vmms ilegivel: plataforma PARTIAL, VMs nao consultadas pelo motivo certo'
        $late = (& $vBase); $late.Hypervisor = { Start-Sleep -Milliseconds 1200; @([pscustomobject]@{ HypervisorPresent = $true }) }
        $q = Invoke-AtmVirtualizationQuery -Source (& $vSrc $late) -Deadline ([datetime]::UtcNow.AddMilliseconds(600))
        Assert-True ($q.VmCoverage.Status -ceq 'TIMEOUT' -and $q.Namespace -ceq 'NOT_QUERIED') 'prazo no meio: VMs TIMEOUT, namespace nao consultado'
        $none = Get-AtmVirtualizationFindings -Query (Invoke-AtmVirtualizationQuery -Source (& $vSrc (& $vBase)) -Deadline ([datetime]::UtcNow.AddSeconds(-1))) -Collection $null -Pseudonymizer $b4Pz
        Assert-Eq @($none.Findings).Count 0 'prazo antes da plataforma: nenhum achado inventado'
    }
    Test-Case 'Virtualizacao' 'P2-B: processos de virtualizacao - vmmem e vmwp isolados (so a classe), identidade nao verificada, contadores lidos ou nao, vinculo VM-processo por prova temporal; snapshot indisponivel' {
        $rows = @((& $vPRow 4 0 'System' $vT0.AddHours(-2)), (& $vPRow 700 4 'vmwp.exe' $vT0.AddMinutes(-10) 3000), (& $vPRow 800 4 'vmmemWSL' $vT0.AddMinutes(-5) 7000), (& $vPRow 900 4 'vmmem.P2BSecretVm' $null), (& $vPRow 950 4 'vmwp.exe' $vT0.AddMinutes(5)), (& $vPRow 960 4 'notepad.exe' $vT0.AddHours(-1)))
        $coll = & $vColl $rows
        $r = & $vRun (& $vBase @((& $vVmRow $vG1 'A' 2 700), (& $vVmRow $vG2 'B' 2 950), (& $vVmRow $vG3 'C' 2 960))) $coll
        $pf = & $vPlat $r
        Assert-True ((((& $vEv $pf 'VIRTUALIZATION_WORKER')) -join ';') -ceq ("VMMEM|" + (ConvertTo-AtmProcessKey -ProcessId 800 -CreationUtc $vT0.AddMinutes(-5)) + ";VMWP|" + (ConvertTo-AtmProcessKey -ProcessId 700 -CreationUtc $vT0.AddMinutes(-10)) + ";VMWP|" + (ConvertTo-AtmProcessKey -ProcessId 950 -CreationUtc $vT0.AddMinutes(5)))) "trabalhadores verificados por classe ($((& $vEv $pf 'VIRTUALIZATION_WORKER') -join ';'))"
        Assert-True ((& $vEv $pf 'VIRTUALIZATION_WORKER_UNVERIFIED')[0] -ceq 'VMMEM|pid:900' -and @((& $vCov $r 'virtualization-processes').Reasons) -ccontains 'WORKER_IDENTITY_UNVERIFIED') 'sem horario: nao verificado'
        Assert-True (-not ((ConvertTo-Json -InputObject @($r.Findings) -Depth 6) -match 'P2BSecretVm|notepad')) 'nome bruto do processo nunca exportado; outros processos ignorados'
        Assert-True ((& $vEv $pf 'VIRTUALIZATION_WORKERS_WORKING_SET_BYTES')[0] -ceq '12000' -and (& $vEv $pf 'VIRTUALIZATION_WORKER_COUNTERS_INCOMPLETE').Count -eq 0) 'totais dos contadores lidos'
        $byKey = @{}; foreach ($v in (& $vVms $r)) { $byKey[$v.Key] = $v }
        Assert-Eq (& $vEv $byKey[(& $vKey $vG1)] 'VM_WORKER_VERIFIED')[0] (ConvertTo-AtmProcessKey -ProcessId 700 -CreationUtc $vT0.AddMinutes(-10)) 'VM ligada ao seu vmwp (criado antes da consulta)'
        Assert-Eq (& $vEv $byKey[(& $vKey $vG2)] 'VM_WORKER_UNVERIFIED')[0] 'CREATED_AFTER_QUERY' 'PID reutilizado (criado depois da consulta): nunca ligado'
        Assert-Eq (& $vEv $byKey[(& $vKey $vG3)] 'VM_WORKER_UNVERIFIED')[0] 'NOT_A_WORKER_PROCESS' 'PID de outro programa: nunca ligado'
        $nc = @((& $vPRow 4 0 'System' $vT0.AddHours(-2)), [pscustomobject]@{ ProcessId = 701; ParentProcessId = 4; Name = 'vmwp.exe'; CreationDate = $vT0.AddMinutes(-3) })
        $r2 = & $vRun (& $vBase) (& $vColl $nc)
        Assert-True ((& $vEv (& $vPlat $r2) 'VIRTUALIZATION_WORKER_COUNTERS_INCOMPLETE')[0] -ceq '0/1' -and (& $vEv (& $vPlat $r2) 'VIRTUALIZATION_WORKERS_WORKING_SET_BYTES').Count -eq 0) 'contadores nao lidos: nenhum total (nunca 0)'
        $r3 = & $vRun (& $vBase @((& $vVmRow $vG1 'A' 2 700))) $null
        Assert-True ((& $vCov $r3 'virtualization-processes').Status -ceq 'NOT_OBSERVABLE' -and (& $vEv (& $vVms $r3)[0] 'VM_WORKER_UNVERIFIED')[0] -ceq 'PROCESS_SNAPSHOT_UNAVAILABLE') 'sem snapshot: processos nao observaveis, vinculo nao verificado'
        foreach ($n in @('vmwp.exe', 'VMWP.EXE', 'vmmem', 'vmmem.exe', 'vmmemWSL', 'vmmem.foo')) { Assert-True ($null -ne (Get-AtmVirtualizationWorkerClass $n)) "classe de $n" }
        foreach ($n in @('vmwpx.exe', 'myvmmem', 'vmcompute.exe', 'vmms.exe', $null, 5)) { Assert-True ($null -eq (Get-AtmVirtualizationWorkerClass $n)) 'outros nomes nao sao trabalhadores' }
    }
    Test-Case 'Virtualizacao' 'P2-B: atribuicao - nome de VM declarado, cadeia servico-processo confirmada e nao confirmada, dois providers, WSL2/Sandbox sem atribuicao, nenhum hint' {
        $rows = @((& $vPRow 4 0 'System' $vT0.AddHours(-2)), (& $vPRow 600 4 'agentsvc.exe' $vT0.AddHours(-1)), (& $vPRow 700 600 'vmwp.exe' $vT0.AddMinutes(-10)), (& $vPRow 710 4 'vmwp.exe' $vT0.AddMinutes(-10)), (& $vPRow 800 4 'vmmemWSL' $vT0.AddMinutes(-5)))
        $coll = & $vColl $rows
        $svcRows = @([pscustomobject]@{ Name = 'AgentSvc'; State = 'Running'; StartMode = 'Auto'; DelayedAutoStart = $false; StartName = 'LocalSystem'; ProcessId = 600; PathName = 'agentsvc.exe' })
        $sh = [pscustomobject]@{ ProviderId = 'prov-a'; ProcessMatchers = @(); ServiceHints = @([pscustomobject]@{ Name = 'AgentSvc'; Role = $null }); VirtualizationHints = @([pscustomobject]@{ Kind = 'ServiceOwner'; Value = 'AgentSvc' }); Coverage = (New-AtmCoverage -Collector 'provider-prov-a' -Status 'COMPLETE') }
        $sq = Invoke-AtmServiceQuery -ProviderHints @($sh) -Source ({ param($Names) $svcRows }.GetNewClosure()) -NowUtc $vT0
        $svc = (Get-AtmServiceFindings -Query $sq -Collection $coll).Findings
        $vmRows = @((& $vVmRow $vG1 'Agent VM' 2 700), (& $vVmRow $vG2 'Other VM' 2 710))
        $r = & $vRun (& $vBase $vmRows) $coll @($sh) $svc
        $byKey = @{}; foreach ($v in (& $vVms $r)) { $byKey[$v.Key] = $v }
        $a = $byKey[(& $vKey $vG1)]; $b = $byKey[(& $vKey $vG2)]
        Assert-True ($a.Provider -ceq 'prov-a' -and (& $vEv $a 'VM_ATTRIBUTED_BY_SERVICE')[0] -ceq 'prov-a|AgentSvc') 'cadeia confirmada: vmwp verificado, pai verificado = processo do servico em execucao declarado pelo mesmo provider'
        Assert-True ($null -eq $b.Provider -and (& $vEv $b 'VM_UNATTRIBUTED').Count -eq 1) 'outra VM (pai nao e o servico): nao atribuida'
        $other = [pscustomobject]@{ ProviderId = 'prov-b'; ProcessMatchers = @(); ServiceHints = @(); VirtualizationHints = @([pscustomobject]@{ Kind = 'ServiceOwner'; Value = 'AgentSvc' }); Coverage = (New-AtmCoverage -Collector 'provider-prov-b' -Status 'COMPLETE') }
        $r = & $vRun (& $vBase $vmRows) $coll @($other) $svc
        Assert-True (@((& $vVms $r) | Where-Object { $_.Provider }).Count -eq 0) 'servico nao declarado pelo mesmo provider: nunca atribuido'
        $stoppedSvc = @($svc | ForEach-Object { New-AtmFinding -Kind 'Service' -Key $_.Key -State 'STOPPED' -Evidence $_.Evidence -Coverage $_.Coverage -Provider $_.Provider })
        $r = & $vRun (& $vBase $vmRows) $coll @($sh) $stoppedSvc
        Assert-True (@((& $vVms $r) | Where-Object { $_.Provider }).Count -eq 0) 'servico parado: nunca atribuido'
        $nh1 = & $vHints 'prov-a' @([pscustomobject]@{ Kind = 'VmName'; Value = 'agent vm' })
        $nh2 = & $vHints 'prov-c' @([pscustomobject]@{ Kind = 'VmName'; Value = 'AGENT VM' }, [pscustomobject]@{ Kind = 'VmName'; Value = 'Never Seen VM' })
        $r = & $vRun (& $vBase $vmRows) $coll @($nh1)
        Assert-True (@((& $vVms $r) | Where-Object { $_.Provider -ceq 'prov-a' }).Count -eq 1 -and (& $vEv @((& $vVms $r) | Where-Object { $_.Provider -ceq 'prov-a' })[0] 'VM_ATTRIBUTED_BY_NAME')[0] -ceq 'prov-a') 'nome declarado (sem diferenca de caixa): atribuida; o nome nao e exportado'
        $r = & $vRun (& $vBase $vmRows) $coll @($nh1, $nh2)
        $amb = @((& $vVms $r) | Where-Object { (& $vEv $_ 'PROVIDER_ATTRIBUTION_AMBIGUOUS').Count -eq 1 })
        Assert-True ($amb.Count -eq 1 -and $null -eq $amb[0].Provider -and (& $vEv $amb[0] 'PROVIDER_ATTRIBUTION_AMBIGUOUS')[0] -ceq 'prov-a,prov-c') 'dois providers na mesma VM: ambigua, provider null'
        Assert-True ((& $vEv (& $vPlat $r) 'VM_HINT_NOT_OBSERVED') -contains 'prov-c' -and -not ((ConvertTo-Json -InputObject @($r.Findings) -Depth 6) -match 'Never Seen VM|Agent VM|Other VM')) 'nome declarado nao observado: so observacao, sem o nome'
        # WSL 2 / Windows Sandbox: utility VMs are not in Msvm_ComputerSystem; vmmem is never attributed.
        $r = & $vRun (& $vBase @($vHostRow)) $coll @($nh1, $sh) $svc
        Assert-True ((& $vVms $r).Count -eq 0 -and (& $vPlat $r).Provider -eq $null -and (& $vEv (& $vPlat $r) 'VIRTUALIZATION_WORKER') -contains ('VMMEM|' + (ConvertTo-AtmProcessKey -ProcessId 800 -CreationUtc $vT0.AddMinutes(-5)))) 'vmmemWSL observado, nunca atribuido'
        $r = & $vRun (& $vBase $vmRows) $coll
        Assert-True (@((& $vVms $r) | Where-Object { $_.Provider -or (& $vEv $_ 'VM_UNATTRIBUTED').Count -ne 1 }).Count -eq 0) 'nenhum hint: todas UNATTRIBUTED'
        # Review P2-B: a display name carried by two VMs identifies neither; a hint not observed only when VMs were
        # looked at, once per provider and name.
        $twin = @((& $vVmRow $vG1 'Twin VM' 2 0), (& $vVmRow $vG2 'twin vm' 3 0))
        $r = & $vRun (& $vBase $twin) $coll @((& $vHints 'prov-a' @([pscustomobject]@{ Kind = 'VmName'; Value = 'Twin VM' })))
        Assert-True (@((& $vVms $r) | Where-Object { $_.Provider }).Count -eq 0 -and @((& $vVms $r) | Where-Object { (& $vEv $_ 'VM_NAME_NOT_UNIQUE').Count -eq 1 }).Count -eq 2) 'nome repetido em duas VMs: nenhuma atribuida'
        $dupHint = & $vHints 'prov-z' @([pscustomobject]@{ Kind = 'VmName'; Value = 'Missing VM' }, [pscustomobject]@{ Kind = 'VmName'; Value = 'MISSING VM' })
        $r = & $vRun (& $vBase $vmRows) $coll @($dupHint)
        Assert-Eq (& $vEv (& $vPlat $r) 'VM_HINT_NOT_OBSERVED').Count 1 'hint nao observado: uma vez por provider e nome'
        $denT = (& $vBase); $denT.Vms = { throw (New-Object UnauthorizedAccessException('x')) }
        $r = & $vRun $denT $coll @($dupHint)
        Assert-Eq (& $vEv (& $vPlat $r) 'VM_HINT_NOT_OBSERVED').Count 0 'VMs nao consultadas: nenhum "nao observado"'
    }
    Test-Case 'Virtualizacao' 'P2-B: prazo excedido, integracao ao diagnose (coberturas, JSON e relatorio sem nomes), privacidade' {
        $calls = @{}
        $q = Invoke-AtmVirtualizationQuery -Source (& $vSrc (& $vBase) $calls) -Deadline ([datetime]::UtcNow.AddSeconds(-1))
        Assert-True ($calls.Count -eq 0 -and $q.PlatformCoverage.Status -ceq 'TIMEOUT' -and $q.VmCoverage.Status -ceq 'TIMEOUT') 'prazo: nada consultado, TIMEOUT'
        $p = New-TestProfile 'p2b-int'
        $null = New-TestRoot -ProfileInfo $p
        $procRows = @([pscustomobject]@{ ProcessId = 4; ParentProcessId = 0; Name = 'System'; CreationDate = [datetime]::UtcNow.AddHours(-2) }, [pscustomobject]@{ ProcessId = 7000; ParentProcessId = 4; Name = 'vmwp.exe'; CreationDate = [datetime]::UtcNow.AddHours(-1) }, [pscustomobject]@{ ProcessId = 7100; ParentProcessId = 4; Name = 'vmmem.P2BSecretVm'; CreationDate = [datetime]::UtcNow.AddHours(-1) })
        $vt = & $vBase @($vHostRow, (& $vVmRow $vG1 'P2B-Secret-VM-Name' 2 7000))
        $rt = [pscustomobject]@{ Id = 'fake-virt'; DisplayName = 'F'; ContractVersion = 2; Capabilities = @('runtime'); GetVirtualizationHints = { @([pscustomobject]@{ Kind = 'VmName'; Value = 'P2B-Secret-VM-Name' }) } }
        $d = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p)) -IdentitySource $diagIdUser -Providers @((Get-AtmProviders)[0], $rt) -ProcessSource ({ $procRows }.GetNewClosure()) -CpuSampleMs 0 -PseudonymKey $testPseudonymKey -ServiceSource { param($Names) @() } -VirtualizationSource (& $vSrc $vt)
        $cols = @($d.Coverage | ForEach-Object { $_.Collector })
        Assert-True ($cols.IndexOf('virtualization-platform') -eq $cols.IndexOf('service-properties') + 1 -and $cols.IndexOf('virtual-machines') -eq $cols.IndexOf('virtualization-platform') + 1 -and $cols.IndexOf('virtualization-processes') -eq $cols.IndexOf('virtual-machines') + 1) "coberturas por camada ($($cols -join ','))"
        $vm = @($d.Findings | Where-Object { $_.Kind -ceq 'VirtualMachine' })
        # One assertion per property, each with a sanitized value (codes and states only; never a PID, key or name).
        Assert-Eq $vm.Count 1 'VM no diagnose: uma'
        Assert-Eq $vm[0].State 'RUNNING' 'VM no diagnose: em execucao'
        Assert-Eq ([string]$vm[0].Provider) 'fake-virt' 'VM no diagnose: atribuida pelo nome'
        Assert-Eq (& $vEv $vm[0] 'VM_WORKER_VERIFIED').Count 1 "VM no diagnose: vmwp verificado, consulta antes do snapshot (nao verificado: $((& $vEv $vm[0] 'VM_WORKER_UNVERIFIED') -join ','))"
        Assert-Eq @($d.Findings | Where-Object { $_.Kind -ceq 'VirtualizationPlatform' -and $_.State -ceq 'PRESENT' }).Count 1 "plataforma PRESENT ($(@($d.Findings | Where-Object { $_.Kind -ceq 'VirtualizationPlatform' } | ForEach-Object { $_.State }) -join ','))"
        Assert-True (@($d.Findings | Where-Object { $_.Kind -ceq 'TempPartition' -and ($_.State -ceq 'NO_DEPENDENCY_OBSERVED' -or $_.State -ceq 'RUNTIME_NOT_DIAGNOSED' -or ($_.State -ceq 'IN_USE' -and @($_.Evidence | Where-Object { $_.Code -ceq 'GRAPH_SOURCE_DIRECT' }).Count -eq 0)) }).Count -eq 0) 'virtualizacao nao torna particao livre (P4-B: estado so pelo grafo, IN_USE so com fonte direta)'
        $json = ConvertTo-AtmDiagnoseJson -Result $d
        $txt = (Show-AtmDiagnose -Result $d 6>&1 | ForEach-Object { [string]$_ }) -join "`n"
        foreach ($x in @('P2B-Secret-VM-Name', 'P2B-HOSTNAME', 'P2BSecretVm', $vG1)) { Assert-True (-not $json.Contains($x) -and -not $txt.Contains($x)) 'JSON e relatorio sem nome de VM, host, nome bruto de processo ou GUID' }
        $j = $json | ConvertFrom-Json
        Assert-True (@($j.findings | Where-Object { $_.kind -eq 'VirtualizationPlatform' -and $_.key -eq 'host' }).Count -eq 1 -and @($j.findings | Where-Object { $_.kind -eq 'VirtualMachine' -and $_.key -like 'vm/v-*' }).Count -eq 1) 'JSON: plataforma e VM com chave pseudonima'
        Assert-True ($txt.Contains((Get-AtmText 'diag.virtTitle')) -and $txt.Contains((Get-AtmText 'diag.virtNoDelete'))) 'relatorio: secao de virtualizacao'
        $d0 = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p)) -IdentitySource $diagIdUser -DeadlineSeconds 0 -VirtualizationSource (& $vSrc $vt $calls)
        Assert-True ($calls.Count -eq 0 -and @($d0.Coverage | Where-Object { $_.Collector -like 'virtual*' -and $_.Collector -cne 'virtualization-processes' -and $_.Status -cne 'TIMEOUT' }).Count -eq 0) 'prazo 0 no diagnose: nada consultado'
    }
    Test-Case 'Virtualizacao' 'P2-B (estatico): nenhuma operacao de VM, metodo CIM, acesso remoto, modulo Hyper-V ou elevacao; consultas so em Get-AtmVirtualizationRaw; CLI sem fonte injetada; textos nos dois idiomas' {
        $diag = [IO.File]::ReadAllText((Join-Path $srcDir 'lib\Engine.Diagnose.ps1'))
        foreach ($pat in @('Start-VM', 'Stop-VM', 'Save-VM', 'Checkpoint-VM', 'Remove-VM', 'New-VM', 'Set-VM', 'Get-VM', 'Import-Module', 'RequestStateChange', 'Invoke-CimMethod', 'Invoke-WmiMethod', 'New-CimSession', '-CimSession', '-ComputerName', 'Mount-VHD', 'Dismount-VHD', 'Start-Service', 'Stop-Service', 'Stop-Process', 'RunAs')) { Assert-True (-not $diag.Contains($pat)) "motor sem '$pat'" }
        Assert-Eq ([regex]::Matches($diag, 'Msvm_ComputerSystem -Property').Count) 1 'uma unica consulta de VMs'
        $raw = $diag.Substring($diag.IndexOf('function Get-AtmVirtualizationRaw'), $diag.IndexOf('function Test-AtmInvalidNamespaceException') - $diag.IndexOf('function Get-AtmVirtualizationRaw'))
        Assert-True ($raw.Contains("Namespace 'root\virtualization\v2'") -and @([regex]::Matches($diag, "root\\virtualization\\v2' -ClassName") | Where-Object { $_.Index -lt $diag.IndexOf('function Get-AtmVirtualizationRaw') -or $_.Index -gt $diag.IndexOf('function Test-AtmInvalidNamespaceException') }).Count -eq 0) 'consultas de virtualizacao so na funcao de leitura'
        Assert-True (-not ($diag -match '(?i)\b(Msvm_VirtualSystemManagementService|Msvm_VirtualSystemSettingData|Msvm_StorageAllocationSettingData|Msvm_ResourceAllocationSettingData)\b')) 'nenhuma classe de configuracao ou disco consultada'
        foreach ($f in @('agent-temp.ps1', 'lib\Report.ps1', 'lib\Tui.ps1')) { $t = [IO.File]::ReadAllText((Join-Path $srcDir $f)); Assert-True (-not $t.Contains('VirtualizationSource')) "$f sem fonte injetada" }
        foreach ($l in @('en-US', 'pt-BR')) {
            foreach ($x in $script:AtmVirtReasonCodes) { Assert-True $script:AtmMessages[$l].ContainsKey("reason.$x") "reason.$x ($l)" }
            foreach ($x in $script:AtmVirtEvidenceCodes) { Assert-True $script:AtmMessages[$l].ContainsKey("evidence.$x") "evidence.$x ($l)" }
            foreach ($k in @('VirtualMachine', 'VirtualizationPlatform')) { foreach ($x in $script:AtmFindingStates[$k]) { Assert-True $script:AtmMessages[$l].ContainsKey("state.$k.$x") "state.$k.$x ($l)" } }
        }
        $sec = $diag.Substring($diag.IndexOf('# Virtualization (P2-B'), $diag.IndexOf('# Open-file evidence (D-2') - $diag.IndexOf('# Virtualization (P2-B'))
        Assert-True (-not ($sec -match "-State\s+'NOT_PRESENT'|=\s*'NOT_PRESENT'")) 'o coletor nunca produz NOT_PRESENT'
    }
    Test-Case 'Virtualizacao' 'P2-B (runner de CI, somente leitura): consultas reais de plataforma, VMs e processos; estados permitidos; estado do vmms identico antes e depois' {
        if ($env:GITHUB_ACTIONS -ne 'true') { $script:caseSkipped = $true; $script:caseNote = 'somente em runner de CI (consultas reais, somente leitura)'; return }
        $snap = { (@(Get-CimInstance -ClassName Win32_Service -Filter "Name='vmms'" -Property Name, State, StartMode -ErrorAction Stop | ForEach-Object { '{0}/{1}' -f $_.State, $_.StartMode })) -join ',' }
        $before = & $snap
        $q = Invoke-AtmVirtualizationQuery
        $r = Get-AtmVirtualizationFindings -Query $q -Collection (Get-AtmProcessCollection) -Pseudonymizer $b4Pz
        $after = & $snap
        Assert-Eq $after $before 'estado do vmms identico antes e depois'
        Assert-True (@('COMPLETE', 'PARTIAL', 'DENIED', 'FAILED') -ccontains $q.PlatformCoverage.Status -and @('COMPLETE', 'PARTIAL', 'DENIED', 'FAILED', 'NOT_OBSERVABLE', 'TIMEOUT') -ccontains $q.VmCoverage.Status -and @('PRESENT', 'UNKNOWN') -ccontains (& $vPlat $r).State) "estados permitidos ($($q.PlatformCoverage.Status)/$($q.VmCoverage.Status)/$((& $vPlat $r).State))"
        Assert-True ($q.VmCoverage.Status -cne 'COMPLETE' -or ($q.Namespace -ceq 'LISTED' -and $q.Vmms -ceq 'RUNNING')) 'VMs consultadas so com namespace listado e vmms em execucao'
        $script:caseNote = "plataforma $($q.PlatformCoverage.Status) [$(@($q.PlatformCoverage.Reasons) -join ',')], namespace $($q.Namespace), vmms $($q.Vmms), hipervisor $($q.Hypervisor), VMs $($q.VmCoverage.Status) [$(@($q.VmCoverage.Reasons) -join ',')], trabalhadores $(@((& $vPlat $r).Evidence | Where-Object { $_.Code -like 'VIRTUALIZATION_WORKER*' }).Count)"
    }
    # ------------------------------------------------------------------ P2-C (Claude Desktop provider, ADR-0008)
    # The provider file is loaded here and removed from the registry at once (the suite runs with Claude Code only);
    # every source is injected: no Claude Desktop installation, service, VM or process is read or touched.
    . (Join-Path $srcDir 'providers\ClaudeDesktop.ps1')
    $cdProvider = @(Get-AtmProviders | Where-Object { $_.Id -eq 'claude-desktop' })[0]
    for ($k = $script:AtmProviders.Count - 1; $k -ge 0; $k--) { if ($script:AtmProviders[$k].Id -eq 'claude-desktop') { $script:AtmProviders.RemoveAt($k) } }
    $cdHints = Get-AtmProviderRuntimeHints $cdProvider
    $ccHints = Get-AtmProviderRuntimeHints (Get-AtmProviders)[0]
    $cdPkg = 'C:\Program Files\WindowsApps\Claude_1.2.3.0_x64__pzs8sxrjxfjjc\app\claude.exe'
    $cdHelper = 'C:\Users\x\AppData\Roaming\Claude\claude-code\2.1.300\abcdefabcdef\claude.exe'
    Test-Case 'Claude Desktop' 'P2-C: contrato v2 somente runtime - processo por marcador do pacote MSIX, servico CoworkVMService (relatado), nenhum hint de virtualizacao nao comprovado; fontes e versao registradas; nenhuma leitura da instalacao' {
        Assert-True ($null -ne $cdProvider -and $cdProvider.ContractVersion -eq 2 -and (@(Get-AtmProviderCapabilities $cdProvider) -join ',') -ceq 'runtime') 'provider v2, somente runtime (sem diretorios temporarios declarados)'
        Assert-Eq @(Get-AtmProviders).Count 1 'suite segue com Claude Code apenas (provider de teste removido)'
        Assert-True ($cdHints.Coverage.Status -ceq 'COMPLETE' -and (@($cdHints.ProcessMatchers | ForEach-Object { $_.ImageName + '/' + $_.CommandLineMarker }) -join ';') -ceq 'claude.exe/pzs8sxrjxfjjc') 'matcher: claude.exe com o id do editor do pacote'
        Assert-Eq (@($cdHints.ServiceHints | ForEach-Object { $_.Name + '/' + $_.Role }) -join ';') 'CoworkVMService/cowork-vm' 'servico: somente o nome relatado, papel cowork-vm'
        Assert-Eq @($cdHints.VirtualizationHints).Count 0 'nenhum hint de virtualizacao (nome de VM arbitrario, relacao servico-VM nao verificavel)'
        $src = [IO.File]::ReadAllText((Join-Path $srcDir 'providers\ClaudeDesktop.ps1'))
        foreach ($x in @('Claude_pzs8sxrjxfjjc', '1.1.3647', 'claude-code#27010', 'claude-code#59035', '2026-10-24', 'Machine Platform', 'cowork-vm-<8 hex>')) { Assert-True $src.Contains($x) "fonte/versao registrada: $x" }
        $code = (($src -split "`r?`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        foreach ($pat in @('Get-ChildItem', 'Get-Item', 'Get-Content', 'Get-CimInstance', 'Get-WmiObject', '[IO.', 'Registry', 'HKLM', 'HKCU', 'Start-', 'Stop-', 'Set-', 'Remove-', 'New-Item', 'Invoke-', 'Get-AppxPackage')) { Assert-True (-not $code.Contains($pat)) "provider nao le nem altera nada: '$pat'" }
        Assert-True (@($cdProvider.PSObject.Properties.Name | Where-Object { $_ -match '(?i)version' -and $_ -cne 'ContractVersion' }).Count -eq 0) 'nenhuma versao da instalacao declarada ou lida (versao desconhecida)'
    }
    Test-Case 'Claude Desktop' 'P2-C: processos - principal e auxiliares do pacote, identidade inconclusiva, linha de comando indisponivel, auxiliar claude.exe e Electron/Node alheios, sobreposicao com Claude Code (ambigua)' {
        $rows = @((& $b4Row 4 0 'System' $b4T0.AddHours(-1)), (& $b4Row 100 4 'claude.exe' $b4T0), (& $b4Row 101 100 'claude.exe' $b4T0.AddSeconds(5)), (& $b4Row 200 100 'claude.exe' $b4T0.AddSeconds(9)),
            (& $b4Row 300 4 'Code.exe' $b4T0), (& $b4Row 301 4 'node.exe' $b4T0), (& $b4Row 400 4 'claude.exe' $b4T0.AddMinutes(1)), (& $b4Row 500 4 'claude.exe' $null))
        $c = Get-AtmProcessCollection -Source ({ $rows }.GetNewClosure())
        $legacy = [pscustomobject]@{ Failed = $false; Processes = @(
                [pscustomobject]@{ Pid = 100; Name = 'claude.exe'; ParentPid = 4; CommandLine = "`"$cdPkg`""; CreationUtc = $b4T0 },
                [pscustomobject]@{ Pid = 101; Name = 'claude.exe'; ParentPid = 100; CommandLine = "`"$cdPkg`" --type=renderer"; CreationUtc = $b4T0.AddSeconds(5) },
                [pscustomobject]@{ Pid = 200; Name = 'claude.exe'; ParentPid = 100; CommandLine = "`"$cdHelper`" --print"; CreationUtc = $b4T0.AddSeconds(9) },
                [pscustomobject]@{ Pid = 300; Name = 'Code.exe'; ParentPid = 4; CommandLine = 'Code.exe --type=renderer'; CreationUtc = $b4T0 },
                [pscustomobject]@{ Pid = 301; Name = 'node.exe'; ParentPid = 4; CommandLine = 'node.exe server.js'; CreationUtc = $b4T0 },
                [pscustomobject]@{ Pid = 400; Name = 'claude.exe'; ParentPid = 4; CommandLine = $null; CreationUtc = $b4T0.AddMinutes(1) }) }
        $r = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $c -ProviderHints @($cdHints) -LegacySnapshot $legacy
        $f = { param([long]$ProcId, $Created) @($r.Findings | Where-Object { $_.Key -ceq (& $b4Key $ProcId $Created) })[0] }
        Assert-True ((& $f 100 $b4T0).State -ceq 'AGENT_PROCESS' -and (& $f 100 $b4T0).Provider -ceq 'claude-desktop' -and @((& $f 100 $b4T0).Evidence | Where-Object { $_.Code -ceq 'PROCESS_MATCHER_MARKER' }).Count -eq 1) 'processo principal do pacote: AGENT_PROCESS do claude-desktop pelo marcador'
        Assert-True ((& $f 101 $b4T0.AddSeconds(5)).Provider -ceq 'claude-desktop') 'processo auxiliar do pacote: claude-desktop'
        $helper = & $f 200 $b4T0.AddSeconds(9)
        Assert-True ($null -eq $helper -or @($helper.Evidence | Where-Object { $_.Code -ceq 'PROCESS_MATCHER_MARKER' }).Count -eq 0) 'auxiliar claude.exe do perfil: nunca casado pelo marcador do pacote'
        Assert-True ($null -eq (& $f 300 $b4T0) -and $null -eq (& $f 301 $b4T0)) 'Electron e Node alheios: nenhum achado'
        Assert-True (@((& $b4State $r (& $b4Key 400 $b4T0.AddMinutes(1)))) -notcontains 'AGENT_PROCESS' -and @(@($r.Coverage | Where-Object { $_.Collector -eq 'agent-processes' })[0].Reasons) -contains 'COMMAND_LINE_MARKER_UNAVAILABLE') 'linha de comando indisponivel: nunca atribuido, lacuna declarada'
        Assert-True (@($r.Findings | Where-Object { $_.Key -ceq ($script:AtmUnverifiedKeyPrefix + '500') -and $_.State -ceq 'IDENTITY_UNVERIFIED' }).Count -eq 1) 'sem horario de criacao: identidade inconclusiva'
        $both = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $c -ProviderHints @($ccHints, $cdHints) -LegacySnapshot $legacy
        $m = @($both.Findings | Where-Object { $_.Key -ceq (& $b4Key 100 $b4T0) })[0]
        $amb = @($m.Evidence | Where-Object { $_.Code -ceq 'PROVIDER_ATTRIBUTION_AMBIGUOUS' } | ForEach-Object { $_.Detail })
        Assert-True ($null -eq $m.Provider -and ($amb -join ';') -ceq 'claude-code,claude-desktop') 'Claude Code (imagem) e Claude Desktop (marcador): atribuicao ambigua, nunca escolhida'
        # Review P2-C: a command line that cannot be read (no V0.1 snapshot) leaves the marker unchecked; the process is
        # then still ambiguous, never resolved to the provider that did not need the command line.
        $nocl = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $c -ProviderHints @($ccHints, $cdHints)
        $n = @($nocl.Findings | Where-Object { $_.Key -ceq (& $b4Key 100 $b4T0) })[0]
        Assert-True ($null -eq $n.Provider -and (@($n.Evidence | Where-Object { $_.Code -ceq 'PROVIDER_ATTRIBUTION_AMBIGUOUS' } | ForEach-Object { $_.Detail }) -join ';') -ceq 'claude-code,claude-desktop' -and @($n.Evidence | Where-Object { $_.Code -ceq 'COMMAND_LINE_MARKER_UNAVAILABLE' }).Count -eq 1) 'linha de comando ilegivel: ambigua (claude-code,claude-desktop), nunca so claude-code'
        $ccOnly = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection $c -ProviderHints @($ccHints)
        Assert-Eq @($ccOnly.Findings | Where-Object { $_.Key -ceq (& $b4Key 100 $b4T0) })[0].Provider 'claude-code' 'so Claude Code: atribuicao inalterada'
    }
    Test-Case 'Claude Desktop' 'P2-C: servico CoworkVMService - em execucao com processo verificado (Cowork local), parado (instalado sem executar), em execucao sem processo vinculado, nao listado (UNKNOWN), negado; dois providers declarando o mesmo servico' {
        $coll = & $svcProcs @((& $svcPRow 4 $svcT0.AddHours(-1)), (& $svcPRow 6100 $svcT0.AddMinutes(-20)))
        $run = & $svcRun $cdHints @((& $svcRow 'CoworkVMService' 'Running' 'Auto' $false 'LocalSystem' 6100 "`"C:\Program Files\WindowsApps\Claude_1.2.3.0_x64__pzs8sxrjxfjjc\cowork-svc.exe`"")) $coll
        $f = @($run.Findings)[0]
        Assert-True ($f.Key -ceq 'CoworkVMService' -and $f.State -ceq 'RUNNING' -and $f.Provider -ceq 'claude-desktop' -and (& $svcEv $f 'SERVICE_HINT')[0] -ceq 'claude-desktop:cowork-vm' -and (& $svcEv $f 'SERVICE_PROCESS_VERIFIED').Count -eq 1) 'em execucao com processo verificado: evidencia positiva de servico local do Cowork'
        Assert-True ((& $svcEv $f 'SERVICE_EXECUTABLE_NAME')[0] -ceq 'cowork-svc.exe' -and (& $svcEv $f 'SERVICE_EXECUTABLE').Count -eq 0) 'pasta de pacote (WindowsApps, com a versao instalada): so o nome do executavel'
        $stopped = & $svcRun $cdHints @((& $svcRow 'CoworkVMService' 'Stopped' 'Manual' $false 'LocalSystem' 0)) $coll
        Assert-True (@($stopped.Findings)[0].State -ceq 'STOPPED' -and (& $svcEv @($stopped.Findings)[0] 'SERVICE_START_MODE')[0] -ceq 'MANUAL') 'parado (instalado, nao executando)'
        $nolink = & $svcRun $cdHints @((& $svcRow 'CoworkVMService' 'Running' 'Auto' $false 'LocalSystem' 0)) $coll
        Assert-True (@($nolink.Findings)[0].State -ceq 'RUNNING' -and (& $svcEv @($nolink.Findings)[0] 'SERVICE_PROCESS_UNVERIFIED')[0] -ceq 'PID_NOT_REPORTED') 'em execucao sem processo vinculado'
        $absent = & $svcRun $cdHints @() $coll
        Assert-True (@($absent.Findings)[0].State -ceq 'UNKNOWN' -and @($absent.Findings)[0].RequestedState -ceq 'UNKNOWN' -and (& $svcCov $absent 'services').Status -ceq 'PARTIAL') 'nao listado (Cowork remoto ou instalacao .exe): UNKNOWN, nunca "nao instalado"'
        $den = Get-AtmServiceFindings -Query (Invoke-AtmServiceQuery -ProviderHints @($cdHints) -Source { param($Names) throw (New-Object UnauthorizedAccessException('x')) })
        Assert-True (@($den.Findings)[0].State -ceq 'UNKNOWN' -and (& $svcCov $den 'services').Status -ceq 'DENIED') 'acesso negado: UNKNOWN, DENIED'
        $other = & $svcHints 'other-agent' @((& $svcHint 'coworkvmservice'))
        $ov = & $svcRun @($cdHints, $other) @((& $svcRow 'CoworkVMService' 'Running')) $coll
        Assert-True ($null -eq @($ov.Findings)[0].Provider -and (& $svcEv @($ov.Findings)[0] 'PROVIDER_ATTRIBUTION_AMBIGUOUS')[0] -ceq 'claude-desktop,other-agent') 'dois providers: ambiguo'
    }
    Test-Case 'Claude Desktop' 'P2-C: virtualizacao - vmmem e vmwp sem vinculo ao provider, VM utilitaria do Cowork ausente de Msvm_ComputerSystem, virtualizacao negada ou indisponivel; nenhuma atribuicao ao Claude Desktop' {
        $prow = @((& $vPRow 4 0 'System' $vT0.AddHours(-2)), (& $vPRow 700 4 'vmwp.exe' $vT0.AddMinutes(-10)), (& $vPRow 800 4 'vmmem' $vT0.AddMinutes(-9)), (& $vPRow 6100 4 'cowork-svc.exe' $vT0.AddMinutes(-20)))
        $coll = & $vColl $prow
        $r = & $vRun (& $vBase @($vHostRow)) $coll @($cdHints)
        $pf = & $vPlat $r
        Assert-True ((& $vVms $r).Count -eq 0 -and (& $vEv $pf 'VIRTUALIZATION_WORKER').Count -eq 2 -and $null -eq $pf.Provider) 'VM utilitaria (HCS) nao listada; vmmem e vmwp observados, nunca atribuidos'
        Assert-True (@($r.Findings | Where-Object { $_.Provider -ceq 'claude-desktop' }).Count -eq 0 -and (& $vEv $pf 'VM_HINT_NOT_OBSERVED').Count -eq 0) 'nenhum achado de virtualizacao do claude-desktop (sem hint de virtualizacao)'
        $den = (& $vBase); $den.Vms = { throw (New-Object UnauthorizedAccessException('x')) }
        $rd = & $vRun $den $coll @($cdHints)
        Assert-True ((& $vCov $rd 'virtual-machines').Status -ceq 'DENIED' -and @($rd.Findings | Where-Object { $_.Provider -ceq 'claude-desktop' }).Count -eq 0) 'virtualizacao negada: nada atribuido'
        $none = (& $vBase); $none.NamespaceRoot = @(); $none.Vmms = @()
        $rn = & $vRun $none $coll @($cdHints)
        Assert-True ((& $vPlat $rn).State -ceq 'UNKNOWN' -and (& $vCov $rn 'virtual-machines').Status -ceq 'NOT_OBSERVABLE') 'Hyper-V nao listado (so Virtual Machine Platform): plataforma UNKNOWN, VMs nao observaveis, nunca "sem virtualizacao"'
    }
    Test-Case 'Claude Desktop' 'P2-C: integracao ao diagnose - provider listado, servico e virtualizacao, prazo, privacidade do JSON e relatorio (sem argumentos nem conta)' {
        $p = New-TestProfile 'p2c-int'
        $null = New-TestRoot -ProfileInfo $p
        $procRows = @([pscustomobject]@{ ProcessId = 4; ParentProcessId = 0; Name = 'System'; CreationDate = [datetime]::UtcNow.AddHours(-2) }, [pscustomobject]@{ ProcessId = 6100; ParentProcessId = 4; Name = 'cowork-svc.exe'; CreationDate = [datetime]::UtcNow.AddHours(-1) }, [pscustomobject]@{ ProcessId = 800; ParentProcessId = 4; Name = 'vmmem'; CreationDate = [datetime]::UtcNow.AddHours(-1) })
        $svc = @(& $svcRow 'CoworkVMService' 'Running' 'Auto' $false 'CORPDOM\p2c-acct' 6100 "`"C:\Program Files\WindowsApps\Claude_1.2.3.0_x64__pzs8sxrjxfjjc\cowork-svc.exe`" --token=p2c-secret")
        $d = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p)) -IdentitySource $diagIdUser -Providers @((Get-AtmProviders)[0], $cdProvider) -ProcessSource ({ $procRows }.GetNewClosure()) -CpuSampleMs 0 -PseudonymKey $testPseudonymKey -ServiceSource ({ param($Names) $svc }.GetNewClosure()) -VirtualizationSource (& $vSrc (& $vBase @($vHostRow)))
        Assert-True ((@($d.Providers | ForEach-Object { $_.Id }) -join ',') -ceq 'claude-code,claude-desktop' -and @($d.Coverage | Where-Object { $_.Collector -ceq 'provider-claude-desktop' -and $_.Status -ceq 'COMPLETE' }).Count -eq 1) 'provider claude-desktop listado, dicas lidas'
        $sf = @($d.Findings | Where-Object { $_.Kind -ceq 'Service' })
        Assert-True ($sf.Count -eq 1 -and $sf[0].Provider -ceq 'claude-desktop' -and $sf[0].State -ceq 'RUNNING' -and (& $svcEv $sf[0] 'SERVICE_PROCESS_VERIFIED').Count -eq 1) 'CoworkVMService no diagnose, processo verificado'
        Assert-True (@($d.Findings | Where-Object { ($_.Kind -ceq 'VirtualMachine' -or $_.Kind -ceq 'VirtualizationPlatform') -and $_.Provider }).Count -eq 0) 'virtualizacao sem atribuicao'
        Assert-True (@($d.Findings | Where-Object { $_.Kind -ceq 'TempPartition' -and ($_.State -ceq 'NO_DEPENDENCY_OBSERVED' -or $_.State -ceq 'RUNTIME_NOT_DIAGNOSED' -or ($_.State -ceq 'IN_USE' -and @($_.Evidence | Where-Object { $_.Code -ceq 'GRAPH_SOURCE_DIRECT' }).Count -eq 0)) }).Count -eq 0) 'nenhuma particao declarada descartavel (IN_USE so com fonte direta)'
        $json = ConvertTo-AtmDiagnoseJson -Result $d
        $txt = (Show-AtmDiagnose -Result $d 6>&1 | ForEach-Object { [string]$_ }) -join "`n"
        foreach ($x in @('p2c-secret', '--token', 'p2c-acct', 'CORPDOM')) { Assert-True (-not $json.Contains($x) -and -not $txt.Contains($x)) "JSON e relatorio sem '$x'" }
        Assert-True ($txt.Contains('CoworkVMService') -and $txt.Contains('claude-desktop')) 'relatorio mostra o servico e o provider'
        $calls = @{ N = 0 }
        $d0 = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p)) -IdentitySource $diagIdUser -Providers @((Get-AtmProviders)[0], $cdProvider) -DeadlineSeconds 0 -ServiceSource ({ param($Names) $calls.N++; @() }.GetNewClosure())
        Assert-True ($calls.N -eq 0 -and @($d0.Coverage | Where-Object { $_.Collector -ceq 'services' -and $_.Status -ceq 'TIMEOUT' }).Count -eq 1 -and @($d0.Findings).Count -eq 0) 'prazo 0: nada consultado, nada inventado'
    }
    Test-Case 'Claude Desktop' 'P2-C (runner de CI, somente leitura): servico CoworkVMService e processos do pacote na maquina real; sem Claude Desktop instalado: NAO_TESTADO' {
        if ($env:GITHUB_ACTIONS -ne 'true') { $script:caseSkipped = $true; $script:caseNote = 'somente em runner de CI (consulta real, somente leitura)'; return }
        $q = Invoke-AtmServiceQuery -ProviderHints @($cdHints)
        $r = Get-AtmServiceFindings -Query $q -Collection (Get-AtmProcessCollection)
        $f = @($r.Findings)[0]
        Assert-True ($f.State -cne 'NOT_PRESENT' -and $f.RequestedState -cne 'NOT_PRESENT') 'nunca NOT_PRESENT'
        if (@($f.Evidence | Where-Object { $_.Code -ceq 'SERVICE_STATE' }).Count -eq 0) { $script:caseSkipped = $true; $script:caseNote = "Claude Desktop nao instalado no runner: CoworkVMService $($f.State) ($($q.Coverage.Status)); instalacao real NAO_TESTADA"; return }
        $script:caseNote = "CoworkVMService $($f.State)"
    }
    # ------------------------------------------------------------------ P4-A (dependency graph, ADR-0002)
    # Synthetic findings and process rows only; no gate is opened and no collector runs inside the graph.
    $gRows = { param([object[]]$R) $rr = @($R); Get-AtmProcessCollection -Source ({ $rr }.GetNewClosure()) }
    $gCov = New-AtmCoverage -Collector 'inventory' -Status 'COMPLETE'
    $gF = { param([string]$Kind, [string]$Key, [string]$State, $Ev = @(), $Prov = $null) New-AtmFinding -Kind $Kind -Key $Key -State $State -Evidence @($Ev) -Coverage @($gCov) -Provider $Prov }
    $gE = { param([string]$Code, $Detail = $null, [string]$Collector = 'diagnose') New-AtmEvidence -Code $Code -Source 'diagnose' -Collector $Collector -Detail $Detail }
    $gEdges = { param($G) return , @($G.Edges | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.Relation, $_.From, $_.To, $_.Strength }) }
    $gSum = { param($G, [string]$Key) @($G.Summaries | Where-Object { $_.Key -ceq $Key })[0] }
    $gCovAll = @(@('inventory', 'processes', 'process-snapshot', 'handles', 'process-cwd', 'worktree-discovery') | ForEach-Object { New-AtmCoverage -Collector $_ -Status 'COMPLETE' })
    $gKf = { param($Provider, $Path) 'claude-code/p-' + ([string]$Path).Substring(([string]$Path).LastIndexOf('\') + 1) }
    $gPart = { param([string]$Leaf, [string[]]$Direct = @(), [string[]]$Ancestor = @(), [string[]]$Ambiguous = @()) [pscustomobject]@{ Provider = 'claude-code'; Path = "D:\t\$Leaf"; Kind = 'SessionRoot'; DirectRefs = @($Direct); AncestorRefs = @($Ancestor); AmbiguousRefs = @($Ambiguous) } }
    $gLegacy = { param([object[]]$Rows) [pscustomobject]@{ Failed = $false; Processes = @($Rows | ForEach-Object { [pscustomobject]@{ Pid = $_.ProcessId; Name = $_.Name; ParentPid = $_.ParentProcessId; CommandLine = 'x'; CreationUtc = $_.CreationDate } }) } }
    $gK = { param([long]$P, $C) ConvertTo-AtmProcessKey -ProcessId $P -CreationUtc $C }
    $gBase = @((& $b4Row 4 0 'System' $b4T0.AddHours(-1)), (& $b4Row 100 4 'claude.exe' $b4T0), (& $b4Row 101 100 'bash.exe' $b4T0.AddMinutes(1)), (& $b4Row 102 101 'node.exe' $b4T0.AddMinutes(2)))
    $gProcF = @((& $gF 'Process' (& $gK 100 $b4T0) 'AGENT_PROCESS' @() 'claude-code'), (& $gF 'Process' (& $gK 101 $b4T0.AddMinutes(1)) 'AGENT_DESCENDANT'), (& $gF 'Process' (& $gK 102 $b4T0.AddMinutes(2)) 'AGENT_DESCENDANT'))
    Test-Case 'Grafo' 'P4-A: processos - pai e filho verificados, PID reutilizado, identidade inconclusiva, SELF excluido, ciclo protegido' {
        $rows = @($gBase) + @((& $b4Row 300 100 'late.exe' $b4T0.AddMinutes(-30)), (& $b4Row 400 100 'atm.exe' $b4T0.AddMinutes(3)), (& $b4Row 500 501 'a.exe' $b4T0.AddMinutes(5)), (& $b4Row 501 500 'b.exe' $b4T0.AddMinutes(5)), (& $b4Row 600 100 'nodate.exe' $null))
        $c = & $gRows $rows
        $f = @($gProcF) + @((& $gF 'Process' (& $gK 300 $b4T0.AddMinutes(-30)) 'AGENT_DESCENDANT'), (& $gF 'Process' (& $gK 400 $b4T0.AddMinutes(3)) 'SELF' @() 'claude-code'), (& $gF 'Process' (& $gK 500 $b4T0.AddMinutes(5)) 'AGENT_DESCENDANT'), (& $gF 'Process' (& $gK 501 $b4T0.AddMinutes(5)) 'AGENT_DESCENDANT'), (& $gF 'TempPartition' 'claude-code/p-cyc' 'RUNTIME_NOT_DIAGNOSED'), (& $gF 'TempPartition' 'claude-code/p-nd' 'RUNTIME_NOT_DIAGNOSED'))
        $parts = @((& $gPart 'cyc' @('PID 500 (a.exe)')), (& $gPart 'nd' @('PID 600 (nodate.exe)')))
        $g = Get-AtmDependencyGraph -Findings $f -Collection $c -LegacySnapshot (& $gLegacy $rows) -Partitions $parts -PartitionKeyFunction $gKf -Coverage @($gCov)
        $e = & $gEdges $g
        Assert-True ($e -contains ('PARENT_OF|' + (& $gK 100 $b4T0) + '|' + (& $gK 101 $b4T0.AddMinutes(1)) + '|DIRECT') -and $e -contains ('PARENT_OF|' + (& $gK 101 $b4T0.AddMinutes(1)) + '|' + (& $gK 102 $b4T0.AddMinutes(2)) + '|DIRECT')) 'pai e filho verificados: PARENT_OF DIRECT'
        Assert-True (@($e | Where-Object { $_ -like ('PARENT_OF|*|' + (& $gK 300 $b4T0.AddMinutes(-30)) + '|*') }).Count -eq 0) 'pai criado depois do filho (PID reutilizado): nenhuma aresta'
        Assert-True (@($e | Where-Object { $_.Contains((& $gK 400 $b4T0.AddMinutes(3))) }).Count -eq 0) 'SELF: nenhuma aresta (nem atribuicao)'
        Assert-True ((& $gSum $g 'claude-code/p-nd').Dependency -ceq 'DEPENDENCY_AMBIGUOUS' -and $e -contains 'REFERENCES_PATH|pid:600|claude-code/p-nd|AMBIGUOUS' -and @($g.Coverage.Reasons) -ccontains 'REFERENCE_IDENTITY_UNVERIFIED') 'identidade inconclusiva: so aresta AMBIGUOUS de pid:N, nunca DIRECT'
        Assert-True ((& $gSum $g 'claude-code/p-cyc').Dependency -ceq 'DEPENDENCY_OBSERVED' -and @($e | Where-Object { $_ -like 'PARENT_OF|500@*|501@*' -or $_ -like 'PARENT_OF|501@*|500@*' }).Count -eq 2) 'ciclo de vinculos verificados: percorrido com protecao, termina'
        Assert-True ($e -contains ('ATTRIBUTED_TO|' + (& $gK 100 $b4T0) + '|claude-code|DIRECT')) 'atribuicao do processo ao provider'
    }
    Test-Case 'Grafo' 'P4-A: caminhos e transitividade - referencia direta, ancestral, ambigua, caminhos convergentes, colisao de chave, cobertura incompleta e conclusiva' {
        $c = & $gRows $gBase
        $f = @($gProcF) + @(@('a', 'b', 'c', 'd') | ForEach-Object { & $gF 'TempPartition' "claude-code/p-$_" 'RUNTIME_NOT_DIAGNOSED' }) + @((& $gF 'TempPartition' 'claude-code/p-e' 'UNKNOWN' @((& $gE 'PARTITION_KEY_COLLISION' '2' 'inventory'))))
        $parts = @((& $gPart 'a' @('PID 102 (node.exe)', 'PID 101 (bash.exe)')), (& $gPart 'b' @() @('PID 102 (node.exe) -> base')), (& $gPart 'c' @() @() @('PID 102 (node.exe) -> unresolved path under the base')), (& $gPart 'd'), (& $gPart 'e' @('PID 102 (node.exe)')))
        $g = Get-AtmDependencyGraph -Findings $f -Collection $c -LegacySnapshot (& $gLegacy $gBase) -Partitions $parts -PartitionKeyFunction $gKf -Coverage @($gCov)
        $a = & $gSum $g 'claude-code/p-a'
        Assert-True ($a.Dependency -ceq 'DEPENDENCY_OBSERVED' -and $a.Strength -ceq 'DIRECT' -and $a.Incoming -eq 2 -and (@($a.Roots) -join ',') -ceq (& $gK 100 $b4T0)) 'referencia direta de um descendente verificado: dependencia observada, raiz do agente pela cadeia; dois caminhos convergentes, uma raiz'
        Assert-True ((& $gSum $g 'claude-code/p-b').Dependency -ceq 'ANCESTOR_REFERENCE' -and (& $gSum $g 'claude-code/p-b').Strength -ceq 'ANCESTOR') 'referencia ancestral: nunca prova uso deste item'
        Assert-True ((& $gSum $g 'claude-code/p-c').Dependency -ceq 'DEPENDENCY_AMBIGUOUS') 'referencia ambigua (texto localizado): AMBIGUOUS'
        Assert-True ((& $gSum $g 'claude-code/p-d').Dependency -ceq 'UNKNOWN' -and @((& $gSum $g 'claude-code/p-d').Reasons) -ccontains 'COVERAGE_INCOMPLETE' -and @((& $gSum $g 'claude-code/p-d').IncompleteCoverage) -ccontains 'process-cwd') 'sem aresta e cobertura incompleta: UNKNOWN, nunca ausencia'
        Assert-True ((& $gSum $g 'claude-code/p-e').Dependency -ceq 'UNKNOWN' -and @((& $gSum $g 'claude-code/p-e').Reasons) -ccontains 'KEY_COLLISION' -and $null -eq (& $gSum $g 'claude-code/p-e').Strength) 'colisao de chave: nenhuma dependencia concluida'
        $full = Get-AtmDependencyGraph -Findings $f -Collection $c -LegacySnapshot (& $gLegacy $gBase) -Partitions $parts -PartitionKeyFunction $gKf -Coverage $gCovAll
        Assert-True ((& $gSum $full 'claude-code/p-d').Dependency -ceq 'NONE_OBSERVED' -and (& $gSum $full 'claude-code/p-a').Dependency -ceq 'DEPENDENCY_OBSERVED') 'cobertura conclusiva em fixture: so entao NONE_OBSERVED; evidencia positiva mantida com cobertura parcial ou completa'
        $pt = Get-AtmDependencyGraph -Findings $f -Collection $c -LegacySnapshot (& $gLegacy $gBase) -Partitions @((& $gPart 'c' @() @() @('PID 102 (node.exe) -> caminho nao resolvido sob a base'))) -PartitionKeyFunction $gKf -Coverage @($gCov)
        Assert-Eq (& $gSum $pt 'claude-code/p-c').Dependency 'DEPENDENCY_AMBIGUOUS' 'referencia ambigua em pt-BR: mesma leitura (so o PID e lido)'
        Assert-True (-not ((ConvertTo-Json -InputObject (ConvertTo-AtmGraphJson -Graph $g) -Depth 8) -match 'node\.exe|bash\.exe|unresolved|D:\\\\t')) 'nenhum texto de referencia, imagem ou caminho no grafo'
    }
    Test-Case 'Grafo' 'P4-A: servicos, sessoes, arquivos abertos e diretorios de trabalho (so fixtures), worktrees e preflight recusado; coletores bloqueados nao produzem arestas' {
        $c = & $gRows $gBase
        $pk = & $gK 100 $b4T0
        $f = @($gProcF) + @(
            (& $gF 'Service' 'AgentSvc' 'RUNNING' @((& $gE 'SERVICE_PROCESS_VERIFIED' '7000@639000000000000000' 'process-snapshot')) 'fake'),
            (& $gF 'Service' 'OtherSvc' 'RUNNING' @((& $gE 'SERVICE_PROCESS_UNVERIFIED' 'CREATED_AFTER_QUERY' 'process-snapshot'))),
            (& $gF 'AgentSession' 'claude-code/s-live' 'LIVE' @((& $gE 'SESSION_PROCESS_KEY' $pk 'sessions-claude-code')) 'claude-code'),
            (& $gF 'AgentSession' 'claude-code/s-old' 'PID_REUSED' @((& $gE 'SESSION_PROCESS_KEY' $pk 'sessions-claude-code')) 'claude-code'),
            (& $gF 'TempPartition' 'claude-code/p-h' 'RUNTIME_NOT_DIAGNOSED' @((& $gE 'FILE_HELD_OPEN' (& $gK 102 $b4T0.AddMinutes(2)) 'handles'))),
            (& $gF 'TempPartition' 'claude-code/p-u' 'RUNTIME_NOT_DIAGNOSED' @((& $gE 'FILE_HELD_OPEN_UNVERIFIED' 'pid:7' 'handles'))),
            (& $gF 'TempPartition' 'claude-code/p-cap' 'RUNTIME_NOT_DIAGNOSED' @((& $gE 'FILE_HELD_OPEN_UNVERIFIED' 'HOLDERS_CAPPED' 'handles'))),
            (& $gF 'TempPartition' 'claude-code/p-w' 'RUNTIME_NOT_DIAGNOSED' @((& $gE 'WORKING_DIRECTORY_IN' (& $gK 101 $b4T0.AddMinutes(1)) 'process-cwd'))),
            (& $gF 'Worktree' 'git/w-1' 'UNKNOWN' @((& $gE 'WORKTREE_REGISTERED' $null 'worktree-discovery'), (& $gE 'IN_REPOSITORY' 'git/r-1' 'worktree-discovery'))),
            (& $gF 'Worktree' 'git/w-2' 'UNKNOWN' @((& $gE 'IN_REPOSITORY' 'git/r-1' 'worktree-discovery'))),
            (& $gF 'Repository' 'git/r-1' 'UNKNOWN'),
            (& $gF 'Repository' 'git/t-1' 'UNKNOWN' @((& $gE 'REPOSITORY_PREFLIGHT_REFUSED' 'CONFIG_INCLUDE' 'worktree-discovery'))))
        $g = Get-AtmDependencyGraph -Findings $f -Collection $c -Coverage @($gCov)
        $e = & $gEdges $g
        Assert-True ($e -contains 'HOSTS_SERVICE|7000@639000000000000000|AgentSvc|DIRECT' -and @($g.Nodes | Where-Object { $_.Key -ceq '7000@639000000000000000' -and -not $_.Finding }).Count -eq 1) 'servico com processo verificado: HOSTS_SERVICE (processo observado, sem achado proprio)'
        Assert-True (@($e | Where-Object { $_ -like 'HOSTS_SERVICE|*|OtherSvc|*' }).Count -eq 0) 'vinculo nao verificado: nenhuma aresta'
        Assert-True ($e -contains ('RUNS_SESSION|' + $pk + '|claude-code/s-live|DIRECT') -and @($e | Where-Object { $_ -like 'RUNS_SESSION|*|claude-code/s-old|*' }).Count -eq 0) 'sessao viva: RUNS_SESSION; sessao antiga ou PID reutilizado: nenhuma'
        Assert-True ((& $gSum $g 'claude-code/p-h').Dependency -ceq 'DEPENDENCY_OBSERVED' -and $e -contains ('HOLDS_HANDLE_IN|' + (& $gK 102 $b4T0.AddMinutes(2)) + '|claude-code/p-h|DIRECT')) 'arquivo aberto (fixture): HOLDS_HANDLE_IN e dependencia observada'
        Assert-True ((& $gSum $g 'claude-code/p-u').Dependency -ceq 'DEPENDENCY_AMBIGUOUS' -and (& $gSum $g 'claude-code/p-cap').Dependency -ceq 'DEPENDENCY_AMBIGUOUS' -and @((& $gSum $g 'claude-code/p-cap').Reasons) -ccontains 'HOLDERS_CAPPED') 'detentor nao verificado ou acima do limite: AMBIGUOUS, nunca livre'
        Assert-True ($e -contains ('WORKING_DIRECTORY_IN|' + (& $gK 101 $b4T0.AddMinutes(1)) + '|claude-code/p-w|DIRECT') -and @((& $gSum $g 'claude-code/p-w').Roots) -ccontains $pk) 'diretorio de trabalho (so fixture): aresta e raiz do agente'
        Assert-True ($e -contains 'WORKTREE_OF|git/w-1|git/r-1|DIRECT' -and $e -contains 'WORKTREE_OF|git/w-2|git/r-1|AMBIGUOUS' -and @($e | Where-Object { $_.Contains('git/t-1') }).Count -eq 0) 'worktree registrada: DIRECT; sem registro: AMBIGUOUS; repositorio recusado: nenhuma aresta'
        Assert-True ($script:AtmHandleDiagnosticsEnabled -eq $false -and $script:AtmWorktreeDiagnosticsEnabled -eq $false) 'travas seguem fechadas'
        $rt = Get-AtmAgentRuntimeFindings -Pseudonymizer $b4Pz -Collection (& $gRows $gBase) -ProviderHints @((& $b4Hints 'claude-code' @([pscustomobject]@{ ImageName = 'claude.exe'; CommandLineMarker = $null }))) -SessionRegistries @([pscustomobject]@{ ProviderId = 'claude-code'; Registry = [pscustomobject]@{ Readable = $true; Unparseable = 0; Entries = @([pscustomobject]@{ SessionId = 's1'; Pid = 100; StartUtc = $b4T0 }) }; Error = $null })
        $ses = @($rt.Findings | Where-Object { $_.Kind -ceq 'AgentSession' })[0]
        Assert-True ($ses.State -ceq 'LIVE' -and @($ses.Evidence | Where-Object { $_.Code -ceq 'SESSION_PROCESS_KEY' -and $_.Detail -ceq $pk }).Count -eq 1) 'sessao viva produz SESSION_PROCESS_KEY com a chave do processo'
    }
    Test-Case 'Grafo' 'P4-A: virtualizacao e providers - VM com worker verificado sem aresta inventada, vmmem sem atribuicao, CoworkVMService sem VM, atribuicao ambigua Claude Code/Desktop nunca exclusiva' {
        $c = & $gRows $gBase
        $amb = & $gF 'Process' (& $gK 100 $b4T0) 'AGENT_PROCESS' @((& $gE 'PROVIDER_ATTRIBUTION_AMBIGUOUS' 'claude-code,claude-desktop' 'agent-processes'))
        $f = @($amb, (& $gF 'Process' (& $gK 101 $b4T0.AddMinutes(1)) 'AGENT_DESCENDANT'), (& $gF 'Process' (& $gK 102 $b4T0.AddMinutes(2)) 'AGENT_DESCENDANT'),
            (& $gF 'VirtualMachine' 'vm/v-1' 'RUNNING' @((& $gE 'VM_WORKER_VERIFIED' '7100@639000000000000000' 'virtualization-processes')) 'fake-virt'),
            (& $gF 'VirtualMachine' 'vm/v-2' 'RUNNING' @((& $gE 'VM_UNATTRIBUTED' $null 'virtual-machines'))),
            (& $gF 'VirtualizationPlatform' 'host' 'PRESENT' @((& $gE 'VIRTUALIZATION_WORKER' 'VMMEM|7200@639000000000000000' 'virtualization-processes'))),
            (& $gF 'Service' 'CoworkVMService' 'RUNNING' @((& $gE 'SERVICE_PROCESS_VERIFIED' '7300@639000000000000000' 'process-snapshot')) 'claude-desktop'),
            (& $gF 'TempPartition' 'claude-code/p-a' 'RUNTIME_NOT_DIAGNOSED'))
        $g = Get-AtmDependencyGraph -Findings $f -Collection $c -LegacySnapshot (& $gLegacy $gBase) -Partitions @((& $gPart 'a' @('PID 102 (node.exe)'))) -PartitionKeyFunction $gKf -Coverage @($gCov)
        $e = & $gEdges $g
        Assert-True (@($e | Where-Object { $_.Contains('7100@') }).Count -eq 0 -and $e -contains 'ATTRIBUTED_TO|vm/v-1|fake-virt|DIRECT') 'VM com worker verificado: nenhuma relacao VM-worker inventada (proposta na ADR-0002); atribuicao da VM mantida'
        Assert-True (@($e | Where-Object { $_.Contains('7200@') -or $_.Contains('|host|') }).Count -eq 0) 'vmmem e plataforma: contexto, nunca aresta'
        Assert-True (@($e | Where-Object { $_.Contains('vm/v-2|') -and $_ -like 'ATTRIBUTED_TO*' }).Count -eq 0) 'VM sem cadeia verificada: nenhuma atribuicao'
        Assert-True ($e -contains 'HOSTS_SERVICE|7300@639000000000000000|CoworkVMService|DIRECT' -and $e -contains 'ATTRIBUTED_TO|CoworkVMService|claude-desktop|DIRECT' -and @($e | Where-Object { $_.Contains('CoworkVMService') -and ($_.Contains('vm/') -or $_.Contains('p-a')) }).Count -eq 0) 'CoworkVMService: servico e provider, nenhuma VM nem particao ligada'
        Assert-True ($e -contains ('ATTRIBUTED_TO|' + (& $gK 100 $b4T0) + '|claude-code|AMBIGUOUS') -and $e -contains ('ATTRIBUTED_TO|' + (& $gK 100 $b4T0) + '|claude-desktop|AMBIGUOUS') -and @($e | Where-Object { $_ -like ('ATTRIBUTED_TO|' + (& $gK 100 $b4T0) + '|*|DIRECT') }).Count -eq 0) 'atribuicao ambigua: uma aresta AMBIGUOUS por provider, nenhuma exclusiva'
        $sa = & $gSum $g 'claude-code/p-a'
        Assert-True ($sa.Dependency -ceq 'DEPENDENCY_OBSERVED' -and @($sa.PSObject.Properties.Name) -notcontains 'Provider') 'dependencia observada pela cadeia de processos; o resumo nunca nomeia um provider'
    }
    Test-Case 'Grafo' 'P4-A: limites de nos, arestas, profundidade e tempo declarados (evidencia positiva mantida, nunca NONE_OBSERVED); saida deterministica' {
        $c = & $gRows $gBase
        $f = @($gProcF) + @(@('a', 'd') | ForEach-Object { & $gF 'TempPartition' "claude-code/p-$_" 'RUNTIME_NOT_DIAGNOSED' })
        $parts = @((& $gPart 'a' @('PID 102 (node.exe)')), (& $gPart 'd'))
        $args0 = @{ Findings = $f; Collection = $c; LegacySnapshot = (& $gLegacy $gBase); Partitions = $parts; PartitionKeyFunction = $gKf; Coverage = $gCovAll }
        $el = Get-AtmDependencyGraph @args0 -MaxEdges 1
        Assert-True ($el.Coverage.Status -ceq 'PARTIAL' -and @($el.Coverage.Reasons) -ccontains 'GRAPH_EDGE_LIMIT' -and $el.Coverage.DroppedEdges -gt 0 -and @($el.Edges).Count -eq 1 -and (& $gSum $el 'claude-code/p-d').Dependency -ceq 'UNKNOWN') "limite de arestas: declarado, contado, nada NONE_OBSERVED ($($el.Coverage.DroppedEdges) descartadas)"
        $nl = Get-AtmDependencyGraph @args0 -MaxNodes 3
        Assert-True (@($nl.Coverage.Reasons) -ccontains 'GRAPH_NODE_LIMIT' -and (& $gSum $nl 'claude-code/p-d').Dependency -ceq 'UNKNOWN') 'limite de nos: declarado'
        $dl = Get-AtmDependencyGraph @args0 -MaxDepth 1
        Assert-True (@($dl.Coverage.Reasons) -ccontains 'GRAPH_DEPTH_LIMIT' -and (& $gSum $dl 'claude-code/p-a').Dependency -ceq 'DEPENDENCY_OBSERVED' -and (& $gSum $dl 'claude-code/p-d').Dependency -ceq 'UNKNOWN') 'limite de profundidade: positiva mantida, ausencia nao concluida'
        $tl = Get-AtmDependencyGraph @args0 -MaxMs -1
        Assert-True (@($tl.Coverage.Reasons) -ccontains 'GRAPH_TIME_LIMIT' -and @($tl.Summaries | Where-Object { $_.Dependency -ceq 'NONE_OBSERVED' }).Count -eq 0) 'limite de tempo: declarado'
        $j1 = ConvertTo-Json -InputObject (ConvertTo-AtmGraphJson -Graph (Get-AtmDependencyGraph @args0)) -Depth 8
        $args1 = @{} + $args0; $args1.Findings = @($f[($f.Count - 1)..0]); $args1.Partitions = @($parts[($parts.Count - 1)..0])
        $j2 = ConvertTo-Json -InputObject (ConvertTo-AtmGraphJson -Graph (Get-AtmDependencyGraph @args1)) -Depth 8
        Assert-Eq ($j2 -replace '"(startedUtc|elapsedMs)":\s*("[^"]*"|\d+)', '') ($j1 -replace '"(startedUtc|elapsedMs)":\s*("[^"]*"|\d+)', '') 'ordem das entradas invertida: grafo identico'
    }
    Test-Case 'Grafo' 'P4-A (revisao): ordem fixa sob limites, identidade nao verificada nunca DIRECT, raizes so por cadeia DIRECT, motivos de limite e de leitura, pior cobertura por coletor, atribuicao ambigua nunca DIRECT' {
        $c = & $gRows $gBase
        $kd = & $gK 102 $b4T0.AddMinutes(2)
        $f = @($gProcF) + @(@('a', 'b', 'd') | ForEach-Object { & $gF 'TempPartition' "claude-code/p-$_" 'RUNTIME_NOT_DIAGNOSED' })
        $parts = @((& $gPart 'a' @('PID 102 (node.exe)', 'PID 101 (bash.exe)')), (& $gPart 'b' @() @('PID 102 (node.exe) -> base')), (& $gPart 'd'))
        $args0 = @{ Findings = $f; Collection = $c; LegacySnapshot = (& $gLegacy $gBase); Partitions = $parts; PartitionKeyFunction = $gKf; Coverage = $gCovAll }
        $args1 = @{} + $args0; $args1.Findings = @($f[($f.Count - 1)..0]); $args1.Partitions = @($parts[($parts.Count - 1)..0])
        $strip = { param($G) (ConvertTo-Json -InputObject (ConvertTo-AtmGraphJson -Graph $G) -Depth 8) -replace '"(startedUtc|elapsedMs)":\s*("[^"]*"|\d+)', '' }
        foreach ($lim in @(@{ MaxEdges = 1 }, @{ MaxEdges = 3 }, @{ MaxNodes = 6 }, @{ MaxDepth = 1 })) {
            Assert-Eq (& $strip (Get-AtmDependencyGraph @args1 @lim)) (& $strip (Get-AtmDependencyGraph @args0 @lim)) "entrada invertida sob limite ($(@($lim.Keys)[0])=$(@($lim.Values)[0])): grafo identico"
        }
        $g = Get-AtmDependencyGraph @args0
        $b = & $gSum $g 'claude-code/p-b'
        Assert-True ($b.Dependency -ceq 'ANCESTOR_REFERENCE' -and @($b.Roots).Count -eq 0 -and $b.Roots -is [array] -and $b.Reasons -is [array]) 'referencia ancestral: nenhuma raiz (raiz nunca mais forte que a cadeia); listas sempre arrays'
        Assert-Eq (@((& $gSum $g 'claude-code/p-a').Roots) -join ',') (& $gK 100 $b4T0) 'referencia direta: raiz do agente'
        # Depth limit with full coverage: the item without edges has the same reasons wherever it is in the input.
        foreach ($a2 in @($args0, $args1)) {
            $dl = Get-AtmDependencyGraph @a2 -MaxDepth 1
            $d = & $gSum $dl 'claude-code/p-d'
            Assert-True ($d.Dependency -ceq 'UNKNOWN' -and (@($d.Reasons) -join ',') -ceq 'GRAPH_LIMIT' -and @($d.IncompleteCoverage).Count -eq 0) "limite de profundidade: GRAPH_LIMIT (nunca COVERAGE_INCOMPLETE sem coletor incompleto), obtido $(@($d.Reasons) -join ',')"
        }
        # An unverified identity is never a DIRECT source, whatever the evidence says.
        $pf = @((& $gF 'Process' 'pid:777' 'IDENTITY_UNVERIFIED' @() 'claude-code'), (& $gF 'TempPartition' 'claude-code/p-h' 'RUNTIME_NOT_DIAGNOSED' @((& $gE 'FILE_HELD_OPEN' 'pid:778' 'handles'))))
        $ug = Get-AtmDependencyGraph -Findings $pf -Collection $c -Coverage $gCovAll
        $ue = & $gEdges $ug
        Assert-True ($ue -contains 'ATTRIBUTED_TO|pid:777|claude-code|AMBIGUOUS' -and @($ue | Where-Object { $_ -like '*|pid:*|DIRECT' -or $_ -like '*|pid:*|*|DIRECT' }).Count -eq 0) "identidade nao verificada: AMBIGUOUS ($($ue -join ' ; '))"
        Assert-True ((& $gSum $ug 'claude-code/p-h').Dependency -ceq 'DEPENDENCY_AMBIGUOUS') 'arquivo aberto por pid nao verificado: nunca DEPENDENCY_OBSERVED'
        # Evidence that cannot be read as a process reference blocks the absence.
        $rf = @(& $gF 'TempPartition' 'claude-code/p-r' 'RUNTIME_NOT_DIAGNOSED') + @(& $gF 'TempPartition' 'claude-code/p-m' 'RUNTIME_NOT_DIAGNOSED' @((& $gE 'FILE_HELD_OPEN' 'garbage' 'handles')))
        $rg = Get-AtmDependencyGraph -Findings $rf -Collection $c -LegacySnapshot (& $gLegacy $gBase) -Partitions @((& $gPart 'r' @('not a reference'))) -PartitionKeyFunction $gKf -Coverage $gCovAll
        Assert-True ((& $gSum $rg 'claude-code/p-r').Dependency -ceq 'UNKNOWN' -and @((& $gSum $rg 'claude-code/p-r').Reasons) -ccontains 'REFERENCE_UNREADABLE' -and (& $gSum $rg 'claude-code/p-m').Dependency -ceq 'UNKNOWN' -and $rg.Coverage.Status -ceq 'PARTIAL' -and @($rg.Coverage.Reasons) -ccontains 'REFERENCE_UNREADABLE') 'referencia ou detalhe ilegivel: UNKNOWN, declarado'
        $nk = Get-AtmDependencyGraph -Findings @(& $gF 'TempPartition' 'claude-code/p-r' 'RUNTIME_NOT_DIAGNOSED') -Collection $c -LegacySnapshot (& $gLegacy $gBase) -Partitions @((& $gPart 'r')) -PartitionKeyFunction $null -Coverage $gCovAll
        Assert-True ((& $gSum $nk 'claude-code/p-r').Dependency -ceq 'UNKNOWN' -and @((& $gSum $nk 'claude-code/p-r').Reasons) -ccontains 'REFERENCE_UNREADABLE') 'sem funcao de chave: referencias nao lidas, nunca NONE_OBSERVED'
        # Worst record per collector: a later COMPLETE does not hide an earlier FAILED.
        $wc = @((New-AtmCoverage -Collector 'handles' -Status 'FAILED' -Reasons @('QUERY_FAILED'))) + @($gCovAll)
        $wg = Get-AtmDependencyGraph -Findings $f -Collection $c -LegacySnapshot (& $gLegacy $gBase) -Partitions $parts -PartitionKeyFunction $gKf -Coverage $wc
        Assert-True ((& $gSum $wg 'claude-code/p-d').Dependency -ceq 'UNKNOWN' -and @((& $gSum $wg 'claude-code/p-d').IncompleteCoverage) -ccontains 'handles') 'pior registro do coletor: FAILED prevalece sobre COMPLETE'
        # A provider next to an ambiguous attribution: never a DIRECT edge.
        $af = @(& $gF 'Process' $kd 'AGENT_DESCENDANT' @((& $gE 'PROVIDER_ATTRIBUTION_AMBIGUOUS' 'claude-code,claude-desktop')) 'claude-code')
        $ae = & $gEdges (Get-AtmDependencyGraph -Findings $af -Collection $c -Coverage $gCovAll)
        Assert-True ($ae -contains ('ATTRIBUTED_TO|' + $kd + '|claude-code|AMBIGUOUS') -and $ae -contains ('ATTRIBUTED_TO|' + $kd + '|claude-desktop|AMBIGUOUS') -and @($ae | Where-Object { $_ -like 'ATTRIBUTED_TO|*|DIRECT' }).Count -eq 0) 'atribuicao ambigua com provider: nenhuma aresta DIRECT'
    }
    Test-Case 'Grafo' 'P4-A: escala - milhares de processos, particoes e arestas em tempo e memoria limitados (sem O(N^2))' {
        $rows = New-Object System.Collections.Generic.List[object]; $f = New-Object System.Collections.Generic.List[object]; $parts = New-Object System.Collections.Generic.List[object]
        $rows.Add((& $b4Row 4 0 'System' $b4T0.AddHours(-1)))
        for ($i = 0; $i -lt 1000; $i++) {
            $root = 10000 + $i * 5
            for ($j = 0; $j -lt 5; $j++) {
                $pidv = $root + $j; $parent = $(if ($j -eq 0) { 4 } else { $pidv - 1 }); $cr = $b4T0.AddSeconds($i * 10 + $j)
                $rows.Add((& $b4Row $pidv $parent 'w.exe' $cr))
                $f.Add((& $gF 'Process' (& $gK $pidv $cr) $(if ($j -eq 0) { 'AGENT_PROCESS' } else { 'AGENT_DESCENDANT' }) @() $(if ($j -eq 0) { 'claude-code' } else { $null })))
            }
            for ($q = 0; $q -lt 2; $q++) { $f.Add((& $gF 'TempPartition' ("claude-code/p-$i-$q") 'RUNTIME_NOT_DIAGNOSED')); $parts.Add((& $gPart "$i-$q" @("PID $($root + 4) (w.exe)"))) }
        }
        $c = & $gRows $rows.ToArray()
        [GC]::Collect(); $m0 = [GC]::GetTotalMemory($true)
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $g = Get-AtmDependencyGraph -Findings $f.ToArray() -Collection $c -LegacySnapshot (& $gLegacy $rows.ToArray()) -Partitions $parts.ToArray() -PartitionKeyFunction $gKf -Coverage @($gCov)
        $sw.Stop(); $m1 = [GC]::GetTotalMemory($false)
        Assert-True ($g.Coverage.Status -ceq 'COMPLETE' -and $g.Coverage.Edges -eq (4000 + 2000 + 1000) -and @($g.Summaries | Where-Object { $_.Dependency -ceq 'DEPENDENCY_OBSERVED' -and @($_.Roots).Count -eq 1 }).Count -eq 2000) "5000 processos, 2000 particoes: $($g.Coverage.Edges) arestas, todas as particoes com raiz"
        Assert-True ($sw.ElapsedMilliseconds -lt 120000) "tempo limitado ($($sw.ElapsedMilliseconds) ms)"
        $script:caseNote = "5000 processos/2000 particoes/$($g.Coverage.Edges) arestas: $($sw.ElapsedMilliseconds) ms, delta de memoria gerenciada ~$([math]::Round(($m1 - $m0) / 1MB, 1)) MB"
    }
    Test-Case 'Grafo' 'P4-A: integracao ao diagnose - grafo no resultado, JSON (campos do schema) e relatorio sem caminhos; nenhum estado alterado; nunca NONE_OBSERVED numa execucao V0.2' {
        $p = New-TestProfile 'p4a-int'
        $root = New-TestRoot -ProfileInfo $p
        $d = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p)) -IdentitySource $diagIdUser -PseudonymKey $testPseudonymKey -ServiceSource { param($Names) @() } -VirtualizationSource (& $vSrc (& $vBase @($vHostRow)))
        Assert-True ($null -ne $d.Graph -and @($d.Graph.Summaries | Where-Object { $_.Kind -ceq 'TempPartition' }).Count -ge 1) 'grafo no resultado, resumo por particao'
        Assert-True (@($d.Graph.Summaries | Where-Object { $_.Dependency -ceq 'NONE_OBSERVED' }).Count -eq 0 -and @($d.Graph.Summaries | Where-Object { @($_.IncompleteCoverage) -contains 'process-cwd' -and @($_.IncompleteCoverage) -contains 'handles' }).Count -eq @($d.Graph.Summaries).Count) 'diretorios de trabalho e arquivos abertos nao observaveis: nunca NONE_OBSERVED'
        Assert-True (@($d.Findings | Where-Object { $_.Kind -ceq 'TempPartition' -and ($_.State -ceq 'NO_DEPENDENCY_OBSERVED' -or $_.State -ceq 'RUNTIME_NOT_DIAGNOSED' -or ($_.State -ceq 'IN_USE' -and @($_.Evidence | Where-Object { $_.Code -ceq 'GRAPH_SOURCE_DIRECT' }).Count -eq 0)) }).Count -eq 0) 'P4-B: nenhuma particao livre ou sem diagnostico; IN_USE so com fonte direta'
        $json = ConvertTo-AtmDiagnoseJson -Result $d
        $txt = (Show-AtmDiagnose -Result $d 6>&1 | ForEach-Object { [string]$_ }) -join "`n"
        foreach ($x in @($root, $root.Replace('\', '\\'), $p.ProfilePath.Replace('\', '\\'))) { Assert-True (-not $json.Contains($x) -and -not $txt.Contains($x)) 'JSON e relatorio sem caminhos' }
        Assert-True ($txt.Contains((Get-AtmText 'diag.graphTitle')) -and $txt.Contains((Get-AtmText 'diag.graphNoDelete'))) 'relatorio: secao do grafo'
        # The edge fields equal the schema document (a synthetic graph with an edge).
        $doc = [IO.File]::ReadAllLines((Join-Path (Split-Path -Parent $testsDir) 'docs\DIAGNOSE-SCHEMA.md'))
        $sec = @{}; $cur = $null
        foreach ($l in $doc) { if ($l -match '^## (.+)$') { $cur = $Matches[1].Trim(); $sec[$cur] = New-Object System.Collections.Generic.List[string]; continue }; if ($cur -and $l -match '^\| `([A-Za-z][A-Za-z0-9]*)` \|') { $sec[$cur].Add($Matches[1]) } }
        $sg = Get-AtmDependencyGraph -Findings @($gProcF) -Collection (& $gRows $gBase)
        $sj = (ConvertTo-Json -InputObject (ConvertTo-AtmGraphJson -Graph $sg) -Depth 8) | ConvertFrom-Json
        Assert-Eq (@($sj.edges[0].PSObject.Properties.Name | Sort-Object) -join ',') (@($sec['graph.edges[]'] | Sort-Object) -join ',') 'campos de graph.edges[]'
        Assert-Eq (@($sj.edges[0].evidence[0].PSObject.Properties.Name | Sort-Object) -join ',') (@($sec['graph.edges[].evidence[]'] | Sort-Object) -join ',') 'campos de graph.edges[].evidence[]'
    }
    Test-Case 'Grafo' 'P4-A (estatico): o grafo nao chama coletor nem le nada; textos nos dois idiomas; travas fechadas' {
        $diag = [IO.File]::ReadAllText((Join-Path $srcDir 'lib\Engine.Diagnose.ps1'))
        $fn = $diag.Substring($diag.IndexOf('function Get-AtmDependencyGraph'), $diag.IndexOf('# Open-file evidence (D-2') - $diag.IndexOf('function Get-AtmDependencyGraph'))
        foreach ($pat in @('Get-CimInstance', 'Invoke-AtmServiceQuery', 'Invoke-AtmVirtualizationQuery', 'Get-AtmProcessCollection', 'Get-AtmWorktreeDiscovery', 'Get-AtmHandleEvidence', 'Get-AtmHandleSampleFiles', 'Invoke-AtmGitCommand', 'Resolve-AtmGitExecutable', 'AtmRestartManager', '[IO.', 'Get-ChildItem', 'Get-Item', 'Invoke-AtmInventory')) { Assert-True (-not $fn.Contains($pat)) "grafo sem '$pat'" }
        foreach ($l in @('en-US', 'pt-BR')) {
            foreach ($x in $script:AtmGraphReasonCodes) { Assert-True $script:AtmMessages[$l].ContainsKey("reason.$x") "reason.$x ($l)" }
            foreach ($x in $script:AtmGraphDependencies) { Assert-True $script:AtmMessages[$l].ContainsKey("graph.dep.$x") "graph.dep.$x ($l)" }
            Assert-True $script:AtmMessages[$l].ContainsKey('evidence.SESSION_PROCESS_KEY') "evidence.SESSION_PROCESS_KEY ($l)"
        }
        Assert-True ($script:AtmRealDeletionEnabled -eq $true -and $shippedDeletionGate -eq $false -and $script:AtmHandleDiagnosticsEnabled -eq $false -and $script:AtmWorktreeDiagnosticsEnabled -eq $false) 'travas distribuidas fechadas (a suite so abre a de exclusao no proprio processo)'
    }
    # ------------------------------------------------------------------ P4-B (temporary partitions and runtime evidence)
    # Graph summaries to finding states (synthetic findings; the P4-A helpers above) and profile discovery through an
    # injected source (fake registry keys: no real profile, registry key, ACL or temporary folder is touched).
    $bState = { param($Fs, $Cov = $gCovAll, $Parts = @(), $Rows = $null, [hashtable]$Lim = @{})
        $r0 = $(if ($null -ne $Rows) { @($Rows) } else { @($gBase) })
        $g = Get-AtmDependencyGraph -Findings @($Fs) -Collection (& $gRows $r0) -LegacySnapshot (& $gLegacy $r0) -Partitions @($Parts) -PartitionKeyFunction $gKf -Coverage @($Cov) @Lim
        $gc = ConvertTo-AtmGraphCoverage -Graph $g
        [pscustomobject]@{ Graph = $g; Findings = (Set-AtmGraphFindingStates -Findings @($Fs) -Graph $g -Coverage @($Cov) -GraphCoverage $gc) } }
    $bFind = { param($R, [string]$Key) @($R.Findings | Where-Object { $_.Key -ceq $Key })[0] }
    $bEv = { param($F, [string]$Code) return , [string[]]@(@($F.Evidence) | Where-Object { $_.Code -ceq $Code } | ForEach-Object { [string]$_.Detail }) }
    $bTp = { param([string]$Leaf, $Ev = @()) & $gF 'TempPartition' "claude-code/p-$Leaf" 'RUNTIME_NOT_DIAGNOSED' $Ev 'claude-code' }
    $bCovNo = @(@('inventory', 'processes', 'process-snapshot', 'worktree-discovery') | ForEach-Object { New-AtmCoverage -Collector $_ -Status 'COMPLETE' }) + @(@('handles', 'process-cwd') | ForEach-Object { New-AtmCoverage -Collector $_ -Status 'NOT_OBSERVABLE' -Reasons @('GATE') })
    # A fake registry key: values (a scriptblock value throws when read), sub keys (a scriptblock opens or throws) and,
    # for HKU, the names of the loaded hives. It has no write member: a write would fail the test.
    $bKey = { param([hashtable]$Values = @{}, [hashtable]$Subs = @{}, $Names = $null, [bool]$ThrowNames = $false)
        $o = [pscustomobject]@{ V = $Values; S = $Subs; N = $Names; T = $ThrowNames }
        $o | Add-Member -MemberType ScriptMethod -Name GetValue -Value { param($n, $d, $opt) $v = $this.V[$n]; if ($v -is [scriptblock]) { & $v } elseif ($null -eq $v) { $d } else { $v } }
        $o | Add-Member -MemberType ScriptMethod -Name GetValueNames -Value { [string[]]@($this.V.Keys) }
        $o | Add-Member -MemberType ScriptMethod -Name GetSubKeyNames -Value { if ($this.T) { throw 'denied' }; if ($null -ne $this.N) { [string[]]@($this.N) } else { [string[]]@($this.S.Keys) } }
        $o | Add-Member -MemberType ScriptMethod -Name OpenSubKey -Value { param($n) $x = $this.S[$n]; if ($x -is [scriptblock]) { & $x } else { $x } }
        $o | Add-Member -MemberType ScriptMethod -Name Close -Value { }
        $o }
    $bSidA = 'S-1-5-21-7-8-9-2001'; $bSidB = 'S-1-5-21-7-8-9-2002'; $bSidC = 'S-1-5-21-7-8-9-2003'
    $bSource = { param([hashtable]$Opt = @{})
        $pl = @{}
        foreach ($sd in @($bSidA, $bSidB, $bSidC)) { $pl[$sd] = (& $bKey @{ ProfileImagePath = ('C:\Users\' + @{ $bSidA = 'alice'; $bSidB = 'x'; $bSidC = 'nome' }[$sd]) }) }
        if ($Opt.ContainsKey('NullEntry')) { $pl['S-1-5-21-7-8-9-2009'] = { $null } }
        $plv = @{ ProfilesDirectory = 'C:\Users'; Public = 'C:\Users\Public'; Default = 'C:\Users\Default' }
        if ($Opt.ContainsKey('PdThrows')) { $plv['ProfilesDirectory'] = { throw 'denied' } }
        if ($Opt.ContainsKey('PdMissing')) { $plv.Remove('ProfilesDirectory') }
        $plKey = $(if ($Opt.ContainsKey('PlNull')) { $null } else { & $bKey $plv $pl })
        $users = @{}
        $users["$bSidA\Environment"] = (& $bKey @{ TEMP = '%USERPROFILE%\AppData\Local\Temp' })
        $users["$bSidA\Volatile Environment"] = $(if ($Opt.ContainsKey('VolThrows')) { { throw 'SECRET-volatile-message' } } else { & $bKey @{ LOCALAPPDATA = 'C:\Users\alice\AppData\Local' } })
        $users["$bSidB\Environment"] = { throw 'denied' }
        $hku = & $bKey @{} $users @($bSidA, $bSidB) ([bool]$Opt.ContainsKey('HivesThrow'))
        $dirs = @([pscustomobject]@{ Name = 'alice'; FullName = 'C:\Users\alice'; Attributes = [IO.FileAttributes]::Directory }, [pscustomobject]@{ Name = 'U'; FullName = 'C:\Users\U'; Attributes = [IO.FileAttributes]::Directory },
            [pscustomobject]@{ Name = 'Public'; FullName = 'C:\Users\Public'; Attributes = [IO.FileAttributes]::Directory }, [pscustomobject]@{ Name = 'EXAMPL~1'; FullName = 'C:\Users\EXAMPL~1'; Attributes = ([IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint) })
        $enumThrows = $Opt.ContainsKey('EnumThrows')
        [pscustomobject]@{ LocalMachine = (& $bKey @{} @{ 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' = $plKey }); Users = $hku
            GetDirectories = $(if ($enumThrows) { { param($Path) throw [UnauthorizedAccessException]::new('SECRET-enum-message') } } else { { param($Path) $dirs }.GetNewClosure() }) } }
    $bGaps = { @($script:AtmDiscoveryGaps.Keys | Sort-Object) -join ',' }

    Test-Case 'Particoes' 'P4-B: grafo para achado - DIRECT vira IN_USE com proveniencia; ancestral, ambigua e sem arestas ficam UNKNOWN com o motivo; coletores bloqueados; NO_DEPENDENCY_OBSERVED so com cobertura conclusiva (verificada de novo pelo motor)' {
        $f = @($gProcF) + @((& $bTp 'a' @((& $gE 'AUDIT_CLASS' 'ORPHAN_SUSPECTED' 'inventory'), (& $gE 'AUDIT_FLAG' 'OTHER_USER' 'inventory'))), (& $bTp 'b'), (& $bTp 'c'), (& $bTp 'd'))
        $parts = @((& $gPart 'a' @('PID 102 (node.exe)')), (& $gPart 'b' @() @('PID 102 (node.exe) -> base')), (& $gPart 'c' @() @() @('PID 102 (node.exe) -> unresolved')), (& $gPart 'd'))
        $r = & $bState $f $bCovNo $parts
        $a = & $bFind $r 'claude-code/p-a'
        $k102 = & $gK 102 $b4T0.AddMinutes(2)
        Assert-True ($a.State -ceq 'IN_USE' -and (& $bEv $a 'GRAPH_SOURCE_DIRECT') -contains ('REFERENCES_PATH ' + $k102) -and (& $bEv $a 'GRAPH_AGENT_ROOT') -contains (& $gK 100 $b4T0) -and (& $bEv $a 'GRAPH_DEPENDENCY') -contains 'DEPENDENCY_OBSERVED') '1: referencia direta de processo verificado: IN_USE, fonte, raiz do agente'
        Assert-True ((& $bEv $a 'AUDIT_CLASS') -ccontains 'ORPHAN_SUSPECTED' -and (& $bEv $a 'AUDIT_FLAG') -ccontains 'OTHER_USER' -and $a.Evidence[0].Code -ceq 'AUDIT_CLASS' -and $a.Provider -ceq 'claude-code') 'provider e evidencias anteriores (classe e flag V0.1) preservados, na mesma ordem'
        $b = & $bFind $r 'claude-code/p-b'
        Assert-True ($b.State -ceq 'UNKNOWN' -and (& $bEv $b 'GRAPH_DEPENDENCY') -contains 'ANCESTOR_REFERENCE' -and (& $bEv $b 'GRAPH_SOURCE_ANCESTOR').Count -eq 1 -and (& $bEv $b 'GRAPH_AGENT_ROOT').Count -eq 0) '2: referencia ancestral: UNKNOWN, nunca IN_USE, sem raiz'
        $c = & $bFind $r 'claude-code/p-c'
        Assert-True ($c.State -ceq 'UNKNOWN' -and (& $bEv $c 'GRAPH_DEPENDENCY') -contains 'DEPENDENCY_AMBIGUOUS' -and (& $bEv $c 'GRAPH_SOURCE_AMBIGUOUS').Count -eq 1) '3: referencia ambigua: UNKNOWN'
        $d = & $bFind $r 'claude-code/p-d'
        Assert-True ($d.State -ceq 'UNKNOWN' -and (& $bEv $d 'GRAPH_REASON') -contains 'COVERAGE_INCOMPLETE' -and @($d.Coverage | Where-Object { $_.Collector -ceq 'handles' -and $_.Status -ceq 'NOT_OBSERVABLE' }).Count -eq 1 -and @($d.Coverage | Where-Object { $_.Collector -ceq 'dependency-graph' }).Count -eq 1) '4/5: sem arestas, handles e process-cwd bloqueados: UNKNOWN, coberturas anexadas'
        $full = & $bState $f $gCovAll $parts
        Assert-Eq (& $bFind $full 'claude-code/p-d').State 'NO_DEPENDENCY_OBSERVED' 'cobertura conclusiva em fixture: NO_DEPENDENCY_OBSERVED'
        # Backstop: a summary that says NONE_OBSERVED next to a non-conclusive collector still gives UNKNOWN.
        $fake = [pscustomobject]@{ Summaries = @([pscustomobject]@{ Kind = 'TempPartition'; Key = 'claude-code/p-d'; Dependency = 'NONE_OBSERVED'; Strength = $null; Incoming = 0; Roots = [string[]]@(); IncompleteCoverage = [string[]]@(); Reasons = [string[]]@() }); Edges = @(); Coverage = $full.Graph.Coverage }
        $bk = @(Set-AtmGraphFindingStates -Findings @(& $bTp 'd') -Graph $fake -Coverage $bCovNo -GraphCoverage (ConvertTo-AtmGraphCoverage -Graph $full.Graph))[0]
        Assert-True ($bk.State -ceq 'UNKNOWN' -and $bk.RequestedState -ceq 'NO_DEPENDENCY_OBSERVED') 'resumo NONE_OBSERVED com handles NOT_OBSERVABLE: o motor recusa a ausencia'
        $nr = @(Set-AtmGraphFindingStates -Findings @(& $bTp 'd') -Graph $fake -Coverage @() -GraphCoverage (ConvertTo-AtmGraphCoverage -Graph $full.Graph))[0]
        Assert-True ($nr.State -ceq 'UNKNOWN' -and @($nr.Coverage | Where-Object { $_.Status -ceq 'NOT_OBSERVABLE' -and @($_.Reasons) -ccontains 'COLLECTOR_NOT_RUN' }).Count -ge 1) 'coletor que nao rodou: NOT_OBSERVABLE, nunca presumido completo'
        Assert-Eq (@($r.Findings | ForEach-Object { $_.Kind + '|' + $_.Key }) -join ',') (@($f | ForEach-Object { $_.Kind + '|' + $_.Key }) -join ',') 'mesmos achados, mesma ordem (nenhum criado)'
    }
    Test-Case 'Particoes' 'P4-B: worktrees (so fixtures), identidade inconclusiva, PID reutilizado, SELF, atribuicao ambigua, CoworkVMService sem VM, no sem achado, limite, evidencia ilegivel' {
        $k101 = & $gK 101 $b4T0.AddMinutes(1)
        $wt = @((& $gF 'Worktree' 'wt/w-1' 'LOCAL_WORK' @((& $gE 'FILE_HELD_OPEN' $k101 'handles'))), (& $gF 'Worktree' 'wt/w-2' 'LOCAL_WORK' @((& $gE 'FILE_HELD_OPEN_UNVERIFIED' 'pid:9' 'handles'))), (& $gF 'Worktree' 'wt/w-3' 'CLEAN_AND_PUBLISHED_UNKNOWN' @((& $gE 'FILE_HELD_OPEN_UNVERIFIED' 'pid:9' 'handles'))))
        $r = & $bState (@($gProcF) + @($wt)) $gCovAll
        Assert-Eq (& $bFind $r 'wt/w-1').State 'IN_USE' '6: worktree com arquivo aberto (fixture) por processo verificado: IN_USE (regra 14, primeiro)'
        Assert-True ((& $bFind $r 'wt/w-2').State -ceq 'LOCAL_WORK' -and (& $bEv (& $bFind $r 'wt/w-2') 'GRAPH_DEPENDENCY') -contains 'DEPENDENCY_AMBIGUOUS') '7: identidade inconclusiva: fatos proprios mantidos, nunca IN_USE'
        Assert-Eq (& $bFind $r 'wt/w-3').State 'UNKNOWN' '7: evidencia ambigua bloqueia o estado sem dependencia (CLEAN_AND_PUBLISHED_UNKNOWN vira UNKNOWN)'
        $ro = & $bState (@($gProcF) + @(& $gF 'Worktree' 'wt/w-4' 'APPARENT_ORPHAN' @((& $gE 'FILE_HELD_OPEN_UNVERIFIED' 'pid:9' 'handles')))) $gCovAll
        Assert-Eq (& $bFind $ro 'wt/w-4').State 'UNKNOWN' '7: orfao aparente com evidencia ambigua: UNKNOWN (nunca parece livre)'
        # 8: a reference by a PID whose creation time differs in the snapshot (reused PID): never IN_USE.
        $legacy = & $gLegacy @((& $b4Row 102 101 'node.exe' $b4T0.AddMinutes(-90)))
        $g8 = Get-AtmDependencyGraph -Findings (@($gProcF) + @(& $bTp 'r')) -Collection (& $gRows $gBase) -LegacySnapshot $legacy -Partitions @((& $gPart 'r' @('PID 102 (node.exe)'))) -PartitionKeyFunction $gKf -Coverage $gCovAll
        $f8 = & $bFind ([pscustomobject]@{ Findings = (Set-AtmGraphFindingStates -Findings (@($gProcF) + @(& $bTp 'r')) -Graph $g8 -Coverage $gCovAll -GraphCoverage (ConvertTo-AtmGraphCoverage -Graph $g8)) }) 'claude-code/p-r'
        Assert-True ($f8.State -ceq 'UNKNOWN' -and (& $bEv $f8 'GRAPH_SOURCE_AMBIGUOUS') -contains 'REFERENCES_PATH pid:102') '8: PID reutilizado: AMBIGUOUS de pid:102, UNKNOWN'
        # 9: only SELF references the partition.
        $rows9 = @($gBase) + @(,(& $b4Row 400 100 'atm.exe' $b4T0.AddMinutes(3)))
        $f9 = @($gProcF) + @((& $gF 'Process' (& $gK 400 $b4T0.AddMinutes(3)) 'SELF'), (& $bTp 's'))
        $r9 = & $bState $f9 $bCovNo @((& $gPart 's' @('PID 400 (atm.exe)'))) $rows9
        $s9 = & $bFind $r9 'claude-code/p-s'
        Assert-True ($s9.State -ceq 'UNKNOWN' -and (& $bEv $s9 'GRAPH_SOURCE_DIRECT').Count -eq 0 -and (& $bEv $s9 'GRAPH_SOURCE_AMBIGUOUS').Count -eq 0) '9: referencia so do SELF: excluida (nenhuma fonte), UNKNOWN com a cobertura distribuida'
        $r9f = & $bState $f9 $gCovAll @((& $gPart 's' @('PID 400 (atm.exe)'))) $rows9
        Assert-Eq (& $bFind $r9f 'claude-code/p-s').State 'NO_DEPENDENCY_OBSERVED' '9: o proprio diagnostico nunca e dependencia (como na V0.1): com cobertura conclusiva em fixture, nenhuma dependencia'
        # 10: the referencing process has an ambiguous attribution: the partition is in use by that process, no provider is claimed.
        $f10 = @((& $gF 'Process' (& $gK 100 $b4T0) 'AGENT_PROCESS' @((& $gE 'PROVIDER_ATTRIBUTION_AMBIGUOUS' 'claude-code,claude-desktop'))), (& $gF 'Process' $k101 'AGENT_DESCENDANT'), (& $gF 'Process' (& $gK 102 $b4T0.AddMinutes(2)) 'AGENT_DESCENDANT'), (& $gF 'TempPartition' 'claude-code/p-q' 'RUNTIME_NOT_DIAGNOSED' @() 'claude-code'))
        $r10 = & $bState $f10 $gCovAll @((& $gPart 'q' @('PID 102 (node.exe)')))
        $q = & $bFind $r10 'claude-code/p-q'
        Assert-True ($q.State -ceq 'IN_USE' -and $q.Provider -ceq 'claude-code' -and -not (@($q.Evidence | ForEach-Object { [string]$_.Detail }) -join ' ').Contains('claude-desktop') -and @($r10.Graph.Edges | Where-Object { $_.Relation -ceq 'ATTRIBUTED_TO' -and $_.Strength -ceq 'DIRECT' }).Count -eq 0) '10: atribuicao ambigua: nenhum provider exclusivo na particao nem no grafo'
        # 11: CoworkVMService with its verified process and no VM: nothing reaches a partition.
        $svc = & $gF 'Service' 'claude-desktop/CoworkVMService' 'RUNNING' @((& $gE 'SERVICE_PROCESS_VERIFIED' $k101 'services')) 'claude-desktop'
        $r11 = & $bState (@($gProcF) + @($svc, (& $bTp 'v'))) $bCovNo @((& $gPart 'v'))
        Assert-True ((& $bFind $r11 'claude-code/p-v').State -ceq 'UNKNOWN' -and (& $bEv (& $bFind $r11 'claude-code/p-v') 'GRAPH_SOURCE_DIRECT').Count -eq 0) '11: CoworkVMService sem VM: nenhuma cadeia ate a particao'
        # 12: a verified process without a finding references the partition: IN_USE by that process, no finding created, no agent root.
        $rows12 = @($gBase) + @(,(& $b4Row 700 4 'other.exe' $b4T0.AddMinutes(4)))
        $r12 = & $bState (@($gProcF) + @(& $bTp 'n')) $gCovAll @((& $gPart 'n' @('PID 700 (other.exe)'))) $rows12
        $n12 = & $bFind $r12 'claude-code/p-n'
        Assert-True ($n12.State -ceq 'IN_USE' -and (& $bEv $n12 'GRAPH_AGENT_ROOT').Count -eq 0 -and @($r12.Findings).Count -eq 4 -and @($r12.Graph.Nodes | Where-Object { $_.Key -ceq (& $gK 700 $b4T0.AddMinutes(4)) -and -not $_.Finding }).Count -eq 1) '12: no sem achado: evidencia direta mantida, nenhum achado criado, nenhuma raiz de agente'
        # 13: a limit hit: positive kept, the item without edges UNKNOWN with GRAPH_LIMIT.
        $r13 = & $bState (@($gProcF) + @((& $bTp 'a'), (& $bTp 'd'))) $gCovAll @((& $gPart 'a' @('PID 102 (node.exe)')), (& $gPart 'd')) $null @{ MaxDepth = 1 }
        Assert-True ((& $bFind $r13 'claude-code/p-a').State -ceq 'IN_USE' -and (& $bFind $r13 'claude-code/p-d').State -ceq 'UNKNOWN' -and (& $bEv (& $bFind $r13 'claude-code/p-d') 'GRAPH_REASON') -contains 'GRAPH_LIMIT' -and @((& $bFind $r13 'claude-code/p-d').Coverage | Where-Object { $_.Collector -ceq 'dependency-graph' -and $_.Status -ceq 'PARTIAL' }).Count -eq 1) '13: limite: positiva mantida, ausencia nao concluida, cobertura do grafo PARTIAL'
        # 14: unreadable evidence.
        $r14 = & $bState @((& $bTp 'm' @((& $gE 'FILE_HELD_OPEN' 'garbage' 'handles')))) $gCovAll
        Assert-True ((& $bFind $r14 'claude-code/p-m').State -ceq 'UNKNOWN' -and (& $bEv (& $bFind $r14 'claude-code/p-m') 'GRAPH_REASON') -contains 'REFERENCE_UNREADABLE') '14: evidencia ilegivel: UNKNOWN com o motivo'
        # Collision: stays UNKNOWN.
        $col = & $gF 'TempPartition' 'claude-code/p-e' 'UNKNOWN' @((& $gE 'PARTITION_KEY_COLLISION' '2' 'inventory'))
        $rc = & $bState (@($gProcF) + @($col)) $gCovAll @((& $gPart 'e' @('PID 102 (node.exe)')))
        Assert-Eq (& $bFind $rc 'claude-code/p-e').State 'UNKNOWN' 'colisao de chave: UNKNOWN mesmo com referencia direta'
        # Sources capped (more than 16): counted, never silently dropped.
        $many = @(1..20 | ForEach-Object { & $gE 'FILE_HELD_OPEN' ('pid:' + (900 + $_)) 'handles' })
        $rm = & $bState @((& $bTp 'z' @($many | ForEach-Object { New-AtmEvidence -Code 'FILE_HELD_OPEN_UNVERIFIED' -Source 'diagnose' -Collector 'handles' -Detail $_.Detail }))) $gCovAll
        $z = & $bFind $rm 'claude-code/p-z'
        Assert-True ((& $bEv $z 'GRAPH_SOURCE_AMBIGUOUS').Count -eq 16 -and (& $bEv $z 'GRAPH_SOURCES_CAPPED') -contains '20') 'mais de 16 fontes: 16 listadas e o total declarado'
    }
    Test-Case 'Particoes' 'P4-B: descoberta de perfis com fonte injetada - varios perfis, ProfilesDirectory legivel e ilegivel, ambiente volatil indisponivel, fonte com erro, descoberta parcial visivel; nenhuma escrita' {
        $ps = @(Get-AtmProfiles -Identity $null -Source (& $bSource))
        $byP = @{}; foreach ($x in $ps) { $byP[[string]$x.ProfilePath] = $x }
        Assert-True ($byP.ContainsKey('C:\Users\alice') -and $byP.ContainsKey('C:\Users\x') -and $byP.ContainsKey('C:\Users\nome') -and $byP['C:\Users\U'].Sid -ceq 'RESIDUAL' -and $byP['C:\Users\Public'].Sid -ceq 'SHARED-PUBLIC' -and -not $byP.ContainsKey('C:\Users\EXAMPL~1')) '16/17: tres perfis do ProfileList, residual e compartilhado pelo ProfilesDirectory legivel; reparse point nao atravessado'
        Assert-True ($byP['C:\Users\alice'].EnvStatus -ceq 'OK' -and $byP['C:\Users\x'].EnvStatus -ceq 'DENIED' -and $byP['C:\Users\nome'].EnvStatus -ceq 'NOT_LOADED') 'perfis observados, negados e nao carregados distinguidos'
        Assert-Eq (& $bGaps) 'USER_ENVIRONMENT_DENIED,USER_ENVIRONMENT_NOT_LOADED' 'lacunas da descoberta completa: so os ambientes nao lidos'
        $null = Get-AtmProfiles -Identity $null -Source (& $bSource @{ PdThrows = 1 })
        Assert-True ((& $bGaps).Contains('PROFILES_DIRECTORY_UNRESOLVED') -and @($script:AtmDiscoveryNotes | Where-Object { $_ -ceq (Get-AtmText 'note.profilesDirUnresolved') }).Count -eq 1) '18: ProfilesDirectory ilegivel: lacuna e nota visivel (residuais nao listados)'
        $pm = @(Get-AtmProfiles -Identity $null -Source (& $bSource @{ PdMissing = 1 }))
        Assert-True ((& $bGaps).Contains('PROFILES_DIRECTORY_UNRESOLVED') -and @($pm | Where-Object { $_.Sid -ceq 'RESIDUAL' }).Count -eq 0 -and @($pm | Where-Object { $_.Origin -like 'ProfileList*' }).Count -eq 3) '18: ProfilesDirectory ausente: os perfis do ProfileList continuam, nenhum TEMP inventado'
        $null = Get-AtmProfiles -Identity $null -Source (& $bSource @{ EnumThrows = 1 })
        Assert-True ((& $bGaps).Contains('PROFILES_DIRECTORY_UNREADABLE')) '18: ProfilesDirectory nao listavel: lacuna'
        $pv = @(Get-AtmProfiles -Identity $null -Source (& $bSource @{ VolThrows = 1 }))
        $al = @($pv | Where-Object { $_.ProfilePath -ceq 'C:\Users\alice' })[0]
        Assert-True ((& $bGaps).Contains('VOLATILE_ENVIRONMENT_UNREADABLE') -and @($al.Notes | Where-Object { $_ -like 'VOLATILE_ENVIRONMENT_ILEGIVEL*' }).Count -eq 1 -and @($script:AtmDiscoveryNotes | Where-Object { $_ -ceq (Get-AtmText 'note.volatileUnreadableCount' 1) }).Count -eq 1) '19: ambiente volatil indisponivel: lacuna, nota do perfil e nota da descoberta'
        $ph = @(Get-AtmProfiles -Identity $null -Source (& $bSource @{ HivesThrow = 1 }))
        Assert-True ((& $bGaps).Contains('LOADED_HIVES_UNREADABLE') -and @($ph | Where-Object { $_.Origin -like 'ProfileList*' -and $_.EnvStatus -cne 'NOT_LOADED' }).Count -eq 0) '20: hives carregados ilegiveis: nenhum ambiente lido, lacuna registrada'
        $pn = @(Get-AtmProfiles -Identity $null -Source (& $bSource @{ NullEntry = 1 }))
        Assert-True ((& $bGaps).Contains('PROFILE_LIST_ENTRY_UNREADABLE') -and @($pn | Where-Object { $_.Origin -like 'ProfileList*' }).Count -eq 3) '20: entrada do ProfileList ausente: contada, nao inventada'
        $threw = $false
        try { $null = Get-AtmProfiles -Identity $null -Source (& $bSource @{ PlNull = 1 }) } catch { $threw = $true; $msg = $_.Exception.Message }
        Assert-True ($threw -and $msg -ceq (Get-AtmText 'err.profileListUnreadable') -and (& $bGaps).Contains('PROFILE_LIST_UNREADABLE')) '20: ProfileList ilegivel: falha explicita, nunca lista vazia de perfis'
        # Coverage of the discovery (codes only).
        $inv = [pscustomobject]@{ Profiles = @(1, 2, 3); DiscoveryStatus = [pscustomobject]@{ Overridden = $false; Gaps = @([pscustomobject]@{ Code = 'PROFILES_DIRECTORY_UNRESOLVED'; Count = 1 }, [pscustomobject]@{ Code = 'VOLATILE_ENVIRONMENT_UNREADABLE'; Count = 2 }) } }
        $cv = Get-AtmProfileDiscoveryCoverage -Inventory $inv -Identity ([pscustomobject]@{ IsElevatedAdministrator = $false })
        Assert-True ($cv.Status -ceq 'PARTIAL' -and (@($cv.Reasons) -join ',') -ceq 'PROFILES_DIRECTORY_UNRESOLVED,VOLATILE_ENVIRONMENT_UNREADABLE' -and $cv.ElevationWouldHelp -ceq 'YES') '21: descoberta parcial: PARTIAL com os codigos'
        $ok = Get-AtmProfileDiscoveryCoverage -Inventory ([pscustomobject]@{ Profiles = @(); DiscoveryStatus = [pscustomobject]@{ Overridden = $false; Gaps = @() } }) -Identity ([pscustomobject]@{ IsElevatedAdministrator = $false })
        $na = Get-AtmProfileDiscoveryCoverage -Inventory ([pscustomobject]@{ Profiles = @() }) -Identity ([pscustomobject]@{ IsElevatedAdministrator = $false })
        Assert-True ($ok.Status -ceq 'COMPLETE' -and @($ok.Reasons).Count -eq 0 -and $na.Status -ceq 'NOT_OBSERVABLE') 'descoberta sem lacunas: COMPLETE; sem estado: NOT_OBSERVABLE (nunca completa por omissao)'
        # Without -Source the discovery reads the real registry through New-AtmProfileSource (read-only): same result.
        $d1 = ConvertTo-Json -InputObject @(Get-AtmProfiles -Identity $null) -Depth 4; $g1 = & $bGaps
        $d2 = ConvertTo-Json -InputObject @(Get-AtmProfiles -Identity $null -Source (New-AtmProfileSource)) -Depth 4; $g2 = & $bGaps
        Assert-True ($d1 -ceq $d2 -and $g1 -ceq $g2) 'sem -Source: a fonte padrao (registro real, somente leitura)'
        # An inventory that fails before the discovery leaves no gap of an earlier run behind.
        $script:AtmDiscoveryGaps = @{ 'PROFILE_LIST_UNREADABLE' = 1 }
        try { $null = Invoke-AtmInventory -Providers @() -NoProgress } catch { $null = $_ }
        Assert-True ($script:AtmDiscoveryGaps.Count -eq 0 -and -not $script:AtmDiscoveryRan) 'inventario que falha antes da descoberta: nenhuma lacuna antiga, descoberta nao executada'
    }
    Test-Case 'Particoes' 'P4-B: integracao ao diagnose - estado das particoes pelo grafo, cobertura profile-discovery e dependency-graph, JSON e relatorio sem caminhos, nomes ou mensagens; classes e flags V0.1 inalteradas' {
        $p = New-TestProfile 'p4b-int'
        $root = New-TestRoot -ProfileInfo $p
        $d = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p)) -IdentitySource $diagIdUser -PseudonymKey $testPseudonymKey -ServiceSource { param($Names) @() } -VirtualizationSource (& $vSrc (& $vBase @($vHostRow)))
        $tp = @($d.Findings | Where-Object { $_.Kind -ceq 'TempPartition' })
        Assert-True ($tp.Count -ge 1 -and @($tp | Where-Object { $_.State -cne 'UNKNOWN' -and $_.State -cne 'IN_USE' }).Count -eq 0 -and @($tp | Where-Object { (& $bEv $_ 'GRAPH_DEPENDENCY').Count -ne 1 }).Count -eq 0) 'toda particao com estado do grafo (UNKNOWN ou IN_USE) e o resumo como evidencia'
        Assert-True (@($d.Coverage | Where-Object { $_.Collector -ceq 'profile-discovery' -and $_.Status -ceq 'COMPLETE' }).Count -eq 1 -and @($d.Coverage | Where-Object { $_.Collector -ceq 'dependency-graph' }).Count -eq 1) 'coberturas profile-discovery (perfis fornecidos) e dependency-graph'
        # V0.1 classes and flags: the evidence equals the inventory of the same run.
        $invParts = @($d.Inventory.Partitions | Where-Object { $_.Kind -ne 'NotScanned' })
        $fromInv = @($invParts | ForEach-Object { [string]$_.Class + '|' + (@($_.Flags | Sort-Object) -join ',') } | Sort-Object)
        $fromFind = @($tp | ForEach-Object { ((& $bEv $_ 'AUDIT_CLASS') -join '') + '|' + (((& $bEv $_ 'AUDIT_FLAG') | Sort-Object) -join ',') } | Sort-Object)
        Assert-Eq ($fromFind -join ';') ($fromInv -join ';') '23: classes e flags V0.1 dos achados iguais as do inventario da mesma execucao'
        # Discovery through an injected source: gaps visible in the JSON and the report; no path, name or exception text.
        $src = & $bSource @{ PdThrows = 1; VolThrows = 1; EnumThrows = 1 }
        $ia = Get-InvArgs -Profiles $null; $ia.Remove('ProfilesOverride'); $ia['ProfileSource'] = $src
        $d2 = Invoke-AtmDiagnose -InventoryArgs $ia -IdentitySource $diagIdUser -PseudonymKey $testPseudonymKey -ServiceSource { param($Names) @() } -VirtualizationSource (& $vSrc (& $vBase @($vHostRow)))
        $pc = @($d2.Coverage | Where-Object { $_.Collector -ceq 'profile-discovery' })[0]
        Assert-True ($pc.Status -ceq 'PARTIAL' -and @($pc.Reasons) -ccontains 'PROFILES_DIRECTORY_UNRESOLVED' -and @($pc.Reasons) -ccontains 'VOLATILE_ENVIRONMENT_UNREADABLE') '21: lacunas da fonte injetada na cobertura'
        $json = ConvertTo-AtmDiagnoseJson -Result $d2
        $txt = (Show-AtmDiagnose -Result $d2 6>&1 | ForEach-Object { [string]$_ }) -join "`n"
        foreach ($x in @('Users\\alice', 'Users\alice', 'C:\\Users', 'SECRET-', $bSidA, $bSidB)) { Assert-True (-not $json.Contains($x)) "25: JSON sem $x" }
        foreach ($x in @('SECRET-', 'C:\Users\alice')) { Assert-True (-not $txt.Contains($x)) "25: relatorio sem $x" }
        Assert-True ($txt.Contains((Get-AtmText 'diag.discoveryIncomplete' 'PARTIAL')) -and $txt.Contains('PROFILES_DIRECTORY_UNRESOLVED')) '21: descoberta parcial visivel no relatorio'
        $j = $json | ConvertFrom-Json
        Assert-True (@($j.coverage | Where-Object { $_.collector -ceq 'profile-discovery' -and $_.status -ceq 'PARTIAL' }).Count -eq 1) 'JSON: cobertura profile-discovery'
    }
    Test-Case 'Particoes' 'P4-B: escala - milhares de particoes passadas do grafo aos achados em uma passada (indices, sem reconstruir o grafo)' {
        $rows = New-Object System.Collections.Generic.List[object]; $f = New-Object System.Collections.Generic.List[object]; $parts = New-Object System.Collections.Generic.List[object]
        $rows.Add((& $b4Row 4 0 'System' $b4T0.AddHours(-1)))
        for ($i = 0; $i -lt 500; $i++) {
            $pidv = 20000 + $i; $cr = $b4T0.AddSeconds($i)
            $rows.Add((& $b4Row $pidv 4 'w.exe' $cr)); $f.Add((& $gF 'Process' (& $gK $pidv $cr) 'AGENT_PROCESS'))
            for ($q = 0; $q -lt 6; $q++) { $f.Add((& $gF 'TempPartition' ("claude-code/p-$i-$q") 'RUNTIME_NOT_DIAGNOSED')); $parts.Add((& $gPart "$i-$q" $(if ($q -lt 3) { @("PID $pidv (w.exe)") } else { @() }))) }
        }
        $c = & $gRows $rows.ToArray()
        $g = Get-AtmDependencyGraph -Findings $f.ToArray() -Collection $c -LegacySnapshot (& $gLegacy $rows.ToArray()) -Partitions $parts.ToArray() -PartitionKeyFunction $gKf -Coverage $gCovAll
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $out = Set-AtmGraphFindingStates -Findings $f.ToArray() -Graph $g -Coverage $gCovAll -GraphCoverage (ConvertTo-AtmGraphCoverage -Graph $g)
        $sw.Stop()
        $inUse = @($out | Where-Object { $_.Kind -ceq 'TempPartition' -and $_.State -ceq 'IN_USE' }).Count
        $none = @($out | Where-Object { $_.Kind -ceq 'TempPartition' -and $_.State -ceq 'NO_DEPENDENCY_OBSERVED' }).Count
        Assert-True ($inUse -eq 1500 -and $none -eq 1500 -and @($out).Count -eq $f.Count) "3000 particoes: 1500 IN_USE, 1500 sem dependencia (fixture conclusiva), mesma contagem de achados"
        Assert-True ($sw.ElapsedMilliseconds -lt 60000) "tempo limitado ($($sw.ElapsedMilliseconds) ms)"
        $script:caseNote = "3000 particoes: $($sw.ElapsedMilliseconds) ms"
    }
    Test-Case 'Particoes' 'P4-B (estatico): descoberta sem escrita no registro, sem hive carregado nem chave remota; a promocao nao chama coletor; clean e auditoria V0.1 nao leem o grafo; textos nos dois idiomas; travas fechadas' {
        $audit = [IO.File]::ReadAllText((Join-Path $srcDir 'lib\Engine.Audit.ps1'))
        foreach ($pat in @('SetValue(', 'CreateSubKey', 'DeleteSubKey', 'DeleteValue', 'OpenRemoteBaseKey', 'OpenBaseKey', 'RegLoadKey', 'reg.exe', 'reg load', 'Set-ItemProperty', 'New-ItemProperty', 'Remove-ItemProperty')) {
            Assert-True (-not $audit.Contains($pat)) "22: Engine.Audit sem '$pat'"
        }
        Assert-True ($audit -notmatch 'OpenSubKey\([^)]*\$true') '22: nenhuma chave aberta para escrita'
        $diag = [IO.File]::ReadAllText((Join-Path $srcDir 'lib\Engine.Diagnose.ps1'))
        $fn = $diag.Substring($diag.IndexOf('function Set-AtmGraphFindingStates'), $diag.IndexOf('# Open-file evidence (D-2') - $diag.IndexOf('function Set-AtmGraphFindingStates'))
        foreach ($pat in @('Get-CimInstance', 'Invoke-AtmInventory', 'Get-AtmProcessCollection', 'Get-AtmDependencyGraph -', 'Get-AtmHandleEvidence', 'Invoke-AtmGitCommand', '[IO.File]', 'Get-ChildItem', 'Registry')) { Assert-True (-not $fn.Contains($pat)) "promocao sem '$pat'" }
        foreach ($fl in @('lib\Engine.Clean.ps1', 'lib\Engine.Audit.ps1')) {
            $t = [IO.File]::ReadAllText((Join-Path $srcDir $fl))
            foreach ($pat in @('Graph', 'GRAPH_', 'IN_USE', 'NO_DEPENDENCY_OBSERVED', 'Set-AtmGraphFindingStates')) { Assert-True (-not $t.Contains($pat)) "24: $fl sem '$pat'" }
        }
        foreach ($l in @('en-US', 'pt-BR')) {
            foreach ($x in $script:AtmDiscoveryGapCodes) { Assert-True $script:AtmMessages[$l].ContainsKey("reason.$x") "reason.$x ($l)" }
            foreach ($x in $script:AtmGraphFindingEvidenceCodes) { Assert-True $script:AtmMessages[$l].ContainsKey("evidence.$x") "evidence.$x ($l)" }
            foreach ($x in @('DISCOVERY_STATUS_UNAVAILABLE', 'COLLECTOR_NOT_RUN', 'GRAPH_INCOMPLETE')) { Assert-True $script:AtmMessages[$l].ContainsKey("reason.$x") "reason.$x ($l)" }
        }
        Assert-True ($script:AtmRealDeletionEnabled -eq $true -and $shippedDeletionGate -eq $false -and $script:AtmHandleDiagnosticsEnabled -eq $false -and $script:AtmWorktreeDiagnosticsEnabled -eq $false) '30: travas distribuidas fechadas (a suite so abre a de exclusao no sandbox)'
    }
    # ------------------------------------------------------------------ P5-A (TUI diagnostics view)
    # A synthetic diagnose result (the P4-A/P4-B helpers above: findings, graph and states as the engine builds them);
    # the TUI receives it from an injected runner, so no collector runs and every count of runs is observable.
    $tdT0 = New-Object DateTime(2026, 10, 25, 3, 0, 0, [DateTimeKind]::Utc)
    $tdCov = { param([string]$C, [string]$S, [string[]]$R = @(), [string]$E = 'NO') New-AtmCoverage -Collector $C -Status $S -Reasons $R -ElevationWouldHelp $E }
    $tdWrap = { param($Findings, $Coverage, $Graph)
        [pscustomobject]@{ SchemaVersion = $script:AtmDiagnoseSchema; ToolVersion = $script:AtmVersion; Machine = 'TESTHOST'; StartedUtc = $tdT0; FinishedUtc = $tdT0.AddSeconds(5); DeadlineUtc = $tdT0.AddSeconds(300); DeadlineSeconds = 300
            Identity = [pscustomobject]@{ Name = 'TEST\alice'; Sid = 'S-1-5-21-9-9-9-1000'; IsElevatedAdministrator = $false; ElevationType = 'LIMITED'; IntegrityLevel = 'MEDIUM'; SessionId = 1 }
            Providers = @(); Coverage = @($Coverage); CoverageComplete = $false; Findings = @($Findings); AgentResources = $null; Graph = $Graph
            Pseudonymization = [pscustomobject]@{ Scheme = $script:AtmPseudonymScheme; KeySource = 'EPHEMERAL'; KeyId = $null }; Inventory = $null } }
    $tdBuild = { param([switch]$WithWorktree)
        $c0 = @((& $tdCov 'identity' 'COMPLETE'), (& $tdCov 'inventory' 'COMPLETE'), (& $tdCov 'processes' 'PARTIAL' @('UNINSPECTABLE_PROCESSES') 'YES'), (& $tdCov 'process-snapshot' 'COMPLETE'), (& $tdCov 'agent-processes' 'COMPLETE'),
            (& $tdCov 'services' 'DENIED' @('ACCESS_DENIED') 'YES'), (& $tdCov 'virtual-machines' 'TIMEOUT' @('DEADLINE_EXCEEDED') 'UNKNOWN'), (& $tdCov 'profile-discovery' 'PARTIAL' @('PROFILES_DIRECTORY_UNRESOLVED') 'NO'),
            $(if ($WithWorktree) { & $tdCov 'worktree-discovery' 'COMPLETE' } else { & $tdCov 'worktree-discovery' 'NOT_OBSERVABLE' @('WORKTREE_DIAGNOSTICS_GATE_CLOSED') }),
            (& $tdCov 'process-cwd' 'NOT_OBSERVABLE' @('WORKING_DIRECTORY_DEFERRED')), (& $tdCov 'handles' 'NOT_OBSERVABLE' @('HANDLE_SECURITY_GATE_CLOSED')))
        $k101 = & $gK 101 $b4T0.AddMinutes(1)
        $f = @($gProcF) + @((& $gF 'Process' 'pid:777' 'IDENTITY_UNVERIFIED' @() 'claude-code'), (& $gF 'AgentSession' 'claude-code/s-1' 'LIVE'),
            (& $gF 'Service' 'claude-desktop/CoworkVMService' 'RUNNING' @((& $gE 'SERVICE_PROCESS_VERIFIED' $k101 'services')) 'claude-desktop'),
            (& $gF 'VirtualizationPlatform' 'host' 'PRESENT'), (& $gF 'VirtualMachine' 'vm/v-1' 'RUNNING' @((& $gE 'PROVIDER_ATTRIBUTION_AMBIGUOUS' 'claude-code,claude-desktop' 'virtual-machines'))),
            (& $bTp 'a'), (& $bTp 'b'), (& $bTp 'c'), (& $bTp 'd'))
        if ($WithWorktree) { $f += @(& $gF 'Worktree' 'wt/w-1' 'LOCAL_WORK' @((& $gE 'IN_REPOSITORY' 'repo/r-1' 'worktree-discovery'))) }
        $parts = @((& $gPart 'a' @('PID 102 (node.exe)')), (& $gPart 'b' @() @('PID 102 (node.exe) -> base')), (& $gPart 'c' @() @() @('PID 102 (node.exe) -> unresolved')), (& $gPart 'd'))
        $g = Get-AtmDependencyGraph -Findings $f -Collection (& $gRows $gBase) -LegacySnapshot (& $gLegacy $gBase) -Partitions $parts -PartitionKeyFunction $gKf -Coverage $c0
        $gc = ConvertTo-AtmGraphCoverage -Graph $g
        & $tdWrap (Set-AtmGraphFindingStates -Findings $f -Graph $g -Coverage $c0 -GraphCoverage $gc) (@($c0) + @($gc)) $g }
    $tdRes = & $tdBuild
    $tdState = { param($Res, [int]$W = 100, [int]$H = 30)
        $v = (ConvertTo-AtmDiagnoseJson -Result $Res) | ConvertFrom-Json
        $st = @{ Diag = @{ View = $v; Index = (New-AtmTuiDiagIndex -View $v); Stale = $false; Error = $null }; Width = $W; Height = $H; G = (Get-AtmTuiGlyphs $true); Inventory = $null; Message = $null; Stack = New-Object System.Collections.Generic.List[object] }
        $st }
    $tdFrame = { param($St, [hashtable]$Screen) $s0 = @{ Sel = 0; Top = 0; Count = 0; Filter = $null; Title = 'T' }; foreach ($k in $Screen.Keys) { $s0[$k] = $Screen[$k] }; $St.Stack.Clear(); $St.Stack.Add($s0)
        return , @(Get-AtmTuiFrame -State $St | ForEach-Object { ($_ | ForEach-Object { $_.Text }) -join '' }) }
    $tdText = { param($St, [hashtable]$Screen) (@(Get-AtmTuiDiagText -State $St -Screen $Screen -Width $St.Width) | ForEach-Object { $_.Text }) -join '' }
    # Headless frames are transliterated when the console has no Unicode output (ASCII fallback): both forms count.
    $tdHas = { param([string]$Text, [string]$S) $Text.Contains($S) -or $Text.Contains((ConvertTo-AtmAscii $S)) }
    # Whole text across wrapped lines (whitespace ignored): wrapping never drops a character.
    $tdHasW = { param([string]$Text, [string]$S) $t = $Text -replace '\s', ''; $x = $S -replace '\s', ''; $t.Contains($x) -or $t.Contains((ConvertTo-AtmAscii $x)) }
    $tdFind = { param($St, [string]$Key) $St.Diag.Index.FindingBy[$Key] }

    Test-Case 'TUI' 'P5-A: menu Diagnostico - entrada (diagnose so nessa acao), categorias, retorno ao menu sem nova coleta, navegacao sem coleta, atualizacao manual explicita' {
        $p = New-TestProfile 'p5a-nav'
        $null = New-TestRoot -ProfileInfo $p
        $script:tdRuns = 0; $script:tdObj = $tdRes
        $runner = { param($a) $script:tdRuns++; $script:tdObj }
        $keys = @((New-Key 'D' 'd'), (New-Key 'Enter'), (New-Key 'Escape'), (New-Key 'DownArrow'), (New-Key 'Enter'), (New-Key 'Enter'), (New-Key 'Escape'), (New-Key 'Escape'),
            (New-Key 'DownArrow'), (New-Key 'Enter'), (New-Key 'PageDown'), (New-Key 'Enter'), (New-Key 'Escape'), (New-Key 'Escape'), (New-Key 'Escape'), (New-Key 'D' 'd'), (New-Key 'Escape'), (New-Key 'Q' 'q'))
        $o = Invoke-HeadlessTui -Keys $keys -InvArgs (Get-InvArgs -Profiles @($p)) -DiagRunner $runner -H 30
        $all = $o.Frames -join "`n=====`n"
        Assert-Eq $script:tdRuns 1 '1/22: um unico diagnose (entrada); voltar, detalhes, paginacao e reentrar nao coletam de novo'
        foreach ($k in @('tui.diag.cat.summary', 'tui.diag.cat.coverage', 'tui.diag.cat.procs', 'tui.diag.cat.services', 'tui.diag.cat.virt', 'tui.diag.cat.worktrees', 'tui.diag.cat.parts', 'tui.diag.cat.graph', 'tui.diag.cat.issues', 'tui.diag.noAuth')) { Assert-True (& $tdHas $all (Get-AtmText $k)) "categoria/aviso: $k" }
        Assert-True ((& $tdHas $o.Frames[-1] (Get-AtmText 'menu.title')) -or (& $tdHas $o.Frames[-2] (Get-AtmText 'menu.title'))) '2: retorno ao menu principal'
        Assert-True (& $tdHas $all (Get-AtmText 'tui.diag.lastRun' (Format-AtmTuiUtc $tdT0.AddSeconds(5)))) 'horario da ultima observacao'
        # 23: U refreshes on request only; the screens above the area are closed.
        $script:tdRuns = 0
        $o2 = Invoke-HeadlessTui -Keys @((New-Key 'D' 'd'), (New-Key 'DownArrow'), (New-Key 'Enter'), (New-Key 'U' 'u'), (New-Key 'Escape'), (New-Key 'Q' 'q')) -InvArgs (Get-InvArgs -Profiles @($p)) -DiagRunner $runner
        $j2 = $o2.Frames -join "`n"
        Assert-True ($script:tdRuns -eq 2 -and (& $tdHas $j2 (Get-AtmText 'tui.diag.refreshed')) -and (& $tdHasW $j2 (Get-AtmText 'tui.diag.running'))) '23: U atualiza (nova observacao, com o aviso de demora inteiro)'
        Assert-True (@($o2.State.Stack | ForEach-Object { $_.Name }) -join ',' -ceq 'menu') 'apos U e Esc: de volta ao menu (telas do resultado anterior fechadas)'
        foreach ($f in $o.Frames) { foreach ($ln in ($f -split "`n")) { Assert-True ($ln.Length -le 120) 'largura' } }
    }
    Test-Case 'TUI' 'P5-A: resumo, categorias, detalhes de achado e no, arestas DIRECT/ANCESTOR/AMBIGUOUS, evidencia positiva, UNKNOWN por cobertura incompleta' {
        $st = & $tdState $tdRes
        $sum = & $tdText $st @{ Name = 'dsum' }
        Assert-True ($sum.Contains((Get-AtmText 'tui.diag.sumParts' 1 3 0)) -and $sum.Contains((Get-AtmText 'tui.diag.noAuth')) -and $sum.Contains((Get-AtmText 'tui.diag.sumProcs' 3 1 1))) "3: resumo (particoes IN_USE/UNKNOWN, processos verificados/nao verificados, sessoes): $sum"
        Assert-True ($sum.Contains((Get-AtmText 'tui.diag.sumCountPartial' (Get-AtmText 'tui.diag.lblServices') 1 'services=DENIED' 'ACCESS_DENIED')) -and $sum.Contains((Get-AtmText 'tui.diag.sumCountPartial' (Get-AtmText 'tui.diag.lblWorktrees') 0 'worktree-discovery=NOT_OBSERVABLE' 'WORKTREE_DIAGNOSTICS_GATE_CLOSED'))) 'NOT_OBSERVABLE e DENIED nunca como zero entidades: ausencia nao comprovada'
        Assert-True ($sum.Contains((Get-AtmText 'tui.diag.sumCoverage' (Get-AtmText 'common.incomplete'))) -and $sum.Contains((Get-AtmText 'tui.diag.sumLimits'))) 'cobertura parcial nunca como completa; limitacoes listadas'
        foreach ($cat in @(@('procs', 'Process'), @('services', 'Service'), @('virt', 'VirtualMachine'), @('parts', 'TempPartition'))) {
            $fr = (& $tdFrame $st @{ Name = 'dlist'; Filter = @{ Cat = $cat[0] } }) -join "`n"
            Assert-True ($fr.Contains($cat[1])) "4-7: categoria $($cat[0])"
        }
        $wt = (& $tdFrame $st @{ Name = 'dlist'; Filter = @{ Cat = 'worktrees' } }) -join "`n"
        Assert-True ($wt.Contains((Get-AtmText 'tui.diag.emptyNotObserved')) -and -not $wt.Contains((Get-AtmText 'common.none')) -and (& $tdHasW $wt (Get-AtmText 'tui.diag.covNote' 'worktree-discovery=NOT_OBSERVABLE' 'WORKTREE_DIAGNOSTICS_GATE_CLOSED'))) '8: worktrees com a trava fechada: "nada observado", nunca "nenhum"'
        $cats = (& $tdFrame $st @{ Name = 'diag' }) -join "`n"
        Assert-True ($cats -match '\s0\*\s' -and $cats -match '\s12\s' -and (& $tdHasW $cats (Get-AtmText 'tui.diag.starLegend'))) 'contagens visiveis (ultima coluna inteira); * marca cobertura incompleta'
        # Nothing observed at all: never shown as zero items.
        $zc = @($tdRes.Coverage | ForEach-Object { if ($_.Collector -ceq 'inventory') { & $tdCov 'inventory' 'FAILED' @('INVENTORY_FAILED') 'UNKNOWN' } elseif ($_.Collector -ceq 'process-snapshot') { & $tdCov 'process-snapshot' 'NOT_OBSERVABLE' @('INVENTORY_FAILED') } else { $_ } })
        $zs = & $tdState (& $tdWrap @() $zc $null)
        $zt = & $tdText $zs @{ Name = 'dsum' }
        Assert-True ($zt.Contains((Get-AtmText 'tui.diag.covNote' 'inventory=FAILED' 'INVENTORY_FAILED')) -and $zt.Contains((Get-AtmText 'tui.diag.covNote' 'process-snapshot=NOT_OBSERVABLE' 'INVENTORY_FAILED'))) 'inventario e snapshot sem observacao: contagens 0 sempre com "ausencia nao comprovada"'
        $zcat = (& $tdFrame $zs @{ Name = 'diag' }) -join "`n"
        Assert-True ($zcat -match '\s0\*\s') 'categorias sem observacao marcadas com *'
        Assert-True (((& $tdFrame $zs @{ Name = 'dlist'; Filter = @{ Cat = 'parts' } }) -join "`n").Contains((Get-AtmText 'tui.diag.emptyNotObserved'))) 'particoes nao observadas: nunca "nenhum"'
        $st2 = & $tdState (& $tdBuild -WithWorktree)
        Assert-True (((& $tdFrame $st2 @{ Name = 'dlist'; Filter = @{ Cat = 'worktrees' } }) -join "`n").Contains('wt/w-1')) '8: worktree de fixture listada'
        $a = & $tdText $st @{ Name = 'dfind'; Filter = @{ F = (& $tdFind $st 'TempPartition|claude-code/p-a') } }
        Assert-True ($a.Contains('IN_USE') -and $a.Contains('GRAPH_SOURCE_DIRECT') -and $a.Contains('[D] REFERENCES_PATH <- Process')) '11/14: evidencia positiva de uso e aresta DIRECT'
        Assert-True ((& $tdText $st @{ Name = 'dfind'; Filter = @{ F = (& $tdFind $st 'TempPartition|claude-code/p-b') } }).Contains('[A] REFERENCES_PATH')) '12: aresta ANCESTOR'
        $c = & $tdText $st @{ Name = 'dfind'; Filter = @{ F = (& $tdFind $st 'TempPartition|claude-code/p-c') } }
        Assert-True ($c.Contains('[?] REFERENCES_PATH') -and $c.Contains((Get-AtmText 'tui.diag.ambEdge'))) '13: aresta AMBIGUOUS diferenciada (marcador e texto)'
        $d = & $tdText $st @{ Name = 'dfind'; Filter = @{ F = (& $tdFind $st 'TempPartition|claude-code/p-d') } }
        Assert-True ($d.Contains('UNKNOWN') -and $d.Contains((Get-AtmText 'tui.diag.unknownNote')) -and $d.Contains('COVERAGE_INCOMPLETE') -and $d.Contains('handles')) '15: UNKNOWN por cobertura incompleta, nunca livre'
        $vm = & $tdText $st @{ Name = 'dfind'; Filter = @{ F = (& $tdFind $st 'VirtualMachine|vm/v-1') } }
        Assert-True ($vm.Contains((Get-AtmText 'tui.diag.det.providerAmbiguous' 'claude-code,claude-desktop')) -and $vm.Contains('[?] ATTRIBUTED_TO -> Provider claude-code')) 'ATTRIBUTED_TO ambigua nunca exclusiva'
        $nodeT = @($st.Diag.Index.Nodes | Where-Object { $_.finding })[0]; $nodeF = @($st.Diag.Index.Nodes | Where-Object { -not $_.finding })[0]
        Assert-True ((& $tdText $st @{ Name = 'dnode'; Filter = @{ N = $nodeT } }).Contains((Get-AtmText 'tui.diag.finding.yes'))) '9: no com achado proprio'
        Assert-True ((& $tdText $st @{ Name = 'dnode'; Filter = @{ N = $nodeF } }).Contains((Get-AtmText 'tui.diag.finding.no'))) '10: finding=false como referencia sem achado proprio'
        Assert-True (((& $tdFrame $st @{ Name = 'dnodes' }) -join "`n").Contains((Get-AtmText 'tui.diag.findingShortNo'))) 'lista de nos marca referencias'
    }
    Test-Case 'TUI' 'P5-A: cobertura - handles e worktrees bloqueados, D-1 adiado, descoberta parcial, DENIED e TIMEOUT; elevacao so quando YES; pendencias' {
        $st = & $tdState $tdRes
        $cov = (& $tdFrame $st @{ Name = 'dcov' }) -join "`n"
        foreach ($x in @('handles', 'HANDLE_SECURITY_GATE_CLOSED', 'worktree-discovery', 'WORKTREE_DIAGNOSTICS_GATE_CLOSED', 'process-cwd', 'WORKING_DIRECTORY_DEFERRED', 'profile-discovery', 'PROFILES_DIRECTORY_UNRESOLVED', 'DENIED', 'TIMEOUT', 'dependency-graph')) { Assert-True ($cov.Contains($x)) "16-20: cobertura mostra $x" }
        $to = & $tdText $st @{ Name = 'dcovdet'; Filter = @{ C = $st.Diag.Index.CovBy['virtual-machines'] } }
        Assert-True ($to.Contains((Get-AtmText 'tui.diag.elevUnknown')) -and -not $to.Contains((Get-AtmText 'tui.diag.elevYes'))) '20: ElevationWouldHelp UNKNOWN nunca prometido como solucao'
        Assert-True ((& $tdText $st @{ Name = 'dcovdet'; Filter = @{ C = $st.Diag.Index.CovBy['services'] } }).Contains((Get-AtmText 'tui.diag.elevYes'))) 'YES: elevacao ajudaria'
        $iss = (& $tdFrame $st @{ Name = 'dissues' } ) -join "`n"
        Assert-True ($iss.Contains((Get-AtmText 'tui.diag.typeCov')) -and $iss.Contains((Get-AtmText 'tui.diag.typeFind'))) '9 (A): pendencias com coberturas e achados UNKNOWN'
        Assert-Eq @($st.Diag.Index.Issues | Where-Object { $_.T -ceq 'cov' }).Count @($st.Diag.Index.Coverage | Where-Object { $script:AtmConclusiveCoverage -cnotcontains [string]$_.status }).Count 'nenhum coletor incompleto ocultado'
    }
    Test-Case 'TUI' 'P5-A: falha do diagnose com mensagem segura, resultado anterior preservado como desatualizado, nenhuma repeticao automatica' {
        $p = New-TestProfile 'p5a-fail'
        $script:tdRuns = 0
        $fail = { param($a) $script:tdRuns++; throw [UnauthorizedAccessException]::new('SECRET-diag C:\Users\alice token=abc') }
        $o = Invoke-HeadlessTui -Keys @((New-Key 'D' 'd'), (New-Key 'Q' 'q')) -InvArgs (Get-InvArgs -Profiles @($p)) -DiagRunner $fail -W 60 -H 20
        $all = $o.Frames -join "`n"
        Assert-True ($script:tdRuns -eq 1 -and (& $tdHasW $all 'EXCEPTION_UNAUTHORIZEDACCESSEXCEPTION') -and -not $all.Contains('SECRET') -and -not $all.Contains('token=')) '24: falha com codigo seguro, sem mensagem bruta, sem repeticao'
        Assert-True (($o.State.Stack | ForEach-Object { $_.Name }) -join ',' -ceq 'menu') 'falha sem resultado: permanece no menu'
        Assert-True (& $tdHasW $all (Get-AtmText 'tui.diag.failed' 'EXCEPTION_UNAUTHORIZEDACCESSEXCEPTION')) 'mensagem de falha inteira em 60 colunas (quebrada, nunca cortada)'
        foreach ($f in $o.Frames) { $ls = @($f -split "`n"); Assert-True ($ls.Count -le 20) '60x20: no maximo 20 linhas'; if ($ls.Count -eq 20) { Assert-True ($ls[-1].Contains('Q')) 'rodape (teclas) sempre visivel em 60x20, mesmo com mensagem (quadros completos; o quadro de espera nao tem teclas)' } }
        $script:tdRuns = 0
        $flaky = { param($a) $script:tdRuns++; if ($script:tdRuns -ge 2) { throw [IO.IOException]::new('SECRET-second') }; $tdRes }
        $o2 = Invoke-HeadlessTui -Keys @((New-Key 'D' 'd'), (New-Key 'U' 'u'), (New-Key 'Enter'), (New-Key 'Escape'), (New-Key 'Q' 'q')) -InvArgs (Get-InvArgs -Profiles @($p)) -DiagRunner $flaky
        $a2 = $o2.Frames -join "`n"
        Assert-True ($script:tdRuns -eq 2 -and $null -ne $o2.State.Diag.View -and $o2.State.Diag.Stale -and $a2.Contains('EXCEPTION_IOEXCEPTION') -and (& $tdHas $a2 (Get-AtmText 'tui.diag.staleShort')) -and -not $a2.Contains('SECRET')) '25: resultado anterior mantido e marcado DESATUALIZADO'
    }
    Test-Case 'TUI' 'P5-A: ASCII e Unicode, terminal 60x20, pt-BR e en-US, privacidade do conteudo renderizado (separado da V0.1)' {
        $p = New-TestProfile 'p5a-view'
        $root = New-TestRoot -ProfileInfo $p
        $script:tdObj = $tdRes
        $runner = { param($a) $script:tdObj }
        $keys = @((New-Key 'D' 'd'), (New-Key 'Enter'), (New-Key 'PageDown'), (New-Key 'Escape'), (New-Key 'DownArrow'), (New-Key 'Enter'), (New-Key 'Enter'), (New-Key 'Escape'), (New-Key 'Escape'),
            (New-Key 'DownArrow'), (New-Key 'DownArrow'), (New-Key 'DownArrow'), (New-Key 'DownArrow'), (New-Key 'DownArrow'), (New-Key 'Enter'), (New-Key 'Enter'), (New-Key 'End'), (New-Key 'Escape'), (New-Key 'Escape'),
            (New-Key 'DownArrow'), (New-Key 'Enter'), (New-Key 'End'), (New-Key 'Enter'), (New-Key 'Escape'), (New-Key 'Escape'), (New-Key 'Escape'), (New-Key 'Q' 'q'))
        $o = Invoke-HeadlessTui -Keys $keys -InvArgs (Get-InvArgs -Profiles @($p)) -DiagRunner $runner -Ascii -W 60 -H 20
        $all = $o.Frames -join "`n"
        Assert-True ($all -match '^[\x09\x0A\x20-\x7E]*$') '26: somente ASCII imprimivel com -Ascii'
        Assert-True (& $tdHasW $all (Get-AtmText 'tui.diag.noAuth')) 'aviso exigido inteiro em 60 colunas'
        foreach ($f in $o.Frames) { $ls = @($f -split "`n"); Assert-True ($ls.Count -le 20) '27: no maximo 20 linhas'; foreach ($ln in $ls) { Assert-True ($ln.Length -le 60) "27: largura 60 ($($ln.Length))" } }
        $u = Invoke-HeadlessTui -Keys @((New-Key 'D' 'd'), (New-Key 'Enter'), (New-Key 'Q' 'q')) -InvArgs (Get-InvArgs -Profiles @($p)) -DiagRunner $runner -W 80 -H 24
        Assert-True (& $tdHas ($u.Frames -join "`n") (Limit-AtmText (Get-AtmText 'tui.diag.noAuth') 70 '').Trim()) '26: Unicode (sem -Ascii) renderiza a mesma area'
        # Privacy: nothing of the identity, the machine or the V0.1 inventory in a diagnostics frame (the V0.1 screens keep their own content).
        $diagFrames = @($o.Frames + $u.Frames | Where-Object { & $tdHas $_ (Get-AtmText 'tui.diag.title') })
        Assert-True ($diagFrames.Count -gt 3) 'quadros da area de diagnostico'
        foreach ($x in @('alice', 'S-1-5-21-9-9-9-1000', 'TESTHOST', $p.ProfilePath, (Split-Path $root -Leaf), 'node.exe', 'unresolved', 'D:\t')) { Assert-True (-not ($diagFrames -join "`n").Contains($x)) "30: diagnostico sem '$x'" }
        # Every detail of the fixture, untruncated (no frame clipping): no identity, machine or V0.1 data.
        $sv = & $tdState $tdRes 200 60
        $full = New-Object System.Collections.Generic.List[string]
        foreach ($x in @($sv.Diag.View.findings)) { $full.Add((& $tdText $sv @{ Name = 'dfind'; Filter = @{ F = $x } })) }
        foreach ($x in @($sv.Diag.Index.Nodes)) { $full.Add((& $tdText $sv @{ Name = 'dnode'; Filter = @{ N = $x } })) }
        foreach ($x in @($sv.Diag.Index.Coverage)) { $full.Add((& $tdText $sv @{ Name = 'dcovdet'; Filter = @{ C = $x } })) }
        $full.Add((& $tdText $sv @{ Name = 'dsum' }))
        foreach ($x in @('alice', 'S-1-5-21-9-9-9-1000', 'TESTHOST', 'node.exe', 'unresolved', 'D:\t', $p.ProfilePath)) { Assert-True (-not ($full -join "`n").Contains($x)) "30: texto completo do diagnostico sem '$x'" }
        $v1 = Invoke-HeadlessTui -Keys @((New-Key 'D2' '2'), (New-Key 'Q' 'q')) -InvArgs (Get-InvArgs -Profiles @($p))
        Assert-True (($v1.Frames -join "`n").Contains('p5a-view') -and -not ($diagFrames -join "`n").Contains('p5a-view')) 'V0.1 continua mostrando a conta do perfil; a area de diagnostico nao (separacao das apresentacoes)'
        $prev = Get-AtmLanguage
        try {
            foreach ($lang in @('pt-BR', 'en-US')) {
                Set-AtmLanguage -Requested $lang
                $st = & $tdState $tdRes
                $t = & $tdText $st @{ Name = 'dsum' }
                Assert-True ($t.Contains((Get-AtmText 'tui.diag.noAuth')) -and $t.Contains((Get-AtmText 'tui.diag.unknownNote'))) "29: textos em $lang"
            }
            Assert-True ($script:AtmMessages['pt-BR']['tui.diag.noAuth'] -ceq 'Os resultados não autorizam exclusão de arquivos ou encerramento de processos.') 'aviso exigido, literal em pt-BR'
        } finally { Set-AtmLanguage -Requested $prev }
        Assert-True ([IO.Directory]::Exists($root)) '32: nada alterado'
    }
    Test-Case 'TUI' 'P5-A: escala - milhares de achados e nos paginados (so a pagina visivel e formatada), indices construidos uma vez; memoria e tempo medidos' {
        $f = New-Object System.Collections.Generic.List[object]
        for ($i = 0; $i -lt 5000; $i++) { $f.Add((& $gF 'TempPartition' ('claude-code/p-' + $i.ToString('D5')) 'UNKNOWN')) }
        $nodes = @(foreach ($x in $f) { [pscustomobject]@{ Kind = 'TempPartition'; Key = $x.Key; Finding = $true } })
        $graph = [pscustomobject]@{ Nodes = $nodes; Edges = @(); Summaries = @(); Coverage = [pscustomobject]@{ Status = 'COMPLETE'; Reasons = @(); Nodes = $nodes.Count; Edges = 0; DroppedEdges = 0; StartedUtc = $tdT0; ElapsedMs = 1 } }
        $res = & $tdWrap $f.ToArray() @((& $tdCov 'inventory' 'COMPLETE')) $graph
        [GC]::Collect(); $m0 = [GC]::GetTotalMemory($true)
        $sw = [Diagnostics.Stopwatch]::StartNew(); $st = & $tdState $res 100 30; $build = $sw.ElapsedMilliseconds
        $m1 = [GC]::GetTotalMemory($true)
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $fr = $null
        foreach ($top in @(0, 2500, 4990)) { $fr = & $tdFrame $st @{ Name = 'dlist'; Filter = @{ Cat = 'parts' }; Sel = $top; Top = $top } }
        foreach ($top in @(0, 4990)) { $null = & $tdFrame $st @{ Name = 'dnodes'; Sel = $top; Top = $top } }
        foreach ($k in 1..3) { $null = & $tdFrame $st @{ Name = 'dsum' } }
        $render = $sw.ElapsedMilliseconds
        Assert-True ($fr.Count -le 30 -and ($fr -join "`n").Contains('p-04990') -and $fr[-1].Contains('/5000')) '21: pagina final, posicao/total no rodape, nunca milhares de linhas'
        Assert-True ($render -lt 15000) "8 quadros (listas, nos e resumo) de 5000 itens em $render ms"
        $script:caseNote = "5000 achados/nos: indice+JSON $build ms, 8 quadros (incl. 3 do resumo) $render ms, memoria ~$([math]::Round(($m1 - $m0) / 1MB, 1)) MB"
    }
    Test-Case 'TUI' 'P5-A (estatico): a TUI so chama Invoke-AtmDiagnose (nenhum coletor, Git, Restart Manager, registro ou arquivo), nao muda estados, nao exclui; menu V0.1 preservado; travas fechadas' {
        $tui = [IO.File]::ReadAllText((Join-Path $srcDir 'lib\Tui.ps1'))
        foreach ($pat in @('Get-CimInstance', 'Get-WmiObject', 'Get-Process', 'Get-Service', 'Get-AtmProcessCollection', 'Invoke-AtmServiceQuery', 'Invoke-AtmVirtualizationQuery', 'Get-AtmWorktreeDiscovery', 'Get-AtmHandleEvidence', 'Get-AtmHandleSampleFiles',
                'Invoke-AtmGitCommand', 'git.exe', 'RmStartSession', 'Registry', 'Get-ChildItem', '[IO.File]::Read', 'Get-AtmDependencyGraph', 'Set-AtmGraphFindingStates', 'New-AtmFinding', 'Get-AtmProfiles', 'AtmHandleDiagnosticsEnabled =', 'AtmWorktreeDiagnosticsEnabled =', 'Stop-Process', 'Stop-Service')) {
            Assert-True (-not $tui.Contains($pat)) "31/32: Tui.ps1 sem '$pat'"
        }
        Assert-Eq ([regex]::Matches($tui, 'Invoke-AtmDiagnose @').Count) 1 'um unico ponto que executa o diagnose'
        $keysV01 = @(Get-AtmTuiMenuItems | ForEach-Object { $_.Key }) -join ''
        Assert-Eq $keysV01 '123456789PDLRHQ' '33: menu V0.1 preservado (D acrescentado)'
        Assert-True ($script:AtmRealDeletionEnabled -eq $true -and $shippedDeletionGate -eq $false -and $script:AtmHandleDiagnosticsEnabled -eq $false -and $script:AtmWorktreeDiagnosticsEnabled -eq $false) '34: travas distribuidas fechadas (a suite so abre a de exclusao no sandbox)'
        foreach ($l in @('en-US', 'pt-BR')) { foreach ($k in @('menu.diagnose', 'tui.diag.noAuth', 'tui.diag.failed', 'tui.diag.stale', 'foot.diagList', 'foot.diagText', 'tui.diag.finding.no', 'tui.diag.elevUnknown')) { Assert-True $script:AtmMessages[$l].ContainsKey($k) "$k ($l)" } }
    }
    Test-Case 'Particoes' 'P5-A: defesa em profundidade - achado com registro conclusivo de um coletor e a execucao com um registro pior do mesmo coletor: nenhuma reconstrucao conclui ausencia; positivos inalterados' {
        $own = & $gF 'TempPartition' 'claude-code/p-x' 'RUNTIME_NOT_DIAGNOSED'
        $own = New-AtmFinding -Kind 'TempPartition' -Key 'claude-code/p-x' -State 'RUNTIME_NOT_DIAGNOSED' -Coverage @((& $tdCov 'handles' 'COMPLETE'), (& $tdCov 'process-cwd' 'COMPLETE'))
        $global = @($gCovAll | Where-Object { $_.Collector -cne 'handles' }) + @((& $tdCov 'handles' 'COMPLETE'), (& $tdCov 'handles' 'NOT_OBSERVABLE' @('HANDLE_SECURITY_GATE_CLOSED')))
        $fake = [pscustomobject]@{ Summaries = @([pscustomobject]@{ Kind = 'TempPartition'; Key = 'claude-code/p-x'; Dependency = 'NONE_OBSERVED'; Strength = $null; Incoming = 0; Roots = [string[]]@(); IncompleteCoverage = [string[]]@(); Reasons = [string[]]@() }); Edges = @()
            Coverage = [pscustomobject]@{ Status = 'COMPLETE'; Reasons = @(); Nodes = 1; Edges = 0; DroppedEdges = 0; StartedUtc = $tdT0; ElapsedMs = 1 } }
        $r = @(Set-AtmGraphFindingStates -Findings @($own) -Graph $fake -Coverage $global -GraphCoverage (ConvertTo-AtmGraphCoverage -Graph $fake))[0]
        Assert-True ($r.State -ceq 'UNKNOWN' -and $r.RequestedState -ceq 'NO_DEPENDENCY_OBSERVED' -and @($r.Coverage | Where-Object { $_.Collector -ceq 'handles' -and $_.Status -ceq 'NOT_OBSERVABLE' }).Count -eq 1) '35: o pior registro da execucao e anexado e a ausencia e recusada'
        $okCov = @($gCovAll)
        $r2 = @(Set-AtmGraphFindingStates -Findings @($own) -Graph $fake -Coverage $okCov -GraphCoverage (ConvertTo-AtmGraphCoverage -Graph $fake))[0]
        Assert-Eq $r2.State 'NO_DEPENDENCY_OBSERVED' 'cobertura toda conclusiva (fixture): sem regressao'
        $pos = & $bState (@($gProcF) + @(& $bTp 'a')) $global @((& $gPart 'a' @('PID 102 (node.exe)')))
        Assert-Eq (& $bFind $pos 'claude-code/p-a').State 'IN_USE' 'positivo DIRECT inalterado com registro pior de outro coletor'
    }
    # ------------------------------------------------------------------ P5-B (CLI, JSON contract, export, documentation)
    # The schema document is the contract: every exported object has exactly its documented fields, with the documented
    # types (string, number, integer, boolean, array, object, "... or null").
    $sdSec = @{}; $sdCur = $null
    foreach ($l in [IO.File]::ReadAllLines((Join-Path (Split-Path -Parent $testsDir) 'docs\DIAGNOSE-SCHEMA.md'))) {
        # Field names are case-sensitive in JSON: an ordinal dictionary.
        if ($l -match '^## (.+)$') { $sdCur = $Matches[1].Trim(); $sdSec[$sdCur] = New-Object System.Collections.Specialized.OrderedDictionary ([StringComparer]::Ordinal); continue }
        if ($sdCur -and $l -match '^\| `([A-Za-z][A-Za-z0-9]*)` \| ([^|]+) \|') { $sdSec[$sdCur][$Matches[1]] = $Matches[2].Trim() }
    }
    $sdType = { param($v)
        if ($null -eq $v) { return 'null' }
        if ($v -is [bool]) { return 'boolean' }
        if ($v -is [string] -or $v -is [datetime]) { return 'string' }
        if ($v -is [int] -or $v -is [long] -or $v -is [int16] -or $v -is [byte]) { return 'integer' }
        if ($v -is [double] -or $v -is [decimal] -or $v -is [single]) { return 'number' }
        if ($v -is [array] -or $v -is [Collections.IList]) { return 'array' }
        if ($v -is [pscustomobject] -or $v -is [Collections.IDictionary]) { return 'object' }
        return $v.GetType().Name }
    $script:sdHits = @{}
    $sdCheck = { param($Obj, [string]$Sec, $Errs)
        if (-not $sdSec.ContainsKey($Sec)) { $Errs.Add("secao ausente no documento: $Sec"); return }
        $script:sdHits[$Sec] = 1 + $(if ($script:sdHits.ContainsKey($Sec)) { $script:sdHits[$Sec] } else { 0 })
        $doc = $sdSec[$Sec]
        $names = @($Obj.PSObject.Properties | ForEach-Object { $_.Name })
        foreach ($n in $names) { if (-not $doc.Contains($n)) { $Errs.Add("${Sec}: campo exportado e nao documentado: $n") } }
        foreach ($n in @($doc.Keys)) {
            if ($names -cnotcontains $n) { $Errs.Add("${Sec}: campo documentado ausente: $n"); continue }
            $t = & $sdType $Obj.$n; $allowed = @($doc[$n] -split ' or ' | ForEach-Object { $_.Trim() })
            if (-not ($allowed -contains $t -or ($t -ceq 'integer' -and $allowed -contains 'number') -or ($t -ceq 'number' -and $allowed -contains 'integer' -and [math]::Floor([double]$Obj.$n) -eq [double]$Obj.$n))) { $Errs.Add("${Sec}.${n}: tipo $t, documentado $($doc[$n])") }
        } }
    $sdValidate = { param([string]$Json)
        $e = New-Object System.Collections.Generic.List[string]
        $j = $Json | ConvertFrom-Json
        & $sdCheck $j 'Top level' $e; & $sdCheck $j.identity 'identity' $e; & $sdCheck $j.pseudonymization 'pseudonymization' $e; & $sdCheck $j.inventory 'inventory' $e
        foreach ($x in @($j.providers)) { & $sdCheck $x 'providers[]' $e }
        foreach ($x in @($j.coverage)) { & $sdCheck $x 'coverage[]' $e }
        foreach ($x in @($j.findings)) { & $sdCheck $x 'findings[]' $e; foreach ($ev in @($x.evidence)) { & $sdCheck $ev 'findings[].evidence[]' $e } }
        & $sdCheck $j.agentResources 'agentResources' $e
        if ($null -ne $j.agentResources.counters) { & $sdCheck $j.agentResources.counters 'agentResources.counters' $e; foreach ($pp in $j.agentResources.counters.PSObject.Properties) { & $sdCheck $pp.Value 'agentResources.counters.*' $e } }
        if ($null -ne $j.graph) {
            & $sdCheck $j.graph 'graph' $e; & $sdCheck $j.graph.coverage 'graph.coverage' $e
            foreach ($x in @($j.graph.nodes)) { & $sdCheck $x 'graph.nodes[]' $e }
            foreach ($x in @($j.graph.edges)) { & $sdCheck $x 'graph.edges[]' $e; foreach ($ev in @($x.evidence)) { & $sdCheck $ev 'graph.edges[].evidence[]' $e } }
            foreach ($x in @($j.graph.summaries)) { & $sdCheck $x 'graph.summaries[]' $e }
        }
        return [pscustomobject]@{ Errors = $e.ToArray(); Json = $j } }

    Test-Case 'Diagnose' 'P5-B: contrato JSON - todo objeto exportado tem exatamente os campos e tipos do DIAGNOSE-SCHEMA (sintetico com grafo, execucao integrada, prazo 0, sem providers); listas vazias como arrays, null preservado, ids estaveis' {
        $p = New-TestProfile 'p5b-json'
        $null = New-TestRoot -ProfileInfo $p
        $real = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p)) -IdentitySource $diagIdUser -PseudonymKey $testPseudonymKey -ServiceSource { param($Names) @() } -VirtualizationSource (& $vSrc (& $vBase @($vHostRow)))
        $zero = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p)) -IdentitySource $diagIdUser -DeadlineSeconds 0
        $none = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p)) -IdentitySource $diagIdUser -Providers @() -ServiceSource { param($Names) @() } -VirtualizationSource (& $vSrc (& $vBase @($vHostRow)))
        foreach ($case in @(@('sintetico', $tdRes), @('integrado', $real), @('prazo 0', $zero), @('sem providers', $none))) {
            $raw = ConvertTo-AtmDiagnoseJson -Result $case[1]
            $v = & $sdValidate $raw
            Assert-Eq ($v.Errors -join ' | ') '' "1/2/15 ($($case[0])): campos e tipos iguais ao documento"
            $j = $v.Json
            # 5: identifiers stable inside the run: edges point to nodes, own-finding nodes are findings, keys unique per kind.
            if ($null -ne $j.graph) {
                $nodeKeys = @{}; foreach ($n in @($j.graph.nodes)) { $nodeKeys[[string]$n.kind + '|' + [string]$n.key] = $n }
                $findKeys = @{}; foreach ($f in @($j.findings)) { $findKeys[[string]$f.kind + '|' + [string]$f.key] = $true }
                Assert-True (@($j.graph.edges | Where-Object { -not $nodeKeys.ContainsKey([string]$_.fromKind + '|' + [string]$_.from) -or -not $nodeKeys.ContainsKey([string]$_.toKind + '|' + [string]$_.to) }).Count -eq 0) "5 ($($case[0])): toda aresta liga nos existentes"
                Assert-True (@($j.graph.nodes | Where-Object { $_.finding -and -not $findKeys.ContainsKey([string]$_.kind + '|' + [string]$_.key) }).Count -eq 0) "5/finding=false ($($case[0])): no com achado proprio corresponde a um achado; os demais sao referencias"
            }
            # 8/10: incomplete coverage kept, never a conclusive absence on top of it.
            $covSt = @{}; foreach ($c in @($j.coverage)) { if (-not $covSt.ContainsKey([string]$c.collector) -or $script:AtmConclusiveCoverage -ccontains $covSt[[string]$c.collector]) { $covSt[[string]$c.collector] = [string]$c.status } }
            Assert-Eq ([bool]$j.coverageComplete) (@($j.coverage | Where-Object { $script:AtmConclusiveCoverage -cnotcontains [string]$_.status }).Count -eq 0) "8 ($($case[0])): coverageComplete coerente com os registros"
            foreach ($f in @($j.findings | Where-Object { @($script:AtmNoDependencyStates) + @($script:AtmAbsenceStates) -ccontains [string]$_.state })) {
                Assert-True (@($f.incompleteCoverage).Count -eq 0 -and @(@($f.coverage) | Where-Object { $script:AtmConclusiveCoverage -cnotcontains $covSt[[string]$_] }).Count -eq 0) "10 ($($case[0])): ausencia $($f.state) so com cobertura conclusiva"
            }
            # 9: positive states carry their evidence.
            foreach ($f in @($j.findings | Where-Object { [string]$_.state -ceq 'IN_USE' })) { Assert-True (@(@($f.evidence) | Where-Object { [string]$_.code -like 'GRAPH_SOURCE_DIRECT' -or [string]$_.code -ceq 'FILE_HELD_OPEN' }).Count -gt 0) "9 ($($case[0])): IN_USE com evidencia direta" }
            # 3/4: raw text keeps empty lists as arrays and absent values as null.
            Assert-True (-not ($raw -match '"(providers|coverage|findings|reasons|evidence|capabilities|incompleteCoverage|roots|nodes|edges|summaries)":\s*(\{\}|null)')) "3 ($($case[0])): listas nunca como {} ou null"
        }
        foreach ($sec in @($sdSec.Keys)) { Assert-True ($script:sdHits.ContainsKey($sec)) "15: secao '$sec' do documento exercitada por algum dos casos" }
        Assert-True ((ConvertTo-AtmDiagnoseJson -Result $tdRes) -match '"keyId":\s*null') '4: null preservado (keyId de chave efemera)'
        Assert-True ((ConvertTo-AtmDiagnoseJson -Result $none) -match '"providers":\s*\[\s*\]') '3: sem providers: lista vazia'
        $nc = @($none.Coverage | Where-Object { $_.Collector -ceq 'profile-discovery' })[0]
        Assert-True ($null -ne $nc -and $nc.Status -ceq 'NOT_OBSERVABLE' -and @($none.Findings | Where-Object { @($script:AtmNoDependencyStates) + @($script:AtmAbsenceStates) -ccontains $_.State }).Count -eq 0) 'H1: todos os providers ausentes - nada concluido, descoberta nao executada'
        # 11: the same result in both languages differs only in "language".
        $prev = Get-AtmLanguage
        try { Set-AtmLanguage -Requested 'pt-BR'; $jp = ConvertTo-AtmDiagnoseJson -Result $real; Set-AtmLanguage -Requested 'en-US'; $je = ConvertTo-AtmDiagnoseJson -Result $real } finally { Set-AtmLanguage -Requested $prev }
        Assert-Eq ($je -replace '"language":\s*"[^"]*"', '') ($jp -replace '"language":\s*"[^"]*"', '') '11: pt-BR e en-US identicos salvo language'
        foreach ($x in @($p.ProfilePath.Replace('\', '\\'), 'C:\\Users\\', 'node.exe', 'CommandLine')) { Assert-True (-not $jp.Contains($x)) "6/7: JSON sem '$x'" }
    }
    Test-Case 'Diagnose' 'P5-B: exportacao (trava aberta so no harness, em fixtures) - destinos proibidos recusados (relativo, rede, dispositivo, fluxo, travessia, dentro de base, repositorio, worktree, juncao no caminho, existente, sem inventario) sem criar arquivo; destino valido criado sem sobrescrever; falha de escrita sem mensagem' {
        $root = Join-Path $sandbox 'p5b-export'
        $base = Join-Path $root 'base'; $repo = Join-Path $root 'repo'; $wt = Join-Path $root 'wt'; $out = Join-Path $root 'out'; $real = Join-Path $root 'real'
        foreach ($d in @($base, (Join-Path $repo '.git'), $wt, $out, $real, (Join-Path $repo 'sub'))) { [void][IO.Directory]::CreateDirectory($d) }
        [IO.File]::WriteAllText((Join-Path $wt '.git'), 'gitdir: elsewhere')
        $junc = Join-Path $root 'junc'; New-Junction $junc $real
        [IO.File]::WriteAllText((Join-Path $out 'exists.json'), 'x')
        $inv = [pscustomobject]@{ Bases = @([pscustomobject]@{ Path = $base }) }
        # P5-B-S: the export gate is opened only around these disposable fixtures and closed again in finally.
        $script:AtmDiagnoseExportEnabled = $true
        try {
        $cases = [ordered]@{
            'relativo' = 'out\x.json'; 'rede' = '\\server\share\x.json'; 'dispositivo' = '\\?\C:\x.json'; 'fluxo' = ($out + '\x.json:ads'); 'travessia' = ($out + '\..\out\x.json')
            'dentro da base' = (Join-Path $base 'x.json'); 'repositorio' = (Join-Path $repo 'sub\x.json'); 'worktree' = (Join-Path $wt 'x.json'); 'juncao' = (Join-Path $junc 'x.json'); 'existente' = (Join-Path $out 'exists.json')
            'variavel' = ($out + '\%TEMP%\x.json'); 'pai inexistente' = (Join-Path $out 'nope\x.json')
        }
        foreach ($k in $cases.Keys) {
            $code = Test-AtmDiagnoseExportPath -Path $cases[$k] -Inventory $inv
            Assert-True ($null -ne $code -and $code -cmatch '^EXPORT_[A-Z_]+$') "12: $k recusado ($code)"
        }
        Assert-Eq (Test-AtmDiagnoseExportPath -Path (Join-Path $repo 'sub\x.json') -Inventory $inv) 'EXPORT_INSIDE_REPOSITORY' 'repositorio: codigo proprio'
        $bare = Join-Path $root 'bare.git'; foreach ($d in @((Join-Path $bare 'objects'), (Join-Path $bare 'refs'), (Join-Path $bare 'x'))) { [void][IO.Directory]::CreateDirectory($d) }; [IO.File]::WriteAllText((Join-Path $bare 'HEAD'), 'ref: refs/heads/main')
        Assert-Eq (Test-AtmDiagnoseExportPath -Path (Join-Path $bare 'x\y.json') -Inventory $inv) 'EXPORT_INSIDE_REPOSITORY' 'repositorio bare (HEAD, objects, refs): recusado'
        Assert-True (-not [AgentTempManager.AtmPathCheck]::IsSubstitutedDrive($out)) 'unidade comum nao e substituida'
        # A substituted drive letter, when one is free (subst of a sandbox folder; removed at the end, as the portability test does).
        $sl = $null; foreach ($l in [char[]]'QRSTUVWXYZ') { if (-not (Test-Path "$($l):\")) { $sl = $l; break } }
        if ($sl) {
            $null = cmd /c subst "$($sl):" "`"$base`"" 2>&1
            try { if (Test-Path "$($sl):\") { Assert-True ([AgentTempManager.AtmPathCheck]::IsSubstitutedDrive("$($sl):\x.json") -and (Test-AtmDiagnoseExportPath -Path "$($sl):\x.json" -Inventory $inv) -ceq 'EXPORT_SUBSTITUTED_DRIVE' -and -not (Test-Path -LiteralPath (Join-Path $base 'x.json'))) 'subst de uma base: recusado (EXPORT_SUBSTITUTED_DRIVE), nada criado' } }
            finally { $null = cmd /c subst "$($sl):" /d 2>&1 }
        }
        Assert-Eq (Test-AtmDiagnoseExportPath -Path (Join-Path $out 'ok.json') -Inventory $null) 'EXPORT_INVENTORY_NOT_RUN' 'sem inventario: recusado'
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $real 'x.json')) -and -not (Test-Path -LiteralPath (Join-Path $repo 'sub\x.json'))) 'nenhum arquivo criado por uma recusa'
        $ok = Join-Path $out 'ok.json'
        Assert-True ($null -eq (Test-AtmDiagnoseExportPath -Path $ok -Inventory $inv)) 'destino valido aceito'
        Assert-Eq (Write-AtmNewTextFile -Path $ok -Text (ConvertTo-AtmDiagnoseJson -Result $tdRes) -Inventory $inv) $null 'gravado (FINAL-A: pinado e relativo ao handle)'
        Assert-Eq ((& $sdValidate ([IO.File]::ReadAllText($ok))).Errors -join ' | ') '' 'arquivo gravado e valido'
        $again = Write-AtmNewTextFile -Path $ok -Text 'other' -Inventory $inv
        Assert-True ($null -ne $again -and ([IO.File]::ReadAllText($ok)).StartsWith('{')) "14: nunca sobrescreve ($again)"
        $miss = Write-AtmNewTextFile -Path (Join-Path $out 'nope\y.json') -Text 'x' -Inventory $inv
        Assert-True ($null -ne $miss -and $miss -cmatch '^EXPORT_[A-Z0-9_]+$') "14: pasta inexistente recusada por codigo ($miss)"
        } finally { $script:AtmDiagnoseExportEnabled = $false }
        Assert-Eq $script:AtmDiagnoseExportEnabled $false 'trava fechada de novo'
        $cli = [IO.File]::ReadAllText((Join-Path $srcDir 'agent-temp.ps1'))
        $blk = $cli.Substring($cli.IndexOf("'diagnose' {"), $cli.IndexOf("'clean' {") - $cli.IndexOf("'diagnose' {"))
        Assert-True ($blk.Contains('Test-AtmDiagnoseExportPath') -and $blk.Contains('Write-AtmNewTextFile') -and -not $blk.Contains('Exception.Message') -and -not $blk.Contains('WriteAllText')) '14: CLI diagnose usa o caminho verificado e nunca mostra a mensagem da excecao'
        # Everything of the branch that touches collected data runs inside a type-only catch (never the global catch).
        Assert-True ($blk -match 'try \{ \$res = Invoke-AtmDiagnose' -and $blk -match 'try \{ Show-AtmDiagnose -Result \$res \}' -and $blk -match 'try \{ \$refusal = Test-AtmDiagnoseExportPath' -and $blk -match 'try \{ \$written = Write-AtmNewTextFile -Path \$ExportJson -Text \(ConvertTo-AtmDiagnoseJson -Result \$res\) -Inventory \$res\.Inventory \}' -and ([regex]::Matches($blk, 'GetBaseException\(\)\.GetType\(\)\.Name').Count -ge 4)) '2: diagnose, relatorio, verificacao e gravacao com captura so pelo tipo'
    }
    Test-Case 'Diagnose' 'P5-B-S: trava da exportacao fechada - CLI recusa com EXPORT_SECURITY_GATE_CLOSED (codigo 10) antes de coletar ou verificar o destino; nenhum arquivo; escritor e verificacao tambem recusam; contraprova do TOCTOU (nao resolvido) so com a trava aberta no harness' {
        Assert-Eq $script:AtmDiagnoseExportEnabled $false 'trava fechada fora dos testes'
        $rep = [IO.File]::ReadAllText((Join-Path $srcDir 'lib\Report.ps1'))
        Assert-Eq ([regex]::Matches($rep, '\$script:AtmDiagnoseExportEnabled\s*=').Count) 1 'uma unica atribuicao da trava'
        Assert-True ($rep -match '(?m)^\$script:AtmDiagnoseExportEnabled = \$false\r?$') 'a trava distribuida e $false (linha inteira)'
        $srcAll = @(Get-ChildItem -LiteralPath $srcDir -Recurse -File | Where-Object { $_.Extension -in @('.ps1', '.psm1', '.psd1', '.cs', '.json', '.cmd', '.bat') } | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Text = [IO.File]::ReadAllText($_.FullName) } })
        Assert-Eq (@($srcAll | ForEach-Object { [regex]::Matches($_.Text, '\$script:AtmDiagnoseExportEnabled\s*=').Count } | Measure-Object -Sum).Sum) 1 'nenhuma outra atribuicao em src (CLI, TUI, configuracao)'
        Assert-True (@($srcAll | Where-Object { $_.Name -notin @('Report.ps1', 'agent-temp.ps1') -and $_.Text.Contains('AtmDiagnoseExportEnabled') }).Count -eq 0 -and -not (@($srcAll | ForEach-Object { $_.Text }) -join "`n").Contains('$env:ATM_DIAGNOSE_EXPORT')) 'nenhuma opcao, variavel de ambiente ou configuracao abre a trava'
        # Any spelling counts (bare variable at script scope, Set-Variable): mentions pinned per file (1 assignment + 2 reads; 1 read).
        Assert-Eq ([regex]::Matches(($srcAll | Where-Object { $_.Name -eq 'Report.ps1' }).Text, 'AtmDiagnoseExportEnabled').Count) 3 'Report.ps1: uma atribuicao e duas leituras'
        Assert-Eq ([regex]::Matches(($srcAll | Where-Object { $_.Name -eq 'agent-temp.ps1' }).Text, 'AtmDiagnoseExportEnabled').Count) 1 'agent-temp.ps1: uma leitura'
        Assert-True (-not ((@($srcAll | ForEach-Object { $_.Text }) -join "`n") -match '(?i)(Set|New)-Variable[^\r\n]*DiagnoseExport')) 'nenhum Set-Variable/New-Variable da trava'
        $cli = ($srcAll | Where-Object { $_.Name -eq 'agent-temp.ps1' }).Text
        $blk = $cli.Substring($cli.IndexOf("'diagnose' {"), $cli.IndexOf("'clean' {") - $cli.IndexOf("'diagnose' {"))
        $gateAt = $blk.IndexOf('-not $script:AtmDiagnoseExportEnabled')
        Assert-True ($gateAt -gt 0 -and $gateAt -lt $blk.IndexOf('Invoke-AtmDiagnose') -and $gateAt -lt $blk.IndexOf('Test-AtmDiagnoseExportPath') -and $gateAt -lt $blk.IndexOf('Write-AtmNewTextFile')) '5: o fluxo do diagnose recusa antes de coletar, verificar o destino ou gravar'
        # 1-5: through the launcher, with a destination whose folder does not exist (a check would answer with another code) and a valid one.
        $cmd = Join-Path $srcDir 'bin\agent-temp.cmd'
        $okDir = Join-Path $sandbox 'p5bs-ok'; [void][IO.Directory]::CreateDirectory($okDir)
        foreach ($t in @((Join-Path $sandbox 'p5bs-missing\x.json'), (Join-Path $okDir 'd.json'))) {
            $o = (& cmd.exe /c "`"$cmd`" diagnose -DeadlineSeconds 0 -NoProgress -Lang en-US -ExportJson `"$t`"" 2>&1) -join "`n"
            $code = $LASTEXITCODE
            Assert-True ($code -eq 10 -and $o.Contains('EXPORT_SECURITY_GATE_CLOSED') -and -not $o.Contains('EXPORT_DESTINATION') -and -not $o.Contains('COVERAGE BY COLLECTOR') -and -not (Test-Path -LiteralPath $t)) "1-5: recusado com codigo 10, sem verificacao, sem coleta, sem arquivo ($code)"
        }
        Assert-True (@(Get-ChildItem -LiteralPath $okDir -Force).Count -eq 0 -and -not (Test-Path -LiteralPath (Join-Path $sandbox 'p5bs-missing'))) '3/4: nenhuma gravacao nem pasta criada'
        # 6: the writer and the check refuse by themselves too.
        $w = Join-Path $okDir 'w.json'
        $msg = $null; try { Write-AtmNewTextFile -Path $w -Text '{}' } catch { $msg = $_.Exception.GetBaseException().Message }
        Assert-True ($msg -ceq 'EXPORT_SECURITY_GATE_CLOSED' -and -not (Test-Path -LiteralPath $w)) '6: escritor chamado diretamente recusa, nada criado'
        Assert-Eq (Test-AtmDiagnoseExportPath -Path $w -Inventory ([pscustomobject]@{ Bases = @() })) 'EXPORT_SECURITY_GATE_CLOSED' 'verificacao recusa com a trava fechada'
        # 9: counter-proof with the gate open in the harness only: a folder validated by name and then replaced by a junction
        # redirects a file created BY NAME (CreateNew does not prevent it); the pinned writer of FINAL-A refuses instead.
        $tt = Join-Path $sandbox 'p5bs-toctou'; $a = Join-Path $tt 'a'; $elsewhere = Join-Path $tt 'elsewhere'
        foreach ($d in @($a, $elsewhere)) { [void][IO.Directory]::CreateDirectory($d) }
        $dest = Join-Path $a 'r.json'
        $script:AtmDiagnoseExportEnabled = $true
        try {
            Assert-True ($null -eq (Test-AtmDiagnoseExportPath -Path $dest -Inventory ([pscustomobject]@{ Bases = @() }))) 'contraprova: destino validado'
            [IO.Directory]::Move($a, (Join-Path $tt 'a-moved'))
            New-Junction $a $elsewhere
            $byName = [IO.File]::Open($dest, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None); $byName.Dispose()
            Assert-True ((Test-Path -LiteralPath (Join-Path $elsewhere 'r.json')) -and -not (Test-Path -LiteralPath (Join-Path $tt 'a-moved\r.json'))) '9: contraprova - criacao POR NOME depois da verificacao segue a juncao trocada (o risco que a trava contem)'
            $w9 = Write-AtmNewTextFile -Path (Join-Path $a 'r3.json') -Text '{}' -Inventory ([pscustomobject]@{ Bases = @() })
            Assert-True ($w9 -ceq 'EXPORT_PIN_PARENT_REPARSE_POINT' -and -not (Test-Path -LiteralPath (Join-Path $elsewhere 'r3.json'))) "o escritor pinado recusa a juncao ($w9)"
            Assert-True ($null -ne (Test-AtmDiagnoseExportPath -Path (Join-Path $a 'r2.json') -Inventory ([pscustomobject]@{ Bases = @() }))) 'uma nova verificacao ve a juncao (a janela e entre verificar e criar)'
        } finally { $script:AtmDiagnoseExportEnabled = $false }
        Assert-Eq $script:AtmDiagnoseExportEnabled $false '10: trava false depois do teste'
    }
    Test-Case 'Diagnose' 'FINAL-A: criacao segura de arquivo (fixtures) - ancestrais e pasta pinados por handle sem compartilhamento de exclusao, criacao relativa ao handle (OBJ_DONT_REPARSE, nunca nome existente), DACL protegida, verificacao antes de escrever; conversao da pasta em juncao DENTRO da janela pinada (deterministica, FSCTL); politica reavaliada dentro da janela' {
        $fa = Join-Path $sandbox 'finala'; $anc = Join-Path $fa 'anc'; $par = Join-Path $anc 'par'; $else = Join-Path $fa 'else'
        foreach ($d in @($par, $else)) { [void][IO.Directory]::CreateDirectory($d) }
        $none = [pscustomobject]@{ Bases = @() }
        # Deterministic: while pinned, neither the folder nor an ancestor can be renamed (and so not replaced by a junction).
        $s = [AgentTempManager.AtmSafeCreate]::Pin($par)
        try {
            Assert-True ($s.IsPinned -and $null -eq $s.Error) "pinado ($($s.Error))"
            foreach ($victim in @($par, $anc)) { $moved = $false; try { [IO.Directory]::Move($victim, $victim + '-x'); $moved = $true } catch { $null = $_ }; Assert-True (-not $moved) "renomear $(Split-Path $victim -Leaf) com a pasta pinada: recusado (compartilhamento)" }
            Assert-Eq ([AgentTempManager.AtmSafeCreate]::CreateNew($s, 'd.json', [Text.Encoding]::UTF8.GetBytes('{"a":1}'))) $null 'arquivo criado relativo ao handle'
            Assert-Eq ([AgentTempManager.AtmSafeCreate]::CreateNew($s, 'd.json', [byte[]]@(1))) 'EXISTS' 'nome existente: nunca sobrescreve'
            foreach ($bad in @('NUL.json', 'CON', 'a:b', 'x\y', '..', 'a.', 'COM1.txt', 'z*', ('COM' + [char]0xB9), ('LPT' + [char]0xB2 + '.txt'))) { Assert-Eq ([AgentTempManager.AtmSafeCreate]::CreateNew($s, $bad, [byte[]]@(1))) 'FILE_NAME_INVALID' "nome invalido '$bad'" }
            $null = cmd /c "mklink /J `"$par\j`" `"$else`" >nul 2>nul"
            Assert-True ((Test-Path -LiteralPath "$par\j") -and [AgentTempManager.AtmSafeCreate]::CreateNew($s, 'j', [byte[]]@(1)) -ceq 'EXISTS' -and @(Get-ChildItem -LiteralPath $else -Force).Count -eq 0) 'juncao no nome do arquivo: recusada, nada no alvo'
            # Without the privilege mklink fails on stderr: redirected inside cmd (a native stderr line is terminating here).
            $null = cmd /c "mklink `"$par\s.json`" `"$else\t.json`" >nul 2>nul"
            if (Test-Path -LiteralPath "$par\s.json") { Assert-True ([AgentTempManager.AtmSafeCreate]::CreateNew($s, 's.json', [byte[]]@(1)) -ceq 'EXISTS' -and -not (Test-Path -LiteralPath "$else\t.json")) 'symlink de arquivo no nome: recusado, alvo nao criado'; $script:caseNote = 'symlink de arquivo: testado' }
            else { $script:caseNote = 'symlink de arquivo: NAO_TESTADO (sem privilegio para criar)' }
        } finally { $s.Dispose() }
        Assert-Eq ([IO.File]::ReadAllText((Join-Path $par 'd.json'))) '{"a":1}' 'conteudo gravado depois da verificacao'
        $acl = Get-Acl -LiteralPath (Join-Path $par 'd.json')
        $sids = @($acl.Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)
        Assert-True ($acl.AreAccessRulesProtected -and (@($sids) -join ',') -ceq 'S-1-3-4,S-1-5-18,S-1-5-32-544') "DACL protegida: dono (OWNER RIGHTS), SYSTEM, Administradores ($($sids -join ','))"
        # Before pinning: a folder already swapped for a junction (or a junction above it) is refused, nothing in the target.
        [IO.Directory]::Move($par, $par + '-moved'); New-Junction $par $else
        $s2 = [AgentTempManager.AtmSafeCreate]::Pin($par); $e2 = $s2.Error; $s2.Dispose()
        $s3 = [AgentTempManager.AtmSafeCreate]::Pin((Join-Path $par 'sub')); $e3 = $s3.Error; $s3.Dispose()
        Assert-True ($e2 -ceq 'PARENT_REPARSE_POINT' -and $e3 -ceq 'ANCESTOR_REPARSE_POINT' -and @(Get-ChildItem -LiteralPath $else -Force | Where-Object { $_.Name -ne 'j' }).Count -eq 0) "pasta ou ancestral trocados antes do pin: recusados ($e2, $e3)"
        foreach ($bp in @('relative\dir', '\\server\share\dir', 'C:\', ($fa + '\anc\..\anc'))) { $sb = [AgentTempManager.AtmSafeCreate]::Pin($bp); Assert-True (-not $sb.IsPinned) "pin recusado: $bp ($($sb.Error))"; $sb.Dispose() }
        # FINAL-A review (M-1), deterministic, INSIDE the pinned window: share modes do not stop another handle with
        # FILE_WRITE_ATTRIBUTES from turning the pinned (empty) folder into a junction in place (FSCTL_SET_REPARSE_POINT).
        # CreateNew must refuse (the folder is re-checked; the creation never follows a reparse point), nothing in the target.
        Initialize-AtmTestReparse
        $ip = Join-Path $fa 'inplace'; $ipt = Join-Path $fa 'inplace-target'; foreach ($d in @($ip, $ipt)) { [void][IO.Directory]::CreateDirectory($d) }
        $ip = [AgentTempManager.AtmNative]::GetLongPath($ip); $ipt = [AgentTempManager.AtmNative]::GetLongPath($ipt)
        $si = [AgentTempManager.AtmSafeCreate]::Pin($ip)
        try {
            Assert-True $si.IsPinned "pasta vazia pinada ($($si.Error))"
            $set = [AtmTestReparse]::SetJunction($ip, $ipt)
            Assert-Eq $set 'SET_OK' 'juncao gravada na pasta pinada por outro handle (o pin nao impede: limite documentado)'
            $ci = [AgentTempManager.AtmSafeCreate]::CreateNew($si, 'in.json', [byte[]]@(123, 125))
            Assert-True ($null -ne $ci -and @(Get-ChildItem -LiteralPath $ipt -Force).Count -eq 0) "conversao em juncao dentro da janela: recusada ($ci), nada no alvo"
            $script:caseNote = "$script:caseNote; FSCTL na janela: $ci"
        } finally { $si.Dispose() }
        # The fixture folder is now a junction link (removing it removes only the link).
        if (([IO.File]::GetAttributes($ip) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { [IO.Directory]::Delete($ip, $false) }
        # The policy runs again inside the pinned window: a .git created after a by-name pre-check still refuses.
        $pol = Join-Path $fa 'pol'; [void][IO.Directory]::CreateDirectory($pol)
        $script:AtmDiagnoseExportEnabled = $true
        try {
            Assert-True ($null -eq (Test-AtmDiagnoseExportPath -Path (Join-Path $pol 'x.json') -Inventory $none)) 'pre-verificacao por nome aceita'
            [void][IO.Directory]::CreateDirectory((Join-Path $pol '.git'))
            Assert-Eq (Write-AtmNewTextFile -Path (Join-Path $pol 'x.json') -Text '{}' -Inventory $none) 'EXPORT_INSIDE_REPOSITORY' 'politica reavaliada sob o pin: repositorio criado depois recusado'
            Assert-True (-not (Test-Path -LiteralPath (Join-Path $pol 'x.json'))) 'nada criado'
        } finally { $script:AtmDiagnoseExportEnabled = $false }
        Assert-Eq $script:AtmDiagnoseExportEnabled $false 'trava fechada de novo'
    }
    Test-Case 'Diagnose' 'FINAL-A: corrida adversarial antes do pin (estocastica, fixtures) - a pasta trocada por juncao em laco; arquivo criado ou recusado, nunca no alvo da juncao; sem troca durante as criacoes: NAO_TESTADO' {
        # Adversarial race (stochastic, BEFORE the pin): another runspace swaps the folder with a junction in a loop between
        # iterations, so Pin meets the folder, the junction or nothing; it does not attack inside the pinned window (that is
        # the deterministic FSCTL case above). A file may be created or refused, but never in the junction target.
        $fa = Join-Path $sandbox 'finala-race'; $rd = Join-Path $fa 'race'; $rt = Join-Path $fa 'race-target'; foreach ($d in @($rd, $rt)) { [void][IO.Directory]::CreateDirectory($d) }
        $flag = [hashtable]::Synchronized(@{ Stop = $false; Swaps = 0; Errors = 0 })
        $ps = [PowerShell]::Create()
        [void]$ps.AddScript({ param($Dir, $Target, $Flag)
            while (-not $Flag.Stop) {
                try {
                    [IO.Directory]::Move($Dir, $Dir + '-real')
                    try { $null = cmd /c "mklink /J `"$Dir`" `"$Target`" >nul 2>nul"; Start-Sleep -Milliseconds 2; if ((Test-Path -LiteralPath $Dir) -and ((Get-Item -LiteralPath $Dir -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { for ($k = 0; $k -lt 500; $k++) { try { [IO.Directory]::Delete($Dir, $false); break } catch { Start-Sleep -Milliseconds 1 } } } }
                    finally { if (-not (Test-Path -LiteralPath $Dir)) { [IO.Directory]::Move($Dir + '-real', $Dir) } }
                    $Flag.Swaps++
                }
                catch { $Flag.Errors++; Start-Sleep -Milliseconds 1 }
            } }).AddArgument($rd).AddArgument($rt).AddArgument($flag)
        $h = $ps.BeginInvoke()
        $made = 0; $refused = 0; $i = 0; $during = 0
        try {
            # The swapper must really be running before the creations start (bounded wait); then at least 150 creations,
            # continued (up to 1500) until 3 swaps completed while they ran.
            $w = [Diagnostics.Stopwatch]::StartNew(); while ($flag.Swaps -eq 0 -and $w.ElapsedMilliseconds -lt 10000) { Start-Sleep -Milliseconds 10 }
            $s0 = $flag.Swaps
            for (; $i -lt 1500 -and ($i -lt 150 -or ($flag.Swaps - $s0) -lt 3); $i++) {
                $sr = [AgentTempManager.AtmSafeCreate]::Pin($rd)
                try { if ($sr.IsPinned -and $null -eq [AgentTempManager.AtmSafeCreate]::CreateNew($sr, "f$i.json", [byte[]]@(123, 125))) { $made++ } else { $refused++ } } finally { $sr.Dispose() }
            }
            $during = $flag.Swaps - $s0
        } finally { $flag.Stop = $true; try { [void]$ps.EndInvoke($h) } catch { $null = $_ }; $ps.Dispose() }
        # A pinned junction cannot be deleted at once: the swapper retries, so it never stays stuck in one state.
        $endedSwapped = Test-Path -LiteralPath ($rd + '-real')
        # Fixture restored (the swapper may stop between its steps): the junction link goes, the real folder comes back.
        # Only a junction link is ever removed here (never a real folder); the real folder is moved back when its name is free.
        if (Test-Path -LiteralPath ($rd + '-real')) {
            if ((Test-Path -LiteralPath $rd) -and ((Get-Item -LiteralPath $rd -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { [IO.Directory]::Delete($rd, $false) }
            if (-not (Test-Path -LiteralPath $rd)) { [IO.Directory]::Move($rd + '-real', $rd) }
        }
        Assert-True (@(Get-ChildItem -LiteralPath $rt -Force).Count -eq 0) "corrida antes do pin: nenhum arquivo no alvo da juncao ($made criados, $refused recusados, $($flag.Swaps) trocas)"
        Assert-Eq ($made + $refused) $i 'cada criacao criou ou recusou'
        # No swap while the creations ran: the race was not exercised on this run (never a PASS for it).
        if ($during -eq 0) { $script:caseSkipped = $true; $script:caseNote = "corrida nao exercitada: nenhuma troca concluida durante as $i criacoes ($($flag.Swaps) no total, $($flag.Errors) tentativas recusadas); nenhum arquivo no alvo"; return }
        $script:caseNote = "corrida: $made criados, $refused recusados, $during trocas durante as $i criacoes; $($flag.Errors) tentativas de troca recusadas; terminou trocada: $endedSwapped"
    }
    Test-Case 'Diagnose' 'FINAL-A: saidas da V0.1 - a verificacao lexica aceita um alias subst de uma base (lacuna demonstrada); audit -ExportJson agora cria pelo escritor pinado (F-02); clean -LogFile segue por nome (latente, trava de exclusao fechada)' {
        $base = Join-Path $sandbox 'finala-v01base'; [void][IO.Directory]::CreateDirectory($base)
        $inv = [pscustomobject]@{ Bases = @([pscustomobject]@{ Path = $base }) }
        Assert-True (-not (Test-AtmOutputPathOutsideBases -Path (Join-Path $base 'x.json') -Inventory $inv)) 'dentro da base por nome: recusado'
        $sl = $null; foreach ($l in [char[]]'QRSTUVWXYZ') { if (-not (Test-Path "$($l):\")) { $sl = $l; break } }
        if (-not $sl) { $script:caseSkipped = $true; $script:caseNote = 'nenhuma letra de unidade livre'; return }
        $null = cmd /c subst "$($sl):" "`"$base`"" 2>&1
        try {
            if (-not (Test-Path "$($sl):\")) { $script:caseSkipped = $true; $script:caseNote = 'subst indisponivel'; return }
            # Known V0.1 gap (FINAL-A record): the V0.1 lexical check accepts the alias; the diagnose writer refuses it.
            Assert-True (Test-AtmOutputPathOutsideBases -Path "$($sl):\x.json" -Inventory $inv -MustNotExist) 'lacuna V0.1 demonstrada em fixture: alias subst de uma base passa na verificacao lexica (nada e gravado por este teste)'
            $sx = [AgentTempManager.AtmSafeCreate]::Pin("$($sl):\d"); $ex = $sx.Error; $sx.Dispose()
            Assert-True ($ex -ceq 'SUBSTITUTED_DRIVE' -or $ex -like 'PARENT_*') "o escritor seguro recusa a unidade subst ($ex)"
            Assert-True (-not (Test-Path -LiteralPath (Join-Path $base 'x.json'))) 'nada gravado na base'
        } finally { $null = cmd /c subst "$($sl):" /d 2>&1 }
        $cli = [IO.File]::ReadAllText((Join-Path $srcDir 'agent-temp.ps1'))
        Assert-True ($cli.Contains('$exported = New-AtmPinnedTextFile -Path $ExportJson') -and -not $cli.Contains("[IO.File]::WriteAllText(`$ExportJson, (ConvertTo-AtmExportJson") -and ([IO.File]::ReadAllText((Join-Path $srcDir 'lib\Engine.Clean.ps1'))).Contains('Add-Content -LiteralPath $LogFile')) 'F-02: audit -ExportJson pelo escritor pinado (mesmas regras, mesma mensagem); F-04: clean -LogFile por nome (latente, registrado)'
        # A refusal after the file exists (CREATED_ codes) never claims that no file was created (review of FINAL-A).
        $ncs = [IO.File]::ReadAllText((Join-Path $srcDir 'lib\Native.cs'))
        Assert-True ($ncs.Contains('return "CREATED_PARENT_CHANGED";') -and ([regex]::Matches($cli, [regex]::Escape("-like 'EXPORT_CREATE_CREATED_*') { 'cli.exportRefusedAfterCreate' }"))).Count -eq 2 -and (Get-AtmText 'cli.exportRefusedAfterCreate' 'X') -notmatch 'nenhum arquivo foi criado|no file was created') 'recusa depois da criacao: codigo CREATED_ e mensagem que nao nega o arquivo (diagnose e auditoria)'
        # F-02 on a fixture: the audit export path keeps its V0.1 rules and gains the pinned creation.
        $ax = Join-Path $sandbox 'finala-auditexp'; $axt = Join-Path $sandbox 'finala-auditexp-target'; foreach ($d in @($ax, $axt)) { [void][IO.Directory]::CreateDirectory($d) }
        $pol = { param($P) if (Test-AtmOutputPathOutsideBases -Path $P -Inventory $inv -MustNotExist) { $null } else { 'EXPORT_DESTINATION_NOT_ALLOWED' } }
        Assert-Eq (New-AtmPinnedTextFile -Path (Join-Path $ax 'a.json') -Text '{}' -Policy $pol) $null 'exportacao de auditoria criada pelo escritor pinado'
        Assert-Eq (New-AtmPinnedTextFile -Path (Join-Path $ax 'a.json') -Text 'x' -Policy $pol) 'EXPORT_DESTINATION_NOT_ALLOWED' 'existente: recusado (regra V0.1), conteudo intacto'
        Assert-Eq ([IO.File]::ReadAllText((Join-Path $ax 'a.json'))) '{}' 'nada sobrescrito'
        Assert-Eq (New-AtmPinnedTextFile -Path (Join-Path $base 'in.json') -Text '{}' -Policy $pol) 'EXPORT_DESTINATION_NOT_ALLOWED' 'dentro da base: recusado'
        [IO.Directory]::Move($ax, $ax + '-moved'); New-Junction $ax $axt
        Assert-True ((New-AtmPinnedTextFile -Path (Join-Path $ax 'b.json') -Text '{}' -Policy $pol) -like 'EXPORT_PIN_*' -and @(Get-ChildItem -LiteralPath $axt -Force).Count -eq 0) 'pasta trocada por juncao: recusada, nada no alvo'
    }
    Test-Case 'Camadas' 'FINAL-A F-01: caminhos de rede ou dispositivo vindos do registro ou ambiente de outros usuarios (TEMP, CLAUDE_CONFIG_DIR, CLAUDE_CODE_TMPDIR): formas de rede ou dispositivo recusadas antes de qualquer API de arquivos (verificacao lexica); pontos de reparse nao atravessados pela normalizacao; pasta de configuracao de outro usuario atraves de ponto de reparse nao lida; lacuna registrada' {
        foreach ($bad in @('\\127.0.0.1\share', '//127.0.0.1/share', '\\?\C:\x', '\\?\UNC\127.0.0.1\x', '\\.\pipe\x', '\\127.0.0.1@80\x', 'C:x', 'C:\a:b', 'relative\x', '', ("C:\a" + [char]27 + "b"), ("C:\a" + [char]0x85 + "b"), ("C:\a" + [char]0x7F + "b"))) {
            Assert-True (-not (Test-AtmLocalPathForm $bad)) "forma recusada: '$bad'"
        }
        Assert-True (Test-AtmLocalPathForm $env:SystemRoot) 'caminho local de unidade fixa aceito'
        $sw = [Diagnostics.Stopwatch]::StartNew()
        Assert-Eq (Get-AtmNormalizedPath '\\127.0.0.1\atm-nope\x') $null 'normalizacao recusa UNC sem tocar a rede'
        Assert-Eq (Get-AtmNormalizedPath '\\127.0.0.1@80\atm-nope') $null 'normalizacao recusa WebDAV'
        Assert-True ($sw.ElapsedMilliseconds -lt 2000) "sem tentativa de rede ($($sw.ElapsedMilliseconds) ms)"
        $p = New-TestProfile 'finala-unc'
        $p.EnvValues = @{ CLAUDE_CONFIG_DIR = @('\\127.0.0.1\atm-nope'); CLAUDE_CODE_TMPDIR = @('\\127.0.0.1\atm-nope2') }
        $cd = Get-AtmClaudeConfigDirs $p
        Assert-True (@($cd.Dirs).Count -eq 0 -and $cd.Refused -eq 1) 'CLAUDE_CONFIG_DIR de rede: nao lido, sem cair para o padrao do perfil'
        $se = Get-AtmClaudeSessionEvidence -ProfileInfo $p -Snapshot ([pscustomobject]@{ Failed = $false; Processes = @() })
        Assert-True (-not $se.Readable -and @($se.Notes).Count -ge 1) 'evidencia de sessao: ilegivel (lacuna), nunca "sem sessoes"'
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $ia = Get-InvArgs -Profiles @($p)
        $i = Invoke-AtmInventory @ia
        $st = @($i.ProfileBaseStatus[$p.Sid + '|' + $p.ProfilePath] | Where-Object { $_.Source -eq 'CLAUDE_CODE_TMPDIR' })
        Assert-True ($st.Count -ge 1 -and @($st | Where-Object { $_.Status -ne 'INVALID' }).Count -eq 0 -and $sw.ElapsedMilliseconds -lt 60000) "CLAUDE_CODE_TMPDIR de rede: base INVALID, nada lido ($($sw.ElapsedMilliseconds) ms)"
        # FINAL-A review (L-1): the raw value of an invalid base is shown with its control characters replaced.
        $pe = New-TestProfile 'finala-ctl'
        $pe.EnvValues = @{ CLAUDE_CODE_TMPDIR = @("C:\a" + [char]27 + "[2J" + [char]0x9B + "b") }
        $ia = Get-InvArgs -Profiles @($pe)
        $ie = Invoke-AtmInventory @ia
        $se2 = @($ie.ProfileBaseStatus[$pe.Sid + '|' + $pe.ProfilePath] | Where-Object { $_.Source -eq 'CLAUDE_CODE_TMPDIR' })
        Assert-True ($se2.Count -ge 1 -and @($se2 | Where-Object { $_.Status -ne 'INVALID' -or [string]$_.BasePath -match '[\x00-\x1f\x7f-\x9f]' }).Count -eq 0) "base invalida exibida sem caracteres de controle ($(@($se2 | ForEach-Object { $_.BasePath }) -join ';'))"
        # FINAL-A review (M-3): a component that is a reparse point is never traversed by the normalization (a directory
        # symbolic link may point to a network share; a junction stands in for it here: creating one needs no privilege).
        $mt = Join-Path $sandbox 'finala-m3-target'; $mj = Join-Path $sandbox 'finala-m3-link'
        [void][IO.Directory]::CreateDirectory((Join-Path $mt 'inner')); New-Junction $mj $mt
        $mlong = [AgentTempManager.AtmNative]::GetLongPath($sandbox).TrimEnd('\')
        Assert-Eq (Get-AtmNormalizedPath (Join-Path $mj 'inner')) ($mlong + '\finala-m3-link\inner') 'normalizacao: prefixo expandido, link e restante mantidos lexicamente (nunca resolvidos)'
        # Another user's CLAUDE_CONFIG_DIR through a reparse point is not read; one's own is read as before.
        $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $po = New-TestProfile 'finala-m3-other' -Sid 'S-1-5-21-1-2-3-1001'
        $po.EnvValues = @{ CLAUDE_CONFIG_DIR = @((Join-Path $mj 'inner')) }
        $co = Get-AtmClaudeConfigDirs $po
        Assert-True (@($co.Dirs).Count -eq 0 -and $co.Refused -eq 1) 'pasta de configuracao de outro usuario atraves de um ponto de reparse: nao lida, recusa contada'
        $pm = New-TestProfile 'finala-m3-me' -Sid $me
        $pm.EnvValues = @{ CLAUDE_CONFIG_DIR = @((Join-Path $mj 'inner')) }
        $cm = Get-AtmClaudeConfigDirs $pm
        Assert-True (@($cm.Dirs).Count -eq 1 -and $cm.Refused -eq 0) 'a propria pasta de configuracao segue lida como antes'
    }
    Test-Case 'Camadas' 'FINAL-A F-03/F-06/F-07/F-08: caracteres de controle de arquivos de sessao nunca chegam ao console; PID de pai reutilizado nao entra na cadeia propria; copia preparada comparada ao manifesto verificado; release confere as quatro travas' {
        $p = New-TestProfile 'finala-esc'
        $sd = Join-Path $p.ProfilePath '.claude\sessions'
        $esc = [char]27
        [IO.File]::WriteAllText((Join-Path $sd '4242.json'), ('{"pid":4242,"sessionId":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' + '\u001b' + '","procStart":"0","cwd":"C:\\work\\proj' + '\u001b[2J' + 'x"}'))
        $se = Get-AtmClaudeSessionEvidence -ProfileInfo $p -Snapshot ([pscustomobject]@{ Failed = $false; Processes = @() })
        $e0 = @($se.Entries)[0]
        Assert-True ($null -ne $e0 -and -not ([string]$e0.ProjectName).Contains($esc) -and -not ([string]$e0.SessionId).Contains($esc) -and ([string]$e0.ProjectName).Contains('?[2J')) 'F-03: ESC do cwd e do sessionId substituido antes de qualquer exibicao'
        $t0 = [datetime]::UtcNow.AddHours(-2)
        $snap = [pscustomobject]@{ Processes = @(
                [pscustomobject]@{ Pid = 100; ParentPid = 50; CommandLine = 'powershell -File C:\PF\CTM\agent-temp.ps1'; CreationUtc = $t0 },
                [pscustomobject]@{ Pid = 50; ParentPid = 4; CommandLine = 'cmd /c C:\PF\CTM\bin\agent-temp.cmd x'; CreationUtc = $t0.AddHours(1) }) }
        Assert-Eq (@(Get-AtmSelfChainPids -Snapshot $snap -SelfPid 100 -Markers @('C:\PF\CTM\agent-temp.ps1', 'C:\PF\CTM\bin\agent-temp.cmd')) -join ',') '100' 'F-06: pai criado depois do filho (PID reutilizado) nunca e excluido como lancador'
        $snap.Processes[1].CreationUtc = $t0.AddMinutes(-1)
        Assert-Eq (@(Get-AtmSelfChainPids -Snapshot $snap -SelfPid 100 -Markers @('C:\PF\CTM\agent-temp.ps1', 'C:\PF\CTM\bin\agent-temp.cmd')) -join ',') '100,50' 'lancador legitimo continua excluido'
        # F-07 (behavioural): the release source is verified, its manifest kept in memory; the staged copy is checked against
        # it (the staged copy has no manifest.json: it is regenerated). A file changed between verification and copy is refused.
        $rel7 = Join-Path $sandbox 'finala-f07-src'; [void][IO.Directory]::CreateDirectory($rel7)
        Copy-AtmTree -From $srcDir -To $rel7
        Write-AtmManifest -Root $rel7 -Version (Get-AtmSourceVersion -SourceDir $rel7)
        $null = Assert-AtmInstallSource -SourceDir $rel7
        Assert-True ($null -ne $script:AtmVerifiedManifest -and $script:AtmVerifiedManifest.Count -gt 10) 'F-07: manifesto verificado guardado em memoria'
        $stg = Join-Path $sandbox 'finala-f07-stage1'; [void][IO.Directory]::CreateDirectory($stg)
        Copy-AtmTree -From $rel7 -To $stg
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $stg 'manifest.json'))) 'copia preparada sem manifest.json (regenerado depois)'
        $ok7 = $true; try { Assert-AtmStagedCopy -Staging $stg } catch { $ok7 = $false; $script:caseNote = $_.Exception.Message }
        Assert-True $ok7 'F-07: copia preparada integra aceita (regressao B-1: toda instalacao era recusada)'
        Add-Content -LiteralPath (Join-Path $rel7 'lib\Report.ps1') -Value '#swapped'
        $stg2 = Join-Path $sandbox 'finala-f07-stage2'; [void][IO.Directory]::CreateDirectory($stg2)
        Copy-AtmTree -From $rel7 -To $stg2
        $msg7 = $null; try { Assert-AtmStagedCopy -Staging $stg2 } catch { $msg7 = $_.Exception.Message }
        Assert-True ($null -ne $msg7 -and $msg7 -match 'Report\.ps1') "F-07: arquivo trocado entre verificacao e copia recusado ($msg7)"
        [IO.File]::WriteAllText((Join-Path $stg 'providers\Plantado.ps1'), 'x')
        $msg8 = $null; try { Assert-AtmStagedCopy -Staging $stg } catch { $msg8 = $_.Exception.Message }
        Assert-True ($null -ne $msg8 -and $msg8 -match 'Plantado') "F-07: arquivo extra na copia preparada recusado ($msg8)"
        $script:AtmVerifiedManifest = $null
        $ic = [IO.File]::ReadAllText((Join-Path (Split-Path -Parent $testsDir) 'install\InstallCommon.ps1'))
        Assert-True ($ic.IndexOf('Copy-AtmTree -From $SourceDir -To $staging') -lt $ic.IndexOf('Assert-AtmStagedCopy -Staging $staging') -and $ic.IndexOf('Assert-AtmStagedCopy -Staging $staging') -lt $ic.IndexOf("Copy-Item -LiteralPath `$ProjectsFile")) 'F-07: verificacao logo apos a copia, antes de qualquer arquivo local'
        $br = [IO.File]::ReadAllText((Join-Path (Split-Path -Parent $testsDir) 'tools\Build-Release.ps1'))
        foreach ($g in @('AtmRealDeletionEnabled', 'AtmWorktreeDiagnosticsEnabled', 'AtmHandleDiagnosticsEnabled', 'AtmDiagnoseExportEnabled')) { Assert-True ($br.Contains($g)) "F-08: release confere $g no arquivo" }
    }
    Test-Case 'Camadas' 'P5-B-S: todo script (src, install, tests) com texto nao ASCII comeca com BOM UTF-8 (o Windows PowerShell 5.1 leria o arquivo como ANSI e corromperia o texto)' {
        # -Include is ignored with -LiteralPath on Windows PowerShell 5.1: filtered by extension (scripts only; the .cmd
        # launcher and JSON files must not get a BOM).
        $repoRoot = Split-Path -Parent $testsDir
        $scripts = @(foreach ($d in @($srcDir, (Join-Path $repoRoot 'install'), $testsDir)) { if (Test-Path -LiteralPath $d) { Get-ChildItem -LiteralPath $d -Recurse -File | Where-Object { $_.Extension -in @('.ps1', '.psm1', '.psd1') } } })
        Assert-True ($scripts.Count -gt 5 -and @($scripts | Where-Object { $_.Extension -notin @('.ps1', '.psm1', '.psd1') }).Count -eq 0) 'somente scripts verificados'
        foreach ($f in $scripts) {
            $b = [IO.File]::ReadAllBytes($f.FullName)
            $hasBom = ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF)
            $nonAscii = $false; foreach ($x in $b) { if ($x -gt 0x7F) { $nonAscii = $true; break } }
            Assert-True ($hasBom -or -not $nonAscii) "$($f.Name): texto nao ASCII sem BOM UTF-8"
        }
    }
    Test-Case 'Diagnose' 'P5-B: CLI - version, help, comando desconhecido, diagnose parcial com codigo 0, nenhuma gravacao sem -ExportJson, nenhuma opcao abre travas, sem elevacao nem limpeza no diagnose' {
        $cmd = Join-Path $srcDir 'bin\agent-temp.cmd'
        $cwd = Join-Path $sandbox 'p5b-cwd'; [void][IO.Directory]::CreateDirectory($cwd)

        $o = (& cmd.exe /c "cd /d `"$cwd`" && `"$cmd`" diagnose -DeadlineSeconds 0 -NoProgress -Lang en-US" 2>&1) -join "`n"
        Assert-Eq $LASTEXITCODE 0 '13: diagnose parcial: codigo 0'
        Assert-True (@(Get-ChildItem -LiteralPath $cwd -Force).Count -eq 0) '13: nenhum arquivo criado sem -ExportJson (diretorio atual)'
        $o = (& cmd.exe /c "`"$cmd`" version -Lang en-US" 2>&1) -join "`n"
        Assert-True ($LASTEXITCODE -eq 0 -and $o -match ('agent-temp ' + [regex]::Escape($script:AtmVersion)) -and $o -match 'Claude Code' -and $o -match 'Claude Desktop') 'version: codigo 0, versao 0.1.0 e providers'
        $o = (& cmd.exe /c "`"$cmd`" help -Lang en-US" 2>&1) -join "`n"
        Assert-True ($LASTEXITCODE -eq 0 -and $o -match 'agent-temp diagnose' -and $o -match '-ExportJson' -and $o -match '-DeadlineSeconds' -and $o -match '-PseudonymKeyFile') 'help: codigo 0 e opcoes do diagnose'
        $o = (& cmd.exe /c "`"$cmd`" nao-existe -Lang en-US" 2>&1) -join "`n"
        Assert-Eq $LASTEXITCODE 1 'comando desconhecido: codigo 1'
        $cli = [IO.File]::ReadAllText((Join-Path $srcDir 'agent-temp.ps1'))
        $param = $cli.Substring($cli.IndexOf('param('), $cli.IndexOf('$ErrorActionPreference') - $cli.IndexOf('param('))
        foreach ($pat in @('Gate', 'Enable', 'Unlock', 'Handle', 'Worktree', 'Delete', 'Repository', 'Git')) { Assert-True (-not $param.Contains($pat)) "nenhum parametro publico '$pat' (travas fechadas, sem leitura Git adicional)" }
        $blk = $cli.Substring($cli.IndexOf("'diagnose' {"), $cli.IndexOf("'clean' {") - $cli.IndexOf("'diagnose' {"))
        foreach ($pat in @('Invoke-AtmClean', 'RunAs', 'Start-Process', 'Verb', 'AtmRealDeletionEnabled =', 'AtmHandleDiagnosticsEnabled =', 'AtmWorktreeDiagnosticsEnabled =')) { Assert-True (-not $blk.Contains($pat)) "diagnose sem '$pat'" }
    }
    Test-Case 'I18n' 'P1-C: todo motivo e evidencia de arquivos abertos tem texto nos dois idiomas' {
        foreach ($l in @('en-US', 'pt-BR')) {
            foreach ($x in $script:AtmHandleReasonCodes) { Assert-True $script:AtmMessages[$l].ContainsKey("reason.$x") "reason.$x ($l)" }
            foreach ($x in $script:AtmHandleEvidenceCodes) { Assert-True $script:AtmMessages[$l].ContainsKey("evidence.$x") "evidence.$x ($l)" }
        }
    }
    Test-Case 'I18n' 'Worktrees (P3-B): todo motivo e evidencia da descoberta tem texto nos dois idiomas' {
        foreach ($l in @('en-US', 'pt-BR')) {
            foreach ($x in $script:AtmWorktreeReasonCodes) { Assert-True $script:AtmMessages[$l].ContainsKey("reason.$x") "reason.$x ($l)" }
            foreach ($x in $script:AtmWorktreeEvidenceCodes) { Assert-True $script:AtmMessages[$l].ContainsKey("evidence.$x") "evidence.$x ($l)" }
            foreach ($x in $script:AtmLocalWorkReasonCodes) { Assert-True $script:AtmMessages[$l].ContainsKey("reason.$x") "reason.$x ($l)" }
            foreach ($x in $script:AtmPublicationReasonCodes) { Assert-True $script:AtmMessages[$l].ContainsKey("reason.$x") "reason.$x ($l)" }
        }
    }
    Test-Case 'Camadas' 'Motor de diagnostico somente leitura, sem saida no terminal nem controle de processos/servicos/VMs; codigo nativo sem privilegios' {
        $lib = Join-Path $srcDir 'lib'
        $files = @(Get-ChildItem -LiteralPath $lib -File | Where-Object { $_.Name -eq 'Engine.Diagnose.ps1' -or $_.Name -like 'Diagnose.*.ps1' })
        Assert-True ($files.Count -ge 1) 'motor de diagnostico presente'
        $banned = @('Write-Host', 'Write-Progress', 'Read-Host', 'AtmDeleter', 'DeleteTree', 'Remove-Item', 'AtmLockProbe', 'Invoke-AtmClean', 'AtmRealDeletionEnabled',
            'Stop-Process', 'Start-Process', 'Stop-Service', 'Start-Service', 'Set-Service', 'Restart-Service', 'Suspend-Service', 'Invoke-CimMethod', 'Invoke-WmiMethod',
            'Set-CimInstance', 'Remove-CimInstance', 'Set-ItemProperty', 'New-Item', 'Set-Acl', 'CreateSubKey', 'SetValue', 'sc.exe', 'net stop', 'net start')
        foreach ($f in $files) {
            $txt = [IO.File]::ReadAllText($f.FullName)
            foreach ($pat in $banned) { Assert-True (-not $txt.Contains($pat)) "$($f.Name) contem '$pat'" }
            Assert-True (-not ($txt -match '(?i)\b(Start|Stop|Save|Suspend|Resume|Restart|Checkpoint|Remove|Set|New)-VM\b')) "$($f.Name) usa cmdlet de VM"
        }
        $native = [IO.File]::ReadAllText((Join-Path $lib 'Native.cs'))
        foreach ($pat in @('SeDebugPrivilege', 'AdjustTokenPrivileges', 'RmShutdown', 'RmRestart', 'TerminateProcess', 'WriteProcessMemory', 'CreateRemoteThread', 'DebugActiveProcess', 'NtTerminate', 'CreateProcessAsUser', 'CreateProcessWithLogon', 'CreateProcessWithToken', 'ShellExecute', 'WinExec', 'DuplicateHandle')) { Assert-True (-not $native.Contains($pat)) "Native.cs contem '$pat'" }
        Assert-True (-not ($native -match '\bOpenProcess\s*\(')) 'Native.cs nao abre outros processos (OpenProcess)'
        Assert-True (-not $native.Contains('ReadProcessMemory') -and -not $native.Contains('NtQueryInformationProcess')) 'P1-C: nenhuma leitura de memoria de outros processos (D-1 adiado)'
        $rm = @([regex]::Matches($native, 'extern\s+int\s+(Rm\w+)\s*\(') | ForEach-Object { $_.Groups[1].Value } | Sort-Object)
        Assert-Eq ($rm -join ',') 'RmEndSession,RmGetList,RmRegisterResources,RmStartSession' 'P1-C D-2: so as quatro funcoes permitidas do Restart Manager'
        $cp = [regex]::Matches($native, '\bCreateProcess\w*\s*\(')
        Assert-True ($cp.Count -ge 1 -and @($cp | Where-Object { $_.Index -lt $native.IndexOf('public static class AtmJobRunner') }).Count -eq 0) 'toda criacao de processo esta dentro do executor'
        # D-4: the only termination is of the runner's own job, and only the runner creates processes.
        $runner = $native.Substring($native.IndexOf('public static class AtmJobRunner'))
        Assert-True ($native.IndexOf('TerminateJobObject') -gt $native.IndexOf('public sealed class AtmJobResult') -and $native.IndexOf('public sealed class AtmJobResult') -gt 0 -and [regex]::Matches($native, 'CreateProcessW\(').Count -eq 2 -and $runner.Contains('PROC_THREAD_ATTRIBUTE_JOB_LIST') -and -not $runner.Contains('AssignProcessToJobObject')) 'Native.cs: processos so pelo executor, criados dentro do job; so o job proprio e encerrado'
        $srcAll = @(Get-ChildItem -LiteralPath $srcDir -Recurse -File -Filter '*.ps1' | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Text = [IO.File]::ReadAllText($_.FullName) } })
        Assert-Eq (@($srcAll | Where-Object { $_.Text.Contains('[AgentTempManager.AtmJobRunner]') } | ForEach-Object { $_.Name }) -join ',') 'Engine.Diagnose.ps1' 'so o motor de diagnostico chama o executor nativo'
        $diag = [IO.File]::ReadAllText((Join-Path $lib 'Engine.Diagnose.ps1'))
        Assert-Eq ([regex]::Matches($diag, '\[AgentTempManager\.AtmJobRunner\]::Run').Count) 1 'um unico ponto de execucao (Invoke-AtmBoundedProcess)'
        Assert-True (-not ($diag -match '(?m)^\s*&\s*(\$git|git(\.exe)?\b)')) 'o motor nunca chama git diretamente'
        $inv = $diag.Substring($diag.IndexOf('function Invoke-AtmDiagnoseRun'))
        # P3-B: the diagnose reaches Git only through the discovery, and only inside the worktree diagnostics gate.
        $gateAt = $inv.IndexOf('if ($script:AtmWorktreeDiagnosticsEnabled) {')
        Assert-True (-not $inv.Contains('Invoke-AtmGitCommand') -and [regex]::Matches($inv, 'Resolve-AtmGitExecutable').Count -eq 1 -and $gateAt -gt 0 -and $inv.IndexOf('Resolve-AtmGitExecutable') -gt $gateAt -and $inv.IndexOf('Resolve-AtmGitExecutable') -lt $inv.IndexOf('# Closed gate (every shipped copy): worktrees are not observed')) 'P3-B: Git no diagnose so pela descoberta, atras da trava'
        foreach ($f in @('Tui.ps1', 'Report.ps1')) {
            $txt = [IO.File]::ReadAllText((Join-Path $lib $f))
            foreach ($pat in @('Get-AtmIdentityRaw', 'Get-AtmIdentityState', 'Get-AtmProviderRuntimeHints', 'Get-AtmInventoryCoverage', 'AtmToken]', 'Get-AtmProcessRaw', 'Get-AtmProcessCollection', 'Resolve-AtmProcessReference', 'Get-AtmProcessParentLink', 'Get-AtmProcessTree', 'Compare-AtmProcessCollections', 'Get-AtmSelfProcessKeys', 'Measure-AtmProcessCpu', 'Invoke-AtmProcessCpuSampling', 'Get-AtmProcessTreeResources', 'Invoke-AtmGitCommand', 'Resolve-AtmGitExecutable', 'Invoke-AtmBoundedProcess', 'AtmJobRunner')) { Assert-True (-not $txt.Contains($pat)) "$f chama coletor diretamente: $pat" }
        }
    }

    # ------------------------------------------------------------------ scale
    if (-not $SkipHeavy) {
        Test-Case 'Escala' 'P3-E: 2000 worktrees e 20000 referencias num repositorio (somente arquivos): parte comum uma vez, tempo e memoria medidos' {
            if (& $gitSkip) { return }
            $h = & $scaleFixture 'scale-heavy' 2000 20000
            $pz = New-AtmPseudonymizer -Key $testPseudonymKey
            try {
                [GC]::Collect(); $m0 = [GC]::GetTotalMemory($true)
                $sw = [Diagnostics.Stopwatch]::StartNew()
                $script:AtmWorktreeDiagnosticsEnabled = $true
                try { $r = Get-AtmWorktreeDiscovery -Partitions $h.Partitions -Git $null -Pseudonymizer $pz -MaxCandidates 3000 -MaxWorktreesPerRepository 3000 }
                finally { $script:AtmWorktreeDiagnosticsEnabled = $false }
                $sw.Stop(); $m1 = [GC]::GetTotalMemory($false)
                Assert-True ($r.Stats.CommonPreflights -eq 1 -and $r.Stats.RefStoreReads -eq 1) 'parte comum e referencias uma vez'
                Assert-Eq @($r.Findings | Where-Object { $_.Kind -eq 'Worktree' -and @($_.Evidence | Where-Object { $_.Code -eq 'WORKTREE_REGISTERED' }).Count -eq 1 }).Count 2000 'todas registradas'
                Write-Host ("   2000 worktrees/20000 refs: {0:N1}s, {1} arquivos, {2:N1} MB lidos, delta memoria gerenciada ~{3:N1} MB" -f $sw.Elapsed.TotalSeconds, $r.Stats.FilesRead, ($r.Stats.BytesRead / 1MB), (($m1 - $m0) / 1MB))
                Assert-True ((($m1 - $m0) / 1MB) -lt 500) 'memoria controlada'
            } finally { Close-AtmPseudonymizer $pz }
        }
        Test-Case 'Escala' "Root com $HeavyFiles arquivos: passagem unica, memoria controlada" {
            $p = New-TestProfile 'heavy'
            $r = New-TestRoot -ProfileInfo $p -Files @{}
            if (-not ('AtmTestGen' -as [type])) {
                Add-Type -TypeDefinition 'public static class AtmTestGen { public static void Make(string root, int n) { for (int i = 0; i < n; i++) { string d = System.IO.Path.Combine(root, "d" + (i / 1000)); if (i % 1000 == 0) System.IO.Directory.CreateDirectory(d); System.IO.File.WriteAllBytes(System.IO.Path.Combine(d, "f" + i + ".bin"), new byte[i % 7]); } } }'
            }
            [AtmTestGen]::Make($r, $HeavyFiles)
            [GC]::Collect(); $m0 = [GC]::GetTotalMemory($true)
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $i = Inv -Profiles @($p)
            $sw.Stop()
            $m1 = [GC]::GetTotalMemory($false)
            $x = Find-Part $i $r
            Assert-Eq $x.Files $HeavyFiles 'contagem'
            Assert-True $x.MeasurementComplete 'completa'
            $expected = 0L; for ($k = 0; $k -lt $HeavyFiles; $k++) { $expected += $k % 7 }
            Assert-Eq $x.Bytes $expected 'bytes'
            Write-Host ("   inventario: {0:N1}s, ~{1:N0} entradas/s, delta memoria gerenciada ~{2:N1} MB" -f $sw.Elapsed.TotalSeconds, ($HeavyFiles / [math]::Max(0.001, $sw.Elapsed.TotalSeconds)), (($m1 - $m0) / 1MB))
            Assert-True ((($m1 - $m0) / 1MB) -lt 200) 'memoria controlada'
        }
    }
} finally {
    # The console encoding of this process is restored, even when the suite aborts (a redirected console may refuse it).
    if ($null -ne $prevOutputEncoding) { try { [Console]::OutputEncoding = $prevOutputEncoding } catch { $null = $_ } }
    # Best-effort cleanup: one failing action must not skip the others or the sandbox removal.
    foreach ($a in $cleanupActions) { try { & $a } catch { $null = $_ } }
    # Sandbox removal: rd does not follow junctions (they were already unlinked above).
    cmd /c rd /s /q "`"$sandbox`"" 2>&1 | Out-Null
}

# A selection pattern that matched nothing would make an empty subset look green.
foreach ($pair in @(@('-Only', $Only, $script:onlyHits), @('-Except', $Except, $script:exceptHits))) {
    foreach ($o in $pair[1]) {
        if (-not $pair[2].ContainsKey($o)) {
            $results.Add([pscustomobject]@{ Area = 'Harness'; Test = "$($pair[0]) sem caso correspondente: $o"; Result = 'FAIL'; Ms = 0; Detail = 'padrao nao corresponde a nenhum caso' })
            Write-Host ("[FAIL] Harness :: {0} sem caso correspondente: {1}" -f $pair[0], $o) -ForegroundColor Red
        }
    }
}
$pass = @($results | Where-Object Result -eq 'PASS').Count
$fail = @($results | Where-Object Result -eq 'FAIL').Count
$skipped = @($results | Where-Object Result -eq 'NAO_TESTADO').Count
Write-Host ''
if ($Only.Count -gt 0 -or $Except.Count -gt 0) {
    foreach ($n in $script:excludedNames) { Write-Host ("EXCLUIDO (-Except): {0}" -f $n) -ForegroundColor Yellow }
    Write-Host ("SUBCONJUNTO (-Only {0}; -Except {1}): {2} casos nao selecionados, nao executados e nao contados" -f ($Only -join ' | '), ($Except -join ' | '), $script:notSelected) -ForegroundColor Yellow
}
Write-Host ("RESULTADO{6}: {0} PASS / {1} FAIL / {5} NAO_TESTADO / {2} total | PowerShell {3} {4}" -f $pass, $fail, $results.Count, $PSVersionTable.PSVersion, $PSVersionTable.PSEdition, $skipped, $(if ($Only.Count -gt 0 -or $Except.Count -gt 0) { ' (SUBCONJUNTO)' } else { '' })) -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Write-Host ("Sandbox removido: {0}" -f (-not [IO.Directory]::Exists($sandbox)))
if ($ReportFile) {
    $rep = [ordered]@{ psVersion = $PSVersionTable.PSVersion.ToString(); psEdition = $PSVersionTable.PSEdition; accountKind = $(if ($me.IsAdmin) { 'ADMINISTRATOR_ELEVATED' } else { 'NOT_ELEVATED' }); isAdmin = $me.IsAdmin; utc = [datetime]::UtcNow.ToString('o'); pass = $pass; fail = $fail; notTested = $skipped; subset = @($Only); except = @($Except); excluded = @($script:excludedNames); notSelected = $script:notSelected; sandboxRemoved = (-not [IO.Directory]::Exists($sandbox)); results = $results }
    [IO.File]::WriteAllText($ReportFile, ($rep | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding($false)))
}
exit $fail