<#
  AgentTempManager automated tests. Self-contained (no Pester), runs on Windows PowerShell 5.1 and PowerShell 7.
  Every destructive operation runs ONLY inside an isolated sandbox created by this script under
  %TEMP%\atm-tests-<random> (outside every real <TEMP>\claude base). Real Claude Code temp files are never
  written; tests that touch the real machine are read-only.
  Usage: powershell -NoProfile -ExecutionPolicy Bypass -File tests\Run-Tests.ps1 [-SkipHeavy] [-ReportFile <path>]
#>
param([switch]$SkipHeavy, [string]$ReportFile, [int]$HeavyFiles = 200000)

$ErrorActionPreference = 'Stop'
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

function Test-Case {
    param([string]$Area, [string]$Name, [scriptblock]$Body)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $status = 'PASS'; $msg = ''
    $script:caseNote = $null; $script:caseSkipped = $false
    try { $null = & $Body 6>$null } catch { $status = 'FAIL'; $msg = $_.Exception.Message + ' @' + $_.InvocationInfo.ScriptLineNumber }
    if ($status -eq 'PASS' -and $script:caseSkipped) { $status = 'NAO_TESTADO' }
    if (-not $msg -and $script:caseNote) { $msg = $script:caseNote }
    $sw.Stop()
    $results.Add([pscustomobject]@{ Area = $Area; Test = $Name; Result = $status; Ms = $sw.ElapsedMilliseconds; Detail = $msg })
    $color = $(if ($status -eq 'PASS') { 'Green' } elseif ($status -eq 'NAO_TESTADO') { 'Yellow' } else { 'Red' })
    Write-Host ("[{0}] {1} :: {2} ({3} ms) {4}" -f $status, $Area, $Name, $sw.ElapsedMilliseconds, $msg) -ForegroundColor $color
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
        $snap = [pscustomobject]@{ Failed = $false; Processes = @(
                [pscustomobject]@{ Pid = 100; ParentPid = 50; CommandLine = 'powershell -File C:\PF\CTM\agent-temp.ps1 clean -Path X'; Name = 'powershell.exe' }
                [pscustomobject]@{ Pid = 50; ParentPid = 10; CommandLine = 'cmd /c "C:\PF\CTM\bin\agent-temp.cmd" clean -Path X'; Name = 'cmd.exe' }
                [pscustomobject]@{ Pid = 10; ParentPid = 1; CommandLine = 'pwsh.exe'; Name = 'pwsh.exe' }) }
        $s = @(Get-AtmSelfChainPids -Snapshot $snap -SelfPid 100 -Markers @('C:\PF\CTM\agent-temp.ps1', 'C:\PF\CTM\bin\agent-temp.cmd'))
        Assert-Eq ($s -join ',') '100,50' 'cadeia'
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
        param([object[]]$Keys, [hashtable]$InvArgs, [string[]]$Lines = @(), [switch]$Ascii, [int]$W = 120, [int]$H = 30)
        $script:tuiKeys = New-Object System.Collections.Generic.Queue[object]; foreach ($k in $Keys) { $script:tuiKeys.Enqueue($k) }
        $script:tuiLines = New-Object System.Collections.Generic.Queue[string]; foreach ($l in $Lines) { $script:tuiLines.Enqueue($l) }
        $script:tuiFrames = New-Object System.Collections.Generic.List[string]
        $ks = { if ($script:tuiKeys.Count -gt 0) { $script:tuiKeys.Dequeue() } else { $null } }
        $lr = { param($p) if ($script:tuiLines.Count -gt 0) { $script:tuiLines.Dequeue() } else { '' } }
        $rd = { param($frame) $script:tuiFrames.Add((($frame | ForEach-Object { ($_ | ForEach-Object { $_.Text }) -join '' }) -join "`n")) }
        $st = Start-AtmTui -InventoryArgs $InvArgs -KeySource $ks -Renderer $rd -LineReader $lr -Ascii:$Ascii -Width $W -Height $H
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
        $hits = @(& $scan -Path $copy -NeedlesFile $env:ATM_PRIVATE_NEEDLES)
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
    function Invoke-Rb5Cli { param([string]$Cmd, [string]$Arguments) $ErrorActionPreference = 'Continue'; $o = & cmd.exe /c "`"$Cmd`" $Arguments" 2>&1; [pscustomobject]@{ Exit = $LASTEXITCODE; Text = (@($o | ForEach-Object { "$_" }) -join ' ') } }
    Test-Case 'Instalacao' 'R-B5 verify: nenhum codigo carregado antes da verificacao; biblioteca removida, adulterada ou que sombreia Get-FileHash e provider plantado nunca executam nem forjam sucesso; manifesto invalido ou ausente recusado' {
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
        Assert-True $d.CoverageComplete 'cobertura completa'
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
        Assert-Eq (@($d.Coverage | ForEach-Object { $_.Collector }) -join ',') 'identity,provider-claude-code,inventory,processes,temp-profiles,process-snapshot,sessions-claude-code,agent-processes,agent-resources' 'coletores (Claude Code v2: dicas de runtime lidas; runtime de agentes da P1-B4-c)'
        foreach ($c in $d.Coverage) { Assert-Eq $c.Status 'COMPLETE' "$($c.Collector) completo" }
        Assert-True $d.CoverageComplete 'cobertura completa'
        Assert-True ($null -eq @($d.Coverage | Where-Object { $_.Collector -eq 'inventory' })[0].BudgetMs) 'inventario V0.1 sem orcamento declarado (nao interrompivel)'
        $f = @($d.Findings | Where-Object { $_.Key -ceq (& $b4PKey $r1) })
        Assert-Eq $f.Count 1 'achado da particao (pela chave pseudonima)'
        Assert-Eq $f[0].State 'RUNTIME_NOT_DIAGNOSED' 'estado'
        Assert-Eq $f[0].Provider 'claude-code' 'provider'
        Assert-Eq (@($f[0].Evidence | Where-Object { $_.Code -eq 'AUDIT_CLASS' })[0].Detail) (Find-Part $d.Inventory $r1).Class 'classe da auditoria como evidencia'
        Assert-Eq (@($f[0].Coverage | ForEach-Object { $_.Collector }) -join ',') 'inventory,processes,temp-profiles' 'cobertura do achado'
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
            Assert-Eq ([bool]$d.CoverageComplete) $control "$n`: diagnose CoverageComplete"
            if (-not $control) {
                $c = @($d.Coverage | Where-Object { $_.Collector -eq $row.Collector })[0]
                Assert-True ($c.Status -ceq $row.Status -and @($c.Reasons) -ccontains $row.Reason) "$n`: $($row.Collector) $($row.Status) $($row.Reason) (obtido $($c.Status) $(@($c.Reasons) -join ','))"
                $f = @($d.Findings | Where-Object { $_.Key -ceq (& $b4PKey $r) })
                Assert-Eq $f.Count 1 "$n`: achado da particao"
                Assert-True (@($f[0].IncompleteCoverage) -ccontains $row.Collector) "$n`: achado lista $($row.Collector) como incompleto"
                if ($n -eq 'inaccessible') { Assert-Eq @($d.Inventory.InaccessibleProfiles).Count 1 'perfil inacessivel no inventario' }
                if ($n -eq 'unverified') { Assert-Eq @($d.Inventory.UnverifiedTempProfiles).Count 1 'TEMP nao verificavel no inventario' }
            } else {
                foreach ($c in $d.Coverage) { Assert-Eq $c.Status 'COMPLETE' "controle: $($c.Collector) completo" }
            }
            $j = (ConvertTo-AtmDiagnoseJson -Result $d) | ConvertFrom-Json
            Assert-Eq ([bool]$j.coverageComplete) $control "$n`: JSON coverageComplete"
            Assert-Eq ([bool]$j.inventory.coverageComplete) $control "$n`: JSON inventory.coverageComplete"
            if (-not $control) { Assert-True (@($j.coverage | Where-Object { $_.collector -ceq $row.Collector -and $_.status -ceq $row.Status -and @($_.reasons) -ccontains $row.Reason }).Count -eq 1) "$n`: JSON com o mesmo codigo" }
            $old = Get-AtmLanguage
            try { Set-AtmLanguage -Requested 'en-US'; $txt = (Show-AtmDiagnose -Result $d 6>&1 | Out-String) } finally { Set-AtmLanguage -Requested $old }
            $yes = $txt.Contains('Complete coverage: YES'); $no = $txt.Contains('Complete coverage: NO')
            Assert-True ($yes -eq $control -and $no -ne $control) "$n`: relatorio (YES=$yes NO=$no)"
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
        $d = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p)) -IdentitySource $diagIdUser -Providers @((Get-AtmProviders)[0], $badProv, $rt)
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
        Assert-Eq @($d.Findings).Count 2 'duas particoes diagnosticadas'
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
            'agentResources' = $j.agentResources; 'agentResources.counters' = $j.agentResources.counters; 'agentResources.counters.*' = $j.agentResources.counters.cpuTime100ns; 'pseudonymization' = $j.pseudonymization }
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
        Assert-Eq ([regex]::Matches($en, '"reasons":\s*\[').Count) (@($j.coverage).Count + 1) 'reasons sempre array (inclusive vazio): coverage[] e agentResources'
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
    Test-Case 'Diagnose' 'CLI diagnose com prazo 0 (nenhum temporario real e lido): codigo 0 e cobertura TIMEOUT; exportacao sem inventario recusada (codigo 10); ajuda' {
        $cmd = Join-Path $srcDir 'bin\agent-temp.cmd'
        $out = (& cmd.exe /c "`"$cmd`" diagnose -DeadlineSeconds 0 -NoProgress -Lang en-US" 2>&1) -join "`n"
        Assert-Eq $LASTEXITCODE 0 'cobertura parcial nao e erro'
        Assert-True ($out -match 'inventory\s+TIMEOUT' -and $out -match 'DEADLINE_EXCEEDED' -and $out -match 'Complete coverage: NO') 'cobertura TIMEOUT relatada'
        Assert-True ($out -match 'identity\s+COMPLETE' -and $out -match 'elevation type: (DEFAULT|FULL|LIMITED)') 'identidade lida no CLI'
        $target = Join-Path $sandbox 'diag-export.json'
        $out = (& cmd.exe /c "`"$cmd`" diagnose -DeadlineSeconds 0 -NoProgress -Lang en-US -ExportJson `"$target`"" 2>&1) -join "`n"
        Assert-Eq $LASTEXITCODE 10 'exportacao recusada'
        Assert-True ($out -match 'ExportJson refused' -and $out -match 'No deletion was performed') 'mensagem de recusa'
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
        Assert-True ($txt.Contains('COVERAGE BY COLLECTOR') -and $txt.Contains('RUNTIME_NOT_DIAGNOSED')) 'en-US e codigos'
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
        $cfgFile = Join-Path $fx.Repo '.git\config'
        foreach ($c in @(@("[core]`n`tworktree = \\\\$uncHost\\share", 'GIT_PREFLIGHT_CONFIG_PATH'), @("[core]`n`texcludesFile = //$uncHost/s/ignore", 'GIT_PREFLIGHT_CONFIG_PATH'), @("[core]`n`tattributesFile = ~/attr", 'GIT_PREFLIGHT_CONFIG_PATH'),
                @("[atm]`n`tsomething = \\\\$uncHost\\x", 'GIT_PREFLIGHT_CONFIG_NETWORK'), @("[core]`n`tbroken = a \`n`tb", 'GIT_CONFIG_UNPARSEABLE'))) {
            $orig = [IO.File]::ReadAllText($cfgFile)
            [IO.File]::WriteAllText($cfgFile, $orig + "`n" + $c[0] + "`n")
            Assert-Eq (Get-AtmGitPreflight -Target $fx.Repo).Reason $c[1] "configuracao recusada: $($c[1])"
            [IO.File]::WriteAllText($cfgFile, $orig)
        }
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
        Assert-True ($err -match 'lazy fetching disabled' -and $err -notmatch 'no-such-server') "lazy fetch desativado e promissor nunca contatado: $($err.Trim())"
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
        Assert-True (-not $inv.Contains('Invoke-AtmGitCommand') -and -not $inv.Contains('Resolve-AtmGitExecutable')) 'P3-A: o executor ainda nao faz parte do diagnose (P3-B)'
        foreach ($f in @('Tui.ps1', 'Report.ps1')) {
            $txt = [IO.File]::ReadAllText((Join-Path $lib $f))
            foreach ($pat in @('Get-AtmIdentityRaw', 'Get-AtmIdentityState', 'Get-AtmProviderRuntimeHints', 'Get-AtmInventoryCoverage', 'AtmToken]', 'Get-AtmProcessRaw', 'Get-AtmProcessCollection', 'Resolve-AtmProcessReference', 'Get-AtmProcessParentLink', 'Get-AtmProcessTree', 'Compare-AtmProcessCollections', 'Get-AtmSelfProcessKeys', 'Measure-AtmProcessCpu', 'Invoke-AtmProcessCpuSampling', 'Get-AtmProcessTreeResources', 'Invoke-AtmGitCommand', 'Resolve-AtmGitExecutable', 'Invoke-AtmBoundedProcess', 'AtmJobRunner')) { Assert-True (-not $txt.Contains($pat)) "$f chama coletor diretamente: $pat" }
        }
    }

    # ------------------------------------------------------------------ scale
    if (-not $SkipHeavy) {
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
    # Best-effort cleanup: one failing action must not skip the others or the sandbox removal.
    foreach ($a in $cleanupActions) { try { & $a } catch { $null = $_ } }
    # Sandbox removal: rd does not follow junctions (they were already unlinked above).
    cmd /c rd /s /q "`"$sandbox`"" 2>&1 | Out-Null
}

$pass = @($results | Where-Object Result -eq 'PASS').Count
$fail = @($results | Where-Object Result -eq 'FAIL').Count
$skipped = @($results | Where-Object Result -eq 'NAO_TESTADO').Count
Write-Host ''
Write-Host ("RESULTADO: {0} PASS / {1} FAIL / {5} NAO_TESTADO / {2} total | PowerShell {3} {4}" -f $pass, $fail, $results.Count, $PSVersionTable.PSVersion, $PSVersionTable.PSEdition, $skipped) -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Write-Host ("Sandbox removido: {0}" -f (-not [IO.Directory]::Exists($sandbox)))
if ($ReportFile) {
    $rep = [ordered]@{ psVersion = $PSVersionTable.PSVersion.ToString(); psEdition = $PSVersionTable.PSEdition; user = $me.Name; isAdmin = $me.IsAdmin; utc = [datetime]::UtcNow.ToString('o'); pass = $pass; fail = $fail; notTested = $skipped; sandboxRemoved = (-not [IO.Directory]::Exists($sandbox)); results = $results }
    [IO.File]::WriteAllText($ReportFile, ($rep | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding($false)))
}
exit $fail