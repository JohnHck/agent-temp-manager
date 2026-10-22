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
                    if ($script:rb5LockWhich -eq 'retirada') { $dir = @(Get-ChildItem -LiteralPath (Split-Path -Parent $InstallDir) -Directory -Filter 'AgentTempManager.staging-*')[0].FullName }
                    $script:rb5Lock = [IO.File]::Open((Join-Path $dir 'agent-temp.ps1'), [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
                    throw 'simulated exception'
                }
                try { $null = Restore-AtmPrevious -InstallDir $cur } catch { $script:rb5UndoMsg = $_.Exception.Message }
            }
            if ($null -ne $script:rb5Lock) { $script:rb5Lock.Dispose() }
            $msg = $script:rb5UndoMsg
            $staging = @(Get-ChildItem -LiteralPath $pf10 -Directory -Filter 'AgentTempManager.staging-*')
            Assert-Eq $staging.Count 1 "desfazer falhou ($which): a copia que estava em uso ficou no diretorio intermediario, nao foi apagada ($msg)"
            Assert-True ($staging.Count -eq 1 -and (& $tagOf $staging[0].FullName) -eq 'atual') "desfazer falhou ($which): copia em uso preservada"
            $prevAt = $(if ($which -eq 'restaurada') { $cur } else { $prev })
            Assert-True ((Test-Path -LiteralPath (Join-Path $prevAt 'install-state.json')) -and (& $tagOf $prevAt) -eq 'anterior') "desfazer falhou ($which): versao anterior preservada em $prevAt"
            Assert-True ($null -ne $msg -and $msg -match 'simulated exception' -and $msg -match 'Nada foi apagado' -and
                $staging.Count -eq 1 -and $msg.Contains($staging[0].FullName) -and $msg.Contains($prevAt)) "desfazer falhou ($which): erro claro com a posicao de cada copia ($msg)"
            if ($which -eq 'retirada') { Assert-True (-not (Test-Path -LiteralPath $cur)) 'desfazer falhou (retirada): nada foi colocado no lugar da instalacao' }
            # Manual recovery by rename only, as the message instructs.
            if ($which -eq 'restaurada') { Rename-Item -LiteralPath $cur -NewName (Split-Path -Leaf $prev) }
            Rename-Item -LiteralPath $staging[0].FullName -NewName (Split-Path -Leaf $cur)
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
        # Reference results and identity statuses are not finding states (T-1): a Process finding still accepts only UNKNOWN.
        foreach ($s in @($script:AtmProcessReferenceResults) + @($script:AtmProcessIdentityStatuses)) {
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
        foreach ($st in @($script:AtmParentLinkResults) + @($script:AtmProcessRunStates) + @('SELF')) {
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
    Test-Case 'Diagnose' 'CLI version mostra identidade, tipo de elevacao e integridade (PRIV-10) nos dois idiomas' {
        $cmd = Join-Path $srcDir 'bin\agent-temp.cmd'
        $out = (& cmd.exe /c "`"$cmd`" version -Lang en-US" 2>&1) -join "`n"
        Assert-True ($out -match 'identity: .+ \| elevated administrator: (yes|no) \| elevation type: (DEFAULT|FULL|LIMITED) \| integrity: [A-Z_]+ \| session: \d+') 'en-US: linha de identidade'
        Assert-True ($out -match 'real deletion: DISABLED' -and $out -match 'language: en-US') 'linhas existentes preservadas'
        $out = (& cmd.exe /c "`"$cmd`" version -Lang pt-BR" 2>&1) -join "`n"
        Assert-True ($out -match 'identidade: .+ \| administrador elevado: (sim|n.{1,3}o) \| tipo de eleva.{1,6}o: (DEFAULT|FULL|LIMITED) \| integridade: [A-Z_]+') 'pt-BR: linha de identidade'
    }
    Test-Case 'Providers' 'Contrato v2: v1 inalterado; provider somente runtime registra sem membros de temporarios; validacao de versao, capacidades e membros' {
        $claude = (Get-AtmProviders)[0]
        $c = Get-AtmProviderContract $claude
        Assert-Eq $c.Version 1 'Claude Code continua v1'
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
        Assert-True ($null -eq (Get-AtmProviderRuntimeHints (Get-AtmProviders)[0])) 'v1 sem runtime: nenhuma leitura'
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
    $diagIdUser = { [pscustomobject]@{ Name = 'TEST\alice'; Sid = 'S-1-5-21-1-2-3-1001'; IsAdmin = $false; ElevationTypeRaw = 3; IntegrityRid = 0x2000; SessionId = 1 } }
    $diagIdAdmin = { [pscustomobject]@{ Name = 'TEST\admin'; Sid = 'S-1-5-21-1-2-3-500'; IsAdmin = $true; ElevationTypeRaw = 2; IntegrityRid = 0x3000; SessionId = 1 } }
    Test-Case 'Diagnose' 'Invoke-AtmDiagnose (fontes injetadas): identidade, providers, inventario e cobertura de processos/perfis; achados das particoes' {
        $p = New-TestProfile 'diag'
        $r1 = New-TestRoot -ProfileInfo $p
        $d = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p)) -IdentitySource $diagIdUser
        Assert-Eq $d.SchemaVersion 'atm.diagnose/1' 'schema'
        Assert-Eq (@($d.Coverage | ForEach-Object { $_.Collector }) -join ',') 'identity,inventory,processes,temp-profiles' 'coletores (Claude Code v1: sem dicas de runtime)'
        foreach ($c in $d.Coverage) { Assert-Eq $c.Status 'COMPLETE' "$($c.Collector) completo" }
        Assert-True $d.CoverageComplete 'cobertura completa'
        Assert-True ($null -eq @($d.Coverage | Where-Object { $_.Collector -eq 'inventory' })[0].BudgetMs) 'inventario V0.1 sem orcamento declarado (nao interrompivel)'
        $f = @($d.Findings | Where-Object { $_.Key -eq $r1 })
        Assert-Eq $f.Count 1 'achado da particao'
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
            try { $d = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p) -Procs $procs) -IdentitySource $diagIdUser -Providers @((Get-AtmProviders)[0]) }
            finally { ${function:script:Get-AtmProcessSnapshot} = $origSnapshot }
            $control = ($n -eq 'controle')
            Assert-Eq ([bool]$d.Inventory.CoverageComplete) $control ("$n`: Inventory.CoverageComplete (bases $(@($d.Inventory.Bases | ForEach-Object { $_.Status }) -join ','); registros legiveis $(@($d.Inventory.Registries.Values | ForEach-Object { $_.Readable }) -join ','))")
            Assert-Eq ([bool]$d.CoverageComplete) $control "$n`: diagnose CoverageComplete"
            if (-not $control) {
                $c = @($d.Coverage | Where-Object { $_.Collector -eq $row.Collector })[0]
                Assert-True ($c.Status -ceq $row.Status -and @($c.Reasons) -ccontains $row.Reason) "$n`: $($row.Collector) $($row.Status) $($row.Reason) (obtido $($c.Status) $(@($c.Reasons) -join ','))"
                $f = @($d.Findings | Where-Object { $_.Key -eq $r })
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
        $v1up = (Get-AtmProviders)[0].PSObject.Copy(); $v1up.Id = 'Fake-Upper-V1'; $v1up.TempSubdir = 'fake-upper'
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
    Test-Case 'Diagnose' 'JSON atm.diagnose/1: campos iguais ao documento do schema; identico nos dois idiomas (exceto language); horarios ISO UTC; listas sempre arrays' {
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
            if ($cur -and $l -match '^\| `([A-Za-z]+)` \|') { $sections[$cur].Add($Matches[1]) }
        }
        $objects = [ordered]@{ 'Top level' = $j; 'identity' = $j.identity; 'providers[]' = $j.providers[0]; 'coverage[]' = $j.coverage[0]; 'findings[]' = $j.findings[0]; 'findings[].evidence[]' = $j.findings[0].evidence[0]; 'inventory' = $j.inventory }
        foreach ($k in $objects.Keys) {
            Assert-True $sections.ContainsKey($k) "secao '$k' no documento do schema"
            Assert-Eq (@($objects[$k].PSObject.Properties.Name | Sort-Object) -join ',') (@($sections[$k] | Sort-Object) -join ',') "campos de '$k'"
        }
        Assert-Eq $j.schemaVersion 'atm.diagnose/1' 'versao'
        foreach ($name in @('startedUtc', 'finishedUtc', 'deadlineUtc', 'observedUtc')) {
            $ms = @([regex]::Matches($en, '"' + $name + '":\s*"([^"]*)"'))
            Assert-True ($ms.Count -ge 1) "$name presente"
            foreach ($m in $ms) { Assert-True ($m.Groups[1].Value -match '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z$') "$name ISO UTC: $($m.Groups[1].Value)" }
        }
        Assert-Eq ([regex]::Matches($en, '"reasons":\s*\[').Count) @($j.coverage).Count 'reasons sempre array (inclusive vazio)'
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
        $d = Invoke-AtmDiagnose -InventoryArgs (Get-InvArgs -Profiles @($p) -Procs $procs) -IdentitySource $diagIdUser -Providers @((Get-AtmProviders)[0], $rt)
        Assert-Eq (@(@($d.Findings | Where-Object { $_.Key -eq $r1 })[0].Evidence | Where-Object { $_.Code -eq 'AUDIT_CLASS' })[0].Detail) 'ACTIVE_EVIDENCE' 'referencia direta considerada (classe da auditoria)'
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
        foreach ($pat in @('SeDebugPrivilege', 'AdjustTokenPrivileges', 'RmShutdown', 'RmRestart', 'TerminateProcess', 'WriteProcessMemory')) { Assert-True (-not $native.Contains($pat)) "Native.cs contem '$pat'" }
        foreach ($f in @('Tui.ps1', 'Report.ps1')) {
            $txt = [IO.File]::ReadAllText((Join-Path $lib $f))
            foreach ($pat in @('Get-AtmIdentityRaw', 'Get-AtmIdentityState', 'Get-AtmProviderRuntimeHints', 'Get-AtmInventoryCoverage', 'AtmToken]', 'Get-AtmProcessRaw', 'Get-AtmProcessCollection', 'Resolve-AtmProcessReference', 'Get-AtmProcessParentLink', 'Get-AtmProcessTree', 'Compare-AtmProcessCollections', 'Get-AtmSelfProcessKeys', 'Measure-AtmProcessCpu', 'Invoke-AtmProcessCpuSampling', 'Get-AtmProcessTreeResources')) { Assert-True (-not $txt.Contains($pat)) "$f chama coletor diretamente: $pat" }
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