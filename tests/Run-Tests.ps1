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

function Get-Base { param($Profile) return (Join-Path $Profile.TempCandidates[0].TempPath 'claude') }

function New-TestRoot {
    param($Profile, [string]$Slug = 'C--work-proj', [string]$Uuid = ([guid]::NewGuid().ToString()), [hashtable]$Files = @{ 'a.txt' = 100; 'sub\b.bin' = 2048 })
    $p = Join-Path (Join-Path (Get-Base $Profile) $Slug) $Uuid
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
        $r = New-TestRoot -Profile $p -Files @{ ('arquivo com espa' + [char]0x00E7 + 'o ' + [char]0x00E3 + '.txt') = 10; ('pasta ' + [char]0x65E5 + '\x y.bin') = 20 }
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
        $r = New-TestRoot -Profile $p
        [IO.File]::SetLastWriteTimeUtc((Join-Path $r 'sub\b.bin'), $nowFuture.AddHours(-1))
        $x = Find-Part (Inv -Profiles @($p)) $r
        Assert-Eq $x.Class 'RECENT' 'classe'
    }
    Test-Case 'Classificacao' 'Idade > 72h sem evidencias = ORPHAN_SUSPECTED (somente informativo)' {
        $p = New-TestProfile 'old'
        $r = New-TestRoot -Profile $p
        $i = Inv -Profiles @($p)
        Assert-Eq (Find-Part $i $r).Class 'ORPHAN_SUSPECTED' 'classe'
    }
    Test-Case 'Classificacao' 'Relogio adiantado (CLOCK_SKEW) bloqueia' {
        $p = New-TestProfile 'skew'
        $r = New-TestRoot -Profile $p
        [IO.File]::SetLastWriteTimeUtc((Join-Path $r 'a.txt'), $nowFuture.AddDays(1))
        $i = Inv -Profiles @($p)
        $x = Find-Part $i $r
        Assert-True ($x.Flags -contains 'CLOCK_SKEW') 'flag'
        Assert-Eq $x.Class 'RECENT' 'classe conservadora'
    }
    Test-Case 'Classificacao' 'Arquivos soltos, diretorio nao-UUID e slug invalido nunca sao roots de sessao' {
        $p = New-TestProfile 'loose'
        $b = Get-Base $p
        $null = New-TestRoot -Profile $p
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
        $r = New-TestRoot -Profile $p1
        $i = Inv -Profiles @($p1, $p2)
        Assert-True ((Find-Part $i $r).Flags -contains 'SHARED_TEMP') 'flag'
        Assert-Eq @($i.Partitions).Count 1 'sem duplicar particoes'
    }

    # ------------------------------------------------------------------ partitions
    Test-Case 'Particoes exclusivas' 'Soma das particoes = total independente, sem duplicidade' {
        $p = New-TestProfile 'sum'
        1..5 | ForEach-Object { $null = New-TestRoot -Profile $p -Slug ('C--p' + ($_ % 2)) -Files @{ 'x.bin' = (1000 * $_); 'd\y.bin' = 7; 'd\e\z.bin' = 3 } }
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
        $r = New-TestRoot -Profile $p -Files @{ 'a.txt' = 1; 'secreto\b.txt' = 2 }
        $d = Join-Path $r 'secreto'
        $o = icacls $d /deny "*$($me.Sid):(OI)(CI)(RD)" 2>&1
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
        $null = New-TestRoot -Profile $p
        $o = icacls $b /deny "*$($me.Sid):(RD)" 2>&1
        $cleanupActions.Add([scriptblock]::Create("icacls '$b' /remove:d '*$($me.Sid)' | Out-Null"))
        $i = Inv -Profiles @($p)
        Assert-True (@($i.Bases)[0].Status -in @('ENUMERATION_FAILED', 'INACCESSIBLE')) "status $(@($i.Bases)[0].Status)"
        Assert-True (-not $i.CoverageComplete) 'cobertura incompleta'
        Assert-Eq @($i.InaccessibleProfiles).Count 1 'perfil listado como inacessivel'
        Show-AtmAudit -Inventory $i
    }
    Test-Case 'Permissoes' 'Sem permissao de exclusao (deny DE/DC) -> sondagem ACCESS_DENIED, BLOQUEADO' {
        $p = New-TestProfile 'nodelete'
        $r = New-TestRoot -Profile $p -Files @{ 'a.txt' = 5 }
        $f = Join-Path $r 'a.txt'
        $o = icacls $f /deny "*$($me.Sid):(DE)" 2>&1
        $o = icacls $r /deny "*$($me.Sid):(DC)" 2>&1
        $cleanupActions.Add([scriptblock]::Create("icacls '$f' /remove:d '*$($me.Sid)' | Out-Null; icacls '$r' /remove:d '*$($me.Sid)' | Out-Null"))
        $i = Inv -Profiles @($p)
        $g = Test-AtmCandidate -Partition (Find-Part $i $r) -Inventory $i
        Assert-Eq $g.Category 'BLOCKED' 'bloqueado'
        Assert-True (($g.Reasons -join ' ') -match 'ACESSO_NEGADO') "motivo: $($g.Reasons -join ';')"
        Assert-True ([IO.File]::Exists($f)) 'arquivo intacto'
    }
    Test-Case 'Permissoes' 'Arquivo somente leitura (protegido) bloqueia; sem -Force' {
        $p = New-TestProfile 'readonly'
        $r = New-TestRoot -Profile $p
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
        $r = New-TestRoot -Profile $p
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
        $r = New-TestRoot -Profile $p
        $ident = [pscustomobject]@{ Sid = 'S-1-5-21-1-2-3-4444'; Name = 'TEST\owner'; IsAdmin = $false }
        $i = Inv -Profiles @($p) -Identity $ident
        $g = Test-AtmCandidate -Partition (Find-Part $i $r) -Inventory $i
        Assert-True (($g.Reasons -join ' ') -match 'OWNER_DIVERGENTE') ($g.Reasons -join ';')
    }

    # ------------------------------------------------------------------ processes / sessions / references
    Test-Case 'Processos' 'Cobertura de processos incompleta bloqueia SEMPRE (nao-admin e admin), sem override' {
        $p = New-TestProfile 'procgap'
        $r = New-TestRoot -Profile $p
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
        $r = New-TestRoot -Profile $p
        $i = Inv -Profiles @($p)
        $i.Snapshot.Failed = $true
        $x = Find-Part $i $r
        Set-AtmClassification -Partition $x -Base @($i.Bases)[0] -Registry ([pscustomobject]@{ Readable = $true; Unparseable = 0; Entries = @() }) -Snapshot $i.Snapshot -NowUtc $nowFuture -StartUtc ([datetime]::UtcNow)
        Assert-True ($x.Flags -contains 'PROCESS_SNAPSHOT_FAILED') 'flag'
        Assert-Eq $x.Class 'LIVENESS_UNKNOWN' 'classe'
    }
    Test-Case 'Referencias' 'Referencia direta em linha de comando -> ACTIVE_EVIDENCE (sem expor a linha)' {
        $p = New-TestProfile 'ref'
        $r = New-TestRoot -Profile $p
        $procs = New-Procs -Extra @([pscustomobject]@{ ProcessId = 501; Name = 'node.exe'; ParentProcessId = 1; CommandLine = "node.exe --token=SEGREDO `"$r\sub\b.bin`""; CreationDate = (Get-Date) })
        $i = Inv -Profiles @($p) -Procs $procs
        $x = Find-Part $i $r
        Assert-Eq $x.Class 'ACTIVE_EVIDENCE' 'classe'
        Assert-True (($x.Evidence -join ' ') -notmatch 'SEGREDO') 'linha de comando nao exposta'
        Assert-Eq (Test-AtmCandidate -Partition $x -Inventory $i).Category 'BLOCKED' 'bloqueado'
    }
    Test-Case 'Referencias' 'Referencia com barras normais e caixa diferente' {
        $p = New-TestProfile 'refslash'
        $r = New-TestRoot -Profile $p
        $procs = New-Procs -Extra @([pscustomobject]@{ ProcessId = 502; Name = 'bash.exe'; ParentProcessId = 1; CommandLine = ('bash -c cd ' + $r.ToUpperInvariant().Replace('\', '/') + '/x'); CreationDate = (Get-Date) })
        Assert-Eq (Find-Part (Inv -Profiles @($p) -Procs $procs) $r).Class 'ACTIVE_EVIDENCE' 'classe'
    }
    Test-Case 'Referencias' 'Referencia so ao ancestral (projeto/base) NAO comprova atividade dos filhos' {
        $p = New-TestProfile 'anc'
        $r1 = New-TestRoot -Profile $p -Slug 'C--a'
        $r2 = New-TestRoot -Profile $p -Slug 'C--b'
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
        $r = New-TestRoot -Profile $p -Slug 'C--longo-projeto'
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
        $r = New-TestRoot -Profile $p
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
        $ra = New-TestRoot -Profile $pa; $rb = New-TestRoot -Profile $pb
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
        $r1 = New-TestRoot -Profile $p; $r2 = New-TestRoot -Profile $p
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
        $r = New-TestRoot -Profile $p -Slug 'C--t'
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
        $r = New-TestRoot -Profile $p
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
        $r = New-TestRoot -Profile $p
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
        $r = New-TestRoot -Profile $p
        $target = Join-Path $sandbox 'alvo-sym'; [void][IO.Directory]::CreateDirectory($target)
        try { $o = cmd /c mklink /D "`"$(Join-Path $r 'sym')`"" "`"$target`"" 2>&1 } catch { }
        if (-not [IO.Directory]::Exists((Join-Path $r 'sym'))) { $script:caseSkipped = $true; $script:caseNote = 'symlink exige privilegio (SeCreateSymbolicLink) ou modo desenvolvedor; reparse coberto por junctions'; return }
        $cleanupActions.Add([scriptblock]::Create("try { [IO.Directory]::Delete('$(Join-Path $r 'sym')', `$false) } catch { }"))
        Assert-True ((Find-Part (Inv -Profiles @($p)) $r).Flags -contains 'REPARSE_POINT') 'flag'
    }

    # ------------------------------------------------------------------ locks / in use
    Test-Case 'Arquivos em uso' 'Arquivo aberto (FileShare.None e ReadWrite|Delete) -> EM_USO, preservado' {
        $p = New-TestProfile 'locked'
        $r = New-TestRoot -Profile $p
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
        $r = New-TestRoot -Profile $p
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
        $r = New-TestRoot -Profile $p
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
        $r = New-TestRoot -Profile $p
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
        $r = New-TestRoot -Profile $p
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
        $r1 = New-TestRoot -Profile $p; $r2 = New-TestRoot -Profile $p
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
        $r = New-TestRoot -Profile $p
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
        $r = New-TestRoot -Profile $p
        $hook = { param($part) [IO.File]::WriteAllBytes((Join-Path $part.Path 'apareceu.bin'), (New-Object byte[] 9)) }
        $c = Invoke-AtmClean -Entries @([pscustomobject]@{ Source = 't'; Path = $r; Fingerprint = $null }) -PlanPresenter $presenter -ConfirmationReader ${function:Confirm-Correct} -InventoryArgs (Get-InvArgs -Profiles @($p)) -BeforeDeleteHook $hook
        Assert-Eq @($c.Deleted).Count 0 'nada excluido'
        Assert-Eq @($c.Skipped).Count 1 'preservado'
        Assert-True ([IO.File]::Exists((Join-Path $r 'apareceu.bin'))) 'arquivo novo intacto'
    }
    Test-Case 'Clean' 'Root removida entre preview e clean / durante a revalidacao' {
        $p = New-TestProfile 'vanish'
        $r = New-TestRoot -Profile $p
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
        $r = New-TestRoot -Profile $p
        $c = Invoke-AtmClean -Entries @([pscustomobject]@{ Source = 't'; Path = $r.ToUpperInvariant().Replace('C:\', 'C:\'); Fingerprint = $null }) -PlanPresenter $presenter -ConfirmationReader ${function:Confirm-Correct} -InventoryArgs (Get-InvArgs -Profiles @($p))
        Assert-Eq $c.Aborted 'NENHUM_CAMINHO_ELEGIVEL' 'caixa'
        $c2 = Invoke-AtmClean -Entries @([pscustomobject]@{ Source = 'a'; Path = $r; Fingerprint = $null }, [pscustomobject]@{ Source = 'b'; Path = $r; Fingerprint = $null }) -PlanPresenter $presenter -ConfirmationReader { param($x) 'nao' } -InventoryArgs (Get-InvArgs -Profiles @($p))
        Assert-True (@($c2.Rejected | Where-Object { $_.Reasons -contains 'DUPLICADO_NA_ALLOWLIST' }).Count -eq 1) 'duplicado'
        Assert-True ([IO.Directory]::Exists($r)) 'preservado'
    }
    Test-Case 'Clean' 'Classes ACTIVE/RECENT/UNKNOWN nunca entram no plano' {
        $p = New-TestProfile 'classes'
        $ra = New-TestRoot -Profile $p; $rr = New-TestRoot -Profile $p; $ru = New-TestRoot -Profile $p
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
        1..3 | ForEach-Object { $null = New-TestRoot -Profile $p }
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
        $r = New-TestRoot -Profile $p -Files @{ 'sub\alvo.txt' = 5; 'a.txt' = 1 }
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
        $r = New-TestRoot -Profile $p
        $b = Get-Base $p
        $o = icacls $b /grant '*S-1-5-32-545:(OI)(CI)(M)' 2>&1
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
        $r = New-TestRoot -Profile $p
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
        $r = New-TestRoot -Profile $p -Slug 'C--longo-projeto'
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
        $r = New-TestRoot -Profile $p
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
        $r = New-TestRoot -Profile $p
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
        $r = New-TestRoot -Profile $p -Files @{ 'sub\x.txt' = 3 }
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
        $r = New-TestRoot -Profile $p -Slug 'C--proj'
        $r2 = New-TestRoot -Profile $p -Slug 'C--proj'
        $other = New-TestRoot -Profile $p -Slug 'C--outro'
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
        $r = New-TestRoot -Profile $p -Files @{ 'a.txt' = 1 }
        [void][IO.Directory]::CreateDirectory((Join-Path $r 'vazio'))
        Assert-Eq ([AtmTestOpen]::TryOpenDirForWrite((Join-Path $r 'vazio'))) 0 'controle: sem fixacao a abertura para escrita funciona'
        $script:pinWrite = -1
        $d = [AgentTempManager.AtmDeleter]::DeleteTree($r, [Action[string]]{ param($root) $script:pinWrite = [AtmTestOpen]::TryOpenDirForWrite((Join-Path $root 'vazio')) })
        Assert-Eq $script:pinWrite 32 'durante a exclusao: violacao de compartilhamento (32)'
        Assert-True $d.Completed "exclusao concluida ($($d.AbortReason))"
    }
    Test-Case 'Gate V0.1' 'Preview sempre exibe o motivo do bloqueio, mesmo com evidencias longas' {
        $p = New-TestProfile 'whyshown'
        $r = New-TestRoot -Profile $p
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
        $r1 = New-TestRoot -Profile $p; $r2 = New-TestRoot -Profile $p
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
        $null = New-TestRoot -Profile $p
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
            $r = New-TestRoot -Profile $p
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
        foreach ($f in @(Get-ChildItem -LiteralPath $repo -File -Force)) { Copy-Item -LiteralPath $f.FullName -Destination $copy }
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
        $r = New-TestRoot -Profile $p
        [IO.File]::SetLastWriteTimeUtc((Join-Path $r 'a.txt'), $nowFuture.AddHours(-1))
        $r2 = New-TestRoot -Profile $p
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
        $null = New-TestRoot -Profile $p
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
        $r = New-TestRoot -Profile $p
        $i = Inv -Profiles @($p)
        Assert-Eq @($i.Profiles).Count 1 'um perfil'
        Assert-Eq (Get-AtmProfileStatusLabel -Inventory $i -Profile $p) 'AUDITADO' 'rotulo'
        Assert-True $i.CoverageComplete 'cobertura completa com processos inspecionaveis'
        Assert-Eq @($i.Partitions).Count 1 'uma particao'
        Show-AtmAudit -Inventory $i
    }
    Test-Case 'Portabilidade' 'Varios usuarios: auditado, inacessivel, hive nao carregado, sem Claude Code' {
        $pa = New-TestProfile 'multiA'; $ra = New-TestRoot -Profile $pa
        $pb = New-TestProfile 'multiB' -Sid 'S-1-5-21-1-2-3-4444'; $null = New-TestRoot -Profile $pb
        $bb = Get-Base $pb
        $o = icacls $bb /deny "*$($me.Sid):(RD)" 2>&1
        $cleanupActions.Add([scriptblock]::Create("icacls '$bb' /remove:d '*$($me.Sid)' | Out-Null"))
        $pc = New-TestProfile 'multiC'; [IO.Directory]::Delete((Get-Base $pc)); $pc.EnvStatus = 'NOT_LOADED'; $pc.Loaded = $false; $pc.EnvKnown = $false
        $pd = New-TestProfile 'multiD' -NoConfig; [IO.Directory]::Delete((Get-Base $pd))
        $i = Inv -Profiles @($pa, $pb, $pc, $pd)
        Assert-Eq (Get-AtmProfileStatusLabel -Inventory $i -Profile $pa) 'AUDITADO' 'A auditado'
        Assert-Eq (Get-AtmProfileStatusLabel -Inventory $i -Profile $pb) 'INACESSIVEL' 'B inacessivel'
        Assert-Eq (Get-AtmProfileStatusLabel -Inventory $i -Profile $pc) 'TEMP_NAO_VERIFICAVEL' 'C: ausencia no local padrao nao prova nada'
        Assert-Eq (Get-AtmProfileStatusLabel -Inventory $i -Profile $pd) 'SEM_TEMP_CLAUDE' 'D: sem Claude Code'
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
        Assert-Eq (Get-AtmProfileStatusLabel -Inventory $i -Profile $p) 'SEM_TEMP_CLAUDE' 'rotulo'
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
        $r1 = New-TestRoot -Profile $p -Slug 'D--src-gamma'; $r2 = New-TestRoot -Profile $p -Slug 'D--src-gamma'
        $r3 = New-TestRoot -Profile $p -Slug 'C--src-delta'; $r4 = New-TestRoot -Profile $p -Slug 'C--src-delta'
        $r5 = New-TestRoot -Profile $p -Slug 'C--a-b'
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
        $r = New-TestRoot -Profile $p -Files @{ ("arq '&' #1 " + [char]0x00E7 + '.txt') = 3 }
        $i = Inv -Profiles @($p)
        $x = Find-Part $i $r
        Assert-True ($x -and $x.Files -eq 1 -and $x.Bytes -eq 3) 'medido'
        $c = Invoke-AtmClean -Entries @([pscustomobject]@{ Source = 't'; Path = $r; Fingerprint = $null }) -PlanPresenter $presenter -ConfirmationReader ${function:Confirm-Correct} -InventoryArgs (Get-InvArgs -Profiles @($p))
        Assert-True (@($c.Deleted | Where-Object { $_.Completed -and $_.Verified }).Count -eq 1) 'motor de exclusao (sandbox) funciona com o nome'
        $inst = Join-Path $sandbox "PF O'Neil & Co (x) #1\AgentTempManager"
        [void][IO.Directory]::CreateDirectory((Split-Path -Parent $inst))
        $res = Install-AtmProduct -SourceDir $srcDir -InstallDir $inst -TrustSid $me.Sid -SkipPath -SourceWithoutManifest
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
        $rc = New-TestRoot -Profile $p
        $fakeRoot = Join-Path $p.TempCandidates[0].TempPath ('fake-agent\scope1\run-0001')
        [void][IO.Directory]::CreateDirectory($fakeRoot); [IO.File]::WriteAllBytes((Join-Path $fakeRoot 'x.bin'), (New-Object byte[] 42))
        $claude = (Get-AtmProviders)[0]
        $fake = [pscustomobject]@{
            Id = 'fake-agent'; DisplayName = 'Fake'; TempSubdir = 'fake-agent'; ScopePattern = '^scope\d+$'; RootPattern = '^run-\d{4}$'; EnvVarNames = @()
            GetExtraTempDirs = { param($Profile) @() }; GetConfigDirs = { param($Profile) [pscustomobject]@{ Dirs = @(); Known = $true } }
            GetSessionEvidence = { param($Profile, $Snapshot) [pscustomobject]@{ Readable = $true; Unparseable = 0; Entries = @() } }
            GetActivityEvidence = { param($Profile, $Scope, $RootName) [pscustomobject]@{ Readable = $true; LastWriteUtc = $null } }
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
        $cleanupActions.Add({ try { [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree('Software\AgentTempManagerTest', $false) } catch { } })
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
        $o = icacls $parent /grant '*S-1-5-32-545:(OI)(CI)(M)' 2>&1
        $threw = $false; try { $null = Install-AtmProduct -SourceDir $srcDir -InstallDir (Join-Path $parent 'AgentTempManager') -TrustSid $me.Sid -SkipPath -SourceWithoutManifest } catch { $threw = ($_.Exception.Message -match 'pai inseguro') }
        Assert-True $threw 'pai inseguro recusado'
        Assert-True (-not (Test-Path (Join-Path $parent 'AgentTempManager'))) 'nada instalado'
        $testKey = 'Software\AgentTempManagerTest\Env2'
        $cleanupActions.Add({ try { [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree('Software\AgentTempManagerTest', $false) } catch { } })
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
        $o = icacls $ok /reset 2>&1
        Assert-Eq $applied.Count 0 "ACL aplicada = SYSTEM + Administradores, protegida ($($applied -join '; '))"
        Assert-Eq $LASTEXITCODE 0 'heranca restaurada'
        if ($script:sandboxAclAdjusted) {
            Assert-Eq @(Get-SandboxAclResultProblems -Path $sandbox -OwnerSid $testOwnerSid).Count 0 'ACL ajustada do sandbox = SYSTEM + Administradores'
            $script:caseNote = 'sessao elevada: ACL do sandbox ajustada e verificada'
        } else { $script:caseNote = 'sessao nao elevada: nenhum ajuste de ACL (owner = usuario)' }
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

    # ------------------------------------------------------------------ scale
    if (-not $SkipHeavy) {
        Test-Case 'Escala' "Root com $HeavyFiles arquivos: passagem unica, memoria controlada" {
            $p = New-TestProfile 'heavy'
            $r = New-TestRoot -Profile $p -Files @{}
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
    foreach ($a in $cleanupActions) { try { & $a } catch { } }
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