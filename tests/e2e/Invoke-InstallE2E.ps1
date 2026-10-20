<#
.SYNOPSIS
  End-to-end validation of a real installation on a DISPOSABLE Windows machine (a GitHub-hosted runner).
.DESCRIPTION
  Refuses to run anywhere else unless -DisposableMachine is given: it installs into %ProgramFiles%, changes the
  machine PATH, creates a temporary local standard user and creates a fake agent session under the current
  user's TEMP. Steps:
    build the release from the checkout; check SHA256SUMS; extract to an administrator-only folder; install (no
    -ProjectsFile); verify / version / audit / preview / help / TUI refusal from a new process using the machine
    PATH; clean of a real-looking session root must stop without deleting it (V0.1); update; rollback; tamper
    detection and repair; audit / preview / verify as a real standard user, who cannot write the install
    directory; uninstall (directory and PATH entry removed).
  Writes summary.json and raw outputs to -OutDir. Exit code = number of failed steps (NOT TESTED is not a failure
  and not a pass).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutDir,
    [ValidateSet('powershell', 'pwsh')][string]$InstallerShell = 'powershell',
    [switch]$DisposableMachine
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

if (-not $DisposableMachine -and -not ($env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -eq 'github-hosted')) {
    throw 'Recusado: este teste instala de verdade e cria um usuario local; so roda em maquina descartavel (runner do GitHub) ou com -DisposableMachine.'
}
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Requer sessao elevada.' }

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$installerExe = $(if ($InstallerShell -eq 'pwsh') { (Get-Command pwsh -ErrorAction Stop).Source } else { $ps51 })
[void][IO.Directory]::CreateDirectory($OutDir)
$installDir = Join-Path $env:ProgramFiles 'AgentTempManager'
$summary = [ordered]@{
    startedUtc = [datetime]::UtcNow.ToString('o'); os = (Get-CimInstance Win32_OperatingSystem).Caption
    osVersion = [Environment]::OSVersion.Version.ToString(); arch = $env:PROCESSOR_ARCHITECTURE
    installerShell = $InstallerShell; driver = "$($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)"
    uacEnabled = [bool](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
    steps = [ordered]@{}
}
$script:notTested = $false

function Step([string]$Name, [scriptblock]$Body) {
    $script:notTested = $false
    try {
        $d = & $Body
        $status = $(if ($script:notTested) { 'NOT_TESTED' } else { 'PASS' })
        $summary.steps[$Name] = [ordered]@{ status = $status; detail = "$d" }
    } catch { $summary.steps[$Name] = [ordered]@{ status = 'FAIL'; detail = $_.Exception.Message } }
    $s = $summary.steps[$Name]
    Write-Host ("[{0}] {1} {2}" -f $s.status, $Name, $s.detail) -ForegroundColor $(switch ($s.status) { 'PASS' { 'Green' } 'FAIL' { 'Red' } default { 'Yellow' } })
}

function Invoke-Agent([string]$ArgLine, [string]$Tag) {
    # New process with the machine PATH, exactly like a new terminal.
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $out = & cmd.exe /c "set `"PATH=$machinePath`" && agent-temp $ArgLine" 2>&1
    $code = $LASTEXITCODE
    $text = ($out | ForEach-Object { "$_" }) -join "`r`n"
    [IO.File]::WriteAllText((Join-Path $OutDir ("agent-temp-$Tag.txt")), $text)
    return [pscustomobject]@{ Code = $code; Text = $text }
}

function Assert([bool]$Cond, [string]$Msg) { if (-not $Cond) { throw $Msg } }

$pkg = $null
Step 'build-release' {
    & $ps51 -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo 'tools\Build-Release.ps1') -SkipTests *> (Join-Path $OutDir 'build.txt')
    Assert ($LASTEXITCODE -eq 0) "Build-Release exit $LASTEXITCODE"
    (Get-ChildItem (Join-Path $repo 'dist') -Filter 'agent-temp-manager-*.zip').Name
}
Step 'sha256' {
    $zip = @(Get-ChildItem (Join-Path $repo 'dist') -Filter 'agent-temp-manager-*.zip')[0]
    $expected = ((Get-Content (Join-Path $repo 'dist\SHA256SUMS.txt') -Raw).Split(' ')[0]).ToUpperInvariant()
    $h = (Get-FileHash -LiteralPath $zip.FullName -Algorithm SHA256).Hash
    Assert ($h -eq $expected) "hash $h != $expected"
    $h
}
Step 'extract-to-admin-only-folder' {
    $zip = @(Get-ChildItem (Join-Path $repo 'dist') -Filter 'agent-temp-manager-*.zip')[0]
    $rel = Join-Path $env:ProgramFiles 'AgentTempManager-release'
    Expand-Archive -LiteralPath $zip.FullName -DestinationPath $rel -Force
    $script:pkg = @(Get-ChildItem -LiteralPath $rel -Directory)[0].FullName
    $script:pkg
}
$pkg = $script:pkg

Step 'install' {
    & $installerExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $pkg 'install\Install-AgentTempManager.ps1') *> (Join-Path $OutDir 'install.txt')
    Assert ($LASTEXITCODE -eq 0) "installer exit $LASTEXITCODE"
    Assert (Test-Path (Join-Path $installDir 'manifest.json')) 'manifest ausente'
    Assert (-not (Test-Path (Join-Path $installDir 'config\projects.local.json'))) 'configuracao pessoal inesperada'
    Assert (([Environment]::GetEnvironmentVariable('Path', 'Machine')) -match [regex]::Escape((Join-Path $installDir 'bin'))) 'PATH da maquina sem bin'
    'ok'
}
Step 'shipped-release-gate' {
    $clean = [IO.File]::ReadAllText((Join-Path $installDir 'lib\Engine.Clean.ps1'))
    Assert ([regex]::Matches($clean, '\$script:AtmRealDeletionEnabled\s*=').Count -eq 1) 'mais de uma atribuicao da trava'
    Assert ($clean -match '\$script:AtmRealDeletionEnabled = \$false') 'trava instalada nao e $false'
    'installed gate = $false (single assignment)'
}
foreach ($c in @(@('verify', 'verify', 0), @('version -Lang en-US', 'version', 0), @('audit -NoProgress -Lang en-US', 'audit', 0),
                 @('preview -NoProgress -Lang en-US', 'preview', 0), @('help', 'help', 0), @('', 'tui-noninteractive', 6))) {
    $argLine = $c[0]; $tag = $c[1]; $expect = $c[2]
    Step "cli-$tag" {
        $r = Invoke-Agent $argLine $tag
        Assert ($r.Code -eq $expect) "exit $($r.Code), esperado $expect"
        if ($tag -eq 'version') { Assert ($r.Text -match '(?i)real deletion\s*:\s*DISABLED') 'version nao informa exclusao desabilitada' }
        if ($tag -eq 'audit') { Assert ($r.Text -match 'elevated administrator: YES') 'auditoria nao mostra a sessao elevada' }
        "exit $($r.Code)"
    }
}

Step 'clean-never-deletes' {
    # A real-looking, old session root of the current user. V0.1 must stop without deleting it.
    $base = Join-Path ([IO.Path]::GetTempPath()) 'claude'
    if (Test-Path -LiteralPath $base) { $script:notTested = $true; return 'base claude ja existia no runner: nao alterada' }
    $root = Join-Path $base ('C--e2e-project\' + [guid]::NewGuid())
    [void][IO.Directory]::CreateDirectory((Join-Path $root 'work'))
    $file = Join-Path $root 'work\data.txt'; [IO.File]::WriteAllText($file, 'e2e')
    $old = [datetime]::UtcNow.AddDays(-10)
    [IO.File]::SetLastWriteTimeUtc($file, $old); [IO.File]::SetCreationTimeUtc($file, $old)
    foreach ($p in @((Join-Path $root 'work'), $root, (Split-Path $root), $base)) { [IO.Directory]::SetLastWriteTimeUtc($p, $old); [IO.Directory]::SetCreationTimeUtc($p, $old) }
    # Owner = the account (files created elevated are owned by Administrators), like a profile's own files.
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
    foreach ($d in @($base, (Split-Path $root), $root)) { $a = Get-Acl -LiteralPath $d; $a.SetOwner($me); Set-Acl -LiteralPath $d -AclObject $a }
    $list = Join-Path $OutDir 'allowlist.txt'; [IO.File]::WriteAllText($list, $root)
    $r = Invoke-Agent "clean -AllowListFile `"$list`" -Lang en-US" 'clean'
    Assert (Test-Path -LiteralPath $file) 'ARQUIVO APAGADO'
    Assert ([IO.File]::ReadAllText($file) -eq 'e2e') 'conteudo alterado'
    Assert ($r.Code -eq 3) "exit $($r.Code), esperado 3 (interrompido)"
    $code = $(if ($r.Text -match 'EXCLUSAO_REAL_DESABILITADA_V0_1') { 'EXCLUSAO_REAL_DESABILITADA_V0_1 (gate reached)' } elseif ($r.Text -match '(NENHUM_CAMINHO_ELEGIVEL)') { 'NENHUM_CAMINHO_ELEGIVEL (blocked before the gate)' } else { 'other' })
    "root intact; $code"
}

Step 'update' {
    & $installerExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $pkg 'install\Install-AgentTempManager.ps1') -Update *> (Join-Path $OutDir 'update.txt')
    Assert ($LASTEXITCODE -eq 0) "update exit $LASTEXITCODE"
    Assert (Test-Path (Join-Path $env:ProgramFiles 'AgentTempManager.previous')) 'versao anterior nao mantida'
    $r = Invoke-Agent 'verify' 'verify-after-update'; Assert ($r.Code -eq 0) "verify exit $($r.Code)"
    'ok'
}
Step 'rollback' {
    & $installerExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $pkg 'install\Restore-AgentTempManagerPrevious.ps1') *> (Join-Path $OutDir 'rollback.txt')
    Assert ($LASTEXITCODE -eq 0) "rollback exit $LASTEXITCODE"
    $r = Invoke-Agent 'verify' 'verify-after-rollback'; Assert ($r.Code -eq 0) "verify exit $($r.Code)"
    'ok'
}
Step 'tamper-detected-and-repaired' {
    $f = Join-Path $installDir 'lib\Report.ps1'
    [IO.File]::AppendAllText($f, "`r`n# tampered by e2e test`r`n")
    $r = Invoke-Agent 'verify' 'verify-tampered'; Assert ($r.Code -eq 5) "verify exit $($r.Code), esperado 5"
    $r = Invoke-Agent 'version' 'version-tampered'; Assert ($r.Code -eq 5) "version exit $($r.Code), esperado 5 (execucao recusada)"
    & $installerExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $pkg 'install\Install-AgentTempManager.ps1') -Update *> (Join-Path $OutDir 'repair.txt')
    Assert ($LASTEXITCODE -eq 0) "reparo exit $LASTEXITCODE"
    $r = Invoke-Agent 'verify' 'verify-repaired'; Assert ($r.Code -eq 0) "verify apos reparo exit $($r.Code)"
    'detected (5) and repaired'
}

# Real standard user (created only in this disposable machine).
$userName = 'atme2e' + (Get-Random -Minimum 1000 -Maximum 9999)
$userDir = Join-Path $env:SystemDrive 'atm-e2e-user'
$cred = $null
Step 'standard-user-create' {
    # Random password built directly as a SecureString (never a plain string), used only in this VM.
    $chars = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'.ToCharArray()
    $sec = New-Object Security.SecureString
    foreach ($ch in @((1..20 | ForEach-Object { $chars | Get-Random }) + @('#', '7', 'a', 'Z'))) { $sec.AppendChar($ch) }
    $sec.MakeReadOnly()
    $null = New-LocalUser -Name $userName -Password $sec -AccountNeverExpires -PasswordNeverExpires -Description 'atm e2e (disposable runner)'
    # Member of Users only (by SID: group names are localized).
    if (-not @(Get-LocalGroupMember -SID 'S-1-5-32-545' | Where-Object { $_.Name -like "*\$userName" }).Count) { Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $userName }
    $script:cred = New-Object Management.Automation.PSCredential(".\$userName", $sec)
    [void][IO.Directory]::CreateDirectory($userDir)
    $null = icacls $userDir /grant "${userName}:(OI)(CI)M"
    $isAdmin = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object { $_.Name -like "*\$userName" }).Count -gt 0
    Assert (-not $isAdmin) 'usuario de teste nao pode ser administrador'
    "$userName (Users only)"
}
$cred = $script:cred
foreach ($c in @(@('audit -NoProgress -Lang en-US', 'audit'), @('preview -NoProgress -Lang en-US', 'preview'), @('verify', 'verify'))) {
    $argLine = $c[0]; $tag = $c[1]
    Step "standard-user-$tag" {
        if (-not $cred) { throw 'usuario de teste indisponivel' }
        $outFile = Join-Path $userDir "$tag.txt"
        try {
            $p = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\cmd.exe') -ArgumentList "/c agent-temp $argLine > `"$outFile`" 2>&1" `
                -Credential $cred -LoadUserProfile -WorkingDirectory $userDir -WindowStyle Hidden -PassThru -Wait
        } catch { $script:notTested = $true; return "processo como usuario comum nao iniciou neste runner: $($_.Exception.Message)" }
        $text = $(if (Test-Path $outFile) { [IO.File]::ReadAllText($outFile) } else { '' })
        [IO.File]::WriteAllText((Join-Path $OutDir "standard-user-$tag.txt"), $text)
        Assert ($p.ExitCode -eq 0) "exit $($p.ExitCode)"
        if ($tag -eq 'audit') { Assert ($text -match 'elevated administrator: NO') 'auditoria nao mostra sessao nao elevada' }
        "exit 0"
    }
}
Step 'standard-user-cannot-write-install-dir' {
    if (-not $cred) { throw 'usuario de teste indisponivel' }
    $target = Join-Path $installDir 'e2e-write-probe.txt'
    try {
        $p = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\cmd.exe') -ArgumentList "/c echo x> `"$target`"" `
            -Credential $cred -LoadUserProfile -WorkingDirectory $userDir -WindowStyle Hidden -PassThru -Wait
    } catch { $script:notTested = $true; return "processo como usuario comum nao iniciou: $($_.Exception.Message)" }
    Assert (-not (Test-Path -LiteralPath $target)) 'usuario comum conseguiu gravar no diretorio de instalacao'
    "denied (exit $($p.ExitCode))"
}

Step 'uninstall' {
    & $installerExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $pkg 'install\Uninstall-AgentTempManager.ps1') *> (Join-Path $OutDir 'uninstall.txt')
    Assert ($LASTEXITCODE -eq 0) "uninstall exit $LASTEXITCODE"
    Assert (-not (Test-Path $installDir)) 'diretorio ainda existe'
    Assert (-not (([Environment]::GetEnvironmentVariable('Path', 'Machine')) -match 'AgentTempManager')) 'PATH ainda contem o produto'
    'removed'
}
try { if (Get-LocalUser -Name $userName -ErrorAction SilentlyContinue) { Remove-LocalUser -Name $userName } } catch { $null = $_ }

$summary.finishedUtc = [datetime]::UtcNow.ToString('o')
$failed = @($summary.steps.Values | Where-Object { $_.status -eq 'FAIL' }).Count
$summary.failed = $failed
$summary.notTested = @($summary.steps.Values | Where-Object { $_.status -eq 'NOT_TESTED' }).Count
$summary.passed = @($summary.steps.Values | Where-Object { $_.status -eq 'PASS' }).Count
[IO.File]::WriteAllText((Join-Path $OutDir 'summary.json'), ($summary | ConvertTo-Json -Depth 5))
Write-Host ("E2E: {0} PASS / {1} FAIL / {2} NOT_TESTED | {3} {4} | installer {5} | UAC enabled: {6}" -f $summary.passed, $failed, $summary.notTested, $summary.os, $summary.arch, $InstallerShell, $summary.uacEnabled)
exit $failed
