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
    [string]$ReleaseDir,      # zip + SHA256SUMS.txt built elsewhere (the same package for every OS); default: build here
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
$releaseDirUsed = $(if ($ReleaseDir) { $ReleaseDir } else { Join-Path $repo 'dist' })
Step 'build-release' {
    if ($ReleaseDir) { return "package provided: $((Get-ChildItem -LiteralPath $ReleaseDir -Filter 'agent-temp-manager-*.zip').Name)" }
    & $ps51 -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo 'tools\Build-Release.ps1') -SkipTests *> (Join-Path $OutDir 'build.txt')
    Assert ($LASTEXITCODE -eq 0) "Build-Release exit $LASTEXITCODE"
    (Get-ChildItem (Join-Path $repo 'dist') -Filter 'agent-temp-manager-*.zip').Name
}
Step 'sha256' {
    $zip = @(Get-ChildItem -LiteralPath $releaseDirUsed -Filter 'agent-temp-manager-*.zip')[0]
    $expected = ((Get-Content (Join-Path $releaseDirUsed 'SHA256SUMS.txt') -Raw).Split(' ')[0]).ToUpperInvariant()
    $h = (Get-FileHash -LiteralPath $zip.FullName -Algorithm SHA256).Hash
    Assert ($h -eq $expected) "hash $h != $expected"
    $h
}
Step 'extract-to-admin-only-folder' {
    $zip = @(Get-ChildItem -LiteralPath $releaseDirUsed -Filter 'agent-temp-manager-*.zip')[0]
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
Step 'native-job-runner-runtime' {
    # The installed native library on this architecture (ARM64 included), in a separate process: the job runner starts
    # a child inside its job (exit code and output), and a deadline terminates the job.
    $dll = Join-Path $installDir 'lib\AgentTempManager.Native.dll'
    $probe = @'
param($Dll)
Add-Type -Path $Dll
$e = @([Environment]::GetEnvironmentVariables().GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" })
$cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'
$a = [AgentTempManager.AtmJobRunner]::Run($cmd, '"cmd.exe" /c echo atm-runner-ok', $env:SystemRoot, $e, 20000, 4096, 256MB, 4)
$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$b = [AgentTempManager.AtmJobRunner]::Run($ps, '"powershell.exe" -NoProfile -Command Start-Sleep 60', $env:SystemRoot, $e, 2000, 4096, 512MB, 4)
'{0}|{1}|{2}|{3}|{4}|{5}|{6}' -f $a.Started, $a.ExitCode, [Text.Encoding]::ASCII.GetString($a.Output).Trim(), $a.ActiveProcessLimit, $b.TimedOut, $b.JobTerminated, $b.Error
'@
    $probeFile = Join-Path $OutDir 'job-runner-probe.ps1'
    [IO.File]::WriteAllText($probeFile, $probe)
    $line = (& $ps51 -NoProfile -ExecutionPolicy Bypass -File $probeFile -Dll $dll 2>&1 | Select-Object -Last 1) -as [string]
    $p = $line.Split('|')
    Assert ($p.Count -eq 7 -and $p[0] -eq 'True' -and $p[1] -eq '0' -and $p[2] -eq 'atm-runner-ok' -and $p[3] -eq '4') "runner: $line"
    Assert ($p[4] -eq 'True' -and $p[5] -eq 'True') "deadline: $line"
    "$($summary.arch): $line"
}
Step 'native-restart-manager-runtime' {
    # P1-C D-2 with the installed native library on this architecture (ARM64 included): a helper started here holds a
    # file of this run's output folder; Restart Manager lists it with its start time; a file not held lists nothing. A
    # 32-bit (WOW64) helper is checked too when this system has one.
    $dll = Join-Path $installDir 'lib\AgentTempManager.Native.dll'
    $probe = @'
param($Dll, $Dir)
Add-Type -Path $Dll
$out = New-Object System.Collections.Generic.List[string]
foreach ($exe in @((Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'), (Join-Path $env:SystemRoot 'SysWOW64\WindowsPowerShell\v1.0\powershell.exe'))) {
    if (-not (Test-Path -LiteralPath $exe)) { $out.Add('absent'); continue }
    $f = Join-Path $Dir ('rm-' + [guid]::NewGuid().ToString('N') + '.txt'); [IO.File]::WriteAllText($f, 'x')
    # A 32-bit PowerShell can take long to start on a busy runner: the helper waits up to 3 minutes, the probe up to 2.
    $c = Start-Process -FilePath $exe -ArgumentList @('-NoProfile', '-Command', "`$h = [IO.File]::Open('$f', 'Open', 'Read', 'ReadWrite'); Start-Sleep 180") -PassThru -WindowStyle Hidden
    try {
        $found = $false; $timeOk = $false
        for ($i = 0; $i -lt 480 -and -not $found; $i++) {
            $h = $null; $null = [AgentTempManager.AtmRestartManager]::Query([string[]]@($f), 8, [ref]$h)
            $m = @($h | Where-Object { $_.Split('|')[0] -eq [string]$c.Id })
            if ($m.Count -gt 0) { $found = $true; $timeOk = ([long]$m[0].Split('|')[1] -eq $c.StartTime.ToUniversalTime().Ticks) } else { Start-Sleep -Milliseconds 250 }
        }
        $out.Add("$found/$timeOk")
    } finally { if (-not $c.HasExited) { $c.Kill() } }
}
$g = Join-Path $Dir 'rm-free.txt'; [IO.File]::WriteAllText($g, 'x')
$h = $null; $st = [AgentTempManager.AtmRestartManager]::Query([string[]]@($g), 8, [ref]$h)
$out.Add("$st/$(@($h).Count)")
$out -join '|'
'@
    $probeFile = Join-Path $OutDir 'restart-manager-probe.ps1'
    [IO.File]::WriteAllText($probeFile, $probe)
    $line = (& $ps51 -NoProfile -ExecutionPolicy Bypass -File $probeFile -Dll $dll -Dir $OutDir 2>&1 | Select-Object -Last 1) -as [string]
    $p = $line.Split('|')
    Assert ($p.Count -eq 3 -and $p[0] -eq 'True/True' -and $p[2] -eq 'OK/0') "restart manager: $line"
    Assert ($p[1] -eq 'True/True' -or $p[1] -eq 'absent') "restart manager (32-bit helper): $line"
    "$($summary.arch): native helper $($p[0]), 32-bit helper $($p[1]), free file $($p[2])"
}

Step 'prototype-handle-relative-open' {
    # ADR-0011 study (test code only, never shipped): opening relative to the volume root with OBJ_DONT_REPARSE on this
    # architecture; a local junction only, no network path.
    $src = Join-Path $PSScriptRoot '..\prototypes\AtmHandleRelativeOpen.cs'
    $probe = @'
param($Src, $Dir)
Add-Type -Path $Src
$T = [AgentTempManagerPrototype.AtmHandleRelativeOpen]
$d = Join-Path $Dir ('proto-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
foreach ($x in @('real\anc', 'evil\anc')) { [void][IO.Directory]::CreateDirectory((Join-Path $d $x)) }
[IO.File]::WriteAllText((Join-Path $d 'real\anc\ref'), 'r'); [IO.File]::WriteAllText((Join-Path $d 'evil\anc\ref'), 'e')
$f = Join-Path $d 'real\anc\ref'
$a = $T::Open($f, $true)
[IO.Directory]::Move((Join-Path $d 'real\anc'), (Join-Path $d 'real\anc-old'))
$null = cmd /c mklink /J "`"$(Join-Path $d 'real\anc')`"" "`"$(Join-Path $d 'evil\anc')`"" 2>&1
$b = $T::Open($f, $false); $c = $T::Open($f, $true)
'{0:X8}|{1:X8}|{2:X8}' -f $a, $b, $c
'@
    $probeFile = Join-Path $OutDir 'handle-relative-open-probe.ps1'
    [IO.File]::WriteAllText($probeFile, $probe)
    $line = (& $ps51 -NoProfile -ExecutionPolicy Bypass -File $probeFile -Src $src -Dir $OutDir 2>&1 | Select-Object -Last 1) -as [string]
    Assert ($line -eq '00000000|00000000|C000050B') "prototype: $line"
    "$($summary.arch): clean $($line.Split('|')[0]), junction without flag $($line.Split('|')[1]), with OBJ_DONT_REPARSE $($line.Split('|')[2])"
}

Step 'services-read-only' {
    # P2-A (ADR-0005): the installed engine queries two services that every Windows has and one name that does not
    # exist, read-only, in the installer's shell; State and StartMode are identical before and after, and the process
    # of Winmgmt (svchost, shared) is linked through the snapshot taken after the query. Nothing is started or changed.
    $probe = @'
param([string]$Lib)
$ErrorActionPreference = 'Stop'
. (Join-Path $Lib 'Engine.Audit.ps1')
. (Join-Path $Lib 'Engine.Diagnose.ps1')
$snap = { (@(Get-CimInstance -ClassName Win32_Service -Filter "Name='EventLog' OR Name='Winmgmt'" -Property Name, State, StartMode | Sort-Object Name | ForEach-Object { '{0}/{1}/{2}' -f $_.Name, $_.State, $_.StartMode })) -join ',' }
$before = & $snap
$names = @('EventLog', 'Winmgmt', 'AtmNoSuchServiceP2A')
$h = [pscustomobject]@{ ProviderId = 'e2e'; ProcessMatchers = @(); ServiceHints = @($names | ForEach-Object { [pscustomobject]@{ Name = $_; Role = $null } }); VirtualizationHints = @(); Coverage = (New-AtmCoverage -Collector 'provider-e2e' -Status 'COMPLETE') }
$q = Invoke-AtmServiceQuery -ProviderHints @($h)
$r = Get-AtmServiceFindings -Query $q -Collection (Get-AtmProcessCollection)
$after = & $snap
$wm = @($r.Findings | Where-Object { $_.Key -eq 'Winmgmt' })[0]
$link = @($wm.Evidence | Where-Object { $_.Code -eq 'SERVICE_PROCESS_VERIFIED' }).Count
'{0}|{1}|{2}|{3}' -f $q.Coverage.Status, (@($r.Findings | ForEach-Object { $_.Key + '=' + $_.State }) -join ','), $link, [int]($before -ceq $after -and $before.Length -gt 0)
'@
    $probeFile = Join-Path $OutDir 'services-probe.ps1'
    [IO.File]::WriteAllText($probeFile, $probe)
    $line = (& $installerExe -NoProfile -ExecutionPolicy Bypass -File $probeFile -Lib (Join-Path $installDir 'lib') 2>&1 | Select-Object -Last 1) -as [string]
    Assert ($line -ceq 'PARTIAL|AtmNoSuchServiceP2A=UNKNOWN,EventLog=RUNNING,Winmgmt=RUNNING|1|1') "services: $line"
    "$($summary.arch) ($InstallerShell): query PARTIAL (a declared name not listed), EventLog/Winmgmt RUNNING, unknown name UNKNOWN (never NOT_PRESENT), Winmgmt process verified, state and start mode unchanged"
}

Step 'virtualization-read-only' {
    # P2-B (ADR-0005 rules 7-9): the installed engine reads the platform, the VMs (only with the namespace listed and
    # vmms running) and the worker processes, read-only, in the installer's shell; the vmms state is identical before
    # and after, and every status is one that never claims an absence. Nothing is created, started or changed.
    $probe = @'
param([string]$Lib)
$ErrorActionPreference = 'Stop'
. (Join-Path $Lib 'Engine.Audit.ps1')
. (Join-Path $Lib 'Engine.Diagnose.ps1')
$snap = { (@(Get-CimInstance -ClassName Win32_Service -Filter "Name='vmms'" -Property Name, State, StartMode | ForEach-Object { '{0}/{1}' -f $_.State, $_.StartMode })) -join ',' }
$before = & $snap
$pz = New-AtmPseudonymizer
$q = Invoke-AtmVirtualizationQuery
$r = Get-AtmVirtualizationFindings -Query $q -Collection (Get-AtmProcessCollection) -Pseudonymizer $pz
$after = & $snap
$plat = @($r.Findings | Where-Object { $_.Kind -eq 'VirtualizationPlatform' })[0]
$ok = (@('COMPLETE', 'PARTIAL', 'DENIED', 'FAILED') -ccontains $q.PlatformCoverage.Status) -and (@('COMPLETE', 'PARTIAL', 'DENIED', 'FAILED', 'NOT_OBSERVABLE', 'TIMEOUT') -ccontains $q.VmCoverage.Status) -and (@('PRESENT', 'UNKNOWN') -ccontains $plat.State) -and ($q.VmCoverage.Status -cne 'COMPLETE' -or ($q.Namespace -ceq 'LISTED' -and $q.Vmms -ceq 'RUNNING')) -and (@($r.Findings | Where-Object { $_.State -eq 'NOT_PRESENT' }).Count -eq 0)
'{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}' -f [int]$ok, [int]($before -ceq $after), $q.PlatformCoverage.Status, $q.Namespace, $q.Vmms, $q.Hypervisor, $q.VmCoverage.Status, @($r.Findings | Where-Object { $_.Kind -eq 'VirtualMachine' }).Count
'@
    $probeFile = Join-Path $OutDir 'virtualization-probe.ps1'
    [IO.File]::WriteAllText($probeFile, $probe)
    $line = (& $installerExe -NoProfile -ExecutionPolicy Bypass -File $probeFile -Lib (Join-Path $installDir 'lib') 2>&1 | Select-Object -Last 1) -as [string]
    $p = $line.Split('|')
    Assert ($p.Count -eq 8 -and $p[0] -eq '1' -and $p[1] -eq '1') "virtualization: $line"
    "$($summary.arch) ($InstallerShell): platform $($p[2]), namespace $($p[3]), vmms $($p[4]), hypervisor flag $($p[5]), VMs $($p[6]) ($($p[7]) observed), vmms state unchanged, no absence claimed"
}

Step 'provider-claude-desktop' {
    # P2-C: the installed copy holds, lists and loads the Claude Desktop provider (runtime only). (The service state on
    # a real machine is checked by the suite's CI-runner case.)
    Assert (Test-Path -LiteralPath (Join-Path $installDir 'providers\ClaudeDesktop.ps1') -PathType Leaf) 'provider Claude Desktop nao instalado'
    $r = Invoke-Agent 'version -Lang en-US' 'version-providers'
    Assert ($r.Code -eq 0 -and $r.Text -match 'providers: Claude Code, Claude Desktop') "version: $($r.Text)"
    'installed providers: Claude Code, Claude Desktop'
}

Step 'shipped-release-gate' {
    $clean = [IO.File]::ReadAllText((Join-Path $installDir 'lib\Engine.Clean.ps1'))
    Assert ([regex]::Matches($clean, '\$script:AtmRealDeletionEnabled\s*=').Count -eq 1) 'mais de uma atribuicao da trava'
    Assert ($clean -match '\$script:AtmRealDeletionEnabled = \$false') 'trava instalada nao e $false'
    'installed gate = $false (single assignment)'
}
Step 'shipped-worktree-diagnostics-gate' {
    # P3-B0: reading repositories and running Git in them stay closed in every shipped copy.
    $diag = [IO.File]::ReadAllText((Join-Path $installDir 'lib\Engine.Diagnose.ps1'))
    Assert ([regex]::Matches($diag, '\$script:AtmWorktreeDiagnosticsEnabled\s*=').Count -eq 1) 'mais de uma atribuicao da trava de worktrees'
    Assert ($diag -match '\$script:AtmWorktreeDiagnosticsEnabled = \$false') 'trava de worktrees instalada nao e $false'
    'installed worktree diagnostics gate = $false (single assignment)'
}
Step 'shipped-handle-diagnostics-gate' {
    # P1-C-S: open-file evidence (Restart Manager) stays closed in every shipped copy; the installed diagnose reports it
    # as not observed (the gate is checked before any file is listed or any Restart Manager call).
    $diag = [IO.File]::ReadAllText((Join-Path $installDir 'lib\Engine.Diagnose.ps1'))
    Assert ([regex]::Matches($diag, '\$script:AtmHandleDiagnosticsEnabled\s*=').Count -eq 1) 'mais de uma atribuicao da trava de arquivos abertos'
    Assert ($diag -match '\$script:AtmHandleDiagnosticsEnabled = \$false') 'trava de arquivos abertos instalada nao e $false'
    $r = Invoke-Agent 'diagnose -NoProgress -Lang en-US -DeadlineSeconds 120' 'diagnose-handle-gate'
    Assert ($r.Code -eq 0) "diagnose exit $($r.Code)"
    Assert ($r.Text -match 'handles\W+NOT_OBSERVABLE\W+HANDLE_SECURITY_GATE_CLOSED') 'diagnose instalado sem handles NOT_OBSERVABLE / HANDLE_SECURITY_GATE_CLOSED'
    Assert ($r.Text.Contains('Open files are not observed') -and -not $r.Text.Contains('Items with a file held open')) 'relatorio instalado sem a linha da trava ou com contagem de itens'
    # P4-B/P5-A: the installed diagnose reports the graph and discovery coverage and the partition section; worktrees as not observed.
    Assert ($r.Text -match 'dependency-graph\W+(COMPLETE|PARTIAL)' -and $r.Text -match 'profile-discovery\W+(COMPLETE|PARTIAL|FAILED|NOT_OBSERVABLE)' -and $r.Text -match 'worktree-discovery\W+NOT_OBSERVABLE\W+WORKTREE_DIAGNOSTICS_GATE_CLOSED' -and $r.Text.Contains('TEMPORARY PARTITIONS AND WORKTREES')) 'diagnose instalado sem coberturas do grafo/descoberta ou sem a secao de particoes'
    'installed handle diagnostics gate = $false (single assignment); installed diagnose: handles NOT_OBSERVABLE (HANDLE_SECURITY_GATE_CLOSED)'
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

Step 'diagnose-export-and-tui-area' {
    # P5-B: the installed TUI has the diagnostics area (menu D); the installed diagnose writes a requested export to a new
    # file outside the audited directories (valid JSON, schema atm.diagnose/2, no profile path) and refuses an existing one.
    $tui = [IO.File]::ReadAllText((Join-Path $installDir 'lib\Tui.ps1'))
    Assert ($tui.Contains("Key = 'D'") -and $tui.Contains('Invoke-AtmTuiDiagnose')) 'TUI instalada sem a area de diagnostico (D)'
    $dir = Join-Path ([IO.Path]::GetTempPath()) ('atm-e2e-export-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    [void][IO.Directory]::CreateDirectory($dir)
    $target = Join-Path (Get-Item -LiteralPath $dir).FullName 'diagnose.json'
    $r = Invoke-Agent ('diagnose -NoProgress -Lang en-US -DeadlineSeconds 300 -ExportJson "' + $target + '"') 'diagnose-export'
    Assert ($r.Code -eq 0) "diagnose com exportacao: exit $($r.Code)"
    $text = [IO.File]::ReadAllText($target)
    $j = $text | ConvertFrom-Json
    Assert ($j.schemaVersion -eq 'atm.diagnose/2' -and $null -ne $j.graph -and @($j.coverage | Where-Object { $_.collector -eq 'dependency-graph' }).Count -eq 1) 'exportacao instalada invalida ou sem grafo'
    Assert (-not ($text -match '[A-Za-z]:\\Users\\')) 'exportacao instalada contem caminho de perfil'
    $len = (Get-Item -LiteralPath $target).Length
    $r2 = Invoke-Agent ('diagnose -NoProgress -Lang en-US -DeadlineSeconds 300 -ExportJson "' + $target + '"') 'diagnose-export-refused'
    Assert ($r2.Code -eq 10 -and $r2.Text.Contains('ExportJson refused') -and (Get-Item -LiteralPath $target).Length -eq $len) 'exportacao sobre arquivo existente nao foi recusada ou alterou o arquivo'
    "installed TUI has menu D; installed export written ($len bytes, schema atm.diagnose/2) and an existing file refused (exit 10, unchanged)"
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
