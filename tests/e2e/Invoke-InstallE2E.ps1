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
    directory; uninstall (directory and PATH entry removed); then the published 0.1.0 package (GitHub Release asset,
    SHA-256 pinned) installed, updated to this package, rolled back to 0.1.0, updated again and uninstalled; then the
    same for the published 0.1.1 package (SHA-256 pinned), with the four gates checked in the installation after
    each update to this package; then the same for the published 0.2.0 package (the latest published version;
    SHA-256 pinned), which also checks the installed manifest version. Before the uninstall, V0.3 V2: the REAL clean of
    roots planted by tests\e2e\Invoke-CleanE2E.ps1 (CI-only, never shipped), as the standard user (leg A) and elevated
    (leg B); only the harness summaries are kept.
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

function Invoke-PublishedFreshInstall([string]$Version, [string]$PkgDir) {
    # INSTALL-RACE (auditor's decision, option b). The published installers (0.1.0, 0.1.1, 0.2.0; pinned by hash) compile
    # the PATH broadcast in their own process; under Windows PowerShell 5.1 a compiler temp folder can disappear while
    # their cleanup walks the private TEMP. ONE new attempt, only of the fresh install of a published version, only when
    # the failure is "Could not find a part of the path" under <InstallDir>.staging-, and only after the uninstaller
    # under test has left the machine clean. Any other failure, or a second one, stays FAIL. Never the installer under
    # test. Returns '' or the note of the new attempt (with the first attempt's text) for the summary.
    Assert ([bool]$PkgDir -and $PkgDir -ne $pkg) 'nova tentativa so para o instalador de uma versao publicada'
    # First attempt: waited for until the installer process has exited, stdout and stderr kept in files. As in the
    # other steps (a native stderr line throws under this driver), any stderr output is a failure, even with exit 0.
    $installer = Join-Path $PkgDir 'install\Install-AgentTempManager.ps1'
    $errFile = Join-Path $OutDir "xversion-install-$Version-stderr.txt"
    $p = Start-Process -FilePath $installerExe -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "' + $installer + '"') -Wait -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $OutDir "xversion-install-$Version.txt") -RedirectStandardError $errFile
    $code = $p.ExitCode
    $errText = $(if (Test-Path -LiteralPath $errFile) { [IO.File]::ReadAllText($errFile) } else { '' })
    if ($code -eq 0 -and -not $errText.Trim()) { return '' }
    # Lines joined back (a long stderr line may have been wrapped) before matching the one tolerated failure.
    $m = [regex]::Match(($errText -replace '\r?\n', ''), "Could not find a part of the path '" + [regex]::Escape("$installDir.staging-") + "[0-9a-f]{8}\\[^']*'", 'IgnoreCase')
    Assert ($m.Success -and $code -ne 0) "$Version installer exit $code; stderr: $((($errText -split '\r?\n') | Where-Object { $_.Trim() } | Select-Object -First 1))"
    if (Test-Path -LiteralPath (Join-Path $installDir 'install-state.json')) {
        & $installerExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $pkg 'install\Uninstall-AgentTempManager.ps1') *> (Join-Path $OutDir "xversion-install-$Version-cleanup.txt")
        Assert ($LASTEXITCODE -eq 0) "$Version installer exit $code ($($m.Value)); cleanup before the new attempt: uninstall exit $LASTEXITCODE"
    }
    $left = @(Get-ChildItem -LiteralPath (Split-Path -Parent $installDir) -Directory -Filter ((Split-Path -Leaf $installDir) + '.staging-*'))
    Assert (-not (Test-Path -LiteralPath $installDir) -and -not (Test-Path -LiteralPath "$installDir.previous") -and $left.Count -eq 0 -and
        -not (([Environment]::GetEnvironmentVariable('Path', 'Machine')) -match 'AgentTempManager')) "$Version installer exit $code ($($m.Value)); machine not clean for a new attempt"
    & $installerExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PkgDir 'install\Install-AgentTempManager.ps1') *> (Join-Path $OutDir "xversion-install-$Version-retry.txt")
    Assert ($LASTEXITCODE -eq 0) "$Version installer exit $code ($($m.Value)), and exit $LASTEXITCODE on the one new attempt"
    return " (after ONE new attempt: first attempt exit $code, $($m.Value); machine cleaned by the uninstaller under test)"
}

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
Step 'package-excludes-ci-harness' {
    # V0.3 V2 (D1): the CI-only harness of the real clean is never in the release package.
    $found = @(Get-ChildItem -LiteralPath $pkg -Recurse -File -Filter 'Invoke-CleanE2E.ps1')
    Assert ($found.Count -eq 0) 'pacote contem o harness da CI (Invoke-CleanE2E.ps1)'
    'tests\e2e\Invoke-CleanE2E.ps1 absent from the package'
}

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
    # Process.Start (FINAL-B-S): the object holds the creation handle, so Kill() below can only reach this helper.
    $psi = New-Object Diagnostics.ProcessStartInfo($exe, ('-NoProfile -Command "$h = [IO.File]::Open(''{0}'', ''Open'', ''Read'', ''ReadWrite''); Start-Sleep 180"' -f $f))
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $c = [Diagnostics.Process]::Start($psi)
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
    # P5-B/P5-B-S: the installed TUI has the diagnostics area (menu D); the diagnose export gate is closed in the
    # installed copy (single assignment, $false), and an installed export is refused (EXPORT_SECURITY_GATE_CLOSED, exit
    # 10) before anything is collected or checked: no file is created. The export itself is tested on fixtures only.
    $tui = [IO.File]::ReadAllText((Join-Path $installDir 'lib\Tui.ps1'))
    Assert ($tui.Contains("Key = 'D'") -and $tui.Contains('Invoke-AtmTuiDiagnose')) 'TUI instalada sem a area de diagnostico (D)'
    $rep = [IO.File]::ReadAllText((Join-Path $installDir 'lib\Report.ps1'))
    $cliText = [IO.File]::ReadAllText((Join-Path $installDir 'agent-temp.ps1'))
    Assert ([regex]::Matches($rep, '\$script:AtmDiagnoseExportEnabled\s*=').Count -eq 1 -and $rep -match '(?m)^\$script:AtmDiagnoseExportEnabled = \$false\r?$' -and [regex]::Matches($rep, 'AtmDiagnoseExportEnabled').Count -eq 3 -and [regex]::Matches($cliText, 'AtmDiagnoseExportEnabled').Count -eq 1) 'trava da exportacao instalada nao e uma unica atribuicao $false'
    # A destination under a folder that does not exist: nothing is created on the runner, and a destination check would
    # have answered with another code.
    $dir = Join-Path ([IO.Path]::GetTempPath()) ('atm-e2e-export-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    $target = Join-Path $dir 'diagnose.json'
    $r = Invoke-Agent ('diagnose -NoProgress -Lang en-US -ExportJson "' + $target + '"') 'diagnose-export-gate'
    Assert ($r.Code -eq 10 -and $r.Text.Contains('EXPORT_SECURITY_GATE_CLOSED') -and -not $r.Text.Contains('COVERAGE BY COLLECTOR')) "exportacao instalada nao recusada pela trava: exit $($r.Code)"
    Assert (-not (Test-Path -LiteralPath $target) -and -not (Test-Path -LiteralPath $dir) -and -not $r.Text.Contains('EXPORT_DESTINATION')) 'arquivo ou pasta criados, ou destino verificado, com a trava fechada'
    "installed TUI has menu D; installed export gate = `$false (single assignment); installed export refused (EXPORT_SECURITY_GATE_CLOSED, exit 10, no file, nothing collected)"
}
Step 'installed-tamper-variants' {
    # FINAL-B: on this run's own installation. A listed provider missing, an unlisted provider planted and an altered
    # manifest hash are each refused (exit 5) by verify and by a normal command; every change is undone afterwards.
    $prov = Join-Path $installDir 'providers\ClaudeCode.ps1'
    $aside = Join-Path $OutDir 'ClaudeCode.ps1.aside'
    [IO.File]::Move($prov, $aside)
    try {
        $r = Invoke-Agent 'verify' 'verify-provider-missing'; Assert ($r.Code -eq 5) "provider ausente: verify exit $($r.Code)"
        $r = Invoke-Agent 'version' 'version-provider-missing'; Assert ($r.Code -eq 5) "provider ausente: version exit $($r.Code)"
    } finally { [IO.File]::Move($aside, $prov) }
    $extra = Join-Path $installDir 'providers\Extra.ps1'
    [IO.File]::WriteAllText($extra, '# planted by e2e')
    try {
        $r = Invoke-Agent 'verify' 'verify-provider-planted'; Assert ($r.Code -eq 5 -and $r.Text -match 'Extra\.ps1') "provider plantado: verify exit $($r.Code)"
        $r = Invoke-Agent 'version' 'version-provider-planted'; Assert ($r.Code -eq 5) "provider plantado: version exit $($r.Code)"
    } finally { [IO.File]::Move($extra, (Join-Path $OutDir 'Extra.ps1.aside')) }
    $mf = Join-Path $installDir 'manifest.json'
    $orig = [IO.File]::ReadAllBytes($mf)
    try {
        $m = [IO.File]::ReadAllText($mf) | ConvertFrom-Json
        $m.files[0].sha256 = ('0' * 64)
        [IO.File]::WriteAllText($mf, ($m | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($false)))
        $r = Invoke-Agent 'verify' 'verify-manifest-altered'; Assert ($r.Code -eq 5) "manifesto alterado: verify exit $($r.Code)"
        $r = Invoke-Agent 'help' 'help-manifest-altered'; Assert ($r.Code -eq 5) "manifesto alterado: help exit $($r.Code)"
    } finally { [IO.File]::WriteAllBytes($mf, $orig) }
    $r = Invoke-Agent 'verify' 'verify-after-variants'; Assert ($r.Code -eq 0) "restaurado: verify exit $($r.Code)"
    'provider missing, provider planted and manifest altered: each refused (exit 5); restored: verify 0'
}
Step 'installed-encoding' {
    # FINAL-B: every installed script with non-ASCII text keeps its UTF-8 BOM (Windows PowerShell 5.1 would read it in
    # the ANSI code page otherwise); the manifest check already proves the bytes equal the package's.
    $bad = @(Get-ChildItem -LiteralPath $installDir -Recurse -File -Filter '*.ps1' | Where-Object {
        $b = [IO.File]::ReadAllBytes($_.FullName)
        (@($b | Where-Object { $_ -gt 127 }).Count -gt 0) -and -not ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF)
    } | ForEach-Object { $_.Name })
    Assert ($bad.Count -eq 0) "scripts nao ASCII sem BOM: $($bad -join ', ')"
    'non-ASCII installed scripts all carry a UTF-8 BOM'
}
Step 'installed-audit-export' {
    # FINAL-B: the installed audit export (V0.1, enabled) goes through the pinned writer: a new file with a protected
    # DACL; an existing file is refused and left unchanged; a folder reached through a junction is refused. Written
    # outside the uploaded evidence folder (the document names this machine's accounts).
    $dir = Join-Path ([IO.Path]::GetTempPath()) ('atm-e2e-audit-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    [void][IO.Directory]::CreateDirectory($dir)
    $target = Join-Path $dir 'audit.json'
    $r = Invoke-Agent ('audit -NoProgress -Lang en-US -ExportJson "' + $target + '"') 'audit-export'
    Assert ($r.Code -eq 0 -and (Test-Path -LiteralPath $target)) "exportacao da auditoria: exit $($r.Code)"
    $null = [IO.File]::ReadAllText($target) | ConvertFrom-Json
    Assert ((Get-Acl -LiteralPath $target).AreAccessRulesProtected) 'arquivo exportado sem DACL protegida'
    $h = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
    $r = Invoke-Agent ('audit -NoProgress -Lang en-US -ExportJson "' + $target + '"') 'audit-export-existing'
    Assert ($r.Code -eq 10 -and (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -eq $h) "arquivo existente: exit $($r.Code), deve recusar sem alterar"
    $real = Join-Path $dir 'real'; [void][IO.Directory]::CreateDirectory($real)
    $link = Join-Path $dir 'link'
    $o = & (Join-Path $env:SystemRoot 'System32\cmd.exe') /c "mklink /J `"$link`" `"$real`"" 2>&1; Assert ($LASTEXITCODE -eq 0) "juncao de teste: $o"
    $r = Invoke-Agent ('audit -NoProgress -Lang en-US -ExportJson "' + (Join-Path $link 'x.json') + '"') 'audit-export-junction'
    Assert ($r.Code -eq 10 -and -not (Test-Path -LiteralPath (Join-Path $real 'x.json'))) "pasta por juncao: exit $($r.Code), nada no alvo"
    'installed audit export: created with a protected DACL; existing file refused unchanged (10); junction folder refused (10), nothing in the target'
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

# V0.3 V2: the REAL clean of roots planted by tests\e2e\Invoke-CleanE2E.ps1 itself, against this installation, in the
# installer's shell. The harness opens the deletion gate only in its own process memory; the installed copy stays
# closed (checked by the harness before and after, and by the shipped-gate steps). Only its summary is kept here (D5:
# codes, counts and labels; the raw clean logs stay in the harness's run root and are never uploaded).
function Read-V2Summary([string]$File, [int]$Exit, [string]$Console) {
    if (-not (Test-Path -LiteralPath $File)) {
        # No summary: the last lines of the harness output (SIDs and the test account replaced) explain the failure.
        $tail = $(if (Test-Path -LiteralPath $Console) { (@(Get-Content -LiteralPath $Console -Tail 15) -join ' / ') } else { '' })
        $tail = [regex]::Replace([regex]::Replace($tail, 'S-1-5-21-[0-9-]+', '<sid>'), [regex]::Escape($userName), '<account>', 'IgnoreCase')
        throw "harness sem resumo (exit $Exit): $tail"
    }
    [IO.File]::Copy($File, (Join-Path $OutDir (Split-Path -Leaf $File)), $true)
    $s = [IO.File]::ReadAllText($File) | ConvertFrom-Json
    $bad = @($s.cases.PSObject.Properties | Where-Object { $_.Value.status -eq 'FAIL' } | ForEach-Object { "$($_.Name): $($_.Value.detail)" })
    $nt = @($s.cases.PSObject.Properties | Where-Object { $_.Value.status -eq 'NOT_TESTED' } | ForEach-Object { $_.Name })
    Assert ($bad.Count -eq 0 -and $Exit -eq 0) ("V2 FAIL (exit $Exit): " + ($bad -join ' | '))
    # V0.3 V3: its cases (V3-*, every phase so far) are counted apart, in the same summary.
    $v3 = $(if ($s.PSObject.Properties['v3']) { "; V3 ($($s.v3.phase)) $($s.v3.passed) PASS / $($s.v3.failed) FAIL / $($s.v3.notTested) NOT_TESTED" } else { '' })
    "$($s.passed) PASS / 0 FAIL / $($s.notTested) NOT_TESTED [$($nt -join ', ')]; $($s.shell); coverage complete=$($s.processCoverage.complete)$v3"
}
# V0.3 V3b (P2, P3): a watcher of THIS account (the runner's, so a process leg A's standard user cannot inspect) starts a
# short process of its own that ends by itself when leg A asks through a file in a signal folder, and confirms it. The
# watcher's script stays in this account's temp folder (the test user cannot change it); it reads only the names of
# the request files and starts one fixed command. It ends by itself (stop file or deadline); nothing is terminated.
$v3Signal = Join-Path $userDir 'v3-signal'
$v3Watcher = $null
try {
    [void][IO.Directory]::CreateDirectory($v3Signal)
    $v3WatchDir = Join-Path ([IO.Path]::GetTempPath()) ('atm-e2e-v3-watch-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    [void][IO.Directory]::CreateDirectory($v3WatchDir)
    $v3WatchScript = Join-Path $v3WatchDir 'v3-signal-watcher.ps1'
    [IO.File]::WriteAllText($v3WatchScript, @'
param([string]$Dir, [string]$Exe)
$deadline = [datetime]::UtcNow.AddMinutes(45)
while ([datetime]::UtcNow -lt $deadline -and -not (Test-Path -LiteralPath (Join-Path $Dir 'stop.txt'))) {
    foreach ($g in @(Get-ChildItem -LiteralPath $Dir -Filter 'go-*.txt' -File)) {
        $tag = $g.BaseName.Substring(3)
        if ($tag -notmatch '^[A-Za-z0-9-]{1,32}$') { continue }
        $ack = Join-Path $Dir "ack-$tag.txt"
        if (Test-Path -LiteralPath $ack) { continue }
        try {
            $psi = New-Object Diagnostics.ProcessStartInfo($Exe, '-NoProfile -NonInteractive -Command Start-Sleep -Seconds 40')
            $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
            $null = [Diagnostics.Process]::Start($psi)
            [IO.File]::WriteAllText($ack, 'STARTED')
        } catch { [IO.File]::WriteAllText($ack, 'FAILED_' + $_.Exception.GetType().Name) }
    }
    Start-Sleep -Milliseconds 200
}
'@)
    $wpsi = New-Object Diagnostics.ProcessStartInfo($installerExe, "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$v3WatchScript`" -Dir `"$v3Signal`" -Exe `"$installerExe`"")
    $wpsi.UseShellExecute = $false; $wpsi.CreateNoWindow = $true
    $v3Watcher = [Diagnostics.Process]::Start($wpsi)
} catch { $v3Watcher = $null }
Step 'v2-clean-leg-A-standard-user' {
    # Leg A: the standard user of this VM (not elevated): B1 restricted exception. The harness is copied to a folder that
    # user can read; the guard is passed explicitly (a process started with other credentials gets that user's
    # environment, not the runner's variables).
    if (-not $cred) { throw 'usuario de teste indisponivel' }
    $copy = Join-Path $userDir 'Invoke-CleanE2E.ps1'
    [IO.File]::Copy((Join-Path $PSScriptRoot 'Invoke-CleanE2E.ps1'), $copy, $true)
    $sum = Join-Path $userDir 'v2-clean-A-summary.json'
    $con = Join-Path $userDir 'v2-clean-A-console.txt'
    $sig = $(if ($null -ne $v3Watcher) { " -SignalDir `"$v3Signal`"" } else { '' })
    $cmdLine = "/c `"`"$installerExe`" -NoProfile -ExecutionPolicy Bypass -File `"$copy`" -Leg A -InstallDir `"$installDir`" -SummaryFile `"$sum`" -WorkDir `"$(Join-Path $userDir 'v2-A')`" -DisposableMachine$sig > `"$con`" 2>&1`""
    try {
        $p = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\cmd.exe') -ArgumentList $cmdLine -Credential $cred -LoadUserProfile -WorkingDirectory $userDir -WindowStyle Hidden -PassThru -Wait
    } catch { $script:notTested = $true; return "processo como usuario comum nao iniciou neste runner: $($_.Exception.Message)" }
    Read-V2Summary $sum $p.ExitCode $con
}
# The watcher ends by itself on this file (never terminated).
if ($null -ne $v3Watcher) { try { [IO.File]::WriteAllText((Join-Path $v3Signal 'stop.txt'), '1') } catch { $null = $_ } }
Step 'v2-clean-leg-B-elevated' {
    # Leg B: the elevated runner account: ELIGIBLE only if the process coverage measured by the harness is complete.
    $work = Join-Path ([IO.Path]::GetTempPath()) ('atm-e2e-v2-B-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    [void][IO.Directory]::CreateDirectory($work)
    $sum = Join-Path $work 'v2-clean-B-summary.json'
    $con = Join-Path $work 'v2-clean-B-console.txt'
    & $installerExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'Invoke-CleanE2E.ps1') -Leg B -InstallDir $installDir -SummaryFile $sum -WorkDir (Join-Path $work 'v2-B') -DisposableMachine *> $con
    Read-V2Summary $sum $LASTEXITCODE $con
}
# V0.3 V3c X2 (CI evidence; it does not replace the V4 row of the operator, J5): the REAL clean lock held by one identity
# and tried by the other, in both orders: the standard user (not elevated) and this elevated account. Taking this lock
# without waiting is the first step of every clean past the gate, so BUSY here is what the other clean gets
# (CLEAN_LOCK_BUSY), and never DENIED (the object carries an explicit Medium label). Each holder releases on a release
# file and ends by itself; nothing is terminated. The user's copy of the helper is in the test user's folder (run only by
# that user); this account's copy is in its own temp folder.
Step 'v3-x2-lock-across-identities' {
    if (-not $cred) { throw 'usuario de teste indisponivel' }
    $helper = @'
param([string]$Dll, [string]$Mode, [string]$Out, [string]$Ready, [string]$Release)
Add-Type -Path $Dll
$l = [AgentTempManager.AtmCleanLock]::TryAcquire('Global\AgentTempManager.Clean')
[IO.File]::WriteAllText($Out, [string]$l.Status)
if ($l.Acquired) {
    if ($Mode -eq 'hold') { [IO.File]::WriteAllText($Ready, '1'); $n = 0; while (-not (Test-Path -LiteralPath $Release) -and $n -lt 1200) { Start-Sleep -Milliseconds 100; $n++ } }
    $rc = $l.Release(); if ($null -ne $rc) { [IO.File]::AppendAllText($Out, '|RELEASE_' + $rc) }
}
'@
    $dll = Join-Path $installDir 'lib\AgentTempManager.Native.dll'
    $u = Join-Path $userDir 'v3-x2'; [void][IO.Directory]::CreateDirectory($u)
    $a = Join-Path ([IO.Path]::GetTempPath()) ('atm-e2e-v3-x2-' + [guid]::NewGuid().ToString('N').Substring(0, 8)); [void][IO.Directory]::CreateDirectory($a)
    $uh = Join-Path $u 'lock-helper.ps1'; [IO.File]::WriteAllText($uh, $helper)
    $ah = Join-Path $a 'lock-helper.ps1'; [IO.File]::WriteAllText($ah, $helper)
    $argsFor = { param($h, $mode, $dir) "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$h`" -Dll `"$dll`" -Mode $mode -Out `"$dir\$mode.txt`" -Ready `"$dir\ready.txt`" -Release `"$dir\release.txt`"" }
    $read = { param($f) if (Test-Path -LiteralPath $f) { [IO.File]::ReadAllText($f) } else { 'NO_OUTPUT' } }
    $waitReady = { param($dir) $n = 0; while (-not (Test-Path -LiteralPath "$dir\ready.txt") -and $n -lt 600) { Start-Sleep -Milliseconds 100; $n++ }; Test-Path -LiteralPath "$dir\ready.txt" }
    # Order 1: the standard user holds, this elevated account tries.
    $hold = Start-Process -FilePath $installerExe -ArgumentList (& $argsFor $uh 'hold' $u) -Credential $cred -LoadUserProfile -WorkingDirectory $userDir -WindowStyle Hidden -PassThru
    try {
        Assert (& $waitReady $u) "usuario padrao nao tomou o lock: $(& $read "$u\hold.txt")"
        $null = & $installerExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $ah -Dll $dll -Mode probe -Out "$a\probe.txt" -Ready 'none' -Release 'none' 2>&1
        $o1 = & $read "$a\probe.txt"
    } finally { [IO.File]::WriteAllText("$u\release.txt", '1'); $null = $hold.WaitForExit(120000) }
    Assert ((& $read "$u\hold.txt") -ceq 'ACQUIRED' -and $o1 -ceq 'BUSY') "ordem 1: usuario padrao $(& $read "$u\hold.txt"), conta elevada $o1"
    # Order 2: this elevated account holds, the standard user tries.
    $b = Join-Path $a 'order2'; [void][IO.Directory]::CreateDirectory($b)
    $psi = New-Object Diagnostics.ProcessStartInfo($installerExe, (& $argsFor $ah 'hold' $b)); $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $hold2 = [Diagnostics.Process]::Start($psi)
    try {
        Assert (& $waitReady $b) "conta elevada nao tomou o lock: $(& $read "$b\hold.txt")"
        $u2 = Join-Path $u 'order2'; [void][IO.Directory]::CreateDirectory($u2)
        $p = Start-Process -FilePath $installerExe -ArgumentList (& $argsFor $uh 'probe' $u2) -Credential $cred -LoadUserProfile -WorkingDirectory $userDir -WindowStyle Hidden -PassThru -Wait
        $o2 = & $read "$u2\probe.txt"
    } finally { [IO.File]::WriteAllText("$b\release.txt", '1'); $null = $hold2.WaitForExit(120000) }
    Assert ((& $read "$b\hold.txt") -ceq 'ACQUIRED' -and $o2 -ceq 'BUSY') "ordem 2: conta elevada $(& $read "$b\hold.txt"), usuario padrao $o2 (exit $($p.ExitCode))"
    # Released in both orders: free again.
    $null = & $installerExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $ah -Dll $dll -Mode probe -Out "$a\after.txt" -Ready 'none' -Release 'none' 2>&1
    Assert ((& $read "$a\after.txt") -ceq 'ACQUIRED') "lock depois das duas ordens: $(& $read "$a\after.txt")"
    'standard user holds -> elevated account BUSY; elevated account holds -> standard user BUSY (never DENIED); free after both (CI evidence, not the V4 row)'
}

Step 'uninstall' {
    & $installerExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $pkg 'install\Uninstall-AgentTempManager.ps1') *> (Join-Path $OutDir 'uninstall.txt')
    Assert ($LASTEXITCODE -eq 0) "uninstall exit $LASTEXITCODE"
    Assert (-not (Test-Path $installDir)) 'diretorio ainda existe'
    Assert (-not (([Environment]::GetEnvironmentVariable('Path', 'Machine')) -match 'AgentTempManager')) 'PATH ainda contem o produto'
    'removed'
}
# FINAL-C: from the published 0.1.0 to this package and back. The 0.1.0 package is the asset of the GitHub Release
# v0.1.0, accepted only with the SHA-256 published with it (pinned here). Runs after the uninstall above, on the same
# disposable machine; ends uninstalled.
$v010Sha = '985CBD4C31349DFEA119C9D4D4CB1C27CFBDC584FA74412BE6AEE0374FA8D7F1'
$v010Url = 'https://github.com/JohnHck/agent-temp-manager/releases/download/v0.1.0/agent-temp-manager-0.1.0.zip'
$v010Dir = Join-Path $env:ProgramFiles 'AgentTempManager-v010'
$script:v010Pkg = $null
$rcVersion = $(if ($pkg) { [regex]::Match([IO.File]::ReadAllText((Join-Path $pkg 'src\lib\Engine.Audit.ps1')), "\`$script:AtmVersion = '([0-9.]+)'").Groups[1].Value } else { '' })
Step 'xversion-0.1.0-package' {
    [void][IO.Directory]::CreateDirectory($v010Dir)
    $zip010 = Join-Path $v010Dir 'agent-temp-manager-0.1.0.zip'
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $v010Url -OutFile $zip010 -UseBasicParsing
    } catch { $script:notTested = $true; return "0.1.0 package not downloadable on this runner: $($_.Exception.GetType().Name)" }
    $h = (Get-FileHash -LiteralPath $zip010 -Algorithm SHA256).Hash
    Assert ($h -eq $v010Sha) "0.1.0 package hash $h != published $v010Sha"
    Expand-Archive -LiteralPath $zip010 -DestinationPath $v010Dir -Force
    $script:v010Pkg = @(Get-ChildItem -LiteralPath $v010Dir -Directory)[0].FullName
    "published 0.1.0 package, SHA-256 $h"
}
Step 'xversion-install-0.1.0' {
    if (-not $script:v010Pkg) { $script:notTested = $true; return '0.1.0 package unavailable' }
    Assert (-not (Test-Path $installDir)) 'instalacao anterior ainda presente'
    $na = Invoke-PublishedFreshInstall '0.1.0' $script:v010Pkg
    $r = Invoke-Agent 'version -Lang en-US' 'xversion-version-0.1.0'; Assert ($r.Code -eq 0 -and $r.Text -match 'agent-temp 0\.1\.0\b') "0.1.0 version: exit $($r.Code)"
    $r = Invoke-Agent 'verify' 'xversion-verify-0.1.0'; Assert ($r.Code -eq 0) "0.1.0 verify exit $($r.Code)"
    '0.1.0 installed and verified' + $na
}
Step 'xversion-update-from-0.1.0' {
    if (-not $script:v010Pkg) { $script:notTested = $true; return '0.1.0 package unavailable' }
    & $installerExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $pkg 'install\Install-AgentTempManager.ps1') -Update *> (Join-Path $OutDir 'xversion-update.txt')
    Assert ($LASTEXITCODE -eq 0) "update exit $LASTEXITCODE"
    $r = Invoke-Agent 'version -Lang en-US' 'xversion-version-updated'
    Assert ($r.Code -eq 0 -and $r.Text -match ('agent-temp ' + [regex]::Escape($rcVersion) + '\b')) "version after update: exit $($r.Code)"
    $r = Invoke-Agent 'verify' 'xversion-verify-updated'; Assert ($r.Code -eq 0) "verify exit $($r.Code)"
    $r = Invoke-Agent 'diagnose -NoProgress -Lang en-US -DeadlineSeconds 60' 'xversion-diagnose'; Assert ($r.Code -eq 0) "diagnose exit $($r.Code)"
    Assert (Test-Path (Join-Path "$installDir.previous" 'agent-temp.ps1')) '0.1.0 nao mantida em .previous'
    "0.1.0 -> $rcVersion, 0.1.0 kept as previous"
}
Step 'xversion-rollback-to-0.1.0' {
    if (-not $script:v010Pkg) { $script:notTested = $true; return '0.1.0 package unavailable' }
    & $installerExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $pkg 'install\Restore-AgentTempManagerPrevious.ps1') *> (Join-Path $OutDir 'xversion-rollback.txt')
    Assert ($LASTEXITCODE -eq 0) "rollback exit $LASTEXITCODE"
    $r = Invoke-Agent 'version -Lang en-US' 'xversion-version-rolledback'; Assert ($r.Code -eq 0 -and $r.Text -match 'agent-temp 0\.1\.0\b') "version after rollback: exit $($r.Code)"
    $r = Invoke-Agent 'verify' 'xversion-verify-rolledback'; Assert ($r.Code -eq 0) "verify exit $($r.Code)"
    "back to 0.1.0, verified"
}
Step 'xversion-update-again-and-uninstall' {
    if (-not $script:v010Pkg) { $script:notTested = $true; return '0.1.0 package unavailable' }
    & $installerExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $pkg 'install\Install-AgentTempManager.ps1') -Update *> (Join-Path $OutDir 'xversion-update2.txt')
    Assert ($LASTEXITCODE -eq 0) "second update exit $LASTEXITCODE"
    $r = Invoke-Agent 'version -Lang en-US' 'xversion-version-updated2'; Assert ($r.Code -eq 0 -and $r.Text -match ('agent-temp ' + [regex]::Escape($rcVersion) + '\b')) "version: exit $($r.Code)"
    & $installerExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $pkg 'install\Uninstall-AgentTempManager.ps1') *> (Join-Path $OutDir 'xversion-uninstall.txt')
    Assert ($LASTEXITCODE -eq 0) "uninstall exit $LASTEXITCODE"
    Assert (-not (Test-Path $installDir) -and -not (Test-Path "$installDir.previous")) 'diretorios ainda existem'
    Assert (-not (([Environment]::GetEnvironmentVariable('Path', 'Machine')) -match 'AgentTempManager')) 'PATH ainda contem o produto'
    "updated to $rcVersion again, uninstalled"
}
# V0.2 stage 2: from the published 0.1.1 (the current published version) to this package and back, after the 0.1.0
# path above (which ends uninstalled). The 0.1.1 package is the asset of the GitHub Release v0.1.1, accepted only with
# its published SHA-256 (pinned here) and never run before that check; a download that fails is NOT TESTED, never a
# pass. After each update to this package the four gates of the installation are checked. Ends uninstalled.
$v011Sha = 'C681761DBB019987A53CAB1C234BE28CD4BFFFDB3F3EDCAEF0A2EEA55C5885A4'
$v011Url = 'https://github.com/JohnHck/agent-temp-manager/releases/download/v0.1.1/agent-temp-manager-0.1.1.zip'
$v011Dir = Join-Path $env:ProgramFiles 'AgentTempManager-v011'
$script:v011Pkg = $null
$installedGates = {
    $files = @{ AtmRealDeletionEnabled = 'lib\Engine.Clean.ps1'; AtmWorktreeDiagnosticsEnabled = 'lib\Engine.Diagnose.ps1'; AtmHandleDiagnosticsEnabled = 'lib\Engine.Diagnose.ps1'; AtmDiagnoseExportEnabled = 'lib\Report.ps1' }
    foreach ($g in $files.Keys) {
        $t = [IO.File]::ReadAllText((Join-Path $installDir $files[$g]))
        Assert ([regex]::Matches($t, ('\$script:' + $g + '\s*=')).Count -eq 1 -and $t -match ('\$script:' + $g + ' = \$false')) "trava instalada $g nao e uma unica atribuicao a `$false"
    }
    'four installed gates $false'
}
Step 'xversion-0.1.1-package' {
    [void][IO.Directory]::CreateDirectory($v011Dir)
    $zip011 = Join-Path $v011Dir 'agent-temp-manager-0.1.1.zip'
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $v011Url -OutFile $zip011 -UseBasicParsing
    } catch { $script:notTested = $true; return "0.1.1 package not downloadable on this runner: $($_.Exception.GetType().Name)" }
    $h = (Get-FileHash -LiteralPath $zip011 -Algorithm SHA256).Hash
    Assert ($h -eq $v011Sha) "0.1.1 package hash $h != published $v011Sha"
    Expand-Archive -LiteralPath $zip011 -DestinationPath $v011Dir -Force
    $script:v011Pkg = @(Get-ChildItem -LiteralPath $v011Dir -Directory)[0].FullName
    "published 0.1.1 package, SHA-256 $h"
}
Step 'xversion-install-0.1.1' {
    if (-not $script:v011Pkg) { $script:notTested = $true; return '0.1.1 package unavailable' }
    Assert (-not (Test-Path $installDir)) 'instalacao anterior ainda presente'
    $na = Invoke-PublishedFreshInstall '0.1.1' $script:v011Pkg
    $r = Invoke-Agent 'version -Lang en-US' 'xversion-version-0.1.1'; Assert ($r.Code -eq 0 -and $r.Text -match 'agent-temp 0\.1\.1\b') "0.1.1 version: exit $($r.Code)"
    $r = Invoke-Agent 'verify' 'xversion-verify-0.1.1'; Assert ($r.Code -eq 0) "0.1.1 verify exit $($r.Code)"
    '0.1.1 installed and verified' + $na
}
Step 'xversion-update-from-0.1.1' {
    if (-not $script:v011Pkg) { $script:notTested = $true; return '0.1.1 package unavailable' }
    & $installerExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $pkg 'install\Install-AgentTempManager.ps1') -Update *> (Join-Path $OutDir 'xversion-update-from-0.1.1.txt')
    Assert ($LASTEXITCODE -eq 0) "update exit $LASTEXITCODE"
    $r = Invoke-Agent 'version -Lang en-US' 'xversion-version-updated-from-0.1.1'
    Assert ($r.Code -eq 0 -and $r.Text -match ('agent-temp ' + [regex]::Escape($rcVersion) + '\b')) "version after update: exit $($r.Code)"
    $r = Invoke-Agent 'verify' 'xversion-verify-updated-from-0.1.1'; Assert ($r.Code -eq 0) "verify exit $($r.Code)"
    $g = & $installedGates
    Assert (Test-Path (Join-Path "$installDir.previous" 'agent-temp.ps1')) '0.1.1 nao mantida em .previous'
    "0.1.1 -> $rcVersion, 0.1.1 kept as previous, $g"
}
Step 'xversion-rollback-to-0.1.1' {
    if (-not $script:v011Pkg) { $script:notTested = $true; return '0.1.1 package unavailable' }
    & $installerExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $pkg 'install\Restore-AgentTempManagerPrevious.ps1') *> (Join-Path $OutDir 'xversion-rollback-to-0.1.1.txt')
    Assert ($LASTEXITCODE -eq 0) "rollback exit $LASTEXITCODE"
    $r = Invoke-Agent 'version -Lang en-US' 'xversion-version-rolledback-0.1.1'; Assert ($r.Code -eq 0 -and $r.Text -match 'agent-temp 0\.1\.1\b') "version after rollback: exit $($r.Code)"
    $r = Invoke-Agent 'verify' 'xversion-verify-rolledback-0.1.1'; Assert ($r.Code -eq 0) "verify exit $($r.Code)"
    'back to 0.1.1, verified'
}
Step 'xversion-update-again-from-0.1.1-and-uninstall' {
    if (-not $script:v011Pkg) { $script:notTested = $true; return '0.1.1 package unavailable' }
    & $installerExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $pkg 'install\Install-AgentTempManager.ps1') -Update *> (Join-Path $OutDir 'xversion-update2-from-0.1.1.txt')
    Assert ($LASTEXITCODE -eq 0) "second update exit $LASTEXITCODE"
    $r = Invoke-Agent 'version -Lang en-US' 'xversion-version-updated2-from-0.1.1'; Assert ($r.Code -eq 0 -and $r.Text -match ('agent-temp ' + [regex]::Escape($rcVersion) + '\b')) "version: exit $($r.Code)"
    $r = Invoke-Agent 'verify' 'xversion-verify-updated2-from-0.1.1'; Assert ($r.Code -eq 0) "verify exit $($r.Code)"
    $g = & $installedGates
    & $installerExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $pkg 'install\Uninstall-AgentTempManager.ps1') *> (Join-Path $OutDir 'xversion-uninstall-0.1.1.txt')
    Assert ($LASTEXITCODE -eq 0) "uninstall exit $LASTEXITCODE"
    Assert (-not (Test-Path $installDir) -and -not (Test-Path "$installDir.previous")) 'diretorios ainda existem'
    Assert (-not (([Environment]::GetEnvironmentVariable('Path', 'Machine')) -match 'AgentTempManager')) 'PATH ainda contem o produto'
    "updated to $rcVersion again ($g), uninstalled"
}
# V0.3 (publication blocker of the 0.3.0 candidate): from the published 0.2.0 (the latest published version) to this
# package and back, after the 0.1.1 path above (which ends uninstalled); the same cycle. The 0.2.0 package is the asset
# of the GitHub Release v0.2.0, accepted only with the SHA-256 published in that release's SHA256SUMS.txt (pinned here;
# the same value as the digest GitHub reports for the asset) and never run before that check; a download that fails is
# NOT TESTED, never a pass. After each step the installed manifest's version is checked too.
$v020Sha = 'E97348E4A071E91805AEFD8CD7DA6B258490BC6D2E88E6BD17ECD92A2E725727'
$v020Url = 'https://github.com/JohnHck/agent-temp-manager/releases/download/v0.2.0/agent-temp-manager-0.2.0.zip'
$v020Dir = Join-Path $env:ProgramFiles 'AgentTempManager-v020'
$script:v020Pkg = $null
$manifestVersion = { param([string]$Dir) ([IO.File]::ReadAllText((Join-Path $Dir 'manifest.json')) | ConvertFrom-Json).version }
Step 'xversion-0.2.0-package' {
    [void][IO.Directory]::CreateDirectory($v020Dir)
    $zip020 = Join-Path $v020Dir 'agent-temp-manager-0.2.0.zip'
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $v020Url -OutFile $zip020 -UseBasicParsing
    } catch { $script:notTested = $true; return "0.2.0 package not downloadable on this runner: $($_.Exception.GetType().Name)" }
    $h = (Get-FileHash -LiteralPath $zip020 -Algorithm SHA256).Hash
    Assert ($h -eq $v020Sha) "0.2.0 package hash $h != published $v020Sha"
    Expand-Archive -LiteralPath $zip020 -DestinationPath $v020Dir -Force
    $script:v020Pkg = @(Get-ChildItem -LiteralPath $v020Dir -Directory)[0].FullName
    "published 0.2.0 package, SHA-256 $h"
}
Step 'xversion-install-0.2.0' {
    if (-not $script:v020Pkg) { $script:notTested = $true; return '0.2.0 package unavailable' }
    Assert (-not (Test-Path $installDir)) 'instalacao anterior ainda presente'
    $na = Invoke-PublishedFreshInstall '0.2.0' $script:v020Pkg
    $r = Invoke-Agent 'version -Lang en-US' 'xversion-version-0.2.0'; Assert ($r.Code -eq 0 -and $r.Text -match 'agent-temp 0\.2\.0\b') "0.2.0 version: exit $($r.Code)"
    $r = Invoke-Agent 'verify' 'xversion-verify-0.2.0'; Assert ($r.Code -eq 0) "0.2.0 verify exit $($r.Code)"
    $mv = & $manifestVersion $installDir; Assert ($mv -ceq '0.2.0') "manifesto instalado: $mv"
    '0.2.0 installed and verified (manifest 0.2.0)' + $na
}
Step 'xversion-update-from-0.2.0' {
    if (-not $script:v020Pkg) { $script:notTested = $true; return '0.2.0 package unavailable' }
    & $installerExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $pkg 'install\Install-AgentTempManager.ps1') -Update *> (Join-Path $OutDir 'xversion-update-from-0.2.0.txt')
    Assert ($LASTEXITCODE -eq 0) "update exit $LASTEXITCODE"
    $r = Invoke-Agent 'version -Lang en-US' 'xversion-version-updated-from-0.2.0'
    Assert ($r.Code -eq 0 -and $r.Text -match ('agent-temp ' + [regex]::Escape($rcVersion) + '\b')) "version after update: exit $($r.Code)"
    $r = Invoke-Agent 'verify' 'xversion-verify-updated-from-0.2.0'; Assert ($r.Code -eq 0) "verify exit $($r.Code)"
    $mv = & $manifestVersion $installDir; Assert ($mv -ceq $rcVersion) "manifesto instalado depois da atualizacao: $mv"
    $mp = & $manifestVersion "$installDir.previous"; Assert ($mp -ceq '0.2.0') "manifesto da copia anterior: $mp"
    $g = & $installedGates
    "0.2.0 -> $rcVersion (manifest $mv), 0.2.0 kept as previous (manifest $mp), $g"
}
Step 'xversion-rollback-to-0.2.0' {
    if (-not $script:v020Pkg) { $script:notTested = $true; return '0.2.0 package unavailable' }
    & $installerExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $pkg 'install\Restore-AgentTempManagerPrevious.ps1') *> (Join-Path $OutDir 'xversion-rollback-to-0.2.0.txt')
    Assert ($LASTEXITCODE -eq 0) "rollback exit $LASTEXITCODE"
    $r = Invoke-Agent 'version -Lang en-US' 'xversion-version-rolledback-0.2.0'; Assert ($r.Code -eq 0 -and $r.Text -match 'agent-temp 0\.2\.0\b') "version after rollback: exit $($r.Code)"
    $r = Invoke-Agent 'verify' 'xversion-verify-rolledback-0.2.0'; Assert ($r.Code -eq 0) "verify exit $($r.Code)"
    $mv = & $manifestVersion $installDir; Assert ($mv -ceq '0.2.0') "manifesto depois do rollback: $mv"
    'back to 0.2.0, verified (manifest 0.2.0)'
}
Step 'xversion-update-again-from-0.2.0-and-uninstall' {
    if (-not $script:v020Pkg) { $script:notTested = $true; return '0.2.0 package unavailable' }
    & $installerExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $pkg 'install\Install-AgentTempManager.ps1') -Update *> (Join-Path $OutDir 'xversion-update2-from-0.2.0.txt')
    Assert ($LASTEXITCODE -eq 0) "second update exit $LASTEXITCODE"
    $r = Invoke-Agent 'version -Lang en-US' 'xversion-version-updated2-from-0.2.0'; Assert ($r.Code -eq 0 -and $r.Text -match ('agent-temp ' + [regex]::Escape($rcVersion) + '\b')) "version: exit $($r.Code)"
    $r = Invoke-Agent 'verify' 'xversion-verify-updated2-from-0.2.0'; Assert ($r.Code -eq 0) "verify exit $($r.Code)"
    $mv = & $manifestVersion $installDir; Assert ($mv -ceq $rcVersion) "manifesto instalado: $mv"
    $g = & $installedGates
    & $installerExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $pkg 'install\Uninstall-AgentTempManager.ps1') *> (Join-Path $OutDir 'xversion-uninstall-0.2.0.txt')
    Assert ($LASTEXITCODE -eq 0) "uninstall exit $LASTEXITCODE"
    Assert (-not (Test-Path $installDir) -and -not (Test-Path "$installDir.previous")) 'diretorios ainda existem'
    Assert (-not (([Environment]::GetEnvironmentVariable('Path', 'Machine')) -match 'AgentTempManager')) 'PATH ainda contem o produto'
    "updated to $rcVersion again (manifest $mv, $g), uninstalled"
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
