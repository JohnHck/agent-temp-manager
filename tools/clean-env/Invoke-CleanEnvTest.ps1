<#
.SYNOPSIS
  Runs INSIDE a disposable clean Windows environment (Windows Sandbox or a fresh VM) as an administrator.
  Validates a release end to end on a machine without any developer configuration:
    1. SHA-256 of the release zip against SHA256SUMS.txt
    2. automated test suite (Windows PowerShell 5.1)
    3. installation WITHOUT -ProjectsFile
    4. agent-temp verify / version / audit / preview (read-only) from a new process (machine PATH)
    5. uninstall and removal check
  Writes results to -OutDir (summary.json + raw outputs). Never deletes agent temporary files.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ReleaseDir, [Parameter(Mandatory)][string]$OutDir)
$ErrorActionPreference = 'Stop'
$ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
[void][IO.Directory]::CreateDirectory($OutDir)
$summary = [ordered]@{ startedUtc = [datetime]::UtcNow.ToString('o'); windows = (Get-CimInstance Win32_OperatingSystem).Caption; steps = [ordered]@{} }
function Step([string]$Name, [scriptblock]$Body) {
    try { $r = & $Body; $summary.steps[$Name] = [ordered]@{ ok = $true; detail = "$r" } }
    catch { $summary.steps[$Name] = [ordered]@{ ok = $false; detail = $_.Exception.Message } }
}
$zip = @(Get-ChildItem -LiteralPath $ReleaseDir -Filter 'agent-temp-manager-*.zip')[0]
$work = Join-Path $env:ProgramFiles ('AgentTempManager-release-test')
Step 'sha256' {
    $expected = ((Get-Content -LiteralPath (Join-Path $ReleaseDir 'SHA256SUMS.txt') -Raw).Split(' ')[0]).ToUpperInvariant()
    $h = (Get-FileHash -LiteralPath $zip.FullName -Algorithm SHA256).Hash
    if ($h -ne $expected) { throw "hash $h != $expected" }
    $h
}
Step 'extract' { Expand-Archive -LiteralPath $zip.FullName -DestinationPath $work -Force; $work }
$pkg = @(Get-ChildItem -LiteralPath $work -Directory)[0].FullName
Step 'tests' {
    & $ps51 -NoProfile -ExecutionPolicy Bypass -File (Join-Path $pkg 'tests\Run-Tests.ps1') -SkipHeavy -ReportFile (Join-Path $OutDir 'tests-ps51.json') *> (Join-Path $OutDir 'tests-ps51.txt')
    if ($LASTEXITCODE -ne 0) { throw "falhas: $LASTEXITCODE" }
    'ok'
}
Step 'install-without-projectsfile' {
    & $ps51 -NoProfile -ExecutionPolicy Bypass -File (Join-Path $pkg 'install\Install-AgentTempManager.ps1') *> (Join-Path $OutDir 'install.txt')
    if ($LASTEXITCODE -ne 0) { throw "exit $LASTEXITCODE" }
    if (Test-Path (Join-Path $env:ProgramFiles 'AgentTempManager\config\projects.local.json')) { throw 'configuracao pessoal inesperada' }
    'ok'
}
foreach ($cmd in @('verify', 'version', 'audit -NoProgress', 'preview -NoProgress', 'version -Lang en-US')) {
    $name = 'agent-temp ' + $cmd
    Step $name {
        # New process with the refreshed MACHINE Path, exactly like a new terminal.
        $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
        $out = & cmd.exe /c "set `"PATH=$machinePath`" && agent-temp $cmd" 2>&1
        [IO.File]::WriteAllText((Join-Path $OutDir (($cmd -replace '[^a-zA-Z-]', '_') + '.txt')), ($out -join "`r`n"))
        if ($LASTEXITCODE -ne 0) { throw "exit $LASTEXITCODE" }
        'ok'
    }
}
Step 'uninstall' {
    & $ps51 -NoProfile -ExecutionPolicy Bypass -File (Join-Path $pkg 'install\Uninstall-AgentTempManager.ps1') *> (Join-Path $OutDir 'uninstall.txt')
    if ($LASTEXITCODE -ne 0) { throw "exit $LASTEXITCODE" }
    if (Test-Path (Join-Path $env:ProgramFiles 'AgentTempManager')) { throw 'diretorio ainda existe' }
    if (([Environment]::GetEnvironmentVariable('Path', 'Machine')) -match 'AgentTempManager') { throw 'PATH ainda contem o produto' }
    'ok'
}
$summary.finishedUtc = [datetime]::UtcNow.ToString('o')
$summary.allPassed = -not @($summary.steps.Values | Where-Object { -not $_.ok }).Count
[IO.File]::WriteAllText((Join-Path $OutDir 'summary.json'), ($summary | ConvertTo-Json -Depth 5))
