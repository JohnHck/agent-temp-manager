# Shared helpers for install / uninstall / release. Only touch the product's own directories and the
# product's own PATH entry. Never touch agent temporary directories.
Set-StrictMode -Version 2.0
# Message catalog (lib\I18n.ps1) of the product. It is code, so it is dot-sourced only once its SHA-256 matches a
# manifest, checked here with .NET before anything else runs (R-B5): the package's src\manifest.json or, when the
# package has none, the installed copy's (the caller sets $script:AtmCatalogInstallDir). A package without a manifest
# (git checkout) is loaded unverified only when the caller trusts it explicitly ($script:AtmCatalogTrustUnverified:
# -SourceWithoutManifest, the release build). Otherwise the built-in bilingual texts below are used. A catalog
# already loaded in this session (the test suite) is kept.
function Test-AtmCatalogVerified {
    param([string]$Root)
    $mf = Join-Path $Root 'manifest.json'
    $cat = Join-Path $Root 'lib\I18n.ps1'
    if (-not ([IO.File]::Exists($mf) -and [IO.File]::Exists($cat))) { return $false }
    try {
        $e = @(([IO.File]::ReadAllText($mf) | ConvertFrom-Json).files | Where-Object { [string]$_.path -eq 'lib\I18n.ps1' })
        if ($e.Count -ne 1) { return $false }
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $stream = [IO.File]::OpenRead($cat)
            try { $h = [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '') } finally { $stream.Dispose() }
        } finally { $sha.Dispose() }
        return ($h -eq [string]$e[0].sha256)
    } catch { return $false }
}
$atmPackageSrc = Join-Path (Split-Path -Parent $PSScriptRoot) 'src'
$atmCatalogInstallDir = [string](Get-Variable -Name AtmCatalogInstallDir -Scope Script -ValueOnly -ErrorAction SilentlyContinue)
$atmCatalog = $null
if ((Test-Path -LiteralPath 'variable:script:AtmMessages') -and (Get-Command -Name Get-AtmText -CommandType Function -ErrorAction SilentlyContinue)) { $atmCatalog = 'loaded' }
elseif (Test-AtmCatalogVerified -Root $atmPackageSrc) { $atmCatalog = Join-Path $atmPackageSrc 'lib\I18n.ps1' }
elseif ($atmCatalogInstallDir -and (Test-AtmCatalogVerified -Root $atmCatalogInstallDir)) { $atmCatalog = Join-Path $atmCatalogInstallDir 'lib\I18n.ps1' }
elseif ((Get-Variable -Name AtmCatalogTrustUnverified -Scope Script -ValueOnly -ErrorAction SilentlyContinue) -and
    -not (Test-Path -LiteralPath (Join-Path $atmPackageSrc 'manifest.json')) -and (Test-Path -LiteralPath (Join-Path $atmPackageSrc 'lib\I18n.ps1') -PathType Leaf)) {
    $atmCatalog = Join-Path $atmPackageSrc 'lib\I18n.ps1'
}
if ($atmCatalog -and $atmCatalog -ne 'loaded') { . $atmCatalog }
elseif (-not $atmCatalog) {
    # Texts of the refusals that can happen before a catalog is available; any other key prints with its arguments.
    $script:AtmInstallerTexts = @{
        'inst.needAdmin'          = 'This operation requires PowerShell run as Administrator (no automatic elevation is performed). / Esta operacao exige um PowerShell executado como Administrador (nenhuma elevacao automatica e feita).'
        'inst.noManifest'         = 'Source without manifest.json. Use a verified release (SHA256SUMS) or, deliberately, -SourceWithoutManifest. / Origem sem manifest.json. Use um release verificado (SHA256SUMS) ou, conscientemente, -SourceWithoutManifest.'
        'inst.noManifestWarn'     = 'Source without manifest.json: source integrity NOT verified (explicit use of -SourceWithoutManifest). / Origem sem manifest.json: integridade da origem NAO verificada (uso explicito de -SourceWithoutManifest).'
        'inst.extraFile'          = 'Source contains a file not listed in the manifest / Origem contem arquivo fora do manifesto: {0}'
        'inst.hashMismatch'       = 'Source modified (hash mismatch) / Origem alterada (hash divergente): {0}'
        'inst.incomplete'         = 'Source incomplete compared to the manifest. / Origem incompleta em relacao ao manifesto.'
        'inst.requiredMissing'    = 'Required file missing in the source / Arquivo obrigatorio ausente na origem: {0}'
        'inst.syntax'             = 'Syntax error / Erro de sintaxe: {0}: {1}'
        'inst.previousIntegrity'  = 'The previous version failed its integrity check; nothing was changed. / A versao anterior falhou na verificacao de integridade; nada foi alterado. {0}'
    }
    function Get-AtmText {
        $key = [string]$args[0]
        $fmtArgs = @()
        if ($args.Count -gt 1) { $fmtArgs = @($args[1..($args.Count - 1)]) }
        $tpl = $script:AtmInstallerTexts[$key]
        if ($null -eq $tpl) { return ("[$key] " + (@($fmtArgs | ForEach-Object { "$_" }) -join ' | ')).TrimEnd() }
        if ($fmtArgs.Count -eq 0) { return $tpl }
        try { return ($tpl -f $fmtArgs) } catch { return ($tpl + ' ' + ($fmtArgs -join ' ')) }
    }
    Write-Warning 'Message catalog not verified (no matching manifest): built-in texts are shown. / Catalogo de mensagens nao verificado (sem manifesto correspondente): textos internos sao exibidos.'
}

$script:AtmRequiredFiles = @('agent-temp.ps1', 'bin\agent-temp.cmd', 'lib\Engine.Audit.ps1', 'lib\I18n.ps1', 'lib\Engine.Clean.ps1', 'lib\Engine.Diagnose.ps1', 'lib\Report.ps1', 'lib\Tui.ps1', 'lib\Native.cs', 'providers\ClaudeCode.ps1', 'config\projects.json')
# Principals that must never hold write-type rights on the install directory.
$script:AtmUntrustedSids = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-4', 'S-1-5-2', 'S-1-5-7')

function Assert-AtmElevated {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw (Get-AtmText 'inst.needAdmin')
    }
}

function Get-AtmSourceVersion {
    param([string]$SourceDir)
    $m = [regex]::Match([IO.File]::ReadAllText((Join-Path $SourceDir 'lib\Engine.Audit.ps1')), "\`$script:AtmVersion = '([0-9]+\.[0-9]+\.[0-9]+)'")
    if (-not $m.Success) { throw (Get-AtmText 'inst.noVersion') }
    return $m.Groups[1].Value
}

function Get-AtmTreeEntries {
    # Relative names are built from the tree itself (never by trimming a path prefix), so 8.3/long forms of the
    # root cannot shift them. Reparse points are refused.
    param([string]$Root)
    $out = New-Object System.Collections.Generic.List[object]
    $stack = New-Object System.Collections.Generic.Stack[object]
    $stack.Push(@((New-Object IO.DirectoryInfo($Root)), ''))
    while ($stack.Count -gt 0) {
        $cur = $stack.Pop()
        foreach ($e in $cur[0].GetFileSystemInfos()) {
            if (($e.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw (Get-AtmText 'inst.reparseInSource' $e.FullName) }
            $rel = $(if ($cur[1]) { $cur[1] + '\' + $e.Name } else { $e.Name })
            $isDir = ($e.Attributes -band [IO.FileAttributes]::Directory) -ne 0
            $out.Add([pscustomobject]@{ Rel = $rel; Full = $e.FullName; IsDir = $isDir; Length = $(if ($isDir) { 0 } else { $e.Length }) })
            if ($isDir) { $stack.Push(@($e, $rel)) }
        }
    }
    return $out.ToArray()
}

function Copy-AtmTree {
    # Copies regular files only; refuses reparse points; skips local/private config.
    param([string]$From, [string]$To)
    foreach ($item in (Get-AtmTreeEntries -Root $From)) {
        $rel = $item.Rel
        if ($rel -like 'config\projects.local.json' -or $rel -like 'manifest.json' -or $rel -like 'install-state.json') { continue }
        $dst = Join-Path $To $rel
        if ($item.IsDir) { [void][IO.Directory]::CreateDirectory($dst) }
        else { [void][IO.Directory]::CreateDirectory((Split-Path -Parent $dst)); [IO.File]::Copy($item.Full, $dst, $false) }
    }
}

function Test-AtmSourceIntegrity {
    # A release ships src\manifest.json. The source must match it exactly: same file set (nothing extra, e.g. a
    # planted provider), same SHA-256. Sources without a manifest (a git checkout) need an explicit switch.
    # -InstalledCopy: an installed directory, which also holds install-state.json (written after the manifest).
    param([string]$SourceDir, [switch]$AllowNoManifest, [switch]$InstalledCopy)
    $mf = Join-Path $SourceDir 'manifest.json'
    if (-not (Test-Path -LiteralPath $mf -PathType Leaf)) {
        if ($AllowNoManifest) { Write-Warning (Get-AtmText 'inst.noManifestWarn'); return }
        throw (Get-AtmText 'inst.noManifest')
    }
    $m = Get-Content -LiteralPath $mf -Raw -Encoding UTF8 | ConvertFrom-Json
    $expected = @{}
    foreach ($e in $m.files) { $expected[$e.path.ToLowerInvariant()] = $e.sha256 }
    $actual = @(Get-AtmTreeEntries -Root $SourceDir | Where-Object { -not $_.IsDir -and $_.Rel -ne 'manifest.json' -and -not ($InstalledCopy -and $_.Rel -eq 'install-state.json') } | ForEach-Object { $_.Rel })
    foreach ($rel in $actual) {
        $k = $rel.ToLowerInvariant()
        if (-not $expected.ContainsKey($k)) { throw (Get-AtmText 'inst.extraFile' $rel) }
        if ((Get-FileHash -LiteralPath (Join-Path $SourceDir $rel) -Algorithm SHA256).Hash -ne $expected[$k]) { throw (Get-AtmText 'inst.hashMismatch' $rel) }
    }
    if ($actual.Count -ne $expected.Count) { throw (Get-AtmText 'inst.incomplete') }
}

function Write-AtmManifest {
    param([string]$Root, [string]$Version)
    $files = foreach ($f in (Get-AtmTreeEntries -Root $Root | Where-Object { -not $_.IsDir } | Sort-Object Rel)) {
        $rel = $f.Rel
        if ($rel -eq 'manifest.json' -or $rel -eq 'install-state.json') { continue }
        [ordered]@{ path = $rel; sha256 = (Get-FileHash -LiteralPath $f.Full -Algorithm SHA256).Hash; bytes = $f.Length }
    }
    $doc = [ordered]@{ product = 'Agent Temp Manager'; version = $Version; files = @($files) }
    [IO.File]::WriteAllText((Join-Path $Root 'manifest.json'), ($doc | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding($false)))
}

function Test-AtmInstallAcl {
    # Allow-list model: only SYSTEM, Administrators, TrustedInstaller, CREATOR OWNER (and the installing
    # administrator, when given) may hold write-type rights; owners must be one of those too.
    param([string]$Path, [string]$AlsoTrustSid, [switch]$NoRecurse)
    $trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464', 'S-1-3-0')
    if ($AlsoTrustSid) { $trusted += $AlsoTrustSid }
    $problems = New-Object System.Collections.Generic.List[string]
    $writeMask = [Security.AccessControl.FileSystemRights]'WriteData, AppendData, WriteExtendedAttributes, WriteAttributes, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
    $targets = @((Get-Item -LiteralPath $Path -Force))
    if (-not $NoRecurse) { $targets += @(Get-ChildItem -LiteralPath $Path -Recurse -Force) }
    foreach ($t in $targets) {
        $acl = Get-Acl -LiteralPath $t.FullName
        $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($trusted -notcontains $owner) { $problems.Add("$($t.FullName): owner $owner") }
        foreach ($ace in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            if ($trusted -contains $ace.IdentityReference.Value) { continue }
            if (($ace.FileSystemRights -band $writeMask) -ne 0) { $problems.Add("$($t.FullName): $($ace.IdentityReference.Value) -> $($ace.FileSystemRights)") }
        }
    }
    return [pscustomobject]@{ Ok = ($problems.Count -eq 0); Problems = $problems.ToArray() }
}

function Remove-AtmOwnTree {
    # Removes ONLY the product's own directories: <InstallDir>, <InstallDir>.previous, <InstallDir>.staging-<8 hex>,
    # <InstallDir>.recovery-<8 hex> (the last only when named explicitly; nothing sweeps them, R-B6).
    # Refuses reparse points anywhere in the tree.
    param([string]$Path, [string]$InstallDir)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $inst = [IO.Path]::GetFullPath($InstallDir).TrimEnd('\')
    $ok = [string]::Equals($full, $inst, [StringComparison]::OrdinalIgnoreCase) -or
          [string]::Equals($full, "$inst.previous", [StringComparison]::OrdinalIgnoreCase) -or
          ($full.StartsWith("$inst.", [StringComparison]::OrdinalIgnoreCase) -and $full.Substring($inst.Length) -match '^\.(staging|recovery)-[0-9a-f]{8}$')
    if (-not $ok) { throw (Get-AtmText 'inst.notProductDir' $Path) }
    foreach ($i in @(Get-Item -LiteralPath $full -Force) + @(Get-ChildItem -LiteralPath $full -Recurse -Force)) {
        if (($i.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw (Get-AtmText 'inst.reparseRefused' $i.FullName) }
    }
    [IO.Directory]::Delete($full, $true)
}

function New-AtmNativeAssembly {
    # Compiles lib\Native.cs into lib\AgentTempManager.Native.dll inside the (admin-only) staging directory,
    # in a child Windows PowerShell whose TEMP/TMP point inside that directory, so no compiler intermediate
    # ever lands in a user-writable location.
    param([string]$Root)
    $tmp = Join-Path $Root '.build-tmp'
    [void][IO.Directory]::CreateDirectory($tmp)
    $cs = Join-Path $Root 'lib\Native.cs'
    $dll = Join-Path $Root 'lib\AgentTempManager.Native.dll'
    $oldTemp = $env:TEMP; $oldTmp = $env:TMP
    try {
        $env:TEMP = $tmp; $env:TMP = $tmp
        $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        # Paths are embedded as single-quoted literals: escape embedded apostrophes (e.g. a folder named O'Neil).
        $csQ = $cs.Replace("'", "''"); $dllQ = $dll.Replace("'", "''")
        & $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Add-Type -Path '$csQ' -OutputAssembly '$dllQ' -OutputType Library -ErrorAction Stop" | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $dll)) { throw (Get-AtmText 'inst.compileFailed') }
    } finally {
        $env:TEMP = $oldTemp; $env:TMP = $oldTmp
        if (Test-Path -LiteralPath $tmp) { [IO.Directory]::Delete($tmp, $true) }
    }
}

function Enter-AtmPrivateTemp {
    # The elevated account's %TEMP% may be writable by other principals. Every compiler/Add-Type intermediate of
    # an admin operation is redirected to a fresh directory that inherits the install parent's admin-only ACL
    # (named <InstallDir>.staging-<8 hex> so that Remove-AtmOwnTree accepts it and uninstall sweeps leftovers).
    param([string]$InstallDir)
    $dir = [IO.Path]::GetFullPath($InstallDir).TrimEnd('\') + '.staging-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    [void][IO.Directory]::CreateDirectory($dir)
    $state = [pscustomobject]@{ Dir = $dir; Temp = $env:TEMP; Tmp = $env:TMP }
    $env:TEMP = $dir; $env:TMP = $dir
    return $state
}

function Exit-AtmPrivateTemp {
    param($State, [string]$InstallDir)
    $env:TEMP = $State.Temp; $env:TMP = $State.Tmp
    if (Test-Path -LiteralPath $State.Dir) { Remove-AtmOwnTree -Path $State.Dir -InstallDir $InstallDir }
}

function Send-AtmEnvironmentChanged {
    if (-not ('AtmInstallNative' -as [type])) {
        Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public static class AtmInstallNative { [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult); }'
    }
    $r = [UIntPtr]::Zero
    [void][AtmInstallNative]::SendMessageTimeout([IntPtr]0xffff, 0x1A, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$r)
}

function Open-AtmPathKey {
    # Default: the MACHINE environment key. -TestKeyPath (HKCU-relative) exists only for the isolated test suite.
    param([string]$TestKeyPath)
    if ($TestKeyPath) { return [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($TestKeyPath) }
    return [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Environment', $true)
}

function Add-AtmMachinePath {
    # Appends Dir to Path, preserving the value kind (REG_EXPAND_SZ keeps %VARIABLES% unexpanded). Idempotent.
    param([string]$Dir, [string]$TestKeyPath)
    $k = Open-AtmPathKey -TestKeyPath $TestKeyPath
    try {
        $raw = [string]$k.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $kind = [Microsoft.Win32.RegistryValueKind]::ExpandString
        if ($k.GetValueNames() -contains 'Path') { $kind = $k.GetValueKind('Path') }
        $parts = @($raw.Split(';') | Where-Object { $_ -ne '' })
        if ($parts | Where-Object { $_.TrimEnd('\') -ieq $Dir.TrimEnd('\') }) { return $false }
        $k.SetValue('Path', (($parts + $Dir) -join ';'), $kind)
    } finally { $k.Close() }
    if (-not $TestKeyPath) { Send-AtmEnvironmentChanged }
    return $true
}

function Remove-AtmMachinePath {
    # Removes exactly the product's entry; every other entry and the value kind are preserved.
    param([string]$Dir, [string]$TestKeyPath)
    $k = Open-AtmPathKey -TestKeyPath $TestKeyPath
    try {
        if ($k.GetValueNames() -notcontains 'Path') { return $false }
        $raw = [string]$k.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $kind = $k.GetValueKind('Path')
        $parts = @($raw.Split(';') | Where-Object { $_ -ne '' })
        $keep = @($parts | Where-Object { $_.TrimEnd('\') -ine $Dir.TrimEnd('\') })
        if ($keep.Count -eq $parts.Count) { return $false }
        $k.SetValue('Path', ($keep -join ';'), $kind)
    } finally { $k.Close() }
    if (-not $TestKeyPath) { Send-AtmEnvironmentChanged }
    return $true
}

# Recovery messages come from this file, never from a message catalog: an installed catalog may be older (V0.1 has
# none of these keys) and must never drop the reason, the copy positions, the pending state or the instruction not to
# uninstall. Bilingual and ASCII, like the built-in texts above.
$script:AtmRecoveryTexts = @{
    'inst.stagingVerifyFailed'  = 'The new version failed its own verification before anything was replaced; nothing was changed: {0} / A nova versao falhou na propria verificacao antes de qualquer substituicao; nada foi alterado: {0}'
    'inst.updateRestored'       = 'The update failed after the swap; the installed version and its previous version were put back where they were: {0} / A atualizacao falhou apos a troca; a versao instalada e a anterior voltaram para onde estavam: {0}'
    'inst.rollbackVerifyFailed' = 'Verification after rollback failed; both versions were put back where they were: {0} / Verificacao apos rollback falhou; as duas versoes voltaram para onde estavam: {0}'
    'inst.updateUndoFailed'     = 'RECOVERY PENDING. The update failed ({0}) and putting the versions back also failed ({1}). Nothing was deleted. The version that was installed is in {2}; the older previous version is in {3}; the new version is in {4}. Do not uninstall. Rename the installed version back to {5} (and the older one, if any, to {5}.previous), check it with {5}\bin\agent-temp.cmd verify, then delete {6}. Until then updates, rollbacks and uninstall are refused. / RECUPERACAO PENDENTE. A atualizacao falhou ({0}) e devolver as versoes tambem falhou ({1}). Nada foi apagado. A versao que estava instalada esta em {2}; a anterior mais antiga esta em {3}; a nova versao esta em {4}. Nao desinstale. Renomeie a versao instalada de volta para {5} (e a mais antiga, se houver, para {5}.previous), confira com {5}\bin\agent-temp.cmd verify e depois apague {6}. Ate la, atualizacoes, rollbacks e desinstalacao sao recusados.'
    'inst.rollbackUndoFailed'   = 'RECOVERY PENDING. The rollback failed ({0}) and putting the versions back also failed ({1}). Nothing was deleted. The version that was current is in {2}; the previous version is in {3}. Do not uninstall. Rename them back by hand (the previous version to {4}.previous, then {2} to {4}), check it with {4}\bin\agent-temp.cmd verify, then delete {5}. Until then updates, rollbacks and uninstall are refused. / RECUPERACAO PENDENTE. O rollback falhou ({0}) e devolver as versoes tambem falhou ({1}). Nada foi apagado. A versao que estava em uso esta em {2}; a versao anterior esta em {3}. Nao desinstale. Renomeie-as de volta manualmente (a versao anterior para {4}.previous e depois {2} para {4}), confira com {4}\bin\agent-temp.cmd verify e depois apague {5}. Ate la, atualizacoes, rollbacks e desinstalacao sao recusados.'
    'inst.recoveryPending'      = 'RECOVERY PENDING: an update or rollback did not complete ({0}). Nothing was changed. Do not uninstall: one of these copies may be the only intact installation. Check each copy with <copy>\bin\agent-temp.cmd verify, put the intact one back as {1} by renaming, remove what is no longer needed, then delete {2} if it exists. / RECUPERACAO PENDENTE: uma atualizacao ou rollback nao terminou ({0}). Nada foi alterado. Nao desinstale: uma dessas copias pode ser a unica instalacao integra. Confira cada copia com <copia>\bin\agent-temp.cmd verify, devolva a integra como {1} renomeando, remova o que nao for mais necessario e depois apague {2}, se existir.'
    'inst.recoveryLeftover'     = 'The operation completed, but {0} (a copy that is no longer needed) could not be removed. Remove it by hand: updates, rollbacks and uninstall are refused while it exists. / A operacao foi concluida, mas nao foi possivel remover {0} (uma copia que nao e mais necessaria). Remova-a manualmente: atualizacoes, rollbacks e desinstalacao sao recusados enquanto ela existir.'
    'inst.interruptedPrevious'  = 'No installation in {0}, but a previous version exists in {1} (an interrupted update or rollback?). Nothing was changed. Do not uninstall. Rename it to {0} by hand, or install without -Update. / Nenhuma instalacao em {0}, mas existe uma versao anterior em {1} (atualizacao ou rollback interrompido?). Nada foi alterado. Nao desinstale. Renomeie-a para {0} manualmente ou instale sem -Update.'
}

function Get-AtmRecoveryText {
    $key = [string]$args[0]
    $fmtArgs = @()
    if ($args.Count -gt 1) { $fmtArgs = @($args[1..($args.Count - 1)]) }
    $tpl = $script:AtmRecoveryTexts[$key]
    if ($fmtArgs.Count -eq 0) { return $tpl }
    return ($tpl -f $fmtArgs)
}

function New-AtmSiblingDir {
    # A sibling name for the product: <InstallDir>.staging-<8 hex> (intermediate, swept by uninstall) or
    # <InstallDir>.recovery-<8 hex> (a copy that may be the only intact installation; never swept, R-B6).
    param([string]$InstallDir, [ValidateSet('staging', 'recovery')][string]$Kind)
    return "$InstallDir.$Kind-" + [guid]::NewGuid().ToString('N').Substring(0, 8)
}

function Get-AtmRecoveryDirs {
    param([string]$InstallDir)
    $leaf = Split-Path -Leaf $InstallDir
    return @(Get-ChildItem -LiteralPath (Split-Path -Parent $InstallDir) -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name.Length -gt $leaf.Length -and $_.Name.StartsWith($leaf, [StringComparison]::OrdinalIgnoreCase) -and $_.Name.Substring($leaf.Length) -match '^\.recovery-[0-9a-f]{8}$' } |
        ForEach-Object { $_.FullName })
}

function Get-AtmTransactionPath {
    # <InstallDir>.transaction.json: written before the first rename of an update or rollback and removed only once
    # the operation completed or every copy is back. While it exists the operation is pending (also after an abrupt
    # interruption, and also when no recovery directory exists, e.g. a first update without .previous).
    param([string]$InstallDir)
    return "$InstallDir.transaction.json"
}

function Write-AtmTransaction {
    param([string]$InstallDir, [string]$Operation, [string]$State, [hashtable]$Copies)
    $doc = [ordered]@{ product = 'Agent Temp Manager'; operation = $Operation; state = $State; updatedUtc = [datetime]::UtcNow.ToString('o'); installDir = $InstallDir; copies = $Copies }
    [IO.File]::WriteAllText((Get-AtmTransactionPath -InstallDir $InstallDir), ($doc | ConvertTo-Json -Depth 3), (New-Object Text.UTF8Encoding($false)))
}

function Clear-AtmTransaction {
    param([string]$InstallDir)
    $m = Get-AtmTransactionPath -InstallDir $InstallDir
    if (Test-Path -LiteralPath $m -PathType Leaf) { [IO.File]::Delete($m) }
}

function Assert-AtmNoRecoveryPending {
    # A pending transaction or a recovery copy means an earlier failed recovery or an interrupted operation: an
    # administrator decides what to keep. Nothing is recovered silently and nothing is changed while one exists. A
    # .previous alone is normal (it exists after every successful update) and is never taken as a failure.
    param([string]$InstallDir)
    $marker = Get-AtmTransactionPath -InstallDir $InstallDir
    $recovery = @(Get-AtmRecoveryDirs -InstallDir $InstallDir)
    if (-not (Test-Path -LiteralPath $marker) -and $recovery.Count -eq 0) { return }
    $found = @()
    if (Test-Path -LiteralPath $marker) { $found += $marker }
    $found += $recovery
    foreach ($d in @($InstallDir, "$InstallDir.previous")) { if (Test-Path -LiteralPath $d) { $found += $d } }
    $leaf = Split-Path -Leaf $InstallDir
    $found += @(Get-ChildItem -LiteralPath (Split-Path -Parent $InstallDir) -Directory -Force -Filter "$leaf.staging-*" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    throw (Get-AtmRecoveryText 'inst.recoveryPending' ($found -join '; ') $InstallDir $marker)
}

function Invoke-AtmRenameSteps {
    # Renames each step (Key, From, To) in order and records where each copy now is in $Where; stops at the first
    # failure and returns its message ($null when every step succeeded). Never deletes anything.
    param([object[]]$Steps, [hashtable]$Where)
    foreach ($s in $Steps) {
        try { Rename-Item -LiteralPath $s.From -NewName (Split-Path -Leaf $s.To) } catch { return $_.Exception.Message }
        $Where[$s.Key] = $s.To
    }
    return $null
}

function Invoke-AtmVerifyInstalled {
    param([string]$InstallDir)
    $out = & cmd.exe /c "`"$(Join-Path $InstallDir 'bin\agent-temp.cmd')`" verify" 2>&1
    return [pscustomobject]@{ Ok = ($LASTEXITCODE -eq 0); Output = ($out -join "`n") }
}

function Install-AtmProduct {
    <#
      Install / update flow. The public script Install-AgentTempManager.ps1 calls Assert-AtmElevated first;
      the isolated test suite calls this function with a sandbox InstallDir and -TestPathKey.
    #>
    param([string]$SourceDir, [string]$InstallDir, [string]$ProjectsFile, [switch]$Update, [switch]$SkipPath, [string]$TrustSid, [string]$TestPathKey, [switch]$SourceWithoutManifest)
    $SourceDir = [IO.Path]::GetFullPath($SourceDir)
    $InstallDir = [IO.Path]::GetFullPath($InstallDir).TrimEnd('\')

    # 1. Source validation: required files, PowerShell syntax.
    foreach ($rel in $script:AtmRequiredFiles) { if (-not (Test-Path -LiteralPath (Join-Path $SourceDir $rel) -PathType Leaf)) { throw (Get-AtmText 'inst.requiredMissing' $rel) } }
    foreach ($f in Get-ChildItem -LiteralPath $SourceDir -Recurse -Filter '*.ps1' -File) {
        $t = $null; $e = $null
        [void][Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$t, [ref]$e)
        if ($e.Count -gt 0) { throw (Get-AtmText 'inst.syntax' $f.FullName $e[0].Message) }
    }
    $version = Get-AtmSourceVersion -SourceDir $SourceDir
    Test-AtmSourceIntegrity -SourceDir $SourceDir -AllowNoManifest:$SourceWithoutManifest

    # 2. Existing installation handling.
    Assert-AtmNoRecoveryPending -InstallDir $InstallDir
    $exists = Test-Path -LiteralPath $InstallDir
    $previous = "$InstallDir.previous"
    if ($exists -and -not $Update) { throw (Get-AtmText 'inst.alreadyInstalled' $InstallDir) }
    if (-not $exists -and $Update) {
        # No installation but a previous version: an interrupted update or rollback. Nothing is guessed or moved.
        if (Test-Path -LiteralPath (Join-Path $previous 'install-state.json')) { throw (Get-AtmRecoveryText 'inst.interruptedPrevious' $InstallDir $previous) }
        throw (Get-AtmText 'inst.nothingToUpdate' $InstallDir)
    }
    if ($exists) {
        if (([IO.File]::GetAttributes($InstallDir) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw (Get-AtmText 'inst.targetReparse') }
        if (-not (Test-Path -LiteralPath (Join-Path $InstallDir 'install-state.json'))) { throw (Get-AtmText 'inst.targetForeign') }
    }
    $parent = Split-Path -Parent $InstallDir
    if (([IO.File]::GetAttributes($parent) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw (Get-AtmText 'inst.parentReparse') }
    # A parent writable by standard users would let them rename the install directory and plant a replacement.
    $pacl = Test-AtmInstallAcl -Path $parent -AlsoTrustSid $TrustSid -NoRecurse
    if (-not $pacl.Ok) { throw (Get-AtmText 'inst.parentInsecure' $parent ($pacl.Problems -join '; ')) }
    $pathAddedBefore = $false
    # Unreadable install state: the PATH entry is not proven ours, so it is never removed later.
    if ($exists) { try { $pathAddedBefore = [bool](Get-Content -LiteralPath (Join-Path $InstallDir 'install-state.json') -Raw | ConvertFrom-Json).pathAddedByInstaller } catch { $pathAddedBefore = $false } }

    # 3. Stage: copy, compile native assembly inside the staging dir, manifest, ACL audit.
    $staging = "$InstallDir.staging-" + [guid]::NewGuid().ToString('N').Substring(0, 8)
    [void][IO.Directory]::CreateDirectory($staging)
    try {
        Copy-AtmTree -From $SourceDir -To $staging
        if ($ProjectsFile) {
            $null = Get-Content -LiteralPath $ProjectsFile -Raw -Encoding UTF8 | ConvertFrom-Json
            Copy-Item -LiteralPath $ProjectsFile -Destination (Join-Path $staging 'config\projects.local.json')
        } elseif ($exists -and (Test-Path -LiteralPath (Join-Path $InstallDir 'config\projects.local.json'))) {
            Copy-Item -LiteralPath (Join-Path $InstallDir 'config\projects.local.json') -Destination (Join-Path $staging 'config\projects.local.json')
        }
        New-AtmNativeAssembly -Root $staging
        Write-AtmManifest -Root $staging -Version $version
        $acl = Test-AtmInstallAcl -Path $staging -AlsoTrustSid $TrustSid
        if (-not $acl.Ok) { throw (Get-AtmText 'inst.aclStaging' ($acl.Problems -join '; ')) }
    } catch {
        Remove-AtmOwnTree -Path $staging -InstallDir $InstallDir
        throw
    }

    # 3b. The staged copy runs its own verify before anything moves: a failure changes nothing.
    $stagedFailure = $null
    try {
        $sv = Invoke-AtmVerifyInstalled -InstallDir $staging
        if (-not $sv.Ok) { $stagedFailure = [string]$sv.Output }
    } catch { $stagedFailure = $_.Exception.Message }
    if ($null -ne $stagedFailure) {
        Remove-AtmOwnTree -Path $staging -InstallDir $InstallDir
        throw (Get-AtmRecoveryText 'inst.stagingVerifyFailed' $stagedFailure)
    }

    # 4. Swap. Nothing is deleted before the new version verified (R-B6): an older .previous is set aside in a
    # recovery directory, the installed copy becomes .previous and the staged copy takes its place. $where tracks
    # each copy, so that every failure up to the end of 6 can put them back, or say where they were left. The
    # transaction marker is written before the first rename and removed only when the update completed or every
    # copy is back; if it cannot be written, nothing moves.
    $where = @{ installed = $null; older = $null; new = $staging }
    $olderAside = $null
    $bin = Join-Path $InstallDir 'bin'
    $pathAdded = $false
    $marker = Get-AtmTransactionPath -InstallDir $InstallDir
    if ($exists) {
        try { Write-AtmTransaction -InstallDir $InstallDir -Operation 'update' -State 'started' -Copies $where }
        catch { Remove-AtmOwnTree -Path $staging -InstallDir $InstallDir; throw }
    }
    try {
        if ($exists) {
            $where.installed = $InstallDir
            if (Test-Path -LiteralPath $previous) {
                $where.older = $previous
                $olderAside = New-AtmSiblingDir -InstallDir $InstallDir -Kind recovery
                Rename-Item -LiteralPath $previous -NewName (Split-Path -Leaf $olderAside); $where.older = $olderAside
            }
            Rename-Item -LiteralPath $InstallDir -NewName (Split-Path -Leaf $previous); $where.installed = $previous
        }
        Rename-Item -LiteralPath $staging -NewName (Split-Path -Leaf $InstallDir); $where.new = $InstallDir

        # 5. PATH, preserving REG_EXPAND_SZ.
        if (-not $SkipPath) { $pathAdded = Add-AtmMachinePath -Dir $bin -TestKeyPath $TestPathKey }

        # 6. State + verification.
        $state = [ordered]@{ product = 'Agent Temp Manager'; version = $version; installedUtc = [datetime]::UtcNow.ToString('o'); installDir = $InstallDir; binOnPath = (-not $SkipPath); pathAddedByInstaller = ($pathAdded -or $pathAddedBefore) }
        [IO.File]::WriteAllText((Join-Path $InstallDir 'install-state.json'), ($state | ConvertTo-Json), (New-Object Text.UTF8Encoding($false)))
        $acl = Test-AtmInstallAcl -Path $InstallDir -AlsoTrustSid $TrustSid
        if (-not $acl.Ok) { throw (Get-AtmText 'inst.aclInstalled' ($acl.Problems -join '; ')) }
        $v = Invoke-AtmVerifyInstalled -InstallDir $InstallDir
        if (-not $v.Ok) { throw (Get-AtmText 'inst.verifyFailed' $v.Output) }
    } catch {
        # A first installation has nothing to put back (V0.1 behaviour).
        if (-not $exists) { throw }
        $failure = $_.Exception.Message
        # Reverse order: the failed new copy out of the way, the installed copy back, the older .previous back.
        $steps = @()
        if ($where.new -eq $InstallDir) { $steps += @{ Key = 'new'; From = $InstallDir; To = (New-AtmSiblingDir -InstallDir $InstallDir -Kind staging) } }
        if ($where.installed -eq $previous) { $steps += @{ Key = 'installed'; From = $previous; To = $InstallDir } }
        if ($null -ne $olderAside -and $where.older -eq $olderAside) { $steps += @{ Key = 'older'; From = $olderAside; To = $previous } }
        $undo = Invoke-AtmRenameSteps -Steps $steps -Where $where
        if ($null -ne $undo) {
            # Nothing more is moved or deleted; the marker stays (with the positions) and blocks every operation.
            try { Write-AtmTransaction -InstallDir $InstallDir -Operation 'update' -State 'recovery-failed' -Copies $where } catch { $null = $_ }
            throw (Get-AtmRecoveryText 'inst.updateUndoFailed' $failure $undo $where.installed $(if ($null -ne $where.older) { $where.older } else { '-' }) $where.new $InstallDir $marker)
        }
        if ($pathAdded) { $null = Remove-AtmMachinePath -Dir $bin -TestKeyPath $TestPathKey }
        # Every intact copy is back: the transaction is over. Only then is the failed new copy removed.
        Clear-AtmTransaction -InstallDir $InstallDir
        try { Remove-AtmOwnTree -Path $where.new -InstallDir $InstallDir } catch { Write-Warning (Get-AtmRecoveryText 'inst.recoveryLeftover' $where.new) }
        throw (Get-AtmRecoveryText 'inst.updateRestored' $failure)
    }
    # The new version verified: the older .previous is no longer needed (if it cannot be removed, its recovery
    # directory keeps further operations blocked), and the transaction is over.
    if ($null -ne $olderAside) {
        try { Remove-AtmOwnTree -Path $olderAside -InstallDir $InstallDir } catch { Write-Warning (Get-AtmRecoveryText 'inst.recoveryLeftover' $olderAside) }
    }
    if ($exists) { Clear-AtmTransaction -InstallDir $InstallDir }
    return [pscustomobject]@{ Version = $version; InstallDir = $InstallDir; PreviousKept = (Test-Path -LiteralPath $previous); PathAdded = $pathAdded }
}

function Restore-AtmPrevious {
    # Rollback to <InstallDir>.previous (created by the last -Update). The PATH entry is unchanged.
    param([string]$InstallDir)
    $InstallDir = [IO.Path]::GetFullPath($InstallDir).TrimEnd('\')
    $previous = "$InstallDir.previous"
    Assert-AtmNoRecoveryPending -InstallDir $InstallDir
    if (-not (Test-Path -LiteralPath (Join-Path $previous 'install-state.json'))) { throw (Get-AtmText 'inst.noPrevious' $previous) }
    if (-not (Test-Path -LiteralPath (Join-Path $InstallDir 'install-state.json'))) { throw (Get-AtmText 'inst.noCurrent' $InstallDir) }
    # The previous copy is checked in this process (manifest, SHA-256, exact file set) before anything moves: an
    # altered or damaged copy never replaces the current one and none of its code runs (R-B5).
    try { Test-AtmSourceIntegrity -SourceDir $previous -InstalledCopy } catch { throw (Get-AtmText 'inst.previousIntegrity' $_.Exception.Message) }
    # The retired copy is a recovery directory (R-B6): if it cannot be put back, nothing sweeps it. The transaction
    # marker is written before the first rename and removed only once the rollback completed or both copies are back.
    $retired = New-AtmSiblingDir -InstallDir $InstallDir -Kind recovery
    $marker = Get-AtmTransactionPath -InstallDir $InstallDir
    $copies = @{ current = $InstallDir; previous = $previous; retired = $retired }
    Write-AtmTransaction -InstallDir $InstallDir -Operation 'rollback' -State 'started' -Copies $copies
    try { Rename-Item -LiteralPath $InstallDir -NewName (Split-Path -Leaf $retired) }
    catch { Clear-AtmTransaction -InstallDir $InstallDir; throw }
    try { Rename-Item -LiteralPath $previous -NewName (Split-Path -Leaf $InstallDir) }
    catch {
        $swapError = $_
        try { Rename-Item -LiteralPath $retired -NewName (Split-Path -Leaf $InstallDir) }
        catch {
            $prevAt = $(if (Test-Path -LiteralPath $previous) { $previous } else { $InstallDir })
            $copies.current = $retired; $copies.previous = $prevAt
            try { Write-AtmTransaction -InstallDir $InstallDir -Operation 'rollback' -State 'recovery-failed' -Copies $copies } catch { $null = $_ }
            throw (Get-AtmRecoveryText 'inst.rollbackUndoFailed' $swapError.Exception.Message $_.Exception.Message $retired $prevAt $InstallDir $marker)
        }
        Clear-AtmTransaction -InstallDir $InstallDir
        throw $swapError
    }
    # A verify that fails or throws is the same failure: both copies go back where they were. The current copy is
    # removed only after the restored one verified; no failure path removes anything.
    $failure = $null
    try {
        $v = Invoke-AtmVerifyInstalled -InstallDir $InstallDir
        if (-not $v.Ok) { $failure = [string]$v.Output }
    } catch { $failure = $_.Exception.Message }
    if ($null -ne $failure) {
        $undo = $null
        try { Rename-Item -LiteralPath $InstallDir -NewName (Split-Path -Leaf $previous) } catch { $undo = $_.Exception.Message }
        if ($null -eq $undo) {
            try { Rename-Item -LiteralPath $retired -NewName (Split-Path -Leaf $InstallDir) } catch { $undo = $_.Exception.Message }
        }
        if ($null -ne $undo) {
            # Where each copy is now (the first rename either happened or not); nothing more is moved or deleted and
            # the marker stays.
            $curAt = $retired
            $prevAt = $(if (Test-Path -LiteralPath $previous) { $previous } else { $InstallDir })
            $copies.current = $curAt; $copies.previous = $prevAt
            try { Write-AtmTransaction -InstallDir $InstallDir -Operation 'rollback' -State 'recovery-failed' -Copies $copies } catch { $null = $_ }
            throw (Get-AtmRecoveryText 'inst.rollbackUndoFailed' $failure $undo $curAt $prevAt $InstallDir $marker)
        }
        Clear-AtmTransaction -InstallDir $InstallDir
        throw (Get-AtmRecoveryText 'inst.rollbackVerifyFailed' $failure)
    }
    try { Remove-AtmOwnTree -Path $retired -InstallDir $InstallDir } catch { Write-Warning (Get-AtmRecoveryText 'inst.recoveryLeftover' $retired) }
    Clear-AtmTransaction -InstallDir $InstallDir
    return (Get-Content -LiteralPath (Join-Path $InstallDir 'install-state.json') -Raw | ConvertFrom-Json).version
}

function Uninstall-AtmProduct {
    param([string]$InstallDir, [string]$TestPathKey)
    $InstallDir = [IO.Path]::GetFullPath($InstallDir).TrimEnd('\')
    # A pending recovery is refused before anything changes (PATH, product directories, sweeps): one of the copies
    # may be the only intact installation (R-B6).
    Assert-AtmNoRecoveryPending -InstallDir $InstallDir
    if (-not (Test-Path -LiteralPath (Join-Path $InstallDir 'install-state.json'))) { throw (Get-AtmText 'inst.notInstalled' $InstallDir) }
    # Only remove the PATH entry if this product added it (never an entry that pre-existed).
    $added = $false
    # Unreadable install state: never remove a PATH entry we cannot prove we added.
    try { $added = [bool](Get-Content -LiteralPath (Join-Path $InstallDir 'install-state.json') -Raw | ConvertFrom-Json).pathAddedByInstaller } catch { $added = $false }
    $removed = $false
    if ($added) { $removed = Remove-AtmMachinePath -Dir (Join-Path $InstallDir 'bin') -TestKeyPath $TestPathKey }
    Remove-AtmOwnTree -Path $InstallDir -InstallDir $InstallDir
    Remove-AtmOwnTree -Path "$InstallDir.previous" -InstallDir $InstallDir
    foreach ($s in @(Get-ChildItem -LiteralPath (Split-Path -Parent $InstallDir) -Directory -Filter ((Split-Path -Leaf $InstallDir) + '.staging-*') -ErrorAction SilentlyContinue)) {
        if ($env:TEMP -and [string]::Equals($s.FullName.TrimEnd('\'), $env:TEMP.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) { continue }   # private temp in use
        Remove-AtmOwnTree -Path $s.FullName -InstallDir $InstallDir
    }
    return $removed
}
