# AgentTempManager AUDIT ENGINE. Compatible with Windows PowerShell 5.1 and PowerShell 7.
# Discovery, read-only inventory, process/session evidence and conservative classification.
# No terminal output: progress goes through an optional callback. Presentation lives in Report.ps1 / Tui.ps1.
#
# Safety contract (see docs/SECURITY-MODEL.md):
#  * audit/preview never create, modify, rename, move or delete anything inside audited paths.
#  * Reparse points are never traversed, including in ancestors of audited paths.
#  * Classification is conservative; no class authorizes deletion by itself.
#  * clean deletes only exact allowlisted session roots that pass every gate, after typed confirmation,
#    re-validating each one immediately before deleting it, without force.

Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot 'I18n.ps1')

$script:AtmVersion = '0.1.0'
$script:AtmRecentHours = 72
$script:AtmMaxSamples = 10
$script:AtmRefTerminators = [char[]]@('"', "'", ' ', "`t", "`r", "`n", '|', '<', '>', ';', ',', '&', '^', '(', ')', '[', ']', '{', '}', '=', '`', ':', '.')

# Flags that make a partition ineligible regardless of anything else (preview: BLOCKED).
$script:AtmHardFlags = @('NOT_SESSION_ROOT', 'REPARSE_POINT', 'MEASUREMENT_INCOMPLETE', 'READ_ERRORS', 'PROTECTED_FILES',
    'SHARED_TEMP', 'BASE_STRUCTURE_UNRECOGNIZED', 'UNRECOGNIZED_SLUG', 'RESIDUAL_PROFILE', 'CLOCK_SKEW')
# Flags that require human investigation (preview: INVESTIGATE).
$script:AtmSoftFlags = @('ANCESTOR_REFERENCE', 'AMBIGUOUS_REFERENCE', 'SESSION_REGISTRY_UNREADABLE', 'SESSION_REGISTRY_ENTRY_UNPARSEABLE',
    'SESSION_PID_ALIVE_UNVERIFIED', 'SESSION_LIVENESS_UNVERIFIABLE', 'TRANSCRIPTS_UNREADABLE', 'TRANSCRIPT_RECENT',
    'PROCESS_SNAPSHOT_FAILED', 'CONFIG_DIR_UNKNOWN')

# ---------------------------------------------------------------------------------------------
# Providers (agent adapters). V1 ships only providers\ClaudeCode.ps1. A provider describes WHERE an agent
# keeps temporary session roots and HOW to read its liveness evidence; every safety decision stays here
# and in Engine.Clean.ps1.
# ---------------------------------------------------------------------------------------------

$script:AtmProviders = New-Object System.Collections.Generic.List[object]
$script:AtmProviderMembers = @('Id', 'DisplayName', 'TempSubdir', 'ScopePattern', 'RootPattern', 'EnvVarNames',
    'GetExtraTempDirs', 'GetConfigDirs', 'GetSessionEvidence', 'GetActivityEvidence', 'GetProjectKey')
# Contract v2 (docs/adr/ADR-0008): capabilities and optional runtime members. A provider without ContractVersion is a
# v1 provider with the single capability 'temp', validated exactly as before.
$script:AtmProviderCapabilityNames = @('temp', 'runtime')
$script:AtmProviderRuntimeMembers = @('GetProcessMatchers', 'GetServiceHints', 'GetVirtualizationHints', 'GetWorktreeHints')

function Get-AtmProviderContract {
    # Works on unregistered objects too (the -Providers override of Invoke-AtmInventory skips registration).
    param($Provider)
    $names = @($Provider.PSObject.Properties.Name)
    if ($names -notcontains 'ContractVersion') { return [pscustomobject]@{ Version = 1; Capabilities = @('temp') } }
    $v = 0
    if (-not [int]::TryParse([string]$Provider.ContractVersion, [ref]$v) -or $v -ne 2) { throw (Get-AtmText 'err.providerContract' ([string]$Provider.ContractVersion)) }
    $caps = @(if ($names -contains 'Capabilities') { @($Provider.Capabilities) | Where-Object { $null -ne $_ } })
    if ($caps.Count -eq 0) { throw (Get-AtmText 'err.providerCapabilities' '-') }
    foreach ($c in $caps) { if (-not ($c -is [string]) -or $script:AtmProviderCapabilityNames -cnotcontains $c) { throw (Get-AtmText 'err.providerCapabilities' ([string]$c)) } }
    if (@($caps | Select-Object -Unique).Count -ne $caps.Count) { throw (Get-AtmText 'err.providerCapabilities' ($caps -join ',')) }
    return [pscustomobject]@{ Version = 2; Capabilities = [string[]]$caps }
}

function Get-AtmProviderCapabilities { param($Provider) return @((Get-AtmProviderContract $Provider).Capabilities) }

function Test-AtmProviderId {
    # v1 keeps the V0.1 check unchanged (case-insensitive, full compatibility with existing providers); v2 requires
    # the documented lower-case form exactly.
    param([string]$Id, $Contract)
    if ($Contract.Version -ge 2) { return ($Id -cmatch '^[a-z0-9-]+$') }
    return ($Id -match '^[a-z0-9-]+$')
}

function Register-AtmProvider {
    param($Provider)
    $names = @($Provider.PSObject.Properties.Name)
    $contract = Get-AtmProviderContract $Provider
    $isTemp = $contract.Capabilities -ccontains 'temp'
    $required = $(if ($isTemp) { $script:AtmProviderMembers } else { @('Id', 'DisplayName') })
    foreach ($m in $required) { if ($names -notcontains $m) { throw (Get-AtmText 'err.providerMember' $m) } }
    if (-not (Test-AtmProviderId -Id $Provider.Id -Contract $contract)) { throw (Get-AtmText 'err.providerId' $Provider.Id) }
    if ($isTemp -and $Provider.TempSubdir -notmatch '^[A-Za-z0-9._-]+$') { throw (Get-AtmText 'err.providerSubdir' $Provider.TempSubdir) }
    foreach ($m in $script:AtmProviderRuntimeMembers) {
        if ($names -notcontains $m) { continue }
        if ($contract.Capabilities -cnotcontains 'runtime' -or -not ($Provider.$m -is [scriptblock])) { throw (Get-AtmText 'err.providerRuntimeMember' $m) }
    }
    for ($i = $script:AtmProviders.Count - 1; $i -ge 0; $i--) { if ($script:AtmProviders[$i].Id -eq $Provider.Id) { $script:AtmProviders.RemoveAt($i) } }
    $script:AtmProviders.Add($Provider)
}

function Get-AtmProviders { return $script:AtmProviders.ToArray() }

function Get-AtmProviderEnvVarNames {
    param($Providers)
    $n = @()
    foreach ($p in @($Providers)) { $n += @($p.EnvVarNames) }
    return @($n | Where-Object { $_ } | Select-Object -Unique)
}

$script:AtmNativeMode = $null

function Join-AtmPath {
    # Purely textual path join. Join-Path (PS 5.1) throws when the drive does not exist, which would break discovery
    # for a profile on a disconnected/removed drive; such profiles must be reported, never crash the audit.
    param([string]$Path, [string]$ChildPath)
    if ([string]::IsNullOrEmpty($Path)) { throw (Get-AtmText 'err.emptyBase') }
    return [IO.Path]::Combine($Path, $ChildPath.TrimStart('\'))
}

function Initialize-AtmNative {
    # Installed copies ship lib\AgentTempManager.Native.dll, compiled by the installer inside the admin-only
    # install directory and listed in manifest.json. It is loaded only if its SHA-256 matches the manifest
    # (fail closed otherwise). Source checkouts compile Native.cs in memory (Add-Type).
    param([string]$LibDir = $PSScriptRoot)
    if ('AgentTempManager.AtmScanner' -as [type]) { return }
    $dll = Join-AtmPath $LibDir 'AgentTempManager.Native.dll'
    if (Test-Path -LiteralPath $dll -PathType Leaf) {
        $manifest = Join-AtmPath (Split-Path -Parent $LibDir) 'manifest.json'
        if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { throw (Get-AtmText 'err.dllNoManifest') }
        $entry = @((Get-Content -LiteralPath $manifest -Raw -Encoding UTF8 | ConvertFrom-Json).files | Where-Object { $_.path -eq 'lib\AgentTempManager.Native.dll' })
        $hash = (Get-FileHash -LiteralPath $dll -Algorithm SHA256).Hash
        if ($entry.Count -ne 1 -or $entry[0].sha256 -ne $hash) { throw (Get-AtmText 'err.dllMismatch') }
        Add-Type -Path $dll -ErrorAction Stop
        $script:AtmNativeMode = 'dll'
        return
    }
    if (Test-Path -LiteralPath (Join-AtmPath (Split-Path -Parent $LibDir) 'install-state.json') -PathType Leaf) { throw (Get-AtmText 'err.dllMissingInstalled') }
    $src = [IO.File]::ReadAllText((Join-AtmPath $LibDir 'Native.cs'))
    Add-Type -TypeDefinition $src -Language CSharp -ErrorAction Stop
    $script:AtmNativeMode = 'memory'
}

function Get-AtmCurrentIdentity {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    [pscustomobject]@{
        Sid     = $id.User.Value
        Name    = $id.Name
        IsAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
}

function Get-AtmNormalizedPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    try {
        $long = [AgentTempManager.AtmNative]::GetLongPath($Path)
        if (-not $long) {
            # Path may not exist; normalize the existing parent and re-append the leaf.
            $parent = [IO.Path]::GetDirectoryName($Path)
            $leaf = [IO.Path]::GetFileName($Path)
            if ($parent -and $leaf) {
                $lp = [AgentTempManager.AtmNative]::GetLongPath($parent)
                if ($lp) { $long = Join-AtmPath $lp $leaf }
            }
        }
        if (-not $long) { $long = $Path }
        $full = [IO.Path]::GetFullPath($long)
        if ($full.Length -gt 3) { $full = $full.TrimEnd('\') }
        return $full
    } catch { return $null }
}

function Test-AtmPathChain {
    <#
      Validates every component from the volume root down to $Path (inclusive):
      it must exist, be readable for attributes, and NOT be a reparse point.
      Returns Status: OK | NOT_FOUND | INACCESSIBLE | REPARSE_IN_PATH | UNSUPPORTED_DRIVE | INVALID
    #>
    param([string]$Path)
    $r = [ordered]@{ Status = 'OK'; At = $null; Detail = $null }
    if (-not $Path -or $Path -notmatch '^[A-Za-z]:\\') { $r.Status = 'INVALID'; $r.At = $Path; return [pscustomobject]$r }
    try {
        $drive = New-Object IO.DriveInfo($Path.Substring(0, 1))
        if ($drive.DriveType -ne [IO.DriveType]::Fixed) { $r.Status = 'UNSUPPORTED_DRIVE'; $r.At = $Path.Substring(0, 3); $r.Detail = [string]$drive.DriveType; return [pscustomobject]$r }
    } catch { $r.Status = 'INVALID'; $r.At = $Path; $r.Detail = $_.Exception.GetType().Name; return [pscustomobject]$r }

    $parts = $Path.Substring(3).Split([char]'\') | Where-Object { $_ -ne '' }
    $cur = $Path.Substring(0, 3)
    foreach ($p in $parts) {
        $cur = Join-AtmPath $cur $p
        try {
            $a = [IO.File]::GetAttributes($cur)
        } catch [IO.FileNotFoundException] { $r.Status = 'NOT_FOUND'; $r.At = $cur; return [pscustomobject]$r }
        catch [IO.DirectoryNotFoundException] { $r.Status = 'NOT_FOUND'; $r.At = $cur; return [pscustomobject]$r }
        catch [UnauthorizedAccessException] { $r.Status = 'INACCESSIBLE'; $r.At = $cur; return [pscustomobject]$r }
        catch { $r.Status = 'INACCESSIBLE'; $r.At = $cur; $r.Detail = $_.Exception.GetType().Name; return [pscustomobject]$r }
        if (($a -band [IO.FileAttributes]::ReparsePoint) -ne 0) { $r.Status = 'REPARSE_IN_PATH'; $r.At = $cur; return [pscustomobject]$r }
    }
    return [pscustomobject]$r
}

function Get-AtmConfig {
    param([string]$ConfigDir)
    # projects.json ships generic defaults; projects.local.json (optional, never versioned) adds
    # site-specific rules and is evaluated first. Recognition is informational only.
    $file = Join-AtmPath $ConfigDir 'projects.json'
    $cfg = Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json
    $local = Join-AtmPath $ConfigDir 'projects.local.json'
    if (Test-Path -LiteralPath $local -PathType Leaf) {
        $lc = Get-Content -LiteralPath $local -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($lc.PSObject.Properties.Name -contains 'projects') { $cfg.projects = @(@($lc.projects) + @($cfg.projects)) }
    }
    $cfg.projects = @($cfg.projects | Where-Object { $_ })
    return $cfg
}

function Resolve-AtmProject {
    # Informational project naming. Returns { Name; Identified; Source }. Never guesses: when no rule or evidence
    # applies, the project is reported as not identified (the scope directory is still shown separately).
    param([string]$Slug, [string]$ProfilePath, $Config, $Provider, [hashtable]$EvidenceNames)
    $unknown = $(if ($Config.PSObject.Properties.Name -contains 'unknownProjectName' -and $Config.unknownProjectName) { $Config.unknownProjectName } else { Get-AtmText 'project.unknown' })
    $homeName = $(if ($Config.PSObject.Properties.Name -contains 'homeProjectName' -and $Config.homeProjectName) { $Config.homeProjectName } else { Get-AtmText 'project.home' })
    $k = & $Provider.GetProjectKey $Slug $ProfilePath
    if ($k.IsHome) { return [pscustomobject]@{ Name = $homeName; Identified = $true; Source = (Get-AtmText 'project.srcHome') } }
    foreach ($p in $Config.projects) {
        if ([regex]::IsMatch($k.Key, $p.pattern, 'IgnoreCase')) { return [pscustomobject]@{ Name = $p.name; Identified = $true; Source = (Get-AtmText 'project.srcRule') } }
    }
    if ($EvidenceNames -and $Slug -and $EvidenceNames.ContainsKey($Slug.ToLowerInvariant())) {
        $n = $EvidenceNames[$Slug.ToLowerInvariant()]
        if ($n) { return [pscustomobject]@{ Name = $n; Identified = $true; Source = (Get-AtmText 'project.srcSession') } }
    }
    return [pscustomobject]@{ Name = $unknown; Identified = $false; Source = '-' }
}

function Get-AtmProjectEvidenceNames {
    # scope (lower) -> display name, from session evidence whose working directory maps to that scope.
    # Conflicting names for one scope (slug collisions) make it unidentified ($null).
    param($Registry)
    $map = @{}
    foreach ($e in @($Registry.Entries)) {
        if (-not ($e.PSObject.Properties.Name -contains 'Scope') -or -not $e.Scope -or -not $e.ProjectName) { continue }
        $k = ([string]$e.Scope).ToLowerInvariant()
        if ($map.ContainsKey($k) -and $map[$k] -ne $e.ProjectName) { $map[$k] = $null } else { $map[$k] = [string]$e.ProjectName }
    }
    return $map
}

# ---------------------------------------------------------------------------------------------
# Profile discovery
# ---------------------------------------------------------------------------------------------

function Get-AtmUserEnvironment {
    # Reads HKU\<SID>\Environment (unexpanded) and HKU\<SID>\Volatile Environment. Never loads hives.
    param([string]$Sid, [string[]]$LoadedHives, [string[]]$VarNames = @())
    $res = [ordered]@{ Status = 'NOT_LOADED'; Env = @{}; Volatile = @{} }
    if ($LoadedHives -notcontains $Sid) { return [pscustomobject]$res }
    $wanted = @('TEMP', 'TMP') + @($VarNames)
    try {
        $k = [Microsoft.Win32.Registry]::Users.OpenSubKey("$Sid\Environment")
        if ($null -eq $k) { $res.Status = 'MISSING'; return [pscustomobject]$res }
        foreach ($n in $k.GetValueNames()) {
            if ($wanted -contains $n) {
                $res.Env[$n] = [string]$k.GetValue($n, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            }
        }
        $k.Close()
        $res.Status = 'OK'
        try {
            $v = [Microsoft.Win32.Registry]::Users.OpenSubKey("$Sid\Volatile Environment")
            if ($v) {
                foreach ($n in @('LOCALAPPDATA', 'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH', 'APPDATA')) {
                    $val = $v.GetValue($n, $null)
                    if ($val) { $res.Volatile[$n] = [string]$val }
                }
                $v.Close()
            }
        # Volatile environment unreadable: expansion falls back to the profile's default folders (documented limit).
        } catch { $null = $_ }
    } catch { $res.Status = 'DENIED' }
    return [pscustomobject]$res
}

function Expand-AtmProfileValue {
    # Expands %VARS% in another user's registry value using THAT user's profile, never the caller's.
    param([string]$Value, [string]$ProfilePath, [hashtable]$Volatile)
    if (-not $Value) { return $null }
    $map = @{
        'USERPROFILE'  = $ProfilePath
        'LOCALAPPDATA' = $(if ($Volatile.ContainsKey('LOCALAPPDATA')) { $Volatile['LOCALAPPDATA'] } else { Join-AtmPath $ProfilePath 'AppData\Local' })
        'APPDATA'      = $(if ($Volatile.ContainsKey('APPDATA')) { $Volatile['APPDATA'] } else { Join-AtmPath $ProfilePath 'AppData\Roaming' })
        'SYSTEMROOT'   = $env:SystemRoot
        'WINDIR'       = $env:SystemRoot
        'SYSTEMDRIVE'  = $env:SystemDrive
    }
    if ($Volatile.ContainsKey('HOMEDRIVE')) { $map['HOMEDRIVE'] = $Volatile['HOMEDRIVE'] }
    if ($Volatile.ContainsKey('HOMEPATH')) { $map['HOMEPATH'] = $Volatile['HOMEPATH'] }
    $out = [regex]::Replace($Value, '%([^%]+)%', {
            param($m)
            $k = $m.Groups[1].Value.ToUpperInvariant()
            if ($map.ContainsKey($k) -and $map[$k]) { return $map[$k] }
            return $m.Value
        })
    if ($out -match '%[^%]+%') { return $null }
    return $out
}

function Get-AtmProfiles {
    # Generic Windows profile discovery. Provider-declared variables are collected into EnvValues
    # (name -> values from the user's registry and, for the current user, the current process).
    param($Identity, [string[]]$VarNames = @())
    $profiles = New-Object System.Collections.Generic.List[object]
    $loaded = @()
    # Loaded hives unknown: no profile is assumed to be loaded.
    try { $loaded = [Microsoft.Win32.Registry]::Users.GetSubKeyNames() } catch { $loaded = @() }
    $pl = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList')
    $profilesDir = $null
    # Not resolvable: residual profile folders are not listed (documented limit); ProfileList profiles are unaffected.
    try { $profilesDir = [Environment]::ExpandEnvironmentVariables([string]$pl.GetValue('ProfilesDirectory')) } catch { $profilesDir = $null }
    $known = @{}

    foreach ($sidKey in $pl.GetSubKeyNames()) {
        $k = $pl.OpenSubKey($sidKey)
        if ($null -eq $k) { continue }
        $img = [string]$k.GetValue('ProfileImagePath')
        $k.Close()
        $sid = $sidKey
        $notes = New-Object System.Collections.Generic.List[string]
        if ($sidKey -like '*.bak') { $sid = $sidKey.Substring(0, $sidKey.Length - 4); $notes.Add('ENTRADA_PROFILELIST_.BAK (' + (Get-AtmText 'note.bak') + ')') }
        $userName = '<desconhecido>'
        try { $userName = (New-Object Security.Principal.SecurityIdentifier($sid)).Translate([Security.Principal.NTAccount]).Value } catch { $notes.Add('SID_NAO_TRADUZIVEL (' + (Get-AtmText 'note.sidUnresolved') + ')') }
        $profilePath = $null
        if ($img) { $profilePath = Get-AtmNormalizedPath $img }
        if ($profilePath) { $known[$profilePath.ToLowerInvariant()] = $true }
        $special = $sid -in @('S-1-5-18', 'S-1-5-19', 'S-1-5-20')
        $envInfo = Get-AtmUserEnvironment -Sid $sid -LoadedHives $loaded -VarNames $VarNames

        $temps = New-Object System.Collections.Generic.List[object]
        $envValues = @{}
        $envKnown = ($envInfo.Status -eq 'OK')
        if ($profilePath) {
            $tempFromReg = $null
            if ($envInfo.Status -eq 'OK' -and $envInfo.Env.ContainsKey('TEMP')) {
                $tempFromReg = Expand-AtmProfileValue -Value $envInfo.Env['TEMP'] -ProfilePath $profilePath -Volatile $envInfo.Volatile
                if (-not $tempFromReg) { $notes.Add('TEMP_DO_REGISTRO_NAO_EXPANDIVEL (' + (Get-AtmText 'note.tempNotExpandable') + ')') }
            }
            if ($tempFromReg) { $temps.Add([pscustomobject]@{ TempPath = $tempFromReg; Source = (Get-AtmText 'src.registryTemp') }) }
            else {
                $temps.Add([pscustomobject]@{ TempPath = (Join-AtmPath $profilePath 'AppData\Local\Temp'); Source = (Get-AtmText 'src.default' $envInfo.Status) })
            }
            if ($sid -eq 'S-1-5-18') { $temps.Add([pscustomobject]@{ TempPath = (Join-AtmPath $env:SystemRoot 'Temp'); Source = (Get-AtmText 'src.systemTemp') }) }
            foreach ($vn in $VarNames) {
                $vals = @()
                if ($envInfo.Status -eq 'OK' -and $envInfo.Env.ContainsKey($vn)) {
                    $x = Expand-AtmProfileValue -Value $envInfo.Env[$vn] -ProfilePath $profilePath -Volatile $envInfo.Volatile
                    if ($x) { $vals += $x } else { $notes.Add("$($vn)_DO_REGISTRO_NAO_EXPANDIVEL") }
                }
                if ($Identity -and $sid -eq $Identity.Sid) {
                    $pv = [Environment]::GetEnvironmentVariable($vn, 'Process')
                    if ($pv) { $vals += $pv }
                }
                if ($vals.Count -gt 0) { $envValues[$vn] = @($vals | Select-Object -Unique) }
            }
            if ($Identity -and $sid -eq $Identity.Sid) {
                if ($env:TEMP) { $temps.Add([pscustomobject]@{ TempPath = $env:TEMP; Source = (Get-AtmText 'src.processTemp') }) }
                $envKnown = $true
            }
        } else {
            $notes.Add('PROFILEIMAGEPATH_AUSENTE')
        }
        $profiles.Add([pscustomobject]@{
                Sid            = $sid
                UserName       = $userName
                ProfilePath    = $profilePath
                Loaded         = ($loaded -contains $sid)
                Special        = $special
                Origin         = $(if ($sidKey -like '*.bak') { 'ProfileList(.bak)' } else { 'ProfileList' })
                EnvStatus      = $envInfo.Status
                TempCandidates = $temps.ToArray()
                EnvValues      = $envValues
                EnvKnown       = $envKnown
                Notes          = $notes.ToArray()
            })
    }

    # Non-user directories declared by Windows itself (ProfileList values 'Public' and 'Default').
    # 'Public' is shown as 'Publico' in localized Explorer; it is a SHARED directory, not a user account.
    $nonUser = @{}
    foreach ($vn in @('Public', 'Default')) {
        try {
            $v = [string]$pl.GetValue($vn)
            if ($v) { $np = Get-AtmNormalizedPath ([Environment]::ExpandEnvironmentVariables($v)); if ($np) { $nonUser[$np.ToLowerInvariant()] = $vn } }
        # Unreadable: the folder is treated as a residual profile, which is more restrictive (other-user and owner gates).
        } catch { $v = $null }
    }
    $pl.Close()

    # Other directories under ProfilesDirectory (one level only): shared/template dirs declared by Windows,
    # or residual directories with no ProfileList entry. Reparse points (e.g. 'All Users', 'Default User')
    # are recorded and never traversed.
    $script:AtmDiscoveryNotes = New-Object System.Collections.Generic.List[string]
    if ($profilesDir) {
        $pd = Get-AtmNormalizedPath $profilesDir
        $entries = @()
        try { $entries = (New-Object IO.DirectoryInfo($pd)).GetDirectories() } catch { $script:AtmDiscoveryNotes.Add((Get-AtmText 'note.profilesDirUnreadable' $pd $_.Exception.GetType().Name)) }
        foreach ($d in $entries) {
            if (($d.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { $script:AtmDiscoveryNotes.Add((Get-AtmText 'note.reparseSkipped' $d.FullName)); continue }
            $key = $d.FullName.ToLowerInvariant()
            if ($known.ContainsKey($key)) { continue }
            $kindName = $null
            if ($nonUser.ContainsKey($key)) { $kindName = $nonUser[$key] }
            $sidLabel = $(if ($kindName -eq 'Public') { 'SHARED-PUBLIC' } elseif ($kindName -eq 'Default') { 'TEMPLATE-DEFAULT' } else { 'RESIDUAL' })
            $label = $(if ($kindName -eq 'Public') { Get-AtmText 'label.shared' $d.Name } elseif ($kindName -eq 'Default') { Get-AtmText 'label.template' $d.Name } else { Get-AtmText 'label.residual' $d.Name })
            $origin = $(if ($kindName -eq 'Public') { Get-AtmText 'origin.shared' } elseif ($kindName -eq 'Default') { Get-AtmText 'origin.template' } else { Get-AtmText 'origin.residual' })
            $note = $(if ($kindName) { 'NAO_E_PERFIL_DE_USUARIO: ' + (Get-AtmText 'note.notUser') } else { 'PERFIL_RESIDUAL: ' + (Get-AtmText 'note.residual') })
            $profiles.Add([pscustomobject]@{
                    Sid            = $sidLabel
                    UserName       = $label
                    ProfilePath    = $d.FullName
                    Loaded         = $false
                    Special        = $false
                    Origin         = $origin
                    EnvStatus      = 'N/A'
                    TempCandidates = @([pscustomobject]@{ TempPath = (Join-AtmPath $d.FullName 'AppData\Local\Temp'); Source = (Get-AtmText 'src.defaultNoSid') })
                    EnvValues      = @{}
                    EnvKnown       = $false
                    Notes          = @($note)
                })
        }
    }
    return $profiles.ToArray()
}

# ---------------------------------------------------------------------------------------------
# Processes (single CIM pass)
# ---------------------------------------------------------------------------------------------

function Get-AtmProcessSnapshot {
    param($Override)
    $snap = [ordered]@{ Failed = $false; Error = $null; Processes = @(); Total = 0; Readable = 0; Uninspectable = 0; UninspectableByName = @{} }
    $raw = $null
    if ($null -ne $Override) { $raw = @($Override) }
    else {
        try {
            $raw = @(Get-CimInstance -ClassName Win32_Process -Property ProcessId, Name, ParentProcessId, CommandLine, CreationDate -ErrorAction Stop |
                ForEach-Object {
                    [pscustomobject]@{ ProcessId = [int]$_.ProcessId; Name = $_.Name; ParentProcessId = [int]$_.ParentProcessId; CommandLine = $_.CommandLine; CreationDate = $_.CreationDate }
                })
        } catch {
            $snap.Failed = $true; $snap.Error = $_.Exception.Message
            return [pscustomobject]$snap
        }
    }
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($p in $raw) {
        $cu = $null
        # Unparseable start time: no start time, so a session is never considered ended.
        if ($p.CreationDate) { try { $cu = ([datetime]$p.CreationDate).ToUniversalTime() } catch { $cu = $null } }
        $list.Add([pscustomobject]@{ Pid = [int]$p.ProcessId; Name = [string]$p.Name; ParentPid = [int]$p.ParentProcessId; CommandLine = $p.CommandLine; CreationUtc = $cu })
        if ($p.CommandLine) { $snap.Readable++ }
        else {
            $snap.Uninspectable++
            $n = [string]$p.Name
            if ($snap.UninspectableByName.ContainsKey($n)) { $snap.UninspectableByName[$n]++ } else { $snap.UninspectableByName[$n] = 1 }
        }
    }
    $snap.Processes = $list.ToArray()
    $snap.Total = $list.Count
    return [pscustomobject]$snap
}

function Get-AtmSelfChainPids {
    # The current process and the launcher chain that carries our own arguments (cmd shim) are excluded,
    # otherwise `clean -Path X` would see its own command line as a reference to X.
    param($Snapshot, [int]$SelfPid, [string[]]$Markers)
    $byPid = @{}
    foreach ($p in $Snapshot.Processes) { $byPid[$p.Pid] = $p }
    $result = New-Object System.Collections.Generic.List[int]
    $result.Add($SelfPid)
    $cur = $byPid[$SelfPid]
    $guard = 0
    while ($cur -and $guard -lt 8) {
        $guard++
        $parent = $byPid[$cur.ParentPid]
        if (-not $parent -or -not $parent.CommandLine) { break }
        $cl = $parent.CommandLine.ToLowerInvariant()
        $hit = $false
        foreach ($m in $Markers) { if ($m -and $cl.Contains($m.ToLowerInvariant())) { $hit = $true; break } }
        if (-not $hit) { break }
        $result.Add($parent.Pid)
        $cur = $parent
    }
    return $result.ToArray()
}

# ---------------------------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------------------------

function New-AtmPartition {
    param([Alias('Profile')]$ProfileInfo, $Base, [string]$Slug, [string]$Name, [string]$Kind, $Stats, [string]$Path)
    [pscustomobject]@{
        Provider              = $Base.Provider.Id
        Kind                  = $Kind            # SessionRoot | UnrecognizedDir | LooseFile | BaseLooseFiles | ReparsePoint | Unmeasured | NotScanned
        Sid                   = $ProfileInfo.Sid
        UserName              = $ProfileInfo.UserName
        ProfilePath           = $ProfileInfo.ProfilePath
        TempPath              = $Base.TempPath
        BasePath              = $Base.Path
        Slug                  = $Slug
        Project               = $null
        ProjectIdentified     = $false
        ProjectSource         = $null
        Name                  = $Name
        Path                  = $Path
        CreationTimeUtc       = $(if ($Stats) { $Stats.CreationTimeUtc } else { $null })
        LastWriteTimeUtc      = $(if ($Stats) { $Stats.LastWriteTimeUtc } else { $null })
        NewestWriteTimeUtc    = $(if ($Stats -and $Stats.NewestWriteTimeUtc -ne [datetime]::MinValue) { $Stats.NewestWriteTimeUtc } else { $null })
        Bytes                 = $(if ($Stats) { [long]$Stats.Bytes } else { 0L })
        AllocatedBytesEstimate = $(if ($Stats) { [long]$Stats.AllocatedBytesEstimate } else { 0L })
        Files                 = $(if ($Stats) { [long]$Stats.Files } else { 0L })
        Dirs                  = $(if ($Stats) { [long]$Stats.Dirs } else { 0L })
        DirectChildren        = $(if ($Stats) { [long]$Stats.DirectChildren } else { 0L })
        ReparsePoints         = $(if ($Stats) { [long]$Stats.ReparsePoints } else { 0L })
        ProtectedFiles        = $(if ($Stats) { [long]$Stats.ReadOnlyOrSystemFiles } else { 0L })
        ErrorCount            = $(if ($Stats) { [long]$Stats.ErrorCount } else { 0L })
        ErrorSamples          = @(if ($Stats) { $Stats.ErrorSamples })
        ReparseSamples        = @(if ($Stats) { $Stats.ReparseSamples })
        MeasurementComplete   = $(if ($Stats) { [bool]$Stats.MeasurementComplete } else { $false })
        Fingerprint           = $(if ($Stats) { Get-AtmFingerprint $Stats } else { $null })
        DirectRefs            = New-Object System.Collections.Generic.List[string]
        AncestorRefs          = New-Object System.Collections.Generic.List[string]
        AmbiguousRefs         = New-Object System.Collections.Generic.List[string]
        Session               = $null
        TranscriptLastWriteUtc = $null
        Flags                 = New-Object System.Collections.Generic.List[string]
        Evidence              = New-Object System.Collections.Generic.List[string]
        Class                 = $null
    }
}

function Get-AtmFingerprint {
    param($Stats)
    $s = '{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}' -f $Stats.Files, $Stats.Dirs, $Stats.Bytes, $Stats.NewestWriteTimeUtc.Ticks, $Stats.ReparsePoints, $Stats.ErrorCount, $Stats.CreationTimeUtc.Ticks, $Stats.ReadOnlyOrSystemFiles
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($s)) } finally { $sha.Dispose() }
    return (-join ($h[0..7] | ForEach-Object { $_.ToString('X2') }))
}

function Get-AtmRegistryKey { param([string]$ProviderId, [Alias('Profile')]$ProfileInfo) return ($ProviderId + '|' + $ProfileInfo.Sid + '|' + $ProfileInfo.ProfilePath) }

function Get-AtmProfileRegistries {
    param($Registries, [Alias('Profile')]$ProfileInfo)
    $suffix = '|' + $ProfileInfo.Sid + '|' + $ProfileInfo.ProfilePath
    return @($Registries.Keys | Where-Object { $_.EndsWith($suffix) } | ForEach-Object { $r = $Registries[$_]; [pscustomobject]@{ Provider = $_.Substring(0, $_.Length - $suffix.Length); Readable = $r.Readable; Unparseable = $r.Unparseable; Entries = $r.Entries } })
}

function Add-AtmFlag { param($Partition, [string]$Flag) if (-not $Partition.Flags.Contains($Flag)) { $Partition.Flags.Add($Flag) } }

function Invoke-AtmInventory {
    <#
      Full read-only inventory.
      -ProfilesOverride / -ProcessesOverride / -NowUtc / -IdentityOverride exist for automated tests.
      -OnlyRootPath: measure only that partition (others are listed as NotScanned) - used by clean revalidation.
    #>
    param(
        $ProfilesOverride,
        $ProcessesOverride,
        $NowUtc,
        $IdentityOverride,
        [string]$OnlyRootPath,
        [string[]]$SelfMarkers = @(),
        [switch]$NoProgress,
        [scriptblock]$ProgressCallback,
        $Providers,
        [string]$ConfigDir = (Join-AtmPath (Split-Path $PSScriptRoot -Parent) 'config')
    )
    Initialize-AtmNative
    $startUtc = [datetime]::UtcNow
    $now = $(if ($null -ne $NowUtc) { ([datetime]$NowUtc).ToUniversalTime() } else { $startUtc })
    $config = Get-AtmConfig -ConfigDir $ConfigDir
    $identity = $(if ($IdentityOverride) { $IdentityOverride } else { Get-AtmCurrentIdentity })
    $progress = (-not $NoProgress) -and ($null -ne $ProgressCallback)
    # Only providers with the 'temp' capability describe temporary directories; runtime-only providers (contract v2)
    # are used by the diagnose engine.
    $providerList = @(@(if ($null -ne $Providers) { $Providers } else { Get-AtmProviders }) | Where-Object { (Get-AtmProviderCapabilities $_) -ccontains 'temp' })
    if ($providerList.Count -eq 0) { throw (Get-AtmText 'err.noProvider') }

    # Phase 1: profiles
    $script:AtmDiscoveryNotes = New-Object System.Collections.Generic.List[string]
    if ($progress) { & $ProgressCallback (5) (Get-AtmText 'progress.1') }
    $profiles = @(if ($null -ne $ProfilesOverride) { $ProfilesOverride } else { Get-AtmProfiles -Identity $identity -VarNames (Get-AtmProviderEnvVarNames $providerList) })

    # Phase 2: resolve and validate bases (<TEMP>\<provider.TempSubdir>) for every profile x provider
    if ($progress) { & $ProgressCallback (10) (Get-AtmText 'progress.2') }
    $bases = New-Object System.Collections.Generic.List[object]
    $baseByPath = @{}
    $profileStatus = @{}
    foreach ($pr in $profiles) {
        $st = New-Object System.Collections.Generic.List[object]
        foreach ($prov in $providerList) {
            $cands = @($pr.TempCandidates) + @(& $prov.GetExtraTempDirs $pr)
            foreach ($tc in $cands) {
                if (-not $tc) { continue }
                $tempNorm = Get-AtmNormalizedPath $tc.TempPath
                $basePath = $null
                if ($tempNorm) { $basePath = Get-AtmNormalizedPath (Join-AtmPath $tempNorm $prov.TempSubdir) }
                if (-not $basePath) { $st.Add([pscustomobject]@{ Provider = $prov.Id; BasePath = $tc.TempPath; Source = $tc.Source; Status = 'INVALID'; At = $null }); continue }
                $key = $basePath.ToLowerInvariant()
                if ($baseByPath.ContainsKey($key)) {
                    $existing = $baseByPath[$key]
                    if ($existing.Sid -ne $pr.Sid -or $existing.Profile.ProfilePath -ne $pr.ProfilePath) { $existing.Shared = $true; $existing.SharedWith += $pr.Sid }
                    $st.Add([pscustomobject]@{ Provider = $prov.Id; BasePath = $basePath; Source = $tc.Source; Status = $(if ($existing.Sid -eq $pr.Sid -and $existing.Profile.ProfilePath -eq $pr.ProfilePath) { 'DUPLICATE_SAME_PROFILE' } else { 'SHARED_WITH_' + $existing.Sid }); At = $null })
                    continue
                }
                $chain = Test-AtmPathChain $basePath
                $status = $chain.Status
                if ($status -eq 'OK') {
                    try { if (([IO.File]::GetAttributes($basePath) -band [IO.FileAttributes]::Directory) -eq 0) { $status = 'NOT_DIRECTORY' } } catch { $status = 'INACCESSIBLE' }
                }
                $b = [pscustomobject]@{
                    Sid = $pr.Sid; Profile = $pr; Provider = $prov; TempPath = $tempNorm; Path = $basePath; Source = $tc.Source; Status = $status; At = $chain.At
                    Shared = $false; SharedWith = @(); Slugs = @{}; Partitions = New-Object System.Collections.Generic.List[object]
                    EnumerationError = $null; StructureRecognized = $true
                }
                # %WINDIR%\Temp is writable by every user: never a single-owner base.
                if ($basePath.StartsWith((Join-AtmPath $env:SystemRoot 'Temp') + '\', [StringComparison]::OrdinalIgnoreCase)) { $b.Shared = $true; $b.SharedWith += 'WINDOWS_TEMP' }
                $baseByPath[$key] = $b
                $bases.Add($b)
                $st.Add([pscustomobject]@{ Provider = $prov.Id; BasePath = $basePath; Source = $tc.Source; Status = $status; At = $chain.At })
            }
        }
        $profileStatus[$pr.Sid + '|' + $pr.ProfilePath] = $st.ToArray()
    }

    # Phase 3: filesystem inventory, one pass per partition root
    $partitions = New-Object System.Collections.Generic.List[object]
    $okBases = @($bases | Where-Object { $_.Status -eq 'OK' })
    $bi = 0
    foreach ($b in $okBases) {
        $bi++
        if ($progress) { & $ProgressCallback ((15 + [int](50 * $bi / [math]::Max(1, $okBases.Count)))) (Get-AtmText 'progress.3' $bi $okBases.Count $b.Path) }
        $cluster = [AgentTempManager.AtmNative]::GetClusterSize($b.Path.Substring(0, 3))
        $children = $null
        try { $children = (New-Object IO.DirectoryInfo($b.Path)).GetFileSystemInfos() }
        catch { $b.EnumerationError = $_.Exception.GetType().Name; $b.Status = 'ENUMERATION_FAILED'; continue }

        $looseStats = $null
        $recognizedSlugs = 0
        foreach ($c in $children) {
            $isReparse = ($c.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
            $isDir = ($c.Attributes -band [IO.FileAttributes]::Directory) -ne 0
            if ($isReparse) {
                $p = New-AtmPartition -ProfileInfo $b.Profile -Base $b -Slug $null -Name $c.Name -Kind 'ReparsePoint' -Stats $null -Path $c.FullName
                $p.ReparsePoints = 1; Add-AtmFlag $p 'REPARSE_POINT'; Add-AtmFlag $p 'NOT_SESSION_ROOT'
                $b.Partitions.Add($p); continue
            }
            if (-not $isDir) {
                # Loose files directly under <TEMP>\claude form ONE partition per base.
                if (-not $looseStats) { $looseStats = [pscustomobject]@{ Bytes = 0L; Alloc = 0L; Files = 0L; Newest = $null; Protected = 0L; Names = 0 } }
                $looseStats.Files++
                $looseStats.Bytes += $c.Length
                $looseStats.Alloc += [AgentTempManager.AtmNative]::EstimateAllocated($c.FullName, $c.Length, $cluster)
                if (($c.Attributes -band ([IO.FileAttributes]::ReadOnly -bor [IO.FileAttributes]::System)) -ne 0) { $looseStats.Protected++ }
                if (-not $looseStats.Newest -or $c.LastWriteTimeUtc -gt $looseStats.Newest) { $looseStats.Newest = $c.LastWriteTimeUtc }
                continue
            }
            $slug = $c.Name
            $slugRec = [pscustomobject]@{ Name = $slug; Path = $c.FullName; Roots = @{}; Partitions = New-Object System.Collections.Generic.List[object]; Recognized = ($slug -match $b.Provider.ScopePattern) }
            $b.Slugs[$slug.ToLowerInvariant()] = $slugRec
            $roots = $null
            try { $roots = $c.GetFileSystemInfos() }
            catch {
                $p = New-AtmPartition -ProfileInfo $b.Profile -Base $b -Slug $slug -Name (Get-AtmText 'part.wholeScope') -Kind 'Unmeasured' -Stats $null -Path $c.FullName
                $p.ErrorCount = 1; $p.ErrorSamples = @($_.Exception.GetType().Name + ': ' + $c.FullName)
                Add-AtmFlag $p 'READ_ERRORS'; Add-AtmFlag $p 'MEASUREMENT_INCOMPLETE'; Add-AtmFlag $p 'NOT_SESSION_ROOT'
                $b.Partitions.Add($p); $slugRec.Partitions.Add($p); continue
            }
            $hasUuid = $false
            foreach ($r in $roots) {
                $rPath = $r.FullName
                $isUuid = $r.Name -match $b.Provider.RootPattern
                $rIsDir = ($r.Attributes -band [IO.FileAttributes]::Directory) -ne 0
                $rIsReparse = ($r.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
                if ($rIsDir -and $isUuid -and -not $rIsReparse) { $hasUuid = $true }
                $kind = $(if ($rIsReparse) { 'ReparsePoint' } elseif (-not $rIsDir) { 'LooseFile' } elseif ($isUuid) { 'SessionRoot' } else { 'UnrecognizedDir' })
                $stats = $null
                if ($OnlyRootPath -and -not [string]::Equals($rPath, $OnlyRootPath, [StringComparison]::OrdinalIgnoreCase)) {
                    $kind2 = 'NotScanned'
                    $p = New-AtmPartition -ProfileInfo $b.Profile -Base $b -Slug $slug -Name $r.Name -Kind $kind2 -Stats $null -Path $rPath
                } else {
                    $stats = [AgentTempManager.AtmScanner]::ScanTree($rPath, $script:AtmMaxSamples, $cluster)
                    if ($stats.RootIsReparsePoint) { $kind = 'ReparsePoint' }
                    if (-not $stats.Exists -and $stats.ErrorCount -eq 0) { continue }   # removed between listing and scan
                    $p = New-AtmPartition -ProfileInfo $b.Profile -Base $b -Slug $slug -Name $r.Name -Kind $kind -Stats $stats -Path $rPath
                }
                $slugRec.Roots[$r.Name.ToLowerInvariant()] = $p
                $slugRec.Partitions.Add($p)
                $b.Partitions.Add($p)
            }
            if ($hasUuid -and $slugRec.Recognized) { $recognizedSlugs++ }
        }
        if ($looseStats) {
            $p = New-AtmPartition -ProfileInfo $b.Profile -Base $b -Slug $null -Name (Get-AtmText 'part.looseFiles') -Kind 'BaseLooseFiles' -Stats $null -Path $b.Path
            $p.Bytes = $looseStats.Bytes; $p.AllocatedBytesEstimate = $looseStats.Alloc; $p.Files = $looseStats.Files
            $p.NewestWriteTimeUtc = $looseStats.Newest; $p.LastWriteTimeUtc = $looseStats.Newest; $p.ProtectedFiles = $looseStats.Protected
            $p.MeasurementComplete = $true
            $b.Partitions.Add($p)
        }
        if ($children.Count -gt 0 -and $recognizedSlugs -eq 0) { $b.StructureRecognized = $false }
        foreach ($p in $b.Partitions) { $partitions.Add($p) }
    }

    # Phase 4: processes (single pass) + self exclusion
    if ($progress) { & $ProgressCallback (70) (Get-AtmText 'progress.4') }
    $snapshot = Get-AtmProcessSnapshot -Override $ProcessesOverride
    $selfPids = @()
    if (-not $snapshot.Failed) { $selfPids = @(Get-AtmSelfChainPids -Snapshot $snapshot -SelfPid $PID -Markers $SelfMarkers) }

    # Phase 5: reference index + session registry + transcripts
    if ($progress) { & $ProgressCallback (80) (Get-AtmText 'progress.5') }
    $refStats = Find-AtmReferences -Bases $okBases -Snapshot $snapshot -SelfPids $selfPids
    $registries = @{}
    foreach ($b in $okBases) {
        $rk = Get-AtmRegistryKey -ProviderId $b.Provider.Id -ProfileInfo $b.Profile
        if (-not $registries.ContainsKey($rk)) { $registries[$rk] = & $b.Provider.GetSessionEvidence $b.Profile $snapshot }
    }

    # Phase 6: classification
    if ($progress) { & $ProgressCallback (90) (Get-AtmText 'progress.6') }
    foreach ($b in $okBases) {
        $reg = $registries[(Get-AtmRegistryKey -ProviderId $b.Provider.Id -ProfileInfo $b.Profile)]
        $evidenceNames = Get-AtmProjectEvidenceNames -Registry $reg
        foreach ($p in $b.Partitions) {
            if ($p.Slug) {
                $pj = Resolve-AtmProject -Slug $p.Slug -ProfilePath $p.ProfilePath -Config $config -Provider $b.Provider -EvidenceNames $evidenceNames
                $p.Project = $pj.Name; $p.ProjectIdentified = $pj.Identified; $p.ProjectSource = $pj.Source
            } else { $p.Project = (Get-AtmText 'project.base'); $p.ProjectIdentified = $true; $p.ProjectSource = '-' }
            Set-AtmClassification -Partition $p -Base $b -Registry $reg -Snapshot $snapshot -NowUtc $now -StartUtc $startUtc
        }
    }
    if ($progress) { & $ProgressCallback 100 (Get-AtmText 'progress.done') }

    $procCoverageComplete = (-not $snapshot.Failed) -and ($snapshot.Uninspectable -eq 0)
    $inaccessibleProfiles = @()
    foreach ($pr in $profiles) {
        $sts = $profileStatus[$pr.Sid + '|' + $pr.ProfilePath]
        $regs = @(Get-AtmProfileRegistries -Registries $registries -ProfileInfo $pr)
        $bad = @($sts | Where-Object { $_.Status -in @('INACCESSIBLE', 'ENUMERATION_FAILED', 'INVALID') })
        $enumFailed = @($bases | Where-Object { $_.Sid -eq $pr.Sid -and $_.Profile.ProfilePath -eq $pr.ProfilePath -and $_.Status -eq 'ENUMERATION_FAILED' })
        if ($bad.Count -gt 0 -or $enumFailed.Count -gt 0 -or @($regs | Where-Object { -not $_.Readable }).Count -gt 0) { $inaccessibleProfiles += $pr }
    }

    # TEMP location not verifiable: the profile's own environment (hive not loaded / access denied) could not be
    # read, so only the Windows default location was checked. Absence there proves nothing; presence there does
    # not exclude a redirected TEMP. Never reported as "no agent temp"; always counted as incomplete coverage.
    $unverifiedTemp = @()
    foreach ($pr in $profiles) {
        if ($pr.EnvStatus -in @('OK', 'N/A')) { continue }
        if ($inaccessibleProfiles -contains $pr) { continue }
        $unverifiedTemp += $pr
    }

    [pscustomobject]@{
        ToolVersion          = $script:AtmVersion
        Machine              = $env:COMPUTERNAME
        Identity             = $identity
        StartedUtc           = $startUtc
        NowUtc               = $now
        FinishedUtc          = [datetime]::UtcNow
        RecentHours          = $script:AtmRecentHours
        Providers            = @($providerList | ForEach-Object { [pscustomobject]@{ Id = $_.Id; DisplayName = $_.DisplayName; TempSubdir = $_.TempSubdir } })
        Profiles             = $profiles
        ProfileBaseStatus    = $profileStatus
        Bases                = $bases.ToArray()
        Partitions           = $partitions.ToArray()
        Snapshot             = $snapshot
        SelfPids             = $selfPids
        References           = $refStats
        Registries           = $registries
        ProcessCoverageComplete = $procCoverageComplete
        InaccessibleProfiles = $inaccessibleProfiles
        UnverifiedTempProfiles = $unverifiedTemp
        CoverageComplete     = $procCoverageComplete -and ($inaccessibleProfiles.Count -eq 0) -and ($unverifiedTemp.Count -eq 0)
        OnlyRootPath         = $OnlyRootPath
        DiscoveryNotes       = @($script:AtmDiscoveryNotes)
    }
}

function Find-AtmReferences {
    <#
      Builds an index of every audited base path (long and 8.3 forms) and resolves each process command line
      against it with IndexOf + component parsing: O(processes x bases), never O(files x processes),
      and no per-file regex. Command lines are never stored or printed.
    #>
    param($Bases, $Snapshot, [int[]]$SelfPids)
    $stats = [ordered]@{ Direct = 0; Ancestor = 0; Ambiguous = 0; Unresolved = New-Object System.Collections.Generic.List[string]; SelfExcluded = @($SelfPids) }
    if ($Snapshot.Failed) { return [pscustomobject]$stats }
    $variants = New-Object System.Collections.Generic.List[object]
    foreach ($b in $Bases) {
        $forms = @($b.Path)
        # GetShortPath returns null on API failure; an exception means the native type is unusable, which already fails initialisation.
        try { $sp = [AgentTempManager.AtmNative]::GetShortPath($b.Path); if ($sp) { $forms += $sp.TrimEnd('\') } } catch { $sp = $null }
        foreach ($f in ($forms | Select-Object -Unique)) { $variants.Add([pscustomobject]@{ Text = $f.ToLowerInvariant(); Base = $b }) }
    }
    $term = $script:AtmRefTerminators
    foreach ($proc in $Snapshot.Processes) {
        if ($SelfPids -contains $proc.Pid) { continue }
        if (-not $proc.CommandLine) { continue }
        $n = $proc.CommandLine.Replace('/', '\').ToLowerInvariant()
        while ($n.Contains('\\')) { $n = $n.Replace('\\', '\') }
        $who = "PID $($proc.Pid) ($($proc.Name))"
        foreach ($v in $variants) {
            $idx = $n.IndexOf($v.Text, [StringComparison]::Ordinal)
            while ($idx -ge 0) {
                $end = $idx + $v.Text.Length
                $b = $v.Base
                if ($end -ge $n.Length -or ($term -contains $n[$end])) {
                    foreach ($p in $b.Partitions) { $p.AncestorRefs.Add("$who -> base"); Add-AtmFlag $p 'ANCESTOR_REFERENCE' }
                    $stats.Ancestor++
                } elseif ($n[$end] -eq '\') {
                    $i = $end + 1; $sb = New-Object Text.StringBuilder
                    while ($i -lt $n.Length -and $n[$i] -ne '\' -and -not ($term -contains $n[$i])) { [void]$sb.Append($n[$i]); $i++ }
                    $slugTok = $sb.ToString()
                    if ($slugTok -eq '') {
                        foreach ($p in $b.Partitions) { $p.AncestorRefs.Add("$who -> base"); Add-AtmFlag $p 'ANCESTOR_REFERENCE' }
                        $stats.Ancestor++
                    } elseif (-not $b.Slugs.ContainsKey($slugTok)) {
                        if ($slugTok.IndexOfAny([char[]]'~*?') -ge 0) {
                            foreach ($p in $b.Partitions) { $p.AmbiguousRefs.Add((Get-AtmText 'ref.ambiguousBase' $who)); Add-AtmFlag $p 'AMBIGUOUS_REFERENCE' }
                            $stats.Ambiguous++
                        } else {
                            # Unresolved name under the base (e.g. "<uuid>suffix", a dir created after the scan,
                            # an encoding we do not parse): never ignore it - every partition of the base is ambiguous.
                            $stats.Unresolved.Add((Get-AtmText 'ref.unresolved' $who $b.Path))
                            foreach ($p in $b.Partitions) { $p.AmbiguousRefs.Add((Get-AtmText 'ref.unresolvedBase' $who)); Add-AtmFlag $p 'AMBIGUOUS_REFERENCE' }
                            $stats.Ambiguous++
                        }
                    } else {
                        $slug = $b.Slugs[$slugTok]
                        if ($i -lt $n.Length -and $n[$i] -eq '\') {
                            $j = $i + 1; $sb2 = New-Object Text.StringBuilder
                            while ($j -lt $n.Length -and $n[$j] -ne '\' -and -not ($term -contains $n[$j])) { [void]$sb2.Append($n[$j]); $j++ }
                            $rootTok = $sb2.ToString()
                            if ($rootTok -eq '') {
                                foreach ($p in $slug.Partitions) { $p.AncestorRefs.Add("$who -> projeto"); Add-AtmFlag $p 'ANCESTOR_REFERENCE' }
                                $stats.Ancestor++
                            } elseif ($slug.Roots.ContainsKey($rootTok)) {
                                $slug.Roots[$rootTok].DirectRefs.Add($who)
                                $stats.Direct++
                            } elseif ($rootTok.IndexOfAny([char[]]'~*?') -ge 0) {
                                foreach ($p in $slug.Partitions) { $p.AmbiguousRefs.Add((Get-AtmText 'ref.ambiguousScope' $who)); Add-AtmFlag $p 'AMBIGUOUS_REFERENCE' }
                                $stats.Ambiguous++
                            } else {
                                $stats.Unresolved.Add((Get-AtmText 'ref.unresolved' $who $slug.Path))
                                foreach ($p in $slug.Partitions) { $p.AmbiguousRefs.Add((Get-AtmText 'ref.unresolvedScope' $who)); Add-AtmFlag $p 'AMBIGUOUS_REFERENCE' }
                                $stats.Ambiguous++
                            }
                        } else {
                            foreach ($p in $slug.Partitions) { $p.AncestorRefs.Add("$who -> projeto"); Add-AtmFlag $p 'ANCESTOR_REFERENCE' }
                            $stats.Ancestor++
                        }
                    }
                }
                $idx = $n.IndexOf($v.Text, $end, [StringComparison]::Ordinal)
            }
        }
    }
    return [pscustomobject]$stats
}

function Set-AtmClassification {
    param($Partition, $Base, $Registry, $Snapshot, [datetime]$NowUtc, [datetime]$StartUtc)
    $p = $Partition
    if ($p.Kind -eq 'NotScanned') { $p.Class = 'NOT_SCANNED'; return }
    if ($p.Kind -ne 'SessionRoot') { Add-AtmFlag $p 'NOT_SESSION_ROOT' }
    if ($p.Kind -eq 'BaseLooseFiles') { Add-AtmFlag $p 'NOT_SESSION_ROOT' }
    if ($p.ReparsePoints -gt 0) { Add-AtmFlag $p 'REPARSE_POINT' }
    if (-not $p.MeasurementComplete) { Add-AtmFlag $p 'MEASUREMENT_INCOMPLETE' }
    if ($p.ErrorCount -gt 0) { Add-AtmFlag $p 'READ_ERRORS' }
    if ($p.ProtectedFiles -gt 0) { Add-AtmFlag $p 'PROTECTED_FILES' }
    if ($Base.Shared) { Add-AtmFlag $p 'SHARED_TEMP' }
    if (-not $Base.StructureRecognized) { Add-AtmFlag $p 'BASE_STRUCTURE_UNRECOGNIZED' }
    if ($p.Slug -and -not ($p.Slug -match $Base.Provider.ScopePattern)) { Add-AtmFlag $p 'UNRECOGNIZED_SLUG' }
    if ($p.Sid -in @('RESIDUAL', 'SHARED-PUBLIC', 'TEMPLATE-DEFAULT')) { Add-AtmFlag $p 'RESIDUAL_PROFILE' }
    if ($Snapshot.Failed) { Add-AtmFlag $p 'PROCESS_SNAPSHOT_FAILED' }
    if (-not $Registry.Readable) { Add-AtmFlag $p 'SESSION_REGISTRY_UNREADABLE' }
    if ($Registry.Unparseable -gt 0) { Add-AtmFlag $p 'SESSION_REGISTRY_ENTRY_UNPARSEABLE' }
    $profileObj = $Base.Profile
    $prov = $Base.Provider
    if (-not (& $prov.GetConfigDirs $profileObj).Known) { Add-AtmFlag $p 'CONFIG_DIR_UNKNOWN' }

    $live = $false
    if ($p.Kind -eq 'SessionRoot') {
        $sid = $p.Name.ToLowerInvariant()
        $regMatches = @($Registry.Entries | Where-Object { $_.SessionId -eq $sid })
        foreach ($m in $regMatches) {
            switch ($m.State) {
                'LIVE' { $live = $true; $p.Evidence.Add('SESSAO_VIVA: ' + (Get-AtmText 'ev.live' $prov.DisplayName $m.Pid)) }
                'LIVE_UNVERIFIED' { Add-AtmFlag $p 'SESSION_PID_ALIVE_UNVERIFIED'; $p.Evidence.Add((Get-AtmText 'ev.liveUnverified' $m.Pid)) }
                'PID_REUSED' { $p.Evidence.Add((Get-AtmText 'ev.pidReused' $m.Pid)) }
                'DEAD' { $p.Evidence.Add((Get-AtmText 'ev.dead' $m.Pid)) }
                'UNVERIFIABLE' { Add-AtmFlag $p 'SESSION_LIVENESS_UNVERIFIABLE' }
            }
        }
        if ($regMatches.Count -gt 0) { $p.Session = ($regMatches | ForEach-Object { "$($_.State):$($_.Pid)" }) -join ',' }
        $t = & $prov.GetActivityEvidence $profileObj $p.Slug $p.Name
        if (-not $t.Readable) { Add-AtmFlag $p 'TRANSCRIPTS_UNREADABLE' }
        if ($t.LastWriteUtc) {
            $p.TranscriptLastWriteUtc = $t.LastWriteUtc
            if (($NowUtc - $t.LastWriteUtc).TotalHours -lt $script:AtmRecentHours) { Add-AtmFlag $p 'TRANSCRIPT_RECENT'; $p.Evidence.Add((Get-AtmText 'ev.transcriptRecent' $script:AtmRecentHours)) }
        }
    }
    foreach ($r in $p.DirectRefs) { $p.Evidence.Add('REFERENCIA_DIRETA: ' + $r) }

    $newest = $p.NewestWriteTimeUtc
    $recent = $false
    if ($newest) {
        if ($newest -gt $NowUtc.AddMinutes(5)) { Add-AtmFlag $p 'CLOCK_SKEW'; $recent = $true }
        elseif (($NowUtc - $newest).TotalHours -lt $script:AtmRecentHours) { $recent = $true }
        if ($newest -ge $StartUtc) { $p.Evidence.Add((Get-AtmText 'ev.writeDuringAudit')) }
    }

    if ($live -or $p.DirectRefs.Count -gt 0) { $p.Class = 'ACTIVE_EVIDENCE' }
    elseif ($recent) { $p.Class = 'RECENT' }
    elseif ($p.Kind -eq 'SessionRoot' -and $newest -and $p.MeasurementComplete -and $p.Flags.Count -eq 0) { $p.Class = 'ORPHAN_SUSPECTED' }
    else { $p.Class = 'LIVENESS_UNKNOWN' }
}

