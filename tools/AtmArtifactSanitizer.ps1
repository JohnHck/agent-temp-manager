<#
.SYNOPSIS
  Replaces identifiers of the machine running a test or a CI job with stable placeholders (FINAL-B, artifact privacy).
  Dot-sourced by tests\Run-Tests.ps1 (test details, console and report) and tools\Protect-AtmArtifact.ps1 (CI
  artifacts before upload). Placeholders keep the structure of a message, so a failure stays readable:
  <profile>, <temp>, <user-path>, <account>, <machine>, <domain>, <profile-name>, <sid>.
#>

# Words of the product's own text that a profile folder may also be named (same list as Test-AtmPrivacy.ps1): never
# replaced, or the product's text itself would be rewritten.
$script:AtmSanitizerProductWords = @('installer')

function Get-AtmArtifactIdentifiers {
    # Literal identifiers of this machine, longest first (a path before the names it contains). Each value is also
    # matched in its JSON-escaped form (doubled backslashes).
    $pairs = New-Object System.Collections.Generic.List[object]
    $add = {
        param([string]$Value, [string]$Placeholder, [int]$Min = 3)
        if ($Value -and $Value.Length -ge $Min) { $pairs.Add([pscustomobject]@{ Value = $Value; Placeholder = $Placeholder }) }
    }
    $paths = New-Object System.Collections.Generic.List[string]
    foreach ($p in @([IO.Path]::GetTempPath(), $env:TEMP, $env:TMP)) { if ($p) { $paths.Add($p.TrimEnd('\')) } }
    foreach ($p in @($paths)) { & $add $p '<temp>' 4; try { & $add ((New-Object IO.DirectoryInfo($p)).FullName.TrimEnd('\')) '<temp>' 4 } catch { $null = $_ } }
    foreach ($p in @($env:USERPROFILE, $env:LOCALAPPDATA, $env:APPDATA)) { if ($p) { & $add $p.TrimEnd('\') '<profile>' 4 } }
    & $add $env:USERNAME '<account>'
    if ($env:COMPUTERNAME) { & $add $env:COMPUTERNAME '<machine>' }
    if ($env:USERDOMAIN -and $env:USERDOMAIN -ne $env:COMPUTERNAME -and $env:USERDOMAIN -ne 'WORKGROUP') { & $add $env:USERDOMAIN '<domain>' }
    try {
        $pl = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList')
        if ($null -ne $pl) {
            foreach ($s in $pl.GetSubKeyNames()) {
                if ($s -notlike 'S-1-5-21-*') { continue }
                $img = [string]$pl.OpenSubKey($s).GetValue('ProfileImagePath')
                if (-not $img) { continue }
                $leaf = Split-Path -Leaf $img
                if (@($script:AtmSanitizerProductWords | Where-Object { $_ -eq $leaf }).Count -eq 0) { & $add $leaf '<profile-name>' }
            }
            $pl.Close()
        }
    } catch { $null = $_ }
    $seen = @{}
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($x in @($pairs | Sort-Object { $_.Value.Length } -Descending)) {
        $k = $x.Value.ToUpperInvariant()
        if ($seen.ContainsKey($k)) { continue }
        $seen[$k] = $true
        $out.Add($x)
    }
    return , $out.ToArray()
}

function ConvertTo-AtmArtifactSafeText {
    # Returns the text with this machine's identifiers replaced (ignoring case), then any account SID (the project's
    # fictitious S-1-5-21-<digit>-<digit>-<digit> test SIDs stay) and any remaining C:\Users\<name> path.
    param([AllowNull()][string]$Text, [object[]]$Identifiers)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $t = $Text
    foreach ($x in @($Identifiers)) {
        foreach ($v in @($x.Value, $x.Value.Replace('\', '\\'))) {
            $t = [regex]::Replace($t, [regex]::Escape($v), $x.Placeholder.Replace('$', '$$'), [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        }
    }
    $t = [regex]::Replace($t, 'S-1-5-21-\d+-\d+-\d+(-\d+)?', { param($m) if ($m.Value -match '^S-1-5-21-\d-\d-\d(-\d+)?$') { $m.Value } else { '<sid>' } })
    $t = [regex]::Replace($t, '(?i)\b[A-Z]:(\\\\|\\)Users(\\\\|\\)[^\\\s"''`<>|*?]+', '<user-path>')
    return $t
}
