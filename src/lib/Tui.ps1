# AgentTempManager TUI (presentation layer only).
#
# Contract:
#  * Reads inventories produced by the audit engine and preview gates from the clean engine.
#  * Cleaning is delegated entirely to Invoke-AtmClean (allowlist -> gates -> exact plan -> typed phrase ->
#    per-path revalidation). This file never calls any filesystem deletion API and offers no shortcut
#    around the engine's validations (enforced by an automated static test).
#  * No ANSI escape sequences: colors use the console color API (Write-Host -ForegroundColor), so it works
#    on Windows PowerShell 5.1 conhost, PowerShell 7 and terminals without VT support. Box drawing falls back
#    to ASCII with -Ascii or when Unicode output is not available.
#  * Rendering is a pure function (state -> frame lines); keys come from an injectable source (headless tests).
Set-StrictMode -Version 2.0

$script:AtmTuiClassColor = @{ ACTIVE_EVIDENCE = 'Red'; RECENT = 'Yellow'; LIVENESS_UNKNOWN = 'DarkYellow'; ORPHAN_SUSPECTED = 'Cyan'; NOT_SCANNED = 'DarkGray' }
$script:AtmTuiCatColor = @{ BLOCKED = 'Red'; INVESTIGATE = 'Yellow'; ELIGIBLE = 'Green' }

function Get-AtmTuiGlyphs {
    param([bool]$Ascii)
    if ($Ascii) { return @{ H = '-'; V = '|'; TL = '+'; TR = '+'; BL = '+'; BR = '+'; Full = '#'; Empty = '.'; Ell = '~'; Sel = '>'; Dot = '*' } }
    return @{ H = [string][char]0x2500; V = [string][char]0x2502; TL = [string][char]0x250C; TR = [string][char]0x2510; BL = [string][char]0x2514; BR = [string][char]0x2518
        Full = [string][char]0x2588; Empty = [string][char]0x2591; Ell = [string][char]0x2026; Sel = [string][char]0x25B6; Dot = [string][char]0x25CF }
}

function Test-AtmTuiUnicodeDefault {
    if ($env:ATM_ASCII -eq '1') { return $false }
    if ($env:WT_SESSION) { return $true }
    if ($PSVersionTable.PSVersion.Major -ge 7) { return $true }
    try { return ([Console]::OutputEncoding.CodePage -in @(65001, 1200)) } catch { return $false }
}

function Test-AtmTuiInteractive {
    try {
        if ($Host.Name -ne 'ConsoleHost') { return $false }
        if ([Console]::IsInputRedirected -or [Console]::IsOutputRedirected) { return $false }
        $null = [Console]::WindowWidth
        return $true
    } catch { return $false }
}

# ------------------------------------------------------------------ frame primitives

function Get-AtmTuiOpt { param($Table, [string]$Key) if ($Table -and $Table.ContainsKey($Key)) { return $Table[$Key] } return $null }

function Limit-AtmTuiLine {
    # Clips a line (array of segments) to the given width; the frame never exceeds the terminal.
    param($Line, [int]$Width)
    $out = @(); $len = 0
    foreach ($s in @($Line)) {
        if ($len -ge $Width) { break }
        $t = $s.Text
        if ($len + $t.Length -gt $Width) { $t = $t.Substring(0, $Width - $len) }
        $out += [pscustomobject]@{ Text = $t; Fg = $s.Fg; Bg = $s.Bg }
        $len += $t.Length
    }
    if ($out.Count -eq 0) { $out = @([pscustomobject]@{ Text = ''; Fg = 'Gray'; Bg = '' }) }
    return ,$out
}

function ConvertTo-AtmAscii {
    # ASCII fallback: strip diacritics (c-cedilla -> c, a-tilde -> a) and replace anything still outside printable ASCII
    # with '?', so terminals without Unicode support never receive characters they cannot render.
    param([string]$Text)
    if (-not $Text) { return $Text }
    $d = $Text.Normalize([Text.NormalizationForm]::FormD)
    $sb = New-Object Text.StringBuilder
    foreach ($ch in $d.ToCharArray()) {
        if ([Globalization.CharUnicodeInfo]::GetUnicodeCategory($ch) -eq [Globalization.UnicodeCategory]::NonSpacingMark) { continue }
        if ([int]$ch -ge 32 -and [int]$ch -le 126) { [void]$sb.Append($ch) } else { [void]$sb.Append('?') }
    }
    return $sb.ToString()
}

function New-AtmSeg { param([string]$Text, [string]$Fg = 'Gray', [string]$Bg = '') return [pscustomobject]@{ Text = $Text; Fg = $Fg; Bg = $Bg } }

function Limit-AtmText {
    param([string]$Text, [int]$Width, [string]$Ell)
    if ($null -eq $Text) { $Text = '' }
    if ($Width -le 0) { return '' }
    if ($Text.Length -le $Width) { return $Text.PadRight($Width) }
    if ($Width -le 1) { return $Text.Substring(0, $Width) }
    return $Text.Substring(0, $Width - 1) + $Ell
}

function Split-AtmWrap {
    param([string]$Text, [int]$Width)
    $out = New-Object System.Collections.Generic.List[string]
    if ($Width -lt 10) { $Width = 10 }
    if (-not $Text) { $out.Add(''); return $out.ToArray() }
    $i = 0
    while ($i -lt $Text.Length) { $n = [math]::Min($Width, $Text.Length - $i); $out.Add($Text.Substring($i, $n)); $i += $n }
    return $out.ToArray()
}

function Format-AtmTuiBar {
    param([double]$Fraction, [int]$Width, $G)
    if ($Fraction -lt 0) { $Fraction = 0 } elseif ($Fraction -gt 1) { $Fraction = 1 }
    $f = [int][math]::Round($Fraction * $Width)
    return ($G.Full * $f) + ($G.Empty * ($Width - $f))
}

function Format-AtmTuiTable {
    # Columns: @{ Name; Width (0 = flexible); Right }; Rows: arrays of strings. Returns header + row strings.
    param([object[]]$Columns, [object[]]$Rows, [int]$Width, $G)
    $fixed = 0; $flex = 0
    foreach ($c in $Columns) { if ($c.Width -gt 0) { $fixed += $c.Width + 1 } else { $flex++ } }
    $flexW = [math]::Max(8, [int](($Width - $fixed - 1) / [math]::Max(1, $flex)))
    $fmt = {
        param($vals)
        $sb = New-Object Text.StringBuilder
        for ($k = 0; $k -lt $Columns.Count; $k++) {
            $w = $(if ($Columns[$k].Width -gt 0) { $Columns[$k].Width } else { $flexW })
            $v = [string]$vals[$k]
            if ($Columns[$k].ContainsKey('Right') -and $Columns[$k]['Right'] -and $v.Length -le $w) { [void]$sb.Append($v.PadLeft($w)) } else { [void]$sb.Append((Limit-AtmText $v $w $G.Ell)) }
            [void]$sb.Append(' ')
        }
        return $sb.ToString()
    }
    $header = & $fmt @($Columns | ForEach-Object { $_.Name })
    $lines = @(foreach ($r in $Rows) { & $fmt $r })
    return [pscustomobject]@{ Header = $header; Lines = $lines }
}

# ------------------------------------------------------------------ data shaping (read-only views of the inventory)

function Get-AtmTuiParts { param($State) return @($State.Inventory.Partitions | Where-Object { $_.Kind -ne 'NotScanned' }) }

function Get-AtmTuiPreviewRows {
    # Preview gates come from the CLEAN ENGINE (Test-AtmCandidate); the TUI only caches the result.
    param($State)
    if ($null -eq $State.Preview) {
        & $State.Draw (Get-AtmTuiBusyFrame -State $State -Text (Get-AtmText 'tui.computingPreview'))
        $State.Preview = @(Invoke-AtmPreview -Inventory $State.Inventory)
    }
    return $State.Preview
}

function Get-AtmTuiScreenRows {
    # Returns @{ Columns; Rows (string arrays); Items (objects for Enter); Colors (per row) }
    param($State, $Screen)
    $inv = $State.Inventory
    $parts = @(Get-AtmTuiParts $State)
    $cols = @(); $rows = New-Object System.Collections.Generic.List[object]; $items = New-Object System.Collections.Generic.List[object]; $colors = New-Object System.Collections.Generic.List[string]
    switch ($Screen.Name) {
        'users' {
            $cols = @(@{ Name = (Get-AtmText 'col.user'); Width = 0 }, @{ Name = 'SID'; Width = 46 }, @{ Name = (Get-AtmText 'col.status'); Width = 22 }, @{ Name = 'Roots'; Width = 6; Right = $true }, @{ Name = (Get-AtmText 'col.files'); Width = 10; Right = $true }, @{ Name = 'MB'; Width = 10; Right = $true }, @{ Name = 'A/R/U/O'; Width = 13 })
            foreach ($pr in $inv.Profiles) {
                $pp = @($parts | Where-Object { $_.Sid -eq $pr.Sid -and $_.ProfilePath -eq $pr.ProfilePath })
                $st = Get-AtmProfileStatusLabel -Inventory $inv -ProfileInfo $pr
                $aruo = '{0}/{1}/{2}/{3}' -f @($pp | Where-Object Class -eq 'ACTIVE_EVIDENCE').Count, @($pp | Where-Object Class -eq 'RECENT').Count, @($pp | Where-Object Class -eq 'LIVENESS_UNKNOWN').Count, @($pp | Where-Object Class -eq 'ORPHAN_SUSPECTED').Count
                $rows.Add(@($pr.UserName, $pr.Sid, (Get-AtmStatusText $st), $pp.Count, ('{0:N0}' -f (Get-AtmSum $pp 'Files')), (Format-AtmMB (Get-AtmSum $pp 'Bytes')), $aruo))
                $items.Add([pscustomobject]@{ Kind = 'user'; Profile = $pr })
                $colors.Add($(if ($st -like 'AUDITADO*') { 'Gray' } elseif ($st -eq 'SEM_TEMP_CLAUDE') { 'DarkGray' } else { 'Yellow' }))
            }
        }
        'projects' {
            $cols = @(@{ Name = (Get-AtmText 'col.project'); Width = 0 }, @{ Name = (Get-AtmText 'col.user'); Width = 24 }, @{ Name = 'Roots'; Width = 6; Right = $true }, @{ Name = (Get-AtmText 'col.files'); Width = 10; Right = $true }, @{ Name = 'MB'; Width = 10; Right = $true }, @{ Name = (Get-AtmText 'col.newest'); Width = 16 })
            $groups = $parts | Group-Object { $_.Project + '|' + $(if ($_.ProjectIdentified) { '' } else { $_.Slug }) + '|' + $_.Sid + '|' + $_.ProfilePath } | Sort-Object { -(Get-AtmSum $_.Group 'Bytes') }
            foreach ($grpObj in $groups) {
                $grp = @($grpObj.Group)
                $newest = ($grp | Where-Object { $_.NewestWriteTimeUtc } | Sort-Object NewestWriteTimeUtc -Descending | Select-Object -First 1)
                $label = $(if ($grp[0].ProjectIdentified) { $grp[0].Project } else { "$($grp[0].Project) ($($grp[0].Slug))" })
                $rows.Add(@($label, $grp[0].UserName, $grp.Count, ('{0:N0}' -f (Get-AtmSum $grp 'Files')), (Format-AtmMB (Get-AtmSum $grp 'Bytes')), $(if ($newest) { Format-AtmTime $newest.NewestWriteTimeUtc } else { '-' })))
                $items.Add([pscustomobject]@{ Kind = 'project'; Project = $grp[0].Project; Slug = $(if ($grp[0].ProjectIdentified) { $null } else { $grp[0].Slug }); Sid = $grp[0].Sid; ProfilePath = $grp[0].ProfilePath; UserName = $grp[0].UserName })
                $colors.Add('Gray')
            }
        }
        'roots' {
            $sel = $parts
            $f = $Screen.Filter
            if ($f) {
                if (Get-AtmTuiOpt $f 'Sid') { $sel = @($sel | Where-Object { $_.Sid -eq $f.Sid -and $_.ProfilePath -eq $f.ProfilePath }) }
                if (Get-AtmTuiOpt $f 'Project') { $sel = @($sel | Where-Object { $_.Project -eq $f.Project }) }
                if (Get-AtmTuiOpt $f 'Slug') { $sel = @($sel | Where-Object { $_.Slug -eq $f.Slug }) }
                if (Get-AtmTuiOpt $f 'Class') { $sel = @($sel | Where-Object { $_.Class -eq $f.Class }) }
            }
            $cols = @(@{ Name = (Get-AtmText 'col.class'); Width = 17 }, @{ Name = (Get-AtmText 'col.agent'); Width = 12 }, @{ Name = (Get-AtmText 'col.user'); Width = 20 }, @{ Name = (Get-AtmText 'col.project'); Width = 22 }, @{ Name = 'Root'; Width = 0 }, @{ Name = 'MB'; Width = 9; Right = $true }, @{ Name = (Get-AtmText 'col.files'); Width = 9; Right = $true }, @{ Name = (Get-AtmText 'col.newest'); Width = 16 }, @{ Name = 'Flags'; Width = 5; Right = $true })
            foreach ($p in ($sel | Sort-Object @{ Expression = 'Bytes'; Descending = $true })) {
                $rows.Add(@($p.Class, $p.Provider, $p.UserName, $p.Project, $(if ($p.Slug) { $p.Slug + '\' + $p.Name } else { $p.Name }), (Format-AtmMB $p.Bytes), ('{0:N0}' -f $p.Files), (Format-AtmTime $p.NewestWriteTimeUtc), $p.Flags.Count))
                $items.Add([pscustomobject]@{ Kind = 'root'; Partition = $p })
                $c = $script:AtmTuiClassColor[$p.Class]; if (-not $c) { $c = 'Gray' }
                $colors.Add($c)
            }
        }
        'gates' {
            $prev = Get-AtmTuiPreviewRows $State
            $want = Get-AtmTuiOpt $Screen.Filter 'Category'
            $cols = @(@{ Name = (Get-AtmText 'col.category'); Width = 11 }, @{ Name = (Get-AtmText 'col.user'); Width = 20 }, @{ Name = 'Root'; Width = 0 }, @{ Name = 'MB'; Width = 9; Right = $true }, @{ Name = (Get-AtmText 'col.reasonReq'); Width = 0 })
            foreach ($r in ($prev | Where-Object { -not $want -or $_.Gate.Category -eq $want } | Sort-Object { $_.Gate.Category }, { -$_.Partition.Bytes })) {
                $p = $r.Partition
                $rows.Add(@($r.Gate.Category, $p.UserName, $(if ($p.Slug) { $p.Slug + '\' + $p.Name } else { $p.Name }), (Format-AtmMB $p.Bytes), ((@($r.Gate.Reasons) + @($r.Gate.Requirements)) -join '; ')))
                $items.Add([pscustomobject]@{ Kind = 'root'; Partition = $p; Gate = $r.Gate })
                $colors.Add($script:AtmTuiCatColor[$r.Gate.Category])
            }
        }
    }
    return [pscustomobject]@{ Columns = $cols; Rows = $rows.ToArray(); Items = $items.ToArray(); Colors = $colors.ToArray() }
}

function Get-AtmTuiTextLines {
    # Non-tabular screens: list of @{ Text; Fg }
    param($State, $Screen, [int]$Width)
    $inv = $State.Inventory
    $L = New-Object System.Collections.Generic.List[object]
    $add = { param($t, $fg = 'Gray') foreach ($w in (Split-AtmWrap $t ($Width - 2))) { $L.Add([pscustomobject]@{ Text = $w; Fg = $fg }) } }
    switch ($Screen.Name) {
        'errors' {
            $s = $inv.Snapshot
            & $add (Get-AtmText 'tui.coverageAll' $(if ($inv.CoverageComplete) { Get-AtmText 'common.complete' } else { Get-AtmText 'common.incomplete' })) $(if ($inv.CoverageComplete) { 'Green' } else { 'Yellow' })
            if ($s.Failed) { & $add (Get-AtmText 'audit.procFailed' $s.Error) 'Red' }
            else { & $add (Get-AtmText 'audit.procSummary' $s.Total $s.Readable $s.Uninspectable @($inv.SelfPids).Count) }
            if ($s.Uninspectable -gt 0) {
                & $add (Get-AtmText 'audit.uninspectable' (($s.UninspectableByName.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { "$($_.Key) x$($_.Value)" }) -join ', ')) 'DarkYellow'
                & $add (Get-AtmText 'audit.absenceNotProof') 'DarkYellow'
            }
            & $add (Get-AtmText 'audit.references' $inv.References.Direct $inv.References.Ancestor $inv.References.Ambiguous $inv.References.Unresolved.Count)
            foreach ($u in $inv.References.Unresolved) { & $add "  $u" }
            & $add ''
            & $add (Get-AtmText 'tui.incompleteProfiles') 'Yellow'
            if (@($inv.InaccessibleProfiles).Count -eq 0 -and @($inv.UnverifiedTempProfiles).Count -eq 0) { & $add ('  ' + (Get-AtmText 'common.none')) }
            foreach ($pr in $inv.InaccessibleProfiles) { & $add ("  {0} ({1}) {2}" -f $pr.UserName, $pr.Sid, $pr.ProfilePath) 'Yellow' }
            foreach ($pr in @($inv.UnverifiedTempProfiles)) { & $add ('  ' + (Get-AtmText 'tui.unverifiedTemp' $pr.UserName $pr.Sid $pr.EnvStatus)) 'Yellow' }
            & $add ''
            & $add (Get-AtmText 'audit.tempDirs')
            foreach ($pr in $inv.Profiles) { foreach ($b in @($inv.ProfileBaseStatus[$pr.Sid + '|' + $pr.ProfilePath])) { & $add ("  [{0}] [{1}] {2} -> {3}" -f $b.Status, $b.Provider, $pr.UserName, $b.BasePath) $(if ($b.Status -eq 'OK') { 'Gray' } elseif ($b.Status -eq 'NOT_FOUND') { 'DarkGray' } else { 'Yellow' }) } }
            & $add ''
            & $add (Get-AtmText 'tui.discoveryNotes')
            foreach ($pr in $inv.Profiles) { foreach ($n in $pr.Notes) { & $add ("  [{0}] {1}" -f $pr.UserName, $n) 'DarkGray' } }
            foreach ($n in $inv.DiscoveryNotes) { & $add "  $n" 'DarkGray' }
            & $add ''
            & $add (Get-AtmText 'tui.partitionsWithIssues')
            $errs = @(Get-AtmTuiParts $State | Where-Object { $_.ErrorCount -gt 0 -or $_.ReparsePoints -gt 0 -or $_.AmbiguousRefs.Count -gt 0 -or $_.AncestorRefs.Count -gt 0 })
            if ($errs.Count -eq 0) { & $add ('  ' + (Get-AtmText 'common.none')) }
            foreach ($e in $errs) {
                & $add ("  [{0}] {1}" -f $e.UserName, $e.Path) 'Yellow'
                foreach ($x in $e.ErrorSamples) { & $add ('     ' + (Get-AtmText 'audit.err' $x)) }
                foreach ($x in $e.ReparseSamples) { & $add ('     ' + (Get-AtmText 'audit.reparse' $x)) }
                foreach ($x in $e.AncestorRefs) { & $add ('     ' + (Get-AtmText 'audit.ancestorRef' $x)) }
                foreach ($x in $e.AmbiguousRefs) { & $add ('     ' + (Get-AtmText 'audit.ambiguousRef' $x)) }
            }
            & $add ''
            & $add (Get-AtmText 'tui.limits') 'DarkGray'
        }
        'detail' {
            $p = $Screen.Filter.Partition
            $pairs = @(
                @('det.path', $p.Path), @('det.agent', $p.Provider), @('det.kind', $p.Kind), @('det.class', $p.Class), @('det.user', $p.UserName), @('det.sid', $p.Sid), @('det.profile', $p.ProfilePath), @('det.temp', $p.TempPath)
                @('det.project', $(if ($p.ProjectIdentified) { Get-AtmText 'det.projectWithSource' $p.Project $p.ProjectSource } else { $p.Project })), @('det.scope', $p.Slug)
                @('det.created', (Format-AtmTime $p.CreationTimeUtc)), @('det.modified', (Format-AtmTime $p.LastWriteTimeUtc)), @('det.newest', (Format-AtmTime $p.NewestWriteTimeUtc))
                @('det.logical', ('{0:N0} ({1} MB | {2} GB)' -f $p.Bytes, (Format-AtmMB $p.Bytes), (Format-AtmGB $p.Bytes))), @('det.physical', ('{0:N0}' -f $p.AllocatedBytesEstimate))
                @('det.files', $p.Files), @('det.dirs', $p.Dirs), @('det.children', $p.DirectChildren), @('det.reparse', $p.ReparsePoints), @('det.protected', $p.ProtectedFiles)
                @('det.errors', $p.ErrorCount), @('det.complete', (Get-AtmYesNo $p.MeasurementComplete)), @('det.session', $(if ($p.Session) { $p.Session } else { '-' }))
                @('det.transcript', (Format-AtmTime $p.TranscriptLastWriteUtc)), @('det.fingerprint', $p.Fingerprint), @('det.flags', $(if ($p.Flags.Count) { $p.Flags -join ', ' } else { Get-AtmText 'common.none' }))
            )
            foreach ($pair in $pairs) { & $add (('{0,-26}: {1}' -f (Get-AtmText $pair[0]), $pair[1])) $(if ($pair[0] -eq 'det.class') { $c = $script:AtmTuiClassColor[$p.Class]; if ($c) { $c } else { 'Gray' } } else { 'Gray' }) }
            if ($Screen.Filter.Gate) { & $add (('{0,-26}: {1} - {2}' -f 'Preview', $Screen.Filter.Gate.Category, ((@($Screen.Filter.Gate.Reasons) + @($Screen.Filter.Gate.Requirements)) -join '; '))) $script:AtmTuiCatColor[$Screen.Filter.Gate.Category] }
            & $add ''
            & $add (Get-AtmText 'audit.evidence')
            if ($p.Evidence.Count -eq 0) { & $add ('  ' + (Get-AtmText 'tui.noEvidence')) 'DarkGray' }
            foreach ($x in $p.Evidence) { & $add "  - $x" }
            foreach ($x in $p.AncestorRefs) { & $add ('  - ' + (Get-AtmText 'audit.ancestorRef' $x)) 'Yellow' }
            foreach ($x in $p.AmbiguousRefs) { & $add ('  - ' + (Get-AtmText 'audit.ambiguousRef' $x)) 'Yellow' }
            foreach ($x in $p.ErrorSamples) { & $add ('  - ' + (Get-AtmText 'audit.err' $x)) 'Yellow' }
            foreach ($x in $p.ReparseSamples) { & $add ('  - ' + (Get-AtmText 'audit.reparse' $x)) 'Yellow' }
            & $add ''
            & $add (Get-AtmText 'tui.moreDetail') 'DarkGray'
        }
        'help' {
            foreach ($k in @('tui.help1', 'tui.help2', 'tui.help3', 'tui.help4', 'tui.help5')) { & $add (Get-AtmText $k); & $add '' }
        }
    }
    return $L.ToArray()
}

# ------------------------------------------------------------------ frames

function Get-AtmTuiChrome {
    param($State, [string]$Title)
    $inv = $State.Inventory
    $w = $State.Width
    $cov = $(if (-not $inv) { '-' } elseif ($inv.CoverageComplete) { Get-AtmText 'common.complete' } else { Get-AtmText 'common.incomplete' })
    $who = $(if ($inv) { $inv.Identity.Name + $(if ($inv.Identity.IsAdmin) { ' (admin)' } else { '' }) } else { '' })
    $head = Limit-AtmText (" agent-temp $script:AtmVersion $($State.G.V) $Title $($State.G.V) $who $($State.G.V) $(Get-AtmText 'tui.coverageLabel') $cov ") ($w - 1) $State.G.Ell
    return New-AtmSeg $head 'White' 'DarkBlue'
}

function Get-AtmTuiBusyFrame {
    param($State, [string]$Text, [int]$Percent = -1)
    $lines = New-Object System.Collections.Generic.List[object]
    $lines.Add(@(Get-AtmTuiChrome -State $State -Title (Get-AtmText 'tui.working')))
    $lines.Add(@(New-AtmSeg ''))
    $lines.Add(@(New-AtmSeg ('  ' + (Limit-AtmText $Text ($State.Width - 4) $State.G.Ell)) 'Cyan'))
    if ($Percent -ge 0) {
        $bw = [math]::Max(10, [math]::Min(60, $State.Width - 14))
        $lines.Add(@(New-AtmSeg ('  [' + (Format-AtmTuiBar ($Percent / 100.0) $bw $State.G) + ('] {0,3}%' -f $Percent)) 'Green'))
    }
    $lines.Add(@(New-AtmSeg ''))
    $lines.Add(@(New-AtmSeg ('  ' + (Get-AtmText 'tui.readOnlyBusy')) 'DarkGray'))
    return $lines.ToArray()
}

function Get-AtmTuiMenuItems {
    return @(
        @{ Key = '1'; Label = (Get-AtmText 'menu.dashboard'); Screen = @{ Name = 'dashboard'; Title = (Get-AtmText 'menu.dashboard') } }
        @{ Key = '2'; Label = (Get-AtmText 'menu.users'); Screen = @{ Name = 'users'; Title = (Get-AtmText 'menu.users') } }
        @{ Key = '3'; Label = (Get-AtmText 'menu.projects'); Screen = @{ Name = 'projects'; Title = (Get-AtmText 'menu.projects') } }
        @{ Key = '4'; Label = (Get-AtmText 'menu.roots'); Screen = @{ Name = 'roots'; Title = 'Roots' } }
        @{ Key = '5'; Label = 'ACTIVE_EVIDENCE'; Screen = @{ Name = 'roots'; Title = 'ACTIVE_EVIDENCE'; Filter = @{ Class = 'ACTIVE_EVIDENCE' } } }
        @{ Key = '6'; Label = 'RECENT'; Screen = @{ Name = 'roots'; Title = 'RECENT'; Filter = @{ Class = 'RECENT' } } }
        @{ Key = '7'; Label = 'LIVENESS_UNKNOWN'; Screen = @{ Name = 'roots'; Title = 'LIVENESS_UNKNOWN'; Filter = @{ Class = 'LIVENESS_UNKNOWN' } } }
        @{ Key = '8'; Label = (Get-AtmText 'menu.blocked'); Screen = @{ Name = 'gates'; Title = (Get-AtmText 'menu.blockedTitle'); Filter = @{ Category = 'BLOCKED' } } }
        @{ Key = '9'; Label = (Get-AtmText 'menu.errors'); Screen = @{ Name = 'errors'; Title = (Get-AtmText 'menu.errorsTitle') } }
        @{ Key = 'P'; Label = (Get-AtmText 'menu.preview'); Screen = @{ Name = 'gates'; Title = 'Preview'; Filter = @{ Category = $null } } }
        @{ Key = 'L'; Label = (Get-AtmText 'menu.clean'); Screen = @{ Name = 'clean'; Title = (Get-AtmText 'menu.cleanTitle') } }
        @{ Key = 'R'; Label = (Get-AtmText 'menu.reaudit'); Screen = @{ Name = 'reaudit' } }
        @{ Key = 'H'; Label = (Get-AtmText 'menu.help'); Screen = @{ Name = 'help'; Title = (Get-AtmText 'menu.help') } }
        @{ Key = 'Q'; Label = (Get-AtmText 'menu.quit'); Screen = @{ Name = 'quit' } }
    )
}

function Get-AtmTuiDashboardLines {
    param($State)
    $inv = $State.Inventory; $G = $State.G; $w = $State.Width
    $parts = @(Get-AtmTuiParts $State)
    $bytes = Get-AtmSum $parts 'Bytes'
    $audited = @($inv.Profiles | Where-Object { (Get-AtmProfileStatusLabel -Inventory $inv -ProfileInfo $_) -like 'AUDITADO*' }).Count
    $cards = @(
        @{ T = (Get-AtmText 'dash.profiles'); L = @((Get-AtmText 'dash.discovered' @($inv.Profiles).Count), (Get-AtmText 'dash.audited' $audited), (Get-AtmText 'dash.incomplete' (@($inv.InaccessibleProfiles).Count + @($inv.UnverifiedTempProfiles).Count))); C = 'Cyan' }
        @{ T = (Get-AtmText 'dash.filesDirs'); L = @((Get-AtmText 'dash.files' (Get-AtmSum $parts 'Files')), (Get-AtmText 'dash.dirs' (Get-AtmSum $parts 'Dirs')), (Get-AtmText 'dash.partitions' $parts.Count)); C = 'Cyan' }
        @{ T = (Get-AtmText 'dash.space'); L = @((Get-AtmText 'dash.mbLogical' (Format-AtmMB $bytes)), (Get-AtmText 'dash.gbLogical' (Format-AtmGB $bytes)), (Get-AtmText 'dash.mbPhysical' (Format-AtmMB (Get-AtmSum $parts 'AllocatedBytesEstimate')))); C = 'Cyan' }
        @{ T = (Get-AtmText 'dash.errorsCoverage'); L = @((Get-AtmText 'dash.readErrors' (Get-AtmSum $parts 'ErrorCount')), (Get-AtmText 'dash.incompleteMeas' @($parts | Where-Object { -not $_.MeasurementComplete }).Count), (Get-AtmText 'dash.coverage' $(if ($inv.CoverageComplete) { Get-AtmText 'common.complete' } else { Get-AtmText 'common.incomplete' }))); C = $(if ($inv.CoverageComplete) { 'Green' } else { 'Yellow' }) }
    )
    $perRow = $(if ($w -ge 110) { 4 } elseif ($w -ge 60) { 2 } else { 1 })
    $cw = [int](($w - 2) / $perRow) - 1
    $out = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt $cards.Count; $i += $perRow) {
        $chunk = @($cards[$i..([math]::Min($i + $perRow, $cards.Count) - 1)])
        $top = @(New-AtmSeg ' '); $bot = @(New-AtmSeg ' ')
        foreach ($c in $chunk) {
            $t = ' ' + $c.T + ' '
            $top += New-AtmSeg ($G.TL + $G.H + (Limit-AtmText $t ([math]::Min($t.Length, $cw - 3)) $G.Ell) + ($G.H * [math]::Max(0, $cw - 3 - $t.Length)) + $G.TR + ' ') $c.C
            $bot += New-AtmSeg ($G.BL + ($G.H * ($cw - 2)) + $G.BR + ' ') $c.C
        }
        $out.Add($top)
        for ($k = 0; $k -lt 3; $k++) {
            $mid = @(New-AtmSeg ' ')
            foreach ($c in $chunk) { $mid += New-AtmSeg $G.V $c.C; $mid += New-AtmSeg (' ' + (Limit-AtmText $c.L[$k] ($cw - 4) $G.Ell) + ' ') 'White'; $mid += New-AtmSeg ($G.V + ' ') $c.C }
            $out.Add($mid)
        }
        $out.Add($bot)
    }
    $out.Add(@(New-AtmSeg ''))
    $out.Add(@(New-AtmSeg (' ' + (Get-AtmText 'dash.classes')) 'White'))
    $bw = [math]::Max(10, [math]::Min(40, $w - 60))
    foreach ($c in @('ACTIVE_EVIDENCE', 'RECENT', 'LIVENESS_UNKNOWN', 'ORPHAN_SUSPECTED')) {
        $grp = @($parts | Where-Object { $_.Class -eq $c })
        $gb = Get-AtmSum $grp 'Bytes'
        $frac = $(if ($bytes -gt 0) { $gb / $bytes } else { 0 })
        $out.Add(@((New-AtmSeg ('  {0,-17} ' -f $c) $script:AtmTuiClassColor[$c]), (New-AtmSeg (Format-AtmTuiBar $frac $bw $G) $script:AtmTuiClassColor[$c]), (New-AtmSeg (' {0,5} roots {1,10} MB' -f $grp.Count, (Format-AtmMB $gb)) 'Gray')))
    }
    $out.Add(@(New-AtmSeg ''))
    $out.Add(@(New-AtmSeg (' ' + (Get-AtmText 'dash.orphanInfo')) 'DarkGray'))
    $out.Add(@(New-AtmSeg (' ' + (Get-AtmText 'dash.auditTime' (Format-AtmTime $inv.StartedUtc) (Format-AtmTime $inv.FinishedUtc))) 'DarkGray'))
    return $out.ToArray()
}

function Get-AtmTuiFrame {
    # Pure: State -> array of lines (each line = array of segments).
    param($State)
    $G = $State.G; $w = $State.Width; $h = $State.Height
    $scr = $State.Stack[$State.Stack.Count - 1]
    $lines = New-Object System.Collections.Generic.List[object]
    $lines.Add(@(Get-AtmTuiChrome -State $State -Title $scr.Title))
    $bodyH = $h - 3
    $footer = Get-AtmText 'foot.default'
    switch ($scr.Name) {
        'menu' {
            $lines.Add(@(New-AtmSeg ''))
            $items = Get-AtmTuiMenuItems
            for ($i = 0; $i -lt $items.Count; $i++) {
                $it = $items[$i]
                $txt = ('  {0}  [{1}] {2}' -f $(if ($i -eq $scr.Sel) { $G.Sel } else { ' ' }), $it.Key, $it.Label)
                if ($i -eq $scr.Sel) { $lines.Add(@(New-AtmSeg (Limit-AtmText $txt ($w - 1) $G.Ell) 'Black' 'Cyan')) }
                else { $lines.Add(@(New-AtmSeg $txt $(if ($it.Key -eq 'L') { 'Yellow' } else { 'Gray' }))) }
            }
            $lines.Add(@(New-AtmSeg ''))
            if ($State.Inventory) {
                $parts = @(Get-AtmTuiParts $State)
                $lines.Add(@(New-AtmSeg ('  ' + (Get-AtmText 'tui.menuSummary' $parts.Count (Get-AtmSum $parts 'Files') (Format-AtmMB (Get-AtmSum $parts 'Bytes')) $(if ($State.Inventory.CoverageComplete) { Get-AtmText 'common.complete' } else { Get-AtmText 'common.incomplete' }))) 'DarkGray'))
            }
            $footer = Get-AtmText 'foot.menu'
        }
        'dashboard' { foreach ($l in (Get-AtmTuiDashboardLines $State)) { $lines.Add($l) }; $footer = Get-AtmText 'foot.dashboard' }
        { $_ -in @('users', 'projects', 'roots', 'gates') } {
            $data = Get-AtmTuiScreenRows -State $State -Screen $scr
            $scr.Count = $data.Rows.Count
            $tbl = Format-AtmTuiTable -Columns $data.Columns -Rows $data.Rows -Width $w -G $G
            $lines.Add(@(New-AtmSeg (' ' + $tbl.Header) 'White' 'DarkGray'))
            $vis = [math]::Max(1, $bodyH - 2)
            if ($scr.Sel -ge $data.Rows.Count) { $scr.Sel = [math]::Max(0, $data.Rows.Count - 1) }
            if ($scr.Sel -lt $scr.Top) { $scr.Top = $scr.Sel }
            if ($scr.Sel -ge $scr.Top + $vis) { $scr.Top = $scr.Sel - $vis + 1 }
            if ($data.Rows.Count -eq 0) { $lines.Add(@(New-AtmSeg ('  ' + (Get-AtmText 'common.none')) 'DarkGray')) }
            for ($i = $scr.Top; $i -lt [math]::Min($data.Rows.Count, $scr.Top + $vis); $i++) {
                $txt = $(if ($i -eq $scr.Sel) { $G.Sel } else { ' ' }) + $tbl.Lines[$i]
                if ($i -eq $scr.Sel) { $lines.Add(@(New-AtmSeg (Limit-AtmText $txt ($w - 1) $G.Ell) 'Black' 'Cyan')) } else { $lines.Add(@(New-AtmSeg (Limit-AtmText $txt ($w - 1) $G.Ell) $data.Colors[$i])) }
            }
            $footer = Get-AtmText 'foot.list' $(if ($data.Rows.Count) { $scr.Sel + 1 } else { 0 }) $data.Rows.Count
        }
        { $_ -in @('errors', 'detail', 'help') } {
            $tl = Get-AtmTuiTextLines -State $State -Screen $scr -Width $w
            $scr.Count = $tl.Count
            $vis = [math]::Max(1, $bodyH - 1)
            if ($scr.Top -gt [math]::Max(0, $tl.Count - $vis)) { $scr.Top = [math]::Max(0, $tl.Count - $vis) }
            for ($i = $scr.Top; $i -lt [math]::Min($tl.Count, $scr.Top + $vis); $i++) { $lines.Add(@(New-AtmSeg (' ' + $tl[$i].Text) $tl[$i].Fg)) }
            $footer = Get-AtmText 'foot.text'
        }
    }
    if ($State.Message) { $lines.Add(@(New-AtmSeg (' ' + $State.Message) 'Yellow')) }
    while ($lines.Count -lt $h - 1) { $lines.Add(@(New-AtmSeg '')) }
    $lines.Add(@(New-AtmSeg (Limit-AtmText (' ' + $footer) ($w - 1) $G.Ell) 'Black' 'Gray'))
    $clipped = New-Object System.Collections.Generic.List[object]
    foreach ($ln in ($lines.ToArray() | Select-Object -First ([math]::Max(1, $h)))) { $clipped.Add((Limit-AtmTuiLine -Line $ln -Width ($w - 1))) }
    return $clipped.ToArray()
}

function Write-AtmTuiFrameToConsole {
    param($Frame, [int]$Width)
    try { [Console]::SetCursorPosition(0, 0) } catch { Clear-Host }
    $n = 0
    foreach ($line in $Frame) {
        $len = 0
        foreach ($s in $line) {
            $t = $s.Text
            if ($len + $t.Length -gt $Width - 1) { $t = $t.Substring(0, [math]::Max(0, $Width - 1 - $len)) }
            if ($t.Length -eq 0) { continue }
            if ($s.Bg) { Write-Host $t -NoNewline -ForegroundColor $s.Fg -BackgroundColor $s.Bg } else { Write-Host $t -NoNewline -ForegroundColor $s.Fg }
            $len += $t.Length
        }
        if ($len -lt $Width - 1) { Write-Host (' ' * ($Width - 1 - $len)) -NoNewline }
        $n++
        if ($n -lt $Frame.Count) { Write-Host '' }
    }
}

# ------------------------------------------------------------------ actions

function Invoke-AtmTuiAudit {
    param($State)
    $State.Preview = $null
    # Dynamic scoping (no GetNewClosure: closures cannot see script-scope functions).
    $tuiAuditState = $State
    $cb = { param($pct, $msg) & $tuiAuditState.Draw (Get-AtmTuiBusyFrame -State $tuiAuditState -Text $msg -Percent $pct) }
    $a = @{} + $State.InventoryArgs
    $a['ProgressCallback'] = $cb
    $a['NoProgress'] = $false
    $State.Inventory = Invoke-AtmInventory @a
}

function Invoke-AtmTuiClean {
    # Leaves the full-screen view and delegates EVERYTHING to the clean engine. No shortcuts.
    param($State)
    $tuiRead = $State.ReadLine
    $State.Leave.Invoke()
    Write-Host ''
    Write-Host (Get-AtmText 'tuiclean.title') -ForegroundColor Cyan
    if (-not $script:AtmRealDeletionEnabled) { Write-Host (Get-AtmText 'tuiclean.planOnly') -ForegroundColor Yellow }
    Write-Host (Get-AtmText 'tuiclean.intro1')
    Write-Host (Get-AtmText 'tuiclean.intro2')
    Write-Host (Get-AtmText 'tuiclean.intro3')
    Write-Host ''
    $file = & $tuiRead (Get-AtmText 'tuiclean.askFile')
    $path = $null
    if (-not $file) { $path = & $tuiRead (Get-AtmText 'tuiclean.askPath') }
    if (-not $file -and -not $path) { Write-Host (Get-AtmText 'tuiclean.cancelled') -ForegroundColor Green; [void](& $tuiRead (Get-AtmText 'tuiclean.enterBack')); return }
    if ($file -and -not (Test-Path -LiteralPath $file -PathType Leaf)) { Write-Host (Get-AtmText 'cli.allowlistMissing' $file) -ForegroundColor Red; [void](& $tuiRead (Get-AtmText 'tuiclean.enterBack')); return }
    $entries = Read-AtmAllowList -File $file -Paths @($path)
    $other = $false
    $id = $State.Inventory.Identity
    if ($id.IsAdmin) {
        $yesWord = Get-AtmText 'tuiclean.yesWord'
        $other = ((& $tuiRead (Get-AtmText 'tuiclean.askOthers' $yesWord)) -ceq $yesWord)
    }
    $presenter = { param($v, $r, $i) Show-AtmCleanPlan -Verified $v -Rejected $r -Inventory $i }
    $reader = { param($phrase) Write-Host ''; Write-Host (Get-AtmText 'cli.typePhrase' $phrase) -ForegroundColor Yellow; & $tuiRead (Get-AtmText 'cli.confirmPrompt') }
    $a = @{} + $State.InventoryArgs
    $a['NoProgress'] = $true
    $res = Invoke-AtmClean -Entries $entries -IncludeOtherUsers:$other -PlanPresenter $presenter -ConfirmationReader $reader -InventoryArgs $a
    Show-AtmCleanResult -Result $res
    $State.LastClean = $res
    if ($res.PostInventory) { $State.Inventory = $res.PostInventory; $State.Preview = $null }
    [void](& $tuiRead (Get-AtmText 'tuiclean.enterPanel'))
}

function Start-AtmTui {
    <#
      -InventoryArgs : splatted into Invoke-AtmInventory (self markers, config dir; overrides in tests)
      -KeySource     : scriptblock returning [ConsoleKeyInfo] (default [Console]::ReadKey($true))
      -Renderer      : scriptblock(frame) (default: console writer)
      -LineReader    : scriptblock(prompt) -> string (default Read-Host)
      -Width/-Height : fixed size (tests); default = console window
    #>
    param([hashtable]$InventoryArgs = @{}, [scriptblock]$KeySource, [scriptblock]$Renderer, [scriptblock]$LineReader, [switch]$Ascii, [int]$Width = 0, [int]$Height = 0, $Inventory)
    $headless = [bool]$Renderer
    $useAscii = $Ascii -or -not (Test-AtmTuiUnicodeDefault)
    # Callbacks below rely on dynamic scoping with tui-prefixed names (no GetNewClosure: such closures
    # cannot resolve script-scope functions).
    $tuiState = @{
        G = (Get-AtmTuiGlyphs $useAscii); Width = 120; Height = 36; Stack = New-Object System.Collections.Generic.List[object]
        Inventory = $Inventory; Preview = $null; Message = $null; InventoryArgs = $InventoryArgs; LastClean = $null; Frames = 0
    }
    $tuiHeadless = $headless
    $sizeOf = {
        if ($Width -gt 0) { $tuiState.Width = $Width; $tuiState.Height = $Height; return }
        # Console size unavailable (redirected output): the previous size is kept; cosmetic only.
        try { $tuiState.Width = [math]::Max(40, [Console]::WindowWidth); $tuiState.Height = [math]::Max(15, [Console]::WindowHeight) } catch { $null = $_ }
    }
    if (-not $KeySource) { $KeySource = { [Console]::ReadKey($true) } }
    if (-not $LineReader) { $LineReader = { param($prompt) Read-Host $prompt } }
    if (-not $Renderer) { $Renderer = { param($frame) Write-AtmTuiFrameToConsole -Frame $frame -Width $tuiState.Width } }
    $tuiRenderer = $Renderer
    $tuiAscii = $useAscii
    $tuiState.Draw = { param($frame) $tuiState.Frames++; & $tuiRenderer @($frame | ForEach-Object { $ln = $_; if ($tuiAscii) { $ln = @($ln | ForEach-Object { [pscustomobject]@{ Text = (ConvertTo-AtmAscii $_.Text); Fg = $_.Fg; Bg = $_.Bg } }) }; ,(Limit-AtmTuiLine -Line $ln -Width ($tuiState.Width - 1)) }) }
    $tuiState.ReadLine = $LineReader
    # Cursor visibility is cosmetic; consoles without it are fine.
    $tuiState.Leave = { if (-not $tuiHeadless) { try { [Console]::CursorVisible = $true } catch { $null = $_ }; Clear-Host } }
    $state = $tuiState
    $state.Stack.Add(@{ Name = 'menu'; Title = (Get-AtmText 'menu.title'); Sel = 0; Top = 0; Count = 0; Filter = $null })

    $oldCursor = $true
    # Cursor visibility is cosmetic; consoles without it are fine.
    if (-not $headless) { try { $oldCursor = [Console]::CursorVisible; [Console]::CursorVisible = $false } catch { $null = $_ }; Clear-Host }
    try {
        & $sizeOf
        if (-not $state.Inventory) { Invoke-AtmTuiAudit -State $state }
        while ($true) {
            & $sizeOf
            & $state.Draw (Get-AtmTuiFrame -State $state)
            $state.Message = $null
            $k = & $KeySource
            if ($null -eq $k) { break }
            $scr = $state.Stack[$state.Stack.Count - 1]
            $ch = [string]$k.KeyChar
            $page = [math]::Max(1, $state.Height - 6)
            $push = $null
            switch ($k.Key) {
                'UpArrow' { if ($scr.Name -in @('errors', 'detail', 'help')) { $scr.Top = [math]::Max(0, $scr.Top - 1) } else { $scr.Sel = [math]::Max(0, $scr.Sel - 1) }; continue }
                'DownArrow' {
                    if ($scr.Name -in @('errors', 'detail', 'help')) { $scr.Top++ }
                    elseif ($scr.Name -eq 'menu') { $scr.Sel = [math]::Min((Get-AtmTuiMenuItems).Count - 1, $scr.Sel + 1) }
                    else { $scr.Sel = [math]::Min([math]::Max(0, $scr.Count - 1), $scr.Sel + 1) }
                    continue
                }
                'PageUp' { if ($scr.Name -in @('errors', 'detail', 'help')) { $scr.Top = [math]::Max(0, $scr.Top - $page) } else { $scr.Sel = [math]::Max(0, $scr.Sel - $page) }; continue }
                'PageDown' { if ($scr.Name -in @('errors', 'detail', 'help')) { $scr.Top += $page } else { $scr.Sel = [math]::Min([math]::Max(0, $scr.Count - 1), $scr.Sel + $page) }; continue }
                'Home' { $scr.Sel = 0; $scr.Top = 0; continue }
                'End' { if ($scr.Name -in @('errors', 'detail', 'help')) { $scr.Top = [math]::Max(0, $scr.Count - 1) } else { $scr.Sel = [math]::Max(0, $scr.Count - 1) }; continue }
                { $_ -in @('Escape', 'Backspace') } {
                    if ($state.Stack.Count -gt 1) { $state.Stack.RemoveAt($state.Stack.Count - 1); continue }
                    if ($k.Key -eq 'Escape') { return $state }
                    continue
                }
                'Enter' {
                    if ($scr.Name -eq 'menu') { $push = (Get-AtmTuiMenuItems)[$scr.Sel].Screen }
                    elseif ($scr.Name -in @('users', 'projects', 'roots', 'gates')) {
                        $data = Get-AtmTuiScreenRows -State $state -Screen $scr
                        if ($data.Items.Count -gt 0) {
                            $it = $data.Items[[math]::Min($scr.Sel, $data.Items.Count - 1)]
                            switch ($it.Kind) {
                                'user' { $push = @{ Name = 'roots'; Title = (Get-AtmText 'tui.rootsOf' $it.Profile.UserName); Filter = @{ Sid = $it.Profile.Sid; ProfilePath = $it.Profile.ProfilePath } } }
                                'project' { $push = @{ Name = 'roots'; Title = (Get-AtmText 'tui.rootsOfProject' $it.Project $it.UserName); Filter = @{ Sid = $it.Sid; ProfilePath = $it.ProfilePath; Project = $it.Project; Slug = $it.Slug } } }
                                'root' { $gate = $null; if ($it.PSObject.Properties.Name -contains 'Gate') { $gate = $it.Gate }; $push = @{ Name = 'detail'; Title = (Get-AtmText 'tui.detailOf' $it.Partition.Name); Filter = @{ Partition = $it.Partition; Gate = $gate } } }
                            }
                        }
                    }
                }
                default {
                    if ($ch -match '^[qQ]$') { return $state }
                    if ($ch -match '^[rR]$') { $push = @{ Name = 'reaudit' } }
                    elseif ($scr.Name -eq 'menu') {
                        $m = @(Get-AtmTuiMenuItems | Where-Object { $_.Key -eq $ch.ToUpperInvariant() })
                        if ($m.Count -eq 1) { $push = $m[0].Screen }
                    }
                }
            }
            if ($push) {
                switch ($push.Name) {
                    'quit' { return $state }
                    'reaudit' { Invoke-AtmTuiAudit -State $state; $state.Message = (Get-AtmText 'tui.reaudited') }
                    # Cursor visibility is cosmetic; consoles without it are fine.
                    'clean' { Invoke-AtmTuiClean -State $state; if (-not $headless) { try { [Console]::CursorVisible = $false } catch { $null = $_ }; Clear-Host } }
                    default {
                        $s = @{} + $push
                        foreach ($dk in @('Sel', 'Top', 'Count')) { if (-not $s.ContainsKey($dk)) { $s[$dk] = 0 } }
                        if (-not $s.ContainsKey('Filter')) { $s['Filter'] = $null }
                        $state.Stack.Add($s)
                    }
                }
            }
        }
        return $state
    } finally {
        # Cursor visibility is cosmetic; consoles without it are fine.
        if (-not $headless) { try { [Console]::CursorVisible = $oldCursor } catch { $null = $_ }; Clear-Host }
    }
}
