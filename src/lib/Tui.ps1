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
#  * The diagnostics area (V0.2 P5-A) only calls Invoke-AtmDiagnose, on an explicit action, and shows the diagnose JSON
#    export of its result (schema fields only); it never calls a collector, opens a gate or changes a state.
Set-StrictMode -Version 2.0

$script:AtmTuiClassColor = @{ ACTIVE_EVIDENCE = 'Red'; RECENT = 'Yellow'; LIVENESS_UNKNOWN = 'DarkYellow'; ORPHAN_SUSPECTED = 'Cyan'; NOT_SCANNED = 'DarkGray' }
$script:AtmTuiCatColor = @{ BLOCKED = 'Red'; INVESTIGATE = 'Yellow'; ELIGIBLE = 'Green'; ELIGIBLE_WITH_DECLARED_RISK = 'Magenta' }

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
        $State.Preview = @(Invoke-AtmPreview -Inventory $State.Inventory -InventoryArgs $State.InventoryArgs)
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
                # The B1 exception category has its own short label: cut to the column it would read like ELIGIBLE.
                $catText = $(if ([string]$r.Gate.Category -ceq 'ELIGIBLE_WITH_DECLARED_RISK') { Get-AtmText 'tui.catDeclaredRisk' } else { $r.Gate.Category })
                $rows.Add(@($catText, $p.UserName, $(if ($p.Slug) { $p.Slug + '\' + $p.Name } else { $p.Name }), (Format-AtmMB $p.Bytes), ((@($r.Gate.Reasons) + @($r.Gate.Requirements)) -join '; ')))
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
            $notAudited = @(Get-AtmInventoryProfileList -Inventory $inv -Name 'NotAuditedProfiles')
            if ((Get-AtmIncompleteProfileCount -Inventory $inv) -eq 0) { & $add ('  ' + (Get-AtmText 'common.none')) }
            foreach ($pr in $inv.InaccessibleProfiles) { & $add ("  {0} ({1}) {2}" -f $pr.UserName, $pr.Sid, $pr.ProfilePath) 'Yellow' }
            foreach ($pr in @($inv.UnverifiedTempProfiles)) { & $add ('  ' + (Get-AtmText 'tui.unverifiedTemp' $pr.UserName $pr.Sid $pr.EnvStatus)) 'Yellow' }
            $idx = Get-AtmBaseIndex -Bases $inv.Bases
            foreach ($pr in $notAudited) { & $add ('  ' + (Get-AtmText 'tui.notAudited' $pr.UserName $pr.Sid ((@(Get-AtmNotAuditedBaseStates -Entries $inv.ProfileBaseStatus[$pr.Sid + '|' + $pr.ProfilePath] -BaseIndex $idx) | Select-Object -Unique) -join ','))) 'Yellow' }
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
    param($State, [string]$Title, [switch]$Diag)
    $inv = $State.Inventory
    $w = $State.Width
    $cov = $(if (-not $inv) { '-' } elseif ($inv.CoverageComplete) { Get-AtmText 'common.complete' } else { Get-AtmText 'common.incomplete' })
    $who = $(if ($inv) { $inv.Identity.Name + $(if ($inv.Identity.IsAdmin) { ' (admin)' } else { '' }) } else { '' })
    # Diagnostics area: no account name (ADR-0010/0012), and the coverage of the diagnose itself.
    if ($Diag) {
        $who = Get-AtmText 'tui.diag.title'
        $dv = $(if ($null -ne $State.Diag) { $State.Diag.View } else { $null })
        $cov = $(if ($null -eq $dv) { '-' } elseif ($dv.coverageComplete) { Get-AtmText 'common.complete' } else { Get-AtmText 'common.incomplete' })
        if ($null -ne $State.Diag -and $State.Diag.Stale) { $cov += ' ' + (Get-AtmText 'tui.diag.staleShort') }
    }
    $head = Limit-AtmText (" agent-temp $script:AtmVersion $($State.G.V) $Title $($State.G.V) $who $($State.G.V) $(Get-AtmText 'tui.coverageLabel') $cov ") ($w - 1) $State.G.Ell
    return New-AtmSeg $head 'White' 'DarkBlue'
}

function Get-AtmTuiBusyFrame {
    param($State, [string]$Text, [int]$Percent = -1, [switch]$Diag)
    $lines = New-Object System.Collections.Generic.List[object]
    $lines.Add(@(Get-AtmTuiChrome -State $State -Title (Get-AtmText 'tui.working') -Diag:$Diag))
    $lines.Add(@(New-AtmSeg ''))
    foreach ($bt in (Split-AtmWrap $Text ($State.Width - 4))) { $lines.Add(@(New-AtmSeg ('  ' + $bt) 'Cyan')) }
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
        @{ Key = 'D'; Label = (Get-AtmText 'menu.diagnose'); Screen = @{ Name = 'diag'; Title = (Get-AtmText 'tui.diag.title') } }
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
        @{ T = (Get-AtmText 'dash.profiles'); L = @((Get-AtmText 'dash.discovered' @($inv.Profiles).Count), (Get-AtmText 'dash.audited' $audited), (Get-AtmText 'dash.incomplete' (Get-AtmIncompleteProfileCount -Inventory $inv))); C = 'Cyan' }
        @{ T = (Get-AtmText 'dash.filesDirs'); L = @((Get-AtmText 'dash.files' (Get-AtmSum $parts 'Files')), (Get-AtmText 'dash.dirs' (Get-AtmSum $parts 'Dirs')), (Get-AtmText 'dash.partitions' $parts.Count)); C = 'Cyan' }
        @{ T = (Get-AtmText 'dash.space'); L = @((Get-AtmText 'dash.mbLogical' (Format-AtmMB $bytes)), (Get-AtmText 'dash.gbLogical' (Format-AtmGB $bytes)), (Get-AtmText 'dash.mbPhysical' (Format-AtmMB (Get-AtmSum $parts 'AllocatedBytesEstimate')))); C = 'Cyan' }
        @{ T = (Get-AtmText 'dash.errorsCoverage'); L = @((Get-AtmText 'dash.readErrors' (Get-AtmSum $parts 'ErrorCount')), (Get-AtmText 'dash.incompleteMeas' @($parts | Where-Object { -not $_.MeasurementComplete }).Count), (Get-AtmText 'dash.coverage' $(if ($inv.CoverageComplete) { Get-AtmText 'common.complete' } else { Get-AtmText 'common.incomplete' }))); C = $(if ($inv.CoverageComplete) { 'Green' } else { 'Yellow' }) }
    )
    # Four cards per row only when each keeps 27 characters of text (130 columns): below that the labels and numbers
    # would be cut, so two per row. Floor, never rounding: a card row must end inside the width.
    $perRow = $(if ($w -ge 130) { 4 } elseif ($w -ge 60) { 2 } else { 1 })
    $cw = [int][math]::Floor(($w - 2) / $perRow) - 1
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
    $lines.Add(@(Get-AtmTuiChrome -State $State -Title $scr.Title -Diag:($script:AtmTuiDiagScreens -contains $scr.Name)))
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
        { $_ -in @('diag', 'dcov', 'dlist', 'dnodes', 'dissues') } {
            $data = Get-AtmTuiDiagList -State $State -Screen $scr
            $items = $data.Items; if ($null -eq $items) { $items = @() }
            $scr.Count = $items.Count
            $pre = 0
            # Lines above the table are wrapped, never clipped (the warning and the outdated marker must stay whole).
            $preLine = { param([string]$T, [string]$Fg) foreach ($pc in (Split-AtmWrap $T ($w - 3))) { $lines.Add(@(New-AtmSeg (' ' + $pc) $Fg)); $script:AtmTuiPre++ } }
            $script:AtmTuiPre = 0
            $gp = $(if ($scr.Name -ceq 'dlist') { $State.Diag.Index.Gap[$scr.Filter.Cat] } else { $null })
            if ($scr.Name -ceq 'diag') {
                & $preLine (Get-AtmText 'tui.diag.lastRun' (Format-AtmTuiUtc $State.Diag.View.finishedUtc)) 'White'
                if ($State.Diag.Stale) { & $preLine (Get-AtmText 'tui.diag.stale' $State.Diag.Error) 'Red' }
                & $preLine (Get-AtmText 'tui.diag.noAuth') 'Green'
                & $preLine (Get-AtmText 'tui.diag.starLegend') 'DarkGray'
            } elseif ($null -ne $gp) { & $preLine (Get-AtmText 'tui.diag.covNote' $gp.Status $gp.Reasons) 'Yellow' }
            $pre = $script:AtmTuiPre
            $vis = [math]::Max(1, $bodyH - 2 - $pre)
            if ($scr.Sel -ge $items.Count) { $scr.Sel = [math]::Max(0, $items.Count - 1) }
            if ($scr.Sel -lt $scr.Top) { $scr.Top = $scr.Sel }
            if ($scr.Sel -ge $scr.Top + $vis) { $scr.Top = $scr.Sel - $vis + 1 }
            # Only the visible page is formatted (thousands of items cost one page per frame).
            $last = [math]::Min($items.Count, $scr.Top + $vis)
            $page = @(for ($i = $scr.Top; $i -lt $last; $i++) { , (& $data.Row $items[$i] $State) })
            # Width - 2: the selection marker and the right edge, so the last (right-aligned) column stays visible.
            $tbl = Format-AtmTuiTable -Columns $data.Columns -Rows $page -Width ($w - 2) -G $G
            $lines.Add(@(New-AtmSeg (' ' + $tbl.Header) 'White' 'DarkGray'))
            if ($items.Count -eq 0) {
                # An empty list with incomplete coverage is "nothing observed", never "none".
                if ($null -ne $gp) { $lines.Add(@(New-AtmSeg ('  ' + (Get-AtmText 'tui.diag.emptyNotObserved')) 'Yellow')) }
                else { $lines.Add(@(New-AtmSeg ('  ' + (Get-AtmText 'common.none')) 'DarkGray')) }
            }
            for ($i = $scr.Top; $i -lt $last; $i++) {
                $txt = $(if ($i -eq $scr.Sel) { $G.Sel } else { ' ' }) + @($tbl.Lines)[$i - $scr.Top]
                if ($i -eq $scr.Sel) { $lines.Add(@(New-AtmSeg (Limit-AtmText $txt ($w - 1) $G.Ell) 'Black' 'Cyan')) } else { $lines.Add(@(New-AtmSeg (Limit-AtmText $txt ($w - 1) $G.Ell) (& $data.Color $items[$i] $State))) }
            }
            $footer = Get-AtmText 'foot.diagList' $(if ($items.Count) { $scr.Sel + 1 } else { 0 }) $items.Count
        }
        { $_ -in @('dsum', 'dcovdet', 'dfind', 'dnode') } {
            $tl = Get-AtmTuiDiagText -State $State -Screen $scr -Width $w
            $scr.Count = $tl.Count
            $vis = [math]::Max(1, $bodyH - 1)
            if ($scr.Top -gt [math]::Max(0, $tl.Count - $vis)) { $scr.Top = [math]::Max(0, $tl.Count - $vis) }
            $last = [math]::Min($tl.Count, $scr.Top + $vis)
            for ($i = $scr.Top; $i -lt $last; $i++) { $lines.Add(@(New-AtmSeg (' ' + $tl[$i].Text) $tl[$i].Fg)) }
            # Where the visible lines are, so more content is never hidden silently.
            $footer = Get-AtmText 'foot.diagText' $(if ($tl.Count) { $scr.Top + 1 } else { 0 }) $last $tl.Count
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
    # The message and the footer (keys) always stay on screen: the body gives way when the frame is taller.
    $msg = @(if ($State.Message) { Split-AtmWrap $State.Message ($w - 3) })
    $room = [math]::Max(1, $h - 1 - $msg.Count)
    if ($lines.Count -gt $room) { $lines.RemoveRange($room, $lines.Count - $room) }
    foreach ($mp in $msg) { $lines.Add(@(New-AtmSeg (' ' + $mp) 'Yellow')) }
    while ($lines.Count -lt $h - 1) { $lines.Add(@(New-AtmSeg '')) }
    if ($lines.Count -gt [math]::Max(1, $h - 1)) { $lines.RemoveRange([math]::Max(1, $h - 1), $lines.Count - [math]::Max(1, $h - 1)) }
    $lines.Add(@(New-AtmSeg (Limit-AtmText (' ' + $footer) ($w - 1) $G.Ell) 'Black' 'Gray'))
    $clipped = New-Object System.Collections.Generic.List[object]
    foreach ($ln in ($lines.ToArray() | Select-Object -First ([math]::Max(1, $h)))) { $clipped.Add((Limit-AtmTuiLine -Line $ln -Width ($w - 1))) }
    return $clipped.ToArray()
}

function Write-AtmTuiFrameToConsole {
    param($Frame, [int]$Width, [int]$Height = 0)
    try { [Console]::SetCursorPosition(0, 0) } catch { Clear-Host }
    # Every row of the window is written: a frame shorter than the one before (the busy screen of R or D drawn over
    # the menu) must not leave the previous screen's rows visible below it. Overwritten in place, never cleared.
    $rows = [math]::Max(@($Frame).Count, $Height)
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
        if ($n -lt $rows) { Write-Host '' }
    }
    while ($n -lt $rows) {
        Write-Host (' ' * ($Width - 1)) -NoNewline
        $n++
        if ($n -lt $rows) { Write-Host '' }
    }
}

# ------------------------------------------------------------------ diagnose view (V0.2 P5-A, ADR-0009)
# Presentation only. The view is the diagnose JSON export (docs/DIAGNOSE-SCHEMA.md) of one Invoke-AtmDiagnose result,
# parsed back: it shows what the export may show and nothing of the V0.1 inventory (no path, account, machine name or
# command line); the identity block of the export is not shown either. Indexes are built once per result; navigation,
# paging and details never run anything again. Only an explicit action (entering the area the first time, or U) runs
# the diagnose.

$script:AtmTuiListScreens = @('users', 'projects', 'roots', 'gates', 'diag', 'dcov', 'dlist', 'dnodes', 'dissues')
$script:AtmTuiTextScreens = @('errors', 'detail', 'help', 'dsum', 'dcovdet', 'dfind', 'dnode')
$script:AtmTuiDiagScreens = @('diag', 'dcov', 'dlist', 'dnodes', 'dissues', 'dsum', 'dcovdet', 'dfind', 'dnode')
$script:AtmTuiDiagStateColor = @{ IN_USE = 'Red'; UNKNOWN = 'Yellow'; NO_DEPENDENCY_OBSERVED = 'Green'; RUNTIME_NOT_DIAGNOSED = 'DarkGray' }
# Strength is told by its marker, not by color alone.
$script:AtmTuiDiagStrength = @{ DIRECT = @('[D]', 'Green'); ANCESTOR = @('[A]', 'Yellow'); AMBIGUOUS = @('[?]', 'Magenta') }
$script:AtmTuiDiagCatKinds = @{ procs = @('Process', 'AgentSession'); services = @('Service'); virt = @('VirtualizationPlatform', 'VirtualMachine'); worktrees = @('Worktree', 'Repository'); parts = @('TempPartition') }
$script:AtmTuiDiagMaxEdges = 40
# Collectors whose coverage decides whether an empty or short category is "none" or "not observed".
$script:AtmTuiDiagCatCollectors = @{ parts = @('inventory'); procs = @('process-snapshot', 'agent-processes'); services = @('services'); virt = @('virtualization-platform', 'virtual-machines'); worktrees = @('worktree-discovery') }

function Format-AtmTuiUtc {
    # One display form for an exported time in both shells (PowerShell 7 parses ISO strings into dates).
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return '-' }
    $d = $null
    if ($Value -is [datetime]) { $d = $Value.ToUniversalTime() }
    else { try { $d = [datetime]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime() } catch { return [string]$Value } }
    return $d.ToString('yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) + ' UTC'
}

function New-AtmTuiDiagIndex {
    # One pass over findings, coverage and edges of the view (no O(N^2) work, nothing recomputed per screen).
    param($View)
    $cat = @{}
    foreach ($c in @($script:AtmTuiDiagCatKinds.Keys)) { $cat[$c] = [System.Collections.Generic.List[object]]::new() }
    $catOf = @{}
    foreach ($c in @($script:AtmTuiDiagCatKinds.Keys)) { foreach ($k in $script:AtmTuiDiagCatKinds[$c]) { $catOf[$k] = $c } }
    $findingBy = @{}; $unknown = [System.Collections.Generic.List[object]]::new()
    foreach ($x in @($View.findings)) {
        if ($null -eq $x) { continue }
        $k = [string]$x.kind
        if ($catOf.ContainsKey($k)) { $cat[$catOf[$k]].Add($x) }
        $findingBy[$k + '|' + [string]$x.key] = $x
        if ([string]$x.state -ceq 'UNKNOWN') { $unknown.Add($x) }
    }
    # Worst record per collector.
    $covBy = @{}
    foreach ($c in @($View.coverage)) {
        if ($null -eq $c) { continue }
        $ck = [string]$c.collector
        if (-not $covBy.ContainsKey($ck) -or ($script:AtmConclusiveCoverage -ccontains [string]$covBy[$ck].status -and $script:AtmConclusiveCoverage -cnotcontains [string]$c.status)) { $covBy[$ck] = $c }
    }
    $nodes = @(); $inBy = @{}; $outBy = @{}; $nodeBy = @{}
    if ($null -ne $View.graph) {
        $nodes = @($View.graph.nodes | Where-Object { $null -ne $_ })
        foreach ($n in $nodes) { $nodeBy[[string]$n.kind + '|' + [string]$n.key] = $n }
        foreach ($e in @($View.graph.edges)) {
            if ($null -eq $e) { continue }
            $tk = [string]$e.toKind + '|' + [string]$e.to; $fk = [string]$e.fromKind + '|' + [string]$e.from
            if (-not $inBy.ContainsKey($tk)) { $inBy[$tk] = [System.Collections.Generic.List[object]]::new() }; $inBy[$tk].Add($e)
            if (-not $outBy.ContainsKey($fk)) { $outBy[$fk] = [System.Collections.Generic.List[object]]::new() }; $outBy[$fk].Add($e)
        }
    }
    $issues = [System.Collections.Generic.List[object]]::new()
    foreach ($c in @($View.coverage)) { if ($null -ne $c -and $script:AtmConclusiveCoverage -cnotcontains [string]$c.status) { $issues.Add([pscustomobject]@{ T = 'cov'; C = $c; F = $null }) } }
    foreach ($x in $unknown) { $issues.Add([pscustomobject]@{ T = 'find'; C = $null; F = $x }) }
    $byCat = @{}; foreach ($c in @($cat.Keys)) { $byCat[$c] = $cat[$c].ToArray() }
    # Coverage gap of each category: the collectors that are missing or not conclusive (null when conclusive).
    $gap = @{}
    foreach ($c in @($script:AtmTuiDiagCatCollectors.Keys)) {
        $parts = [System.Collections.Generic.List[string]]::new(); $why = [System.Collections.Generic.List[string]]::new(); $missing = 0
        foreach ($cn in $script:AtmTuiDiagCatCollectors[$c]) {
            if (-not $covBy.ContainsKey($cn)) { $parts.Add($cn + '=-'); $missing++; continue }
            $r = $covBy[$cn]
            if ($script:AtmConclusiveCoverage -cnotcontains [string]$r.status) { $parts.Add($cn + '=' + [string]$r.status); foreach ($x in @($r.reasons)) { $why.Add([string]$x) } }
        }
        $gap[$c] = $(if ($parts.Count -eq 0) { $null } else { [pscustomobject]@{ Status = ($parts -join ', '); Reasons = $(if ($why.Count) { $why -join ',' } else { '-' }); AllMissing = ($missing -eq @($script:AtmTuiDiagCatCollectors[$c]).Count) } })
    }
    # Summary figures, once per result (the summary screen only formats them).
    $kinds = @(@($View.findings) | Where-Object { $null -ne $_ } | Group-Object { [string]$_.kind } | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Kind = $_.Name; Count = $_.Count; States = (@($_.Group | Group-Object { [string]$_.state } | Sort-Object Name | ForEach-Object { $_.Name + ' ' + $_.Count }) -join ', ') } })
    $cnt = { param($Arr, [scriptblock]$Pred) $n = 0; foreach ($y in $Arr) { if (& $Pred $y) { $n++ } }; $n }
    $tp = $byCat['parts']; $pc = $byCat['procs']
    $sum = [pscustomobject]@{
        Kinds = $kinds
        PartsInUse = (& $cnt $tp { param($y) [string]$y.state -ceq 'IN_USE' }); PartsUnknown = (& $cnt $tp { param($y) [string]$y.state -ceq 'UNKNOWN' }); PartsNone = (& $cnt $tp { param($y) [string]$y.state -ceq 'NO_DEPENDENCY_OBSERVED' })
        ProcVerified = (& $cnt $pc { param($y) [string]$y.kind -ceq 'Process' -and ([string]$y.key).Contains('@') }); ProcUnverified = (& $cnt $pc { param($y) [string]$y.kind -ceq 'Process' -and -not ([string]$y.key).Contains('@') })
        Sessions = (& $cnt $pc { param($y) [string]$y.kind -ceq 'AgentSession' }); Services = @($byCat['services']).Count
        Vms = (& $cnt $byCat['virt'] { param($y) [string]$y.kind -ceq 'VirtualMachine' }); Worktrees = (& $cnt $byCat['worktrees'] { param($y) [string]$y.kind -ceq 'Worktree' })
        Incomplete = @(@($View.coverage) | Where-Object { $null -ne $_ -and $script:AtmConclusiveCoverage -cnotcontains [string]$_.status })
    }
    return [pscustomobject]@{ ByCat = $byCat; Gap = $gap; Sum = $sum; FindingBy = $findingBy; CovBy = $covBy; Coverage = @($View.coverage | Where-Object { $null -ne $_ }); Nodes = $nodes; NodeBy = $nodeBy; InBy = $inBy; OutBy = $outBy; Issues = $issues.ToArray() }
}

function Get-AtmTuiDiagCategories {
    param($State)
    $ix = $State.Diag.Index
    # A count whose coverage is incomplete carries '*': it is what was observed, never proof that there is no more.
    $n = { param($c) [string]@($ix.ByCat[$c]).Count + $(if ($null -ne $ix.Gap[$c]) { '*' } else { '' }) }
    return @(
        @{ Label = (Get-AtmText 'tui.diag.cat.summary'); Count = '-'; Push = @{ Name = 'dsum'; Title = (Get-AtmText 'tui.diag.cat.summary') } }
        @{ Label = (Get-AtmText 'tui.diag.cat.coverage'); Count = @($ix.Coverage).Count; Push = @{ Name = 'dcov'; Title = (Get-AtmText 'tui.diag.cat.coverage') } }
        @{ Label = (Get-AtmText 'tui.diag.cat.procs'); Count = (& $n 'procs'); Push = @{ Name = 'dlist'; Title = (Get-AtmText 'tui.diag.cat.procs'); Filter = @{ Cat = 'procs' } } }
        @{ Label = (Get-AtmText 'tui.diag.cat.services'); Count = (& $n 'services'); Push = @{ Name = 'dlist'; Title = (Get-AtmText 'tui.diag.cat.services'); Filter = @{ Cat = 'services' } } }
        @{ Label = (Get-AtmText 'tui.diag.cat.virt'); Count = (& $n 'virt'); Push = @{ Name = 'dlist'; Title = (Get-AtmText 'tui.diag.cat.virt'); Filter = @{ Cat = 'virt' } } }
        @{ Label = (Get-AtmText 'tui.diag.cat.worktrees'); Count = (& $n 'worktrees'); Push = @{ Name = 'dlist'; Title = (Get-AtmText 'tui.diag.cat.worktrees'); Filter = @{ Cat = 'worktrees' } } }
        @{ Label = (Get-AtmText 'tui.diag.cat.parts'); Count = (& $n 'parts'); Push = @{ Name = 'dlist'; Title = (Get-AtmText 'tui.diag.cat.parts'); Filter = @{ Cat = 'parts' } } }
        @{ Label = (Get-AtmText 'tui.diag.cat.graph'); Count = @($ix.Nodes).Count; Push = @{ Name = 'dnodes'; Title = (Get-AtmText 'tui.diag.cat.graph') } }
        @{ Label = (Get-AtmText 'tui.diag.cat.issues'); Count = @($ix.Issues).Count; Push = @{ Name = 'dissues'; Title = (Get-AtmText 'tui.diag.cat.issues') } }
    )
}

function Get-AtmTuiDiagList {
    # Columns, the items of a diagnose list screen and how one item becomes a row; only visible rows are formatted.
    param($State, $Screen)
    $ix = $State.Diag.Index; $w = $State.Width
    $narrow = ($w -lt 90)
    switch ($Screen.Name) {
        'diag' {
            return [pscustomobject]@{ Columns = @(@{ Name = (Get-AtmText 'tui.diag.col.area'); Width = 0 }, @{ Name = (Get-AtmText 'tui.diag.col.items'); Width = 8; Right = $true })
                Items = @(Get-AtmTuiDiagCategories $State); Row = { param($i, $S) , @($i.Label, [string]$i.Count) }; Color = { param($i, $S) 'Gray' } }
        }
        'dcov' {
            $cols = @(@{ Name = (Get-AtmText 'tui.diag.col.collector'); Width = $(if ($narrow) { 18 } else { 26 }) }, @{ Name = (Get-AtmText 'tui.diag.col.status'); Width = 15 }, @{ Name = (Get-AtmText 'tui.diag.col.reasons'); Width = 0 })
            if (-not $narrow) { $cols += @{ Name = (Get-AtmText 'tui.diag.col.elev'); Width = 8 } }
            return [pscustomobject]@{ Columns = $cols; Items = $ix.Coverage
                Row = { param($c, $S) $r = @([string]$c.collector, [string]$c.status, $(if (@($c.reasons).Count) { @($c.reasons) -join ',' } else { '-' })); if ($S.Width -ge 90) { $r += [string]$c.elevationWouldHelp }; , $r }
                Color = { param($c, $S) if ($script:AtmConclusiveCoverage -ccontains [string]$c.status) { 'Gray' } else { 'Yellow' } } }
        }
        'dlist' {
            $cols = @(@{ Name = (Get-AtmText 'tui.diag.col.state'); Width = $(if ($narrow) { 16 } else { 24 }) }, @{ Name = (Get-AtmText 'tui.diag.col.kind'); Width = $(if ($narrow) { 12 } else { 22 }) }, @{ Name = (Get-AtmText 'tui.diag.col.key'); Width = 0 })
            if (-not $narrow) { $cols += @{ Name = (Get-AtmText 'tui.diag.col.provider'); Width = 16 } }
            return [pscustomobject]@{ Columns = $cols; Items = $ix.ByCat[$Screen.Filter.Cat]
                Row = { param($f, $S) $r = @([string]$f.state, [string]$f.kind, [string]$f.key); if ($S.Width -ge 90) { $r += $(if ($f.provider) { [string]$f.provider } else { '-' }) }; , $r }
                Color = { param($f, $S) $c = $script:AtmTuiDiagStateColor[[string]$f.state]; if ($c) { $c } else { 'Gray' } } }
        }
        'dnodes' {
            $cols = @(@{ Name = (Get-AtmText 'tui.diag.col.kind'); Width = $(if ($narrow) { 12 } else { 22 }) }, @{ Name = (Get-AtmText 'tui.diag.col.key'); Width = 0 }, @{ Name = (Get-AtmText 'tui.diag.col.finding'); Width = $(if ($narrow) { 7 } else { 12 }) }, @{ Name = (Get-AtmText 'tui.diag.col.inout'); Width = 9; Right = $true })
            return [pscustomobject]@{ Columns = $cols; Items = $ix.Nodes
                Row = { param($n, $S) $x0 = $S.Diag.Index; $nk = [string]$n.kind + '|' + [string]$n.key; $i0 = $(if ($x0.InBy.ContainsKey($nk)) { $x0.InBy[$nk].Count } else { 0 }); $o0 = $(if ($x0.OutBy.ContainsKey($nk)) { $x0.OutBy[$nk].Count } else { 0 })
                    , @([string]$n.kind, [string]$n.key, $(if ($n.finding) { Get-AtmText 'tui.diag.findingShortYes' } else { Get-AtmText 'tui.diag.findingShortNo' }), "$i0/$o0") }
                Color = { param($n, $S) if ($n.finding) { 'Gray' } else { 'DarkCyan' } } }
        }
        'dissues' {
            $cols = @(@{ Name = (Get-AtmText 'tui.diag.col.type'); Width = 10 }, @{ Name = (Get-AtmText 'tui.diag.col.status'); Width = 15 }, @{ Name = (Get-AtmText 'tui.diag.col.item'); Width = 0 }, @{ Name = (Get-AtmText 'tui.diag.col.reasons'); Width = $(if ($narrow) { 14 } else { 34 }) })
            return [pscustomobject]@{ Columns = $cols; Items = $ix.Issues
                Row = { param($i, $S)
                    if ($i.T -ceq 'cov') { , @((Get-AtmText 'tui.diag.typeCov'), [string]$i.C.status, [string]$i.C.collector, $(if (@($i.C.reasons).Count) { @($i.C.reasons) -join ',' } else { '-' })) }
                    else { $why = @(@($i.F.evidence) | Where-Object { $_.code -ceq 'GRAPH_REASON' } | ForEach-Object { [string]$_.detail }) + @($i.F.incompleteCoverage); , @((Get-AtmText 'tui.diag.typeFind'), [string]$i.F.state, ([string]$i.F.kind + ' ' + [string]$i.F.key), $(if ($why.Count) { ($why | Select-Object -Unique) -join ',' } else { '-' })) } }
                Color = { param($i, $S) 'Yellow' } }
        }
    }
}

function Get-AtmTuiDiagEdgeLines {
    # Edges of a node, both directions, with marker, relation, the other end and the evidence (code, collector, detail).
    param($State, [string]$NodeKey, $Add)
    $ix = $State.Diag.Index
    foreach ($dir in @('in', 'out')) {
        $list = @(if ($dir -ceq 'in') { if ($ix.InBy.ContainsKey($NodeKey)) { $ix.InBy[$NodeKey].ToArray() } } else { if ($ix.OutBy.ContainsKey($NodeKey)) { $ix.OutBy[$NodeKey].ToArray() } })
        & $Add (Get-AtmText $(if ($dir -ceq 'in') { 'tui.diag.det.in' } else { 'tui.diag.det.out' }) $list.Count) 'White'
        if ($list.Count -eq 0) { & $Add ('  ' + (Get-AtmText 'common.none')) 'DarkGray' }
        $shown = 0
        foreach ($e in $list) {
            if ($shown -ge $script:AtmTuiDiagMaxEdges) { & $Add ('  ' + (Get-AtmText 'tui.diag.det.more' ($list.Count - $shown))) 'DarkGray'; break }
            $mk = $script:AtmTuiDiagStrength[[string]$e.strength]; if (-not $mk) { $mk = @('[ ]', 'Gray') }
            $other = $(if ($dir -ceq 'in') { [string]$e.fromKind + ' ' + [string]$e.from } else { [string]$e.toKind + ' ' + [string]$e.to })
            $arrow = $(if ($dir -ceq 'in') { '<-' } else { '->' })
            $amb = $(if ([string]$e.strength -ceq 'AMBIGUOUS') { ' ' + (Get-AtmText 'tui.diag.ambEdge') } else { '' })
            & $Add ('  {0} {1} {2} {3}{4}' -f $mk[0], [string]$e.relation, $arrow, $other, $amb) $mk[1]
            foreach ($ev in @($e.evidence)) { & $Add ('      {0} [{1}]{2}' -f [string]$ev.code, [string]$ev.collector, $(if ($ev.detail) { ' ' + [string]$ev.detail } else { '' })) 'DarkGray' }
            $shown++
        }
    }
}

function Get-AtmTuiDiagText {
    param($State, $Screen, [int]$Width)
    $D = $State.Diag; $v = $D.View; $ix = $D.Index
    $L = New-Object System.Collections.Generic.List[object]
    $add = { param($t, $fg = 'Gray') foreach ($w in (Split-AtmWrap $t ($Width - 2))) { $L.Add([pscustomobject]@{ Text = $w; Fg = $fg }) } }
    $covLine = {
        param([string]$Label, [int]$Count, [string]$Cat)
        $gp = $ix.Gap[$Cat]
        if ($null -eq $gp) { & $add (Get-AtmText 'tui.diag.sumCount' $Label $Count) }
        elseif ($gp.AllMissing) { & $add (Get-AtmText 'tui.diag.sumNotObserved' $Label (@($script:AtmTuiDiagCatCollectors[$Cat]) -join ',')) 'Yellow' }
        else { & $add (Get-AtmText 'tui.diag.sumCountPartial' $Label $Count $gp.Status $gp.Reasons) 'Yellow' }
    }
    $gapNote = { param([string]$Cat) $gp = $ix.Gap[$Cat]; if ($null -ne $gp) { & $add ('  ' + (Get-AtmText 'tui.diag.covNote' $gp.Status $gp.Reasons)) 'Yellow' } }
    switch ($Screen.Name) {
        'dsum' {
            & $add (Get-AtmText 'tui.diag.lastRun' (Format-AtmTuiUtc $v.finishedUtc)) 'White'
            if ($D.Stale) { & $add (Get-AtmText 'tui.diag.stale' $D.Error) 'Red' }
            & $add (Get-AtmText 'tui.diag.noAuth') 'Green'
            & $add ''
            $sm = $ix.Sum
            $inc = $sm.Incomplete
            & $add (Get-AtmText 'tui.diag.sumCoverage' $(if ($v.coverageComplete) { Get-AtmText 'common.complete' } else { Get-AtmText 'common.incomplete' })) $(if ($v.coverageComplete) { 'Green' } else { 'Yellow' })
            if ($inc.Count) { & $add (Get-AtmText 'tui.diag.sumIncomplete' (@($inc | ForEach-Object { [string]$_.collector + '=' + [string]$_.status }) -join ', ')) 'Yellow' }
            & $add ''
            foreach ($g in $sm.Kinds) { & $add (Get-AtmText 'tui.diag.sumKind' $g.Kind $g.Count $g.States) }
            & $add ''
            & $add (Get-AtmText 'tui.diag.sumParts' $sm.PartsInUse $sm.PartsUnknown $sm.PartsNone) 'White'
            & $gapNote 'parts'
            & $add (Get-AtmText 'tui.diag.sumProcs' $sm.ProcVerified $sm.ProcUnverified $sm.Sessions)
            & $gapNote 'procs'
            & $covLine (Get-AtmText 'tui.diag.lblServices') $sm.Services 'services'
            & $covLine (Get-AtmText 'tui.diag.lblVms') $sm.Vms 'virt'
            & $covLine (Get-AtmText 'tui.diag.lblWorktrees') $sm.Worktrees 'worktrees'
            $gc = $(if ($null -ne $v.graph) { $v.graph.coverage } else { $null })
            if ($null -ne $gc) { & $add (Get-AtmText 'tui.diag.sumGraph' $gc.nodes $gc.edges ([string]$gc.status + $(if (@($gc.reasons).Count) { ' (' + (@($gc.reasons) -join ',') + ')' } else { '' }))) $(if ([string]$gc.status -ceq 'COMPLETE') { 'Gray' } else { 'Yellow' }) }
            if ($inc.Count) {
                & $add ''
                & $add (Get-AtmText 'tui.diag.sumLimits') 'White'
                foreach ($c in $inc) { & $add ('  ' + (Get-AtmText 'tui.diag.limitLine' ([string]$c.collector) ([string]$c.status) $(if (@($c.reasons).Count) { @($c.reasons) -join ',' } else { '-' }))) 'Yellow' }
            }
            & $add ''
            & $add (Get-AtmText 'tui.diag.unknownNote') 'DarkGray'
        }
        'dcovdet' {
            $c = $Screen.Filter.C
            & $add ('{0,-22}: {1}' -f (Get-AtmText 'tui.diag.col.collector'), [string]$c.collector)
            & $add ('{0,-22}: {1} - {2}' -f (Get-AtmText 'tui.diag.col.status'), [string]$c.status, (Get-AtmText ('coverage.' + [string]$c.status))) $(if ($script:AtmConclusiveCoverage -ccontains [string]$c.status) { 'Gray' } else { 'Yellow' })
            if ($null -ne $c.observed -and $null -ne $c.expected) { & $add (Get-AtmText 'tui.diag.cov.observed' $c.observed $c.expected) }
            & $add (Get-AtmText $(switch ([string]$c.elevationWouldHelp) { 'YES' { 'tui.diag.elevYes' } 'NO' { 'tui.diag.elevNo' } default { 'tui.diag.elevUnknown' } }))
            & $add ''
            & $add (Get-AtmText 'tui.diag.col.reasons') 'White'
            if (@($c.reasons).Count -eq 0) { & $add ('  ' + (Get-AtmText 'common.none')) 'DarkGray' }
            foreach ($x in @($c.reasons)) { $tx = Get-AtmCodeText 'reason' ([string]$x); & $add ('  ' + [string]$x + $(if ($tx) { ' - ' + $tx } else { '' })) 'Yellow' }
        }
        'dfind' {
            $f = $Screen.Filter.F
            $nk = [string]$f.kind + '|' + [string]$f.key
            & $add ('{0,-22}: {1}' -f (Get-AtmText 'tui.diag.col.kind'), [string]$f.kind)
            & $add ('{0,-22}: {1}' -f (Get-AtmText 'tui.diag.det.key'), [string]$f.key)
            $sc = $script:AtmTuiDiagStateColor[[string]$f.state]; if (-not $sc) { $sc = 'Gray' }
            & $add ('{0,-22}: {1}' -f (Get-AtmText 'tui.diag.col.state'), [string]$f.state) $sc
            if ($f.requestedState -and [string]$f.requestedState -cne [string]$f.state) { & $add ('{0,-22}: {1}' -f (Get-AtmText 'tui.diag.det.requested'), [string]$f.requestedState) 'Yellow' }
            $amb = @(@($f.evidence) | Where-Object { $_.code -ceq 'PROVIDER_ATTRIBUTION_AMBIGUOUS' } | ForEach-Object { [string]$_.detail })
            if ($amb.Count) { & $add ('{0,-22}: {1}' -f (Get-AtmText 'tui.diag.col.provider'), (Get-AtmText 'tui.diag.det.providerAmbiguous' ($amb -join ','))) 'Magenta' }
            elseif ($f.provider) { & $add ('{0,-22}: {1}' -f (Get-AtmText 'tui.diag.col.provider'), [string]$f.provider) }
            $times = @(@($f.evidence) | ForEach-Object { Format-AtmTuiUtc $_.observedUtc } | Where-Object { $_ -ne '-' } | Sort-Object -Unique)
            & $add ('{0,-22}: {1}' -f (Get-AtmText 'tui.diag.det.observed'), $(if ($times.Count) { $times -join ', ' } else { '-' }))
            if ([string]$f.state -ceq 'UNKNOWN') { & $add (Get-AtmText 'tui.diag.unknownNote') 'Yellow' }
            & $add ''
            & $add (Get-AtmText 'tui.diag.det.evidence') 'White'
            if (@($f.evidence).Count -eq 0) { & $add ('  ' + (Get-AtmText 'common.none')) 'DarkGray' }
            foreach ($ev in @($f.evidence)) {
                $tx = Get-AtmCodeText 'evidence' ([string]$ev.code)
                & $add ('  - {0} [{1}]{2}{3}' -f [string]$ev.code, [string]$ev.collector, $(if ($ev.detail) { ' ' + [string]$ev.detail } else { '' }), $(if ($tx) { ' - ' + $tx } else { '' }))
            }
            & $add ''
            & $add (Get-AtmText 'tui.diag.det.coverage') 'White'
            foreach ($cn in @($f.coverage)) { $cr = $(if ($ix.CovBy.ContainsKey([string]$cn)) { [string]$ix.CovBy[[string]$cn].status } else { '-' }); & $add ('  - {0}: {1}' -f [string]$cn, $cr) $(if ($script:AtmConclusiveCoverage -ccontains $cr) { 'Gray' } else { 'Yellow' }) }
            & $add ('{0}: {1}' -f (Get-AtmText 'tui.diag.det.incomplete'), $(if (@($f.incompleteCoverage).Count) { @($f.incompleteCoverage) -join ', ' } else { Get-AtmText 'common.none' })) $(if (@($f.incompleteCoverage).Count) { 'Yellow' } else { 'Gray' })
            & $add ''
            & $add (Get-AtmText 'tui.diag.det.graph') 'White'
            & $add (Get-AtmText 'tui.diag.legend') 'DarkGray'
            if (-not $ix.NodeBy.ContainsKey($nk)) { & $add ('  ' + (Get-AtmText 'tui.diag.det.noNode')) 'DarkGray' }
            else { Get-AtmTuiDiagEdgeLines -State $State -NodeKey $nk -Add $add }
        }
        'dnode' {
            $n = $Screen.Filter.N
            $nk = [string]$n.kind + '|' + [string]$n.key
            & $add ('{0,-22}: {1}' -f (Get-AtmText 'tui.diag.col.kind'), [string]$n.kind)
            & $add ('{0,-22}: {1}' -f (Get-AtmText 'tui.diag.det.key'), [string]$n.key)
            if ($n.finding) {
                & $add ('{0,-22}: {1}' -f (Get-AtmText 'tui.diag.col.finding'), (Get-AtmText 'tui.diag.finding.yes'))
                if ($ix.FindingBy.ContainsKey($nk)) { & $add ('{0,-22}: {1}' -f (Get-AtmText 'tui.diag.col.state'), [string]$ix.FindingBy[$nk].state) }
            } else { & $add ('{0,-22}: {1}' -f (Get-AtmText 'tui.diag.col.finding'), (Get-AtmText 'tui.diag.finding.no')) 'DarkCyan' }
            & $add (Get-AtmText 'tui.diag.legend') 'DarkGray'
            & $add ''
            Get-AtmTuiDiagEdgeLines -State $State -NodeKey $nk -Add $add
        }
    }
    return $L.ToArray()
}

function Invoke-AtmTuiDiagnose {
    # The only place the TUI runs the diagnose (explicit action). A failure keeps the previous view, marked outdated,
    # and reports the exception TYPE only (its message could carry collected data). Never retried by itself.
    param($State)
    # Dynamic scoping (no GetNewClosure: closures cannot see script-scope functions).
    $tuiDiagState = $State
    $a = @{} + $State.DiagnoseArgs
    if ($a.ContainsKey('InventoryArgs')) {
        $ia = @{} + $a['InventoryArgs']
        # Progress shows a percentage and a fixed text only: the inventory's own messages name temporary bases.
        $ia['NoProgress'] = $false
        $ia['ProgressCallback'] = { param($pct, $msg) & $tuiDiagState.Draw (Get-AtmTuiBusyFrame -State $tuiDiagState -Text (Get-AtmText 'tui.diag.running') -Percent $pct -Diag) }
        $a['InventoryArgs'] = $ia
    }
    & $State.Draw (Get-AtmTuiBusyFrame -State $State -Text (Get-AtmText 'tui.diag.running') -Diag)
    $State.DiagRuns++
    $code = $null; $view = $null
    try { $res = & $State.DiagnoseRunner $a; $view = (ConvertTo-AtmDiagnoseJson -Result $res) | ConvertFrom-Json } catch { $code = ConvertTo-AtmExceptionCode $_.Exception.GetType().Name }
    if ($null -ne $code) {
        if ($null -ne $State.Diag -and $null -ne $State.Diag.View) { $State.Diag.Stale = $true; $State.Diag.Error = $code }
        else { $State.Diag = @{ View = $null; Index = $null; Stale = $false; Error = $code } }
        $State.Message = Get-AtmText 'tui.diag.failed' $code
        return $false
    }
    $State.Diag = @{ View = $view; Index = (New-AtmTuiDiagIndex -View $view); Stale = $false; Error = $null }
    return $true
}

# ------------------------------------------------------------------ actions

function Invoke-AtmTuiAudit {
    param($State)
    $State.Preview = $null
    # Dynamic scoping (no GetNewClosure: closures cannot see script-scope functions).
    $tuiAuditState = $State
    $cb = { param($pct, $msg) & $tuiAuditState.Draw (Get-AtmTuiBusyFrame -State $tuiAuditState -Text $msg -Percent $pct) }
    # Drawn before the inventory starts (its first progress call comes after its own setup).
    & $State.Draw (Get-AtmTuiBusyFrame -State $State -Text (Get-AtmText 'tui.auditStarting'))
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
    $reader = { param($phrase, $kind, $rootPath, $choices) Read-AtmCleanAnswer -Phrase $phrase -Kind $kind -RootPath $rootPath -Choices $choices -LineReader $tuiRead }
    # T1: only with real deletion enabled (never in a distributed copy) the engine requires a new log file; the TUI asks
    # for it and never picks one. An empty answer passes none and the engine refuses the run (LOG_REQUIRED).
    $logFile = $null
    if ($script:AtmRealDeletionEnabled) { $logFile = & $tuiRead (Get-AtmText 'tuiclean.askLog') }
    $a = @{} + $State.InventoryArgs
    $a['NoProgress'] = $true
    $res = Invoke-AtmClean -Entries $entries -IncludeOtherUsers:$other -PlanPresenter $presenter -ConfirmationReader $reader -InventoryArgs $a -LogFile $logFile -Interaction @{ Caller = 'TUI'; ConsoleRequired = $true }
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
      -LineReader    : scriptblock(prompt[, phrase shown]) -> string (default Read-Host)
      -Width/-Height : fixed size (tests); default = console window
      -DiagnoseArgs  : splatted into Invoke-AtmDiagnose (default: the inventory arguments above)
      -DiagnoseRunner: scriptblock(args) -> diagnose result (tests; default Invoke-AtmDiagnose)
    #>
    param([hashtable]$InventoryArgs = @{}, [scriptblock]$KeySource, [scriptblock]$Renderer, [scriptblock]$LineReader, [switch]$Ascii, [int]$Width = 0, [int]$Height = 0, $Inventory,
        [hashtable]$DiagnoseArgs = $null, [scriptblock]$DiagnoseRunner = $null, [scriptblock]$KeyFlush = $null)
    $headless = [bool]$Renderer
    $useAscii = $Ascii -or -not (Test-AtmTuiUnicodeDefault)
    # Callbacks below rely on dynamic scoping with tui-prefixed names (no GetNewClosure: such closures
    # cannot resolve script-scope functions).
    $tuiState = @{
        G = (Get-AtmTuiGlyphs $useAscii); Width = 120; Height = 36; Stack = New-Object System.Collections.Generic.List[object]
        Inventory = $Inventory; Preview = $null; Message = $null; InventoryArgs = $InventoryArgs; LastClean = $null; Frames = 0
        Diag = $null; DiagRuns = 0
        DiagnoseArgs = $(if ($null -ne $DiagnoseArgs) { $DiagnoseArgs } else { @{ InventoryArgs = (@{} + $InventoryArgs) } })
        DiagnoseRunner = $(if ($null -ne $DiagnoseRunner) { $DiagnoseRunner } else { { param($a) Invoke-AtmDiagnose @a } })
    }
    $tuiHeadless = $headless
    $sizeOf = {
        if ($Width -gt 0) { $tuiState.Width = $Width; $tuiState.Height = $Height; return }
        # Console size unavailable (redirected output): the previous size is kept; cosmetic only.
        try { $tuiState.Width = [math]::Max(40, [Console]::WindowWidth); $tuiState.Height = [math]::Max(15, [Console]::WindowHeight) } catch { $null = $_ }
    }
    if (-not $KeySource) { $KeySource = { [Console]::ReadKey($true) } }
    if (-not $LineReader) { $LineReader = { param($prompt) Read-Host $prompt } }
    if (-not $Renderer) { $Renderer = { param($frame) Write-AtmTuiFrameToConsole -Frame $frame -Width $tuiState.Width -Height $tuiState.Height } }
    # Keys typed while R, D or U run are discarded when the work ends: a menu key pressed meanwhile must not run then.
    if (-not $KeyFlush) { $KeyFlush = $(if ($headless) { { } } else { { try { while ([Console]::KeyAvailable) { $null = [Console]::ReadKey($true) } } catch { $null = $_ } } }) }
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
                'UpArrow' { if ($scr.Name -in $script:AtmTuiTextScreens) { $scr.Top = [math]::Max(0, $scr.Top - 1) } else { $scr.Sel = [math]::Max(0, $scr.Sel - 1) }; continue }
                'DownArrow' {
                    if ($scr.Name -in $script:AtmTuiTextScreens) { $scr.Top++ }
                    elseif ($scr.Name -eq 'menu') { $scr.Sel = [math]::Min((Get-AtmTuiMenuItems).Count - 1, $scr.Sel + 1) }
                    else { $scr.Sel = [math]::Min([math]::Max(0, $scr.Count - 1), $scr.Sel + 1) }
                    continue
                }
                'PageUp' { if ($scr.Name -in $script:AtmTuiTextScreens) { $scr.Top = [math]::Max(0, $scr.Top - $page) } else { $scr.Sel = [math]::Max(0, $scr.Sel - $page) }; continue }
                'PageDown' { if ($scr.Name -in $script:AtmTuiTextScreens) { $scr.Top += $page } else { $scr.Sel = [math]::Min([math]::Max(0, $scr.Count - 1), $scr.Sel + $page) }; continue }
                'Home' { $scr.Sel = 0; $scr.Top = 0; continue }
                'End' { if ($scr.Name -in $script:AtmTuiTextScreens) { $scr.Top = [math]::Max(0, $scr.Count - 1) } else { $scr.Sel = [math]::Max(0, $scr.Count - 1) }; continue }
                { $_ -in @('Escape', 'Backspace') } {
                    if ($state.Stack.Count -gt 1) { $state.Stack.RemoveAt($state.Stack.Count - 1); continue }
                    if ($k.Key -eq 'Escape') { return $state }
                    continue
                }
                'Enter' {
                    if ($scr.Name -eq 'menu') { $push = (Get-AtmTuiMenuItems)[$scr.Sel].Screen }
                    elseif ($scr.Name -in @('diag', 'dcov', 'dlist', 'dnodes', 'dissues')) {
                        $items = (Get-AtmTuiDiagList -State $state -Screen $scr).Items; if ($null -eq $items) { $items = @() }
                        if ($items.Count -gt 0) {
                            $it = $items[[math]::Min($scr.Sel, $items.Count - 1)]
                            switch ($scr.Name) {
                                'diag' { $push = $it.Push }
                                'dcov' { $push = @{ Name = 'dcovdet'; Title = [string]$it.collector; Filter = @{ C = $it } } }
                                'dlist' { $push = @{ Name = 'dfind'; Title = [string]$it.kind; Filter = @{ F = $it } } }
                                'dnodes' { $push = @{ Name = 'dnode'; Title = [string]$it.kind; Filter = @{ N = $it } } }
                                'dissues' { if ($it.T -ceq 'cov') { $push = @{ Name = 'dcovdet'; Title = [string]$it.C.collector; Filter = @{ C = $it.C } } } else { $push = @{ Name = 'dfind'; Title = [string]$it.F.kind; Filter = @{ F = $it.F } } } }
                            }
                        }
                    }
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
                    $inDiag = ($script:AtmTuiDiagScreens -contains $scr.Name)
                    # U (diagnostics area only): a new observation, on request; the screens above the area are closed
                    # because they show items of the previous result.
                    if ($inDiag -and $ch -match '^[uU]$') { $push = @{ Name = 'diagrefresh' } }
                    elseif ($inDiag) { $null = $ch }
                    elseif ($ch -match '^[rR]$') { $push = @{ Name = 'reaudit' } }
                    elseif ($scr.Name -eq 'menu') {
                        $m = @(Get-AtmTuiMenuItems | Where-Object { $_.Key -eq $ch.ToUpperInvariant() })
                        if ($m.Count -eq 1) { $push = $m[0].Screen }
                    }
                }
            }
            if ($push) {
                switch ($push.Name) {
                    'quit' { return $state }
                    'reaudit' { Invoke-AtmTuiAudit -State $state; & $KeyFlush; $state.Message = (Get-AtmText 'tui.reaudited') }
                    'diagrefresh' {
                        $okU = Invoke-AtmTuiDiagnose -State $state; & $KeyFlush
                        if ($okU) { $state.Message = (Get-AtmText 'tui.diag.refreshed') }
                        while ($state.Stack.Count -gt 1 -and $state.Stack[$state.Stack.Count - 1].Name -cne 'diag') { $state.Stack.RemoveAt($state.Stack.Count - 1) }
                        if ($state.Stack.Count -gt 1) { $state.Stack[$state.Stack.Count - 1].Sel = 0; $state.Stack[$state.Stack.Count - 1].Top = 0 }
                    }
                    'diag' {
                        # Entering the area runs the diagnose only when there is no result yet (explicit action).
                        $ok = ($null -ne $state.Diag -and $null -ne $state.Diag.View)
                        if (-not $ok) { $ok = Invoke-AtmTuiDiagnose -State $state; & $KeyFlush }
                        if ($ok) { $state.Stack.Add(@{ Name = 'diag'; Title = $push.Title; Sel = 0; Top = 0; Count = 0; Filter = $null }) }
                    }
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
