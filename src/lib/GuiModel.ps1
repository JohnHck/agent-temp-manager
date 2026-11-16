# Agent Temp Manager - view models of the desktop GUI (V0.2.1, docs/adr/ADR-0014-desktop-gui-winforms.md).
#
# Rules (ADR-0014 section 3):
#  * Plain PowerShell objects, no WinForms type: all view models are testable without a window.
#  * View models call only the engine read functions of the closed list; the static test of the suite reads this
#    file and src/lib/Gui.ps1 and fails on any other command.
#  * Nothing here decides: no class, eligibility, gate or coverage verdict is computed. The engine's results are only
#    counted and formatted, with the helpers the TUI dashboard uses (Get-AtmTuiDashboardLines).
#  * Loading this file defines functions and one numeric constant only (no assembly, no type, no state).
# Phase P1: the identity header (PRIV-10). Phase P2: the dashboard, the state of the view and the automatic purge
# notice (GUI-D1). Phase P3: the drill-down by user, project and root, the detail of a root, the coverage and errors
# screen, and the navigation between them (the TUI's screens, keys 1 to 7 and 9). Phase P4a: the screens of the preview
# (P every category, 8 the blocked paths) over the rows of the clean engine, and the Preview line of a detail opened
# from them; the categories, reasons and requirements are the engine's, as they come. Phase P4b: the diagnose area (D),
# the TUI's screens over the schema view of one diagnose result, with the features behind the V0.2 gates shown as
# disabled in this version.

function Get-AtmGuiIdentityHeader {
    # The process identity and its elevation state, as `version` shows them, and the language. -Source: test override
    # of the identity read (same shape as the engine's raw identity), passed through to the engine.
    param([scriptblock]$Source)
    $id = $(if ($null -ne $Source) { Get-AtmIdentityState -Source $Source } else { Get-AtmIdentityState })
    $name = [string]$id.Name
    $elevated = $(if ($null -eq $id.IsElevatedAdministrator) { 'UNKNOWN' } elseif ([bool]$id.IsElevatedAdministrator) { 'YES' } else { 'NO' })
    $nameText = $(if ([string]::IsNullOrEmpty($name)) { Get-AtmText 'gui.identityUnknown' } else { $name })
    $elevatedText = Get-AtmText ('gui.elevated.' + $elevated)
    [pscustomobject]@{
        Name            = $(if ([string]::IsNullOrEmpty($name)) { $null } else { $name })
        Elevated        = $elevated
        ElevationType   = [string]$id.ElevationType
        IntegrityLevel  = [string]$id.IntegrityLevel
        Title           = (Get-AtmText 'gui.title' $script:AtmVersion)
        IdentityLine    = (Get-AtmText 'gui.identity' $nameText)
        ElevationLine   = (Get-AtmText 'gui.elevation' $elevatedText ([string]$id.ElevationType) ([string]$id.IntegrityLevel))
        ReadOnlyLine    = (Get-AtmText 'gui.readOnly')
        Language        = (Get-AtmLanguage)
        LanguageLine    = (Get-AtmText 'gui.language' (Get-AtmLanguage))
    }
}

function Get-AtmGuiDashboardItem {
    # One line of a dashboard group: the value (a number, or UNKNOWN) and its text from the same catalog key as the TUI.
    param([string]$Id, [string]$Key, $Value)
    return [pscustomobject]@{ Id = $Id; Value = $Value; Text = (Get-AtmText $Key $Value) }
}

function Get-AtmGuiDashboard {
    # The four groups of the TUI dashboard (profiles; files, directories and partitions; space; errors and coverage),
    # the count and MB of each class and the audit time. -Inventory $null (before the first audit): every value is the
    # word UNKNOWN, never zero.
    param($Inventory)
    $known = ($null -ne $Inventory)
    $u = 'UNKNOWN'
    $parts = New-Object System.Collections.Generic.List[object]
    if ($known) { foreach ($p in @($Inventory.Partitions)) { if ($null -ne $p -and [string]$p.Kind -ne 'NotScanned') { $parts.Add($p) } } }
    $partArr = $parts.ToArray()
    $bytes = $(if ($known) { Get-AtmSum $partArr 'Bytes' } else { $null })
    $audited = 0; $measIncomplete = 0
    if ($known) {
        foreach ($pr in @($Inventory.Profiles)) { if ($null -ne $pr -and (Get-AtmProfileStatusLabel -Inventory $Inventory -ProfileInfo $pr) -like 'AUDITADO*') { $audited++ } }
        foreach ($p in $partArr) { if (-not $p.MeasurementComplete) { $measIncomplete++ } }
    }
    $coverage = $(if (-not $known) { $u } elseif ($Inventory.CoverageComplete) { Get-AtmText 'common.complete' } else { Get-AtmText 'common.incomplete' })
    $groups = @(
        [pscustomobject]@{ Id = 'profiles'; Title = (Get-AtmText 'dash.profiles'); Items = @(
                (Get-AtmGuiDashboardItem 'discovered' 'dash.discovered' $(if ($known) { @($Inventory.Profiles).Count } else { $u })),
                (Get-AtmGuiDashboardItem 'audited' 'dash.audited' $(if ($known) { $audited } else { $u })),
                (Get-AtmGuiDashboardItem 'incomplete' 'dash.incomplete' $(if ($known) { Get-AtmIncompleteProfileCount -Inventory $Inventory } else { $u }))) }
        [pscustomobject]@{ Id = 'filesDirs'; Title = (Get-AtmText 'dash.filesDirs'); Items = @(
                (Get-AtmGuiDashboardItem 'files' 'dash.files' $(if ($known) { Get-AtmSum $partArr 'Files' } else { $u })),
                (Get-AtmGuiDashboardItem 'dirs' 'dash.dirs' $(if ($known) { Get-AtmSum $partArr 'Dirs' } else { $u })),
                (Get-AtmGuiDashboardItem 'partitions' 'dash.partitions' $(if ($known) { $partArr.Count } else { $u }))) }
        [pscustomobject]@{ Id = 'space'; Title = (Get-AtmText 'dash.space'); Items = @(
                (Get-AtmGuiDashboardItem 'mbLogical' 'dash.mbLogical' $(if ($known) { Format-AtmMB $bytes } else { $u })),
                (Get-AtmGuiDashboardItem 'gbLogical' 'dash.gbLogical' $(if ($known) { Format-AtmGB $bytes } else { $u })),
                (Get-AtmGuiDashboardItem 'mbPhysical' 'dash.mbPhysical' $(if ($known) { Format-AtmMB (Get-AtmSum $partArr 'AllocatedBytesEstimate') } else { $u }))) }
        [pscustomobject]@{ Id = 'errorsCoverage'; Title = (Get-AtmText 'dash.errorsCoverage'); Items = @(
                (Get-AtmGuiDashboardItem 'readErrors' 'dash.readErrors' $(if ($known) { Get-AtmSum $partArr 'ErrorCount' } else { $u })),
                (Get-AtmGuiDashboardItem 'incompleteMeas' 'dash.incompleteMeas' $(if ($known) { $measIncomplete } else { $u })),
                (Get-AtmGuiDashboardItem 'coverage' 'dash.coverage' $coverage)) }
    )
    # The classes, in the TUI's order; the class is always written (no information by color alone).
    $classes = New-Object System.Collections.Generic.List[object]
    foreach ($c in @('ACTIVE_EVIDENCE', 'RECENT', 'LIVENESS_UNKNOWN', 'ORPHAN_SUSPECTED')) {
        if ($known) {
            $grp = New-Object System.Collections.Generic.List[object]
            foreach ($p in $partArr) { if ([string]$p.Class -eq $c) { $grp.Add($p) } }
            $classes.Add([pscustomobject]@{ Class = $c; Roots = $grp.Count; MB = (Format-AtmMB (Get-AtmSum ($grp.ToArray()) 'Bytes')) })
        } else { $classes.Add([pscustomobject]@{ Class = $c; Roots = $u; MB = $u }) }
    }
    return [pscustomobject]@{
        Known     = $known
        Groups    = $groups
        Classes   = $classes.ToArray()
        AuditTime = $(if ($known) { Get-AtmText 'dash.auditTime' (Format-AtmTime $Inventory.StartedUtc) (Format-AtmTime $Inventory.FinishedUtc) } else { Get-AtmText 'dash.auditTime' $u $u })
        OrphanInfo = (Get-AtmText 'dash.orphanInfo')
        ClassesTitle = (Get-AtmText 'dash.classes')
    }
}

function Get-AtmGuiViewState {
    # The state of the view (ADR-0014 section 5), always as a word: UNKNOWN before any audit has finished (a first audit
    # that failed leaves nothing known: UNKNOWN, with the exception type); STALE when the last audit failed (the earlier
    # result stays shown); PARTIAL when the engine's coverage is incomplete; CURRENT otherwise. P2 has no STALE by
    # slowness or age: those depend on the interval of P5.
    param($Inventory, [string]$FailureType, $RefreshedUtc)
    $at = $(if ($null -ne $RefreshedUtc) { ([datetime]$RefreshedUtc).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) } else { '-' })
    if ($null -eq $Inventory) {
        $code = 'UNKNOWN'
        $text = $(if ($FailureType) { Get-AtmText 'gui.state.UNKNOWN_FAILED' $FailureType } else { Get-AtmText 'gui.state.UNKNOWN' })
    } elseif ($FailureType) {
        $code = 'STALE'; $text = Get-AtmText 'gui.state.STALE' $at $FailureType
    } elseif (-not $Inventory.CoverageComplete) {
        $code = 'PARTIAL'; $text = Get-AtmText 'gui.state.PARTIAL' $at
    } else {
        $code = 'CURRENT'; $text = Get-AtmText 'gui.state.CURRENT' $at
    }
    return [pscustomobject]@{ Code = $code; FailureType = $(if ($FailureType) { $FailureType } else { $null }); RefreshedUtc = $at; Text = $text }
}

function Get-AtmGuiAutoPurgeNotice {
    # GUI-D1: the notice of the automatic purge, the lines the TUI shows (Get-AtmAutoPurgeNoticeLines), read once when
    # the window opens. Empty when the policy of this copy is absent, invalid or has the automatic purge off.
    param([string]$ConfigDir)
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($l in @(Get-AtmAutoPurgeNoticeLines -ConfigDir $ConfigDir)) { if ($l) { $lines.Add([string]$l) } }
    # Unrolled: callers wrap the result in @().
    return $lines.ToArray()
}

# ------------------------------------------------------------------ P3: drill-down, detail, coverage and errors
# Each screen is computed as the TUI computes it (Get-AtmTuiScreenRows and Get-AtmTuiTextLines in Tui.ps1), over the
# same inventory, with the same filters, order, catalog keys and text: the suite compares both, row by row. Only
# filtering, grouping, counting and formatting; the classes, the coverage and every other verdict are the engine's.

function Get-AtmGuiPartitionList {
    # The measured partitions (the TUI leaves NotScanned out). Unrolled: callers wrap the result in @().
    param($Inventory)
    $l = New-Object System.Collections.Generic.List[object]
    if ($null -ne $Inventory) { foreach ($p in @($Inventory.Partitions)) { if ($p.Kind -ne 'NotScanned') { $l.Add($p) } } }
    return $l.ToArray()
}

function Get-AtmGuiSorted {
    # List.Sort with the comparison Sort-Object applies: Sort-Object sorts its list with the same unstable algorithm, so
    # the order is the TUI's, equal keys included. Unrolled: callers wrap the result in @().
    param([object[]]$Items, [scriptblock]$Compare)
    $l = New-Object System.Collections.Generic.List[object]
    foreach ($i in $Items) { $l.Add($i) }
    $l.Sort([System.Comparison[object]]$Compare)
    return $l.ToArray()
}

function Get-AtmGuiOpt {
    # A key of a screen filter, as the TUI reads it (Get-AtmTuiOpt): $null when the filter or the key is absent.
    param($Table, [string]$Key)
    if ($Table -and $Table.ContainsKey($Key)) { return $Table[$Key] }
    return $null
}

function Get-AtmGuiNavItemList {
    # The screens of the TUI menu that the GUI shows (keys 1 to 9, P and D), with the TUI's labels, titles and filters.
    # D (P4b) opens the diagnose area; isolation, cleanup and the quarantine area are never offered (ADR-0014 section 6).
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
    )
}

function ConvertTo-AtmGuiRow {
    # A row as the TUI table writes it ([string] of each cell, Format-AtmTuiTable).
    param([object[]]$Values)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($v in $Values) { $out.Add([string]$v) }
    return , $out.ToArray()
}

function Get-AtmGuiUserTable {
    # Screen `users`: one row per profile, in the inventory's order.
    param($Inventory)
    $parts = @(Get-AtmGuiPartitionList -Inventory $Inventory)
    $rows = New-Object System.Collections.Generic.List[object]; $items = New-Object System.Collections.Generic.List[object]
    if ($null -ne $Inventory) {
        foreach ($pr in $Inventory.Profiles) {
            $pp = New-Object System.Collections.Generic.List[object]
            foreach ($x in $parts) { if ($x.Sid -eq $pr.Sid -and $x.ProfilePath -eq $pr.ProfilePath) { $pp.Add($x) } }
            $ppa = $pp.ToArray()
            $st = Get-AtmProfileStatusLabel -Inventory $Inventory -ProfileInfo $pr
            $n = @{ ACTIVE_EVIDENCE = 0; RECENT = 0; LIVENESS_UNKNOWN = 0; ORPHAN_SUSPECTED = 0 }
            foreach ($x in $ppa) { foreach ($c in @('ACTIVE_EVIDENCE', 'RECENT', 'LIVENESS_UNKNOWN', 'ORPHAN_SUSPECTED')) { if ($x.Class -eq $c) { $n[$c]++ } } }
            $aruo = '{0}/{1}/{2}/{3}' -f $n['ACTIVE_EVIDENCE'], $n['RECENT'], $n['LIVENESS_UNKNOWN'], $n['ORPHAN_SUSPECTED']
            $rows.Add((ConvertTo-AtmGuiRow @($pr.UserName, $pr.Sid, (Get-AtmStatusText $st), $ppa.Count, ('{0:N0}' -f (Get-AtmSum $ppa 'Files')), (Format-AtmMB (Get-AtmSum $ppa 'Bytes')), $aruo)))
            $items.Add([pscustomobject]@{ Kind = 'user'; Profile = $pr })
        }
    }
    return [pscustomobject]@{
        Columns = @((Get-AtmText 'col.user'), 'SID', (Get-AtmText 'col.status'), 'Roots', (Get-AtmText 'col.files'), 'MB', 'A/R/U/O')
        Rows = $rows.ToArray(); Items = $items.ToArray()
    }
}

function Get-AtmGuiProjectTable {
    # Screen `projects`: the TUI's groups (project, the slug when the project is not identified, SID and profile path),
    # in the order they first appear, then by bytes in decreasing order. Keys are compared ignoring case, as Group-Object
    # compares them.
    param($Inventory)
    $parts = @(Get-AtmGuiPartitionList -Inventory $Inventory)
    $order = New-Object System.Collections.Generic.List[string]
    $byKey = New-Object 'System.Collections.Generic.Dictionary[string,object]' -ArgumentList ([StringComparer]::CurrentCultureIgnoreCase)
    foreach ($p in $parts) {
        $k = [string]($p.Project + '|' + $(if ($p.ProjectIdentified) { '' } else { $p.Slug }) + '|' + $p.Sid + '|' + $p.ProfilePath)
        if (-not $byKey.ContainsKey($k)) { $byKey[$k] = New-Object System.Collections.Generic.List[object]; $order.Add($k) }
        $byKey[$k].Add($p)
    }
    $groups = New-Object System.Collections.Generic.List[object]
    foreach ($k in $order) { $g = $byKey[$k].ToArray(); $groups.Add([pscustomobject]@{ Group = $g; Neg = (-(Get-AtmSum $g 'Bytes')) }) }
    $rows = New-Object System.Collections.Generic.List[object]; $items = New-Object System.Collections.Generic.List[object]
    foreach ($go in @(Get-AtmGuiSorted -Items $groups.ToArray() -Compare { param($x, $y) ([long]$x.Neg).CompareTo([long]$y.Neg) })) {
        $grp = @($go.Group)
        $newest = $null
        foreach ($x in $grp) { if ($x.NewestWriteTimeUtc -and ($null -eq $newest -or $x.NewestWriteTimeUtc -gt $newest.NewestWriteTimeUtc)) { $newest = $x } }
        $label = $(if ($grp[0].ProjectIdentified) { $grp[0].Project } else { "$($grp[0].Project) ($($grp[0].Slug))" })
        $rows.Add((ConvertTo-AtmGuiRow @($label, $grp[0].UserName, $grp.Count, ('{0:N0}' -f (Get-AtmSum $grp 'Files')), (Format-AtmMB (Get-AtmSum $grp 'Bytes')), $(if ($newest) { Format-AtmTime $newest.NewestWriteTimeUtc } else { '-' }))))
        $items.Add([pscustomobject]@{ Kind = 'project'; Project = $grp[0].Project; Slug = $(if ($grp[0].ProjectIdentified) { $null } else { $grp[0].Slug }); Sid = $grp[0].Sid; ProfilePath = $grp[0].ProfilePath; UserName = $grp[0].UserName })
    }
    return [pscustomobject]@{
        Columns = @((Get-AtmText 'col.project'), (Get-AtmText 'col.user'), 'Roots', (Get-AtmText 'col.files'), 'MB', (Get-AtmText 'col.newest'))
        Rows = $rows.ToArray(); Items = $items.ToArray()
    }
}

function Get-AtmGuiRootTable {
    # Screen `roots`: the TUI's filters (user: SID and profile path; project; slug; class), by bytes in decreasing order.
    param($Inventory, $Filter)
    $sel = @(Get-AtmGuiPartitionList -Inventory $Inventory)
    $f = $Filter
    if ($f) {
        $keep = New-Object System.Collections.Generic.List[object]
        foreach ($x in $sel) {
            $ok = $true
            if ((Get-AtmGuiOpt $f 'Sid') -and -not ($x.Sid -eq $f.Sid -and $x.ProfilePath -eq $f.ProfilePath)) { $ok = $false }
            if ((Get-AtmGuiOpt $f 'Project') -and -not ($x.Project -eq $f.Project)) { $ok = $false }
            if ((Get-AtmGuiOpt $f 'Slug') -and -not ($x.Slug -eq $f.Slug)) { $ok = $false }
            if ((Get-AtmGuiOpt $f 'Class') -and -not ($x.Class -eq $f.Class)) { $ok = $false }
            if ($ok) { $keep.Add($x) }
        }
        $sel = $keep.ToArray()
    }
    $rows = New-Object System.Collections.Generic.List[object]; $items = New-Object System.Collections.Generic.List[object]
    foreach ($p in @(Get-AtmGuiSorted -Items $sel -Compare { param($x, $y) ([long]$y.Bytes).CompareTo([long]$x.Bytes) })) {
        $rows.Add((ConvertTo-AtmGuiRow @($p.Class, $p.Provider, $p.UserName, $p.Project, $(if ($p.Slug) { $p.Slug + '\' + $p.Name } else { $p.Name }), (Format-AtmMB $p.Bytes), ('{0:N0}' -f $p.Files), (Format-AtmTime $p.NewestWriteTimeUtc), $p.Flags.Count)))
        $items.Add([pscustomobject]@{ Kind = 'root'; Partition = $p })
    }
    return [pscustomobject]@{
        Columns = @((Get-AtmText 'col.class'), (Get-AtmText 'col.agent'), (Get-AtmText 'col.user'), (Get-AtmText 'col.project'), 'Root', 'MB', (Get-AtmText 'col.files'), (Get-AtmText 'col.newest'), 'Flags')
        Rows = $rows.ToArray(); Items = $items.ToArray()
    }
}

function Get-AtmGuiPreviewTable {
    # Screens `gates` (P: every category; 8: BLOCKED): the TUI's rows over the preview rows of the clean engine, by
    # category, then by bytes in decreasing order (List.Sort with the comparison of the TUI's Sort-Object, ties
    # included). Category, reasons and requirements are the engine's, as they come; the declared-risk category gets the
    # TUI's short label. -Preview: the rows kept in the window's session.
    param([object[]]$Preview, $Filter)
    $want = Get-AtmGuiOpt $Filter 'Category'
    $sel = New-Object System.Collections.Generic.List[object]
    foreach ($r in $Preview) { if (-not $want -or $r.Gate.Category -eq $want) { $sel.Add($r) } }
    # Sort-Object compares text with the current culture, ignoring case; then the negated bytes.
    $cmp = { param($x, $y)
        $c = [string]::Compare([string]$x.Gate.Category, [string]$y.Gate.Category, $true, [Globalization.CultureInfo]::CurrentCulture)
        if ($c -ne 0) { return $c }
        return ([long]$y.Partition.Bytes).CompareTo([long]$x.Partition.Bytes)
    }
    $rows = New-Object System.Collections.Generic.List[object]; $items = New-Object System.Collections.Generic.List[object]
    foreach ($r in @(Get-AtmGuiSorted -Items $sel.ToArray() -Compare $cmp)) {
        $p = $r.Partition
        $catText = [string]$r.Gate.Category
        if ($catText -ceq 'ELIGIBLE_WITH_DECLARED_RISK') { $catText = Get-AtmText 'tui.catDeclaredRisk' }
        $rows.Add((ConvertTo-AtmGuiRow @($catText, $p.UserName, $(if ($p.Slug) { $p.Slug + '\' + $p.Name } else { $p.Name }), (Format-AtmMB $p.Bytes), ((@($r.Gate.Reasons) + @($r.Gate.Requirements)) -join '; '))))
        $items.Add([pscustomobject]@{ Kind = 'root'; Partition = $p; Gate = $r.Gate })
    }
    return [pscustomobject]@{
        Columns = @((Get-AtmText 'col.category'), (Get-AtmText 'col.user'), 'Root', 'MB', (Get-AtmText 'col.reasonReq'))
        Rows = $rows.ToArray(); Items = $items.ToArray()
    }
}

function Get-AtmGuiRootDetail {
    # Screen `detail` of the root with this path in the inventory: the TUI's fields, with the same det.* keys, then the
    # evidence, the ancestor and ambiguous references and the samples of errors and reparse points. -Gate (a detail
    # opened from the preview): the TUI's Preview line after the fields, with the engine's category, reasons and
    # requirements. Not here: the isolation hint and the hint of the CLI's path drill-down (no action in the GUI).
    # Found = $false when the root is no longer in the inventory: nothing is shown for it.
    param($Inventory, [string]$Path, $Gate)
    $p = $null
    foreach ($x in @(Get-AtmGuiPartitionList -Inventory $Inventory)) { if ($null -eq $p -and $x.Path -eq $Path) { $p = $x } }
    if ($null -eq $p) { return [pscustomobject]@{ Found = $false; Partition = $null; Pairs = @(); Lines = @() } }
    $raw = @(
        @('det.path', $p.Path), @('det.agent', $p.Provider), @('det.kind', $p.Kind), @('det.class', $p.Class), @('det.user', $p.UserName), @('det.sid', $p.Sid), @('det.profile', $p.ProfilePath), @('det.temp', $p.TempPath)
        @('det.project', $(if ($p.ProjectIdentified) { Get-AtmText 'det.projectWithSource' $p.Project $p.ProjectSource } else { $p.Project })), @('det.scope', $p.Slug)
        @('det.created', (Format-AtmTime $p.CreationTimeUtc)), @('det.modified', (Format-AtmTime $p.LastWriteTimeUtc)), @('det.newest', (Format-AtmTime $p.NewestWriteTimeUtc))
        @('det.logical', ('{0:N0} ({1} MB | {2} GB)' -f $p.Bytes, (Format-AtmMB $p.Bytes), (Format-AtmGB $p.Bytes))), @('det.physical', ('{0:N0}' -f $p.AllocatedBytesEstimate))
        @('det.files', $p.Files), @('det.dirs', $p.Dirs), @('det.children', $p.DirectChildren), @('det.reparse', $p.ReparsePoints), @('det.protected', $p.ProtectedFiles)
        @('det.errors', $p.ErrorCount), @('det.complete', (Get-AtmYesNo $p.MeasurementComplete)), @('det.session', $(if ($p.Session) { $p.Session } else { '-' }))
        @('det.transcript', (Format-AtmTime $p.TranscriptLastWriteUtc)), @('det.fingerprint', $p.Fingerprint), @('det.flags', $(if ($p.Flags.Count) { $p.Flags -join ', ' } else { Get-AtmText 'common.none' }))
    )
    $pairs = New-Object System.Collections.Generic.List[object]
    # The value as the TUI writes it ('{0,-26}: {1}' formats with the current culture).
    foreach ($r in $raw) { $pairs.Add([pscustomobject]@{ Key = $r[0]; Label = (Get-AtmText $r[0]); Value = ('{0}' -f $r[1]) }) }
    if ($Gate) { $pairs.Add([pscustomobject]@{ Key = 'preview'; Label = 'Preview'; Value = ('{0} - {1}' -f $Gate.Category, ((@($Gate.Reasons) + @($Gate.Requirements)) -join '; ')) }) }
    $L = New-Object System.Collections.Generic.List[string]
    $L.Add('')
    $L.Add((Get-AtmText 'audit.evidence'))
    if ($p.Evidence.Count -eq 0) { $L.Add(('  ' + (Get-AtmText 'tui.noEvidence'))) }
    foreach ($x in $p.Evidence) { $L.Add("  - $x") }
    foreach ($x in $p.AncestorRefs) { $L.Add(('  - ' + (Get-AtmText 'audit.ancestorRef' $x))) }
    foreach ($x in $p.AmbiguousRefs) { $L.Add(('  - ' + (Get-AtmText 'audit.ambiguousRef' $x))) }
    foreach ($x in $p.ErrorSamples) { $L.Add(('  - ' + (Get-AtmText 'audit.err' $x))) }
    foreach ($x in $p.ReparseSamples) { $L.Add(('  - ' + (Get-AtmText 'audit.reparse' $x))) }
    return [pscustomobject]@{ Found = $true; Partition = $p; Pairs = $pairs.ToArray(); Lines = $L.ToArray() }
}

function Get-AtmGuiCoverageLineList {
    # Screen `errors`: the TUI's lines, in its order and with its text (coverage and process summary or failure,
    # references, incomplete profiles, temporary directories, discovery notes, partitions with issues, limits).
    param($Inventory)
    $inv = $Inventory
    $L = New-Object System.Collections.Generic.List[string]
    if ($null -eq $inv) { return $L.ToArray() }
    $s = $inv.Snapshot
    $L.Add((Get-AtmText 'tui.coverageAll' $(if ($inv.CoverageComplete) { Get-AtmText 'common.complete' } else { Get-AtmText 'common.incomplete' })))
    if ($s.Failed) { $L.Add((Get-AtmText 'audit.procFailed' $s.Error)) }
    else { $L.Add((Get-AtmText 'audit.procSummary' $s.Total $s.Readable $s.Uninspectable @($inv.SelfPids).Count)) }
    if ($s.Uninspectable -gt 0) {
        $byName = New-Object System.Collections.Generic.List[object]
        foreach ($e in $s.UninspectableByName.GetEnumerator()) { $byName.Add($e) }
        $names = New-Object System.Collections.Generic.List[string]
        foreach ($e in @(Get-AtmGuiSorted -Items $byName.ToArray() -Compare { param($x, $y) [Collections.Comparer]::Default.Compare($y.Value, $x.Value) })) { $names.Add("$($e.Key) x$($e.Value)") }
        $L.Add((Get-AtmText 'audit.uninspectable' ($names.ToArray() -join ', ')))
        $L.Add((Get-AtmText 'audit.absenceNotProof'))
    }
    $L.Add((Get-AtmText 'audit.references' $inv.References.Direct $inv.References.Ancestor $inv.References.Ambiguous $inv.References.Unresolved.Count))
    foreach ($u in $inv.References.Unresolved) { $L.Add("  $u") }
    $L.Add('')
    $L.Add((Get-AtmText 'tui.incompleteProfiles'))
    $notAudited = @(Get-AtmInventoryProfileList -Inventory $inv -Name 'NotAuditedProfiles')
    if ((Get-AtmIncompleteProfileCount -Inventory $inv) -eq 0) { $L.Add(('  ' + (Get-AtmText 'common.none'))) }
    foreach ($pr in $inv.InaccessibleProfiles) { $L.Add(("  {0} ({1}) {2}" -f $pr.UserName, $pr.Sid, $pr.ProfilePath)) }
    foreach ($pr in @($inv.UnverifiedTempProfiles)) { $L.Add(('  ' + (Get-AtmText 'tui.unverifiedTemp' $pr.UserName $pr.Sid $pr.EnvStatus))) }
    $idx = Get-AtmBaseIndex -Bases $inv.Bases
    foreach ($pr in $notAudited) {
        # The distinct states in their first order (as Select-Object -Unique keeps them).
        $uniq = New-Object System.Collections.Generic.List[string]
        foreach ($st in @(Get-AtmNotAuditedBaseStates -Entries $inv.ProfileBaseStatus[$pr.Sid + '|' + $pr.ProfilePath] -BaseIndex $idx)) { if (-not $uniq.Contains([string]$st)) { $uniq.Add([string]$st) } }
        $L.Add(('  ' + (Get-AtmText 'tui.notAudited' $pr.UserName $pr.Sid ($uniq.ToArray() -join ','))))
    }
    $L.Add('')
    $L.Add((Get-AtmText 'audit.tempDirs'))
    foreach ($pr in $inv.Profiles) { foreach ($b in @($inv.ProfileBaseStatus[$pr.Sid + '|' + $pr.ProfilePath])) { $L.Add(("  [{0}] [{1}] {2} -> {3}" -f $b.Status, $b.Provider, $pr.UserName, $b.BasePath)) } }
    $L.Add('')
    $L.Add((Get-AtmText 'tui.discoveryNotes'))
    foreach ($pr in $inv.Profiles) { foreach ($n in $pr.Notes) { $L.Add(("  [{0}] {1}" -f $pr.UserName, $n)) } }
    foreach ($n in $inv.DiscoveryNotes) { $L.Add("  $n") }
    $L.Add('')
    $L.Add((Get-AtmText 'tui.partitionsWithIssues'))
    $errs = New-Object System.Collections.Generic.List[object]
    foreach ($e in @(Get-AtmGuiPartitionList -Inventory $inv)) { if ($e.ErrorCount -gt 0 -or $e.ReparsePoints -gt 0 -or $e.AmbiguousRefs.Count -gt 0 -or $e.AncestorRefs.Count -gt 0) { $errs.Add($e) } }
    if ($errs.Count -eq 0) { $L.Add(('  ' + (Get-AtmText 'common.none'))) }
    foreach ($e in $errs) {
        $L.Add(("  [{0}] {1}" -f $e.UserName, $e.Path))
        foreach ($x in $e.ErrorSamples) { $L.Add(('     ' + (Get-AtmText 'audit.err' $x))) }
        foreach ($x in $e.ReparseSamples) { $L.Add(('     ' + (Get-AtmText 'audit.reparse' $x))) }
        foreach ($x in $e.AncestorRefs) { $L.Add(('     ' + (Get-AtmText 'audit.ancestorRef' $x))) }
        foreach ($x in $e.AmbiguousRefs) { $L.Add(('     ' + (Get-AtmText 'audit.ambiguousRef' $x))) }
    }
    $L.Add('')
    $L.Add((Get-AtmText 'tui.limits'))
    return $L.ToArray()
}

function Get-AtmGuiScreen {
    # The content of one screen of the navigation stack. Kind: dashboard, table (users, projects, roots, the preview),
    # pairs (the detail) or lines (coverage and errors). Known = $false before the first audit: no row is invented. Gone
    # = $true when the root of a detail is not in the inventory. Notice: the fixed line of the preview's screens.
    # -Preview: the preview rows kept in the session ($null: not computed for this audit); -PreviewFailure: the
    # exception type of the last failed preview (never its message). -Diag (P4b): the diagnose result the session keeps
    # (New-AtmGuiDiagState); its screens do not depend on an audit. Pre: the lines above a diagnose table; Empty: the
    # text of an empty diagnose table; GateLines: the lines of the V0.2 gates among Pre or Lines.
    param($Inventory, [hashtable]$Screen, $Preview, [string]$PreviewFailure, $Diag)
    $known = ($null -ne $Inventory)
    $isDiag = (@(Get-AtmGuiDiagScreenNames) -ccontains [string]$Screen.Name)
    $vm = [ordered]@{ Name = $Screen.Name; Title = $Screen.Title; Kind = 'table'; Known = $known; Gone = $false; Columns = @(); Rows = @(); Items = @(); Pairs = @(); Lines = @(); Note = $(if ($known -or $isDiag) { $null } else { Get-AtmText 'gui.noAudit' }); Notice = $null; Pre = @(); Empty = $null; GateLines = @() }
    if ($isDiag) {
        if (@(Get-AtmGuiDiagListNames) -ccontains [string]$Screen.Name) {
            $t = Get-AtmGuiDiagTable -Diag $Diag -Screen $Screen
            $vm.Columns = $t.Columns; $vm.Rows = $t.Rows; $vm.Items = $t.Items; $vm.Pre = $t.Pre; $vm.Empty = $t.Empty; $vm.GateLines = $t.GateLines
        } else {
            $t = Get-AtmGuiDiagText -Diag $Diag -Screen $Screen
            $vm.Kind = 'lines'; $vm.Columns = @((Get-AtmText 'gui.col.line')); $vm.Lines = $t.Lines; $vm.GateLines = $t.GateLines
        }
        return [pscustomobject]$vm
    }
    switch ($Screen.Name) {
        'dashboard' { $vm.Kind = 'dashboard' }
        'users' { $t = Get-AtmGuiUserTable -Inventory $Inventory; $vm.Columns = $t.Columns; $vm.Rows = $t.Rows; $vm.Items = $t.Items }
        'projects' { $t = Get-AtmGuiProjectTable -Inventory $Inventory; $vm.Columns = $t.Columns; $vm.Rows = $t.Rows; $vm.Items = $t.Items }
        'roots' { $t = Get-AtmGuiRootTable -Inventory $Inventory -Filter $Screen.Filter; $vm.Columns = $t.Columns; $vm.Rows = $t.Rows; $vm.Items = $t.Items }
        'detail' {
            $vm.Kind = 'pairs'
            $vm.Columns = @((Get-AtmText 'gui.col.field'), (Get-AtmText 'gui.col.value'))
            $gate = Get-AtmGuiOpt $Screen.Filter 'Gate'
            if ($gate) { $vm.Notice = Get-AtmText 'gui.previewNotice' }
            if ($known) {
                $d = Get-AtmGuiRootDetail -Inventory $Inventory -Path ([string]$Screen.Filter.Path) -Gate $gate
                $vm.Gone = (-not $d.Found); $vm.Pairs = $d.Pairs; $vm.Lines = $d.Lines
            }
        }
        'gates' {
            # P4a: only the rows the session keeps; nothing is computed here. Before the first audit, the P3 note.
            $vm.Notice = Get-AtmText 'gui.previewNotice'
            $rowsIn = @()
            if ($known -and $null -ne $Preview) { $rowsIn = $Preview }
            elseif ($known -and $PreviewFailure) { $vm.Note = Get-AtmText 'gui.previewFailed' $PreviewFailure }
            elseif ($known) { $vm.Note = Get-AtmText 'gui.previewNotRun' }
            $t = Get-AtmGuiPreviewTable -Preview $rowsIn -Filter $Screen.Filter
            $vm.Columns = $t.Columns; $vm.Rows = $t.Rows; $vm.Items = $t.Items
        }
        'errors' { $vm.Kind = 'lines'; $vm.Columns = @((Get-AtmText 'gui.col.line')); $vm.Lines = @(Get-AtmGuiCoverageLineList -Inventory $Inventory) }
    }
    return [pscustomobject]$vm
}

function Initialize-AtmGuiNav {
    # The navigation of one window: a stack of screens (the dashboard at the bottom), each with its selected row, and the
    # message of the last move (a catalog text, or $null).
    $stack = New-Object System.Collections.Generic.List[object]
    $stack.Add(@{ Name = 'dashboard'; Title = (Get-AtmText 'menu.dashboard'); Filter = $null; Sel = 0 })
    return @{ Stack = $stack; Message = $null }
}

function Get-AtmGuiNavTop {
    param([hashtable]$Nav)
    return $Nav.Stack[$Nav.Stack.Count - 1]
}

function Invoke-AtmGuiNavKey {
    # One key or screen button, as the TUI handles it. -Key: '1' to '9' (or D1/NumPad1 to 9), 'P', 'D', 'U',
    # Return/Enter, Escape. Returns RENDER (the screen changed), CLOSE (Esc on the dashboard), IGNORED (an audit, the
    # preview or the diagnose runs: nothing moves), DIAG_OPEN or DIAG_REFRESH (the form asks for the diagnose, then
    # Invoke-AtmGuiNavDiag moves) or NONE. -Preview: the preview rows kept in the session (the rows Enter opens on its
    # screens). -Diag: the diagnose result kept in the session (the items Enter opens in its area).
    #  * 1 to 9 and P: the screen of that key, over the dashboard (1: the dashboard itself);
    #  * D: the diagnose area (DIAG_OPEN, nothing moves yet); U, only inside the area: a new observation (DIAG_REFRESH);
    #  * Enter on a row: user -> the roots of that user; project -> the roots of that project; root -> its detail (from
    #    the preview, with its gate: the detail shows the Preview line); in the diagnose area, as the TUI: a category ->
    #    its screen; a coverage record -> its detail; a finding -> its detail; a node -> its detail; an issue -> the
    #    detail of its coverage record or finding;
    #  * Esc: one screen back; on the dashboard it closes the window.
    param([hashtable]$Nav, $Inventory, [string]$Key, [bool]$Busy, $Preview, $Diag)
    if ($Busy) { return 'IGNORED' }
    if ($Key -ceq 'D') { return 'DIAG_OPEN' }
    if ($Key -ceq 'U') {
        if (@(Get-AtmGuiDiagScreenNames) -ccontains [string](Get-AtmGuiNavTop -Nav $Nav).Name) { return 'DIAG_REFRESH' }
        return 'NONE'
    }
    $digit = $null
    if ($Key -cmatch '^(D|NumPad)?([1-9])$') { $digit = $Matches[2] }
    elseif ($Key -ceq 'P') { $digit = 'P' }
    if ($null -ne $digit) {
        $item = $null
        foreach ($m in @(Get-AtmGuiNavItemList)) { if ($m.Key -ceq $digit) { $item = $m } }
        if ($null -eq $item) { return 'NONE' }
        $Nav.Message = $null
        while ($Nav.Stack.Count -gt 1) { $Nav.Stack.RemoveAt($Nav.Stack.Count - 1) }
        if ($item.Screen.Name -cne 'dashboard') {
            $s = @{} + $item.Screen
            if (-not $s.ContainsKey('Filter')) { $s['Filter'] = $null }
            $s['Sel'] = 0
            $Nav.Stack.Add($s)
        }
        return 'RENDER'
    }
    if ($Key -ceq 'Escape') {
        if ($Nav.Stack.Count -le 1) { return 'CLOSE' }
        $Nav.Message = $null
        $Nav.Stack.RemoveAt($Nav.Stack.Count - 1)
        return 'RENDER'
    }
    if ($Key -ceq 'Return' -or $Key -ceq 'Enter') {
        $top = Get-AtmGuiNavTop -Nav $Nav
        if (@(Get-AtmGuiDiagListNames) -ccontains [string]$top.Name) {
            # The diagnose area, before the items of the audit: its items are the view's records (a finding has its own
            # kind property).
            $dItems = @((Get-AtmGuiScreen -Inventory $Inventory -Screen $top -Diag $Diag).Items)
            if ($dItems.Count -eq 0) { return 'NONE' }
            $it = $dItems[[math]::Min([int]$top.Sel, $dItems.Count - 1)]
            $push = $null
            switch ([string]$top.Name) {
                'diag' { $push = @{} + $it.Push }
                'dcov' { $push = @{ Name = 'dcovdet'; Title = [string]$it.collector; Filter = @{ C = $it } } }
                'dlist' { $push = @{ Name = 'dfind'; Title = [string]$it.kind; Filter = @{ F = $it } } }
                'dnodes' { $push = @{ Name = 'dnode'; Title = [string]$it.kind; Filter = @{ N = $it } } }
                'dissues' { if ($it.T -ceq 'cov') { $push = @{ Name = 'dcovdet'; Title = [string]$it.C.collector; Filter = @{ C = $it.C } } } else { $push = @{ Name = 'dfind'; Title = [string]$it.F.kind; Filter = @{ F = $it.F } } } }
            }
            if ($null -eq $push) { return 'NONE' }
            if (-not $push.ContainsKey('Filter')) { $push['Filter'] = $null }
            $push['Sel'] = 0
            $Nav.Message = $null
            $Nav.Stack.Add($push)
            return 'RENDER'
        }
        $vm = Get-AtmGuiScreen -Inventory $Inventory -Screen $top -Preview $Preview
        if ($vm.Kind -cne 'table' -or @($vm.Items).Count -eq 0) { return 'NONE' }
        $it = @($vm.Items)[[math]::Max(0, [math]::Min([int]$top.Sel, @($vm.Items).Count - 1))]
        $push = $null
        switch ($it.Kind) {
            'user' { $push = @{ Name = 'roots'; Title = (Get-AtmText 'tui.rootsOf' $it.Profile.UserName); Filter = @{ Sid = $it.Profile.Sid; ProfilePath = $it.Profile.ProfilePath } } }
            'project' { $push = @{ Name = 'roots'; Title = (Get-AtmText 'tui.rootsOfProject' $it.Project $it.UserName); Filter = @{ Sid = $it.Sid; ProfilePath = $it.ProfilePath; Project = $it.Project; Slug = $it.Slug } } }
            'root' {
                $gate = $null
                if ($it.PSObject.Properties.Name -contains 'Gate') { $gate = $it.Gate }
                $push = @{ Name = 'detail'; Title = (Get-AtmText 'tui.detailOf' $it.Partition.Name); Filter = @{ Path = [string]$it.Partition.Path; Name = [string]$it.Partition.Name; Gate = $gate } }
            }
        }
        if ($null -eq $push) { return 'NONE' }
        $push['Sel'] = 0
        $Nav.Message = $null
        $Nav.Stack.Add($push)
        return 'RENDER'
    }
    return 'NONE'
}

function Invoke-AtmGuiNavRefreshed {
    # After an audit: the current screen is computed again over the new result. A detail whose root is not in it goes
    # back to its list, with a catalog text; nothing is invented. The selected row stays inside the new rows.
    # -PreviewDiscarded (P4a: a successful audit discards the kept preview): the preview's screens, and a detail opened
    # from them, are left for the dashboard with a catalog text, because a new preview starts only when P or 8 is opened.
    # -Preview: the preview rows the session keeps (a failed audit keeps them). -Diag (P4b): the diagnose result the
    # session keeps; an audit never discards it (as in the TUI), and its screens stay where they are.
    param([hashtable]$Nav, $Inventory, [bool]$PreviewDiscarded, $Preview, $Diag)
    if ($PreviewDiscarded) {
        $at = -1
        for ($i = 0; $i -lt $Nav.Stack.Count; $i++) { if ($at -lt 0 -and $Nav.Stack[$i].Name -ceq 'gates') { $at = $i } }
        if ($at -ge 1) {
            while ($Nav.Stack.Count -gt $at) { $Nav.Stack.RemoveAt($Nav.Stack.Count - 1) }
            $Nav.Message = Get-AtmText 'gui.previewDiscarded'
        }
    }
    $top = Get-AtmGuiNavTop -Nav $Nav
    if ($top.Name -ceq 'detail' -and $null -ne $Inventory -and -not (Get-AtmGuiRootDetail -Inventory $Inventory -Path ([string]$top.Filter.Path)).Found) {
        $Nav.Stack.RemoveAt($Nav.Stack.Count - 1)
        $Nav.Message = Get-AtmText 'gui.detailGone' ([string]$top.Filter.Name)
        $top = Get-AtmGuiNavTop -Nav $Nav
    }
    $n = @((Get-AtmGuiScreen -Inventory $Inventory -Screen $top -Preview $Preview -Diag $Diag).Items).Count
    if ([int]$top.Sel -ge $n) { $top.Sel = [math]::Max(0, $n - 1) }
}

# ------------------------------------------------------------------ the diagnose area (P4b)
# The TUI's diagnose screens over the schema view of one diagnose result (the JSON export, parsed back), with the same
# rows, order and text. The GUI keeps its own copies of the TUI's tables (a test checks they equal the TUI's) and never
# reads the TUI's variables. Nothing here runs the diagnose: Gui.ps1 runs it on request, and the index below is built
# once per result. The only difference from the TUI: a line "disabled in this version" for each coverage reason that is
# one of the V0.2 gates, in the category it affects and in the summary.

$script:AtmGuiDiagMaxEdges = 40

function Get-AtmGuiDiagCatKinds {
    # The finding kinds of each category (copy of the TUI table).
    return @{ procs = @('Process', 'AgentSession'); services = @('Service'); virt = @('VirtualizationPlatform', 'VirtualMachine'); worktrees = @('Worktree', 'Repository'); parts = @('TempPartition') }
}

function Get-AtmGuiDiagCatCollectors {
    # The collectors whose coverage decides whether an empty or short category is "none" or "not observed" (copy of the
    # TUI table).
    return @{ parts = @('inventory'); procs = @('process-snapshot', 'agent-processes'); services = @('services'); virt = @('virtualization-platform', 'virtual-machines'); worktrees = @('worktree-discovery') }
}

function Get-AtmGuiDiagStrength {
    # The marker of each edge strength (copy of the TUI table, marker only: the GUI has no colors).
    return @{ DIRECT = '[D]'; ANCESTOR = '[A]'; AMBIGUOUS = '[?]' }
}

function Get-AtmGuiDiagGateCodes {
    # The coverage reasons of the features behind the V0.2 gates: shown as disabled in this version.
    return @('WORKTREE_DIAGNOSTICS_GATE_CLOSED', 'HANDLE_SECURITY_GATE_CLOSED', 'EXPORT_SECURITY_GATE_CLOSED', 'GIT_EXECUTION_GATE_CLOSED')
}

function Get-AtmGuiDiagScreenNames {
    return @('diag', 'dcov', 'dlist', 'dnodes', 'dissues', 'dsum', 'dcovdet', 'dfind', 'dnode')
}

function Get-AtmGuiDiagListNames {
    # The screens of the area that are tables (the others are lines).
    return @('diag', 'dcov', 'dlist', 'dnodes', 'dissues')
}

function Format-AtmGuiUtc {
    # Copy of the TUI's display form of an exported time, the same in both shells (PowerShell 7 parses ISO strings into
    # dates).
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return '-' }
    $d = $null
    if ($Value -is [datetime]) { $d = $Value.ToUniversalTime() }
    else { try { $d = [datetime]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime() } catch { return [string]$Value } }
    return $d.ToString('yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) + ' UTC'
}

function Get-AtmGuiCultureCompare {
    # The comparison Sort-Object applies to strings: current culture, case ignored.
    param([string]$A, [string]$B)
    return [string]::Compare($A, $B, $true, [Globalization.CultureInfo]::CurrentCulture)
}

function Get-AtmGuiGroupList {
    # Group-Object by a string key, then Sort-Object Name, without the cmdlets: groups in the order of their first item,
    # keys compared in the current culture with case ignored, a group named by its first key, then sorted by name.
    # Returns objects with Name and Group (an array), unrolled: callers wrap the result in @().
    param([object[]]$Items, [scriptblock]$Key)
    $by = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::CurrentCultureIgnoreCase)
    $order = New-Object System.Collections.Generic.List[object]
    foreach ($i in $Items) {
        $k = [string](& $Key $i)
        if (-not $by.ContainsKey($k)) {
            $g = [pscustomobject]@{ Name = $k; List = (New-Object System.Collections.Generic.List[object]) }
            $by[$k] = $g
            $order.Add($g)
        }
        $by[$k].List.Add($i)
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($g in @(Get-AtmGuiSorted -Items $order.ToArray() -Compare { param($a, $b) Get-AtmGuiCultureCompare $a.Name $b.Name })) { $out.Add([pscustomobject]@{ Name = $g.Name; Group = $g.List.ToArray() }) }
    return $out.ToArray()
}

function Get-AtmGuiSortedUnique {
    # Sort-Object -Unique over strings, without the cmdlet: sorted in the current culture with case ignored, equal
    # strings (case ignored) kept once. Unrolled: callers wrap the result in @().
    param([object[]]$Items)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($s in @(Get-AtmGuiSorted -Items $Items -Compare { param($a, $b) Get-AtmGuiCultureCompare $a $b })) {
        if ($out.Count -gt 0 -and (Get-AtmGuiCultureCompare $out[$out.Count - 1] $s) -eq 0) { continue }
        $out.Add($s)
    }
    return $out.ToArray()
}

function New-AtmGuiDiagIndex {
    # The TUI's index of one view (New-AtmTuiDiagIndex), built once per result: findings by category, the coverage gap of
    # each category, the summary figures, findings, worst coverage record and node by key, edges in and out of each
    # node, and the issues (coverage records that are not conclusive, then UNKNOWN findings).
    param($View)
    $kinds = Get-AtmGuiDiagCatKinds; $colls = Get-AtmGuiDiagCatCollectors
    $cat = @{}
    foreach ($c in @($kinds.Keys)) { $cat[$c] = New-Object System.Collections.Generic.List[object] }
    $catOf = @{}
    foreach ($c in @($kinds.Keys)) { foreach ($k in $kinds[$c]) { $catOf[$k] = $c } }
    $findingBy = @{}; $unknown = New-Object System.Collections.Generic.List[object]; $found = New-Object System.Collections.Generic.List[object]
    foreach ($x in @($View.findings)) {
        if ($null -eq $x) { continue }
        $found.Add($x)
        $k = [string]$x.kind
        if ($catOf.ContainsKey($k)) { $cat[$catOf[$k]].Add($x) }
        $findingBy[$k + '|' + [string]$x.key] = $x
        if ([string]$x.state -ceq 'UNKNOWN') { $unknown.Add($x) }
    }
    # Worst record per collector.
    $covBy = @{}
    $coverage = New-Object System.Collections.Generic.List[object]
    $incomplete = New-Object System.Collections.Generic.List[object]
    foreach ($c in @($View.coverage)) {
        if ($null -eq $c) { continue }
        $coverage.Add($c)
        if ($script:AtmConclusiveCoverage -cnotcontains [string]$c.status) { $incomplete.Add($c) }
        $ck = [string]$c.collector
        if (-not $covBy.ContainsKey($ck) -or ($script:AtmConclusiveCoverage -ccontains [string]$covBy[$ck].status -and $script:AtmConclusiveCoverage -cnotcontains [string]$c.status)) { $covBy[$ck] = $c }
    }
    $nodeList = New-Object System.Collections.Generic.List[object]; $inBy = @{}; $outBy = @{}; $nodeBy = @{}
    if ($null -ne $View.graph) {
        foreach ($n in @($View.graph.nodes)) { if ($null -ne $n) { $nodeList.Add($n) } }
        foreach ($n in $nodeList) { $nodeBy[[string]$n.kind + '|' + [string]$n.key] = $n }
        foreach ($e in @($View.graph.edges)) {
            if ($null -eq $e) { continue }
            $tk = [string]$e.toKind + '|' + [string]$e.to; $fk = [string]$e.fromKind + '|' + [string]$e.from
            if (-not $inBy.ContainsKey($tk)) { $inBy[$tk] = New-Object System.Collections.Generic.List[object] }; $inBy[$tk].Add($e)
            if (-not $outBy.ContainsKey($fk)) { $outBy[$fk] = New-Object System.Collections.Generic.List[object] }; $outBy[$fk].Add($e)
        }
    }
    $issues = New-Object System.Collections.Generic.List[object]
    foreach ($c in $incomplete) { $issues.Add([pscustomobject]@{ T = 'cov'; C = $c; F = $null }) }
    foreach ($x in $unknown) { $issues.Add([pscustomobject]@{ T = 'find'; C = $null; F = $x }) }
    $byCat = @{}; foreach ($c in @($cat.Keys)) { $byCat[$c] = $cat[$c].ToArray() }
    # Coverage gap of each category: the collectors that are missing or not conclusive (null when conclusive).
    $gap = @{}
    foreach ($c in @($colls.Keys)) {
        $parts = New-Object System.Collections.Generic.List[string]; $why = New-Object System.Collections.Generic.List[string]; $missing = 0
        foreach ($cn in $colls[$c]) {
            if (-not $covBy.ContainsKey($cn)) { $parts.Add($cn + '=-'); $missing++; continue }
            $r = $covBy[$cn]
            if ($script:AtmConclusiveCoverage -cnotcontains [string]$r.status) { $parts.Add($cn + '=' + [string]$r.status); foreach ($x in @($r.reasons)) { $why.Add([string]$x) } }
        }
        $gap[$c] = $null
        if ($parts.Count -gt 0) { $gap[$c] = [pscustomobject]@{ Status = ($parts -join ', '); Reasons = $(if ($why.Count) { $why -join ',' } else { '-' }); AllMissing = ($missing -eq @($colls[$c]).Count) } }
    }
    # Summary figures, once per result (the summary screen only formats them).
    $kindList = New-Object System.Collections.Generic.List[object]
    foreach ($g in @(Get-AtmGuiGroupList -Items $found.ToArray() -Key { param($y) [string]$y.kind })) {
        $st = New-Object System.Collections.Generic.List[string]
        foreach ($s in @(Get-AtmGuiGroupList -Items $g.Group -Key { param($y) [string]$y.state })) { $st.Add($s.Name + ' ' + @($s.Group).Count) }
        $kindList.Add([pscustomobject]@{ Kind = $g.Name; Count = @($g.Group).Count; States = ($st.ToArray() -join ', ') })
    }
    $cnt = @{ PartsInUse = 0; PartsUnknown = 0; PartsNone = 0; ProcVerified = 0; ProcUnverified = 0; Sessions = 0; Vms = 0; Worktrees = 0 }
    foreach ($y in $byCat['parts']) {
        if ([string]$y.state -ceq 'IN_USE') { $cnt.PartsInUse++ }
        if ([string]$y.state -ceq 'UNKNOWN') { $cnt.PartsUnknown++ }
        if ([string]$y.state -ceq 'NO_DEPENDENCY_OBSERVED') { $cnt.PartsNone++ }
    }
    foreach ($y in $byCat['procs']) {
        if ([string]$y.kind -ceq 'Process' -and ([string]$y.key).Contains('@')) { $cnt.ProcVerified++ }
        if ([string]$y.kind -ceq 'Process' -and -not ([string]$y.key).Contains('@')) { $cnt.ProcUnverified++ }
        if ([string]$y.kind -ceq 'AgentSession') { $cnt.Sessions++ }
    }
    foreach ($y in $byCat['virt']) { if ([string]$y.kind -ceq 'VirtualMachine') { $cnt.Vms++ } }
    foreach ($y in $byCat['worktrees']) { if ([string]$y.kind -ceq 'Worktree') { $cnt.Worktrees++ } }
    $sum = [pscustomobject]@{
        Kinds = $kindList.ToArray()
        PartsInUse = $cnt.PartsInUse; PartsUnknown = $cnt.PartsUnknown; PartsNone = $cnt.PartsNone
        ProcVerified = $cnt.ProcVerified; ProcUnverified = $cnt.ProcUnverified; Sessions = $cnt.Sessions; Services = @($byCat['services']).Count
        Vms = $cnt.Vms; Worktrees = $cnt.Worktrees
        Incomplete = $incomplete.ToArray()
    }
    return [pscustomobject]@{ ByCat = $byCat; Gap = $gap; Sum = $sum; FindingBy = $findingBy; CovBy = $covBy; Coverage = $coverage.ToArray(); Nodes = $nodeList.ToArray(); NodeBy = $nodeBy; InBy = $inBy; OutBy = $outBy; Issues = $issues.ToArray() }
}

function Get-AtmGuiDiagGateList {
    # One entry per (gate code, collector) among the coverage reasons, in the order of the coverage records: the code, the
    # collector, the category it affects ($null: the summary only) and its line, with the catalog text of the reason (or
    # the GUI's own text when the catalog has none).
    param($Index)
    $codes = Get-AtmGuiDiagGateCodes; $colls = Get-AtmGuiDiagCatCollectors
    $seen = @{}
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($c in @($Index.Coverage)) {
        foreach ($r in @($c.reasons)) {
            $code = [string]$r
            if ($codes -cnotcontains $code) { continue }
            $cn = [string]$c.collector
            if ($seen.ContainsKey($code + '|' + $cn)) { continue }
            $seen[$code + '|' + $cn] = $true
            $cat = $null
            foreach ($k in @($colls.Keys)) { if (@($colls[$k]) -ccontains $cn) { $cat = $k } }
            $tx = Get-AtmCodeText 'reason' $code
            if (-not $tx) { $tx = Get-AtmText ('gui.diag.gate.' + $code) }
            $out.Add([pscustomobject]@{ Code = $code; Collector = $cn; Cat = $cat; Line = (Get-AtmText 'gui.diag.disabled' $code $cn $tx) })
        }
    }
    # Unrolled: callers wrap the result in @().
    return $out.ToArray()
}

function New-AtmGuiDiagState {
    # The diagnose result the session keeps: the view, its index and its gate lines (built once), outdated or not, and the
    # exception type of the last failure.
    param($View)
    $ix = New-AtmGuiDiagIndex -View $View
    return @{ View = $View; Index = $ix; Gates = @(Get-AtmGuiDiagGateList -Index $ix); Stale = $false; Error = $null }
}

function Get-AtmGuiDiagCategoryList {
    # The rows of the area's first screen, as the TUI's categories: label, count (with '*' when the coverage of the
    # category is incomplete) and the screen it opens.
    param($Diag)
    $ix = $Diag.Index
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

function Get-AtmGuiDiagReasonText {
    # The reasons of a coverage record as the TUI writes them: joined by commas, or '-'.
    param($Record)
    if (@($Record.reasons).Count) { return (@($Record.reasons) -join ',') }
    return '-'
}

function Get-AtmGuiDiagTable {
    # A table screen of the area, with the TUI's columns at width 90 or more, its items and rows, the lines the TUI draws
    # above the table (Pre), the text of an empty table (Empty) and the gate lines among Pre (GateLines).
    param($Diag, [hashtable]$Screen)
    $out = [ordered]@{ Columns = @(); Rows = @(); Items = @(); Pre = @(); Empty = $null; GateLines = @() }
    if ($null -eq $Diag -or $null -eq $Diag.View) { return [pscustomobject]$out }
    $ix = $Diag.Index
    $rows = New-Object System.Collections.Generic.List[object]
    $pre = New-Object System.Collections.Generic.List[string]
    $gates = New-Object System.Collections.Generic.List[string]
    $items = @()
    $gp = $null
    switch ([string]$Screen.Name) {
        'diag' {
            $out.Columns = @((Get-AtmText 'tui.diag.col.area'), (Get-AtmText 'tui.diag.col.items'))
            $items = @(Get-AtmGuiDiagCategoryList -Diag $Diag)
            foreach ($i in $items) { $rows.Add((ConvertTo-AtmGuiRow @($i.Label, [string]$i.Count))) }
            $pre.Add((Get-AtmText 'tui.diag.lastRun' (Format-AtmGuiUtc $Diag.View.finishedUtc)))
            if ($Diag.Stale) { $pre.Add((Get-AtmText 'tui.diag.stale' $Diag.Error)) }
            $pre.Add((Get-AtmText 'tui.diag.noAuth'))
            $pre.Add((Get-AtmText 'tui.diag.starLegend'))
        }
        'dcov' {
            $out.Columns = @((Get-AtmText 'tui.diag.col.collector'), (Get-AtmText 'tui.diag.col.status'), (Get-AtmText 'tui.diag.col.reasons'), (Get-AtmText 'tui.diag.col.elev'))
            $items = @($ix.Coverage)
            foreach ($c in $items) { $rows.Add((ConvertTo-AtmGuiRow @([string]$c.collector, [string]$c.status, (Get-AtmGuiDiagReasonText $c), [string]$c.elevationWouldHelp))) }
        }
        'dlist' {
            $out.Columns = @((Get-AtmText 'tui.diag.col.state'), (Get-AtmText 'tui.diag.col.kind'), (Get-AtmText 'tui.diag.col.key'), (Get-AtmText 'tui.diag.col.provider'))
            $catName = [string](Get-AtmGuiOpt $Screen.Filter 'Cat')
            if ($ix.ByCat.ContainsKey($catName)) { $items = @($ix.ByCat[$catName]) }
            foreach ($f in $items) { $rows.Add((ConvertTo-AtmGuiRow @([string]$f.state, [string]$f.kind, [string]$f.key, $(if ($f.provider) { [string]$f.provider } else { '-' })))) }
            $gp = $ix.Gap[$catName]
            if ($null -ne $gp) { $pre.Add((Get-AtmText 'tui.diag.covNote' $gp.Status $gp.Reasons)) }
            foreach ($g in @($Diag.Gates)) { if ($g.Cat -ceq $catName) { $pre.Add($g.Line); $gates.Add($g.Line) } }
        }
        'dnodes' {
            $out.Columns = @((Get-AtmText 'tui.diag.col.kind'), (Get-AtmText 'tui.diag.col.key'), (Get-AtmText 'tui.diag.col.finding'), (Get-AtmText 'tui.diag.col.inout'))
            $items = @($ix.Nodes)
            foreach ($n in $items) {
                $nk = [string]$n.kind + '|' + [string]$n.key
                $i0 = 0; if ($ix.InBy.ContainsKey($nk)) { $i0 = $ix.InBy[$nk].Count }
                $o0 = 0; if ($ix.OutBy.ContainsKey($nk)) { $o0 = $ix.OutBy[$nk].Count }
                $rows.Add((ConvertTo-AtmGuiRow @([string]$n.kind, [string]$n.key, $(if ($n.finding) { Get-AtmText 'tui.diag.findingShortYes' } else { Get-AtmText 'tui.diag.findingShortNo' }), "$i0/$o0")))
            }
        }
        'dissues' {
            $out.Columns = @((Get-AtmText 'tui.diag.col.type'), (Get-AtmText 'tui.diag.col.status'), (Get-AtmText 'tui.diag.col.item'), (Get-AtmText 'tui.diag.col.reasons'))
            $items = @($ix.Issues)
            foreach ($i in $items) {
                if ($i.T -ceq 'cov') { $rows.Add((ConvertTo-AtmGuiRow @((Get-AtmText 'tui.diag.typeCov'), [string]$i.C.status, [string]$i.C.collector, (Get-AtmGuiDiagReasonText $i.C)))) }
                else {
                    # The GRAPH_REASON details, then the incomplete coverage, each kept once (case-sensitive), as the TUI.
                    $why = New-Object System.Collections.Generic.List[object]
                    foreach ($ev in @($i.F.evidence)) { if ($ev.code -ceq 'GRAPH_REASON') { $why.Add([string]$ev.detail) } }
                    foreach ($x in @($i.F.incompleteCoverage)) { $why.Add($x) }
                    $uniq = New-Object System.Collections.Generic.List[object]
                    foreach ($x in $why) {
                        $dup = $false
                        foreach ($u in $uniq) { if ($u -ceq $x) { $dup = $true } }
                        if (-not $dup) { $uniq.Add($x) }
                    }
                    $rows.Add((ConvertTo-AtmGuiRow @((Get-AtmText 'tui.diag.typeFind'), [string]$i.F.state, ([string]$i.F.kind + ' ' + [string]$i.F.key), $(if ($why.Count) { $uniq.ToArray() -join ',' } else { '-' }))))
                }
            }
        }
    }
    $out.Items = $items
    $out.Rows = $rows.ToArray()
    $out.Pre = $pre.ToArray()
    $out.GateLines = $gates.ToArray()
    if (@($items).Count -eq 0) {
        # An empty list with incomplete coverage (or a feature behind a gate) is "nothing observed", never "none".
        if ($null -ne $gp -or $gates.Count -gt 0) { $out.Empty = Get-AtmText 'tui.diag.emptyNotObserved' } else { $out.Empty = Get-AtmText 'common.none' }
    }
    return [pscustomobject]$out
}

function Add-AtmGuiDiagEdgeLines {
    # The edges of a node, both directions, as the TUI writes them: marker, relation, the other end and the evidence; at
    # most AtmGuiDiagMaxEdges per direction, then a line with how many more.
    param($Index, [string]$NodeKey, $Lines)
    $strength = Get-AtmGuiDiagStrength
    foreach ($dir in @('in', 'out')) {
        $list = @(if ($dir -ceq 'in') { if ($Index.InBy.ContainsKey($NodeKey)) { $Index.InBy[$NodeKey].ToArray() } } else { if ($Index.OutBy.ContainsKey($NodeKey)) { $Index.OutBy[$NodeKey].ToArray() } })
        $Lines.Add((Get-AtmText $(if ($dir -ceq 'in') { 'tui.diag.det.in' } else { 'tui.diag.det.out' }) $list.Count))
        if ($list.Count -eq 0) { $Lines.Add(('  ' + (Get-AtmText 'common.none'))) }
        $shown = 0
        foreach ($e in $list) {
            if ($shown -ge $script:AtmGuiDiagMaxEdges) { $Lines.Add(('  ' + (Get-AtmText 'tui.diag.det.more' ($list.Count - $shown)))); break }
            $mk = $strength[[string]$e.strength]; if (-not $mk) { $mk = '[ ]' }
            $other = $(if ($dir -ceq 'in') { [string]$e.fromKind + ' ' + [string]$e.from } else { [string]$e.toKind + ' ' + [string]$e.to })
            $arrow = $(if ($dir -ceq 'in') { '<-' } else { '->' })
            $amb = $(if ([string]$e.strength -ceq 'AMBIGUOUS') { ' ' + (Get-AtmText 'tui.diag.ambEdge') } else { '' })
            $Lines.Add(('  {0} {1} {2} {3}{4}' -f $mk, [string]$e.relation, $arrow, $other, $amb))
            foreach ($ev in @($e.evidence)) { $Lines.Add(('      {0} [{1}]{2}' -f [string]$ev.code, [string]$ev.collector, $(if ($ev.detail) { ' ' + [string]$ev.detail } else { '' }))) }
            $shown++
        }
    }
}

function Get-AtmGuiDiagText {
    # A text screen of the area (summary, coverage record, finding, node), line by line as the TUI writes it, without the
    # wrapping of the console. Returns Lines and GateLines (the gate lines among them: the summary only).
    param($Diag, [hashtable]$Screen)
    $L = New-Object System.Collections.Generic.List[string]
    $gates = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Diag -or $null -eq $Diag.View) { return [pscustomobject]@{ Lines = @(); GateLines = @() } }
    $v = $Diag.View; $ix = $Diag.Index; $colls = Get-AtmGuiDiagCatCollectors
    $covLine = {
        param([string]$Label, [int]$Count, [string]$Cat)
        $gp = $ix.Gap[$Cat]
        if ($null -eq $gp) { $L.Add((Get-AtmText 'tui.diag.sumCount' $Label $Count)) }
        elseif ($gp.AllMissing) { $L.Add((Get-AtmText 'tui.diag.sumNotObserved' $Label (@($colls[$Cat]) -join ','))) }
        else { $L.Add((Get-AtmText 'tui.diag.sumCountPartial' $Label $Count $gp.Status $gp.Reasons)) }
    }
    $gapNote = { param([string]$Cat) $gp = $ix.Gap[$Cat]; if ($null -ne $gp) { $L.Add(('  ' + (Get-AtmText 'tui.diag.covNote' $gp.Status $gp.Reasons))) } }
    switch ([string]$Screen.Name) {
        'dsum' {
            $L.Add((Get-AtmText 'tui.diag.lastRun' (Format-AtmGuiUtc $v.finishedUtc)))
            if ($Diag.Stale) { $L.Add((Get-AtmText 'tui.diag.stale' $Diag.Error)) }
            $L.Add((Get-AtmText 'tui.diag.noAuth'))
            foreach ($g in @($Diag.Gates)) { $L.Add($g.Line); $gates.Add($g.Line) }
            $L.Add('')
            $sm = $ix.Sum
            $inc = @($sm.Incomplete)
            $L.Add((Get-AtmText 'tui.diag.sumCoverage' $(if ($v.coverageComplete) { Get-AtmText 'common.complete' } else { Get-AtmText 'common.incomplete' })))
            if ($inc.Count) {
                $parts = New-Object System.Collections.Generic.List[string]
                foreach ($c in $inc) { $parts.Add(([string]$c.collector + '=' + [string]$c.status)) }
                $L.Add((Get-AtmText 'tui.diag.sumIncomplete' ($parts.ToArray() -join ', ')))
            }
            $L.Add('')
            foreach ($g in @($sm.Kinds)) { $L.Add((Get-AtmText 'tui.diag.sumKind' $g.Kind $g.Count $g.States)) }
            $L.Add('')
            $L.Add((Get-AtmText 'tui.diag.sumParts' $sm.PartsInUse $sm.PartsUnknown $sm.PartsNone))
            & $gapNote 'parts'
            $L.Add((Get-AtmText 'tui.diag.sumProcs' $sm.ProcVerified $sm.ProcUnverified $sm.Sessions))
            & $gapNote 'procs'
            & $covLine (Get-AtmText 'tui.diag.lblServices') $sm.Services 'services'
            & $covLine (Get-AtmText 'tui.diag.lblVms') $sm.Vms 'virt'
            & $covLine (Get-AtmText 'tui.diag.lblWorktrees') $sm.Worktrees 'worktrees'
            $gc = $(if ($null -ne $v.graph) { $v.graph.coverage } else { $null })
            if ($null -ne $gc) { $L.Add((Get-AtmText 'tui.diag.sumGraph' $gc.nodes $gc.edges ([string]$gc.status + $(if (@($gc.reasons).Count) { ' (' + (@($gc.reasons) -join ',') + ')' } else { '' })))) }
            if ($inc.Count) {
                $L.Add('')
                $L.Add((Get-AtmText 'tui.diag.sumLimits'))
                foreach ($c in $inc) { $L.Add(('  ' + (Get-AtmText 'tui.diag.limitLine' ([string]$c.collector) ([string]$c.status) (Get-AtmGuiDiagReasonText $c)))) }
            }
            $L.Add('')
            $L.Add((Get-AtmText 'tui.diag.unknownNote'))
        }
        'dcovdet' {
            $c = $Screen.Filter.C
            $L.Add(('{0,-22}: {1}' -f (Get-AtmText 'tui.diag.col.collector'), [string]$c.collector))
            $L.Add(('{0,-22}: {1} - {2}' -f (Get-AtmText 'tui.diag.col.status'), [string]$c.status, (Get-AtmText ('coverage.' + [string]$c.status))))
            if ($null -ne $c.observed -and $null -ne $c.expected) { $L.Add((Get-AtmText 'tui.diag.cov.observed' $c.observed $c.expected)) }
            $L.Add((Get-AtmText $(switch ([string]$c.elevationWouldHelp) { 'YES' { 'tui.diag.elevYes' } 'NO' { 'tui.diag.elevNo' } default { 'tui.diag.elevUnknown' } })))
            $L.Add('')
            $L.Add((Get-AtmText 'tui.diag.col.reasons'))
            if (@($c.reasons).Count -eq 0) { $L.Add(('  ' + (Get-AtmText 'common.none'))) }
            foreach ($x in @($c.reasons)) { $tx = Get-AtmCodeText 'reason' ([string]$x); $L.Add(('  ' + [string]$x + $(if ($tx) { ' - ' + $tx } else { '' }))) }
        }
        'dfind' {
            $f = $Screen.Filter.F
            $nk = [string]$f.kind + '|' + [string]$f.key
            $L.Add(('{0,-22}: {1}' -f (Get-AtmText 'tui.diag.col.kind'), [string]$f.kind))
            $L.Add(('{0,-22}: {1}' -f (Get-AtmText 'tui.diag.det.key'), [string]$f.key))
            $L.Add(('{0,-22}: {1}' -f (Get-AtmText 'tui.diag.col.state'), [string]$f.state))
            if ($f.requestedState -and [string]$f.requestedState -cne [string]$f.state) { $L.Add(('{0,-22}: {1}' -f (Get-AtmText 'tui.diag.det.requested'), [string]$f.requestedState)) }
            $amb = New-Object System.Collections.Generic.List[string]
            foreach ($ev in @($f.evidence)) { if ($ev.code -ceq 'PROVIDER_ATTRIBUTION_AMBIGUOUS') { $amb.Add([string]$ev.detail) } }
            if ($amb.Count) { $L.Add(('{0,-22}: {1}' -f (Get-AtmText 'tui.diag.col.provider'), (Get-AtmText 'tui.diag.det.providerAmbiguous' ($amb.ToArray() -join ',')))) }
            elseif ($f.provider) { $L.Add(('{0,-22}: {1}' -f (Get-AtmText 'tui.diag.col.provider'), [string]$f.provider)) }
            $tl = New-Object System.Collections.Generic.List[object]
            foreach ($ev in @($f.evidence)) { $t0 = Format-AtmGuiUtc $ev.observedUtc; if ($t0 -ne '-') { $tl.Add($t0) } }
            $times = @(Get-AtmGuiSortedUnique -Items $tl.ToArray())
            $L.Add(('{0,-22}: {1}' -f (Get-AtmText 'tui.diag.det.observed'), $(if ($times.Count) { $times -join ', ' } else { '-' })))
            if ([string]$f.state -ceq 'UNKNOWN') { $L.Add((Get-AtmText 'tui.diag.unknownNote')) }
            $L.Add('')
            $L.Add((Get-AtmText 'tui.diag.det.evidence'))
            if (@($f.evidence).Count -eq 0) { $L.Add(('  ' + (Get-AtmText 'common.none'))) }
            foreach ($ev in @($f.evidence)) {
                $tx = Get-AtmCodeText 'evidence' ([string]$ev.code)
                $L.Add(('  - {0} [{1}]{2}{3}' -f [string]$ev.code, [string]$ev.collector, $(if ($ev.detail) { ' ' + [string]$ev.detail } else { '' }), $(if ($tx) { ' - ' + $tx } else { '' })))
            }
            $L.Add('')
            $L.Add((Get-AtmText 'tui.diag.det.coverage'))
            foreach ($cn in @($f.coverage)) { $cr = $(if ($ix.CovBy.ContainsKey([string]$cn)) { [string]$ix.CovBy[[string]$cn].status } else { '-' }); $L.Add(('  - {0}: {1}' -f [string]$cn, $cr)) }
            $L.Add(('{0}: {1}' -f (Get-AtmText 'tui.diag.det.incomplete'), $(if (@($f.incompleteCoverage).Count) { @($f.incompleteCoverage) -join ', ' } else { Get-AtmText 'common.none' })))
            $L.Add('')
            $L.Add((Get-AtmText 'tui.diag.det.graph'))
            $L.Add((Get-AtmText 'tui.diag.legend'))
            if (-not $ix.NodeBy.ContainsKey($nk)) { $L.Add(('  ' + (Get-AtmText 'tui.diag.det.noNode'))) }
            else { Add-AtmGuiDiagEdgeLines -Index $ix -NodeKey $nk -Lines $L }
        }
        'dnode' {
            $n = $Screen.Filter.N
            $nk = [string]$n.kind + '|' + [string]$n.key
            $L.Add(('{0,-22}: {1}' -f (Get-AtmText 'tui.diag.col.kind'), [string]$n.kind))
            $L.Add(('{0,-22}: {1}' -f (Get-AtmText 'tui.diag.det.key'), [string]$n.key))
            if ($n.finding) {
                $L.Add(('{0,-22}: {1}' -f (Get-AtmText 'tui.diag.col.finding'), (Get-AtmText 'tui.diag.finding.yes')))
                if ($ix.FindingBy.ContainsKey($nk)) { $L.Add(('{0,-22}: {1}' -f (Get-AtmText 'tui.diag.col.state'), [string]$ix.FindingBy[$nk].state)) }
            } else { $L.Add(('{0,-22}: {1}' -f (Get-AtmText 'tui.diag.col.finding'), (Get-AtmText 'tui.diag.finding.no'))) }
            $L.Add((Get-AtmText 'tui.diag.legend'))
            $L.Add('')
            Add-AtmGuiDiagEdgeLines -Index $ix -NodeKey $nk -Lines $L
        }
    }
    return [pscustomobject]@{ Lines = $L.ToArray(); GateLines = $gates.ToArray() }
}

function Invoke-AtmGuiNavDiag {
    # The move after a diagnose request (Gui.ps1 ran it, or not), as the TUI moves. -Result: what the request did (CACHED,
    # OK, FAILED or IGNORED; CANCELLED never comes here). -Diag: the result the session keeps after it.
    #  * D: with a view, the area opens over the dashboard; without one (the first run failed), the window stays where it
    #    is with the failure's text (its type only);
    #  * U (-Refresh): back to the area's first screen, first row; the text says the result is new, or that the run
    #    failed (the previous result stays, marked outdated).
    param([hashtable]$Nav, $Diag, [string]$Result, [switch]$Refresh)
    if ($Result -ceq 'IGNORED') { return }
    $hasView = ($null -ne $Diag -and $null -ne $Diag.View)
    $failed = $(if ($Result -ceq 'FAILED' -and $null -ne $Diag) { Get-AtmText 'tui.diag.failed' $Diag.Error } else { $null })
    if ($Refresh) {
        while ($Nav.Stack.Count -gt 1 -and $Nav.Stack[$Nav.Stack.Count - 1].Name -cne 'diag') { $Nav.Stack.RemoveAt($Nav.Stack.Count - 1) }
        if ($Nav.Stack.Count -gt 1) { $Nav.Stack[$Nav.Stack.Count - 1].Sel = 0 }
        $Nav.Message = $(if ($Result -ceq 'OK') { Get-AtmText 'tui.diag.refreshed' } else { $failed })
        return
    }
    if (-not $hasView) { $Nav.Message = $failed; return }
    while ($Nav.Stack.Count -gt 1) { $Nav.Stack.RemoveAt($Nav.Stack.Count - 1) }
    $Nav.Stack.Add(@{ Name = 'diag'; Title = (Get-AtmText 'tui.diag.title'); Filter = $null; Sel = 0 })
    $Nav.Message = $failed
}
