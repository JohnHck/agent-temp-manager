# Agent Temp Manager - view models of the desktop GUI (V0.2.1, docs/adr/ADR-0014-desktop-gui-winforms.md).
#
# Rules (ADR-0014 section 3):
#  * Plain PowerShell objects, no WinForms type: all view models are testable without a window.
#  * View models call only the engine read functions of the closed list; the static test of the suite reads this
#    file and src/lib/Gui.ps1 and fails on any other command.
#  * Nothing here decides: no class, eligibility, gate or coverage verdict is computed. The engine's results are only
#    counted and formatted, with the helpers the TUI dashboard uses (Get-AtmTuiDashboardLines).
#  * Loading this file defines functions only (no assembly, no type, no state).
# Phase P1: the identity header (PRIV-10). Phase P2: the dashboard, the state of the view and the automatic purge
# notice (GUI-D1). Phase P3: the drill-down by user, project and root, the detail of a root, the coverage and errors
# screen, and the navigation between them (the TUI's screens, keys 1 to 7 and 9).

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
    # The screens of the TUI menu that the GUI shows (keys 1 to 7 and 9), with the TUI's labels and titles. Preview,
    # diagnose, isolation, cleanup and the quarantine area are not offered here (ADR-0014 section 10, later phases).
    return @(
        @{ Key = '1'; Label = (Get-AtmText 'menu.dashboard'); Screen = @{ Name = 'dashboard'; Title = (Get-AtmText 'menu.dashboard') } }
        @{ Key = '2'; Label = (Get-AtmText 'menu.users'); Screen = @{ Name = 'users'; Title = (Get-AtmText 'menu.users') } }
        @{ Key = '3'; Label = (Get-AtmText 'menu.projects'); Screen = @{ Name = 'projects'; Title = (Get-AtmText 'menu.projects') } }
        @{ Key = '4'; Label = (Get-AtmText 'menu.roots'); Screen = @{ Name = 'roots'; Title = 'Roots' } }
        @{ Key = '5'; Label = 'ACTIVE_EVIDENCE'; Screen = @{ Name = 'roots'; Title = 'ACTIVE_EVIDENCE'; Filter = @{ Class = 'ACTIVE_EVIDENCE' } } }
        @{ Key = '6'; Label = 'RECENT'; Screen = @{ Name = 'roots'; Title = 'RECENT'; Filter = @{ Class = 'RECENT' } } }
        @{ Key = '7'; Label = 'LIVENESS_UNKNOWN'; Screen = @{ Name = 'roots'; Title = 'LIVENESS_UNKNOWN'; Filter = @{ Class = 'LIVENESS_UNKNOWN' } } }
        @{ Key = '9'; Label = (Get-AtmText 'menu.errors'); Screen = @{ Name = 'errors'; Title = (Get-AtmText 'menu.errorsTitle') } }
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

function Get-AtmGuiRootDetail {
    # Screen `detail` of the root with this path in the inventory: the TUI's fields, with the same det.* keys, then the
    # evidence, the ancestor and ambiguous references and the samples of errors and reparse points. Not here: the
    # preview line (phase P4), the isolation hint and the hint of the CLI's path drill-down (no action in the GUI).
    # Found = $false when the root is no longer in the inventory: nothing is shown for it.
    param($Inventory, [string]$Path)
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
    # The content of one screen of the navigation stack. Kind: dashboard, table (users, projects, roots), pairs (the
    # detail) or lines (coverage and errors). Known = $false before the first audit: no row is invented. Gone = $true
    # when the root of a detail is not in the inventory.
    param($Inventory, [hashtable]$Screen)
    $known = ($null -ne $Inventory)
    $vm = [ordered]@{ Name = $Screen.Name; Title = $Screen.Title; Kind = 'table'; Known = $known; Gone = $false; Columns = @(); Rows = @(); Items = @(); Pairs = @(); Lines = @(); Note = $(if ($known) { $null } else { Get-AtmText 'gui.noAudit' }) }
    switch ($Screen.Name) {
        'dashboard' { $vm.Kind = 'dashboard' }
        'users' { $t = Get-AtmGuiUserTable -Inventory $Inventory; $vm.Columns = $t.Columns; $vm.Rows = $t.Rows; $vm.Items = $t.Items }
        'projects' { $t = Get-AtmGuiProjectTable -Inventory $Inventory; $vm.Columns = $t.Columns; $vm.Rows = $t.Rows; $vm.Items = $t.Items }
        'roots' { $t = Get-AtmGuiRootTable -Inventory $Inventory -Filter $Screen.Filter; $vm.Columns = $t.Columns; $vm.Rows = $t.Rows; $vm.Items = $t.Items }
        'detail' {
            $vm.Kind = 'pairs'
            $vm.Columns = @((Get-AtmText 'gui.col.field'), (Get-AtmText 'gui.col.value'))
            if ($known) {
                $d = Get-AtmGuiRootDetail -Inventory $Inventory -Path ([string]$Screen.Filter.Path)
                $vm.Gone = (-not $d.Found); $vm.Pairs = $d.Pairs; $vm.Lines = $d.Lines
            }
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
    # One key or screen button, as the TUI handles it. -Key: '1' to '9' (or D1/NumPad1 to 9), Return/Enter, Escape.
    # Returns RENDER (the screen changed), CLOSE (Esc on the dashboard), IGNORED (an audit runs: nothing moves) or NONE.
    #  * 1 to 7 and 9: the screen of that key, over the dashboard (1: the dashboard itself);
    #  * Enter on a row: user -> the roots of that user; project -> the roots of that project; root -> its detail;
    #  * Esc: one screen back; on the dashboard it closes the window.
    param([hashtable]$Nav, $Inventory, [string]$Key, [bool]$Busy)
    if ($Busy) { return 'IGNORED' }
    $digit = $null
    if ($Key -cmatch '^(D|NumPad)?([1-9])$') { $digit = $Matches[2] }
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
        $vm = Get-AtmGuiScreen -Inventory $Inventory -Screen $top
        if ($vm.Kind -cne 'table' -or @($vm.Items).Count -eq 0) { return 'NONE' }
        $it = @($vm.Items)[[math]::Max(0, [math]::Min([int]$top.Sel, @($vm.Items).Count - 1))]
        $push = $null
        switch ($it.Kind) {
            'user' { $push = @{ Name = 'roots'; Title = (Get-AtmText 'tui.rootsOf' $it.Profile.UserName); Filter = @{ Sid = $it.Profile.Sid; ProfilePath = $it.Profile.ProfilePath } } }
            'project' { $push = @{ Name = 'roots'; Title = (Get-AtmText 'tui.rootsOfProject' $it.Project $it.UserName); Filter = @{ Sid = $it.Sid; ProfilePath = $it.ProfilePath; Project = $it.Project; Slug = $it.Slug } } }
            'root' { $push = @{ Name = 'detail'; Title = (Get-AtmText 'tui.detailOf' $it.Partition.Name); Filter = @{ Path = [string]$it.Partition.Path; Name = [string]$it.Partition.Name } } }
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
    param([hashtable]$Nav, $Inventory)
    $top = Get-AtmGuiNavTop -Nav $Nav
    if ($top.Name -ceq 'detail' -and $null -ne $Inventory -and -not (Get-AtmGuiRootDetail -Inventory $Inventory -Path ([string]$top.Filter.Path)).Found) {
        $Nav.Stack.RemoveAt($Nav.Stack.Count - 1)
        $Nav.Message = Get-AtmText 'gui.detailGone' ([string]$top.Filter.Name)
        $top = Get-AtmGuiNavTop -Nav $Nav
    }
    $n = @((Get-AtmGuiScreen -Inventory $Inventory -Screen $top).Items).Count
    if ([int]$top.Sel -ge $n) { $top.Sel = [math]::Max(0, $n - 1) }
}
