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
# notice (GUI-D1).

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
