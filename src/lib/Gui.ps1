# Agent Temp Manager - desktop GUI (V0.2.1, docs/adr/ADR-0014-desktop-gui-winforms.md).
#
# Rules (ADR-0014 sections 2 to 8):
#  * Presentation only: the form reads view models (src/lib/GuiModel.ps1), and nothing here decides, deletes, moves,
#    writes a file or starts a process. The static test of the suite reads src/lib/Gui*.ps1 and fails on any command
#    outside the closed list.
#  * Loading this file defines functions and constants only: no assembly is loaded and no type is declared. WinForms is
#    loaded by Import-AtmGuiAssemblies, only past the release gate and the environment checks.
#  * Order of `agent-temp gui`, after the launcher's integrity check: the release gate, then the STA thread and the
#    interactive desktop, then the assemblies, then the window.
# Phase P1: a minimal window with the title, the identity and the elevation state (PRIV-10).
# Phase P2: the dashboard. One audit when the window opens, then only on an explicit request (the Refresh button or
# F5), on the UI thread (GUI-D9); nothing repeats by itself (live monitoring is P5).
# Phase P3: the TUI's screens 1 to 7 and 9 (users, projects, roots, roots by class, coverage and errors), Enter on a row
# (the roots of a user or project, the detail of a root) and Esc one screen back. They only read the inventory of the
# last audit, and no screen offers an action over a root.
# Phase P4a: the preview screens (P every category, 8 the blocked paths) and the Preview line of a detail opened from
# them. The clean engine computes the preview once, when P or 8 is first opened after an audit; the session keeps it
# until the next audit. It is an evaluation only: no category is a button, and nothing is cleaned or isolated.
# Phase P4b: the diagnose area (D), the TUI's screens over the schema view of one diagnose result. The diagnose runs
# only on request: D runs it when the session has no result yet, U (inside the area) runs it again; an audit keeps it.
# The features behind the V0.2 gates are shown as disabled in this version; nothing is exported or acted on.
# Phase P5: the live monitoring (GUI-D2, GUI-D3, GUI-D10). Off when the window opens, 60 s by default, nothing kept for
# the next window. One ticker of the form, created in one place, only wakes a check: Invoke-AtmGuiTick decides by the
# session's NextDueUtc and runs the audit on the F5 path (never the diagnose), keeping the screen; a tick while anything
# runs is dropped, never queued. A slow audit, an old view or a failure marks the view STALE; closing the window stops
# and releases the ticker. No process, job, runspace or thread, and nothing is written.
# Phase P6: languages and accessibility (ADR-0014 section 7). Every visible text and every accessible name comes from the
# catalog, in the language chosen at start; every control has an accessible name; the tab order follows the visual one
# (header, state, monitoring, screens, title, lists, commands); Enter presses a focused button; system colors only; the
# fixed widths of the lists and their columns are scaled by the form's DPI.
# V0.4 R5 (ADR-0016): the recovery area (S), view only. Opening it is the one action that collects: one blocking,
# read-only collection of the recovery engine on the UI thread (no progress, as the preview), then its list; Enter shows
# the plan of a service chosen from that list. The live monitoring's ticker never collects. There is no button that
# executes or undoes anything: executing stays in the CLI (T-ISO-6).

# Release gate of the desktop GUI (D-A). Closed in every distributed copy: `agent-temp gui` opens no window and loads no
# WinForms assembly. Tests open it only in their own process memory.
$script:AtmGuiEnabled = $false

# Exit codes of `agent-temp gui` (GUI-D8): 7 the release gate is closed; 8 this environment cannot show a window.
$script:AtmGuiExitGateClosed = 7
$script:AtmGuiExitEnvironment = 8

# Test seams (suite only; $null = the real source). Apartment: returns the thread's apartment state as text. Desktop:
# returns whether an interactive desktop is available. Assembly loader: loads the assemblies or throws. Inventory
# source: called with the inventory arguments (a hashtable that carries the ProgressCallback); returns an inventory or
# throws. Preview source (P4a): called with the session's inventory and inventory arguments; returns the preview rows or
# throws. Diagnose source (P4b): called with the diagnose arguments (InventoryArgs, which carries the ProgressCallback);
# returns a diagnose result or throws. Clock source (P5): returns the current time as a UTC [datetime]; used only for
# "now" (the audit time, the duration of a refresh and the live monitoring's schedule). Recover source (V0.4 R5): called
# with no argument when the recovery area is opened; returns one collection of the recovery engine or throws.
$script:AtmGuiApartmentSource = $null
$script:AtmGuiDesktopSource = $null
$script:AtmGuiAssemblyLoader = $null
$script:AtmGuiInventorySource = $null
$script:AtmGuiPreviewSource = $null
$script:AtmGuiDiagnoseSource = $null
$script:AtmGuiClockSource = $null
$script:AtmGuiRecoverSource = $null

# P5: a wake of the ticker this close to the due time counts as due (the ticker and the clock have different
# granularity), in milliseconds.
$script:AtmGuiTickToleranceMs = 500

function Get-AtmGuiNow {
    # The current time in UTC, from the clock seam in tests.
    if ($null -ne $script:AtmGuiClockSource) { return [datetime](& $script:AtmGuiClockSource) }
    return [datetime]::UtcNow
}

function Test-AtmGuiEnvironment {
    # $null when a window can be shown here, otherwise the reason code. Loads nothing and changes nothing.
    $apartment = $(if ($null -ne $script:AtmGuiApartmentSource) { [string](& $script:AtmGuiApartmentSource) } else { [string][Threading.Thread]::CurrentThread.GetApartmentState() })
    if ($apartment -cne 'STA') { return 'GUI_NOT_STA' }
    # A service, session 0 or a non-interactive window station has no desktop a person can see.
    $desktop = $(if ($null -ne $script:AtmGuiDesktopSource) { [bool](& $script:AtmGuiDesktopSource) } else { [Environment]::UserInteractive -and ([Diagnostics.Process]::GetCurrentProcess().SessionId -ne 0) })
    if (-not $desktop) { return 'GUI_NO_INTERACTIVE_DESKTOP' }
    return $null
}

function Import-AtmGuiAssemblies {
    # The only place WinForms is loaded. $null when loaded, otherwise the reason code (never the exception text).
    try {
        if ($null -ne $script:AtmGuiAssemblyLoader) { & $script:AtmGuiAssemblyLoader }
        else { Add-Type -AssemblyName System.Windows.Forms, System.Drawing -ErrorAction Stop }
    } catch { return 'GUI_WINFORMS_UNAVAILABLE' }
    return $null
}

function Get-AtmGuiInventoryArgs {
    # The launcher's inventory arguments (agent-temp.ps1: $selfMarkers and $invArgs), built from this file's place, so
    # the launcher is not changed for the GUI: its own launcher chain is left out of process evidence, and the
    # configuration is the one next to lib. The suite checks that both stay equal.
    $root = [IO.Path]::GetDirectoryName($PSScriptRoot)
    return @{ SelfMarkers = @([IO.Path]::Combine($root, 'agent-temp.ps1'), [IO.Path]::Combine($root, 'bin\agent-temp.cmd')); ConfigDir = [IO.Path]::Combine($root, 'config') }
}

function Initialize-AtmGuiSession {
    # The audits of one window: the last result, the failure of the last audit (its exception type only), the counters
    # and the automatic purge notice (GUI-D1, read once). No WinForms type: the refresh logic is testable without a
    # window. -ConfigDir: test override of the configuration read for the notice and passed to the inventory.
    param([string]$ConfigDir)
    $ia = Get-AtmGuiInventoryArgs
    if ($ConfigDir) { $ia['ConfigDir'] = $ConfigDir }
    return @{
        InventoryArgs = $ia; Inventory = $null; FailureType = $null; RefreshedUtc = $null
        Busy = $false; CancelRequested = $false; CloseAfterRefresh = $false; Percent = -1
        Refreshes = 0; Failures = 0; Cancelled = 0; Ignored = 0; SourceCalls = 0
        AutoPurgeNotice = @(Get-AtmGuiAutoPurgeNotice -ConfigDir $ia['ConfigDir'])
        Nav = (Initialize-AtmGuiNav)
        # P4a: the preview rows of the current audit ($null: not computed), the exception type of a failed preview, and
        # a close requested while the preview runs.
        Preview = $null; PreviewFailureType = $null; PreviewBusy = $false; CloseAfterPreview = $false; PreviewCalls = 0; PreviewFailures = 0
        # P4b: the diagnose result (New-AtmGuiDiagState; an audit keeps it), a run in progress, a close requested during
        # it, the counters and the percentage of its inventory phase.
        Diag = $null; DiagBusy = $false; DiagCancelRequested = $false; CloseAfterDiag = $false; DiagCalls = 0; DiagFailures = 0; DiagCancelled = 0; DiagPercent = -1
        # P5: the live monitoring, off and at 60 s when the window opens (nothing is remembered); the time the next tick
        # may audit ($null: none), whether that time is the backoff after a slow audit, why the view is STALE besides a
        # failure (SLOW, OLD or $null), the duration of the last audit, a close in progress, and the tick counters.
        Monitor = $false; IntervalSeconds = 60; NextDueUtc = $null; Backoff = $false; StaleReason = $null; LastDurationSeconds = $null; Closing = $false
        Ticks = 0; TickRuns = 0; TicksNotDue = 0; TicksBusy = 0; TicksBackoff = 0
        # P6: the DPI of the window (Get-AtmGuiDpi), for the fixed widths of the lists and their columns; 96 until the form
        # exists.
        Dpi = 96
        # V0.4 R5: the recovery area's last opening (its collection and list, or the exception code of its failure) and
        # the counters of the openings that collected.
        Recover = $null; RecoverCalls = 0; RecoverFailures = 0
    }
}

function Get-AtmGuiDpi {
    # P6: the DPI of the form: DeviceDpi where the .NET of this machine has it (4.7 and later), otherwise the DpiX of a
    # graphics object of the form, released at once. Never below 96 when unknown.
    param($Form)
    if ($null -ne $Form.PSObject.Properties['DeviceDpi']) {
        $d = [int]$Form.DeviceDpi
        if ($d -gt 0) { return $d }
    }
    $g = $Form.CreateGraphics()
    try { $d = [int][math]::Round($g.DpiX) } finally { $g.Dispose() }
    if ($d -le 0) { return 96 }
    return $d
}

function Set-AtmGuiMonitor {
    # The live monitoring's check box (GUI-D2). On: the first tick is due one interval from -Now (turning it on audits
    # nothing). Off: nothing is due; an audit in progress ends normally; the age of the view marks nothing.
    param([hashtable]$Session, [bool]$On, [datetime]$Now)
    $Session.Monitor = ($On -and -not $Session.Closing)
    $Session.Backoff = $false
    if ($Session.Monitor) { $Session.NextDueUtc = $Now.AddSeconds([int]$Session.IntervalSeconds) }
    else {
        $Session.NextDueUtc = $null
        if ($Session.StaleReason -ceq 'OLD') { $Session.StaleReason = $null }
    }
}

function Set-AtmGuiMonitorInterval {
    # The interval list (one of Get-AtmGuiMonitorIntervals, nothing else). With the monitoring on, the count starts again
    # from -Now. Returns $false (and changes nothing) for any other value.
    param([hashtable]$Session, [int]$Seconds, [datetime]$Now)
    if (@(Get-AtmGuiMonitorIntervals) -notcontains $Seconds) { return $false }
    $Session.IntervalSeconds = $Seconds
    if ($Session.Monitor) {
        $Session.NextDueUtc = $Now.AddSeconds($Seconds)
        $Session.Backoff = $false
    }
    return $true
}

function Update-AtmGuiRefreshTiming {
    # After an audit (a tick or F5), from its start and end: the duration is kept; with the monitoring on, an audit slower
    # than half the interval marks the view STALE (SLOW) and the next tick waits max(interval, 2 x duration) from the
    # end (the backoff); a good, fast audit clears both. A failure keeps the failure's mark and is tried again one
    # interval later, as any tick. A cancelled or ignored audit changes nothing.
    param([hashtable]$Session, [string]$Result, [datetime]$StartUtc, [datetime]$EndUtc)
    if ($Result -cne 'OK' -and $Result -cne 'FAILED') { return }
    $d = ($EndUtc - $StartUtc).TotalSeconds
    if ($d -lt 0) { $d = 0 }
    $Session.LastDurationSeconds = $d
    $iv = [int]$Session.IntervalSeconds
    $wait = $iv
    if ($Result -ceq 'OK') {
        if ($Session.Monitor -and $d -gt ($iv / 2)) {
            $Session.StaleReason = 'SLOW'
            $Session.Backoff = $true
            $wait = [math]::Max([double]$iv, 2 * $d)
        } else {
            $Session.StaleReason = $null
            $Session.Backoff = $false
        }
    } else { $Session.Backoff = $false }
    if ($Session.Monitor -and -not $Session.Closing) { $Session.NextDueUtc = $EndUtc.AddSeconds($wait) }
}

function Invoke-AtmGuiTick {
    # The one decision of the live monitoring (ADR-0014 section 5), testable without a window; the ticker's handler only
    # calls it. -Now: the time of this wake. First the age of the view is checked (on every tick, also the skipped ones):
    # with the monitoring on, no good audit for more than twice the interval marks it STALE (OLD). Then it returns:
    #  SKIPPED_NOT_DUE  no time is due (off or closing), or -Now is before NextDueUtc: nothing is called;
    #  SKIPPED_BACKOFF  -Now is before NextDueUtc set by the backoff of a slow audit: nothing is called;
    #  SKIPPED_BUSY     an audit, the preview or a D or U run is in progress: dropped, never queued;
    #  REFRESHED        the audit ran (Invoke-AtmGuiRefresh, the F5 path) and replaced the result;
    #  FAILED           the audit failed: the earlier result stays, STALE with the exception code only;
    #  CANCELLED        the window was closed during the audit (it stops at its next callback).
    # The screen stays (unlike F5 on a preview screen): it is computed again over the new result, and a detail whose root
    # is gone goes back to its list (P3). On a preview screen (P, 8 or a detail opened from them) the same tick computes
    # the preview again, and its time counts in the duration; on any other screen the audit has discarded the kept
    # preview. The kept result of D and U is never touched by a tick (GUI-D3). -Pump: the progress callback's pump;
    # -OnStart: just before the audit, only when it runs; -OnPreviewStart: just before the preview of a preview screen.
    param([hashtable]$Session, [datetime]$Now, [scriptblock]$Pump, [scriptblock]$OnStart, [scriptblock]$OnPreviewStart)
    $Session.Ticks++
    $iv = [int]$Session.IntervalSeconds
    if ($Session.Monitor -and $null -ne $Session.Inventory -and -not $Session.FailureType -and $null -eq $Session.StaleReason -and $null -ne $Session.RefreshedUtc -and ($Now - [datetime]$Session.RefreshedUtc).TotalSeconds -gt (2 * $iv)) {
        $Session.StaleReason = 'OLD'
    }
    if (-not $Session.Monitor -or $Session.Closing -or $null -eq $Session.NextDueUtc) { $Session.TicksNotDue++; return 'SKIPPED_NOT_DUE' }
    if ($Now.AddMilliseconds($script:AtmGuiTickToleranceMs) -lt [datetime]$Session.NextDueUtc) {
        if ($Session.Backoff) { $Session.TicksBackoff++; return 'SKIPPED_BACKOFF' }
        $Session.TicksNotDue++
        return 'SKIPPED_NOT_DUE'
    }
    if ($Session.Busy -or $Session.PreviewBusy -or $Session.DiagBusy) { $Session.TicksBusy++; return 'SKIPPED_BUSY' }
    $onPreview = $false
    foreach ($sc in $Session.Nav.Stack) { if ([string]$sc.Name -ceq 'gates') { $onPreview = $true } }
    $Session.TickRuns++
    if ($null -ne $OnStart) { & $OnStart }
    $r = Invoke-AtmGuiRefresh -Session $Session -Pump $Pump
    if ($r -ceq 'OK' -and $onPreview -and -not $Session.Closing) { $null = Invoke-AtmGuiPreview -Session $Session -OnStart $OnPreviewStart }
    Update-AtmGuiRefreshTiming -Session $Session -Result $r -StartUtc $Now -EndUtc (Get-AtmGuiNow)
    if ($r -ceq 'IGNORED') { $Session.TicksBusy++; return 'SKIPPED_BUSY' }
    if ($r -ceq 'CANCELLED') { return 'CANCELLED' }
    Invoke-AtmGuiNavRefreshed -Nav $Session.Nav -Inventory $Session.Inventory -PreviewDiscarded $false -Preview $Session.Preview -Diag $Session.Diag
    if ($r -ceq 'OK') { return 'REFRESHED' }
    return 'FAILED'
}

function Invoke-AtmGuiDiagnose {
    # The only place the GUI runs the diagnose, on request (D when the session has no result, U inside the area), on the
    # calling (UI) thread, with the TUI's arguments: the session's inventory arguments. -Pump is called at each progress
    # callback of the inventory phase (the form shows the percentage and a fixed text, never the engine's message, and
    # handles its messages there). -OnStart runs just before the call, only when the call happens. -Refresh: U. Returns:
    #  OK         the new result replaces the earlier one (its index is built once, here);
    #  CACHED     D with a result kept: no call;
    #  IGNORED    an audit, the preview or the diagnose runs: no call (a request is dropped, never queued);
    #  CANCELLED  a close request: the inventory phase stops at its next callback, the collectors end within their own
    #             deadlines, and the result is discarded; the earlier result stays as it was;
    #  FAILED     only the exception code of the type is kept (never its message): an earlier result stays, marked
    #             outdated; without one, there is no result. Nothing retries by itself.
    param([hashtable]$Session, [scriptblock]$Pump, [scriptblock]$OnStart, [switch]$Refresh)
    if ($Session.Busy -or $Session.PreviewBusy -or $Session.DiagBusy) { return 'IGNORED' }
    if (-not $Refresh -and $null -ne $Session.Diag -and $null -ne $Session.Diag.View) { return 'CACHED' }
    $Session.DiagBusy = $true
    $Session.DiagCancelRequested = $false
    $Session.DiagPercent = 0
    # Read by the callback through dynamic scoping (gui-prefixed names; no closure, which could not see the functions).
    $guiDiagSession = $Session
    $guiDiagPump = $Pump
    $cb = {
        param($pct, $msg)
        # The engine's progress message names temporary bases: never shown.
        $null = $msg
        if ($guiDiagSession.DiagCancelRequested) { throw 'ATM_GUI_DIAGNOSE_CANCELLED' }
        $guiDiagSession.DiagPercent = [int]$pct
        if ($null -ne $guiDiagPump) { & $guiDiagPump }
        if ($guiDiagSession.DiagCancelRequested) { throw 'ATM_GUI_DIAGNOSE_CANCELLED' }
    }
    try {
        if ($null -ne $OnStart) { & $OnStart }
        $ia = @{} + $Session.InventoryArgs
        $ia['NoProgress'] = $false
        $ia['ProgressCallback'] = $cb
        $a = @{ InventoryArgs = $ia }
        $Session.DiagCalls++
        $res = $null
        if ($null -ne $script:AtmGuiDiagnoseSource) { $res = & $script:AtmGuiDiagnoseSource $a } else { $res = Invoke-AtmDiagnose @a }
        # The engine records a failed inventory phase in its coverage and goes on: a cancel is known by the flag.
        if ($Session.DiagCancelRequested) { $Session.DiagCancelled++; return 'CANCELLED' }
        # The schema view: what the export may show, parsed back in memory (the TUI's path; nothing is written).
        $view = (ConvertTo-AtmDiagnoseJson -Result $res) | ConvertFrom-Json
        $Session.Diag = New-AtmGuiDiagState -View $view
        return 'OK'
    } catch {
        if ($Session.DiagCancelRequested) { $Session.DiagCancelled++; return 'CANCELLED' }
        $code = ConvertTo-AtmExceptionCode $_.Exception.GetType().Name
        if ($null -ne $Session.Diag -and $null -ne $Session.Diag.View) { $Session.Diag.Stale = $true; $Session.Diag.Error = $code }
        else { $Session.Diag = @{ View = $null; Index = $null; Gates = @(); Stale = $false; Error = $code } }
        $Session.DiagFailures++
        return 'FAILED'
    } finally {
        $Session.DiagBusy = $false
        $Session.DiagPercent = -1
    }
}

function Invoke-AtmGuiPreview {
    # The preview of the clean engine over the session's inventory, as the TUI computes it: once, when P or 8 is first
    # opened after an audit; the session keeps the rows until the next successful audit discards them. One blocking
    # call on the calling (UI) thread, with no progress (the limit ADR-0014 section 5 declares). -OnStart runs just
    # before the call, only when the call happens (the form disables its controls and shows a fixed text). Returns:
    #  OK        the rows are kept;
    #  CACHED    the rows of this audit are kept already: no call;
    #  NO_AUDIT  no audit has finished: no call;
    #  IGNORED   an audit or a preview runs: no call;
    #  FAILED    nothing is kept but the exception type (never its message); the next opening tries again.
    param([hashtable]$Session, [scriptblock]$OnStart)
    if ($Session.Busy -or $Session.PreviewBusy -or $Session.DiagBusy) { return 'IGNORED' }
    if ($null -eq $Session.Inventory) { return 'NO_AUDIT' }
    if ($null -ne $Session.Preview) { return 'CACHED' }
    $Session.PreviewBusy = $true
    try {
        if ($null -ne $OnStart) { & $OnStart }
        $Session.PreviewCalls++
        $rows = @(if ($null -ne $script:AtmGuiPreviewSource) { & $script:AtmGuiPreviewSource $Session.Inventory $Session.InventoryArgs } else { Invoke-AtmPreview -Inventory $Session.Inventory -InventoryArgs $Session.InventoryArgs })
        $Session.Preview = $rows
        $Session.PreviewFailureType = $null
        return 'OK'
    } catch {
        $Session.Preview = $null
        $Session.PreviewFailureType = $_.Exception.GetType().Name
        $Session.PreviewFailures++
        return 'FAILED'
    } finally {
        $Session.PreviewBusy = $false
    }
}

function Invoke-AtmGuiRecover {
    # V0.4 R5: the only place the GUI collects for the recovery area, on the explicit action of opening it (S or its
    # button), never from the live monitoring's ticker. One blocking call on the calling (UI) thread, with no progress (as
    # the preview): a fresh, read-only collection of the recovery engine with its own deadline, then its list. -OnStart
    # runs just before the call, only when the call happens. Returns:
    #  OK       the session keeps the new collection and its list (each opening collects again);
    #  IGNORED  an audit, the preview or the diagnose runs: no call;
    #  FAILED   nothing is kept but the exception code (never its message); nothing is shown.
    # Nothing is asked, locked, logged, started or elevated here: executing stays in the CLI.
    param([hashtable]$Session, [scriptblock]$OnStart)
    if ($Session.Busy -or $Session.PreviewBusy -or $Session.DiagBusy) { return 'IGNORED' }
    try {
        if ($null -ne $OnStart) { & $OnStart }
        $Session.RecoverCalls++
        $coll = $null
        if ($null -ne $script:AtmGuiRecoverSource) { $coll = & $script:AtmGuiRecoverSource } else { $coll = Get-AtmRecoverCollection }
        $Session.Recover = @{ Collection = $coll; List = (Get-AtmRecoverList -Collection $coll); Error = $null }
        return 'OK'
    } catch {
        $Session.Recover = @{ Collection = $null; List = $null; Error = (ConvertTo-AtmExceptionCode $_.Exception.GetBaseException().GetType().Name) }
        $Session.RecoverFailures++
        return 'FAILED'
    }
}

function Invoke-AtmGuiRefresh {
    # One audit (GUI-D9), on the calling (UI) thread. -Pump is called at each progress callback of the inventory: the
    # form shows the percentage and handles its messages there. Returns:
    #  OK         the result replaces the earlier one;
    #  IGNORED    an audit already runs (a request during it is dropped, never queued);
    #  CANCELLED  a close request, honoured at the next callback; the earlier result stays;
    #  FAILED     the earlier result stays, and only the exception code of its type is kept (never its message; P5: the
    #             code, as the diagnose keeps it, ConvertTo-AtmExceptionCode).
    param([hashtable]$Session, [scriptblock]$Pump)
    if ($Session.Busy -or $Session.PreviewBusy -or $Session.DiagBusy) { $Session.Ignored++; return 'IGNORED' }
    $Session.Busy = $true
    $Session.CancelRequested = $false
    $Session.Percent = 0
    # Read by the callback through dynamic scoping (gui-prefixed names; no closure, which could not see the functions).
    $guiRefreshSession = $Session
    $guiRefreshPump = $Pump
    $cb = {
        param($pct, $msg)
        # The engine's progress message names temporary bases: never shown (ADR-0014 section 8).
        $null = $msg
        if ($guiRefreshSession.CancelRequested) { throw 'ATM_GUI_REFRESH_CANCELLED' }
        $guiRefreshSession.Percent = [int]$pct
        if ($null -ne $guiRefreshPump) { & $guiRefreshPump }
        if ($guiRefreshSession.CancelRequested) { throw 'ATM_GUI_REFRESH_CANCELLED' }
    }
    try {
        $a = @{} + $Session.InventoryArgs
        $a['ProgressCallback'] = $cb
        $a['NoProgress'] = $false
        $Session.SourceCalls++
        $inv = $(if ($null -ne $script:AtmGuiInventorySource) { & $script:AtmGuiInventorySource $a } else { Invoke-AtmInventory @a })
        if ($Session.CancelRequested) { $Session.Cancelled++; return 'CANCELLED' }
        $Session.Inventory = $inv
        # P4a: the kept preview belonged to the earlier result (a failed or cancelled audit keeps both).
        $Session.Preview = $null
        $Session.PreviewFailureType = $null
        $Session.FailureType = $null
        $Session.RefreshedUtc = Get-AtmGuiNow
        $Session.Refreshes++
        return 'OK'
    } catch {
        # A cancel is known by the session's flag, never by the exception's text.
        if ($Session.CancelRequested) { $Session.Cancelled++; return 'CANCELLED' }
        $Session.FailureType = ConvertTo-AtmExceptionCode $_.Exception.GetType().Name
        $Session.Failures++
        return 'FAILED'
    } finally {
        $Session.Busy = $false
        $Session.Percent = -1
    }
}

function New-AtmGuiLabel {
    # -AccessibleName: the name a screen reader reads when it differs from the text (P6: every control has one, from the
    # catalog; a label that starts empty is named here).
    param([string]$Text, [int]$TabIndex, [string]$Name, [string]$AccessibleName)
    $l = New-Object -TypeName System.Windows.Forms.Label
    $l.Text = $Text
    $l.AutoSize = $true
    $l.AccessibleName = $(if ($AccessibleName) { $AccessibleName } else { $Text })
    $l.TabIndex = $TabIndex
    if ($Name) { $l.Name = $Name }
    $l.Margin = New-Object -TypeName System.Windows.Forms.Padding -ArgumentList 8
    return $l
}

function New-AtmGuiListView {
    # A read-only list (ADR-0014 section 8): details view, no label editing, no check boxes. -Columns: pairs of header
    # text and width. P6: -Width, -Height and the column widths are pixels at 96 DPI, scaled to -Dpi (Get-AtmGuiScaled).
    param([string]$Name, [string]$AccessibleName, [object[]]$Columns, [int]$Width, [int]$Height, [int]$TabIndex, [int]$Dpi)
    $v = New-Object -TypeName System.Windows.Forms.ListView
    $v.Name = $Name
    $v.AccessibleName = $AccessibleName
    $v.View = [System.Windows.Forms.View]::Details
    $v.LabelEdit = $false
    $v.CheckBoxes = $false
    $v.MultiSelect = $false
    $v.FullRowSelect = $true
    $v.HeaderStyle = [System.Windows.Forms.ColumnHeaderStyle]::Nonclickable
    $v.Size = New-Object -TypeName System.Drawing.Size -ArgumentList (Get-AtmGuiScaled -Pixels $Width -Dpi $Dpi), (Get-AtmGuiScaled -Pixels $Height -Dpi $Dpi)
    $v.TabIndex = $TabIndex
    $v.Margin = New-Object -TypeName System.Windows.Forms.Padding -ArgumentList 8
    foreach ($c in $Columns) { $null = $v.Columns.Add([string]$c[0], (Get-AtmGuiScaled -Pixels ([int]$c[1]) -Dpi $Dpi)) }
    return $v
}

function Show-AtmGuiMonitor {
    # The state line of the view and the live monitoring's status line (P5), without the lists: a skipped tick changes
    # only these (the age of the view). Returns the state of the view.
    param($Form, [hashtable]$Session)
    $state = Get-AtmGuiViewState -Inventory $Session.Inventory -FailureType $Session.FailureType -RefreshedUtc $Session.RefreshedUtc -StaleReason $Session.StaleReason -DurationSeconds $Session.LastDurationSeconds
    $stateLine = $Form.Controls.Find('StateLine', $true)[0]
    $stateLine.Text = $state.Text
    $stateLine.AccessibleName = $state.Text
    $status = $Form.Controls.Find('MonitorStatus', $true)[0]
    $status.Text = Get-AtmGuiMonitorStatus -Monitor ([bool]$Session.Monitor) -IntervalSeconds ([int]$Session.IntervalSeconds) -NextDueUtc $Session.NextDueUtc -Backoff ([bool]$Session.Backoff)
    $status.AccessibleName = $status.Text
    return $state
}

function Show-AtmGuiView {
    # Puts the session's result on the form's read-only controls (found by name). Returns the state of the view.
    param($Form, [hashtable]$Session)
    $state = Show-AtmGuiMonitor -Form $Form -Session $Session
    $dash = Get-AtmGuiDashboard -Inventory $Session.Inventory
    $summary = $Form.Controls.Find('Summary', $true)[0]
    $summary.BeginUpdate()
    $summary.Items.Clear()
    foreach ($g in $dash.Groups) {
        foreach ($it in $g.Items) {
            $row = New-Object -TypeName System.Windows.Forms.ListViewItem -ArgumentList ([string]$g.Title)
            $null = $row.SubItems.Add([string]$it.Text)
            $null = $summary.Items.Add($row)
        }
    }
    $summary.EndUpdate()
    $classes = $Form.Controls.Find('Classes', $true)[0]
    $classes.BeginUpdate()
    $classes.Items.Clear()
    foreach ($c in $dash.Classes) {
        $row = New-Object -TypeName System.Windows.Forms.ListViewItem -ArgumentList ([string]$c.Class)
        $null = $row.SubItems.Add(('{0}' -f $c.Roots))
        $null = $row.SubItems.Add(('{0}' -f $c.MB))
        $null = $classes.Items.Add($row)
    }
    $classes.EndUpdate()
    $time = $Form.Controls.Find('AuditTime', $true)[0]
    $time.Text = $dash.AuditTime
    $time.AccessibleName = $dash.AuditTime
    $null = Show-AtmGuiScreen -Form $Form -Session $Session
    return $state
}

function Show-AtmGuiScreen {
    # Puts the current screen of the navigation on the form: the dashboard's controls, or the screen's read-only list
    # (the rows of a table; the field and value pairs of a detail, then its lines; the lines of coverage and errors). The
    # class is written in its column: nothing is told by color alone. Returns the screen.
    param($Form, [hashtable]$Session)
    $nav = $Session.Nav
    $top = Get-AtmGuiNavTop -Nav $nav
    $vm = Get-AtmGuiScreen -Inventory $Session.Inventory -Screen $top -Preview $Session.Preview -PreviewFailure $Session.PreviewFailureType -Diag $Session.Diag
    $isDash = ($vm.Kind -ceq 'dashboard')
    # P4b: the lines the TUI draws above a diagnose table (last run, outdated, the no-authorization line, the legend, the
    # coverage note, the lines of the V0.2 gates) and the text of an empty one; U only inside the area.
    $diagText = New-Object System.Collections.Generic.List[string]
    foreach ($ln in @($vm.Pre)) { $diagText.Add([string]$ln) }
    if ($vm.Empty) { $diagText.Add([string]$vm.Empty) }
    $diagLines = $Form.Controls.Find('DiagLines', $true)[0]
    $diagLines.Visible = ($diagText.Count -gt 0)
    $diagLines.Text = ($diagText.ToArray() -join [Environment]::NewLine)
    $diagLines.AccessibleName = $(if ($diagText.Count -gt 0) { $diagLines.Text } else { Get-AtmText 'gui.diagLinesName' })
    $Form.Controls.Find('DiagRefresh', $true)[0].Enabled = (@(Get-AtmGuiDiagScreenNames) -ccontains [string]$top.Name)
    foreach ($n in @('Summary', 'ClassesTitle', 'Classes', 'OrphanInfo', 'AuditTime')) { $Form.Controls.Find($n, $true)[0].Visible = $isDash }
    $title = $Form.Controls.Find('ScreenTitle', $true)[0]
    $title.Text = Get-AtmText 'gui.screenTitle' $vm.Title
    $title.AccessibleName = $title.Text
    $msgText = $(if ($nav.Message) { [string]$nav.Message } elseif ($vm.Note) { [string]$vm.Note } else { '' })
    $msg = $Form.Controls.Find('Message', $true)[0]
    $msg.Text = $msgText
    $msg.AccessibleName = $(if ($msgText) { $msgText } else { Get-AtmText 'gui.messageName' })
    # P4a: the fixed line of the preview's screens (an evaluation only; no cleanup or isolation here).
    $notice = $Form.Controls.Find('PreviewNotice', $true)[0]
    $notice.Visible = [bool]$vm.Notice
    if ($vm.Notice) { $notice.Text = [string]$vm.Notice; $notice.AccessibleName = $notice.Text }
    $rows = $Form.Controls.Find('Rows', $true)[0]
    $rows.BeginUpdate()
    $rows.Items.Clear()
    $rows.Columns.Clear()
    if (-not $isDash) {
        $cols = @($vm.Columns)
        $widths = @(if ($vm.Kind -ceq 'pairs') { 260, 640 } elseif ($vm.Kind -ceq 'lines') { 900 })
        # P6: the widths are pixels at 96 DPI, scaled to the window's DPI.
        for ($i = 0; $i -lt $cols.Count; $i++) { $null = $rows.Columns.Add([string]$cols[$i], (Get-AtmGuiScaled -Pixels $(if ($i -lt $widths.Count) { [int]$widths[$i] } else { 150 }) -Dpi ([int]$Session.Dpi))) }
        if ($vm.Kind -ceq 'table') {
            foreach ($r in @($vm.Rows)) {
                $cells = @($r)
                $row = New-Object -TypeName System.Windows.Forms.ListViewItem -ArgumentList ([string]$cells[0])
                for ($i = 1; $i -lt $cells.Count; $i++) { $null = $row.SubItems.Add([string]$cells[$i]) }
                $null = $rows.Items.Add($row)
            }
        } elseif ($vm.Kind -ceq 'pairs') {
            foreach ($pr in @($vm.Pairs)) {
                $row = New-Object -TypeName System.Windows.Forms.ListViewItem -ArgumentList ([string]$pr.Label)
                $null = $row.SubItems.Add([string]$pr.Value)
                $null = $rows.Items.Add($row)
            }
            # The lines after the fields (evidence, references, samples) in the value column, whole.
            foreach ($ln in @($vm.Lines)) {
                $row = New-Object -TypeName System.Windows.Forms.ListViewItem -ArgumentList ''
                $null = $row.SubItems.Add([string]$ln)
                $null = $rows.Items.Add($row)
            }
        } else {
            foreach ($ln in @($vm.Lines)) { $null = $rows.Items.Add((New-Object -TypeName System.Windows.Forms.ListViewItem -ArgumentList ([string]$ln))) }
        }
    }
    $rows.EndUpdate()
    $rows.AccessibleName = Get-AtmText 'gui.rowsName' $vm.Title
    $rows.Visible = (-not $isDash)
    if ($vm.Kind -ceq 'table' -and $rows.Items.Count -gt 0) {
        $sel = [math]::Max(0, [math]::Min([int]$top.Sel, $rows.Items.Count - 1))
        $rows.Items[$sel].Selected = $true
        $rows.Items[$sel].Focused = $true
        $rows.EnsureVisible($sel)
    }
    return $vm
}

function Start-AtmGui {
    # The window: modal and read-only, closed by its button, the window's close box or Esc on the dashboard. It audits
    # once when shown, then again only on Refresh, F5 or a due tick of the live monitoring (P5, off when the window opens).
    # Returns what was shown and released. -IdentitySource: test override of the identity read. -OnShown: test hook,
    # called with the form after the first audit, and with the handles the suite drives the live monitoring with (the
    # ticker, its handler and the session); the real-window cases of the suite act and close the window there.
    param([scriptblock]$IdentitySource, [scriptblock]$OnShown)
    $header = Get-AtmGuiIdentityHeader -Source $IdentitySource
    # Read by the event handlers through dynamic scoping while the window is shown (gui-prefixed names).
    $guiSession = Initialize-AtmGuiSession
    $guiSummary = [ordered]@{ Shown = $false; Closed = $false; Disposed = $false; Title = $header.Title; Lines = @($header.IdentityLine, $header.ElevationLine, $header.LanguageLine, $header.ReadOnlyLine); State = 'UNKNOWN'; Refreshes = 0; Failures = 0; Cancelled = 0; Ignored = 0; Ticks = 0; TickRuns = 0; TickerReleased = $false }
    $guiOnShown = $OnShown
    $guiTicker = $null
    $form = New-Object -TypeName System.Windows.Forms.Form
    $guiForm = $form
    try {
        $form.Text = $header.Title
        $form.AccessibleName = $header.Title
        $form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi
        $form.AutoSize = $true
        $form.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
        $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
        $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
        $form.MaximizeBox = $false
        $form.MinimizeBox = $false
        # F5 reaches the form first, whichever control has the focus.
        $form.KeyPreview = $true
        # P6: the fixed widths below are pixels at 96 DPI, scaled once to the DPI of this form (Get-AtmGuiScaled).
        $guiSession.Dpi = Get-AtmGuiDpi -Form $form
        $dpi = [int]$guiSession.Dpi
        $layout = New-Object -TypeName System.Windows.Forms.FlowLayoutPanel
        $layout.Name = 'Layout'
        $layout.AccessibleName = Get-AtmText 'gui.layoutName'
        $layout.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
        $layout.AutoSize = $true
        $layout.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
        $layout.WrapContents = $false
        $layout.Padding = New-Object -TypeName System.Windows.Forms.Padding -ArgumentList 8
        $tab = 0
        # The header, on the window's only screen (ADR-0014 section 6): identity, elevation, language, the view's state.
        $layout.Controls.Add((New-AtmGuiLabel -Text $header.IdentityLine -TabIndex ($tab++) -Name 'IdentityLine'))
        $layout.Controls.Add((New-AtmGuiLabel -Text $header.ElevationLine -TabIndex ($tab++) -Name 'ElevationLine'))
        $layout.Controls.Add((New-AtmGuiLabel -Text $header.LanguageLine -TabIndex ($tab++) -Name 'LanguageLine'))
        $layout.Controls.Add((New-AtmGuiLabel -Text (Get-AtmGuiViewState).Text -TabIndex ($tab++) -Name 'StateLine'))
        # GUI-D1: the automatic purge notice under the header while the policy of this copy has it on.
        foreach ($nl in @($guiSession.AutoPurgeNotice)) { $layout.Controls.Add((New-AtmGuiLabel -Text $nl -TabIndex ($tab++) -Name 'AutoPurgeNotice')) }
        $layout.Controls.Add((New-AtmGuiLabel -Text $header.ReadOnlyLine -TabIndex ($tab++) -Name 'ReadOnlyLine'))
        $guiProgress = New-AtmGuiLabel -Text '' -TabIndex ($tab++) -Name 'Progress'
        $guiProgress.AccessibleName = Get-AtmText 'gui.progressName'
        $layout.Controls.Add($guiProgress)
        # P5: the live monitoring (GUI-D2): a check box, off when the window opens; the interval, a fixed list that cannot
        # be edited (60 s by default); and its status line. Nothing of it is remembered. P6: under the header and the
        # view's state, before the screens, in the visual order and in the tab order.
        $guiMonitorPanel = New-Object -TypeName System.Windows.Forms.FlowLayoutPanel
        $guiMonitorPanel.Name = 'MonitorPanel'
        $guiMonitorPanel.AccessibleName = Get-AtmText 'gui.monitorPanelName'
        $guiMonitorPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
        $guiMonitorPanel.AutoSize = $true
        $guiMonitorPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
        $guiMonitorPanel.TabIndex = ($tab++)
        $guiMonitor = New-Object -TypeName System.Windows.Forms.CheckBox
        $guiMonitor.Name = 'Monitor'
        $guiMonitor.Text = Get-AtmText 'gui.monitor.check'
        $guiMonitor.AccessibleName = ($guiMonitor.Text -replace '&', '')
        $guiMonitor.Checked = $false
        $guiMonitor.AutoSize = $true
        $guiMonitor.TabIndex = 0
        $guiMonitor.Margin = New-Object -TypeName System.Windows.Forms.Padding -ArgumentList 8
        $guiIntervalLabel = New-AtmGuiLabel -Text (Get-AtmText 'gui.monitor.intervalLabel') -TabIndex 1 -Name 'MonitorIntervalLabel'
        $guiIntervalLabel.AccessibleName = ($guiIntervalLabel.Text -replace '&', '')
        $guiInterval = New-Object -TypeName System.Windows.Forms.ComboBox
        $guiInterval.Name = 'MonitorInterval'
        $guiInterval.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
        $guiInterval.AccessibleName = Get-AtmText 'gui.monitor.intervalName'
        $guiInterval.TabIndex = 2
        $guiInterval.Width = Get-AtmGuiScaled -Pixels 110 -Dpi $dpi
        $guiInterval.Margin = New-Object -TypeName System.Windows.Forms.Padding -ArgumentList 8
        foreach ($sec in @(Get-AtmGuiMonitorIntervals)) { $null = $guiInterval.Items.Add((Format-AtmGuiInterval -Seconds $sec)) }
        $guiInterval.SelectedIndex = [array]::IndexOf(@(Get-AtmGuiMonitorIntervals), [int]$guiSession.IntervalSeconds)
        $guiMonitorStatus = New-AtmGuiLabel -Text (Get-AtmText 'gui.monitor.off') -TabIndex 3 -Name 'MonitorStatus'
        $guiMonitorPanel.Controls.Add($guiMonitor)
        $guiMonitorPanel.Controls.Add($guiIntervalLabel)
        $guiMonitorPanel.Controls.Add($guiInterval)
        $guiMonitorPanel.Controls.Add($guiMonitorStatus)
        $layout.Controls.Add($guiMonitorPanel)
        # P3: the screens, each with a visible button (access key: its digit) and the TUI's key; the screen's title and
        # the message of the last move.
        $layout.Controls.Add((New-AtmGuiLabel -Text (Get-AtmText 'gui.navHint') -TabIndex ($tab++) -Name 'NavHint'))
        $layout.Controls.Add((New-AtmGuiLabel -Text (Get-AtmText 'gui.navHintPreview') -TabIndex ($tab++) -Name 'NavHintPreview'))
        $layout.Controls.Add((New-AtmGuiLabel -Text (Get-AtmText 'gui.navHintDiag') -TabIndex ($tab++) -Name 'NavHintDiag'))
        $guiScreens = New-Object -TypeName System.Windows.Forms.FlowLayoutPanel
        $guiScreens.Name = 'Screens'
        $guiScreens.AccessibleName = Get-AtmText 'gui.screensName'
        $guiScreens.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
        $guiScreens.AutoSize = $true
        $guiScreens.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
        $guiScreens.MaximumSize = New-Object -TypeName System.Drawing.Size -ArgumentList (Get-AtmGuiScaled -Pixels 920 -Dpi $dpi), 0
        $guiScreens.TabIndex = ($tab++)
        $btab = 0
        foreach ($m in @(Get-AtmGuiNavItemList)) {
            $b = New-Object -TypeName System.Windows.Forms.Button
            $b.Name = 'Screen' + $m.Key
            $b.Text = Get-AtmText 'gui.screenButton' $m.Key $m.Label
            $b.AccessibleName = ($b.Text -replace '&', '')
            $b.Tag = [string]$m.Key
            $b.AutoSize = $true
            $b.TabIndex = ($btab++)
            $b.add_Click({ param($src, $ev) $null = $ev; & $guiNavKey ([string]$src.Tag) })
            $guiScreens.Controls.Add($b)
        }
        # P4b: U, a new diagnose, enabled only inside the area (Show-AtmGuiScreen sets it).
        $guiDiagRefresh = New-Object -TypeName System.Windows.Forms.Button
        $guiDiagRefresh.Name = 'DiagRefresh'
        $guiDiagRefresh.Text = Get-AtmText 'gui.diagRefresh'
        $guiDiagRefresh.AccessibleName = ($guiDiagRefresh.Text -replace '&', '')
        $guiDiagRefresh.Tag = 'U'
        $guiDiagRefresh.AutoSize = $true
        $guiDiagRefresh.TabIndex = ($btab++)
        $guiDiagRefresh.Enabled = $false
        $guiDiagRefresh.add_Click({ param($src, $ev) $null = $ev; & $guiNavKey ([string]$src.Tag) })
        $guiScreens.Controls.Add($guiDiagRefresh)
        $layout.Controls.Add($guiScreens)
        $layout.Controls.Add((New-AtmGuiLabel -Text '' -TabIndex ($tab++) -Name 'ScreenTitle' -AccessibleName (Get-AtmText 'gui.screenTitleName')))
        $guiMessage = New-AtmGuiLabel -Text '' -TabIndex ($tab++) -Name 'Message'
        $guiMessage.AccessibleName = Get-AtmText 'gui.messageName'
        $layout.Controls.Add($guiMessage)
        # P4a: the fixed line of the preview's screens, shown only there.
        $guiNotice = New-AtmGuiLabel -Text (Get-AtmText 'gui.previewNotice') -TabIndex ($tab++) -Name 'PreviewNotice'
        $guiNotice.Visible = $false
        $layout.Controls.Add($guiNotice)
        # P4b: the lines above a diagnose table, shown only there.
        $guiDiagLines = New-AtmGuiLabel -Text '' -TabIndex ($tab++) -Name 'DiagLines'
        $guiDiagLines.AccessibleName = Get-AtmText 'gui.diagLinesName'
        $guiDiagLines.Visible = $false
        $layout.Controls.Add($guiDiagLines)
        $layout.Controls.Add((New-AtmGuiListView -Name 'Summary' -AccessibleName (Get-AtmText 'gui.summaryName') -Columns @(@((Get-AtmText 'gui.col.group'), 200), @((Get-AtmText 'gui.col.measure'), 340)) -Width 560 -Height 250 -TabIndex ($tab++) -Dpi $dpi))
        $layout.Controls.Add((New-AtmGuiLabel -Text (Get-AtmText 'dash.classes') -TabIndex ($tab++) -Name 'ClassesTitle'))
        $layout.Controls.Add((New-AtmGuiListView -Name 'Classes' -AccessibleName (Get-AtmText 'gui.classesName') -Columns @(@((Get-AtmText 'gui.col.class'), 220), @((Get-AtmText 'gui.col.roots'), 120), @((Get-AtmText 'gui.col.mb'), 160)) -Width 560 -Height 120 -TabIndex ($tab++) -Dpi $dpi))
        $layout.Controls.Add((New-AtmGuiLabel -Text (Get-AtmText 'dash.orphanInfo') -TabIndex ($tab++) -Name 'OrphanInfo'))
        # P6: before the first audit, the dashboard's own text for an unknown time (no literal in the window).
        $layout.Controls.Add((New-AtmGuiLabel -Text (Get-AtmGuiDashboard -Inventory $null).AuditTime -TabIndex ($tab++) -Name 'AuditTime'))
        # The read-only list of every other screen (its columns change with the screen).
        $guiRows = New-AtmGuiListView -Name 'Rows' -AccessibleName (Get-AtmText 'gui.rowsName' (Get-AtmText 'menu.dashboard')) -Columns @() -Width 920 -Height 360 -TabIndex ($tab++) -Dpi $dpi
        $guiRows.Visible = $false
        $layout.Controls.Add($guiRows)
        $buttons = New-Object -TypeName System.Windows.Forms.FlowLayoutPanel
        $buttons.Name = 'Buttons'
        $buttons.AccessibleName = Get-AtmText 'gui.buttonsName'
        $buttons.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
        $buttons.AutoSize = $true
        $buttons.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
        $buttons.TabIndex = ($tab++)
        $guiRefresh = New-Object -TypeName System.Windows.Forms.Button
        $guiRefresh.Name = 'Refresh'
        $guiRefresh.Text = Get-AtmText 'gui.refresh'
        $guiRefresh.AccessibleName = ($guiRefresh.Text -replace '&', '')
        $guiRefresh.AutoSize = $true
        $guiRefresh.TabIndex = 0
        $guiRefresh.Margin = New-Object -TypeName System.Windows.Forms.Padding -ArgumentList 8
        $close = New-Object -TypeName System.Windows.Forms.Button
        $close.Name = 'Close'
        $close.Text = Get-AtmText 'gui.close'
        $close.AccessibleName = ($close.Text -replace '&', '')
        $close.AutoSize = $true
        $close.TabIndex = 1
        $close.Margin = New-Object -TypeName System.Windows.Forms.Padding -ArgumentList 8
        # A dialog button: a click closes the modal window, with no handler of its own. Esc is not tied to it (P3): Esc
        # goes one screen back, and closes the window only on the dashboard.
        $close.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $buttons.Controls.Add($guiRefresh)
        $buttons.Controls.Add($close)
        $layout.Controls.Add($buttons)
        # The one ticker of the form (ADR-0014 section 5), created here only. It only wakes the check: its period never
        # passes the chosen interval, and Invoke-AtmGuiTick decides by the session's NextDueUtc.
        $guiTicker = New-Object -TypeName System.Windows.Forms.Timer
        $guiTicker.Interval = [int]$guiSession.IntervalSeconds * 1000
        $guiTicker.Enabled = $false
        $form.Controls.Add($layout)
        # The progress shows a percentage and a fixed text only; the window handles its messages at each callback.
        $guiPump = {
            $guiProgress.Text = Get-AtmText 'gui.progress' $guiSession.Percent
            [System.Windows.Forms.Application]::DoEvents()
        }
        $guiDoRefresh = {
            # A request while an audit runs is dropped (counted), never queued: F5 reaches the form even with the button
            # disabled.
            if ($guiSession.Busy -or $guiSession.PreviewBusy -or $guiSession.DiagBusy) { $null = Invoke-AtmGuiRefresh -Session $guiSession; return }
            $guiRefresh.Enabled = $false
            $guiScreens.Enabled = $false
            $guiProgress.Text = Get-AtmText 'gui.progress' 0
            $rr = $null
            $hadPreview = ($null -ne $guiSession.Preview -or [bool]$guiSession.PreviewFailureType)
            # P5: every audit is measured; with the monitoring on, the next tick counts from its end.
            $t0 = Get-AtmGuiNow
            try { $rr = Invoke-AtmGuiRefresh -Session $guiSession -Pump $guiPump }
            finally {
                Update-AtmGuiRefreshTiming -Session $guiSession -Result ([string]$rr) -StartUtc $t0 -EndUtc (Get-AtmGuiNow)
                & $guiRestartTicker
                $guiProgress.Text = ''
                $guiRefresh.Enabled = $true
                $guiScreens.Enabled = $true
                # P3: the current screen is computed again over the new result (a detail whose root is gone goes back).
                # P4a: a successful audit discards a kept (or failed) preview; its screens go back to the dashboard.
                # P4b: an audit keeps the diagnose result; its screens stay.
                Invoke-AtmGuiNavRefreshed -Nav $guiSession.Nav -Inventory $guiSession.Inventory -PreviewDiscarded ($rr -ceq 'OK' -and $hadPreview) -Preview $guiSession.Preview -Diag $guiSession.Diag
                $guiSummary.State = (Show-AtmGuiView -Form $guiForm -Session $guiSession).Code
            }
            # A close requested during the audit: the audit is cancelled, then the window closes.
            if ($guiSession.CloseAfterRefresh) { $guiSession.CloseAfterRefresh = $false; $guiForm.Close() }
        }
        # P5: the ticker is restarted whenever the next due time is set (turning on, a new interval, the end of an audit),
        # so a wake never falls just before that time; it runs only while the monitoring is on and the window is open.
        $guiRestartTicker = {
            if ($null -eq $guiTicker -or $guiSession.Closing) { return }
            $guiTicker.Stop()
            $guiTicker.Interval = [int]$guiSession.IntervalSeconds * 1000
            if ($guiSession.Monitor) { $guiTicker.Start() }
        }
        # P5: while a tick audits, the screens and Refresh are disabled, as for F5; the progress shows a percentage only.
        $guiTickStart = {
            $guiRefresh.Enabled = $false
            $guiScreens.Enabled = $false
            $guiProgress.Text = Get-AtmText 'gui.progress' 0
        }
        # P5: one wake of the ticker (the suite calls it directly). Invoke-AtmGuiTick decides; only a tick that ran the
        # audit gives the controls back and redraws the screen (a tick nested in a running audit, through the progress
        # pump, changes nothing else). A skipped tick updates the state and status lines only (the age of the view).
        $guiTick = {
            $tr = Invoke-AtmGuiTick -Session $guiSession -Now (Get-AtmGuiNow) -Pump $guiPump -OnStart $guiTickStart -OnPreviewStart $guiPreviewStart
            $guiSummary.Ticks = $guiSession.Ticks
            $guiSummary.TickRuns = $guiSession.TickRuns
            if ($tr -ceq 'REFRESHED' -or $tr -ceq 'FAILED' -or $tr -ceq 'CANCELLED') {
                $guiProgress.Text = ''
                $guiRefresh.Enabled = $true
                $guiScreens.Enabled = $true
                & $guiRestartTicker
                $guiSummary.State = (Show-AtmGuiView -Form $guiForm -Session $guiSession).Code
                # A close requested during the audit or the preview of this tick: the window closes now.
                if ($guiSession.CloseAfterRefresh) { $guiSession.CloseAfterRefresh = $false; $guiForm.Close() }
                elseif ($guiSession.CloseAfterPreview) { $guiSession.CloseAfterPreview = $false; $guiForm.Close() }
            } elseif (-not $guiSession.Closing) { $null = Show-AtmGuiMonitor -Form $guiForm -Session $guiSession }
            return $tr
        }
        # P3: a key or screen button moves through the screens (ignored while an audit runs); Esc on the dashboard closes.
        # P4a: while the preview runs, the screens and Refresh are disabled and the progress label shows a fixed text (no
        # percentage: the call is a single block). Painted before the call starts.
        $guiPreviewStart = {
            $guiRefresh.Enabled = $false
            $guiScreens.Enabled = $false
            $guiProgress.Text = Get-AtmText 'tui.computingPreview'
            $guiForm.Refresh()
        }
        # P4b: while the diagnose runs, the screens, U and Refresh are disabled; the progress label shows a fixed text and
        # the percentage of the inventory phase.
        $guiDiagStart = {
            $guiRefresh.Enabled = $false
            $guiScreens.Enabled = $false
            $guiProgress.Text = Get-AtmText 'tui.diag.running'
            $guiForm.Refresh()
        }
        $guiDiagProgress = {
            $guiProgress.Text = Get-AtmText 'gui.diagProgress' (Get-AtmText 'tui.diag.running') $guiSession.DiagPercent
            [System.Windows.Forms.Application]::DoEvents()
        }
        # V0.4 R5: while the recovery collection runs, the screens and Refresh are disabled and the progress label shows a
        # fixed text (no percentage: the call is a single block). Painted before the call starts.
        $guiRecoverStart = {
            $guiRefresh.Enabled = $false
            $guiScreens.Enabled = $false
            $guiProgress.Text = Get-AtmText 'rec.view.running'
            $guiForm.Refresh()
        }
        $guiNavKey = {
            param([string]$Key)
            $r = Invoke-AtmGuiNavKey -Nav $guiSession.Nav -Inventory $guiSession.Inventory -Key $Key -Busy ([bool]$guiSession.Busy -or [bool]$guiSession.PreviewBusy -or [bool]$guiSession.DiagBusy) -Preview $guiSession.Preview -Diag $guiSession.Diag
            if ($r -ceq 'DIAG_OPEN' -or $r -ceq 'DIAG_REFRESH') {
                # D or U: the session's function decides whether the diagnose runs (D: only without a result).
                $isU = ($r -ceq 'DIAG_REFRESH')
                $dr = $null
                try { $dr = Invoke-AtmGuiDiagnose -Session $guiSession -Pump $guiDiagProgress -OnStart $guiDiagStart -Refresh:$isU }
                finally {
                    $guiProgress.Text = ''
                    $guiRefresh.Enabled = $true
                    $guiScreens.Enabled = $true
                }
                if ($dr -cne 'CANCELLED') { Invoke-AtmGuiNavDiag -Nav $guiSession.Nav -Diag $guiSession.Diag -Result $dr -Refresh:$isU }
                $null = Show-AtmGuiScreen -Form $guiForm -Session $guiSession
                if ($guiRows.Visible) { $guiForm.ActiveControl = $guiRows }
                # A close requested while the diagnose ran: its result was discarded; the window closes now.
                if ($guiSession.CloseAfterDiag) { $guiSession.CloseAfterDiag = $false; $guiForm.Close() }
                return
            }
            if ($r -ceq 'RECOVER_OPEN') {
                # V0.4 R5: S or its button: the session's function collects (each opening), then the area opens.
                $rr = $null
                try { $rr = Invoke-AtmGuiRecover -Session $guiSession -OnStart $guiRecoverStart }
                finally {
                    $guiProgress.Text = ''
                    $guiRefresh.Enabled = $true
                    $guiScreens.Enabled = $true
                }
                Invoke-AtmGuiNavRecover -Nav $guiSession.Nav -Recover $guiSession.Recover -Result $rr
                $null = Show-AtmGuiScreen -Form $guiForm -Session $guiSession
                if ($guiRows.Visible) { $guiForm.ActiveControl = $guiRows }
                return
            }
            if ($r -ceq 'CLOSE') { $guiForm.Close() }
            elseif ($r -ceq 'RENDER') {
                # P4a: opening P or 8 asks for the preview; the session's function decides whether the engine is called
                # (once per audit; never before an audit).
                if ((Get-AtmGuiNavTop -Nav $guiSession.Nav).Name -ceq 'gates') {
                    try { $null = Invoke-AtmGuiPreview -Session $guiSession -OnStart $guiPreviewStart }
                    finally {
                        $guiProgress.Text = ''
                        $guiRefresh.Enabled = $true
                        $guiScreens.Enabled = $true
                    }
                }
                $null = Show-AtmGuiScreen -Form $guiForm -Session $guiSession
                if ($guiRows.Visible) { $guiForm.ActiveControl = $guiRows }
                # A close requested while the preview ran: the window closes now that the call has ended.
                if ($guiSession.CloseAfterPreview) { $guiSession.CloseAfterPreview = $false; $guiForm.Close() }
            }
        }
        $guiRefresh.add_Click({ & $guiDoRefresh })
        # P5: the check box and the interval only set the due time (Set-AtmGuiMonitor, Set-AtmGuiMonitorInterval) and
        # restart the ticker; neither audits by itself.
        $guiMonitor.add_CheckedChanged({
                Set-AtmGuiMonitor -Session $guiSession -On ([bool]$guiMonitor.Checked) -Now (Get-AtmGuiNow)
                & $guiRestartTicker
                $null = Show-AtmGuiMonitor -Form $guiForm -Session $guiSession
            })
        $guiInterval.add_SelectedIndexChanged({
                $iv = @(Get-AtmGuiMonitorIntervals)
                if ($guiInterval.SelectedIndex -ge 0 -and $guiInterval.SelectedIndex -lt $iv.Count) { $null = Set-AtmGuiMonitorInterval -Session $guiSession -Seconds ([int]$iv[$guiInterval.SelectedIndex]) -Now (Get-AtmGuiNow) }
                & $guiRestartTicker
                $null = Show-AtmGuiMonitor -Form $guiForm -Session $guiSession
            })
        $guiTicker.add_Tick({ $null = & $guiTick })
        $guiRows.add_SelectedIndexChanged({ if ($guiRows.SelectedIndices.Count -gt 0) { (Get-AtmGuiNavTop -Nav $guiSession.Nav).Sel = [int]$guiRows.SelectedIndices[0] } })
        $guiRows.add_ItemActivate({ & $guiNavKey 'Return' })
        $form.add_KeyDown({
                param($src, $ev)
                $null = $src
                if ($ev.KeyCode -eq [System.Windows.Forms.Keys]::F5) { $ev.Handled = $true; & $guiDoRefresh; return }
                # With Alt the digit is the button's access key; with Ctrl it is not a screen key.
                if ($ev.Alt -or $ev.Control) { return }
                $kn = [string]$ev.KeyCode
                # P6 (GUI-ENTER-ON-BUTTON): Enter belongs to the focused control before the lists. On a button it presses
                # the button, as Space does; on the check box or the interval it changes nothing and moves nowhere (Space
                # toggles the box). Only elsewhere (a list) does it open the selected row.
                if ($kn -ceq 'Return' -or $kn -ceq 'Enter') {
                    $ac = $guiForm.ActiveControl
                    if ($ac -is [System.Windows.Forms.Button]) {
                        $ev.Handled = $true
                        $ev.SuppressKeyPress = $true
                        if ($ac.Enabled) { $ac.PerformClick() }
                        return
                    }
                    if ($ac -eq $guiMonitor -or $ac -eq $guiInterval) {
                        $ev.Handled = $true
                        $ev.SuppressKeyPress = $true
                        return
                    }
                }
                # Keys.Return and Keys.Enter are one value; its name can be either.
                if ($kn -cmatch '^(D|NumPad)[1-9]$' -or $kn -ceq 'P' -or $kn -ceq 'D' -or $kn -ceq 'S' -or $kn -ceq 'U' -or $kn -ceq 'Return' -or $kn -ceq 'Enter' -or $kn -ceq 'Escape') {
                    $ev.Handled = $true
                    $ev.SuppressKeyPress = $true
                    & $guiNavKey $kn
                }
            })
        $form.add_FormClosing({
                param($src, $ev)
                $null = $src
                # P5: the live monitoring stops for good: nothing is due, the ticker is stopped and released, and a tick
                # that still arrives does nothing.
                $guiSession.Closing = $true
                Set-AtmGuiMonitor -Session $guiSession -On $false -Now (Get-AtmGuiNow)
                if (-not $guiSummary.TickerReleased) { $guiTicker.Stop(); $guiTicker.Dispose(); $guiSummary.TickerReleased = $true }
                if ($guiSession.Busy) { $guiSession.CancelRequested = $true; $guiSession.CloseAfterRefresh = $true; $ev.Cancel = $true }
                # P4b: the diagnose stops its inventory phase at the next callback; the window closes when the call ends.
                elseif ($guiSession.DiagBusy) { $guiSession.DiagCancelRequested = $true; $guiSession.CloseAfterDiag = $true; $ev.Cancel = $true }
                # P4a: the preview cannot be cancelled inside its call; the window closes when it ends.
                elseif ($guiSession.PreviewBusy) { $guiSession.CloseAfterPreview = $true; $ev.Cancel = $true }
            })
        $form.add_Shown({
                $guiSummary.Shown = $true
                # The first audit: opening the window is the request (as the TUI does when it starts).
                & $guiDoRefresh
                if ($null -ne $guiOnShown -and -not $guiForm.IsDisposed) { & $guiOnShown $this @{ Ticker = $guiTicker; Tick = $guiTick; Session = $guiSession } }
            })
        $null = $form.ShowDialog()
        $guiSummary.Closed = $true
    } finally {
        if ($null -ne $guiTicker -and -not $guiSummary.TickerReleased) { $guiTicker.Stop(); $guiTicker.Dispose(); $guiSummary.TickerReleased = $true }
        $form.Dispose()
        $guiSummary.Disposed = [bool]$form.IsDisposed
        $guiSummary.Refreshes = $guiSession.Refreshes
        $guiSummary.Failures = $guiSession.Failures
        $guiSummary.Cancelled = $guiSession.Cancelled
        $guiSummary.Ignored = $guiSession.Ignored
    }
    return [pscustomobject]$guiSummary
}

function Invoke-AtmGuiCommand {
    # `agent-temp gui`, after the launcher's integrity check. Returns the exit code: 0 the window opened and closed; 7
    # the release gate is closed (GUI_GATE_CLOSED); 8 this environment cannot show a window (GUI_NOT_STA,
    # GUI_NO_INTERACTIVE_DESKTOP, GUI_WINFORMS_UNAVAILABLE). Nothing is relaunched in another shell.
    param([scriptblock]$IdentitySource, [scriptblock]$OnShown)
    if (-not $script:AtmGuiEnabled) {
        Write-Host (Get-AtmText 'cli.guiGateClosed') -ForegroundColor Yellow
        return $script:AtmGuiExitGateClosed
    }
    $reason = Test-AtmGuiEnvironment
    if ($null -eq $reason) { $reason = Import-AtmGuiAssemblies }
    if ($null -ne $reason) {
        Write-Host (Get-AtmText 'cli.guiEnvRefused' $reason (Get-AtmText ('gui.env.' + $reason))) -ForegroundColor Yellow
        return $script:AtmGuiExitEnvironment
    }
    $null = Start-AtmGui -IdentitySource $IdentitySource -OnShown $OnShown
    return 0
}
