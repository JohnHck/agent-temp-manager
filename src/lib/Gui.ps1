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

# Release gate of the desktop GUI (D-A). Closed in every distributed copy: `agent-temp gui` opens no window and loads no
# WinForms assembly. Tests open it only in their own process memory.
$script:AtmGuiEnabled = $false

# Exit codes of `agent-temp gui` (GUI-D8): 7 the release gate is closed; 8 this environment cannot show a window.
$script:AtmGuiExitGateClosed = 7
$script:AtmGuiExitEnvironment = 8

# Test seams (suite only; $null = the real source). Apartment: returns the thread's apartment state as text. Desktop:
# returns whether an interactive desktop is available. Assembly loader: loads the assemblies or throws. Inventory
# source: called with the inventory arguments (a hashtable that carries the ProgressCallback); returns an inventory or
# throws.
$script:AtmGuiApartmentSource = $null
$script:AtmGuiDesktopSource = $null
$script:AtmGuiAssemblyLoader = $null
$script:AtmGuiInventorySource = $null

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
    }
}

function Invoke-AtmGuiRefresh {
    # One audit (GUI-D9), on the calling (UI) thread. -Pump is called at each progress callback of the inventory: the
    # form shows the percentage and handles its messages there. Returns:
    #  OK         the result replaces the earlier one;
    #  IGNORED    an audit already runs (a request during it is dropped, never queued);
    #  CANCELLED  a close request, honoured at the next callback; the earlier result stays;
    #  FAILED     the earlier result stays, and only the exception type is kept (never its message).
    param([hashtable]$Session, [scriptblock]$Pump)
    if ($Session.Busy) { $Session.Ignored++; return 'IGNORED' }
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
        $Session.FailureType = $null
        $Session.RefreshedUtc = [datetime]::UtcNow
        $Session.Refreshes++
        return 'OK'
    } catch {
        # A cancel is known by the session's flag, never by the exception's text.
        if ($Session.CancelRequested) { $Session.Cancelled++; return 'CANCELLED' }
        $Session.FailureType = $_.Exception.GetType().Name
        $Session.Failures++
        return 'FAILED'
    } finally {
        $Session.Busy = $false
        $Session.Percent = -1
    }
}

function New-AtmGuiLabel {
    param([string]$Text, [int]$TabIndex, [string]$Name)
    $l = New-Object -TypeName System.Windows.Forms.Label
    $l.Text = $Text
    $l.AutoSize = $true
    $l.AccessibleName = $Text
    $l.TabIndex = $TabIndex
    if ($Name) { $l.Name = $Name }
    $l.Margin = New-Object -TypeName System.Windows.Forms.Padding -ArgumentList 8
    return $l
}

function New-AtmGuiListView {
    # A read-only list (ADR-0014 section 8): details view, no label editing, no check boxes. -Columns: pairs of header
    # text and width.
    param([string]$Name, [string]$AccessibleName, [object[]]$Columns, [int]$Width, [int]$Height, [int]$TabIndex)
    $v = New-Object -TypeName System.Windows.Forms.ListView
    $v.Name = $Name
    $v.AccessibleName = $AccessibleName
    $v.View = [System.Windows.Forms.View]::Details
    $v.LabelEdit = $false
    $v.CheckBoxes = $false
    $v.MultiSelect = $false
    $v.FullRowSelect = $true
    $v.HeaderStyle = [System.Windows.Forms.ColumnHeaderStyle]::Nonclickable
    $v.Size = New-Object -TypeName System.Drawing.Size -ArgumentList $Width, $Height
    $v.TabIndex = $TabIndex
    $v.Margin = New-Object -TypeName System.Windows.Forms.Padding -ArgumentList 8
    foreach ($c in $Columns) { $null = $v.Columns.Add([string]$c[0], [int]$c[1]) }
    return $v
}

function Show-AtmGuiView {
    # Puts the session's result on the form's read-only controls (found by name). Returns the state of the view.
    param($Form, [hashtable]$Session)
    $state = Get-AtmGuiViewState -Inventory $Session.Inventory -FailureType $Session.FailureType -RefreshedUtc $Session.RefreshedUtc
    $dash = Get-AtmGuiDashboard -Inventory $Session.Inventory
    $stateLine = $Form.Controls.Find('StateLine', $true)[0]
    $stateLine.Text = $state.Text
    $stateLine.AccessibleName = $state.Text
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
    $vm = Get-AtmGuiScreen -Inventory $Session.Inventory -Screen $top
    $isDash = ($vm.Kind -ceq 'dashboard')
    foreach ($n in @('Summary', 'ClassesTitle', 'Classes', 'OrphanInfo', 'AuditTime')) { $Form.Controls.Find($n, $true)[0].Visible = $isDash }
    $title = $Form.Controls.Find('ScreenTitle', $true)[0]
    $title.Text = Get-AtmText 'gui.screenTitle' $vm.Title
    $title.AccessibleName = $title.Text
    $msgText = $(if ($nav.Message) { [string]$nav.Message } elseif ($vm.Note) { [string]$vm.Note } else { '' })
    $msg = $Form.Controls.Find('Message', $true)[0]
    $msg.Text = $msgText
    $msg.AccessibleName = $(if ($msgText) { $msgText } else { Get-AtmText 'gui.messageName' })
    $rows = $Form.Controls.Find('Rows', $true)[0]
    $rows.BeginUpdate()
    $rows.Items.Clear()
    $rows.Columns.Clear()
    if (-not $isDash) {
        $cols = @($vm.Columns)
        $widths = $(if ($vm.Kind -ceq 'pairs') { @(260, 640) } elseif ($vm.Kind -ceq 'lines') { @(900) } else { @() })
        for ($i = 0; $i -lt $cols.Count; $i++) { $null = $rows.Columns.Add([string]$cols[$i], $(if ($i -lt $widths.Count) { [int]$widths[$i] } else { 150 })) }
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
    # once when shown, then again only on Refresh or F5. Returns what was shown and released. -IdentitySource: test override of the
    # identity read. -OnShown: test hook, called with the form after the first audit (the real-window case of the suite
    # refreshes and closes it there).
    param([scriptblock]$IdentitySource, [scriptblock]$OnShown)
    $header = Get-AtmGuiIdentityHeader -Source $IdentitySource
    # Read by the event handlers through dynamic scoping while the window is shown (gui-prefixed names).
    $guiSession = Initialize-AtmGuiSession
    $guiSummary = [ordered]@{ Shown = $false; Closed = $false; Disposed = $false; Title = $header.Title; Lines = @($header.IdentityLine, $header.ElevationLine, $header.LanguageLine, $header.ReadOnlyLine); State = 'UNKNOWN'; Refreshes = 0; Failures = 0; Cancelled = 0; Ignored = 0 }
    $guiOnShown = $OnShown
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
        $layout = New-Object -TypeName System.Windows.Forms.FlowLayoutPanel
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
        # P3: the screens, each with a visible button (access key: its digit) and the TUI's key; the screen's title and
        # the message of the last move.
        $layout.Controls.Add((New-AtmGuiLabel -Text (Get-AtmText 'gui.navHint') -TabIndex ($tab++) -Name 'NavHint'))
        $guiScreens = New-Object -TypeName System.Windows.Forms.FlowLayoutPanel
        $guiScreens.Name = 'Screens'
        $guiScreens.AccessibleName = Get-AtmText 'gui.screensName'
        $guiScreens.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
        $guiScreens.AutoSize = $true
        $guiScreens.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
        $guiScreens.MaximumSize = New-Object -TypeName System.Drawing.Size -ArgumentList 920, 0
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
        $layout.Controls.Add($guiScreens)
        $layout.Controls.Add((New-AtmGuiLabel -Text '' -TabIndex ($tab++) -Name 'ScreenTitle'))
        $guiMessage = New-AtmGuiLabel -Text '' -TabIndex ($tab++) -Name 'Message'
        $guiMessage.AccessibleName = Get-AtmText 'gui.messageName'
        $layout.Controls.Add($guiMessage)
        $layout.Controls.Add((New-AtmGuiListView -Name 'Summary' -AccessibleName (Get-AtmText 'gui.summaryName') -Columns @(@((Get-AtmText 'gui.col.group'), 200), @((Get-AtmText 'gui.col.measure'), 340)) -Width 560 -Height 250 -TabIndex ($tab++)))
        $layout.Controls.Add((New-AtmGuiLabel -Text (Get-AtmText 'dash.classes') -TabIndex ($tab++) -Name 'ClassesTitle'))
        $layout.Controls.Add((New-AtmGuiListView -Name 'Classes' -AccessibleName (Get-AtmText 'gui.classesName') -Columns @(@((Get-AtmText 'gui.col.class'), 220), @((Get-AtmText 'gui.col.roots'), 120), @((Get-AtmText 'gui.col.mb'), 160)) -Width 560 -Height 120 -TabIndex ($tab++)))
        $layout.Controls.Add((New-AtmGuiLabel -Text (Get-AtmText 'dash.orphanInfo') -TabIndex ($tab++) -Name 'OrphanInfo'))
        $layout.Controls.Add((New-AtmGuiLabel -Text '-' -TabIndex ($tab++) -Name 'AuditTime'))
        # The read-only list of every other screen (its columns change with the screen).
        $guiRows = New-AtmGuiListView -Name 'Rows' -AccessibleName (Get-AtmText 'gui.rowsName' (Get-AtmText 'menu.dashboard')) -Columns @() -Width 920 -Height 360 -TabIndex ($tab++)
        $guiRows.Visible = $false
        $layout.Controls.Add($guiRows)
        $buttons = New-Object -TypeName System.Windows.Forms.FlowLayoutPanel
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
        $form.Controls.Add($layout)
        # The progress shows a percentage and a fixed text only; the window handles its messages at each callback.
        $guiPump = {
            $guiProgress.Text = Get-AtmText 'gui.progress' $guiSession.Percent
            [System.Windows.Forms.Application]::DoEvents()
        }
        $guiDoRefresh = {
            # A request while an audit runs is dropped (counted), never queued: F5 reaches the form even with the button
            # disabled.
            if ($guiSession.Busy) { $null = Invoke-AtmGuiRefresh -Session $guiSession; return }
            $guiRefresh.Enabled = $false
            $guiScreens.Enabled = $false
            $guiProgress.Text = Get-AtmText 'gui.progress' 0
            try { $null = Invoke-AtmGuiRefresh -Session $guiSession -Pump $guiPump }
            finally {
                $guiProgress.Text = ''
                $guiRefresh.Enabled = $true
                $guiScreens.Enabled = $true
                # P3: the current screen is computed again over the new result (a detail whose root is gone goes back).
                Invoke-AtmGuiNavRefreshed -Nav $guiSession.Nav -Inventory $guiSession.Inventory
                $guiSummary.State = (Show-AtmGuiView -Form $guiForm -Session $guiSession).Code
            }
            # A close requested during the audit: the audit is cancelled, then the window closes.
            if ($guiSession.CloseAfterRefresh) { $guiSession.CloseAfterRefresh = $false; $guiForm.Close() }
        }
        # P3: a key or screen button moves through the screens (ignored while an audit runs); Esc on the dashboard closes.
        $guiNavKey = {
            param([string]$Key)
            $r = Invoke-AtmGuiNavKey -Nav $guiSession.Nav -Inventory $guiSession.Inventory -Key $Key -Busy ([bool]$guiSession.Busy)
            if ($r -ceq 'CLOSE') { $guiForm.Close() }
            elseif ($r -ceq 'RENDER') {
                $null = Show-AtmGuiScreen -Form $guiForm -Session $guiSession
                if ($guiRows.Visible) { $null = $guiRows.Focus() }
            }
        }
        $guiRefresh.add_Click({ & $guiDoRefresh })
        $guiRows.add_SelectedIndexChanged({ if ($guiRows.SelectedIndices.Count -gt 0) { (Get-AtmGuiNavTop -Nav $guiSession.Nav).Sel = [int]$guiRows.SelectedIndices[0] } })
        $guiRows.add_ItemActivate({ & $guiNavKey 'Return' })
        $form.add_KeyDown({
                param($src, $ev)
                $null = $src
                if ($ev.KeyCode -eq [System.Windows.Forms.Keys]::F5) { $ev.Handled = $true; & $guiDoRefresh; return }
                # With Alt the digit is the button's access key; with Ctrl it is not a screen key.
                if ($ev.Alt -or $ev.Control) { return }
                $kn = [string]$ev.KeyCode
                # Keys.Return and Keys.Enter are one value; its name can be either.
                if ($kn -cmatch '^(D|NumPad)[1-9]$' -or $kn -ceq 'Return' -or $kn -ceq 'Enter' -or $kn -ceq 'Escape') {
                    $ev.Handled = $true
                    $ev.SuppressKeyPress = $true
                    & $guiNavKey $kn
                }
            })
        $form.add_FormClosing({ param($src, $ev) if ($guiSession.Busy) { $guiSession.CancelRequested = $true; $guiSession.CloseAfterRefresh = $true; $ev.Cancel = $true } })
        $form.add_Shown({
                $guiSummary.Shown = $true
                # The first audit: opening the window is the request (as the TUI does when it starts).
                & $guiDoRefresh
                if ($null -ne $guiOnShown -and -not $guiForm.IsDisposed) { & $guiOnShown $this }
            })
        $null = $form.ShowDialog()
        $guiSummary.Closed = $true
    } finally {
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
