# Agent Temp Manager - desktop GUI (V0.2.1, docs/adr/ADR-0014-desktop-gui-winforms.md).
#
# Rules (ADR-0014 sections 2 to 4):
#  * Presentation only: the form reads view models (src/lib/GuiModel.ps1), and nothing here decides, deletes, moves,
#    writes a file or starts a process. The static test of the suite reads src/lib/Gui*.ps1 and fails on any command
#    outside the closed list.
#  * Loading this file defines functions and constants only: no assembly is loaded and no type is declared. WinForms is
#    loaded by Import-AtmGuiAssemblies, only past the release gate and the environment checks.
#  * Order of `agent-temp gui`, after the launcher's integrity check: the release gate, then the STA thread and the
#    interactive desktop, then the assemblies, then the window.
# Phase P1: a minimal window with the title, the identity and the elevation state (PRIV-10).

# Release gate of the desktop GUI (D-A). Closed in every distributed copy: `agent-temp gui` opens no window and loads no
# WinForms assembly. Tests open it only in their own process memory.
$script:AtmGuiEnabled = $false

# Exit codes of `agent-temp gui` (GUI-D8): 7 the release gate is closed; 8 this environment cannot show a window.
$script:AtmGuiExitGateClosed = 7
$script:AtmGuiExitEnvironment = 8

# Test seams (suite only; $null = the real source). Apartment: returns the thread's apartment state as text. Desktop:
# returns whether an interactive desktop is available. Assembly loader: loads the assemblies or throws.
$script:AtmGuiApartmentSource = $null
$script:AtmGuiDesktopSource = $null
$script:AtmGuiAssemblyLoader = $null

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

function New-AtmGuiLabel {
    param([string]$Text, [int]$TabIndex)
    $l = New-Object -TypeName System.Windows.Forms.Label
    $l.Text = $Text
    $l.AutoSize = $true
    $l.AccessibleName = $Text
    $l.TabIndex = $TabIndex
    $l.Margin = New-Object -TypeName System.Windows.Forms.Padding -ArgumentList 8
    return $l
}

function Start-AtmGui {
    # The minimal window of P1: modal, read-only, closed by its button, Esc or the window's close box. Returns what was
    # shown and released. -IdentitySource: test override of the identity read. -OnShown: test hook, called with the
    # form once it is shown (the real-window case of the suite closes it there).
    param([scriptblock]$IdentitySource, [scriptblock]$OnShown)
    $header = Get-AtmGuiIdentityHeader -Source $IdentitySource
    $guiSummary = [ordered]@{ Shown = $false; Closed = $false; Disposed = $false; Title = $header.Title; Lines = @($header.IdentityLine, $header.ElevationLine, $header.ReadOnlyLine) }
    $guiOnShown = $OnShown
    $form = New-Object -TypeName System.Windows.Forms.Form
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
        $layout = New-Object -TypeName System.Windows.Forms.FlowLayoutPanel
        $layout.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
        $layout.AutoSize = $true
        $layout.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
        $layout.WrapContents = $false
        $layout.Padding = New-Object -TypeName System.Windows.Forms.Padding -ArgumentList 8
        $layout.Controls.Add((New-AtmGuiLabel -Text $header.IdentityLine -TabIndex 0))
        $layout.Controls.Add((New-AtmGuiLabel -Text $header.ElevationLine -TabIndex 1))
        $layout.Controls.Add((New-AtmGuiLabel -Text $header.ReadOnlyLine -TabIndex 2))
        $close = New-Object -TypeName System.Windows.Forms.Button
        $close.Text = Get-AtmText 'gui.close'
        $close.AccessibleName = ($close.Text -replace '&', '')
        $close.AutoSize = $true
        $close.TabIndex = 3
        $close.Margin = New-Object -TypeName System.Windows.Forms.Padding -ArgumentList 8
        # A dialog button: a click or Esc closes the modal window, with no handler of its own.
        $close.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $layout.Controls.Add($close)
        $form.Controls.Add($layout)
        $form.CancelButton = $close
        $form.AcceptButton = $close
        $form.add_Shown({ $guiSummary.Shown = $true; if ($null -ne $guiOnShown) { & $guiOnShown $this } })
        $null = $form.ShowDialog()
        $guiSummary.Closed = $true
    } finally {
        $form.Dispose()
        $guiSummary.Disposed = [bool]$form.IsDisposed
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
