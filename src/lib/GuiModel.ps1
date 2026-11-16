# Agent Temp Manager - view models of the desktop GUI (V0.2.1, docs/adr/ADR-0014-desktop-gui-winforms.md).
#
# Rules (ADR-0014 section 3):
#  * Plain PowerShell objects, no WinForms type: all view models are testable without a window.
#  * View models call only the engine read functions of the closed list; the static test of the suite reads this
#    file and src/lib/Gui.ps1 and fails on any other command.
#  * Nothing here decides: the engines' codes are shown as they are.
#  * Loading this file defines functions only (no assembly, no type, no state).
# Phase P1: the identity header only (PRIV-10).

function Get-AtmGuiIdentityHeader {
    # The process identity and its elevation state, as `version` shows them. -Source: test override of the identity
    # read (same shape as the engine's raw identity), passed through to the engine.
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
    }
}
