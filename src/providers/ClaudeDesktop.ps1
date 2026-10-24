# AgentTempManager PROVIDER: Claude Desktop (Windows, MSIX package), contract v2 (ADR-0008), capability runtime only.
# Compatible with Windows PowerShell 5.1 and PowerShell 7.
#
# Providers only READ. They never decide eligibility and never delete.
#
# Claude Desktop has no per-session temporary directory confirmed for this tool, so the provider declares no temp
# members (no 'temp' capability). Every hint below is a published or publicly reported fact, with its source; nothing
# here is read from the installation, and no file, log, registry key or configuration of Claude Desktop is opened.
#
# Sources (checked 2026-10-24):
#  * Anthropic documentation, "Windows fleet checklist" (claude.com/docs/government/deploy-desktop/windows-checklist)
#    and "Installation and setup" (claude.com/docs/third-party/claude-desktop/installation): Cowork requires the
#    .msix package (package name Claude, package family name Claude_pzs8sxrjxfjjc, publisher Anthropic, PBC; the
#    values "do not change between versions or architectures"); the package "registers a Windows service that Cowork
#    uses" (its name is not given there); Cowork runs in a virtual machine that the app manages, needs the Virtual
#    Machine Platform feature (not the full Hyper-V role) and runs under NT VIRTUAL MACHINE\Virtual Machines; the
#    agent helper claude.exe lives under the user profile (%APPDATA%\Claude\claude-code\<version>\<build-id>\).
#  * Public reports in Anthropic's issue tracker: anthropics/claude-code#27010 (opened 2026-02-19, Claude Desktop
#    1.1.3647, Windows 10 Pro 22H2): service "Claude (CoworkVMService)", start type Manual in that version;
#    anthropics/claude-code#59035 (opened 2026-05-14, Windows 11): CoworkVMService Running/Automatic, and the VM
#    created through the Host Compute Service (HCS) as "cowork-vm-<8 hex>".
#
# What is declared, and why:
#  * Service CoworkVMService (role cowork-vm): the exact name in both reports. Not named in Anthropic's documentation,
#    so it is a reported name; a service not listed is UNKNOWN (never "not installed"), and a running service is not
#    proof that a Cowork VM runs. The legacy .exe installer has no Cowork and registers no such service.
#  * Process claude.exe with the command-line marker pzs8sxrjxfjjc: the publisher id of the package family name. An
#    MSIX package runs from a folder named after its full name (Name_Version_Architecture_ResourceId_PublisherId),
#    so an executable started from the package carries that id in its path. The marker is matched in memory against
#    the command line (never stored). The agent helper claude.exe (under the user profile, no marker) is not matched
#    here; Claude Code's own image matcher also matches claude.exe, so a process matched by both is reported as
#    attributable to both (ambiguous), never resolved by guessing.
#  * No virtualization hint: the Cowork VM is an HCS compute system with a per-installation name (cowork-vm-<hex>),
#    not a Hyper-V Manager VM, so it is not expected in Msvm_ComputerSystem and a VmName hint would depend on an
#    arbitrary individual name; no ServiceOwner relation (service -> VM worker process) is established or verifiable
#    by the collectors. vmmem, vmwp, vmcompute and HCS processes are never attributed to Claude Desktop.
#  * No version is read from the installation: the hints apply to MSIX builds since the reported 1.1.3647.

Register-AtmProvider ([pscustomobject]@{
        Id                     = 'claude-desktop'
        DisplayName            = 'Claude Desktop'
        ContractVersion        = 2
        Capabilities           = @('runtime')
        GetProcessMatchers     = { @([pscustomobject]@{ ImageName = 'claude.exe'; CommandLineMarker = 'pzs8sxrjxfjjc' }) }
        GetServiceHints        = { @([pscustomobject]@{ Name = 'CoworkVMService'; Role = 'cowork-vm' }) }
        GetVirtualizationHints = { @() }
    })
