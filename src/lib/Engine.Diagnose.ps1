# AgentTempManager DIAGNOSE ENGINE (V0.2, read-only). Compatible with Windows PowerShell 5.1 and PowerShell 7.
# Evidence, coverage and findings model (docs/adr/ADR-0001) and identity / elevation state (ADR-0003).
# No terminal output: progress goes through an optional callback. Presentation lives in Report.ps1 / Tui.ps1.
#
# Safety contract (see docs/adr/ADR-0009):
#  * Diagnostics only read. They never change files, ACLs, services, processes, virtual machines or configuration,
#    and never request elevation.
#  * Unknown is never reported as absent: a state meaning "nothing depends on it" is only kept when every coverage
#    record it depends on is conclusive (COMPLETE or NOT_PRESENT); otherwise it becomes UNKNOWN (New-AtmFinding).
#  * Codes are stable and language-neutral; text comes only from the message catalog.

Set-StrictMode -Version 2.0

$script:AtmCoverageStatuses = @('COMPLETE', 'PARTIAL', 'DENIED', 'TIMEOUT', 'NOT_PRESENT', 'NOT_OBSERVABLE', 'UNAVAILABLE', 'FAILED')
$script:AtmConclusiveCoverage = @('COMPLETE', 'NOT_PRESENT')
$script:AtmElevationHelpValues = @('YES', 'NO', 'UNKNOWN')
$script:AtmFindingKinds = @('Process', 'Service', 'VirtualMachine', 'Worktree', 'Repository', 'AgentSession', 'TempPartition')
# States meaning "nothing depends on it". New-AtmFinding replaces them with UNKNOWN unless every coverage record of
# the finding is conclusive. There is no option to change this.
$script:AtmNoDependencyStates = @('NO_DEPENDENCY_OBSERVED', 'CLEAN_AND_PUBLISHED_UNKNOWN')
$script:AtmElevationTypes = @('DEFAULT', 'FULL', 'LIMITED', 'UNKNOWN')
$script:AtmIntegrityLevels = @('UNTRUSTED', 'LOW', 'MEDIUM', 'MEDIUM_PLUS', 'HIGH', 'SYSTEM', 'PROTECTED', 'UNKNOWN')
$script:AtmCodePattern = '^[A-Z][A-Z0-9_]*$'
$script:AtmIdPattern = '^[a-z][a-z0-9-]*$'
$script:AtmEvidenceDetailMax = 512

# ---------------------------------------------------------------------------------------------
# Model (ADR-0001)
# ---------------------------------------------------------------------------------------------

function New-AtmCoverage {
    # One collector's coverage. Status and reasons are codes; Observed/Expected are counts when known.
    param(
        [string]$Collector,
        [string]$Status,
        [string[]]$Reasons = @(),
        [string]$ElevationWouldHelp = 'UNKNOWN',
        $Observed = $null,
        $Expected = $null,
        $StartedUtc = $null,
        $ElapsedMs = $null,
        $BudgetMs = $null
    )
    if ($Collector -cnotmatch $script:AtmIdPattern) { throw (Get-AtmText 'err.diagCoverage' "collector '$Collector'") }
    if ($script:AtmCoverageStatuses -cnotcontains $Status) { throw (Get-AtmText 'err.diagCoverage' "status '$Status'") }
    if ($script:AtmElevationHelpValues -cnotcontains $ElevationWouldHelp) { throw (Get-AtmText 'err.diagCoverage' "elevationWouldHelp '$ElevationWouldHelp'") }
    $rs = @($Reasons | Where-Object { $_ })
    foreach ($r in $rs) { if ($r -cnotmatch $script:AtmCodePattern) { throw (Get-AtmText 'err.diagCoverage' "reason '$r'") } }
    if ($Status -ne 'COMPLETE' -and $Status -ne 'NOT_PRESENT' -and $rs.Count -eq 0) { throw (Get-AtmText 'err.diagCoverage' "status '$Status' without reason") }
    [pscustomobject]@{
        Collector          = $Collector
        Status             = $Status
        Reasons            = @($rs | Select-Object -Unique)
        ElevationWouldHelp = $ElevationWouldHelp
        Observed           = $Observed
        Expected           = $Expected
        StartedUtc         = $StartedUtc
        ElapsedMs          = $ElapsedMs
        BudgetMs           = $BudgetMs
    }
}

function New-AtmEvidence {
    # Detail is a short code-like value (a flag, a class, a count). It must never carry a command line, an
    # environment value, a token or file contents; callers pass only values they produced themselves.
    param([string]$Code, [string]$Source, [string]$Collector, $ObservedUtc = [datetime]::UtcNow, [string]$Detail)
    if ($Code -cnotmatch $script:AtmCodePattern) { throw (Get-AtmText 'err.diagEvidence' "code '$Code'") }
    if ($Source -cnotmatch $script:AtmIdPattern) { throw (Get-AtmText 'err.diagEvidence' "source '$Source'") }
    if ($Collector -cnotmatch $script:AtmIdPattern) { throw (Get-AtmText 'err.diagEvidence' "collector '$Collector'") }
    $d = $null
    if ($Detail) {
        $d = ($Detail -replace '[\x00-\x1f]', ' ')
        if ($d.Length -gt $script:AtmEvidenceDetailMax) { $d = $d.Substring(0, $script:AtmEvidenceDetailMax) }
    }
    [pscustomobject]@{ Code = $Code; Source = $Source; Collector = $Collector; ObservedUtc = ([datetime]$ObservedUtc).ToUniversalTime(); Detail = $d }
}

function New-AtmFinding {
    # A finding with its evidence and the coverage records its state depends on. A "no dependency" state is kept
    # only with conclusive coverage (ADR-0001 rule 3); otherwise State becomes UNKNOWN and RequestedState keeps
    # what the caller asked for.
    param([string]$Kind, [string]$Key, [string]$State, $Evidence = @(), $Coverage = @(), [string]$Provider)
    if ($script:AtmFindingKinds -cnotcontains $Kind) { throw (Get-AtmText 'err.diagFinding' "kind '$Kind'") }
    if ([string]::IsNullOrWhiteSpace($Key)) { throw (Get-AtmText 'err.diagFinding' 'empty key') }
    if ($State -cnotmatch $script:AtmCodePattern) { throw (Get-AtmText 'err.diagFinding' "state '$State'") }
    $ev = @($Evidence | Where-Object { $null -ne $_ })
    foreach ($e in $ev) { if (@($e.PSObject.Properties.Name) -cnotcontains 'Code') { throw (Get-AtmText 'err.diagFinding' 'evidence') } }
    $cov = @($Coverage | Where-Object { $null -ne $_ })
    foreach ($c in $cov) { if (@($c.PSObject.Properties.Name) -cnotcontains 'Status') { throw (Get-AtmText 'err.diagFinding' 'coverage') } }
    $incomplete = @($cov | Where-Object { $script:AtmConclusiveCoverage -cnotcontains $_.Status } | ForEach-Object { $_.Collector })
    $final = $State
    if ($script:AtmNoDependencyStates -ccontains $State -and ($cov.Count -eq 0 -or $incomplete.Count -gt 0)) { $final = 'UNKNOWN' }
    [pscustomobject]@{
        Kind               = $Kind
        Key                = $Key
        State              = $final
        RequestedState     = $State
        Evidence           = $ev
        Coverage           = $cov
        IncompleteCoverage = @($incomplete | Select-Object -Unique)
        Provider           = $(if ($Provider) { $Provider } else { $null })
    }
}

function ConvertTo-AtmExceptionCode {
    # Exception TYPE name as a code (EXCEPTION_UNAUTHORIZEDACCESSEXCEPTION); the message is never kept.
    param([string]$TypeName)
    $n = ($TypeName -replace '[^A-Za-z0-9]', '').ToUpperInvariant()
    if (-not $n) { $n = 'UNKNOWN' }
    return ('EXCEPTION_' + $n)
}

# ---------------------------------------------------------------------------------------------
# Identity and elevation state (ADR-0003, PRIV-10)
# ---------------------------------------------------------------------------------------------

function ConvertTo-AtmElevationType {
    param($Raw)
    switch ([int]$Raw) { 1 { return 'DEFAULT' } 2 { return 'FULL' } 3 { return 'LIMITED' } default { return 'UNKNOWN' } }
}

function ConvertTo-AtmIntegrityLevel {
    param($Rid)
    $r = [long]$Rid
    if ($r -lt 0) { return 'UNKNOWN' }
    if ($r -lt 0x1000) { return 'UNTRUSTED' }
    if ($r -lt 0x2000) { return 'LOW' }
    if ($r -lt 0x2100) { return 'MEDIUM' }
    if ($r -lt 0x3000) { return 'MEDIUM_PLUS' }
    if ($r -lt 0x4000) { return 'HIGH' }
    if ($r -lt 0x5000) { return 'SYSTEM' }
    return 'PROTECTED'
}

function Get-AtmIdentityRaw {
    # The current process token only. Get-AtmCurrentIdentity (V0.1, used by the gates) is deliberately unchanged.
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    [pscustomobject]@{
        Name             = $id.Name
        Sid              = $id.User.Value
        IsAdmin          = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        ElevationTypeRaw = [AgentTempManager.AtmToken]::GetElevationType()
        IntegrityRid     = [AgentTempManager.AtmToken]::GetIntegrityRid()
        SessionId        = [Diagnostics.Process]::GetCurrentProcess().SessionId
    }
}

function Get-AtmIdentityState {
    # -Source: test override returning the same shape as Get-AtmIdentityRaw (or throwing).
    param([scriptblock]$Source)
    $started = [datetime]::UtcNow
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $raw = $null; $err = $null
    try { $raw = $(if ($Source) { & $Source } else { Get-AtmIdentityRaw }) } catch { $err = $_.Exception.GetType().Name }
    $sw.Stop()
    if ($null -eq $raw) {
        $reasons = @('IDENTITY_UNREADABLE')
        if ($err) { $reasons += ConvertTo-AtmExceptionCode $err }
        $cov = New-AtmCoverage -Collector 'identity' -Status 'FAILED' -Reasons $reasons -StartedUtc $started -ElapsedMs $sw.ElapsedMilliseconds
        return [pscustomobject]@{ Name = $null; Sid = $null; IsElevatedAdministrator = $null; ElevationType = 'UNKNOWN'; IntegrityLevel = 'UNKNOWN'; SessionId = $null; Coverage = $cov }
    }
    $type = ConvertTo-AtmElevationType $raw.ElevationTypeRaw
    $integrity = ConvertTo-AtmIntegrityLevel $raw.IntegrityRid
    $reasons = @()
    if ($type -eq 'UNKNOWN') { $reasons += 'TOKEN_ELEVATION_TYPE_UNREADABLE' }
    if ($integrity -eq 'UNKNOWN') { $reasons += 'TOKEN_INTEGRITY_UNREADABLE' }
    $status = $(if ($reasons.Count -gt 0) { 'PARTIAL' } else { 'COMPLETE' })
    $cov = New-AtmCoverage -Collector 'identity' -Status $status -Reasons $reasons -ElevationWouldHelp 'NO' -StartedUtc $started -ElapsedMs $sw.ElapsedMilliseconds
    [pscustomobject]@{
        Name                    = [string]$raw.Name
        Sid                     = [string]$raw.Sid
        IsElevatedAdministrator = [bool]$raw.IsAdmin
        ElevationType           = $type
        IntegrityLevel          = $integrity
        SessionId               = $raw.SessionId
        Coverage                = $cov
    }
}

# ---------------------------------------------------------------------------------------------
# Provider runtime hints (contract v2, ADR-0008)
# ---------------------------------------------------------------------------------------------

$script:AtmHintMaxItems = 256
$script:AtmHintSpecs = @(
    [pscustomobject]@{ Member = 'GetProcessMatchers'; Slot = 'ProcessMatchers'; Code = 'PROCESS_MATCHERS'; Props = @('ImageName', 'CommandLineMarker') },
    [pscustomobject]@{ Member = 'GetServiceHints'; Slot = 'ServiceHints'; Code = 'SERVICE_HINTS'; Props = @('Name', 'Role') },
    [pscustomobject]@{ Member = 'GetVirtualizationHints'; Slot = 'VirtualizationHints'; Code = 'VIRTUALIZATION_HINTS'; Props = @('Kind', 'Value') }
)

function Get-AtmHintProperty {
    # Hints may be hashtables or objects; a missing property is $null (never a StrictMode error).
    param($Item, [string]$Name)
    if ($Item -is [System.Collections.IDictionary]) { if ($Item.Contains($Name)) { return $Item[$Name] } return $null }
    if (@($Item.PSObject.Properties.Name) -contains $Name) { return $Item.$Name }
    return $null
}

function Test-AtmHintText {
    param($Value, [int]$Max = 256)
    return (($Value -is [string]) -and $Value.Length -gt 0 -and $Value.Length -le $Max -and $Value -notmatch '[\x00-\x1f]')
}

function Test-AtmHintItem {
    param([string]$Slot, $Values)
    switch ($Slot) {
        'ProcessMatchers' { return ((Test-AtmHintText $Values.ImageName) -and $Values.ImageName -match '^[^\/:*?"<>|]+\.exe$' -and ($null -eq $Values.CommandLineMarker -or (Test-AtmHintText $Values.CommandLineMarker))) }
        'ServiceHints' { return ((Test-AtmHintText $Values.Name) -and $Values.Name -match '^[A-Za-z0-9_.\- ]+$' -and ($null -eq $Values.Role -or ($Values.Role -is [string] -and $Values.Role -cmatch $script:AtmIdPattern))) }
        'VirtualizationHints' { return (@('ServiceOwner', 'VmName') -ccontains $Values.Kind -and (Test-AtmHintText $Values.Value)) }
    }
    return $false
}

function Get-AtmProviderRuntimeHints {
    # Calls the parameterless runtime members of one provider with the 'runtime' capability and validates them.
    # Returns $null for a provider without that capability. An absent member means "no hints", never "nothing
    # running". A member that throws or returns anything malformed is discarded as a whole and makes the provider's
    # coverage record (provider-<id>) FAILED; valid members are kept.
    param($Provider)
    if ((Get-AtmProviderCapabilities $Provider) -cnotcontains 'runtime') { return $null }
    $names = @($Provider.PSObject.Properties.Name)
    $started = [datetime]::UtcNow
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $reasons = New-Object System.Collections.Generic.List[string]
    $slots = @{ ProcessMatchers = @(); ServiceHints = @(); VirtualizationHints = @() }
    foreach ($spec in $script:AtmHintSpecs) {
        if ($names -notcontains $spec.Member) { continue }
        $raw = $null
        try { $raw = @(& $Provider.($spec.Member)) }
        catch { $reasons.Add('HINT_FAILED_' + $spec.Code); $reasons.Add((ConvertTo-AtmExceptionCode $_.Exception.GetType().Name)); continue }
        $items = @($raw | Where-Object { $null -ne $_ })
        $valid = New-Object System.Collections.Generic.List[object]
        $ok = $items.Count -le $script:AtmHintMaxItems
        foreach ($it in $items) {
            if (-not $ok) { break }
            $v = [ordered]@{}
            foreach ($p in $spec.Props) { $v[$p] = Get-AtmHintProperty -Item $it -Name $p }
            $o = [pscustomobject]$v
            if (Test-AtmHintItem -Slot $spec.Slot -Values $o) { $valid.Add($o) } else { $ok = $false }
        }
        if ($ok) { $slots[$spec.Slot] = $valid.ToArray() } else { $reasons.Add('HINT_MALFORMED_' + $spec.Code) }
    }
    $sw.Stop()
    $status = $(if ($reasons.Count -gt 0) { 'FAILED' } else { 'COMPLETE' })
    $cov = New-AtmCoverage -Collector ('provider-' + $Provider.Id) -Status $status -Reasons $reasons.ToArray() -ElevationWouldHelp 'NO' -StartedUtc $started -ElapsedMs $sw.ElapsedMilliseconds
    [pscustomobject]@{
        ProviderId          = $Provider.Id
        ProcessMatchers     = @($slots['ProcessMatchers'])
        ServiceHints        = @($slots['ServiceHints'])
        VirtualizationHints = @($slots['VirtualizationHints'])
        Coverage            = $cov
    }
}
