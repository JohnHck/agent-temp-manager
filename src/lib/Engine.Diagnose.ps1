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
$script:AtmFindingKinds = @('Process', 'Service', 'VirtualMachine', 'VirtualizationPlatform', 'Worktree', 'Repository', 'AgentSession', 'TempPartition')
# States meaning "nothing depends on it". New-AtmFinding replaces them with UNKNOWN unless every coverage record of
# the finding is conclusive. There is no option to change this.
$script:AtmNoDependencyStates = @('NO_DEPENDENCY_OBSERVED', 'CLEAN_AND_PUBLISHED_UNKNOWN')
# States meaning "the process was looked for and is not there". Same rule: New-AtmFinding replaces them with UNKNOWN
# unless every coverage record of the finding is conclusive (a PARTIAL or failed collection never proves absence).
$script:AtmAbsenceStates = @('SESSION_PROCESS_NOT_FOUND', 'NOT_PRESENT')
# Closed list of states per finding kind (ADR-0001 rule 2). Only states with an accepted basis are listed:
# TempPartition: RUNTIME_NOT_DIAGNOSED (P1-A) and the graph states of ADR-0002; Worktree: the summary states of
# ADR-0006 rule 14; Process and AgentSession: the runtime states of P1-B4-b (Get-AtmAgentRuntimeFindings); Service:
# the state reported by the service control manager for a provider-declared name (P2-A, ADR-0005); NOT_PRESENT stays
# in the list for a future source that tells a missing service from one the account may not see, and the current
# collector never produces it (P2-A-S). The other kinds have no state yet: each later phase adds its
# own, with tests. VirtualMachine: the documented EnabledState of an observed VM (P2-B); VirtualizationPlatform (P2-B,
# ADR-0001 amendment): PRESENT on a positive sign only, NOT_PRESENT never produced (no source proves absence). UNKNOWN
# is in every list because New-AtmFinding may replace a requested state with it. No Process,
# AgentSession or Service state says anything about a temporary directory.
$script:AtmFindingStates = @{
    'Process'        = @('SELF', 'AGENT_PROCESS', 'AGENT_DESCENDANT', 'IDENTITY_UNVERIFIED', 'UNKNOWN')
    'Service'        = @('RUNNING', 'STOPPED', 'PAUSED', 'PENDING', 'NOT_PRESENT', 'UNKNOWN')
    'VirtualMachine' = @('RUNNING', 'OFF', 'SAVED', 'PAUSED', 'PENDING', 'UNKNOWN')
    'VirtualizationPlatform' = @('PRESENT', 'NOT_PRESENT', 'UNKNOWN')
    'Worktree'       = @('IN_USE', 'LOCAL_WORK', 'UNPUBLISHED_COMMITS', 'APPARENT_ORPHAN', 'CLEAN_AND_PUBLISHED_UNKNOWN', 'UNKNOWN')
    'Repository'     = @('UNKNOWN')
    'AgentSession'   = @('LIVE', 'PID_REUSED', 'IDENTITY_UNVERIFIED', 'SESSION_PROCESS_NOT_FOUND', 'UNKNOWN')
    'TempPartition'  = @('RUNTIME_NOT_DIAGNOSED', 'IN_USE', 'NO_DEPENDENCY_OBSERVED', 'UNKNOWN')
}
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
    # A conclusive status never carries a reason: a reason means something was not observed (ADR-0001).
    if (($Status -ceq 'COMPLETE' -or $Status -ceq 'NOT_PRESENT') -and $rs.Count -gt 0) { throw (Get-AtmText 'err.diagCoverage' "status '$Status' with reasons") }
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
    # A finding with its evidence and the coverage records its state depends on. A "no dependency" or an absence
    # state is kept only with conclusive coverage (ADR-0001 rule 3); otherwise State becomes UNKNOWN and
    # RequestedState keeps what the caller asked for.
    param([string]$Kind, [string]$Key, [string]$State, $Evidence = @(), $Coverage = @(), [string]$Provider)
    if ($script:AtmFindingKinds -cnotcontains $Kind) { throw (Get-AtmText 'err.diagFinding' "kind '$Kind'") }
    if ([string]::IsNullOrWhiteSpace($Key)) { throw (Get-AtmText 'err.diagFinding' 'empty key') }
    if ($State -cnotmatch $script:AtmCodePattern) { throw (Get-AtmText 'err.diagFinding' "state '$State'") }
    # The kind was checked case-sensitively above, so the (case-insensitive) table lookup cannot stand in for it.
    if (@($script:AtmFindingStates[$Kind]) -cnotcontains $State) { throw (Get-AtmText 'err.diagFinding' "state '$State' for kind '$Kind'") }
    $ev = @($Evidence | Where-Object { $null -ne $_ })
    foreach ($e in $ev) { if (@($e.PSObject.Properties.Name) -cnotcontains 'Code') { throw (Get-AtmText 'err.diagFinding' 'evidence') } }
    $cov = @($Coverage | Where-Object { $null -ne $_ })
    # A malformed coverage record is refused, never read as "incomplete" or "complete".
    foreach ($c in $cov) {
        $names = @($c.PSObject.Properties.Name)
        if ($names -cnotcontains 'Status' -or $names -cnotcontains 'Collector') { throw (Get-AtmText 'err.diagFinding' 'coverage') }
        if ($script:AtmCoverageStatuses -cnotcontains [string]$c.Status) { throw (Get-AtmText 'err.diagFinding' "coverage status '$($c.Status)'") }
        if ([string]$c.Collector -cnotmatch $script:AtmIdPattern) { throw (Get-AtmText 'err.diagFinding' "coverage collector '$($c.Collector)'") }
    }
    $incomplete = @($cov | Where-Object { $script:AtmConclusiveCoverage -cnotcontains $_.Status } | ForEach-Object { $_.Collector })
    $final = $State
    $needsConclusive = ($script:AtmNoDependencyStates -ccontains $State -or $script:AtmAbsenceStates -ccontains $State)
    if ($needsConclusive -and ($cov.Count -eq 0 -or $incomplete.Count -gt 0)) { $final = 'UNKNOWN' }
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
    Initialize-AtmNative
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

# ---------------------------------------------------------------------------------------------
# Process collection and identity (ADR-0003 rule 1, P1-B1) with resource counters (rule 6, P1-B3), used by the agent
# runtime of Invoke-AtmDiagnose (P1-B4-c). Command lines and executable paths are never requested.
# ---------------------------------------------------------------------------------------------

$script:AtmProcessIdentityProperties = @('ProcessId', 'ParentProcessId', 'Name', 'CreationDate')
# Win32_Process counter -> Resources member. Times are in 100 ns units; the others are bytes or a count. Values are
# as Win32_Process reports them (minimal and secure system processes may report 0); an unreadable value is $null.
$script:AtmProcessCounterMap = [ordered]@{
    KernelModeTime     = 'KernelTime100ns'
    UserModeTime       = 'UserTime100ns'
    WorkingSetSize     = 'WorkingSetBytes'
    PrivatePageCount   = 'PrivateBytes'
    HandleCount        = 'HandleCount'
    ReadTransferCount  = 'ReadTransferBytes'
    WriteTransferCount = 'WriteTransferBytes'
    OtherTransferCount = 'OtherTransferBytes'
}
$script:AtmProcessCimProperties = @($script:AtmProcessIdentityProperties) + @($script:AtmProcessCounterMap.Keys)
$script:AtmProcessMaxRecords = 65536
$script:AtmProcessTimeoutSec = 30
$script:AtmProcessNameMax = 260
# Same-source references compare exact ticks; another source (a session registry, Process.StartTime) states its own
# precision with -ToleranceMs, never more than this.
$script:AtmProcessToleranceMaxMs = 2000
# Resolution of Win32_Process.CreationDate (DMTF, microseconds): 10 ticks. Verified against Process.StartTime by the
# real-process test of the suite (truncation, never rounding).
$script:AtmCimCreationResolutionTicks = 10
$script:AtmProcessIdentityStatuses = @('VERIFIED', 'CREATION_TIME_UNKNOWN', 'DUPLICATE_PID')
# Results of matching a reference; not finding states. NOT_FOUND only against a COMPLETE collection.
$script:AtmProcessReferenceResults = @('MATCH', 'PID_REUSED', 'IDENTITY_UNVERIFIED', 'NOT_FOUND')

function ConvertTo-AtmProcessKey {
    # pid@creationTicksUtc. $null when the creation time is unknown: such a process has no identity.
    param([long]$ProcessId, $CreationUtc)
    if ($null -eq $CreationUtc) { return $null }
    return ('{0}@{1}' -f $ProcessId, ([datetime]$CreationUtc).ToUniversalTime().Ticks)
}

function ConvertFrom-AtmProcessKey {
    # $null for anything that is not a well-formed key.
    param([string]$Key)
    if (-not ($Key -cmatch '^(\d{1,10})@(\d{1,19})$')) { return $null }
    $p = 0L; $t = 0L
    if (-not [long]::TryParse($Matches[1], [ref]$p) -or $p -gt [uint32]::MaxValue) { return $null }
    if (-not [long]::TryParse($Matches[2], [ref]$t) -or $t -gt [datetime]::MaxValue.Ticks) { return $null }
    return [pscustomobject]@{ ProcessId = $p; CreationUtc = (New-Object DateTime($t, [DateTimeKind]::Utc)) }
}

function ConvertTo-AtmProcessId {
    # A PID is an integer from 0 to 2^32-1; anything else is $null.
    param($Value)
    if ($null -eq $Value -or $Value -is [bool]) { return $null }
    $n = 0L
    if (-not [long]::TryParse([string]$Value, [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture, [ref]$n)) { return $null }
    if ($n -gt [uint32]::MaxValue) { return $null }
    return $n
}

function ConvertTo-AtmProcessCreationUtc {
    # A [datetime] or an ISO 8601 string between 2000-01-01 and one day from now; anything else is $null.
    param($Value)
    $dt = $null
    if ($Value -is [datetime]) { $dt = $Value.ToUniversalTime() }
    elseif ($Value -is [string] -and $Value) {
        $parsed = [datetime]::MinValue
        $styles = [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal
        if ([datetime]::TryParse($Value, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) { $dt = [datetime]::SpecifyKind($parsed, [DateTimeKind]::Utc) }
    }
    if ($null -eq $dt -or $dt -lt [datetime]'2000-01-01' -or $dt -gt [datetime]::UtcNow.AddDays(1)) { return $null }
    return $dt
}

function ConvertTo-AtmProcessCounter {
    # A counter is an integer from 0 to Int64.MaxValue; anything else is $null (never 0).
    param($Value)
    if ($null -eq $Value -or $Value -is [bool]) { return $null }
    $n = 0L
    if (-not [long]::TryParse([string]$Value, [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture, [ref]$n)) { return $null }
    return $n
}

function Get-AtmProcessRaw {
    # One CIM pass, identity properties and resource counters only, bounded by the CIM operation timeout.
    param([int]$TimeoutSec)
    @(Get-CimInstance -ClassName Win32_Process -Property $script:AtmProcessCimProperties -OperationTimeoutSec $TimeoutSec -ErrorAction Stop |
        ForEach-Object {
            $row = [ordered]@{}
            foreach ($n in $script:AtmProcessCimProperties) { $row[$n] = $_.$n }
            [pscustomobject]$row
        })
}

function Get-AtmProcessCollection {
    <#
      Process collector 'process-snapshot'. -Source: test override returning rows with the properties of
      AtmProcessCimProperties (or throwing). -MaxRecords: rows beyond it are not read (PARTIAL). -TimeoutSec: CIM
      operation timeout. -Deadline: a collection not started before it is TIMEOUT. The row cap bounds the rows
      processed, and the timeout bounds the CIM operation; neither bounds the memory of the answer or the total time
      of a run.
      Every process gets IdentityStatus VERIFIED (Key = pid@creationTicksUtc), CREATION_TIME_UNKNOWN or DUPLICATE_PID
      (the same PID twice in one snapshot: the enumeration is not atomic). Only VERIFIED processes have a Key.
      An empty answer is FAILED: it never means "no processes".
      Resource counters have their own coverage record ('process-resources'), so an unreadable counter never changes
      what the identity coverage says. Timestamp: Stopwatch timestamp taken when the answer was complete (for
      CPU sampling).
    #>
    param([scriptblock]$Source, [int]$MaxRecords = $script:AtmProcessMaxRecords, [int]$TimeoutSec = $script:AtmProcessTimeoutSec, $Deadline = $null)
    if ($MaxRecords -lt 1) { throw (Get-AtmText 'err.diagProcess' "MaxRecords $MaxRecords") }
    if ($TimeoutSec -lt 1) { throw (Get-AtmText 'err.diagProcess' "TimeoutSec $TimeoutSec") }
    $collector = 'process-snapshot'
    $empty = @{ Collector = $collector; Failed = $true; CollectedUtc = $null; Timestamp = $null; Processes = @(); ByPid = @{}; Duplicates = @{} }
    if ($null -ne $Deadline -and [datetime]::UtcNow -ge $Deadline) {
        $empty.Coverage = New-AtmDeadlineCoverage $collector
        $empty.ResourceCoverage = New-AtmDeadlineCoverage 'process-resources'
        return [pscustomobject]$empty
    }
    $started = [datetime]::UtcNow
    $budgetMs = [long]$TimeoutSec * 1000
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $raw = $null; $err = $null
    try { $raw = @(if ($Source) { & $Source } else { Get-AtmProcessRaw -TimeoutSec $TimeoutSec }) } catch { $err = $_.Exception.GetType().Name }
    $sw.Stop()
    $stamp = [Diagnostics.Stopwatch]::GetTimestamp()
    $rows = @($raw | Where-Object { $null -ne $_ })
    if ($null -ne $err -or $rows.Count -eq 0) {
        # Exception type only, never its message. A failure after the whole budget is a timeout.
        if ($null -ne $err -and $sw.ElapsedMilliseconds -ge $budgetMs) { $status = 'TIMEOUT'; $reasons = @('PROCESS_SNAPSHOT_TIMEOUT', (ConvertTo-AtmExceptionCode $err)) }
        elseif ($null -ne $err) { $status = 'FAILED'; $reasons = @('PROCESS_SNAPSHOT_FAILED', (ConvertTo-AtmExceptionCode $err)) }
        else { $status = 'FAILED'; $reasons = @('PROCESS_SNAPSHOT_EMPTY') }
        $empty.Coverage = New-AtmCoverage -Collector $collector -Status $status -Reasons $reasons -StartedUtc $started -ElapsedMs $sw.ElapsedMilliseconds -BudgetMs $budgetMs
        $empty.ResourceCoverage = New-AtmCoverage -Collector 'process-resources' -Status $status -Reasons $reasons -StartedUtc $started -ElapsedMs $sw.ElapsedMilliseconds -BudgetMs $budgetMs
        return [pscustomobject]$empty
    }
    $reasons = New-Object System.Collections.Generic.List[string]
    if ($rows.Count -gt $MaxRecords) { $reasons.Add('PROCESS_LIMIT_EXCEEDED'); $rows = @($rows[0..($MaxRecords - 1)]) }
    $list = New-Object System.Collections.Generic.List[object]
    $countByPid = @{}
    $malformed = 0
    $countersRead = 0
    foreach ($r in $rows) {
        $id = ConvertTo-AtmProcessId (Get-AtmHintProperty -Item $r -Name 'ProcessId')
        if ($null -eq $id) { $malformed++; continue }
        $parentRaw = Get-AtmHintProperty -Item $r -Name 'ParentProcessId'
        $parent = ConvertTo-AtmProcessId $parentRaw
        if ($null -eq $parent) { $reasons.Add('PARENT_ID_UNREADABLE') }
        $name = Get-AtmHintProperty -Item $r -Name 'Name'
        if (-not (Test-AtmHintText -Value $name -Max $script:AtmProcessNameMax)) { $name = $null; $reasons.Add('PROCESS_NAME_UNREADABLE') }
        $created = ConvertTo-AtmProcessCreationUtc (Get-AtmHintProperty -Item $r -Name 'CreationDate')
        if ($null -eq $created) { $reasons.Add('CREATION_TIME_UNREADABLE') }
        $countByPid[$id] = 1 + $(if ($countByPid.ContainsKey($id)) { $countByPid[$id] } else { 0 })
        $res = [ordered]@{}
        $allRead = $true
        foreach ($cn in $script:AtmProcessCounterMap.Keys) {
            $v = ConvertTo-AtmProcessCounter (Get-AtmHintProperty -Item $r -Name $cn)
            if ($null -eq $v) { $allRead = $false }
            $res[$script:AtmProcessCounterMap[$cn]] = $v
        }
        if ($allRead) { $countersRead++ }
        $list.Add([pscustomobject]@{ Pid = $id; ParentPid = $parent; Name = $name; CreationUtc = $created; Key = $null; IdentityStatus = $null; Resources = [pscustomobject]$res })
    }
    if ($malformed -gt 0) { $reasons.Add('MALFORMED_PROCESS_RECORDS') }
    $byPid = @{}
    $dups = @{}
    $verified = 0
    foreach ($p in $list) {
        if ($countByPid[$p.Pid] -gt 1) { $p.IdentityStatus = 'DUPLICATE_PID'; $dups[$p.Pid] = $true; $reasons.Add('DUPLICATE_PID'); continue }
        $byPid[$p.Pid] = $p
        if ($null -eq $p.CreationUtc) { $p.IdentityStatus = 'CREATION_TIME_UNKNOWN'; continue }
        $p.IdentityStatus = 'VERIFIED'
        $p.Key = ConvertTo-AtmProcessKey -ProcessId $p.Pid -CreationUtc $p.CreationUtc
        $verified++
    }
    $status = $(if ($reasons.Count -gt 0) { 'PARTIAL' } else { 'COMPLETE' })
    # Win32_Process lists every process with its creation time for any account; elevation would not add rows.
    $help = $(if ($status -eq 'COMPLETE') { 'NO' } else { 'UNKNOWN' })
    $cov = New-AtmCoverage -Collector $collector -Status $status -Reasons $reasons.ToArray() -ElevationWouldHelp $help -Observed $verified -Expected @($raw | Where-Object { $null -ne $_ }).Count -StartedUtc $started -ElapsedMs $sw.ElapsedMilliseconds -BudgetMs $budgetMs
    # Counters: complete only when every collected process has all of them and no row was left out.
    $rr = @()
    if ($countersRead -lt $list.Count) { $rr += 'RESOURCE_COUNTERS_UNREADABLE' }
    if ($reasons -ccontains 'PROCESS_LIMIT_EXCEEDED' -or $malformed -gt 0) { $rr += 'PROCESS_ROWS_NOT_READ' }
    $rst = $(if ($rr.Count -gt 0) { 'PARTIAL' } else { 'COMPLETE' })
    $resCov = New-AtmCoverage -Collector 'process-resources' -Status $rst -Reasons $rr -ElevationWouldHelp $(if ($rst -eq 'COMPLETE') { 'NO' } else { 'UNKNOWN' }) -Observed $countersRead -Expected $list.Count -StartedUtc $started -ElapsedMs $sw.ElapsedMilliseconds -BudgetMs $budgetMs
    [pscustomobject]@{ Collector = $collector; Failed = $false; CollectedUtc = $started; Timestamp = $stamp; Processes = $list.ToArray(); ByPid = $byPid; Duplicates = $dups; Coverage = $cov; ResourceCoverage = $resCov }
}

function Resolve-AtmProcessReference {
    <#
      Matches a reference (a PID and the creation time the referrer recorded) against one collection. Returns Result
      (AtmProcessReferenceResults) and the collected Process, if any. A PID alone never identifies a process:
      without both creation times the result is IDENTITY_UNVERIFIED. NOT_FOUND only when the collection is COMPLETE;
      otherwise an absent PID is IDENTITY_UNVERIFIED (it may be among the rows that were not read).
      Default: exact ticks (same source). -CimPrecision: the reference has 100 ns precision (Process.StartTime) and
      is truncated to the CIM resolution (1 us) before an exact comparison; a collected time that is not on that
      resolution is IDENTITY_UNVERIFIED. -ToleranceMs: another source with its own precision (a session registry);
      Approximate is then $true for a MATCH that differs, and such a match never confirms SELF.
    #>
    param($Collection, $ProcessId, $CreationUtc, [int]$ToleranceMs = 0, [switch]$CimPrecision)
    if ($ToleranceMs -lt 0 -or $ToleranceMs -gt $script:AtmProcessToleranceMaxMs) { throw (Get-AtmText 'err.diagProcess' "ToleranceMs $ToleranceMs") }
    if ($CimPrecision -and $ToleranceMs -ne 0) { throw (Get-AtmText 'err.diagProcess' 'CimPrecision with ToleranceMs') }
    $result = 'IDENTITY_UNVERIFIED'; $proc = $null; $approx = $false
    $id = ConvertTo-AtmProcessId $ProcessId
    $created = ConvertTo-AtmProcessCreationUtc $CreationUtc
    if ($null -ne $id -and $null -ne $Collection -and -not $Collection.Failed) {
        if (-not $Collection.Duplicates.ContainsKey($id)) {
            if ($Collection.ByPid.ContainsKey($id)) {
                $proc = $Collection.ByPid[$id]
                if ($null -ne $created -and $proc.IdentityStatus -eq 'VERIFIED') {
                    $res = $script:AtmCimCreationResolutionTicks
                    if ($CimPrecision -and ($proc.CreationUtc.Ticks % $res) -ne 0) { $result = 'IDENTITY_UNVERIFIED' }
                    elseif ($CimPrecision) { $result = $(if (($created.Ticks - ($created.Ticks % $res)) -eq $proc.CreationUtc.Ticks) { 'MATCH' } else { 'PID_REUSED' }) }
                    else {
                        $diff = [math]::Abs(($created - $proc.CreationUtc).Ticks)
                        $result = $(if ($diff -le [long]$ToleranceMs * [TimeSpan]::TicksPerMillisecond) { 'MATCH' } else { 'PID_REUSED' })
                        $approx = ($result -ceq 'MATCH' -and $diff -ne 0)
                    }
                }
            } elseif ($Collection.Coverage.Status -ceq 'COMPLETE') { $result = 'NOT_FOUND' }
        }
    }
    [pscustomobject]@{ Result = $result; Process = $proc; Approximate = $approx }
}

# ---------------------------------------------------------------------------------------------
# Process trees, run consistency and self-exclusion (ADR-0003 rules 2-4, P1-B2), used by the agent runtime (P1-B4-c).
# ---------------------------------------------------------------------------------------------

$script:AtmParentLinkResults = @('VERIFIED', 'ROOT', 'PARENT_EXITED_OR_REUSED', 'UNVERIFIED')
$script:AtmProcessRunStates = @('PRESENT', 'EXITED_DURING_RUN', 'UNVERIFIED')
$script:AtmProcessTreeMaxMembers = 4096
$script:AtmProcessTreeMaxDepth = 256

function Get-AtmProcessParentLink {
    <#
      Link from a collected process to its parent in the same collection (ADR-0003 rule 2). ParentProcessId survives
      the parent's exit and may point to a later process with the same PID, so the link is VERIFIED only when both
      identities are verified and the parent was created no later than the child. A parent created after the child,
      or absent from a COMPLETE collection, is PARENT_EXITED_OR_REUSED: the chain stops there. Anything else that
      cannot be checked is UNVERIFIED. ROOT: the process is its own parent (the idle process).
    #>
    param($Collection, $Process)
    $result = 'UNVERIFIED'; $parent = $null
    if ($null -ne $Collection -and -not $Collection.Failed -and $null -ne $Process -and $Process.IdentityStatus -ceq 'VERIFIED' -and $null -ne $Process.ParentPid) {
        if ($Process.ParentPid -eq $Process.Pid) { $result = 'ROOT' }
        elseif ($Collection.Duplicates.ContainsKey($Process.ParentPid)) { $result = 'UNVERIFIED' }
        elseif ($Collection.ByPid.ContainsKey($Process.ParentPid)) {
            $cand = $Collection.ByPid[$Process.ParentPid]
            if ($cand.IdentityStatus -ceq 'VERIFIED') {
                if ($cand.CreationUtc -le $Process.CreationUtc) { $result = 'VERIFIED'; $parent = $cand } else { $result = 'PARENT_EXITED_OR_REUSED' }
            }
        } elseif ($Collection.Coverage.Status -ceq 'COMPLETE') { $result = 'PARENT_EXITED_OR_REUSED' }
    }
    [pscustomobject]@{ Result = $result; Parent = $parent }
}

function Get-AtmProcessTree {
    <#
      The verified descendants of one process, root first (breadth-first), by Key. A child is followed only through a
      VERIFIED parent link. Complete is $true only when the collection is COMPLETE, every process naming a member as
      parent has a decided link, and no limit was reached; otherwise Reasons says why. A process whose link to a member
      is PARENT_EXITED_OR_REUSED is not a descendant (it only reuses the PID of an exited parent).
    #>
    param($Collection, [string]$RootKey, [int]$MaxMembers = $script:AtmProcessTreeMaxMembers, [int]$MaxDepth = $script:AtmProcessTreeMaxDepth)
    if ($MaxMembers -lt 1 -or $MaxDepth -lt 1) { throw (Get-AtmText 'err.diagProcess' "MaxMembers $MaxMembers / MaxDepth $MaxDepth") }
    $reasons = New-Object System.Collections.Generic.List[string]
    $members = New-Object System.Collections.Generic.List[string]
    $root = $null
    $parsed = ConvertFrom-AtmProcessKey $RootKey
    if ($null -ne $Collection -and -not $Collection.Failed -and $null -ne $parsed -and $Collection.ByPid.ContainsKey($parsed.ProcessId)) {
        $cand = $Collection.ByPid[$parsed.ProcessId]
        if ($cand.Key -ceq $RootKey) { $root = $cand }
    }
    if ($null -eq $root) {
        return [pscustomobject]@{ RootKey = $RootKey; Members = @(); Complete = $false; Reasons = @('ROOT_NOT_VERIFIED') }
    }
    if ($Collection.Coverage.Status -cne 'COMPLETE') { $reasons.Add('COLLECTION_INCOMPLETE') }
    $children = @{}
    foreach ($p in $Collection.Processes) {
        if ($null -eq $p.ParentPid -or $p.ParentPid -eq $p.Pid) { continue }
        if (-not $children.ContainsKey($p.ParentPid)) { $children[$p.ParentPid] = New-Object System.Collections.Generic.List[object] }
        $children[$p.ParentPid].Add($p)
    }
    $seen = @{ $root.Key = $true }
    $members.Add($root.Key)
    $level = @($root)
    $depth = 0
    while ($level.Count -gt 0) {
        $next = New-Object System.Collections.Generic.List[object]
        foreach ($node in $level) {
            if (-not $children.ContainsKey($node.Pid)) { continue }
            foreach ($ch in $children[$node.Pid]) {
                $link = Get-AtmProcessParentLink -Collection $Collection -Process $ch
                if ($link.Result -ceq 'PARENT_EXITED_OR_REUSED') { continue }
                if ($link.Result -cne 'VERIFIED' -or $link.Parent.Key -cne $node.Key) { $reasons.Add('UNVERIFIED_CHILD_LINKS'); continue }
                if ($seen.ContainsKey($ch.Key)) { continue }
                if ($members.Count -ge $MaxMembers) { $reasons.Add('TREE_LIMIT_EXCEEDED'); break }
                $seen[$ch.Key] = $true
                $members.Add($ch.Key)
                $next.Add($ch)
            }
        }
        $depth++
        # Stop at MaxDepth levels below the root; it is a limit only if there was more to read.
        if ($depth -ge $MaxDepth) {
            if (@($next | Where-Object { $children.ContainsKey($_.Pid) }).Count -gt 0) { $reasons.Add('TREE_LIMIT_EXCEEDED') }
            break
        }
        $level = $next.ToArray()
    }
    [pscustomobject]@{ RootKey = $RootKey; Members = $members.ToArray(); Complete = ($reasons.Count -eq 0); Reasons = @($reasons | Select-Object -Unique) }
}

function Compare-AtmProcessCollections {
    <#
      Run consistency (ADR-0003 rule 3): for every VERIFIED process of the first collection, PRESENT when the same
      Key is in the second, EXITED_DURING_RUN when its PID is absent from a COMPLETE second collection or now has
      another verified creation time, UNVERIFIED otherwise. Returns a hashtable Key -> state.
    #>
    param($First, $Second)
    $out = @{}
    if ($null -eq $First -or $First.Failed) { return $out }
    foreach ($p in @($First.Processes | Where-Object { $_.IdentityStatus -ceq 'VERIFIED' })) {
        $r = Resolve-AtmProcessReference -Collection $Second -ProcessId $p.Pid -CreationUtc $p.CreationUtc
        $out[$p.Key] = $(switch ($r.Result) { 'MATCH' { 'PRESENT' } 'PID_REUSED' { 'EXITED_DURING_RUN' } 'NOT_FOUND' { 'EXITED_DURING_RUN' } default { 'UNVERIFIED' } })
    }
    return $out
}

function Get-AtmSelfProcessKeys {
    <#
      Keys to mark SELF (ADR-0003 rule 4): this process, every verified descendant of it (children the engine
      started) and the launcher references the caller passes (Pid and CreationUtc of the V0.1 self chain) that are
      verified ancestors of it; a launcher's other children are not ours. No tolerance is used (R-B1): this process is
      matched with -CimPrecision (its 100 ns start time truncated to the CIM resolution, then compared exactly) and
      launchers, which come from the V0.1 CIM snapshot, the same way (already on that resolution). A reference that
      cannot be verified is listed in Unverified and is NOT excluded: an unverifiable process is never hidden from the
      diagnostics.
    #>
    param($Collection, $SelfPid = $PID, $SelfCreationUtc = $null, $LauncherReferences = @())
    if ($null -eq $SelfCreationUtc) {
        # Unreadable start time: the reference stays unverified and nothing is excluded.
        try { $SelfCreationUtc = [Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime() } catch { $SelfCreationUtc = $null }
    }
    $keys = New-Object System.Collections.Generic.List[string]
    $unverified = New-Object System.Collections.Generic.List[object]
    $self = Resolve-AtmProcessReference -Collection $Collection -ProcessId $SelfPid -CreationUtc $SelfCreationUtc -CimPrecision
    if ($self.Result -cne 'MATCH') {
        $unverified.Add([pscustomobject]@{ Pid = $SelfPid; Result = $self.Result })
        return [pscustomobject]@{ Keys = @(); Unverified = $unverified.ToArray() }
    }
    # Ancestors of this process through verified links only.
    $ancestors = @{}
    $cur = $self.Process; $guard = 0
    while ($guard -lt $script:AtmProcessTreeMaxDepth) {
        $guard++
        $l = Get-AtmProcessParentLink -Collection $Collection -Process $cur
        if ($l.Result -cne 'VERIFIED') { break }
        $ancestors[$l.Parent.Key] = $true
        $cur = $l.Parent
    }
    $roots = New-Object System.Collections.Generic.List[string]
    $roots.Add($self.Process.Key)
    foreach ($ref in @($LauncherReferences | Where-Object { $null -ne $_ })) {
        $rp = Get-AtmHintProperty -Item $ref -Name 'Pid'
        $r = Resolve-AtmProcessReference -Collection $Collection -ProcessId $rp -CreationUtc (Get-AtmHintProperty -Item $ref -Name 'CreationUtc') -CimPrecision
        if ($r.Result -ceq 'MATCH' -and $ancestors.ContainsKey($r.Process.Key)) { $roots.Add($r.Process.Key) }
        elseif ($r.Result -ceq 'MATCH' -and $r.Process.Key -ceq $self.Process.Key) { continue }
        else { $unverified.Add([pscustomobject]@{ Pid = $rp; Result = $(if ($r.Result -ceq 'MATCH') { 'NOT_AN_ANCESTOR' } else { $r.Result }) }) }
    }
    # Descendants of this process only; a launcher's other children (the user's shell siblings) are not ours.
    foreach ($k in (Get-AtmProcessTree -Collection $Collection -RootKey $self.Process.Key).Members) { if (-not $keys.Contains($k)) { $keys.Add($k) } }
    foreach ($k in $roots) { if (-not $keys.Contains($k)) { $keys.Add($k) } }
    [pscustomobject]@{ Keys = $keys.ToArray(); Unverified = $unverified.ToArray() }
}

# ---------------------------------------------------------------------------------------------
# Resources: CPU sampling and per-tree sums (ADR-0003 rules 6-8, P1-B3), used by the agent runtime (P1-B4-c).
# "Disk" here is only process I/O transfer counts; space used by paths is the inventory's (rule 8).
# ---------------------------------------------------------------------------------------------

$script:AtmCpuSampleDefaultMs = 1000
$script:AtmCpuSampleMinMs = 100
$script:AtmCpuSampleMaxMs = 5000
$script:AtmTreeCounters = @('CpuTime100ns', 'KernelTime100ns', 'UserTime100ns', 'WorkingSetBytes', 'PrivateBytes', 'HandleCount', 'ReadTransferBytes', 'WriteTransferBytes', 'OtherTransferBytes')

function Get-AtmProcessCpuTime {
    # Kernel + user time in 100 ns units; $null unless both were read.
    param($Process)
    if ($null -eq $Process -or $null -eq $Process.Resources) { return $null }
    $k = $Process.Resources.KernelTime100ns; $u = $Process.Resources.UserTime100ns
    if ($null -eq $k -or $null -eq $u) { return $null }
    return ([long]$k + [long]$u)
}

function Get-AtmCollectedProcess {
    # The VERIFIED process of a collection with exactly this Key, or $null.
    param($Collection, [string]$Key)
    $parsed = ConvertFrom-AtmProcessKey $Key
    if ($null -eq $Collection -or $Collection.Failed -or $null -eq $parsed -or -not $Collection.ByPid.ContainsKey($parsed.ProcessId)) { return $null }
    $p = $Collection.ByPid[$parsed.ProcessId]
    if ($p.Key -ceq $Key) { return $p }
    return $null
}

function Measure-AtmProcessCpu {
    <#
      CPU percentage of every process present in both collections (same Key):
      delta(kernel + user) / (interval x logical processors) x 100 (ADR-0003 rule 7). The interval is the time between
      the two answers (Stopwatch); -ElapsedMs overrides it (tests). A process with an unreadable counter, a counter
      that went down or an identity that cannot be compared has $null, never 0; a process that exited between the
      samples has no percentage and is counted in Exited. Coverage record 'process-cpu'.
    #>
    param($First, $Second, [int]$LogicalProcessors = [Environment]::ProcessorCount, $ElapsedMs = $null)
    if ($LogicalProcessors -lt 1) { throw (Get-AtmText 'err.diagProcess' "LogicalProcessors $LogicalProcessors") }
    $collector = 'process-cpu'
    $byKey = @{}
    $out = @{ IntervalMs = $null; LogicalProcessors = $LogicalProcessors; ByKey = $byKey; Exited = 0 }
    if ($null -eq $First -or $null -eq $Second -or $First.Failed -or $Second.Failed) {
        $timedOut = @(@($First, $Second) | Where-Object { $null -ne $_ -and $_.Coverage.Status -ceq 'TIMEOUT' }).Count -gt 0
        $out.Coverage = $(if ($timedOut) { New-AtmCoverage -Collector $collector -Status 'TIMEOUT' -Reasons @('CPU_SAMPLE_TIMEOUT') } else { New-AtmCoverage -Collector $collector -Status 'FAILED' -Reasons @('CPU_SAMPLE_UNAVAILABLE') })
        return [pscustomobject]$out
    }
    $interval = $null
    if ($null -ne $ElapsedMs) { $interval = [double]$ElapsedMs }
    elseif ($null -ne $First.Timestamp -and $null -ne $Second.Timestamp) { $interval = ([double]($Second.Timestamp - $First.Timestamp)) * 1000 / [Diagnostics.Stopwatch]::Frequency }
    if ($null -eq $interval -or $interval -le 0) {
        $out.Coverage = New-AtmCoverage -Collector $collector -Status 'FAILED' -Reasons @('CPU_INTERVAL_INVALID')
        return [pscustomobject]$out
    }
    $out.IntervalMs = $interval
    $capacity = $interval * [TimeSpan]::TicksPerMillisecond * $LogicalProcessors
    $reasons = New-Object System.Collections.Generic.List[string]
    if ($First.Coverage.Status -cne 'COMPLETE' -or $Second.Coverage.Status -cne 'COMPLETE') { $reasons.Add('CPU_SAMPLE_INCOMPLETE') }
    $observed = 0; $expected = 0
    $states = Compare-AtmProcessCollections -First $First -Second $Second
    foreach ($key in $states.Keys) {
        $byKey[$key] = $null
        if ($states[$key] -ceq 'EXITED_DURING_RUN') { $out.Exited++; continue }
        $expected++
        if ($states[$key] -cne 'PRESENT') { $reasons.Add('CPU_SAMPLE_IDENTITY_UNVERIFIED'); continue }
        $c1 = Get-AtmProcessCpuTime (Get-AtmCollectedProcess -Collection $First -Key $key)
        $c2 = Get-AtmProcessCpuTime (Get-AtmCollectedProcess -Collection $Second -Key $key)
        if ($null -eq $c1 -or $null -eq $c2) { $reasons.Add('CPU_COUNTERS_UNREADABLE'); continue }
        if ($c2 -lt $c1) { $reasons.Add('CPU_COUNTER_DECREASED'); continue }
        $byKey[$key] = [double]($c2 - $c1) * 100 / $capacity
        $observed++
    }
    $status = $(if ($reasons.Count -gt 0) { 'PARTIAL' } else { 'COMPLETE' })
    $out.Coverage = New-AtmCoverage -Collector $collector -Status $status -Reasons $reasons.ToArray() -ElevationWouldHelp $(if ($status -eq 'COMPLETE') { 'NO' } else { 'UNKNOWN' }) -Observed $observed -Expected $expected -ElapsedMs ([long]$interval)
    return [pscustomobject]$out
}

function Invoke-AtmProcessCpuSampling {
    <#
      Two collections -IntervalMs apart (100 to 5000 ms, default 1000) and their CPU percentages. When the interval
      would end at or after -Deadline, only the first collection is taken: its cumulative CPU times stand and the CPU
      record is TIMEOUT. Waiting is the only cost: nothing is started or changed.
    #>
    param([scriptblock]$Source, [int]$IntervalMs = $script:AtmCpuSampleDefaultMs, $Deadline = $null, [int]$LogicalProcessors = [Environment]::ProcessorCount, [int]$MaxRecords = $script:AtmProcessMaxRecords, [int]$TimeoutSec = $script:AtmProcessTimeoutSec)
    if ($IntervalMs -lt $script:AtmCpuSampleMinMs -or $IntervalMs -gt $script:AtmCpuSampleMaxMs) { throw (Get-AtmText 'err.diagProcess' "IntervalMs $IntervalMs") }
    if ($LogicalProcessors -lt 1) { throw (Get-AtmText 'err.diagProcess' "LogicalProcessors $LogicalProcessors") }
    $first = Get-AtmProcessCollection -Source $Source -MaxRecords $MaxRecords -TimeoutSec $TimeoutSec -Deadline $Deadline
    if ($null -ne $Deadline -and [datetime]::UtcNow.AddMilliseconds($IntervalMs) -ge $Deadline) {
        $cpu = [pscustomobject]@{ IntervalMs = $null; LogicalProcessors = $LogicalProcessors; ByKey = @{}; Exited = 0; Coverage = (New-AtmDeadlineCoverage 'process-cpu') }
        return [pscustomobject]@{ First = $first; Second = $null; Cpu = $cpu }
    }
    $second = $null
    if (-not $first.Failed) {
        Start-Sleep -Milliseconds $IntervalMs
        $second = Get-AtmProcessCollection -Source $Source -MaxRecords $MaxRecords -TimeoutSec $TimeoutSec -Deadline $Deadline
    }
    [pscustomobject]@{ First = $first; Second = $second; Cpu = (Measure-AtmProcessCpu -First $first -Second $second -LogicalProcessors $LogicalProcessors) }
}

function Get-AtmProcessTreeResources {
    <#
      Sums over the members of one verified tree (Get-AtmProcessTree) for each counter of AtmTreeCounters and, with
      -Cpu (Measure-AtmProcessCpu), CpuPercent. For each: Sum of the values that were read ($null when none was),
      Known (members read) and Complete. Complete only when the tree is complete and every member was read, and for
      CpuPercent also only when the CPU sample is COMPLETE; otherwise Sum is a lower bound and Reasons says why. Unread
      values are never counted as 0.
    #>
    param($Collection, $Tree, $Cpu = $null)
    $reasons = New-Object System.Collections.Generic.List[string]
    $members = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Tree -or -not $Tree.Complete) { $reasons.Add('TREE_INCOMPLETE') }
    foreach ($k in @(if ($null -ne $Tree) { $Tree.Members })) {
        $p = Get-AtmCollectedProcess -Collection $Collection -Key $k
        if ($null -eq $p) { $reasons.Add('TREE_MEMBER_NOT_COLLECTED') } else { $members.Add($p) }
    }
    # A partial CPU sample makes CpuPercent incomplete even when every member has a value; the other counters come
    # from the collection itself and do not depend on it.
    $cpuConclusive = ($null -ne $Cpu -and $Cpu.Coverage.Status -ceq 'COMPLETE')
    $names = @($script:AtmTreeCounters) + @('CpuPercent')
    $counters = [ordered]@{}
    foreach ($n in $names) {
        $sum = $null; $known = 0
        foreach ($p in $members) {
            $v = $null
            if ($n -ceq 'CpuTime100ns') { $v = Get-AtmProcessCpuTime $p }
            elseif ($n -ceq 'CpuPercent') { if ($null -ne $Cpu -and $Cpu.ByKey.ContainsKey($p.Key)) { $v = $Cpu.ByKey[$p.Key] } }
            elseif ($null -ne $p.Resources) { $v = $p.Resources.$n }
            if ($null -eq $v) { continue }
            $known++
            $sum = $(if ($n -ceq 'CpuPercent') { [double]$(if ($null -eq $sum) { 0 } else { $sum }) + [double]$v } else { [long]$(if ($null -eq $sum) { 0 } else { $sum }) + [long]$v })
        }
        $complete = ($known -eq $members.Count -and $members.Count -gt 0 -and $reasons.Count -eq 0 -and ($n -cne 'CpuPercent' -or $cpuConclusive))
        $counters[$n] = [pscustomobject]@{ Sum = $sum; Known = $known; Complete = $complete }
    }
    if ($null -eq $Cpu) { $reasons.Add('CPU_NOT_SAMPLED') }
    elseif ($Cpu.Coverage.Status -cne 'COMPLETE') { $reasons.Add('CPU_SAMPLE_INCOMPLETE') }
    if (@($script:AtmTreeCounters | Where-Object { $counters[$_].Known -lt $members.Count }).Count -gt 0) { $reasons.Add('COUNTERS_UNREADABLE') }
    $all = @($counters.Values | Where-Object { -not $_.Complete }).Count -eq 0
    [pscustomobject]@{
        RootKey  = $(if ($null -ne $Tree) { $Tree.RootKey } else { $null })
        Members  = $members.Count
        Counters = [pscustomobject]$counters
        Complete = ($all -and $reasons.Count -eq 0)
        Reasons  = @($reasons | Select-Object -Unique)
    }
}

# ---------------------------------------------------------------------------------------------
# Agent runtime: sessions, agent-related processes and their trees (ADR-0003 rule 5, ADR-0008, P1-B4-b), called by
# Invoke-AtmDiagnose since P1-B4-c. Inputs are injected: a process collection (P1-B1), provider runtime hints, session
# registries, the V0.1 snapshot (command lines, in memory only), V0.1 partitions (path references) and the SELF keys.
# Command lines, markers, working directories and paths are never put in a finding, an evidence item, a coverage
# record or a result.
# ---------------------------------------------------------------------------------------------

# A session's recorded start time (100 ns) and the CIM creation time (1 us) are the same process when they are equal
# at the CIM resolution. A difference inside the V0.1 tolerance is not proof either way (IDENTITY_UNVERIFIED); beyond
# it, the PID belongs to another process (PID_REUSED).
$script:AtmSessionToleranceMs = 2000
$script:AtmUnverifiedKeyPrefix = 'pid:'
$script:AtmPathReferencePattern = '^PID (\d{1,10}) \('
# Codes the agent runtime collectors can report (besides EXCEPTION_<TYPE>); each has a text in both languages
# (reason.<code>, evidence.<code>), checked by the suite against what the collectors actually emit.
$script:AtmRuntimeReasonCodes = @(
    'DEADLINE_EXCEEDED', 'PROCESS_SNAPSHOT_TIMEOUT', 'PROCESS_SNAPSHOT_FAILED', 'PROCESS_SNAPSHOT_EMPTY', 'PROCESS_LIMIT_EXCEEDED',
    'PARENT_ID_UNREADABLE', 'PROCESS_NAME_UNREADABLE', 'CREATION_TIME_UNREADABLE', 'DUPLICATE_PID', 'MALFORMED_PROCESS_RECORDS',
    'PROCESS_SNAPSHOT_UNAVAILABLE', 'PROCESS_SNAPSHOT_INCOMPLETE', 'PROVIDER_HINTS_INCOMPLETE', 'IDENTITY_UNVERIFIED_CANDIDATES',
    'COMMAND_LINE_MARKER_UNAVAILABLE', 'SESSION_REGISTRY_INCOMPLETE', 'LEGACY_SNAPSHOT_UNAVAILABLE', 'PATH_REFERENCE_UNVERIFIED',
    'TREE_INCOMPLETE', 'NO_RUNTIME_EVIDENCE_SOURCE', 'SESSION_REGISTRY_PROVIDER_INVALID', 'SESSION_REGISTRY_FAILED',
    'SESSION_REGISTRY_UNREADABLE', 'SESSION_ENTRIES_UNPARSEABLE', 'SESSION_KEY_COLLISION', 'SESSION_ENTRIES_CONFLICT',
    'INVENTORY_UNAVAILABLE', 'AGENT_PROCESSES_INCOMPLETE', 'MEMBER_NOT_COLLECTED', 'CPU_NOT_SAMPLED', 'COUNTERS_UNREADABLE',
    'CPU_PROCESS_EXITED', 'CPU_VALUES_INCOMPLETE', 'CPU_SAMPLE_UNAVAILABLE', 'CPU_SAMPLE_TIMEOUT', 'CPU_INTERVAL_INVALID')
$script:AtmRuntimeEvidenceCodes = @(
    'PROCESS_MATCHER_IMAGE', 'PROCESS_MATCHER_MARKER', 'COMMAND_LINE_MARKER_UNAVAILABLE', 'SESSION_REGISTRY', 'SESSION_PROCESS',
    'SESSION_PROCESS_MATCH', 'PATH_REFERENCE', 'SELF_EXCLUSION', 'PARENT_LINK_VERIFIED', 'PROVIDER_ATTRIBUTION_AMBIGUOUS',
    'PROCESS_EXITED_DURING_RUN', 'SESSION_KEY_COLLISION', 'SESSION_ENTRIES_CONFLICT', 'PARTITION_KEY_COLLISION', 'SESSION_PROCESS_KEY')

function Resolve-AtmSessionProcess {
    <#
      State of one session reference (PID and the start time the session recorded) against a collection:
      LIVE                       exact identity at the CIM resolution (Resolve-AtmProcessReference -CimPrecision).
      PID_REUSED                 the PID has a verified process created more than 2 s away from the recorded time.
      IDENTITY_UNVERIFIED        the process is there but its identity cannot be proven: no recorded start time, a
                                 difference inside 2 s that is not exact, a creation time off the CIM resolution,
                                 an unknown creation time or a duplicate PID.
      SESSION_PROCESS_NOT_FOUND  the PID is absent from a COMPLETE collection.
      UNKNOWN                    no usable collection, or the PID is absent from an incomplete one.
      Reason: a code saying why. Process: the collected process, if any.
    #>
    param($Collection, $ProcessId, $StartUtc)
    $out = @{ State = 'UNKNOWN'; Reason = 'PROCESS_SNAPSHOT_UNAVAILABLE'; Process = $null }
    if ($null -eq $Collection -or $Collection.Failed) { return [pscustomobject]$out }
    $id = ConvertTo-AtmProcessId $ProcessId
    if ($null -eq $id) { $out.State = 'IDENTITY_UNVERIFIED'; $out.Reason = 'SESSION_PID_INVALID'; return [pscustomobject]$out }
    $start = ConvertTo-AtmProcessCreationUtc $StartUtc
    $present = ($Collection.ByPid.ContainsKey($id) -or $Collection.Duplicates.ContainsKey($id))
    if (-not $present) {
        if ($Collection.Coverage.Status -ceq 'COMPLETE') { $out.State = 'SESSION_PROCESS_NOT_FOUND'; $out.Reason = 'PID_NOT_IN_COMPLETE_SNAPSHOT' }
        else { $out.Reason = 'PROCESS_SNAPSHOT_INCOMPLETE' }
        return [pscustomobject]$out
    }
    $out.State = 'IDENTITY_UNVERIFIED'
    if ($Collection.Duplicates.ContainsKey($id)) { $out.Reason = 'DUPLICATE_PID'; return [pscustomobject]$out }
    $out.Process = $Collection.ByPid[$id]
    if ($out.Process.IdentityStatus -cne 'VERIFIED') { $out.Reason = 'PROCESS_CREATION_TIME_UNKNOWN'; return [pscustomobject]$out }
    if ($null -eq $start) { $out.Reason = 'SESSION_START_UNKNOWN'; return [pscustomobject]$out }
    $exact = Resolve-AtmProcessReference -Collection $Collection -ProcessId $id -CreationUtc $start -CimPrecision
    if ($exact.Result -ceq 'MATCH') { $out.State = 'LIVE'; $out.Reason = 'IDENTITY_EXACT'; return [pscustomobject]$out }
    if ($exact.Result -ceq 'IDENTITY_UNVERIFIED') { $out.Reason = 'CREATION_TIME_OFF_RESOLUTION'; return [pscustomobject]$out }
    $near = Resolve-AtmProcessReference -Collection $Collection -ProcessId $id -CreationUtc $start -ToleranceMs $script:AtmSessionToleranceMs
    if ($near.Result -ceq 'MATCH') { $out.Reason = 'CREATION_TIME_PRECISION_MISMATCH'; return [pscustomobject]$out }
    $out.State = 'PID_REUSED'; $out.Reason = 'CREATION_TIME_DIFFERS'
    return [pscustomobject]$out
}

function Get-AtmLegacyCommandLine {
    # The command line of the V0.1 snapshot process with the same PID and the same creation time (exact ticks; both
    # come from Win32_Process.CreationDate). $null when it is not there, was not readable, or the PID appears more than
    # once in the V0.1 snapshot (an ambiguous reference is never used, even when one entry has the exact ticks). Used
    # in memory only.
    param($LegacySnapshot, $Process)
    if ($null -eq $LegacySnapshot -or $LegacySnapshot.Failed -or $null -eq $Process -or $null -eq $Process.CreationUtc) { return $null }
    $same = @($LegacySnapshot.Processes | Where-Object { $null -ne $_ -and [long]$_.Pid -eq [long]$Process.Pid })
    if ($same.Count -ne 1) { return $null }
    $lp = $same[0]
    if ($null -eq $lp.CreationUtc -or ([datetime]$lp.CreationUtc).ToUniversalTime().Ticks -ne $Process.CreationUtc.Ticks) { return $null }
    if ($lp.CommandLine -is [string] -and $lp.CommandLine.Length -gt 0) { return $lp.CommandLine }
    return $null
}

function Add-AtmProviderToSet {
    # A provider set keyed by the lower-case Id (a V0.1 Id may be upper case); the value is the Id itself, the
    # ordinally smaller one when two differ only by case, so the result does not depend on the order of the inputs.
    param([hashtable]$Set, [string]$Provider)
    $low = $Provider.ToLowerInvariant()
    if (-not $Set.ContainsKey($low) -or [string]::CompareOrdinal($Provider, [string]$Set[$low]) -lt 0) { $Set[$low] = $Provider }
}

function Get-AtmProviderAttribution {
    # The provider responsible for a process, from the union of provider sets: the one Id when there is exactly one;
    # $null with Ambiguous when there are several (never one picked among them); $null when there is none. Ids is
    # the sorted list (ordinal).
    param([hashtable[]]$Sets)
    $all = @{}
    foreach ($s in @($Sets | Where-Object { $null -ne $_ })) { foreach ($v in $s.Values) { Add-AtmProviderToSet -Set $all -Provider ([string]$v) } }
    $ids = [string[]]@($all.Values)
    [Array]::Sort($ids, [StringComparer]::Ordinal)
    [pscustomobject]@{ Provider = $(if ($ids.Count -eq 1) { $ids[0] } else { $null }); Ambiguous = ($ids.Count -gt 1); Ids = $ids }
}

function Get-AtmOrdinalSorted {
    # Items sorted by a string signature (ordinal), so the order of providers and partitions does not change results.
    # The items are written to the pipeline one by one; callers collect them with @().
    param($Items, [scriptblock]$Signature)
    $arr = @($Items | Where-Object { $null -ne $_ })
    if ($arr.Count -lt 2) { return $arr }
    # One string[] of "signature NUL index" (a keys/items Sort overload would sort a converted copy of the items).
    $keys = New-Object string[] $arr.Count
    for ($i = 0; $i -lt $arr.Count; $i++) { $keys[$i] = [string](& $Signature $arr[$i]) + [char]0 + $i.ToString('D10') }
    [Array]::Sort($keys, [StringComparer]::Ordinal)
    return @($keys | ForEach-Object { $arr[[int]$_.Substring($_.LastIndexOf([char]0) + 1)] })
}

function Get-AtmSortedCodes {
    # Distinct codes in ordinal order: the reasons of the runtime records never depend on the order of the inputs.
    param($Codes)
    $a = [string[]]@($Codes | Where-Object { $_ } | ForEach-Object { [string]$_ } | Select-Object -Unique)
    [Array]::Sort($a, [StringComparer]::Ordinal)
    return $a
}

function Get-AtmAgentRuntimeFindings {
    <#
      Process and AgentSession findings for the agents of the providers, from evidence only (ADR-0003 rule 5):
      provider process matchers (image name; an optional marker is checked in memory against the V0.1 command line of
      the same verified process), session registries (Resolve-AtmSessionProcess), V0.1 path references (the PID of
      the reference, through the V0.1 snapshot, to an exact identity), and verified descendants of those processes.
      -Collection: Get-AtmProcessCollection. -ProviderHints: Get-AtmProviderRuntimeHints results.
      -SessionRegistries: @({ ProviderId; Registry (GetSessionEvidence result); Error (exception type or $null) }).
      -LegacySnapshot: the V0.1 snapshot. -Partitions: V0.1 partitions. -InventoryCoverage: the coverage records of the
      V0.1 inventory (Get-AtmInventoryCoverage), carried by path-reference findings. -SelfKeys: Get-AtmSelfProcessKeys.
      -Cpu: Measure-AtmProcessCpu (optional, for the tree resources).
      Evidence Source is a fixed code (process-matcher, session-registry, path-reference, diagnose); the provider Id is
      only in Finding.Provider, and collector names use it in lower case (a V0.1 Id may be upper case). Each finding
      carries the coverage of the process collection, of agent-processes and of the source of each evidence item.
      Precedence per process: SELF, then AGENT_PROCESS, then AGENT_DESCENDANT, then UNKNOWN (a matcher that could not
      be checked). One finding per process key. Finding.Provider is set only when the evidence names exactly one
      provider; with several, it is $null and a PROVIDER_ATTRIBUTION_AMBIGUOUS evidence lists them. agent-processes is
      never COMPLETE while a session registry is failed or partial (SESSION_REGISTRY_INCOMPLETE). A process without a
      verified identity is IDENTITY_UNVERIFIED with the key pid:<n>.
      Session registries (P1-B4-c): one item per provider and profile ({ ProviderId; Registry; Error; Reason (a code,
      instead of Error); ProfileSid; ProfilePath }); there is one sessions-<provider> record per provider, aggregated over
      its profiles, and the session findings carry that same record. AgentSession keys are pseudonyms
      (ConvertTo-AtmSessionKey); the SessionId stays in memory. Two different sessions with the same key, or one session
      listed with different PIDs, give one UNKNOWN finding (SESSION_KEY_COLLISION / SESSION_ENTRIES_CONFLICT), never an
      overwritten one. -Pseudonymizer: New-AtmPseudonymizer (ADR-0010; without it an ephemeral key is used for this
      call only). -SessionKeyFunction: test override of the key function.
      -Second: the second collection of the CPU sample. A process (or the process of a LIVE session) that exited between
      the two collections gets the PROCESS_EXITED_DURING_RUN evidence, only when both collections are COMPLETE.
      Findings are ordered by Kind and Key (ordinal). Returns Findings, Coverage (sessions-<provider> sorted,
      agent-processes, agent-resources: exactly one record each, also on failure), Trees (Get-AtmProcessTreeResources
      per agent process, overlapping) and Totals (Get-AtmAgentResourceTotals over the union of the agent processes).
    #>
    param($Collection, $ProviderHints = @(), $SessionRegistries = @(), $LegacySnapshot = $null, $Partitions = @(), $InventoryCoverage = @(), $SelfKeys = $null, $Cpu = $null, $Second = $null, [scriptblock]$SessionKeyFunction = $null, $Pseudonymizer = $null)
    # Without a pseudonymizer (direct calls), an ephemeral one for this call only, closed even when the call throws.
    $own = $null
    if ($null -eq $Pseudonymizer -and $null -eq $SessionKeyFunction) { $own = New-AtmPseudonymizer; $PSBoundParameters['Pseudonymizer'] = $own }
    try { return (Get-AtmAgentRuntimeFindingsRun @PSBoundParameters) } finally { Close-AtmPseudonymizer $own }
}

function Get-AtmAgentRuntimeFindingsRun {
    # The body of Get-AtmAgentRuntimeFindings (same parameters; the pseudonymizer is already set there).
    param($Collection, $ProviderHints = @(), $SessionRegistries = @(), $LegacySnapshot = $null, $Partitions = @(), $InventoryCoverage = @(), $SelfKeys = $null, $Cpu = $null, $Second = $null, [scriptblock]$SessionKeyFunction = $null, $Pseudonymizer = $null)
    if ($null -eq $Collection) { throw (Get-AtmText 'err.diagProcess' 'Collection') }
    $findings = New-Object System.Collections.Generic.List[object]
    $coverage = New-Object System.Collections.Generic.List[object]
    $trees = New-Object System.Collections.Generic.List[object]
    $snapCov = $Collection.Coverage
    $reasons = New-Object System.Collections.Generic.List[string]
    $now = [datetime]::UtcNow
    # Exit during the run: only between two COMPLETE collections (a reused PID in a partial one proves nothing).
    $runStates = @{}
    if ($null -ne $Second -and -not $Collection.Failed -and -not $Second.Failed -and $snapCov.Status -ceq 'COMPLETE' -and $Second.Coverage.Status -ceq 'COMPLETE') { $runStates = Compare-AtmProcessCollections -First $Collection -Second $Second }
    $exitEv = { param([string]$Key) if ($Key -and $runStates.ContainsKey($Key) -and $runStates[$Key] -ceq 'EXITED_DURING_RUN') { New-AtmEvidence -Code 'PROCESS_EXITED_DURING_RUN' -Source 'diagnose' -Collector 'process-snapshot' -ObservedUtc $now } }
    $keyFn = $(if ($null -ne $SessionKeyFunction) { $SessionKeyFunction } else { { param($Provider, $ProfileSid, $ProfilePath, $SessionId) ConvertTo-AtmSessionKey -Pseudonymizer $Pseudonymizer -Provider $Provider -ProfileSid $ProfileSid -ProfilePath $ProfilePath -SessionId $SessionId } })
    # Candidates by key: Process (or $null for pid:<n>), Evidence, Kind (AGENT | UNVERIFIED | UNCHECKED), the providers
    # of the AGENT evidence and of the other evidence (sets: one process can be related to several providers), and
    # SourceCoverage (the coverage records of the sources of the evidence, one per collector). Whether a process is
    # agent-related (Kind) is kept apart from which provider is responsible (Get-AtmCandidateProvider): the provider is
    # never chosen by iteration order.
    $cand = @{}
    $addCand = {
        param([string]$Key, $Process, [string]$Kind, $Evidence, $Providers, $SourceCoverage = @())
        if (-not $cand.ContainsKey($Key)) { $cand[$Key] = [pscustomobject]@{ Process = $Process; Kind = $Kind; Evidence = (New-Object System.Collections.Generic.List[object]); AgentProviders = @{}; OtherProviders = @{}; UncheckedProviders = @{}; SourceCoverage = @{} } }
        $c = $cand[$Key]
        # AGENT outranks UNCHECKED; UNVERIFIED keys (pid:<n>) never collide with verified ones.
        if ($Kind -ceq 'AGENT') { $c.Kind = 'AGENT' }
        $set = $(if ($Kind -ceq 'AGENT') { $c.AgentProviders } else { $c.OtherProviders })
        foreach ($pv in @($Providers | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })) { Add-AtmProviderToSet -Set $set -Provider ([string]$pv); if ($Kind -ceq 'UNCHECKED') { Add-AtmProviderToSet -Set $c.UncheckedProviders -Provider ([string]$pv) } }
        $sig = '{0}|{1}|{2}|{3}' -f $Evidence.Code, $Evidence.Source, $Evidence.Collector, $Evidence.Detail
        if (@($c.Evidence | Where-Object { ('{0}|{1}|{2}|{3}' -f $_.Code, $_.Source, $_.Collector, $_.Detail) -ceq $sig }).Count -eq 0) { $c.Evidence.Add($Evidence) }
        foreach ($sc in @($SourceCoverage | Where-Object { $null -ne $_ })) { if (-not $c.SourceCoverage.ContainsKey($sc.Collector)) { $c.SourceCoverage[$sc.Collector] = $sc } }
    }
    $matcherCount = 0

    $runtimeProviders = @($ProviderHints | Where-Object { $null -ne $_ })
    $registries = @($SessionRegistries | Where-Object { $null -ne $_ })
    $failStatus = $(if ($snapCov.Status -ceq 'TIMEOUT') { 'TIMEOUT' } else { 'FAILED' })
    foreach ($h in $runtimeProviders) { if ($h.Coverage.Status -cne 'COMPLETE') { $reasons.Add('PROVIDER_HINTS_INCOMPLETE') } }

    # 1. Provider process matchers.
    if (-not $Collection.Failed) {
        foreach ($h in $runtimeProviders) {
            $hc = @($h.Coverage)
            foreach ($m in @($h.ProcessMatchers)) {
                $matcherCount++
                foreach ($p in @($Collection.Processes | Where-Object { $null -ne $_.Name -and [string]::Equals($_.Name, $m.ImageName, [StringComparison]::OrdinalIgnoreCase) })) {
                    if ($p.IdentityStatus -cne 'VERIFIED') {
                        $reasons.Add('IDENTITY_UNVERIFIED_CANDIDATES')
                        & $addCand ($script:AtmUnverifiedKeyPrefix + $p.Pid) $null 'UNVERIFIED' (New-AtmEvidence -Code 'PROCESS_MATCHER_IMAGE' -Source 'process-matcher' -Collector 'agent-processes' -ObservedUtc $now -Detail $p.IdentityStatus) $h.ProviderId $hc
                        continue
                    }
                    if ($null -eq $m.CommandLineMarker) {
                        & $addCand $p.Key $p 'AGENT' (New-AtmEvidence -Code 'PROCESS_MATCHER_IMAGE' -Source 'process-matcher' -Collector 'agent-processes' -ObservedUtc $now) $h.ProviderId $hc
                        continue
                    }
                    $cl = Get-AtmLegacyCommandLine -LegacySnapshot $LegacySnapshot -Process $p
                    if ($null -eq $cl) {
                        $reasons.Add('COMMAND_LINE_MARKER_UNAVAILABLE')
                        & $addCand $p.Key $p 'UNCHECKED' (New-AtmEvidence -Code 'COMMAND_LINE_MARKER_UNAVAILABLE' -Source 'process-matcher' -Collector 'agent-processes' -ObservedUtc $now) $h.ProviderId $hc
                    } elseif ($cl.IndexOf([string]$m.CommandLineMarker, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                        & $addCand $p.Key $p 'AGENT' (New-AtmEvidence -Code 'PROCESS_MATCHER_MARKER' -Source 'process-matcher' -Collector 'agent-processes' -ObservedUtc $now) $h.ProviderId $hc
                    }
                    $cl = $null
                }
            }
        }
    }

    # 2. Session registries: grouped by provider (one collector each), every profile of the provider in it.
    $regGroups = @{}
    foreach ($reg in $registries) {
        $prov = [string](Get-AtmHintProperty -Item $reg -Name 'ProviderId')
        # Same Id rule as the registration (a V0.1 Id may be upper case); the collector name is only lower-cased.
        $valid = ($prov -match '^[A-Za-z0-9-]+$')
        $collector = $(if ($valid) { 'sessions-' + $prov.ToLowerInvariant() } else { 'sessions-invalid' })
        if (-not $regGroups.ContainsKey($collector)) { $regGroups[$collector] = [pscustomobject]@{ Collector = $collector; Provider = $null; Reasons = (New-Object System.Collections.Generic.List[string]); Usable = 0; Entries = (New-Object System.Collections.Generic.List[object]); SessionKeys = @{} } }
        $g = $regGroups[$collector]
        if (-not $valid) { $g.Reasons.Add('SESSION_REGISTRY_PROVIDER_INVALID'); continue }
        # Ids that differ only by case share the collector; the ordinally smaller one is kept (order-independent).
        if ($null -eq $g.Provider -or [string]::CompareOrdinal($prov, $g.Provider) -lt 0) { $g.Provider = $prov }
        $r = Get-AtmHintProperty -Item $reg -Name 'Registry'
        $err = Get-AtmHintProperty -Item $reg -Name 'Error'
        $code = [string](Get-AtmHintProperty -Item $reg -Name 'Reason')
        if ($code -and $code -cmatch $script:AtmCodePattern) { $g.Reasons.Add($code); continue }
        if ($null -ne $err -or $null -eq $r) {
            $g.Reasons.Add('SESSION_REGISTRY_FAILED'); if ($null -ne $err) { $g.Reasons.Add((ConvertTo-AtmExceptionCode ([string]$err))) }
            continue
        }
        $readable = [bool](Get-AtmHintProperty -Item $r -Name 'Readable')
        $unparseable = 0; [void][int]::TryParse([string](Get-AtmHintProperty -Item $r -Name 'Unparseable'), [ref]$unparseable)
        if (-not $readable) { $g.Reasons.Add('SESSION_REGISTRY_UNREADABLE') } else { $g.Usable++ }
        if ($unparseable -gt 0) { $g.Reasons.Add('SESSION_ENTRIES_UNPARSEABLE') }
        $psid = [string](Get-AtmHintProperty -Item $reg -Name 'ProfileSid')
        $ppath = [string](Get-AtmHintProperty -Item $reg -Name 'ProfilePath')
        foreach ($e in @(@(Get-AtmHintProperty -Item $r -Name 'Entries') | Where-Object { $null -ne $_ })) {
            $g.Entries.Add([pscustomobject]@{ Entry = $e; ProfileSid = $psid; ProfilePath = $ppath })
        }
    }
    # Keys first (pseudonyms; the SessionId stays here, in memory): a collision or a conflicting entry is a gap of
    # the registry record, so it is known before the record is built.
    foreach ($g in $regGroups.Values) {
        if ($null -eq $g.Provider) { continue }
        foreach ($x in $g.Entries) {
            $sid = ([string](Get-AtmHintProperty -Item $x.Entry -Name 'SessionId')).Trim().ToLowerInvariant()
            if ([string]::IsNullOrWhiteSpace($sid)) { continue }
            $key = [string](& $keyFn $g.Provider $x.ProfileSid $x.ProfilePath $sid)
            if (-not $g.SessionKeys.ContainsKey($key)) { $g.SessionKeys[$key] = New-Object System.Collections.Generic.List[object] }
            $epid = Get-AtmHintProperty -Item $x.Entry -Name 'Pid'
            $who = '{0}|{1}|{2}' -f $x.ProfileSid, ([string]$x.ProfilePath).ToLowerInvariant(), $sid
            # The same entry listed twice (same session, profile and PID) is read once.
            if (@($g.SessionKeys[$key] | Where-Object { $_.Who -ceq $who -and [string]$_.Pid -ceq [string]$epid }).Count -gt 0) { continue }
            $g.SessionKeys[$key].Add([pscustomobject]@{ Who = $who; Pid = $epid; StartUtc = (Get-AtmHintProperty -Item $x.Entry -Name 'StartUtc') })
        }
        foreach ($k in $g.SessionKeys.Keys) {
            $list = $g.SessionKeys[$k]
            if (@($list | ForEach-Object { $_.Who } | Select-Object -Unique).Count -gt 1) { $g.Reasons.Add('SESSION_KEY_COLLISION') }
            elseif ($list.Count -gt 1) { $g.Reasons.Add('SESSION_ENTRIES_CONFLICT') }
        }
    }
    $groupKeys = [string[]]@($regGroups.Keys)
    [Array]::Sort($groupKeys, [StringComparer]::Ordinal)
    foreach ($gk in $groupKeys) {
        $g = $regGroups[$gk]
        $rs = @(Get-AtmSortedCodes $g.Reasons)
        # Every profile failed: FAILED; some gap: PARTIAL; all read: COMPLETE.
        $status = $(if ($g.Usable -eq 0 -and $rs.Count -gt 0) { 'FAILED' } elseif ($rs.Count -gt 0) { 'PARTIAL' } else { 'COMPLETE' })
        $regCov = New-AtmCoverage -Collector $gk -Status $status -Reasons $rs -ElevationWouldHelp $(if ($status -eq 'COMPLETE') { 'NO' } elseif ($null -eq $g.Provider) { 'NO' } else { 'UNKNOWN' }) -Observed $g.Entries.Count
        $coverage.Add($regCov)
        if ($null -eq $g.Provider) { continue }
        foreach ($key in @($g.SessionKeys.Keys)) {
            $list = $g.SessionKeys[$key].ToArray()
            $conflict = $(if (@($list | ForEach-Object { $_.Who } | Select-Object -Unique).Count -gt 1) { 'SESSION_KEY_COLLISION' } elseif ($list.Count -gt 1) { 'SESSION_ENTRIES_CONFLICT' } else { $null })
            $ev = New-Object System.Collections.Generic.List[object]
            $ev.Add((New-AtmEvidence -Code 'SESSION_REGISTRY' -Source 'session-registry' -Collector $gk -ObservedUtc $now))
            $state = 'UNKNOWN'
            foreach ($x in $list) {
                $res = Resolve-AtmSessionProcess -Collection $Collection -ProcessId $x.Pid -StartUtc $x.StartUtc
                # A process proven by a session stays agent-related even when the session key is in conflict.
                if ($res.State -ceq 'LIVE') {
                    & $addCand $res.Process.Key $res.Process 'AGENT' (New-AtmEvidence -Code 'SESSION_PROCESS_MATCH' -Source 'session-registry' -Collector $gk -ObservedUtc $now) $g.Provider @($regCov)
                    $xe = & $exitEv $res.Process.Key; if ($null -ne $xe) { $ev.Add($xe) }
                }
                if ($null -eq $conflict) {
                    $state = $res.State
                    $ev.Add((New-AtmEvidence -Code 'SESSION_PROCESS' -Source 'session-registry' -Collector 'process-snapshot' -ObservedUtc $now -Detail $res.Reason))
                    # The process of a live session without conflict (P4-A: RUNS_SESSION). Process keys are exported already.
                    if ($res.State -ceq 'LIVE') { $ev.Add((New-AtmEvidence -Code 'SESSION_PROCESS_KEY' -Source 'session-registry' -Collector $gk -ObservedUtc $now -Detail $res.Process.Key)) }
                }
            }
            if ($null -ne $conflict) { $ev.Add((New-AtmEvidence -Code $conflict -Source 'session-registry' -Collector $gk -ObservedUtc $now)) }
            $findings.Add((New-AtmFinding -Kind 'AgentSession' -Key $key -State $state -Evidence $ev.ToArray() -Coverage @($snapCov, $regCov) -Provider $g.Provider))
        }
    }

    # A session source that is failed or partial is a gap in the discovery of agent processes: agent-processes cannot
    # be COMPLETE (the processes found stay, the gap is never read as absence).
    if (@($coverage | Where-Object { $_.Collector -like 'sessions-*' -and $_.Status -cne 'COMPLETE' }).Count -gt 0) { $reasons.Add('SESSION_REGISTRY_INCOMPLETE') }

    # 3. V0.1 path references: the PID of each reference, resolved through the V0.1 snapshot to an exact identity. A
    # PID referenced by several partitions keeps every provider (a set), never the last one read.
    $refPids = @{}
    foreach ($part in @($Partitions | Where-Object { $null -ne $_ })) {
        $partProv = [string](Get-AtmHintProperty -Item $part -Name 'Provider')
        foreach ($list in @('DirectRefs', 'AncestorRefs')) {
            foreach ($ref in @(Get-AtmHintProperty -Item $part -Name $list)) {
                if ([string]$ref -notmatch $script:AtmPathReferencePattern) { continue }
                $rpid = [long]$Matches[1]
                if (-not $refPids.ContainsKey($rpid)) { $refPids[$rpid] = @{} }
                if (-not [string]::IsNullOrWhiteSpace($partProv)) { Add-AtmProviderToSet -Set $refPids[$rpid] -Provider $partProv }
            }
        }
    }
    if ($refPids.Count -gt 0 -and -not $Collection.Failed) {
        if ($null -eq $LegacySnapshot -or $LegacySnapshot.Failed) { $reasons.Add('LEGACY_SNAPSHOT_UNAVAILABLE') }
        else {
            $invCov = @($InventoryCoverage | Where-Object { $null -ne $_ })
            foreach ($rp in @($refPids.Keys | Sort-Object)) {
                # The same PID twice in the V0.1 snapshot: the reference cannot be attributed to one process.
                $lps = @($LegacySnapshot.Processes | Where-Object { [long]$_.Pid -eq $rp })
                $prov = @($refPids[$rp].Values)
                $res = $(if ($lps.Count -eq 1) { Resolve-AtmProcessReference -Collection $Collection -ProcessId $rp -CreationUtc $lps[0].CreationUtc } else { $null })
                if ($null -ne $res -and $res.Result -ceq 'MATCH') {
                    & $addCand $res.Process.Key $res.Process 'AGENT' (New-AtmEvidence -Code 'PATH_REFERENCE' -Source 'path-reference' -Collector 'inventory' -ObservedUtc $now) $prov $invCov
                } elseif ($null -ne $res -and $res.Result -ceq 'IDENTITY_UNVERIFIED' -and ($Collection.ByPid.ContainsKey($rp) -or $Collection.Duplicates.ContainsKey($rp))) {
                    $reasons.Add('IDENTITY_UNVERIFIED_CANDIDATES')
                    & $addCand ($script:AtmUnverifiedKeyPrefix + $rp) $null 'UNVERIFIED' (New-AtmEvidence -Code 'PATH_REFERENCE' -Source 'path-reference' -Collector 'inventory' -ObservedUtc $now) $prov $invCov
                } else { $reasons.Add('PATH_REFERENCE_UNVERIFIED') }
            }
        }
    }

    # 4. SELF (exact rules of R-B1, Get-AtmSelfProcessKeys) outranks everything.
    $selfSet = @{}
    if ($null -ne $SelfKeys) { foreach ($k in @($SelfKeys.Keys)) { if ($k) { $selfSet[$k] = $true } } }

    # Keys in ordinal order and the attribution of each candidate: the result does not depend on the order of the
    # providers, registries or partitions.
    $candKeys = [string[]]@($cand.Keys)
    [Array]::Sort($candKeys, [StringComparer]::Ordinal)
    $attr = @{}
    foreach ($k in $candKeys) {
        $c = $cand[$k]
        # A provider whose marker could not be checked on this process may still own it (P2-C: Claude Code matches the
        # image, Claude Desktop needs the marker): it takes part in the attribution, so the result is ambiguous, never
        # resolved to the provider that did not need the command line.
        $attr[$k] = $(if ($c.Kind -ceq 'AGENT') { Get-AtmProviderAttribution -Sets @($c.AgentProviders, $c.UncheckedProviders) } else { Get-AtmProviderAttribution -Sets @($c.AgentProviders, $c.OtherProviders) })
    }

    # 5. Verified descendants of every agent process. A descendant under several agent roots (nested roots) keeps every
    # root: one evidence item per root, the union of their source coverage and of their providers.
    $agentKeys = @($candKeys | Where-Object { $cand[$_].Kind -ceq 'AGENT' -and -not $selfSet.ContainsKey($_) })
    $descendants = @{}
    foreach ($k in $agentKeys) {
        $tree = Get-AtmProcessTree -Collection $Collection -RootKey $k
        if (-not $tree.Complete) { $reasons.Add('TREE_INCOMPLETE') }
        foreach ($m in @($tree.Members | Select-Object -Skip 1)) {
            if ($selfSet.ContainsKey($m) -or ($cand.ContainsKey($m) -and $cand[$m].Kind -ceq 'AGENT')) { continue }
            if (-not $descendants.ContainsKey($m)) { $descendants[$m] = [pscustomobject]@{ Roots = (New-Object System.Collections.Generic.List[string]); Providers = @{}; SourceCoverage = @{} } }
            $d = $descendants[$m]
            $d.Roots.Add($k)
            foreach ($pv in $cand[$k].AgentProviders.Values) { Add-AtmProviderToSet -Set $d.Providers -Provider ([string]$pv) }
            foreach ($sc in $cand[$k].SourceCoverage.Values) { if (-not $d.SourceCoverage.ContainsKey($sc.Collector)) { $d.SourceCoverage[$sc.Collector] = $sc } }
        }
        # Per-tree sums overlap when agent roots are nested: they are never added together (see Totals).
        $tr = Get-AtmProcessTreeResources -Collection $Collection -Tree $tree -Cpu $Cpu
        $trees.Add([pscustomobject]@{ RootKey = $k; Provider = $attr[$k].Provider; Tree = $tree; Resources = $tr })
    }
    # Evidence and source coverage in a fixed order; an ambiguous attribution is stated as evidence, never resolved.
    $sortEv = { param($Items) Get-AtmOrdinalSorted -Items $Items -Signature { param($e) '{0}|{1}|{2}|{3}' -f $e.Code, $e.Source, $e.Collector, $e.Detail } }
    $sortCov = { param($Items) Get-AtmOrdinalSorted -Items $Items -Signature { param($x) [string]$x.Collector } }
    $ambEv = { param($a) if ($a.Ambiguous) { New-AtmEvidence -Code 'PROVIDER_ATTRIBUTION_AMBIGUOUS' -Source 'diagnose' -Collector 'agent-processes' -ObservedUtc $now -Detail ($a.Ids -join ',') } }

    # 6. Findings and the agent-processes coverage. Without a collection: no process finding, and agent-processes and
    # agent-resources are FAILED/TIMEOUT (one record each, never missing).
    $agentCov = $null
    if ($Collection.Failed) {
        $agentCov = New-AtmCoverage -Collector 'agent-processes' -Status $failStatus -Reasons @('PROCESS_SNAPSHOT_UNAVAILABLE') -ElevationWouldHelp 'UNKNOWN'
        $coverage.Add($agentCov)
    } else {
        if ($snapCov.Status -cne 'COMPLETE') { $reasons.Add('PROCESS_SNAPSHOT_INCOMPLETE') }
        $rs = @(Get-AtmSortedCodes $reasons)
        # Nothing was searched (no matcher, no session registry, no path reference): not observable, never "no agent".
        if ($matcherCount -eq 0 -and $registries.Count -eq 0 -and $refPids.Count -eq 0) { $agentCov = New-AtmCoverage -Collector 'agent-processes' -Status 'NOT_OBSERVABLE' -Reasons (@('NO_RUNTIME_EVIDENCE_SOURCE') + $rs) -ElevationWouldHelp 'NO' }
        else { $agentCov = New-AtmCoverage -Collector 'agent-processes' -Status $(if ($rs.Count -gt 0) { 'PARTIAL' } else { 'COMPLETE' }) -Reasons $rs -ElevationWouldHelp $(if ($rs.Count -eq 0) { 'NO' } else { 'UNKNOWN' }) -Observed $agentKeys.Count }
        $coverage.Add($agentCov)
        $pcov = @($snapCov, $agentCov)
        foreach ($k in $selfSet.Keys) {
            if ($null -eq (Get-AtmCollectedProcess -Collection $Collection -Key $k)) { continue }
            $ev = @(New-AtmEvidence -Code 'SELF_EXCLUSION' -Source 'diagnose' -Collector 'process-snapshot' -ObservedUtc $now) + @(& $exitEv $k)
            $findings.Add((New-AtmFinding -Kind 'Process' -Key $k -State 'SELF' -Evidence $ev -Coverage $pcov))
        }
        foreach ($k in $candKeys) {
            if ($selfSet.ContainsKey($k)) { continue }
            $c = $cand[$k]
            $state = $(switch ($c.Kind) { 'AGENT' { 'AGENT_PROCESS' } 'UNVERIFIED' { 'IDENTITY_UNVERIFIED' } default { 'UNKNOWN' } })
            # A process seen by a matcher that could not be checked, but under a verified agent process, is a descendant.
            if ($state -ceq 'UNKNOWN' -and $descendants.ContainsKey($k)) { continue }
            $ev = & $sortEv (@($c.Evidence.ToArray()) + @(& $ambEv $attr[$k]) + @(& $exitEv $k))
            $findings.Add((New-AtmFinding -Kind 'Process' -Key $k -State $state -Evidence $ev -Coverage (@($pcov) + @(& $sortCov @($c.SourceCoverage.Values))) -Provider $attr[$k].Provider))
        }
        $descKeys = [string[]]@($descendants.Keys)
        [Array]::Sort($descKeys, [StringComparer]::Ordinal)
        foreach ($k in $descKeys) {
            $d = $descendants[$k]
            $da = Get-AtmProviderAttribution -Sets @($d.Providers)
            $ev = & $sortEv (@($d.Roots | ForEach-Object { New-AtmEvidence -Code 'PARENT_LINK_VERIFIED' -Source 'diagnose' -Collector 'process-snapshot' -ObservedUtc $now -Detail $_ }) + @(& $ambEv $da) + @(& $exitEv $k))
            $findings.Add((New-AtmFinding -Kind 'Process' -Key $k -State 'AGENT_DESCENDANT' -Evidence $ev -Coverage (@($pcov) + @(& $sortCov @($d.SourceCoverage.Values))) -Provider $da.Provider))
        }
    }
    # Resources of the union of the agent processes (SELF excluded), each process counted once.
    $memberKeys = @($findings | Where-Object { $_.Kind -ceq 'Process' -and ($_.State -ceq 'AGENT_PROCESS' -or $_.State -ceq 'AGENT_DESCENDANT') } | ForEach-Object { $_.Key })
    $totals = Get-AtmAgentResourceTotals -Collection $Collection -MemberKeys $memberKeys -AgentCoverage $agentCov -Cpu $Cpu -RunStates $runStates
    if ($Collection.Failed) { $resCov = New-AtmCoverage -Collector 'agent-resources' -Status $failStatus -Reasons @('PROCESS_SNAPSHOT_UNAVAILABLE') -ElevationWouldHelp 'UNKNOWN' }
    else { $resCov = New-AtmCoverage -Collector 'agent-resources' -Status $(if ($totals.Complete) { 'COMPLETE' } else { 'PARTIAL' }) -Reasons $totals.Reasons -ElevationWouldHelp $(if ($totals.Complete) { 'NO' } else { 'UNKNOWN' }) -Observed $totals.Processes }
    $coverage.Add($resCov)
    # Runtime findings by Kind, then Key (ordinal): the order of the inputs never changes the result (D6).
    $sorted = @(Get-AtmOrdinalSorted -Items $findings.ToArray() -Signature { param($f) [string]$f.Kind + [char]1 + [string]$f.Key })
    [pscustomobject]@{ Findings = $sorted; Coverage = $coverage.ToArray(); Trees = $trees.ToArray(); Totals = $totals }
}

function Get-AtmAgentResourceTotals {
    <#
      Resource totals over the union of the agent processes (-MemberKeys: AGENT_PROCESS and AGENT_DESCENDANT keys, SELF
      excluded): every process once, even when it is in several overlapping trees. For each counter of AtmTreeCounters
      and CpuPercent: Sum of the values read ($null when none was), Known and Complete. Unread values are never 0. With
      no member, a sum is 0 only when agent-processes is conclusive (no agent process identified by the observed
      sources), otherwise $null. Complete only when agent-processes is conclusive, every member and counter was read
      and, with members, the CPU was sampled. A member that exited during the run keeps the counters of the first
      collection and has no CPU percentage.
    #>
    param($Collection, [string[]]$MemberKeys = @(), $AgentCoverage = $null, $Cpu = $null, [hashtable]$RunStates = @{})
    $reasons = New-Object System.Collections.Generic.List[string]
    $conclusive = ($null -ne $AgentCoverage -and $script:AtmConclusiveCoverage -ccontains $AgentCoverage.Status)
    if (-not $conclusive) { $reasons.Add('AGENT_PROCESSES_INCOMPLETE') }
    $members = New-Object System.Collections.Generic.List[object]
    foreach ($k in @($MemberKeys | Where-Object { $_ } | Select-Object -Unique)) {
        $p = Get-AtmCollectedProcess -Collection $Collection -Key $k
        if ($null -eq $p) { $reasons.Add('MEMBER_NOT_COLLECTED') } else { $members.Add($p) }
    }
    $cpuUsable = ($null -ne $Cpu -and $null -ne $Cpu.IntervalMs)
    if ($members.Count -gt 0 -and -not $cpuUsable) {
        $reasons.Add('CPU_NOT_SAMPLED')
        if ($null -ne $Cpu -and $null -ne $Cpu.Coverage) { foreach ($x in @($Cpu.Coverage.Reasons)) { if ($x) { $reasons.Add($x) } } }
    }
    $counters = [ordered]@{}
    foreach ($n in @($script:AtmTreeCounters) + @('CpuPercent')) {
        $sum = $null; $known = 0
        foreach ($p in $members) {
            $v = $null
            if ($n -ceq 'CpuTime100ns') { $v = Get-AtmProcessCpuTime $p }
            elseif ($n -ceq 'CpuPercent') { if ($cpuUsable -and $Cpu.ByKey.ContainsKey($p.Key)) { $v = $Cpu.ByKey[$p.Key] } }
            elseif ($null -ne $p.Resources) { $v = $p.Resources.$n }
            if ($null -eq $v) { continue }
            $known++
            $sum = $(if ($n -ceq 'CpuPercent') { [double]$(if ($null -eq $sum) { 0 } else { $sum }) + [double]$v } else { [long]$(if ($null -eq $sum) { 0 } else { $sum }) + [long]$v })
        }
        if ($members.Count -eq 0 -and $conclusive) { $sum = $(if ($n -ceq 'CpuPercent') { [double]0 } else { [long]0 }) }
        $complete = ($conclusive -and $known -eq $members.Count)
        if ($known -lt $members.Count) {
            if ($n -cne 'CpuPercent') { $reasons.Add('COUNTERS_UNREADABLE') }
            elseif ($cpuUsable) {
                $exited = @($members | Where-Object { $RunStates.ContainsKey($_.Key) -and $RunStates[$_.Key] -ceq 'EXITED_DURING_RUN' }).Count
                $reasons.Add($(if ($exited -gt 0) { 'CPU_PROCESS_EXITED' } else { 'CPU_VALUES_INCOMPLETE' }))
            }
        }
        $counters[$n] = [pscustomobject]@{ Sum = $sum; Known = $known; Complete = $complete }
    }
    $rs = @(Get-AtmSortedCodes $reasons)
    [pscustomobject]@{
        Processes     = $members.Count
        Complete      = ($rs.Count -eq 0)
        Reasons       = $rs
        CpuIntervalMs = $(if ($cpuUsable) { [long][math]::Round([double]$Cpu.IntervalMs) } else { $null })
        Counters      = [pscustomobject]$counters
    }
}

# ---------------------------------------------------------------------------------------------
# Git runner (ADR-0006 rules 1-7 and 10-11, D-4, P3-A): the only way the engine runs Git. Not yet part of
# Invoke-AtmDiagnose (discovery and the git coverage record are P3-B). Every call: the allow-list below, refused before
# any process is started; global options and an environment that keep Git from writing, prompting, reaching the
# network or leaving the target directory; and a job object of its own (AtmJobRunner) with a timeout, an output cap,
# a memory limit and a process limit. The only process ever terminated is that job. `status` is listed in ADR-0006
# rule 4, but repositories whose configuration can run commands during reads (D-3) are handled in P3-C: until then it is
# run only on the suite's own fixtures. Known before P3-B wires it to real repositories: configuration a repository
# controls (include paths, alternates, a `gitdir:` file) can make Git open UNC paths, and configuration names can carry
# credentials (`url.<url>.insteadof`): output stays in memory and must never be exported verbatim.
# ---------------------------------------------------------------------------------------------

$script:AtmGitDefaultTimeoutMs = 10000
$script:AtmGitDefaultMaxOutputBytes = 4MB
$script:AtmGitDefaultJobMemoryBytes = 1GB
# The Git for Windows launcher (cmd\git.exe) starts mingw64\bin\git.exe; console programs also get a conhost.
$script:AtmGitDefaultActiveProcessLimit = 8
# protocol.allow is only the default for protocols without a setting of their own: each transport is refused by name
# too, so a repository's protocol.<name>.allow cannot switch the network back on (the command line takes precedence).
$script:AtmGitGlobalArguments = @('--no-pager', '--no-optional-locks', '-c', 'core.fsmonitor=false', '-c', 'core.untrackedCache=false', '-c', 'protocol.allow=never',
    '-c', 'protocol.file.allow=never', '-c', 'protocol.git.allow=never', '-c', 'protocol.ssh.allow=never', '-c', 'protocol.http.allow=never', '-c', 'protocol.https.allow=never', '-c', 'protocol.ext.allow=never',
    '-c', 'color.ui=never', '-c', 'core.quotePath=false', '-c', 'core.excludesFile=NUL', '-c', 'core.attributesFile=NUL')
# Test spy: when it is a list, every argument vector that reaches the native runner is added to it.
$script:AtmGitInvocationLog = $null
# Same rule as the installer's Test-AtmInstallAcl: only SYSTEM, Administrators, TrustedInstaller and CREATOR OWNER
# may own the item or hold write-type rights.
$script:AtmTrustedWriterSids = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464', 'S-1-3-0')
$script:AtmGitRevisionPattern = '^\^?(HEAD|[0-9a-fA-F]{4,64}|refs/[A-Za-z0-9._/\-]+)$'

function Test-AtmTrustedLocationAcl {
    # $true when the item's owner and every account with a write-type right are trusted (AtmTrustedWriterSids):
    # an elevated run must not start a binary a standard user could replace (ADR-0006 rule 2).
    param([string]$Path)
    try {
        $acl = Get-Acl -LiteralPath $Path
        if ($script:AtmTrustedWriterSids -cnotcontains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) { return $false }
        $writeMask = [Security.AccessControl.FileSystemRights]'WriteData, AppendData, WriteExtendedAttributes, WriteAttributes, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
        foreach ($ace in @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))) {
            if ($ace.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
            if ($script:AtmTrustedWriterSids -ccontains $ace.IdentityReference.Value) { continue }
            if (($ace.FileSystemRights -band $writeMask) -ne 0) { return $false }
        }
        return $true
    } catch { return $false }
}

function Test-AtmGitArguments {
    <#
      The allow-list of ADR-0006 rule 4, checked before a process exists. Returns $null when allowed, otherwise a code:
      GIT_VERB_NOT_ALLOWED (any other verb, including fetch, pull, push, prune, gc, maintenance, repack, checkout,
      switch, restore, reset, clean, stash, worktree add/remove/..., update-index, reflog, commit-graph) or
      GIT_ARGUMENT_REFUSED (an option or value outside the verb's list). No argument may hold whitespace, a quote or a
      control character, so the command line needs no quoting.
    #>
    param([string[]]$Arguments)
    $a = @($Arguments)
    if ($a.Count -eq 0) { return 'GIT_VERB_NOT_ALLOWED' }
    foreach ($x in $a) { if ([string]::IsNullOrEmpty($x) -or $x -match '[\s"\x00-\x1f]') { return 'GIT_ARGUMENT_REFUSED' } }
    $verb = $a[0]; $rest = @($a | Select-Object -Skip 1)
    $revision = { param([string]$v) $v -cmatch $script:AtmGitRevisionPattern }
    switch -CaseSensitive ($verb) {
        '--version' { if ($rest.Count -eq 0) { return $null }; return 'GIT_ARGUMENT_REFUSED' }
        'rev-parse' {
            $opts = @('--show-toplevel', '--git-dir', '--git-common-dir', '--absolute-git-dir', '--is-inside-work-tree', '--is-bare-repository', '--is-shallow-repository', '--show-prefix', '--symbolic-full-name', '--abbrev-ref', '--verify', '--quiet')
            foreach ($x in $rest) { if ($opts -cnotcontains $x -and -not (& $revision $x)) { return 'GIT_ARGUMENT_REFUSED' } }
            if ($rest.Count -eq 0) { return 'GIT_ARGUMENT_REFUSED' }
            return $null
        }
        'worktree' { if (($rest -join ' ') -ceq 'list --porcelain -z') { return $null }; return 'GIT_VERB_NOT_ALLOWED' }
        'status' {
            if ($rest -cnotcontains '--porcelain=v2' -or $rest -cnotcontains '-z') { return 'GIT_ARGUMENT_REFUSED' }
            $opts = @('--porcelain=v2', '-z', '--branch', '--show-stash', '--ahead-behind', '--no-ahead-behind', '--no-renames', '--untracked-files=no', '--untracked-files=normal', '--untracked-files=all', '--ignored=no', '--ignored=traditional', '--ignored=matching', '--ignore-submodules=all')
            foreach ($x in $rest) { if ($opts -cnotcontains $x) { return 'GIT_ARGUMENT_REFUSED' } }
            return $null
        }
        'for-each-ref' {
            foreach ($x in $rest) {
                if ($x -cmatch '^--format=[%A-Za-z0-9()_:./\-]+$' -or $x -cmatch '^--count=\d{1,6}$' -or $x -cmatch '^refs/[A-Za-z0-9._/*\-]*$') { continue }
                return 'GIT_ARGUMENT_REFUSED'
            }
            return $null
        }
        'rev-list' {
            $opts = @('--count', '--all', '--branches', '--tags', '--remotes', '--not', '--first-parent')
            foreach ($x in $rest) { if ($opts -cnotcontains $x -and $x -cnotmatch '^--max-count=\d{1,9}$' -and -not (& $revision $x)) { return 'GIT_ARGUMENT_REFUSED' } }
            if ($rest.Count -eq 0) { return 'GIT_ARGUMENT_REFUSED' }
            return $null
        }
        'config' {
            # Names only, never values.
            if ($rest.Count -eq 3 -and $rest[0] -ceq '--name-only' -and $rest[1] -ceq '--get-regexp' -and $rest[2] -notmatch '^-') { return $null }
            return 'GIT_ARGUMENT_REFUSED'
        }
        'cat-file' { if ($rest.Count -eq 2 -and $rest[0] -ceq '-e' -and (& $revision $rest[1]) -and $rest[1] -notmatch '^\^') { return $null }; return 'GIT_ARGUMENT_REFUSED' }
        default { return 'GIT_VERB_NOT_ALLOWED' }
    }
}

function Get-AtmGitEnvironment {
    <#
      The whole environment of a Git child (ADR-0006 rule 6): the caller's environment without any GIT_* variable (GIT_DIR,
      GIT_WORK_TREE, GIT_INDEX_FILE, GIT_CONFIG_PARAMETERS, GIT_CONFIG_COUNT/KEY_*/VALUE_*, ...), then no optional
      locks, no prompt or askpass, no lazy fetch, discovery bounded by -Ceiling and on one file system, and messages in
      the C locale (stderr is classified by its text). Configuration is isolated (P3-B0): no global file
      (GIT_CONFIG_GLOBAL=NUL, which also covers the XDG file), no system configuration or attributes, and HOME,
      USERPROFILE and XDG_CONFIG_HOME pointing to -IsolatedHome, a directory that does not exist inside the Git
      installation. P3-C0: -CommonDir (the preflight's validated common directory) is given as GIT_COMMON_DIR, so a
      `commondir` file created after the preflight is never read.
    #>
    param([string]$Ceiling, [string]$IsolatedHome, [string]$CommonDir)
    $vars = @{}
    foreach ($e in [Environment]::GetEnvironmentVariables().GetEnumerator()) {
        $k = [string]$e.Key
        if ($k.StartsWith('GIT_', [StringComparison]::OrdinalIgnoreCase) -or @('SSH_ASKPASS', 'GCM_INTERACTIVE', 'LC_ALL', 'LANG', 'LANGUAGE') -contains $k) { continue }
        $vars[$k] = [string]$e.Value
    }
    foreach ($k in @('HOME', 'USERPROFILE', 'XDG_CONFIG_HOME')) { $vars.Remove($k) }
    $set = [ordered]@{ GIT_OPTIONAL_LOCKS = '0'; GIT_TERMINAL_PROMPT = '0'; GCM_INTERACTIVE = 'never'; GIT_ASKPASS = ''; SSH_ASKPASS = ''; GIT_NO_LAZY_FETCH = '1'; GIT_DISCOVERY_ACROSS_FILESYSTEM = '0'; LC_ALL = 'C'; LANG = 'C'; LANGUAGE = 'C'
        GIT_CONFIG_GLOBAL = 'NUL'; GIT_CONFIG_NOSYSTEM = '1'; GIT_ATTR_NOSYSTEM = '1' }
    if ($Ceiling) { $set['GIT_CEILING_DIRECTORIES'] = $Ceiling }
    if ($IsolatedHome) { $set['HOME'] = $IsolatedHome; $set['USERPROFILE'] = $IsolatedHome; $set['XDG_CONFIG_HOME'] = $IsolatedHome }
    if ($CommonDir) { $set['GIT_COMMON_DIR'] = $CommonDir }
    foreach ($k in $set.Keys) { $vars[$k] = $set[$k] }
    $keys = [string[]]@($vars.Keys)
    [Array]::Sort($keys, [StringComparer]::OrdinalIgnoreCase)
    return [string[]]@($keys | ForEach-Object { $_ + '=' + $vars[$_] })
}

function Invoke-AtmBoundedProcess {
    # One program in a job object of its own (AtmJobRunner). Used by Invoke-AtmGitCommand; the suite uses it directly to
    # prove the job limits and that only the job is ever terminated (D-4).
    param([string]$Executable, [string]$CommandLine, [string]$WorkingDirectory, [string[]]$Environment, [int]$TimeoutMs, [int]$MaxOutputBytes, [long]$JobMemoryBytes, [int]$ActiveProcessLimit)
    if ($TimeoutMs -lt 0 -or $MaxOutputBytes -lt 1 -or $JobMemoryBytes -lt 1MB -or $ActiveProcessLimit -lt 1) { throw (Get-AtmText 'err.diagProcess' 'limits') }
    Initialize-AtmNative
    return [AgentTempManager.AtmJobRunner]::Run($Executable, $CommandLine, $WorkingDirectory, $Environment, $TimeoutMs, $MaxOutputBytes, $JobMemoryBytes, $ActiveProcessLimit)
}

function Invoke-AtmGitCommand {
    <#
      One allow-listed Git command. -Git: Resolve-AtmGitExecutable. -WorkingDirectory: mandatory, an existing directory on
      a fixed drive (8.3 names normalized) with no reparse point in its path (Test-AtmPathChain); discovery is bounded by
      its parent (GIT_CEILING_DIRECTORIES), so Git does not report on a repository above it. Returns Status (COMPLETE | PARTIAL output truncated | FAILED | TIMEOUT | REFUSED | UNAVAILABLE),
      Reason (a code), ExitCode, Output (UTF-8 text, in memory only), ElapsedMs, TotalProcesses. Git's error text is
      never returned: it is classified (GIT_OWNERSHIP_REFUSED, GIT_NOT_A_REPOSITORY, GIT_COMMAND_FAILED).
      P3-B0: every command but `--version` needs the worktree diagnostics gate open (GIT_EXECUTION_GATE_CLOSED) and a
      -Preflight (Get-AtmGitPreflight) that is OK for this very working directory (GIT_PREFLIGHT_REQUIRED); `status`
      also needs its D-3 preconditions (GIT_STATUS_PRECONDITION). `config` returns no names: only MatchCount.
    #>
    param($Git, [string[]]$Arguments, [string]$WorkingDirectory, $Preflight = $null, [int]$TimeoutMs = $script:AtmGitDefaultTimeoutMs, [int]$MaxOutputBytes = $script:AtmGitDefaultMaxOutputBytes,
        [long]$JobMemoryBytes = $script:AtmGitDefaultJobMemoryBytes, [int]$ActiveProcessLimit = $script:AtmGitDefaultActiveProcessLimit)
    $out = [ordered]@{ Status = 'REFUSED'; Reason = $null; ExitCode = $null; Output = $null; OutputTruncated = $false; ElapsedMs = 0; TotalProcesses = 0; MatchCount = $null; PinnedMs = 0 }
    $code = Test-AtmGitArguments -Arguments $Arguments
    if ($null -ne $code) { $out.Reason = $code; return [pscustomobject]$out }
    $versionOnly = (@($Arguments).Count -eq 1 -and $Arguments[0] -ceq '--version')
    if (-not $versionOnly -and -not $script:AtmWorktreeDiagnosticsEnabled) { $out.Reason = 'GIT_EXECUTION_GATE_CLOSED'; return [pscustomobject]$out }
    if ($null -eq $Git -or [string]::IsNullOrEmpty([string]$Git.Path)) { $out.Status = 'UNAVAILABLE'; $out.Reason = 'GIT_NOT_FOUND'; return [pscustomobject]$out }
    if ([string]::IsNullOrWhiteSpace($WorkingDirectory) -or $WorkingDirectory -notmatch '^[A-Za-z]:\\') { $out.Reason = 'GIT_WORKDIR_INVALID'; return [pscustomobject]$out }
    # Git works from the resolved directory: a junction or symbolic link in the path would put the ceiling somewhere Git
    # never passes, and discovery could reach a repository above the target. Every component must be a plain directory,
    # on a fixed drive, checked before anything else touches the path (a mapped network drive is never opened).
    $chain = Resolve-AtmGitReferencedPath -Value $WorkingDirectory -BaseDir $null
    if ($chain.Status -cne 'OK') { $out.Reason = $(if ($chain.Reason -ceq 'GIT_REF_PATH_REPARSE' -or $chain.Reason -ceq 'GIT_REF_PATH_NETWORK' -or $chain.Reason -ceq 'GIT_REF_PATH_UNREADABLE') { 'GIT_WORKDIR_REPARSE_OR_UNREADABLE' } else { 'GIT_WORKDIR_INVALID' }); return [pscustomobject]$out }
    if (-not [IO.Directory]::Exists($WorkingDirectory)) { $out.Reason = 'GIT_WORKDIR_INVALID'; return [pscustomobject]$out }
    $wd = Get-AtmNormalizedPath $WorkingDirectory
    if (-not $wd -or (Test-AtmPathChain $wd).Status -cne 'OK') { $out.Reason = 'GIT_WORKDIR_INVALID'; return [pscustomobject]$out }
    if (-not $versionOnly) {
        if ($null -eq $Preflight -or @($Preflight.PSObject.Properties.Name) -cnotcontains 'PinPaths' -or $Preflight.Status -cne 'OK' -or -not [string]::Equals([string]$Preflight.WorkTree, $wd, [StringComparison]::OrdinalIgnoreCase)) { $out.Reason = 'GIT_PREFLIGHT_REQUIRED'; return [pscustomobject]$out }
    }
    # P3-C0: every file and directory the preflight validated for this call is pinned (read handle without write or
    # delete sharing) for the whole call, then a fresh preflight runs UNDER the pins and must agree with the caller's:
    # what it reads can no longer change, be replaced or be renamed until Git has exited. A file created after the
    # preflight cannot be prevented (an absence cannot be pinned): see SECURITY-MODEL.md for the vectors left open.
    $pins = $(if ($versionOnly) { [pscustomobject]@{ Handles = @(); Error = $null } } else { Open-AtmGitReadPins -Paths @($Preflight.PinPaths) })
    if ($pins.Error) { $out.Reason = $pins.Error; return [pscustomobject]$out }
    $pinWatch = [Diagnostics.Stopwatch]::StartNew()
    try {
        $commonDir = $null
        if (-not $versionOnly) {
            $fresh = Get-AtmGitPreflight -Target $wd
            $same = { param($a, $b) [string]::Equals([string]$a, [string]$b, [StringComparison]::OrdinalIgnoreCase) }
            if ($fresh.Status -cne 'OK' -or -not (& $same $fresh.WorkTree $wd) -or -not (& $same $fresh.GitDir $Preflight.GitDir) -or -not (& $same $fresh.CommonDir $Preflight.CommonDir) -or
                (@($fresh.PinPaths) -join '|') -ine (@($Preflight.PinPaths) -join '|')) { $out.Reason = 'GIT_PREFLIGHT_REQUIRED'; return [pscustomobject]$out }
            if ($Arguments[0] -ceq 'status' -and -not ($fresh.StatusAllowed -and $Preflight.StatusAllowed)) { $out.Reason = 'GIT_STATUS_PRECONDITION'; return [pscustomobject]$out }
            $commonDir = $fresh.CommonDir
        }
        $parent = [IO.Path]::GetDirectoryName($wd.TrimEnd('\'))
        $ceiling = $(if ($parent) { Get-AtmNormalizedPath $parent } else { $null })
        # `status` never looks into submodules (a gitlink's .git file would be another path to follow).
        $args2 = @($Arguments)
        if ($Arguments[0] -ceq 'status' -and $args2 -cnotcontains '--ignore-submodules=all') { $args2 += '--ignore-submodules=all' }
        $vector = @($script:AtmGitGlobalArguments) + $args2
        $commandLine = '"' + [string]$Git.Path + '" ' + ($vector -join ' ')
        if ($null -ne $script:AtmGitInvocationLog) { $script:AtmGitInvocationLog.Add([pscustomobject]@{ Arguments = [string[]]$vector; WorkingDirectory = $wd; Pins = @($pins.Handles).Count }) }
        $childEnv = Get-AtmGitEnvironment -Ceiling $ceiling -IsolatedHome ([string]$Git.IsolatedHome) -CommonDir $commonDir
        $r = Invoke-AtmBoundedProcess -Executable ([string]$Git.Path) -CommandLine $commandLine -WorkingDirectory $wd -Environment $childEnv -TimeoutMs $TimeoutMs -MaxOutputBytes $MaxOutputBytes -JobMemoryBytes $JobMemoryBytes -ActiveProcessLimit $ActiveProcessLimit
    } finally {
        foreach ($h in @($pins.Handles)) { $h.Dispose() }
        $out.PinnedMs = $pinWatch.ElapsedMilliseconds
    }
    $out.ElapsedMs = $r.ElapsedMs; $out.TotalProcesses = $r.TotalProcesses; $out.ExitCode = $(if ($r.Started) { $r.ExitCode } else { $null })
    if (-not $r.Started) { $out.Status = 'FAILED'; $out.Reason = $(if ($r.Error -like 'JOB_*') { 'GIT_JOB_UNAVAILABLE' } else { 'GIT_START_FAILED' }); return [pscustomobject]$out }
    if ($r.TimedOut) { $out.Status = 'TIMEOUT'; $out.Reason = 'GIT_TIMEOUT'; return [pscustomobject]$out }
    $err = [Text.Encoding]::UTF8.GetString($r.ErrorOutput)
    if ($r.ExitCode -ne 0) {
        $out.Status = 'FAILED'
        $out.Reason = $(if ($err -match 'dubious ownership') { 'GIT_OWNERSHIP_REFUSED' } elseif ($err -match 'not a git repository') { 'GIT_NOT_A_REPOSITORY' } else { 'GIT_COMMAND_FAILED' })
        return [pscustomobject]$out
    }
    $text = [Text.Encoding]::UTF8.GetString($r.Output)
    # Configuration names can carry credentials (url.<url>.insteadof): they are counted, never returned.
    if ($Arguments[0] -ceq 'config') { $out.MatchCount = @($text.Split([char[]]"`n`0") | Where-Object { $_ }).Count } else { $out.Output = $text }
    $out.OutputTruncated = [bool]$r.OutputTruncated
    if ($r.OutputTruncated) { $out.Status = 'PARTIAL'; $out.Reason = 'GIT_OUTPUT_TRUNCATED' } else { $out.Status = 'COMPLETE' }
    return [pscustomobject]$out
}

function Resolve-AtmGitExecutable {
    <#
      git.exe from the absolute entries of -PathVariable only (never the current directory, a relative entry, or a .cmd
      or .bat), normalized. Elevated runs (-Elevated): see below.
      Then `git --version` through the runner. Returns Status (COMPLETE | UNAVAILABLE), Reason (GIT_NOT_FOUND,
      GIT_LOCATION_NOT_TRUSTED, GIT_VERSION_UNREADABLE, GIT_VERSION_TOO_OLD below AtmGitMinimumVersion), Path, Version,
      EffectivePath (the program the Git for Windows launcher starts, when that layout is recognized) and IsolatedHome.
      Elevated (P3-B0): the launcher, the effective program, every program and library in the effective program's
      directory, and every directory above both up to (not including) the volume root must pass
      Test-AtmTrustedLocationAcl. The volume root is not checked (its default ACL lets users create folders); the time
      between this check and the start is not covered.
    #>
    param([string]$PathVariable = $env:Path, $Elevated = $null)
    $out = [ordered]@{ Status = 'UNAVAILABLE'; Reason = 'GIT_NOT_FOUND'; Path = $null; Version = $null; EffectivePath = $null; IsolatedHome = $null }
    if ($null -eq $Elevated) { $Elevated = [bool](Get-AtmCurrentIdentity).IsAdmin }
    $found = $null
    foreach ($entry in @(([string]$PathVariable).Split(';'))) {
        $dir = $entry.Trim().Trim('"')
        if ($dir -notmatch '^[A-Za-z]:\\') { continue }
        # Only fixed drives: a PATH entry on a mapped network drive is skipped before any file-system call.
        try { if ((New-Object IO.DriveInfo($dir.Substring(0, 1))).DriveType -ne [IO.DriveType]::Fixed) { continue } } catch { continue }
        $cand = Resolve-AtmGitReferencedPath -Value (Join-AtmPath $dir 'git.exe') -BaseDir $null
        if ($cand.Status -eq 'OK') { $found = $cand.Path; break }
    }
    if (-not $found) { return [pscustomobject]$out }
    $norm = Get-AtmNormalizedPath $found
    if (-not $norm) { return [pscustomobject]$out }
    $dir = [IO.Path]::GetDirectoryName($norm)
    $root = $dir
    $effective = $norm
    if (@('cmd', 'bin') -contains [IO.Path]::GetFileName($dir).ToLowerInvariant()) {
        $root = [IO.Path]::GetDirectoryName($dir)
        foreach ($sub in @('mingw64', 'clangarm64', 'mingw32')) {
            $cand = Join-AtmPath (Join-AtmPath (Join-AtmPath $root $sub) 'bin') 'git.exe'
            $ec = Resolve-AtmGitReferencedPath -Value $cand -BaseDir $null
            if ($ec.Status -eq 'OK') { $effective = $ec.Path; break }
        }
    }
    if ($Elevated) {
        $items = New-Object System.Collections.Generic.List[string]
        foreach ($f in @($norm, $effective)) {
            $items.Add($f)
            $cur = [IO.Path]::GetDirectoryName($f)
            while ($cur -and $cur.Length -gt 3) { $items.Add($cur); $cur = [IO.Path]::GetDirectoryName($cur) }
        }
        try { foreach ($f in @([IO.Directory]::GetFiles([IO.Path]::GetDirectoryName($effective)) | Where-Object { $_ -match '\.(exe|dll)$' })) { $items.Add($f) } } catch { $out.Reason = 'GIT_LOCATION_NOT_TRUSTED'; return [pscustomobject]$out }
        foreach ($it in @($items | Select-Object -Unique)) { if (-not (Test-AtmTrustedLocationAcl -Path $it)) { $out.Reason = 'GIT_LOCATION_NOT_TRUSTED'; return [pscustomobject]$out } }
    }
    $isolated = Join-AtmPath $root '.atm-isolated-home'
    $probe = Invoke-AtmGitCommand -Git ([pscustomobject]@{ Path = $norm; IsolatedHome = $isolated }) -Arguments @('--version') -WorkingDirectory $dir
    $v = $null
    if ($probe.Status -ceq 'COMPLETE' -and $probe.Output -match '^git version (\d+)\.(\d+)\.(\d+)') { $v = New-Object Version([int]$Matches[1], [int]$Matches[2], [int]$Matches[3]) }
    if ($null -eq $v) { $out.Reason = 'GIT_VERSION_UNREADABLE'; $out.Path = $norm; return [pscustomobject]$out }
    $out.Path = $norm; $out.Version = $v; $out.EffectivePath = $effective; $out.IsolatedHome = $isolated
    if ($v -lt $script:AtmGitMinimumVersion) { $out.Reason = 'GIT_VERSION_TOO_OLD'; return [pscustomobject]$out }
    $out.Status = 'COMPLETE'; $out.Reason = $null
    return [pscustomobject]$out
}

# ---------------------------------------------------------------------------------------------
# Worktree diagnostics gate and Git preflight (P3-B0, ADR-0006, ADR-0007). Reading repositories (their .git files,
# configuration and administrative entries) and running Git in them are both behind one gate that is $false in every
# shipped copy; only the automated suite opens it, in its own process, for its disposable fixtures. Opening it for real
# repositories is a maintainer decision (HUMAN_GATE). `git --version` is the only Git call allowed while it is closed.
# Before any Git call on a target, Get-AtmGitPreflight reads the files Git would follow and refuses the target when one
# of them could make Git open a network path (UNC, a mapped network drive, file://), a reparse point, a path outside a
# fixed drive, or included configuration. Every such path goes through Resolve-AtmGitReferencedPath first: no file-system
# call is ever made on a value that has not passed it, by Git or by this engine.
# ---------------------------------------------------------------------------------------------

$script:AtmWorktreeDiagnosticsEnabled = $false
# Git features used and the release that introduced them (Git's own release notes): --no-optional-locks 2.15.0,
# `worktree list -z` 2.36.0, `--no-lazy-fetch` / GIT_NO_LAZY_FETCH 2.45.0.
$script:AtmGitMinimumVersion = New-Object Version(2, 45, 0)
$script:AtmGitConfigMaxBytes = 1MB
$script:AtmGitSmallFileMaxBytes = 64KB
$script:AtmGitAlternatesMaxDepth = 5
$script:AtmGitAlternatesMax = 32
$script:AtmGitAdminEntriesMax = 4096
# Configuration keys whose value is a path Git may open (lower case, section.key).
$script:AtmGitRefEntriesMax = 100000
$script:AtmGitPathKeys = @('core.worktree', 'core.excludesfile', 'core.attributesfile', 'core.hookspath', 'commit.template', 'core.notesref', 'gpg.program', 'gpg.ssh.program')

function Test-AtmGitPathChain {
    # Test-AtmPathChain's rule and result (Status, At) in native code (AtmPathCheck, P3-E): the resolver checks thousands
    # of paths per discovery run. Test-AtmPathChain itself (V0.1) is unchanged; a test keeps the two in parity.
    param([string]$Path)
    $at = $null
    $st = [AgentTempManager.AtmPathCheck]::Chain($Path, [ref]$at)
    return [pscustomobject]@{ Status = $st; At = $at; Detail = $null }
}

function Resolve-AtmGitReferencedPath {
    <#
      A path read from a repository file (.git, commondir, an administrative gitdir, alternates, a configuration value),
      relative to -BaseDir. Status: OK (Path: an existing local path, every component a plain directory or file),
      MISSING (a local, safe path that does not exist: the first missing component's parent was read), or REFUSED with
      Reason. Refused before any file-system call: empty or control characters, expansions (~, %(prefix), $, %VAR%),
      UNC and device forms (\\, //, /\, \/, \\?\, \\.\), URLs (file:, any scheme), alternate data streams, and a result
      that is not on a drive letter. Then Test-AtmPathChain: a drive that is not fixed (a mapped network drive) or a
      reparse point anywhere in the path is refused.
    #>
    param([string]$Value, [string]$BaseDir)
    $refuse = { param([string]$Code) [pscustomobject]@{ Status = 'REFUSED'; Reason = $Code; Path = $null } }
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -match '[\x00-\x1f]') { return (& $refuse 'GIT_REF_PATH_INVALID') }
    $v = $Value.Trim()
    if ($v -match '^(\\\\|//|/\\|\\/)') { return (& $refuse 'GIT_REF_PATH_NETWORK') }
    if ($v -match '^[A-Za-z][A-Za-z0-9+.\-]*://' -or $v -match '^file:') { return (& $refuse 'GIT_REF_PATH_NETWORK') }
    if ($v.StartsWith('~') -or $v.Contains('%(') -or $v.Contains('$') -or $v -match '%[^%]+%') { return (& $refuse 'GIT_REF_PATH_EXPANSION') }
    if ($v -match '^[A-Za-z]:[^\\/]' -or $v -match '^[A-Za-z]:$') { return (& $refuse 'GIT_REF_PATH_INVALID') }
    if ($v.IndexOf(':') -ge 0 -and $v -notmatch '^[A-Za-z]:[\\/]' ) { return (& $refuse 'GIT_REF_PATH_INVALID') }
    if ($v.LastIndexOf(':') -gt 1) { return (& $refuse 'GIT_REF_PATH_INVALID') }
    $v = $v.Replace('/', '\')
    if ($v -match '^\\') { return (& $refuse 'GIT_REF_PATH_INVALID') }
    if ($v -match '^[A-Za-z]:\\') { $full = $v }
    else {
        if ([string]::IsNullOrWhiteSpace($BaseDir) -or $BaseDir -notmatch '^[A-Za-z]:\\') { return (& $refuse 'GIT_REF_PATH_INVALID') }
        $full = $BaseDir.TrimEnd('\') + '\' + $v
    }
    # Normalize . and .. by text only (no file-system call).
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($seg in $full.Substring(3).Split('\')) {
        if ($seg -eq '' -or $seg -eq '.') { continue }
        if ($seg -eq '..') { if ($parts.Count -gt 0) { $parts.RemoveAt($parts.Count - 1) }; continue }
        if ($seg -match '[<>"|?*]' -or $seg.EndsWith('.') -or $seg.EndsWith(' ')) { return (& $refuse 'GIT_REF_PATH_INVALID') }
        # Reserved device names (with or without an extension) open a device, not a file.
        if ($seg -match '^(?i)(CON|PRN|AUX|NUL|CONIN|CONOUT|COM[0-9\u00B9\u00B2\u00B3]|LPT[0-9\u00B9\u00B2\u00B3])(\..*)?$') { return (& $refuse 'GIT_REF_PATH_INVALID') }
        $parts.Add($seg)
    }
    $norm = $full.Substring(0, 3) + ($parts -join '\')
    $chain = Test-AtmGitPathChain $norm
    switch ($chain.Status) {
        'OK' { return [pscustomobject]@{ Status = 'OK'; Reason = $null; Path = $norm } }
        'NOT_FOUND' { return [pscustomobject]@{ Status = 'MISSING'; Reason = 'GIT_REF_PATH_MISSING'; Path = $norm } }
        'REPARSE_IN_PATH' { return (& $refuse 'GIT_REF_PATH_REPARSE') }
        'UNSUPPORTED_DRIVE' { return (& $refuse 'GIT_REF_PATH_NETWORK') }
        default { return (& $refuse 'GIT_REF_PATH_UNREADABLE') }
    }
}

# P3-E: counters of the work done by repository reads (preflights, cache use, reference entries, files and bytes
# read). Reset by Get-AtmWorktreeDiscovery; returned as its Stats; never exported.
$script:AtmScaleStats = @{ CommonPreflights = 0; CommonCacheHits = 0; CommonCacheInvalidations = 0; RefEntriesWalked = 0; FilesRead = 0; BytesRead = 0; RefStoreReads = 0 }
function Reset-AtmScaleStats { foreach ($k in @($script:AtmScaleStats.Keys)) { $script:AtmScaleStats[$k] = 0 } }

function New-AtmGitSharedReadStream {
    # P3-D: a read stream that shares read, write AND delete with everyone, so reading a repository file never stops
    # another process (an agent's Git) from rewriting or renaming over it. Git replaces files by lockfile and rename, so
    # what is read is one whole version; a torn read by another kind of writer must fail the strict parsers.
    # The final component is opened without following a reparse point (AtmSharedRead): a file swapped for a link after
    # the path checks is refused, never followed. Throws when the file cannot be opened that way.
    param([string]$Path)
    $err = $null
    $h = [AgentTempManager.AtmSharedRead]::Open($Path, [ref]$err)
    if ($null -eq $h) { throw (New-Object IO.IOException("ATM_SHARED_READ_$err")) }
    return New-Object IO.FileStream($h, [IO.FileAccess]::Read)
}

function Read-AtmGitSmallFile {
    # The text of a small repository file at a path that already passed Resolve-AtmGitReferencedPath; $null when it is
    # larger than -MaxBytes or unreadable. Opened with New-AtmGitSharedReadStream (never blocks other processes).
    param([string]$Path, [int]$MaxBytes = $script:AtmGitSmallFileMaxBytes)
    $fs = $null
    try {
        $fs = New-AtmGitSharedReadStream -Path $Path
        if ($fs.Length -gt $MaxBytes) { return $null }
        # Raw UTF-8, no byte-order-mark detection: Git reads bytes, so a UTF-16 or BOM-prefixed file must fail the strict
        # parsers here as it does in Git.
        $sr = New-Object IO.StreamReader($fs, (New-Object Text.UTF8Encoding($false)), $false)
        $text = $sr.ReadToEnd()
        $script:AtmScaleStats.FilesRead++; $script:AtmScaleStats.BytesRead += $fs.Length
        return $text
    } catch { return $null }
    finally { if ($null -ne $fs) { $fs.Dispose() } }
}

function Read-AtmGitConfigText {
    <#
      Strict parser of a Git configuration file (the subset Git writes): blank lines, comments (# ;), [section],
      [section "subsection"], key = value and a bare key. Values are decoded (quotes, \\ \" \n \t \b, inline comments
      outside quotes). Anything else (a continuation line, an unknown escape, a malformed header) refuses the whole file:
      Error is a code and Entries is empty. Entries: Section (lower case), Subsection (as written), Key (lower case), Value.
    #>
    param([string]$Text)
    $entries = New-Object System.Collections.Generic.List[object]
    $fail = { param([string]$Code) [pscustomobject]@{ Error = $Code; Entries = @() } }
    $section = $null; $sub = $null
    $lines = $Text.Replace("`r`n", "`n").Split("`n")
    foreach ($raw in $lines) {
        $line = $raw.Trim()
        if ($line -eq '' -or $line.StartsWith('#') -or $line.StartsWith(';')) { continue }
        if ($line.StartsWith('[')) {
            if ($line -cmatch '^\[([A-Za-z0-9.\-]+)\]\s*([#;].*)?$') { $section = $Matches[1].ToLowerInvariant(); $sub = $null; continue }
            if ($line -cmatch '^\[([A-Za-z0-9\-]+)\s+"((?:[^"\\]|\\.)*)"\]\s*([#;].*)?$') {
                $section = $Matches[1].ToLowerInvariant()
                $sub = [regex]::Replace($Matches[2], '\\(.)', '$1')
                continue
            }
            return (& $fail 'GIT_CONFIG_UNPARSEABLE')
        }
        if ($null -eq $section) { return (& $fail 'GIT_CONFIG_UNPARSEABLE') }
        if ($line -notmatch '^([A-Za-z][A-Za-z0-9\-]*)\s*(=\s*(.*))?$') { return (& $fail 'GIT_CONFIG_UNPARSEABLE') }
        $key = $Matches[1].ToLowerInvariant()
        $value = 'true'
        if ($Matches[2]) {
            $rv = $Matches[3]
            $sb = New-Object System.Text.StringBuilder
            $inQ = $false; $i = 0
            while ($i -lt $rv.Length) {
                $c = $rv[$i]
                if ($c -eq '\') {
                    if ($i + 1 -ge $rv.Length) { return (& $fail 'GIT_CONFIG_UNPARSEABLE') }
                    $n = $rv[$i + 1]
                    switch -CaseSensitive ([string]$n) { '\' { [void]$sb.Append('\') } '"' { [void]$sb.Append('"') } 'n' { [void]$sb.Append("`n") } 't' { [void]$sb.Append("`t") } 'b' { [void]$sb.Append("`b") } default { return (& $fail 'GIT_CONFIG_UNPARSEABLE') } }
                    $i += 2; continue
                }
                if ($c -eq '"') { $inQ = -not $inQ; $i++; continue }
                if (-not $inQ -and ($c -eq '#' -or $c -eq ';')) { break }
                [void]$sb.Append($c); $i++
            }
            if ($inQ) { return (& $fail 'GIT_CONFIG_UNPARSEABLE') }
            $value = $sb.ToString().Trim()
        }
        $entries.Add([pscustomobject]@{ Section = $section; Subsection = $sub; Key = $key; Value = $value })
    }
    return [pscustomobject]@{ Error = $null; Entries = $entries.ToArray() }
}

function Get-AtmGitConfigFindings {
    # Configuration entries that make a target unsafe for any Git call (Refuse) or for `status` only (StatusBlock).
    param($Entries, [string]$BaseDir)
    $refuse = $null; $block = $null
    foreach ($e in @($Entries)) {
        $name = $e.Section + '.' + $e.Key
        # Included configuration is read by Git from wherever it points: never followed, so never allowed.
        if ($e.Section -eq 'include' -or $e.Section -eq 'includeif' -or $e.Section.StartsWith('include.') -or $e.Section.StartsWith('includeif.')) { $refuse = 'GIT_PREFLIGHT_INCLUDE'; break }
        # core.worktree moves the work tree somewhere the preflight did not check (Git resolves it against the Git
        # directory): never allowed. The other path keys are not read by the allowed commands (hooks, templates, signing
        # never run; excludes and attributes files are overridden on the command line): refused only when their value
        # is refused (network, expansion, reparse point), so a relative hooks path (Husky) is not a reason to refuse.
        if ($name -eq 'core.worktree') { $refuse = 'GIT_PREFLIGHT_CORE_WORKTREE'; break }
        if ($script:AtmGitPathKeys -contains $name -and $e.Value) {
            $r = Resolve-AtmGitReferencedPath -Value $e.Value -BaseDir $BaseDir
            if ($r.Status -eq 'REFUSED') { $refuse = 'GIT_PREFLIGHT_CONFIG_PATH'; break }
        }
        # Any other value written as a network path (URLs of remotes are never opened: no transport is allowed).
        if (-not ($e.Section -eq 'remote' -and ($e.Key -eq 'url' -or $e.Key -eq 'pushurl')) -and $e.Section -ne 'url' -and $e.Value -match '^\s*(\\\\|//|/\\|\\/|file:)') { $refuse = 'GIT_PREFLIGHT_CONFIG_NETWORK'; break }
        # Any value on a drive that is not fixed (a mapped network drive), whatever the key: the drive type is read
        # without touching the drive.
        if ($e.Value -match '^\s*([A-Za-z]):[\\/]') {
            $dt = $null; try { $dt = (New-Object IO.DriveInfo($Matches[1])).DriveType } catch { $dt = $null }
            if ($dt -ne [IO.DriveType]::Fixed) { $refuse = 'GIT_PREFLIGHT_CONFIG_NETWORK'; break }
        }
        # D-3: drivers configured in the repository can run commands during `status`.
        if ($e.Section -eq 'filter' -and $null -eq $block) { $block = 'D3_FILTER_DRIVER' }
        if ($e.Section -eq 'diff' -and $e.Key -eq 'textconv' -and $null -eq $block) { $block = 'D3_TEXTCONV' }
        if ($e.Section -eq 'submodule' -and $null -eq $block) { $block = 'D3_SUBMODULES' }
    }
    return [pscustomobject]@{ Refuse = $refuse; StatusBlock = $block }
}

function Open-AtmGitReadPins {
    # P3-C0: AtmReadPin on every path of -Paths (the preflight's PinPaths, all validated by the resolver and existing
    # when it ran). Any failure (gone, now a reparse point, held open for writing by someone else) closes what was
    # opened and returns Error (GIT_PIN_CHANGED, GIT_PIN_REPARSE, GIT_PIN_BUSY); nothing is retried.
    param([string[]]$Paths)
    $hs = New-Object System.Collections.Generic.List[object]
    foreach ($p in @($Paths)) {
        $err = $null
        $h = [AgentTempManager.AtmReadPin]::Open($p, [ref]$err)
        if ($null -eq $h) {
            foreach ($x in $hs) { $x.Dispose() }
            $code = $(if ($err -ceq 'NOT_FOUND') { 'GIT_PIN_CHANGED' } elseif ($err -ceq 'REPARSE') { 'GIT_PIN_REPARSE' } elseif ($err -ceq 'WIN32_32') { 'GIT_PIN_BUSY' } else { 'GIT_PIN_FAILED' })
            return [pscustomobject]@{ Handles = @(); Error = $code }
        }
        $hs.Add($h)
    }
    return [pscustomobject]@{ Handles = $hs.ToArray(); Error = $null }
}

function Get-AtmGitExactPathText {
    # A path stored in a Git file (gitfile after "gitdir: ", commondir, an administrative gitdir) exactly as Git reads
    # it: only trailing CR/LF are dropped. Leading or trailing blanks, an inner line break or an empty value give $null
    # (Git would use a different path than a trimmed one).
    param([string]$Text)
    if ($null -eq $Text) { return $null }
    $v = $Text.TrimEnd([char[]]"`r`n")
    if ($v -eq '' -or $v -match "[`r`n]" -or $v -cne $v.Trim()) { return $null }
    return $v
}

function Test-AtmGitRefStore {
    # Refs that `worktree list` resolves: no reparse point (or unreadable entry) under refs\, at packed-refs or under
    # reftable\, bounded by AtmGitRefEntriesMax. Returns $null or a refusal code.
    param([string]$CommonDir)
    foreach ($name in @('packed-refs', 'reftable')) {
        $p = Resolve-AtmGitReferencedPath -Value $name -BaseDir $CommonDir
        if ($p.Status -eq 'REFUSED') { return ('GIT_PREFLIGHT_REFS_' + $p.Reason.Substring('GIT_REF_PATH_'.Length)) }
    }
    $count = 0
    foreach ($top in @('refs', 'reftable')) {
        $r = Resolve-AtmGitReferencedPath -Value $top -BaseDir $CommonDir
        if ($r.Status -ne 'OK') { continue }
        $stack = New-Object System.Collections.Generic.Stack[string]
        $stack.Push($r.Path)
        while ($stack.Count -gt 0) {
            $d = $stack.Pop()
            try {
                foreach ($fi in (New-Object IO.DirectoryInfo($d)).EnumerateFileSystemInfos()) {
                    $count++
                    $script:AtmScaleStats.RefEntriesWalked++
                    if ($count -gt $script:AtmGitRefEntriesMax) { return 'GIT_PREFLIGHT_REFS_LIMIT' }
                    if (($fi.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return 'GIT_PREFLIGHT_REFS_REPARSE' }
                    if (($fi.Attributes -band [IO.FileAttributes]::Directory) -ne 0) { $stack.Push($fi.FullName) }
                }
            } catch { return 'GIT_PREFLIGHT_REFS_UNREADABLE' }
        }
    }
    return $null
}

function Get-AtmGitCommonFingerprint {
    # Sizes and last-write times of what the common part of the preflight depends on (attributes only, no content):
    # a change to any of them invalidates the cached part. Not a guarantee: a change that keeps both (or one deeper in
    # refs\ or inside an administrative entry) is not seen; the runner's fresh preflight is never cached.
    param([string]$CommonDir)
    return [AgentTempManager.AtmPathCheck]::Fingerprint($CommonDir, [string[]]@('.', 'config', 'packed-refs', 'objects', 'objects\info', 'objects\info\alternates', 'refs', 'refs\heads', 'refs\tags', 'refs\remotes', 'worktrees'))
}

function Get-AtmGitCommonPreflight {
    <#
      The common-directory part of Get-AtmGitPreflight (P3-E): the reference store walk, objects and refs, the common
      configuration (strict parser), the alternates chain and the administrative entries, with the paths to pin. With
      -Cache (one discovery run) the result is reused while Get-AtmGitCommonFingerprint is unchanged; a refusal is
      cached the same way. Returns Reason (a refusal before the configuration findings), Entries, PinsBefore,
      AlternatesReason, PinsAfter, Alternates, AdminReason, Admin (the caller applies them in the original order).
    #>
    param([string]$CommonDir, [hashtable]$Cache = $null)
    # The key is the path as written (ordinal): two spellings never share an entry (they are just computed twice).
    $key = 'common|' + $CommonDir
    $fpr = $null
    if ($null -ne $Cache) {
        $fpr = Get-AtmGitCommonFingerprint -CommonDir $CommonDir
        if ($Cache.ContainsKey($key)) {
            $hit = $Cache[$key]
            # Besides the fixed names, the alternates files and alternate object directories found last time.
            $watch = $(if (@($hit.Watch).Count -gt 0) { [AgentTempManager.AtmPathCheck]::Fingerprint('', [string[]]@($hit.Watch)) } else { '' })
            if ([string]::Equals($hit.Fingerprint, $fpr, [StringComparison]::Ordinal) -and [string]::Equals($hit.WatchPrint, $watch, [StringComparison]::Ordinal)) { $script:AtmScaleStats.CommonCacheHits++; return $hit.Result }
            $script:AtmScaleStats.CommonCacheInvalidations++
        }
    }
    $script:AtmScaleStats.CommonPreflights++
    $r = Get-AtmGitCommonPreflightUncached -CommonDir $CommonDir
    if ($null -ne $Cache) {
        $w = New-Object System.Collections.Generic.List[string]
        foreach ($x in @($r.PinsAfter)) { $w.Add($x); $w.Add((Join-Path $x 'info\alternates')) }
        $Cache[$key] = @{ Fingerprint = $fpr; Result = $r; Watch = $w.ToArray(); WatchPrint = $(if ($w.Count -gt 0) { [AgentTempManager.AtmPathCheck]::Fingerprint('', $w.ToArray()) } else { '' }) }
    }
    return $r
}

function Get-AtmGitCommonPreflightUncached {
    param([string]$CommonDir)
    $out = [ordered]@{ Reason = $null; Entries = @(); PinsBefore = @(); AlternatesReason = $null; PinsAfter = @(); Alternates = 0; AdminReason = $null; Admin = @() }
    $pin = New-Object System.Collections.Generic.List[string]
    $refsCode = Test-AtmGitRefStore -CommonDir $CommonDir
    if ($null -ne $refsCode) { $out.Reason = $refsCode; return [pscustomobject]$out }
    foreach ($sub in @('objects', 'refs')) {
        $sd = Resolve-AtmGitReferencedPath -Value $sub -BaseDir $CommonDir
        $isSubDir = $false
        if ($sd.Status -eq 'OK') { try { $isSubDir = (([IO.File]::GetAttributes($sd.Path) -band [IO.FileAttributes]::Directory) -ne 0) } catch { $isSubDir = $false } }
        if (-not $isSubDir) { $out.Reason = $(if ($sd.Status -eq 'REFUSED') { $sd.Reason } else { 'GIT_PREFLIGHT_GITDIR_INVALID' }); return [pscustomobject]$out }
        # Directory pins: neither can be renamed and replaced (by a junction, which needs no privilege) during the call.
        # Writes into their subdirectories (loose objects, packs, ref updates) are not blocked.
        $pin.Add($sd.Path)
    }
    foreach ($opt in @('objects\info', 'packed-refs')) {
        $o = Resolve-AtmGitReferencedPath -Value $opt -BaseDir $CommonDir
        if ($o.Status -eq 'OK') { $pin.Add($o.Path) } elseif ($o.Status -eq 'REFUSED') { $out.Reason = $o.Reason; return [pscustomobject]$out }
    }
    # The common configuration (config.worktree is per worktree: read by the caller).
    $f = Resolve-AtmGitReferencedPath -Value 'config' -BaseDir $CommonDir
    if ($f.Status -eq 'OK') {
        $pin.Add($f.Path)
        $text = Read-AtmGitSmallFile -Path $f.Path -MaxBytes $script:AtmGitConfigMaxBytes
        if ($null -eq $text) { $out.Reason = 'GIT_CONFIG_UNREADABLE'; return [pscustomobject]$out }
        $parsed = Read-AtmGitConfigText -Text $text
        if ($parsed.Error) { $out.Reason = $parsed.Error; return [pscustomobject]$out }
        $out.Entries = @($parsed.Entries)
    } elseif ($f.Status -ne 'MISSING') { $out.Reason = $f.Reason; return [pscustomobject]$out }
    $out.PinsBefore = $pin.ToArray()
    # Alternates: every object directory Git would read, recursively and bounded.
    $out.AlternatesReason = Get-AtmGitAlternatesCheck -CommonDir $CommonDir -Result $out
    if ($out.AlternatesReason) { return [pscustomobject]$out }
    # Administrative entries.
    $out.AdminReason = Get-AtmGitAdminEntriesCheck -CommonDir $CommonDir -Result $out
    return [pscustomobject]$out
}

function Get-AtmGitAlternatesCheck {
    # Fills -Result.Alternates and -Result.PinsAfter; returns a refusal code or $null.
    param([string]$CommonDir, $Result)
    $pin = New-Object System.Collections.Generic.List[string]
    $queue = New-Object System.Collections.Generic.Queue[object]
    $queue.Enqueue(@((Join-Path $CommonDir 'objects'), 0))
    $seen = @{}; $alts = 0
    try {
        while ($queue.Count -gt 0) {
            $item = $queue.Dequeue(); $objDir = $item[0]; $depth = $item[1]
            $af = Resolve-AtmGitReferencedPath -Value 'info\alternates' -BaseDir $objDir
            if ($af.Status -eq 'MISSING') { continue }
            if ($af.Status -ne 'OK') { return $af.Reason }
            $pin.Add($af.Path)
            $atext = Read-AtmGitSmallFile -Path $af.Path
            if ($null -eq $atext) { return 'GIT_PREFLIGHT_ALTERNATES_UNREADABLE' }
            foreach ($line in $atext.Replace("`r`n", "`n").Split("`n")) {
                $l = $line.Trim()
                if ($l -eq '' -or $l.StartsWith('#')) { continue }
                if ($l.StartsWith('"')) { return 'GIT_PREFLIGHT_ALTERNATES_QUOTED' }
                $a = Resolve-AtmGitReferencedPath -Value $l -BaseDir $objDir
                if ($a.Status -ne 'OK') { return $(if ($a.Status -eq 'MISSING') { 'GIT_PREFLIGHT_ALTERNATE_MISSING' } else { 'GIT_PREFLIGHT_ALTERNATE_' + $a.Reason.Substring('GIT_REF_PATH_'.Length) }) }
                $alts++
                $pin.Add($a.Path)
                if ($alts -gt $script:AtmGitAlternatesMax -or $depth + 1 -gt $script:AtmGitAlternatesMaxDepth) { return 'GIT_PREFLIGHT_ALTERNATES_LIMIT' }
                $k = $a.Path.ToLowerInvariant()
                if (-not $seen.ContainsKey($k)) { $seen[$k] = $true; $queue.Enqueue(@($a.Path, ($depth + 1))) }
            }
        }
        return $null
    } finally { $Result.Alternates = $alts; $Result.PinsAfter = $pin.ToArray() }
}

function Get-AtmGitAdminEntriesCheck {
    # Fills -Result.Admin (Name, Gitdir, Locked, HasHead); returns a refusal code or $null.
    param([string]$CommonDir, $Result)
    $admin = New-Object System.Collections.Generic.List[object]
    $wtRoot = Resolve-AtmGitReferencedPath -Value 'worktrees' -BaseDir $CommonDir
    if ($wtRoot.Status -eq 'REFUSED') { return $wtRoot.Reason }
    if ($wtRoot.Status -ne 'OK') { $Result.Admin = @(); return $null }
    $names = @()
    try { $names = @([IO.Directory]::GetDirectories($wtRoot.Path) | ForEach-Object { [IO.Path]::GetFileName($_) } | Sort-Object) } catch { return 'GIT_PREFLIGHT_ADMIN_UNREADABLE' }
    if ($names.Count -gt $script:AtmGitAdminEntriesMax) { return 'GIT_PREFLIGHT_ADMIN_LIMIT' }
    foreach ($n in $names) {
        $entryDir = Resolve-AtmGitReferencedPath -Value $n -BaseDir $wtRoot.Path
        if ($entryDir.Status -ne 'OK') { return $entryDir.Reason }
        $gf = Resolve-AtmGitReferencedPath -Value 'gitdir' -BaseDir $entryDir.Path
        $g = [pscustomobject]@{ Status = 'MISSING'; Reason = 'GIT_ADMIN_GITDIR_FILE_MISSING'; Path = $null }
        if ($gf.Status -eq 'OK') {
            $gtext = Read-AtmGitSmallFile -Path $gf.Path -MaxBytes 4096
            $gav = Get-AtmGitExactPathText $gtext
            if ($null -eq $gav) { return 'GIT_PREFLIGHT_ADMIN_GITDIR_INVALID' }
            $g = Resolve-AtmGitReferencedPath -Value $gav -BaseDir $entryDir.Path
            # A network or reparse gitdir would be stat-ed by `worktree list`: the whole repository is refused.
            if ($g.Status -eq 'REFUSED') { return ('GIT_PREFLIGHT_ADMIN_' + $g.Reason.Substring('GIT_REF_PATH_'.Length)) }
        } elseif ($gf.Status -eq 'REFUSED') { return $gf.Reason }
        # A lock is recorded by its presence only: its reason is never read here. `worktree list` reads the lock and
        # the entry's HEAD, so either one being a link or otherwise refused refuses the repository.
        $lk = Resolve-AtmGitReferencedPath -Value 'locked' -BaseDir $entryDir.Path
        $hd = Resolve-AtmGitReferencedPath -Value 'HEAD' -BaseDir $entryDir.Path
        if ($lk.Status -eq 'REFUSED' -or $hd.Status -eq 'REFUSED') { return ('GIT_PREFLIGHT_ADMIN_' + $(if ($lk.Status -eq 'REFUSED') { $lk.Reason } else { $hd.Reason }).Substring('GIT_REF_PATH_'.Length)) }
        $admin.Add([pscustomobject]@{ Name = $n; Gitdir = $g; Locked = ($lk.Status -eq 'OK'); HasHead = ($hd.Status -eq 'OK') })
    }
    $Result.Admin = $admin.ToArray()
    return $null
}

function Get-AtmGitPreflight {
    <#
      File-based check of a target directory before any Git call (P3-B0); no Git process. Reads, through
      Resolve-AtmGitReferencedPath: the target's .git (directory, or a `gitdir:` file), commondir, the configuration
      (common config and config.worktree, strict parser), every administrative entry's gitdir (stat-ed by `worktree
      list`) and the alternates chain (bounded). Status: OK, NOT_A_REPOSITORY (no .git entry in the target), or REFUSED
      with a reason code. StatusAllowed is $true only when no filter driver, textconv, submodule or .gitmodules is present
      (D-3). AdminEntries: Name, Gitdir (Status OK | MISSING | REFUSED), Locked (presence of the lock only), HasHead. Nothing is
      exported: callers turn this into codes and pseudonyms.
    #>
    param([string]$Target, [hashtable]$Cache = $null)
    $out = [ordered]@{ Status = 'REFUSED'; Reason = $null; WorkTree = $null; GitDir = $null; CommonDir = $null; StatusAllowed = $false; StatusBlock = $null; AdminEntries = @(); Alternates = 0; Bare = $false; PinPaths = @() }
    # P3-C0: the files (and alternate object directories) Git reads to set up the repository and its configuration, in
    # the order checked; the runner pins them for the whole call. Pinning files, not their directories, still prevents
    # renaming any directory above them, and leaves index and ref updates by other processes possible.
    $pin = New-Object System.Collections.Generic.List[string]
    $t = Resolve-AtmGitReferencedPath -Value $Target -BaseDir $null
    if ($t.Status -ne 'OK') { $out.Reason = $(if ($t.Status -eq 'MISSING') { 'GIT_PREFLIGHT_TARGET_MISSING' } else { $t.Reason }); return [pscustomobject]$out }
    $target = $t.Path
    try { if (([IO.File]::GetAttributes($target) -band [IO.FileAttributes]::Directory) -eq 0) { $out.Reason = 'GIT_PREFLIGHT_TARGET_NOT_DIRECTORY'; return [pscustomobject]$out } } catch { $out.Reason = 'GIT_REF_PATH_UNREADABLE'; return [pscustomobject]$out }
    $dotGit = Resolve-AtmGitReferencedPath -Value '.git' -BaseDir $target
    if ($dotGit.Status -eq 'MISSING') { $out.Status = 'NOT_A_REPOSITORY'; $out.Reason = 'GIT_PREFLIGHT_NO_GIT_ENTRY'; return [pscustomobject]$out }
    if ($dotGit.Status -ne 'OK') { $out.Reason = $dotGit.Reason; return [pscustomobject]$out }
    # When <target>\.git is not a Git directory Git tries <target> itself as a bare repository (and reads its config,
    # which this preflight would not have checked); Git needs HEAD, objects and refs there: a target holding all three
    # (or one that cannot be checked) is refused.
    $selfGit = @(@('HEAD', 'objects', 'refs') | ForEach-Object { (Resolve-AtmGitReferencedPath -Value $_ -BaseDir $target).Status })
    if ($selfGit -contains 'REFUSED' -or $selfGit -notcontains 'MISSING') { $out.Reason = 'GIT_PREFLIGHT_TARGET_IS_GITDIR'; return [pscustomobject]$out }
    $isDir = $false
    try { $isDir = (([IO.File]::GetAttributes($dotGit.Path) -band [IO.FileAttributes]::Directory) -ne 0) } catch { $out.Reason = 'GIT_REF_PATH_UNREADABLE'; return [pscustomobject]$out }
    if ($isDir) { $gitDir = $dotGit.Path }
    else {
        $pin.Add($dotGit.Path)
        $txt = Read-AtmGitSmallFile -Path $dotGit.Path -MaxBytes 4096
        $gv = $(if ($null -ne $txt -and $txt.StartsWith('gitdir: ')) { Get-AtmGitExactPathText $txt.Substring(8) } else { $null })
        if ($null -eq $gv) { $out.Reason = 'GIT_PREFLIGHT_GITFILE_INVALID'; return [pscustomobject]$out }
        $g = Resolve-AtmGitReferencedPath -Value $gv -BaseDir $target
        if ($g.Status -eq 'MISSING') { $out.Reason = 'GIT_PREFLIGHT_GITDIR_MISSING'; $out.GitDir = $g.Path; return [pscustomobject]$out }
        if ($g.Status -ne 'OK') { $out.Reason = 'GIT_PREFLIGHT_GITDIR_' + $g.Reason.Substring('GIT_REF_PATH_'.Length); return [pscustomobject]$out }
        $gitDir = $g.Path
    }
    $commonDir = $gitDir
    $cd = Resolve-AtmGitReferencedPath -Value 'commondir' -BaseDir $gitDir
    if ($cd.Status -eq 'OK') {
        $ctext = Read-AtmGitSmallFile -Path $cd.Path -MaxBytes 4096
        $pin.Add($cd.Path)
        $cv = Get-AtmGitExactPathText $ctext
        if ($null -eq $cv) { $out.Reason = 'GIT_PREFLIGHT_COMMONDIR_INVALID'; return [pscustomobject]$out }
        $c = Resolve-AtmGitReferencedPath -Value $cv -BaseDir $gitDir
        if ($c.Status -ne 'OK') { $out.Reason = $(if ($c.Status -eq 'MISSING') { 'GIT_PREFLIGHT_COMMONDIR_MISSING' } else { 'GIT_PREFLIGHT_COMMONDIR_' + $c.Reason.Substring('GIT_REF_PATH_'.Length) }); return [pscustomobject]$out }
        $commonDir = $c.Path
    } elseif ($cd.Status -eq 'REFUSED') { $out.Reason = $cd.Reason; return [pscustomobject]$out }
    # A Git directory as Git validates it: HEAD (a symbolic ref under refs/ or an object id), objects and refs in the
    # common directory. Otherwise Git would not use it (and could fall back to the target, refused above).
    $head = Resolve-AtmGitReferencedPath -Value 'HEAD' -BaseDir $gitDir
    $htext = $(if ($head.Status -eq 'OK') { Read-AtmGitSmallFile -Path $head.Path -MaxBytes 4096 } else { $null })
    if ($null -eq $htext -or $htext.Trim() -notmatch '^(ref: refs/\S+|[0-9a-f]{40}|[0-9a-f]{64})$') { $out.Reason = 'GIT_PREFLIGHT_GITDIR_INVALID'; return [pscustomobject]$out }
    $pin.Add($head.Path)
    # The part of the check that depends only on the common directory (references, objects, common configuration,
    # alternates, administrative entries) is shared by every worktree of the repository: computed once per run when
    # -Cache is given (discovery), recomputed whenever its fingerprint changes. The runner never passes a cache.
    $common = Get-AtmGitCommonPreflight -CommonDir $commonDir -Cache $Cache
    if ($common.Reason) { $out.Reason = $common.Reason; return [pscustomobject]$out }
    foreach ($x in $common.PinsBefore) { $pin.Add($x) }
    $entries = New-Object System.Collections.Generic.List[object]
    foreach ($e in $common.Entries) { $entries.Add($e) }
    # Configuration of this worktree: config.worktree (read by Git when the extension is on).
    $f = Resolve-AtmGitReferencedPath -Value 'config.worktree' -BaseDir $gitDir
    if ($f.Status -eq 'OK') {
        $pin.Add($f.Path)
        $text = Read-AtmGitSmallFile -Path $f.Path -MaxBytes $script:AtmGitConfigMaxBytes
        if ($null -eq $text) { $out.Reason = 'GIT_CONFIG_UNREADABLE'; return [pscustomobject]$out }
        $parsed = Read-AtmGitConfigText -Text $text
        if ($parsed.Error) { $out.Reason = $parsed.Error; return [pscustomobject]$out }
        foreach ($e in $parsed.Entries) { $entries.Add($e) }
    } elseif ($f.Status -ne 'MISSING') { $out.Reason = $f.Reason; return [pscustomobject]$out }
    $cf = Get-AtmGitConfigFindings -Entries $entries.ToArray() -BaseDir $target
    if ($cf.Refuse) { $out.Reason = $cf.Refuse; return [pscustomobject]$out }
    $bare = @($entries | Where-Object { $_.Section -eq 'core' -and $_.Key -eq 'bare' -and $_.Value -match '^(true|yes|on|1)$' }).Count -gt 0
    if ($common.AlternatesReason) { $out.Reason = $common.AlternatesReason; return [pscustomobject]$out }
    foreach ($x in $common.PinsAfter) { $pin.Add($x) }
    if ($common.AdminReason) { $out.Reason = $common.AdminReason; return [pscustomobject]$out }
    $alts = $common.Alternates
    $admin = $common.Admin
    # D-3 for `status`: submodules declared in the work tree also block it.
    $block = $cf.StatusBlock
    if ($null -eq $block -and -not $bare) {
        $gm = Resolve-AtmGitReferencedPath -Value '.gitmodules' -BaseDir $target
        if ($gm.Status -eq 'OK') { $block = 'D3_SUBMODULES' } elseif ($gm.Status -eq 'REFUSED') { $block = 'D3_GITMODULES_UNREADABLE' }
    }
    $out.Status = 'OK'; $out.Reason = $null; $out.WorkTree = $(if ($bare) { $null } else { $target }); $out.GitDir = $gitDir; $out.CommonDir = $commonDir
    $out.StatusAllowed = ($null -eq $block -and -not $bare); $out.StatusBlock = $(if ($bare) { 'D3_BARE_REPOSITORY' } else { $block }); $out.AdminEntries = @($admin); $out.Alternates = $alts; $out.Bare = $bare; $out.PinPaths = $pin.ToArray()
    return [pscustomobject]$out
}

# ---------------------------------------------------------------------------------------------
# Worktree discovery and registration (ADR-0007, P3-B), behind the worktree diagnostics gate. Sources (closed list):
# temporary partitions (the root and its direct children), and explicit paths; each start resolves upwards to the first
# `.git` (at most -MaxWalkLevels levels, never through a reparse point). Every candidate passes Get-AtmGitPreflight
# before anything else; a refused one is reported, never given to Git. Registration comes from the administrative
# entries (files) and, when Git is available, `rev-parse` and `worktree list` confirm it. Findings carry pseudonyms only
# (ADR-0010 rule: `git/r-<32 hex>` repositories, `git/w-<32 hex>` worktrees); no path, branch or Git output leaves the
# engine. Local work (P3-C) and publication (P3-D) are not diagnosed: every worktree states that its local work is
# unknown, and no state makes a directory disposable.
# ---------------------------------------------------------------------------------------------

$script:AtmDiscoveryMaxWalkLevels = 64
$script:AtmDiscoveryMaxRepositories = 200
$script:AtmDiscoveryMaxWorktreesPerRepository = 1000
$script:AtmDiscoveryMaxCandidates = 1000
# P3-E: bytes the discovery may read in one run (repository files only); beyond it the run stops early (PARTIAL).
$script:AtmDiscoveryMaxBytesRead = 268435456
$script:AtmWorktreeReasonCodes = @('DISCOVERY_BOUNDED', 'WORKTREE_DIAGNOSTICS_GATE_CLOSED', 'REPOSITORY_LIMIT', 'WORKTREE_LIMIT', 'PREFLIGHT_REFUSED_TARGETS', 'EXPLICIT_PATH_INVALID',
    'WALK_LIMIT', 'WALK_REFUSED', 'PARTITION_UNREADABLE', 'GIT_NOT_FOUND', 'GIT_VERSION_TOO_OLD', 'GIT_LOCATION_NOT_TRUSTED', 'GIT_VERSION_UNREADABLE', 'GIT_CALLS_INCOMPLETE',
    'DEADLINE_EXCEEDED', 'CANDIDATE_LIMIT', 'READ_BUDGET')
$script:AtmWorktreeEvidenceCodes = @('REPOSITORY_DISCOVERED', 'REPOSITORY_PREFLIGHT_REFUSED', 'REPOSITORY_CONFIRMED_BY_GIT', 'REPOSITORY_MISMATCH', 'GIT_NOT_RUN', 'ALTERNATES', 'WORKTREES_REGISTERED',
    'WORKTREE_MAIN', 'WORKTREE_REGISTERED', 'WORKTREE_LOCKED', 'WORKTREE_DIRECTORY_MISSING', 'ADMINISTRATIVE_ENTRY_NOT_FOUND', 'LOCAL_WORK_UNKNOWN', 'IN_REPOSITORY',
    'STAGED', 'UNSTAGED', 'UNTRACKED', 'IGNORED', 'CONFLICTS', 'SUBMODULES', 'OPERATION_IN_PROGRESS', 'STASHES_IN_REPOSITORY', 'STASH_MENTIONS_BRANCH',
    'LOCAL_WORK_NONE_OBSERVED', 'LOCAL_WORK_NOT_OBSERVED', 'PUBLICATION_NOT_DIAGNOSED',
    'HEAD_STATE', 'UPSTREAM_CONFIGURED', 'NO_UPSTREAM', 'NO_REMOTE_TRACKING_REFS', 'PUBLICATION_UNVERIFIED', 'PUBLICATION_UNKNOWN', 'PUBLICATION_NOT_OBSERVED',
    'DETACHED_TIP_REFERENCED', 'COMMITS_ONLY_IN_THIS_WORKTREE_POSSIBLE', 'LAST_FETCH_AGE_DAYS', 'REPOSITORY_NOT_EXAMINED')
# P3-C: local work (ADR-0006 rules 9 and 12). Operation markers in a worktree's Git directory, read as files.
$script:AtmGitOperationMarkers = [ordered]@{ 'MERGE_HEAD' = 'MERGE'; 'rebase-merge' = 'REBASE'; 'rebase-apply' = 'REBASE'; 'CHERRY_PICK_HEAD' = 'CHERRY_PICK'; 'REVERT_HEAD' = 'REVERT'; 'BISECT_LOG' = 'BISECT'; 'sequencer' = 'SEQUENCER' }
$script:AtmGitStashLogMaxBytes = 1048576
$script:AtmGitStatusArguments = @('status', '--porcelain=v2', '-z', '--untracked-files=normal', '--ignored=matching', '--ignore-submodules=all', '--no-renames')
$script:AtmLocalWorkReasonCodes = @('STATUS_NOT_RUN', 'STATUS_INCOMPLETE', 'FILES_INCOMPLETE', 'WORKTREE_OUTSIDE_SOURCES', 'HIDDEN_ENTRIES_NOT_OBSERVED', 'STASH_NOT_ATTRIBUTABLE', 'STASH_REF_WITHOUT_LOG', 'PACKED_REFS_UNREADABLE')

function Find-AtmGitStart {
    # The first directory at or above -Start whose `.git` resolves (Resolve-AtmGitReferencedPath), at most -MaxLevels
    # levels up, stopping at the drive root. Status: FOUND (Path), NONE, REFUSED (a reparse point or network form on the
    # way) or LIMIT.
    param([string]$Start, [int]$MaxLevels)
    $cur = $Start
    for ($i = 0; $i -le $MaxLevels; $i++) {
        $g = Resolve-AtmGitReferencedPath -Value '.git' -BaseDir $cur
        if ($g.Status -eq 'OK') { return [pscustomobject]@{ Status = 'FOUND'; Path = $cur } }
        if ($g.Status -eq 'REFUSED') { return [pscustomobject]@{ Status = 'REFUSED'; Path = $null } }
        $parent = [IO.Path]::GetDirectoryName($cur.TrimEnd('\'))
        if ([string]::IsNullOrEmpty($parent) -or $cur.Length -le 3) { return [pscustomobject]@{ Status = 'NONE'; Path = $null } }
        $cur = $parent
    }
    return [pscustomobject]@{ Status = 'LIMIT'; Path = $null }
}

function ConvertFrom-AtmGitStatusV2 {
    # Counts from `status --porcelain=v2 -z` (in memory only: no path, branch or name leaves this function): Staged,
    # Unstaged, Untracked, Ignored, Conflicts, Submodules (entries, so an untracked or ignored directory counts once).
    # Error is GIT_STATUS_UNPARSEABLE for any record it does not recognize; the counts are then not to be used.
    param([string]$Text)
    $c = [ordered]@{ Staged = 0; Unstaged = 0; Untracked = 0; Ignored = 0; Conflicts = 0; Submodules = 0; Error = $null }
    $toks = ([string]$Text).Split([char]0)
    $i = 0
    while ($i -lt $toks.Length) {
        $t = $toks[$i]; $i++
        if ($t -eq '' -or $t.StartsWith('# ')) { continue }
        if ($t.Length -lt 3 -or $t[1] -ne ' ') { $c.Error = 'GIT_STATUS_UNPARSEABLE'; break }
        switch -CaseSensitive ([string]$t[0]) {
            '?' { $c.Untracked++ }
            '!' { $c.Ignored++ }
            'u' {
                $f = $t.Split(' ', 11)
                if ($f.Length -lt 11 -or $f[2].Length -ne 4) { $c.Error = 'GIT_STATUS_UNPARSEABLE'; break }
                $c.Conflicts++
                if ($f[2][0] -eq 'S') { $c.Submodules++ }
            }
            default {
                # 1: ordinary change (9 fields); 2: rename or copy (10 fields, then the original path as its own record).
                $n = $(if ($t[0] -eq '1') { 9 } elseif ($t[0] -eq '2') { 10 } else { 0 })
                $f = $(if ($n -gt 0) { $t.Split(' ', $n) } else { @() })
                if ($n -eq 0 -or $f.Length -lt $n -or $f[1].Length -ne 2 -or $f[2].Length -ne 4) { $c.Error = 'GIT_STATUS_UNPARSEABLE'; break }
                if ($f[1][0] -ne '.') { $c.Staged++ }
                if ($f[1][1] -ne '.') { $c.Unstaged++ }
                if ($f[2][0] -eq 'S') { $c.Submodules++ }
                if ($n -eq 10) { if ($i -ge $toks.Length) { $c.Error = 'GIT_STATUS_UNPARSEABLE'; break }; $i++ }
            }
        }
        if ($c.Error) { break }
    }
    return [pscustomobject]$c
}

function Get-AtmGitStashSummary {
    # The stash reflog of a repository (<common>\logs\refs\stash), read as a file through the resolver (ADR-0006 rule 9):
    # Status COMPLETE | NOT_PRESENT | PARTIAL (larger than AtmGitStashLogMaxBytes) | FAILED (refused or unreadable),
    # Count (entries), Branches (the branch each entry was made on, from "WIP on <b>:" / "On <b>:", in memory only).
    param([string]$CommonDir)
    $out = [ordered]@{ Status = 'FAILED'; Reason = $null; Count = 0; Branches = @() }
    $f = Resolve-AtmGitReferencedPath -Value 'logs\refs\stash' -BaseDir $CommonDir
    # A stash ref without its reflog (expired, or written directly) holds stashes that cannot be counted.
    $refPresent = $false
    $lr = Resolve-AtmGitReferencedPath -Value 'refs\stash' -BaseDir $CommonDir
    if ($lr.Status -eq 'OK') { $refPresent = $true } elseif ($lr.Status -eq 'REFUSED') { $out.Reason = $lr.Reason; return [pscustomobject]$out }
    $pr = Resolve-AtmGitReferencedPath -Value 'packed-refs' -BaseDir $CommonDir
    if ($pr.Status -eq 'OK') {
        $ptext = Read-AtmGitSmallFile -Path $pr.Path -MaxBytes $script:AtmGitStashLogMaxBytes
        if ($null -eq $ptext) { $out.Status = 'PARTIAL'; $out.Reason = 'PACKED_REFS_UNREADABLE'; return [pscustomobject]$out }
        if ($ptext -match '(?m)^[0-9a-f]{40,64} refs/stash\r?$') { $refPresent = $true }
    } elseif ($pr.Status -eq 'REFUSED') { $out.Reason = $pr.Reason; return [pscustomobject]$out }
    if ($f.Status -eq 'MISSING') {
        if ($refPresent) { $out.Status = 'PARTIAL'; $out.Reason = 'STASH_REF_WITHOUT_LOG' } else { $out.Status = 'NOT_PRESENT' }
        return [pscustomobject]$out
    }
    if ($f.Status -ne 'OK') { $out.Reason = $f.Reason; return [pscustomobject]$out }
    try { $len = (New-Object IO.FileInfo($f.Path)).Length } catch { $out.Reason = 'GIT_REF_PATH_UNREADABLE'; return [pscustomobject]$out }
    if ($len -gt $script:AtmGitStashLogMaxBytes) { $out.Status = 'PARTIAL'; $out.Reason = 'STASH_LOG_TOO_LARGE'; return [pscustomobject]$out }
    $text = Read-AtmGitSmallFile -Path $f.Path -MaxBytes $script:AtmGitStashLogMaxBytes
    if ($null -eq $text) { $out.Reason = 'GIT_REF_PATH_UNREADABLE'; return [pscustomobject]$out }
    $br = New-Object System.Collections.Generic.List[string]
    foreach ($line in $text.Replace("`r`n", "`n").Split("`n")) {
        if ($line -eq '') { continue }
        $out.Count++
        $tab = $line.IndexOf("`t")
        $msg = $(if ($tab -ge 0) { $line.Substring($tab + 1) } else { '' })
        if ($msg -match '^(?:WIP on|On) ([^:]+):') { $br.Add($Matches[1]) } else { $br.Add('') }
    }
    if ($out.Count -eq 0 -and $refPresent) { $out.Status = 'PARTIAL'; $out.Reason = 'STASH_REF_WITHOUT_LOG'; return [pscustomobject]$out }
    $out.Status = 'COMPLETE'; $out.Branches = $br.ToArray()
    return [pscustomobject]$out
}

$script:AtmGitPackedRefsTraits = @('peeled', 'fully-peeled', 'sorted')
$script:AtmGitPackedRefsMaxBytes = 16777216
$script:AtmPublicationReasonCodes = @('REF_STORE_UNSUPPORTED', 'REF_STORE_UNSTABLE', 'REF_STORE_FAILED', 'REF_STORE_LIMIT', 'HEAD_UNREADABLE', 'REACHABILITY_NOT_READ', 'NO_REMOTE_TRACKING_REFS', 'HEAD_TIP_ON_REMOTE_TRACKING', 'HEAD_BRANCH_NOT_FOUND', 'NO_WORKTREE_OBSERVED')

function Read-AtmGitHead {
    # A worktree's HEAD, read through the resolver from its Git directory: Kind BRANCH (Value: the branch name, in memory
    # only) | DETACHED (Value: the object id) | UNREADABLE (missing, refused, not a plain file, or not in a known form).
    param([string]$GitDir)
    $r = Resolve-AtmGitReferencedPath -Value 'HEAD' -BaseDir $GitDir
    $t = $null
    if ($r.Status -eq 'OK') {
        $isFile = $false
        try { $isFile = (([IO.File]::GetAttributes($r.Path) -band [IO.FileAttributes]::Directory) -eq 0) } catch { $isFile = $false }
        if ($isFile) { $t = Read-AtmGitSmallFile -Path $r.Path -MaxBytes 4096 }
    }
    if ($null -ne $t) {
        $v = $t.TrimEnd([char[]]"`r`n")
        if ($v -cmatch '^ref: refs/heads/(\S+)$') { return [pscustomobject]@{ Kind = 'BRANCH'; Value = $Matches[1] } }
        if ($v -cmatch '^([0-9a-f]{40}|[0-9a-f]{64})$') { return [pscustomobject]@{ Kind = 'DETACHED'; Value = $Matches[1] } }
    }
    return [pscustomobject]@{ Kind = 'UNREADABLE'; Value = $null }
}

function Get-AtmWorktreeStashAttribution {
    # Stashes of a repository attributed to one worktree (ADR-0006 rule 12): only entries made on its branch. Returns
    # Code (STASH_MENTIONS_BRANCH with Count, STASH_NOT_ATTRIBUTABLE when HEAD is detached or unreadable, or $null when
    # nothing is attributed) and Complete ($false when a stash may belong here and that cannot be told).
    param([string]$GitDir, $Stash)
    if ($null -eq $Stash -or $Stash.Status -cne 'COMPLETE' -or $Stash.Count -eq 0) { return [pscustomobject]@{ Code = $null; Count = 0; Complete = ($null -eq $Stash -or $Stash.Status -ceq 'COMPLETE' -or $Stash.Status -ceq 'NOT_PRESENT') } }
    $h = Read-AtmGitHead -GitDir $GitDir
    if ($h.Kind -cne 'BRANCH') { return [pscustomobject]@{ Code = 'STASH_NOT_ATTRIBUTABLE'; Count = 0; Complete = $false } }
    $n = @($Stash.Branches | Where-Object { [string]::Equals($_, $h.Value, [StringComparison]::Ordinal) }).Count
    return [pscustomobject]@{ Code = $(if ($n -gt 0) { 'STASH_MENTIONS_BRANCH' } else { $null }); Count = $n; Complete = $true }
}

function Get-AtmGitRefStore {
    <#
      The shared references of a repository, read as files from its common directory (P3-D; no Git): local branches
      (refs/heads), tags (refs/tags) and remote-tracking refs (refs/remotes), loose first, then packed-refs (a ref Git
      moves into packed-refs meanwhile is then seen in one of the two). Two full passes must agree, otherwise UNSTABLE.
      Status: COMPLETE | UNSUPPORTED (reftable, or a packed-refs trait it does not know) | FAILED (unreadable, a reparse
      point, a line it does not recognize, a packed-refs file not ending with a line break) | UNSTABLE | PARTIAL (more
      entries than AtmGitRefEntriesMax). Only COMPLETE may be used for any conclusion. Returns Local (branch -> id),
      Tags and Remote (sets of ids; a packed peeled id is added, a loose annotated tag is not peeled), Upstreams (branch
      names with branch.<name>.merge set), names in memory only. -ReadFile (tests) replaces the file reader.
    #>
    param([string]$CommonDir, [scriptblock]$ReadFile = $null)
    $out = [ordered]@{ Status = 'FAILED'; Reason = 'REF_STORE_FAILED'; Local = (New-Object Collections.Hashtable([StringComparer]::Ordinal)); Tags = @{}; Remote = @{}; Upstreams = @(); RemoteCount = 0; SymbolicBranches = @(); WorktreeConfig = $false }
    $script:AtmScaleStats.RefStoreReads++
    $read = $(if ($null -ne $ReadFile) { $ReadFile } else { { param([string]$P, [int]$Max) Read-AtmGitSmallFile -Path $P -MaxBytes $Max } })
    # Configuration: the reference storage and the upstreams.
    $cfgPath = Resolve-AtmGitReferencedPath -Value 'config' -BaseDir $CommonDir
    $entries = @()
    if ($cfgPath.Status -eq 'OK') {
        $ct = & $read $cfgPath.Path $script:AtmGitConfigMaxBytes
        if ($null -eq $ct) { return [pscustomobject]$out }
        $pc = Read-AtmGitConfigText -Text $ct
        if ($pc.Error) { return [pscustomobject]$out }
        $entries = @($pc.Entries)
    } elseif ($cfgPath.Status -ne 'MISSING') { return [pscustomobject]$out }
    $rs = @($entries | Where-Object { $_.Section -eq 'extensions' -and $_.Key -eq 'refstorage' })
    $rt = Resolve-AtmGitReferencedPath -Value 'reftable' -BaseDir $CommonDir
    if (@($rs | Where-Object { $_.Value -ine 'files' }).Count -gt 0 -or $rt.Status -ne 'MISSING') { $out.Status = 'UNSUPPORTED'; $out.Reason = 'REF_STORE_UNSUPPORTED'; return [pscustomobject]$out }
    $out.Upstreams = @($entries | Where-Object { $_.Section -eq 'branch' -and $_.Key -eq 'merge' -and $_.Value } | ForEach-Object { $_.Subsection } | Select-Object -Unique)
    $out.WorktreeConfig = (@($entries | Where-Object { $_.Section -eq 'extensions' -and $_.Key -eq 'worktreeconfig' -and $_.Value -match '^(true|yes|on|1)$' }).Count -gt 0)
    $idPattern = '^([0-9a-f]{40}|[0-9a-f]{64})$'
    $pass = {
        $refs = New-Object 'System.Collections.Generic.SortedDictionary[string,string]' ([StringComparer]::Ordinal)
        $peeled = New-Object System.Collections.Generic.List[string]
        $sym = New-Object System.Collections.Generic.List[string]
        $count = 0
        foreach ($top in @('refs\heads', 'refs\tags', 'refs\remotes')) {
            $root = Resolve-AtmGitReferencedPath -Value $top -BaseDir $CommonDir
            if ($root.Status -eq 'MISSING') { continue }
            if ($root.Status -ne 'OK') { return 'REF_STORE_FAILED' }
            $stack = New-Object System.Collections.Generic.Stack[string]
            $stack.Push($root.Path)
            while ($stack.Count -gt 0) {
                $d = $stack.Pop()
                try { $items = @((New-Object IO.DirectoryInfo($d)).EnumerateFileSystemInfos()) } catch { return 'REF_STORE_FAILED' }
                foreach ($fi in $items) {
                    $count++
                    if ($count -gt $script:AtmGitRefEntriesMax) { return 'REF_STORE_LIMIT' }
                    # Git ignores names starting with a dot and lock files.
                    if ($fi.Name.StartsWith('.') -or $fi.Name.EndsWith('.lock')) { continue }
                    # Every entry goes through the resolver (text checks, no reparse point in its chain) before it is used.
                    $er = Resolve-AtmGitReferencedPath -Value $fi.Name -BaseDir $d
                    if ($er.Status -eq 'MISSING') { return 'REF_STORE_UNSTABLE' }
                    if ($er.Status -ne 'OK') { return 'REF_STORE_FAILED' }
                    if (($fi.Attributes -band [IO.FileAttributes]::Directory) -ne 0) { $stack.Push($er.Path); continue }
                    $t = & $read $er.Path 4096
                    # A loose ref that disappears between the listing and the read moved meanwhile: not stable.
                    if ($null -eq $t) { if (-not [IO.File]::Exists($er.Path)) { return 'REF_STORE_UNSTABLE' }; return 'REF_STORE_FAILED' }
                    $v = $t.TrimEnd([char[]]"`n")
                    $name = ($er.Path.Substring($CommonDir.TrimEnd('\').Length + 1)).Replace('\', '/')
                    # A symbolic ref is not followed; a branch that is one is recorded (its HEAD then gives no tip).
                    if ($v.StartsWith('ref: ')) { if ($name -clike 'refs/heads/*') { $sym.Add($name.Substring(11)) }; continue }
                    if ($v -cnotmatch $idPattern -or -not $t.EndsWith("`n")) { return 'REF_STORE_FAILED' }
                    $refs[$name] = $v
                }
            }
        }
        $pr = Resolve-AtmGitReferencedPath -Value 'packed-refs' -BaseDir $CommonDir
        if ($pr.Status -eq 'OK') {
            $pt = & $read $pr.Path $script:AtmGitPackedRefsMaxBytes
            if ($null -eq $pt) { return 'REF_STORE_FAILED' }
            if ($pt.Length -gt 0 -and -not $pt.EndsWith("`n")) { return 'REF_STORE_FAILED' }
            $last = $null; $lastUsed = $false
            foreach ($line in $pt.TrimEnd([char[]]"`n").Split("`n")) {
                if ($line -eq '' -and $pt.Length -eq 0) { continue }
                if ($line.StartsWith('# pack-refs with:')) {
                    foreach ($tr in @($line.Substring(17).Trim().Split(' ') | Where-Object { $_ })) { if ($script:AtmGitPackedRefsTraits -cnotcontains $tr) { return 'REF_STORE_UNSUPPORTED' } }
                    continue
                }
                if ($line.StartsWith('^')) {
                    if ($null -eq $last -or $line.Substring(1) -cnotmatch $idPattern) { return 'REF_STORE_FAILED' }
                    # Only for a packed entry actually used: a loose ref overriding it makes its peeled id stale.
                    if ($lastUsed -and ($last -clike 'refs/tags/*' -or $last -clike 'refs/remotes/*')) { $peeled.Add($last + '|' + $line.Substring(1)) }
                    continue
                }
                $sp = $line.IndexOf(' ')
                if ($sp -le 0 -or $line.Substring(0, $sp) -cnotmatch $idPattern) { return 'REF_STORE_FAILED' }
                $n = $line.Substring($sp + 1)
                if ($n -cnotmatch '^refs/\S+$') { return 'REF_STORE_FAILED' }
                $last = $n
                $lastUsed = $false
                if (($n -clike 'refs/heads/*' -or $n -clike 'refs/tags/*' -or $n -clike 'refs/remotes/*') -and -not $refs.ContainsKey($n)) { $refs[$n] = $line.Substring(0, $sp); $lastUsed = $true }
            }
        } elseif ($pr.Status -ne 'MISSING') { return 'REF_STORE_FAILED' }
        return [pscustomobject]@{ Refs = $refs; Peeled = $peeled.ToArray(); Symbolic = $sym.ToArray() }
    }
    $a = & $pass
    if ($a -is [string]) { $out.Reason = $a; $out.Status = $(if ($a -ceq 'REF_STORE_UNSUPPORTED') { 'UNSUPPORTED' } elseif ($a -ceq 'REF_STORE_UNSTABLE') { 'UNSTABLE' } elseif ($a -ceq 'REF_STORE_LIMIT') { 'PARTIAL' } else { 'FAILED' }); return [pscustomobject]$out }
    $b = & $pass
    if ($b -is [string]) { $out.Reason = $b; $out.Status = $(if ($b -ceq 'REF_STORE_UNSUPPORTED') { 'UNSUPPORTED' } elseif ($b -ceq 'REF_STORE_LIMIT') { 'PARTIAL' } else { 'UNSTABLE' }); if ($out.Status -ceq 'UNSTABLE') { $out.Reason = 'REF_STORE_UNSTABLE' }; return [pscustomobject]$out }
    $sig = { param($x) (@($x.Refs.GetEnumerator() | ForEach-Object { $_.Key + '=' + $_.Value }) + @($x.Peeled) + @($x.Symbolic | ForEach-Object { 'sym:' + $_ })) -join "`n" }
    if ((& $sig $a) -cne (& $sig $b)) { $out.Status = 'UNSTABLE'; $out.Reason = 'REF_STORE_UNSTABLE'; return [pscustomobject]$out }
    foreach ($kv in $a.Refs.GetEnumerator()) {
        if ($kv.Key -clike 'refs/heads/*') { $out.Local[$kv.Key.Substring(11)] = $kv.Value }
        elseif ($kv.Key -clike 'refs/tags/*') { $out.Tags[$kv.Value] = $true }
        elseif ($kv.Key -clike 'refs/remotes/*') { $out.Remote[$kv.Value] = $true; $out.RemoteCount++ }
    }
    foreach ($pe in $a.Peeled) { $i = $pe.IndexOf('|'); $id = $pe.Substring($i + 1); if ($pe -clike 'refs/tags/*') { $out.Tags[$id] = $true } else { $out.Remote[$id] = $true } }
    $out.SymbolicBranches = @($a.Symbolic)
    $out.Status = 'COMPLETE'; $out.Reason = $null
    return [pscustomobject]$out
}

function Get-AtmWorktreePublication {
    <#
      Publication facts of one worktree from files only (P3-D; ADR-0006 rule 13; no network, no Git, no object read).
      -GitDir: the worktree's Git directory (its HEAD); -RefStore: Get-AtmGitRefStore of its repository; -CommonDir for
      FETCH_HEAD. Observations only, on a COMPLETE ref store, and never a publication state: NO_REMOTE_TRACKING_REFS (the
      repository holds no remote-tracking reference; that is NOT proof that the commits were never published: they may
      have been pushed and the local references removed, or pushed without tracking references), PUBLICATION_UNVERIFIED
      (HEAD_TIP_ON_REMOTE_TRACKING: the tip equals a remote-tracking ref, which is never proof the server has it), a
      detached tip referenced by no ref is COMMITS_ONLY_IN_THIS_WORKTREE_POSSIBLE. Publication stays PUBLICATION_UNKNOWN
      unless a stronger proof exists (none from files). Returns Evidence and Coverage (Status + Reason).
    #>
    param([string]$GitDir, $RefStore, [string]$CommonDir)
    $now = [datetime]::UtcNow
    $ev = New-Object System.Collections.Generic.List[object]
    $add = { param([string]$Code, [string]$Detail) $ev.Add((New-AtmEvidence -Code $Code -Source 'publication' -Collector 'publication-files' -ObservedUtc $now -Detail $Detail)) }
    $res = [ordered]@{ Evidence = $null; Coverage = $null }
    $h = Read-AtmGitHead -GitDir $GitDir
    if ($h.Kind -ceq 'UNREADABLE') {
        & $add 'PUBLICATION_NOT_OBSERVED' 'HEAD_UNREADABLE'
        $res.Coverage = [pscustomobject]@{ Status = 'FAILED'; Reason = 'HEAD_UNREADABLE' }
        $res.Evidence = $ev.ToArray(); return [pscustomobject]$res
    }
    if ($null -eq $RefStore -or $RefStore.Status -cne 'COMPLETE') {
        & $add 'HEAD_STATE' $h.Kind
        $why = $(if ($null -eq $RefStore) { 'REF_STORE_FAILED' } else { [string]$RefStore.Reason })
        & $add 'PUBLICATION_NOT_OBSERVED' $why
        $res.Coverage = [pscustomobject]@{ Status = $(if ($null -ne $RefStore -and $RefStore.Status -ceq 'UNSUPPORTED') { 'NOT_OBSERVABLE' } else { 'PARTIAL' }); Reason = $why }
        $res.Evidence = $ev.ToArray(); return [pscustomobject]$res
    }
    $tip = $null
    if ($h.Kind -ceq 'BRANCH') {
        & $add 'HEAD_STATE' 'BRANCH'
        if (-not $RefStore.Local.ContainsKey($h.Value)) {
            # No tip for HEAD's branch: unborn, moved after the reference read (HEAD is read later, per worktree), or a
            # symbolic branch. They cannot be told apart, so nothing is claimed (never "no commits").
            & $add 'PUBLICATION_NOT_OBSERVED' 'HEAD_BRANCH_NOT_FOUND'
            $res.Coverage = [pscustomobject]@{ Status = 'PARTIAL'; Reason = 'HEAD_BRANCH_NOT_FOUND' }
            $res.Evidence = $ev.ToArray(); return [pscustomobject]$res
        }
        $tip = $RefStore.Local[$h.Value]
        $up = (@($RefStore.Upstreams) -ccontains $h.Value)
        $upKnown = $true
        if (-not $up -and $RefStore.WorktreeConfig) {
            # extensions.worktreeConfig: the upstream may be set in this worktree's config.worktree.
            $upKnown = $false
            $wc = Resolve-AtmGitReferencedPath -Value 'config.worktree' -BaseDir $GitDir
            if ($wc.Status -eq 'MISSING') { $upKnown = $true }
            elseif ($wc.Status -eq 'OK') {
                $wt = Read-AtmGitSmallFile -Path $wc.Path -MaxBytes $script:AtmGitConfigMaxBytes
                $wp = $(if ($null -ne $wt) { Read-AtmGitConfigText -Text $wt } else { $null })
                if ($null -ne $wp -and -not $wp.Error) { $upKnown = $true; $up = (@($wp.Entries | Where-Object { $_.Section -eq 'branch' -and $_.Key -eq 'merge' -and $_.Value -and [string]::Equals($_.Subsection, $h.Value, [StringComparison]::Ordinal) }).Count -gt 0) }
            }
        }
        if ($up) { & $add 'UPSTREAM_CONFIGURED' $null } elseif ($upKnown) { & $add 'NO_UPSTREAM' $null }
    } else { $tip = $h.Value; & $add 'HEAD_STATE' 'DETACHED' }
    $res.Coverage = [pscustomobject]@{ Status = 'COMPLETE'; Reason = $null }
    if ($null -ne $tip) {
        # The absence of remote-tracking references is an observation, not proof of non-publication.
        if ($RefStore.RemoteCount -eq 0) { & $add 'NO_REMOTE_TRACKING_REFS' $null; & $add 'PUBLICATION_UNKNOWN' 'NO_REMOTE_TRACKING_REFS' }
        elseif ($RefStore.Remote.ContainsKey($tip)) { & $add 'PUBLICATION_UNVERIFIED' 'HEAD_TIP_ON_REMOTE_TRACKING' }
        else { & $add 'PUBLICATION_UNKNOWN' 'REACHABILITY_NOT_READ' }
        if ($h.Kind -ceq 'DETACHED') {
            $referenced = ($RefStore.Remote.ContainsKey($tip) -or $RefStore.Tags.ContainsKey($tip) -or @($RefStore.Local.Values) -ccontains $tip)
            if ($referenced) { & $add 'DETACHED_TIP_REFERENCED' $null } else { & $add 'COMMITS_ONLY_IN_THIS_WORKTREE_POSSIBLE' $null }
        }
    }
    # Informative only (ADR-0006 rule 13): days since the last fetch recorded by FETCH_HEAD.
    $fh = Resolve-AtmGitReferencedPath -Value 'FETCH_HEAD' -BaseDir $CommonDir
    if ($fh.Status -eq 'OK') { try { & $add 'LAST_FETCH_AGE_DAYS' ([string][int][Math]::Floor(($now - [IO.File]::GetLastWriteTimeUtc($fh.Path)).TotalDays)) } catch { } }
    $res.Evidence = $ev.ToArray()
    return [pscustomobject]$res
}

function Get-AtmWorktreeLocalWork {
    <#
      Local work facts of one worktree directory (P3-C; ADR-0006 rules 9 and 12), behind the worktree diagnostics gate.
      Files (through the resolver): in-progress operation markers in its Git directory, its branch (HEAD) to attribute
      stashes (-Stash: Get-AtmGitStashSummary of its repository; only entries that name its branch). Git (only with -Git
      usable, a preflight that allows `status` and before -Deadline): `status --porcelain=v2 -z`, counted in memory.
      Returns Evidence (codes and counts only), LocalWork ($true when any fact is positive), StatusCoverage and
      FilesCoverage (each Status + Reason). A fact that could not be observed is never zero.
    #>
    param([string]$WorkTree, $Git = $null, $Stash = $null, $Deadline = $null, $Preflight = $null)
    if (-not $script:AtmWorktreeDiagnosticsEnabled) {
        return [pscustomobject]@{ Evidence = @(); LocalWork = $false; StatusCoverage = [pscustomobject]@{ Status = 'NOT_OBSERVABLE'; Reason = 'WORKTREE_DIAGNOSTICS_GATE_CLOSED' }; FilesCoverage = [pscustomobject]@{ Status = 'NOT_OBSERVABLE'; Reason = 'WORKTREE_DIAGNOSTICS_GATE_CLOSED' } }
    }
    $now = [datetime]::UtcNow
    $ev = New-Object System.Collections.Generic.List[object]
    $add = { param([string]$Code, [string]$Collector, [string]$Detail) $ev.Add((New-AtmEvidence -Code $Code -Source 'local-work' -Collector $Collector -ObservedUtc $now -Detail $Detail)) }
    $res = [ordered]@{ Evidence = $null; LocalWork = $false; StatusCoverage = $null; FilesCoverage = $null; StatusRan = $false }
    $pf = $(if ($null -ne $Preflight) { $Preflight } else { Get-AtmGitPreflight -Target $WorkTree })
    if ($pf.Status -cne 'OK') {
        & $add 'LOCAL_WORK_NOT_OBSERVED' 'local-work-files' $(if ($pf.Reason) { [string]$pf.Reason } else { 'GIT_PREFLIGHT_REFUSED' })
        $res.StatusCoverage = [pscustomobject]@{ Status = 'NOT_OBSERVABLE'; Reason = 'STATUS_NOT_RUN' }
        $res.FilesCoverage = [pscustomobject]@{ Status = 'NOT_OBSERVABLE'; Reason = 'FILES_INCOMPLETE' }
        $res.Evidence = $ev.ToArray(); return [pscustomobject]$res
    }
    # Files: operation markers and the branch.
    $filesOk = $true
    $ops = New-Object System.Collections.Generic.List[string]
    foreach ($m in $script:AtmGitOperationMarkers.Keys) {
        $r = Resolve-AtmGitReferencedPath -Value $m -BaseDir $pf.GitDir
        if ($r.Status -eq 'OK') { $op = $script:AtmGitOperationMarkers[$m]; if (-not $ops.Contains($op)) { $ops.Add($op) } }
        elseif ($r.Status -ne 'MISSING') { $filesOk = $false }
    }
    foreach ($op in $ops) { & $add 'OPERATION_IN_PROGRESS' 'local-work-files' $op }
    if ($null -ne $Stash) {
        # Detached or unreadable HEAD: a stash of this repository may have been made here; it cannot be told.
        $sa = Get-AtmWorktreeStashAttribution -GitDir $pf.GitDir -Stash $Stash
        if ($sa.Code -ceq 'STASH_MENTIONS_BRANCH') { & $add 'STASH_MENTIONS_BRANCH' 'local-work-files' ([string]$sa.Count) }
        elseif ($sa.Code -ceq 'STASH_NOT_ATTRIBUTABLE') { & $add 'LOCAL_WORK_NOT_OBSERVED' 'local-work-files' 'STASH_NOT_ATTRIBUTABLE' }
        if (-not $sa.Complete) { $filesOk = $false }
    }
    $res.FilesCoverage = [pscustomobject]@{ Status = $(if ($filesOk) { 'COMPLETE' } else { 'PARTIAL' }); Reason = $(if ($filesOk) { $null } else { 'FILES_INCOMPLETE' }) }
    $positive = ($ops.Count -gt 0 -or @($ev | Where-Object { $_.Code -ceq 'STASH_MENTIONS_BRANCH' }).Count -gt 0)
    # Git: status counts.
    $statusDone = $false
    if ($null -eq $Git -or $Git.Status -cne 'COMPLETE') {
        $res.StatusCoverage = [pscustomobject]@{ Status = 'UNAVAILABLE'; Reason = $(if ($null -ne $Git -and $Git.Reason) { [string]$Git.Reason } else { 'GIT_NOT_FOUND' }) }
    } elseif (-not $pf.StatusAllowed) {
        if ($pf.StatusBlock -ceq 'D3_SUBMODULES') { & $add 'SUBMODULES' 'local-work-status' 'DECLARED' }
        & $add 'LOCAL_WORK_NOT_OBSERVED' 'local-work-status' ([string]$pf.StatusBlock)
        $res.StatusCoverage = [pscustomobject]@{ Status = 'NOT_OBSERVABLE'; Reason = [string]$pf.StatusBlock }
    } elseif ($null -ne $Deadline -and [datetime]::UtcNow -ge $Deadline) {
        $res.StatusCoverage = [pscustomobject]@{ Status = 'TIMEOUT'; Reason = 'DEADLINE_EXCEEDED' }
    } else {
        $st = Invoke-AtmGitCommand -Git $Git -Arguments $script:AtmGitStatusArguments -WorkingDirectory $pf.WorkTree -Preflight $pf
        if ($st.Status -ceq 'COMPLETE' -or $st.Status -ceq 'PARTIAL') {
            $c = ConvertFrom-AtmGitStatusV2 -Text $st.Output
            if ($c.Error) { $res.StatusCoverage = [pscustomobject]@{ Status = 'FAILED'; Reason = $c.Error } }
            else {
                # Truncated output: what was read is positive evidence (a lower bound); the rest is unknown.
                foreach ($k in @('Staged', 'Unstaged', 'Untracked', 'Ignored', 'Conflicts', 'Submodules')) { if ($c.$k -gt 0) { & $add $k.ToUpperInvariant() 'local-work-status' ([string]$c.$k) } }
                if ($c.Staged + $c.Unstaged + $c.Untracked + $c.Ignored + $c.Conflicts -gt 0) { $positive = $true }
                # Even complete, `status` does not show changes inside a gitlink (submodules ignored, and one can exist
                # without .gitmodules) or in entries flagged assume-unchanged or skip-worktree: never complete coverage.
                $res.StatusCoverage = [pscustomobject]@{ Status = 'PARTIAL'; Reason = $(if ($st.Status -ceq 'PARTIAL') { 'GIT_OUTPUT_TRUNCATED' } else { 'HIDDEN_ENTRIES_NOT_OBSERVED' }) }
                $statusDone = ($st.Status -ceq 'COMPLETE')
                $res.StatusRan = $statusDone
            }
        } else { $res.StatusCoverage = [pscustomobject]@{ Status = $(if ($st.Status -ceq 'TIMEOUT') { 'TIMEOUT' } elseif ($st.Status -ceq 'REFUSED') { 'NOT_OBSERVABLE' } else { 'FAILED' }); Reason = [string]$st.Reason } }
    }
    $res.LocalWork = $positive
    if (-not $positive) {
        if ($statusDone -and $filesOk) { & $add 'LOCAL_WORK_NONE_OBSERVED' 'local-work-status' $null }
        else { & $add 'LOCAL_WORK_UNKNOWN' 'local-work-status' $null }
    }
    $res.Evidence = $ev.ToArray()
    return [pscustomobject]$res
}

function Get-AtmWorktreeDiscovery {
    <#
      Repositories and worktrees reachable from -Partitions (V0.1 partitions: Path, Kind) and -RepositoryPaths (validated
      like V0.1 allow-list paths). -Git: Resolve-AtmGitExecutable (optional; without it nothing is confirmed by Git).
      -Pseudonymizer: New-AtmPseudonymizer. Caps (-MaxRepositories, -MaxWorktreesPerRepository, -MaxWalkLevels, -MaxCandidates:
      directories examined, refused ones included) and the deadline make the
      coverage PARTIAL. Returns Findings (Repository, Worktree; ordered by Kind and Key) and Coverage (worktree-discovery,
      git). Refused while the worktree diagnostics gate is closed (no file of any repository is read).
    #>
    param($Partitions = @(), [string[]]$RepositoryPaths = @(), $Git = $null, $Pseudonymizer, $Deadline = $null,
        [int]$MaxRepositories = $script:AtmDiscoveryMaxRepositories, [int]$MaxWorktreesPerRepository = $script:AtmDiscoveryMaxWorktreesPerRepository, [int]$MaxWalkLevels = $script:AtmDiscoveryMaxWalkLevels,
        [int]$MaxCandidates = $script:AtmDiscoveryMaxCandidates, [long]$MaxBytesRead = $script:AtmDiscoveryMaxBytesRead, [switch]$NoPreflightCache)
    $findings = New-Object System.Collections.Generic.List[object]
    $reasons = New-Object System.Collections.Generic.List[string]
    if (-not $script:AtmWorktreeDiagnosticsEnabled) {
        return [pscustomobject]@{ Findings = @(); Coverage = @((New-AtmCoverage -Collector 'worktree-discovery' -Status 'NOT_OBSERVABLE' -Reasons @('WORKTREE_DIAGNOSTICS_GATE_CLOSED') -ElevationWouldHelp 'NO')) }
    }
    $reasons.Add('DISCOVERY_BOUNDED')
    $now = [datetime]::UtcNow
    # P3-E: one run shares the common-directory part of the preflights (fingerprint-guarded) and reuses each
    # candidate's preflight for the same directory; counters for measurements (-NoPreflightCache: for comparison only).
    Reset-AtmScaleStats
    $pfCache = $(if ($NoPreflightCache) { $null } else { @{} })
    $pfByDir = @{}
    $reusePf = -not $NoPreflightCache
    $handleNodes = New-Object System.Collections.Generic.List[object]
    $budgetHit = { if ($script:AtmScaleStats.BytesRead -gt $MaxBytesRead) { if (-not $reasons.Contains('READ_BUDGET')) { $reasons.Add('READ_BUDGET') }; return $true }; return $false }
    $pz = { param([string]$Domain, [string]$Value) Get-AtmPseudonym -Pseudonymizer $Pseudonymizer -Domain $Domain -Fields @($Value.TrimEnd('\').ToLowerInvariant()) }
    $repoKey = { param([string]$CommonDir) 'git/r-' + (& $pz 'atm-repository/1' $CommonDir) }
    $wtKey = { param([string]$Dir) 'git/w-' + (& $pz 'atm-worktree/1' $Dir) }
    # Starting directories with their source.
    $starts = New-Object System.Collections.Generic.List[object]
    foreach ($part in @($Partitions | Where-Object { $null -ne $_ -and $_.Kind -ne 'NotScanned' -and $_.Path })) {
        $root = Resolve-AtmGitReferencedPath -Value ([string]$part.Path) -BaseDir $null
        if ($root.Status -ne 'OK') { if ($root.Status -eq 'REFUSED') { $reasons.Add('PARTITION_UNREADABLE') }; continue }
        $starts.Add([pscustomobject]@{ Dir = $root.Path; Source = 'PARTITION'; Walk = $false })
        $children = New-Object System.Collections.Generic.List[string]
        try {
            if (([IO.File]::GetAttributes($root.Path) -band [IO.FileAttributes]::Directory) -ne 0) {
                foreach ($ch in [IO.Directory]::EnumerateDirectories($root.Path)) { if ($children.Count -ge $MaxCandidates) { $reasons.Add('CANDIDATE_LIMIT'); break }; $children.Add($ch) }
            }
        } catch { $reasons.Add('PARTITION_UNREADABLE') }
        foreach ($ch in $children) {
            $c = Resolve-AtmGitReferencedPath -Value ([IO.Path]::GetFileName($ch)) -BaseDir $root.Path
            if ($c.Status -eq 'OK') { $starts.Add([pscustomobject]@{ Dir = $c.Path; Source = 'PARTITION'; Walk = $false }) }
        }
    }
    foreach ($rp in @($RepositoryPaths | Where-Object { $null -ne $_ })) {
        if ($null -ne (Test-AtmAllowListPathSyntax $rp)) { $reasons.Add('EXPLICIT_PATH_INVALID'); continue }
        $r = Resolve-AtmGitReferencedPath -Value $rp -BaseDir $null
        if ($r.Status -ne 'OK') { $reasons.Add('EXPLICIT_PATH_INVALID'); continue }
        $starts.Add([pscustomobject]@{ Dir = $r.Path; Source = 'EXPLICIT'; Walk = $true })
    }
    # Candidates: directories that hold a `.git` entry (explicit paths walk upwards).
    $cands = [ordered]@{}
    foreach ($s in $starts) {
        if ($null -ne $Deadline -and [datetime]::UtcNow -ge $Deadline) { $reasons.Add('DEADLINE_EXCEEDED'); break }
        $dir = $null
        if ($s.Walk) {
            $f = Find-AtmGitStart -Start $s.Dir -MaxLevels $MaxWalkLevels
            if ($f.Status -eq 'FOUND') { $dir = $f.Path } elseif ($f.Status -eq 'LIMIT') { $reasons.Add('WALK_LIMIT') } elseif ($f.Status -eq 'REFUSED') { $reasons.Add('WALK_REFUSED') }
        } elseif ((Resolve-AtmGitReferencedPath -Value '.git' -BaseDir $s.Dir).Status -eq 'OK') { $dir = $s.Dir }
        if ($null -eq $dir) { continue }
        $dir = Get-AtmNormalizedPath $dir
        if (-not $dir) { $reasons.Add('PARTITION_UNREADABLE'); continue }
        $k = $dir.ToLowerInvariant()
        if (-not $cands.Contains($k) -and $cands.Count -ge $MaxCandidates) { $reasons.Add('CANDIDATE_LIMIT'); continue }
        if (-not $cands.Contains($k)) { $cands[$k] = [pscustomobject]@{ Dir = $dir; Sources = (New-Object System.Collections.Generic.List[string]) } }
        if (-not $cands[$k].Sources.Contains($s.Source)) { $cands[$k].Sources.Add($s.Source) }
    }
    # Repositories, deduplicated by their common directory.
    $repos = [ordered]@{}
    foreach ($c in $cands.Values) {
        if ($null -ne $Deadline -and [datetime]::UtcNow -ge $Deadline) { $reasons.Add('DEADLINE_EXCEEDED'); break }
        if (& $budgetHit) { break }
        $pf = Get-AtmGitPreflight -Target $c.Dir -Cache $pfCache
        if ($reusePf) { $pfByDir[$c.Dir.ToLowerInvariant()] = $pf }
        if ($pf.Status -eq 'NOT_A_REPOSITORY') { continue }
        if ($pf.Status -ne 'OK') {
            # A worktree directory whose administrative entry is positively absent: apparent orphan (local work unknown).
            if ($pf.Reason -eq 'GIT_PREFLIGHT_GITDIR_MISSING') {
                $ev = @((New-AtmEvidence -Code 'ADMINISTRATIVE_ENTRY_NOT_FOUND' -Source 'worktree-discovery' -Collector 'worktree-discovery' -ObservedUtc $now), (New-AtmEvidence -Code 'LOCAL_WORK_UNKNOWN' -Source 'worktree-discovery' -Collector 'worktree-discovery' -ObservedUtc $now))
                $findings.Add([pscustomobject]@{ Kind = 'Worktree'; Key = (& $wtKey $c.Dir); State = 'APPARENT_ORPHAN'; Evidence = $ev })
                continue
            }
            $reasons.Add('PREFLIGHT_REFUSED_TARGETS')
            $findings.Add([pscustomobject]@{ Kind = 'Repository'; Key = ('git/t-' + (& $pz 'atm-repository-target/1' $c.Dir)); State = 'UNKNOWN'; Evidence = @(
                    (New-AtmEvidence -Code 'REPOSITORY_PREFLIGHT_REFUSED' -Source 'worktree-discovery' -Collector 'worktree-discovery' -ObservedUtc $now -Detail $pf.Reason)) })
            continue
        }
        $rkPath = Get-AtmNormalizedPath $pf.CommonDir
        if (-not $rkPath) { $reasons.Add('PREFLIGHT_REFUSED_TARGETS'); continue }
        $rk = $rkPath.ToLowerInvariant()
        if (-not $repos.Contains($rk)) {
            if ($repos.Count -ge $MaxRepositories) { $reasons.Add('REPOSITORY_LIMIT'); continue }
            $repos[$rk] = [pscustomobject]@{ Preflight = $pf; Sources = (New-Object System.Collections.Generic.List[string]); Dirs = (New-Object System.Collections.Generic.List[string]) }
        }
        foreach ($src in $c.Sources) { if (-not $repos[$rk].Sources.Contains($src)) { $repos[$rk].Sources.Add($src) } }
        $repos[$rk].Dirs.Add($c.Dir)
    }
    $gitUsable = ($null -ne $Git -and $Git.Status -ceq 'COMPLETE')
    $gitCalls = 0; $gitFailed = 0
    # Local work coverage (P3-C): one record per collector over every worktree observed.
    $lwCount = 0; $lwStatusOk = 0; $lwFilesOk = 0; $lwUnavailable = 0
    $pubCount = 0; $pubOk = 0; $pubReasons = New-Object System.Collections.Generic.List[string]
    $lwStatus = New-Object System.Collections.Generic.List[string]; $lwFiles = New-Object System.Collections.Generic.List[string]
    # Every path Git reports goes through the single resolver (text checks, fixed local drive, no reparse point) before
    # anything touches it; $null when refused.
    $gitPath = { param([string]$P, [string]$Base)
        $rr = Resolve-AtmGitReferencedPath -Value $P.Replace('/', '\') -BaseDir $Base
        if ($rr.Status -ceq 'OK' -or $rr.Status -ceq 'MISSING') { Get-AtmNormalizedPath $rr.Path } else { $null } }
    foreach ($r in $repos.Values) {
        # A stop (read budget or deadline) never drops a repository already discovered: it is still reported from its
        # preflight (registration, alternates), marked REPOSITORY_NOT_EXAMINED; nothing more is read for it.
        $stopReason = $null
        if (& $budgetHit) { $stopReason = 'READ_BUDGET' }
        elseif ($null -ne $Deadline -and [datetime]::UtcNow -ge $Deadline) { if (-not $reasons.Contains('DEADLINE_EXCEEDED')) { $reasons.Add('DEADLINE_EXCEEDED') }; $stopReason = 'DEADLINE_EXCEEDED' }
        $pf = $r.Preflight
        $rKey = & $repoKey (Get-AtmNormalizedPath $pf.CommonDir)
        $rev = New-Object System.Collections.Generic.List[object]
        foreach ($src in ($r.Sources | Sort-Object)) { $rev.Add((New-AtmEvidence -Code 'REPOSITORY_DISCOVERED' -Source 'worktree-discovery' -Collector 'worktree-discovery' -ObservedUtc $now -Detail $src)) }
        if ($pf.Alternates -gt 0) { $rev.Add((New-AtmEvidence -Code 'ALTERNATES' -Source 'worktree-discovery' -Collector 'worktree-discovery' -ObservedUtc $now -Detail ([string]$pf.Alternates))) }
        # Worktrees from the files: the main one (a non-bare common directory named .git) and every administrative entry.
        $wts = [ordered]@{}
        $mainDir = $(if ([IO.Path]::GetFileName($pf.CommonDir) -ieq '.git') { Get-AtmNormalizedPath ([IO.Path]::GetDirectoryName($pf.CommonDir)) } else { $null })
        if ($mainDir) { $wts[$mainDir.ToLowerInvariant()] = [pscustomobject]@{ Dir = $mainDir; Codes = (New-Object System.Collections.Generic.List[object]) }; $wts[$mainDir.ToLowerInvariant()].Codes.Add(@('WORKTREE_MAIN', $null)) }
        $n = 0
        foreach ($a in @($pf.AdminEntries)) {
            $n++
            if ($n -gt $MaxWorktreesPerRepository) { $reasons.Add('WORKTREE_LIMIT'); break }
            $dir = $(if ($a.Gitdir.Path) { Get-AtmNormalizedPath ([IO.Path]::GetDirectoryName($a.Gitdir.Path)) } else { Get-AtmNormalizedPath ($pf.CommonDir + '\worktrees\' + $a.Name) })
            if (-not $dir) { continue }
            $k = $dir.ToLowerInvariant()
            if (-not $wts.Contains($k)) { $wts[$k] = [pscustomobject]@{ Dir = $dir; Codes = (New-Object System.Collections.Generic.List[object]) } }
            $wts[$k].Codes.Add(@('WORKTREE_REGISTERED', $null))
            if ($a.Locked) { $wts[$k].Codes.Add(@('WORKTREE_LOCKED', $null)) }
            if ($a.Gitdir.Status -eq 'MISSING') { $wts[$k].Codes.Add(@('WORKTREE_DIRECTORY_MISSING', $null)) }
        }
        $rev.Add((New-AtmEvidence -Code 'WORKTREES_REGISTERED' -Source 'worktree-discovery' -Collector 'worktree-discovery' -ObservedUtc $now -Detail ([string]@($pf.AdminEntries).Count)))
        if ($stopReason) { $rev.Add((New-AtmEvidence -Code 'REPOSITORY_NOT_EXAMINED' -Source 'worktree-discovery' -Collector 'worktree-discovery' -ObservedUtc $now -Detail $stopReason)) }
        # Confirmation by Git, through the runner, with this repository's preflight.
        # A repository reached only through a worktree's gitdir (its main worktree outside the sources) is registered
        # from its files but never given to Git: Git runs only where a source led.
        # Directories a source led to, as a set (O(1) per worktree).
        $ledSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($x in $r.Dirs) { [void]$ledSet.Add($x) }
        $inSources = ($mainDir -and $ledSet.Contains($mainDir))
        if ($stopReason) { }
        elseif ($gitUsable -and $mainDir -and -not $inSources) { $rev.Add((New-AtmEvidence -Code 'GIT_NOT_RUN' -Source 'worktree-discovery' -Collector 'worktree-discovery' -ObservedUtc $now -Detail 'REPOSITORY_OUTSIDE_SOURCES')) }
        elseif ($gitUsable -and $mainDir -and $null -ne $Deadline -and [datetime]::UtcNow -ge $Deadline) { $reasons.Add('DEADLINE_EXCEEDED') }
        elseif ($gitUsable -and $mainDir) {
            $mpf = $(if ($pfByDir.ContainsKey($mainDir.ToLowerInvariant())) { $pfByDir[$mainDir.ToLowerInvariant()] } else { Get-AtmGitPreflight -Target $mainDir -Cache $pfCache })
            $gitCalls++
            # The common directory is not asked: Git would only repeat GIT_COMMON_DIR, which the engine sets itself.
            $rp = Invoke-AtmGitCommand -Git $Git -Arguments @('rev-parse', '--show-toplevel', '--absolute-git-dir') -WorkingDirectory $mainDir -Preflight $mpf
            if ($rp.Status -ceq 'COMPLETE') {
                $lines = @($rp.Output.Split("`n") | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                $ok = ($lines.Count -ge 2)
                if ($ok) {
                    $top = & $gitPath $lines[0] $mainDir; $gd = & $gitPath $lines[1] $mainDir
                    $ok = ($null -ne $top -and $null -ne $gd -and [string]::Equals($top, $mainDir, [StringComparison]::OrdinalIgnoreCase) -and [string]::Equals($gd, (Get-AtmNormalizedPath $mpf.GitDir), [StringComparison]::OrdinalIgnoreCase))
                }
                $rev.Add((New-AtmEvidence -Code $(if ($ok) { 'REPOSITORY_CONFIRMED_BY_GIT' } else { 'REPOSITORY_MISMATCH' }) -Source 'worktree-discovery' -Collector 'git' -ObservedUtc $now))
                # P3-C0: `worktree list` is not run. It enumerates the administrative entries and follows each gitdir, so
                # an entry created after the preflight would be followed (an absence cannot be pinned); registration
                # comes from the files only (a missing worktree directory is WORKTREE_DIRECTORY_MISSING).
            } else { $gitFailed++; $rev.Add((New-AtmEvidence -Code 'GIT_NOT_RUN' -Source 'worktree-discovery' -Collector 'git' -ObservedUtc $now -Detail $rp.Reason)) }
        } elseif (-not $gitUsable) { $rev.Add((New-AtmEvidence -Code 'GIT_NOT_RUN' -Source 'worktree-discovery' -Collector 'git' -ObservedUtc $now -Detail $(if ($null -ne $Git) { [string]$Git.Reason } else { 'GIT_NOT_FOUND' }))) }
        # Stashes belong to the repository (ADR-0006 rule 12): counted once, attributed to a worktree only by branch.
        $stash = $(if ($stopReason) { $null } else { Get-AtmGitStashSummary -CommonDir $pf.CommonDir })
        # P3-D: the shared references, read once per repository (two passes) and used for each of its worktrees.
        $refStore = $(if ($stopReason) { $null } else { Get-AtmGitRefStore -CommonDir $pf.CommonDir })
        if ($null -eq $stash) { }
        elseif ($stash.Status -ceq 'COMPLETE' -and $stash.Count -gt 0) { $rev.Add((New-AtmEvidence -Code 'STASHES_IN_REPOSITORY' -Source 'local-work' -Collector 'local-work-files' -ObservedUtc $now -Detail ([string]$stash.Count))) }
        elseif ($stash.Status -cne 'COMPLETE' -and $stash.Status -cne 'NOT_PRESENT') { $lwFiles.Add('FILES_INCOMPLETE') }
        $findings.Add([pscustomobject]@{ Kind = 'Repository'; Key = $rKey; State = 'UNKNOWN'; Evidence = $rev.ToArray() })
        foreach ($w in $wts.Values) {
            $ev = New-Object System.Collections.Generic.List[object]
            foreach ($cd in $w.Codes) { $ev.Add((New-AtmEvidence -Code $cd[0] -Source 'worktree-discovery' -Collector 'worktree-discovery' -ObservedUtc $now -Detail $cd[1])) }
            $ev.Add((New-AtmEvidence -Code 'IN_REPOSITORY' -Source 'worktree-discovery' -Collector 'worktree-discovery' -ObservedUtc $now -Detail $rKey))
            $state = 'UNKNOWN'
            # Local work only where a source led (the same rule as for Git); elsewhere it stays unknown.
            $led = $ledSet.Contains($w.Dir)
            if (-not $stopReason -and $led -and @($w.Codes | Where-Object { $_[0] -ceq 'WORKTREE_DIRECTORY_MISSING' }).Count -eq 0) {
                $wpf = $(if ($pfByDir.ContainsKey($w.Dir.ToLowerInvariant())) { $pfByDir[$w.Dir.ToLowerInvariant()] } else { Get-AtmGitPreflight -Target $w.Dir -Cache $pfCache })
                if ($wpf.Status -ceq 'OK') {
                    # P1-C: the worktree's index is the file sampled for open-file evidence (D-2), only with the
                    # handle diagnostics gate open.
                    if ($script:AtmHandleDiagnosticsEnabled) {
                        $ix = Resolve-AtmGitReferencedPath -Value 'index' -BaseDir $wpf.GitDir
                        $handleNodes.Add([pscustomobject]@{ Key = (& $wtKey $w.Dir); Files = $(if ($ix.Status -eq 'OK') { @($ix.Path) } else { @() }); Capped = $false; Error = $null })
                    }
                }
                $lw = Get-AtmWorktreeLocalWork -WorkTree $w.Dir -Git $(if ($gitUsable) { $Git } else { $null }) -Stash $stash -Deadline $Deadline -Preflight $wpf
                foreach ($e in $lw.Evidence) { $ev.Add($e) }
                if ($wpf.Status -ceq 'OK') {
                    $sameStore = [string]::Equals((Get-AtmNormalizedPath $wpf.CommonDir), (Get-AtmNormalizedPath $pf.CommonDir), [StringComparison]::OrdinalIgnoreCase)
                    $pub = Get-AtmWorktreePublication -GitDir $wpf.GitDir -RefStore $(if ($sameStore) { $refStore } else { $null }) -CommonDir $wpf.CommonDir
                    foreach ($e in $pub.Evidence) { $ev.Add($e) }
                    $pubCount++
                    if ($script:AtmConclusiveCoverage -ccontains $pub.Coverage.Status) { $pubOk++ } else { $pubReasons.Add([string]$pub.Coverage.Reason) }
                }
                $lwCount++
                $lwStatus.Add($(if ($lw.StatusCoverage.Reason) { [string]$lw.StatusCoverage.Reason } else { 'STATUS_INCOMPLETE' }))
                if ($lw.StatusRan) { $lwStatusOk++ }
                if ($lw.StatusCoverage.Status -ceq 'UNAVAILABLE') { $lwUnavailable++ }
                if ($script:AtmConclusiveCoverage -cnotcontains $lw.FilesCoverage.Status) { $lwFiles.Add('FILES_INCOMPLETE') } else { $lwFilesOk++ }
                # P3-D gives no publication state from files: UNPUBLISHED_COMMITS needs a proof files cannot give.
                if ($lw.LocalWork) { $state = 'LOCAL_WORK' }
            } else {
                $ev.Add((New-AtmEvidence -Code 'LOCAL_WORK_UNKNOWN' -Source 'worktree-discovery' -Collector 'worktree-discovery' -ObservedUtc $now -Detail $(if ($stopReason) { $stopReason } elseif ($led) { $null } else { 'WORKTREE_OUTSIDE_SOURCES' })))
            }
            # Where no publication fact was read (outside the sources, or refused), publication stays undiagnosed.
            if (@($ev | Where-Object { $_.Collector -ceq 'publication-files' }).Count -eq 0) { $ev.Add((New-AtmEvidence -Code 'PUBLICATION_NOT_DIAGNOSED' -Source 'worktree-discovery' -Collector 'worktree-discovery' -ObservedUtc $now)) }
            $findings.Add([pscustomobject]@{ Kind = 'Worktree'; Key = (& $wtKey $w.Dir); State = $state; Evidence = $ev.ToArray() })
        }
    }
    # Coverage records and findings (one per key: a key seen twice keeps the first, its evidence merged).
    $rs = @(Get-AtmSortedCodes $reasons)
    $disc = New-AtmCoverage -Collector 'worktree-discovery' -Status 'PARTIAL' -Reasons $rs -ElevationWouldHelp 'UNKNOWN' -Observed $repos.Count
    if (-not $gitUsable) { $gitCov = New-AtmCoverage -Collector 'git' -Status 'UNAVAILABLE' -Reasons @($(if ($null -ne $Git -and $Git.Reason) { [string]$Git.Reason } else { 'GIT_NOT_FOUND' })) -ElevationWouldHelp 'NO' }
    elseif ($gitFailed -gt 0) { $gitCov = New-AtmCoverage -Collector 'git' -Status 'PARTIAL' -Reasons @('GIT_CALLS_INCOMPLETE') -ElevationWouldHelp 'UNKNOWN' -Observed ($gitCalls - $gitFailed) -Expected $gitCalls }
    else { $gitCov = New-AtmCoverage -Collector 'git' -Status 'COMPLETE' -ElevationWouldHelp 'NO' -Observed $gitCalls -Expected $gitCalls }
    # local-work-status is never COMPLETE (HIDDEN_ENTRIES_NOT_OBSERVED); Observed counts the status runs that completed.
    $stCov = $(if ($lwCount -eq 0) { New-AtmCoverage -Collector 'local-work-status' -Status 'NOT_OBSERVABLE' -Reasons @('STATUS_NOT_RUN') -ElevationWouldHelp 'NO' }
        elseif ($lwUnavailable -eq $lwCount) { New-AtmCoverage -Collector 'local-work-status' -Status 'UNAVAILABLE' -Reasons @(Get-AtmSortedCodes $lwStatus) -ElevationWouldHelp 'NO' -Observed 0 -Expected $lwCount }
        else { New-AtmCoverage -Collector 'local-work-status' -Status 'PARTIAL' -Reasons @(Get-AtmSortedCodes $lwStatus) -ElevationWouldHelp 'UNKNOWN' -Observed $lwStatusOk -Expected $lwCount })
    $pbCov = $(if ($pubCount -eq 0) { New-AtmCoverage -Collector 'publication-files' -Status 'NOT_OBSERVABLE' -Reasons @('NO_WORKTREE_OBSERVED') -ElevationWouldHelp 'NO' }
        elseif ($pubReasons.Count -eq 0) { New-AtmCoverage -Collector 'publication-files' -Status 'COMPLETE' -ElevationWouldHelp 'NO' -Observed $pubOk -Expected $pubCount }
        else { New-AtmCoverage -Collector 'publication-files' -Status 'PARTIAL' -Reasons @(Get-AtmSortedCodes $pubReasons) -ElevationWouldHelp 'UNKNOWN' -Observed $pubOk -Expected $pubCount })
    $fiCov = $(if ($lwCount -eq 0 -and $lwFiles.Count -eq 0) { New-AtmCoverage -Collector 'local-work-files' -Status 'NOT_OBSERVABLE' -Reasons @('FILES_INCOMPLETE') -ElevationWouldHelp 'NO' }
        elseif ($lwFiles.Count -eq 0) { New-AtmCoverage -Collector 'local-work-files' -Status 'COMPLETE' -ElevationWouldHelp 'NO' -Observed $lwFilesOk -Expected $lwCount }
        else { New-AtmCoverage -Collector 'local-work-files' -Status 'PARTIAL' -Reasons @(Get-AtmSortedCodes $lwFiles) -ElevationWouldHelp 'UNKNOWN' -Observed $lwFilesOk -Expected $lwCount })
    $byKey = [ordered]@{}
    foreach ($f in $findings) {
        if (-not $byKey.Contains($f.Key)) { $byKey[$f.Key] = [pscustomobject]@{ Kind = $f.Kind; Key = $f.Key; State = $f.State; Evidence = (New-Object System.Collections.Generic.List[object]) } }
        $t = $byKey[$f.Key]
        # Precedence of ADR-0006 rule 14 among the states this phase can give.
        $rank = @{ 'LOCAL_WORK' = 4; 'UNPUBLISHED_COMMITS' = 3; 'APPARENT_ORPHAN' = 2; 'UNKNOWN' = 1 }
        if ($rank[[string]$f.State] -gt $rank[[string]$t.State]) { $t.State = $f.State }
        foreach ($e in $f.Evidence) { if (@($t.Evidence | Where-Object { $_.Code -ceq $e.Code -and $_.Detail -ceq $e.Detail }).Count -eq 0) { $t.Evidence.Add($e) } }
    }
    $built = New-Object System.Collections.Generic.List[object]
    foreach ($t in $byKey.Values) {
        # An apparent orphan that turns out to be registered somewhere else is not an orphan.
        $state = $t.State
        if ($state -eq 'APPARENT_ORPHAN' -and @($t.Evidence | Where-Object { $_.Code -eq 'WORKTREE_REGISTERED' }).Count -gt 0) { $state = 'UNKNOWN' }
        # A positive local work observation removes the generic "unknown" marker of the same worktree (seen twice).
        if ($state -ceq 'LOCAL_WORK') { $t.Evidence = [System.Collections.Generic.List[object]]@($t.Evidence | Where-Object { $_.Code -cne 'LOCAL_WORK_UNKNOWN' -and $_.Code -cne 'PUBLICATION_NOT_DIAGNOSED' }) }
        elseif ($state -ceq 'UNPUBLISHED_COMMITS') { $t.Evidence = [System.Collections.Generic.List[object]]@($t.Evidence | Where-Object { $_.Code -cne 'PUBLICATION_NOT_DIAGNOSED' }) }
        $cov = @($disc) + $(if (@($t.Evidence | Where-Object { $_.Collector -eq 'git' }).Count -gt 0) { @($gitCov) } else { @() }) +
            $(if (@($t.Evidence | Where-Object { $_.Collector -eq 'local-work-status' }).Count -gt 0) { @($stCov) } else { @() }) +
            $(if (@($t.Evidence | Where-Object { $_.Collector -eq 'local-work-files' }).Count -gt 0) { @($fiCov) } else { @() }) +
            $(if (@($t.Evidence | Where-Object { $_.Collector -eq 'publication-files' }).Count -gt 0) { @($pbCov) } else { @() })
        $built.Add((New-AtmFinding -Kind $t.Kind -Key $t.Key -State $state -Evidence (@(Get-AtmOrdinalSorted -Items $t.Evidence.ToArray() -Signature { param($e) '{0}|{1}' -f $e.Code, $e.Detail })) -Coverage $cov))
    }
    $sorted = @(Get-AtmOrdinalSorted -Items $built.ToArray() -Signature { param($f) [string]$f.Kind + [char]1 + [string]$f.Key })
    $stats = [pscustomobject]@{ CommonPreflights = $script:AtmScaleStats.CommonPreflights; CommonCacheHits = $script:AtmScaleStats.CommonCacheHits; CommonCacheInvalidations = $script:AtmScaleStats.CommonCacheInvalidations
        RefEntriesWalked = $script:AtmScaleStats.RefEntriesWalked; FilesRead = $script:AtmScaleStats.FilesRead; BytesRead = $script:AtmScaleStats.BytesRead; RefStoreReads = $script:AtmScaleStats.RefStoreReads; Candidates = $cands.Count; Repositories = $repos.Count }
    return [pscustomobject]@{ Findings = $sorted; Coverage = @($disc, $gitCov, $stCov, $fiCov, $pbCov); Stats = $stats; HandleNodes = $handleNodes.ToArray() }
}

# ---------------------------------------------------------------------------------------------
# Pseudonyms of exported identifiers (ADR-0010, P1-B4-d): keyed HMAC-SHA256, first 128 bits. Without the key nobody
# can compute or check a pseudonym from the inputs, the export included. The key is EPHEMERAL (random, one run) unless
# the operator supplies a key file (read only, never written by the tool) to correlate runs. The key never enters a
# result, a string, a log or a message; the HMAC object is disposed at the end of the run.
# ---------------------------------------------------------------------------------------------

$script:AtmPseudonymScheme = 'HMAC-SHA256-128/1'
$script:AtmPseudonymKeyMinBytes = 32
$script:AtmPseudonymKeyMaxBytes = 4096
# Besides the current user, only SYSTEM and Administrators may own, read or change a key file.
$script:AtmPseudonymKeyTrustedSids = @('S-1-5-18', 'S-1-5-32-544')
# Rights that read or change a key file (FileSystemRights, generic rights included).
$script:AtmPseudonymKeyReadMask = [uint32](0x1 -bor 0x10000000) + [uint32]2147483648
$script:AtmPseudonymKeyWriteMask = [uint32](0x2 -bor 0x4 -bor 0x10 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000)

function New-AtmPseudonymizer {
    # -Key: the operator's key (32 to 4096 bytes; the caller's array is copied, never kept); $null = an ephemeral random
    # key of 32 bytes. KeyId identifies an operator key (another HMAC domain) so two exports can be compared; it is
    # $null for an ephemeral key, whose pseudonyms are never comparable between runs.
    param([byte[]]$Key = $null)
    $source = 'OPERATOR_KEY_FILE'
    if ($null -eq $Key) {
        $k = New-Object byte[] 32
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($k) } finally { $rng.Dispose() }
        $source = 'EPHEMERAL'
    } else {
        if ($Key.Length -lt $script:AtmPseudonymKeyMinBytes -or $Key.Length -gt $script:AtmPseudonymKeyMaxBytes) { throw (Get-AtmText 'err.diagPseudonymKey' 'PSEUDONYM_KEY_SIZE_INVALID') }
        $k = [byte[]]$Key.Clone()
    }
    # The private copy is cleared by Close-AtmPseudonymizer after the HMAC object is disposed (some runtimes keep a
    # reference to the array they were given).
    $p = [pscustomobject]@{ Hmac = $null; Buffer = $k; KeySource = $source; KeyId = $null }
    try {
        $p.Hmac = New-Object Security.Cryptography.HMACSHA256 (, $k)
        if ($source -ceq 'OPERATOR_KEY_FILE') { $p.KeyId = (Get-AtmPseudonym -Pseudonymizer $p -Domain 'atm-key-id/1' -Fields @()) }
    } catch { Close-AtmPseudonymizer $p; throw }
    return $p
}

function Get-AtmPseudonym {
    # 32 hex characters: HMAC over the domain and the fields, each length-prefixed (no two field lists give one input).
    param($Pseudonymizer, [string]$Domain, [string[]]$Fields = @())
    $sb = New-Object System.Text.StringBuilder
    foreach ($f in @($Domain) + @($Fields)) { $v = [string]$f; [void]$sb.Append($v.Length).Append(':').Append($v).Append(';') }
    $hash = $Pseudonymizer.Hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($sb.ToString()))
    return (-join @($hash[0..15] | ForEach-Object { $_.ToString('x2') }))
}

function Close-AtmPseudonymizer {
    param($Pseudonymizer)
    if ($null -eq $Pseudonymizer) { return }
    if ($null -ne $Pseudonymizer.Hmac) { $Pseudonymizer.Hmac.Dispose(); $Pseudonymizer.Hmac = $null }
    if ($null -ne $Pseudonymizer.Buffer) { [Array]::Clear($Pseudonymizer.Buffer, 0, $Pseudonymizer.Buffer.Length); $Pseudonymizer.Buffer = $null }
}

function ConvertTo-AtmSessionKey {
    <#
      Exported key of an agent session: <provider>/s-<32 hex>, the keyed pseudonym of the provider Id (lower case), the
      profile SID, the profile path (lower case, no trailing separator) and the SessionId (lower case). With the same
      key, the same session of the same profile has the same pseudonym and the same SessionId in another profile has
      another one. The SessionId and the profile never leave memory.
    #>
    param($Pseudonymizer, [string]$Provider, [string]$ProfileSid, [string]$ProfilePath, [string]$SessionId)
    $prov = $Provider.ToLowerInvariant()
    return ($prov + '/s-' + (Get-AtmPseudonym -Pseudonymizer $Pseudonymizer -Domain 'atm-session/2' -Fields @($prov, [string]$ProfileSid, ([string]$ProfilePath).TrimEnd('\', '/').ToLowerInvariant(), $SessionId.Trim().ToLowerInvariant())))
}

function ConvertTo-AtmPartitionKey {
    # Exported key of a temporary partition: <provider>/p-<32 hex>, the keyed pseudonym of the provider Id and the
    # partition path (lower case, no trailing separator). The path never leaves memory.
    param($Pseudonymizer, [string]$Provider, [string]$Path)
    $prov = $(if ([string]::IsNullOrWhiteSpace($Provider)) { 'none' } else { $Provider.ToLowerInvariant() })
    return ($prov + '/p-' + (Get-AtmPseudonym -Pseudonymizer $Pseudonymizer -Domain 'atm-partition/1' -Fields @($prov, ([string]$Path).TrimEnd('\', '/').ToLowerInvariant())))
}

function Read-AtmPseudonymKeyFile {
    <#
      The operator's key file, read only. Refused (Reason, a code; the path and the content are never part of a message)
      unless: a drive-absolute path on a fixed drive whose every component exists and none is a reparse point
      (Test-AtmPathChain); a regular file of 32 to 4096 bytes; owned by the current user, SYSTEM or Administrators; and
      no other account may read or change it (generic rights included). The file is opened once, without write or
      delete sharing, so the file checked is the file read. Returns Key (bytes) or Reason.
    #>
    param([string]$Path)
    $fail = { param([string]$Code) [pscustomobject]@{ Key = $null; Reason = $Code } }
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -notmatch '^[A-Za-z]:\\[^\\]') { return (& $fail 'PSEUDONYM_KEY_PATH_INVALID') }
    $chain = Test-AtmPathChain $Path
    switch ($chain.Status) {
        'OK' { }
        'NOT_FOUND' { return (& $fail 'PSEUDONYM_KEY_NOT_FOUND') }
        'REPARSE_IN_PATH' { return (& $fail 'PSEUDONYM_KEY_REPARSE_POINT') }
        'INACCESSIBLE' { return (& $fail 'PSEUDONYM_KEY_UNREADABLE') }
        default { return (& $fail 'PSEUDONYM_KEY_PATH_INVALID') }
    }
    try { if (([IO.File]::GetAttributes($Path) -band [IO.FileAttributes]::Directory) -ne 0) { return (& $fail 'PSEUDONYM_KEY_NOT_A_FILE') } } catch { return (& $fail 'PSEUDONYM_KEY_UNREADABLE') }
    $fs = $null; $bytes = $null
    try {
        $fs = New-Object IO.FileStream($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        if ($fs.Length -lt $script:AtmPseudonymKeyMinBytes -or $fs.Length -gt $script:AtmPseudonymKeyMaxBytes) { return (& $fail 'PSEUDONYM_KEY_SIZE_INVALID') }
        $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $trusted = @($me) + $script:AtmPseudonymKeyTrustedSids
        $acl = Get-Acl -LiteralPath $Path
        if ($trusted -cnotcontains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) { return (& $fail 'PSEUDONYM_KEY_ACL_TOO_OPEN') }
        foreach ($ace in @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))) {
            if ($ace.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
            if ($trusted -ccontains $ace.IdentityReference.Value) { continue }
            $rights = [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$ace.FileSystemRights), 0)
            if (($rights -band ($script:AtmPseudonymKeyReadMask -bor $script:AtmPseudonymKeyWriteMask)) -ne 0) { return (& $fail 'PSEUDONYM_KEY_ACL_TOO_OPEN') }
        }
        $bytes = New-Object byte[] ([int]$fs.Length)
        $read = 0
        while ($read -lt $bytes.Length) { $n = $fs.Read($bytes, $read, $bytes.Length - $read); if ($n -le 0) { break }; $read += $n }
        if ($read -ne $bytes.Length) { [Array]::Clear($bytes, 0, $bytes.Length); return (& $fail 'PSEUDONYM_KEY_UNREADABLE') }
    } catch {
        if ($null -ne $bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
        return (& $fail 'PSEUDONYM_KEY_UNREADABLE')
    } finally { if ($null -ne $fs) { $fs.Dispose() } }
    return [pscustomobject]@{ Key = $bytes; Reason = $null }
}

function Get-AtmPartitionFindings {
    <#
      TempPartition findings keyed by ConvertTo-AtmPartitionKey (no path in a finding), ordered by Key (ordinal; ADR-0010
      D-8): the position of a directory in the file-system enumeration is not kept, and every finding carries the same
      observation time, so no field gives that order back. Collisions are grouped first: two partitions with the same key
      are one UNKNOWN finding with PARTITION_KEY_COLLISION, never an overwritten one; its provider is kept only when both
      name the same one. -KeyFunction: test override.
    #>
    param($Partitions, $InventoryCoverage, $Pseudonymizer, [scriptblock]$KeyFunction = $null)
    $keyFn = $(if ($null -ne $KeyFunction) { $KeyFunction } else { { param($Provider, $Path) ConvertTo-AtmPartitionKey -Pseudonymizer $Pseudonymizer -Provider $Provider -Path $Path } })
    $groups = @{}
    foreach ($part in @($Partitions | Where-Object { $null -ne $_ -and $_.Kind -ne 'NotScanned' })) {
        $key = [string](& $keyFn $part.Provider $part.Path)
        if (-not $groups.ContainsKey($key)) { $groups[$key] = New-Object System.Collections.Generic.List[object] }
        $groups[$key].Add($part)
    }
    $keys = [string[]]@($groups.Keys)
    [Array]::Sort($keys, [StringComparer]::Ordinal)
    $now = [datetime]::UtcNow
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($key in $keys) {
        $parts = $groups[$key].ToArray()
        $ev = New-Object System.Collections.Generic.List[object]
        if ($parts.Count -gt 1) {
            $ev.Add((New-AtmEvidence -Code 'PARTITION_KEY_COLLISION' -Source 'diagnose' -Collector 'inventory' -ObservedUtc $now -Detail ([string]$parts.Count)))
            $provs = @($parts | ForEach-Object { [string]$_.Provider } | Select-Object -Unique)
            $out.Add((New-AtmFinding -Kind 'TempPartition' -Key $key -State 'UNKNOWN' -Evidence $ev.ToArray() -Coverage $InventoryCoverage -Provider $(if ($provs.Count -eq 1) { $provs[0] } else { $null })))
            continue
        }
        $part = $parts[0]
        $ev.Add((New-AtmEvidence -Code 'AUDIT_CLASS' -Source 'audit' -Collector 'inventory' -ObservedUtc $now -Detail $part.Class))
        foreach ($fl in $part.Flags) { $ev.Add((New-AtmEvidence -Code 'AUDIT_FLAG' -Source 'audit' -Collector 'inventory' -ObservedUtc $now -Detail $fl)) }
        # Runtime evidence of partitions (handles, working directories, dependencies) comes in later phases.
        $out.Add((New-AtmFinding -Kind 'TempPartition' -Key $key -State 'RUNTIME_NOT_DIAGNOSED' -Evidence $ev.ToArray() -Coverage $InventoryCoverage -Provider $part.Provider))
    }
    return $out.ToArray()
}

# ---------------------------------------------------------------------------------------------
# Invoke-AtmDiagnose (ADR-0009). P1-A collectors: identity, provider runtime hints, the V0.1 temporary-directory
# inventory and the coverage it implies (processes, temp-profiles). P1-B4-c: the agent runtime (process-snapshot,
# sessions-<provider>, agent-processes, agent-resources). Collectors of later phases (services, virtualization, Git
# worktrees) add coverage records and findings here.
# ---------------------------------------------------------------------------------------------

$script:AtmDiagnoseSchema = 'atm.diagnose/2'
$script:AtmDiagnoseDefaultDeadlineSeconds = 300
$script:AtmDiagnoseCpuSampleMs = 500

function New-AtmDeadlineCoverage {
    param([string]$Collector)
    return (New-AtmCoverage -Collector $Collector -Status 'TIMEOUT' -Reasons @('DEADLINE_EXCEEDED'))
}

function Get-AtmInventoryCoverage {
    # Coverage implied by a V0.1 inventory. Read from the inventory itself; nothing is re-measured.
    param($Inventory, $Identity, [datetime]$StartedUtc, [long]$ElapsedMs, [bool]$OverDeadline)
    $out = New-Object System.Collections.Generic.List[object]
    # The V0.1 inventory cannot be interrupted: no budget is enforced on it (BudgetMs = $null). Finishing after the
    # deadline is reported as PARTIAL, never hidden.
    if ($OverDeadline) { $out.Add((New-AtmCoverage -Collector 'inventory' -Status 'PARTIAL' -Reasons @('DEADLINE_EXCEEDED') -ElevationWouldHelp 'NO' -StartedUtc $StartedUtc -ElapsedMs $ElapsedMs)) }
    else { $out.Add((New-AtmCoverage -Collector 'inventory' -Status 'COMPLETE' -ElevationWouldHelp 'NO' -StartedUtc $StartedUtc -ElapsedMs $ElapsedMs)) }
    $admin = [bool]$Identity.IsElevatedAdministrator
    $s = $Inventory.Snapshot
    if ($s.Failed) {
        $out.Add((New-AtmCoverage -Collector 'processes' -Status 'FAILED' -Reasons @('PROCESS_SNAPSHOT_FAILED') -ElevationWouldHelp 'UNKNOWN'))
    } elseif ($s.Uninspectable -gt 0) {
        # Other accounts' processes need elevation; protected processes stay uninspectable even when elevated.
        $out.Add((New-AtmCoverage -Collector 'processes' -Status 'PARTIAL' -Reasons @('UNINSPECTABLE_PROCESSES') -ElevationWouldHelp $(if ($admin) { 'NO' } else { 'YES' }) -Observed $s.Readable -Expected $s.Total))
    } else {
        $out.Add((New-AtmCoverage -Collector 'processes' -Status 'COMPLETE' -ElevationWouldHelp 'NO' -Observed $s.Readable -Expected $s.Total))
    }
    $profiles = @($Inventory.Profiles)
    $inacc = @($Inventory.InaccessibleProfiles).Count
    $unver = @($Inventory.UnverifiedTempProfiles).Count
    $reasons = @()
    if ($inacc -gt 0) { $reasons += 'PROFILES_INACCESSIBLE' }
    if ($unver -gt 0) { $reasons += 'TEMP_LOCATION_UNVERIFIED' }
    $st = $(if ($reasons.Count -gt 0) { 'PARTIAL' } else { 'COMPLETE' })
    $help = $(if ($reasons.Count -eq 0) { 'NO' } elseif ($admin) { 'UNKNOWN' } else { 'YES' })
    $out.Add((New-AtmCoverage -Collector 'temp-profiles' -Status $st -Reasons $reasons -ElevationWouldHelp $help -Observed ($profiles.Count - $inacc - $unver) -Expected $profiles.Count))
    $out.Add((Get-AtmProfileDiscoveryCoverage -Inventory $Inventory -Identity $Identity))
    return $out.ToArray()
}

function Get-AtmProfileDiscoveryCoverage {
    <#
      Coverage of Windows profile discovery (P4-B, SECURITY-MODEL "Discovery visibility"), from the gap codes the
      inventory recorded (Get-AtmProfiles): codes only, never a path, a profile name or an exception message. A gap is a
      reason (PARTIAL): a source that could not be read is not proof that a profile or a TEMP folder does not exist.
      Profiles supplied by the caller (tests) were not discovered: COMPLETE, nothing to report.
    #>
    param($Inventory, $Identity)
    $ds = Get-AtmHintProperty -Item $Inventory -Name 'DiscoveryStatus'
    if ($null -eq $ds) { return New-AtmCoverage -Collector 'profile-discovery' -Status 'NOT_OBSERVABLE' -Reasons @('DISCOVERY_STATUS_UNAVAILABLE') -ElevationWouldHelp 'NO' }
    $gaps = @($ds.Gaps | Where-Object { $null -ne $_ -and $script:AtmDiscoveryGapCodes -ccontains [string]$_.Code })
    $n = @($Inventory.Profiles).Count
    if ($ds.Overridden -or $gaps.Count -eq 0) { return New-AtmCoverage -Collector 'profile-discovery' -Status 'COMPLETE' -ElevationWouldHelp 'NO' -Observed $n }
    $denied = @($gaps | Where-Object { @('USER_ENVIRONMENT_DENIED', 'VOLATILE_ENVIRONMENT_UNREADABLE', 'PROFILES_DIRECTORY_UNREADABLE', 'LOADED_HIVES_UNREADABLE') -ccontains [string]$_.Code }).Count
    $help = $(if ($denied -eq 0) { 'NO' } elseif ([bool]$Identity.IsElevatedAdministrator) { 'UNKNOWN' } else { 'YES' })
    return New-AtmCoverage -Collector 'profile-discovery' -Status 'PARTIAL' -Reasons @(Get-AtmSortedCodes @($gaps | ForEach-Object { [string]$_.Code })) -ElevationWouldHelp $help -Observed $n
}

# ---------------------------------------------------------------------------------------------
# Windows services (P2-A, ADR-0005). One local CIM query of Win32_Service, filtered by the exact names that providers
# declare (GetServiceHints, ADR-0008); nothing is started, stopped or reconfigured, no other machine is asked, and no
# name is guessed from display names or paths. The query runs before the process snapshot of the run: a PID reported
# by the service control manager is linked to a process only when the snapshot (taken after the query) holds that PID
# with a verified identity created before the query started, so the process owned the PID during the whole query.
# PathName is reduced in memory to the executable (full path only in a well-known program location, otherwise the file
# name, read as text only: nothing is looked up on disk) and dropped; its arguments are never kept. A declared name
# the service control manager does not list is UNKNOWN (P2-A-S: not listed for this account is not proof of absence);
# the collector never produces NOT_PRESENT. Account names are never exported (ADR-0012). No state authorizes anything.
# ---------------------------------------------------------------------------------------------

$script:AtmServiceCimProperties = @('Name', 'State', 'StartMode', 'DelayedAutoStart', 'StartName', 'ProcessId', 'PathName')
$script:AtmServiceMaxNames = 64
$script:AtmServiceTimeoutSec = 30
$script:AtmServiceStateMap = @{ 'Running' = 'RUNNING'; 'Stopped' = 'STOPPED'; 'Paused' = 'PAUSED'; 'Start Pending' = 'PENDING'; 'Stop Pending' = 'PENDING'; 'Continue Pending' = 'PENDING'; 'Pause Pending' = 'PENDING' }
$script:AtmServiceStartModes = @('Boot', 'System', 'Auto', 'Manual', 'Disabled')
$script:AtmServiceAccountKinds = @('LOCAL_SYSTEM', 'LOCAL_SERVICE', 'NETWORK_SERVICE', 'VIRTUAL', 'BUILTIN', 'MANAGED', 'USER')
$script:AtmServiceReasonCodes = @('SERVICE_HINTS_NONE', 'SERVICE_HINTS_INCOMPLETE', 'SERVICE_HINTS_CAPPED', 'SERVICE_QUERY_DENIED', 'SERVICE_QUERY_FAILED', 'SERVICE_QUERY_TIMEOUT',
    'SERVICE_QUERY_NOT_COMPLETED', 'SERVICE_UNEXPECTED_ROW', 'SERVICE_DUPLICATE_ROW', 'SERVICE_PROPERTY_UNREADABLE', 'SERVICE_PROCESS_UNVERIFIED', 'SERVICE_NOT_LISTED_FOR_ACCOUNT')
$script:AtmServiceEvidenceCodes = @('SERVICE_HINT', 'SERVICE_NOT_LISTED', 'SERVICE_NOT_QUERIED', 'SERVICE_STATE', 'SERVICE_STATE_UNREADABLE', 'SERVICE_START_MODE', 'SERVICE_START_MODE_UNREADABLE',
    'SERVICE_DELAYED_AUTO_START', 'SERVICE_DELAYED_AUTO_START_UNREADABLE', 'SERVICE_ACCOUNT_KIND', 'SERVICE_ACCOUNT', 'SERVICE_ACCOUNT_UNREADABLE', 'SERVICE_EXECUTABLE', 'SERVICE_EXECUTABLE_NAME',
    'SERVICE_EXECUTABLE_UNREADABLE', 'SERVICE_PROCESS_VERIFIED', 'SERVICE_PROCESS_UNVERIFIED', 'SERVICE_DUPLICATE_ROW')
# Why a reported PID is not linked (detail of SERVICE_PROCESS_UNVERIFIED).
$script:AtmServiceLinkCodes = @('PID_NOT_REPORTED', 'SERVICE_NOT_RUNNING', 'PROCESS_SNAPSHOT_UNAVAILABLE', 'SNAPSHOT_BEFORE_QUERY', 'DUPLICATE_PID', 'PROCESS_NOT_COLLECTED', 'CREATION_TIME_UNKNOWN', 'CREATED_AFTER_QUERY')

function Get-AtmServiceProgramRoots {
    # Well-known program locations (ADR-0005): the Windows folder and the program files folders, drive-absolute, each
    # ending with a backslash.
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($v in @($env:SystemRoot, [Environment]::GetFolderPath('Windows'), $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramW6432)) {
        if ([string]::IsNullOrWhiteSpace($v) -or $v -notmatch '^[A-Za-z]:\\[^%*?"<>|]*$') { continue }
        $r = $v.TrimEnd('\') + '\'
        if (-not $out.Contains($r)) { $out.Add($r) }
    }
    return $out.ToArray()
}

function ConvertFrom-AtmServicePathName {
    <#
      The executable of a service command line, read as untrusted text only (ADR-0005 rule 4, P2-A-S): nothing is
      opened, run, resolved or looked up on any disk. Returns Path (the full path, only under a well-known program
      location), Name (the file name) and Reason (EXECUTABLE_UNREADABLE when there is no value, EXECUTABLE_UNPARSEABLE
      otherwise); the command line and its arguments are never returned, and a failure keeps only that code.
      Candidate: the text between the first pair of quotes, or (unquoted) the text up to the first ".exe" followed by
      a space or the end. Unambiguous only when:
        * unquoted, it holds no white space (arguments are separated by white space);
        * quoted, ".exe" appears once, at its end (a whole command line inside the quotes is refused);
        * it holds no '=', '/', '*', '?', '<', '>', '|', control character, second ':' or variable other than
          \SystemRoot\, %SystemRoot%, %windir% and the program files variables (read as their folders);
        * it is not a network or device form (\\server\..., \\.\..., \\?\...); \??\ before a drive letter is dropped;
        * the file name has no white space.
      The full path is returned only when every folder is plain (no empty, '.', '..', dots-only, or leading or
      trailing space or dot) and it is textually under a well-known program location; otherwise the file name only.
    #>
    param($PathName, [string[]]$Roots = (Get-AtmServiceProgramRoots))
    $out = [ordered]@{ Path = $null; Name = $null; Reason = $null }
    if (-not ($PathName -is [string]) -or [string]::IsNullOrWhiteSpace($PathName)) { $out.Reason = 'EXECUTABLE_UNREADABLE'; return [pscustomobject]$out }
    $bad = [pscustomobject]@{ Path = $null; Name = $null; Reason = 'EXECUTABLE_UNPARSEABLE' }
    try {
        $s = $PathName.TrimStart()
        $exe = $null; $quoted = $false
        if ($s.StartsWith('"')) {
            $end = $s.IndexOf('"', 1)
            if ($end -gt 1) { $exe = $s.Substring(1, $end - 1); $quoted = $true }
        } else {
            # Windows splits a command line only on space and tab.
            $m = [regex]::Match($s, '^(.+?\.exe)(?=[ \t]|$)', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
            if ($m.Success) { $exe = $m.Groups[1].Value }
        }
        if ($null -eq $exe) { return $bad }
        if ($exe.StartsWith('\??\') -and $exe -match '^\\\?\?\\[A-Za-z]:\\') { $exe = $exe.Substring(4) }
        # No control, format or line/paragraph separator characters (display spoofing), no list separators.
        if ($exe.StartsWith('\\') -or $exe -match '[\x00-\x1f"*?<>|=/,;]' -or $exe -match '[\p{C}\p{Zl}\p{Zp}]') { return $bad }
        if ($quoted) {
            # ".exe" once, at the end, and no switch-like " -": a misquoted command line is never taken apart.
            if ([regex]::Matches($exe, '\.exe', [Text.RegularExpressions.RegexOptions]::IgnoreCase).Count -ne 1 -or $exe -notmatch '(?i)\.exe$' -or $exe -match '\s-') { return $bad }
            if ($exe -match '[^\S ]') { return $bad }
        } elseif ($exe -match '\s') { return $bad }
        $map = [ordered]@{ '\SystemRoot\' = $env:SystemRoot; '%SystemRoot%\' = $env:SystemRoot; '%windir%\' = $env:SystemRoot; '%ProgramFiles%\' = $env:ProgramFiles; '%ProgramFiles(x86)%\' = ${env:ProgramFiles(x86)}; '%ProgramW6432%\' = $env:ProgramW6432 }
        foreach ($k in $map.Keys) {
            if ($exe.StartsWith($k, [StringComparison]::OrdinalIgnoreCase)) { if ($map[$k]) { $exe = $map[$k].TrimEnd('\') + '\' + $exe.Substring($k.Length) }; break }
        }
        if ($exe.Contains('%') -or $exe.IndexOf(':', 2) -ge 0 -or ($exe.IndexOf(':') -ge 0 -and $exe -notmatch '^[A-Za-z]:\\')) { return $bad }
        $i = $exe.LastIndexOf('\')
        $leaf = $(if ($i -ge 0) { $exe.Substring($i + 1) } else { $exe })
        if ($leaf -notmatch '^[^\\\s]+\.exe$' -or $leaf -match '^\.+exe$') { return $bad }
        $out.Name = $leaf
        if ($exe -match '^[A-Za-z]:\\' -and -not $exe.Contains('~')) {
            $plain = (@($exe.Substring(3).Split('\') | Where-Object { $_ -eq '' -or $_ -match '^\.+$|[\s.]$|^\s' }).Count -eq 0)
            # A packaged app folder (\WindowsApps\) carries the package version and architecture: file name only.
            if ($plain -and $exe.IndexOf('\WindowsApps\', [StringComparison]::OrdinalIgnoreCase) -lt 0) { foreach ($r in @($Roots)) { if ($exe.StartsWith($r, [StringComparison]::OrdinalIgnoreCase)) { $out.Path = $exe; break } } }
        }
    } catch { return $bad }
    return [pscustomobject]$out
}

function ConvertTo-AtmServiceAccount {
    # Kind of the account a service runs as, and a standard identifier only for the three built-in service accounts
    # (ADR-0012, replacing ADR-0005 rule 6): LocalSystem, NT AUTHORITY\LocalService, NT AUTHORITY\NetworkService.
    # VIRTUAL (NT SERVICE\...), MANAGED (ending with $), BUILTIN (other NT AUTHORITY\...) and USER give the kind only;
    # the raw StartName is read here and never returned. $null when unreadable.
    param($StartName)
    if (-not (Test-AtmHintText -Value $StartName -Max 256)) { return $null }
    $u = $StartName.Trim().ToUpperInvariant()
    if (-not $u) { return $null }
    # One of: name, domain\name, name@domain (no empty part, no second separator, no other control or format character).
    if ($u -notmatch '^(?:[^\\@]+|[^\\@]+\\[^\\@]+|[^\\@]+@[^\\@]+)$' -or $u -match '[\p{C}\p{Zl}\p{Zp}]') { return $null }
    if ($u -ceq 'LOCALSYSTEM' -or $u -ceq 'NT AUTHORITY\SYSTEM' -or $u -ceq '.\LOCALSYSTEM') { return [pscustomobject]@{ Kind = 'LOCAL_SYSTEM'; Account = 'LocalSystem' } }
    if ($u -ceq 'NT AUTHORITY\LOCALSERVICE' -or $u -ceq 'NT AUTHORITY\LOCAL SERVICE') { return [pscustomobject]@{ Kind = 'LOCAL_SERVICE'; Account = 'NT AUTHORITY\LocalService' } }
    if ($u -ceq 'NT AUTHORITY\NETWORKSERVICE' -or $u -ceq 'NT AUTHORITY\NETWORK SERVICE') { return [pscustomobject]@{ Kind = 'NETWORK_SERVICE'; Account = 'NT AUTHORITY\NetworkService' } }
    if ($u.StartsWith('NT SERVICE\', [StringComparison]::Ordinal)) { return [pscustomobject]@{ Kind = 'VIRTUAL'; Account = $null } }
    if ($u.StartsWith('NT AUTHORITY\', [StringComparison]::Ordinal)) { return [pscustomobject]@{ Kind = 'BUILTIN'; Account = $null } }
    if ($u.EndsWith('$')) { return [pscustomobject]@{ Kind = 'MANAGED'; Account = $null } }
    return [pscustomobject]@{ Kind = 'USER'; Account = $null }
}

function Get-AtmServiceRaw {
    # One local CIM query of Win32_Service for the given exact names, the allowed properties only, bounded by the CIM
    # operation timeout (enforced by CIM; not a guaranteed cancellation). Names are checked again here (letters,
    # digits, space, '_', '.', '-'), so the filter holds only quoted literals.
    param([string[]]$Names, [int]$TimeoutSec)
    foreach ($n in $Names) { if ($n -notmatch '^[A-Za-z0-9_.\- ]+$') { throw (New-Object ArgumentException('name')) } }
    $filter = (@($Names | ForEach-Object { "Name='$_'" }) -join ' OR ')
    @(Get-CimInstance -ClassName Win32_Service -Property $script:AtmServiceCimProperties -Filter $filter -OperationTimeoutSec $TimeoutSec -ErrorAction Stop |
        ForEach-Object {
            $row = [ordered]@{}
            foreach ($p in $script:AtmServiceCimProperties) { $row[$p] = $_.$p }
            [pscustomobject]$row
        })
}

function Test-AtmAccessDeniedException {
    # Access denied by type (UnauthorizedAccessException), CIM native code (AccessDenied) or HRESULT (E_ACCESSDENIED,
    # WBEM_E_ACCESS_DENIED). Nothing of the message is read.
    param($Exception)
    if ($null -eq $Exception) { return $false }
    if ($Exception -is [UnauthorizedAccessException]) { return $true }
    $nc = $Exception.PSObject.Properties['NativeErrorCode']
    if ($null -ne $nc -and [string]$nc.Value -ceq 'AccessDenied') { return $true }
    # 0x80070005 and 0x80041003 as signed 32-bit values (the same literal reads differently in 5.1 and 7).
    return (@(-2147024891, -2147217405) -contains [int]$Exception.HResult)
}

function Invoke-AtmServiceQuery {
    <#
      The services query of a run (before its process snapshot). -ProviderHints: Get-AtmProviderRuntimeHints results.
      -Source (tests): param($Names) returning rows with AtmServiceCimProperties (or throwing). -NowUtc (tests): the
      query start. Returns Declared (one entry per name, case-insensitive, with its providers and roles), Rows (by
      declared name; PathName already reduced to the executable and dropped), QueryUtc, Capped (names not queried) and
      Coverage ('services'): NOT_OBSERVABLE (no declared name: nothing is queried, never "no services"), TIMEOUT,
      DENIED, FAILED, COMPLETE, or PARTIAL (hints incomplete or capped, unexpected or duplicate rows).
    #>
    param($ProviderHints = @(), [scriptblock]$Source = $null, $Deadline = $null, [int]$TimeoutSec = $script:AtmServiceTimeoutSec, [int]$MaxNames = $script:AtmServiceMaxNames, $NowUtc = $null, [switch]$HintsIncomplete)
    $reasons = New-Object System.Collections.Generic.List[string]
    # A provider whose hints were never read (deadline, invalid contract) may declare names nobody asked for.
    if ($HintsIncomplete) { $reasons.Add('SERVICE_HINTS_INCOMPLETE') }
    $byName = @{}
    foreach ($h in @($ProviderHints | Where-Object { $null -ne $_ })) {
        if ($h.Coverage.Status -cne 'COMPLETE' -and @($h.Coverage.Reasons | Where-Object { $_ -like 'HINT_*_SERVICE_HINTS' }).Count -gt 0) { $reasons.Add('SERVICE_HINTS_INCOMPLETE') }
        foreach ($s in @($h.ServiceHints)) {
            $k = ([string]$s.Name).ToUpperInvariant()
            if (-not $byName.ContainsKey($k)) { $byName[$k] = [pscustomobject]@{ Name = [string]$s.Name; Providers = New-Object System.Collections.Generic.List[object] } }
            $e = $byName[$k]
            if ([string]::CompareOrdinal([string]$s.Name, $e.Name) -lt 0) { $e.Name = [string]$s.Name }
            if (@($e.Providers | Where-Object { $_.Id -ceq [string]$h.ProviderId -and $_.Role -ceq [string]$s.Role }).Count -eq 0) { $e.Providers.Add([pscustomobject]@{ Id = [string]$h.ProviderId; Role = $(if ($s.Role) { [string]$s.Role } else { $null }) }) }
        }
    }
    foreach ($e in @($byName.Values)) { $e.Providers = $e.Providers.ToArray() }
    $declared = @(Get-AtmOrdinalSorted -Items @($byName.Values) -Signature { param($x) $x.Name.ToUpperInvariant() })
    $out = [ordered]@{ Declared = $declared; Rows = @{}; QueryUtc = $null; QueryEndUtc = $null; Capped = @(); Coverage = $null }
    # The deadline first: a run that ran out of time is TIMEOUT, never "nothing declared".
    if ($null -ne $Deadline -and [datetime]::UtcNow -ge $Deadline) { $out.Coverage = New-AtmDeadlineCoverage 'services'; return [pscustomobject]$out }
    if ($declared.Count -eq 0) {
        $reasons.Insert(0, 'SERVICE_HINTS_NONE')
        $out.Coverage = New-AtmCoverage -Collector 'services' -Status 'NOT_OBSERVABLE' -Reasons @(Get-AtmSortedCodes $reasons) -ElevationWouldHelp 'NO' -Observed 0 -Expected 0
        return [pscustomobject]$out
    }
    $names = @($declared | ForEach-Object { $_.Name })
    if ($names.Count -gt $MaxNames) { $reasons.Add('SERVICE_HINTS_CAPPED'); $out.Capped = @($names[$MaxNames..($names.Count - 1)]); $names = @($names[0..($MaxNames - 1)]) }
    $started = $(if ($null -ne $NowUtc) { ([datetime]$NowUtc).ToUniversalTime() } else { [datetime]::UtcNow })
    $out.QueryUtc = $started
    $budgetMs = [long]$TimeoutSec * 1000
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $raw = $null; $ex = $null
    try { $raw = @(if ($null -ne $Source) { & $Source $names } else { Get-AtmServiceRaw -Names $names -TimeoutSec $TimeoutSec }) } catch { $ex = $_.Exception }
    $sw.Stop()
    $out.QueryEndUtc = $started.AddTicks($sw.Elapsed.Ticks)
    if ($null -ne $ex) {
        # Exception type only, never its message (it could carry a command line).
        $code = ConvertTo-AtmExceptionCode $ex.GetType().Name
        if (Test-AtmAccessDeniedException $ex) { $st = 'DENIED'; $rs = @('SERVICE_QUERY_DENIED', $code); $help = 'UNKNOWN' }
        elseif ($sw.ElapsedMilliseconds -ge $budgetMs) { $st = 'TIMEOUT'; $rs = @('SERVICE_QUERY_TIMEOUT', $code); $help = 'NO' }
        else { $st = 'FAILED'; $rs = @('SERVICE_QUERY_FAILED', $code); $help = 'UNKNOWN' }
        $out.Coverage = New-AtmCoverage -Collector 'services' -Status $st -Reasons (@($rs) + @($reasons)) -ElevationWouldHelp $help -Observed 0 -Expected $declared.Count -StartedUtc $started -ElapsedMs $sw.ElapsedMilliseconds -BudgetMs $budgetMs
        return [pscustomobject]$out
    }
    $want = @{}; foreach ($n in $names) { $want[$n.ToUpperInvariant()] = $n }
    $rows = @{}; $dup = @{}
    foreach ($r in @($raw | Where-Object { $null -ne $_ })) {
        $rn = Get-AtmHintProperty -Item $r -Name 'Name'
        if (-not ($rn -is [string]) -or -not $want.ContainsKey($rn.ToUpperInvariant())) { $reasons.Add('SERVICE_UNEXPECTED_ROW'); continue }
        $dn = $want[$rn.ToUpperInvariant()]
        if ($rows.ContainsKey($dn)) { $dup[$dn] = $true; $reasons.Add('SERVICE_DUPLICATE_ROW'); continue }
        # The command line is reduced here and never stored.
        $exe = ConvertFrom-AtmServicePathName (Get-AtmHintProperty -Item $r -Name 'PathName')
        $rows[$dn] = [pscustomobject]@{
            State = Get-AtmHintProperty -Item $r -Name 'State'; StartMode = Get-AtmHintProperty -Item $r -Name 'StartMode'; DelayedAutoStart = Get-AtmHintProperty -Item $r -Name 'DelayedAutoStart'
            StartName = Get-AtmHintProperty -Item $r -Name 'StartName'; ProcessId = Get-AtmHintProperty -Item $r -Name 'ProcessId'; Executable = $exe; Duplicate = $false
        }
    }
    foreach ($d in @($dup.Keys)) { $rows[$d].Duplicate = $true }
    $out.Rows = $rows
    # The service control manager leaves out services the caller may not query (EnumServicesStatusEx): a declared
    # name that is not listed is not proof of absence, so the query is PARTIAL and the service UNKNOWN (P2-A-S).
    if (@($names | Where-Object { -not $rows.ContainsKey($_) }).Count -gt 0) { $reasons.Add('SERVICE_NOT_LISTED_FOR_ACCOUNT') }
    $st = $(if ($reasons.Count -gt 0) { 'PARTIAL' } else { 'COMPLETE' })
    $out.Coverage = New-AtmCoverage -Collector 'services' -Status $st -Reasons @(Get-AtmSortedCodes $reasons) -ElevationWouldHelp $(if ($st -ceq 'COMPLETE') { 'NO' } else { 'UNKNOWN' }) -Observed @($rows.Keys).Count -Expected $declared.Count -StartedUtc $started -ElapsedMs $sw.ElapsedMilliseconds -BudgetMs $budgetMs
    return [pscustomobject]$out
}

function Resolve-AtmServiceProcess {
    # The services name of Resolve-AtmTemporalProcessLink (kept for its callers and tests).
    param($Collection, $ProcessId, $QueryUtc, $QueryEndUtc = $null)
    return (Resolve-AtmTemporalProcessLink -Collection $Collection -ProcessId $ProcessId -QueryUtc $QueryUtc -QueryEndUtc $QueryEndUtc)
}

function Resolve-AtmTemporalProcessLink {
    # Link of a PID reported by a source without creation time (a running service, a VM's worker) to a process of a
    # snapshot taken after the query: the process must be verified and created at least 1 us before the query started,
    # and the snapshot must start after the query ended, so the process owned the PID during the whole query.
    # Returns Result MATCH (with Process) or a code of AtmServiceLinkCodes.
    param($Collection, $ProcessId, $QueryUtc, $QueryEndUtc = $null)
    $id = ConvertTo-AtmProcessId $ProcessId
    $endUtc = $(if ($null -ne $QueryEndUtc) { $QueryEndUtc } else { $QueryUtc })
    if ($null -eq $id -or $id -eq 0) { return [pscustomobject]@{ Result = 'PID_NOT_REPORTED'; Process = $null } }
    if ($null -eq $Collection -or $Collection.Failed -or $null -eq $QueryUtc) { return [pscustomobject]@{ Result = 'PROCESS_SNAPSHOT_UNAVAILABLE'; Process = $null } }
    # The snapshot must start after the query ended (and the process must have been created before it started).
    if ($null -eq $Collection.CollectedUtc -or ([datetime]$Collection.CollectedUtc) -lt ([datetime]$endUtc)) { return [pscustomobject]@{ Result = 'SNAPSHOT_BEFORE_QUERY'; Process = $null } }
    if ($Collection.Duplicates.ContainsKey($id)) { return [pscustomobject]@{ Result = 'DUPLICATE_PID'; Process = $null } }
    if (-not $Collection.ByPid.ContainsKey($id)) { return [pscustomobject]@{ Result = 'PROCESS_NOT_COLLECTED'; Process = $null } }
    $p = $Collection.ByPid[$id]
    if ($p.IdentityStatus -cne 'VERIFIED') { return [pscustomobject]@{ Result = 'CREATION_TIME_UNKNOWN'; Process = $null } }
    # The CIM creation time is truncated to 1 us: created before the query only with that margin.
    if ($p.CreationUtc.Ticks + $script:AtmCimCreationResolutionTicks -gt ([datetime]$QueryUtc).ToUniversalTime().Ticks) { return [pscustomobject]@{ Result = 'CREATED_AFTER_QUERY'; Process = $null } }
    return [pscustomobject]@{ Result = 'MATCH'; Process = $p }
}

function Get-AtmServiceFindings {
    <#
      Service findings of a run from its query (Invoke-AtmServiceQuery) and the process snapshot taken after it.
      One finding per declared name, ordered by key (ordinal); key = the declared name. Provider: the declaring
      provider, or $null with PROVIDER_ATTRIBUTION_AMBIGUOUS when several declare it. Coverage: 'services' (the query;
      a name not listed is UNKNOWN, never NOT_PRESENT) and 'service-properties' (unreadable values and unverified links: a value that
      cannot be read is absent from the evidence with an _UNREADABLE code, never 0 or false).
    #>
    param($Query, $Collection = $null)
    $svcCov = $Query.Coverage
    $now = $(if ($null -ne $Query.QueryUtc) { $Query.QueryUtc } else { [datetime]::UtcNow })
    $queried = (@('COMPLETE', 'PARTIAL') -ccontains [string]$svcCov.Status)
    $propReasons = New-Object System.Collections.Generic.List[string]
    $present = 0; $fullyRead = 0
    $items = New-Object System.Collections.Generic.List[object]
    $ev = { param($Code, $Detail) New-AtmEvidence -Code $Code -Source 'service-control-manager' -Collector 'services' -ObservedUtc $now -Detail $Detail }
    foreach ($d in @($Query.Declared)) {
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($p in @(Get-AtmOrdinalSorted -Items @($d.Providers) -Signature { param($x) '{0}|{1}' -f $x.Id, $x.Role })) { $list.Add((New-AtmEvidence -Code 'SERVICE_HINT' -Source 'provider' -Collector 'services' -ObservedUtc $now -Detail $(if ($p.Role) { $p.Id + ':' + $p.Role } else { $p.Id }))) }
        $ids = @($d.Providers | ForEach-Object { $_.Id } | Sort-Object -Unique)
        $prov = $(if ($ids.Count -eq 1) { $ids[0] } else { $null })
        if ($ids.Count -gt 1) { $list.Add((New-AtmEvidence -Code 'PROVIDER_ATTRIBUTION_AMBIGUOUS' -Source 'diagnose' -Collector 'services' -ObservedUtc $now -Detail (@(Get-AtmOrdinalSorted -Items $ids -Signature { param($x) $x }) -join ','))) }
        $state = 'UNKNOWN'; $cov = @($svcCov)
        if (-not $queried -or @($Query.Capped) -ccontains $d.Name) {
            $list.Add((& $ev 'SERVICE_NOT_QUERIED' $(if (@($Query.Capped) -ccontains $d.Name) { 'SERVICE_HINTS_CAPPED' } else { [string]$svcCov.Status })))
        } elseif (-not $Query.Rows.ContainsKey($d.Name)) {
            # Not listed for this account: an observation, never proof that the service does not exist (UNKNOWN; no
            # source distinguishes a missing service from one the account may not see).
            $list.Add((& $ev 'SERVICE_NOT_LISTED' 'NOT_LISTED_FOR_ACCOUNT'))
        } else {
            $present++
            $row = $Query.Rows[$d.Name]; $ok = $true
            $cov = @($svcCov, $null)
            if ($row.Duplicate) { $list.Add((& $ev 'SERVICE_DUPLICATE_ROW' $null)); $ok = $false }
            # Exact spelling only (the table lookup itself ignores case).
            $sc = $(if ($row.State -is [string] -and @($script:AtmServiceStateMap.Keys) -ccontains $row.State) { $script:AtmServiceStateMap[$row.State] } else { $null })
            if ($null -ne $sc) { $list.Add((& $ev 'SERVICE_STATE' $sc)); if (-not $row.Duplicate) { $state = $sc } } else { $list.Add((& $ev 'SERVICE_STATE_UNREADABLE' $null)); $ok = $false }
            $sm = @(if ($row.StartMode -is [string]) { $script:AtmServiceStartModes | Where-Object { $_ -ceq $row.StartMode } })
            if ($sm.Count -eq 1) { $list.Add((& $ev 'SERVICE_START_MODE' $sm[0].ToUpperInvariant())) } else { $list.Add((& $ev 'SERVICE_START_MODE_UNREADABLE' $null)); $ok = $false }
            if ($row.DelayedAutoStart -is [bool]) { $list.Add((& $ev 'SERVICE_DELAYED_AUTO_START' $(if ($row.DelayedAutoStart) { 'TRUE' } else { 'FALSE' }))) } else { $list.Add((& $ev 'SERVICE_DELAYED_AUTO_START_UNREADABLE' $null)); $ok = $false }
            $acc = ConvertTo-AtmServiceAccount $row.StartName
            if ($null -ne $acc) { $list.Add((& $ev 'SERVICE_ACCOUNT_KIND' $acc.Kind)); if ($acc.Account) { $list.Add((& $ev 'SERVICE_ACCOUNT' $acc.Account)) } } else { $list.Add((& $ev 'SERVICE_ACCOUNT_UNREADABLE' $null)); $ok = $false }
            $x = $row.Executable
            if ($x.Path) { $list.Add((& $ev 'SERVICE_EXECUTABLE' $x.Path)) } elseif ($x.Name) { $list.Add((& $ev 'SERVICE_EXECUTABLE_NAME' $x.Name)) } else { $list.Add((& $ev 'SERVICE_EXECUTABLE_UNREADABLE' $x.Reason)); $ok = $false }
            if (-not $ok) { $propReasons.Add('SERVICE_PROPERTY_UNREADABLE') }
            # Process link: only for a running service, only through the snapshot taken after the query.
            $pid0 = ConvertTo-AtmProcessId $row.ProcessId
            if ($sc -ceq 'RUNNING' -and -not $row.Duplicate) {
                $lk = Resolve-AtmServiceProcess -Collection $Collection -ProcessId $row.ProcessId -QueryUtc $Query.QueryUtc -QueryEndUtc $Query.QueryEndUtc
                if ($lk.Result -ceq 'MATCH') { $list.Add((New-AtmEvidence -Code 'SERVICE_PROCESS_VERIFIED' -Source 'diagnose' -Collector 'process-snapshot' -ObservedUtc $now -Detail $lk.Process.Key)) }
                else { $list.Add((New-AtmEvidence -Code 'SERVICE_PROCESS_UNVERIFIED' -Source 'diagnose' -Collector 'process-snapshot' -ObservedUtc $now -Detail $lk.Result)); $propReasons.Add('SERVICE_PROCESS_UNVERIFIED'); $ok = $false }
            } elseif ($null -ne $pid0 -and $pid0 -ne 0) {
                $list.Add((New-AtmEvidence -Code 'SERVICE_PROCESS_UNVERIFIED' -Source 'diagnose' -Collector 'process-snapshot' -ObservedUtc $now -Detail 'SERVICE_NOT_RUNNING'))
            }
            if ($ok) { $fullyRead++ }
        }
        $items.Add([pscustomobject]@{ Declared = $d; State = $state; Evidence = $list.ToArray(); Coverage = $cov; Provider = $prov })
    }
    # One record for the values and links of the services that were listed.
    if (-not $queried) { $pc = New-AtmCoverage -Collector 'service-properties' -Status 'NOT_OBSERVABLE' -Reasons @($(if (@($svcCov.Reasons) -ccontains 'SERVICE_HINTS_NONE') { 'SERVICE_HINTS_NONE' } else { 'SERVICE_QUERY_NOT_COMPLETED' })) -ElevationWouldHelp $svcCov.ElevationWouldHelp }
    else {
        $pst = $(if ($propReasons.Count -gt 0) { 'PARTIAL' } else { 'COMPLETE' })
        $pc = New-AtmCoverage -Collector 'service-properties' -Status $pst -Reasons @(Get-AtmSortedCodes $propReasons) -ElevationWouldHelp $(if ($pst -ceq 'COMPLETE') { 'NO' } else { 'UNKNOWN' }) -Observed $fullyRead -Expected $present -StartedUtc $svcCov.StartedUtc
    }
    $findings = New-Object System.Collections.Generic.List[object]
    foreach ($it in $items) {
        $c = @($it.Coverage | ForEach-Object { if ($null -eq $_) { $pc } else { $_ } })
        $findings.Add((New-AtmFinding -Kind 'Service' -Key $it.Declared.Name -State $it.State -Evidence $it.Evidence -Coverage $c -Provider $it.Provider))
    }
    $sorted = @(Get-AtmOrdinalSorted -Items $findings.ToArray() -Signature { param($f) $f.Key })
    return [pscustomobject]@{ Findings = $sorted; Coverage = @($svcCov, $pc) }
}

# ---------------------------------------------------------------------------------------------
# Virtualization (P2-B, ADR-0005 rules 7-9). Three layers, each with its own coverage record, all read-only and local:
#  * platform ('virtualization-platform'): Win32_ComputerSystem.HypervisorPresent (true inside a virtual machine too:
#    evidence only), the WMI namespace root\virtualization\v2 listed (static namespace instances, no provider) and the
#    state of the Hyper-V management service vmms (one exact-name Win32_Service read, engine-owned, never used to
#    attribute anything). PRESENT only on a positive sign; a namespace or service not listed is UNKNOWN, never absent.
#  * virtual machines ('virtual-machines'): one Msvm_ComputerSystem query, only when the namespace is listed and vmms is
#    running (its provider is hosted by vmms.exe; a stopped service is never started by a query of this tool). A row is
#    a virtual machine only when its Name is a GUID and Caption and Description are the documented VM values; the host
#    row is left out. Display names and GUIDs never leave memory (keyed pseudonyms, ADR-0010).
#  * worker processes ('virtualization-processes'): vmwp.exe and vmmem* from the process snapshot of the run (class
#    only, never the raw name), with the ADR-0003 counters as observed. A worker is never attributed by its name.
# The VM query runs before the process snapshot: a VM's ProcessID is linked to its worker with the same temporal proof
# as services. A VM is attributed to a provider only by an exact VmName hint or by a verified chain (VM -> worker ->
# parent -> process of a running service the same provider declares with ServiceOwner and GetServiceHints). Nothing
# is started, stopped, saved, checkpointed or configured; no VM state authorizes anything.
# ---------------------------------------------------------------------------------------------

$script:AtmVirtTimeoutSec = 30
$script:AtmVmMaxObjects = 256
$script:AtmVmCimProperties = @('Name', 'Caption', 'Description', 'ElementName', 'EnabledState', 'ProcessID')
# EnabledState values whose meaning for a VM the Msvm_ComputerSystem documentation states (the table: 2 running, 3
# turned off, 4 shutting down, 10 starting; the text: 32768 paused, 32769 suspended); any other value (6 enabled but
# offline, 9 quiesce, ...) is UNKNOWN rather than guessed.
$script:AtmVmStateMap = @{ 2 = 'RUNNING'; 3 = 'OFF'; 4 = 'PENDING'; 10 = 'PENDING'; 32768 = 'PAUSED'; 32769 = 'SAVED' }
$script:AtmVirtReasonCodes = @('HYPERVISOR_FLAG_UNREADABLE', 'VIRTUALIZATION_NAMESPACE_NOT_LISTED', 'VIRTUALIZATION_NAMESPACE_DENIED', 'VIRTUALIZATION_NAMESPACE_FAILED',
    'VMMS_NOT_LISTED', 'VMMS_NOT_RUNNING', 'VMMS_STATE_UNREADABLE', 'VMMS_QUERY_DENIED', 'VMMS_QUERY_FAILED', 'VM_QUERY_DENIED', 'VM_QUERY_FAILED', 'VM_QUERY_TIMEOUT', 'VM_LIMIT_EXCEEDED', 'VM_ROW_AMBIGUOUS',
    'VM_ROW_MALFORMED', 'VM_KEY_COLLISION', 'VM_WORKER_UNVERIFIED', 'VM_PROPERTY_UNREADABLE', 'PLATFORM_NOT_OBSERVED', 'WORKER_IDENTITY_UNVERIFIED', 'WORKER_COUNTERS_UNREADABLE',
    'PROCESS_SNAPSHOT_INCOMPLETE', 'PROCESS_SNAPSHOT_UNAVAILABLE')
$script:AtmVirtEvidenceCodes = @('HYPERVISOR_PRESENT_FLAG', 'HYPERVISOR_FLAG_UNREADABLE', 'VIRTUALIZATION_NAMESPACE_LISTED', 'VIRTUALIZATION_NAMESPACE_NOT_LISTED', 'VIRTUALIZATION_NAMESPACE_NOT_QUERIED',
    'VMMS_SERVICE_STATE', 'VMMS_SERVICE_NOT_LISTED', 'VMMS_NOT_QUERIED', 'VIRTUALIZATION_WORKER', 'VIRTUALIZATION_WORKER_UNVERIFIED', 'VIRTUALIZATION_WORKERS_WORKING_SET_BYTES',
    'VIRTUALIZATION_WORKERS_PRIVATE_BYTES', 'VIRTUALIZATION_WORKERS_CPU_TIME_100NS', 'VIRTUALIZATION_WORKER_COUNTERS_INCOMPLETE', 'VM_HINT_NOT_OBSERVED', 'VM_ENABLED_STATE', 'VM_STATE_UNREADABLE',
    'VM_WORKER_VERIFIED', 'VM_WORKER_UNVERIFIED', 'VM_ATTRIBUTED_BY_NAME', 'VM_ATTRIBUTED_BY_SERVICE', 'VM_UNATTRIBUTED', 'VM_KEY_COLLISION', 'VM_NAME_NOT_UNIQUE')

function Get-AtmVirtualizationRaw {
    # One local read-only CIM query per call (-Op), bounded by the CIM operation timeout (enforced by CIM; not a
    # guaranteed cancellation). Never a method, never another machine.
    param([string]$Op, [int]$TimeoutSec)
    switch ($Op) {
        'NamespaceRoot' { return @(Get-CimInstance -Namespace 'root' -ClassName '__NAMESPACE' -Filter "Name='virtualization'" -OperationTimeoutSec $TimeoutSec -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name } }) }
        'NamespaceV2' { return @(Get-CimInstance -Namespace 'root\virtualization' -ClassName '__NAMESPACE' -Filter "Name='v2'" -OperationTimeoutSec $TimeoutSec -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name } }) }
        'Vmms' { return @(Get-CimInstance -ClassName Win32_Service -Property Name, State -Filter "Name='vmms'" -OperationTimeoutSec $TimeoutSec -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Name = $_.Name; State = $_.State } }) }
        # Only HypervisorPresent is kept: the row's other values (the computer name) never leave this line.
        'Hypervisor' { return @(Get-CimInstance -ClassName Win32_ComputerSystem -Property HypervisorPresent -OperationTimeoutSec $TimeoutSec -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ HypervisorPresent = $_.HypervisorPresent } }) }
        'Vms' {
            return @(Get-CimInstance -Namespace 'root\virtualization\v2' -ClassName Msvm_ComputerSystem -Property $script:AtmVmCimProperties -OperationTimeoutSec $TimeoutSec -ErrorAction Stop | ForEach-Object {
                    $row = [ordered]@{}
                    foreach ($p in $script:AtmVmCimProperties) { $row[$p] = $_.$p }
                    [pscustomobject]$row
                })
        }
    }
    throw (New-Object ArgumentException('op'))
}

function Test-AtmInvalidNamespaceException {
    # WBEM_E_INVALID_NAMESPACE (0x8004100E) or the CIM code InvalidNamespace: the namespace is not there for this query.
    param($Exception)
    if ($null -eq $Exception) { return $false }
    $nc = $Exception.PSObject.Properties['NativeErrorCode']
    if ($null -ne $nc -and [string]$nc.Value -ceq 'InvalidNamespace') { return $true }
    return ([int]$Exception.HResult -eq -2147217394)
}

function Invoke-AtmVirtualizationQuery {
    <#
      The platform and VM queries of a run (before its process snapshot). -Source (tests): param($Op) returning rows
      or throwing, Op one of Hypervisor, NamespaceRoot, NamespaceV2, Vmms, Vms. -NowUtc (tests): the VM query start.
      Returns the observations (no display name or GUID leaves the function except inside VmRows, in memory) and the
      coverage records 'virtualization-platform' and 'virtual-machines'.
    #>
    param([scriptblock]$Source = $null, $Deadline = $null, [int]$TimeoutSec = $script:AtmVirtTimeoutSec, [int]$MaxObjects = $script:AtmVmMaxObjects, $NowUtc = $null, $Elevated = $null)
    $out = [ordered]@{ Hypervisor = $null; Namespace = 'NOT_QUERIED'; Vmms = 'NOT_QUERIED'; VmRows = @(); VmQueryUtc = $null; VmQueryEndUtc = $null; HostRows = 0; PlatformCoverage = $null; VmCoverage = $null }
    $run = { param([string]$Op) if ($null -ne $Source) { @(& $Source $Op) } else { Get-AtmVirtualizationRaw -Op $Op -TimeoutSec $TimeoutSec } }
    if ($null -ne $Deadline -and [datetime]::UtcNow -ge $Deadline) {
        $out.PlatformCoverage = New-AtmDeadlineCoverage 'virtualization-platform'; $out.VmCoverage = New-AtmDeadlineCoverage 'virtual-machines'
        return [pscustomobject]$out
    }
    $started = [datetime]::UtcNow
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $pr = New-Object System.Collections.Generic.List[string]
    $outcomes = New-Object System.Collections.Generic.List[string]
    # Hypervisor flag (evidence only).
    try {
        $h = @(& $run 'Hypervisor')
        $v = $(if ($h.Count -eq 1) { Get-AtmHintProperty -Item $h[0] -Name 'HypervisorPresent' } else { $null })
        if ($v -is [bool]) { $out.Hypervisor = $v; $outcomes.Add('OK') } else { $pr.Add('HYPERVISOR_FLAG_UNREADABLE'); $outcomes.Add('UNREADABLE') }
    } catch { $pr.Add('HYPERVISOR_FLAG_UNREADABLE'); $outcomes.Add($(if (Test-AtmAccessDeniedException $_.Exception) { 'DENIED' } else { 'FAILED' })) }
    # Namespace root\virtualization\v2: listed, not listed, denied or failed.
    if ($null -ne $Deadline -and [datetime]::UtcNow -ge $Deadline) { $pr.Add('DEADLINE_EXCEEDED') }
    else {
        try {
            $ns = 'NOT_LISTED'
            if (@(& $run 'NamespaceRoot' | Where-Object { [string](Get-AtmHintProperty -Item $_ -Name 'Name') -ieq 'virtualization' }).Count -gt 0) {
                try { if (@(& $run 'NamespaceV2' | Where-Object { [string](Get-AtmHintProperty -Item $_ -Name 'Name') -ieq 'v2' }).Count -gt 0) { $ns = 'LISTED' } }
                catch { if (-not (Test-AtmInvalidNamespaceException $_.Exception)) { throw } }
            }
            $out.Namespace = $ns; $outcomes.Add('OK')
            if ($ns -ceq 'NOT_LISTED') { $pr.Add('VIRTUALIZATION_NAMESPACE_NOT_LISTED') }
        } catch {
            if (Test-AtmInvalidNamespaceException $_.Exception) { $out.Namespace = 'NOT_LISTED'; $pr.Add('VIRTUALIZATION_NAMESPACE_NOT_LISTED'); $outcomes.Add('OK') }
            elseif (Test-AtmAccessDeniedException $_.Exception) { $out.Namespace = 'DENIED'; $pr.Add('VIRTUALIZATION_NAMESPACE_DENIED'); $outcomes.Add('DENIED') }
            else { $out.Namespace = 'FAILED'; $pr.Add('VIRTUALIZATION_NAMESPACE_FAILED'); $pr.Add((ConvertTo-AtmExceptionCode $_.Exception.GetType().Name)); $outcomes.Add('FAILED') }
        }
    }
    # The management service vmms (exact name, state only).
    if ($null -ne $Deadline -and [datetime]::UtcNow -ge $Deadline) { $pr.Add('DEADLINE_EXCEEDED') }
    else {
        try {
            $rows = @(& $run 'Vmms' | Where-Object { [string](Get-AtmHintProperty -Item $_ -Name 'Name') -ieq 'vmms' })
            if ($rows.Count -eq 0) { $out.Vmms = 'NOT_LISTED'; $pr.Add('VMMS_NOT_LISTED') }
            else {
                $st = Get-AtmHintProperty -Item $rows[0] -Name 'State'
                $out.Vmms = $(if ($st -is [string] -and @($script:AtmServiceStateMap.Keys) -ccontains $st) { $script:AtmServiceStateMap[$st] } else { 'UNREADABLE' })
                if ($out.Vmms -ceq 'UNREADABLE') { $pr.Add('VMMS_STATE_UNREADABLE') }
            }
            $outcomes.Add('OK')
        } catch {
            if (Test-AtmAccessDeniedException $_.Exception) { $out.Vmms = 'DENIED'; $pr.Add('VMMS_QUERY_DENIED'); $outcomes.Add('DENIED') }
            else { $out.Vmms = 'FAILED'; $pr.Add('VMMS_QUERY_FAILED'); $pr.Add((ConvertTo-AtmExceptionCode $_.Exception.GetType().Name)); $outcomes.Add('FAILED') }
        }
    }
    $sw.Stop()
    if ($out.Namespace -cne 'LISTED' -and $out.Vmms -ceq 'NOT_LISTED') { $pr.Add('PLATFORM_NOT_OBSERVED') }
    $bad = @($outcomes | Where-Object { $_ -ceq 'DENIED' -or $_ -ceq 'FAILED' })
    $pst = $(if ($pr.Count -eq 0) { 'COMPLETE' } elseif ($outcomes.Count -gt 0 -and $bad.Count -eq $outcomes.Count) { if (@($bad | Where-Object { $_ -ceq 'FAILED' }).Count -eq 0) { 'DENIED' } else { 'FAILED' } } else { 'PARTIAL' })
    $out.PlatformCoverage = New-AtmCoverage -Collector 'virtualization-platform' -Status $pst -Reasons @(Get-AtmSortedCodes $pr) -ElevationWouldHelp $(if ($pst -ceq 'COMPLETE') { 'NO' } else { 'UNKNOWN' }) -StartedUtc $started -ElapsedMs $sw.ElapsedMilliseconds
    # Virtual machines: only with the namespace listed and vmms running (no query may start the service).
    if ($out.Namespace -cne 'LISTED' -or $out.Vmms -cne 'RUNNING') {
        if (@($pr) -ccontains 'DEADLINE_EXCEEDED') { $out.VmCoverage = New-AtmDeadlineCoverage 'virtual-machines'; return [pscustomobject]$out }
        $why = $(if ($out.Namespace -ceq 'DENIED' -or $out.Namespace -ceq 'FAILED') { 'VIRTUALIZATION_NAMESPACE_' + $out.Namespace } elseif ($out.Namespace -cne 'LISTED') { 'VIRTUALIZATION_NAMESPACE_NOT_LISTED' } elseif ($out.Vmms -ceq 'NOT_LISTED') { 'VMMS_NOT_LISTED' } elseif ($out.Vmms -ceq 'DENIED') { 'VMMS_QUERY_DENIED' } elseif ($out.Vmms -ceq 'FAILED') { 'VMMS_QUERY_FAILED' } elseif ($out.Vmms -ceq 'UNREADABLE') { 'VMMS_STATE_UNREADABLE' } else { 'VMMS_NOT_RUNNING' })
        $out.VmCoverage = New-AtmCoverage -Collector 'virtual-machines' -Status 'NOT_OBSERVABLE' -Reasons @($why) -ElevationWouldHelp 'UNKNOWN'
        return [pscustomobject]$out
    }
    if ($null -ne $Deadline -and [datetime]::UtcNow -ge $Deadline) { $out.VmCoverage = New-AtmDeadlineCoverage 'virtual-machines'; return [pscustomobject]$out }
    $vStarted = $(if ($null -ne $NowUtc) { ([datetime]$NowUtc).ToUniversalTime() } else { [datetime]::UtcNow })
    $out.VmQueryUtc = $vStarted
    $budgetMs = [long]$TimeoutSec * 1000
    $vsw = [Diagnostics.Stopwatch]::StartNew()
    $raw = $null; $ex = $null
    try { $raw = @(& $run 'Vms') } catch { $ex = $_.Exception }
    $vsw.Stop()
    $out.VmQueryEndUtc = $vStarted.AddTicks($vsw.Elapsed.Ticks)
    if ($null -ne $ex) {
        $code = ConvertTo-AtmExceptionCode $ex.GetType().Name
        if (Test-AtmAccessDeniedException $ex) { $out.VmCoverage = New-AtmCoverage -Collector 'virtual-machines' -Status 'DENIED' -Reasons @('VM_QUERY_DENIED', $code) -ElevationWouldHelp $(if ($Elevated -eq $true) { 'UNKNOWN' } else { 'YES' }) -StartedUtc $vStarted -ElapsedMs $vsw.ElapsedMilliseconds -BudgetMs $budgetMs }
        elseif ($vsw.ElapsedMilliseconds -ge $budgetMs) { $out.VmCoverage = New-AtmCoverage -Collector 'virtual-machines' -Status 'TIMEOUT' -Reasons @('VM_QUERY_TIMEOUT', $code) -ElevationWouldHelp 'NO' -StartedUtc $vStarted -ElapsedMs $vsw.ElapsedMilliseconds -BudgetMs $budgetMs }
        else { $out.VmCoverage = New-AtmCoverage -Collector 'virtual-machines' -Status 'FAILED' -Reasons @('VM_QUERY_FAILED', $code) -ElevationWouldHelp 'UNKNOWN' -StartedUtc $vStarted -ElapsedMs $vsw.ElapsedMilliseconds -BudgetMs $budgetMs }
        return [pscustomobject]$out
    }
    $vr = New-Object System.Collections.Generic.List[string]
    $rows = @($raw | Where-Object { $null -ne $_ })
    if ($rows.Count -gt $MaxObjects) { $vr.Add('VM_LIMIT_EXCEEDED'); $rows = @($rows[0..($MaxObjects - 1)]) }
    $vms = New-Object System.Collections.Generic.List[object]
    $hosts = 0
    foreach ($r in $rows) {
        $name = Get-AtmHintProperty -Item $r -Name 'Name'; $cap = Get-AtmHintProperty -Item $r -Name 'Caption'; $desc = Get-AtmHintProperty -Item $r -Name 'Description'
        $guid = ($name -is [string] -and $name -match '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$')
        if ($cap -ceq 'Hosting Computer System' -and $desc -ceq 'Microsoft Hosting Computer System' -and -not $guid) { $hosts++; continue }
        # The documented description, or the wording also reported by Hyper-V hosts; anything else is not counted.
        if (-not ($guid -and $cap -ceq 'Virtual Machine' -and @('Microsoft Virtual Computer System', 'Microsoft Virtual Machine') -ccontains $desc)) {
            $vr.Add($(if ($name -is [string] -or $cap -is [string]) { 'VM_ROW_AMBIGUOUS' } else { 'VM_ROW_MALFORMED' })); continue
        }
        # An integer type only (never a string), within the uint16 range of the property.
        $es = Get-AtmHintProperty -Item $r -Name 'EnabledState'
        $esn = $(if ($null -ne $es -and -not ($es -is [string]) -and -not ($es -is [bool])) { ConvertTo-AtmProcessCounter $es } else { $null })
        if ($null -ne $esn -and $esn -gt 65535) { $esn = $null }
        $en = Get-AtmHintProperty -Item $r -Name 'ElementName'
        $vms.Add([pscustomobject]@{ Guid = $name.ToLowerInvariant(); ElementName = $(if (Test-AtmHintText -Value $en -Max 256) { $en } else { $null }); EnabledState = $esn; ProcessId = (Get-AtmHintProperty -Item $r -Name 'ProcessID') })
    }
    $out.VmRows = $vms.ToArray(); $out.HostRows = $hosts
    $vst = $(if ($vr.Count -gt 0) { 'PARTIAL' } else { 'COMPLETE' })
    $out.VmCoverage = New-AtmCoverage -Collector 'virtual-machines' -Status $vst -Reasons @(Get-AtmSortedCodes $vr) -ElevationWouldHelp $(if ($vst -ceq 'COMPLETE') { 'NO' } else { 'UNKNOWN' }) -Observed $vms.Count -Expected $null -StartedUtc $vStarted -ElapsedMs $vsw.ElapsedMilliseconds -BudgetMs $budgetMs
    return [pscustomobject]$out
}

function Get-AtmVirtualizationWorkerClass {
    # VMWP (vmwp.exe) or VMMEM (vmmem, vmmem.<suffix>, vmmemWSL); $null for any other name. The raw name is never kept.
    param($Name)
    if (-not ($Name -is [string])) { return $null }
    if ($Name -ieq 'vmwp.exe') { return 'VMWP' }
    if ($Name -match '(?i)^vmmem(wsl)?(\.exe)?$' -or $Name -match '(?i)^vmmem\.[^\\/]+$') { return 'VMMEM' }
    return $null
}

function Get-AtmVirtualizationFindings {
    <#
      Findings of the run from its virtualization query and the process snapshot taken after it: one
      VirtualizationPlatform finding (key 'host') and one VirtualMachine finding per VM (key 'vm/v-<32 hex>', keyed
      pseudonym of the VM GUID; colliding keys are one UNKNOWN finding). -ProviderHints: Get-AtmProviderRuntimeHints
      results; -ServiceFindings: the run's Service findings (for ServiceOwner chains). Coverage adds
      'virtualization-processes'.
    #>
    param($Query, $Collection = $null, $Pseudonymizer, $ProviderHints = @(), $ServiceFindings = @())
    $now = $(if ($null -ne $Query.VmQueryUtc) { $Query.VmQueryUtc } else { [datetime]::UtcNow })
    $ev = { param([string]$Code, [string]$Collector, $Detail) New-AtmEvidence -Code $Code -Source 'virtualization' -Collector $Collector -ObservedUtc $now -Detail $Detail }
    # Worker processes (layer 3).
    $wr = New-Object System.Collections.Generic.List[string]
    $plat = New-Object System.Collections.Generic.List[object]
    $workers = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Collection -or $Collection.Failed) {
        $pc = New-AtmCoverage -Collector 'virtualization-processes' -Status 'NOT_OBSERVABLE' -Reasons @('PROCESS_SNAPSHOT_UNAVAILABLE') -ElevationWouldHelp 'UNKNOWN'
    } else {
        if ($Collection.Coverage.Status -cne 'COMPLETE') { $wr.Add('PROCESS_SNAPSHOT_INCOMPLETE') }
        foreach ($p in @($Collection.Processes)) { $cls = Get-AtmVirtualizationWorkerClass $p.Name; if ($cls) { $workers.Add([pscustomobject]@{ Class = $cls; Process = $p }) } }
        $sums = [ordered]@{ WorkingSetBytes = 0L; PrivateBytes = 0L; Cpu = 0L }; $known = 0; $incomplete = $false
        foreach ($w in @(Get-AtmOrdinalSorted -Items $workers.ToArray() -Signature { param($x) '{0}|{1:D10}' -f $x.Class, $x.Process.Pid })) {
            $p = $w.Process
            if ($p.IdentityStatus -ceq 'VERIFIED' -and $p.Key) { $plat.Add((& $ev 'VIRTUALIZATION_WORKER' 'virtualization-processes' ($w.Class + '|' + $p.Key))) }
            else { $plat.Add((& $ev 'VIRTUALIZATION_WORKER_UNVERIFIED' 'virtualization-processes' ($w.Class + '|pid:' + $p.Pid))); $wr.Add('WORKER_IDENTITY_UNVERIFIED') }
            $rs = $p.Resources
            $ws = $(if ($null -ne $rs) { $rs.WorkingSetBytes } else { $null }); $pb = $(if ($null -ne $rs) { $rs.PrivateBytes } else { $null })
            $kt = $(if ($null -ne $rs) { $rs.KernelTime100ns } else { $null }); $ut = $(if ($null -ne $rs) { $rs.UserTime100ns } else { $null })
            if ($null -eq $ws -or $null -eq $pb -or $null -eq $kt -or $null -eq $ut) { $incomplete = $true; continue }
            $sums.WorkingSetBytes += [long]$ws; $sums.PrivateBytes += [long]$pb; $sums.Cpu += ([long]$kt + [long]$ut); $known++
        }
        if ($workers.Count -gt 0) {
            # Totals over the workers whose counters were read; never 0 for an unread value (no total when none was read).
            if ($known -gt 0) {
                $plat.Add((& $ev 'VIRTUALIZATION_WORKERS_WORKING_SET_BYTES' 'virtualization-processes' ([string]$sums.WorkingSetBytes)))
                $plat.Add((& $ev 'VIRTUALIZATION_WORKERS_PRIVATE_BYTES' 'virtualization-processes' ([string]$sums.PrivateBytes)))
                $plat.Add((& $ev 'VIRTUALIZATION_WORKERS_CPU_TIME_100NS' 'virtualization-processes' ([string]$sums.Cpu)))
            }
            if ($incomplete) { $plat.Add((& $ev 'VIRTUALIZATION_WORKER_COUNTERS_INCOMPLETE' 'virtualization-processes' ('{0}/{1}' -f $known, $workers.Count))); $wr.Add('WORKER_COUNTERS_UNREADABLE') }
        }
        $wst = $(if ($wr.Count -gt 0) { 'PARTIAL' } else { 'COMPLETE' })
        $pc = New-AtmCoverage -Collector 'virtualization-processes' -Status $wst -Reasons @(Get-AtmSortedCodes $wr) -ElevationWouldHelp $(if ($wst -ceq 'COMPLETE') { 'NO' } else { 'UNKNOWN' }) -Observed $workers.Count -Expected $null
    }
    # Platform finding (layer 1).
    $pe = New-Object System.Collections.Generic.List[object]
    if ($null -ne $Query.Hypervisor) { $pe.Add((& $ev 'HYPERVISOR_PRESENT_FLAG' 'virtualization-platform' $(if ($Query.Hypervisor) { 'TRUE' } else { 'FALSE' }))) }
    elseif ($Query.PlatformCoverage.Status -cne 'TIMEOUT') { $pe.Add((& $ev 'HYPERVISOR_FLAG_UNREADABLE' 'virtualization-platform' $null)) }
    switch ($Query.Namespace) {
        'LISTED' { $pe.Add((& $ev 'VIRTUALIZATION_NAMESPACE_LISTED' 'virtualization-platform' 'root\virtualization\v2')) }
        'NOT_LISTED' { $pe.Add((& $ev 'VIRTUALIZATION_NAMESPACE_NOT_LISTED' 'virtualization-platform' 'NOT_LISTED_FOR_ACCOUNT')) }
        default { $pe.Add((& $ev 'VIRTUALIZATION_NAMESPACE_NOT_QUERIED' 'virtualization-platform' ([string]$Query.Namespace))) }
    }
    if ($Query.Vmms -ceq 'NOT_LISTED') { $pe.Add((& $ev 'VMMS_SERVICE_NOT_LISTED' 'virtualization-platform' 'NOT_LISTED_FOR_ACCOUNT')) }
    elseif (@('NOT_QUERIED', 'DENIED', 'FAILED') -ccontains [string]$Query.Vmms) { $pe.Add((& $ev 'VMMS_NOT_QUERIED' 'virtualization-platform' ([string]$Query.Vmms))) }
    else { $pe.Add((& $ev 'VMMS_SERVICE_STATE' 'virtualization-platform' ([string]$Query.Vmms))) }
    $present = ($Query.Namespace -ceq 'LISTED' -or @('RUNNING', 'STOPPED', 'PAUSED', 'PENDING', 'UNREADABLE') -ccontains [string]$Query.Vmms)
    foreach ($e in $plat) { $pe.Add($e) }
    # Virtual machines (layer 2) and attribution.
    $hintsBy = @{}
    foreach ($h in @($ProviderHints | Where-Object { $null -ne $_ })) { foreach ($vh in @($h.VirtualizationHints)) { $hintsBy[[string]$h.ProviderId] = @(@($hintsBy[[string]$h.ProviderId]) + @($vh) | Where-Object { $null -ne $_ }) } }
    $svcByName = @{}; foreach ($sf in @($ServiceFindings | Where-Object { $null -ne $_ })) { $svcByName[$sf.Key.ToUpperInvariant()] = $sf }
    $vmCov = $Query.VmCoverage
    $byKey = @{}
    $matchedNames = @{}
    $vmGaps = New-Object System.Collections.Generic.List[string]
    # A display name carried by two observed VMs identifies neither (no VmName attribution for them).
    $nameCount = @{}; foreach ($vm in @($Query.VmRows)) { if ($null -ne $vm.ElementName) { $u = $vm.ElementName.ToUpperInvariant(); $nameCount[$u] = 1 + $(if ($nameCount.ContainsKey($u)) { $nameCount[$u] } else { 0 }) } }
    foreach ($vm in @($Query.VmRows)) {
        $key = 'vm/v-' + (Get-AtmPseudonym -Pseudonymizer $Pseudonymizer -Domain 'atm-virtual-machine/1' -Fields @($vm.Guid))
        $list = New-Object System.Collections.Generic.List[object]
        $state = 'UNKNOWN'
        if ($null -ne $vm.EnabledState) {
            $list.Add((& $ev 'VM_ENABLED_STATE' 'virtual-machines' ([string]$vm.EnabledState)))
            if ($script:AtmVmStateMap.ContainsKey([int]$vm.EnabledState)) { $state = $script:AtmVmStateMap[[int]$vm.EnabledState] }
        } else { $list.Add((& $ev 'VM_STATE_UNREADABLE' 'virtual-machines' $null)); $vmGaps.Add('VM_PROPERTY_UNREADABLE') }
        # Worker link (temporal proof) and the verified worker process.
        $worker = $null
        $vpid = ConvertTo-AtmProcessId $vm.ProcessId
        if ($null -ne $vpid -and $vpid -ne 0) {
            $lk = Resolve-AtmTemporalProcessLink -Collection $Collection -ProcessId $vpid -QueryUtc $Query.VmQueryUtc -QueryEndUtc $Query.VmQueryEndUtc
            if ($lk.Result -ceq 'MATCH' -and (Get-AtmVirtualizationWorkerClass $lk.Process.Name) -ceq 'VMWP') { $worker = $lk.Process; $list.Add((& $ev 'VM_WORKER_VERIFIED' 'virtualization-processes' $lk.Process.Key)) }
            else { $list.Add((& $ev 'VM_WORKER_UNVERIFIED' 'virtualization-processes' $(if ($lk.Result -ceq 'MATCH') { 'NOT_A_WORKER_PROCESS' } else { $lk.Result }))); $vmGaps.Add('VM_WORKER_UNVERIFIED') }
        }
        # Attribution: exact VmName, or the verified ServiceOwner chain.
        $provs = New-Object System.Collections.Generic.List[string]
        foreach ($pid0 in @(Get-AtmOrdinalSorted -Items @($hintsBy.Keys) -Signature { param($x) $x })) {
            foreach ($vh in @($hintsBy[$pid0])) {
                if ($vh.Kind -ceq 'VmName' -and $null -ne $vm.ElementName -and [string]::Equals([string]$vh.Value, $vm.ElementName, [StringComparison]::OrdinalIgnoreCase)) {
                    $matchedNames[$pid0 + '|' + ([string]$vh.Value).ToUpperInvariant()] = $true
                    if ($nameCount[$vm.ElementName.ToUpperInvariant()] -gt 1) { if (@($list | Where-Object { $_.Code -ceq 'VM_NAME_NOT_UNIQUE' }).Count -eq 0) { $list.Add((& $ev 'VM_NAME_NOT_UNIQUE' 'virtual-machines' $pid0)) }; continue }
                    if (-not $provs.Contains($pid0)) { $provs.Add($pid0) }
                    $list.Add((& $ev 'VM_ATTRIBUTED_BY_NAME' 'virtual-machines' $pid0))
                }
                if ($vh.Kind -ceq 'ServiceOwner' -and $null -ne $worker) {
                    $sf = $svcByName[([string]$vh.Value).ToUpperInvariant()]
                    if ($null -eq $sf -or $sf.State -cne 'RUNNING') { continue }
                    $declared = @($sf.Evidence | Where-Object { $_.Code -ceq 'SERVICE_HINT' -and ([string]$_.Detail -ceq $pid0 -or ([string]$_.Detail).StartsWith($pid0 + ':', [StringComparison]::Ordinal)) }).Count -gt 0
                    $svcKey = @($sf.Evidence | Where-Object { $_.Code -ceq 'SERVICE_PROCESS_VERIFIED' } | ForEach-Object { [string]$_.Detail })
                    $parent = Get-AtmProcessParentLink -Collection $Collection -Process $worker
                    if ($declared -and $svcKey.Count -eq 1 -and $parent.Result -ceq 'VERIFIED' -and $parent.Parent.Key -ceq $svcKey[0]) {
                        if (-not $provs.Contains($pid0)) { $provs.Add($pid0) }
                        $list.Add((& $ev 'VM_ATTRIBUTED_BY_SERVICE' 'virtual-machines' ($pid0 + '|' + $sf.Key)))
                    }
                }
            }
        }
        $prov = $null
        if ($provs.Count -eq 1) { $prov = $provs[0] }
        elseif ($provs.Count -gt 1) { $list.Add((New-AtmEvidence -Code 'PROVIDER_ATTRIBUTION_AMBIGUOUS' -Source 'diagnose' -Collector 'virtual-machines' -ObservedUtc $now -Detail (@(Get-AtmOrdinalSorted -Items $provs.ToArray() -Signature { param($x) $x }) -join ','))) }
        else { $list.Add((& $ev 'VM_UNATTRIBUTED' 'virtual-machines' $null)) }
        if ($byKey.ContainsKey($key)) { $byKey[$key].Collision = $true; $vmGaps.Add('VM_KEY_COLLISION'); continue }
        $byKey[$key] = [pscustomobject]@{ Key = $key; State = $state; Evidence = $list.ToArray(); Provider = $prov; Collision = $false }
    }
    $findings = New-Object System.Collections.Generic.List[object]
    # Declared VM names that no observed VM carries: an observation on the platform finding, only when VMs were looked
    # at (the query ran), once per provider and name, never an absence.
    if (@('COMPLETE', 'PARTIAL') -ccontains [string]$vmCov.Status) {
        $seenHint = @{}
        foreach ($pid0 in @(Get-AtmOrdinalSorted -Items @($hintsBy.Keys) -Signature { param($x) $x })) {
            foreach ($vh in @($hintsBy[$pid0] | Where-Object { $_.Kind -ceq 'VmName' })) {
                $hk = $pid0 + '|' + ([string]$vh.Value).ToUpperInvariant()
                if (-not $matchedNames.ContainsKey($hk) -and -not $seenHint.ContainsKey($hk)) { $seenHint[$hk] = $true; $pe.Add((& $ev 'VM_HINT_NOT_OBSERVED' 'virtual-machines' $pid0)) }
            }
        }
    }
    # VM-level gaps (unreadable state, unverified worker, key collision) make the VM coverage partial.
    if ($vmGaps.Count -gt 0 -and @('COMPLETE', 'PARTIAL') -ccontains [string]$vmCov.Status) {
        $vmCov = New-AtmCoverage -Collector 'virtual-machines' -Status 'PARTIAL' -Reasons @(Get-AtmSortedCodes (@($vmCov.Reasons) + @($vmGaps))) -ElevationWouldHelp 'UNKNOWN' -Observed $vmCov.Observed -Expected $vmCov.Expected -StartedUtc $vmCov.StartedUtc -ElapsedMs $vmCov.ElapsedMs -BudgetMs $vmCov.BudgetMs
    }
    # VMs first, then the platform: ordinal order of the kinds (VirtualMachine < VirtualizationPlatform), then keys.
    foreach ($k in @(Get-AtmOrdinalSorted -Items @($byKey.Keys) -Signature { param($x) $x })) {
        $v = $byKey[$k]
        if ($v.Collision) { $findings.Add((New-AtmFinding -Kind 'VirtualMachine' -Key $k -State 'UNKNOWN' -Evidence @((& $ev 'VM_KEY_COLLISION' 'virtual-machines' $null)) -Coverage @($vmCov, $pc))); continue }
        $findings.Add((New-AtmFinding -Kind 'VirtualMachine' -Key $k -State $v.State -Evidence $v.Evidence -Coverage @($vmCov, $pc) -Provider $v.Provider))
    }
    # No platform finding when the deadline came before the platform was read (nothing is invented).
    if ($Query.PlatformCoverage.Status -cne 'TIMEOUT') { $findings.Add((New-AtmFinding -Kind 'VirtualizationPlatform' -Key 'host' -State $(if ($present) { 'PRESENT' } else { 'UNKNOWN' }) -Evidence $pe.ToArray() -Coverage @($Query.PlatformCoverage, $pc))) }
    return [pscustomobject]@{ Findings = $findings.ToArray(); Coverage = @($Query.PlatformCoverage, $vmCov, $pc) }
}

# ---------------------------------------------------------------------------------------------
# Dependency graph (P4-A, ADR-0002). A correlation layer over evidence the collectors already produced: it never runs a
# query, opens a file or calls a collector. Nodes are the findings (ADR-0001 kinds, by Key); an endpoint named by
# verified evidence but without a finding (the verified process of a service, the holder of a file) is a node marked
# finding = false; a provider id is the target of ATTRIBUTED_TO (kind Provider, ADR-0002 addendum). Edges carry a
# Relation, a Strength (DIRECT, ANCESTOR, AMBIGUOUS; no number) and the evidence codes that created them. A summary per
# TempPartition and Worktree says what the graph observed (its own vocabulary, never a finding state): states are not
# changed here (P4-B), and nothing in the graph authorizes anything.
# ---------------------------------------------------------------------------------------------

$script:AtmGraphMaxNodes = 100000
$script:AtmGraphMaxEdges = 400000
$script:AtmGraphMaxDepth = 256
$script:AtmGraphMaxMs = 30000
$script:AtmGraphRelations = @('PARENT_OF', 'HOSTS_SERVICE', 'RUNS_SESSION', 'WORKING_DIRECTORY_IN', 'HOLDS_HANDLE_IN', 'REFERENCES_PATH', 'WORKTREE_OF', 'MAPS_PATH', 'ATTRIBUTED_TO')
$script:AtmGraphStrengths = @('DIRECT', 'ANCESTOR', 'AMBIGUOUS')
# Summary of a TempPartition or Worktree: DEPENDENCY_OBSERVED (a DIRECT edge, through any chain of proven edges),
# ANCESTOR_REFERENCE (only references to a parent path: not proof that this item is used), DEPENDENCY_AMBIGUOUS (only
# ambiguous evidence), NONE_OBSERVED (no edge and every relevant collector conclusive), UNKNOWN (anything else).
$script:AtmGraphDependencies = @('DEPENDENCY_OBSERVED', 'ANCESTOR_REFERENCE', 'DEPENDENCY_AMBIGUOUS', 'NONE_OBSERVED', 'UNKNOWN')
$script:AtmGraphReasonCodes = @('GRAPH_NODE_LIMIT', 'GRAPH_EDGE_LIMIT', 'GRAPH_DEPTH_LIMIT', 'GRAPH_TIME_LIMIT', 'GRAPH_PROCESS_SNAPSHOT_UNAVAILABLE', 'GRAPH_LEGACY_SNAPSHOT_UNAVAILABLE',
    'REFERENCE_IDENTITY_UNVERIFIED', 'REFERENCE_UNREADABLE', 'KEY_COLLISION', 'HOLDERS_CAPPED', 'COVERAGE_INCOMPLETE', 'GRAPH_LIMIT')
$script:AtmGraphEdgeEvidenceCodes = @('PATH_REFERENCE_DIRECT', 'PATH_REFERENCE_ANCESTOR', 'PATH_REFERENCE_AMBIGUOUS', 'PARENT_LINK_VERIFIED', 'SERVICE_PROCESS_VERIFIED', 'SESSION_PROCESS_KEY',
    'FILE_HELD_OPEN', 'FILE_HELD_OPEN_UNVERIFIED', 'WORKING_DIRECTORY_IN', 'IN_REPOSITORY', 'WORKTREE_REGISTERED', 'WORKTREE_MAIN', 'PROVIDER_ATTRIBUTION', 'PROVIDER_ATTRIBUTION_AMBIGUOUS')
# Collectors whose coverage a "nothing observed" summary needs (any other status keeps it UNKNOWN).
$script:AtmGraphRelevantCollectors = @{
    'TempPartition' = @('inventory', 'processes', 'process-snapshot', 'handles', 'process-cwd')
    'Worktree'      = @('worktree-discovery', 'process-snapshot', 'handles', 'process-cwd')
}

function Get-AtmDependencyGraph {
    <#
      The dependency graph of a run. -Findings: every finding of the run. -Collection: the process snapshot the
      findings came from (PARENT_OF and reference identities). -LegacySnapshot / -Partitions: the V0.1 inventory (its
      references, resolved in memory to verified identities exactly as the runtime does; their text never leaves this
      function). -PartitionKeyFunction: param($Provider, $Path) -> the partition finding key. -Coverage: the run's
      coverage records. Limits: nodes, edges, depth of the upward walk, milliseconds; a limit that is hit is declared in
      the graph coverage, positive edges already found stay, and no summary says NONE_OBSERVED.
    #>
    param($Findings = @(), $Collection = $null, $LegacySnapshot = $null, $Partitions = @(), [scriptblock]$PartitionKeyFunction = $null, $Coverage = @(),
        [int]$MaxNodes = $script:AtmGraphMaxNodes, [int]$MaxEdges = $script:AtmGraphMaxEdges, [int]$MaxDepth = $script:AtmGraphMaxDepth, [int]$MaxMs = $script:AtmGraphMaxMs)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $started = [datetime]::UtcNow
    $reasons = New-Object System.Collections.Generic.List[string]
    $nodes = @{}          # "Kind|Key" -> node
    $edges = @{}          # "Relation|FromKind|From|ToKind|To" -> edge
    $byTo = @{}           # "Kind|Key" -> list of edge ids
    $byFrom = @{}
    $ctr = @{ Dropped = 0; TimedOut = $false }
    $rank = @{ 'DIRECT' = 0; 'ANCESTOR' = 1; 'AMBIGUOUS' = 2 }
    $dropped = 0
    $limitHit = $false
    $finding = @{}        # "Kind|Key" -> finding
    $allOf = @{}          # "Kind|Key" -> every finding with that key (a duplicate is a collision; its evidence still counts)
    $byKind = @{}         # Kind -> "Kind|Key" in ordinal order
    $self = @{}
    $collided = @{}
    $unread = @{}         # "Kind|Key" -> evidence of the item that could not be read (blocks NONE_OBSERVED)
    foreach ($f in @($Findings | Where-Object { $null -ne $_ })) {
        $nk = [string]$f.Kind + '|' + [string]$f.Key
        if ($f.Kind -ceq 'Process' -and $f.State -ceq 'SELF') { $self[[string]$f.Key] = $true }
        foreach ($ce in @($f.Evidence)) { if ($ce.Code -ceq 'PARTITION_KEY_COLLISION' -or $ce.Code -ceq 'VM_KEY_COLLISION' -or $ce.Code -ceq 'SESSION_KEY_COLLISION') { $collided[$nk] = $true } }
        if ($finding.ContainsKey($nk)) { $collided[$nk] = $true; $allOf[$nk].Add($f); continue }
        $finding[$nk] = $f
        $allOf[$nk] = [System.Collections.Generic.List[object]]::new(); $allOf[$nk].Add($f)
    }
    # Every loop runs in this order, so the items kept under a limit do not depend on the input order (and not on the
    # hash order of a hashtable, which differs between processes in PowerShell 7).
    $fkeys = [string[]]@($finding.Keys)
    [Array]::Sort($fkeys, [StringComparer]::Ordinal)
    foreach ($nk in $fkeys) {
        $kd = [string]$finding[$nk].Kind
        if (-not $byKind.ContainsKey($kd)) { $byKind[$kd] = [System.Collections.Generic.List[string]]::new() }
        $byKind[$kd].Add($nk)
    }
    # The time limit is checked every 256 iterations ($tick), not on each one.
    $tick = 0
    $timeUp = { if ($ctr.TimedOut) { return $true }; if ($sw.ElapsedMilliseconds -gt $MaxMs) { $ctr.TimedOut = $true; if (-not $reasons.Contains('GRAPH_TIME_LIMIT')) { $reasons.Add('GRAPH_TIME_LIMIT') }; return $true }; return $false }
    $addNode = {
        param([string]$Kind, [string]$Key)
        $nk = $Kind + '|' + $Key
        if ($nodes.ContainsKey($nk)) { return $true }
        if ($nodes.Count -ge $MaxNodes) { if (-not $reasons.Contains('GRAPH_NODE_LIMIT')) { $reasons.Add('GRAPH_NODE_LIMIT') }; return $false }
        $nodes[$nk] = [pscustomobject]@{ Kind = $Kind; Key = $Key; Finding = $finding.ContainsKey($nk) }
        return $true
    }
    $addEdge = {
        param([string]$Relation, [string]$FromKind, [string]$From, [string]$ToKind, [string]$To, [string]$Strength, [string]$Code, [string]$Collector, [string]$Detail)
        # The tool's own process is not a dependency of anything (SELF is left out on purpose, not counted).
        if ($FromKind -ceq 'Process' -and $self.ContainsKey($From)) { return }
        if ($FromKind -ceq 'Process' -and $From.StartsWith($script:AtmUnverifiedKeyPrefix, [StringComparison]::Ordinal)) { $Strength = 'AMBIGUOUS' }
        $id = $Relation + '|' + $FromKind + '|' + $From + '|' + $ToKind + '|' + $To
        if (-not $edges.ContainsKey($id)) {
            if ($edges.Count -ge $MaxEdges) { $ctr.Dropped++; if (-not $reasons.Contains('GRAPH_EDGE_LIMIT')) { $reasons.Add('GRAPH_EDGE_LIMIT') }; return }
            if ((-not $nodes.ContainsKey($FromKind + '|' + $From) -and -not (& $addNode $FromKind $From)) -or (-not $nodes.ContainsKey($ToKind + '|' + $To) -and -not (& $addNode $ToKind $To))) { $ctr.Dropped++; return }
            $edges[$id] = [pscustomobject]@{ Relation = $Relation; FromKind = $FromKind; From = $From; ToKind = $ToKind; To = $To; Strength = $Strength; Evidence = [System.Collections.Generic.List[object]]::new(); Seen = @{} }
            $tk = $ToKind + '|' + $To; $fk = $FromKind + '|' + $From
            if (-not $byTo.ContainsKey($tk)) { $byTo[$tk] = [System.Collections.Generic.List[string]]::new() }; $byTo[$tk].Add($id)
            if (-not $byFrom.ContainsKey($fk)) { $byFrom[$fk] = [System.Collections.Generic.List[string]]::new() }; $byFrom[$fk].Add($id)
        }
        $e = $edges[$id]
        # The strongest evidence decides the edge strength (DIRECT > ANCESTOR > AMBIGUOUS); each evidence code is kept.
        if ($rank[$Strength] -lt $rank[$e.Strength]) { $e.Strength = $Strength }
        $sig = $Code + '|' + $Collector + '|' + $Detail
        if (-not $e.Seen.ContainsKey($sig)) { $e.Seen[$sig] = $true; $e.Evidence.Add([pscustomobject]@{ Code = $Code; Collector = $Collector; Detail = $(if ($Detail) { $Detail } else { $null }) }) }
    }
    foreach ($nk in $fkeys) {
        if ($nodes.Count -ge $MaxNodes) { if (-not $reasons.Contains('GRAPH_NODE_LIMIT')) { $reasons.Add('GRAPH_NODE_LIMIT') }; break }
        $nodes[$nk] = [pscustomobject]@{ Kind = [string]$finding[$nk].Kind; Key = [string]$finding[$nk].Key; Finding = $true }
    }
    $listOf = { param([string]$K) if ($byKind.ContainsKey($K)) { return , $byKind[$K].ToArray() }; return , @() }
    $isProcKey = { param([string]$K) ($K -cmatch '^\d{1,10}@\d{1,19}$') -or ($K -cmatch ('^' + [regex]::Escape($script:AtmUnverifiedKeyPrefix) + '\d{1,10}$')) }

    # PARENT_OF: verified parent links between process nodes of the same snapshot.
    if ($null -eq $Collection -or $Collection.Failed) { $reasons.Add('GRAPH_PROCESS_SNAPSHOT_UNAVAILABLE') }
    else {
        foreach ($nk in (& $listOf 'Process')) {
            if ($ctr.TimedOut -or ((++$tick % 256) -eq 0 -and (& $timeUp))) { break }
            $f = $finding[$nk]; $k = [string]$f.Key
            if ($self.ContainsKey($k) -or $k -notmatch '^(\d{1,10})@') { continue }
            $id = [long]$Matches[1]
            if (-not $Collection.ByPid.ContainsKey($id) -or $Collection.ByPid[$id].Key -cne $k) { continue }
            $link = Get-AtmProcessParentLink -Collection $Collection -Process $Collection.ByPid[$id]
            if ($link.Result -ceq 'VERIFIED' -and $finding.ContainsKey('Process|' + $link.Parent.Key) -and -not $self.ContainsKey($link.Parent.Key)) {
                & $addEdge 'PARENT_OF' 'Process' $link.Parent.Key 'Process' $k 'DIRECT' 'PARENT_LINK_VERIFIED' 'process-snapshot' $null
            }
        }
    }

    $null = & $timeUp
    # REFERENCES_PATH: V0.1 references of each partition, resolved to verified identities (unverified: AMBIGUOUS from
    # pid:<n>). Indexes are built once (no per-reference scan of the snapshot).
    $legacyByPid = @{}
    if ($null -ne $LegacySnapshot -and -not $LegacySnapshot.Failed) {
        foreach ($lp in @($LegacySnapshot.Processes | Where-Object { $null -ne $_ })) { $p0 = [long]$lp.Pid; if (-not $legacyByPid.ContainsKey($p0)) { $legacyByPid[$p0] = New-Object System.Collections.Generic.List[object] }; $legacyByPid[$p0].Add($lp) }
    }
    $parts = @($Partitions | Where-Object { $null -ne $_ -and [string](Get-AtmHintProperty -Item $_ -Name 'Kind') -cne 'NotScanned' })
    if ($parts.Count -gt 0 -and ($null -eq $LegacySnapshot -or $LegacySnapshot.Failed)) { $reasons.Add('GRAPH_LEGACY_SNAPSHOT_UNAVAILABLE') }
    $resolved = @{}
    $refsUnread = $false
    $partKeys = [System.Collections.Generic.List[string]]::new(); $partRows = [System.Collections.Generic.List[object]]::new()
    if ($parts.Count -gt 0 -and $null -eq $PartitionKeyFunction) { $refsUnread = $true; $reasons.Add('REFERENCE_UNREADABLE') }
    elseif ($parts.Count -gt 0) {
        # The sort key includes the path only in memory, to order partitions that share a key (a collision).
        foreach ($part in $parts) { $pk0 = [string](& $PartitionKeyFunction ([string]$part.Provider) ([string]$part.Path)); $partKeys.Add($pk0 + '|' + [string]$part.Provider + '|' + [string]$part.Path); $partRows.Add([pscustomobject]@{ Key = $pk0; Part = $part }) }
    }
    $pks = $partKeys.ToArray(); $prs = $partRows.ToArray()
    if ($prs.Count -gt 1) { [Array]::Sort([Array]$pks, [Array]$prs, [Collections.IComparer][StringComparer]::Ordinal) }
    foreach ($pr in $prs) {
        if ($ctr.TimedOut -or ((++$tick % 256) -eq 0 -and (& $timeUp))) { break }
        $part = $pr.Part; $pkey = $pr.Key
        foreach ($spec in @(@('DirectRefs', 'DIRECT', 'PATH_REFERENCE_DIRECT'), @('AncestorRefs', 'ANCESTOR', 'PATH_REFERENCE_ANCESTOR'), @('AmbiguousRefs', 'AMBIGUOUS', 'PATH_REFERENCE_AMBIGUOUS'))) {
            $refs = [string[]]@(foreach ($r0 in @(Get-AtmHintProperty -Item $part -Name $spec[0])) { if ($null -ne $r0) { $r0 } })
            if ($refs.Count -gt 1) { [Array]::Sort($refs, [StringComparer]::Ordinal) }
            foreach ($ref in $refs) {
                # The reference text (an image name and a path tail) is read here only for its PID.
                if (-not ([string]$ref -match $script:AtmPathReferencePattern)) {
                    $unread['TempPartition|' + $pkey] = $true
                    if (-not $reasons.Contains('REFERENCE_UNREADABLE')) { $reasons.Add('REFERENCE_UNREADABLE') }
                    continue
                }
                $rpid = [long]$Matches[1]
                if (-not $resolved.ContainsKey($rpid)) {
                    $from = $null
                    if ($null -ne $Collection -and -not $Collection.Failed -and $legacyByPid.ContainsKey($rpid) -and $legacyByPid[$rpid].Count -eq 1) {
                        $res = Resolve-AtmProcessReference -Collection $Collection -ProcessId $rpid -CreationUtc $legacyByPid[$rpid][0].CreationUtc
                        if ($res.Result -ceq 'MATCH') { $from = $res.Process.Key }
                    }
                    $resolved[$rpid] = $from
                }
                $fromKey = $resolved[$rpid]
                if ($null -ne $fromKey) { & $addEdge 'REFERENCES_PATH' 'Process' $fromKey 'TempPartition' $pkey $spec[1] $spec[2] 'inventory' $null }
                else {
                    if (-not $reasons.Contains('REFERENCE_IDENTITY_UNVERIFIED')) { $reasons.Add('REFERENCE_IDENTITY_UNVERIFIED') }
                    & $addEdge 'REFERENCES_PATH' 'Process' ($script:AtmUnverifiedKeyPrefix + $rpid) 'TempPartition' $pkey 'AMBIGUOUS' $spec[2] 'inventory' $null
                }
            }
        }
    }

    # Evidence on findings: services, sessions, handles, working directories, worktrees, attribution.
    $verifiedKey = '^\d{1,10}@\d{1,19}$'
    $holder = { param([string]$Kind) $Kind -ceq 'TempPartition' -or $Kind -ceq 'Worktree' }
    foreach ($nk in $fkeys) {
      if ($ctr.TimedOut) { break }
      foreach ($f in $allOf[$nk]) {
        if ($ctr.TimedOut -or ((++$tick % 256) -eq 0 -and (& $timeUp))) { break }
        $k = [string]$f.Key; $kind = [string]$f.Kind
        foreach ($e in @($f.Evidence)) {
            $d = [string]$e.Detail
            # Evidence of a holder kind whose detail is not a process key cannot become an edge: recorded, never dropped silently.
            if (@('FILE_HELD_OPEN', 'FILE_HELD_OPEN_UNVERIFIED', 'WORKING_DIRECTORY_IN') -ccontains $e.Code -and (& $holder $kind) -and -not (& $isProcKey $d) -and -not ($d -cmatch '^pid:\d{1,10}$') -and -not ($e.Code -ceq 'FILE_HELD_OPEN_UNVERIFIED' -and $d -ceq 'HOLDERS_CAPPED')) {
                $unread[$nk] = $true
                if (-not $reasons.Contains('REFERENCE_UNREADABLE')) { $reasons.Add('REFERENCE_UNREADABLE') }
            }
            switch ($e.Code) {
                'SERVICE_PROCESS_VERIFIED' { if ($kind -ceq 'Service' -and $d -cmatch $verifiedKey) { & $addEdge 'HOSTS_SERVICE' 'Process' $d 'Service' $k 'DIRECT' 'SERVICE_PROCESS_VERIFIED' 'process-snapshot' $d } }
                'SESSION_PROCESS_KEY' { if ($kind -ceq 'AgentSession' -and $f.State -ceq 'LIVE' -and $d -cmatch '^\d{1,10}@\d{1,19}$') { & $addEdge 'RUNS_SESSION' 'Process' $d 'AgentSession' $k 'DIRECT' 'SESSION_PROCESS_KEY' ([string]$e.Collector) $d } }
                'FILE_HELD_OPEN' { if (($kind -ceq 'TempPartition' -or $kind -ceq 'Worktree') -and (& $isProcKey $d)) { & $addEdge 'HOLDS_HANDLE_IN' 'Process' $d $kind $k 'DIRECT' 'FILE_HELD_OPEN' 'handles' $d } }
                'FILE_HELD_OPEN_UNVERIFIED' { if (($kind -ceq 'TempPartition' -or $kind -ceq 'Worktree') -and $d -cmatch '^pid:\d{1,10}$') { & $addEdge 'HOLDS_HANDLE_IN' 'Process' $d $kind $k 'AMBIGUOUS' 'FILE_HELD_OPEN_UNVERIFIED' 'handles' $d } }
                # No collector produces this in V0.2 (D-1 DEFERRED); fixtures only.
                'WORKING_DIRECTORY_IN' { if (($kind -ceq 'TempPartition' -or $kind -ceq 'Worktree') -and (& $isProcKey $d)) { & $addEdge 'WORKING_DIRECTORY_IN' 'Process' $d $kind $k $(if ($d -cmatch '@') { 'DIRECT' } else { 'AMBIGUOUS' }) 'WORKING_DIRECTORY_IN' 'process-cwd' $d } }
                'IN_REPOSITORY' {
                    if ($kind -ceq 'Worktree' -and $d) {
                        $reg = @($f.Evidence | Where-Object { $_.Code -ceq 'WORKTREE_REGISTERED' -or $_.Code -ceq 'WORKTREE_MAIN' } | ForEach-Object { $_.Code })
                        if ($reg.Count -gt 0) { & $addEdge 'WORKTREE_OF' 'Worktree' $k 'Repository' $d 'DIRECT' $reg[0] 'worktree-discovery' $null }
                        else { & $addEdge 'WORKTREE_OF' 'Worktree' $k 'Repository' $d 'AMBIGUOUS' 'IN_REPOSITORY' 'worktree-discovery' $null }
                    }
                }
            }
        }
        if (@('Process', 'AgentSession', 'Service', 'VirtualMachine') -ccontains $kind -and -not ($kind -ceq 'Process' -and $self.ContainsKey($k))) {
            $amb = @(foreach ($a in @($f.Evidence)) { if ($a.Code -ceq 'PROVIDER_ATTRIBUTION_AMBIGUOUS') { foreach ($pv in ([string]$a.Detail).Split(',')) { if ($pv) { $pv } } } })
            # An ambiguous attribution is one AMBIGUOUS edge per provider and never a DIRECT one, even next to a provider (P2-C D2).
            if ($amb.Count -gt 0) { foreach ($pv in $amb) { & $addEdge 'ATTRIBUTED_TO' $kind $k 'Provider' $pv 'AMBIGUOUS' 'PROVIDER_ATTRIBUTION_AMBIGUOUS' 'diagnose' $null } }
            elseif ($f.Provider) { & $addEdge 'ATTRIBUTED_TO' $kind $k 'Provider' ([string]$f.Provider) 'DIRECT' 'PROVIDER_ATTRIBUTION' 'diagnose' $null }
        }
      }
    }
    # The time limit is also checked once at the end of the edge phase (a small graph never reaches tick 256).
    $null = & $timeUp
    $dropped = $ctr.Dropped
    if ($dropped -gt 0 -or $reasons.Contains('GRAPH_NODE_LIMIT') -or $reasons.Contains('GRAPH_TIME_LIMIT')) { $limitHit = $true }

    # Summaries: TempPartition and Worktree findings. Upward walk through PARENT_OF (bounded, visited set) to the agent
    # roots of each source process.
    # A collector with several records counts by its worst one (one non-conclusive record is enough to block absence).
    $covBy = @{}
    foreach ($c in @($Coverage | Where-Object { $null -ne $_ })) {
        $ck = [string]$c.Collector
        if (-not $covBy.ContainsKey($ck) -or ($script:AtmConclusiveCoverage -ccontains [string]$covBy[$ck].Status -and $script:AtmConclusiveCoverage -cnotcontains [string]$c.Status)) { $covBy[$ck] = $c }
    }
    $summaries = New-Object System.Collections.Generic.List[object]
    # The relevant collectors are the same for every item of a kind: computed once.
    $incompleteBy = @{}
    foreach ($kd in @($script:AtmGraphRelevantCollectors.Keys)) { $incompleteBy[$kd] = @(Get-AtmOrdinalSorted -Items @($script:AtmGraphRelevantCollectors[$kd] | Where-Object { -not $covBy.ContainsKey($_) -or $script:AtmConclusiveCoverage -cnotcontains [string]$covBy[$_].Status }) -Signature { param($x) $x }) }
    $sumKeys = [System.Collections.Generic.List[string]]::new()
    foreach ($kd in @('TempPartition', 'Worktree')) { if ($byKind.ContainsKey($kd)) { $sumKeys.AddRange($byKind[$kd]) } }
    $pending = [System.Collections.Generic.List[object]]::new()
    foreach ($nk in $sumKeys) {
        $f = $finding[$nk]
        $sr = [System.Collections.Generic.List[string]]::new()
        $incoming = [System.Collections.Generic.List[object]]::new()
        if ($byTo.ContainsKey($nk)) { foreach ($id in $byTo[$nk]) { $e = $edges[$id]; if ($e.Relation -ceq 'REFERENCES_PATH' -or $e.Relation -ceq 'HOLDS_HANDLE_IN' -or $e.Relation -ceq 'WORKING_DIRECTORY_IN') { $incoming.Add($e) } } }
        $best = $null
        foreach ($e in $incoming) { if ($null -eq $best -or $rank[$e.Strength] -lt $rank[$best]) { $best = $e.Strength } }
        foreach ($hf in $allOf[$nk]) { foreach ($he in @($hf.Evidence)) { if ($he.Code -ceq 'FILE_HELD_OPEN_UNVERIFIED' -and [string]$he.Detail -ceq 'HOLDERS_CAPPED' -and -not $sr.Contains('HOLDERS_CAPPED')) { $sr.Add('HOLDERS_CAPPED'); if ($null -eq $best) { $best = 'AMBIGUOUS' } } } }
        # Agent roots: PARENT_OF upward only from the DIRECT sources (a verified identity), so a root is never stronger
        # than the chain that leads to it; ancestor and ambiguous sources give no root.
        $roots = [System.Collections.Generic.List[string]]::new()
        foreach ($e in $incoming) {
            if ($e.Strength -cne 'DIRECT' -or -not ($e.From -cmatch $verifiedKey)) { continue }
            $cur = $e.From; $visited = @{}; $depth = 0
            while ($true) {
                if ($ctr.TimedOut -or ((++$tick % 256) -eq 0 -and (& $timeUp))) { $limitHit = $true; break }
                if ($visited.ContainsKey($cur)) { break }
                $visited[$cur] = $true
                $pf = $finding['Process|' + $cur]
                if ($null -ne $pf -and $pf.State -ceq 'AGENT_PROCESS' -and -not $roots.Contains($cur)) { $roots.Add($cur) }
                $next = $null
                if ($byTo.ContainsKey('Process|' + $cur)) { foreach ($id in $byTo['Process|' + $cur]) { if ($edges[$id].Relation -ceq 'PARENT_OF') { $next = $edges[$id].From; break } } }
                if ($null -eq $next) { break }
                $depth++
                if ($depth -gt $MaxDepth) { if (-not $reasons.Contains('GRAPH_DEPTH_LIMIT')) { $reasons.Add('GRAPH_DEPTH_LIMIT') }; $limitHit = $true; break }
                $cur = $next
            }
        }
        $rootArr = $roots.ToArray()
        if ($rootArr.Count -gt 1) { [Array]::Sort($rootArr, [StringComparer]::Ordinal) }
        $pending.Add([pscustomobject]@{ Key = $nk; Finding = $f; Best = $best; Incoming = $incoming.Count; Roots = $rootArr; Reasons = $sr })
    }
    # Decision, with every limit known: a positive source stays; absence needs every relevant collector conclusive, no
    # graph limit and nothing unreadable; anything else is UNKNOWN with the reasons that stopped it.
    foreach ($pd in $pending) {
        $f = $pd.Finding; $kind = [string]$f.Kind; $sr = $pd.Reasons; $best = $pd.Best
        $incomplete = $incompleteBy[$kind]
        $dep = 'UNKNOWN'
        if ($collided.ContainsKey($pd.Key)) { $sr.Add('KEY_COLLISION'); $best = $null }
        elseif ($best -ceq 'DIRECT') { $dep = 'DEPENDENCY_OBSERVED' }
        elseif ($best -ceq 'ANCESTOR') { $dep = 'ANCESTOR_REFERENCE' }
        elseif ($best -ceq 'AMBIGUOUS') { $dep = 'DEPENDENCY_AMBIGUOUS' }
        else {
            if ($incomplete.Count -gt 0) { $sr.Add('COVERAGE_INCOMPLETE') }
            if ($limitHit) { $sr.Add('GRAPH_LIMIT') }
            if ($unread.ContainsKey($pd.Key) -or ($refsUnread -and $kind -ceq 'TempPartition')) { $sr.Add('REFERENCE_UNREADABLE') }
            if ($sr.Count -eq 0) { $dep = 'NONE_OBSERVED' }
        }
        $summaries.Add([pscustomobject]@{ Kind = $kind; Key = [string]$f.Key; Dependency = $dep; Strength = $best; Incoming = $pd.Incoming
                Roots = [string[]]@($pd.Roots); IncompleteCoverage = [string[]]@($incomplete); Reasons = [string[]]@(Get-AtmSortedCodes $sr) })
    }
    $sw.Stop()
    # The [Array]/IComparer casts select the non-generic keys/items overload: the generic one sorts a converted copy of the items.
    # Ordinal order by the ids already built (Relation|FromKind|From|ToKind|To and Kind|Key): no per-item scriptblock.
    $byId = { param([hashtable]$H) $ks = [string[]]@($H.Keys); $vs = [object[]]@(foreach ($x in $ks) { $H[$x] }); [Array]::Sort([Array]$ks, [Array]$vs, [Collections.IComparer][StringComparer]::Ordinal); return , $vs }
    $edgeList = & $byId $edges
    foreach ($e in $edgeList) {
        $e.Evidence = $(if ($e.Evidence.Count -gt 1) { @(Get-AtmOrdinalSorted -Items $e.Evidence.ToArray() -Signature { param($x) '{0}|{1}|{2}' -f $x.Code, $x.Collector, $x.Detail }) } else { $e.Evidence.ToArray() })
        $e.PSObject.Properties.Remove('Seen')
    }
    $graphReasons = @(Get-AtmSortedCodes @($reasons | Where-Object { @('GRAPH_NODE_LIMIT', 'GRAPH_EDGE_LIMIT', 'GRAPH_DEPTH_LIMIT', 'GRAPH_TIME_LIMIT', 'GRAPH_PROCESS_SNAPSHOT_UNAVAILABLE', 'GRAPH_LEGACY_SNAPSHOT_UNAVAILABLE', 'REFERENCE_IDENTITY_UNVERIFIED', 'REFERENCE_UNREADABLE') -ccontains $_ }))
    $st = $(if ($graphReasons.Count -gt 0) { 'PARTIAL' } else { 'COMPLETE' })
    return [pscustomobject]@{
        Nodes     = (& $byId $nodes)
        Edges     = $edgeList
        Summaries = $(if ($summaries.Count -gt 0) { $sk = [string[]]@(foreach ($x in $summaries) { $x.Kind + '|' + $x.Key }); $sv = $summaries.ToArray(); [Array]::Sort([Array]$sk, [Array]$sv, [Collections.IComparer][StringComparer]::Ordinal); , $sv } else { , @() })
        Coverage  = [pscustomobject]@{ Status = $st; Reasons = $graphReasons; Nodes = $nodes.Count; Edges = $edges.Count; DroppedEdges = $dropped; StartedUtc = $started; ElapsedMs = $sw.ElapsedMilliseconds }
    }
}

# ---------------------------------------------------------------------------------------------
# Graph to findings (P4-B, ADR-0002 rule 6). The summaries of the graph of the same run decide the state of each
# TempPartition and Worktree finding, inside the closed lists of ADR-0001: DEPENDENCY_OBSERVED (a DIRECT edge from a
# verified process) is IN_USE; NONE_OBSERVED requests NO_DEPENDENCY_OBSERVED, which New-AtmFinding keeps only with
# conclusive coverage (the relevant collectors and the graph are attached to the finding, so the engine checks it
# again); anything else (ancestor, ambiguous, unknown, collision) is UNKNOWN for a partition and leaves a worktree's
# own facts in place (a no-dependency worktree state needs the same conclusive coverage). The evidence says why: the
# summary, the sources of the incoming edges by strength (process key and relation), the agent roots and the reasons.
# Nothing is collected here, no finding is created for a node without one, and nothing authorizes anything.
# ---------------------------------------------------------------------------------------------

$script:AtmGraphFindingEvidenceCodes = @('GRAPH_DEPENDENCY', 'GRAPH_SOURCE_DIRECT', 'GRAPH_SOURCE_ANCESTOR', 'GRAPH_SOURCE_AMBIGUOUS', 'GRAPH_SOURCES_CAPPED', 'GRAPH_AGENT_ROOT', 'GRAPH_REASON')
$script:AtmGraphFindingMaxSources = 16

function ConvertTo-AtmGraphCoverage {
    # The graph's own coverage as a coverage record (collector 'dependency-graph'), so findings can depend on it.
    param($Graph)
    $gc = $Graph.Coverage
    $rs = @($gc.Reasons)
    if ([string]$gc.Status -ceq 'COMPLETE' -and $rs.Count -eq 0) { return New-AtmCoverage -Collector 'dependency-graph' -Status 'COMPLETE' -ElevationWouldHelp 'NO' -Observed $gc.Edges -StartedUtc $gc.StartedUtc -ElapsedMs $gc.ElapsedMs }
    return New-AtmCoverage -Collector 'dependency-graph' -Status 'PARTIAL' -Reasons @($(if ($rs.Count -gt 0) { $rs } else { 'GRAPH_INCOMPLETE' })) -ElevationWouldHelp 'NO' -Observed $gc.Edges -StartedUtc $gc.StartedUtc -ElapsedMs $gc.ElapsedMs
}

function Set-AtmGraphFindingStates {
    <#
      -Findings: the run's findings (in order); -Graph: Get-AtmDependencyGraph of the same findings; -Coverage: the run's
      coverage records; -GraphCoverage: ConvertTo-AtmGraphCoverage of the graph. Returns the findings in the same
      order, with TempPartition and Worktree findings rebuilt from their summary (one pass over edges and summaries).
    #>
    param($Findings, $Graph, $Coverage, $GraphCoverage)
    $sumBy = @{}
    foreach ($sm in @($Graph.Summaries)) { $sumBy[[string]$sm.Kind + '|' + [string]$sm.Key] = $sm }
    $inBy = @{}
    foreach ($e in @($Graph.Edges)) {
        if (@('REFERENCES_PATH', 'HOLDS_HANDLE_IN', 'WORKING_DIRECTORY_IN') -cnotcontains $e.Relation) { continue }
        $tk = [string]$e.ToKind + '|' + [string]$e.To
        if (-not $inBy.ContainsKey($tk)) { $inBy[$tk] = [System.Collections.Generic.List[object]]::new() }
        $inBy[$tk].Add($e)
    }
    # Worst record per collector (one non-conclusive record is enough to block an absence).
    $covBy = @{}
    foreach ($c in @($Coverage | Where-Object { $null -ne $_ })) {
        $ck = [string]$c.Collector
        if (-not $covBy.ContainsKey($ck) -or ($script:AtmConclusiveCoverage -ccontains [string]$covBy[$ck].Status -and $script:AtmConclusiveCoverage -cnotcontains [string]$c.Status)) { $covBy[$ck] = $c }
    }
    $runNow = [datetime]::UtcNow
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($f in @($Findings)) {
        $kind = [string]$f.Kind
        $nk = $kind + '|' + [string]$f.Key
        if (($kind -cne 'TempPartition' -and $kind -cne 'Worktree') -or -not $sumBy.ContainsKey($nk)) { $out.Add($f); continue }
        $sm = $sumBy[$nk]
        # The graph evidence carries the observation time of the finding's own first evidence: every partition keeps one
        # common time (ADR-0010 D-8), so no field gives the enumeration order back.
        $fev = @($f.Evidence)
        $now = $(if ($fev.Count -gt 0 -and $null -ne $fev[0].ObservedUtc) { $fev[0].ObservedUtc } else { $runNow })
        $ev = [System.Collections.Generic.List[object]]::new()
        $ev.Add((New-AtmEvidence -Code 'GRAPH_DEPENDENCY' -Source 'diagnose' -Collector 'dependency-graph' -ObservedUtc $now -Detail ([string]$sm.Dependency)))
        if ($inBy.ContainsKey($nk)) {
            $srcs = [string[]]@(foreach ($e in $inBy[$nk]) { [string]$e.Strength + '|' + [string]$e.Relation + ' ' + [string]$e.From })
            [Array]::Sort($srcs, [StringComparer]::Ordinal)
            $i = 0
            foreach ($sx in $srcs) {
                if ($i -ge $script:AtmGraphFindingMaxSources) { $ev.Add((New-AtmEvidence -Code 'GRAPH_SOURCES_CAPPED' -Source 'diagnose' -Collector 'dependency-graph' -ObservedUtc $now -Detail ([string]$srcs.Count))); break }
                $cut = $sx.IndexOf('|')
                $ev.Add((New-AtmEvidence -Code ('GRAPH_SOURCE_' + $sx.Substring(0, $cut)) -Source 'diagnose' -Collector 'dependency-graph' -ObservedUtc $now -Detail $sx.Substring($cut + 1)))
                $i++
            }
        }
        $ri = 0
        foreach ($r in @($sm.Roots)) { if ($ri -ge $script:AtmGraphFindingMaxSources) { break }; $ev.Add((New-AtmEvidence -Code 'GRAPH_AGENT_ROOT' -Source 'diagnose' -Collector 'dependency-graph' -ObservedUtc $now -Detail ([string]$r))); $ri++ }
        foreach ($r in @($sm.Reasons)) { $ev.Add((New-AtmEvidence -Code 'GRAPH_REASON' -Source 'diagnose' -Collector 'dependency-graph' -ObservedUtc $now -Detail ([string]$r))) }
        # Coverage the state depends on: the finding's own, the graph's and every relevant collector (a collector that
        # did not run at all is NOT_OBSERVABLE here, never assumed complete).
        $cov = [System.Collections.Generic.List[object]]::new()
        $have = @{}
        foreach ($c in @($f.Coverage)) { $cov.Add($c); $have[[string]$c.Collector] = $true }
        if ($null -ne $GraphCoverage) { $cov.Add($GraphCoverage) }
        foreach ($rc in @($script:AtmGraphRelevantCollectors[$kind])) {
            # Defense in depth (P5-A): the run's worst record of a relevant collector is attached even when the finding
            # already carries a conclusive record of it, so no rebuild can read an absence past a worse record.
            if ($covBy.ContainsKey($rc)) {
                $worst = $covBy[$rc]
                $dup = $false; foreach ($c in $cov) { if ([object]::ReferenceEquals($c, $worst)) { $dup = $true; break } }
                if (-not $dup -and (-not $have.ContainsKey($rc) -or $script:AtmConclusiveCoverage -cnotcontains [string]$worst.Status)) { $cov.Add($worst) }
            } elseif (-not $have.ContainsKey($rc)) { $cov.Add((New-AtmCoverage -Collector $rc -Status 'NOT_OBSERVABLE' -Reasons @('COLLECTOR_NOT_RUN') -ElevationWouldHelp 'NO')) }
        }
        $requested = [string]$f.RequestedState
        $collided = @($f.Evidence | Where-Object { $_.Code -ceq 'PARTITION_KEY_COLLISION' }).Count -gt 0
        if ($kind -ceq 'TempPartition') {
            $state = $(if ($collided) { 'UNKNOWN' } elseif ($sm.Dependency -ceq 'DEPENDENCY_OBSERVED') { 'IN_USE' } elseif ($sm.Dependency -ceq 'NONE_OBSERVED') { 'NO_DEPENDENCY_OBSERVED' } else { 'UNKNOWN' })
        } else {
            # ADR-0006 rule 14: IN_USE first; otherwise the worktree's own facts, and a no-dependency state only when the
            # graph observed nothing (New-AtmFinding then checks the attached coverage).
            # An apparent orphan with ambiguous or ancestor evidence is UNKNOWN: ambiguous evidence never leaves an item
            # looking free (LOCAL_WORK and UNPUBLISHED_COMMITS are reasons to keep it and stay).
            $state = $(if ($sm.Dependency -ceq 'DEPENDENCY_OBSERVED') { 'IN_USE' } elseif ($script:AtmNoDependencyStates -ccontains $requested -and $sm.Dependency -cne 'NONE_OBSERVED') { 'UNKNOWN' } elseif ($requested -ceq 'APPARENT_ORPHAN' -and ($sm.Dependency -ceq 'DEPENDENCY_AMBIGUOUS' -or $sm.Dependency -ceq 'ANCESTOR_REFERENCE')) { 'UNKNOWN' } else { $requested })
        }
        $out.Add((New-AtmFinding -Kind $kind -Key ([string]$f.Key) -State $state -Evidence (@($f.Evidence) + @($ev.ToArray())) -Coverage $cov.ToArray() -Provider $f.Provider))
    }
    return , $out.ToArray()
}

# ---------------------------------------------------------------------------------------------
# Open-file evidence (D-2, ADR-0004, P1-C) and working directories (D-1, deferred). Restart Manager lists the processes
# holding a bounded sample of files of each indexed node (temporary partitions; worktrees when discovery ran); a holder
# is matched with the process snapshot by PID and start time. A sample never proves that a node is free, a holder never
# authorizes anything, and no file path or process name leaves memory: findings get FILE_HELD_OPEN with a process key.
# ---------------------------------------------------------------------------------------------

# P1-C-S security gate: closed in every shipped copy (single assignment; no option, environment variable or file opens
# it). A sampled path is checked and then handed to Restart Manager by name; a concurrent replacement of an ancestor in
# that window is not excluded (TOCTOU, not resolved). Closed, no file of any node is listed and Restart Manager is never
# called: 'handles' is NOT_OBSERVABLE (HANDLE_SECURITY_GATE_CLOSED), never an absence. Tests open it for fixtures only.
$script:AtmHandleDiagnosticsEnabled = $false
# Test spy: when it is a list, every file listing and every Restart Manager query of the collector is added to it
# (operation and count only).
$script:AtmHandleInvocationLog = $null
$script:AtmHandleMaxFilesPerNode = 16
$script:AtmHandleMaxFilesPerRun = 256
$script:AtmHandleMaxSessions = 64
$script:AtmHandleMaxHolders = 64
$script:AtmHandleReasonCodes = @('HANDLE_SECURITY_GATE_CLOSED', 'HANDLES_SAMPLED', 'HANDLE_NO_FILES', 'HANDLE_FILES_CAPPED', 'HANDLE_SESSION_LIMIT', 'HANDLE_QUERY_FAILED', 'HANDLE_HOLDERS_CAPPED', 'HANDLE_IDENTITY_UNVERIFIED',
    'HANDLE_NODE_UNREADABLE', 'HANDLE_NO_NODE', 'PROCESS_SNAPSHOT_UNAVAILABLE', 'WORKING_DIRECTORY_DEFERRED')
$script:AtmHandleEvidenceCodes = @('FILE_HELD_OPEN', 'FILE_HELD_OPEN_UNVERIFIED', 'OPEN_FILES_SAMPLED')

function Get-AtmHandleSampleFiles {
    # Up to -Max regular files directly in -Dir (never recursive). -Dir must be drive-absolute on a fixed drive with no
    # reparse point in its chain (native check); a file name is taken as listed (no expansion, so names such as
    # ~$doc.docx are kept) unless it holds a control character or a colon, and its own chain is checked natively. At
    # most 4 x -Max entries are looked at. Capped is $true when more files exist than were taken. Error:
    # HANDLE_NODE_UNREADABLE; HANDLE_SECURITY_GATE_CLOSED (gate closed: nothing is listed).
    param([string]$Dir, [int]$Max = $script:AtmHandleMaxFilesPerNode)
    $out = [ordered]@{ Files = @(); Capped = $false; Error = $null }
    if (-not $script:AtmHandleDiagnosticsEnabled) { $out.Error = 'HANDLE_SECURITY_GATE_CLOSED'; return [pscustomobject]$out }
    if ([string]::IsNullOrWhiteSpace($Dir) -or $Dir -notmatch '^[A-Za-z]:\\' -or $Dir -match '[\x00-\x1f]' -or $Dir.IndexOf(':', 2) -ge 0) { $out.Error = 'HANDLE_NODE_UNREADABLE'; return [pscustomobject]$out }
    $dirPath = $Dir.TrimEnd('\')
    if ((Test-AtmGitPathChain $dirPath).Status -cne 'OK') { $out.Error = 'HANDLE_NODE_UNREADABLE'; return [pscustomobject]$out }
    $files = New-Object System.Collections.Generic.List[string]
    $seen = 0
    if ($null -ne $script:AtmHandleInvocationLog) { $script:AtmHandleInvocationLog.Add([pscustomobject]@{ Op = 'LIST'; Files = 0 }) }
    try {
        foreach ($fi in (New-Object IO.DirectoryInfo($dirPath)).EnumerateFiles()) {
            $seen++
            if ($seen -gt 4 * $Max) { $out.Capped = $true; break }
            if (($fi.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
            if ($files.Count -ge $Max) { $out.Capped = $true; break }
            if ($fi.Name -match '[\x00-\x1f:]') { continue }
            $fp = $dirPath + '\' + $fi.Name
            if ($fp.Length -lt 260 -and (Test-AtmGitPathChain $fp).Status -ceq 'OK') { $files.Add($fp) }
        }
    } catch { $out.Error = 'HANDLE_NODE_UNREADABLE' }
    $out.Files = $files.ToArray()
    return [pscustomobject]$out
}

function Get-AtmHandleEvidence {
    <#
      Collector 'handles' (D-2). -Nodes: Key, Files (validated local paths), Capped. -Collection: the process snapshot
      (identity of holders); -SelfKeys: this run's own processes (never reported). Limits: files per run, Restart Manager
      sessions (one per node, one at a time), holders per query; -Deadline stops before the next node. -Query (tests):
      param($Files, $MaxHolders) returning Status and Holders ("pid|startTicksUtc"). Returns Evidence (Key -> list) and
      Coverage: never COMPLETE (a sample of files; directories and working directories are not seen by Restart Manager).
      Observation time: every evidence entry of the batch carries the instant the batch started (before its first
      query), which is also the coverage StartedUtc; never the time of another collector. The gate is checked first:
      closed, nothing is queried (not even an injected -Query) and the coverage is NOT_OBSERVABLE.
    #>
    param($Nodes = @(), $Collection = $null, $SelfKeys = $null, [int]$MaxFilesPerRun = $script:AtmHandleMaxFilesPerRun, [int]$MaxSessions = $script:AtmHandleMaxSessions,
        [int]$MaxHolders = $script:AtmHandleMaxHolders, $Deadline = $null, [scriptblock]$Query = $null)
    if (-not $script:AtmHandleDiagnosticsEnabled) { return [pscustomobject]@{ Evidence = @{}; Coverage = (New-AtmCoverage -Collector 'handles' -Status 'NOT_OBSERVABLE' -Reasons @('HANDLE_SECURITY_GATE_CLOSED') -ElevationWouldHelp 'NO') } }
    $started = [datetime]::UtcNow
    $now = $started
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $reasons = New-Object System.Collections.Generic.List[string]
    $evidence = @{}
    # One node per key (the first kept), in ordinal order (caps cut the same nodes on every machine).
    $byKey = [ordered]@{}
    foreach ($x in @($Nodes | Where-Object { $null -ne $_ })) { if (-not $byKey.Contains([string]$x.Key)) { $byKey[[string]$x.Key] = $x } }
    $nodes = @(Get-AtmOrdinalSorted -Items @($byKey.Values) -Signature { param($x) [string]$x.Key })
    if ($nodes.Count -eq 0) { return [pscustomobject]@{ Evidence = $evidence; Coverage = (New-AtmCoverage -Collector 'handles' -Status 'NOT_OBSERVABLE' -Reasons @('HANDLE_NO_NODE') -ElevationWouldHelp 'NO') } }
    if ($null -eq $Collection -or $Collection.Failed) { $reasons.Add('PROCESS_SNAPSHOT_UNAVAILABLE') }
    $self = @{}; if ($null -ne $SelfKeys) { foreach ($k in @($SelfKeys.Keys)) { if ($k) { $self[$k] = $true } } }
    $q = $(if ($null -ne $Query) { $Query } else { { param($Files, $Max) $h = $null; $st = [AgentTempManager.AtmRestartManager]::Query([string[]]$Files, $Max, [ref]$h); [pscustomobject]@{ Status = $st; Holders = @($h) } } })
    $filesUsed = 0; $sessions = 0; $queried = 0
    foreach ($n in $nodes) {
        if ($null -ne $Deadline -and [datetime]::UtcNow -ge $Deadline) { $reasons.Add('DEADLINE_EXCEEDED'); break }
        if ($n.Error) { $reasons.Add([string]$n.Error); continue }
        if ($n.Capped) { $reasons.Add('HANDLE_FILES_CAPPED') }
        $files = @($n.Files)
        if ($files.Count -eq 0) { continue }
        if ($sessions -ge $MaxSessions) { $reasons.Add('HANDLE_SESSION_LIMIT'); break }
        if ($filesUsed + $files.Count -gt $MaxFilesPerRun) {
            $room = $MaxFilesPerRun - $filesUsed
            $reasons.Add('HANDLE_FILES_CAPPED')
            if ($room -le 0) { break }
            $files = @($files[0..($room - 1)])
        }
        $sessions++; $filesUsed += $files.Count
        $res = $null
        if ($null -ne $script:AtmHandleInvocationLog) { $script:AtmHandleInvocationLog.Add([pscustomobject]@{ Op = 'QUERY'; Files = $files.Count }) }
        try { $res = & $q $files $MaxHolders } catch { $res = [pscustomobject]@{ Status = 'FAILED_' + (ConvertTo-AtmExceptionCode $_.Exception.GetType().Name); Holders = @() } }
        $list = New-Object System.Collections.Generic.List[object]
        if ([string]$res.Status -notin @('OK', 'PARTIAL')) { $reasons.Add('HANDLE_QUERY_FAILED'); continue }
        $queried++
        if ($res.Status -ceq 'PARTIAL') {
            $reasons.Add('HANDLE_HOLDERS_CAPPED')
            # More holders than could be listed: the item is held; who holds it is only partly known.
            if (@($res.Holders).Count -eq 0) { $list.Add((New-AtmEvidence -Code 'FILE_HELD_OPEN_UNVERIFIED' -Source 'restart-manager' -Collector 'handles' -ObservedUtc $now -Detail 'HOLDERS_CAPPED')) }
        }
        $list.Add((New-AtmEvidence -Code 'OPEN_FILES_SAMPLED' -Source 'restart-manager' -Collector 'handles' -ObservedUtc $now -Detail ([string]$files.Count)))
        $seen = @{}
        $holders = @($res.Holders)
        if ($holders.Count -gt $MaxHolders) { $reasons.Add('HANDLE_HOLDERS_CAPPED'); $holders = @($holders[0..($MaxHolders - 1)]) }
        foreach ($h in $holders) {
            $parts = ([string]$h).Split('|')
            if ($parts.Count -ne 2) { continue }
            $hpid = ConvertTo-AtmProcessId $parts[0]
            $ticks = 0L; [void][long]::TryParse($parts[1], [ref]$ticks)
            if ($null -eq $hpid) { continue }
            $created = $(if ($ticks -gt 0) { New-Object DateTime($ticks, [DateTimeKind]::Utc) } else { $null })
            $ref = Resolve-AtmProcessReference -Collection $Collection -ProcessId $hpid -CreationUtc $created -CimPrecision
            if ($ref.Result -ceq 'MATCH' -and $ref.Process.Key) {
                if ($self.ContainsKey($ref.Process.Key)) { continue }
                $code = 'FILE_HELD_OPEN'; $detail = [string]$ref.Process.Key
            } else { $code = 'FILE_HELD_OPEN_UNVERIFIED'; $detail = 'pid:' + $hpid; $reasons.Add('HANDLE_IDENTITY_UNVERIFIED') }
            if ($seen.ContainsKey($code + $detail)) { continue }
            $seen[$code + $detail] = $true
            $list.Add((New-AtmEvidence -Code $code -Source 'restart-manager' -Collector 'handles' -ObservedUtc $now -Detail $detail))
        }
        # A node with no holder gets nothing on its finding (absence proves nothing; the coverage record says "sampled").
        if (@($list | Where-Object { $_.Code -like 'FILE_HELD_OPEN*' }).Count -gt 0) { $evidence[[string]$n.Key] = @(Get-AtmOrdinalSorted -Items $list.ToArray() -Signature { param($e) '{0}|{1}' -f $e.Code, $e.Detail }) }
    }
    $sw.Stop()
    if ($queried -gt 0) { $reasons.Add('HANDLES_SAMPLED') } elseif ($reasons.Count -eq 0) { $reasons.Add('HANDLE_NO_FILES') }
    $cov = New-AtmCoverage -Collector 'handles' -Status $(if ($queried -gt 0) { 'PARTIAL' } else { 'NOT_OBSERVABLE' }) -Reasons @(Get-AtmSortedCodes $reasons) -ElevationWouldHelp 'UNKNOWN' -Observed $queried -Expected $nodes.Count -StartedUtc $started -ElapsedMs $sw.ElapsedMilliseconds
    return [pscustomobject]@{ Evidence = $evidence; Coverage = $cov }
}

function Add-AtmFindingEvidence {
    # The same finding with -Evidence appended (ordered after its own) and -Coverage added; New-AtmFinding applies its
    # rules again to the requested state, so added evidence never changes a state by itself.
    param($Finding, $Evidence, $Coverage)
    return New-AtmFinding -Kind $Finding.Kind -Key $Finding.Key -State $Finding.RequestedState -Evidence (@($Finding.Evidence) + @($Evidence)) -Coverage (@($Finding.Coverage) + @($Coverage)) -Provider $Finding.Provider
}

function Invoke-AtmDiagnose {
    <#
      Read-only diagnose run. Never calls the clean engine, never requests elevation.
      -InventoryArgs: passed to Invoke-AtmInventory (tests pass ProfilesOverride / ProcessesOverride / NowUtc).
      -IdentitySource: test override for the token identity. -Providers: provider objects (default: registered).
      -DeadlineSeconds: global deadline; a collector not started before it is TIMEOUT, never COMPLETE.
      Agent runtime (P1-B4-c): -ProcessSource: test override of the process rows (default: CIM; when the inventory
      gets ProcessesOverride, the same rows feed both collections). -CpuSampleMs: interval of the CPU sample (default
      500; 0 = not sampled; otherwise 100 to 5000). -SelfPid / -SelfCreationUtc: identity of this process (R-B1).
      Pseudonyms (ADR-0010, P1-B4-d): -PseudonymKey: the operator's key bytes (Read-AtmPseudonymKeyFile); without it
      the key is ephemeral. The key lives only in this call: the pseudonymizer is closed (HMAC disposed, buffer cleared)
      when it returns or throws. -PartitionKeyFunction: test override of the partition key.
      Services (P2-A): -ServiceSource: test override of the Win32_Service rows (param($Names)).
      Virtualization (P2-B): -VirtualizationSource: test override of the platform and VM queries (param($Op)).
    #>
    param([hashtable]$InventoryArgs = @{}, [scriptblock]$IdentitySource, $Providers, [int]$DeadlineSeconds = $script:AtmDiagnoseDefaultDeadlineSeconds,
        [scriptblock]$ProcessSource = $null, [int]$CpuSampleMs = $script:AtmDiagnoseCpuSampleMs, $SelfPid = $PID, $SelfCreationUtc = $null,
        [byte[]]$PseudonymKey = $null, [scriptblock]$PartitionKeyFunction = $null, [string[]]$RepositoryPaths = @(), [scriptblock]$HandleQuery = $null, [scriptblock]$ServiceSource = $null,
        [scriptblock]$VirtualizationSource = $null)
    if ($DeadlineSeconds -lt 0) { throw (Get-AtmText 'err.diagDeadline' $DeadlineSeconds) }
    if ($CpuSampleMs -ne 0 -and ($CpuSampleMs -lt $script:AtmCpuSampleMinMs -or $CpuSampleMs -gt $script:AtmCpuSampleMaxMs)) { throw (Get-AtmText 'err.diagProcess' "CpuSampleMs $CpuSampleMs") }
    $pz = New-AtmPseudonymizer -Key $PseudonymKey
    try {
        $runArgs = @{ InventoryArgs = $InventoryArgs; IdentitySource = $IdentitySource; Providers = $Providers; DeadlineSeconds = $DeadlineSeconds; ProcessSource = $ProcessSource
            CpuSampleMs = $CpuSampleMs; SelfPid = $SelfPid; SelfCreationUtc = $SelfCreationUtc; Pseudonymizer = $pz; PartitionKeyFunction = $PartitionKeyFunction; RepositoryPaths = $RepositoryPaths; HandleQuery = $HandleQuery; ServiceSource = $ServiceSource; VirtualizationSource = $VirtualizationSource }
        return (Invoke-AtmDiagnoseRun @runArgs)
    } finally { Close-AtmPseudonymizer $pz }
}

function Invoke-AtmDiagnoseRun {
    # The body of Invoke-AtmDiagnose, with its pseudonymizer (parameters already checked there).
    param([hashtable]$InventoryArgs, [scriptblock]$IdentitySource, $Providers, [int]$DeadlineSeconds, [scriptblock]$ProcessSource, [int]$CpuSampleMs, $SelfPid, $SelfCreationUtc,
        $Pseudonymizer, [scriptblock]$PartitionKeyFunction, [string[]]$RepositoryPaths = @(), [scriptblock]$HandleQuery = $null, [scriptblock]$ServiceSource = $null,
        [scriptblock]$VirtualizationSource = $null)
    $started = [datetime]::UtcNow
    $deadline = $started.AddSeconds($DeadlineSeconds)
    $coverage = New-Object System.Collections.Generic.List[object]
    $findings = New-Object System.Collections.Generic.List[object]
    # Set by the agent runtime part when it runs (used by the open-file collector).
    $procCollection = $null; $selfKeys = $null

    # Identity always runs: it reads only the own token, and every other coverage record is explained by it.
    $identity = Get-AtmIdentityState -Source $IdentitySource
    $coverage.Add($identity.Coverage)

    # Providers: contract and runtime hints. An invalid provider object is reported and left out of the run.
    $provList = @(if ($null -ne $Providers) { $Providers } else { Get-AtmProviders })
    $validProviders = New-Object System.Collections.Generic.List[object]
    $provInfo = New-Object System.Collections.Generic.List[object]
    $hints = New-Object System.Collections.Generic.List[object]
    foreach ($p in $provList) {
        $rawId = $(if ($null -ne $p -and @($p.PSObject.Properties.Name) -contains 'Id') { [string]$p.Id } else { '' })
        $contract = $null
        # Contract violation: reported below as PROVIDER_CONTRACT_INVALID; the provider takes no part in the run.
        try { $contract = Get-AtmProviderContract $p } catch { $contract = $null }
        # Validity follows the registration rules (v1 Id check unchanged); the collector name is only lower-cased.
        $collector = $(if ($rawId -match '^[A-Za-z0-9-]+$') { 'provider-' + $rawId.ToLowerInvariant() } else { 'provider-invalid' })
        if ($null -eq $contract -or -not (Test-AtmProviderId -Id $rawId -Contract $contract)) {
            $coverage.Add((New-AtmCoverage -Collector $collector -Status 'FAILED' -Reasons @('PROVIDER_CONTRACT_INVALID') -ElevationWouldHelp 'NO'))
            continue
        }
        $validProviders.Add($p)
        $provInfo.Add([pscustomobject]@{ Id = $rawId; DisplayName = [string]$p.DisplayName; ContractVersion = $contract.Version; Capabilities = @($contract.Capabilities) })
        if ($contract.Capabilities -cnotcontains 'runtime') { continue }
        # -ge: a deadline of 0 means that only the identity is read.
        if ([datetime]::UtcNow -ge $deadline) { $coverage.Add((New-AtmDeadlineCoverage $collector)); continue }
        $h = Get-AtmProviderRuntimeHints $p
        $hints.Add($h)
        $coverage.Add($h.Coverage)
    }

    # V0.1 temporary-directory inventory (read-only) and the coverage it implies.
    $inv = $null
    if ([datetime]::UtcNow -ge $deadline) {
        foreach ($c in @('inventory', 'processes', 'temp-profiles', 'profile-discovery')) { $coverage.Add((New-AtmDeadlineCoverage $c)) }
    } else {
        $ia = @{} + $InventoryArgs
        if ($null -ne $Providers) { $ia['Providers'] = @($validProviders | Where-Object { (Get-AtmProviderCapabilities $_) -ccontains 'temp' }) }
        $invStarted = [datetime]::UtcNow
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $err = $null
        # Inventory failure: reported as INVENTORY_FAILED (exception type only); nothing is reported as absent.
        $script:AtmDiscoveryGaps = @{}; $script:AtmDiscoveryRan = $false
        try { $inv = Invoke-AtmInventory @ia } catch { $err = $_.Exception.GetType().Name; $inv = $null }
        $sw.Stop()
        if ($null -eq $inv) {
            $coverage.Add((New-AtmCoverage -Collector 'inventory' -Status 'FAILED' -Reasons @('INVENTORY_FAILED', (ConvertTo-AtmExceptionCode $err)) -ElevationWouldHelp 'UNKNOWN' -StartedUtc $invStarted -ElapsedMs $sw.ElapsedMilliseconds))
            foreach ($c in @('processes', 'temp-profiles')) { $coverage.Add((New-AtmCoverage -Collector $c -Status 'FAILED' -Reasons @('INVENTORY_FAILED'))) }
            # An unreadable profile list fails the discovery itself (never an empty list of profiles).
            # Discovery that did not start (the inventory failed before it) is not observed, never a failure of its own.
            if ($script:AtmDiscoveryGaps.ContainsKey('PROFILE_LIST_UNREADABLE')) { $coverage.Add((New-AtmCoverage -Collector 'profile-discovery' -Status 'FAILED' -Reasons @('PROFILE_LIST_UNREADABLE') -ElevationWouldHelp 'UNKNOWN')) }
            elseif (-not $script:AtmDiscoveryRan) { $coverage.Add((New-AtmCoverage -Collector 'profile-discovery' -Status 'NOT_OBSERVABLE' -Reasons @('DISCOVERY_NOT_RUN', 'INVENTORY_FAILED') -ElevationWouldHelp 'UNKNOWN')) }
            else { $coverage.Add((New-AtmCoverage -Collector 'profile-discovery' -Status 'FAILED' -Reasons @('INVENTORY_FAILED') -ElevationWouldHelp 'UNKNOWN')) }
        } else {
            $invCov = @(Get-AtmInventoryCoverage -Inventory $inv -Identity $identity -StartedUtc $invStarted -ElapsedMs $sw.ElapsedMilliseconds -OverDeadline ([datetime]::UtcNow -gt $deadline))
            foreach ($c in $invCov) { $coverage.Add($c) }
            # Temporary partitions: keyed pseudonyms, never the path (ADR-0010).
            # A discovery gap (another profile not read) says nothing about a partition already found: not attached.
            foreach ($f in @(Get-AtmPartitionFindings -Partitions @($inv.Partitions) -InventoryCoverage @($invCov | Where-Object { $_.Collector -cne 'profile-discovery' }) -Pseudonymizer $Pseudonymizer -KeyFunction $PartitionKeyFunction)) { $findings.Add($f) }
        }
    }

    # Services (P2-A): queried here, before the process snapshot of the agent runtime, so that a PID the service
    # control manager reports can be proved to belong to a snapshot process (Resolve-AtmServiceProcess). Only names
    # declared by providers; none declared: nothing is queried.
    $svcIncomplete = (@($coverage | Where-Object { $_.Collector.StartsWith('provider-', [StringComparison]::Ordinal) -and ($_.Status -ceq 'TIMEOUT' -or @($_.Reasons) -ccontains 'PROVIDER_CONTRACT_INVALID') }).Count -gt 0)
    $svcQuery = Invoke-AtmServiceQuery -ProviderHints $hints.ToArray() -Source $ServiceSource -Deadline $deadline -HintsIncomplete:$svcIncomplete
    # Virtualization (P2-B): platform and VM queries here too, before the snapshot (VM worker links).
    $virtQuery = Invoke-AtmVirtualizationQuery -Source $VirtualizationSource -Deadline $deadline -Elevated $identity.IsElevatedAdministrator

    # Agent runtime (P1-B4-c): a process collection with a CPU sample, the session registries of every profile, SELF,
    # the agent findings (P1-B4-b) and the resource totals. Each collector has exactly one record, TIMEOUT when the
    # deadline came first.
    $tempProviders = @($validProviders | Where-Object { (Get-AtmProviderCapabilities $_) -ccontains 'temp' })
    $sessionCollectors = [string[]]@($tempProviders | ForEach-Object { 'sessions-' + ([string]$_.Id).ToLowerInvariant() } | Select-Object -Unique)
    [Array]::Sort($sessionCollectors, [StringComparer]::Ordinal)
    $runtime = $null
    if ([datetime]::UtcNow -ge $deadline) {
        foreach ($c in @('process-snapshot') + @($sessionCollectors) + @('agent-processes', 'agent-resources')) { $coverage.Add((New-AtmDeadlineCoverage $c)) }
    } else {
        $src = $ProcessSource
        if ($null -eq $src -and $InventoryArgs.ContainsKey('ProcessesOverride')) { $ovRows = @($InventoryArgs['ProcessesOverride']); $src = { $ovRows }.GetNewClosure() }
        if ($CpuSampleMs -gt 0) { $sample = Invoke-AtmProcessCpuSampling -Source $src -IntervalMs $CpuSampleMs -Deadline $deadline }
        else { $sample = [pscustomobject]@{ First = (Get-AtmProcessCollection -Source $src -Deadline $deadline); Second = $null; Cpu = $null } }
        $coverage.Add($sample.First.Coverage)
        # Session registries: the inventory's own reading is reused; a profile and provider it did not read (no
        # temporary base there) is read through the same provider member, read-only. Exception type only.
        $regs = New-Object System.Collections.Generic.List[object]
        foreach ($tp in $tempProviders) {
            if ($null -eq $inv) { $regs.Add([pscustomobject]@{ ProviderId = $tp.Id; Registry = $null; Error = $null; Reason = 'INVENTORY_UNAVAILABLE' }); continue }
            foreach ($pr in @($inv.Profiles)) {
                $item = [pscustomobject]@{ ProviderId = $tp.Id; Registry = $null; Error = $null; Reason = $null; ProfileSid = [string]$pr.Sid; ProfilePath = [string]$pr.ProfilePath }
                $rk = Get-AtmRegistryKey -ProviderId $tp.Id -ProfileInfo $pr
                if ($inv.Registries.ContainsKey($rk)) { $item.Registry = $inv.Registries[$rk] }
                elseif ([datetime]::UtcNow -ge $deadline) { $item.Reason = 'DEADLINE_EXCEEDED' }
                else { try { $item.Registry = & $tp.GetSessionEvidence $pr $inv.Snapshot } catch { $item.Error = $_.Exception.GetType().Name } }
                $regs.Add($item)
            }
        }
        # SELF: this process and the launchers of the V0.1 self chain (their PID and creation time from the V0.1 snapshot).
        $launchers = New-Object System.Collections.Generic.List[object]
        if ($null -ne $inv -and -not $inv.Snapshot.Failed) {
            foreach ($sp in @($inv.SelfPids | Where-Object { $_ -ne $SelfPid })) {
                $lp = @($inv.Snapshot.Processes | Where-Object { $_.Pid -eq $sp })
                if ($lp.Count -eq 1) { $launchers.Add([pscustomobject]@{ Pid = $sp; CreationUtc = $lp[0].CreationUtc }) }
            }
        }
        $procCollection = $sample.First
        $selfKeys = Get-AtmSelfProcessKeys -Collection $sample.First -SelfPid $SelfPid -SelfCreationUtc $SelfCreationUtc -LauncherReferences $launchers.ToArray()
        $invCovRecords = @($coverage | Where-Object { @('inventory', 'processes', 'temp-profiles') -ccontains $_.Collector })
        $rtArgs = @{ Collection = $sample.First; Second = $sample.Second; ProviderHints = $hints.ToArray(); SessionRegistries = $regs.ToArray(); InventoryCoverage = $invCovRecords; SelfKeys = $selfKeys; Cpu = $sample.Cpu; Pseudonymizer = $Pseudonymizer }
        if ($null -ne $inv) { $rtArgs['LegacySnapshot'] = $inv.Snapshot; $rtArgs['Partitions'] = @($inv.Partitions) }
        $runtime = Get-AtmAgentRuntimeFindings @rtArgs
        foreach ($c in $runtime.Coverage) { $coverage.Add($c) }
        # Temporary partitions first (ordered by pseudonym, ADR-0010 D-8); runtime findings follow, ordered by Kind and Key.
        foreach ($f in $runtime.Findings) { $findings.Add($f) }
    }

    # Service findings, with the snapshot taken after the query (none when the runtime part did not run).
    $svc = Get-AtmServiceFindings -Query $svcQuery -Collection $procCollection
    foreach ($c in $svc.Coverage) { $coverage.Add($c) }
    foreach ($f in $svc.Findings) { $findings.Add($f) }
    # Virtualization findings: the platform, then VMs by key; worker processes from the same snapshot.
    $virt = Get-AtmVirtualizationFindings -Query $virtQuery -Collection $procCollection -Pseudonymizer $Pseudonymizer -ProviderHints $hints.ToArray() -ServiceFindings @($svc.Findings)
    foreach ($c in $virt.Coverage) { $coverage.Add($c) }
    foreach ($f in $virt.Findings) { $findings.Add($f) }

    $wtNodes = @()
    # Worktrees (P3-B): only with the worktree diagnostics gate open (closed in every shipped copy). Closed, nothing is
    # discovered and worktree-discovery is reported as not observable (P5-A).
    if ($script:AtmWorktreeDiagnosticsEnabled) {
        if ([datetime]::UtcNow -ge $deadline) { foreach ($c in @('worktree-discovery', 'git')) { $coverage.Add((New-AtmDeadlineCoverage $c)) } }
        else {
            $wd = Get-AtmWorktreeDiscovery -Partitions $(if ($null -ne $inv) { @($inv.Partitions) } else { @() }) -RepositoryPaths $RepositoryPaths -Git (Resolve-AtmGitExecutable) -Pseudonymizer $Pseudonymizer -Deadline $deadline
            foreach ($c in $wd.Coverage) { $coverage.Add($c) }
            foreach ($f in $wd.Findings) { $findings.Add($f) }
            $wtNodes = @($wd.HandleNodes)
        }
    } else {
        # Closed gate (every shipped copy): worktrees are not observed, which is reported (P5-A: never read as "none").
        $coverage.Add((New-AtmCoverage -Collector 'worktree-discovery' -Status 'NOT_OBSERVABLE' -Reasons @('WORKTREE_DIAGNOSTICS_GATE_CLOSED') -ElevationWouldHelp 'NO'))
    }

    # Working directories (D-1): deferred (ADR-0004 amendment); never observed, so never an absence.
    $coverage.Add((New-AtmCoverage -Collector 'process-cwd' -Status 'NOT_OBSERVABLE' -Reasons @('WORKING_DIRECTORY_DEFERRED') -ElevationWouldHelp 'NO'))
    # Open files (D-2): a bounded sample of files of each temporary partition (and worktree, when discovery ran), only
    # with the handle diagnostics gate open (closed in every shipped copy: no file is listed, Restart Manager is not
    # called, and 'handles' is NOT_OBSERVABLE). Checked before the deadline, so a closed gate is always reported as such.
    if (-not $script:AtmHandleDiagnosticsEnabled) { $coverage.Add((New-AtmCoverage -Collector 'handles' -Status 'NOT_OBSERVABLE' -Reasons @('HANDLE_SECURITY_GATE_CLOSED') -ElevationWouldHelp 'NO')) }
    elseif ([datetime]::UtcNow -ge $deadline) { $coverage.Add((New-AtmDeadlineCoverage 'handles')) }
    else {
        $nodes = New-Object System.Collections.Generic.List[object]
        if ($null -ne $inv) {
            $keyFn = $(if ($null -ne $PartitionKeyFunction) { $PartitionKeyFunction } else { { param($Provider, $Path) ConvertTo-AtmPartitionKey -Pseudonymizer $Pseudonymizer -Provider $Provider -Path $Path } })
            foreach ($part in @($inv.Partitions | Where-Object { $null -ne $_ -and $_.Kind -ne 'NotScanned' })) {
                if ([datetime]::UtcNow -ge $deadline) { break }
                $smp = Get-AtmHandleSampleFiles -Dir ([string]$part.Path)
                $nodes.Add([pscustomobject]@{ Key = [string](& $keyFn $part.Provider $part.Path); Files = $smp.Files; Capped = $smp.Capped; Error = $smp.Error })
            }
        }
        foreach ($wn in $wtNodes) { $nodes.Add($wn) }
        # Handle evidence carries the start of the handle batch (the coverage StartedUtc), not the partitions' time.
        $he = Get-AtmHandleEvidence -Nodes $nodes.ToArray() -Collection $procCollection -SelfKeys $selfKeys -Deadline $deadline -Query $HandleQuery
        $coverage.Add($he.Coverage)
        for ($i = 0; $i -lt $findings.Count; $i++) {
            $f = $findings[$i]
            if ($he.Evidence.ContainsKey([string]$f.Key) -and ($f.Kind -ceq 'TempPartition' -or $f.Kind -ceq 'Worktree')) { $findings[$i] = Add-AtmFindingEvidence -Finding $f -Evidence $he.Evidence[[string]$f.Key] -Coverage @($he.Coverage) }
        }
    }

    # Dependency graph (P4-A): correlation over the evidence above; no collector runs here.
    $graphKeyFn = $(if ($null -ne $PartitionKeyFunction) { $PartitionKeyFunction } else { { param($Provider, $Path) ConvertTo-AtmPartitionKey -Pseudonymizer $Pseudonymizer -Provider $Provider -Path $Path } })
    # The graph's time limit is also bounded by the run deadline (past it, GRAPH_TIME_LIMIT is declared at once).
    $graphLeft = ($deadline - [datetime]::UtcNow).TotalMilliseconds
    $graphMs = $(if ($graphLeft -le 0) { -1 } else { [int][Math]::Min([double]$script:AtmGraphMaxMs, $graphLeft) })
    $graph = Get-AtmDependencyGraph -MaxMs $graphMs -Findings $findings.ToArray() -Collection $procCollection -LegacySnapshot $(if ($null -ne $inv) { $inv.Snapshot } else { $null }) -Partitions $(if ($null -ne $inv) { @($inv.Partitions) } else { @() }) -PartitionKeyFunction $graphKeyFn -Coverage $coverage.ToArray()
    # P4-B: partition and worktree states from the graph summaries (same findings, same order; no collector runs).
    $graphCov = ConvertTo-AtmGraphCoverage -Graph $graph
    $promoted = Set-AtmGraphFindingStates -Findings $findings.ToArray() -Graph $graph -Coverage $coverage.ToArray() -GraphCoverage $graphCov
    $findings = [System.Collections.Generic.List[object]]::new(); foreach ($f in $promoted) { $findings.Add($f) }
    $coverage.Add($graphCov)
    $covArr = $coverage.ToArray()
    [pscustomobject]@{
        SchemaVersion    = $script:AtmDiagnoseSchema
        ToolVersion      = $script:AtmVersion
        Machine          = $env:COMPUTERNAME
        StartedUtc       = $started
        FinishedUtc      = [datetime]::UtcNow
        DeadlineUtc      = $deadline
        DeadlineSeconds  = $DeadlineSeconds
        Identity         = $identity
        Providers        = $provInfo.ToArray()
        ProviderHints    = $hints.ToArray()
        Coverage         = $covArr
        CoverageComplete = (@($covArr | Where-Object { $script:AtmConclusiveCoverage -cnotcontains $_.Status }).Count -eq 0)
        Findings         = $findings.ToArray()
        AgentResources   = $(if ($null -ne $runtime) { $runtime.Totals } else { $null })
        Graph            = $graph
        Pseudonymization = [pscustomobject]@{ Scheme = $script:AtmPseudonymScheme; KeySource = $Pseudonymizer.KeySource; KeyId = $Pseudonymizer.KeyId }
        Inventory        = $inv
    }
}
