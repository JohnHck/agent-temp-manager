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
# States meaning "the process was looked for and is not there". Same rule: New-AtmFinding replaces them with UNKNOWN
# unless every coverage record of the finding is conclusive (a PARTIAL or failed collection never proves absence).
$script:AtmAbsenceStates = @('SESSION_PROCESS_NOT_FOUND')
# Closed list of states per finding kind (ADR-0001 rule 2). Only states with an accepted basis are listed:
# TempPartition: RUNTIME_NOT_DIAGNOSED (P1-A) and the graph states of ADR-0002; Worktree: the summary states of
# ADR-0006 rule 14; Process and AgentSession: the runtime states of P1-B4-b (Get-AtmAgentRuntimeFindings). The other
# kinds have no state yet: each later phase adds its own, with tests. UNKNOWN is in every list because New-AtmFinding
# may replace a requested state with it. No Process or AgentSession state says anything about a temporary directory.
$script:AtmFindingStates = @{
    'Process'        = @('SELF', 'AGENT_PROCESS', 'AGENT_DESCENDANT', 'IDENTITY_UNVERIFIED', 'UNKNOWN')
    'Service'        = @('UNKNOWN')
    'VirtualMachine' = @('UNKNOWN')
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
    'PROCESS_EXITED_DURING_RUN', 'SESSION_KEY_COLLISION', 'SESSION_ENTRIES_CONFLICT', 'PARTITION_KEY_COLLISION')

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
        if (-not $cand.ContainsKey($Key)) { $cand[$Key] = [pscustomobject]@{ Process = $Process; Kind = $Kind; Evidence = (New-Object System.Collections.Generic.List[object]); AgentProviders = @{}; OtherProviders = @{}; SourceCoverage = @{} } }
        $c = $cand[$Key]
        # AGENT outranks UNCHECKED; UNVERIFIED keys (pid:<n>) never collide with verified ones.
        if ($Kind -ceq 'AGENT') { $c.Kind = 'AGENT' }
        $set = $(if ($Kind -ceq 'AGENT') { $c.AgentProviders } else { $c.OtherProviders })
        foreach ($pv in @($Providers | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })) { Add-AtmProviderToSet -Set $set -Provider ([string]$pv) }
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
        $attr[$k] = $(if ($c.Kind -ceq 'AGENT') { Get-AtmProviderAttribution -Sets @($c.AgentProviders) } else { Get-AtmProviderAttribution -Sets @($c.AgentProviders, $c.OtherProviders) })
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
      TempPartition findings in the V0.1 order, keyed by ConvertTo-AtmPartitionKey (no path in a finding). Two partitions
      with the same key are one UNKNOWN finding with PARTITION_KEY_COLLISION, never an overwritten one; its provider is
      kept only when both name the same one. -KeyFunction: test override.
    #>
    param($Partitions, $InventoryCoverage, $Pseudonymizer, [scriptblock]$KeyFunction = $null)
    $keyFn = $(if ($null -ne $KeyFunction) { $KeyFunction } else { { param($Provider, $Path) ConvertTo-AtmPartitionKey -Pseudonymizer $Pseudonymizer -Provider $Provider -Path $Path } })
    $order = New-Object System.Collections.Generic.List[string]
    $groups = @{}
    foreach ($part in @($Partitions | Where-Object { $null -ne $_ -and $_.Kind -ne 'NotScanned' })) {
        $key = [string](& $keyFn $part.Provider $part.Path)
        if (-not $groups.ContainsKey($key)) { $groups[$key] = New-Object System.Collections.Generic.List[object]; $order.Add($key) }
        $groups[$key].Add($part)
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($key in $order) {
        $parts = $groups[$key].ToArray()
        $now = [datetime]::UtcNow
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
    return $out.ToArray()
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
    #>
    param([hashtable]$InventoryArgs = @{}, [scriptblock]$IdentitySource, $Providers, [int]$DeadlineSeconds = $script:AtmDiagnoseDefaultDeadlineSeconds,
        [scriptblock]$ProcessSource = $null, [int]$CpuSampleMs = $script:AtmDiagnoseCpuSampleMs, $SelfPid = $PID, $SelfCreationUtc = $null,
        [byte[]]$PseudonymKey = $null, [scriptblock]$PartitionKeyFunction = $null)
    if ($DeadlineSeconds -lt 0) { throw (Get-AtmText 'err.diagDeadline' $DeadlineSeconds) }
    if ($CpuSampleMs -ne 0 -and ($CpuSampleMs -lt $script:AtmCpuSampleMinMs -or $CpuSampleMs -gt $script:AtmCpuSampleMaxMs)) { throw (Get-AtmText 'err.diagProcess' "CpuSampleMs $CpuSampleMs") }
    $pz = New-AtmPseudonymizer -Key $PseudonymKey
    try {
        $runArgs = @{ InventoryArgs = $InventoryArgs; IdentitySource = $IdentitySource; Providers = $Providers; DeadlineSeconds = $DeadlineSeconds; ProcessSource = $ProcessSource
            CpuSampleMs = $CpuSampleMs; SelfPid = $SelfPid; SelfCreationUtc = $SelfCreationUtc; Pseudonymizer = $pz; PartitionKeyFunction = $PartitionKeyFunction }
        return (Invoke-AtmDiagnoseRun @runArgs)
    } finally { Close-AtmPseudonymizer $pz }
}

function Invoke-AtmDiagnoseRun {
    # The body of Invoke-AtmDiagnose, with its pseudonymizer (parameters already checked there).
    param([hashtable]$InventoryArgs, [scriptblock]$IdentitySource, $Providers, [int]$DeadlineSeconds, [scriptblock]$ProcessSource, [int]$CpuSampleMs, $SelfPid, $SelfCreationUtc,
        $Pseudonymizer, [scriptblock]$PartitionKeyFunction)
    $started = [datetime]::UtcNow
    $deadline = $started.AddSeconds($DeadlineSeconds)
    $coverage = New-Object System.Collections.Generic.List[object]
    $findings = New-Object System.Collections.Generic.List[object]

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
        foreach ($c in @('inventory', 'processes', 'temp-profiles')) { $coverage.Add((New-AtmDeadlineCoverage $c)) }
    } else {
        $ia = @{} + $InventoryArgs
        if ($null -ne $Providers) { $ia['Providers'] = @($validProviders | Where-Object { (Get-AtmProviderCapabilities $_) -ccontains 'temp' }) }
        $invStarted = [datetime]::UtcNow
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $err = $null
        # Inventory failure: reported as INVENTORY_FAILED (exception type only); nothing is reported as absent.
        try { $inv = Invoke-AtmInventory @ia } catch { $err = $_.Exception.GetType().Name; $inv = $null }
        $sw.Stop()
        if ($null -eq $inv) {
            $coverage.Add((New-AtmCoverage -Collector 'inventory' -Status 'FAILED' -Reasons @('INVENTORY_FAILED', (ConvertTo-AtmExceptionCode $err)) -ElevationWouldHelp 'UNKNOWN' -StartedUtc $invStarted -ElapsedMs $sw.ElapsedMilliseconds))
            foreach ($c in @('processes', 'temp-profiles')) { $coverage.Add((New-AtmCoverage -Collector $c -Status 'FAILED' -Reasons @('INVENTORY_FAILED'))) }
        } else {
            $invCov = @(Get-AtmInventoryCoverage -Inventory $inv -Identity $identity -StartedUtc $invStarted -ElapsedMs $sw.ElapsedMilliseconds -OverDeadline ([datetime]::UtcNow -gt $deadline))
            foreach ($c in $invCov) { $coverage.Add($c) }
            # Temporary partitions: keyed pseudonyms, never the path (ADR-0010).
            foreach ($f in @(Get-AtmPartitionFindings -Partitions @($inv.Partitions) -InventoryCoverage $invCov -Pseudonymizer $Pseudonymizer -KeyFunction $PartitionKeyFunction)) { $findings.Add($f) }
        }
    }

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
        $selfKeys = Get-AtmSelfProcessKeys -Collection $sample.First -SelfPid $SelfPid -SelfCreationUtc $SelfCreationUtc -LauncherReferences $launchers.ToArray()
        $invCovRecords = @($coverage | Where-Object { @('inventory', 'processes', 'temp-profiles') -ccontains $_.Collector })
        $rtArgs = @{ Collection = $sample.First; Second = $sample.Second; ProviderHints = $hints.ToArray(); SessionRegistries = $regs.ToArray(); InventoryCoverage = $invCovRecords; SelfKeys = $selfKeys; Cpu = $sample.Cpu; Pseudonymizer = $Pseudonymizer }
        if ($null -ne $inv) { $rtArgs['LegacySnapshot'] = $inv.Snapshot; $rtArgs['Partitions'] = @($inv.Partitions) }
        $runtime = Get-AtmAgentRuntimeFindings @rtArgs
        foreach ($c in $runtime.Coverage) { $coverage.Add($c) }
        # Temporary partitions keep their V0.1 order; runtime findings follow, ordered by Kind and Key.
        foreach ($f in $runtime.Findings) { $findings.Add($f) }
    }

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
        Pseudonymization = [pscustomobject]@{ Scheme = $script:AtmPseudonymScheme; KeySource = $Pseudonymizer.KeySource; KeyId = $Pseudonymizer.KeyId }
        Inventory        = $inv
    }
}
