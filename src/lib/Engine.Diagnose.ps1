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
# Closed list of states per finding kind (ADR-0001 rule 2). Only states with an accepted basis are listed:
# TempPartition: RUNTIME_NOT_DIAGNOSED (P1-A) and the graph states of ADR-0002; Worktree: the summary states of
# ADR-0006 rule 14. The other kinds have no state yet: each later phase adds its own, with tests. UNKNOWN is in every
# list because New-AtmFinding may replace a requested state with it.
$script:AtmFindingStates = @{
    'Process'        = @('UNKNOWN')
    'Service'        = @('UNKNOWN')
    'VirtualMachine' = @('UNKNOWN')
    'Worktree'       = @('IN_USE', 'LOCAL_WORK', 'UNPUBLISHED_COMMITS', 'APPARENT_ORPHAN', 'CLEAN_AND_PUBLISHED_UNKNOWN', 'UNKNOWN')
    'Repository'     = @('UNKNOWN')
    'AgentSession'   = @('UNKNOWN')
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
    # A finding with its evidence and the coverage records its state depends on. A "no dependency" state is kept
    # only with conclusive coverage (ADR-0001 rule 3); otherwise State becomes UNKNOWN and RequestedState keeps
    # what the caller asked for.
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
# Process collection and identity (ADR-0003 rule 1, P1-B1). Not yet part of Invoke-AtmDiagnose: trees, resources and
# the findings that use them come in later increments. Command lines and executable paths are never requested.
# ---------------------------------------------------------------------------------------------

$script:AtmProcessCimProperties = @('ProcessId', 'ParentProcessId', 'Name', 'CreationDate')
$script:AtmProcessMaxRecords = 65536
$script:AtmProcessTimeoutSec = 30
$script:AtmProcessNameMax = 260
# Same-source references compare exact ticks; another source (a session registry, Process.StartTime) states its own
# precision with -ToleranceMs, never more than this.
$script:AtmProcessToleranceMaxMs = 2000
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

function Get-AtmProcessRaw {
    # One CIM pass, identity properties only, bounded by the CIM operation timeout.
    param([int]$TimeoutSec)
    @(Get-CimInstance -ClassName Win32_Process -Property $script:AtmProcessCimProperties -OperationTimeoutSec $TimeoutSec -ErrorAction Stop |
        ForEach-Object { [pscustomobject]@{ ProcessId = $_.ProcessId; ParentProcessId = $_.ParentProcessId; Name = $_.Name; CreationDate = $_.CreationDate } })
}

function Get-AtmProcessCollection {
    <#
      Process collector 'process-snapshot'. -Source: test override returning rows with ProcessId, ParentProcessId,
      Name and CreationDate (or throwing). -MaxRecords: rows beyond it are not read (PARTIAL). -TimeoutSec: CIM
      operation timeout. -Deadline: a collection not started before it is TIMEOUT.
      Every process gets IdentityStatus VERIFIED (Key = pid@creationTicksUtc), CREATION_TIME_UNKNOWN or DUPLICATE_PID
      (the same PID twice in one snapshot: the enumeration is not atomic). Only VERIFIED processes have a Key.
      An empty answer is FAILED: it never means "no processes".
    #>
    param([scriptblock]$Source, [int]$MaxRecords = $script:AtmProcessMaxRecords, [int]$TimeoutSec = $script:AtmProcessTimeoutSec, $Deadline = $null)
    if ($MaxRecords -lt 1) { throw (Get-AtmText 'err.diagProcess' "MaxRecords $MaxRecords") }
    if ($TimeoutSec -lt 1) { throw (Get-AtmText 'err.diagProcess' "TimeoutSec $TimeoutSec") }
    $collector = 'process-snapshot'
    $empty = @{ Collector = $collector; Failed = $true; CollectedUtc = $null; Processes = @(); ByPid = @{}; Duplicates = @{} }
    if ($null -ne $Deadline -and [datetime]::UtcNow -ge $Deadline) {
        $empty.Coverage = New-AtmDeadlineCoverage $collector
        return [pscustomobject]$empty
    }
    $started = [datetime]::UtcNow
    $budgetMs = [long]$TimeoutSec * 1000
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $raw = $null; $err = $null
    try { $raw = @(if ($Source) { & $Source } else { Get-AtmProcessRaw -TimeoutSec $TimeoutSec }) } catch { $err = $_.Exception.GetType().Name }
    $sw.Stop()
    $rows = @($raw | Where-Object { $null -ne $_ })
    if ($null -ne $err -or $rows.Count -eq 0) {
        # Exception type only, never its message. A failure after the whole budget is a timeout.
        if ($null -ne $err -and $sw.ElapsedMilliseconds -ge $budgetMs) { $status = 'TIMEOUT'; $reasons = @('PROCESS_SNAPSHOT_TIMEOUT', (ConvertTo-AtmExceptionCode $err)) }
        elseif ($null -ne $err) { $status = 'FAILED'; $reasons = @('PROCESS_SNAPSHOT_FAILED', (ConvertTo-AtmExceptionCode $err)) }
        else { $status = 'FAILED'; $reasons = @('PROCESS_SNAPSHOT_EMPTY') }
        $empty.Coverage = New-AtmCoverage -Collector $collector -Status $status -Reasons $reasons -StartedUtc $started -ElapsedMs $sw.ElapsedMilliseconds -BudgetMs $budgetMs
        return [pscustomobject]$empty
    }
    $reasons = New-Object System.Collections.Generic.List[string]
    if ($rows.Count -gt $MaxRecords) { $reasons.Add('PROCESS_LIMIT_EXCEEDED'); $rows = @($rows[0..($MaxRecords - 1)]) }
    $list = New-Object System.Collections.Generic.List[object]
    $countByPid = @{}
    $malformed = 0
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
        $list.Add([pscustomobject]@{ Pid = $id; ParentPid = $parent; Name = $name; CreationUtc = $created; Key = $null; IdentityStatus = $null })
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
    [pscustomobject]@{ Collector = $collector; Failed = $false; CollectedUtc = $started; Processes = $list.ToArray(); ByPid = $byPid; Duplicates = $dups; Coverage = $cov }
}

function Resolve-AtmProcessReference {
    <#
      Matches a reference (a PID and the creation time the referrer recorded) against one collection. Returns Result
      (AtmProcessReferenceResults) and the collected Process, if any. A PID alone never identifies a process:
      without both creation times the result is IDENTITY_UNVERIFIED. NOT_FOUND only when the collection is COMPLETE;
      otherwise an absent PID is IDENTITY_UNVERIFIED (it may be among the rows that were not read).
    #>
    param($Collection, $ProcessId, $CreationUtc, [int]$ToleranceMs = 0)
    if ($ToleranceMs -lt 0 -or $ToleranceMs -gt $script:AtmProcessToleranceMaxMs) { throw (Get-AtmText 'err.diagProcess' "ToleranceMs $ToleranceMs") }
    $result = 'IDENTITY_UNVERIFIED'; $proc = $null
    $id = ConvertTo-AtmProcessId $ProcessId
    $created = ConvertTo-AtmProcessCreationUtc $CreationUtc
    if ($null -ne $id -and $null -ne $Collection -and -not $Collection.Failed) {
        if (-not $Collection.Duplicates.ContainsKey($id)) {
            if ($Collection.ByPid.ContainsKey($id)) {
                $proc = $Collection.ByPid[$id]
                if ($null -ne $created -and $proc.IdentityStatus -eq 'VERIFIED') {
                    $diff = [math]::Abs(($created - $proc.CreationUtc).Ticks)
                    $result = $(if ($diff -le [long]$ToleranceMs * [TimeSpan]::TicksPerMillisecond) { 'MATCH' } else { 'PID_REUSED' })
                }
            } elseif ($Collection.Coverage.Status -ceq 'COMPLETE') { $result = 'NOT_FOUND' }
        }
    }
    [pscustomobject]@{ Result = $result; Process = $proc }
}

# ---------------------------------------------------------------------------------------------
# Process trees, run consistency and self-exclusion (ADR-0003 rules 2-4, P1-B2). Not yet part of Invoke-AtmDiagnose.
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
      verified ancestors of it; a launcher's other children are not ours. Self and launchers come from other sources
      than CIM, so they are matched with a bounded tolerance. A reference that cannot be verified is listed in Unverified and is NOT excluded: an
      unverifiable process is never hidden from the diagnostics.
    #>
    param($Collection, $SelfPid = $PID, $SelfCreationUtc = $null, $LauncherReferences = @(), [int]$ToleranceMs = 1000)
    if ($null -eq $SelfCreationUtc) {
        # Unreadable start time: the reference stays unverified and nothing is excluded.
        try { $SelfCreationUtc = [Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime() } catch { $SelfCreationUtc = $null }
    }
    $keys = New-Object System.Collections.Generic.List[string]
    $unverified = New-Object System.Collections.Generic.List[object]
    $self = Resolve-AtmProcessReference -Collection $Collection -ProcessId $SelfPid -CreationUtc $SelfCreationUtc -ToleranceMs $ToleranceMs
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
        $r = Resolve-AtmProcessReference -Collection $Collection -ProcessId $rp -CreationUtc (Get-AtmHintProperty -Item $ref -Name 'CreationUtc') -ToleranceMs $ToleranceMs
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
# Invoke-AtmDiagnose (ADR-0009). P1-A collectors: identity, provider runtime hints, the V0.1 temporary-directory
# inventory and the coverage it implies (processes, temp-profiles). Runtime collectors of later phases (process
# trees, services, virtualization, Git worktrees) add coverage records and findings here.
# ---------------------------------------------------------------------------------------------

$script:AtmDiagnoseSchema = 'atm.diagnose/1'
$script:AtmDiagnoseDefaultDeadlineSeconds = 300

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
    #>
    param([hashtable]$InventoryArgs = @{}, [scriptblock]$IdentitySource, $Providers, [int]$DeadlineSeconds = $script:AtmDiagnoseDefaultDeadlineSeconds)
    if ($DeadlineSeconds -lt 0) { throw (Get-AtmText 'err.diagDeadline' $DeadlineSeconds) }
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
            foreach ($part in @($inv.Partitions | Where-Object { $_.Kind -ne 'NotScanned' })) {
                $now = [datetime]::UtcNow
                $ev = New-Object System.Collections.Generic.List[object]
                $ev.Add((New-AtmEvidence -Code 'AUDIT_CLASS' -Source 'audit' -Collector 'inventory' -ObservedUtc $now -Detail $part.Class))
                foreach ($fl in $part.Flags) { $ev.Add((New-AtmEvidence -Code 'AUDIT_FLAG' -Source 'audit' -Collector 'inventory' -ObservedUtc $now -Detail $fl)) }
                # Runtime evidence (process trees, handles, services, worktrees) is not collected in P1-A.
                $findings.Add((New-AtmFinding -Kind 'TempPartition' -Key $part.Path -State 'RUNTIME_NOT_DIAGNOSED' -Evidence $ev.ToArray() -Coverage $invCov -Provider $part.Provider))
            }
        }
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
        Inventory        = $inv
    }
}
