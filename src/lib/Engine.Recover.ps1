# AgentTempManager RECOVERY ENGINE (V0.4, docs/adr/ADR-0016: assisted recovery of services). Phase R1: the closed
# catalog, a fresh read-only collection made with the diagnose engine's own functions (Engine.Diagnose.ps1: identity,
# provider runtime hints, the services query with its V0.4 R0 fault signals, dependencies and image comparison, and the
# service findings), the criteria that offer or refuse an operation for one declared service, and the plan of one
# operation for one target. Phases R2 and R3 (end of this file): the start of one declared service, and the undo of one
# such start, past the recovery gate, through their seams. Depends on Engine.Audit.ps1, Engine.Diagnose.ps1 and
# Engine.Clean.ps1 (lock B8, log writer, console; the undo's source read in both gate states). No terminal output of its
# own. With the gate closed (every copy) nothing is asked, locked, logged or written, and no seam is ever reached.
Set-StrictMode -Version 2.0

# RECOVERY GATE (V0.4, ADR-0016 section 5): assisted recovery is DISABLED. recover list and recover plan collect, apply
# the criteria and present the plan, then stop. There is deliberately no switch, environment variable, config file or UI
# option to change this: enabling recovery requires a code change in this administrator-owned, manifest-verified file,
# released under a specific authorization. Only the automated test suite flips it, inside its own process.
$script:AtmRecoveryEnabled = $false

# The catalog, closed in code (V04-D1 (a)): one operation. REC-SVC-STOP exists only as the undo of a start (phase R3);
# changing a start mode (REC-SVC-STARTMODE), ending a process (V04-D2) and operating a virtual machine are not offered.
# Captured: the "before" fields of ADR-0016 section 4, read by the diagnose functions and reduced as the diagnose
# reduces them (the account as its kind plus one of the three standard service accounts, the executable as a full path
# only under a well-known program location, otherwise its file name; never a command line).
$script:AtmRecoveryCatalog = @(
    [pscustomobject]@{
        Id             = 'REC-SVC-START'
        Target         = 'SERVICE'
        Description    = 'Start one stopped service that a provider declares.'
        DescriptionKey = 'rec.opSvcStart'
        Reversible     = $true
        Undo           = 'REC-SVC-STOP'
        UndoScope      = 'SERVICE_STATE_ONLY'
        NotUndone      = 'WHAT_THE_SERVICE_DID_WHILE_RUNNING'
        Captured       = @('STATE', 'START_MODE', 'DELAYED_AUTO_START', 'EXIT_CODE', 'SERVICE_SPECIFIC_EXIT_CODE', 'CHECKPOINT', 'WAIT_HINT', 'ACCEPT_STOP',
            'ACCOUNT_KIND', 'ACCOUNT', 'EXECUTABLE', 'IMAGE', 'DEPENDS_ON', 'DEPENDENTS')
    }
)
# Not offered, shown by recover list as a fixed line (V04-D2 and the catalog).
$script:AtmRecoveryNotOffered = @('PROCESS_TERMINATION', 'VM_OPERATION')
# Refusal codes, closed. RECOVERY_NOT_DECLARED is the answer to a name no provider declares (the CLI reports it as a
# usage error, exit 2); every other code refuses an operation for a declared service (exit 3 for plan).
$script:AtmRecoveryRefusalCodes = @(
    'RECOVERY_NOT_DECLARED',            # no provider declares this exact name
    'RECOVERY_ATTRIBUTION_AMBIGUOUS',   # several providers declare it (PROVIDER_ATTRIBUTION_AMBIGUOUS)
    'RECOVERY_COVERAGE_INCOMPLETE',     # services not queried, this name not queried (capped), or some provider hints unread
    'RECOVERY_NOT_LISTED',              # declared but not listed for this account (SERVICE_NOT_LISTED)
    'RECOVERY_DUPLICATE_ROW',           # more than one row for this name (SERVICE_DUPLICATE_ROW)
    'RECOVERY_PROPERTY_UNREADABLE',     # state, start mode, delayed start, account or executable unreadable
    'RECOVERY_SIGNALS_UNREADABLE',      # a fault signal of the capture not collected or unreadable
    'RECOVERY_NOT_STOPPED',             # SERVICE_STATE is not STOPPED
    'RECOVERY_START_MODE_DISABLED',     # SERVICE_START_MODE is DISABLED (changing it is REC-SVC-STARTMODE, not offered)
    'RECOVERY_IMAGE_NOT_DECLARED',      # no provider declares an ExpectedImage for it (refused from R2 on: 2026-11-17)
    'RECOVERY_IMAGE_MISMATCH',          # SERVICE_IMAGE is IMAGE_MISMATCH
    'RECOVERY_IMAGE_UNKNOWN',           # SERVICE_IMAGE is IMAGE_UNKNOWN
    'RECOVERY_DEPENDENCY_STOPPED',      # a service it depends on is STOPPED and is not itself a declared service
    'RECOVERY_DEPENDENCIES_UNREADABLE', # dependencies not collected, failed, or a related state UNREADABLE or NOT_LISTED
    'RECOVERY_DEPENDENCIES_CAPPED'      # a related service over the cap (NOT_QUERIED)
)
# Likely elevation, from the token only (ADR-0016 section 5): never a probe of the service's security.
$script:AtmRecoveryElevationCodes = @('LIKELY_HAS_RIGHT', 'NEEDS_ELEVATION', 'UNKNOWN')
$script:AtmRecoveryPlanSchema = 'atm-recover-plan/1'
# The run's deadline: the services query and the dependency read are each bounded by the CIM operation timeout.
$script:AtmRecoveryDeadlineSeconds = 120
$script:AtmRecoveryPropertyUnreadable = @('SERVICE_STATE_UNREADABLE', 'SERVICE_START_MODE_UNREADABLE', 'SERVICE_DELAYED_AUTO_START_UNREADABLE', 'SERVICE_ACCOUNT_UNREADABLE', 'SERVICE_EXECUTABLE_UNREADABLE')

function Get-AtmRecoveryOperation {
    # The catalog entry of an operation id (exact spelling), or $null.
    param([string]$Id)
    foreach ($op in $script:AtmRecoveryCatalog) { if ($op.Id -ceq $Id) { return $op } }
    return $null
}

function Get-AtmRecoveryElevation {
    # LIKELY_HAS_RIGHT for an elevated administrator token, NEEDS_ELEVATION otherwise (executing would ask through UAC,
    # in phase R4: V04-D3 (b)), UNKNOWN when the token could not be read.
    param($Identity)
    if ($null -eq $Identity -or $null -eq $Identity.IsElevatedAdministrator) { return 'UNKNOWN' }
    if ($Identity.IsElevatedAdministrator) { return 'LIKELY_HAS_RIGHT' }
    return 'NEEDS_ELEVATION'
}

function Get-AtmRecoverCollection {
    <#
      The fresh collection of one recover run, in this process and read only: the identity (own token), the providers'
      runtime hints, one services query (Invoke-AtmServiceQuery: first read, second read of a PENDING service,
      dependencies and image) and its findings (Get-AtmServiceFindings). Nothing else is read: no inventory, no process
      snapshot (only a STOPPED service is ever offered, so no process key is needed), no export, pseudonym key or plan
      of another process. The provider loop follows Invoke-AtmDiagnoseRun: an invalid contract or a provider whose hints
      ran out of time makes the hints incomplete. Test overrides: -Providers, -IdentitySource, -ServiceSource,
      -ServiceDependencySource and -ServiceWait (as Invoke-AtmDiagnose takes them).
    #>
    param($Providers = $null, [scriptblock]$IdentitySource = $null, [scriptblock]$ServiceSource = $null, [scriptblock]$ServiceDependencySource = $null,
        [scriptblock]$ServiceWait = $null, [int]$DeadlineSeconds = $script:AtmRecoveryDeadlineSeconds)
    if ($DeadlineSeconds -lt 0) { throw (Get-AtmText 'err.diagDeadline' $DeadlineSeconds) }
    $started = [datetime]::UtcNow
    $deadline = $started.AddSeconds($DeadlineSeconds)
    $coverage = New-Object System.Collections.Generic.List[object]
    $identity = Get-AtmIdentityState -Source $IdentitySource
    $coverage.Add($identity.Coverage)
    $hints = New-Object System.Collections.Generic.List[object]
    foreach ($p in @(if ($null -ne $Providers) { $Providers } else { Get-AtmProviders })) {
        $rawId = $(if ($null -ne $p -and @($p.PSObject.Properties.Name) -contains 'Id') { [string]$p.Id } else { '' })
        $contract = $null
        try { $contract = Get-AtmProviderContract $p } catch { $contract = $null }
        $collector = $(if ($rawId -match '^[A-Za-z0-9-]+$') { 'provider-' + $rawId.ToLowerInvariant() } else { 'provider-invalid' })
        if ($null -eq $contract -or -not (Test-AtmProviderId -Id $rawId -Contract $contract)) {
            $coverage.Add((New-AtmCoverage -Collector $collector -Status 'FAILED' -Reasons @('PROVIDER_CONTRACT_INVALID') -ElevationWouldHelp 'NO'))
            continue
        }
        if ($contract.Capabilities -cnotcontains 'runtime') { continue }
        if ([datetime]::UtcNow -ge $deadline) { $coverage.Add((New-AtmDeadlineCoverage $collector)); continue }
        $h = Get-AtmProviderRuntimeHints $p
        $hints.Add($h)
        $coverage.Add($h.Coverage)
    }
    $incomplete = (@($coverage | Where-Object { $_.Collector.StartsWith('provider-', [StringComparison]::Ordinal) -and ($_.Status -ceq 'TIMEOUT' -or @($_.Reasons) -ccontains 'PROVIDER_CONTRACT_INVALID') }).Count -gt 0)
    $query = Invoke-AtmServiceQuery -ProviderHints $hints.ToArray() -Source $ServiceSource -Deadline $deadline -HintsIncomplete:$incomplete -DependencySource $ServiceDependencySource -Wait $ServiceWait
    $sf = Get-AtmServiceFindings -Query $query -Collection $null
    foreach ($c in @($sf.Coverage)) { $coverage.Add($c) }
    $byName = @{}; foreach ($f in @($sf.Findings)) { $byName[$f.Key] = $f }
    $declared = @{}; foreach ($d in @($query.Declared)) { $declared[$d.Name] = $d }
    return [pscustomobject]@{
        StartedUtc         = $started
        Identity           = $identity
        Elevation          = (Get-AtmRecoveryElevation $identity)
        Query              = $query
        Findings           = @($sf.Findings)
        FindingsByName     = $byName
        DeclaredByName     = $declared
        DeclaredNames      = [string[]]@($query.Declared | ForEach-Object { [string]$_.Name })
        ServiceCoverage    = @($sf.Coverage)[0]
        PropertiesCoverage = @($sf.Coverage)[1]
        Coverage           = $coverage.ToArray()
    }
}

function Get-AtmRecoverDeclaredImages {
    # The distinct ExpectedImage values the providers of one declared name give (case-insensitive), in their order.
    param($Declared)
    $images = @()
    foreach ($p in @($Declared.Providers)) {
        $im = Get-AtmHintProperty -Item $p -Name 'ExpectedImage'
        if ($im -is [string] -and $im -and @($images | Where-Object { [string]::Equals($_, $im, [StringComparison]::OrdinalIgnoreCase) }).Count -eq 0) { $images += $im }
    }
    return $images
}

function Split-AtmRecoverDependencyLabel {
    # 'name|STATE' (Get-AtmServiceDependencies) -> Name, State.
    param([string]$Label)
    $i = $Label.LastIndexOf('|')
    if ($i -lt 0) { return [pscustomobject]@{ Name = $Label; State = 'UNREADABLE' } }
    return [pscustomobject]@{ Name = $Label.Substring(0, $i); State = $Label.Substring($i + 1) }
}

function Get-AtmRecoverEvidenceDetails {
    # The details of every evidence item of a finding with this code, in order.
    param($Finding, [string]$Code)
    return @(@($Finding.Evidence) | Where-Object { $_.Code -ceq $Code } | ForEach-Object { [string]$_.Detail })
}

function Test-AtmRecoverEvidence {
    param($Finding, [string]$Code)
    return (@(@($Finding.Evidence) | Where-Object { $_.Code -ceq $Code }).Count -gt 0)
}

function Get-AtmRecoverRefusals {
    <#
      The refusal codes of REC-SVC-START for one declared name of a collection (AtmRecoveryRefusalCodes), ordinal order;
      none means offered. Each criterion is evaluated on its own and every failing one is returned:
        * one provider declares it (RECOVERY_ATTRIBUTION_AMBIGUOUS);
        * the services coverage lets this service be read: queried (COMPLETE or PARTIAL), the name not capped, every
          provider's hints read (RECOVERY_COVERAGE_INCOMPLETE);
        * a provider declares its executable (RECOVERY_IMAGE_NOT_DECLARED, from the declarations alone);
        * it is listed (RECOVERY_NOT_LISTED), once (RECOVERY_DUPLICATE_ROW), with every property readable
          (RECOVERY_PROPERTY_UNREADABLE) and every fault signal of the capture read (RECOVERY_SIGNALS_UNREADABLE);
        * its state is STOPPED (RECOVERY_NOT_STOPPED) and its start mode is not DISABLED (RECOVERY_START_MODE_DISABLED);
        * SERVICE_IMAGE is IMAGE_MATCH (RECOVERY_IMAGE_MISMATCH, RECOVERY_IMAGE_UNKNOWN);
        * its dependencies were read in both directions (RECOVERY_DEPENDENCIES_UNREADABLE: not collected, failed, or a
          related state UNREADABLE or NOT_LISTED; RECOVERY_DEPENDENCIES_CAPPED: a related service NOT_QUERIED);
        * no service it depends on is STOPPED unless that service is itself declared by a provider
          (RECOVERY_DEPENDENCY_STOPPED; a hidden name '*' is never declared).
    #>
    param($Collection, [string]$Name)
    $codes = New-Object System.Collections.Generic.List[string]
    if (@($Collection.DeclaredNames) -cnotcontains $Name) { return @('RECOVERY_NOT_DECLARED') }
    $f = $Collection.FindingsByName[$Name]
    $d = $Collection.DeclaredByName[$Name]
    $svc = $Collection.ServiceCoverage
    if (Test-AtmRecoverEvidence $f 'PROVIDER_ATTRIBUTION_AMBIGUOUS') { $codes.Add('RECOVERY_ATTRIBUTION_AMBIGUOUS') }
    if (@('COMPLETE', 'PARTIAL') -cnotcontains [string]$svc.Status -or @($svc.Reasons) -ccontains 'SERVICE_HINTS_INCOMPLETE' -or (Test-AtmRecoverEvidence $f 'SERVICE_NOT_QUERIED')) { $codes.Add('RECOVERY_COVERAGE_INCOMPLETE') }
    if (@(Get-AtmRecoverDeclaredImages $d).Count -eq 0) { $codes.Add('RECOVERY_IMAGE_NOT_DECLARED') }
    if (Test-AtmRecoverEvidence $f 'SERVICE_NOT_LISTED') { $codes.Add('RECOVERY_NOT_LISTED') }
    $listed = ((Test-AtmRecoverEvidence $f 'SERVICE_STATE') -or (Test-AtmRecoverEvidence $f 'SERVICE_STATE_UNREADABLE'))
    if ($listed) {
        if (Test-AtmRecoverEvidence $f 'SERVICE_DUPLICATE_ROW') { $codes.Add('RECOVERY_DUPLICATE_ROW') }
        if (@($script:AtmRecoveryPropertyUnreadable | Where-Object { Test-AtmRecoverEvidence $f $_ }).Count -gt 0) { $codes.Add('RECOVERY_PROPERTY_UNREADABLE') }
        $row = $(if ($Collection.Query.Rows.ContainsKey($Name)) { $Collection.Query.Rows[$Name] } else { $null })
        $sig = $(if ($null -ne $row) { Get-AtmHintProperty -Item $row -Name 'Signals' } else { $null })
        if ($null -eq $sig -or $null -eq $sig.ExitCode -or $null -eq $sig.ServiceSpecificExitCode -or $null -eq $sig.CheckPoint -or $null -eq $sig.WaitHint -or $null -eq $sig.AcceptStop) { $codes.Add('RECOVERY_SIGNALS_UNREADABLE') }
        $state = @(Get-AtmRecoverEvidenceDetails $f 'SERVICE_STATE')
        if ($state.Count -gt 0 -and @($state | Where-Object { $_ -cne 'STOPPED' }).Count -gt 0) { $codes.Add('RECOVERY_NOT_STOPPED') }
        if (@(Get-AtmRecoverEvidenceDetails $f 'SERVICE_START_MODE') -ccontains 'DISABLED') { $codes.Add('RECOVERY_START_MODE_DISABLED') }
        $image = @(Get-AtmRecoverEvidenceDetails $f 'SERVICE_IMAGE')
        if ($image -ccontains 'IMAGE_MISMATCH') { $codes.Add('RECOVERY_IMAGE_MISMATCH') }
        if ($image -ccontains 'IMAGE_UNKNOWN') { $codes.Add('RECOVERY_IMAGE_UNKNOWN') }
        if ((Test-AtmRecoverEvidence $f 'SERVICE_DEPENDENCIES_NOT_COLLECTED') -or (Test-AtmRecoverEvidence $f 'SERVICE_DEPENDENCIES_UNREADABLE')) { $codes.Add('RECOVERY_DEPENDENCIES_UNREADABLE') }
        if (Test-AtmRecoverEvidence $f 'SERVICE_DEPENDENCIES_CAPPED') { $codes.Add('RECOVERY_DEPENDENCIES_CAPPED') }
        foreach ($dir in @('SERVICE_DEPENDS_ON', 'SERVICE_DEPENDENT')) {
            foreach ($label in @(Get-AtmRecoverEvidenceDetails $f $dir)) {
                $dep = Split-AtmRecoverDependencyLabel $label
                if ($dep.State -ceq 'UNREADABLE' -or $dep.State -ceq 'NOT_LISTED') { $codes.Add('RECOVERY_DEPENDENCIES_UNREADABLE') }
                elseif ($dep.State -ceq 'NOT_QUERIED') { $codes.Add('RECOVERY_DEPENDENCIES_CAPPED') }
                elseif ($dir -ceq 'SERVICE_DEPENDS_ON' -and $dep.State -ceq 'STOPPED' -and @($Collection.DeclaredNames) -cnotcontains $dep.Name) { $codes.Add('RECOVERY_DEPENDENCY_STOPPED') }
            }
        }
    }
    return @(Get-AtmSortedCodes $codes)
}

function Get-AtmRecoverCapture {
    <#
      The "before" capture of one listed declared service (ADR-0016 section 4), from the same collection the criteria
      read: the evidence values of the diagnose (state, start mode, delayed start, account kind, standard account,
      reduced executable, image result, dependencies as 'name|STATE') and the fault signals of its row as numbers. A
      value that was not read is $null, never a default.
    #>
    param($Collection, [string]$Name)
    $f = $Collection.FindingsByName[$Name]
    $one = { param($Code) $v = @(Get-AtmRecoverEvidenceDetails $f $Code); if ($v.Count -eq 1) { $v[0] } else { $null } }
    $row = $(if ($Collection.Query.Rows.ContainsKey($Name)) { $Collection.Query.Rows[$Name] } else { $null })
    $sig = $(if ($null -ne $row) { Get-AtmHintProperty -Item $row -Name 'Signals' } else { $null })
    $num = { param($Value) if ($null -eq $Value) { $null } else { [string]$Value } }
    $exePath = & $one 'SERVICE_EXECUTABLE'
    $exeName = & $one 'SERVICE_EXECUTABLE_NAME'
    $accept = $(if ($null -ne $sig -and $sig.AcceptStop -is [bool]) { $(if ($sig.AcceptStop) { 'TRUE' } else { 'FALSE' }) } else { $null })
    return [pscustomobject]@{
        State                   = & $one 'SERVICE_STATE'
        StartMode               = & $one 'SERVICE_START_MODE'
        DelayedAutoStart        = & $one 'SERVICE_DELAYED_AUTO_START'
        ExitCode                = $(if ($null -ne $sig) { & $num $sig.ExitCode } else { $null })
        ServiceSpecificExitCode = $(if ($null -ne $sig) { & $num $sig.ServiceSpecificExitCode } else { $null })
        CheckPoint              = $(if ($null -ne $sig) { & $num $sig.CheckPoint } else { $null })
        WaitHint                = $(if ($null -ne $sig) { & $num $sig.WaitHint } else { $null })
        AcceptStop              = $accept
        Condition               = & $one 'SERVICE_CONDITION'
        AccountKind             = & $one 'SERVICE_ACCOUNT_KIND'
        Account                 = & $one 'SERVICE_ACCOUNT'
        Executable              = $(if ($exePath) { $exePath } else { $exeName })
        ExecutableForm          = $(if ($exePath) { 'PATH' } elseif ($exeName) { 'NAME' } else { $null })
        Image                   = & $one 'SERVICE_IMAGE'
        DependsOn               = @(Get-AtmRecoverEvidenceDetails $f 'SERVICE_DEPENDS_ON')
        Dependents              = @(Get-AtmRecoverEvidenceDetails $f 'SERVICE_DEPENDENT')
    }
}

function Get-AtmRecoverPlanId {
    <#
      The plan id of one operation (ADR-0016 section 3): SHA-256 of its own prefix and, in a fixed order, the operation,
      the target's identity (its declared name and each provider's id, role and ExpectedImage) and every field of the
      "before" capture. Each value is length-prefixed ($null is distinct from empty) and each list carries its count,
      so no two different inputs give the same text. No run id or time: the same input gives the same id.
    #>
    param([string]$Operation, [string]$Target, $Declared, $Capture)
    $parts = New-Object System.Collections.Generic.List[object]
    $parts.Add($script:AtmRecoveryPlanSchema); $parts.Add($Operation); $parts.Add($Target)
    $provs = @(Get-AtmOrdinalSorted -Items @($Declared.Providers) -Signature { param($x) '{0}|{1}|{2}' -f $x.Id, $x.Role, $x.ExpectedImage })
    $parts.Add([string]$provs.Count)
    foreach ($p in $provs) { $parts.Add([string]$p.Id); $parts.Add($p.Role); $parts.Add($p.ExpectedImage) }
    foreach ($k in @('State', 'StartMode', 'DelayedAutoStart', 'ExitCode', 'ServiceSpecificExitCode', 'CheckPoint', 'WaitHint', 'AcceptStop', 'Condition', 'AccountKind', 'Account', 'Executable', 'ExecutableForm', 'Image')) { $parts.Add($Capture.$k) }
    foreach ($k in @('DependsOn', 'Dependents')) { $list = @($Capture.$k); $parts.Add([string]$list.Count); foreach ($x in $list) { $parts.Add($x) } }
    $text = -join @($parts | ForEach-Object { if ($null -eq $_) { '~;' } else { $s = [string]$_; '{0}:{1};' -f $s.Length, $s } })
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)) } finally { $sha.Dispose() }
    return (-join @($h | ForEach-Object { $_.ToString('x2') }))
}

function Get-AtmRecoverList {
    <#
      recover list: for each declared service of the collection (ordinal order), the catalog operation with offered or
      refused and its codes. Read only: nothing is asked, locked, logged or written. Changed is always $false.
    #>
    param($Collection)
    $op = $script:AtmRecoveryCatalog[0]
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($f in @($Collection.Findings)) {
        $codes = @(Get-AtmRecoverRefusals -Collection $Collection -Name $f.Key)
        $rows.Add([pscustomobject]@{ Operation = $op.Id; Target = $f.Key; Provider = $f.Provider; Offered = ($codes.Count -eq 0); Codes = $codes; Reversible = $op.Reversible; Undo = $op.Undo })
    }
    return [pscustomobject]@{
        Candidates         = $rows.ToArray()
        NotOffered         = @($script:AtmRecoveryNotOffered)
        Elevation          = $Collection.Elevation
        ServiceCoverage    = $Collection.ServiceCoverage
        PropertiesCoverage = $Collection.PropertiesCoverage
        GateOpen           = [bool]$script:AtmRecoveryEnabled
        Changed            = $false
    }
}

function Get-AtmRecoverPlan {
    <#
      recover plan: one operation of the catalog for one target, the exact declared name (compared case-sensitively;
      anything else is RECOVERY_NOT_DECLARED). Offered: the "before" capture, the undo path and what it does not undo,
      the likely elevation and the plan id. Refused: the codes (no plan id). Read only in every case: nothing is asked,
      locked, logged or written, and Changed is always $false. One operation and one target per call; there is no list
      or batch form.
    #>
    param($Collection, [string]$Operation, [string]$Service)
    $op = Get-AtmRecoveryOperation $Operation
    if ($null -eq $op) { throw (New-Object ArgumentException('Operation')) }
    $codes = @(Get-AtmRecoverRefusals -Collection $Collection -Name $Service)
    $declared = (@($Collection.DeclaredNames) -ccontains $Service)
    $out = [ordered]@{
        Operation = $op; Target = $Service; Declared = $declared; Provider = $null; Providers = @(); Offered = ($codes.Count -eq 0); Codes = $codes
        Capture = $null; PlanId = $null; Elevation = $Collection.Elevation; DeclaredDependencyStopped = @(); GateOpen = [bool]$script:AtmRecoveryEnabled; Changed = $false
    }
    if ($declared) {
        $d = $Collection.DeclaredByName[$Service]
        $out.Provider = $Collection.FindingsByName[$Service].Provider
        $out.Providers = @(@($d.Providers) | ForEach-Object { if ($_.Role) { $_.Id + ':' + $_.Role } else { $_.Id } })
        if ($out.Offered) {
            $cap = Get-AtmRecoverCapture -Collection $Collection -Name $Service
            $out.Capture = $cap
            $out.PlanId = Get-AtmRecoverPlanId -Operation $op.Id -Target $Service -Declared $d -Capture $cap
            # A stopped declared dependency is started with it by the service control manager: shown, never hidden.
            $out.DeclaredDependencyStopped = @(@($cap.DependsOn) | ForEach-Object { Split-AtmRecoverDependencyLabel $_ } | Where-Object { $_.State -ceq 'STOPPED' } | ForEach-Object { $_.Name })
        }
    }
    return [pscustomobject]$out
}

# ---------------------------------------------------------------------------------------------
# Phase R2 (ADR-0016 sections 3 and 4): REC-SVC-START past the recovery gate. Only the test suite reaches it, with the
# gate opened inside its own process and the service control seam injected; no caller passes an execution verb yet (the
# CLI verb is phase R4). One operation for one declared service per call, fixed in code. No compensation, ever (V04-D7
# (a)): the engine reports field by field what differs between "before" and "after", and stops.
# ---------------------------------------------------------------------------------------------
$script:AtmRecoverLogSchema = 'atm.recoverlog/1'
# The closed results of the seam: OK; ACCESS_DENIED (the outcome REFUSED); the other Win32 errors of a start, by number
# (the outcome FAILED, with no wait); a Win32 error outside this map is SERVICE_WIN32_OTHER.
$script:AtmRecoveryWin32Codes = @{
    5 = 'ACCESS_DENIED'; 1053 = 'SERVICE_REQUEST_TIMEOUT'; 1054 = 'SERVICE_NO_THREAD'; 1055 = 'SERVICE_DATABASE_LOCKED'; 1056 = 'SERVICE_ALREADY_RUNNING'
    1058 = 'SERVICE_DISABLED'; 1060 = 'SERVICE_DOES_NOT_EXIST'; 1068 = 'SERVICE_DEPENDENCY_FAIL'; 1069 = 'SERVICE_LOGON_FAILED'; 1072 = 'SERVICE_MARKED_FOR_DELETE'
    1075 = 'SERVICE_DEPENDENCY_DELETED'
}
$script:AtmRecoverySeamCodes = @('OK', 'ACCESS_DENIED', 'SERVICE_REQUEST_TIMEOUT', 'SERVICE_NO_THREAD', 'SERVICE_DATABASE_LOCKED', 'SERVICE_ALREADY_RUNNING', 'SERVICE_DISABLED',
    'SERVICE_DOES_NOT_EXIST', 'SERVICE_DEPENDENCY_FAIL', 'SERVICE_LOGON_FAILED', 'SERVICE_MARKED_FOR_DELETE', 'SERVICE_DEPENDENCY_DELETED', 'SERVICE_WIN32_OTHER')
$script:AtmRecoveryOutcomes = @('COMPLETE', 'PARTIAL', 'FAILED', 'REFUSED', 'EXCEPTION')
# The settle wait (step 9): one read right after the seam, then one every 500 ms, until RUNNING, back to STOPPED, or the
# limit: the largest WaitHint read meanwhile, at least 5 s and at most 30 s. The limit is counted in waited milliseconds
# and on the clock, whichever ends first (a real read of a pending service also waits inside the diagnose's second read).
$script:AtmRecoverySettlePollMs = 500
$script:AtmRecoverySettleMinMs = 5000
$script:AtmRecoverySettleCapMs = 30000
# The capture fields in order, with their names in the log (before, after, the diff and plan-check changedFields).
$script:AtmRecoveryCaptureFields = [ordered]@{
    State = 'state'; StartMode = 'startMode'; DelayedAutoStart = 'delayedAutoStart'; ExitCode = 'exitCode'; ServiceSpecificExitCode = 'serviceSpecificExitCode'
    CheckPoint = 'checkPoint'; WaitHint = 'waitHint'; AcceptStop = 'acceptStop'; Condition = 'condition'; AccountKind = 'accountKind'; Account = 'account'
    Executable = 'executable'; ExecutableForm = 'executableForm'; Image = 'image'; DependsOn = 'dependsOn'; Dependents = 'dependents'
}
# The other names plan-check gives: the target no longer declared, its declaring providers (ids, roles and images), the
# token's identity (compared in memory, never written) and its elevation.
$script:AtmRecoveryChangedFieldsExtra = @('target', 'provider', 'identity', 'elevation')

function ConvertTo-AtmRecoverCaptureRecord {
    # A capture as the fields of a log record (the names of AtmRecoveryCaptureFields); every field $null without one.
    param($Capture)
    $o = [ordered]@{}
    foreach ($k in $script:AtmRecoveryCaptureFields.Keys) {
        $n = $script:AtmRecoveryCaptureFields[$k]
        if ($null -eq $Capture) { $o[$n] = $null }
        elseif ($k -ceq 'DependsOn' -or $k -ceq 'Dependents') { $o[$n] = [string[]]@($Capture.$k) }
        else { $o[$n] = $Capture.$k }
    }
    return $o
}

function Get-AtmRecoverFieldKey {
    # One captured value as comparable text: $null, a value and a list (with its count) never give the same text.
    param($Value)
    if ($null -eq $Value) { return '~' }
    if ($Value -is [array]) { return ('[{0}]' -f $Value.Count) + (-join @($Value | ForEach-Object { $s = [string]$_; '{0}:{1};' -f $s.Length, $s })) }
    $t = [string]$Value
    return ('{0}:{1}' -f $t.Length, $t)
}

function Compare-AtmRecoverCapture {
    # The fields that differ between two captures, in the order of AtmRecoveryCaptureFields: field (its log name),
    # before and after. Lists are compared item by item, in order; $null differs from empty.
    param($Before, $After)
    $b = ConvertTo-AtmRecoverCaptureRecord $Before
    $a = ConvertTo-AtmRecoverCaptureRecord $After
    $diff = New-Object System.Collections.Generic.List[object]
    foreach ($n in @($b.Keys)) {
        if ((Get-AtmRecoverFieldKey $b[$n]) -cne (Get-AtmRecoverFieldKey $a[$n])) { $diff.Add([ordered]@{ field = $n; before = $b[$n]; after = $a[$n] }) }
    }
    return $diff.ToArray()
}

function Get-AtmRecoverPlanCheck {
    <#
      The revalidation of step 7: the R1 criteria on a fresh collection (Reasons: its refusal codes) and its comparison
      with the confirmed plan (ChangedFields, names only): the target still declared ('target'), its declaring providers
      with their roles and images ('provider'), every capture field, the token's identity (its SID, compared in memory
      and never written: 'identity') and its elevation (the code and the elevation type: 'elevation'). Any reason or
      changed field refuses.
    #>
    param($Plan, $Collection, $Fresh, [string]$Service)
    $reasons = @(Get-AtmRecoverRefusals -Collection $Fresh -Name $Service)
    $fields = New-Object System.Collections.Generic.List[string]
    $provSig = {
        param($Coll)
        if (-not $Coll.DeclaredByName.ContainsKey($Service)) { return '' }
        return ((@(@($Coll.DeclaredByName[$Service].Providers) | ForEach-Object { '{0}|{1}|{2}' -f $_.Id, $_.Role, $_.ExpectedImage } | Sort-Object -CaseSensitive)) -join ';')
    }
    if (@($Fresh.DeclaredNames) -cnotcontains $Service -or -not $Fresh.FindingsByName.ContainsKey($Service)) { $fields.Add('target') }
    else {
        if ((& $provSig $Collection) -cne (& $provSig $Fresh)) { $fields.Add('provider') }
        $now = Get-AtmRecoverCapture -Collection $Fresh -Name $Service
        foreach ($d in @(Compare-AtmRecoverCapture -Before $Plan.Capture -After $now)) { $fields.Add([string]$d.field) }
    }
    if ([string]$Collection.Identity.Sid -cne [string]$Fresh.Identity.Sid) { $fields.Add('identity') }
    if ([string]$Collection.Elevation -cne [string]$Fresh.Elevation -or [string]$Collection.Identity.ElevationType -cne [string]$Fresh.Identity.ElevationType) { $fields.Add('elevation') }
    return [pscustomobject]@{ Reasons = $reasons; ChangedFields = $fields.ToArray() }
}

function Write-AtmRecoverRecord {
    # One JSON line of the recovery log (atm.recoverlog/1), written and flushed by -Log. $null, or the code.
    param($Log, [hashtable]$State, [string]$Type, [System.Collections.IDictionary]$Fields = @{})
    $State.Seq++
    $rec = [ordered]@{ schema = $script:AtmRecoverLogSchema; type = $Type; runId = $State.Id; recSeq = $State.Seq; utc = [datetime]::UtcNow.ToString('o') }
    foreach ($k in $Fields.Keys) { $rec[$k] = $Fields[$k] }
    $line = $null
    try { $line = ConvertTo-Json -InputObject $rec -Compress -Depth 6 } catch { return 'RECORD_INVALID' }
    try { return $Log.AppendLine($line) } catch { return ('WRITE_' + $_.Exception.GetBaseException().GetType().Name) }
}

function Wait-AtmRecoverSettle {
    # The real wait between two settle reads (step 9). The suite passes -SettleWait instead.
    param([int]$Milliseconds)
    Start-Sleep -Milliseconds $Milliseconds
}

function Invoke-AtmRecoverServiceStartDefault {
    <#
      The default service control seam: starts one service, by name, with no arguments, and nothing else. It uses
      System.ServiceProcess.ServiceController.Start(), which opens the service control manager with connect access and
      the service with the start right only (SERVICE_START): no other right on the service is asked, and nothing but
      its start is requested through it. Returns a closed code of
      AtmRecoverySeamCodes: OK, or the Win32 error of the start mapped by number (ACCESS_DENIED, SERVICE_...,
      SERVICE_WIN32_OTHER). Anything that is not a Win32 error of the start is thrown again: the outcome EXCEPTION, recorded
      by exception type only. Called only by Invoke-AtmRecoverLocked, past the recovery gate, when no -ServiceControlImpl
      is given; the suite never reaches it.
    #>
    param([string]$Name)
    $type = 'System.ServiceProcess.ServiceController' -as [type]
    if ($null -eq $type) {
        # Windows PowerShell 5.1 does not load the assembly by default; PowerShell 7 ships it as its own package.
        foreach ($asm in @('System.ServiceProcess, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a', 'System.ServiceProcess.ServiceController')) {
            try { $null = [Reflection.Assembly]::Load($asm) } catch { $null = $_ }
            $type = 'System.ServiceProcess.ServiceController' -as [type]
            if ($null -ne $type) { break }
        }
    }
    if ($null -eq $type) { throw (New-Object InvalidOperationException('SERVICE_CONTROL_UNAVAILABLE')) }
    $sc = New-Object -TypeName $type.FullName -ArgumentList $Name
    try {
        try { $sc.Start(); return 'OK' }
        catch {
            $w = $_.Exception
            while ($null -ne $w -and -not ($w -is [ComponentModel.Win32Exception])) { $w = $w.InnerException }
            if ($null -eq $w) { throw }
            $n = [int]$w.NativeErrorCode
            if ($script:AtmRecoveryWin32Codes.ContainsKey($n)) { return $script:AtmRecoveryWin32Codes[$n] }
            return 'SERVICE_WIN32_OTHER'
        }
    } finally { $sc.Dispose() }
}

function Invoke-AtmRecover {
    <#
      REC-SVC-START for ONE declared service (ADR-0016 sections 3 and 4): one operation per call, fixed in code, with no
      list or batch form. Every collection is fresh and made in this process (Get-AtmRecoverCollection, with the test
      overrides -Providers, -IdentitySource, -ServiceSource, -ServiceDependencySource, -ServiceWait, -DeadlineSeconds).
      Gate closed (every copy): the collection, the plan and the presenter, then RECUPERACAO_REAL_DESABILITADA. Nothing is
      asked, locked or logged, no inventory is read and the seam is never called.
      Past the gate (the suite only), in this order:
        1. an interactive console observed by the engine (CONSOLE_NOT_OBSERVED), then a confirmation reader;
        2. a NEW -LogFile outside every audited base (LOG_REQUIRED, LOG_DESTINATION_NOT_ALLOWED, LOG_ALREADY_EXISTS),
           checked against a fresh inventory (-InventoryArgs; only its bases are read);
        3. a fresh collection and the R1 criteria: any refusal stops here, before anything is asked (RECOVERY_REFUSED,
           with the codes in RefusalCodes);
        4. the plan through the mandatory -PlanPresenter scriptblock(plan): the "before" capture, the undo and what it
           does not undo;
        5. to 11. under the lock B8 (Invoke-AtmUnderSharedLock, without waiting: CLEAN_LOCK_<status> starts nothing):
           Invoke-AtmRecoverLocked.
      -ServiceControlImpl: test seam, scriptblock(name) returning a code of AtmRecoverySeamCodes; without it the default
      seam runs. -SettleWait: test seam, scriptblock(milliseconds) in place of the real wait. -NewRunId: the run id the
      CLI generated (phase R4: its log is named after it), lower-case D form or RUN_ID_INVALID; without it, a new one.
      Returns one object. Aborted: the seam was never called; StoppedBy: a failure after it; Outcome: what the seam's call
      gave.
    #>
    [CmdletBinding()]
    param(
        [string]$Operation,
        [string]$Service,
        [scriptblock]$PlanPresenter,
        [scriptblock]$ConfirmationReader,
        [hashtable]$InventoryArgs = @{},
        [string]$LogFile,
        [hashtable]$Interaction = @{},
        $Providers = $null,
        [scriptblock]$IdentitySource = $null,
        [scriptblock]$ServiceSource = $null,
        [scriptblock]$ServiceDependencySource = $null,
        [scriptblock]$ServiceWait = $null,
        [int]$DeadlineSeconds = $script:AtmRecoveryDeadlineSeconds,
        [scriptblock]$ServiceControlImpl,
        [scriptblock]$SettleWait,
        [string]$NewRunId
    )
    $logErrors = New-Object System.Collections.Generic.List[object]
    $res = [ordered]@{
        Operation = $Operation; Target = $Service; GateOpen = [bool]$script:AtmRecoveryEnabled; Plan = $null; PlanId = $null; Phrase = $null
        Aborted = $null; RefusalCodes = @(); ConfirmationCode = $null; RevalidationCodes = @(); ChangedFields = @(); StoppedBy = $null
        SeamCalled = $false; SeamCode = $null; ExceptionType = $null; Outcome = $null; WaitedMs = 0; Reads = 0
        Before = $null; After = $null; Diff = @(); Changed = $false
        RunId = $null; LogFile = $null; LogCreated = $false; LogErrors = @(); LockReleaseError = $null
    }
    $done = { $res.LogErrors = $logErrors.ToArray(); $res.Changed = (@($res.Diff).Count -gt 0); [pscustomobject]$res }
    $op = Get-AtmRecoveryOperation $Operation
    if ($null -eq $op) { $res.Aborted = 'RECOVERY_OPERATION_INVALID'; return (& $done) }
    if (-not $PlanPresenter) { $res.Aborted = 'SEM_APRESENTACAO'; return (& $done) }
    if ($NewRunId -and -not (Test-AtmRecoverRunIdForm $NewRunId)) { $res.Aborted = 'RUN_ID_INVALID'; return (& $done) }
    $collArgs = @{ Providers = $Providers; IdentitySource = $IdentitySource; ServiceSource = $ServiceSource; ServiceDependencySource = $ServiceDependencySource; ServiceWait = $ServiceWait; DeadlineSeconds = $DeadlineSeconds }
    if (-not $script:AtmRecoveryEnabled) {
        $coll = Get-AtmRecoverCollection @collArgs
        $plan = Get-AtmRecoverPlan -Collection $coll -Operation $op.Id -Service $Service
        $res.Plan = $plan; $res.PlanId = $plan.PlanId; $res.RefusalCodes = @($plan.Codes); $res.Before = $plan.Capture
        & $PlanPresenter $plan
        $res.Aborted = 'RECUPERACAO_REAL_DESABILITADA'
        return (& $done)
    }

    # ---- past the recovery gate (the suite only, in its own process) ----
    $console = Get-AtmEngineConsoleObservation
    if (-not $console.Observed) { $res.Aborted = 'CONSOLE_NOT_OBSERVED'; return (& $done) }
    if (-not $ConfirmationReader) { $res.Aborted = 'SEM_APRESENTACAO_OU_CONFIRMACAO'; return (& $done) }
    if (-not $LogFile) { $res.Aborted = 'LOG_REQUIRED'; return (& $done) }
    $ia = @{} + $InventoryArgs; $ia['NoProgress'] = $true
    $inv = Invoke-AtmInventory @ia
    if (-not (Test-AtmOutputPathOutsideBases -Path $LogFile -Inventory $inv)) { $res.Aborted = 'LOG_DESTINATION_NOT_ALLOWED'; return (& $done) }
    if (Test-Path -LiteralPath $LogFile) { $res.Aborted = 'LOG_ALREADY_EXISTS'; return (& $done) }
    $coll = Get-AtmRecoverCollection @collArgs
    $plan = Get-AtmRecoverPlan -Collection $coll -Operation $op.Id -Service $Service
    $res.Plan = $plan; $res.PlanId = $plan.PlanId; $res.RefusalCodes = @($plan.Codes); $res.Before = $plan.Capture
    if (-not $plan.Offered) { $res.Aborted = 'RECOVERY_REFUSED'; return (& $done) }
    & $PlanPresenter $plan
    # No closure: the body runs in this session state, where the engine's functions are, and finds $recBound here.
    $recBound = @{ Res = $res; LogErrors = $logErrors; Collection = $coll; Plan = $plan; Inventory = $inv; CollectionArgs = $collArgs; LogFile = $LogFile
        ConfirmationReader = $ConfirmationReader; Interaction = $Interaction; Console = $console; ServiceControlImpl = $ServiceControlImpl; SettleWait = $SettleWait; NewRunId = $NewRunId }
    $u = Invoke-AtmUnderSharedLock -Body { Invoke-AtmRecoverLocked @recBound }
    if (-not $u.Acquired) { $res.Aborted = 'CLEAN_LOCK_' + $u.Status; $res.LockReleaseError = $u.ReleaseError; return (& $done) }
    # A failed release never replaces the main code; with none it makes the run incomplete.
    if ($null -ne $u.ReleaseError) {
        $res.LockReleaseError = $u.ReleaseError
        if (-not $res.Aborted -and -not $res.StoppedBy) { if ($res.SeamCalled) { $res.StoppedBy = 'LOCK_RELEASE_FAILED' } else { $res.Aborted = 'LOCK_RELEASE_FAILED' } }
    }
    return (& $done)
}

function Invoke-AtmRecoverLocked {
    <#
      Steps 5 to 11 of Invoke-AtmRecover, called only by it, past the recovery gate and under the lock B8; fills -Res.
        5. the log (Open-AtmCleanLog: a new file through the pinned folder, outside every base, protected DACL), then
           run-start, plan and before;
        6. the typed phrase INICIAR SERVICO <the first 8 characters of the plan id, upper case>, compared exactly
           (Test-AtmTypedPhrase); confirmation. Empty or cancelled, or anything else: CONFIRMACAO_AUSENTE_OU_DIVERGENTE;
        7. the revalidation on a fresh collection (Get-AtmRecoverPlanCheck); plan-check. Any reason or changed field:
           REVALIDATION_REFUSED;
        8. intent, flushed, then the seam, with the service name and nothing else;
        9. the settle wait, after OK only;
       10. result (outcome, seam code, exception type, waited milliseconds, reads, exit codes and the diff) and after;
       11. run-end (only while the log has not failed); the log is closed here, the lock released by the caller.
      Outcomes: EXCEPTION (the seam threw, or gave no closed code); REFUSED (ACCESS_DENIED); FAILED (another seam code,
      with no wait, or back to STOPPED); COMPLETE (RUNNING); PARTIAL (anything else at the end of the wait). "After" is
      read and the diff computed in every outcome. Nothing is compensated or retried. The log never holds the token's
      name or SID, a command line, a path outside a known program location or an exception message.
    #>
    param([System.Collections.IDictionary]$Res, $LogErrors, $Collection, $Plan, $Inventory, [hashtable]$CollectionArgs, [string]$LogFile, [scriptblock]$ConfirmationReader,
        [hashtable]$Interaction = @{}, $Console, [scriptblock]$ServiceControlImpl, [scriptblock]$SettleWait, [string]$NewRunId)
    $service = [string]$Plan.Target
    $op = $Plan.Operation
    $logFail = { param([string]$Stage, [string]$Code) $LogErrors.Add([pscustomobject]@{ Stage = $Stage; Code = $Code }) }
    $halt = { param([string]$Code) if (-not $Res.Aborted -and -not $Res.StoppedBy) { if ($Res.SeamCalled) { $Res.StoppedBy = $Code } else { $Res.Aborted = $Code } } }
    $me = Get-AtmCurrentIdentity
    # R4: the CLI generates the run id once and names the log after it; any other caller gets a new one here.
    $runId = $(if ($NewRunId) { $NewRunId } else { [guid]::NewGuid().ToString() })
    $Res.RunId = $runId; $Res.LogFile = $LogFile
    $Res.Phrase = 'INICIAR SERVICO ' + ([string]$Plan.PlanId).Substring(0, 8).ToUpperInvariant()
    $ls = @{ Id = $runId; Seq = 0 }
    $log = $null
    try {
        $opened = Open-AtmCleanLog -Path $LogFile -Inventory $Inventory -ProcessUserSid $me.Sid
        $Res.LogCreated = [bool]$opened.Created
        if ($null -eq $opened.Log) { & $logFail 'open' $opened.Code; $Res.Aborted = 'LOG_OPEN_FAILED'; return }
        $log = $opened.Log
        $lc = Write-AtmRecoverRecord -Log $log -State $ls -Type 'run-start' -Fields ([ordered]@{ tool = $script:AtmVersion; operation = $op.Id; target = $service; planId = $Plan.PlanId
                elevation = $Collection.Elevation; elevationType = [string]$Collection.Identity.ElevationType; gateOpen = $true })
        if ($null -eq $lc) {
            $lc = Write-AtmRecoverRecord -Log $log -State $ls -Type 'plan' -Fields ([ordered]@{ operation = $op.Id; target = $service; provider = $Plan.Provider; providers = [string[]]@($Plan.Providers)
                    reversible = [bool]$op.Reversible; undo = $op.Undo; undoScope = $op.UndoScope; notUndone = $op.NotUndone; declaredDependencyStopped = [string[]]@($Plan.DeclaredDependencyStopped); planId = $Plan.PlanId })
        }
        if ($null -eq $lc) { $lc = Write-AtmRecoverRecord -Log $log -State $ls -Type 'before' -Fields (ConvertTo-AtmRecoverCaptureRecord $Plan.Capture) }
        if ($null -ne $lc) { & $logFail 'plan' $lc; $Res.Aborted = 'LOG_WRITE_FAILED'; return }

        # Step 6: the typed phrase, bound to the plan id.
        $callerName = [string]$Interaction['Caller']
        $interactionRec = [ordered]@{ caller = $(if ($callerName -ceq 'CLI' -or $callerName -ceq 'TUI') { $callerName } else { 'DIRECT_CALL' }); consoleRequiredByCaller = ($Interaction['ConsoleRequired'] -eq $true)
            callerFieldsVerified = $false; interactiveConsoleObserved = $true; observedBy = $Console.By; identifiesRespondent = $false }
        $tp = Test-AtmTypedPhrase -Typed (& $ConfirmationReader $Res.Phrase 'confirm' $null @($Res.Phrase)) -Phrases @($Res.Phrase)
        if ($tp.Code) {
            $Res.ConfirmationCode = $tp.Code
            $lc = Write-AtmRecoverRecord -Log $log -State $ls -Type 'confirmation' -Fields ([ordered]@{ accepted = $false; planId = $Plan.PlanId; refusal = 'CONFIRMACAO_AUSENTE_OU_DIVERGENTE'; reason = $tp.Code; interaction = $interactionRec })
            if ($null -ne $lc) { & $logFail 'confirmation' $lc }
            $Res.Aborted = 'CONFIRMACAO_AUSENTE_OU_DIVERGENTE'
        } else {
            $lc = Write-AtmRecoverRecord -Log $log -State $ls -Type 'confirmation' -Fields ([ordered]@{ accepted = $true; planId = $Plan.PlanId; interaction = $interactionRec })
            if ($null -ne $lc) { & $logFail 'confirmation' $lc; $Res.Aborted = 'LOG_WRITE_FAILED' }
        }

        # Step 7: the revalidation, immediately before acting.
        if (-not $Res.Aborted) {
            $fresh = Get-AtmRecoverCollection @CollectionArgs
            $chk = Get-AtmRecoverPlanCheck -Plan $Plan -Collection $Collection -Fresh $fresh -Service $service
            $Res.RevalidationCodes = @($chk.Reasons); $Res.ChangedFields = @($chk.ChangedFields)
            $matched = (@($chk.Reasons).Count -eq 0 -and @($chk.ChangedFields).Count -eq 0)
            $lc = Write-AtmRecoverRecord -Log $log -State $ls -Type 'plan-check' -Fields ([ordered]@{ planId = $Plan.PlanId; matched = $matched; reasons = [string[]]@($chk.Reasons); changedFields = [string[]]@($chk.ChangedFields) })
            if ($null -ne $lc) { & $logFail 'plan-check' $lc; $Res.Aborted = 'LOG_WRITE_FAILED' }
            elseif (-not $matched) { $Res.Aborted = 'REVALIDATION_REFUSED' }
        }

        # Step 8: the intent, written and flushed BEFORE the seam; without it, no call.
        if (-not $Res.Aborted) {
            $lc = Write-AtmRecoverRecord -Log $log -State $ls -Type 'intent' -Fields ([ordered]@{ operation = $op.Id; target = $service; planId = $Plan.PlanId; seam = $(if ($ServiceControlImpl) { 'TEST_SEAM' } else { 'DEFAULT' }) })
            if ($null -ne $lc) { & $logFail 'intent' $lc; $Res.Aborted = 'LOG_INTENT_FAILED' }
        }
        if (-not $Res.Aborted) {
            # The only call to the seam: the service name and nothing else.
            $Res.SeamCalled = $true
            $code = $null; $exType = $null
            try {
                if ($ServiceControlImpl) { $code = & $ServiceControlImpl $service } else { $code = Invoke-AtmRecoverServiceStartDefault -Name $service }
            } catch { $code = $null; $exType = $_.Exception.GetBaseException().GetType().Name }
            if ($null -eq $exType -and (-not ($code -is [string]) -or $script:AtmRecoverySeamCodes -cnotcontains $code)) { $code = $null; $exType = 'SEAM_RESULT_INVALID' }
            $Res.SeamCode = $code; $Res.ExceptionType = $exType

            # Step 9: the settle wait, bounded (after OK only).
            $last = $null
            $limit = $script:AtmRecoverySettleMinMs
            if ($code -ceq 'OK') {
                $clock = [Diagnostics.Stopwatch]::StartNew()
                while ($true) {
                    $last = Get-AtmRecoverCollection @CollectionArgs
                    $Res.Reads = $Res.Reads + 1
                    $cap = $(if ($last.FindingsByName.ContainsKey($service)) { Get-AtmRecoverCapture -Collection $last -Name $service } else { $null })
                    $st = $(if ($null -ne $cap) { [string]$cap.State } else { '' })
                    $wh = 0
                    if ($null -ne $cap -and [int]::TryParse([string]$cap.WaitHint, [ref]$wh) -and $wh -gt $limit) { $limit = [Math]::Min($wh, $script:AtmRecoverySettleCapMs) }
                    if ($st -ceq 'RUNNING' -or $st -ceq 'STOPPED') { break }
                    if ($Res.WaitedMs -ge $limit -or $clock.ElapsedMilliseconds -ge $limit) { break }
                    if ($SettleWait) { & $SettleWait $script:AtmRecoverySettlePollMs } else { Wait-AtmRecoverSettle -Milliseconds $script:AtmRecoverySettlePollMs }
                    $Res.WaitedMs = $Res.WaitedMs + $script:AtmRecoverySettlePollMs
                }
            }
            # Step 10: "after", read again in every outcome.
            if ($null -eq $last) { $last = Get-AtmRecoverCollection @CollectionArgs; $Res.Reads = $Res.Reads + 1 }
            $after = $(if ($last.FindingsByName.ContainsKey($service)) { Get-AtmRecoverCapture -Collection $last -Name $service } else { $null })
            $Res.After = $after
            $afterState = $(if ($null -ne $after) { [string]$after.State } else { '' })
            $Res.Outcome = $(if ($null -ne $exType) { 'EXCEPTION' } elseif ($code -ceq 'ACCESS_DENIED') { 'REFUSED' } elseif ($code -cne 'OK') { 'FAILED' }
                elseif ($afterState -ceq 'RUNNING') { 'COMPLETE' } elseif ($afterState -ceq 'STOPPED') { 'FAILED' } else { 'PARTIAL' })
            $Res.Diff = @(Compare-AtmRecoverCapture -Before $Plan.Capture -After $after)
            $lc = Write-AtmRecoverRecord -Log $log -State $ls -Type 'result' -Fields ([ordered]@{ operation = $op.Id; target = $service; outcome = $Res.Outcome; seamCode = $code; exceptionType = $exType
                    waitedMs = $Res.WaitedMs; limitMs = $limit; reads = $Res.Reads; exitCode = $(if ($null -ne $after) { $after.ExitCode } else { $null }); serviceSpecificExitCode = $(if ($null -ne $after) { $after.ServiceSpecificExitCode } else { $null })
                    diff = @($Res.Diff) })
            if ($null -ne $lc) { & $logFail 'result' $lc; & $halt 'LOG_RESULT_FAILED' }
            else {
                $lc = Write-AtmRecoverRecord -Log $log -State $ls -Type 'after' -Fields (ConvertTo-AtmRecoverCaptureRecord $after)
                if ($null -ne $lc) { & $logFail 'after' $lc; & $halt 'LOG_AFTER_FAILED' }
            }
        }

        # Step 11: run-end only while the log has not failed; neither a failed run-end nor a failed close replaces the
        # main code.
        if ($LogErrors.Count -eq 0) {
            $lc = Write-AtmRecoverRecord -Log $log -State $ls -Type 'run-end' -Fields ([ordered]@{ outcome = $Res.Outcome; stoppedBy = $(if ($Res.StoppedBy) { $Res.StoppedBy } else { $Res.Aborted }); seamCalled = [bool]$Res.SeamCalled
                    changedFields = @($Res.Diff).Count })
            if ($null -ne $lc) { & $logFail 'run-end' $lc; & $halt 'LOG_END_FAILED' }
        }
        $cc = $log.Close()
        if ($null -ne $cc) { & $logFail 'close' $cc; & $halt 'LOG_CLOSE_FAILED' }
    } finally {
        if ($null -ne $log) { try { $log.Dispose() } catch { $null = $_ } }
    }
}

# ---------------------------------------------------------------------------------------------
# Phase R3 (ADR-0016 sections 3, 4 and 6): the undo of one REC-SVC-START run, REC-SVC-STOP, which exists only as that
# undo (V04-D1 (a)): never in the catalog, never offered by recover list, never accepted by recover plan or
# Invoke-AtmRecover. The inverse plan is built from the "before" and "after" records of that run's log and a fresh
# collection, and it is refused when the service is no longer in the recorded "after" state: the undo never overwrites a
# newer state. The stop seam is reached past the gate only, by the undo only, and only the suite reaches it (with the
# gate opened in its own process and the seam injected). No compensation and no repetition, ever (V04-D7 (a)); the
# undo of an undo does not exist (a new start is a new REC-SVC-START run).
# ---------------------------------------------------------------------------------------------
$script:AtmRecoveryUndoOperation = [pscustomobject]@{
    Id        = 'REC-SVC-STOP'
    UndoOf    = 'REC-SVC-START'
    Target    = 'SERVICE'
    NotUndone = @('WHAT_THE_SERVICE_DID_WHILE_RUNNING', 'STATE_HELD_IN_MEMORY')
}
$script:AtmRecoveryUndoPlanSchema = 'atm-recover-undo-plan/1'
# The source log: read once, at most 1 MiB, through a handle that never follows a reparse point.
$script:AtmRecoveryUndoSourceMaxBytes = 1048576
# The records of a complete R2 run, in order (Invoke-AtmRecoverLocked).
$script:AtmRecoveryRunTypes = @('run-start', 'plan', 'before', 'confirmation', 'plan-check', 'intent', 'result', 'after', 'run-end')
$script:AtmRecoveryUndoableOutcomes = @('COMPLETE', 'PARTIAL')
# Why a source log gives no plan, closed, in the order they are checked.
$script:AtmRecoveryUndoSourceCodes = @(
    'UNDO_SOURCE_UNREADABLE',           # not a plain absolute local path, not found, or not readable
    'UNDO_SOURCE_NOT_REGULAR',          # a reparse point in its path or the file itself, or a directory
    'UNDO_SOURCE_TOO_LARGE',            # over AtmRecoveryUndoSourceMaxBytes
    'UNDO_SOURCE_PROVENANCE',           # not the owner and protected DACL Open-AtmCleanLog gives a log
    'UNDO_SOURCE_INVALID',              # not strict JSON lines of atm.recoverlog/1 with one run id, a contiguous recSeq and the records of an R2 run
    'UNDO_SOURCE_RUN_MISMATCH',         # -RunId is not the log's run id
    'UNDO_SOURCE_INCOMPLETE',           # the run's records stop before run-end
    'UNDO_SOURCE_OPERATION_INVALID',    # the run's operation is not REC-SVC-START
    'UNDO_SOURCE_NOT_STARTED',          # a run that stopped before the seam: nothing was started
    'UNDO_SOURCE_OUTCOME_NOT_UNDOABLE'  # FAILED, REFUSED or EXCEPTION: nothing the engine can undo
)
# Why an inverse plan is refused (with the R1 codes of the criteria it shares: declaration, coverage, image, properties,
# signals and dependencies read).
$script:AtmRecoveryUndoRefusalCodes = @(
    'UNDO_STATE_CHANGED',      # a field differs from the recorded "after" (ChangedFields names them)
    'UNDO_STILL_PENDING',      # a PARTIAL run whose service is still pending: stopping a pending service is out
    'UNDO_NOT_RUNNING',        # the service is not RUNNING
    'UNDO_ACCEPT_STOP_FALSE',  # it does not accept a stop
    'UNDO_DEPENDENT_ACTIVE'    # a dependent service is not STOPPED (hidden names included): never a cascade
)
# The R1 criteria that belong to a start only, left out of the undo's.
$script:AtmRecoveryUndoStartOnly = @('RECOVERY_NOT_STOPPED', 'RECOVERY_START_MODE_DISABLED', 'RECOVERY_DEPENDENCY_STOPPED')
# A PARTIAL run's natural continuation, pending to RUNNING, changes these capture fields (R0's capture: CheckPoint and
# WaitHint as the service reports them, which only a pending service advances; the condition only for STOPPED and
# PENDING; whether it accepts a stop). Any other changed field refuses, exitCode included.
$script:AtmRecoveryUndoPartialTransition = @('state', 'checkPoint', 'waitHint', 'condition', 'acceptStop')
# The stop seam's closed results, as R2's: OK, ACCESS_DENIED (REFUSED), the other Win32 errors of a stop by number
# (FAILED, no wait), SERVICE_WIN32_OTHER outside the map.
$script:AtmRecoveryStopWin32Codes = @{
    5 = 'ACCESS_DENIED'; 1051 = 'DEPENDENT_SERVICES_RUNNING'; 1053 = 'SERVICE_REQUEST_TIMEOUT'; 1060 = 'SERVICE_DOES_NOT_EXIST'; 1061 = 'SERVICE_CANNOT_ACCEPT_CTRL'
    1062 = 'SERVICE_NOT_ACTIVE'; 1072 = 'SERVICE_MARKED_FOR_DELETE'
}
$script:AtmRecoveryStopSeamCodes = @('OK', 'ACCESS_DENIED', 'DEPENDENT_SERVICES_RUNNING', 'SERVICE_REQUEST_TIMEOUT', 'SERVICE_DOES_NOT_EXIST', 'SERVICE_CANNOT_ACCEPT_CTRL',
    'SERVICE_NOT_ACTIVE', 'SERVICE_MARKED_FOR_DELETE', 'SERVICE_WIN32_OTHER')
$script:AtmRecoverJsonNumber = New-Object System.Text.RegularExpressions.Regex('\G-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?', [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
$script:AtmRecoverJsonMaxDepth = 8

function Skip-AtmRecoverJsonSpace {
    param([hashtable]$S)
    while ($S.I -lt $S.T.Length -and ([int]$S.T[$S.I] -eq 32 -or [int]$S.T[$S.I] -eq 9)) { $S.I++ }
}

function Read-AtmRecoverJsonHex4 {
    param([string]$T, [int]$At)
    if ($At + 4 -gt $T.Length) { throw (New-Object FormatException('JSON_ESCAPE')) }
    $h = $T.Substring($At, 4)
    if ($h -cnotmatch '^[0-9A-Fa-f]{4}$') { throw (New-Object FormatException('JSON_ESCAPE')) }
    return [Convert]::ToInt32($h, 16)
}

function Read-AtmRecoverJsonString {
    # A JSON string at S.I (its opening quote) into S.V. Refused: a control character, an unknown escape, a lone surrogate.
    param([hashtable]$S)
    $t = $S.T; $i = $S.I + 1
    $sb = New-Object System.Text.StringBuilder
    while ($true) {
        if ($i -ge $t.Length) { throw (New-Object FormatException('JSON_STRING_END')) }
        $c = [int]$t[$i]
        if ($c -eq 34) { $i++; break }
        if ($c -lt 32) { throw (New-Object FormatException('JSON_CONTROL_CHAR')) }
        if ($c -ne 92) { [void]$sb.Append([char]$c); $i++; continue }
        if ($i + 1 -ge $t.Length) { throw (New-Object FormatException('JSON_ESCAPE')) }
        $e = [int]$t[$i + 1]; $i += 2
        if ($e -eq 34 -or $e -eq 92 -or $e -eq 47) { [void]$sb.Append([char]$e) }
        elseif ($e -eq 98) { [void]$sb.Append([char]8) }
        elseif ($e -eq 102) { [void]$sb.Append([char]12) }
        elseif ($e -eq 110) { [void]$sb.Append([char]10) }
        elseif ($e -eq 114) { [void]$sb.Append([char]13) }
        elseif ($e -eq 116) { [void]$sb.Append([char]9) }
        elseif ($e -eq 117) {
            $u = Read-AtmRecoverJsonHex4 $t $i; $i += 4
            if ($u -ge 0xD800 -and $u -le 0xDBFF) {
                if ($i + 2 -gt $t.Length -or [int]$t[$i] -ne 92 -or [int]$t[$i + 1] -ne 117) { throw (New-Object FormatException('JSON_SURROGATE')) }
                $lo = Read-AtmRecoverJsonHex4 $t ($i + 2)
                if ($lo -lt 0xDC00 -or $lo -gt 0xDFFF) { throw (New-Object FormatException('JSON_SURROGATE')) }
                $i += 6
                [void]$sb.Append([char]$u); [void]$sb.Append([char]$lo)
            } elseif ($u -ge 0xDC00 -and $u -le 0xDFFF) { throw (New-Object FormatException('JSON_SURROGATE')) }
            else { [void]$sb.Append([char]$u) }
        } else { throw (New-Object FormatException('JSON_ESCAPE')) }
    }
    $S.I = $i
    $S.V = $sb.ToString()
}

function Read-AtmRecoverJsonValue {
    # One JSON value at S.I into S.V: an object (an ordered dictionary with ordinal keys, a duplicate key refused), an
    # array (object[], never unrolled), a string, a number (long, or double with a fraction or an exponent), true, false
    # or null. Deeper than AtmRecoverJsonMaxDepth is refused.
    param([hashtable]$S)
    $t = $S.T
    Skip-AtmRecoverJsonSpace $S
    if ($S.I -ge $t.Length) { throw (New-Object FormatException('JSON_END')) }
    $c = [int]$t[$S.I]
    if ($c -eq 123 -or $c -eq 91) {
        $S.D++
        if ($S.D -gt $script:AtmRecoverJsonMaxDepth) { throw (New-Object FormatException('JSON_DEPTH')) }
        $S.I++
        Skip-AtmRecoverJsonSpace $S
        if ($c -eq 123) {
            $o = New-Object System.Collections.Specialized.OrderedDictionary([StringComparer]::Ordinal)
            if ($S.I -lt $t.Length -and [int]$t[$S.I] -eq 125) { $S.I++ }
            else {
                while ($true) {
                    Skip-AtmRecoverJsonSpace $S
                    if ($S.I -ge $t.Length -or [int]$t[$S.I] -ne 34) { throw (New-Object FormatException('JSON_KEY')) }
                    Read-AtmRecoverJsonString $S
                    $k = [string]$S.V
                    if ($o.Contains($k)) { throw (New-Object FormatException('JSON_DUPLICATE_KEY')) }
                    Skip-AtmRecoverJsonSpace $S
                    if ($S.I -ge $t.Length -or [int]$t[$S.I] -ne 58) { throw (New-Object FormatException('JSON_COLON')) }
                    $S.I++
                    Read-AtmRecoverJsonValue $S
                    $o[$k] = $S.V
                    Skip-AtmRecoverJsonSpace $S
                    if ($S.I -lt $t.Length -and [int]$t[$S.I] -eq 44) { $S.I++; continue }
                    if ($S.I -lt $t.Length -and [int]$t[$S.I] -eq 125) { $S.I++; break }
                    throw (New-Object FormatException('JSON_OBJECT'))
                }
            }
            $S.V = $o
        } else {
            $list = New-Object System.Collections.Generic.List[object]
            if ($S.I -lt $t.Length -and [int]$t[$S.I] -eq 93) { $S.I++ }
            else {
                while ($true) {
                    Read-AtmRecoverJsonValue $S
                    $list.Add($S.V)
                    Skip-AtmRecoverJsonSpace $S
                    if ($S.I -lt $t.Length -and [int]$t[$S.I] -eq 44) { $S.I++; continue }
                    if ($S.I -lt $t.Length -and [int]$t[$S.I] -eq 93) { $S.I++; break }
                    throw (New-Object FormatException('JSON_ARRAY'))
                }
            }
            $S.V = $list.ToArray()
        }
        $S.D--
        return
    }
    if ($c -eq 34) { Read-AtmRecoverJsonString $S; return }
    foreach ($lit in @(@('true', $true), @('false', $false), @('null', $null))) {
        $w = [string]$lit[0]
        if ($S.I + $w.Length -le $t.Length -and [string]::CompareOrdinal($t, $S.I, $w, 0, $w.Length) -eq 0) { $S.I += $w.Length; $S.V = $lit[1]; return }
    }
    $m = $script:AtmRecoverJsonNumber.Match($t, $S.I)
    if (-not $m.Success -or $m.Length -eq 0) { throw (New-Object FormatException('JSON_VALUE')) }
    $S.I += $m.Length
    if ($m.Value.IndexOfAny([char[]]'.eE') -ge 0) { $S.V = [double]::Parse($m.Value, [Globalization.CultureInfo]::InvariantCulture); return }
    $l = [long]0
    if (-not [long]::TryParse($m.Value, [Globalization.NumberStyles]::AllowLeadingSign, [Globalization.CultureInfo]::InvariantCulture, [ref]$l)) { throw (New-Object FormatException('JSON_NUMBER')) }
    $S.V = $l
}

function ConvertFrom-AtmRecoverJsonLine {
    # One log line as strict JSON: one object and nothing after it. Throws FormatException otherwise.
    param([string]$Text)
    $S = @{ T = $Text; I = 0; V = $null; D = 0 }
    Read-AtmRecoverJsonValue $S
    Skip-AtmRecoverJsonSpace $S
    if ($S.I -ne $Text.Length) { throw (New-Object FormatException('JSON_TRAILING')) }
    if (-not ($S.V -is [System.Collections.Specialized.OrderedDictionary])) { throw (New-Object FormatException('JSON_NOT_OBJECT')) }
    return $S.V
}

function ConvertFrom-AtmRecoverCaptureRecord {
    # A before or after record back to a capture (the inverse of ConvertTo-AtmRecoverCaptureRecord). Ok: exactly the
    # record's header and the capture fields, each $null or a string, the two lists arrays of strings; or every capture
    # field $null (the service was not read: Capture $null). Any other shape is not Ok.
    param($Record)
    $bad = [pscustomobject]@{ Ok = $false; Capture = $null }
    $want = @('schema', 'type', 'runId', 'recSeq', 'utc') + @($script:AtmRecoveryCaptureFields.Values)
    if ($null -eq $Record -or $Record.Count -ne $want.Count) { return $bad }
    foreach ($k in $want) { if (-not $Record.Contains($k)) { return $bad } }
    if (@(@($script:AtmRecoveryCaptureFields.Values) | Where-Object { $null -ne $Record[$_] }).Count -eq 0) { return [pscustomobject]@{ Ok = $true; Capture = $null } }
    $o = [ordered]@{}
    foreach ($k in $script:AtmRecoveryCaptureFields.Keys) {
        $v = $Record[$script:AtmRecoveryCaptureFields[$k]]
        if ($k -ceq 'DependsOn' -or $k -ceq 'Dependents') {
            if (-not ($v -is [object[]])) { return $bad }
            foreach ($x in $v) { if (-not ($x -is [string])) { return $bad } }
            $o[$k] = [string[]]$v
        } else {
            if ($null -ne $v -and -not ($v -is [string])) { return $bad }
            $o[$k] = $v
        }
    }
    return [pscustomobject]@{ Ok = $true; Capture = [pscustomobject]$o }
}

function Test-AtmRecoverSourceProvenance {
    <#
      The owner and DACL that Open-AtmCleanLog gives every log, read through the open handle: owned by this process's
      user or by Administrators, a protected DACL, and access allowed to no one but this user, SYSTEM, Administrators and
      OWNER RIGHTS. It shows who could have written the file, not that the engine wrote what it says (ADR-0016, R3).
    #>
    param($Stream)
    $me = Get-AtmCurrentIdentity
    $sec = $(if ($null -ne ('System.IO.FileSystemAclExtensions' -as [type])) { [System.IO.FileSystemAclExtensions]::GetAccessControl($Stream) } else { $Stream.GetAccessControl() })
    $owner = $sec.GetOwner([Security.Principal.SecurityIdentifier])
    if ($null -eq $owner -or @([string]$me.Sid, 'S-1-5-32-544') -cnotcontains $owner.Value) { return $false }
    if (-not $sec.AreAccessRulesProtected) { return $false }
    $allowed = @([string]$me.Sid, 'S-1-5-18', 'S-1-5-32-544', 'S-1-3-4')
    foreach ($r in @($sec.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))) {
        if ($r.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $allowed -cnotcontains $r.IdentityReference.Value) { return $false }
    }
    return $true
}

function Read-AtmRecoverRunLog {
    <#
      The source of an undo: the log of one R2 run, given by the caller (-Path) and its run id (-RunId), read only and as
      untrusted data. In this order: a plain absolute local path; no reparse point in its path or on the file (checked on
      the handle, which follows none); a regular file of at most 1 MiB, read once; the owner and protected DACL of a log
      (Test-AtmRecoverSourceProvenance); UTF-8 without BOM, LF only, ending with LF, no blank line; each line strict JSON
      of atm.recoverlog/1, one run id (that of -RunId), recSeq contiguous from 1, the records of an R2 run in order,
      none unknown or repeated; operation REC-SVC-START with one target and one plan id throughout, confirmed, matched,
      the seam called with OK, and the outcome COMPLETE or PARTIAL; before STOPPED, after RUNNING (COMPLETE) or neither
      RUNNING nor STOPPED (PARTIAL). Returns Code ($null, or one of AtmRecoveryUndoSourceCodes), RunId, Target, PlanId, Outcome, Before and
      After (captures). Never throws: every failure is a code. Nothing in it is used unchecked: the target must still be
      declared and the state comes only from a fresh collection.
    #>
    param([string]$Path, [string]$RunId)
    $out = [ordered]@{ Code = $null; RunId = $null; Target = $null; PlanId = $null; Outcome = $null; Before = $null; After = $null }
    $fail = { param([string]$Code) $out.Code = $Code; [pscustomobject]$out }
    $g = [guid]::Empty
    if (-not [guid]::TryParseExact([string]$RunId, 'D', [ref]$g) -or $g.ToString() -cne $RunId) { return (& $fail 'UNDO_SOURCE_RUN_MISMATCH') }
    if ($null -ne (Test-AtmAllowListPathSyntax $Path)) { return (& $fail 'UNDO_SOURCE_UNREADABLE') }
    $bytes = $null
    try {
        Initialize-AtmNative
        $at = $null
        $chain = [AgentTempManager.AtmPathCheck]::Chain($Path, [ref]$at)
        if ($chain -ceq 'REPARSE_IN_PATH') { return (& $fail 'UNDO_SOURCE_NOT_REGULAR') }
        if ($chain -cne 'OK') { return (& $fail 'UNDO_SOURCE_UNREADABLE') }
        $err = $null
        $h = [AgentTempManager.AtmSharedRead]::Open($Path, [ref]$err)
        if ($null -eq $h) { return (& $fail $(if ($err -ceq 'REPARSE' -or $err -ceq 'DIRECTORY') { 'UNDO_SOURCE_NOT_REGULAR' } else { 'UNDO_SOURCE_UNREADABLE' })) }
        $fs = New-Object IO.FileStream($h, [IO.FileAccess]::Read)
        try {
            $len = $fs.Length
            if ($len -gt $script:AtmRecoveryUndoSourceMaxBytes) { return (& $fail 'UNDO_SOURCE_TOO_LARGE') }
            if (-not (Test-AtmRecoverSourceProvenance -Stream $fs)) { return (& $fail 'UNDO_SOURCE_PROVENANCE') }
            $bytes = New-Object byte[] ([int]$len)
            $n = 0
            while ($n -lt $len) { $r = $fs.Read($bytes, $n, [int]$len - $n); if ($r -le 0) { break }; $n += $r }
            if ($n -ne $len) { return (& $fail 'UNDO_SOURCE_UNREADABLE') }
        } finally { $fs.Dispose() }
    } catch { return (& $fail 'UNDO_SOURCE_UNREADABLE') }

    $str = { param($R, [string]$K) if ($null -ne $R -and $R.Contains($K) -and $R[$K] -is [string]) { $R[$K] } else { $null } }
    $isTrue = { param($R, [string]$K) ($null -ne $R -and $R.Contains($K) -and $R[$K] -is [bool] -and $R[$K]) }
    try {
        if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { return (& $fail 'UNDO_SOURCE_INVALID') }
        $text = (New-Object System.Text.UTF8Encoding($false, $true)).GetString($bytes)
        if ($text.Length -eq 0) { return (& $fail 'UNDO_SOURCE_INCOMPLETE') }
        if ($text.Contains([string][char]13) -or -not $text.EndsWith([string][char]10)) { return (& $fail 'UNDO_SOURCE_INVALID') }
        $lines = $text.Substring(0, $text.Length - 1).Split([char]10)
        if ($lines.Count -gt $script:AtmRecoveryRunTypes.Count) { return (& $fail 'UNDO_SOURCE_INVALID') }
        $recs = New-Object System.Collections.Generic.List[object]
        foreach ($ln in $lines) {
            if ($ln.Length -eq 0) { return (& $fail 'UNDO_SOURCE_INVALID') }
            $rec = ConvertFrom-AtmRecoverJsonLine $ln
            if ((& $str $rec 'schema') -cne $script:AtmRecoverLogSchema -or $null -eq (& $str $rec 'type') -or $null -eq (& $str $rec 'runId') -or $null -eq (& $str $rec 'utc') -or
                -not $rec.Contains('recSeq') -or -not ($rec['recSeq'] -is [long])) { return (& $fail 'UNDO_SOURCE_INVALID') }
            $recs.Add($rec)
        }
        $byType = @{}
        $types = New-Object System.Collections.Generic.List[string]
        for ($i = 0; $i -lt $recs.Count; $i++) {
            $ty = [string]$recs[$i]['type']
            if ([string]$recs[$i]['runId'] -cne [string]$recs[0]['runId'] -or $recs[$i]['recSeq'] -ne ($i + 1) -or $script:AtmRecoveryRunTypes -cnotcontains $ty -or $byType.ContainsKey($ty)) { return (& $fail 'UNDO_SOURCE_INVALID') }
            $byType[$ty] = $recs[$i]
            $types.Add($ty)
        }
        if ([string]$recs[0]['runId'] -cne $RunId) { return (& $fail 'UNDO_SOURCE_RUN_MISMATCH') }
        $full = $script:AtmRecoveryRunTypes
        $isPrefix = { param($List) for ($j = 0; $j -lt $List.Count; $j++) { if ($List[$j] -cne $full[$j]) { return $false } }; return $true }
        $stopped = $false
        if ($types.Count -lt $full.Count) {
            if (& $isPrefix $types) { return (& $fail 'UNDO_SOURCE_INCOMPLETE') }
            # A run stopped before the seam: its records up to the stop, then run-end, and never an intent.
            $head = @($types.GetRange(0, $types.Count - 1))
            if ($types[$types.Count - 1] -ceq 'run-end' -and (& $isPrefix $head) -and $head -cnotcontains 'intent') { $stopped = $true }
            else { return (& $fail 'UNDO_SOURCE_INVALID') }
        } elseif (-not (& $isPrefix $types)) { return (& $fail 'UNDO_SOURCE_INVALID') }
        $rs = $byType['run-start']
        $op = & $str $rs 'operation'; $target = & $str $rs 'target'; $planId = & $str $rs 'planId'
        if (-not $op -or -not $target -or $planId -cnotmatch '^[0-9a-f]{64}$' -or -not (& $isTrue $rs 'gateOpen')) { return (& $fail 'UNDO_SOURCE_INVALID') }
        if ($op -cne $script:AtmRecoveryUndoOperation.UndoOf) { return (& $fail 'UNDO_SOURCE_OPERATION_INVALID') }
        if ($stopped) { return (& $fail 'UNDO_SOURCE_NOT_STARTED') }
        foreach ($ty in @('plan', 'intent', 'result')) { if ((& $str $byType[$ty] 'operation') -cne $op -or (& $str $byType[$ty] 'target') -cne $target) { return (& $fail 'UNDO_SOURCE_INVALID') } }
        foreach ($ty in @('plan', 'confirmation', 'plan-check', 'intent')) { if ((& $str $byType[$ty] 'planId') -cne $planId) { return (& $fail 'UNDO_SOURCE_INVALID') } }
        if (-not (& $isTrue $byType['confirmation'] 'accepted') -or -not (& $isTrue $byType['plan-check'] 'matched') -or -not (& $isTrue $byType['run-end'] 'seamCalled')) { return (& $fail 'UNDO_SOURCE_INVALID') }
        $outcome = & $str $byType['result'] 'outcome'
        if ($script:AtmRecoveryOutcomes -cnotcontains $outcome -or (& $str $byType['run-end'] 'outcome') -cne $outcome) { return (& $fail 'UNDO_SOURCE_INVALID') }
        if ($script:AtmRecoveryUndoableOutcomes -cnotcontains $outcome) { return (& $fail 'UNDO_SOURCE_OUTCOME_NOT_UNDOABLE') }
        if ((& $str $byType['result'] 'seamCode') -cne 'OK') { return (& $fail 'UNDO_SOURCE_INVALID') }
        # R2's outcomes: COMPLETE ends RUNNING; PARTIAL ends neither RUNNING nor STOPPED (pending, paused, unreadable or
        # not read at all).
        $before = ConvertFrom-AtmRecoverCaptureRecord $byType['before']
        $after = ConvertFrom-AtmRecoverCaptureRecord $byType['after']
        if (-not $before.Ok -or -not $after.Ok -or $null -eq $before.Capture -or [string]$before.Capture.State -cne 'STOPPED') { return (& $fail 'UNDO_SOURCE_INVALID') }
        $afterState = $(if ($null -ne $after.Capture) { [string]$after.Capture.State } else { '' })
        if (($outcome -ceq 'COMPLETE' -and $afterState -cne 'RUNNING') -or ($outcome -ceq 'PARTIAL' -and ($afterState -ceq 'RUNNING' -or $afterState -ceq 'STOPPED'))) { return (& $fail 'UNDO_SOURCE_INVALID') }
        $out.RunId = $RunId; $out.Target = $target; $out.PlanId = $planId; $out.Outcome = $outcome; $out.Before = $before.Capture; $out.After = $after.Capture
        return [pscustomobject]$out
    } catch { return (& $fail 'UNDO_SOURCE_INVALID') }
}

function Test-AtmRecoverUndoPendingSource {
    # A PARTIAL run that ended with its service pending: the only source whose natural continuation is accepted.
    param([string]$SourceOutcome, $Recorded)
    return ($SourceOutcome -ceq 'PARTIAL' -and $null -ne $Recorded -and [string]$Recorded.State -ceq 'PENDING')
}

function Get-AtmRecoverUndoRefusals {
    <#
      The criteria of the undo of one recorded run for one declared name of a collection. Codes (ordinal order; none
      means offered) and ChangedFields (log names):
        * the R1 criteria it shares with a start (declared, one provider, coverage, a declared image that matches,
          listed once, properties and fault signals read, dependencies read in both directions);
        * the current capture equals the recorded "after", field by field (UNDO_STATE_CHANGED with the fields). For a
          PARTIAL run that ended pending, the fields of its natural continuation (AtmRecoveryUndoPartialTransition) may
          differ, and only while the service is RUNNING or still pending; still pending is UNDO_STILL_PENDING;
        * it is RUNNING (UNDO_NOT_RUNNING) and accepts a stop (UNDO_ACCEPT_STOP_FALSE);
        * every dependent is STOPPED, hidden names included (UNDO_DEPENDENT_ACTIVE): read from the capture, no new
          query.
    #>
    param($Collection, [string]$Name, $Recorded, [string]$SourceOutcome)
    $codes = New-Object System.Collections.Generic.List[string]
    $fields = New-Object System.Collections.Generic.List[string]
    foreach ($c in @(Get-AtmRecoverRefusals -Collection $Collection -Name $Name)) { if ($script:AtmRecoveryUndoStartOnly -cnotcontains $c) { $codes.Add($c) } }
    if ($codes -ccontains 'RECOVERY_NOT_DECLARED') { return [pscustomobject]@{ Codes = @('RECOVERY_NOT_DECLARED'); ChangedFields = @() } }
    $f = $Collection.FindingsByName[$Name]
    if ((Test-AtmRecoverEvidence $f 'SERVICE_STATE') -or (Test-AtmRecoverEvidence $f 'SERVICE_STATE_UNREADABLE')) {
        $now = Get-AtmRecoverCapture -Collection $Collection -Name $Name
        $st = [string]$now.State
        $pendingSource = (Test-AtmRecoverUndoPendingSource -SourceOutcome $SourceOutcome -Recorded $Recorded)
        $natural = ($pendingSource -and ($st -ceq 'RUNNING' -or $st -ceq 'PENDING'))
        foreach ($d in @(Compare-AtmRecoverCapture -Before $Recorded -After $now)) {
            if (-not ($natural -and $script:AtmRecoveryUndoPartialTransition -ccontains [string]$d.field)) { $fields.Add([string]$d.field) }
        }
        if ($pendingSource -and $st -ceq 'PENDING') { $codes.Add('UNDO_STILL_PENDING') }
        elseif ($st -cne 'RUNNING') { $codes.Add('UNDO_NOT_RUNNING') }
        elseif ([string]$now.AcceptStop -cne 'TRUE') { $codes.Add('UNDO_ACCEPT_STOP_FALSE') }
        foreach ($label in @($now.Dependents)) { if ((Split-AtmRecoverDependencyLabel $label).State -cne 'STOPPED') { $codes.Add('UNDO_DEPENDENT_ACTIVE'); break } }
        if ($fields.Count -gt 0) { $codes.Add('UNDO_STATE_CHANGED') }
    }
    return [pscustomobject]@{ Codes = @(Get-AtmSortedCodes $codes); ChangedFields = $fields.ToArray() }
}

function Get-AtmRecoverUndoPlanId {
    # The undo's plan id: SHA-256 of its own prefix and, in a fixed order, the operation, the target, the source run id
    # and every field of the current capture, each value length-prefixed ($null distinct from empty), each list with its
    # count (the encoding of Get-AtmRecoverPlanId).
    param([string]$Target, [string]$SourceRunId, $Capture)
    $parts = New-Object System.Collections.Generic.List[object]
    $parts.Add($script:AtmRecoveryUndoPlanSchema); $parts.Add($script:AtmRecoveryUndoOperation.Id); $parts.Add($Target); $parts.Add($SourceRunId)
    foreach ($k in @('State', 'StartMode', 'DelayedAutoStart', 'ExitCode', 'ServiceSpecificExitCode', 'CheckPoint', 'WaitHint', 'AcceptStop', 'Condition', 'AccountKind', 'Account', 'Executable', 'ExecutableForm', 'Image')) { $parts.Add($Capture.$k) }
    foreach ($k in @('DependsOn', 'Dependents')) { $list = @($Capture.$k); $parts.Add([string]$list.Count); foreach ($x in $list) { $parts.Add($x) } }
    $text = -join @($parts | ForEach-Object { if ($null -eq $_) { '~;' } else { $s = [string]$_; '{0}:{1};' -f $s.Length, $s } })
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)) } finally { $sha.Dispose() }
    return (-join @($hash | ForEach-Object { $_.ToString('x2') }))
}

function Get-AtmRecoverUndoPlan {
    <#
      The inverse plan of one source run (Read-AtmRecoverRunLog) on a collection: REC-SVC-STOP for its target, the source
      run id and outcome, the recorded "after", the current capture, the fields a PARTIAL run's continuation may change,
      what the undo does not undo, the likely elevation and the plan id. Refused: the source's code, or the codes and
      changed fields of Get-AtmRecoverUndoRefusals (no plan id). Read only; Changed is always $false.
    #>
    param($Collection, $Source)
    $op = $script:AtmRecoveryUndoOperation
    $out = [ordered]@{
        Operation = $op; UndoOf = $op.UndoOf; Target = $Source.Target; SourceRunId = $Source.RunId; SourceOutcome = $Source.Outcome; SourceCode = $Source.Code
        Declared = $false; Provider = $null; Providers = @(); Offered = $false; Codes = @(); ChangedFields = @(); Recorded = $Source.After; SourceBefore = $Source.Before
        Capture = $null; PlanId = $null; Elevation = $(if ($null -ne $Collection) { $Collection.Elevation } else { $null }); NotUndone = @($op.NotUndone); AcceptedTransition = @()
        GateOpen = [bool]$script:AtmRecoveryEnabled; Changed = $false
    }
    if ($null -ne $Source.Code) { $out.Codes = @($Source.Code); return [pscustomobject]$out }
    $r = Get-AtmRecoverUndoRefusals -Collection $Collection -Name $Source.Target -Recorded $Source.After -SourceOutcome $Source.Outcome
    $out.Codes = @($r.Codes); $out.ChangedFields = @($r.ChangedFields); $out.Offered = (@($r.Codes).Count -eq 0)
    if (Test-AtmRecoverUndoPendingSource -SourceOutcome $Source.Outcome -Recorded $Source.After) { $out.AcceptedTransition = @($script:AtmRecoveryUndoPartialTransition) }
    $out.Declared = (@($Collection.DeclaredNames) -ccontains $Source.Target)
    if ($out.Declared) {
        $d = $Collection.DeclaredByName[$Source.Target]
        $out.Provider = $Collection.FindingsByName[$Source.Target].Provider
        $out.Providers = @(@($d.Providers) | ForEach-Object { if ($_.Role) { $_.Id + ':' + $_.Role } else { $_.Id } })
        if ($out.Offered) {
            $cap = Get-AtmRecoverCapture -Collection $Collection -Name $Source.Target
            $out.Capture = $cap
            $out.PlanId = Get-AtmRecoverUndoPlanId -Target $Source.Target -SourceRunId $Source.RunId -Capture $cap
        }
    }
    return [pscustomobject]$out
}

function Invoke-AtmRecoverServiceStopDefault {
    <#
      The default stop seam: stops one service, by name, and nothing else (AtmServiceStop in Native.cs). The service
      control manager is opened with connect access only, the service with the stop right only (SERVICE_STOP), and
      SERVICE_CONTROL_STOP is sent once. Its dependent services are never enumerated, opened or stopped: a running
      dependent makes the stop fail (DEPENDENT_SERVICES_RUNNING), never a cascade. Returns a closed code of
      AtmRecoveryStopSeamCodes, mapped by Win32 number. Called only by Invoke-AtmRecoverUndoLocked, past the recovery
      gate, when no -ServiceStopImpl is given; the suite never reaches it.
    #>
    param([string]$Name)
    Initialize-AtmNative
    $n = [int][AgentTempManager.AtmServiceStop]::Stop($Name)
    if ($n -eq 0) { return 'OK' }
    if ($script:AtmRecoveryStopWin32Codes.ContainsKey($n)) { return $script:AtmRecoveryStopWin32Codes[$n] }
    return 'SERVICE_WIN32_OTHER'
}

function Invoke-AtmRecoverUndo {
    <#
      The undo of ONE REC-SVC-START run (ADR-0016 sections 3, 4 and 6): REC-SVC-STOP for its one service, with no list
      or batch form. -SourceLog is the run's log, -RunId its run id (a cross-check: the log must carry it). Every
      collection is fresh and made in this process (the test overrides as Invoke-AtmRecover).
      Gate closed (every copy): the source read, the collection, the inverse plan and the presenter, then
      RECUPERACAO_REAL_DESABILITADA. Nothing is asked, locked or logged, no inventory is read and no seam is called.
      Past the gate (the suite only), the steps of Invoke-AtmRecover in the same order:
        1. an interactive console observed by the engine (CONSOLE_NOT_OBSERVED), then a confirmation reader;
        2. a NEW -LogFile, not the -SourceLog, outside every audited base (LOG_REQUIRED, LOG_SAME_AS_SOURCE,
           LOG_DESTINATION_NOT_ALLOWED, LOG_ALREADY_EXISTS);
        3. the source read (UNDO_SOURCE_REFUSED, the code in RefusalCodes), a fresh collection and the undo's criteria
           (UNDO_REFUSED, with the codes and ChangedFields): any refusal stops before anything is asked;
        4. the inverse plan through the mandatory -PlanPresenter;
        5. to 11. under the lock B8 (CLEAN_LOCK_<status> starts nothing): Invoke-AtmRecoverUndoLocked.
      -ServiceStopImpl: test seam, scriptblock(name) returning a code of AtmRecoveryStopSeamCodes; without it the default
      stop seam runs. -SettleWait and -NewRunId as Invoke-AtmRecover. Aborted: the seam was never called; StoppedBy: a
      failure after it; Outcome: what the stop gave.
    #>
    [CmdletBinding()]
    param(
        [string]$SourceLog,
        [string]$RunId,
        [scriptblock]$PlanPresenter,
        [scriptblock]$ConfirmationReader,
        [hashtable]$InventoryArgs = @{},
        [string]$LogFile,
        [hashtable]$Interaction = @{},
        $Providers = $null,
        [scriptblock]$IdentitySource = $null,
        [scriptblock]$ServiceSource = $null,
        [scriptblock]$ServiceDependencySource = $null,
        [scriptblock]$ServiceWait = $null,
        [int]$DeadlineSeconds = $script:AtmRecoveryDeadlineSeconds,
        [scriptblock]$ServiceStopImpl,
        [scriptblock]$SettleWait,
        [string]$NewRunId
    )
    $logErrors = New-Object System.Collections.Generic.List[object]
    $res = [ordered]@{
        Operation = $script:AtmRecoveryUndoOperation.Id; Target = $null; SourceRunId = $RunId; SourceOutcome = $null; GateOpen = [bool]$script:AtmRecoveryEnabled; Plan = $null; PlanId = $null; Phrase = $null
        Aborted = $null; RefusalCodes = @(); ConfirmationCode = $null; RevalidationCodes = @(); ChangedFields = @(); StoppedBy = $null
        SeamCalled = $false; SeamCode = $null; ExceptionType = $null; Outcome = $null; WaitedMs = 0; Reads = 0
        Before = $null; After = $null; Diff = @(); Changed = $false
        RunId = $null; LogFile = $null; LogCreated = $false; LogErrors = @(); LockReleaseError = $null
    }
    $done = { $res.LogErrors = $logErrors.ToArray(); $res.Changed = (@($res.Diff).Count -gt 0); [pscustomobject]$res }
    if (-not $PlanPresenter) { $res.Aborted = 'SEM_APRESENTACAO'; return (& $done) }
    if ($NewRunId -and -not (Test-AtmRecoverRunIdForm $NewRunId)) { $res.Aborted = 'RUN_ID_INVALID'; return (& $done) }
    $collArgs = @{ Providers = $Providers; IdentitySource = $IdentitySource; ServiceSource = $ServiceSource; ServiceDependencySource = $ServiceDependencySource; ServiceWait = $ServiceWait; DeadlineSeconds = $DeadlineSeconds }
    $plan = $null
    $build = {
        $src = Read-AtmRecoverRunLog -Path $SourceLog -RunId $RunId
        $coll = $(if ($null -eq $src.Code) { Get-AtmRecoverCollection @collArgs } else { $null })
        $p = Get-AtmRecoverUndoPlan -Collection $coll -Source $src
        $res.Plan = $p; $res.PlanId = $p.PlanId; $res.Target = $p.Target; $res.SourceOutcome = $p.SourceOutcome; $res.RefusalCodes = @($p.Codes); $res.ChangedFields = @($p.ChangedFields); $res.Before = $p.Capture
        return [pscustomobject]@{ Plan = $p; Collection = $coll }
    }
    if (-not $script:AtmRecoveryEnabled) {
        $b = & $build
        & $PlanPresenter $b.Plan
        $res.Aborted = 'RECUPERACAO_REAL_DESABILITADA'
        return (& $done)
    }

    # ---- past the recovery gate (the suite only, in its own process) ----
    $console = Get-AtmEngineConsoleObservation
    if (-not $console.Observed) { $res.Aborted = 'CONSOLE_NOT_OBSERVED'; return (& $done) }
    if (-not $ConfirmationReader) { $res.Aborted = 'SEM_APRESENTACAO_OU_CONFIRMACAO'; return (& $done) }
    if (-not $LogFile) { $res.Aborted = 'LOG_REQUIRED'; return (& $done) }
    $same = $false
    if ($SourceLog) { try { $same = [string]::Equals([IO.Path]::GetFullPath($LogFile), [IO.Path]::GetFullPath($SourceLog), [StringComparison]::OrdinalIgnoreCase) } catch { $same = $false } }
    if ($same) { $res.Aborted = 'LOG_SAME_AS_SOURCE'; return (& $done) }
    $ia = @{} + $InventoryArgs; $ia['NoProgress'] = $true
    $inv = Invoke-AtmInventory @ia
    if (-not (Test-AtmOutputPathOutsideBases -Path $LogFile -Inventory $inv)) { $res.Aborted = 'LOG_DESTINATION_NOT_ALLOWED'; return (& $done) }
    if (Test-Path -LiteralPath $LogFile) { $res.Aborted = 'LOG_ALREADY_EXISTS'; return (& $done) }
    $b = & $build
    $plan = $b.Plan
    if ($null -ne $plan.SourceCode) { $res.Aborted = 'UNDO_SOURCE_REFUSED'; return (& $done) }
    if (-not $plan.Offered) { $res.Aborted = 'UNDO_REFUSED'; return (& $done) }
    & $PlanPresenter $plan
    # No closure: the body runs in this session state, where the engine's functions are, and finds $undoBound here.
    $undoBound = @{ Res = $res; LogErrors = $logErrors; Collection = $b.Collection; Plan = $plan; Inventory = $inv; CollectionArgs = $collArgs; LogFile = $LogFile
        ConfirmationReader = $ConfirmationReader; Interaction = $Interaction; Console = $console; ServiceStopImpl = $ServiceStopImpl; SettleWait = $SettleWait; NewRunId = $NewRunId }
    $u = Invoke-AtmUnderSharedLock -Body { Invoke-AtmRecoverUndoLocked @undoBound }
    if (-not $u.Acquired) { $res.Aborted = 'CLEAN_LOCK_' + $u.Status; $res.LockReleaseError = $u.ReleaseError; return (& $done) }
    # A failed release never replaces the main code; with none it makes the run incomplete.
    if ($null -ne $u.ReleaseError) {
        $res.LockReleaseError = $u.ReleaseError
        if (-not $res.Aborted -and -not $res.StoppedBy) { if ($res.SeamCalled) { $res.StoppedBy = 'LOCK_RELEASE_FAILED' } else { $res.Aborted = 'LOCK_RELEASE_FAILED' } }
    }
    return (& $done)
}

function Invoke-AtmRecoverUndoLocked {
    <#
      Steps 5 to 11 of Invoke-AtmRecoverUndo, called only by it, past the recovery gate and under the lock B8; fills -Res.
        5. the log (Open-AtmCleanLog), then run-start (with the source run id), plan and before (the current capture);
        6. the typed phrase PARAR SERVICO <the first 8 characters of the plan id, upper case>, compared exactly
           (Test-AtmTypedPhrase); confirmation. Anything else: CONFIRMACAO_AUSENTE_OU_DIVERGENTE;
        7. the revalidation on a fresh collection: the undo's criteria again (reasons) and the fields changed since the
           presented capture, its providers, the token's identity and its elevation (Get-AtmRecoverPlanCheck's
           ChangedFields); plan-check. Any reason or changed field: REVALIDATION_REFUSED;
        8. intent, flushed, then the stop seam, with the service name and nothing else;
        9. the settle wait, after OK only: until STOPPED, back to RUNNING after a read that was not RUNNING, or the
           limit (as Invoke-AtmRecoverLocked's);
       10. result and after; 11. run-end, the log closed, the lock released by the caller.
      Outcomes: EXCEPTION (the seam threw, or gave no closed code); REFUSED (ACCESS_DENIED); FAILED (another seam code,
      with no wait, or RUNNING at the end); COMPLETE (STOPPED); PARTIAL (anything else). "After" is read and the diff
      computed in every outcome. Nothing is compensated or retried: a failed undo starts nothing again.
    #>
    param([System.Collections.IDictionary]$Res, $LogErrors, $Collection, $Plan, $Inventory, [hashtable]$CollectionArgs, [string]$LogFile, [scriptblock]$ConfirmationReader,
        [hashtable]$Interaction = @{}, $Console, [scriptblock]$ServiceStopImpl, [scriptblock]$SettleWait, [string]$NewRunId)
    $service = [string]$Plan.Target
    $op = $Plan.Operation
    $logFail = { param([string]$Stage, [string]$Code) $LogErrors.Add([pscustomobject]@{ Stage = $Stage; Code = $Code }) }
    $halt = { param([string]$Code) if (-not $Res.Aborted -and -not $Res.StoppedBy) { if ($Res.SeamCalled) { $Res.StoppedBy = $Code } else { $Res.Aborted = $Code } } }
    $me = Get-AtmCurrentIdentity
    # R4: the CLI generates the run id once and names the log after it; any other caller gets a new one here.
    $runId = $(if ($NewRunId) { $NewRunId } else { [guid]::NewGuid().ToString() })
    $Res.RunId = $runId; $Res.LogFile = $LogFile
    $Res.Phrase = 'PARAR SERVICO ' + ([string]$Plan.PlanId).Substring(0, 8).ToUpperInvariant()
    $ls = @{ Id = $runId; Seq = 0 }
    $log = $null
    try {
        $opened = Open-AtmCleanLog -Path $LogFile -Inventory $Inventory -ProcessUserSid $me.Sid
        $Res.LogCreated = [bool]$opened.Created
        if ($null -eq $opened.Log) { & $logFail 'open' $opened.Code; $Res.Aborted = 'LOG_OPEN_FAILED'; return }
        $log = $opened.Log
        $lc = Write-AtmRecoverRecord -Log $log -State $ls -Type 'run-start' -Fields ([ordered]@{ tool = $script:AtmVersion; operation = $op.Id; undoOf = $op.UndoOf; target = $service; planId = $Plan.PlanId
                sourceRunId = $Plan.SourceRunId; sourceOutcome = $Plan.SourceOutcome; elevation = $Collection.Elevation; elevationType = [string]$Collection.Identity.ElevationType; gateOpen = $true })
        if ($null -eq $lc) {
            $lc = Write-AtmRecoverRecord -Log $log -State $ls -Type 'plan' -Fields ([ordered]@{ operation = $op.Id; undoOf = $op.UndoOf; target = $service; provider = $Plan.Provider; providers = [string[]]@($Plan.Providers)
                    sourceRunId = $Plan.SourceRunId; sourceOutcome = $Plan.SourceOutcome; acceptedTransition = [string[]]@($Plan.AcceptedTransition); notUndone = [string[]]@($Plan.NotUndone); planId = $Plan.PlanId })
        }
        if ($null -eq $lc) { $lc = Write-AtmRecoverRecord -Log $log -State $ls -Type 'before' -Fields (ConvertTo-AtmRecoverCaptureRecord $Plan.Capture) }
        if ($null -ne $lc) { & $logFail 'plan' $lc; $Res.Aborted = 'LOG_WRITE_FAILED'; return }

        # Step 6: the typed phrase, bound to the plan id.
        $callerName = [string]$Interaction['Caller']
        $interactionRec = [ordered]@{ caller = $(if ($callerName -ceq 'CLI' -or $callerName -ceq 'TUI') { $callerName } else { 'DIRECT_CALL' }); consoleRequiredByCaller = ($Interaction['ConsoleRequired'] -eq $true)
            callerFieldsVerified = $false; interactiveConsoleObserved = $true; observedBy = $Console.By; identifiesRespondent = $false }
        $tp = Test-AtmTypedPhrase -Typed (& $ConfirmationReader $Res.Phrase 'confirm' $null @($Res.Phrase)) -Phrases @($Res.Phrase)
        if ($tp.Code) {
            $Res.ConfirmationCode = $tp.Code
            $lc = Write-AtmRecoverRecord -Log $log -State $ls -Type 'confirmation' -Fields ([ordered]@{ accepted = $false; planId = $Plan.PlanId; refusal = 'CONFIRMACAO_AUSENTE_OU_DIVERGENTE'; reason = $tp.Code; interaction = $interactionRec })
            if ($null -ne $lc) { & $logFail 'confirmation' $lc }
            $Res.Aborted = 'CONFIRMACAO_AUSENTE_OU_DIVERGENTE'
        } else {
            $lc = Write-AtmRecoverRecord -Log $log -State $ls -Type 'confirmation' -Fields ([ordered]@{ accepted = $true; planId = $Plan.PlanId; interaction = $interactionRec })
            if ($null -ne $lc) { & $logFail 'confirmation' $lc; $Res.Aborted = 'LOG_WRITE_FAILED' }
        }

        # Step 7: the revalidation, immediately before acting.
        if (-not $Res.Aborted) {
            $fresh = Get-AtmRecoverCollection @CollectionArgs
            $again = Get-AtmRecoverUndoRefusals -Collection $fresh -Name $service -Recorded $Plan.Recorded -SourceOutcome $Plan.SourceOutcome
            $chk = Get-AtmRecoverPlanCheck -Plan $Plan -Collection $Collection -Fresh $fresh -Service $service
            $Res.RevalidationCodes = @($again.Codes); $Res.ChangedFields = @($chk.ChangedFields)
            $matched = (@($again.Codes).Count -eq 0 -and @($chk.ChangedFields).Count -eq 0)
            $lc = Write-AtmRecoverRecord -Log $log -State $ls -Type 'plan-check' -Fields ([ordered]@{ planId = $Plan.PlanId; matched = $matched; reasons = [string[]]@($again.Codes); changedFields = [string[]]@($chk.ChangedFields) })
            if ($null -ne $lc) { & $logFail 'plan-check' $lc; $Res.Aborted = 'LOG_WRITE_FAILED' }
            elseif (-not $matched) { $Res.Aborted = 'REVALIDATION_REFUSED' }
        }

        # Step 8: the intent, written and flushed BEFORE the stop seam; without it, no call.
        if (-not $Res.Aborted) {
            $lc = Write-AtmRecoverRecord -Log $log -State $ls -Type 'intent' -Fields ([ordered]@{ operation = $op.Id; target = $service; planId = $Plan.PlanId; sourceRunId = $Plan.SourceRunId; seam = $(if ($ServiceStopImpl) { 'TEST_SEAM' } else { 'DEFAULT' }) })
            if ($null -ne $lc) { & $logFail 'intent' $lc; $Res.Aborted = 'LOG_INTENT_FAILED' }
        }
        if (-not $Res.Aborted) {
            # The only call to the stop seam: the service name and nothing else.
            $Res.SeamCalled = $true
            $code = $null; $exType = $null
            try {
                if ($ServiceStopImpl) { $code = & $ServiceStopImpl $service } else { $code = Invoke-AtmRecoverServiceStopDefault -Name $service }
            } catch { $code = $null; $exType = $_.Exception.GetBaseException().GetType().Name }
            if ($null -eq $exType -and (-not ($code -is [string]) -or $script:AtmRecoveryStopSeamCodes -cnotcontains $code)) { $code = $null; $exType = 'SEAM_RESULT_INVALID' }
            $Res.SeamCode = $code; $Res.ExceptionType = $exType

            # Step 9: the settle wait, bounded (after OK only). RUNNING ends it only after a read that was not RUNNING.
            $last = $null
            $limit = $script:AtmRecoverySettleMinMs
            if ($code -ceq 'OK') {
                $clock = [Diagnostics.Stopwatch]::StartNew()
                $left = $false
                while ($true) {
                    $last = Get-AtmRecoverCollection @CollectionArgs
                    $Res.Reads = $Res.Reads + 1
                    $cap = $(if ($last.FindingsByName.ContainsKey($service)) { Get-AtmRecoverCapture -Collection $last -Name $service } else { $null })
                    $st = $(if ($null -ne $cap) { [string]$cap.State } else { '' })
                    $wh = 0
                    if ($null -ne $cap -and [int]::TryParse([string]$cap.WaitHint, [ref]$wh) -and $wh -gt $limit) { $limit = [Math]::Min($wh, $script:AtmRecoverySettleCapMs) }
                    if ($st -ceq 'STOPPED') { break }
                    if ($st -ceq 'RUNNING') { if ($left) { break } } else { $left = $true }
                    if ($Res.WaitedMs -ge $limit -or $clock.ElapsedMilliseconds -ge $limit) { break }
                    if ($SettleWait) { & $SettleWait $script:AtmRecoverySettlePollMs } else { Wait-AtmRecoverSettle -Milliseconds $script:AtmRecoverySettlePollMs }
                    $Res.WaitedMs = $Res.WaitedMs + $script:AtmRecoverySettlePollMs
                }
            }
            # Step 10: "after", read again in every outcome.
            if ($null -eq $last) { $last = Get-AtmRecoverCollection @CollectionArgs; $Res.Reads = $Res.Reads + 1 }
            $after = $(if ($last.FindingsByName.ContainsKey($service)) { Get-AtmRecoverCapture -Collection $last -Name $service } else { $null })
            $Res.After = $after
            $afterState = $(if ($null -ne $after) { [string]$after.State } else { '' })
            $Res.Outcome = $(if ($null -ne $exType) { 'EXCEPTION' } elseif ($code -ceq 'ACCESS_DENIED') { 'REFUSED' } elseif ($code -cne 'OK') { 'FAILED' }
                elseif ($afterState -ceq 'STOPPED') { 'COMPLETE' } elseif ($afterState -ceq 'RUNNING') { 'FAILED' } else { 'PARTIAL' })
            $Res.Diff = @(Compare-AtmRecoverCapture -Before $Plan.Capture -After $after)
            $lc = Write-AtmRecoverRecord -Log $log -State $ls -Type 'result' -Fields ([ordered]@{ operation = $op.Id; target = $service; outcome = $Res.Outcome; seamCode = $code; exceptionType = $exType
                    waitedMs = $Res.WaitedMs; limitMs = $limit; reads = $Res.Reads; exitCode = $(if ($null -ne $after) { $after.ExitCode } else { $null }); serviceSpecificExitCode = $(if ($null -ne $after) { $after.ServiceSpecificExitCode } else { $null })
                    diff = @($Res.Diff) })
            if ($null -ne $lc) { & $logFail 'result' $lc; & $halt 'LOG_RESULT_FAILED' }
            else {
                $lc = Write-AtmRecoverRecord -Log $log -State $ls -Type 'after' -Fields (ConvertTo-AtmRecoverCaptureRecord $after)
                if ($null -ne $lc) { & $logFail 'after' $lc; & $halt 'LOG_AFTER_FAILED' }
            }
        }

        # Step 11: run-end only while the log has not failed; neither a failed run-end nor a failed close replaces the
        # main code.
        if ($LogErrors.Count -eq 0) {
            $lc = Write-AtmRecoverRecord -Log $log -State $ls -Type 'run-end' -Fields ([ordered]@{ outcome = $Res.Outcome; stoppedBy = $(if ($Res.StoppedBy) { $Res.StoppedBy } else { $Res.Aborted }); seamCalled = [bool]$Res.SeamCalled
                    changedFields = @($Res.Diff).Count })
            if ($null -ne $lc) { & $logFail 'run-end' $lc; & $halt 'LOG_END_FAILED' }
        }
        $cc = $log.Close()
        if ($null -ne $cc) { & $logFail 'close' $cc; & $halt 'LOG_CLOSE_FAILED' }
    } finally {
        if ($null -ne $log) { try { $log.Dispose() } catch { $null = $_ } }
    }
}

# ---------------------------------------------------------------------------------------------
# Phase R4 (ADR-0016 section 3, alternative (b), V04-D3 (b)): the CLI verbs recover start and recover undo, one operation
# per process, and the elevation on demand through UAC. Invoke-AtmRecoverCommand is their only entry, called by the
# launcher once per process. Gate closed (every copy): the plan, or the inverse plan read from the fixed folder, then
# RECUPERACAO_REAL_DESABILITADA: no elevation is requested and nothing is asked, locked or logged. Past the gate (the
# suite only): an elevated administrator token runs the engine in this process (the manual model (a)); any other token
# relaunches the installed launcher once, elevated, with fixed arguments (the verb, the operation and the name or the run
# id, and the marker), through the elevated launcher seam, and reports only by that copy's exit code: it reads no log and
# receives no path. The elevated copy trusts nothing from its requester: its own launcher checked the installation, and
# it collects, applies the criteria, shows the plan, asks for the phrase in its own console, takes the lock, logs and
# revalidates again, does one operation and exits. Its logs live in a fixed machine folder that only the installer
# creates; it refuses that folder when it differs, and never creates or fixes it.
# ---------------------------------------------------------------------------------------------
# The exit codes of the two verbs (ADR-0016, R4 implementation record; docs/USAGE.md). The requester relays an exit code
# of the elevated copy that is in AtmRecoverRelayedExitCodes as its own; any other is ELEVATED_EXIT_UNKNOWN.
$script:AtmRecoverExitCodes = [ordered]@{
    USAGE = 2; PLAN_REFUSED = 3; INTEGRITY = 5; UNEXPECTED = 10
    COMPLETE = 20; PARTIAL = 21; FAILED = 22; REFUSED = 23; EXCEPTION = 24; STOPPED_BEFORE_SEAM = 25; STOPPED_AFTER_SEAM = 26
    GATE_CLOSED = 27; LOG_DIR_REFUSED = 28; ELEVATED_REFUSED = 29; SECOND_OPERATION = 30; NOT_INSTALLED = 31
    UAC_ERROR_1223 = 40; UAC_WIN32_ERROR = 41; UAC_LAUNCHER_EXCEPTION = 42; UAC_NOT_STARTED = 43; ELEVATED_EXIT_UNKNOWN = 44
}
$script:AtmRecoverRelayedExitCodes = @(2, 3, 5, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31)
$script:AtmRecoverOutcomeExitCodes = @{ COMPLETE = 20; PARTIAL = 21; FAILED = 22; REFUSED = 23; EXCEPTION = 24 }
# The engine's refusals before anything is asked (exit PLAN_REFUSED).
$script:AtmRecoverPlanRefusals = @('RECOVERY_REFUSED', 'UNDO_REFUSED', 'UNDO_SOURCE_REFUSED')
$script:AtmRecoverLogDirCodes = @('RECOVER_LOG_DIR_MISSING', 'RECOVER_LOG_DIR_REPARSE', 'RECOVER_LOG_DIR_OWNER', 'RECOVER_LOG_DIR_DACL', 'RECOVER_LOG_DIR_UNREADABLE')
$script:AtmRecoverRequesterStatuses = @('UNVERIFIED', 'SAME', 'DIFFERENT', 'UNREADABLE')
# The only parameters a relaunched copy accepts, as its launcher bound them (the marker included); anything else is
# ELEVATED_REFUSED. -Lang, -DeadlineSeconds, -NoProgress and -Ascii are never relayed.
$script:AtmRecoverElevatedArguments = @{ start = @('Command', 'SubCommand', 'Operation', 'Service', 'AtmElevatedRecovery'); undo = @('Command', 'SubCommand', 'RunId', 'AtmElevatedRecovery') }
# One operation past the gate per process (PRIV-9): set on entry, before any work; never cleared by the engine.
$script:AtmRecoverOperationTaken = $false

function Test-AtmRecoverRunIdForm {
    # A run id as the engine writes it: a GUID in the lower-case D form, exactly (the undo compares it ordinally).
    param([string]$Value)
    $g = [guid]::Empty
    return ([guid]::TryParseExact([string]$Value, 'D', [ref]$g) -and $g.ToString() -ceq $Value)
}

function Get-AtmRecoverLogDir {
    <#
      The fixed folder of the CLI's recovery logs, <CommonApplicationData>\AgentTempManager\recover, and its parent.
      -Base: test seam in place of the machine's CommonApplicationData folder; the launcher never passes it.
    #>
    param([string]$Base)
    $root = $(if ($Base) { $Base } else { [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData) })
    $parent = [IO.Path]::Combine([string]$root, 'AgentTempManager')
    return [pscustomobject]@{ Parent = $parent; Dir = [IO.Path]::Combine($parent, 'recover') }
}

function Test-AtmRecoverLogDirSecurity {
    <#
      The owner and DACL the installer gives the fixed folder and its parent: owned by Administrators, a protected DACL,
      access allowed to SYSTEM and Administrators only, each with full control on the folder itself (nothing for Users or
      anyone else). Deny entries only take rights away. Returns $null, RECOVER_LOG_DIR_OWNER or RECOVER_LOG_DIR_DACL.
    #>
    param($Security)
    $owner = $Security.GetOwner([Security.Principal.SecurityIdentifier])
    if ($null -eq $owner -or $owner.Value -cne 'S-1-5-32-544') { return 'RECOVER_LOG_DIR_OWNER' }
    if (-not $Security.AreAccessRulesProtected) { return 'RECOVER_LOG_DIR_DACL' }
    $fc = [Security.AccessControl.FileSystemRights]::FullControl
    $full = @{}
    foreach ($r in @($Security.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))) {
        if ($r.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        $sid = $r.IdentityReference.Value
        if ($sid -cne 'S-1-5-18' -and $sid -cne 'S-1-5-32-544') { return 'RECOVER_LOG_DIR_DACL' }
        if (($r.FileSystemRights -band $fc) -eq $fc -and ($r.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0) { $full[$sid] = $true }
    }
    if (-not $full.ContainsKey('S-1-5-18') -or -not $full.ContainsKey('S-1-5-32-544')) { return 'RECOVER_LOG_DIR_DACL' }
    return $null
}

function Test-AtmRecoverLogDir {
    <#
      The fixed folder, checked before every use by the copy that acts (and, read only, before the inverse plan with the
      gate closed): its parent, then the folder, each on a fixed local drive with no reparse point in its path (AtmPathCheck),
      a directory, and Test-AtmRecoverLogDirSecurity on its security descriptor. Never creates, changes or fixes anything:
      that is the installer's (Install-AgentTempManager.ps1). Returns Code ($null or one of AtmRecoverLogDirCodes), Dir
      and Parent. -Base as Get-AtmRecoverLogDir.
    #>
    param([string]$Base)
    $d = Get-AtmRecoverLogDir -Base $Base
    $out = [ordered]@{ Code = $null; Dir = $d.Dir; Parent = $d.Parent }
    try {
        Initialize-AtmNative
        foreach ($p in @($d.Parent, $d.Dir)) {
            $at = $null
            $chain = [AgentTempManager.AtmPathCheck]::Chain($p, [ref]$at)
            if ($chain -ceq 'NOT_FOUND') { $out.Code = 'RECOVER_LOG_DIR_MISSING'; break }
            if ($chain -ceq 'REPARSE_IN_PATH') { $out.Code = 'RECOVER_LOG_DIR_REPARSE'; break }
            if ($chain -cne 'OK') { $out.Code = 'RECOVER_LOG_DIR_UNREADABLE'; break }
            $di = New-Object IO.DirectoryInfo($p)
            if (-not $di.Exists) { $out.Code = 'RECOVER_LOG_DIR_MISSING'; break }
            $sec = $(if ($null -ne ('System.IO.FileSystemAclExtensions' -as [type])) { [System.IO.FileSystemAclExtensions]::GetAccessControl($di) } else { $di.GetAccessControl() })
            $code = Test-AtmRecoverLogDirSecurity -Security $sec
            if ($null -ne $code) { $out.Code = $code; break }
        }
    } catch { $out.Code = 'RECOVER_LOG_DIR_UNREADABLE' }
    return [pscustomobject]$out
}

function Get-AtmRecoverActingIdentity {
    # PRIV-5: the identity of this process's own token, the only one that acts and decides (-Source as Get-AtmIdentityState).
    param([scriptblock]$Source)
    return (Get-AtmIdentityState -Source $Source)
}

function Get-AtmRecoverRequesterEvidence {
    <#
      PRIV-5: what a relaunched copy knows of who requested it. The default reads nothing and answers UNVERIFIED: the
      elevated copy cannot verify its requester (ADR-0016, R4 record: a parent process id can be forged or reused, and
      reading another process's token would need a process handle that src never opens). -Source: test seam returning an
      object with Status (one of AtmRecoverRequesterStatuses) and, for DIFFERENT, Name; anything else, or a throw, is
      UNREADABLE. Whatever it says, decisions use the acting identity only, and any other profile is another user's.
    #>
    param([scriptblock]$Source)
    if (-not $Source) { return [pscustomobject]@{ Status = 'UNVERIFIED'; Name = $null } }
    $e = $null
    try { $e = & $Source } catch { return [pscustomobject]@{ Status = 'UNREADABLE'; Name = $null } }
    $names = $(if ($null -ne $e) { @($e.PSObject.Properties.Name) } else { @() })
    $st = $(if ($names -ccontains 'Status') { [string]$e.Status } else { '' })
    if ($script:AtmRecoverRequesterStatuses -cnotcontains $st) { return [pscustomobject]@{ Status = 'UNREADABLE'; Name = $null } }
    return [pscustomobject]@{ Status = $st; Name = $(if ($st -ceq 'DIFFERENT' -and $names -ccontains 'Name') { [string]$e.Name } else { $null }) }
}

function Invoke-AtmRecoverElevatedLaunchDefault {
    <#
      The default elevated launcher (PRIV-4, PRIV-7): ShellExecuteEx with the elevation verb, which shows the UAC prompt,
      for Windows PowerShell by its absolute path (-FilePath, an .exe: no file association) running the installed
      agent-temp.ps1 with the fixed arguments (SR-03); waits for that process and reads its exit code.
      Returns Started, ExitCode and Win32Error: a refused, cancelled or failed request gives the Win32 error of the failed
      start; no process at all gives Started false with none. Called only by Invoke-AtmRecoverCommand, past the recovery
      gate, when no -ElevatedLauncherImpl is given: the suite and the CI never reach it.
    #>
    param([string]$FilePath, [string]$Arguments)
    $psi = New-Object Diagnostics.ProcessStartInfo($FilePath, $Arguments)
    $psi.UseShellExecute = $true
    $psi.Verb = 'runas'
    $p = $null
    try { $p = [Diagnostics.Process]::Start($psi) }
    catch {
        $b = $_.Exception.GetBaseException()
        if ($b -is [ComponentModel.Win32Exception]) { return [pscustomobject]@{ Started = $false; ExitCode = $null; Win32Error = [int]$b.NativeErrorCode } }
        throw
    }
    if ($null -eq $p) { return [pscustomobject]@{ Started = $false; ExitCode = $null; Win32Error = $null } }
    try {
        $p.WaitForExit()
        $code = $null
        try { $code = [int]$p.ExitCode } catch { $code = $null }
        return [pscustomobject]@{ Started = $true; ExitCode = $code; Win32Error = $null }
    } finally { $p.Dispose() }
}

function Get-AtmRecoverLaunchExitCode {
    <#
      PRIV-4: the requester's exit code from what the elevated launcher gave, never a reason guessed from one number.
      Not started: with Win32 error 1223 (UAC_ERROR_1223: usually a cancelled prompt, not proof), with another error
      (UAC_WIN32_ERROR), with none (UAC_NOT_STARTED); a launcher exception or an unreadable result
      (UAC_LAUNCHER_EXCEPTION). In these four no elevated copy ran. Started: an exit code in AtmRecoverRelayedExitCodes is
      relayed as is; any other, or none (a crash, a closed window, a run that ended without its result), is
      ELEVATED_EXIT_UNKNOWN: that copy may have acted before it ended.
    #>
    param($Launch, [string]$ExceptionType)
    $r = { param([int]$E, [string]$C, $D, [bool]$Rel) [pscustomobject]@{ ExitCode = $E; Code = $C; Detail = $D; Relayed = $Rel } }
    if ($ExceptionType) { return (& $r 42 'UAC_LAUNCHER_EXCEPTION' $ExceptionType $false) }
    $names = $(if ($null -ne $Launch) { @($Launch.PSObject.Properties.Name) } else { @() })
    if ($names -cnotcontains 'Started' -or -not ($Launch.Started -is [bool])) { return (& $r 42 'UAC_LAUNCHER_EXCEPTION' 'LAUNCHER_RESULT_INVALID' $false) }
    $w32 = $(if ($names -ccontains 'Win32Error') { $Launch.Win32Error } else { $null })
    $ec = $(if ($names -ccontains 'ExitCode') { $Launch.ExitCode } else { $null })
    if (-not $Launch.Started) {
        if ($null -eq $w32) { return (& $r 43 'UAC_NOT_STARTED' $null $false) }
        if (-not ($w32 -is [int])) { return (& $r 42 'UAC_LAUNCHER_EXCEPTION' 'LAUNCHER_RESULT_INVALID' $false) }
        if ($w32 -eq 1223) { return (& $r 40 'UAC_ERROR_1223' 1223 $false) }
        return (& $r 41 'UAC_WIN32_ERROR' $w32 $false)
    }
    if ($ec -is [int] -and $script:AtmRecoverRelayedExitCodes -contains $ec) { return (& $r $ec 'ELEVATED_EXIT' $ec $true) }
    return (& $r 44 'ELEVATED_EXIT_UNKNOWN' $ec $false)
}

function Get-AtmRecoverResultExitCode {
    # The exit code of one engine result: after the seam, STOPPED_AFTER_SEAM when the run is incomplete, else the
    # outcome's; before it, GATE_CLOSED, PLAN_REFUSED (AtmRecoverPlanRefusals) or STOPPED_BEFORE_SEAM.
    param($Result)
    if ($null -ne $Result.StoppedBy -or ($Result.SeamCalled -and $null -eq $Result.Outcome)) { return [pscustomobject]@{ ExitCode = 26; Code = [string]$Result.StoppedBy } }
    if ($null -ne $Result.Outcome) { return [pscustomobject]@{ ExitCode = [int]$script:AtmRecoverOutcomeExitCodes[[string]$Result.Outcome]; Code = [string]$Result.Outcome } }
    if ($Result.Aborted -ceq 'RECUPERACAO_REAL_DESABILITADA') { return [pscustomobject]@{ ExitCode = 27; Code = 'RECUPERACAO_REAL_DESABILITADA' } }
    if ($script:AtmRecoverPlanRefusals -ccontains [string]$Result.Aborted) { return [pscustomobject]@{ ExitCode = 3; Code = [string]$Result.Aborted } }
    return [pscustomobject]@{ ExitCode = 25; Code = [string]$Result.Aborted }
}

function Invoke-AtmRecoverOneOperation {
    <#
      The one operation of an elevated copy (relaunched, or the manual model (a)), called only by Invoke-AtmRecoverCommand
      past the gate; fills -Out (Result, RunId, LogDir) and returns ExitCode, Code and Detail. In this order: the identity
      that acts and, for a relaunched copy, what is known of its requester (PRIV-5); the fixed folder (Test-AtmRecoverLogDir:
      LOG_DIR_REFUSED); one run id, generated here and used as the new log's name; then Invoke-AtmRecover (start), or for
      undo the source <folder>\<run id>.log (RECOVER_RUN_NOT_FOUND, exit PLAN_REFUSED, when there is none) and
      Invoke-AtmRecoverUndo; each runs every step of its own (plan, phrase in this console, lock B8, log, revalidation,
      seam, wait); then the result, with the run id only when its log was created.
    #>
    param([System.Collections.IDictionary]$Out, [string]$Verb, [string]$Operation, [string]$Service, [string]$RunId, $Acting, [hashtable]$InventoryArgs,
        [scriptblock]$ConfirmationReader, [string]$LogDirBase, [hashtable]$EngineArgs, [scriptblock]$Presenter)
    $atmRecShow = { param([string]$Kind, $Data) if ($Presenter) { $null = & $Presenter $Kind $Data } }
    & $atmRecShow 'identity' ([pscustomobject]@{ Name = $Acting.Name; ElevationType = $Acting.ElevationType; IntegrityLevel = $Acting.IntegrityLevel; Requester = $Out.Requester; Relaunched = ($Out.Side -ceq 'ELEVATED') })
    $ld = Test-AtmRecoverLogDir -Base $LogDirBase
    $Out.LogDir = $ld.Code
    if ($null -ne $ld.Code) { return [pscustomobject]@{ ExitCode = 28; Code = $ld.Code; Detail = $null } }
    $newRunId = [guid]::NewGuid().ToString()
    $logFile = Join-Path $ld.Dir ($newRunId + '.log')
    $interaction = @{ Caller = 'CLI'; ConsoleRequired = $true }
    if ($Verb -ceq 'start') {
        $r = Invoke-AtmRecover -Operation $Operation -Service $Service -PlanPresenter { param($p) & $atmRecShow 'plan' $p } -ConfirmationReader $ConfirmationReader -InventoryArgs $InventoryArgs `
            -LogFile $logFile -Interaction $interaction -NewRunId $newRunId @EngineArgs
    } else {
        $src = Join-Path $ld.Dir ($RunId + '.log')
        if (-not (Test-Path -LiteralPath $src -PathType Leaf)) { return [pscustomobject]@{ ExitCode = 3; Code = 'RECOVER_RUN_NOT_FOUND'; Detail = $RunId } }
        $r = Invoke-AtmRecoverUndo -SourceLog $src -RunId $RunId -PlanPresenter { param($p) & $atmRecShow 'undoPlan' $p } -ConfirmationReader $ConfirmationReader -InventoryArgs $InventoryArgs `
            -LogFile $logFile -Interaction $interaction -NewRunId $newRunId @EngineArgs
    }
    $Out.Result = $r
    if ($r.LogCreated) { $Out.RunId = $r.RunId }
    & $atmRecShow 'result' ([pscustomobject]@{ Verb = $Verb; Result = $r; RunId = $Out.RunId })
    $x = Get-AtmRecoverResultExitCode -Result $r
    return [pscustomobject]@{ ExitCode = $x.ExitCode; Code = $x.Code; Detail = $(if ($x.ExitCode -eq 3) { @($r.RefusalCodes) -join ',' } else { $null }) }
}

function Invoke-AtmRecoverCommand {
    <#
      recover start and recover undo (phase R4), called by the launcher once per process. All output goes through
      -Presenter scriptblock(kind, data); kinds: plan, undoPlan, undoRequest, identity, elevationNotice, result, end and
      waitKey. -Verb start (-Operation, -Service) or undo (-RunId), checked by the launcher and again here (USAGE).
      -Elevated: the launcher's marker of a relaunched copy, as bound; it proves nothing and only makes the copy stricter.
      -BoundNames: the parameter names the launcher bound (a relaunched copy accepts AtmRecoverElevatedArguments only).
      -Installed, -LauncherListed (agent-temp.ps1, the file that runs elevated, listed and verified by the launcher's
      manifest check; SR-03) and -InstallRoot (the launcher's own folder): the relaunch is only ever of the installed
      agent-temp.ps1, at its installed path, by Windows PowerShell from the system directory.
      -InventoryArgs and -DeadlineSeconds: for the engine. -ConfirmationReader: the typed phrase, in this console.
      -KeyReader: the key a relaunched copy waits for before its window closes.
      Test seams, never passed by the launcher: -ElevatedLauncherImpl scriptblock(filePath, arguments) returning Started,
      ExitCode and Win32Error (without it, Invoke-AtmRecoverElevatedLaunchDefault); -RequesterEvidence
      (Get-AtmRecoverRequesterEvidence); -LogDirBase (Get-AtmRecoverLogDir); -EngineArgs, passed as is to Invoke-AtmRecover
      or Invoke-AtmRecoverUndo (providers, identity, services, seams, settle wait).
      Gate closed: the plan, or the inverse plan when the fixed folder passes its check, then GATE_CLOSED. Past the gate,
      once per process (SECOND_OPERATION, before anything else):
        relaunched copy: the fixed arguments (ELEVATED_REFUSED), an elevated token (ELEVATED_REFUSED: with UAC off, the
          relaunch is not elevated), an installed copy (NOT_INSTALLED), Invoke-AtmRecoverOneOperation, then the key, in a
          finally;
        elevated token: Invoke-AtmRecoverOneOperation in this process, with no key;
        any other token, the requester: start: a fresh collection and the plan (not declared: USAGE; refused:
          PLAN_REFUSED, and nothing is requested); undo: the run id only (this token cannot read the fixed folder); an
          installed copy (NOT_INSTALLED); the notice that UAC is requested for this one operation and why (PRIV-2); one
          call to the elevated launcher; its exit code (Get-AtmRecoverLaunchExitCode). It takes no lock, reads no log and
          passes no path but the installed agent-temp.ps1's own.
      Returns Side, ExitCode, Code, Detail, Relayed, Launches, LaunchFile, LaunchArguments, Result (the engine's), RunId,
      LogDir and Requester. An unexpected failure is UNEXPECTED, by its exception type only.
    #>
    [CmdletBinding()]
    param(
        [string]$Verb,
        [string]$Operation,
        [string]$Service,
        [string]$RunId,
        [switch]$Elevated,
        [string[]]$BoundNames = @(),
        [bool]$Installed = $false,
        [bool]$LauncherListed = $false,
        [string]$InstallRoot,
        [hashtable]$InventoryArgs = @{},
        [int]$DeadlineSeconds = $script:AtmRecoveryDeadlineSeconds,
        [scriptblock]$Presenter,
        [scriptblock]$ConfirmationReader,
        [scriptblock]$KeyReader,
        [scriptblock]$ElevatedLauncherImpl,
        [scriptblock]$RequesterEvidence,
        [string]$LogDirBase,
        [hashtable]$EngineArgs = @{}
    )
    $out = [ordered]@{ Verb = $Verb; Side = $null; ExitCode = $null; Code = $null; Detail = $null; Relayed = $false; Launches = 0; LaunchFile = $null; LaunchArguments = $null
        Result = $null; RunId = $null; LogDir = $null; Requester = $null }
    $atmRecShow = { param([string]$Kind, $Data) if ($Presenter) { $null = & $Presenter $Kind $Data } }
    $finish = {
        param([int]$Exit, [string]$Code, $Detail)
        $out.ExitCode = $Exit; $out.Code = $Code; $out.Detail = $Detail
        & $atmRecShow 'end' ([pscustomobject]@{ ExitCode = $Exit; Code = $Code; Detail = $Detail; Relayed = [bool]$out.Relayed; Side = $out.Side; Verb = $Verb })
        [pscustomobject]$out
    }
    $engine = @{} + $EngineArgs
    if ($PSBoundParameters.ContainsKey('DeadlineSeconds')) { $engine['DeadlineSeconds'] = $DeadlineSeconds }
    $collArgs = @{}
    foreach ($k in @('Providers', 'IdentitySource', 'ServiceSource', 'ServiceDependencySource', 'ServiceWait', 'DeadlineSeconds')) { if ($engine.ContainsKey($k)) { $collArgs[$k] = $engine[$k] } }
    $unexpected = { param($Err) & $finish 10 'RECOVER_UNEXPECTED' (ConvertTo-AtmExceptionCode $Err.Exception.GetBaseException().GetType().Name) }
    try {
        if ($Verb -cne 'start' -and $Verb -cne 'undo') { return (& $finish 2 'RECOVER_VERB_INVALID' $null) }
        if ($Verb -ceq 'start' -and ($null -eq (Get-AtmRecoveryOperation $Operation) -or -not $Service -or $Service.Length -gt 256 -or $Service -cnotmatch '^[A-Za-z0-9_.\- ]+$')) { return (& $finish 2 'RECOVER_ARGUMENTS_INVALID' $null) }
        if ($Verb -ceq 'undo' -and -not (Test-AtmRecoverRunIdForm $RunId)) { return (& $finish 2 'RECOVER_ARGUMENTS_INVALID' $null) }
        if (-not $script:AtmRecoveryEnabled) {
            $out.Side = 'GATE_CLOSED'
            if ($Verb -ceq 'start') {
                $out.Result = Invoke-AtmRecover -Operation $Operation -Service $Service -PlanPresenter { param($p) & $atmRecShow 'plan' $p } @collArgs
            } else {
                $ld = Test-AtmRecoverLogDir -Base $LogDirBase
                $out.LogDir = $ld.Code
                if ($null -eq $ld.Code) { $out.Result = Invoke-AtmRecoverUndo -SourceLog (Join-Path $ld.Dir ($RunId + '.log')) -RunId $RunId -PlanPresenter { param($p) & $atmRecShow 'undoPlan' $p } @collArgs }
                else { & $atmRecShow 'undoRequest' ([pscustomobject]@{ RunId = $RunId; LogDir = $ld.Code; GateOpen = $false }) }
            }
            return (& $finish 27 'RECUPERACAO_REAL_DESABILITADA' $out.LogDir)
        }
    } catch { return (& $unexpected $_) }

    # ---- past the recovery gate (the suite only, in its own process) ----
    if ($script:AtmRecoverOperationTaken) { return (& $finish 30 'RECOVER_SECOND_OPERATION' $null) }
    $script:AtmRecoverOperationTaken = $true
    $one = @{ Out = $out; Verb = $Verb; Operation = $Operation; Service = $Service; RunId = $RunId; InventoryArgs = $InventoryArgs; ConfirmationReader = $ConfirmationReader
        LogDirBase = $LogDirBase; EngineArgs = $engine; Presenter = $Presenter }
    if ($Elevated) {
        # The relaunched copy: every path ends with the key, so its window shows how it ended.
        $out.Side = 'ELEVATED'
        try {
            $allowed = $script:AtmRecoverElevatedArguments[$Verb]
            $extra = @(@($BoundNames) | Where-Object { $allowed -cnotcontains [string]$_ })
            if ($extra.Count -gt 0 -or @($BoundNames) -cnotcontains 'AtmElevatedRecovery') { return (& $finish 29 'RECOVER_ELEVATED_ARGUMENTS' ($extra -join ',')) }
            $acting = Get-AtmRecoverActingIdentity -Source $engine['IdentitySource']
            if ($acting.IsElevatedAdministrator -ne $true) { return (& $finish 29 'RECOVER_ELEVATED_NOT_ELEVATED' $acting.ElevationType) }
            if (-not $Installed -or -not $LauncherListed) { return (& $finish 31 'RECOVER_NOT_INSTALLED' $null) }
            $out.Requester = Get-AtmRecoverRequesterEvidence -Source $RequesterEvidence
            $x = Invoke-AtmRecoverOneOperation @one -Acting $acting
            return (& $finish $x.ExitCode $x.Code $x.Detail)
        } catch { return (& $unexpected $_) }
        finally {
            & $atmRecShow 'waitKey' ([pscustomobject]@{ RunId = $out.RunId })
            if ($KeyReader) { try { $null = & $KeyReader } catch { $null = $_ } }
        }
    }
    try {
        $acting = Get-AtmRecoverActingIdentity -Source $engine['IdentitySource']
        if ($acting.IsElevatedAdministrator -eq $true) {
            $out.Side = 'SAME_PROCESS'
            $x = Invoke-AtmRecoverOneOperation @one -Acting $acting
            return (& $finish $x.ExitCode $x.Code $x.Detail)
        }
        # The requester: never elevated, it changes nothing and takes no lock.
        $out.Side = 'REQUESTER'
        if ($Verb -ceq 'start') {
            $coll = Get-AtmRecoverCollection @collArgs
            $plan = Get-AtmRecoverPlan -Collection $coll -Operation $Operation -Service $Service
            & $atmRecShow 'plan' $plan
            if (-not $plan.Declared) { return (& $finish 2 'RECOVERY_NOT_DECLARED' $null) }
            if (-not $plan.Offered) { return (& $finish 3 'RECOVERY_REFUSED' (@($plan.Codes) -join ',')) }
        } else { & $atmRecShow 'undoRequest' ([pscustomobject]@{ RunId = $RunId; LogDir = $null; GateOpen = $true }) }
        if (-not $Installed -or -not $LauncherListed -or -not $InstallRoot) { return (& $finish 31 'RECOVER_ELEVATION_NEEDS_INSTALL' $null) }
        # SR-03 (V1.0 security review): no file association chooses what runs elevated. The target is Windows PowerShell
        # 5.1 by its absolute path, with bin\agent-temp.cmd's own flags, running this installation's verified
        # agent-temp.ps1. The path comes from the system directory (GetSystemDirectory), never from the requester's
        # environment, which with another account's credentials would choose what runs as that account.
        $file = [IO.Path]::Combine([Environment]::SystemDirectory, 'WindowsPowerShell\v1.0\powershell.exe')
        $fixed = $(if ($Verb -ceq 'start') { 'recover start -Operation ' + $Operation + ' -Service "' + $Service + '" -AtmElevatedRecovery' } else { 'recover undo -RunId ' + $RunId + ' -AtmElevatedRecovery' })
        $argLine = '-NoLogo -NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $InstallRoot 'agent-temp.ps1') + '" ' + $fixed
        $out.LaunchFile = $file; $out.LaunchArguments = $argLine
        & $atmRecShow 'elevationNotice' ([pscustomobject]@{ Verb = $Verb; Operation = $Operation; Target = $Service; RunId = $RunId })
        $out.Launches = $out.Launches + 1
        $launch = $null; $exType = $null
        try { $launch = $(if ($ElevatedLauncherImpl) { & $ElevatedLauncherImpl $file $argLine } else { Invoke-AtmRecoverElevatedLaunchDefault -FilePath $file -Arguments $argLine }) }
        catch { $exType = ConvertTo-AtmExceptionCode $_.Exception.GetBaseException().GetType().Name }
        $m = Get-AtmRecoverLaunchExitCode -Launch $launch -ExceptionType $exType
        $out.Relayed = $m.Relayed
        return (& $finish $m.ExitCode $m.Code $m.Detail)
    } catch { return (& $unexpected $_) }
}
