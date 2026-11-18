# AgentTempManager RECOVERY ENGINE (V0.4, docs/adr/ADR-0016: assisted recovery of services). Phase R1: the closed
# catalog, a fresh read-only collection made with the diagnose engine's own functions (Engine.Diagnose.ps1: identity,
# provider runtime hints, the services query with its V0.4 R0 fault signals, dependencies and image comparison, and the
# service findings), the criteria that offer or refuse an operation for one declared service, and the plan of one
# operation for one target. Phase R2 (end of this file): the start of one declared service past the recovery gate,
# through the service control seam. Depends on Engine.Audit.ps1, Engine.Diagnose.ps1 and, past the gate, Engine.Clean.ps1
# (lock B8, log writer, console). No terminal output of its own. With the recovery gate closed (every copy) nothing is
# asked, locked, logged or written, and no service is opened with a control right: the seam is reached past it only.
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
      seam runs. -SettleWait: test seam, scriptblock(milliseconds) in place of the real wait. Returns one object. Aborted:
      the seam was never called; StoppedBy: a failure after it; Outcome: what the seam's call gave.
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
        [scriptblock]$SettleWait
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
        ConfirmationReader = $ConfirmationReader; Interaction = $Interaction; Console = $console; ServiceControlImpl = $ServiceControlImpl; SettleWait = $SettleWait }
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
        [hashtable]$Interaction = @{}, $Console, [scriptblock]$ServiceControlImpl, [scriptblock]$SettleWait)
    $service = [string]$Plan.Target
    $op = $Plan.Operation
    $logFail = { param([string]$Stage, [string]$Code) $LogErrors.Add([pscustomobject]@{ Stage = $Stage; Code = $Code }) }
    $halt = { param([string]$Code) if (-not $Res.Aborted -and -not $Res.StoppedBy) { if ($Res.SeamCalled) { $Res.StoppedBy = $Code } else { $Res.Aborted = $Code } } }
    $me = Get-AtmCurrentIdentity
    $runId = [guid]::NewGuid().ToString()
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
