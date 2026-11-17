# AgentTempManager RECOVERY ENGINE (V0.4, docs/adr/ADR-0016: assisted recovery of services). Phase R1: the closed
# catalog, a fresh read-only collection made with the diagnose engine's own functions (Engine.Diagnose.ps1: identity,
# provider runtime hints, the services query with its V0.4 R0 fault signals, dependencies and image comparison, and the
# service findings), the criteria that offer or refuse an operation for one declared service, and the plan of one
# operation for one target. Depends on Engine.Audit.ps1 and Engine.Diagnose.ps1; no terminal output of its own (the list
# and the plan are presented by Report.ps1). With the recovery gate closed (every copy) recover only lists and plans:
# nothing is asked, locked, logged or written, and no service is opened, let alone controlled. Phase R1 has no control
# path at all, gate open or closed: the control seam is added in phase R2, in this file only.
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
    'RECOVERY_IMAGE_NOT_DECLARED',      # no provider declares an ExpectedImage for it (R1; R2 depends on the maintainer)
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
