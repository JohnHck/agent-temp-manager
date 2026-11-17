<#
.SYNOPSIS
  V5 pilot evidence tool (ADR-0015, sections 6 and 7; decision V5-D7 (a); V5-TOOLS-ISO): reads the log of one run of
  clean, isolate, quarantine restore or quarantine purge (and, optionally, the output of Compare-AtmPilotSnapshot.ps1)
  and writes the only evidence that may leave the pilot VM: record types, codes, counts and yes/no. Never a path, a SID,
  an account, a machine name, a quarantine entry id, a plan id or any free text.
.DESCRIPTION
  The kind of the log (log.kind) comes from its schema and its records; every record must be of the same schema:
  * atm.cleanlog/1: clean;
  * atm.isolatelog/1: restore when its run-start says operation 'restore' or it holds a reconcile, restore-intent or
    restore-result record; isolate otherwise;
  * atm.purgelog/1: purge (the manual one; the automatic pass writes another schema, which is refused).
  The closed lists below (record types, stop and refusal codes, reason codes, outcomes, steps) are what each kind of log
  holds, taken from the product's clean and isolation modules at the commit of this tool. A field that does not apply
  to the kind, or that the log does not answer, is null.
  Allow list, not deny list: every output field has a fixed type (a code from a known list, a non-negative integer, a
  yes/no, the 40-hex pinned SHA). Before anything is written, every value is checked:
  * refused when it holds a path separator ('\' or '/'), 'S-1-', '@', or equals (ignoring case) USERNAME, COMPUTERNAME,
    USERDOMAIN or a part of USERPROFILE of this environment;
  * refused when it holds a quarantine entry id (yyyyMMddTHHmmssZ-<8 hex>) or 64 hex digits (a plan id), or, as text,
    holds an entry id or a plan id of this log, or the 8 characters of one that its phrases show (ENTRY_ID, PLAN_ID):
    they identify the run, and only types, codes, counts and yes/no leave the VM;
  * refused when it is not of its field's type.
  A refused value stops the script: the summary is not written; a file named '<-Out name>.<id>.REFUSED' is left in
  the folder of -Out with only the names of the fields that failed and the rule each one broke (never the value), and
  the console says the same. Exit code 3.
  Otherwise the summary is written to '<-Out name>.<id>.REFUSED' in the folder of -Out, then tools\Test-AtmPrivacy.ps1
  (the repository's scanner, with -NeedlesFile when given) scans that folder and only its findings in that file count.
  With no finding the file is renamed to -Out (the only rename in these tools). With a finding, or when the scanner
  cannot run, the file keeps its REFUSED name and the exit code is 4 or 5. This script never deletes anything:
  discarding a REFUSED file is the operator's. Keep -Out in a folder of its own: the scanner reads every file in that
  folder, and one it cannot read (a transcript still being written) makes the scan fail closed.
  What the log cannot answer is written as null, for the operator to mark by hand in the run sheet, never guessed:
  the checkout differs from the pinned SHA by the gate line only, the guest clock within a few seconds of the host's,
  and the network disconnected at the deleting run.
  Runs that write no log (exit 6 when the console is not observed; CLEAN_LOCK_BUSY, because the clean engine refuses
  the lock before any log is opened; isolate, restore or purge with its gate closed, which stops after the plan, as
  ISOLAMENTO_REAL_DESABILITADO or EXPURGO_REAL_DESABILITADO) are summarized with -NoLog and the code and exit code the
  console showed (-ShownCode, -ExitCode); with -LogFile too, the summary records whether that file is absent.
  It does not load the product's engine and never uses the network. Read only, except the two files named above.
.PARAMETER LogFile
  The log of the run (JSON Lines, schema atm.cleanlog/1, atm.isolatelog/1 or atm.purgelog/1). Required unless -NoLog.
.PARAMETER NoLog
  The run wrote no log. Needs -ShownCode or -ExitCode. log.kind is then null.
.PARAMETER ShownCode
  The code the console showed (for example CLEAN_LOCK_BUSY or ISOLAMENTO_REAL_DESABILITADO), typed by the operator;
  checked like any value, against the stop codes of every kind (with no log there is no kind).
.PARAMETER ExitCode
  The exit code the console showed (0 to 255).
.PARAMETER Compare
  The -Out file of Compare-AtmPilotSnapshot.ps1: only onlyExpectedChange and the counts are taken.
.PARAMETER PinnedSha
  The pinned commit of the pilot checkout (git rev-parse HEAD: 40 lowercase hex).
.PARAMETER Out
  The summary to write (a new file; never overwritten).
.PARAMETER NeedlesFile
  Optional private identifiers for the scanner, one per line, kept outside the repository.
.EXITCODES
  0  the summary was written to -Out and the privacy scanner found nothing in it.
  2  refused before writing anything: parameters, a missing or malformed log or compare file, an unknown log schema
     or records of more than one schema, -Out exists, its folder or the scanner is missing.
  3  a value was refused (type or privacy rule): no summary; '<-Out name>.<id>.REFUSED' names the fields and rules.
  4  the privacy scanner found something in the summary: it stays as '<-Out name>.<id>.REFUSED'.
  5  the privacy scanner could not run, or the final rename failed: the summary stays as '<-Out name>.<id>.REFUSED'.
  6  unexpected failure.
#>
[CmdletBinding()]
param(
    [string]$LogFile,
    [switch]$NoLog,
    [string]$ShownCode,
    [string]$ExitCode,
    [string]$Compare,
    [string]$PinnedSha,
    [Parameter(Mandatory)][string]$Out,
    [string]$NeedlesFile
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# --- the types: closed lists of what each kind of log holds and the console shows (the product's clean and isolation
# modules at the commit of this tool) ---
$logSchemas = @('atm.cleanlog/1', 'atm.isolatelog/1', 'atm.purgelog/1')
$logKinds = @{ 'atm.cleanlog/1' = 'clean'; 'atm.isolatelog/1' = 'isolate'; 'atm.purgelog/1' = 'purge' }
$recordTypesByKind = @{
    clean = @('run-start', 'plan', 'declaration', 'confirmation', 'plan-check', 'skip', 'intent', 'result', 'run-end')
    isolate = @('run-start', 'plan', 'confirmation', 'plan-check', 'skip', 'move-intent', 'move-result', 'run-end')
    restore = @('run-start', 'confirmation', 'plan-check', 'reconcile', 'restore-intent', 'restore-result', 'run-end')
    purge = @('run-start', 'declaration', 'confirmation', 'plan-check', 'purge-intent', 'purge-result', 'run-end')
}
# The records of one complete run of each kind, in order (log.fullRunOrder).
$fullRunOrder = @{
    clean = 'run-start,plan,declaration,confirmation,plan-check,intent,result,run-end'
    isolate = 'run-start,plan,confirmation,plan-check,move-intent,move-result,run-end'
    restore = 'run-start,confirmation,plan-check,restore-intent,restore-result,run-end'
    purge = 'run-start,declaration,confirmation,plan-check,purge-intent,purge-result,run-end'
}
$intentTypes = @{ clean = 'intent'; isolate = 'move-intent'; restore = 'restore-intent'; purge = 'purge-intent' }
$resultTypes = @{ clean = 'result'; isolate = 'move-result'; restore = 'restore-result'; purge = 'purge-result' }
# The field that names the run in every record: runId in the clean log, id in the isolation and purge logs.
$runFields = @{ clean = 'runId'; isolate = 'id'; restore = 'id'; purge = 'id' }
$stopCodes = @('ALLOWLIST_VAZIA', 'SEM_APRESENTACAO_OU_CONFIRMACAO', 'NENHUM_CAMINHO_ELEGIVEL', 'EXCLUSAO_REAL_DESABILITADA_V0_1',
    'B1_EXCEPTION_LIMIT_EXCEEDED', 'LOG_REQUIRED', 'CONSOLE_NOT_OBSERVED', 'LOG_OPEN_FAILED', 'LOG_WRITE_FAILED', 'DECLARATION_CANCELLED',
    'DECLARATION_DECLINED', 'CONFIRMACAO_AUSENTE_OU_DIVERGENTE', 'PLAN_CHANGED_BEFORE_EXECUTION', 'REVALIDATION_REFUSED', 'LOG_INTENT_FAILED',
    'LOG_RESULT_FAILED', 'LOG_END_FAILED', 'LOG_CLOSE_FAILED', 'LOCK_RELEASE_FAILED', 'STOPPED_AFTER_REFUSED', 'STOPPED_AFTER_PARTIAL',
    'STOPPED_AFTER_VERIFICATION_FAILED', 'STOPPED_AFTER_EXCEPTION', 'CLEAN_LOCK_BUSY', 'CLEAN_LOCK_ABANDONED', 'CLEAN_LOCK_NESTED',
    'CLEAN_LOCK_DENIED', 'CLEAN_LOCK_TYPE_MISMATCH', 'CLEAN_LOCK_NAME_INVALID')
# The lock's refusals that carry a number or a policy name (closed families, still codes only).
$stopFamilies = '^CLEAN_LOCK_(POLICY_[A-Z_]+|POLICY_UNREADABLE_[0-9]+|ERROR_[A-Za-z0-9_]+|WAIT_FAILED_[0-9]+)$'
$reasonCodes = @('B1_EXCEPTION_NEW_UNINSPECTABLE_PROCESS', 'B1_EXCEPTION_NO_LONGER_APPLIES', 'B1_EXCEPTION_RESIDUAL_RISK',
    'DESAPARECEU_OU_AMBIGUO_NA_REVALIDACAO', 'ALTERADO_APOS_CONFIRMACAO', 'EM_USO', 'ACESSO_NEGADO_PARA_EXCLUSAO', 'REPARSE_POINT_NA_SONDAGEM',
    'SONDAGEM_INCOMPLETA', 'COBERTURA_DE_PROCESSOS_INCOMPLETA', 'OUTRO_USUARIO_EXIGE_ADMINISTRADOR_ELEVADO', 'ESTRUTURA_PAI_INVALIDA',
    'CAMINHO_E_RAIZ_PROTEGIDA', 'ACL_ILEGIVEL', 'OWNER_ILEGIVEL', 'NOT_SESSION_ROOT', 'REPARSE_POINT', 'MEASUREMENT_INCOMPLETE', 'READ_ERRORS',
    'PROTECTED_FILES', 'SHARED_TEMP', 'BASE_STRUCTURE_UNRECOGNIZED', 'UNRECOGNIZED_SLUG', 'RESIDUAL_PROFILE', 'CLOCK_SKEW', 'ANCESTOR_REFERENCE',
    'AMBIGUOUS_REFERENCE', 'SESSION_REGISTRY_UNREADABLE', 'SESSION_REGISTRY_ENTRY_UNPARSEABLE', 'SESSION_PID_ALIVE_UNVERIFIED',
    'SESSION_LIVENESS_UNVERIFIABLE', 'TRANSCRIPTS_UNREADABLE', 'TRANSCRIPT_RECENT', 'PROCESS_SNAPSHOT_FAILED', 'CONFIG_DIR_UNKNOWN',
    'RUNTIME_NOT_COLLECTED', 'RUNTIME_TIMEOUT', 'RUNTIME_OBSERVATION_INCOMPLETE', 'RUNTIME_USE_OBSERVED', 'RUNTIME_ANCESTOR_REFERENCE',
    'RUNTIME_ASSOCIATION_AMBIGUOUS', 'RUNTIME_KEY_COLLISION', 'RUNTIME_SESSION_UNVERIFIED', 'RUNTIME_SESSION_LIVE', 'ELIGIBLE', 'INVESTIGATE', 'BLOCKED')
# Isolate, restore and purge: the stop codes they share (the lock's codes as clean's: the same lock), then each one's own.
$isoSharedStop = @('SEM_APRESENTACAO', 'SEM_APRESENTACAO_OU_CONFIRMACAO', 'LOG_REQUIRED', 'LOG_DESTINATION_NOT_ALLOWED', 'CONSOLE_NOT_OBSERVED', 'LOG_OPEN_FAILED',
    'LOG_WRITE_FAILED', 'CONFIRMACAO_AUSENTE_OU_DIVERGENTE', 'REVALIDATION_REFUSED', 'MANIFEST_INTENT_FAILED', 'LOG_INTENT_FAILED', 'LOG_RESULT_FAILED',
    'MANIFEST_RESULT_FAILED', 'STOPPED_AFTER_EXCEPTION', 'STOPPED_AFTER_REFUSED', 'LOG_END_FAILED', 'LOG_CLOSE_FAILED', 'LOCK_RELEASE_FAILED', 'CLEAN_LOCK_BUSY',
    'CLEAN_LOCK_ABANDONED', 'CLEAN_LOCK_NESTED', 'CLEAN_LOCK_DENIED', 'CLEAN_LOCK_TYPE_MISMATCH', 'CLEAN_LOCK_NAME_INVALID')
$stopByKind = @{
    clean = $stopCodes
    isolate = $isoSharedStop + @('ALLOWLIST_VAZIA', 'NENHUM_CAMINHO_ISOLAVEL', 'ISOLAMENTO_REAL_DESABILITADO', 'ISOLAMENTO_UMA_RAIZ_POR_EXECUCAO', 'QUARANTINE_PATH_INVALID',
        'DECLARATION_CANCELLED', 'DECLARATION_DECLINED', 'PLAN_CHANGED_BEFORE_EXECUTION', 'MANIFEST_WRITE_FAILED', 'MANIFEST_CLOSE_FAILED', 'STOPPED_AFTER_INTEGRITY_FAILED')
    restore = $isoSharedStop + @('ENTRY_ID_INVALID', 'RESTAURACAO_RECUSADA', 'RESTAURACAO_REAL_DESABILITADA', 'MANIFEST_RECONCILE_FAILED', 'RESTORED_INTEGRITY_FAILED')
    purge = $isoSharedStop + @('ENTRY_ID_INVALID', 'EXPURGO_RECUSADO', 'EXPURGO_REAL_DESABILITADO', 'DECLARATION_CANCELLED', 'DECLARATION_DECLINED', 'STOPPED_AFTER_PARTIAL',
        'STOPPED_AFTER_VERIFICATION_FAILED')
}
# Isolate only: the quarantine and its manifest refuse with a fixed prefix and the native layer's own code (upper case,
# digits and '_', or an exception type name after '_', or NTSTATUS_0x<8 hex>). Closed families, still codes only.
$isoStopFamily = '^(?:QUARANTINE_(?:PARENT_|CREATE_|PIN_|ENTRY_)?|MANIFEST_)(?:[A-Z][A-Z0-9_]*(?:[A-Z][A-Za-z0-9]*Exception)?|NTSTATUS_0x[0-9A-F]{8})$'
$familiesByKind = @{ clean = @($stopFamilies); isolate = @($stopFamilies, $isoStopFamily); restore = @($stopFamilies); purge = @($stopFamilies) }
# Isolate, restore and purge: their plan-check and skip reasons, reduced to the leading code as clean's: the gates of
# clean (the list above) plus the plan check of isolate, the capacity of the quarantine, and the plans of restore and
# purge (the entry, its payload, the destination, the chain, owner and ACL, the lock probe, the command lines).
$isoReasonCodes = $reasonCodes + @('ROOT_NOT_SEEN_ONCE', 'PLAN_ITEM_CHANGED', 'UNCODED_REASON', 'OWNER_DIVERGENTE', 'ESCRITA_CONCEDIDA_A_TERCEIROS', 'CADEIA_DE_ANCESTRAIS',
    'QUARANTINE_QUOTA_REACHED', 'QUARANTINE_QUOTA_UNMEASURED', 'LOW_DISK_SPACE', 'MOVE_OTHER_VOLUME', 'ENTRY_NOT_FOUND', 'ENTRY_MANIFEST_INVALID',
    'ALVO_FORA_DO_PROPRIO_PERFIL', 'ENTRY_ALREADY_RESTORED', 'ENTRY_PURGED', 'ENTRY_FAILED', 'ENTRY_INCOMPLETE', 'ENTRY_VERIFY_DIFFERS', 'ENTRY_VERIFY_PAYLOAD_MISSING',
    'ORIGINAL_PATH_INVALID', 'RESTORE_PARENT_NOT_IN_OWN_BASE', 'RESTORE_PARENT_MISSING', 'RESTORE_PARENT_ACTIVE_EVIDENCE', 'RESTORE_PARENT_RECENT', 'RESTORE_CONFLICT',
    'RUNTIME_QUARANTINE_REFERENCED', 'PURGE_REFUSED_ENTRY_NOT_FOUND', 'PURGE_REFUSED_UNRECOGNIZED', 'PURGE_REFUSED_ENTRY_MANIFEST_INVALID', 'PURGE_REFUSED_ABANDONED',
    'PURGE_REFUSED_ISOLATED', 'PURGE_REFUSED_EXPIRED', 'PURGE_REFUSED_INCOMPLETE', 'PURGE_REFUSED_FAILED', 'PURGE_REFUSED_RESTORED', 'PURGE_REFUSED_PURGED',
    'PURGE_REFUSED_DIFFERS', 'PURGE_REFUSED_PAYLOAD_MISSING')
$reasonByKind = @{ clean = $reasonCodes; isolate = $isoReasonCodes; restore = $isoReasonCodes; purge = $isoReasonCodes }
$outcomeByKind = @{
    clean = @('COMPLETE', 'PARTIAL', 'REFUSED', 'VERIFICATION_FAILED', 'EXCEPTION')
    isolate = @('COMPLETE', 'INTEGRITY_FAILED', 'REFUSED', 'EXCEPTION')
    restore = @('COMPLETE', 'INTEGRITY_FAILED', 'REFUSED', 'EXCEPTION')
    purge = @('COMPLETE', 'PARTIAL', 'REFUSED', 'VERIFICATION_FAILED', 'EXCEPTION')
}
# The step of a refused confirmation.
$stepByKind = @{ clean = @('task', 'results', 'risk', 'confirm'); isolate = @('risk', 'confirm'); restore = @('restore', 'alternative'); purge = @('task', 'results', 'purge') }
$enums = @{
    kind = @('clean', 'isolate', 'restore', 'purge')
    verifiedGone = @('GONE', 'PRESENT', 'UNKNOWN')
    consoleBy = @('ENGINE_CONSOLE_CHECK', 'TEST_SEAM')
    caller = @('CLI', 'TUI', 'DIRECT_CALL')
    contentDecision = @('RESULTS_PRESERVED', 'NOTHING_NEEDED')
    category = @('ELIGIBLE', 'ELIGIBLE_WITH_DECLARED_RISK')
    declaredBy = @('OPERATOR')
    changedField = @('path', 'fingerprint', 'files', 'dirs', 'bytes', 'newestWrite')
}
# Set once the kind is known (with no log: every kind's stop codes, and no record type).
$activeStop = @(); $activeFamilies = @()
# The entry ids and plan ids of this log (and the 8 characters of each that its phrases show): never in the summary.
$idNeedles = New-Object System.Collections.Generic.List[object]

function Stop-Pilot {
    param([int]$Code, [string]$Message)
    Write-Host $Message -ForegroundColor $(if ($Code -eq 0) { 'Green' } else { 'Red' })
    exit $Code
}

function Get-PilotProp {
    # A field of a parsed record, or $null when absent.
    param($Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    $p = $Obj.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

function Get-PilotDenyRule {
    # The privacy rule a value breaks, or $null (checked on every value, before its type).
    param($Value)
    $s = [string]$Value
    if ($s.IndexOf('\') -ge 0 -or $s.IndexOf('/') -ge 0) { return 'PATH_SEPARATOR' }
    if ($s.IndexOf('S-1-', [StringComparison]::OrdinalIgnoreCase) -ge 0) { return 'SID_PREFIX' }
    if ($s.IndexOf('@') -ge 0) { return 'AT_SIGN' }
    foreach ($n in @($env:USERNAME, $env:COMPUTERNAME, $env:USERDOMAIN)) { if ($n -and [string]::Equals($s, $n, [StringComparison]::OrdinalIgnoreCase)) { return 'ENVIRONMENT_NAME' } }
    if ($env:USERPROFILE) { foreach ($part in $env:USERPROFILE.Split('\')) { if ($part -and [string]::Equals($s, $part, [StringComparison]::OrdinalIgnoreCase)) { return 'PROFILE_PART' } } }
    # The run's identifiers: an entry id or a plan id anywhere, and (as text) those of this log or their 8 characters.
    if ($s -match '[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}') { return 'ENTRY_ID' }
    if ($s -match '[0-9a-f]{64}') { return 'PLAN_ID' }
    if ($Value -is [string]) { foreach ($nd in $idNeedles) { if ($s.IndexOf($nd.Text, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $nd.Rule } } }
    return $null
}

function Test-PilotType {
    param($Value, [string]$Type)
    switch -CaseSensitive ($Type) {
        'bool' { return ($Value -is [bool]) }
        'falseOnly' { return ($Value -is [bool] -and -not $Value) }
        'int' { return (($Value -is [int] -or $Value -is [long]) -and $Value -ge 0) }
        'sha40' { return ($Value -is [string] -and $Value -cmatch '^[0-9a-f]{40}$') }
        'stopCode' {
            if (-not ($Value -is [string])) { return $false }
            if ($activeStop -ccontains $Value) { return $true }
            foreach ($fam in $activeFamilies) { if ($Value -cmatch $fam) { return $true } }
            return $false
        }
        default { return ($Value -is [string] -and $enums[$Type] -ccontains $Value) }
    }
}

$fields = New-Object System.Collections.Generic.List[object]
function Add-PilotField {
    # One output field: its name, its type and the raw value (a list for -List). Checked later, all together.
    param([string]$Name, [string]$Type, $Value, [switch]$List)
    $fields.Add([pscustomobject]@{ Name = $Name; Type = $Type; Value = $Value; List = [bool]$List })
}

function Write-PilotNewFile {
    # The only way these tools write: a NEW file (never an existing one), UTF-8 without BOM.
    param([string]$Path, [string]$Text)
    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($Text)
    $fs = New-Object IO.FileStream($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $fs.Write($bytes, 0, $bytes.Length); $fs.Flush($true) } finally { $fs.Dispose() }
}

try {
    # --- parameters: nothing is written before these pass ---
    $outFull = [IO.Path]::GetFullPath($Out)
    $outDir = [IO.Path]::GetDirectoryName($outFull)
    $outLeaf = [IO.Path]::GetFileName($outFull)
    if (-not $outLeaf) { Stop-Pilot 2 'refused: -Out names no file (OUT_PATH_INVALID)' }
    if ([IO.File]::Exists($outFull) -or [IO.Directory]::Exists($outFull)) { Stop-Pilot 2 'refused: -Out already exists; it is never overwritten (OUT_EXISTS)' }
    if (-not [IO.Directory]::Exists($outDir)) { Stop-Pilot 2 'refused: the folder of -Out does not exist (OUT_FOLDER_MISSING)' }
    $scanner = Join-Path (Split-Path -Parent $PSScriptRoot) 'Test-AtmPrivacy.ps1'
    if (-not [IO.File]::Exists($scanner)) { Stop-Pilot 2 'refused: the privacy scanner tools\Test-AtmPrivacy.ps1 is missing (SCANNER_MISSING)' }
    if ($NeedlesFile -and -not [IO.File]::Exists($NeedlesFile)) { Stop-Pilot 2 'refused: -NeedlesFile does not exist (NEEDLES_MISSING)' }
    if (-not $NoLog -and -not $LogFile) { Stop-Pilot 2 'refused: give -LogFile, or -NoLog for a run that wrote no log (LOG_OR_NOLOG)' }
    if ($NoLog -and -not $ShownCode -and -not $ExitCode) { Stop-Pilot 2 'refused: -NoLog needs -ShownCode or -ExitCode (NOLOG_NEEDS_CODE)' }
    if (-not $NoLog -and -not [IO.File]::Exists($LogFile)) { Stop-Pilot 2 'refused: -LogFile does not exist (LOG_MISSING); for a run that wrote no log use -NoLog' }
    if ($Compare -and -not [IO.File]::Exists($Compare)) { Stop-Pilot 2 'refused: -Compare does not exist (COMPARE_MISSING)' }
    $exit = $null
    if ($ExitCode) {
        if ($ExitCode -cnotmatch '^[0-9]{1,3}$' -or [int]$ExitCode -gt 255) { Stop-Pilot 2 'refused: -ExitCode is not a number from 0 to 255 (EXIT_CODE_INVALID)' }
        $exit = [int]$ExitCode
    }

    # --- the log (JSON Lines, one record per line: schema, type, the run (runId or id), recSeq, utc, then its fields) ---
    $recs = New-Object System.Collections.Generic.List[object]
    $kind = $null
    if (-not $NoLog) {
        $schema = $null
        $fs = New-Object IO.FileStream($LogFile, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        $sr = New-Object IO.StreamReader($fs, (New-Object System.Text.UTF8Encoding($false)))
        try {
            $n = 0
            while ($null -ne ($line = $sr.ReadLine())) {
                $n++
                if ($line.Trim() -eq '') { continue }
                $r = $null
                try { $r = $line | ConvertFrom-Json } catch { Stop-Pilot 2 "refused: line $n of the log is not a JSON record (LOG_LINE_INVALID)" }
                $sch = [string](Get-PilotProp $r 'schema')
                if ($logSchemas -cnotcontains $sch) { Stop-Pilot 2 "refused: line $n of the log is not of a known schema (LOG_SCHEMA_UNKNOWN)" }
                if ($null -eq $schema) { $schema = $sch } elseif ($sch -cne $schema) { Stop-Pilot 2 "refused: line $n of the log is of another schema than its first record (LOG_SCHEMA_MIXED)" }
                $recs.Add($r)
            }
        } finally { $sr.Dispose(); $fs.Dispose() }
        if ($recs.Count -eq 0) { Stop-Pilot 2 'refused: the log has no record (LOG_EMPTY)' }
        $kind = $logKinds[$schema]
        if ($kind -ceq 'isolate') {
            # The restore writes the isolation log too: its run-start says so, and so do its own record types.
            $rs = @($recs | Where-Object { [string](Get-PilotProp $_ 'type') -ceq 'run-start' }) | Select-Object -First 1
            $own = @($recs | Where-Object { @('reconcile', 'restore-intent', 'restore-result') -ccontains [string](Get-PilotProp $_ 'type') })
            if ([string](Get-PilotProp $rs 'operation') -ceq 'restore' -or $own.Count -gt 0) { $kind = 'restore' }
        }
        # The entry ids and plan ids this log names, and the 8 characters of each shown in its phrases (an entry id's
        # last 8, a plan id's first 8): never in the summary, not even inside another value.
        foreach ($r in $recs) {
            foreach ($nm in @('planId', 'entryId')) {
                $v = Get-PilotProp $r $nm
                if (-not ($v -is [string]) -or $v.Length -lt 8) { continue }
                $rule = $(if ($nm -ceq 'planId') { 'PLAN_ID' } else { 'ENTRY_ID' })
                $short = $(if ($nm -ceq 'planId') { $v.Substring(0, 8) } else { $v.Substring($v.Length - 8) })
                foreach ($x in @($v, $short)) { $idNeedles.Add([pscustomobject]@{ Text = $x; Rule = $rule }) }
            }
        }
    }
    if ($kind) {
        $activeStop = $stopByKind[$kind]; $activeFamilies = $familiesByKind[$kind]
        $enums['recordType'] = $recordTypesByKind[$kind]; $enums['reasonCode'] = $reasonByKind[$kind]
        $enums['outcome'] = $outcomeByKind[$kind]; $enums['step'] = $stepByKind[$kind]
    } else {
        # No log, no kind: a code typed by the operator may be any kind's.
        $activeStop = @($stopByKind.Values | ForEach-Object { $_ } | Select-Object -Unique); $activeFamilies = @($stopFamilies, $isoStopFamily)
        $enums['recordType'] = @(); $enums['reasonCode'] = @(); $enums['outcome'] = @(); $enums['step'] = @()
    }
    $byType = { param([string]$T) @($recs | Where-Object { [string](Get-PilotProp $_ 'type') -ceq $T }) }

    # --- the compare output (only onlyExpectedChange and the counts) ---
    $cmp = $null
    if ($Compare) {
        $cmp = [ordered]@{}
        $known = @('onlyExpectedChange', 'roots', 'expectedRemovedGiven', 'expectedRemovedFound', 'expectedNewPatterns', 'expectedTouchedPatterns', 'removed.expected',
            'removed.unexpected', 'new.expected', 'new.unexpected', 'changed.expected', 'changed.unexpected', 'touched.expected', 'unchanged.expected', 'unchanged.unexpected',
            'rootsChanged.expected', 'rootsChanged.unexpected')
        $lines = @([IO.File]::ReadAllLines($Compare) | Where-Object { $_ -ne '' })
        if ($lines.Count -ne $known.Count + 2 -or $lines[0] -cne "atm-pilot-compare`t2" -or $lines[$lines.Count - 1] -cne "end`tcompare") { Stop-Pilot 2 'refused: -Compare is not a compare output of a known format (COMPARE_FORMAT_UNKNOWN)' }
        for ($i = 1; $i -lt $lines.Count - 1; $i++) {
            $kv = $lines[$i].Split("`t")
            if ($kv.Count -ne 2 -or $kv[0] -cne $known[$i - 1]) { Stop-Pilot 2 'refused: -Compare is not a compare output of a known format (COMPARE_FORMAT_UNKNOWN)' }
            if ($kv[0] -ceq 'roots') { continue }
            if ($kv[1] -ceq 'true' -or $kv[1] -ceq 'false') { $cmp[$kv[0]] = ($kv[1] -ceq 'true') }
            elseif ($kv[1] -cmatch '^[0-9]{1,9}$') { $cmp[$kv[0]] = [long]$kv[1] }
            else { Stop-Pilot 2 'refused: -Compare holds a value that is neither yes/no nor a count (COMPARE_FORMAT_UNKNOWN)' }
        }
        foreach ($k in @('onlyExpectedChange', 'expectedRemovedGiven', 'expectedRemovedFound')) { if (-not ($cmp[$k] -is [bool])) { Stop-Pilot 2 'refused: -Compare is not a compare output of a known format (COMPARE_FORMAT_UNKNOWN)' } }
    }

    # --- the fields (raw values; every one is checked below) ---
    $start = @(& $byType 'run-start') | Select-Object -First 1
    $confirm = @(& $byType 'confirmation') | Select-Object -Last 1
    $decl = @(& $byType 'declaration')
    $check = @(& $byType 'plan-check') | Select-Object -Last 1
    $ends = @(& $byType 'run-end') | Select-Object -Last 1
    $results = @(); $intents = @()
    if ($kind) { $results = @(& $byType $resultTypes[$kind]); $intents = @(& $byType $intentTypes[$kind]) }
    $skips = @(& $byType 'skip')
    $plans = @(& $byType 'plan')
    $interaction = Get-PilotProp $confirm 'interaction'
    $types = @($recs | ForEach-Object { Get-PilotProp $_ 'type' })
    $seq = @($recs | ForEach-Object { Get-PilotProp $_ 'recSeq' })
    $contig = $null; $oneRun = $null; $order = $null; $fullOrder = $null
    if ($recs.Count -gt 0) {
        $contig = $true; for ($i = 0; $i -lt $seq.Count; $i++) { if (-not (($seq[$i] -is [int] -or $seq[$i] -is [long]) -and $seq[$i] -eq $i + 1)) { $contig = $false } }
        $oneRun = (@($recs | ForEach-Object { [string](Get-PilotProp $_ $runFields[$kind]) } | Select-Object -Unique).Count -eq 1)
        $fullOrder = ((($types | ForEach-Object { [string]$_ }) -join ',') -ceq $fullRunOrder[$kind])
        # V5-P4, the deleting run of clean (the same order, kept for clean only).
        if ($kind -ceq 'clean') { $order = $fullOrder }
    }
    # Skip and plan-check reasons: each reduced to its leading code; B1_EXCEPTION_NEW_UNINSPECTABLE_PROCESS (N) also gives
    # N, the new identities of an F-A refusal. A reason with no leading code is kept whole, so it can only be refused.
    $newIdCounts = New-Object System.Collections.Generic.List[long]
    $reduce = {
        param($Rows)
        $out = New-Object System.Collections.Generic.List[object]
        foreach ($s in @($Rows)) {
            foreach ($why in @(Get-PilotProp $s 'reasons')) {
                if ($null -eq $why) { continue }
                $t = [string]$why
                if ($t -cmatch '^B1_EXCEPTION_NEW_UNINSPECTABLE_PROCESS \(([0-9]{1,9})\)$') { $out.Add('B1_EXCEPTION_NEW_UNINSPECTABLE_PROCESS'); $newIdCounts.Add([long]$Matches[1]) }
                elseif ($t -cmatch '^([A-Z][A-Z0-9_]*)(?=$|[\s:(])') { $out.Add($Matches[1]) }
                else { $out.Add($why) }
            }
        }
        return , $out.ToArray()
    }
    $reasonList = & $reduce $skips
    # The plan check of clean records what changed (counts.planCheckChanged); the others record reasons.
    $checkReasons = $null
    if ($kind -and $kind -cne 'clean') { $checkReasons = & $reduce @($check) }
    $newIds = $null
    if ($newIdCounts.Count -gt 0) { $newIds = [long]0; foreach ($x in $newIdCounts) { $newIds += $x } }
    $sumInts = {
        param($Rows, [string]$Name)
        if (@($Rows).Count -eq 0) { return $null }
        $t = [long]0
        foreach ($r in @($Rows)) { $v = Get-PilotProp $r $Name; if (-not ($v -is [int] -or $v -is [long])) { return $null }; $t += $v }
        return $t
    }
    # The bytes of the intents of the operations that ended COMPLETE (clean and purge: what the deleter was given).
    $completeBytes = {
        $ops = @($results | Where-Object { [string](Get-PilotProp $_ 'outcome') -ceq 'COMPLETE' } | ForEach-Object { [string](Get-PilotProp $_ 'opId') })
        if ($ops.Count -eq 0) { return $null }
        return (& $sumInts @($intents | Where-Object { $ops -ccontains [string](Get-PilotProp $_ 'opId') }) 'bytes')
    }
    # Isolate and restore: what the mover measured after a tree that moved (filesAfter, dirsAfter, bytesAfter); 0 when
    # none moved; null without a result.
    $movedSum = {
        param([string]$Name)
        if ($results.Count -eq 0) { return $null }
        $rows = @($results | Where-Object { (Get-PilotProp $_ 'moved') -is [bool] -and (Get-PilotProp $_ 'moved') })
        if ($rows.Count -eq 0) { return [long]0 }
        return (& $sumInts $rows $Name)
    }
    $isClean = ($kind -ceq 'clean'); $isIsolate = ($kind -ceq 'isolate'); $isRestore = ($kind -ceq 'restore'); $isPurge = ($kind -ceq 'purge')
    $gone = $null
    if ($isClean -or $isPurge -or -not $kind) { $gone = @(foreach ($r in $results) { $v = Get-PilotProp $r 'verifiedGone'; if ($v -is [bool]) { $(if ($v) { 'GONE' } else { 'PRESENT' }) } else { $v } }) }
    $consoleBy = Get-PilotProp $interaction 'observedBy'
    $accepted = Get-PilotProp $confirm 'accepted'
    # The B1 risk accepted: per declaration in clean; in the confirmation in isolate (it asks no declaration).
    $b1Rows = $(if ($isIsolate) { @(& $byType 'confirmation') } else { $decl })
    $lastDecl = $decl | Select-Object -Last 1
    # Lists of isolate and restore (null for the other kinds; an empty list stays a list).
    $changedFields = $null; $movedList = $null; $verifiedList = $null
    if ($isIsolate) { $changedFields = @(@(Get-PilotProp $check 'changedFields') | Where-Object { $null -ne $_ }) }
    if ($isIsolate -or $isRestore) { $movedList = @($results | ForEach-Object { Get-PilotProp $_ 'moved' }); $verifiedList = @($results | ForEach-Object { Get-PilotProp $_ 'verified' }) }
    $automatic = $null
    if ($isPurge) {
        # The manual purge writes automatic = false in its intent and its result; anything else is refused by its type.
        $autos = @(@($intents) + @($results) | ForEach-Object { Get-PilotProp $_ 'automatic' } | Where-Object { $null -ne $_ })
        if ($autos.Count -gt 0) { $automatic = $false; foreach ($a in $autos) { if (-not ($a -is [bool]) -or $a) { $automatic = $a; break } } }
    }

    Add-PilotField 'pinnedSha' 'sha40' $(if ($PinnedSha) { $PinnedSha } else { $null })
    Add-PilotField 'log.present' 'bool' (-not $NoLog)
    Add-PilotField 'log.kind' 'kind' $kind
    Add-PilotField 'log.fileAbsent' 'bool' $(if ($NoLog -and $LogFile) { -not [IO.File]::Exists($LogFile) } else { $null })
    Add-PilotField 'log.recordTypes' 'recordType' $types -List
    Add-PilotField 'log.fullRunOrder' 'bool' $fullOrder
    Add-PilotField 'log.deletingRunOrder' 'bool' $order
    Add-PilotField 'log.recSeqContiguous' 'bool' $contig
    Add-PilotField 'log.singleRun' 'bool' $oneRun
    Add-PilotField 'run.shownCode' 'stopCode' $(if ($ShownCode) { $ShownCode } else { $null })
    Add-PilotField 'run.exitCode' 'int' $exit
    Add-PilotField 'run.elevated' 'bool' (Get-PilotProp $start 'elevated')
    Add-PilotField 'run.b1Exception' 'bool' (Get-PilotProp $start 'b1Exception')
    Add-PilotField 'run.planned' 'int' (Get-PilotProp $start 'planned')
    Add-PilotField 'run.planCategories' 'category' @($plans | ForEach-Object { Get-PilotProp $_ 'category' }) -List
    Add-PilotField 'run.consoleBy' 'consoleBy' $consoleBy
    Add-PilotField 'run.caller' 'caller' (Get-PilotProp $interaction 'caller')
    Add-PilotField 'run.confirmationAccepted' 'bool' $accepted
    Add-PilotField 'run.refusalStep' 'step' $(if ($accepted -eq $false) { Get-PilotProp $confirm 'step' } else { $null })
    Add-PilotField 'run.refusalCode' 'stopCode' $(if ($accepted -eq $false) { Get-PilotProp $confirm 'refusal' } else { $null })
    Add-PilotField 'run.b1ResidualRiskAccepted' 'bool' @($b1Rows | ForEach-Object { Get-PilotProp $_ 'b1ResidualRiskAccepted' } | Where-Object { $null -ne $_ }) -List
    Add-PilotField 'run.contentDecisions' 'contentDecision' @($decl | ForEach-Object { Get-PilotProp $_ 'contentDecision' }) -List
    Add-PilotField 'run.declaredBy' 'declaredBy' $(if ($isPurge) { Get-PilotProp $lastDecl 'declaredBy' } else { $null })
    Add-PilotField 'run.verifiedByTool' 'bool' $(if ($isPurge) { Get-PilotProp (Get-PilotProp $lastDecl 'preservation') 'verifiedByTool' } else { $null })
    Add-PilotField 'run.automatic' 'falseOnly' $automatic
    Add-PilotField 'run.alternative' 'bool' $(if ($isRestore) { Get-PilotProp $start 'alternative' } else { $null })
    Add-PilotField 'run.reconcile' 'bool' $(if ($isRestore) { Get-PilotProp $start 'reconcile' } else { $null })
    Add-PilotField 'run.planCheckMatched' 'bool' (Get-PilotProp $check 'matched')
    Add-PilotField 'run.planCheckReasonCodes' 'reasonCode' $checkReasons -List
    Add-PilotField 'run.planCheckChangedFields' 'changedField' $changedFields -List
    Add-PilotField 'run.skipReasonCodes' 'reasonCode' $reasonList -List
    Add-PilotField 'run.outcomes' 'outcome' @($results | ForEach-Object { Get-PilotProp $_ 'outcome' }) -List
    Add-PilotField 'run.moved' 'bool' $movedList -List
    Add-PilotField 'run.verified' 'bool' $verifiedList -List
    Add-PilotField 'run.verifiedGone' 'verifiedGone' $gone -List
    Add-PilotField 'run.stoppedBy' 'stopCode' (Get-PilotProp $ends 'stoppedBy')
    Add-PilotField 'counts.uninspectableProcesses' 'int' (Get-PilotProp $start 'uninspectableProcesses')
    Add-PilotField 'counts.newUninspectableIdentities' 'int' $newIds
    Add-PilotField 'counts.planCheckChanged' 'int' $(if ($isClean -and $null -ne $check) { [long]@(Get-PilotProp $check 'changed').Count } else { $null })
    Add-PilotField 'counts.filesDeleted' 'int' $(if ($isClean) { & $sumInts $results 'filesDeleted' } else { $null })
    Add-PilotField 'counts.dirsDeleted' 'int' $(if ($isClean) { & $sumInts $results 'dirsDeleted' } else { $null })
    Add-PilotField 'counts.bytesDeleted' 'int' $(if ($isClean) { & $completeBytes } else { $null })
    Add-PilotField 'counts.filesMoved' 'int' $(if ($isIsolate) { & $movedSum 'filesAfter' } else { $null })
    Add-PilotField 'counts.dirsMoved' 'int' $(if ($isIsolate) { & $movedSum 'dirsAfter' } else { $null })
    Add-PilotField 'counts.bytesMoved' 'int' $(if ($isIsolate) { & $movedSum 'bytesAfter' } else { $null })
    Add-PilotField 'counts.filesRestored' 'int' $(if ($isRestore) { & $movedSum 'filesAfter' } else { $null })
    Add-PilotField 'counts.dirsRestored' 'int' $(if ($isRestore) { & $movedSum 'dirsAfter' } else { $null })
    Add-PilotField 'counts.bytesRestored' 'int' $(if ($isRestore) { & $movedSum 'bytesAfter' } else { $null })
    Add-PilotField 'counts.filesPurged' 'int' $(if ($isPurge) { & $sumInts $results 'filesDeleted' } else { $null })
    Add-PilotField 'counts.dirsPurged' 'int' $(if ($isPurge) { & $sumInts $results 'dirsDeleted' } else { $null })
    Add-PilotField 'counts.bytesPurged' 'int' $(if ($isPurge) { & $completeBytes } else { $null })
    Add-PilotField 'counts.results' 'int' (Get-PilotProp $ends 'results')
    Add-PilotField 'counts.complete' 'int' (Get-PilotProp $ends 'complete')
    Add-PilotField 'counts.skipped' 'int' (Get-PilotProp $ends 'skipped')
    Add-PilotField 'compare.given' 'bool' ($null -ne $cmp)
    foreach ($k in @('onlyExpectedChange', 'expectedRemovedGiven', 'expectedRemovedFound')) { Add-PilotField "compare.$k" 'bool' $(if ($null -ne $cmp) { $cmp[$k] } else { $null }) }
    foreach ($k in @('expectedNewPatterns', 'expectedTouchedPatterns', 'removed.expected', 'removed.unexpected', 'new.expected', 'new.unexpected', 'changed.expected',
            'changed.unexpected', 'touched.expected', 'unchanged.expected', 'unchanged.unexpected', 'rootsChanged.expected', 'rootsChanged.unexpected')) { Add-PilotField "compare.$k" 'int' $(if ($null -ne $cmp) { $cmp[$k] } else { $null }) }
    # ADR-0015 section 6: the yes/no answers. Null when the log (or the compare) cannot answer; the operator marks those.
    Add-PilotField 'checks.changedOutsideRoot' 'bool' $(if ($null -ne $cmp) { -not $cmp['onlyExpectedChange'] } else { $null })
    Add-PilotField 'checks.consoleByEngineCheck' 'bool' $(if ($consoleBy -is [string]) { $consoleBy -ceq 'ENGINE_CONSOLE_CHECK' } else { $null })
    Add-PilotField 'checks.checkoutDiffersByGateLineOnly' 'bool' $null
    Add-PilotField 'checks.guestClockWithinSecondsOfHost' 'bool' $null
    Add-PilotField 'checks.networkDisconnectedAtDeletingRun' 'bool' $null

    # --- every value checked: privacy rule first, then its type ---
    $bad = New-Object System.Collections.Generic.List[object]
    foreach ($f in $fields) {
        # A one-value field stays whole: an array there is checked as one value, so it fails its type and is refused.
        if ($f.List) { $vals = @($f.Value) } else { $vals = @(, $f.Value) }
        $i = 0
        foreach ($v in $vals) {
            $nm = $(if ($f.List) { "$($f.Name)[$i]" } else { $f.Name })
            $i++
            if ($null -eq $v) { continue }
            $rule = Get-PilotDenyRule $v
            if (-not $rule -and -not (Test-PilotType $v $f.Type)) { $rule = 'NOT_OF_TYPE_' + $f.Type }
            if ($rule) { $bad.Add([pscustomobject]@{ Name = $nm; Rule = $rule }) }
        }
    }
    $id = [guid]::NewGuid().ToString('N').Substring(0, 8)
    $tmpLeaf = "$outLeaf.$id.REFUSED"
    $tmp = Join-Path $outDir $tmpLeaf
    if ($bad.Count -gt 0) {
        $t = "atm-pilot-summary-refused`t1`r`nreason`tVALUE_REFUSED`r`n" + (($bad | ForEach-Object { "field`t$($_.Name)`t$($_.Rule)" }) -join "`r`n") + "`r`nend`trefused`r`n"
        Write-PilotNewFile -Path $tmp -Text $t
        foreach ($b in $bad) { Write-Host "refused: field $($b.Name) ($($b.Rule)); the value is not shown" -ForegroundColor Red }
        Stop-Pilot 3 "no summary written; $tmpLeaf names the refused fields (never the values); discarding it is the operator's"
    }

    # --- the summary: typed values only ---
    $doc = [ordered]@{ schema = 'atm-pilot-summary-2' }
    foreach ($f in $fields) {
        $parts = $f.Name.Split('.', 2)
        $v = $f.Value
        # A list field that does not apply to the kind is null, not a list.
        if ($f.List -and $null -ne $v) { $v = [object[]]@(@($v) | ForEach-Object { if ($_ -is [int]) { [long]$_ } else { $_ } }) } elseif ($v -is [int]) { $v = [long]$v }
        if ($parts.Count -eq 1) { $doc[$parts[0]] = $v; continue }
        if (-not $doc.Contains($parts[0])) { $doc[$parts[0]] = [ordered]@{} }
        $doc[$parts[0]][$parts[1]] = $v
    }
    Write-PilotNewFile -Path $tmp -Text ((ConvertTo-Json -InputObject $doc -Depth 5) + "`r`n")

    # --- the repository's privacy scanner on the folder of -Out; only findings in this file count ---
    $hits = $null
    try {
        $sw = $null
        $hits = @(& $scanner -Path $outDir -NeedlesFile $NeedlesFile -WarningAction SilentlyContinue -WarningVariable sw | Where-Object { [string]$_.File -ceq $tmpLeaf })
        foreach ($w in @($sw)) { Write-Host ('scanner warning: ' + [string]$w) -ForegroundColor Yellow }
    } catch {
        Stop-Pilot 5 "the privacy scanner could not run ($($_.Exception.GetBaseException().GetType().Name)); the summary stays as $tmpLeaf and must not leave the VM"
    }
    if ($hits.Count -gt 0) {
        foreach ($h in $hits) { Write-Host "privacy finding: line $($h.Line) $($h.Kind)" -ForegroundColor Red }
        Stop-Pilot 4 "the privacy scanner found $($hits.Count) item(s); the summary stays as $tmpLeaf and must not leave the VM"
    }
    try { [IO.File]::Move($tmp, $outFull) } catch { Stop-Pilot 5 "the summary passed the scanner but could not get its final name; it stays as $tmpLeaf" }
    Stop-Pilot 0 "summary written ($($fields.Count) fields); the privacy scanner found nothing in it"
} catch {
    Write-Host ('failed: ' + $_.Exception.GetBaseException().GetType().Name) -ForegroundColor Red
    exit 6
}
