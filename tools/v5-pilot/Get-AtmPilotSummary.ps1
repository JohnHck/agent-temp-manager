<#
.SYNOPSIS
  V5 pilot evidence tool (ADR-0015, sections 6 and 7; decision V5-D7 (a)): reads the T1 log of one clean run (and,
  optionally, the output of Compare-AtmPilotSnapshot.ps1) and writes the only evidence that may leave the pilot VM:
  record types, codes, counts and yes/no. Never a path, a SID, an account, a machine name or any free text.
.DESCRIPTION
  Allow list, not deny list: every output field has a fixed type (a code from a known list, a non-negative integer, a
  yes/no, the 40-hex pinned SHA). Before anything is written, every value is checked:
  * refused when it holds a path separator ('\' or '/'), 'S-1-', '@', or equals (ignoring case) USERNAME, COMPUTERNAME,
    USERDOMAIN or a part of USERPROFILE of this environment;
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
  the lock before any log is opened) are summarized with -NoLog and the code and exit code the console showed
  (-ShownCode, -ExitCode); with -LogFile too, the summary records whether that file is absent.
  It does not load the product's engine and never uses the network. Read only, except the two files named above.
.PARAMETER LogFile
  The T1 log of the run (JSON Lines, schema atm.cleanlog/1). Required unless -NoLog.
.PARAMETER NoLog
  The run wrote no log. Needs -ShownCode or -ExitCode.
.PARAMETER ShownCode
  The code the console showed (for example CLEAN_LOCK_BUSY), typed by the operator; checked like any value.
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
  2  refused before writing anything: parameters, a missing or malformed log or compare file, an unknown log schema,
     -Out exists, its folder or the scanner is missing.
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

# --- the types (closed lists of the codes the clean engine writes in its T1 log and shows on the console) ---
$recordTypes = @('run-start', 'plan', 'declaration', 'confirmation', 'plan-check', 'skip', 'intent', 'result', 'run-end')
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
$enums = @{
    recordType = $recordTypes
    stopCode = $stopCodes
    reasonCode = $reasonCodes
    outcome = @('COMPLETE', 'PARTIAL', 'REFUSED', 'VERIFICATION_FAILED', 'EXCEPTION')
    verifiedGone = @('GONE', 'PRESENT', 'UNKNOWN')
    consoleBy = @('ENGINE_CONSOLE_CHECK', 'TEST_SEAM')
    caller = @('CLI', 'TUI', 'DIRECT_CALL')
    step = @('task', 'results', 'risk', 'confirm')
    contentDecision = @('RESULTS_PRESERVED', 'NOTHING_NEEDED')
    category = @('ELIGIBLE', 'ELIGIBLE_WITH_DECLARED_RISK')
}

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
    return $null
}

function Test-PilotType {
    param($Value, [string]$Type)
    switch -CaseSensitive ($Type) {
        'bool' { return ($Value -is [bool]) }
        'int' { return (($Value -is [int] -or $Value -is [long]) -and $Value -ge 0) }
        'sha40' { return ($Value -is [string] -and $Value -cmatch '^[0-9a-f]{40}$') }
        'stopCode' { return ($Value -is [string] -and ($stopCodes -ccontains $Value -or $Value -cmatch $stopFamilies)) }
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

    # --- the T1 log (JSON Lines, one record per line: schema, type, runId, recSeq, utc, then the record's fields) ---
    $recs = New-Object System.Collections.Generic.List[object]
    if (-not $NoLog) {
        $fs = New-Object IO.FileStream($LogFile, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        $sr = New-Object IO.StreamReader($fs, (New-Object System.Text.UTF8Encoding($false)))
        try {
            $n = 0
            while ($null -ne ($line = $sr.ReadLine())) {
                $n++
                if ($line.Trim() -eq '') { continue }
                $r = $null
                try { $r = $line | ConvertFrom-Json } catch { Stop-Pilot 2 "refused: line $n of the log is not a JSON record (LOG_LINE_INVALID)" }
                if ([string](Get-PilotProp $r 'schema') -cne 'atm.cleanlog/1') { Stop-Pilot 2 "refused: line $n of the log is not of the known schema (LOG_SCHEMA_UNKNOWN)" }
                $recs.Add($r)
            }
        } finally { $sr.Dispose(); $fs.Dispose() }
        if ($recs.Count -eq 0) { Stop-Pilot 2 'refused: the log has no record (LOG_EMPTY)' }
    }
    $byType = { param([string]$T) @($recs | Where-Object { [string](Get-PilotProp $_ 'type') -ceq $T }) }

    # --- the compare output (only onlyExpectedChange and the counts) ---
    $cmp = $null
    if ($Compare) {
        $cmp = [ordered]@{}
        $known = @('onlyExpectedChange', 'roots', 'expectedRemovedGiven', 'expectedRemovedFound', 'expectedNewPatterns', 'removed.expected', 'removed.unexpected',
            'new.expected', 'new.unexpected', 'changed.expected', 'changed.unexpected', 'unchanged.expected', 'unchanged.unexpected', 'rootsChanged.expected', 'rootsChanged.unexpected')
        $lines = @([IO.File]::ReadAllLines($Compare) | Where-Object { $_ -ne '' })
        if ($lines.Count -ne $known.Count + 2 -or $lines[0] -cne "atm-pilot-compare`t1" -or $lines[$lines.Count - 1] -cne "end`tcompare") { Stop-Pilot 2 'refused: -Compare is not a compare output of a known format (COMPARE_FORMAT_UNKNOWN)' }
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
    $results = @(& $byType 'result')
    $intents = @(& $byType 'intent')
    $skips = @(& $byType 'skip')
    $plans = @(& $byType 'plan')
    $interaction = Get-PilotProp $confirm 'interaction'
    $types = @($recs | ForEach-Object { Get-PilotProp $_ 'type' })
    $seq = @($recs | ForEach-Object { Get-PilotProp $_ 'recSeq' })
    $contig = $null; $oneRun = $null; $order = $null
    if ($recs.Count -gt 0) {
        $contig = $true; for ($i = 0; $i -lt $seq.Count; $i++) { if (-not (($seq[$i] -is [int] -or $seq[$i] -is [long]) -and $seq[$i] -eq $i + 1)) { $contig = $false } }
        $oneRun = (@($recs | ForEach-Object { [string](Get-PilotProp $_ 'runId') } | Select-Object -Unique).Count -eq 1)
        $order = ((($types | ForEach-Object { [string]$_ }) -join ',') -ceq 'run-start,plan,declaration,confirmation,plan-check,intent,result,run-end')
    }
    # Skip reasons: each reduced to its leading code; B1_EXCEPTION_NEW_UNINSPECTABLE_PROCESS (N) also gives N, the new
    # identities of an F-A refusal. A reason with no leading code is kept whole, so it can only be refused.
    $reasonList = New-Object System.Collections.Generic.List[object]
    $newIds = $null
    foreach ($s in $skips) {
        foreach ($why in @(Get-PilotProp $s 'reasons')) {
            $t = [string]$why
            if ($t -cmatch '^B1_EXCEPTION_NEW_UNINSPECTABLE_PROCESS \(([0-9]{1,9})\)$') { $reasonList.Add('B1_EXCEPTION_NEW_UNINSPECTABLE_PROCESS'); $newIds = $(if ($null -eq $newIds) { 0 } else { $newIds }) + [long]$Matches[1] }
            elseif ($t -cmatch '^([A-Z][A-Z0-9_]*)(?=$|[\s:(])') { $reasonList.Add($Matches[1]) }
            else { $reasonList.Add($why) }
        }
    }
    $sumInts = {
        param($Rows, [string]$Name)
        if (@($Rows).Count -eq 0) { return $null }
        $t = [long]0
        foreach ($r in @($Rows)) { $v = Get-PilotProp $r $Name; if (-not ($v -is [int] -or $v -is [long])) { return $null }; $t += $v }
        return $t
    }
    $completeOps = @($results | Where-Object { [string](Get-PilotProp $_ 'outcome') -ceq 'COMPLETE' } | ForEach-Object { [string](Get-PilotProp $_ 'opId') })
    $bytes = $null
    if ($completeOps.Count -gt 0) { $bytes = & $sumInts @($intents | Where-Object { $completeOps -ccontains [string](Get-PilotProp $_ 'opId') }) 'bytes' }
    $gone = @(foreach ($r in $results) { $v = Get-PilotProp $r 'verifiedGone'; if ($v -is [bool]) { $(if ($v) { 'GONE' } else { 'PRESENT' }) } else { $v } })
    $consoleBy = Get-PilotProp $interaction 'observedBy'
    $accepted = Get-PilotProp $confirm 'accepted'

    Add-PilotField 'pinnedSha' 'sha40' $(if ($PinnedSha) { $PinnedSha } else { $null })
    Add-PilotField 'log.present' 'bool' (-not $NoLog)
    Add-PilotField 'log.fileAbsent' 'bool' $(if ($NoLog -and $LogFile) { -not [IO.File]::Exists($LogFile) } else { $null })
    Add-PilotField 'log.recordTypes' 'recordType' $types -List
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
    Add-PilotField 'run.b1ResidualRiskAccepted' 'bool' @($decl | ForEach-Object { Get-PilotProp $_ 'b1ResidualRiskAccepted' }) -List
    Add-PilotField 'run.contentDecisions' 'contentDecision' @($decl | ForEach-Object { Get-PilotProp $_ 'contentDecision' }) -List
    Add-PilotField 'run.planCheckMatched' 'bool' (Get-PilotProp $check 'matched')
    Add-PilotField 'run.skipReasonCodes' 'reasonCode' $reasonList.ToArray() -List
    Add-PilotField 'run.outcomes' 'outcome' @($results | ForEach-Object { Get-PilotProp $_ 'outcome' }) -List
    Add-PilotField 'run.verifiedGone' 'verifiedGone' $gone -List
    Add-PilotField 'run.stoppedBy' 'stopCode' (Get-PilotProp $ends 'stoppedBy')
    Add-PilotField 'counts.uninspectableProcesses' 'int' (Get-PilotProp $start 'uninspectableProcesses')
    Add-PilotField 'counts.newUninspectableIdentities' 'int' $newIds
    Add-PilotField 'counts.planCheckChanged' 'int' $(if ($null -ne $check) { [long]@(Get-PilotProp $check 'changed').Count } else { $null })
    Add-PilotField 'counts.filesDeleted' 'int' (& $sumInts $results 'filesDeleted')
    Add-PilotField 'counts.dirsDeleted' 'int' (& $sumInts $results 'dirsDeleted')
    Add-PilotField 'counts.bytesDeleted' 'int' $bytes
    Add-PilotField 'counts.results' 'int' (Get-PilotProp $ends 'results')
    Add-PilotField 'counts.complete' 'int' (Get-PilotProp $ends 'complete')
    Add-PilotField 'counts.skipped' 'int' (Get-PilotProp $ends 'skipped')
    Add-PilotField 'compare.given' 'bool' ($null -ne $cmp)
    foreach ($k in @('onlyExpectedChange', 'expectedRemovedGiven', 'expectedRemovedFound')) { Add-PilotField "compare.$k" 'bool' $(if ($null -ne $cmp) { $cmp[$k] } else { $null }) }
    foreach ($k in @('expectedNewPatterns', 'removed.expected', 'removed.unexpected', 'new.expected', 'new.unexpected', 'changed.expected', 'changed.unexpected', 'unchanged.expected',
            'unchanged.unexpected', 'rootsChanged.expected', 'rootsChanged.unexpected')) { Add-PilotField "compare.$k" 'int' $(if ($null -ne $cmp) { $cmp[$k] } else { $null }) }
    # ADR-0015 section 6: the yes/no answers. Null when the log (or the compare) cannot answer; the operator marks those.
    Add-PilotField 'checks.changedOutsideRoot' 'bool' $(if ($null -ne $cmp) { -not $cmp['onlyExpectedChange'] } else { $null })
    Add-PilotField 'checks.consoleByEngineCheck' 'bool' $(if ($consoleBy -is [string]) { $consoleBy -ceq 'ENGINE_CONSOLE_CHECK' } else { $null })
    Add-PilotField 'checks.checkoutDiffersByGateLineOnly' 'bool' $null
    Add-PilotField 'checks.guestClockWithinSecondsOfHost' 'bool' $null
    Add-PilotField 'checks.networkDisconnectedAtDeletingRun' 'bool' $null

    # --- every value checked: privacy rule first, then its type ---
    $bad = New-Object System.Collections.Generic.List[object]
    foreach ($f in $fields) {
        $vals = $(if ($f.List) { @($f.Value) } else { @(, $f.Value) })
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
    $doc = [ordered]@{ schema = 'atm-pilot-summary-1' }
    foreach ($f in $fields) {
        $parts = $f.Name.Split('.', 2)
        $v = $f.Value
        if ($f.List) { $v = [object[]]@(@($v) | ForEach-Object { if ($_ -is [int]) { [long]$_ } else { $_ } }) } elseif ($v -is [int]) { $v = [long]$v }
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
