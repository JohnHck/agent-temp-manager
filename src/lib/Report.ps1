# AgentTempManager CLI REPORT (presentation only). Never prints command lines, tokens or file contents.
# All user-facing text comes from the message catalog (I18n.ps1). Reason/flag/class/status CODES are stable,
# language-neutral identifiers and are printed as-is.
Set-StrictMode -Version 2.0

function Format-AtmMB { param([long]$B) return [math]::Round($B / 1MB, 2) }
function Format-AtmGB { param([long]$B) return [math]::Round($B / 1GB, 3) }
function Format-AtmTime { param($Utc) if (-not $Utc) { return '-' } return ([datetime]$Utc).ToLocalTime().ToString('yyyy-MM-dd HH:mm') }

function Write-AtmHeader {
    param([string]$Text)
    Write-Host ''
    Write-Host ('=' * 100) -ForegroundColor DarkCyan
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host ('=' * 100) -ForegroundColor DarkCyan
}

function New-AtmRow {
    # Builds a table row whose column names come from the catalog (keys 'col.*').
    param([System.Collections.Specialized.OrderedDictionary]$Cells)
    $o = [ordered]@{}
    foreach ($k in $Cells.Keys) { $o[(Get-AtmText $k)] = $Cells[$k] }
    return [pscustomobject]$o
}

function Write-AtmTable {
    param($Rows)
    $r = @($Rows)
    if ($r.Count -eq 0) { Write-Host ('  ' + (Get-AtmText 'common.none')); return }
    $txt = $r | Format-Table -AutoSize -Wrap | Out-String -Width 4096
    Write-Host ($txt.TrimEnd())
}

function Get-AtmSum {
    param($Items, [string]$Prop)
    $s = 0L
    foreach ($i in @($Items)) { if ($null -ne $i) { $s += [long]$i.$Prop } }
    return $s
}

function Get-AtmYesNo { param([bool]$Value, [switch]$Upper) if ($Upper) { if ($Value) { Get-AtmText 'common.yesUpper' } else { Get-AtmText 'common.noUpper' } } else { if ($Value) { Get-AtmText 'common.yes' } else { Get-AtmText 'common.no' } } }

function Select-AtmPartitions {
    # Display filters for drill-down. They never change what was measured.
    param($Inventory, [string]$User, [string]$Project, [string]$Root)
    $p = @($Inventory.Partitions | Where-Object { $_.Kind -ne 'NotScanned' })
    if ($User) { $p = @($p | Where-Object { $_.UserName -like "*$User*" -or $_.Sid -eq $User }) }
    if ($Project) { $p = @($p | Where-Object { $_.Project -like "*$Project*" -or $_.Slug -like "*$Project*" }) }
    if ($Root) { $p = @($p | Where-Object { $_.Name -eq $Root -or [string]::Equals($_.Path, $Root, [StringComparison]::OrdinalIgnoreCase) }) }
    return $p
}

function Get-AtmProfileStatusLabel {
    # Returns a stable status CODE; Get-AtmStatusText renders it in the current language.
    param($Inventory, [Alias('Profile')]$ProfileInfo)
    $sts = @($Inventory.ProfileBaseStatus[$ProfileInfo.Sid + '|' + $ProfileInfo.ProfilePath])
    $unreadable = @(Get-AtmProfileRegistries -Registries $Inventory.Registries -ProfileInfo $ProfileInfo | Where-Object { -not $_.Readable }).Count
    $bases = @($Inventory.Bases | Where-Object { $_.Sid -eq $ProfileInfo.Sid -and $_.Profile.ProfilePath -eq $ProfileInfo.ProfilePath })
    $tempUnverified = (@($Inventory.PSObject.Properties.Name) -contains 'UnverifiedTempProfiles') -and (@($Inventory.UnverifiedTempProfiles) -contains $ProfileInfo)
    if (@($bases | Where-Object { $_.Status -eq 'OK' }).Count -gt 0) {
        if (@($sts | Where-Object { $_.Status -in @('INACCESSIBLE', 'INVALID') }).Count -gt 0 -or @($bases | Where-Object { $_.Status -eq 'ENUMERATION_FAILED' }).Count -gt 0 -or $unreadable -gt 0 -or $tempUnverified) { return 'AUDITADO_PARCIAL' }
        return 'AUDITADO'
    }
    if ($tempUnverified -and @($sts | Where-Object { $_.Status -ne 'NOT_FOUND' }).Count -eq 0) { return 'TEMP_NAO_VERIFICAVEL' }
    if (@($sts | Where-Object { $_.Status -in @('INACCESSIBLE', 'ENUMERATION_FAILED', 'INVALID') }).Count -gt 0 -or @($bases | Where-Object { $_.Status -eq 'ENUMERATION_FAILED' }).Count -gt 0) { return 'INACESSIVEL' }
    if (@($sts | Where-Object { $_.Status -eq 'REPARSE_IN_PATH' }).Count -gt 0) { return 'NAO_AUDITADO_REPARSE' }
    if (@($sts | Where-Object { $_.Status -eq 'UNSUPPORTED_DRIVE' }).Count -gt 0) { return 'NAO_AUDITADO_UNIDADE' }
    return 'SEM_TEMP_CLAUDE'
}

function Get-AtmStatusText { param([string]$Code) return (Get-AtmText "status.$Code") }

function Show-AtmAudit {
    param($Inventory, [string]$User, [string]$Project, [string]$Root)
    $inv = $Inventory
    $all = @($inv.Partitions | Where-Object { $_.Kind -ne 'NotScanned' })
    $sel = Select-AtmPartitions -Inventory $inv -User $User -Project $Project -Root $Root
    $filtered = [bool]($User -or $Project -or $Root)

    # 1. General summary: exclusive partitions only.
    Write-AtmHeader (Get-AtmText 'audit.s1')
    $bytes = Get-AtmSum $all 'Bytes'
    Write-Host (Get-AtmText 'audit.runBy' $inv.Identity.Name $inv.Identity.Sid (Get-AtmYesNo $inv.Identity.IsAdmin -Upper))
    Write-Host (Get-AtmText 'audit.startEnd' (Format-AtmTime $inv.StartedUtc) (Format-AtmTime $inv.FinishedUtc))
    Write-Host (Get-AtmText 'audit.providers' ((@($inv.Providers) | ForEach-Object { "$($_.DisplayName) [<TEMP>\$($_.TempSubdir)]" }) -join ', '))
    Write-Host (Get-AtmText 'audit.profiles' @($inv.Profiles).Count @($inv.Bases | Where-Object { $_.Status -eq 'OK' }).Count)
    Write-Host (Get-AtmText 'audit.partitions' $all.Count)
    Write-Host (Get-AtmText 'audit.logical' $bytes (Format-AtmMB $bytes) (Format-AtmGB $bytes))
    $alloc = Get-AtmSum $all 'AllocatedBytesEstimate'
    Write-Host (Get-AtmText 'audit.physical' $alloc (Format-AtmMB $alloc) (Format-AtmGB $alloc))
    Write-Host (Get-AtmText 'audit.filesDirs' (Get-AtmSum $all 'Files') (Get-AtmSum $all 'Dirs'))
    Write-Host (Get-AtmText 'audit.reparseErrors' (Get-AtmSum $all 'ReparsePoints') (Get-AtmSum $all 'ErrorCount') @($all | Where-Object { -not $_.MeasurementComplete }).Count)
    $cls = $all | Group-Object Class | Sort-Object Name | ForEach-Object { New-AtmRow ([ordered]@{ 'col.class' = $_.Name; 'col.partitions' = $_.Count; 'col.files' = (Get-AtmSum $_.Group 'Files'); 'col.mb' = (Format-AtmMB (Get-AtmSum $_.Group 'Bytes')); 'col.gb' = (Format-AtmGB (Get-AtmSum $_.Group 'Bytes')) }) }
    Write-AtmTable $cls
    $cov = $(if ($inv.CoverageComplete) { Get-AtmText 'common.complete' } else { Get-AtmText 'audit.coverageIncompleteSee' })
    Write-Host (Get-AtmText 'audit.coverage' $cov) -ForegroundColor $(if ($inv.CoverageComplete) { 'Green' } else { 'Yellow' })
    if ($filtered) { Write-Host (Get-AtmText 'audit.filter' $User $Project $Root $sel.Count) -ForegroundColor Yellow }

    # 2. Per user / SID
    Write-AtmHeader (Get-AtmText 'audit.s2')
    $rows = foreach ($pr in $inv.Profiles) {
        $pp = @($all | Where-Object { $_.Sid -eq $pr.Sid -and $_.ProfilePath -eq $pr.ProfilePath })
        New-AtmRow ([ordered]@{
                'col.user' = $pr.UserName; 'col.sid' = $pr.Sid; 'col.profile' = $pr.ProfilePath; 'col.origin' = $pr.Origin; 'col.loaded' = (Get-AtmYesNo $pr.Loaded)
                'col.status' = (Get-AtmStatusText (Get-AtmProfileStatusLabel -Inventory $inv -ProfileInfo $pr))
                'col.roots' = $pp.Count; 'col.files' = (Get-AtmSum $pp 'Files'); 'col.dirs' = (Get-AtmSum $pp 'Dirs'); 'col.mb' = (Format-AtmMB (Get-AtmSum $pp 'Bytes')); 'col.gb' = (Format-AtmGB (Get-AtmSum $pp 'Bytes'))
                'col.active' = @($pp | Where-Object { $_.Class -eq 'ACTIVE_EVIDENCE' }).Count; 'col.recent' = @($pp | Where-Object { $_.Class -eq 'RECENT' }).Count
                'col.unknown' = @($pp | Where-Object { $_.Class -eq 'LIVENESS_UNKNOWN' }).Count; 'col.orphan' = @($pp | Where-Object { $_.Class -eq 'ORPHAN_SUSPECTED' }).Count
            })
    }
    Write-AtmTable $rows
    Write-Host ('  ' + (Get-AtmText 'audit.tempDirs'))
    $trows = foreach ($pr in $inv.Profiles) {
        foreach ($s in @($inv.ProfileBaseStatus[$pr.Sid + '|' + $pr.ProfilePath])) {
            New-AtmRow ([ordered]@{ 'col.user' = $pr.UserName; 'col.agent' = $s.Provider; 'col.base' = $s.BasePath; 'col.origin' = $s.Source; 'col.status' = $s.Status })
        }
    }
    Write-AtmTable $trows

    # 3. Per project (unidentified projects are never merged: grouped by scope directory)
    Write-AtmHeader (Get-AtmText 'audit.s3')
    $prow = $sel | Group-Object { $_.Project + '|' + $(if ($_.ProjectIdentified) { '' } else { $_.Slug }) + '|' + $_.UserName } | ForEach-Object {
        $g = $_.Group
        $newest = ($g | Where-Object { $_.NewestWriteTimeUtc } | Sort-Object NewestWriteTimeUtc -Descending | Select-Object -First 1)
        [pscustomobject]@{ Sort = (Get-AtmSum $g 'Bytes'); Row = (New-AtmRow ([ordered]@{ 'col.project' = $g[0].Project; 'col.scope' = $(if ($g[0].ProjectIdentified) { '-' } else { $g[0].Slug }); 'col.source' = $g[0].ProjectSource; 'col.user' = $g[0].UserName; 'col.roots' = $g.Count; 'col.files' = (Get-AtmSum $g 'Files'); 'col.dirs' = (Get-AtmSum $g 'Dirs')
                        'col.mb' = (Format-AtmMB (Get-AtmSum $g 'Bytes')); 'col.gb' = (Format-AtmGB (Get-AtmSum $g 'Bytes')); 'col.newest' = $(if ($newest) { Format-AtmTime $newest.NewestWriteTimeUtc } else { '-' }) })) }
    } | Sort-Object Sort -Descending | ForEach-Object { $_.Row }
    Write-AtmTable $prow

    # 4. Per direct root
    Write-AtmHeader (Get-AtmText 'audit.s4')
    $rrow = $sel | Sort-Object UserName, Project, Slug, Name | ForEach-Object {
        New-AtmRow ([ordered]@{
                'col.agent' = $_.Provider; 'col.user' = $_.UserName; 'col.project' = $_.Project; 'col.root' = $(if ($_.Slug) { $_.Slug + '\' + $_.Name } else { $_.Name }); 'col.kind' = $_.Kind; 'col.class' = $_.Class
                'col.created' = (Format-AtmTime $_.CreationTimeUtc); 'col.modified' = (Format-AtmTime $_.LastWriteTimeUtc); 'col.newest' = (Format-AtmTime $_.NewestWriteTimeUtc)
                'col.filesShort' = $_.Files; 'col.dirs' = $_.Dirs; 'col.children' = $_.DirectChildren; 'col.mb' = (Format-AtmMB $_.Bytes); 'col.complete' = (Get-AtmYesNo $_.MeasurementComplete)
                'col.flags' = ($_.Flags -join ',')
            })
    }
    Write-AtmTable $rrow
    $ev = @($sel | Where-Object { $_.Evidence.Count -gt 0 })
    if ($ev.Count -gt 0) {
        Write-Host ('  ' + (Get-AtmText 'audit.evidence'))
        foreach ($e in $ev) { foreach ($x in $e.Evidence) { Write-Host ("   - {0}\{1}: {2}" -f $e.Slug, $e.Name, $x) } }
    }

    # 5. LIVENESS_UNKNOWN > 72h
    Write-AtmHeader (Get-AtmText 'audit.s5' $inv.RecentHours)
    $lu = $sel | Where-Object { $_.Class -eq 'LIVENESS_UNKNOWN' -and $_.NewestWriteTimeUtc -and (($inv.NowUtc - $_.NewestWriteTimeUtc).TotalHours -ge $inv.RecentHours) } | ForEach-Object {
        New-AtmRow ([ordered]@{ 'col.user' = $_.UserName; 'col.project' = $_.Project; 'col.path' = $_.Path; 'col.newest' = (Format-AtmTime $_.NewestWriteTimeUtc); 'col.mb' = (Format-AtmMB $_.Bytes); 'col.reasons' = ($_.Flags -join ',') })
    }
    Write-AtmTable $lu
    Write-Host ('  ' + (Get-AtmText 'audit.ageNotProof')) -ForegroundColor DarkYellow

    # 6. Errors, ambiguities, coverage
    Write-AtmHeader (Get-AtmText 'audit.s6')
    $s = $inv.Snapshot
    if ($s.Failed) { Write-Host ('  ' + (Get-AtmText 'audit.procFailed' $s.Error)) -ForegroundColor Red }
    else {
        Write-Host ('  ' + (Get-AtmText 'audit.procSummary' $s.Total $s.Readable $s.Uninspectable @($inv.SelfPids).Count))
        if ($s.Uninspectable -gt 0) {
            $names = ($s.UninspectableByName.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { "$($_.Key) x$($_.Value)" }) -join ', '
            Write-Host ('  ' + (Get-AtmText 'audit.uninspectable' $names)) -ForegroundColor DarkYellow
            Write-Host ('  ' + (Get-AtmText 'audit.absenceNotProof')) -ForegroundColor DarkYellow
        }
    }
    Write-Host ('  ' + (Get-AtmText 'audit.references' $inv.References.Direct $inv.References.Ancestor $inv.References.Ambiguous $inv.References.Unresolved.Count))
    foreach ($u in $inv.References.Unresolved) { Write-Host "   - $u" }
    foreach ($pr in $inv.Profiles) {
        foreach ($reg in @(Get-AtmProfileRegistries -Registries $inv.Registries -ProfileInfo $pr)) {
            $live = @($reg.Entries | Where-Object { $_.State -eq 'LIVE' }).Count
            Write-Host ('  ' + (Get-AtmText 'audit.registry' $reg.Provider $pr.UserName $(if ($reg.Readable) { Get-AtmText 'audit.readable' } else { Get-AtmText 'audit.unreadable' }) @($reg.Entries).Count $live $reg.Unparseable))
        }
    }
    if (@($inv.InaccessibleProfiles).Count -gt 0) {
        Write-Host ('  ' + (Get-AtmText 'audit.incompleteProfiles')) -ForegroundColor Yellow
        foreach ($pr in $inv.InaccessibleProfiles) { Write-Host ("   - {0} ({1}) {2}" -f $pr.UserName, $pr.Sid, $pr.ProfilePath) -ForegroundColor Yellow }
    }
    if (@($inv.UnverifiedTempProfiles).Count -gt 0) {
        Write-Host ('  ' + (Get-AtmText 'audit.unverifiedTemp')) -ForegroundColor Yellow
        foreach ($pr in $inv.UnverifiedTempProfiles) { Write-Host ("   - {0} ({1}) env={2}" -f $pr.UserName, $pr.Sid, $pr.EnvStatus) -ForegroundColor Yellow }
    }
    foreach ($pr in $inv.Profiles) { foreach ($n in $pr.Notes) { Write-Host ('  ' + (Get-AtmText 'audit.note' $pr.UserName $n)) } }
    foreach ($n in $inv.DiscoveryNotes) { Write-Host ('  ' + (Get-AtmText 'audit.discovery' $n)) }
    $errs = @($all | Where-Object { $_.ErrorCount -gt 0 -or $_.ReparsePoints -gt 0 -or $_.AmbiguousRefs.Count -gt 0 -or $_.AncestorRefs.Count -gt 0 })
    foreach ($e in $errs) {
        Write-Host ("  [{0}] {1}" -f $e.UserName, $e.Path) -ForegroundColor Yellow
        foreach ($x in $e.ErrorSamples) { Write-Host ('     ' + (Get-AtmText 'audit.err' $x)) }
        foreach ($x in $e.ReparseSamples) { Write-Host ('     ' + (Get-AtmText 'audit.reparse' $x)) }
        foreach ($x in $e.AncestorRefs) { Write-Host ('     ' + (Get-AtmText 'audit.ancestorRef' $x)) }
        foreach ($x in $e.AmbiguousRefs) { Write-Host ('     ' + (Get-AtmText 'audit.ambiguousRef' $x)) }
    }
    Write-Host ('  ' + (Get-AtmText 'audit.limits'))

    # 7. Final summary
    Write-AtmHeader (Get-AtmText 'audit.s7')
    Write-Host ('  ' + (Get-AtmText 'audit.total' $all.Count (Get-AtmSum $all 'Files') (Format-AtmMB $bytes) (Format-AtmGB $bytes)))
    foreach ($c in @('ACTIVE_EVIDENCE', 'RECENT', 'LIVENESS_UNKNOWN', 'ORPHAN_SUSPECTED')) {
        $g = @($all | Where-Object { $_.Class -eq $c })
        Write-Host ('  ' + (Get-AtmText 'audit.classLine' $c $g.Count (Format-AtmMB (Get-AtmSum $g 'Bytes'))))
    }
    Write-Host ('  ' + (Get-AtmText 'audit.coverageShort' $cov))
    Write-Host ('  ' + (Get-AtmText 'audit.readOnly')) -ForegroundColor Green
    Write-Host ('  ' + (Get-AtmText 'audit.orphanInfo'))
}

function ConvertTo-AtmExportJson {
    # Aggregates only (no file listings, no command lines, no session file contents). Language-neutral codes.
    param($Inventory)
    $inv = $Inventory
    $export = [ordered]@{
        toolVersion = $inv.ToolVersion; language = (Get-AtmLanguage); machine = $inv.Machine; user = $inv.Identity.Name; startedUtc = $inv.StartedUtc.ToString('o'); coverageComplete = $inv.CoverageComplete
        processes = [ordered]@{ total = $inv.Snapshot.Total; readable = $inv.Snapshot.Readable; uninspectable = $inv.Snapshot.Uninspectable; failed = $inv.Snapshot.Failed }
        profiles = @($inv.Profiles | ForEach-Object { [ordered]@{ sid = $_.Sid; user = $_.UserName; path = $_.ProfilePath; origin = $_.Origin; status = (Get-AtmProfileStatusLabel -Inventory $inv -ProfileInfo $_) } })
        partitions = @($inv.Partitions | Where-Object { $_.Kind -ne 'NotScanned' } | ForEach-Object {
                [ordered]@{ sid = $_.Sid; user = $_.UserName; project = $_.Project; projectIdentified = $_.ProjectIdentified; projectSource = $_.ProjectSource; scope = $_.Slug; kind = $_.Kind; path = $_.Path; class = $_.Class; bytes = $_.Bytes; allocatedBytesEstimate = $_.AllocatedBytesEstimate
                    files = $_.Files; dirs = $_.Dirs; directChildren = $_.DirectChildren; reparsePoints = $_.ReparsePoints; errors = $_.ErrorCount; measurementComplete = $_.MeasurementComplete
                    creationUtc = $(if ($_.CreationTimeUtc) { $_.CreationTimeUtc.ToString('o') } else { $null }); lastWriteUtc = $(if ($_.LastWriteTimeUtc) { $_.LastWriteTimeUtc.ToString('o') } else { $null })
                    newestWriteUtc = $(if ($_.NewestWriteTimeUtc) { $_.NewestWriteTimeUtc.ToString('o') } else { $null }); flags = @($_.Flags); evidence = @($_.Evidence); fingerprint = $_.Fingerprint }
            })
    }
    return ($export | ConvertTo-Json -Depth 6)
}

function Show-AtmPathDetail {
    # Drill-down: direct children of one audited path, each measured once (no reparse traversal).
    param($Inventory, [string]$Path)
    if (Test-AtmAllowListPathSyntax $Path) { Write-AtmHeader (Get-AtmText 'detail.title' $Path); Write-Host ('  ' + (Get-AtmText 'detail.badPath')) -ForegroundColor Red; return }
    $full = [IO.Path]::GetFullPath($Path)
    $base = @($Inventory.Bases | Where-Object { $_.Status -eq 'OK' -and ($full.StartsWith($_.Path + '\', [StringComparison]::OrdinalIgnoreCase) -or [string]::Equals($full, $_.Path, [StringComparison]::OrdinalIgnoreCase)) })
    Write-AtmHeader (Get-AtmText 'detail.title' $Path)
    if ($base.Count -eq 0) { Write-Host ('  ' + (Get-AtmText 'detail.outside')) -ForegroundColor Red; return }
    $chain = Test-AtmPathChain $full
    if ($chain.Status -ne 'OK') { Write-Host ('  ' + (Get-AtmText 'detail.chain' $chain.Status $chain.At)) -ForegroundColor Red; return }
    $cluster = [AgentTempManager.AtmNative]::GetClusterSize($full.Substring(0, 3))
    $kids = $null
    try { $kids = (New-Object IO.DirectoryInfo($full)).GetFileSystemInfos() } catch { Write-Host ('  ' + (Get-AtmText 'detail.error' $_.Exception.GetType().Name)); return }
    $rows = foreach ($k in $kids) {
        $s = [AgentTempManager.AtmScanner]::ScanTree($k.FullName, 3, $cluster)
        [pscustomobject]@{ Sort = $s.Bytes; Row = (New-AtmRow ([ordered]@{ 'col.name' = $k.Name; 'col.kind' = $(if ($s.RootIsReparsePoint) { 'REPARSE' } elseif ($s.IsDirectory) { 'dir' } else { Get-AtmText 'detail.file' }); 'col.filesShort' = $s.Files; 'col.dirs' = $s.Dirs; 'col.mb' = (Format-AtmMB $s.Bytes)
                        'col.newest' = (Format-AtmTime $(if ($s.NewestWriteTimeUtc -ne [datetime]::MinValue) { $s.NewestWriteTimeUtc } else { $null })); 'col.complete' = (Get-AtmYesNo $s.MeasurementComplete); 'col.errors' = $s.ErrorCount })) }
    }
    Write-AtmTable (@($rows) | Sort-Object Sort -Descending | ForEach-Object { $_.Row })
}

function Show-AtmPreview {
    param($Inventory, $Rows, [string]$User, [string]$Project, [string]$Root)
    $sel = @(Select-AtmPartitions -Inventory $Inventory -User $User -Project $Project -Root $Root)
    $selPaths = @{}
    foreach ($p in $sel) { $selPaths[$p.Path + '|' + $p.Kind + '|' + $p.Name] = $true }
    $rows = @(@($Rows) | Where-Object { $_ -and $selPaths.ContainsKey($_.Partition.Path + '|' + $_.Partition.Kind + '|' + $_.Partition.Name) })
    # One block per path (no wide table): the reason and the evidence are always printed in full, never dropped
    # by column fitting.
    foreach ($cat in @(@('BLOCKED', 'preview.blocked', 'Red'), @('INVESTIGATE', 'preview.investigate', 'Yellow'), @('ELIGIBLE', 'preview.eligible', 'Green'))) {
        $g = @($rows | Where-Object { $_.Gate.Category -eq $cat[0] })
        Write-AtmHeader (Get-AtmText 'preview.header' (Get-AtmText $cat[1]) $g.Count (Format-AtmMB (Get-AtmSum ($g | ForEach-Object { $_.Partition }) 'Bytes')))
        if ($g.Count -eq 0) { Write-Host ('  ' + (Get-AtmText 'common.none')); continue }
        foreach ($r in ($g | Sort-Object { $_.Partition.UserName }, { $_.Partition.Path })) {
            $p = $r.Partition
            Write-Host ("  [{0}] {1}" -f $cat[0], $p.Path) -ForegroundColor $cat[2]
            Write-Host ('     ' + (Get-AtmText 'preview.line' $p.UserName $p.Sid $p.Project $p.Class (Format-AtmMB $p.Bytes) $p.Files $p.Dirs (Format-AtmTime $p.NewestWriteTimeUtc)))
            $why = @(@($r.Gate.Reasons) + @($r.Gate.Requirements))
            Write-Host ('     ' + (Get-AtmText 'preview.reason' $(if ($why.Count) { $why -join ' ; ' } else { '-' })))
            if ($p.Evidence.Count -gt 0) { Write-Host ('     ' + (Get-AtmText 'preview.evidence' ($p.Evidence -join ' ; '))) }
        }
    }
    $el = @($rows | Where-Object { $_.Gate.Category -eq 'ELIGIBLE' })
    if ($el.Count -gt 0) {
        Write-Host ''
        Write-Host ('  ' + (Get-AtmText 'preview.allowlist')) -ForegroundColor Cyan
        foreach ($r in $el) { Write-Host ("  {0}|{1}" -f $r.Partition.Path, $r.Partition.Fingerprint) }
        Write-Host ('  ' + (Get-AtmText 'preview.fingerprint'))
    }
    Write-Host ''
    Write-Host ('  ' + (Get-AtmText 'preview.done')) -ForegroundColor Green
}

function Show-AtmCleanPlan {
    param($Verified, $Rejected, $Inventory)
    Write-AtmHeader (Get-AtmText 'clean.rejectedHeader')
    Write-AtmTable (@($Rejected) | ForEach-Object { New-AtmRow ([ordered]@{ 'col.origin' = $_.Source; 'col.path' = $_.Path; 'col.reasons' = (@($_.Reasons) -join ' ; ') }) })
    Write-AtmHeader (Get-AtmText 'clean.approvedHeader')
    Write-AtmTable (@($Verified) | ForEach-Object { New-AtmRow ([ordered]@{ 'col.user' = $_.UserName; 'col.sid' = $_.Sid; 'col.project' = $_.Project; 'col.path' = $_.Path; 'col.mb' = (Format-AtmMB $_.Bytes); 'col.filesShort' = $_.Files; 'col.dirs' = $_.Dirs; 'col.newest' = (Format-AtmTime $_.NewestWriteTimeUtc); 'col.fingerprint' = $_.Fingerprint }) })
    $t = Get-AtmSum $Verified 'Bytes'
    Write-Host ('  ' + (Get-AtmText 'clean.total' @($Verified).Count (Format-AtmMB $t)))
    if (-not $script:AtmRealDeletionEnabled) { Write-Host ('  ' + (Get-AtmText 'clean.planOnly')) -ForegroundColor Yellow }
    Write-Host ('  ' + (Get-AtmText 'clean.toctou')) -ForegroundColor DarkYellow
    Write-Host ''
    Write-Host ('  ' + (Get-AtmText 'clean.nothingYet')) -ForegroundColor Black -BackgroundColor Yellow
}

function Show-AtmCleanResult {
    param($Result)
    Write-AtmHeader (Get-AtmText 'clean.resultHeader')
    if ($Result.Aborted) {
        Write-Host ('  ' + (Get-AtmText 'clean.aborted' $Result.Aborted)) -ForegroundColor Yellow
        if ($Result.Aborted -eq 'EXCLUSAO_REAL_DESABILITADA_V0_1') { Write-Host ('  ' + (Get-AtmText 'clean.gateMsg' @($Result.Verified).Count)) -ForegroundColor Yellow }
        if ($Result.Aborted -eq 'NENHUM_CAMINHO_ELEGIVEL') { Write-AtmTable (@($Result.Rejected) | ForEach-Object { New-AtmRow ([ordered]@{ 'col.origin' = $_.Source; 'col.path' = $_.Path; 'col.reasons' = (@($_.Reasons) -join ' ; ') }) }) }
        Write-Host ('  ' + (Get-AtmText 'clean.nothing')) -ForegroundColor Green
        return
    }
    Write-AtmTable (@($Result.Deleted) | ForEach-Object { New-AtmRow ([ordered]@{ 'col.path' = $_.Path; 'col.mb' = (Format-AtmMB $_.Bytes); 'col.done' = $_.Completed; 'col.verified' = $_.Verified; 'col.files' = "$($_.FilesDeleted)/$($_.FilesPlanned)"; 'col.dirs' = "$($_.DirsDeleted)/$($_.DirsPlanned)"; 'col.interruption' = $_.AbortReason }) })
    if (@($Result.Skipped).Count -gt 0) {
        Write-Host ('  ' + (Get-AtmText 'clean.skipped')) -ForegroundColor Yellow
        Write-AtmTable (@($Result.Skipped) | ForEach-Object { New-AtmRow ([ordered]@{ 'col.path' = $_.Path; 'col.reasons' = (@($_.Reasons) -join ' ; ') }) })
    }
    $ok = @($Result.Deleted | Where-Object { $_.Completed -and $_.Verified })
    Write-Host ('  ' + (Get-AtmText 'clean.deleted' $ok.Count (Format-AtmMB (Get-AtmSum $ok 'Bytes'))))
}

# ---------------------------------------------------------------------------------------------
# Diagnose (V0.2): presentation of an Invoke-AtmDiagnose result. Codes are printed as-is; text from the catalog.
# ---------------------------------------------------------------------------------------------

function Format-AtmUtcIso { param($Utc) if ($null -eq $Utc) { return $null } return ([datetime]$Utc).ToUniversalTime().ToString('o') }

function Show-AtmDiagnose {
    param($Result)
    $r = $Result
    Write-AtmHeader (Get-AtmText 'diag.title')
    $id = $r.Identity
    Write-Host ('  ' + (Get-AtmText 'cli.identity' $id.Name (Get-AtmYesNo ([bool]$id.IsElevatedAdministrator)) $id.ElevationType $id.IntegrityLevel $id.SessionId))
    Write-Host ('  ' + (Get-AtmText 'diag.deadline' $r.DeadlineSeconds (Format-AtmUtcIso $r.StartedUtc) (Format-AtmUtcIso $r.FinishedUtc)))
    Write-Host ('  ' + (Get-AtmText 'diag.providers' ((@($r.Providers) | ForEach-Object { "$($_.Id) v$($_.ContractVersion) [$(@($_.Capabilities) -join ',')]" }) -join '; ')))
    if ($null -ne $r.Pseudonymization) {
        if ($r.Pseudonymization.KeySource -ceq 'OPERATOR_KEY_FILE') { Write-Host ('  ' + (Get-AtmText 'diag.pseudonymOperator' $r.Pseudonymization.KeyId)) }
        else { Write-Host ('  ' + (Get-AtmText 'diag.pseudonymEphemeral')) }
    }

    Write-AtmHeader (Get-AtmText 'diag.coverageTitle')
    $rows = foreach ($c in @($r.Coverage)) {
        $obs = $(if ($null -ne $c.Observed -and $null -ne $c.Expected) { "$($c.Observed)/$($c.Expected)" } else { '-' })
        New-AtmRow ([ordered]@{
                'col.collector' = $c.Collector
                'col.coverage'  = $c.Status
                'col.meaning'   = (Get-AtmText ('coverage.' + $c.Status))
                'col.reasons'   = $(if (@($c.Reasons).Count) { @($c.Reasons) -join ', ' } else { '-' })
                'col.elevation' = $c.ElevationWouldHelp
                'col.observed'  = $obs
            })
    }
    Write-AtmTable $rows

    Write-AtmHeader (Get-AtmText 'diag.findingsTitle')
    $f = @($r.Findings)
    if ($f.Count -eq 0) { Write-Host ('  ' + (Get-AtmText 'common.none')) }
    foreach ($g in @($f | Group-Object Kind, State | Sort-Object Name)) {
        Write-Host ('  ' + (Get-AtmText 'diag.findingsLine' $g.Group[0].Kind $g.Group[0].State $g.Count))
    }
    $classes = @($f | ForEach-Object { @($_.Evidence | Where-Object { $_.Code -eq 'AUDIT_CLASS' } | ForEach-Object { $_.Detail }) } | Group-Object | Sort-Object Name)
    foreach ($c in $classes) { Write-Host ('    ' + (Get-AtmText 'diag.auditClassLine' $c.Name $c.Count)) }
    if (@($r.Coverage | Where-Object { $_.Collector -eq 'inventory' -and $_.Status -ne 'COMPLETE' }).Count -gt 0) { Write-Host ('  ' + (Get-AtmText 'diag.inventoryIncomplete')) -ForegroundColor Yellow }
    Write-Host ('  ' + (Get-AtmText 'diag.notYet'))

    Show-AtmDiagnoseRuntime -Result $r
    Show-AtmDiagnoseServices -Result $r
    Show-AtmDiagnoseVirtualization -Result $r
    Show-AtmDiagnoseWorktrees -Result $r
    Show-AtmDiagnoseHandles -Result $r

    Write-AtmHeader (Get-AtmText 'diag.summaryTitle')
    Write-Host ('  ' + (Get-AtmText 'diag.coverageComplete' (Get-AtmYesNo ([bool]$r.CoverageComplete) -Upper))) -ForegroundColor $(if ($r.CoverageComplete) { 'Green' } else { 'Yellow' })
    Write-Host ('  ' + (Get-AtmText 'diag.unknownNote'))
    Write-Host ('  ' + (Get-AtmText 'diag.readOnly')) -ForegroundColor Green
}

$script:AtmRuntimeListMax = 20
$script:AtmRuntimeCollectors = @('process-snapshot', 'agent-processes', 'agent-resources')

function Test-AtmRuntimeCollector { param([string]$Collector) return ($script:AtmRuntimeCollectors -ccontains $Collector -or $Collector.StartsWith('sessions-', [StringComparison]::Ordinal)) }

function Get-AtmCodeText {
    # Catalog text of a code (reason.<code>, evidence.<code>), or $null when the code has none (EXCEPTION_<TYPE>).
    param([string]$Prefix, [string]$Code)
    $k = $Prefix + '.' + $Code
    if ($script:AtmMessages['en-US'].ContainsKey($k)) { return (Get-AtmText $k) }
    return $null
}

function Get-AtmRuntimePid {
    # The PID of a Process finding key (pid@ticks or pid:<n>).
    param([string]$Key)
    if ($Key -match '^(\d{1,10})[@:]') { return $Matches[1] }
    if ($Key -match '^pid:(\d{1,10})$') { return $Matches[1] }
    return $Key
}

function Format-AtmResourceValue {
    # A total for the report: unknown when nothing was read, marked partial when it is a lower bound. Never 0 for
    # an unread value.
    param([string]$Name, $Counter)
    if ($null -eq $Counter -or $null -eq $Counter.Sum) { return (Get-AtmText 'diag.runtimeUnknownValue') }
    $v = $Counter.Sum
    if ($Name.EndsWith('Time100ns')) { $txt = [string][math]::Round([double]$v / 10000000, 1) }
    elseif ($Name.EndsWith('Bytes')) { $txt = [string](Format-AtmMB ([long]$v)) }
    elseif ($Name -ceq 'CpuPercent') { $txt = [string][math]::Round([double]$v, 1) }
    else { $txt = [string]$v }
    if (-not $Counter.Complete) { $txt = $txt + ' ' + (Get-AtmText 'diag.runtimePartialTag') }
    return $txt
}

function Show-AtmDiagnoseRuntime {
    # Agent runtime section of the diagnose report (P1-B4-c). States, attribution (ambiguity shown, never resolved),
    # processes that exited during the run, totals counted once per process, coverage gaps and the meaning of the
    # codes. Never states that no agent exists, and never relates a runtime state to deleting a temporary directory.
    param($Result)
    $r = $Result
    Write-AtmHeader (Get-AtmText 'diag.runtimeTitle')
    $cov = @($r.Coverage | Where-Object { Test-AtmRuntimeCollector $_.Collector })
    $rt = @($r.Findings | Where-Object { $_.Kind -ceq 'Process' -or $_.Kind -ceq 'AgentSession' })
    $ap = @($cov | Where-Object { $_.Collector -ceq 'agent-processes' })
    if ($ap.Count -eq 0 -or $ap[0].Status -ceq 'TIMEOUT') {
        Write-Host ('  ' + (Get-AtmText 'diag.runtimeNotRun')) -ForegroundColor Yellow
    } else {
        if (@($rt | Where-Object { $_.State -cne 'SELF' }).Count -eq 0) { Write-Host ('  ' + (Get-AtmText 'diag.runtimeNone')) }
        foreach ($kind in @('Process', 'AgentSession')) {
            foreach ($st in @($script:AtmFindingStates[$kind])) {
                $n = @($rt | Where-Object { $_.Kind -ceq $kind -and $_.State -ceq $st }).Count
                if ($n -gt 0) { Write-Host ('  ' + (Get-AtmText 'diag.runtimeStateLine' $kind $st $n (Get-AtmText "state.$kind.$st"))) }
            }
        }
        $ambOf = { param($F) @($F.Evidence | Where-Object { $_.Code -ceq 'PROVIDER_ATTRIBUTION_AMBIGUOUS' } | ForEach-Object { [string]$_.Detail }) -join ';' }
        $exited = { param($F) @($F.Evidence | Where-Object { $_.Code -ceq 'PROCESS_EXITED_DURING_RUN' }).Count -gt 0 }
        $agents = @($rt | Where-Object { $_.Kind -ceq 'Process' -and ($_.State -ceq 'AGENT_PROCESS' -or $_.State -ceq 'AGENT_DESCENDANT') })
        foreach ($g in @($agents | Where-Object { $_.Provider } | Group-Object Provider | Sort-Object Name)) { Write-Host ('  ' + (Get-AtmText 'diag.runtimeProviderLine' $g.Name $g.Count)) }
        $amb = @($agents | Where-Object { -not $_.Provider -and (& $ambOf $_) })
        if ($amb.Count -gt 0) { Write-Host ('  ' + (Get-AtmText 'diag.runtimeAmbiguous' $amb.Count ((@($amb | ForEach-Object { & $ambOf $_ } | Sort-Object -Unique)) -join '; '))) -ForegroundColor Yellow }
        $un = @($agents | Where-Object { -not $_.Provider -and -not (& $ambOf $_) })
        if ($un.Count -gt 0) { Write-Host ('  ' + (Get-AtmText 'diag.runtimeUnattributed' $un.Count)) }
        $procs = @($rt | Where-Object { $_.Kind -ceq 'Process' -and $_.State -cne 'SELF' })
        if ($procs.Count -gt 0) {
            Write-Host ('  ' + (Get-AtmText 'diag.runtimeProcessesTitle'))
            foreach ($p in @($procs | Select-Object -First $script:AtmRuntimeListMax)) {
                $who = $(if ($p.Provider) { $p.Provider } elseif (& $ambOf $p) { Get-AtmText 'diag.runtimeAmbiguousTag' (& $ambOf $p) } else { '-' })
                $line = Get-AtmText 'diag.runtimeProcessLine' (Get-AtmRuntimePid $p.Key) $p.State $who
                if (& $exited $p) { $line = $line + '  ' + (Get-AtmText 'diag.runtimeExitedTag') }
                Write-Host ('    ' + $line)
            }
            if ($procs.Count -gt $script:AtmRuntimeListMax) { Write-Host ('    ' + (Get-AtmText 'diag.runtimeMore' ($procs.Count - $script:AtmRuntimeListMax))) }
        }
        $sess = @($rt | Where-Object { $_.Kind -ceq 'AgentSession' })
        if ($sess.Count -gt 0) {
            Write-Host ('  ' + (Get-AtmText 'diag.runtimeSessionsTitle'))
            foreach ($s in @($sess | Select-Object -First $script:AtmRuntimeListMax)) {
                $line = Get-AtmText 'diag.runtimeSessionLine' $s.Key $s.State
                if (& $exited $s) { $line = $line + '  ' + (Get-AtmText 'diag.runtimeExitedTag') }
                Write-Host ('    ' + $line)
            }
            if ($sess.Count -gt $script:AtmRuntimeListMax) { Write-Host ('    ' + (Get-AtmText 'diag.runtimeMore' ($sess.Count - $script:AtmRuntimeListMax))) }
        }
        $ex = @($rt | Where-Object { & $exited $_ }).Count
        if ($ex -gt 0) { Write-Host ('  ' + (Get-AtmText 'diag.runtimeExited' $ex)) -ForegroundColor Yellow }
        $t = $r.AgentResources
        if ($null -ne $t) {
            Write-Host ('  ' + (Get-AtmText 'diag.runtimeResourcesTitle'))
            Write-Host ('    ' + (Get-AtmText 'diag.runtimeResourcesProcesses' $t.Processes))
            foreach ($n in @($t.Counters.PSObject.Properties.Name)) {
                $label = $(if ($n -ceq 'CpuPercent') { Get-AtmText 'diag.res.CpuPercent' $(if ($null -ne $t.CpuIntervalMs) { $t.CpuIntervalMs } else { '-' }) } else { Get-AtmText "diag.res.$n" })
                Write-Host ('    ' + (Get-AtmText 'diag.runtimeResourcesLine' $label (Format-AtmResourceValue -Name $n -Counter $t.Counters.$n)))
            }
            if (-not $t.Complete) { Write-Host ('    ' + (Get-AtmText 'diag.runtimeResourcesPartial' (@($t.Reasons) -join ', '))) -ForegroundColor Yellow }
        }
    }
    foreach ($c in @($cov | Where-Object { $script:AtmConclusiveCoverage -cnotcontains $_.Status })) {
        Write-Host ('  ' + (Get-AtmText 'diag.runtimeCoverageLine' $c.Collector $c.Status (@($c.Reasons) -join ', '))) -ForegroundColor Yellow
    }
    # Meaning of every reason and evidence code shown in this section.
    $codes = New-Object System.Collections.Generic.List[string]
    foreach ($x in @($cov | ForEach-Object { @($_.Reasons) }) + @($r.AgentResources | Where-Object { $null -ne $_ } | ForEach-Object { @($_.Reasons) })) { $tx = Get-AtmCodeText 'reason' $x; if ($tx -and -not $codes.Contains("$x|$tx")) { $codes.Add("$x|$tx") } }
    foreach ($x in @($rt | ForEach-Object { @($_.Evidence | ForEach-Object { $_.Code }) })) { $tx = Get-AtmCodeText 'evidence' $x; if ($tx -and -not $codes.Contains("$x|$tx")) { $codes.Add("$x|$tx") } }
    if ($codes.Count -gt 0) {
        Write-Host ('  ' + (Get-AtmText 'diag.runtimeLegendTitle'))
        foreach ($c in @($codes | Sort-Object)) { $i = $c.IndexOf('|'); Write-Host ('    ' + (Get-AtmText 'diag.runtimeLegendLine' $c.Substring(0, $i) $c.Substring($i + 1))) }
    }
    Write-Host ('  ' + (Get-AtmText 'diag.runtimeScope'))
    Write-Host ('  ' + (Get-AtmText 'diag.runtimeNoDelete')) -ForegroundColor Green
}

function Show-AtmDiagnoseServices {
    # Windows services (P2-A): only names declared by providers. No declared name: says that nothing was checked
    # (never "no services"). Per service: state, start mode, delayed start, account, executable (full path only in a
    # well-known program location), verified process key, provider; then coverage gaps and the meaning of the codes.
    param($Result)
    $r = $Result
    $cov = @($r.Coverage | Where-Object { $_.Collector -ceq 'services' -or $_.Collector -ceq 'service-properties' })
    if ($cov.Count -eq 0) { return }
    Write-AtmHeader (Get-AtmText 'diag.svcTitle')
    $sf = @($r.Findings | Where-Object { $_.Kind -ceq 'Service' })
    # "No provider declares a service" only when every provider's names were read.
    if (@($cov | Where-Object { $_.Collector -ceq 'services' -and @($_.Reasons) -ccontains 'SERVICE_HINTS_NONE' -and @($_.Reasons) -cnotcontains 'SERVICE_HINTS_INCOMPLETE' }).Count -gt 0) { Write-Host ('  ' + (Get-AtmText 'diag.svcNone')) }
    $val = { param($F, [string]$Code) $e = @($F.Evidence | Where-Object { $_.Code -ceq $Code }); if ($e.Count -gt 0 -and $e[0].Detail) { [string]$e[0].Detail } else { Get-AtmText 'diag.svcUnknownValue' } }
    foreach ($s in @($sf | Select-Object -First $script:AtmRuntimeListMax)) {
        Write-Host ('  ' + (Get-AtmText 'diag.svcLine' $s.Key $s.State) + '  ' + (Get-AtmText "state.Service.$($s.State)"))
        if (@($s.Evidence | Where-Object { $_.Code -ceq 'SERVICE_STATE' }).Count -eq 0) { continue }
        # The kind always; a name only for the standard built-in accounts (ADR-0012).
        $acct = $(if (@($s.Evidence | Where-Object { $_.Code -ceq 'SERVICE_ACCOUNT' }).Count -gt 0) { (& $val $s 'SERVICE_ACCOUNT_KIND') + ' ' + (& $val $s 'SERVICE_ACCOUNT') } elseif (@($s.Evidence | Where-Object { $_.Code -ceq 'SERVICE_ACCOUNT_KIND' }).Count -gt 0) { & $val $s 'SERVICE_ACCOUNT_KIND' } else { Get-AtmText 'diag.svcUnknownValue' })
        $exe = $(if (@($s.Evidence | Where-Object { $_.Code -ceq 'SERVICE_EXECUTABLE' }).Count -gt 0) { & $val $s 'SERVICE_EXECUTABLE' } else { & $val $s 'SERVICE_EXECUTABLE_NAME' })
        $proc = $(if (@($s.Evidence | Where-Object { $_.Code -ceq 'SERVICE_PROCESS_VERIFIED' }).Count -gt 0) { & $val $s 'SERVICE_PROCESS_VERIFIED' } elseif (@($s.Evidence | Where-Object { $_.Code -ceq 'SERVICE_PROCESS_UNVERIFIED' }).Count -gt 0) { 'UNVERIFIED (' + (& $val $s 'SERVICE_PROCESS_UNVERIFIED') + ')' } else { '-' })
        $who = $(if ($s.Provider) { $s.Provider } else { & $val $s 'PROVIDER_ATTRIBUTION_AMBIGUOUS' })
        Write-Host ('    ' + (Get-AtmText 'diag.svcDetail' (& $val $s 'SERVICE_START_MODE') (& $val $s 'SERVICE_DELAYED_AUTO_START') $acct $exe $proc $who))
    }
    if ($sf.Count -gt $script:AtmRuntimeListMax) { Write-Host ('  ' + (Get-AtmText 'diag.runtimeMore' ($sf.Count - $script:AtmRuntimeListMax))) }
    foreach ($c in @($cov | Where-Object { $script:AtmConclusiveCoverage -cnotcontains $_.Status })) { Write-Host ('  ' + (Get-AtmText 'diag.runtimeCoverageLine' $c.Collector $c.Status (@($c.Reasons) -join ', '))) -ForegroundColor Yellow }
    $codes = New-Object System.Collections.Generic.List[string]
    foreach ($x in @($cov | ForEach-Object { @($_.Reasons) })) { $tx = Get-AtmCodeText 'reason' $x; if ($tx -and -not $codes.Contains("$x|$tx")) { $codes.Add("$x|$tx") } }
    foreach ($x in @($sf | ForEach-Object { @($_.Evidence | ForEach-Object { $_.Code }) })) { $tx = Get-AtmCodeText 'evidence' $x; if ($tx -and -not $codes.Contains("$x|$tx")) { $codes.Add("$x|$tx") } }
    if ($codes.Count -gt 0) {
        Write-Host ('  ' + (Get-AtmText 'diag.runtimeLegendTitle'))
        foreach ($c in @($codes | Sort-Object)) { $i = $c.IndexOf('|'); Write-Host ('    ' + (Get-AtmText 'diag.runtimeLegendLine' $c.Substring(0, $i) $c.Substring($i + 1))) }
    }
    if ($sf.Count -gt 0) { Write-Host ('  ' + (Get-AtmText 'diag.svcNotPresentNote')) }
    Write-Host ('  ' + (Get-AtmText 'diag.svcNoDelete')) -ForegroundColor Green
}

function Show-AtmDiagnoseVirtualization {
    # Virtualization (P2-B): the platform state and how it was seen, virtual machines by state (pseudonymous keys, never
    # names), worker processes by class with the totals that were read, coverage gaps and the meaning of the codes.
    # Never says that no VM or no platform exists.
    param($Result)
    $r = $Result
    $cov = @($r.Coverage | Where-Object { @('virtualization-platform', 'virtual-machines', 'virtualization-processes') -ccontains $_.Collector })
    if ($cov.Count -eq 0) { return }
    Write-AtmHeader (Get-AtmText 'diag.virtTitle')
    $vf = @($r.Findings | Where-Object { $_.Kind -ceq 'VirtualizationPlatform' -or $_.Kind -ceq 'VirtualMachine' })
    foreach ($p in @($vf | Where-Object { $_.Kind -ceq 'VirtualizationPlatform' })) {
        Write-Host ('  ' + (Get-AtmText 'diag.virtPlatform' $p.State (Get-AtmText "state.VirtualizationPlatform.$($p.State)")))
        $w = @($p.Evidence | Where-Object { $_.Code -ceq 'VIRTUALIZATION_WORKER' }).Count
        $wu = @($p.Evidence | Where-Object { $_.Code -ceq 'VIRTUALIZATION_WORKER_UNVERIFIED' }).Count
        Write-Host ('  ' + (Get-AtmText 'diag.virtWorkers' $w $wu))
        foreach ($c in @('VIRTUALIZATION_WORKERS_WORKING_SET_BYTES', 'VIRTUALIZATION_WORKERS_PRIVATE_BYTES', 'VIRTUALIZATION_WORKERS_CPU_TIME_100NS')) {
            $e = @($p.Evidence | Where-Object { $_.Code -ceq $c })
            if ($e.Count -gt 0) { Write-Host ('    ' + (Get-AtmText 'diag.virtTotal' (Get-AtmText "evidence.$c") $e[0].Detail)) }
        }
    }
    $vms = @($vf | Where-Object { $_.Kind -ceq 'VirtualMachine' })
    $vc = @($cov | Where-Object { $_.Collector -ceq 'virtual-machines' })
    if ($vms.Count -eq 0 -and $vc.Count -gt 0 -and $vc[0].Status -ceq 'COMPLETE') { Write-Host ('  ' + (Get-AtmText 'diag.virtNoVmObserved')) }
    foreach ($st in @($script:AtmFindingStates['VirtualMachine'])) {
        $n = @($vms | Where-Object { $_.State -ceq $st }).Count
        if ($n -gt 0) { Write-Host ('  ' + (Get-AtmText 'diag.virtVmLine' $st $n (Get-AtmText "state.VirtualMachine.$st"))) }
    }
    foreach ($v in @($vms | Select-Object -First $script:AtmRuntimeListMax)) {
        $who = $(if ($v.Provider) { $v.Provider } elseif (@($v.Evidence | Where-Object { $_.Code -ceq 'PROVIDER_ATTRIBUTION_AMBIGUOUS' }).Count -gt 0) { Get-AtmText 'diag.runtimeAmbiguousTag' (@($v.Evidence | Where-Object { $_.Code -ceq 'PROVIDER_ATTRIBUTION_AMBIGUOUS' })[0].Detail) } else { 'UNATTRIBUTED' })
        Write-Host ('    ' + (Get-AtmText 'diag.virtVmItem' $v.Key $v.State $who))
    }
    foreach ($c in @($cov | Where-Object { $script:AtmConclusiveCoverage -cnotcontains $_.Status })) { Write-Host ('  ' + (Get-AtmText 'diag.runtimeCoverageLine' $c.Collector $c.Status (@($c.Reasons) -join ', '))) -ForegroundColor Yellow }
    $codes = New-Object System.Collections.Generic.List[string]
    foreach ($x in @($cov | ForEach-Object { @($_.Reasons) })) { $tx = Get-AtmCodeText 'reason' $x; if ($tx -and -not $codes.Contains("$x|$tx")) { $codes.Add("$x|$tx") } }
    foreach ($x in @($vf | ForEach-Object { @($_.Evidence | ForEach-Object { $_.Code }) })) { $tx = Get-AtmCodeText 'evidence' $x; if ($tx -and -not $codes.Contains("$x|$tx")) { $codes.Add("$x|$tx") } }
    if ($codes.Count -gt 0) {
        Write-Host ('  ' + (Get-AtmText 'diag.runtimeLegendTitle'))
        foreach ($c in @($codes | Sort-Object)) { $i = $c.IndexOf('|'); Write-Host ('    ' + (Get-AtmText 'diag.runtimeLegendLine' $c.Substring(0, $i) $c.Substring($i + 1))) }
    }
    Write-Host ('  ' + (Get-AtmText 'diag.virtNotes'))
    Write-Host ('  ' + (Get-AtmText 'diag.virtNoDelete')) -ForegroundColor Green
}

function Show-AtmDiagnoseHandles {
    # Open files (D-2) and working directories (D-1, deferred): counts and codes only, never a path or process name.
    param($Result)
    $r = $Result
    $cov = @($r.Coverage | Where-Object { $_.Collector -ceq 'handles' -or $_.Collector -ceq 'process-cwd' })
    if ($cov.Count -eq 0) { return }
    Write-AtmHeader (Get-AtmText 'diag.hTitle')
    # Not queried (security gate closed): no count is shown, so nothing reads as "no item held".
    $gate = (@($cov | Where-Object { $_.Collector -ceq 'handles' -and @($_.Reasons) -ccontains 'HANDLE_SECURITY_GATE_CLOSED' }).Count -gt 0)
    if ($gate) { Write-Host ('  ' + (Get-AtmText 'diag.hGate')) -ForegroundColor Yellow }
    else {
        $items = @($r.Findings | Where-Object { $_.Kind -ceq 'TempPartition' -or $_.Kind -ceq 'Worktree' })
        $held = @($items | Where-Object { @($_.Evidence | Where-Object { $_.Code -ceq 'FILE_HELD_OPEN' -or $_.Code -ceq 'FILE_HELD_OPEN_UNVERIFIED' }).Count -gt 0 })
        Write-Host ('  ' + (Get-AtmText 'diag.hLine' $held.Count $items.Count))
    }
    foreach ($c in @($cov | Where-Object { $script:AtmConclusiveCoverage -cnotcontains $_.Status })) { Write-Host ('  ' + (Get-AtmText 'diag.runtimeCoverageLine' $c.Collector $c.Status (@($c.Reasons) -join ', '))) -ForegroundColor Yellow }
    if (-not $gate) { Write-Host ('  ' + (Get-AtmText 'diag.hSample')) }
    Write-Host ('  ' + (Get-AtmText 'diag.hCwd'))
    Write-Host ('  ' + (Get-AtmText 'diag.hState')) -ForegroundColor Green
}

function Show-AtmDiagnoseWorktrees {
    # Git worktrees (P3-B): shown only when the run has worktree records (the worktree diagnostics gate is closed in
    # shipped copies). Counts by kind and state, coverage gaps, the meaning of the codes and the limits of discovery.
    param($Result)
    $r = $Result
    $cov = @($r.Coverage | Where-Object { $_.Collector -ceq 'worktree-discovery' -or $_.Collector -ceq 'git' })
    if ($cov.Count -eq 0) { return }
    Write-AtmHeader (Get-AtmText 'diag.wtTitle')
    $wf = @($r.Findings | Where-Object { $_.Kind -ceq 'Repository' -or $_.Kind -ceq 'Worktree' })
    foreach ($g in @($wf | Group-Object Kind, State | Sort-Object Name)) { Write-Host ('  ' + (Get-AtmText 'diag.wtLine' $g.Group[0].Kind $g.Group[0].State $g.Count)) }
    foreach ($c in @($cov | Where-Object { $script:AtmConclusiveCoverage -cnotcontains $_.Status })) { Write-Host ('  ' + (Get-AtmText 'diag.runtimeCoverageLine' $c.Collector $c.Status (@($c.Reasons) -join ', '))) -ForegroundColor Yellow }
    $codes = New-Object System.Collections.Generic.List[string]
    foreach ($x in @($cov | ForEach-Object { @($_.Reasons) })) { $tx = Get-AtmCodeText 'reason' $x; if ($tx -and -not $codes.Contains("$x|$tx")) { $codes.Add("$x|$tx") } }
    foreach ($x in @($wf | ForEach-Object { @($_.Evidence | ForEach-Object { $_.Code }) })) { $tx = Get-AtmCodeText 'evidence' $x; if ($tx -and -not $codes.Contains("$x|$tx")) { $codes.Add("$x|$tx") } }
    if ($codes.Count -gt 0) {
        Write-Host ('  ' + (Get-AtmText 'diag.runtimeLegendTitle'))
        foreach ($c in @($codes | Sort-Object)) { $i = $c.IndexOf('|'); Write-Host ('    ' + (Get-AtmText 'diag.runtimeLegendLine' $c.Substring(0, $i) $c.Substring($i + 1))) }
    }
    Write-Host ('  ' + (Get-AtmText 'diag.wtBounded'))
    Write-Host ('  ' + (Get-AtmText 'diag.wtNoDelete')) -ForegroundColor Green
}

function ConvertTo-AtmAgentResourcesJson {
    # agentResources (docs/DIAGNOSE-SCHEMA.md): totals over the union of the agent processes, each counted once. Unread
    # values stay null; collected = false when the runtime was not observed.
    param($Totals)
    if ($null -eq $Totals) { return [ordered]@{ collected = $false; processes = $null; complete = $false; reasons = @(); cpuIntervalMs = $null; counters = $null } }
    $counters = [ordered]@{}
    foreach ($n in @($Totals.Counters.PSObject.Properties.Name)) {
        $c = $Totals.Counters.$n
        $sum = $(if ($null -eq $c.Sum) { $null } elseif ($n -ceq 'CpuPercent') { [math]::Round([double]$c.Sum, 3) } else { [long]$c.Sum })
        $counters[$n.Substring(0, 1).ToLowerInvariant() + $n.Substring(1)] = [ordered]@{ sum = $sum; known = $c.Known; complete = [bool]$c.Complete }
    }
    return [ordered]@{ collected = $true; processes = $Totals.Processes; complete = [bool]$Totals.Complete; reasons = @($Totals.Reasons); cpuIntervalMs = $Totals.CpuIntervalMs; counters = $counters }
}

function ConvertTo-AtmDiagnoseJson {
    # Schema atm.diagnose/2 (docs/DIAGNOSE-SCHEMA.md). Codes only; no command lines, environment values, tokens,
    # exception messages or file contents. Every array is explicit, every time is ISO 8601 UTC.
    param($Result)
    $r = $Result
    $id = $r.Identity
    $inv = $r.Inventory
    $export = [ordered]@{
        schemaVersion    = $r.SchemaVersion
        toolVersion      = $r.ToolVersion
        language         = (Get-AtmLanguage)
        machine          = $r.Machine
        startedUtc       = (Format-AtmUtcIso $r.StartedUtc)
        finishedUtc      = (Format-AtmUtcIso $r.FinishedUtc)
        deadlineUtc      = (Format-AtmUtcIso $r.DeadlineUtc)
        deadlineSeconds  = $r.DeadlineSeconds
        coverageComplete = [bool]$r.CoverageComplete
        identity         = [ordered]@{ user = $id.Name; sid = $id.Sid; elevatedAdministrator = $id.IsElevatedAdministrator; elevationType = $id.ElevationType; integrityLevel = $id.IntegrityLevel; sessionId = $id.SessionId }
        providers        = @(@($r.Providers) | ForEach-Object { [ordered]@{ id = $_.Id; displayName = $_.DisplayName; contractVersion = $_.ContractVersion; capabilities = @($_.Capabilities) } })
        coverage         = @(@($r.Coverage) | ForEach-Object {
                [ordered]@{ collector = $_.Collector; status = $_.Status; reasons = @($_.Reasons); elevationWouldHelp = $_.ElevationWouldHelp; observed = $_.Observed; expected = $_.Expected
                    startedUtc = (Format-AtmUtcIso $_.StartedUtc); elapsedMs = $_.ElapsedMs; budgetMs = $_.BudgetMs }
            })
        findings         = @(@($r.Findings) | ForEach-Object {
                [ordered]@{ kind = $_.Kind; key = $_.Key; state = $_.State; requestedState = $_.RequestedState; provider = $_.Provider
                    coverage = @(@($_.Coverage) | ForEach-Object { $_.Collector }); incompleteCoverage = @($_.IncompleteCoverage)
                    evidence = @(@($_.Evidence) | ForEach-Object { [ordered]@{ code = $_.Code; source = $_.Source; collector = $_.Collector; observedUtc = (Format-AtmUtcIso $_.ObservedUtc); detail = $_.Detail } }) }
            })
        agentResources   = (ConvertTo-AtmAgentResourcesJson -Totals $r.AgentResources)
        pseudonymization = [ordered]@{ scheme = $r.Pseudonymization.Scheme; keySource = $r.Pseudonymization.KeySource; keyId = $r.Pseudonymization.KeyId }
        inventory        = [ordered]@{
            collected        = ($null -ne $inv)
            coverageComplete = $(if ($inv) { [bool]$inv.CoverageComplete } else { $null })
            partitions       = $(if ($inv) { @($inv.Partitions | Where-Object { $_.Kind -ne 'NotScanned' }).Count } else { $null })
            bytes            = $(if ($inv) { Get-AtmSum @($inv.Partitions | Where-Object { $_.Kind -ne 'NotScanned' }) 'Bytes' } else { $null })
        }
    }
    return ($export | ConvertTo-Json -Depth 8)
}
