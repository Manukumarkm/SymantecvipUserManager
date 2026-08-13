<#
.SYNOPSIS
    Example: bulk-delete VIP users from a CSV with an exception list.

.DESCRIPTION
    Reads a CSV of users to delete, filters out any UserId that matches one or
    more exception patterns (literal user IDs or wildcards like 'ADM_*'),
    backs up each remaining user, then deletes them. Skipped rows are
    recorded in the output CSV alongside the actual delete results so you
    always have a full audit trail.

    Exception patterns can be supplied inline via -ExceptionUserId and / or
    loaded from a text file via -ExceptionListPath (one pattern per line,
    blank lines and '#' comments ignored). Matching is case-insensitive and
    supports the standard PowerShell wildcards '*' and '?'.

.PARAMETER CertificatePath
    Path to the PKCS#12 (.p12 / .pfx) client certificate used for mTLS.

.PARAMETER CsvPath
    CSV of users to delete. Required column: UserId. May include a
    JurisdictionHash column (aliases: OnBehalfOfAccountId, AuthorizerAccountId).
    If omitted, supply the tenant via the -JurisdictionHash parameter instead.

.PARAMETER JurisdictionHash
    Overrides the tenant / jurisdiction hash for every row. Use this when
    (a) the CSV has only a UserId column, or (b) you want to force a single
    tenant regardless of what the CSV says.

.PARAMETER ExceptionUserId
    One or more literal user IDs or wildcard patterns that must NOT be
    deleted. Example: -ExceptionUserId 'ADM_*','svc_backup'.

.PARAMETER ExceptionListPath
    Text file containing one exception pattern per line. Blank lines and
    lines starting with '#' are ignored.

.PARAMETER BackupPath
    Directory that a pre-delete snapshot of each user is written into.
    Defaults to '.\vip-user-backups'. Ignored when -SkipBackup is set.

.PARAMETER SkipBackup
    Skip the pre-delete snapshot for every row (fast but unrecoverable).

.PARAMETER OutFile
    Combined result CSV (skipped + deleted rows). Defaults to a timestamped
    file in the current directory.

.EXAMPLE
    .\bulk-delete-users.ps1 -CertificatePath C:\vip\vip.p12 -CsvPath .\bulk-delete-users.csv

.EXAMPLE
    # Inline exceptions + custom backup folder
    .\bulk-delete-users.ps1 -CertificatePath C:\vip\vip.p12 -CsvPath .\users.csv `
                            -ExceptionUserId 'ADM_*','BREAKGLASS_*' `
                            -BackupPath D:\vip-backups\2026-08

.EXAMPLE
    # Exceptions read from a file
    .\bulk-delete-users.ps1 -CertificatePath C:\vip\vip.p12 -CsvPath .\users.csv `
                            -ExceptionListPath .\exception-list.txt

.EXAMPLE
    # CSV contains only a UserId column - tenant supplied via parameter
    .\bulk-delete-users.ps1 -CertificatePath C:\vip\vip.p12 -CsvPath .\just-user-ids.csv `
                            -JurisdictionHash 1234567890
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$CertificatePath,
    [Parameter(Mandatory)][string]$CsvPath,
    [string]$JurisdictionHash,   # overrides / supplies the tenant when CSV has only UserId
    [string[]]$ExceptionUserId,  # default exceptions to avoid deleting admin / emergency accounts
    [string]$ExceptionListPath = (Join-Path $PSScriptRoot 'exception-list.txt'),
    [string]$BackupPath = '.\vip-user-backups',
    [switch]$SkipBackup,
    [string]$OutFile = "delete-users-results-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
)

# --- import the module (robust to script being moved out of examples\) --------
# If a local checkout is discoverable, always Force-reload it so script runs
# pick up module edits without needing a fresh PowerShell session.
$moduleName = 'SymantecvipUserManager'
$candidates = @(
    # Sibling folder inside the repo (i.e. running from examples\)
    Join-Path $PSScriptRoot "..\$moduleName\$moduleName.psd1"
    # Sibling repo folder when the script is moved next to the repo, e.g.
    # <parent>\BulkUserDeletion\Bulk-*.ps1 with <parent>\SymantecVIP_BulkOperation_Tool\.
    Join-Path $PSScriptRoot "..\SymantecVIP_BulkOperation_Tool\$moduleName\$moduleName.psd1"
    # Module dropped alongside the script
    Join-Path $PSScriptRoot "$moduleName\$moduleName.psd1"
    # Environment override
    ($env:SymantecvipUserManagerPath)
) | Where-Object { $_ }
$psd = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if ($psd) {
    Remove-Module $moduleName -Force -ErrorAction SilentlyContinue
    Import-Module -Force -Name $psd
    Write-Verbose "Imported $moduleName from $psd"
} elseif (Get-Module -Name $moduleName) {
    Write-Warning "Using already-loaded $moduleName. If you edited the module, run: Remove-Module $moduleName -Force; then re-run."
} else {
    $searched = ($candidates | ForEach-Object { "  - $_" }) -join [Environment]::NewLine
    throw @"
Could not find $moduleName. Looked in:
$searched
Fix one of these:
  * Copy the SymantecvipUserManager folder next to this script, OR
  * Set `$env:SymantecvipUserManagerPath = 'C:\full\path\to\SymantecvipUserManager\SymantecvipUserManager.psd1', OR
  * Install the module into a `$env:PSModulePath directory.
"@
}

# --- assemble the exception pattern list --------------------------------------
$patterns = New-Object System.Collections.Generic.List[string]
if ($ExceptionUserId) { $ExceptionUserId | ForEach-Object { [void]$patterns.Add($_.Trim()) } }
if ($ExceptionListPath) {
    if (-not (Test-Path -LiteralPath $ExceptionListPath -PathType Leaf)) {
        throw "Exception list file '$ExceptionListPath' not found."
    }
    Get-Content -LiteralPath $ExceptionListPath |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -and -not $_.StartsWith('#') } |
        ForEach-Object { [void]$patterns.Add($_) }
}
$patterns = @($patterns | Where-Object { $_ } | Select-Object -Unique)
if ($patterns.Count -gt 0) {
    Write-Host "Loaded $($patterns.Count) exception pattern(s):" -ForegroundColor Cyan
    $patterns | ForEach-Object { Write-Host "  - $_" -ForegroundColor Cyan }
}

# Returns the first pattern that matches, or $null if none.
function Get-MatchingException {
    param([string]$UserId, [string[]]$Patterns)
    foreach ($p in $Patterns) {
        if ($UserId -like $p) { return $p }
    }
    return $null
}

# --- connect and process ------------------------------------------------------
$pw = Read-Host -AsSecureString -Prompt "PFX password for $CertificatePath"
Connect-SymantecVip -CertificatePath $CertificatePath -CertificatePassword $pw

try {
    $rows = @(Import-Csv -LiteralPath $CsvPath)
    Write-Host "Loaded $($rows.Count) row(s) from $CsvPath" -ForegroundColor Cyan

    # --- validate / inject JurisdictionHash ---------------------------------
    $firstRow   = $rows | Select-Object -First 1
    $csvHasHash = $firstRow -and (
        $firstRow.PSObject.Properties['JurisdictionHash'] -or
        $firstRow.PSObject.Properties['OnBehalfOfAccountId'] -or
        $firstRow.PSObject.Properties['AuthorizerAccountId']
    )
    if (-not $JurisdictionHash -and -not $csvHasHash) {
        throw "Input CSV '$CsvPath' has no JurisdictionHash / OnBehalfOfAccountId / AuthorizerAccountId column, and no -JurisdictionHash parameter was supplied. Provide one or the other."
    }
    if ($JurisdictionHash) {
        Write-Host "Overriding JurisdictionHash with parameter value: $JurisdictionHash" -ForegroundColor Cyan
        foreach ($row in $rows) {
            $row | Add-Member -NotePropertyName JurisdictionHash -NotePropertyValue $JurisdictionHash -Force
        }
    }

    $skipped  = New-Object System.Collections.Generic.List[object]
    $toDelete = New-Object System.Collections.Generic.List[object]
    foreach ($row in $rows) {
        $match = if ($patterns.Count -gt 0) { Get-MatchingException -UserId $row.UserId -Patterns $patterns } else { $null }
        if ($match) {
            [void]$skipped.Add([pscustomobject]@{ Row = $row; Exception = $match })
        } else {
            [void]$toDelete.Add($row)
        }
    }

    if ($skipped.Count -gt 0) {
        Write-Warning "$($skipped.Count) user(s) matched an exception pattern and will NOT be deleted:"
        $skipped | ForEach-Object { Write-Warning "  $($_.Row.UserId)  (matched '$($_.Exception)')" }
    }
    if ($toDelete.Count -eq 0) {
        Write-Host "Nothing to delete after applying exceptions." -ForegroundColor Yellow
        # Still produce an output CSV so the caller has a record.
        $skippedIndex = 0
        $out = @(foreach ($s in $skipped) {
            $skippedIndex++
            [pscustomobject]@{
                Row              = $skippedIndex
                Operation        = 'DeleteUser'
                Success          = $false
                StatusCode       = 'SKIPPED'
                StatusMessage    = "Matched exception pattern '$($s.Exception)'"
                RequestId        = $null
                BackupFile       = $null
                Error            = $null
                JurisdictionHash = $s.Row.JurisdictionHash
                UserId           = $s.Row.UserId
            }
        })
        if ($out.Count -gt 0) { $out | Export-Csv -NoTypeInformation -LiteralPath $OutFile }
        Write-Host "Wrote $($skipped.Count) result rows (all skipped) to $OutFile"
        return
    }

    $bulkParams = @{ Operation = 'DeleteUser'; ThrottleSeconds = 0.2 }
    if ($SkipBackup) { $bulkParams.SkipBackup = $true } else { $bulkParams.BackupPath = $BackupPath }

    $processed = 0
    $total     = $toDelete.Count
    $activity  = "Deleting VIP users (BackupPath = $BackupPath)"
    $started   = Get-Date
    $results   = @($toDelete | Invoke-SymantecVipBulkOperation @bulkParams | ForEach-Object {
        $processed++
        $pct     = [int](($processed / $total) * 100)
        $elapsed = (Get-Date) - $started
        $avg     = if ($processed) { $elapsed.TotalSeconds / $processed } else { 0 }
        $etaSec  = [int](($total - $processed) * $avg)
        $state   = if ($_.Success) { 'OK' } elseif ($_.StatusCode) { $_.StatusCode } else { 'FAIL' }
        Write-Progress -Activity $activity `
            -Status  ("[{0}/{1}] {2}  [{3}]" -f $processed, $total, $_.Input.UserId, $state) `
            -PercentComplete $pct `
            -SecondsRemaining $etaSec
        $_
    })
    Write-Progress -Activity $activity -Completed
    $results | Format-Table Row, Success, StatusCode, StatusMessage -AutoSize

    # Combined output CSV: skipped rows first (for prominence), then processed rows.
    # @() guards ensure $out is always an array so += works even for single rows.
    $skippedIndex = 0
    $out = @(foreach ($s in $skipped) {
        $skippedIndex++
        [pscustomobject]@{
            Row              = $skippedIndex
            Operation        = 'DeleteUser'
            Success          = $false
            StatusCode       = 'SKIPPED'
            StatusMessage    = "Matched exception pattern '$($s.Exception)'"
            RequestId        = $null
            BackupFile       = $null
            Error            = $null
            JurisdictionHash = $s.Row.JurisdictionHash
            UserId           = $s.Row.UserId
        }
    })
    $out += @(foreach ($r in $results) {
        [pscustomobject]@{
            Row              = $skippedIndex + $r.Row
            Operation        = $r.Operation
            Success          = $r.Success
            StatusCode       = $r.StatusCode
            StatusMessage    = $r.StatusMessage
            RequestId        = $r.RequestId
            BackupFile       = $r.BackupFile
            Error            = $r.Error
            JurisdictionHash = $r.Input.JurisdictionHash
            UserId           = $r.Input.UserId
        }
    })
    $out | Export-Csv -NoTypeInformation -LiteralPath $OutFile

    $failed = @($results | Where-Object { -not $_.Success }).Count
    Write-Host ("Wrote {0} result rows to {1} (skipped={2}, deleted={3}, failed={4})" -f `
        $out.Count, $OutFile, $skipped.Count, ($results.Count - $failed), $failed)
} finally {
    Disconnect-SymantecVip
}
