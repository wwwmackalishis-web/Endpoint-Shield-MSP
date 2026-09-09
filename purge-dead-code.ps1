# Removes backend attempts superseded by app/main.py, plus other confirmed
# dead files. None of these are tracked by git (only app/ is - check with
# `git status`), so this is not a git-reversible operation: it's a real
# delete. Defaults to a dry run; pass -Apply to actually remove anything.
#
# Usage:
#   .\purge-dead-code.ps1            # lists what would be removed
#   .\purge-dead-code.ps1 -Apply     # actually removes it
param(
    [switch]$Apply
)

$root = $PSScriptRoot

$targets = @(
    # Superseded backend attempts (app/main.py is the one that's live and tested)
    "$root\main.py",
    "$root\api\devices.py",
    "$root\api",                       # remove the now-empty directory too
    "$root\backend\app.py",
    "$root\backend",
    "$root\database.py",
    "$root\models.py",
    "$root\app\models.py",             # corrupted: a PowerShell heredoc saved as .py
    "$root\app\database.py",           # points at msp.db, never imported by app/main.py
    "$root\app\api\routes.py",         # empty file

    # Retired agent (incompatible schema - see agent.ps1's own header comment)
    "$root\agent.py",
    "$root\signatures.py",

    # Orphaned databases - only devices.db (via MSP_DB_PATH) is live
    "$root\mackalishis_av.db",
    "$root\msp.db",
    "$root\temp.db",

    # Frontend leftovers
    "$root\msp-dashboard\devices.json",
    "$root\msp-dashboard\src\hello-node.js"
)

$found = $targets | Where-Object { Test-Path $_ }

if (-not $found) {
    Write-Host "Nothing to remove - already clean."
    exit 0
}

Write-Host "$(if ($Apply) { 'Removing' } else { '[DRY RUN] Would remove' }) $($found.Count) item(s):"
$found | ForEach-Object { Write-Host "  - $_" }

if (-not $Apply) {
    Write-Host "`nRe-run with -Apply to actually delete these."
    exit 0
}

foreach ($path in $found) {
    Remove-Item -Path $path -Recurse -Force
}
Write-Host "`nDone."
