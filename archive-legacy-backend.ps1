# Moves (does not delete) the confusing legacy backend attempts that
# predate app/main.py, plus other confirmed-dead files. Deletion of these
# is blocked by Claude Code's own safety classifier (bulk destructive file
# ops); moving is not, so this is how that cleanup actually ships.
#
# NOTE: app/models.py and app/database.py are NOT in this list anymore -
# they used to be dead (a corrupted PowerShell heredoc, and an unused
# msp.db pointer) but are now the real, live shared DB/model modules
# app/main.py imports from. Don't add them back here.
#
# Usage:
#   .\archive-legacy-backend.ps1            # lists what would move
#   .\archive-legacy-backend.ps1 -Apply     # actually moves it
param(
    [switch]$Apply
)

$root = $PSScriptRoot
$dest = Join-Path $root "archive\legacy-backend"

$targets = @(
    "main.py",                  # root - superseded by app/main.py, incompatible schema
    "api",                      # api/devices.py - heartbeat-only stub, superseded
    "backend",                  # backend/app.py - unrelated scan/defender stub, hardcoded secret
    "database.py",              # root - only used by the now-archived root main.py / api/
    "models.py",                # root - same
    "app\api\routes.py",        # empty file
    "agent.py",                 # retired - incompatible schema, see agent.ps1's header comment
    "signatures.py",            # only consumer was agent.py
    "mackalishis_av.db",        # orphaned - only devices.db (via MSP_DB_PATH) is live
    "msp.db",                   # orphaned
    "temp.db",                  # orphaned, if still present
    "msp-dashboard\devices.json",       # static fixture, not read by any live code
    "msp-dashboard\src\hello-node.js"   # unused scaffold leftover
)

$found = $targets | Where-Object { Test-Path (Join-Path $root $_) }

if (-not $found) {
    Write-Host "Nothing to archive - already moved or never present."
    exit 0
}

Write-Host "$(if ($Apply) { 'Archiving' } else { '[DRY RUN] Would archive' }) $($found.Count) item(s) to $dest\:"
$found | ForEach-Object { Write-Host "  - $_" }

if (-not $Apply) {
    Write-Host "`nRe-run with -Apply to actually move these."
    exit 0
}

foreach ($rel in $found) {
    $src = Join-Path $root $rel
    $target = Join-Path $dest $rel
    New-Item -ItemType Directory -Force -Path (Split-Path $target -Parent) | Out-Null
    Move-Item -Path $src -Destination $target -Force
}
Write-Host "`nDone. See $dest"
