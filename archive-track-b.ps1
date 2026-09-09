# Archives the Defender/AI scan subsystem (Track B) instead of deleting it -
# see the recommendation in chat for why it isn't being wired into app/main.py
# right now. Moves (not deletes) app/api, app/core, app/ai, app/defender,
# and app/orchestration under archive/track-b-defender/, preserving structure,
# so the code is out of the way but not lost for a real Phase 2 build-out.
# app/main.py imports nothing from any of these - confirmed safe to move.
#
# Usage:
#   .\archive-track-b.ps1            # lists what would move
#   .\archive-track-b.ps1 -Apply     # actually moves it
param(
    [switch]$Apply
)

$root = $PSScriptRoot
$dest = Join-Path $root "archive\track-b-defender"

$dirs = @("app\api", "app\core", "app\ai", "app\defender", "app\orchestration")
$found = $dirs | Where-Object { Test-Path (Join-Path $root $_) }

if (-not $found) {
    Write-Host "Nothing to archive - already moved or never present."
    exit 0
}

Write-Host "$(if ($Apply) { 'Archiving' } else { '[DRY RUN] Would archive' }) to $dest\:"
$found | ForEach-Object { Write-Host "  - $_" }

if (-not $Apply) {
    Write-Host "`nRe-run with -Apply to actually move these."
    exit 0
}

New-Item -ItemType Directory -Force -Path $dest | Out-Null
foreach ($rel in $found) {
    $src = Join-Path $root $rel
    $target = Join-Path $dest $rel
    New-Item -ItemType Directory -Force -Path (Split-Path $target -Parent) | Out-Null
    Move-Item -Path $src -Destination $target -Force
}

$readme = Join-Path $dest "README.md"
@"
# Track B - Defender / AI Orchestration (archived)

Moved here instead of deleted because it's real design work, not junk - but
it wasn't wired into app/main.py, and enabling it as-is would present fake
results as real ones:

- app/core/policy_engine.py matches exactly one demo hash - the SHA-256 of
  an empty file (a well-known placeholder value, not real threat intel).
- app/ai/analyzer.py is a hardcoded stub that returns "SUSPICIOUS" at 0.72
  confidence for every input, unconditionally.
- Combined, any file that misses the one demo hash gets flagged suspicious
  100% of the time - that's not a working detector, it's a coin that always
  lands on "suspicious."

To bring this back for a real Phase 2: replace policy_engine's hash set
with a real feed, replace analyzer.py's stub with a real model or
heuristic, then mount the routers in app/main.py with
``app.include_router(...)`` and give the whole path its own
verify_api.py-style end-to-end test before it ever runs against a real
endpoint.
"@ | Set-Content -Path $readme

Write-Host "`nDone. See $readme"
