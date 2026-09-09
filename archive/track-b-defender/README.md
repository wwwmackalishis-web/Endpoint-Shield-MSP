# Track B — Defender / AI Orchestration (archived)

Moved here instead of deleted because it's real design work, not junk — but
it wasn't wired into app/main.py, and enabling it as-is would present fake
results as real ones:

- app/core/policy_engine.py matches exactly one demo hash — the SHA-256 of
  an empty file (a well-known placeholder value, not real threat intel).
- app/ai/analyzer.py is a hardcoded stub that returns "SUSPICIOUS" at 0.72
  confidence for every input, unconditionally.
- Combined, any file that misses the one demo hash gets flagged suspicious
  100% of the time — that's not a working detector, it's a coin that always
  lands on "suspicious."

To bring this back for a real Phase 2: replace policy_engine's hash set
with a real feed, replace analyzer.py's stub with a real model or
heuristic, then mount the routers in app/main.py with
`app.include_router(...)` and give the whole path its own
verify_api.py-style end-to-end test before it ever runs against a real
endpoint.
