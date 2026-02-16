# Copilot / AI Agent Instructions for `antivirus-orchestrator` 🔧

Summary
- Small FastAPI-based microservice that receives file uploads, hashes them, queries VirusTotal, runs a (currently simulated) Defender scan, and logs results to `scan_history.json`. ✅

How the code is organized (big picture)
- `app/main.py` — FastAPI app and HTTP endpoints
  - GET `/` health/status
  - POST `/scan/file` - accepts a file upload and performs the pipeline
- `app/scanner.py` — file hashing (SHA256). Use `hash_file(path) -> {path, sha256}`.
- `app/threat_intel.py` — VirusTotal lookup (uses `VT_API_KEY` env var; returns `{"error": "VT_API_KEY not set"}` when missing).
- `app/defender.py` — OS antivirus integration interface (currently returns a simulated result). Replace/extend this to call real platform scanners.
- `app/utils.py` — logging to `scan_history.json` (a JSON array). Handles corrupt/empty log files gracefully.
- `uploads/` — files uploaded by the service. Created at start.

Key behaviors & patterns (be explicit)
- Files are saved under `uploads/<original_filename>` with no sanitization or collision handling — changes here will affect all downstream behavior (hashing, scanning, logging).
- The scan pipeline order in `app/main.py` is: hash -> VirusTotal lookup -> Defender scan -> combine result -> log. Modifying order or making steps parallel requires updating `log_scan` expectations and tests.
- `threat_intel.virustotal_lookup(sha256)` uses `requests` to call VirusTotal API and returns either `{ "engine": "VirusTotal", "detections": {...} }`, `{ "status": "not_found" }` or the `error` dict above.
- `app/utils.log_scan` writes the complete scan result into `scan_history.json` as an appended element.
- `print("🔥 THIS IS THE ACTIVE main.py 🔥")` is intentionally present and is a useful local runtime marker for which file is being executed when debugging.

Running & debugging locally
- Install dependencies: `pip install -r requirements.txt`
- Start app (development):
  - `uvicorn app.main:app --reload --port 8000` or `python -m uvicorn app.main:app --reload --port 8000`
  - Verify health: `curl http://127.0.0.1:8000/`
- Example upload tests:
  - `curl -X POST http://127.0.0.1:8000/scan/file -F "file=@<path-to-file>"`
  - Or run the provided `test_upload.py` while server is running (`python test_upload.py`).

Environment & external integrations
- VirusTotal API: set `VT_API_KEY` in the environment to enable real lookups. When unset, `virustotal_lookup` returns `{ "error": "VT_API_KEY not set" }`.
- No other external services are required to run locally.

Files & formats to inspect when changing behavior
- Incoming POST response shape (returned by `/scan/file`):
  - `file_info` => `{ path, sha256 }`
  - `virustotal` => either `{ engine, detections }`, `{ status: "not_found" }`, or `{ error: ... }`
  - `defender_scan` => `{ engine, file, status, threat_detected }`
- `scan_history.json` is a JSON array where each element is the combined result object returned by `/scan/file`.

Testing guidance specific to this repo
- There is no pytest suite yet; use `test_upload.py` as an integration smoke test.
- When writing unit tests for `app/threat_intel.py`, avoid calling VirusTotal directly. Use dependency injection or mock `requests.get` and assert the returned dict structure.
- When testing `app/defender.py`, tests should assert expected structure (engine/name/status) since the implementation is a stub.

Conventions & small pitfalls
- Use relative paths as in current modules (e.g., `Path("uploads")` / `Path("scan_history.json")`) — the runtime working directory is the repo root in the standard dev workflow.
- The codebase currently uses synchronous I/O (blocking read/write). If you convert to async file I/O, update endpoint signatures and tests accordingly.
- Filename handling: uploaded filenames are used directly; consider sanitization if adding production features.

Where to implement common changes
- Add/replace real Windows Defender integration: `app/defender.py` (module-level function `scan_with_defender(file_path: str)`) — keep function signature to avoid widespread changes.
- Add caching of VT lookups or rate-limit handling in `app/threat_intel.py`.
- Centralize configuration (port, upload dir, VT key) into a `settings.py` / env-aware config if multiple services or deployments are planned.

Examples (quick copy/paste)
- Run dev server:
```
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```
- Example cURL upload:
```
curl -X POST http://127.0.0.1:8000/scan/file -F "file=@C:\Windows\System32\notepad.exe"
```

If anything above is unclear or you want me to add examples for CI, automated tests, or a recommended implementation plan for real Defender integration, tell me which part to expand. ✨
