# app/utils.py
import json
from pathlib import Path

LOG_FILE = Path("scan_history.json")

def log_scan(result: dict):
    history = []
    if LOG_FILE.exists():
        with open(LOG_FILE, "r") as f:
            try:
                history = json.load(f)
            except json.JSONDecodeError:
                history = []

    history.append(result)

    with open(LOG_FILE, "w") as f:
        json.dump(history, f, indent=2)
import hashlib
from pathlib import Path

def calculate_hash(file_path: str) -> str:
    """
    Calculate SHA-256 hash of a file.
    """
    sha256 = hashlib.sha256()
    path = Path(file_path)

    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)

    return sha256.hexdigest()

