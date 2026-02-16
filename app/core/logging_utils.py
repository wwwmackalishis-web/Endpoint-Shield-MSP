import logging
from pathlib import Path

# Create logs folder if it doesn't exist
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

LOG_FILE = LOG_DIR / "scan.log"

# Configure logging
logging.basicConfig(
    filename=LOG_FILE,
    filemode="a",
    format="%(asctime)s | %(levelname)s | %(message)s",
    level=logging.INFO
)

def log_scan(file_path: str, file_hash: str, verdict: str, reason: str, confidence: float = None):
    msg = f"File: {file_path} | Hash: {file_hash} | Verdict: {verdict} | Reason: {reason}"
    if confidence is not None:
        msg += f" | Confidence: {confidence:.2f}"
    logging.info(msg)
