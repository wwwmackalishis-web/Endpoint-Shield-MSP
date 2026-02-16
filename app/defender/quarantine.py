import subprocess
import logging
from pathlib import Path


def quarantine_file(file_path: str):
    """
    Send a file to Windows Defender for quarantine.
    Defender decides the final action.
    """
    file = Path(file_path)

    if not file.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    command = [
        "powershell",
        "-Command",
        f"Start-MpScan -ScanPath '{file.absolute()}'"
    ]

    try:
        subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
        logging.warning(f"File sent to Defender quarantine: {file_path}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Defender quarantine failed: {e.stderr}")
        raise RuntimeError("Defender quarantine failed")
