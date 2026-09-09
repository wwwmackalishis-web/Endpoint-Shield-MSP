# app/defender.py

def scan_with_defender(file_path: str) -> dict:
    # Simulated Windows Defender scan
    return {
        "engine": "Windows Defender",
        "file": file_path,
        "status": "scan simulated",
        "threat_detected": False
    }

