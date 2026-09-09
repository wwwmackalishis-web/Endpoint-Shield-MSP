# app/threat_intel.py
import requests
import os

VT_API_KEY = os.getenv("VT_API_KEY")

def virustotal_lookup(sha256: str) -> dict:
    if not VT_API_KEY:
        return {"error": "VT_API_KEY not set"}

    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": VT_API_KEY}

    r = requests.get(url, headers=headers)

    if r.status_code == 200:
        data = r.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "engine": "VirusTotal",
            "detections": data
        }

    return {"status": "not_found"}

