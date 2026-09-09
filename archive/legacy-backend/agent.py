import time
import os
import requests
import hashlib
from pathlib import Path
from signatures import SIGNATURES

SERVER = "http://127.0.0.1:9000"
HOSTNAME = os.getenv("COMPUTERNAME", "Agent1")
IP = "10.0.0.253"
TENANT_ID = 1

DEVICE_REG = requests.post(f"{SERVER}/devices/", json={"hostname": HOSTNAME,"ip_address":IP,"tenant_id":TENANT_ID}).json()
print(f"Device registered: {DEVICE_REG}")

SCAN_DIR = Path("scan")

while True:
    for f in SCAN_DIR.iterdir():
        if f.is_file():
            file_hash = hashlib.md5(f.read_bytes()).hexdigest()
            if file_hash in SIGNATURES:
                threat = {"file_hash": file_hash, "threat_type":"Test","severity":"High"}
                requests.post(f"{SERVER}/threats/", json=threat)
                print(f"Threat reported: {threat}")

    heartbeat = {"hostname": HOSTNAME, "status":"online", "os":os.name}
    r = requests.post(f"{SERVER}/agents/heartbeat", json=heartbeat)
    print(f"Heartbeat sent: {r.status_code}")

    time.sleep(10)
