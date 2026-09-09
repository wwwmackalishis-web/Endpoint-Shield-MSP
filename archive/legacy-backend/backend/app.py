# app.py - Mackalishis AV API
from fastapi import FastAPI, UploadFile, File, HTTPException, Header, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Dict, Optional
from datetime import datetime
import os
import shutil

# -------------------------------
# Config
# -------------------------------
API_KEY = "supersecretapikey"
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# -------------------------------
# Authentication Dependency
# -------------------------------
def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

# -------------------------------
# Pydantic Models
# -------------------------------
class Event(BaseModel):
    timestamp: Optional[str] = datetime.utcnow().isoformat()
    type: str
    details: Dict

class EventsPayload(BaseModel):
    events: List[Event]

# -------------------------------
# App Initialization
# -------------------------------
app = FastAPI(title="Mackalishis AV API", version="0.1.0")

# -------------------------------
# Health Check
# -------------------------------
@app.get("/")
async def root():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}

# -------------------------------
# Scan Endpoint
# -------------------------------
@app.post("/api/scan")
async def scan_file(file: UploadFile = File(...), x_api_key: str = Depends(verify_api_key)):
    if not file.filename:
        raise HTTPException(status_code=422, detail="No file uploaded")
    
    temp_path = os.path.join(UPLOAD_DIR, file.filename)
    
    try:
        with open(temp_path, "wb") as f:
            shutil.copyfileobj(file.file, f)

        # TODO: Insert real scan logic here
        verdict = "clean"  # or "infected"

        # Remove file after scanning
        os.remove(temp_path)

        return {"filename": file.filename, "verdict": verdict}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# -------------------------------
# Defender Events Endpoint
# -------------------------------
@app.post("/api/defender/events")
async def ingest_events(payload: EventsPayload, x_api_key: str = Depends(verify_api_key)):
    try:
        log_file = os.path.join(UPLOAD_DIR, "events.log")
        with open(log_file, "a") as f:
            for event in payload.events:
                f.write(f"{datetime.utcnow().isoformat()} - {event.json()}\n")
        return {"status": "success", "count": len(payload.events)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
