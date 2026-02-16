from fastapi import APIRouter, UploadFile, File, HTTPException
from pathlib import Path
import shutil
import uuid

from app.orchestration.scanner import scan_file

# Create uploads folder if it doesn't exist
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

router = APIRouter()


@router.post("/scan")
async def scan_uploaded_file(file: UploadFile = File(...)):
    # 1️⃣ Create a unique filename
    file_id = uuid.uuid4().hex
    file_path = UPLOAD_DIR / f"{file_id}_{file.filename}"

    try:
        # 2️⃣ Save the uploaded file to disk
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # 3️⃣ Run the AI + policy scan pipeline
        verdict = scan_file(str(file_path))

        # 4️⃣ Return JSON verdict
        return {
            "filename": file.filename,
            "verdict": verdict.verdict.value,
            "reason": verdict.reason,
            "confidence": verdict.confidence
        }

    except Exception as e:
        # If anything fails, return HTTP 500
        raise HTTPException(status_code=500, detail=str(e))

