from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from datetime import datetime
from database import get_db
from models import Device

router = APIRouter()

@router.post("/api/agent/heartbeat")
def heartbeat(data: dict, db: Session = Depends(get_db)):

    hostname = data.get("hostname")

    device = db.query(Device).filter(Device.hostname == hostname).first()

    if not device:
        device = Device(
            hostname=hostname,
            ip_address=data.get("ip"),
            os=data.get("os"),
            agent_version=data.get("agent_version")
        )
        db.add(device)

    device.last_seen = datetime.utcnow()

    db.commit()

    return {"status": "ok"}
