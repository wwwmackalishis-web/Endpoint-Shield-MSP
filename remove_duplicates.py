from app.database import SessionLocal
from app.models import Device
db = SessionLocal()
seen = {}
for d in db.query(Device).all():
    if d.hostname in seen:
        db.delete(d)
    else:
        seen[d.hostname] = True
db.commit()
db.close()
