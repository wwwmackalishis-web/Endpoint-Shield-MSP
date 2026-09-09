from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from database import engine, get_db
from models import Base, Tenant, Device, Threat
from pydantic import BaseModel

Base.metadata.create_all(bind=engine)

app = FastAPI(title='Mackalishis AV')

# Pydantic Schemas
class TenantCreate(BaseModel):
    name: str
    address: str = None

class DeviceCreate(BaseModel):
    hostname: str
    ip_address: str
    tenant_id: int

class ThreatCreate(BaseModel):
    file_hash: str
    threat_type: str
    severity: str

# Root
@app.get('/')
def root():
    return {"service":"Mackalishis AV","version":"0.1"}

# Tenants
@app.post('/tenants/')
def add_tenant(tenant: TenantCreate, db: Session = Depends(get_db)):
    db_tenant = Tenant(name=tenant.name, address=tenant.address)
    db.add(db_tenant)
    db.commit()
    db.refresh(db_tenant)
    return db_tenant

@app.get('/tenants/')
def list_tenants(db: Session = Depends(get_db)):
    return db.query(Tenant).all()

# Devices
@app.post('/devices/')
def add_device(device: DeviceCreate, db: Session = Depends(get_db)):
    db_device = Device(
        hostname=device.hostname,
        ip_address=device.ip_address,
        tenant_id=device.tenant_id
    )
    db.add(db_device)
    db.commit()
    db.refresh(db_device)
    return db_device

@app.get('/devices/')
def list_devices(db: Session = Depends(get_db)):
    return db.query(Device).all()

# Threats
@app.post('/threats/')
def add_threat(threat: ThreatCreate, db: Session = Depends(get_db)):
    db_threat = Threat(
        file_hash=threat.file_hash,
        threat_type=threat.threat_type,
        severity=threat.severity
    )
    db.add(db_threat)
    db.commit()
    db.refresh(db_threat)
    return db_threat

@app.get('/threats/')
def list_threats(db: Session = Depends(get_db)):
    return db.query(Threat).all()
