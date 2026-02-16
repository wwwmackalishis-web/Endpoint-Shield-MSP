from fastapi import FastAPI
from app.api import scan, defender

app = FastAPI(title="Mackalishis AV")

app.include_router(scan.router, prefix="/api", tags=["scan"])
app.include_router(defender.router, prefix="/api", tags=["defender"])

@app.get("/")
def root():
    return {
        "service": "Mackalishis AV",
        "app_version": "0.1.0",
        "policy_version": "1.0.0"
    }


