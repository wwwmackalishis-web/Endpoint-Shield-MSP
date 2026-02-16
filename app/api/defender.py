# app/api/defender.py

from fastapi import APIRouter
from app.core.decision_engine import evaluate_event

router = APIRouter()

@router.post("/defender/events")
def ingest_events(payload: dict):
    results = []

    for event in payload.get("events", []):
        decision = evaluate_event(event)
        results.append(decision)

    return {"decisions": results}

