# app/core/decision_engine.py

def evaluate_event(event: dict) -> dict:
    """
    Core AI decision logic for Defender events
    """

    severity = event.get("severity", "low")
    confidence = float(event.get("confidence", 0))

    verdict = "benign"
    action = "allow"

    if severity == "high" or confidence >= 0.8:
        verdict = "malicious"
        action = "quarantine"
    elif severity == "medium" or confidence >= 0.5:
        verdict = "suspicious"
        action = "monitor"

    return {
        "threat": event.get("threat", "unknown"),
        "verdict": verdict,
        "action": action,
        "confidence": confidence,
    }

