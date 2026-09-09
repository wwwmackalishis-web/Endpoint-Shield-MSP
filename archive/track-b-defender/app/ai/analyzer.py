from app.core.verdicts import Verdict, VerdictType

def classify(file_path: str) -> Verdict:
    # Placeholder AI logic
    return Verdict(
        verdict=VerdictType.SUSPICIOUS,
        reason="AI heuristic classification",
        confidence=0.72
    )
