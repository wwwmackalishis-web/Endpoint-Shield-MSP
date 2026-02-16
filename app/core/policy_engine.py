from app.core.verdicts import Verdict, VerdictType

# Example hardcoded malicious hashes (demo only)
KNOWN_BAD_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}

def evaluate(file_hash: str) -> Verdict:
    if file_hash in KNOWN_BAD_HASHES:
        return Verdict(
            verdict=VerdictType.MALICIOUS,
            reason="Matched known malicious hash",
            confidence=1.0
        )

    return Verdict(
        verdict=VerdictType.UNKNOWN,
        reason="No matching policy rule"
    )
