from app.core.file_utils import calculate_hash
from app.core.policy_engine import evaluate
from app.ai.analyzer import classify
from app.core.verdicts import VerdictType, Verdict
from app.core.logging_utils import log_scan
from app.defender.quarantine import quarantine_file


def scan_file(file_path: str) -> Verdict:
    # 1️⃣ Calculate file hash
    file_hash = calculate_hash(file_path)

    # 2️⃣ Policy-based evaluation
    verdict = evaluate(file_hash)

    # 3️⃣ AI fallback if policy is unknown
    if verdict.verdict == VerdictType.UNKNOWN:
        verdict = classify(file_path)

    # 4️⃣ Audit log
    log_scan(
        file_path=file_path,
        file_hash=file_hash,
        verdict=verdict.verdict.value,
        reason=verdict.reason,
        confidence=verdict.confidence
    )

    # 5️⃣ Enforce protection
    if verdict.verdict == VerdictType.MALICIOUS:
        quarantine_file(file_path)

    # 6️⃣ Return verdict
    return verdict




