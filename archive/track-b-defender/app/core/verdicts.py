from enum import Enum
from dataclasses import dataclass
from typing import Optional

class VerdictType(str, Enum):
    CLEAN = "clean"
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"

@dataclass
class Verdict:
    verdict: VerdictType
    reason: str
    confidence: Optional[float] = None
