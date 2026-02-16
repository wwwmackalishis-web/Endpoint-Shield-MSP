import sys
import json

sys.path.append("..\\..")

from app.core.decision_engine import evaluate_event

if __name__ == "__main__":
    raw_event = json.loads(sys.argv[1])
    decision = evaluate_event(raw_event)
    print(json.dumps(decision))
