def calculate_threat_score(threat_type, severity):

    score = 0

    # Severity scoring
    severity_scores = {
        "low": 10,
        "medium": 40,
        "high": 70,
        "critical": 90
    }

    # Threat type scoring
    threat_scores = {
        "adware": 5,
        "spyware": 25,
        "malware": 50,
        "trojan": 65,
        "ransomware": 95
    }

    score += severity_scores.get(severity.lower(), 0)
    score += threat_scores.get(threat_type.lower(), 0)

    if score > 100:
        score = 100

    return score
