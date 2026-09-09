def classify_threat(threat_type):

    threat_map = {
        "adware": "LOW",
        "spyware": "MEDIUM",
        "trojan": "HIGH",
        "malware": "HIGH",
        "ransomware": "CRITICAL",
        "rootkit": "CRITICAL"
    }

    return threat_map.get(threat_type.lower(), "MEDIUM")
