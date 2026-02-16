import win32evtlog
import xml.etree.ElementTree as ET

DEFENDER_LOG = "Microsoft-Windows-Windows Defender/Operational"

DEFENDER_EVENTS = {
    1116: "ThreatDetected",
    1117: "ThreatRemediated",
    1121: "ASRBlocked",
    5007: "ConfigChanged"
}


def parse_event_xml(event):
    root = ET.fromstring(event.Xml)
    data = {}

    for elem in root.iter():
        if elem.tag.endswith("Data") and "Name" in elem.attrib:
            data[elem.attrib["Name"]] = elem.text

    return data


def normalize_event(event, parsed):
    return {
        "event_id": event.EventID,
        "event_type": DEFENDER_EVENTS.get(event.EventID, "Unknown"),
        "time_created": event.TimeGenerated.Format(),
        "computer": event.ComputerName,
        "threat_name": parsed.get("ThreatName"),
        "severity": parsed.get("Severity"),
        "file_path": parsed.get("Path"),
        "process": parsed.get("ProcessName"),
    }


def read_defender_events(limit=10):
    handle = win32evtlog.OpenEventLog("localhost", DEFENDER_LOG)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    events = win32evtlog.ReadEventLog(handle, flags, 0)

    results = []

    for event in events[:limit]:
        if event.EventID in DEFENDER_EVENTS:
            parsed = parse_event_xml(event)
            results.append(normalize_event(event, parsed))

    win32evtlog.CloseEventLog(handle)
    return results


if __name__ == "__main__":
    for evt in read_defender_events():
        print(evt)

