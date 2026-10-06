import argparse
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


EVENT_NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"
NS = {"event": EVENT_NAMESPACE}


# finds namespaced direct child and return the text
def child_text(parent, name):
    if parent is None:
        return None

    element = parent.find(f"event:{name}", NS)
    return element.text if element is not None else None


# checks dictioinary keys in order and returns the first non-empty value
def first_value(data, *names):
    return next((data[name] for name in names if data.get(name)), None)

# convert sysmon hashes to a dictionary of algorithm:hash, all lower case
def parse_hashes(value):
    hashes = {}
    for item in (value or "").split(","):
        algorithm, separator, digest = item.strip().partition("=")
        if separator and algorithm and digest:
            hashes[algorithm.lower()] = digest
    return hashes

# parses decimal/hexadecimal windows PID to int
def parse_process_id(value):
    if value is None:
        return None

    try:
        return int(value, 0)
    except ValueError:
        return value


def parse_boolean(value):
    """Convert common Windows event boolean strings while preserving unknown values."""
    if value is None:
        return None

    normalized = value.strip().lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    return value


def normalize_event(root):
    system = root.find("event:System", NS)
    if system is None:
        raise ValueError("Event has no System element")

    event_id_text = child_text(system, "EventID")
    try:
        event_id = int(event_id_text) if event_id_text is not None else None
    except ValueError:
        event_id = event_id_text

    provider = system.find("event:Provider", NS)
    time_created = system.find("event:TimeCreated", NS)
    event_data = {
        element.get("Name"): element.text
        for element in root.findall("event:EventData/event:Data", NS)
        if element.get("Name")
    }

    # Security event 4688 describes the created process with NewProcess* and
    # the creator/parent with ProcessId and ParentProcessName. Sysmon event 1
    # uses Process* and ParentProcess* consistently.
    if event_id == 4688:
        process_pid = event_data.get("NewProcessId")
        process_image = event_data.get("NewProcessName")
        parent_pid = event_data.get("ProcessId")
        parent_image = event_data.get("ParentProcessName")
    else:
        process_pid = event_data.get("ProcessId")
        process_image = event_data.get("Image")
        parent_pid = event_data.get("ParentProcessId")
        parent_image = event_data.get("ParentImage")

    event = {
        "event_id": event_id,
        "time_created": (
            time_created.get("SystemTime") if time_created is not None else None
        ),
        "file_hashes": parse_hashes(event_data.get("Hashes")),
        "hostname": child_text(system, "Computer"),
        "user": first_value(event_data, "User", "SubjectUserName"),
        "parent_process": {
            "guid": event_data.get("ParentProcessGuid"),
            "pid": parse_process_id(parent_pid),
            "image": parent_image,
            "command_line": event_data.get("ParentCommandLine"),
        },
        "source": provider.get("Name") if provider is not None else None,
        "process_guid": event_data.get("ProcessGuid"),
        "process_pid": parse_process_id(process_pid),
        "process_image": process_image,
        "process_command_line": event_data.get("CommandLine"),
    }

    if event_id == 2:
        event["file"] = {
            "path": event_data.get("TargetFilename"),
            "creation_time": event_data.get("CreationUtcTime"),
            "previous_creation_time": event_data.get("PreviousCreationUtcTime"),
        }

    if event_id == 3:
        event["network"] = {
            "protocol": event_data.get("Protocol"),
            "initiated": parse_boolean(event_data.get("Initiated")),
            "source": {
                "ip": event_data.get("SourceIp"),
                "hostname": event_data.get("SourceHostname"),
                "port": parse_process_id(event_data.get("SourcePort")),
                "port_name": event_data.get("SourcePortName"),
                "is_ipv6": parse_boolean(event_data.get("SourceIsIpv6")),
            },
            "destination": {
                "ip": event_data.get("DestinationIp"),
                "hostname": event_data.get("DestinationHostname"),
                "port": parse_process_id(event_data.get("DestinationPort")),
                "port_name": event_data.get("DestinationPortName"),
                "is_ipv6": parse_boolean(event_data.get("DestinationIsIpv6")),
            },
        }

    if event_id == 6:
        event["driver"] = {
            "path": event_data.get("ImageLoaded"),
            "signed": parse_boolean(event_data.get("Signed")),
            "signature": event_data.get("Signature"),
            "signature_status": event_data.get("SignatureStatus"),
        }

    if event_id == 7:
        event["loaded_image"] = {
            "path": event_data.get("ImageLoaded"),
            "file_version": event_data.get("FileVersion"),
            "description": event_data.get("Description"),
            "product": event_data.get("Product"),
            "company": event_data.get("Company"),
            "original_file_name": event_data.get("OriginalFileName"),
            "signed": parse_boolean(event_data.get("Signed")),
            "signature": event_data.get("Signature"),
            "signature_status": event_data.get("SignatureStatus"),
        }

    return event


def parse_events(path):
    """Parse a log containing one complete Windows Event XML record per line."""
    with path.open("r", encoding="utf-8-sig") as input_file:
        for line_number, line in enumerate(input_file, start=1):
            if not line.strip():
                continue

            try:
                root = ET.fromstring(line)
                yield normalize_event(root)
            except (ET.ParseError, ValueError) as error:
                raise ValueError(f"Could not parse event on line {line_number}: {error}") from error


def build_argument_parser():
    parser = argparse.ArgumentParser(
        description="Normalize newline-delimited Windows Event XML as JSON."
    )
    parser.add_argument("input", type=Path, help="path to the Windows event log")
    return parser


def main():
    args = build_argument_parser().parse_args()

    try:
        events = list(parse_events(args.input))
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    print(json.dumps(events, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
