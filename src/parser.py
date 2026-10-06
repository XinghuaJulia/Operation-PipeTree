import argparse
import json
import sqlite3
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from sqlite_store import store_events


EVENT_NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"
NS = {"event": EVENT_NAMESPACE}


def child_text(parent, name):
    """find a namespaced direct child and return its text."""
    if parent is None:
        return None

    element = parent.find(f"event:{name}", NS)
    return element.text if element is not None else None


def parse_user(data):
    """return the user as domain\\username when the domain is available."""
    user = data.get("User")
    if user:
        return user

    username = data.get("SubjectUserName")
    domain = data.get("SubjectDomainName")
    if domain and domain != "-" and username:
        return f"{domain}\\{username}"
    return username


def parse_hashes(value):
    """convert Sysmon hashes to a dictionary with lowercase algorithm names."""
    hashes = {}
    for item in (value or "").split(","):
        algorithm, separator, digest = item.strip().partition("=")
        if separator and algorithm and digest:
            hashes[algorithm.lower()] = digest
    return hashes


def parse_process_id(value):
    """convert a decimal or hexadecimal Windows process ID to an integer."""
    if value is None:
        return None

    try:
        return int(value, 0)
    except ValueError:
        return value


def parse_boolean(value):
    """convert Windows event boolean strings and preserve unknown values."""
    if value is None:
        return None

    normalized = value.strip().lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    return value


def normalize_event(root):
    """normalize one Windows Event XML element."""
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

    # event 4688 uses NewProcess* for the child and ProcessId for the parent
    # sysmon event 1 uses Process* for the child and ParentProcess* for the parent
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
        "user": parse_user(event_data),
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
    """parse a log containing one Windows Event XML record per line."""
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
    """build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Normalize newline-delimited Windows Event XML as JSON."
    )
    parser.add_argument("input", type=Path, help="path to the Windows event log")
    parser.add_argument(
        "--database",
        type=Path,
        help="store normalized events in this SQLite database",
    )
    return parser


def main():
    """run the parser command-line interface."""
    args = build_argument_parser().parse_args()

    try:
        events = parse_events(args.input)
        if args.database:
            count = store_events(args.database, events)
            print(f"stored {count} events in {args.database}")
        else:
            print(json.dumps(list(events), indent=2))
    except (OSError, sqlite3.Error, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
