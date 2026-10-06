import argparse
import gzip
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from parser import normalize_event


def open_text(path):
    """open plain or gzip-compressed JSON Lines as text."""
    if path.suffix.lower() == ".gz":
        return gzip.open(path, "rt", encoding="utf-8-sig")
    return path.open("r", encoding="utf-8-sig")


def normalize_bots_record(record):
    """normalize one Splunk BOTS record through the XML parser."""
    result = record.get("result")
    if not isinstance(result, dict):
        raise ValueError("record does not contain a result object")

    raw_event = result.get("_raw")
    if not isinstance(raw_event, str) or not raw_event.strip():
        raise ValueError("record result does not contain a non-empty _raw event")

    try:
        root = ET.fromstring(raw_event.strip())
    except ET.ParseError as error:
        raise ValueError(f"_raw is not valid Windows Event XML: {error}") from error

    event = normalize_event(root)
    event["provenance"] = {
        "dataset": "botsv1",
        "input_format": "splunk_json",
        "sourcetype": result.get("sourcetype") or result.get("_sourcetype"),
        "splunk_source": result.get("source"),
        "splunk_time": result.get("_time"),
        "splunk_host": result.get("host"),
    }
    return event


def parse_bots_events(path, limit=None):
    """stream normalized events from a BOTS JSON Lines export."""
    emitted = 0

    with open_text(path) as input_file:
        for line_number, line in enumerate(input_file, start=1):
            if not line.strip():
                continue

            try:
                record = json.loads(line)
                if record.get("lastrow") is True and not isinstance(
                    record.get("result"), dict
                ):
                    continue
                event = normalize_bots_record(record)
            except (json.JSONDecodeError, ValueError) as error:
                raise ValueError(
                    f"Could not parse BOTS record on line {line_number}: {error}"
                ) from error

            yield event
            emitted += 1
            if limit is not None and emitted >= limit:
                return


def write_json_array(events, output):
    """write a JSON array without storing every event in memory."""
    output.write("[")
    first = True

    for event in events:
        if not first:
            output.write(",")
        output.write("\n")
        json.dump(event, output, indent=2)
        first = False

    if not first:
        output.write("\n")
    output.write("]\n")


def write_json_lines(events, output):
    """write one compact normalized JSON object per line."""
    for event in events:
        output.write(json.dumps(event, separators=(",", ":")))
        output.write("\n")


def build_argument_parser():
    parser = argparse.ArgumentParser(
        description="Normalize BOTS Splunk JSON Lines containing Windows Event XML."
    )
    parser.add_argument(
        "input",
        type=Path,
        help="path to a BOTS .json or .json.gz export",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="stop after this many events (useful for inspecting large datasets)",
    )
    parser.add_argument(
        "--output-format",
        choices=("json", "jsonl"),
        default="json",
        help="write a JSON array (default) or newline-delimited JSON",
    )
    return parser


def main():
    args = build_argument_parser().parse_args()
    if args.limit is not None and args.limit < 1:
        print("error: --limit must be greater than zero", file=sys.stderr)
        return 2

    try:
        events = parse_bots_events(args.input, limit=args.limit)
        if args.output_format == "jsonl":
            write_json_lines(events, sys.stdout)
        else:
            write_json_array(events, sys.stdout)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except BrokenPipeError:
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
