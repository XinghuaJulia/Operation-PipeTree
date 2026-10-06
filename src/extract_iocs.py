import argparse
import ipaddress
import json
import re
import sqlite3
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
TRAILING_URL_CHARACTERS = ").,;:!?]}"

CREATE_INDICATORS_TABLE = """
CREATE TABLE IF NOT EXISTS indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator_type TEXT NOT NULL,
    value TEXT NOT NULL,
    hash_algorithm TEXT,
    is_public INTEGER,
    first_seen TEXT,
    last_seen TEXT,
    occurrence_count INTEGER NOT NULL DEFAULT 0,
    UNIQUE(indicator_type, value)
)
"""

CREATE_INDICATOR_EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS indicator_events (
    indicator_id INTEGER NOT NULL,
    event_row_id INTEGER NOT NULL,
    source_field TEXT NOT NULL,
    PRIMARY KEY (indicator_id, event_row_id, source_field),
    FOREIGN KEY (indicator_id) REFERENCES indicators(id) ON DELETE CASCADE,
    FOREIGN KEY (event_row_id) REFERENCES events(id) ON DELETE CASCADE
)
"""

EVENT_COLUMNS = """
SELECT
    id,
    time_created,
    process_command_line,
    parent_process_command_line,
    source_ip,
    source_hostname,
    destination_ip,
    destination_hostname,
    hash_md5,
    hash_sha1,
    hash_sha256,
    hash_imphash
FROM events
"""

HASH_FIELDS = {
    "hash_md5": "md5",
    "hash_sha1": "sha1",
    "hash_sha256": "sha256",
    "hash_imphash": "imphash",
}


def normalize_ip(value):
    """normalize an IP address and report whether it is public."""
    if not value:
        return None
    try:
        address = ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return None
    is_public = not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )
    return address.compressed.lower(), is_public


def normalize_domain(value):
    """normalize a domain name."""
    if not value:
        return None

    domain = value.strip().rstrip(".").lower()
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    if len(domain) > 253 or "." not in domain:
        return None
    labels = domain.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not re.fullmatch(r"[a-z0-9-]+", label)
        for label in labels
    ):
        return None
    return domain


def normalize_url(value):
    """normalize an HTTP or HTTPS URL."""
    if not value:
        return None

    candidate = value.strip().rstrip(TRAILING_URL_CHARACTERS)
    try:
        parsed = urlsplit(candidate)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None

        host = normalize_ip(parsed.hostname)
        normalized_host = host[0] if host else normalize_domain(parsed.hostname)
        if not normalized_host:
            return None

        port = parsed.port
        if (parsed.scheme.lower(), port) in {("http", 80), ("https", 443)}:
            port = None
        host_for_url = f"[{normalized_host}]" if ":" in normalized_host else normalized_host
        netloc = host_for_url if port is None else f"{host_for_url}:{port}"
        if parsed.username:
            credentials = parsed.username
            if parsed.password:
                credentials += f":{parsed.password}"
            netloc = f"{credentials}@{netloc}"

        path = parsed.path or "/"
        return urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))
    except ValueError:
        return None


def normalize_hash(value, algorithm):
    """normalize a hash and validate its length."""
    if not value:
        return None
    normalized = value.strip().lower()
    expected_lengths = {"md5": 32, "sha1": 40, "sha256": 64, "imphash": 32}
    if len(normalized) != expected_lengths[algorithm]:
        return None
    if not re.fullmatch(r"[0-9a-f]+", normalized):
        return None
    return normalized


def urls_from_text(value):
    """extract normalized URLs from text."""
    if not value:
        return set()
    return {
        normalized
        for match in URL_PATTERN.findall(value)
        if (normalized := normalize_url(match)) is not None
    }


def indicators_from_event(event):
    """extract normalized indicators from one database event."""
    indicators = set()

    for field in ("source_ip", "destination_ip"):
        normalized = normalize_ip(event[field])
        if normalized:
            value, is_public = normalized
            indicators.add(("ip", value, None, is_public, field))

    for field in ("source_hostname", "destination_hostname"):
        value = normalize_domain(event[field])
        if value:
            indicators.add(("domain", value, None, None, field))

    for field in ("process_command_line", "parent_process_command_line"):
        for value in urls_from_text(event[field]):
            indicators.add(("url", value, None, None, field))
            hostname = urlsplit(value).hostname
            normalized_ip = normalize_ip(hostname)
            if normalized_ip:
                ip_value, is_public = normalized_ip
                indicators.add(("ip", ip_value, None, is_public, field))
            else:
                domain = normalize_domain(hostname)
                if domain:
                    indicators.add(("domain", domain, None, None, field))

    for field, algorithm in HASH_FIELDS.items():
        value = normalize_hash(event[field], algorithm)
        if value:
            indicators.add(("hash", value, algorithm, None, field))

    return indicators


def create_tables(connection):
    """create the IOC tables and indexes."""
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute(CREATE_INDICATORS_TABLE)
    connection.execute(CREATE_INDICATOR_EVENTS_TABLE)
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_indicators_type ON indicators(indicator_type)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_indicator_events_event "
        "ON indicator_events(event_row_id)"
    )


def store_indicator(connection, event, indicator, indicator_ids):
    """store one indicator and link it to its source event."""
    indicator_type, value, algorithm, is_public, source_field = indicator
    connection.execute(
        """
        INSERT INTO indicators (
            indicator_type,
            value,
            hash_algorithm,
            is_public,
            first_seen,
            last_seen,
            occurrence_count
        ) VALUES (?, ?, ?, ?, ?, ?, 1)
        ON CONFLICT(indicator_type, value) DO UPDATE SET
            first_seen = MIN(first_seen, excluded.first_seen),
            last_seen = MAX(last_seen, excluded.last_seen),
            occurrence_count = occurrence_count + 1
        """,
        (
            indicator_type,
            value,
            algorithm,
            is_public,
            event["time_created"],
            event["time_created"],
        ),
    )
    key = (indicator_type, value)
    indicator_id = indicator_ids.get(key)
    if indicator_id is None:
        indicator_id = connection.execute(
            "SELECT id FROM indicators WHERE indicator_type = ? AND value = ?",
            key,
        ).fetchone()[0]
        indicator_ids[key] = indicator_id
    connection.execute(
        """
        INSERT OR IGNORE INTO indicator_events (
            indicator_id,
            event_row_id,
            source_field
        ) VALUES (?, ?, ?)
        """,
        (indicator_id, event["id"], source_field),
    )


def extract_iocs(database):
    """extract and store IOCs from normalized events."""
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        create_tables(connection)
        connection.execute("DELETE FROM indicator_events")
        connection.execute("DELETE FROM indicators")

        indicator_ids = {}
        read_cursor = connection.execute(EVENT_COLUMNS)
        for event in read_cursor:
            for indicator in indicators_from_event(event):
                store_indicator(connection, event, indicator, indicator_ids)

        return dict(
            connection.execute(
                "SELECT indicator_type, COUNT(*) FROM indicators GROUP BY indicator_type"
            ).fetchall()
        )


def write_json(database, output):
    """write the deduplicated indicators to JSON."""
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        indicators = [
            dict(row)
            for row in connection.execute(
                """
                SELECT
                    indicator_type,
                    value,
                    hash_algorithm,
                    is_public,
                    first_seen,
                    last_seen,
                    occurrence_count
                FROM indicators
                ORDER BY indicator_type, value
                """
            )
        ]
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(indicators, indent=2), encoding="utf-8")


def build_argument_parser():
    """build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Extract normalized IOCs from stored Windows events."
    )
    parser.add_argument("database", type=Path, help="path to the SQLite database")
    parser.add_argument("--output", type=Path, help="also write the IOCs to JSON")
    return parser


def main():
    """run the IOC extractor command-line interface."""
    args = build_argument_parser().parse_args()
    try:
        counts = extract_iocs(args.database)
        if args.output:
            write_json(args.database, args.output)
    except (OSError, sqlite3.Error) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    total = sum(counts.values())
    summary = ", ".join(f"{name}: {count}" for name, count in sorted(counts.items()))
    print(f"stored {total} unique indicators ({summary})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
