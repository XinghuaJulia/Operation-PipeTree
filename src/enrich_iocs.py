import argparse
import hashlib
import json
import os
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen


THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
RDAP_URL = "https://rdap.org"
USER_AGENT = "Operation-PipeTree/1.0"
NON_PUBLIC_DOMAIN_SUFFIXES = (
    ".arpa",
    ".example",
    ".home",
    ".internal",
    ".invalid",
    ".lan",
    ".local",
    ".localhost",
    ".test",
)

CREATE_API_CACHE_TABLE = """
CREATE TABLE IF NOT EXISTS api_cache (
    cache_key TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    request_method TEXT NOT NULL,
    request_url TEXT NOT NULL,
    request_body TEXT,
    response_url TEXT,
    response_status INTEGER,
    response_headers TEXT,
    response_body TEXT,
    queried_at TEXT NOT NULL
)
"""

CREATE_ENRICHMENTS_TABLE = """
CREATE TABLE IF NOT EXISTS enrichments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator_id INTEGER NOT NULL,
    source_dataset TEXT NOT NULL,
    source TEXT NOT NULL,
    query_time TEXT NOT NULL,
    status TEXT NOT NULL,
    status_detail TEXT NOT NULL,
    confidence INTEGER,
    cache_key TEXT NOT NULL,
    http_status INTEGER,
    error TEXT,
    UNIQUE(indicator_id, source),
    FOREIGN KEY (indicator_id) REFERENCES indicators(id) ON DELETE CASCADE,
    FOREIGN KEY (cache_key) REFERENCES api_cache(cache_key)
)
"""


def utc_now():
    """return the current UTC time."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_env_value(path, name):
    """load one value from a simple environment file."""
    if not path or not path.exists():
        return None
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        if key.strip() == name:
            return value.strip().strip("\"").strip("'")
    return None


def create_tables(connection):
    """create the enrichment and response cache tables."""
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute(CREATE_API_CACHE_TABLE)
    connection.execute(CREATE_ENRICHMENTS_TABLE)
    columns = {
        row[1] for row in connection.execute("PRAGMA table_info(enrichments)")
    }
    if "source_dataset" not in columns:
        connection.execute("ALTER TABLE enrichments ADD COLUMN source_dataset TEXT")
    if "status_detail" not in columns:
        connection.execute("ALTER TABLE enrichments ADD COLUMN status_detail TEXT")
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_enrichments_status "
        "ON enrichments(source, status)"
    )


def make_cache_key(source, method, url, body):
    """create a stable key from a request without secret headers."""
    value = json.dumps(
        {"source": source, "method": method, "url": url, "body": body},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def request_data(source, method, url, body=None, headers=None):
    """make one API request and return its raw response."""
    request_headers = {
        "Accept": "application/rdap+json, application/json",
        "User-Agent": USER_AGENT,
    }
    request_headers.update(headers or {})
    encoded_body = body.encode("utf-8") if body is not None else None
    request = Request(url, data=encoded_body, headers=request_headers, method=method)
    queried_at = utc_now()

    try:
        with urlopen(request, timeout=30) as response:
            return {
                "source": source,
                "request_method": method,
                "request_url": url,
                "request_body": body,
                "response_url": response.geturl(),
                "response_status": response.status,
                "response_headers": json.dumps(dict(response.headers.items())),
                "response_body": response.read().decode("utf-8", errors="replace"),
                "queried_at": queried_at,
                "request_error": None,
            }
    except HTTPError as error:
        return {
            "source": source,
            "request_method": method,
            "request_url": url,
            "request_body": body,
            "response_url": error.geturl(),
            "response_status": error.code,
            "response_headers": json.dumps(dict(error.headers.items())),
            "response_body": error.read().decode("utf-8", errors="replace"),
            "queried_at": queried_at,
            "request_error": None,
        }
    except URLError as error:
        return {
            "source": source,
            "request_method": method,
            "request_url": url,
            "request_body": body,
            "response_url": None,
            "response_status": None,
            "response_headers": "{}",
            "response_body": "",
            "queried_at": queried_at,
            "request_error": str(error.reason),
        }


def store_cache(connection, cache_key, response):
    """store an API response exactly as received."""
    connection.execute(
        """
        INSERT INTO api_cache (
            cache_key, source, request_method, request_url, request_body,
            response_url, response_status, response_headers, response_body, queried_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cache_key) DO UPDATE SET
            source = excluded.source,
            request_method = excluded.request_method,
            request_url = excluded.request_url,
            request_body = excluded.request_body,
            response_url = excluded.response_url,
            response_status = excluded.response_status,
            response_headers = excluded.response_headers,
            response_body = excluded.response_body,
            queried_at = excluded.queried_at
        """,
        (
            cache_key,
            response["source"],
            response["request_method"],
            response["request_url"],
            response["request_body"],
            response["response_url"],
            response["response_status"],
            response["response_headers"],
            response["response_body"],
            response["queried_at"],
        ),
    )


def load_cache(connection, cache_key):
    """load a cached API response."""
    row = connection.execute(
        "SELECT * FROM api_cache WHERE cache_key = ?", (cache_key,)
    ).fetchone()
    if not row:
        return None
    response = dict(row)
    response["request_error"] = None
    return response


def parse_json_body(response):
    """parse a cached response body as JSON."""
    try:
        return json.loads(response.get("response_body") or "")
    except json.JSONDecodeError:
        return None


def threatfox_request(indicator, auth_key):
    """build a read-only ThreatFox IOC search request."""
    body = json.dumps(
        {
            "query": "search_ioc",
            "search_term": indicator["value"],
            "exact_match": True,
        },
        separators=(",", ":"),
    )
    return {
        "source": "threatfox",
        "method": "POST",
        "url": THREATFOX_URL,
        "body": body,
        "headers": {"Auth-Key": auth_key, "Content-Type": "application/json"},
    }


def rdap_request(indicator):
    """build an RDAP domain or IP lookup request."""
    object_type = "ip" if indicator["indicator_type"] == "ip" else "domain"
    value = quote(indicator["value"], safe=":.")
    return {
        "source": "rdap",
        "method": "GET",
        "url": f"{RDAP_URL}/{object_type}/{value}",
        "body": None,
        "headers": {},
    }


def threatfox_result(response):
    """derive the ThreatFox status and confidence from a raw response."""
    if response.get("request_error"):
        return "error", None, response["request_error"]
    data = parse_json_body(response)
    if not isinstance(data, dict):
        return "error", None, "response body is not valid JSON"

    query_status = data.get("query_status")
    matches = data.get("data")
    if query_status == "ok" and isinstance(matches, list) and matches:
        confidence_values = [
            match.get("confidence_level")
            for match in matches
            if isinstance(match, dict) and isinstance(match.get("confidence_level"), int)
        ]
        confidence = max(confidence_values) if confidence_values else None
        return "found", confidence, None
    if query_status in {"no_result", "no_results"} or matches == []:
        return "not_found", None, None
    return "error", None, f"ThreatFox query status: {query_status or 'unknown'}"


def rdap_result(response):
    """derive the RDAP status from a raw response."""
    if response.get("request_error"):
        return "error", None, response["request_error"]
    status = response.get("response_status")
    if status is not None and 200 <= status < 300:
        if parse_json_body(response) is None:
            return "error", None, "response body is not valid JSON"
        return "found", None, None
    if status == 404:
        return "not_found", None, None
    return "error", None, f"RDAP returned HTTP {status}"


def indicator_dataset(connection, indicator_id):
    """return a clear label for the indicator source dataset."""
    try:
        values = {
            row[0]
            for row in connection.execute(
                """
                SELECT DISTINCT events.dataset
                FROM indicator_events
                JOIN events ON events.id = indicator_events.event_row_id
                WHERE indicator_events.indicator_id = ?
                  AND events.dataset IS NOT NULL
                """,
                (indicator_id,),
            )
        }
    except sqlite3.OperationalError:
        values = set()

    labels = ["BOTS v1" if value == "botsv1" else value for value in sorted(values)]
    return ", ".join(labels) if labels else "unknown"


def describe_status(source, status):
    """explain what an enrichment status means."""
    details = {
        ("threatfox", "found"): "current ThreatFox match",
        ("threatfox", "not_found"): "no current non-expired ThreatFox match",
        ("threatfox", "error"): "ThreatFox query failed",
        ("rdap", "found"): "current registration context available",
        ("rdap", "not_found"): "no current RDAP registration response",
        ("rdap", "error"): "RDAP query failed",
    }
    return details.get((source, status), "unknown enrichment result")


def store_enrichment(connection, indicator_id, source, response, result, cache_key):
    """store the enrichment status linked to its cached response."""
    status, confidence, error = result
    source_dataset = indicator_dataset(connection, indicator_id)
    status_detail = describe_status(source, status)
    connection.execute(
        """
        INSERT INTO enrichments (
            indicator_id, source_dataset, source, query_time, status, status_detail,
            confidence, cache_key, http_status, error
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(indicator_id, source) DO UPDATE SET
            source_dataset = excluded.source_dataset,
            query_time = excluded.query_time,
            status = excluded.status,
            status_detail = excluded.status_detail,
            confidence = excluded.confidence,
            cache_key = excluded.cache_key,
            http_status = excluded.http_status,
            error = excluded.error
        """,
        (
            indicator_id,
            source_dataset,
            source,
            response["queried_at"],
            status,
            status_detail,
            confidence,
            cache_key,
            response.get("response_status"),
            error,
        ),
    )


def write_report(connection, output):
    """write a clearly labeled enrichment report as JSON."""
    rows = [
        dict(row)
        for row in connection.execute(
            """
            SELECT
                enrichments.source_dataset,
                indicators.indicator_type,
                indicators.value AS indicator,
                enrichments.source AS enrichment_source,
                enrichments.query_time,
                enrichments.confidence,
                enrichments.status AS enrichment_status,
                enrichments.status_detail,
                enrichments.http_status,
                enrichments.error,
                enrichments.cache_key
            FROM enrichments
            JOIN indicators ON indicators.id = enrichments.indicator_id
            ORDER BY indicators.occurrence_count DESC, enrichments.source
            """
        )
    ]
    report = {
        "title": "BOTS v1 IOC enrichment report",
        "dataset": "BOTS v1",
        "generated_at": utc_now(),
        "note": "RDAP provides current registration context. ThreatFox not_found is not a benign verdict.",
        "results": rows,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")


def eligible_for_rdap(indicator):
    """check whether an indicator can be queried through public RDAP."""
    if indicator["indicator_type"] == "ip":
        return indicator["is_public"] == 1
    if indicator["indicator_type"] == "domain":
        return not indicator["value"].endswith(NON_PUBLIC_DOMAIN_SUFFIXES)
    return False


def eligible_for_threatfox(indicator):
    """check whether an indicator is safe to send to ThreatFox."""
    indicator_type = indicator["indicator_type"]
    if indicator_type == "ip":
        return indicator["is_public"] == 1
    if indicator_type == "domain":
        return not indicator["value"].endswith(NON_PUBLIC_DOMAIN_SUFFIXES)
    if indicator_type == "url":
        hostname = urlsplit(indicator["value"]).hostname or ""
        return not hostname.endswith(NON_PUBLIC_DOMAIN_SUFFIXES)
    return indicator_type == "hash"


def load_indicators(connection, source, limit, indicator_type=None):
    """load the highest-frequency indicators eligible for a service."""
    conditions = []
    parameters = []
    if source == "rdap":
        conditions.append("indicator_type IN ('domain', 'ip')")
    if indicator_type:
        conditions.append("indicator_type = ?")
        parameters.append(indicator_type)

    query = "SELECT * FROM indicators"
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY occurrence_count DESC, id LIMIT ?"
    parameters.append(limit * 10)

    rows = [dict(row) for row in connection.execute(query, parameters)]
    if source == "rdap":
        rows = [row for row in rows if eligible_for_rdap(row)]
    else:
        rows = [row for row in rows if eligible_for_threatfox(row)]
    return rows[:limit]


def enrich_service(
    connection,
    source,
    limit,
    delay,
    refresh,
    auth_key=None,
    indicator_type=None,
):
    """enrich a bounded set of indicators through one service."""
    counts = {"found": 0, "not_found": 0, "error": 0, "cached": 0}
    indicators = load_indicators(connection, source, limit, indicator_type)

    for index, indicator in enumerate(indicators):
        request = (
            threatfox_request(indicator, auth_key)
            if source == "threatfox"
            else rdap_request(indicator)
        )
        cache_key = make_cache_key(
            request["source"], request["method"], request["url"], request["body"]
        )
        response = None if refresh else load_cache(connection, cache_key)
        if response is not None:
            counts["cached"] += 1
        else:
            if index > 0 and delay:
                time.sleep(delay)
            response = request_data(**request)
            store_cache(connection, cache_key, response)

        result = (
            threatfox_result(response) if source == "threatfox" else rdap_result(response)
        )
        store_enrichment(
            connection, indicator["id"], source, response, result, cache_key
        )
        counts[result[0]] += 1

    return counts


def build_argument_parser():
    """build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Query ThreatFox and RDAP with a reproducible response cache."
    )
    parser.add_argument("database", type=Path, help="path to the SQLite database")
    parser.add_argument(
        "--service",
        choices=("all", "threatfox", "rdap"),
        default="all",
        help="service to query",
    )
    parser.add_argument(
        "--indicator-type",
        choices=("domain", "ip", "url", "hash"),
        help="only enrich this indicator type",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=25,
        help="maximum indicators queried per service",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="seconds between uncached requests",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="replace cached responses with new API requests",
    )
    parser.add_argument(
        "--auth-key-env",
        default="THREATFOX_AUTH_KEY",
        help="environment variable containing the ThreatFox Auth-Key",
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        default=Path(".env"),
        help="file containing the ThreatFox Auth-Key",
    )
    parser.add_argument("--output", type=Path, help="write enrichment results to JSON")
    return parser


def main():
    """run the IOC enrichment command-line interface."""
    args = build_argument_parser().parse_args()
    if args.limit < 1:
        print("error: --limit must be greater than zero", file=sys.stderr)
        return 2
    if args.delay < 0:
        print("error: --delay cannot be negative", file=sys.stderr)
        return 2

    services = ["threatfox", "rdap"] if args.service == "all" else [args.service]
    auth_key = os.environ.get(args.auth_key_env) or load_env_value(
        args.env_file, args.auth_key_env
    )
    if "threatfox" in services and not auth_key:
        if args.service == "threatfox":
            print(
                f"error: set {args.auth_key_env} to query ThreatFox",
                file=sys.stderr,
            )
            return 2
        print(
            f"warning: skipping ThreatFox because {args.auth_key_env} is not set",
            file=sys.stderr,
        )
        services.remove("threatfox")

    try:
        with sqlite3.connect(args.database) as connection:
            connection.row_factory = sqlite3.Row
            create_tables(connection)
            for service in services:
                counts = enrich_service(
                    connection,
                    service,
                    args.limit,
                    args.delay,
                    args.refresh,
                    auth_key,
                    args.indicator_type,
                )
                summary = ", ".join(
                    f"{name}: {count}" for name, count in counts.items()
                )
                print(f"{service}: {summary}")
            if args.output:
                write_report(connection, args.output)
                print(f"wrote enrichment report to {args.output}")
    except (OSError, sqlite3.Error) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
