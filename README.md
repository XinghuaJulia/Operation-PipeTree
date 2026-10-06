General idea of project:

Parser:
 - start w one dataset first, gather the events
 - store in a lightweight db (e.g.) sqlite
 - parse it into timestamps, hosts, users, processes, network destinations, hashes, and event IDs.


Indicator Enrichment:
- Extract domain, IP, URL, Hashes
- Query public threat intel sharing platforms 
- Record source, query time, confidence, and enrichment status


Threat Modelling and Visualisation:
- Have PiVy's graph showing the nodes
- Use the Diamond Model: adversary, infra, capability, victim
- MITRE mapping


## How to run the scripts


### `parser.py`

Parses a log containing one Windows Event XML record per line. It normalizes fields such as the timestamp, host, user, process, parent process, network destination, hashes and event ID.

Prints the normalized events as JSON:

```bash
python3 src/parser.py data/parser/ironlung_language_download.log
```

Store the normalized events in SQLite:

```bash
python3 src/parser.py data/parser/ironlung_language_download.log \
  --database data/events.db
```

### `src/bots_json_parser.py`

Parses plain or gzip-compressed Splunk BOTS JSON Lines. It extracts the Windows Event XML from each `_raw` field, sends it through `parser.py` and adds the BOTS source information.

Inspect the first five normalized events:

```bash
python3 src/bots_json_parser.py data/botsv1/botsv1-sysmon.json.gz \
  --limit 5
```

Write newline-delimited JSON:

```bash
python3 src/bots_json_parser.py data/botsv1/botsv1-sysmon.json.gz \
  --limit 5 \
  --output-format jsonl
```

Store the full dataset in SQLite:

```bash
python3 src/bots_json_parser.py data/botsv1/botsv1-sysmon.json.gz \
  --database data/operation_pipetree.db
```

Each database run appends events. Use a new database file if you do not want duplicate rows from an earlier run.

### `src/sqlite_store.py`

Creates the `events` table, flattens normalized events into searchable columns and inserts them into SQLite. It also creates indexes for timestamps, event IDs, hosts, destination IPs and SHA-256 hashes.

This is a shared module used by both parsers. It is not run directly.

The complete normalized event is also stored in `event_json`, so event-specific fields remain available even when they do not have a separate table column.

Inspect the stored event counts:

```bash
sqlite3 data/operation_pipetree.db \
  "SELECT event_id, COUNT(*) FROM events GROUP BY event_id ORDER BY event_id;"
```

### `src/timeline.py`

Queries the SQLite database and creates a HTML timeline of events. It shows events in chronological order and includes search and event ID filters.

Create a timeline for one host and time range:

```bash
python3 src/timeline.py data/operation_pipetree.db \
  --host we1087srv.waynecorpinc.local \
  --start 2016-08-01T00:00:00Z \
  --end 2016-08-02T00:00:00Z \
  --output outputs/timeline.html
```

The available filters:

- `--host` exact hostname
- `--user` exact user
- `--start` and `--end` UTC time range
- `--event-id` one Windows event ID
- `--process` part of a process path
- `--ip` exact source or destination IP
- `--hash` MD5, SHA-1, SHA-256 or IMPHASH value
- `--limit` max number of events loaded into the page

If `--output` is not supplied, the timeline is written to `outputs/timeline.html`. Default event limit is 500.

### `src/extract_iocs.py`

Extracts domains, IP addresses, URLs and hashes from the normalized events in SQLite. It normalizes and deduplicates the values, then stores them in the `indicators` table. The `indicator_events` table links each indicator to the event and field it came from.

Extract and store IOCs:

```bash
python3 src/extract_iocs.py data/operation_pipetree.db
```

Also export the deduplicated IOCs to JSON:

```bash
python3 src/extract_iocs.py data/operation_pipetree.db \
  --output outputs/indicators.json
```

Running the script again rebuilds the IOC tables from the stored events, so it does not duplicate the extracted indicators. This step is offline and does not query or submit data to external services.

### `src/enrich_iocs.py`

Queries ThreatFox and RDAP for extracted IOCs. It stores the raw API response in `api_cache` and the source, query time, confidence and status in `enrichments`.

Add the ThreatFox key to the ignored `.env` file:

```text
THREATFOX_AUTH_KEY=your-auth-key
```

Query both services for a bounded set of IOCs:

```bash
python3 src/enrich_iocs.py data/operation_pipetree.db \
  --service all \
  --limit 5
```

Query one service or indicator type:

```bash
python3 src/enrich_iocs.py data/operation_pipetree.db \
  --service threatfox \
  --indicator-type hash \
  --limit 5
```

Cached responses are reused by default. Use `--refresh` only when a new API response is required. The script only performs read-only lookups. It excludes non-public IP addresses and internal domains from external queries.

