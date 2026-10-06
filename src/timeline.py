import argparse
import html
import json
import sqlite3
import sys
from collections import Counter
from pathlib import Path


EVENT_LABELS = {
    1: "process created",
    2: "file time changed",
    3: "network connection",
    5: "process terminated",
    6: "driver loaded",
    7: "image loaded",
    4688: "process created",
}


def build_query(args):
    """build the timeline query and its parameters."""
    conditions = []
    parameters = []

    filters = (
        (args.host, "hostname = ?"),
        (args.user, "user = ?"),
        (args.start, "time_created >= ?"),
        (args.end, "time_created <= ?"),
        (args.event_id, "event_id = ?"),
    )
    for value, condition in filters:
        if value is not None:
            conditions.append(condition)
            parameters.append(value)

    if args.process:
        conditions.append("process_image LIKE ?")
        parameters.append(f"%{args.process}%")

    if args.ip:
        conditions.append("(source_ip = ? OR destination_ip = ?)")
        parameters.extend((args.ip, args.ip))

    if args.hash_value:
        conditions.append(
            "(" 
            "hash_md5 = ? COLLATE NOCASE OR "
            "hash_sha1 = ? COLLATE NOCASE OR "
            "hash_sha256 = ? COLLATE NOCASE OR "
            "hash_imphash = ? COLLATE NOCASE"
            ")"
        )
        parameters.extend([args.hash_value] * 4)

    query = "SELECT * FROM events"
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY time_created, id LIMIT ?"
    parameters.append(args.limit)
    return query, parameters


def load_events(database, query, parameters):
    """load timeline events from SQLite."""
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        return [dict(row) for row in connection.execute(query, parameters)]


def read_event_json(row):
    """read the complete normalized event stored with the row."""
    try:
        return json.loads(row.get("event_json") or "{}")
    except json.JSONDecodeError:
        return {}


def add_detail(details, label, value):
    """add one non-empty detail to an event card."""
    if value is not None and value != "":
        details.append((label, str(value)))


def event_details(row):
    """select useful details for one timeline event."""
    event = read_event_json(row)
    details = []

    add_detail(details, "user", row.get("user"))
    add_detail(details, "process", row.get("process_image"))
    add_detail(details, "pid", row.get("process_pid"))
    add_detail(details, "command", row.get("process_command_line"))
    add_detail(details, "parent", row.get("parent_process_image"))
    add_detail(details, "parent pid", row.get("parent_process_pid"))

    if row.get("event_id") == 2:
        add_detail(details, "file", row.get("file_path"))
        add_detail(details, "creation time", row.get("file_creation_time"))

    if row.get("event_id") == 3:
        destination = row.get("destination_ip") or row.get("destination_hostname")
        if destination and row.get("destination_port") is not None:
            destination = f"{destination}:{row['destination_port']}"
        add_detail(details, "destination", destination)
        add_detail(details, "protocol", row.get("network_protocol"))

    if row.get("event_id") == 6:
        driver = event.get("driver") or {}
        add_detail(details, "driver", driver.get("path"))
        add_detail(details, "signature", driver.get("signature"))

    if row.get("event_id") == 7:
        loaded_image = event.get("loaded_image") or {}
        add_detail(details, "loaded image", loaded_image.get("path"))
        add_detail(details, "company", loaded_image.get("company"))
        add_detail(details, "signature", loaded_image.get("signature"))

    hash_value = (
        row.get("hash_sha256")
        or row.get("hash_sha1")
        or row.get("hash_md5")
        or row.get("hash_imphash")
    )
    add_detail(details, "hash", hash_value)
    return details


def render_card(row):
    """render one event as an HTML timeline card."""
    event_id = row.get("event_id")
    label = EVENT_LABELS.get(event_id, "other event")
    details = "".join(
        "<div class='detail'>"
        f"<span>{html.escape(name)}</span>"
        f"<code>{html.escape(value)}</code>"
        "</div>"
        for name, value in event_details(row)
    )
    search_text = " ".join(str(value or "") for value in row.values()).lower()

    return (
        f"<article class='event event-{html.escape(str(event_id))}' "
        f"data-event-id='{html.escape(str(event_id))}' "
        f"data-search='{html.escape(search_text, quote=True)}'>"
        "<div class='marker'></div>"
        "<div class='card'>"
        "<header>"
        f"<time>{html.escape(row.get('time_created') or 'unknown time')}</time>"
        f"<span class='event-label'>{html.escape(label)}</span>"
        f"<span class='event-id'>event {html.escape(str(event_id))}</span>"
        "</header>"
        f"<h2>{html.escape(row.get('hostname') or 'unknown host')}</h2>"
        f"{details}"
        "</div>"
        "</article>"
    )


def render_timeline(events, database, filters):
    """render a complete searchable HTML timeline."""
    counts = Counter(event.get("event_id") for event in events)
    buttons = "".join(
        f"<button data-filter='{html.escape(str(event_id))}'>"
        f"event {html.escape(str(event_id))} <span>{count}</span>"
        "</button>"
        for event_id, count in sorted(counts.items(), key=lambda item: str(item[0]))
    )
    cards = "".join(render_card(event) for event in events)
    filter_text = ", ".join(filters) if filters else "no filters"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Operation PipeTree timeline</title>
<style>
:root {{ color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }}
* {{ box-sizing: border-box; }}
body {{ margin: 0; background: #07111f; color: #dce8f5; }}
.page {{ width: min(1100px, calc(100% - 32px)); margin: 0 auto; padding: 48px 0 80px; }}
.eyebrow {{ color: #55d6be; font-size: 12px; font-weight: 800; letter-spacing: .18em; text-transform: uppercase; }}
h1 {{ margin: 8px 0; font-size: clamp(32px, 6vw, 64px); letter-spacing: -.04em; }}
.subtitle {{ color: #91a7bd; margin: 0 0 28px; }}
.controls {{ position: sticky; top: 0; z-index: 3; padding: 16px; border: 1px solid #23354a; border-radius: 16px; background: rgba(10, 24, 41, .94); backdrop-filter: blur(12px); }}
input {{ width: 100%; padding: 12px 14px; border: 1px solid #31465d; border-radius: 10px; background: #07111f; color: #fff; font: inherit; }}
.buttons {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }}
button {{ border: 1px solid #31465d; border-radius: 999px; padding: 7px 11px; background: #102238; color: #bcd0e4; cursor: pointer; }}
button.active {{ border-color: #55d6be; color: #55d6be; }}
button span {{ color: #718ba4; margin-left: 4px; }}
.status {{ margin: 18px 0; color: #91a7bd; }}
.timeline {{ position: relative; padding-left: 32px; }}
.timeline::before {{ content: ""; position: absolute; top: 0; bottom: 0; left: 9px; width: 2px; background: #23354a; }}
.event {{ position: relative; margin: 0 0 16px; }}
.marker {{ position: absolute; left: -30px; top: 23px; width: 14px; height: 14px; border: 3px solid #07111f; border-radius: 50%; background: #55d6be; box-shadow: 0 0 0 2px #55d6be; }}
.event-3 .marker {{ background: #5da9ff; box-shadow: 0 0 0 2px #5da9ff; }}
.event-6 .marker, .event-7 .marker {{ background: #bd8cff; box-shadow: 0 0 0 2px #bd8cff; }}
.card {{ padding: 18px 20px; border: 1px solid #23354a; border-radius: 14px; background: #0c1b2d; box-shadow: 0 12px 28px rgba(0,0,0,.16); }}
header {{ display: flex; flex-wrap: wrap; align-items: center; gap: 8px 12px; }}
time {{ color: #91a7bd; font-family: ui-monospace, SFMono-Regular, monospace; font-size: 13px; }}
.event-label {{ color: #55d6be; font-weight: 800; }}
.event-id {{ margin-left: auto; color: #718ba4; font-size: 12px; text-transform: uppercase; }}
h2 {{ margin: 13px 0; font-size: 18px; }}
.detail {{ display: grid; grid-template-columns: 110px minmax(0, 1fr); gap: 12px; padding: 6px 0; border-top: 1px solid #172a3e; }}
.detail span {{ color: #718ba4; font-size: 12px; text-transform: uppercase; }}
code {{ color: #dce8f5; overflow-wrap: anywhere; white-space: pre-wrap; }}
.hidden {{ display: none; }}
@media (max-width: 620px) {{ .detail {{ grid-template-columns: 1fr; gap: 3px; }} .event-id {{ margin-left: 0; }} }}
</style>
</head>
<body>
<main class="page">
  <div class="eyebrow">Operation PipeTree</div>
  <h1>Investigation timeline</h1>
  <p class="subtitle">{len(events):,} events from {html.escape(str(database))} | {html.escape(filter_text)}</p>
  <section class="controls">
    <input id="search" type="search" placeholder="filter the loaded timeline">
    <div class="buttons"><button class="active" data-filter="all">all <span>{len(events)}</span></button>{buttons}</div>
  </section>
  <p class="status" id="status">showing {len(events):,} events</p>
  <section class="timeline" id="timeline">{cards}</section>
</main>
<script>
const events = [...document.querySelectorAll('.event')];
const search = document.querySelector('#search');
const status = document.querySelector('#status');
let selected = 'all';
function applyFilters() {{
  const query = search.value.trim().toLowerCase();
  let visible = 0;
  for (const event of events) {{
    const matchesType = selected === 'all' || event.dataset.eventId === selected;
    const matchesSearch = !query || event.dataset.search.includes(query);
    event.classList.toggle('hidden', !(matchesType && matchesSearch));
    if (matchesType && matchesSearch) visible += 1;
  }}
  status.textContent = `showing ${{visible.toLocaleString()}} events`;
}}
search.addEventListener('input', applyFilters);
for (const button of document.querySelectorAll('button[data-filter]')) {{
  button.addEventListener('click', () => {{
    selected = button.dataset.filter;
    document.querySelector('button.active').classList.remove('active');
    button.classList.add('active');
    applyFilters();
  }});
}}
</script>
</body>
</html>
"""


def build_argument_parser():
    """build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Create an HTML timeline from normalized SQLite events."
    )
    parser.add_argument("database", type=Path, help="path to the SQLite database")
    parser.add_argument("--output", type=Path, default=Path("outputs/timeline.html"))
    parser.add_argument("--host", help="only include this hostname")
    parser.add_argument("--user", help="only include this user")
    parser.add_argument("--start", help="include events at or after this UTC timestamp")
    parser.add_argument("--end", help="include events at or before this UTC timestamp")
    parser.add_argument("--event-id", type=int, help="only include this event ID")
    parser.add_argument("--process", help="include process paths containing this value")
    parser.add_argument("--ip", help="include this source or destination IP")
    parser.add_argument("--hash", dest="hash_value", help="include this file hash")
    parser.add_argument("--limit", type=int, default=500, help="maximum events to load")
    return parser


def describe_filters(args):
    """describe the filters used to build the timeline."""
    values = {
        "host": args.host,
        "user": args.user,
        "start": args.start,
        "end": args.end,
        "event ID": args.event_id,
        "process": args.process,
        "IP": args.ip,
        "hash": args.hash_value,
    }
    return [f"{name}: {value}" for name, value in values.items() if value is not None]


def main():
    """run the timeline command-line interface."""
    args = build_argument_parser().parse_args()
    if args.limit < 1:
        print("error: --limit must be greater than zero", file=sys.stderr)
        return 2

    try:
        query, parameters = build_query(args)
        events = load_events(args.database, query, parameters)
        output = render_timeline(events, args.database, describe_filters(args))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
    except (OSError, sqlite3.Error) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    print(f"wrote {len(events)} events to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
