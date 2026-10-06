import json
import sqlite3


CREATE_EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER,
    time_created TEXT,
    hostname TEXT,
    user TEXT,
    source TEXT,
    process_guid TEXT,
    process_pid INTEGER,
    process_image TEXT,
    process_command_line TEXT,
    parent_process_guid TEXT,
    parent_process_pid INTEGER,
    parent_process_image TEXT,
    parent_process_command_line TEXT,
    hash_md5 TEXT,
    hash_sha1 TEXT,
    hash_sha256 TEXT,
    hash_imphash TEXT,
    network_protocol TEXT,
    network_initiated INTEGER,
    source_ip TEXT,
    source_hostname TEXT,
    source_port INTEGER,
    destination_ip TEXT,
    destination_hostname TEXT,
    destination_port INTEGER,
    file_path TEXT,
    file_creation_time TEXT,
    dataset TEXT,
    input_format TEXT,
    sourcetype TEXT,
    splunk_source TEXT,
    splunk_time TEXT,
    splunk_host TEXT,
    event_json TEXT NOT NULL
)
"""

INSERT_EVENT = """
INSERT INTO events (
    event_id,
    time_created,
    hostname,
    user,
    source,
    process_guid,
    process_pid,
    process_image,
    process_command_line,
    parent_process_guid,
    parent_process_pid,
    parent_process_image,
    parent_process_command_line,
    hash_md5,
    hash_sha1,
    hash_sha256,
    hash_imphash,
    network_protocol,
    network_initiated,
    source_ip,
    source_hostname,
    source_port,
    destination_ip,
    destination_hostname,
    destination_port,
    file_path,
    file_creation_time,
    dataset,
    input_format,
    sourcetype,
    splunk_source,
    splunk_time,
    splunk_host,
    event_json
) VALUES (
    :event_id,
    :time_created,
    :hostname,
    :user,
    :source,
    :process_guid,
    :process_pid,
    :process_image,
    :process_command_line,
    :parent_process_guid,
    :parent_process_pid,
    :parent_process_image,
    :parent_process_command_line,
    :hash_md5,
    :hash_sha1,
    :hash_sha256,
    :hash_imphash,
    :network_protocol,
    :network_initiated,
    :source_ip,
    :source_hostname,
    :source_port,
    :destination_ip,
    :destination_hostname,
    :destination_port,
    :file_path,
    :file_creation_time,
    :dataset,
    :input_format,
    :sourcetype,
    :splunk_source,
    :splunk_time,
    :splunk_host,
    :event_json
)
"""

INDEXES = (
    "CREATE INDEX IF NOT EXISTS idx_events_time ON events(time_created)",
    "CREATE INDEX IF NOT EXISTS idx_events_id ON events(event_id)",
    "CREATE INDEX IF NOT EXISTS idx_events_host ON events(hostname)",
    "CREATE INDEX IF NOT EXISTS idx_events_destination_ip ON events(destination_ip)",
    "CREATE INDEX IF NOT EXISTS idx_events_sha256 ON events(hash_sha256)",
)


def event_row(event):
    """flatten one normalized event for SQLite storage."""
    hashes = event.get("file_hashes") or {}
    parent = event.get("parent_process") or {}
    network = event.get("network") or {}
    network_source = network.get("source") or {}
    destination = network.get("destination") or {}
    file_data = event.get("file") or {}
    provenance = event.get("provenance") or {}

    return {
        "event_id": event.get("event_id"),
        "time_created": event.get("time_created"),
        "hostname": event.get("hostname"),
        "user": event.get("user"),
        "source": event.get("source"),
        "process_guid": event.get("process_guid"),
        "process_pid": event.get("process_pid"),
        "process_image": event.get("process_image"),
        "process_command_line": event.get("process_command_line"),
        "parent_process_guid": parent.get("guid"),
        "parent_process_pid": parent.get("pid"),
        "parent_process_image": parent.get("image"),
        "parent_process_command_line": parent.get("command_line"),
        "hash_md5": hashes.get("md5"),
        "hash_sha1": hashes.get("sha1"),
        "hash_sha256": hashes.get("sha256"),
        "hash_imphash": hashes.get("imphash"),
        "network_protocol": network.get("protocol"),
        "network_initiated": network.get("initiated"),
        "source_ip": network_source.get("ip"),
        "source_hostname": network_source.get("hostname"),
        "source_port": network_source.get("port"),
        "destination_ip": destination.get("ip"),
        "destination_hostname": destination.get("hostname"),
        "destination_port": destination.get("port"),
        "file_path": file_data.get("path"),
        "file_creation_time": file_data.get("creation_time"),
        "dataset": provenance.get("dataset"),
        "input_format": provenance.get("input_format"),
        "sourcetype": provenance.get("sourcetype"),
        "splunk_source": provenance.get("splunk_source"),
        "splunk_time": provenance.get("splunk_time"),
        "splunk_host": provenance.get("splunk_host"),
        "event_json": json.dumps(event, separators=(",", ":")),
    }


def store_events(database_path, events):
    """store normalized events and return the number inserted."""
    count = 0
    with sqlite3.connect(database_path) as connection:
        connection.execute(CREATE_EVENTS_TABLE)
        for statement in INDEXES:
            connection.execute(statement)

        for event in events:
            connection.execute(INSERT_EVENT, event_row(event))
            count += 1

    return count
