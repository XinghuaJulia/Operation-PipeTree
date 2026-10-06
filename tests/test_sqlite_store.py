import sqlite3
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from parser import normalize_event  # noqa: E402
from sqlite_store import store_events  # noqa: E402
from tests.fixtures import SYSMON_EVENT_1, SYSMON_EVENT_3  # noqa: E402


class SQLiteStoreTests(unittest.TestCase):
    def test_stores_process_hash_and_network_fields(self):
        events = [
            normalize_event(ET.fromstring(SYSMON_EVENT_1)),
            normalize_event(ET.fromstring(SYSMON_EVENT_3)),
        ]

        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "events.db"
            count = store_events(database, events)

            with sqlite3.connect(database) as connection:
                process = connection.execute(
                    "SELECT process_pid, parent_process_pid, hash_sha256 "
                    "FROM events WHERE event_id = 1"
                ).fetchone()
                network = connection.execute(
                    "SELECT destination_ip, destination_port "
                    "FROM events WHERE event_id = 3"
                ).fetchone()

        self.assertEqual(count, 2)
        self.assertEqual(process, (616, 6940, "EEFF"))
        self.assertEqual(network, ("203.0.113.10", 443))

    def test_creates_the_timeline_indexes(self):
        event = normalize_event(ET.fromstring(SYSMON_EVENT_1))

        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "events.db"
            store_events(database, [event])

            with sqlite3.connect(database) as connection:
                indexes = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'index'"
                    )
                }

        self.assertIn("idx_events_time", indexes)
        self.assertIn("idx_events_destination_ip", indexes)
        self.assertIn("idx_events_sha256", indexes)

    def test_appends_events_to_an_existing_database(self):
        event = normalize_event(ET.fromstring(SYSMON_EVENT_1))

        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "events.db"
            store_events(database, [event])
            store_events(database, [event])

            with sqlite3.connect(database) as connection:
                count = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]

        self.assertEqual(count, 2)


if __name__ == "__main__":
    unittest.main()
