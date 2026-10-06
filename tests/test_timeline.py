import argparse
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from parser import normalize_event  # noqa: E402
from sqlite_store import store_events  # noqa: E402
from timeline import build_query, load_events, render_timeline  # noqa: E402
from tests.fixtures import SYSMON_EVENT_1, SYSMON_EVENT_3  # noqa: E402


def timeline_args(**changes):
    values = {
        "host": None,
        "user": None,
        "start": None,
        "end": None,
        "event_id": None,
        "process": None,
        "ip": None,
        "hash_value": None,
        "limit": 500,
    }
    values.update(changes)
    return argparse.Namespace(**values)


class TimelineTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary_directory.name) / "events.db"
        events = [
            normalize_event(ET.fromstring(SYSMON_EVENT_1)),
            normalize_event(ET.fromstring(SYSMON_EVENT_3)),
        ]
        store_events(self.database, events)

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_filters_by_event_id_and_ip(self):
        query, parameters = build_query(
            timeline_args(event_id=3, ip="203.0.113.10")
        )

        events = load_events(self.database, query, parameters)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_id"], 3)

    def test_orders_events_by_timestamp(self):
        query, parameters = build_query(timeline_args())

        events = load_events(self.database, query, parameters)

        self.assertEqual([event["event_id"] for event in events], [1, 3])

    def test_renders_searchable_html(self):
        query, parameters = build_query(timeline_args())
        events = load_events(self.database, query, parameters)

        output = render_timeline(events, self.database, ["host: LAB-HOST"])

        self.assertIn("Investigation timeline", output)
        self.assertIn('id="search"', output)
        self.assertIn("event 1", output)
        self.assertIn("203.0.113.10:443", output)
        self.assertEqual(output.count("<article class="), 2)


if __name__ == "__main__":
    unittest.main()
