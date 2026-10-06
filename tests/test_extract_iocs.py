import sqlite3
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from extract_iocs import (  # noqa: E402
    extract_iocs,
    indicators_from_event,
    normalize_domain,
    normalize_hash,
    normalize_ip,
    normalize_url,
)
from parser import normalize_event  # noqa: E402
from sqlite_store import store_events  # noqa: E402
from tests.fixtures import SYSMON_EVENT_1, SYSMON_EVENT_3  # noqa: E402


class NormalizeIndicatorTests(unittest.TestCase):
    def test_normalizes_domains(self):
        self.assertEqual(normalize_domain("Example.COM."), "example.com")
        self.assertIsNone(normalize_domain("LAB-HOST"))

    def test_normalizes_ipv4_and_ipv6(self):
        self.assertEqual(normalize_ip("203.0.113.10"), ("203.0.113.10", False))
        self.assertEqual(normalize_ip("2001:0db8::1"), ("2001:db8::1", False))
        self.assertEqual(normalize_ip("224.0.0.252"), ("224.0.0.252", False))
        self.assertEqual(normalize_ip("8.8.8.8"), ("8.8.8.8", True))
        self.assertIsNone(normalize_ip("999.0.0.1"))

    def test_normalizes_urls(self):
        self.assertEqual(
            normalize_url("HTTPS://Example.COM:443/path#section"),
            "https://example.com/path",
        )

    def test_validates_hashes(self):
        self.assertEqual(normalize_hash("AA" * 16, "md5"), "aa" * 16)
        self.assertIsNone(normalize_hash("not-a-hash", "sha256"))


class ExtractIOCTests(unittest.TestCase):
    def test_extracts_iocs_from_one_event(self):
        event = {
            "source_ip": "10.0.0.5",
            "destination_ip": "8.8.8.8",
            "source_hostname": "LAB-HOST",
            "destination_hostname": "Example.COM",
            "process_command_line": "curl HTTPS://Example.COM:443/file",
            "parent_process_command_line": None,
            "hash_md5": "AA" * 16,
            "hash_sha1": None,
            "hash_sha256": None,
            "hash_imphash": None,
        }

        indicators = indicators_from_event(event)
        values = {(indicator[0], indicator[1]) for indicator in indicators}

        self.assertIn(("ip", "10.0.0.5"), values)
        self.assertIn(("ip", "8.8.8.8"), values)
        self.assertIn(("domain", "example.com"), values)
        self.assertIn(("url", "https://example.com/file"), values)
        self.assertIn(("hash", "aa" * 16), values)

    def test_stores_deduplicated_iocs_and_event_links(self):
        events = [
            normalize_event(ET.fromstring(SYSMON_EVENT_1)),
            normalize_event(ET.fromstring(SYSMON_EVENT_3)),
        ]

        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "events.db"
            store_events(database, events)
            counts = extract_iocs(database)

            with sqlite3.connect(database) as connection:
                duplicate_count = connection.execute(
                    """
                    SELECT COUNT(*) FROM indicators
                    WHERE indicator_type = 'domain' AND value = 'example.test'
                    """
                ).fetchone()[0]
                links = connection.execute(
                    "SELECT COUNT(*) FROM indicator_events"
                ).fetchone()[0]

        self.assertGreater(counts["domain"], 0)
        self.assertEqual(duplicate_count, 1)
        self.assertGreater(links, 0)

    def test_rebuild_is_idempotent(self):
        event = normalize_event(ET.fromstring(SYSMON_EVENT_1))

        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "events.db"
            store_events(database, [event])
            first_counts = extract_iocs(database)
            second_counts = extract_iocs(database)

        self.assertEqual(first_counts, second_counts)


if __name__ == "__main__":
    unittest.main()
