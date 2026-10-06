import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from parser import normalize_event, parse_events  # noqa: E402
from tests.fixtures import SECURITY_EVENT_4688, SYSMON_EVENT_1  # noqa: E402


class NormalizeEventTests(unittest.TestCase):
    def test_normalizes_sysmon_event_1(self):
        event = normalize_event(ET.fromstring(SYSMON_EVENT_1))

        self.assertEqual(event["event_id"], 1)
        self.assertEqual(event["hostname"], "LAB-HOST")
        self.assertEqual(event["user"], "LAB\\analyst")
        self.assertEqual(event["process_pid"], 616)
        self.assertEqual(event["parent_process"]["pid"], 6940)
        self.assertEqual(event["file_hashes"]["sha256"], "EEFF")

    def test_normalizes_security_event_4688_to_the_same_process_fields(self):
        event = normalize_event(ET.fromstring(SECURITY_EVENT_4688))

        self.assertEqual(event["event_id"], 4688)
        self.assertEqual(event["user"], "LAB\\analyst")
        self.assertEqual(event["process_pid"], 616)
        self.assertEqual(event["parent_process"]["pid"], 6940)
        self.assertEqual(event["process_image"], "C:\\Windows\\System32\\curl.exe")

    def test_parses_one_xml_event_per_line(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.log"
            path.write_text(f"{SYSMON_EVENT_1.replace(chr(10), '')}\n\n", encoding="utf-8")

            events = list(parse_events(path))

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_id"], 1)

    def test_reports_the_invalid_line_number(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.log"
            path.write_text("\n<not-valid\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "line 2"):
                list(parse_events(path))


if __name__ == "__main__":
    unittest.main()
