import gzip
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bots_json_parser import normalize_bots_record, parse_bots_events  # noqa: E402
from tests.fixtures import SYSMON_EVENT_1  # noqa: E402


def bots_record():
    return {
        "result": {
            "_raw": SYSMON_EVENT_1,
            "_time": "2026-09-16T14:10:06.6324262Z",
            "host": "splunk-host",
            "source": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        }
    }


class BotsParserTests(unittest.TestCase):
    def test_adds_bots_provenance(self):
        event = normalize_bots_record(bots_record())

        self.assertEqual(event["event_id"], 1)
        self.assertEqual(event["provenance"]["dataset"], "botsv1")
        self.assertEqual(event["provenance"]["splunk_host"], "splunk-host")

    def test_skips_the_splunk_footer(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            lines = (json.dumps(bots_record()), json.dumps({"lastrow": True}))
            path.write_text("\n".join(lines), encoding="utf-8")

            events = list(parse_bots_events(path))

        self.assertEqual(len(events), 1)

    def test_reads_gzip_json_lines_and_applies_the_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.json.gz"
            with gzip.open(path, "wt", encoding="utf-8") as output:
                output.write(json.dumps(bots_record()) + "\n")
                output.write(json.dumps(bots_record()) + "\n")

            events = list(parse_bots_events(path, limit=1))

        self.assertEqual(len(events), 1)


if __name__ == "__main__":
    unittest.main()
