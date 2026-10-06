import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from enrich_iocs import (  # noqa: E402
    create_tables,
    eligible_for_rdap,
    eligible_for_threatfox,
    make_cache_key,
    rdap_request,
    rdap_result,
    store_cache,
    store_enrichment,
    threatfox_request,
    threatfox_result,
)


class RequestTests(unittest.TestCase):
    def test_threatfox_request_is_an_exact_read_only_search(self):
        request = threatfox_request({"value": "example.com"}, "secret")
        body = json.loads(request["body"])

        self.assertEqual(body["query"], "search_ioc")
        self.assertTrue(body["exact_match"])
        self.assertEqual(request["headers"]["Auth-Key"], "secret")
        self.assertNotIn(
            "secret",
            make_cache_key("threatfox", "POST", request["url"], request["body"]),
        )

    def test_rdap_request_uses_the_correct_object_type(self):
        request = rdap_request({"indicator_type": "ip", "value": "8.8.8.8"})
        self.assertEqual(request["url"], "https://rdap.org/ip/8.8.8.8")

    def test_rdap_rejects_non_public_resources(self):
        self.assertFalse(
            eligible_for_rdap(
                {"indicator_type": "ip", "value": "10.0.0.1", "is_public": 0}
            )
        )

    def test_threatfox_rejects_non_public_resources(self):
        self.assertFalse(
            eligible_for_threatfox(
                {"indicator_type": "ip", "value": "10.0.0.1", "is_public": 0}
            )
        )
        self.assertFalse(
            eligible_for_threatfox(
                {
                    "indicator_type": "domain",
                    "value": "host.example.local",
                    "is_public": None,
                }
            )
        )
        self.assertTrue(
            eligible_for_threatfox(
                {
                    "indicator_type": "hash",
                    "value": "aa" * 32,
                    "is_public": None,
                }
            )
        )
        self.assertFalse(
            eligible_for_rdap(
                {
                    "indicator_type": "domain",
                    "value": "host.example.local",
                    "is_public": None,
                }
            )
        )


class ResultTests(unittest.TestCase):
    def test_reads_threatfox_confidence(self):
        response = {
            "response_body": json.dumps(
                {
                    "query_status": "ok",
                    "data": [{"confidence_level": 75}, {"confidence_level": 50}],
                }
            )
        }
        self.assertEqual(threatfox_result(response), ("found", 75, None))

    def test_marks_empty_threatfox_results_not_found(self):
        response = {
            "response_body": json.dumps({"query_status": "no_result", "data": []})
        }
        self.assertEqual(threatfox_result(response), ("not_found", None, None))

    def test_reads_rdap_status(self):
        found = {"response_status": 200, "response_body": "{}"}
        missing = {"response_status": 404, "response_body": "{}"}
        self.assertEqual(rdap_result(found), ("found", None, None))
        self.assertEqual(rdap_result(missing), ("not_found", None, None))


class CacheTests(unittest.TestCase):
    def test_stores_raw_response_and_enrichment_metadata(self):
        response = {
            "source": "rdap",
            "request_method": "GET",
            "request_url": "https://rdap.org/ip/8.8.8.8",
            "request_body": None,
            "response_url": "https://rdap.arin.net/registry/ip/8.8.8.8",
            "response_status": 200,
            "response_headers": '{"Content-Type":"application/rdap+json"}',
            "response_body": '{"objectClassName":"ip network"}',
            "queried_at": "2026-10-06T00:00:00Z",
        }
        cache_key = make_cache_key("rdap", "GET", response["request_url"], None)

        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "events.db"
            with sqlite3.connect(database) as connection:
                connection.execute("PRAGMA foreign_keys = ON")
                connection.execute(
                    "CREATE TABLE indicators (id INTEGER PRIMARY KEY, value TEXT)"
                )
                connection.execute("INSERT INTO indicators VALUES (1, '8.8.8.8')")
                create_tables(connection)
                store_cache(connection, cache_key, response)
                store_enrichment(
                    connection,
                    1,
                    "rdap",
                    response,
                    ("found", None, None),
                    cache_key,
                )
                refreshed = dict(response)
                refreshed["queried_at"] = "2026-10-07T00:00:00Z"
                store_cache(connection, cache_key, refreshed)

                cached_body = connection.execute(
                    "SELECT response_body FROM api_cache WHERE cache_key = ?",
                    (cache_key,),
                ).fetchone()[0]
                enrichment = connection.execute(
                    """
                    SELECT source_dataset, source, status, status_detail, query_time
                    FROM enrichments
                    """
                ).fetchone()
                refreshed_time = connection.execute(
                    "SELECT queried_at FROM api_cache WHERE cache_key = ?",
                    (cache_key,),
                ).fetchone()[0]

        self.assertEqual(cached_body, response["response_body"])
        self.assertEqual(
            enrichment,
            (
                "unknown",
                "rdap",
                "found",
                "current registration context available",
                "2026-10-06T00:00:00Z",
            ),
        )
        self.assertEqual(refreshed_time, "2026-10-07T00:00:00Z")


if __name__ == "__main__":
    unittest.main()
