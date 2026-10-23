"""Offline checks for the scheduled report fetcher's durable cursor and errors."""
import importlib.util
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "report_fetcher", Path(__file__).resolve().parents[1] / "intelligence" / "fetch-h1-reports.py"
)
fetcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fetcher)


class FetchReportsTest(unittest.TestCase):
    def test_auth_check_uses_hacker_endpoint_without_writing_reports(self):
        with tempfile.TemporaryDirectory() as root:
            reports = Path(root) / "reports"
            response = type("Response", (), {"ok": True, "status_code": 200,
                                            "json": lambda self: {"data": []}})()
            with patch.object(fetcher, "LOCAL_DIR", reports), \
                 patch.dict(os.environ, {"H1_API_USERNAME": "test", "H1_API_TOKEN": "test"}), \
                 patch.object(fetcher.requests, "get", return_value=response) as get, \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                fetcher.check_api_auth()
                self.assertIn("authentication: OK", output.getvalue())
                self.assertEqual(get.call_args.args[0], "https://api.hackerone.com/v1/hackers/hacktivity")
                self.assertEqual(get.call_args.kwargs["auth"], ("test", "test"))
                self.assertFalse(reports.exists())

    def test_api_reads_every_page_before_advancing_cursor(self):
        with tempfile.TemporaryDirectory() as root:
            reports = Path(root) / "reports"
            queue = Path(root) / "queue"
            pages = [
                [{"id": str(i), "attributes": {"title": "Fixture", "disclosed": True,
                  "severity_rating": "high", "disclosed_at": "2026-01-01T00:00:00Z"}}
                 for i in range(100)],
                [{"id": "100", "attributes": {"title": "Fixture", "disclosed": True,
                  "severity_rating": "high", "disclosed_at": "2026-01-01T00:00:00Z"}}],
            ]
            def get(_url, *, params, **_kwargs):
                data = pages[params["page[number]"] - 1]
                return type("Response", (), {"ok": True, "status_code": 200,
                                              "json": lambda self: {"data": data}})()
            with patch.object(fetcher, "LOCAL_DIR", reports), \
                 patch.object(fetcher, "QUEUE_DIR", queue), \
                 patch.dict(os.environ, {"H1_API_USERNAME": "test", "H1_API_TOKEN": "test"}), \
                 patch.object(fetcher.requests, "get", side_effect=get), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(fetcher.fetch_via_api(), 101)
                self.assertEqual(len(list(queue.glob("h1-*.json"))), 101)
                self.assertTrue((reports / ".last-fetch.json").exists())

    def test_api_persists_cursor_in_reports_and_queues_disclosure(self):
        with tempfile.TemporaryDirectory() as root:
            reports = Path(root) / "reports"
            queue = Path(root) / "queue"
            response = type("Response", (), {
                "ok": True, "status_code": 200,
                "json": lambda self: {"data": [{"id": "79", "attributes": {
                    "title": "Fixture", "disclosed_at": "2026-01-01T00:00:00Z",
                    "disclosed": True, "severity_rating": "high", "cwe": "CWE-79",
                    "url": "https://hackerone.com/reports/79", "total_awarded_amount": 500,
                }, "relationships": {
                    "report_generated_content": {"data": {"attributes": {"hacktivity_summary": "Reflected script execution"}}},
                    "program": {"data": {"attributes": {"handle": "fixture", "name": "Fixture"}}},
                }}]},
            })()
            with patch.object(fetcher, "LOCAL_DIR", reports), \
                 patch.object(fetcher, "QUEUE_DIR", queue), \
                 patch.dict(os.environ, {"H1_API_USERNAME": "test", "H1_API_TOKEN": "test"}), \
                 patch.object(fetcher.requests, "get", return_value=response) as get:
                self.assertEqual(fetcher.fetch_via_api(), 1)
                self.assertEqual(json.loads((reports / ".last-fetch.json").read_text()),
                                 {"lastDisclosedAt": "2026-01-01T00:00:00Z"})
                self.assertEqual(json.loads((queue / "h1-79.json").read_text())["cwe"],
                                 {"id": "CWE-79"})
                item = json.loads((queue / "h1-79.json").read_text())
                self.assertEqual(item["vulnerabilityInformation"], "Reflected script execution")
                self.assertEqual(item["teamHandle"], "fixture")
                self.assertEqual(item["bountyAmount"], 500)
                self.assertEqual(get.call_count, 1)
                args, kwargs = get.call_args
                self.assertEqual(args[0], "https://api.hackerone.com/v1/hackers/hacktivity")
                self.assertEqual(kwargs["auth"], ("test", "test"))
                self.assertIn("disclosed:true", kwargs["params"]["queryString"])

    def test_api_error_fails_the_action(self):
        with tempfile.TemporaryDirectory() as root:
            failure = type("Response", (), {"ok": False, "status_code": 403, "text": "Forbidden"})()
            with patch.object(fetcher, "LOCAL_DIR", Path(root)), \
                 patch.dict(os.environ, {"H1_API_USERNAME": "test", "H1_API_TOKEN": "test"}), \
                 patch.object(fetcher.requests, "get", return_value=failure):
                with self.assertRaisesRegex(RuntimeError, "HackerOne Hacker API 403"):
                    fetcher.fetch_via_api()

    def test_undisclosed_and_low_severity_reports_never_enter_queue(self):
        with tempfile.TemporaryDirectory() as root:
            reports = Path(root) / "reports"
            queue = Path(root) / "queue"
            data = [
                {"id": "1", "attributes": {"disclosed": False, "severity_rating": "high", "disclosed_at": "2026-01-01T00:00:00Z"}},
                {"id": "2", "attributes": {"disclosed": True, "severity_rating": "low", "disclosed_at": "2026-01-02T00:00:00Z"}},
            ]
            response = type("Response", (), {"ok": True, "status_code": 200,
                                            "json": lambda self: {"data": data}})()
            with patch.object(fetcher, "LOCAL_DIR", reports), \
                 patch.object(fetcher, "QUEUE_DIR", queue), \
                 patch.dict(os.environ, {"H1_API_USERNAME": "test", "H1_API_TOKEN": "test"}), \
                 patch.object(fetcher.requests, "get", return_value=response):
                self.assertEqual(fetcher.fetch_via_api(), 0)
                self.assertEqual(list(queue.glob("*.json")), [])
                self.assertEqual(json.loads((reports / ".last-fetch.json").read_text()),
                                 {"lastDisclosedAt": "2026-01-02T00:00:00Z"})


if __name__ == "__main__":
    unittest.main()
