from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from adapters.katana_scan import _url_from_katana_record, parse_katana_jsonl


class KatanaParseTests(unittest.TestCase):
    def test_url_from_legacy_top_level(self) -> None:
        obj = {"url": "http://example.com/path"}
        self.assertEqual(_url_from_katana_record(obj), "http://example.com/path")

    def test_url_from_request_endpoint(self) -> None:
        obj = {
            "request": {
                "method": "GET",
                "endpoint": "http://juice.local:3000/scripts.js",
            }
        }
        self.assertEqual(_url_from_katana_record(obj), "http://juice.local:3000/scripts.js")

    def test_parse_jsonl_mixed_lines(self) -> None:
        lines = [
            {"url": "http://legacy.example/"},
            {"request": {"endpoint": "http://juice.local:3000/api/Users"}},
            {"timestamp": "ignored"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "katana.jsonl"
            path.write_text("\n".join(json.dumps(x) for x in lines) + "\n", encoding="utf-8")
            urls, hosts = parse_katana_jsonl(path)

        self.assertEqual(
            urls,
            ["http://juice.local:3000/api/Users", "http://legacy.example/"],
        )
        self.assertIn("juice.local:3000", hosts)
        self.assertIn("legacy.example", hosts)


if __name__ == "__main__":
    unittest.main()
