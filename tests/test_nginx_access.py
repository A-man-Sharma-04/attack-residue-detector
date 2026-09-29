#!/usr/bin/env python3
"""Tests for the nginx access-log evidence source.

Run: python3 tests/test_nginx_access.py
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from residue_system.evidence import nginx_access  # noqa: E402

# Real lines from the target's college.access.log, verbatim.
LOG = """\
127.0.0.1 - - [29/Sep/2026:08:38:22 +0000] "GET /index.php HTTP/1.1" 200 387 "-" "curl/8.18.0"
127.0.0.1 - - [29/Sep/2026:08:45:56 +0000] "GET /index.php?cmd=id HTTP/1.1" 200 399 "-" "curl/8.18.0"
127.0.0.1 - - [29/Sep/2026:08:45:57 +0000] "GET /favicon.ico HTTP/1.1" 404 153 "-" "curl/8.18.0"
10.0.0.5 - - [29/Sep/2026:08:45:58 +0000] "POST /index.php HTTP/1.1" 500 0 "http://x/" "python-requests/2.31"
"""


class TestAccessLog(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile("w", suffix=".log", delete=False)
        self.tmp.write(LOG)
        self.tmp.close()

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_parses_all_non_noise_lines(self):
        """4 lines in, but /favicon.ico is dropped as noise -> 3 events."""
        events = nginx_access.parse_access_log(self.tmp.name)
        self.assertEqual(len(events), 3)

    def test_favicon_noise_is_dropped(self):
        events = nginx_access.parse_access_log(self.tmp.name)
        self.assertNotIn("/favicon.ico", [e.argv[1] for e in events])

    def test_audit_key_is_web_request(self):
        """Web-request evidence must be labelled as such, not inferred from
        a file-write audit record."""
        events = nginx_access.parse_access_log(self.tmp.name)
        self.assertTrue(all(e.audit_key == "web_request" for e in events))

    def test_status_is_captured_and_success_computed(self):
        events = nginx_access.parse_access_log(self.tmp.name)
        get_ok = [e for e in events
                  if e.argv == ["GET", "/index.php?cmd=id"]][0]
        self.assertTrue(get_ok.success)          # 200
        post = [e for e in events if e.argv[0] == "POST"][0]
        self.assertFalse(post.success)           # 500
        self.assertEqual(post.raw.split()[8], "500")

    def test_query_string_preserved(self):
        events = nginx_access.parse_access_log(self.tmp.name)
        paths = [e.argv[1] for e in events]
        self.assertIn("/index.php?cmd=id", paths)

    def test_suspicious_filter_flags_c2_probe(self):
        events = nginx_access.parse_access_log(self.tmp.name)
        sus = nginx_access.suspicious_requests(events)
        self.assertTrue(any("cmd=id" in e.argv[1] for e in sus))

    def test_since_filter(self):
        events = nginx_access.parse_access_log(self.tmp.name, since=1e12)
        self.assertEqual(events, [])

    def test_missing_file_is_safe(self):
        self.assertEqual(
            nginx_access.parse_access_log("/nonexistent/access.log"), [])

    def test_garbage_lines_ignored(self):
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
            f.write("this is not a log line\n\n###\n")
            name = f.name
        try:
            self.assertEqual(nginx_access.parse_access_log(name), [])
        finally:
            os.unlink(name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
