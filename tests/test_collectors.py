#!/usr/bin/env python3
"""Regression tests for the state collectors.

These are stdlib-only and run without a target host, so the parsing logic is
verified in CI/dev rather than only on the box being monitored.

Run: python3 tests/test_collectors.py
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from residue_system.collectors.state import parse_ss_ports  # noqa: E402

# Real `ss -tlnH` output captured from the target, verbatim. Note the leading
# LISTEN token: an earlier regex matched *that* as the address and returned an
# empty result, which made the collector look like "no listening ports".
SS_SAMPLE = """\
LISTEN 0      4096         0.0.0.0:111   0.0.0.0:*
LISTEN 0      4096   127.0.0.53%lo:53    0.0.0.0:*
LISTEN 0      4096       127.0.0.1:43685 0.0.0.0:*
LISTEN 0      4096         0.0.0.0:22    0.0.0.0:*
LISTEN 0      4096       127.0.0.54:53    0.0.0.0:*
LISTEN 0      4096       127.0.0.1:5678  0.0.0.0:*
LISTEN 0      511        127.0.0.1:8081  0.0.0.0:*
LISTEN 0      5            0.0.0.0:8080  0.0.0.0:*
"""


class TestParseSsPorts(unittest.TestCase):

    def test_finds_every_listening_port(self):
        result = parse_ss_ports(SS_SAMPLE)
        found = [p["port"] for p in result["listening_ports"]]
        self.assertEqual(found, [22, 53, 111, 5678, 8080, 8081, 43685])

    def test_bind_address_is_not_the_state_column(self):
        """The original bug: 'LISTEN' was captured as the address."""
        result = parse_ss_ports(SS_SAMPLE)
        for entry in result["listening_ports"]:
            self.assertNotEqual(entry["bind"], "LISTEN")

    def test_loopback_bind_recorded(self):
        result = parse_ss_ports(SS_SAMPLE)
        binds = {p["port"]: p["bind"] for p in result["listening_ports"]}
        self.assertEqual(binds[8081], "127.0.0.1")
        self.assertEqual(binds[22], "0.0.0.0")

    def test_ports_are_sorted_and_unique(self):
        result = parse_ss_ports(SS_SAMPLE)
        found = [p["port"] for p in result["listening_ports"]]
        self.assertEqual(found, sorted(found))
        self.assertEqual(len(found), len(set(found)))

    def test_ipv6_bracket_form(self):
        out = "LISTEN 0      128    [::]:8080      [::]:*\n"
        result = parse_ss_ports(out)
        self.assertEqual(result["listening_ports"][0]["bind"], "::")

    def test_empty_and_garbage_input_is_safe(self):
        self.assertEqual(parse_ss_ports("")["listening_ports"], [])
        self.assertEqual(parse_ss_ports("garbage\nnope\n")["listening_ports"], [])

    def test_header_row_is_ignored(self):
        """If -H ever stops suppressing the header, don't emit a bogus port."""
        out = ("State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
               "LISTEN 0      128    0.0.0.0:22       0.0.0.0:*\n")
        result = parse_ss_ports(out)
        self.assertEqual([p["port"] for p in result["listening_ports"]], [22])


if __name__ == "__main__":
    unittest.main(verbosity=2)
