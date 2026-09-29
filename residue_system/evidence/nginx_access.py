#!/usr/bin/env python3
"""Nginx access-log evidence source.

Auditd proves *file writes*; it does not record that an HTTP request arrived.
Claiming a "web request" stage from a `web_changes` audit record is a category
error, so genuine request evidence is read from the vhost access log instead
and emitted as EvidenceEvent objects with audit_key="web_request".

This is what lets the reconstructed attack path genuinely begin with
Web Request instead of asserting it.

Format handled (the default nginx 'combined'):
    127.0.0.1 - - [29/Sep/2026:08:38:22 +0000] "GET /index.php?cmd=id HTTP/1.1" 200 399 "-" "curl/8.18.0"
"""

from __future__ import annotations

import re
import time
from typing import Iterable

from ..core.statemodel import EvidenceEvent

# combined log format, tolerant of the usual "-" placeholders
LINE_RE = re.compile(
    r'^(?P<client>\S+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+(?P<proto>[^"]*))?"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\S+)'
    r'(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

TS_FMT = "%d/%b/%Y:%H:%M:%S %z"

# Request paths that are obviously routine and would drown the signal.
NOISE_EXACT = {"/favicon.ico"}
NOISE_PREFIX = ("/static/", "/assets/", "/css/", "/js/", "/images/")


def _is_noise(path: str) -> bool:
    clean = path.split("?", 1)[0]
    if clean in NOISE_EXACT:
        return True
    return any(clean.startswith(p) for p in NOISE_PREFIX)


def parse_access_log(path: str,
                     since: float | None = None) -> list[EvidenceEvent]:
    """Parse an access log into EvidenceEvent objects."""
    events: list[EvidenceEvent] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines: Iterable[str] = fh.readlines()
    except OSError:
        return events

    for line in lines:
        m = LINE_RE.match(line.strip())
        if not m:
            continue
        try:
            ts = time.mktime(time.strptime(m.group("ts"), TS_FMT))
        except (ValueError, OverflowError):
            continue
        if since is not None and ts < since:
            continue

        req_path = m.group("path")
        if _is_noise(req_path):
            continue

        try:
            status = int(m.group("status"))
        except ValueError:
            status = 0

        events.append(EvidenceEvent(
            # synthetic id: the access log has no serial to join on
            event_id=f"nginx:{ts:.3f}:{req_path}",
            timestamp=ts,
            event_type="ACCESS",
            audit_key="web_request",
            comm="nginx",
            paths=[{"name": req_path, "nametype": "REQUEST"}],
            argv=[m.group("method"), req_path],
            success=(200 <= status < 400),
            raw=line.strip(),
        ))
    return events


def suspicious_requests(events: Iterable[EvidenceEvent]) -> list[EvidenceEvent]:
    """Requests worth showing: injection-flavoured query strings or 5xx."""
    needles = ("cmd=", "exec=", "id=", "whoami", "cat ", ";", "|", "$(", "..")
    out = []
    for ev in events:
        target = (ev.argv[1] if len(ev.argv) > 1 else "").lower()
        if any(n in target for n in needles) or not ev.success:
            out.append(ev)
    return out
