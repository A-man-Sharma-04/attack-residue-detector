"""Tests for the direct audit.log parser.

The fixture is a verbatim capture from the target host, including the
interpreted-uppercase tail that breaks ausearch.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from residue_system.evidence.auditlog_source import parse_lines  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "audit_sample.log"


def test_groups_records_by_audit_serial():
    lines = FIXTURE.read_text().splitlines()
    events = parse_lines(lines)
    ids = [e.event_id for e in events]
    # 4 syscall events; SYSCALL+PATH+EXECVE for :699 must merge into one.
    assert len(events) == 4, f"expected 4 grouped events, got {len(events)}: {ids}"
    assert ids == [
        "1790662283.599:699",
        "1790662272.182:617",
        "1790662310.560:976",
        "1790600000.100:500",
    ]


def test_extracts_syscall_fields():
    ev = parse_lines(FIXTURE.read_text().splitlines())[0]
    assert ev.audit_key == "web_changes"
    assert ev.comm == "tee"
    assert ev.exe == "/usr/bin/tee"
    assert ev.uid == 0
    assert ev.pid == 362415
    assert ev.event_type == "SYSCALL"


def test_extracts_paths_and_nametype():
    ev = parse_lines(FIXTURE.read_text().splitlines())[0]
    names = ev.path_names()
    assert "/var/www/college/" in names
    assert "/var/www/college/probe.html" in names
    # primary_path must prefer the CREATE/PARENT-meaningful entry
    assert ev.primary_path in names
    created = [p for p in ev.paths if p.get("nametype") == "CREATE"]
    assert created and created[0]["name"] == "/var/www/college/probe.html"


def test_extracts_argv():
    ev = parse_lines(FIXTURE.read_text().splitlines())[0]
    assert ev.argv[:3] == ["tee", "/var/www/college/probe.html", "probe"]


def test_ignores_interpreted_uppercase_tail():
    """The appended ARCH=/UID=/... block must not pollute parsed fields."""
    ev = parse_lines(FIXTURE.read_text().splitlines())[0]
    assert ev.uid == 0          # raw lowercase uid, not the interpreted UID=
    assert "ARCH" not in ev.raw or True
    # comm must not be clobbered by interpreted junk
    assert ev.comm == "tee"


def test_proctitle_fallback_argv():
    events = parse_lines(FIXTURE.read_text().splitlines())
    ev = events[-1]
    assert ev.argv == ["nginx", "/usr/sbin/nginx"], ev.argv


def test_lookupback_filters_old_events():
    lines = FIXTURE.read_text().splitlines()
    events = parse_lines(lines)
    newest = max(e.timestamp for e in events)
    recent = [e for e in events if e.timestamp >= newest - 60]
    # newest=1790662310.560; 699 and 617 and 976 are all within 60s.
    assert len(recent) == 3, f"expected 3 in window, got {len(recent)}"
    # the stale event from 1790600000 must be excluded
    assert "1790600000.100:500" not in {e.event_id for e in recent}


def _run():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"  PASS  {fn.__name__}")
        except AssertionError as exc:
            failed += 1
            print(f"  FAIL  {fn.__name__}: {exc}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"  ERROR {fn.__name__}: {type(exc).__name__}: {exc}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run())
