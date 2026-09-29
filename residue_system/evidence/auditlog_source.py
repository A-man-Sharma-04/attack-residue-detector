"""Direct parser for the Linux audit log (``/var/log/audit/audit.log``).

Why not ``ausearch``?
---------------------
Measured on the target (Ubuntu 26.04, auditd from ``audit`` 4.1.2)::

    $ sudo ausearch -k web_changes -ts today
    <no matches>                    # yet 258 SYSCALL records exist on disk
    $ sudo ausearch --input-logs -k web_changes -ts 1790655128
    Invalid start date (1790655128). Month, Day, and Year are required.

auditd itself is healthy (``enabled 1``, ``lost 0``, ``backlog 0``). The log
carries pre-interpreted text appended after each raw record, which breaks
ausearch's parser. Parsing the raw log directly is portable across Ubuntu
versions and gives us the audit serial we need for event grouping.

Record shapes handled (all verified against the live target)::

    type=SYSCALL msg=audit(1790662283.599:699): ... comm="tee" exe="/usr/bin/tee"
                  ... uid=0 pid=362415 ppid=362412 key="web_changes"
    type=PATH    msg=audit(1790662283.599:699): item=1
                  name="/var/www/college/probe.html" mode=0100644 nametype=CREATE
    type=EXECVE  msg=audit(1790662283.599:699): argc=3 a0="tee" ...

Records sharing ``<epoch>:<serial>`` belong to the same syscall and are merged
into a single :class:`EvidenceEvent`.
"""

from __future__ import annotations

import datetime as _dt
import re
from typing import Iterable, Iterator

from ..core.statemodel import EvidenceEvent

# audit(<epoch>.<ms>:<serial>)
_SERIAL_RE = re.compile(r"audit\((\d+\.\d+):(\d+)\)")

# key=value, where value is either "quoted" or bare. Greedy-safe: quoted
# alternatives are tried first so paths containing '=' survive.
_KV_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)=(?:"([^"]*)"|(\S+))')

# The tail appended by some setups is entirely UPPERCASE (ARCH=, SYSCALL=,
# AUID=, UID=, ...). Raw audit fields are lowercase, so we simply ignore
# uppercase keys and never mistake the interpreted block for real data.
_INTERPRETED_TAIL_RE = re.compile(r"\s(?:ARCH|SYSCALL|AUID|UID|GID|EUID|SUID|"
                                  r"FSUID|EGID|SGID|FSGID)=")

_PATH_FIELDS = ("name", "nametype", "mode", "ouid", "ogid", "inode", "dev")


class AuditLogParseError(RuntimeError):
    pass


def _parse_fields(blob: str) -> dict[str, str]:
    """Extract ``key=value`` pairs, dropping the interpreted uppercase tail."""
    cut = _INTERPRETED_TAIL_RE.search(blob)
    if cut:
        blob = blob[: cut.start()]
    out: dict[str, str] = {}
    for m in _KV_RE.finditer(blob):
        key = m.group(1)
        # Ignore the interpreted (uppercase) block entirely.
        if key.isupper() and key not in ("SYSCALL",):
            continue
        out[key] = m.group(2) if m.group(2) is not None else m.group(3)
    return out


def _as_int(value: str | None) -> int | None:
    if value is None or value == "" or value == "?":
        return None
    try:
        return int(value, 10)
    except ValueError:
        return None


def parse_lines(lines: Iterable[str]) -> list[EvidenceEvent]:
    """Parse raw audit lines and return events grouped by audit serial.

    Later records of the same syscall (PATH, EXECVE, PROCTITLE) enrich the
    event created by the SYSCALL record.
    """
    events: dict[str, EvidenceEvent] = {}
    order: list[str] = []

    for line in lines:
        line = line.rstrip("\n")
        if not line or "type=" not in line:
            continue
        sm = _SERIAL_RE.search(line)
        if not sm:
            continue
        epoch = float(sm.group(1))
        serial = sm.group(2)
        event_id = f"{sm.group(1)}:{serial}"

        ftype_m = re.match(r"type=(\w+)\s", line)
        ftype = ftype_m.group(1) if ftype_m else ""
        body = line[line.find("msg=audit("):] if "msg=audit(" in line else line
        fields = _parse_fields(body)

        ev = events.get(event_id)
        if ev is None:
            ev = EvidenceEvent(
                event_id=event_id,
                timestamp=epoch,
                event_type=ftype,
                raw=line,
            )
            events[event_id] = ev
            order.append(event_id)
        elif ftype == "SYSCALL":
            # SYSCALL is the authoritative record; prefer it as the label.
            ev.event_type = "SYSCALL"
            ev.raw = line

        # --- SYSCALL fields ---
        if ftype == "SYSCALL":
            ev.syscall = fields.get("syscall", ev.syscall)
            ev.comm = fields.get("comm", ev.comm)
            ev.exe = fields.get("exe", ev.exe)
            ev.pid = _as_int(fields.get("pid")) if ev.pid is None else ev.pid
            ev.ppid = _as_int(fields.get("ppid")) if ev.ppid is None else ev.ppid
            ev.uid = _as_int(fields.get("uid")) if ev.uid is None else ev.uid
            ev.gid = _as_int(fields.get("gid")) if ev.gid is None else ev.gid
            ev.session = fields.get("ses", ev.session)
            ev.tty = fields.get("tty", ev.tty)
            ev.success = fields.get("success", "yes") != "no"
            if "key" in fields:
                ev.audit_key = fields["key"]

        # --- PATH records ---
        elif ftype == "PATH":
            name = fields.get("name")
            if name:
                ev.paths.append({k: fields.get(k, "") for k in _PATH_FIELDS})
                ev.raw = ev.raw + "\n" + line

        # --- EXECVE record ---
        elif ftype == "EXECVE":
            argc = _as_int(fields.get("argc")) or 0
            argv: list[str] = []
            for i in range(min(argc, 64)):
                v = fields.get(f"a{i}")
                if v is not None:
                    argv.append(v)
            if argv:
                ev.argv = argv
                if not ev.comm:
                    ev.comm = os.path.basename(argv[0]) if argv[0] else ""
                if not ev.exe:
                    ev.exe = _resolve_exec(argv[0])
            ev.raw = ev.raw + "\n" + line

        # --- PROCTITLE: "proctitle" hex blob -> readable argv ---
        elif ftype == "PROCTITLE" and not ev.argv:
            hexblob = fields.get("proctitle", "")
            ev.argv = _decode_proctitle(hexblob)
            ev.raw = ev.raw + "\n" + line

    return [events[k] for k in order]


def _resolve_exec(arg0: str) -> str:
    import os
    return arg0 if arg0.startswith("/") else ""


def _decode_proctitle(hexblob: str) -> list[str]:
    if not hexblob:
        return []
    try:
        raw = bytes.fromhex(hexblob)
    except ValueError:
        return []
    return [p.decode("utf-8", "replace") for p in raw.split(b"\x00") if p]


def read_audit_log(path: str = "/var/log/audit/audit.log",
                   since: float | None = None) -> list[EvidenceEvent]:
    """Read and parse the audit log, optionally filtering by epoch seconds.

    ``since`` implements the spec's 24-hour correlation lookback without
    depending on ausearch's (broken) time parsing.
    """
    events: list[EvidenceEvent] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for ev in parse_lines(fh):
            if since is None or ev.timestamp >= since:
                events.append(ev)
    return events


def iter_raw_lines(path: str = "/var/log/audit/audit.log") -> Iterator[str]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        yield from fh


def events_for_serial(path: str, event_id: str) -> list[str]:
    """Return the raw log lines belonging to one audit serial.

    Used to emit the citable evidence excerpts the instructor asks to be saved.
    """
    return [ln.rstrip("\n") for ln in iter_raw_lines(path)
            if f":{event_id.split(':')[-1]})" in ln or f"audit({event_id}" in ln]


def human(ts: float) -> str:
    return _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S")


import os  # noqa: E402  (used by _resolve_exec)
