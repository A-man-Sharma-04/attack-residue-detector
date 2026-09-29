"""Residue detector: diff current host state against the trusted baseline.

A residue is NOT proof of compromise (final_plan section 17). It becomes
meaningful only once the forensic engine correlates it with historical security
evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

from ..collectors import state as collectors
from ..core.statemodel import Residue, ResidueType, Spec

DETECTOR_VERSION = "1.0.0"

# Severities: how much a lone residue should worry us before corroboration.
SEVERITY = {
    ResidueType.NEW_EXECUTABLE: 8,
    ResidueType.NEW_SERVICE: 8,
    ResidueType.FILE_MODIFIED: 7,
    ResidueType.FILE_CREATED: 7,
    ResidueType.NEW_SSH_KEY: 9,
    ResidueType.NEW_USER: 8,
    ResidueType.PERMISSION_CHANGE: 6,
    ResidueType.NEW_PORT: 6,
    ResidueType.NEW_SCHEDULED_TASK: 7,
    ResidueType.NEW_PROCESS: 5,
    ResidueType.LOG_TAMPERING: 9,
}


def _rid() -> str:
    return uuid.uuid4().hex[:12]


def _residue(rtype: ResidueType, target: str, detail: str,
             baseline_value: Any = None, current_value: Any = None,
             stat: dict[str, Any] | None = None) -> Residue:
    stat = stat or {}
    return Residue(
        residue_id=_rid(),
        residue_type=rtype,
        target=target,
        detail=detail,
        severity=SEVERITY.get(rtype, 5),
        detected_at=time.time(),
        baseline_value=baseline_value,
        current_value=current_value,
        sha256_before=str(baseline_value or ""),
        sha256_after=str(stat.get("sha256", "")),
        owner=str(stat.get("owner", "")),
        mode=str(stat.get("mode", "")),
        mtime=stat.get("mtime"),
        detector_version=DETECTOR_VERSION,
    )


# --------------------------------------------------------------------------
# per-type comparisons
# --------------------------------------------------------------------------

def _diff_services(base: dict, cur: dict) -> list[Residue]:
    out: list[Residue] = []
    b_units = set(base.get("unit_files", []))
    c_units = set(cur.get("unit_files", []))
    for unit in sorted(c_units - b_units):
        stat = collectors.file_stat(unit)
        out.append(_residue(
            ResidueType.NEW_SERVICE, unit,
            "systemd unit file present that is absent from the trusted baseline",
            baseline_value=None, current_value=unit, stat=stat))

    b_en = set(base.get("enabled_services", []))
    c_en = set(cur.get("enabled_services", []))
    for svc in sorted(c_en - b_en):
        out.append(_residue(
            ResidueType.NEW_SERVICE, svc,
            "service newly enabled at boot", baseline_value=None,
            current_value=svc))
    return out


def _diff_ports(base: dict, cur: dict) -> list[Residue]:
    b_ports = {p["port"] for p in base.get("listening_ports", [])}
    c_ports = {p["port"]: p for p in cur.get("listening_ports", [])}
    return [
        _residue(ResidueType.NEW_PORT, str(port),
                 f"new listening TCP port bound to {info.get('bind', '?')}",
                 baseline_value=None, current_value=info)
        for port, info in sorted(c_ports.items()) if port not in b_ports
    ]


def _diff_files(base: dict, cur: dict) -> list[Residue]:
    out: list[Residue] = []
    b_files = base.get("files", {})
    c_files = cur.get("files", {})

    for path, b in sorted(b_files.items()):
        c = c_files.get(path)
        if not c:
            out.append(_residue(
                ResidueType.FILE_MODIFIED, path,
                "watched file present in baseline but now missing",
                baseline_value=b.get("sha256"), current_value=None))
            continue
        if b.get("sha256") and c.get("sha256") != b.get("sha256"):
            out.append(_residue(
                ResidueType.FILE_MODIFIED, path,
                "content hash differs from the trusted baseline",
                baseline_value=b.get("sha256"), current_value=c.get("sha256"),
                stat=c))
        if b.get("mode") and c.get("mode") != b.get("mode"):
            out.append(_residue(
                ResidueType.PERMISSION_CHANGE, path,
                f"permissions changed {b.get('mode')} -> {c.get('mode')}",
                baseline_value=b.get("mode"), current_value=c.get("mode"),
                stat=c))

    b_dirs = base.get("dir_listings", {})
    c_dirs = cur.get("dir_listings", {})
    for d, names in sorted(c_dirs.items()):
        known = set(b_dirs.get(d, []))
        for name in sorted(set(names) - known):
            full = os.path.join(d, name)
            out.append(_residue(
                ResidueType.FILE_CREATED, full,
                "new file appeared in a watched directory",
                baseline_value=None, current_value=full,
                stat=collectors.file_stat(full)))
    return out


def _diff_executables(base: dict, cur: dict) -> list[Residue]:
    b_ex = base.get("executables", {})
    c_ex = cur.get("executables", {})
    out: list[Residue] = []
    for path, info in sorted(c_ex.items()):
        if path not in b_ex:
            out.append(_residue(
                ResidueType.NEW_EXECUTABLE, path,
                "unknown executable in a watched staging directory",
                baseline_value=None, current_value=path, stat=info))
        else:
            b = b_ex[path]
            if b.get("sha256") and info.get("sha256") != b.get("sha256"):
                out.append(_residue(
                    ResidueType.NEW_EXECUTABLE, path,
                    "known executable content changed",
                    baseline_value=b.get("sha256"), current_value=info.get("sha256"),
                    stat=info))
    return out


def _diff_users(base: dict, cur: dict) -> list[Residue]:
    b_u = base.get("users", {})
    c_u = cur.get("users", {})
    return [
        _residue(ResidueType.NEW_USER, name,
                 "local account present that is absent from the baseline",
                 baseline_value=None, current_value=info)
        for name, info in sorted(c_u.items()) if name not in b_u
    ]


def _diff_ssh_keys(base: dict, cur: dict) -> list[Residue]:
    b_k = base.get("ssh_keys", {})
    c_k = cur.get("ssh_keys", {})
    out: list[Residue] = []
    for path, info in sorted(c_k.items()):
        if path not in b_k:
            out.append(_residue(
                ResidueType.NEW_SSH_KEY, path,
                "authorized_keys file that did not exist at baseline",
                baseline_value=None, current_value=path, stat=info))
        elif (b_k[path].get("sha256")
              and info.get("sha256") != b_k[path].get("sha256")):
            out.append(_residue(
                ResidueType.NEW_SSH_KEY, path,
                "authorized_keys content changed - possible key persistence",
                baseline_value=b_k[path].get("sha256"),
                current_value=info.get("sha256"), stat=info))
    return out


def _diff_cron(base: dict, cur: dict) -> list[Residue]:
    out: list[Residue] = []
    b_c = base.get("cron", {})
    c_c = cur.get("cron", {})
    for loc, info in sorted(c_c.items()):
        if loc not in b_c:
            out.append(_residue(
                ResidueType.NEW_SCHEDULED_TASK, loc,
                "scheduled task present that is absent from the baseline",
                baseline_value=None, current_value=info))
    b_t = set(base.get("timers", []))
    for timer in sorted(set(cur.get("timers", [])) - b_t):
        out.append(_residue(
            ResidueType.NEW_SCHEDULED_TASK, timer,
            "new systemd timer", baseline_value=None, current_value=timer))
    return out


# --------------------------------------------------------------------------
# engine
# --------------------------------------------------------------------------

def scan(baseline_doc: dict[str, Any],
         current: dict[str, Any] | None = None) -> list[Residue]:
    """Compare current state against the baseline and return typed residues."""
    base = baseline_doc.get("state", {})
    cur = current if current is not None else collectors.collect_all()

    residues: list[Residue] = []
    for fn in (_diff_services, _diff_ports, _diff_files, _diff_executables,
               _diff_users, _diff_ssh_keys, _diff_cron):
        residues.extend(fn(base.get(fn.__name__[6:], {}) or {}, cur.get(fn.__name__[6:], {}) or {}))

    residues.sort(key=lambda r: (-r.severity, r.target))
    return residues


def suppress_authorized(residues: list[Residue],
                        window_start: float | None) -> list[Residue]:
    """Mark residues whose targets were touched inside a maintenance window.

    final_plan section 18: without this, ordinary administration produces a
    flood of false positives.
    """
    if not window_start:
        return residues
    for r in residues:
        if r.mtime and r.mtime >= window_start:
            r.authorized = True
            r.detail += " [authorized: inside maintenance window]"
    return residues
