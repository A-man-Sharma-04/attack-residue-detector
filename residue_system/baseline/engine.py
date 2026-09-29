"""Baseline engine: record the trusted state, then diff against it.

The baseline is versioned (final_plan section 15) so drift over time is visible,
and every snapshot carries a content manifest so tampering with a baseline is
itself detectable.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import socket
import subprocess
from pathlib import Path
from typing import Any

from ..collectors import state as collectors

BASELINE_ROOT = os.environ.get(
    "RESIDUE_BASELINE_DIR",
    "/var/lib/residue-system/baselines",
)


class BaselineError(RuntimeError):
    pass


def _now() -> float:
    import time
    return time.time()


def _host_fingerprint() -> dict[str, Any]:
    ver = subprocess.run(["uname", "-r"], capture_output=True, text=True,
                         check=False).stdout.strip()
    try:
        osrel = Path("/etc/os-release").read_text(encoding="utf-8")
        pretty = ""
        for line in osrel.splitlines():
            if line.startswith("PRETTY_NAME="):
                pretty = line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pretty = ""
    return {
        "hostname": socket.gethostname(),
        "kernel": ver,
        "os": pretty,
        "python": f"{os.sys.version_info.major}.{os.sys.version_info.minor}."
                  f"{os.sys.version_info.micro}",
    }


def _manifest(state: dict[str, Any]) -> str:
    blob = json.dumps(state, sort_keys=True, default=str).encode()
    return hashlib.sha256(blob).hexdigest()


def create(name: str = "local", note: str = "") -> dict[str, Any]:
    """Snapshot the current host as the trusted baseline."""
    state = collectors.collect_all()
    doc = {
        "schema": 1,
        "baseline_name": name,
        "version": 1,
        "created_at": _now(),
        "created_at_iso": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "note": note,
        "host": _host_fingerprint(),
        "manifest_sha256": _manifest(state),
        "state": state,
    }

    root = Path(BASELINE_ROOT)
    root.mkdir(parents=True, exist_ok=True)
    # Keep the newest N versions; do not delete anything we did not create.
    for old in sorted(root.glob(f"{name}.v*.json")):
        try:
            ver = int(old.stem.rsplit(".v", 1)[1])
        except (IndexError, ValueError):
            continue
        if ver > 1:
            old.unlink()

    path = root / f"{name}.v1.json"
    path.write_text(json.dumps(doc, indent=2, sort_keys=True, default=str),
                    encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    doc["_path"] = str(path)
    return doc


def load(name: str = "local", version: int = 1) -> dict[str, Any]:
    path = Path(BASELINE_ROOT) / f"{name}.v{version}.json"
    if not path.exists():
        raise BaselineError(
            f"no baseline at {path}. Run: cli.py baseline create")
    return json.loads(path.read_text(encoding="utf-8"))


def verify(doc: dict[str, Any]) -> bool:
    """Confirm the baseline has not been edited since it was written."""
    recomputed = _manifest(doc.get("state", {}))
    return recomputed == doc.get("manifest_sha256")


def describe(doc: dict[str, Any]) -> str:
    st = doc.get("state", {})
    svc = st.get("services", {})
    ports = st.get("ports", {})
    files = st.get("files", {})
    lines = [
        f"baseline     : {doc.get('baseline_name')} v{doc.get('version')}",
        f"created      : {doc.get('created_at_iso')}",
        f"host         : {doc.get('host', {}).get('hostname')} "
        f"({doc.get('host', {}).get('os')})",
        f"manifest     : {doc.get('manifest_sha256', '')[:16]}…",
        f"units enabled: {len(svc.get('enabled_services', []))}",
        f"unit files   : {len(svc.get('unit_files', []))}",
        f"listening    : {[p['port'] for p in ports.get('listening_ports', [])]}",
        f"web files    : {len(files.get('files', {}))}",
        f"executables  : {len(st.get('executables', {}).get('executables', {}))}",
        f"users        : {len(st.get('users', {}).get('users', {}))}",
    ]
    return "\n".join(lines)
