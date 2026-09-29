"""Read-only collectors of live host state.

Every function here is side-effect free. The residue detector must never mutate
the host; only the response engine may, and only under an explicit flag.

Scope is deliberately small and explicit. Hashing all of /usr would make each
60-second scan slow and would drown the signal in environment churn.
"""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import re
import stat
import subprocess
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------
# Watched scope - the artifact classes the project spec cares about
# --------------------------------------------------------------------------

WATCHED_FILES = [
    "/var/www/college/index.php",
]

WATCHED_FILE_DIRS = [
    "/var/www/college",
]

# Directories scanned for candidate planted executables.
WATCHED_EXEC_DIRS = [
    "/opt",
]

# Our own deployment lives under /opt too. Never report it as residue, or the
# detector would flag its own source tree and drown real findings.
SELF_EXCLUDE_PREFIXES = (
    "/opt/residue-system",
)

# Where a new systemd unit would appear.
SYSTEMD_UNIT_DIRS = [
    "/etc/systemd/system",
    "/lib/systemd/system",
]

SSH_KEY_FILES = [
    "/root/.ssh/authorized_keys",
    "/home/ubuntu/.ssh/authorized_keys",
]

CRON_LOCATIONS = [
    "/etc/crontab",
    "/etc/cron.d",
    "/var/spool/cron/crontabs",
]

# Ports that may be ignored regardless of baseline (ephemeral / local infra).
PORT_IGNORE = {0}


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _run(cmd: list[str], timeout: int = 15) -> str:
    """Run a command, returning stdout. Empty string on any failure."""
    try:
        res = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout, check=False)
        return res.stdout
    except (subprocess.TimeoutExpired, OSError):
        return ""


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def file_stat(path: str) -> dict[str, Any]:
    try:
        st = os.stat(path)
    except OSError:
        return {}
    try:
        owner = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        owner = str(st.st_uid)
    return {
        "sha256": sha256_file(path),
        "size": st.st_size,
        "mode": oct(st.st_mode & 0o7777),
        "uid": st.st_uid,
        "owner": owner,
        "gid": st.st_gid,
        "mtime": st.st_mtime,
    }


def _listdir(path: str) -> list[str]:
    try:
        return sorted(os.listdir(path))
    except OSError:
        return []


# --------------------------------------------------------------------------
# collectors - each returns a JSON-serialisable dict
# --------------------------------------------------------------------------

def collect_services() -> dict[str, Any]:
    """Enabled + running systemd units, and the on-disk unit files.

    Unit FILES are what matter for detecting a planted persistence unit, because
    a dropped unit does not have to be enabled to be residue.
    """
    enabled_out = _run(["systemctl", "list-unit-files", "--state=enabled",
                        "--no-pager", "--no-legend", "--plain"])
    enabled: list[str] = []
    for line in enabled_out.splitlines():
        name = line.split()[0] if line.split() else ""
        if name.endswith(".service"):
            enabled.append(name)

    unit_files: list[str] = []
    for d in SYSTEMD_UNIT_DIRS:
        for fn in _listdir(d):
            if fn.endswith((".service", ".timer", ".socket")):
                unit_files.append(os.path.join(d, fn))

    return {
        "enabled_services": sorted(set(enabled)),
        "unit_files": sorted(set(unit_files)),
    }


def parse_ss_ports(out: str) -> dict[str, Any]:
    """Parse `ss -tlnH` output. Pure function, so it is directly testable.

    `ss -tlnH` prints whitespace-separated columns with no header:
        State Recv-Q Send-Q Local-Address:Port Peer-Address:Port
    so the local endpoint is always column index 3. Parse positionally
    instead of with a regex: a regex over the whole line happily matches
    'LISTEN' as the address and silently drops every socket.
    """
    ports: dict[str, Any] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        if parts[0] not in ("LISTEN", "UNCONN"):
            continue
        endpoint = parts[3]
        if ":" not in endpoint:
            continue
        host, _, port_s = endpoint.rpartition(":")
        host = host.strip("[]")          # [::1]:8080 -> ::1
        try:
            port = int(port_s)
        except ValueError:
            continue
        if port in PORT_IGNORE:
            continue
        entry = ports.setdefault(port, {"port": port, "bind": host,
                                        "state": parts[0]})
        entry.setdefault("also_bound", [])
        if host != entry["bind"]:
            entry["also_bound"].append(host)
    return {"listening_ports": [ports[p] for p in sorted(ports)]}


def collect_ports() -> dict[str, Any]:
    """Listening TCP sockets."""
    return parse_ss_ports(_run(["ss", "-tlnH"]))


def collect_files() -> dict[str, Any]:
    """Hash + metadata for watched files, and listings of watched dirs."""
    files: dict[str, Any] = {}
    for path in WATCHED_FILES:
        st = file_stat(path)
        if st:
            files[path] = st

    listings: dict[str, list[str]] = {}
    for d in WATCHED_FILE_DIRS:
        names = _listdir(d)
        if names:
            listings[d] = names
    return {"files": files, "dir_listings": listings}


def collect_executables() -> dict[str, Any]:
    """Candidate executable / staging artefacts under watched dirs.

    Only counts a file as executable when it actually carries an execute bit
    or starts with a shebang. Treating every non-empty file as executable
    drowns the signal: /opt holds our own deployment, so a naive
    "non-empty == executable" rule reported our own source tree as residue
    noise. Our own install tree is excluded outright for the same reason.
    """
    found: dict[str, Any] = {}
    for root_dir in WATCHED_EXEC_DIRS:
        if not os.path.isdir(root_dir):
            continue
        for dirpath, dirnames, filenames in os.walk(root_dir):
            dirnames[:] = [d for d in dirnames
                           if os.path.join(dirpath, d) not in SELF_EXCLUDE_PREFIXES]
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                if any(full.startswith(p) for p in SELF_EXCLUDE_PREFIXES):
                    continue
                try:
                    st = os.stat(full)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode) or st.st_size == 0:
                    continue
                exec_bit = bool(st.st_mode & 0o111)
                try:
                    with open(full, "rb") as fh:
                        shebang = fh.read(2) == b"#!"
                except OSError:
                    shebang = False
                if not (exec_bit or shebang):
                    continue
                found[full] = {
                    "sha256": sha256_file(full),
                    "size": st.st_size,
                    "mode": oct(st.st_mode & 0o7777),
                    "executable": exec_bit,
                    "shebang": shebang,
                    "mtime": st.st_mtime,
                }
    return {"executables": found}


def collect_users() -> dict[str, Any]:
    """Regular (non-system) local accounts."""
    users: dict[str, Any] = {}
    for line in _read_lines("/etc/passwd"):
        f = line.split(":")
        if len(f) < 7:
            continue
        name, uid, shell, home = f[0], f[2], f[6], f[5]
        try:
            uid_i = int(uid)
        except ValueError:
            continue
        if uid_i < 1000 or uid_i >= 65534:
            continue
        users[name] = {"uid": uid_i, "shell": shell, "home": home}
    return {"users": users}


def collect_ssh_keys() -> dict[str, Any]:
    """Hash of each user's authorized_keys, so a planted key is visible."""
    keys: dict[str, Any] = {}
    for path in SSH_KEY_FILES:
        if os.path.exists(path):
            st = file_stat(path)
            keys[path] = st
    return {"ssh_keys": keys}


def collect_cron() -> dict[str, Any]:
    """Scheduled tasks: cron files and systemd timers."""
    entries: dict[str, Any] = {}
    for loc in CRON_LOCATIONS:
        if os.path.isfile(loc):
            st = file_stat(loc)
            if st:
                entries[loc] = st
        elif os.path.isdir(loc):
            names = _listdir(loc)
            if names:
                entries[loc] = names
    timers_out = _run(["systemctl", "list-timers", "--all", "--no-pager",
                       "--no-legend"])
    timers: list[str] = []
    for line in timers_out.splitlines():
        parts = line.split()
        if parts:
            timers.append(parts[-1])
    return {"cron": entries, "timers": sorted(set(timers))}


def _read_lines(path: str) -> list[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read().splitlines()
    except OSError:
        return []


# --------------------------------------------------------------------------
# aggregate
# --------------------------------------------------------------------------

COLLECTORS = {
    "services": collect_services,
    "ports": collect_ports,
    "files": collect_files,
    "executables": collect_executables,
    "users": collect_users,
    "ssh_keys": collect_ssh_keys,
    "cron": collect_cron,
}


def collect_all() -> dict[str, Any]:
    return {name: fn() for name, fn in COLLECTORS.items()}


def dump_state(state: dict[str, Any]) -> str:
    return json.dumps(state, indent=2, sort_keys=True, default=str)
