#!/usr/bin/env python3
"""Self-contained compromise SIMULATION for the residue detection demo.

THIS IS A SIMULATION. Nothing here is malicious code and nothing here is
exfiltrating anything. It plants four inert artefacts so the residue detector
has something real to find:

    1. a web request against the demo app          -> web / process evidence
    2. /opt/.cache/update                          -> unknown executable
    3. a modified /var/www/college/index.php       -> modified web file
    4. /etc/systemd/system/update-service.service  -> persistence unit

Safety choices, deliberate:
  * the dropped unit is NEVER enabled or started, so nothing executes
  * the dropped "executable" is an inert shell script that only echoes
  * every artefact is written with SIM_ markers or a self-identifying name so a
    real compromise can never be confused with the demo

Usage:
    sudo python3 attack/compromise_sim.py --app-url http://127.0.0.1:8081
    sudo python3 attack/compromise_sim.py --reset
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

APP_INDEX = "/var/www/college/index.php"
CACHE_DIR = "/opt/.cache"
CACHE_BIN = "/opt/.cache/update"
UNIT_PATH = "/etc/systemd/system/update-service.service"

# Appended to the clean app to simulate a dropped backdoor.
INJECTION = """
<?php /* SIMULATED BACKDOOR MARKER - residue detection demo, not real code */
if (isset($_GET['cmd'])) { echo "SIMULATED: " . $_GET['cmd']; }
?>
"""

UNIT_BODY = """# SIMULATED persistence artefact for the residue detection demo.
# Written by attack/compromise_sim.py. Never enabled, never started.
[Unit]
Description=SIM update service (residue detection demo artefact)
After=network.target

[Service]
Type=simple
ExecStart=/bin/sh -c 'while true; do sleep 3600; done'
Restart=always

[Install]
WantedBy=multi-user.target
"""

PAYLOAD_BODY = """#!/bin/sh
# SIMULATED attacker payload - inert placeholder, contains no exploit.
# Exists so the residue detector has an unknown executable to find in /opt.
echo "SIMULATED residue artefact - not functional malware"
exit 0
"""


def run(cmd: list[str], shell: bool = False) -> tuple[int, str]:
    try:
        res = subprocess.run(cmd, shell=shell, capture_output=True, text=True,
                             timeout=30, check=False)
        return res.returncode, (res.stdout + res.stderr).strip()
    except (subprocess.TimeoutExpired, OSError) as exc:
        return 1, str(exc)


def step(n: int, title: str) -> None:
    print(f"\n[{n}/4] {title}")
    print("-" * 68)


def do_attack(app_url: str) -> int:
    print("=" * 68)
    print("  CONTROLLED COMPROMISE SIMULATION")
    print("  Simulated attacker activity begins now.")
    print("=" * 68)

    # -- 1. web request -----------------------------------------------------
    step(1, "Access the web application (simulated attacker web request)")
    rc, out = run(["curl", "-s", "-o", "/dev/null", "-w",
                   "http_code=%{http_code} bytes=%{size_download}",
                   f"{app_url}/index.php"])
    print(f"  curl {app_url}/index.php")
    print(f"  -> {out or 'no response'} (rc={rc})")
    # a second, more suspicious request so the access log has a trail
    run(["curl", "-s", "-o", "/dev/null", f"{app_url}/index.php?cmd=id"])
    print("  -> requested /index.php?cmd=id (simulated C2 probe)")

    # -- 2. unknown executable ---------------------------------------------
    step(2, "Create unknown executable /opt/.cache/update")
    run(["mkdir", "-p", CACHE_DIR])
    with open(CACHE_BIN, "w", encoding="utf-8") as fh:
        fh.write(PAYLOAD_BODY)
    os.chmod(CACHE_BIN, 0o755)
    rc, _ = run(["ls", "-l", CACHE_BIN])
    print(f"  created {CACHE_BIN} (mode 0755)")
    print(f"  -> {out}")
    import hashlib
    with open(CACHE_BIN, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    print(f"  sha256 {digest}")

    # -- 3. modified web file ----------------------------------------------
    step(3, "Modify the clean web file /var/www/college/index.php")
    if not os.path.exists(APP_INDEX):
        print(f"  ERROR {APP_INDEX} missing - run deploy/seed_app.sh first")
        return 1
    with open(APP_INDEX, "r", encoding="utf-8") as fh:
        before = fh.read()
    import hashlib
    before_hash = hashlib.sha256(before.encode()).hexdigest()
    print(f"  before sha256 {before_hash}")
    with open(APP_INDEX, "a", encoding="utf-8") as fh:
        fh.write(INJECTION)
    with open(APP_INDEX, "r", encoding="utf-8") as fh:
        after = fh.read()
    after_hash = hashlib.sha256(after.encode()).hexdigest()
    print(f"  after  sha256 {after_hash}")
    print("  injected a clearly-marked SIMULATED backdoor block")

    # -- 4. persistence unit ----------------------------------------------
    step(4, "Create persistence unit /etc/systemd/system/update-service.service")
    with open(UNIT_PATH, "w", encoding="utf-8") as fh:
        fh.write(UNIT_BODY)
    os.chmod(UNIT_PATH, 0o644)
    print(f"  wrote {UNIT_PATH}")
    print("  NOTE: unit is NOT enabled and NOT started - it is residue only,")
    print("        which is exactly what the detector is meant to notice.")
    run(["systemctl", "daemon-reload"])

    print("\n" + "=" * 68)
    print("  SIMULATED ATTACK COMPLETE - all four actions finished.")
    print("  Attacker activity now goes quiet. Nothing remains running.")
    print("=" * 68)
    return 0


def do_reset() -> int:
    print("=" * 68)
    print("  RESET - removing simulated artefacts")
    print("=" * 68)

    if os.path.exists(UNIT_PATH):
        os.remove(UNIT_PATH)
        run(["systemctl", "daemon-reload"])
        print(f"  removed {UNIT_PATH}")
    else:
        print(f"  {UNIT_PATH} absent")

    if os.path.exists(CACHE_BIN):
        os.remove(CACHE_BIN)
        print(f"  removed {CACHE_BIN}")
    try:
        os.rmdir(CACHE_DIR)
        print(f"  removed {CACHE_DIR}")
    except OSError:
        pass

    if os.path.exists(APP_INDEX):
        with open(APP_INDEX, "r", encoding="utf-8") as fh:
            content = fh.read()
        marker = "<?php /* SIMULATED BACKDOOR MARKER"
        if marker in content:
            content = content[: content.index(marker)].rstrip() + "\n"
            with open(APP_INDEX, "w", encoding="utf-8") as fh:
                fh.write(content)
            print(f"  stripped injection from {APP_INDEX}")
        else:
            print(f"  {APP_INDEX} had no injection marker")

    print("\n  Reset complete. The residue scan should now report ZERO items.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--app-url", default="http://127.0.0.1:8081")
    ap.add_argument("--reset", action="store_true",
                    help="remove the simulated artefacts instead of planting them")
    ap.add_argument("--i-understand-this-plants-artifacts", action="store_true",
                    help="required acknowledgement: this writes files to the host")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("ERROR: must run as root (needs to write /opt and /etc/systemd)",
              file=sys.stderr)
        return 1

    if not args.reset and not args.i_understand_this_plants_artifacts:
        print("Refusing to run without explicit acknowledgement.", file=sys.stderr)
        print("Re-run with: --i-understand-this-plants-artifacts", file=sys.stderr)
        return 2

    t0 = time.time()
    rc = do_reset() if args.reset else do_attack(args.app_url)
    print(f"[timing] simulation wall time {time.time() - t0:.2f}s")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
