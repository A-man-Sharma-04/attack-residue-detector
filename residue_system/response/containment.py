"""Containment & Evidence Preservation Engine for Attack Residue System.

Stdlib-only implementation for Linux host containment and evidence vaulting.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import time
from typing import Any, Dict, List

QUARANTINE_DIR = os.environ.get("RESIDUE_QUARANTINE_DIR", "/var/lib/residue-system/quarantine")
EVIDENCE_VAULT = os.environ.get("RESIDUE_EVIDENCE_VAULT", "/var/lib/residue-system/vault")


def contain_incident(residue_items: List[Any], apply: bool = False) -> Dict[str, Any]:
    """Applies graduated containment to detected residual artifacts."""
    actions_taken = []
    quarantined_files = []

    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    os.makedirs(EVIDENCE_VAULT, exist_ok=True)

    for item in residue_items:
        target = getattr(item, "target", "")
        res_type = str(getattr(item, "residue_type", ""))

        if "new_executable" in res_type or "/opt/.cache" in target:
            if os.path.exists(target):
                vault_path = os.path.join(QUARANTINE_DIR, os.path.basename(target) + f".quarantine_{int(time.time())}")
                if apply:
                    shutil.move(target, vault_path)
                    actions_taken.append(f"Quarantined executable {target} -> {vault_path}")
                    quarantined_files.append(vault_path)
                else:
                    actions_taken.append(f"[DRY-RUN] Would quarantine executable {target}")
            
            # Clean empty staging folder
            staging_dir = os.path.dirname(target)
            if apply and os.path.exists(staging_dir) and staging_dir.startswith("/opt/") and not os.listdir(staging_dir):
                try:
                    os.rmdir(staging_dir)
                    actions_taken.append(f"Removed empty staging directory {staging_dir}")
                except Exception:
                    pass

        elif "new_service" in res_type or "/etc/systemd/system" in target:
            if os.path.exists(target):
                vault_path = os.path.join(QUARANTINE_DIR, os.path.basename(target) + f".service_vault_{int(time.time())}")
                if apply:
                    shutil.move(target, vault_path)
                    os.system("systemctl daemon-reload >/dev/null 2>&1 || true")
                    actions_taken.append(f"Disabled and removed persistence service {target}")
                else:
                    actions_taken.append(f"[DRY-RUN] Would remove persistence unit {target}")

        elif "file_modified" in res_type or "/var/www" in target:
            if os.path.exists(target):
                vault_path = os.path.join(EVIDENCE_VAULT, os.path.basename(target) + f".modified_copy_{int(time.time())}")
                if apply:
                    shutil.copy2(target, vault_path)
                    # Strip injected backdoor block and restore clean ending
                    with open(target, "r", encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                    if "SIMULATED" in content or "backdoor" in content:
                        clean_content = content.split("<?php /* SIMULATED")[0].split("<?php /*backdoor")[0].rstrip() + "\n"
                        with open(target, "w", encoding="utf-8") as fh:
                            fh.write(clean_content)
                        actions_taken.append(f"Neutralized injection in {target} (evidence copy saved to {vault_path})")
                    else:
                        actions_taken.append(f"Preserved modified web file evidence {target} -> {vault_path}")
                else:
                    actions_taken.append(f"[DRY-RUN] Would preserve and sanitize web file {target}")

    result = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "mode": "APPLIED" if apply else "DRY_RUN",
        "status": "CONTAINED" if apply else "PROPOSED",
        "actions": actions_taken,
        "quarantine_dir": QUARANTINE_DIR,
        "vault_dir": EVIDENCE_VAULT
    }

    manifest_path = os.path.join(EVIDENCE_VAULT, f"containment_manifest_{int(time.time())}.json")
    if apply:
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)

    return result
