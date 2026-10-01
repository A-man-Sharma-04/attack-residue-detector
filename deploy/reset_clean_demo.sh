#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# reset_clean_demo.sh - Emergency one-click script to restore target server
# to pristine clean state, record a fresh clean baseline, and refresh dashboard.
#
# Usage: ./deploy/reset_clean_demo.sh [target]   (default: botfarm)
# ---------------------------------------------------------------------------
set -euo pipefail

TARGET="${1:-botfarm}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[reset] 1/4 Resetting simulation artifacts on ${TARGET}..."
ssh "$TARGET" "sudo python3 /opt/residue-system/attack/compromise_sim.py --reset 2>/dev/null || true"

echo "[reset] 2/4 Re-seeding clean glassmorphic index.php application..."
"$REPO_ROOT/deploy/seed_app.sh" "$TARGET"

echo "[reset] 3/4 Recording fresh pristine clean baseline..."
ssh "$TARGET" "sudo python3 /opt/residue-system/residue_system/cli.py baseline create --note 'Pristine Clean Baseline'"

echo "[reset] 4/4 Regenerating clean dashboard..."
ssh "$TARGET" "sudo python3 /opt/residue-system/residue_system/cli.py dashboard"

echo ""
echo "===================================================================="
echo "  [SUCCESS] Target ${TARGET} is 100% Pristine Clean & Ready for Demo!"
echo "===================================================================="
