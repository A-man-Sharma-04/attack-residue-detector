#!/usr/bin/env bash
# deploy.sh - push the detector code from this repo to the target host.
#
# The repo is the single source of truth. Nothing is edited on the target by
# hand; the target is a deployment destination, not a working copy.
#
# Uses ONE ssh connection (tar over stdin) rather than rsync + a second ssh.
# bot-farm runs fail2ban and each extra connection multiplies the chance of
# tripping a ban mid-workflow. One connection, one auth, one session.
#
# Usage: ./deploy/deploy.sh [target]      (default: botfarm, see ~/.ssh/config)
set -euo pipefail

TARGET="${1:-botfarm}"
REMOTE_DIR="${2:-/opt/residue-system}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SSH_OPTS=(-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=30)

COMMIT="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo 'n/a')"

echo "[deploy] repo         : $REPO_ROOT"
echo "[deploy] commit       : $COMMIT"
echo "[deploy] target       : $TARGET -> $REMOTE_DIR"

# --- single connection: stream a tarball over stdin -----------------------
tar -C "$REPO_ROOT" \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    -czf - residue_system attack deploy \
  | ssh "${SSH_OPTS[@]}" "$TARGET" "sudo tar -xzf - -C '$REMOTE_DIR' 2>/dev/null || { sudo mkdir -p '$REMOTE_DIR' && sudo tar -xzf - -C '$REMOTE_DIR'; }; sudo chmod +x '$REMOTE_DIR'/deploy/*.sh '$REMOTE_DIR'/attack/*.py 2>/dev/null; true"

echo "[deploy] installing stamp"
ssh "${SSH_OPTS[@]}" "$TARGET" "
    echo '$COMMIT' | sudo tee '$REMOTE_DIR/.deployed_commit' >/dev/null
    sudo chmod 0644 '$REMOTE_DIR/.deployed_commit'
    ls -1 '$REMOTE_DIR'
"

echo "[deploy] done (commit $COMMIT)"
