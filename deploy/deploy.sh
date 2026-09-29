#!/usr/bin/env bash
# deploy.sh - push the detector code from this repo to the target host.
#
# The repo is the single source of truth. Nothing is edited on the target by
# hand; the target is a deployment destination, not a working copy.
#
# Usage: ./deploy/deploy.sh <user@host> [remote_dir]
set -euo pipefail

TARGET="${1:?usage: deploy.sh <user@host> [remote_dir]}"
REMOTE_DIR="${2:-/opt/residue-system}"
KEY="${SSH_KEY:-$HOME/Downloads/ssh-key-2026-09-02.key}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[deploy] repo    : $REPO_ROOT"
echo "[deploy] target  : $TARGET:$REMOTE_DIR"
echo "[deploy] commit  : $(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo 'not a git repo')"

echo "[deploy] syncing residue_system/"
rsync -az --delete \
    --exclude '__pycache__' \
    --exclude '*.pyc' \
    "$REPO_ROOT/residue_system/" "$TARGET:~/residue_system/"

echo "[deploy] syncing attack/ and deploy/"
rsync -az --delete --exclude '__pycache__' \
    "$REPO_ROOT/attack/" "$TARGET:~/attack/"
rsync -az --exclude '__pycache__' \
    "$REPO_ROOT/deploy/" "$TARGET:~/deploy/"

echo "[deploy] installing to ${REMOTE_DIR}"
ssh -i "$KEY" -o BatchMode=yes "$TARGET" "
    sudo mkdir -p '$REMOTE_DIR'
    sudo cp -r ~/residue_system '$REMOTE_DIR/' 2>/dev/null || true
    sudo cp -r ~/attack '$REMOTE_DIR/' 2>/dev/null || true
    sudo cp -r ~/deploy  '$REMOTE_DIR/' 2>/dev/null || true
    sudo chmod +x '$REMOTE_DIR'/deploy/*.sh '$REMOTE_DIR'/attack/*.py 2>/dev/null || true
    echo '[deploy] installed:'
    ls -1 '$REMOTE_DIR'
"

echo "[deploy] done"
