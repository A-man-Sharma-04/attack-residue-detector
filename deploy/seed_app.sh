#!/usr/bin/env bash
# seed_app.sh - write the CLEAN, TRUSTED demo application to the target.
#
# MUST run BEFORE `baseline create`, otherwise the baseline would record the
# app as an unknown new file and the compromise step would look like a no-op.
#
# Usage: ./deploy/seed_app.sh <user@host>
set -euo pipefail

TARGET="${1:?usage: seed_app.sh <user@host>}"
APP_PATH="/var/www/college/index.php"

read -r -d '' APP <<'PHP' || true
<?php
/**
 * College Portal - demo target application
 *
 * CLEAN, TRUSTED version. The baseline records this file's SHA-256.
 * During the compromise simulation this file is modified and the residue
 * detector must detect the hash change (ResidueType.FILE_MODIFIED).
 */
$page = 'Student Portal';
$build = '2026-09-29-clean';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title><?= htmlspecialchars($page) ?></title>
</head>
<body>
    <h1><?= htmlspecialchars($page) ?></h1>
    <p>Build: <?= htmlspecialchars($build) ?></p>
    <ul>
        <li><a href="/index.php">Home</a></li>
        <li><a href="/results.php">Results</a></li>
        <li><a href="/login.php">Login</a></li>
    </ul>
    <p id="status">ok</p>
</body>
</html>
PHP

echo "[seed] writing clean app to ${TARGET}:${APP_PATH}"
printf '%s\n' "$APP" | ssh -i "${SSH_KEY:-$HOME/Downloads/ssh-key-2026-09-02.key}" \
    -o BatchMode=yes "$TARGET" \
    "sudo mkdir -p /var/www/college && sudo tee ${APP_PATH} >/dev/null && sudo chmod 0644 ${APP_PATH}"

echo "[seed] sha256 on target:"
ssh -i "${SSH_KEY:-$HOME/Downloads/ssh-key-2026-09-02.key}" -o BatchMode=yes "$TARGET" \
    "sha256sum ${APP_PATH}; sudo chown root:root ${APP_PATH}"

echo "[seed] serving check:"
ssh -i "${SSH_KEY:-$HOME/Downloads/ssh-key-2026-09-02.key}" -o BatchMode=yes "$TARGET" \
    "curl -s -o /dev/null -w 'http_code=%{http_code} size=%{size_download}\\n' http://127.0.0.1:8081/index.php"
