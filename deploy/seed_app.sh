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
 * College Portal - ABES Engineering College Demo Target Application
 *
 * CLEAN, TRUSTED version. The baseline records this file's SHA-256.
 * During the compromise simulation this file is modified and the residue
 * detector must detect the hash change (ResidueType.FILE_MODIFIED).
 */
$page = 'ABES Engineering College - Student Portal';
$build = '2026-09-29-clean';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($page) ?></title>
    <style>
        :root {
            --bg-color: #0f172a;
            --card-bg: rgba(30, 41, 59, 0.75);
            --border-color: rgba(255, 255, 255, 0.12);
            --accent-blue: #38bdf8;
            --accent-teal: #2dd4bf;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
        }
        body {
            background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%);
            color: var(--text-primary);
            font-family: system-ui, -apple-system, sans-serif;
            margin: 0;
            padding: 0;
            min-height: 100vh;
        }
        .navbar {
            background: rgba(15, 23, 42, 0.85);
            backdrop-filter: blur(12px);
            border-bottom: 1px solid var(--border-color);
            padding: 16px 32px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .brand {
            font-size: 20px;
            font-weight: 700;
            color: var(--accent-blue);
        }
        .nav-links {
            display: flex;
            gap: 20px;
        }
        .nav-links a {
            color: var(--text-secondary);
            text-decoration: none;
            font-weight: 500;
        }
        .nav-links a:hover { color: var(--accent-blue); }
        .container {
            max-width: 1000px;
            margin: 40px auto;
            padding: 0 24px;
        }
        .hero-card {
            background: var(--card-bg);
            backdrop-filter: blur(16px);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 32px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.4);
            margin-bottom: 32px;
        }
        .hero-title {
            font-size: 28px;
            font-weight: 700;
            margin-top: 0;
            margin-bottom: 8px;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
        }
        .card {
            background: var(--card-bg);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 24px;
        }
        .card-title {
            font-size: 18px;
            font-weight: 600;
            color: var(--accent-teal);
            margin-bottom: 8px;
        }
        .status-pill {
            display: inline-block;
            background: rgba(45, 212, 191, 0.15);
            color: #2dd4bf;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 600;
        }
    </style>
</head>
<body>
    <div class="navbar">
        <div class="brand">🎓 ABES Engineering College</div>
        <div class="nav-links">
            <a href="/index.php">Home</a>
            <a href="/dashboard.html">Forensic Dashboard</a>
        </div>
    </div>
    <div class="container">
        <div class="hero-card">
            <h1 class="hero-title">Student Academic & Telemetry Portal</h1>
            <p style="color: var(--text-secondary); margin-bottom: 20px;">Department of Computer Science & Engineering · AKTU Session 2026-27</p>
            <div>
                <span class="status-pill">● System Status: Operational</span>
                <span style="color: var(--text-secondary); font-size: 13px; margin-left: 12px;">Build: <?= htmlspecialchars($build) ?></span>
            </div>
        </div>
        <div class="grid">
            <div class="card">
                <div class="card-title">📚 Course Management</div>
                <p style="color: var(--text-secondary); font-size: 14px;">Access enrolled subjects, lecture schedules, and lab manuals.</p>
            </div>
            <div class="card">
                <div class="card-title">🔒 Host Security & Audit</div>
                <p style="color: var(--text-secondary); font-size: 14px;">Monitored by SHA256 baseline verification & real-time Auditd kernel telemetry.</p>
            </div>
        </div>
    </div>
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
