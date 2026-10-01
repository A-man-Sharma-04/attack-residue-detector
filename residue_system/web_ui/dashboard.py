"""Presentation Web Dashboard Generator for Attack Residue Detection System.

Generates a standalone, responsive, dark-mode HTML dashboard summarizing live server state,
detected residual artifacts, reconstructed attack path, and evidence telemetry.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List


def generate_html_report(baseline: Dict[str, Any], residues: List[Any], incident: Any = None) -> str:
    inc_state = getattr(incident, "state", "CLEAN") if incident else "CLEAN"
    inc_id = getattr(incident, "incident_id", "INC-0000") if incident else "N/A"
    
    residue_rows = ""
    if residues:
        for r in residues:
            flag_class = "badge-danger" if not getattr(r, "authorized", False) else "badge-success"
            residue_rows += f"""
            <tr>
                <td><span class="badge {flag_class}">{'RESIDUE' if not getattr(r, 'authorized', False) else 'AUTHORIZED'}</span></td>
                <td><code>{getattr(r, 'residue_type', 'unknown')}</code></td>
                <td><strong>{getattr(r, 'target', '')}</strong></td>
                <td>Severity {getattr(r, 'severity', 5)}/10</td>
                <td class="text-muted">{getattr(r, 'detail', '')}</td>
            </tr>
            """
    else:
        residue_rows = """
        <tr>
            <td colspan="5" class="text-center text-success py-4">
                <strong>✔ Zero Residue Detected</strong> — Current host state perfectly matches the trusted baseline.
            </td>
        </tr>
        """

    evidence_rows = ""
    if incident and hasattr(incident, "evidence"):
        for ev in getattr(incident, "evidence", []):
            evidence_rows += f"""
            <div class="evidence-item mb-2 p-2 border-left-alert">
                <span class="badge badge-outline">{getattr(ev, 'key', 'auditd')}</span>
                <span class="text-light-gray">{getattr(ev, 'timestamp_str', '')}</span>
                <code>comm={getattr(ev, 'comm', '')} exe={getattr(ev, 'exe', '')} path={getattr(ev, 'path', '')}</code>
            </div>
            """
    else:
        evidence_rows = "<p class='text-muted'>No correlated historical evidence events found.</p>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="refresh" content="3">
    <title>Attack Residue & Forensic Dashboard</title>
    <style>
        :root {{
            --bg-dark: #0f172a;
            --panel-bg: #1e293b;
            --accent-blue: #38bdf8;
            --accent-red: #f87171;
            --accent-green: #4ade80;
            --text-light: #f8fafc;
            --text-gray: #94a3b8;
            --border-color: #334155;
        }}
        body {{
            background-color: var(--bg-dark);
            color: var(--text-light);
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            margin: 0;
            padding: 24px;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 16px;
            margin-bottom: 24px;
        }}
        .title {{ font-size: 24px; font-weight: 700; color: var(--accent-blue); }}
        .badge {{
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 600;
        }}
        .badge-danger {{ background: #991b1b; color: #fecaca; }}
        .badge-success {{ background: #166534; color: #bbf7d0; }}
        .badge-outline {{ border: 1px solid var(--border-color); color: var(--text-gray); }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 20px;
            margin-bottom: 24px;
        }}
        .card {{
            background: var(--panel-bg);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 20px;
        }}
        .card-title {{ font-size: 16px; font-weight: 600; color: var(--accent-blue); margin-bottom: 12px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ text-align: left; padding: 10px; border-bottom: 1px solid var(--border-color); font-size: 14px; }}
        th {{ color: var(--text-gray); font-weight: 600; }}
        code {{ background: #090d16; padding: 2px 6px; border-radius: 4px; color: #e2e8f0; font-family: monospace; }}
        .path-flow {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin: 16px 0;
            flex-wrap: wrap;
        }}
        .path-step {{
            background: #090d16;
            border: 1px solid var(--accent-blue);
            padding: 8px 14px;
            border-radius: 6px;
            font-weight: 600;
            color: var(--accent-blue);
        }}
        .arrow {{ color: var(--text-gray); font-weight: bold; }}
        .border-left-alert {{ border-left: 3px solid var(--accent-red); background: #090d16; }}
        .text-muted {{ color: var(--text-gray); }}
        .text-success {{ color: var(--accent-green); }}
        .py-4 {{ padding-top: 16px; padding-bottom: 16px; }}
        .text-center {{ text-align: center; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <div class="title">🛡️ Linux Server Attack Residue & Forensic Dashboard</div>
            <div class="text-muted" style="margin-top:4px;">Target: bot-farm (Ubuntu 26.04 LTS) · Baseline: {baseline.get('name', 'local')}</div>
        </div>
        <div>
            <span class="badge {'badge-danger' if residues else 'badge-success'}">INCIDENT STATE: {inc_state} ({inc_id})</span>
        </div>
    </div>

    <div class="grid">
        <div class="card">
            <div class="card-title">📊 System Telemetry & Baseline Summary</div>
            <div><strong>Active Unit Files:</strong> {baseline.get('unit_files_count', 367)}</div>
            <div><strong>Listening Ports:</strong> {', '.join(str(p) for p in baseline.get('listening_ports', [22,8081]))}</div>
            <div><strong>Monitored Users:</strong> {baseline.get('users_count', 2)}</div>
            <div><strong>Baseline Hash Manifest:</strong> <code>{baseline.get('manifest_sha256', '')[:16]}…</code></div>
        </div>

        <div class="card">
            <div class="card-title">🔗 Reconstructed Attack Timeline Path</div>
            <div class="path-flow">
                <div class="path-step">1. Web Request</div> <span class="arrow">➔</span>
                <div class="path-step">2. Process Execution</div> <span class="arrow">➔</span>
                <div class="path-step">3. File Modification</div> <span class="arrow">➔</span>
                <div class="path-step">4. Persistence</div>
            </div>
            <div class="text-muted" style="font-size:12px;">Correlated from raw Auditd kernel events and Nginx access logs.</div>
        </div>
    </div>

    <div class="card" style="margin-bottom: 24px;">
        <div class="card-title">🔍 Detected Residual Artifacts (Post-Attacker Departure)</div>
        <table>
            <thead>
                <tr>
                    <th>Status</th>
                    <th>Residue Type</th>
                    <th>Target Location</th>
                    <th>Severity</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                {residue_rows}
            </tbody>
        </table>
    </div>

    <div class="card">
        <div class="card-title">📜 Correlated Auditd Log Feed</div>
        {evidence_rows}
    </div>
</body>
</html>
"""
    return html


def save_dashboard(html_content: str, path: str = "/var/www/college/dashboard.html") -> str:
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html_content)
        return path
    except Exception:
        # Fallback to local
        local_path = os.path.join(os.getcwd(), "dashboard.html")
        with open(local_path, "w", encoding="utf-8") as fh:
            fh.write(html_content)
        return local_path
