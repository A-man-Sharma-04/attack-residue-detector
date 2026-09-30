#!/usr/bin/env python3
"""Command line entry point for the residue detection system.

    python3 -m residue_system.cli baseline create
    python3 -m residue_system.cli baseline show
    python3 -m residue_system.cli residue scan
    python3 -m residue_system.cli forensic correlate
    python3 -m residue_system.cli response contain --apply
    python3 -m residue_system.cli response verify
    python3 -m residue_system.cli dashboard
    python3 -m residue_system.cli demo

Stdlib only by design: the target runs Python 3.14 and we install no wheels.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

if __package__ in (None, ""):  # allow running the file directly
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from residue_system.baseline import engine as baseline_mod
from residue_system.collectors import state as collectors
from residue_system.core.statemodel import Spec
from residue_system.evidence import auditlog_source
from residue_system.evidence import nginx_access
from residue_system.forensic import correlator as forensic
from residue_system.residue import detector
from residue_system.response import containment
from residue_system.web_ui import dashboard as web_dashboard

AUDIT_LOG = os.environ.get("RESIDUE_AUDIT_LOG", "/var/log/audit/audit.log")
ACCESS_LOG = os.environ.get("RESIDUE_ACCESS_LOG", "/var/log/nginx/college.access.log")
ARTIFACT_DIR = os.environ.get("RESIDUE_ARTIFACT_DIR", "/var/lib/residue-system/artifacts")


# --------------------------------------------------------------------------
def _save(name: str, payload: str) -> str:
    try:
        os.makedirs(ARTIFACT_DIR, exist_ok=True)
        path = os.path.join(ARTIFACT_DIR, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(payload)
        os.chmod(path, 0o600)
        return path
    except OSError as exc:
        print(f"[warn] could not save artifact {name}: {exc}", file=sys.stderr)
        return ""


def _stamp() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

def cmd_baseline(args: argparse.Namespace) -> int:
    if args.baseline_cmd == "create":
        doc = baseline_mod.create(args.name, note=args.note or "")
        print("[baseline] recorded trusted state")
        print(baseline_mod.describe(doc))
        path = _save(f"baseline-{args.name}-{_stamp()}.json",
                     json.dumps(doc, indent=2, sort_keys=True, default=str))
        if path:
            print(f"[baseline] artifact: {path}")
        return 0

    if args.baseline_cmd == "show":
        doc = baseline_mod.load(args.name)
        print(baseline_mod.describe(doc))
        print(f"[baseline] integrity: "
              f"{'OK' if baseline_mod.verify(doc) else 'TAMPERED'}")
        return 0

    if args.baseline_cmd == "verify":
        doc = baseline_mod.load(args.name)
        ok = baseline_mod.verify(doc)
        print(f"[baseline] manifest: "
              f"{'OK' if ok else 'MISMATCH - baseline may have been modified'}")
        return 0 if ok else 2

    return 1


def cmd_residue(args: argparse.Namespace) -> int:
    doc = baseline_mod.load(args.name)
    if not baseline_mod.verify(doc):
        print("[residue] WARNING baseline manifest mismatch", file=sys.stderr)

    residues = detector.scan(doc)

    if args.json:
        print(json.dumps([r.to_dict() for r in residues], indent=2,
                         sort_keys=True, default=str))
        return 0

    print("=" * 68)
    print(f"  RESIDUE SCAN  ({time.strftime('%Y-%m-%d %H:%M:%S')} UTC)")
    print("=" * 68)
    if not residues:
        print("  No residue detected. Current state matches the trusted baseline.")
        _save(f"residue-scan-{_stamp()}.txt",
              "No residue detected. Current state matches the trusted baseline.\n")
        return 0

    print(f"  {len(residues)} residue item(s) vs baseline '{args.name}' v{doc.get('version')}:\n")
    for r in residues:
        flag = "AUTHORIZED" if r.authorized else "RESIDUE"
        print(f"  [{flag}] {r.residue_type.value:<20} {r.target}")
        print(f"        severity {r.severity}/10  {r.detail}")
        if r.sha256_before and r.sha256_after:
            print(f"        sha256 {r.sha256_before[:16]}… -> {r.sha256_after[:16]}…")
        if r.owner or r.mode:
            print(f"        owner={r.owner or '?'} mode={r.mode or '?'}")
        print()

    path = _save(f"residue-scan-{_stamp()}.txt", _render_residues(residues))
    if path:
        print(f"[residue] artifact: {path}")
    return 0


def _render_residues(residues) -> str:
    out = [f"RESIDUE SCAN {time.strftime('%Y-%m-%d %H:%M:%S')} UTC",
           f"count={len(residues)}", ""]
    for r in residues:
        out.append(f"[{'AUTHORIZED' if r.authorized else 'RESIDUE'}] "
                   f"{r.residue_type.value} {r.target}")
        out.append(f"    severity={r.severity} {r.detail}")
        out.append(f"    before={r.sha256_before} after={r.sha256_after}")
        out.append("")
    return "\n".join(out)


def cmd_forensic(args: argparse.Namespace) -> int:
    doc = baseline_mod.load(args.name)
    residues = detector.scan(doc)

    if not os.path.exists(AUDIT_LOG):
        print(f"[forensic] no audit log at {AUDIT_LOG}", file=sys.stderr)
        return 2

    since = time.time() - Spec.LOOKBACK_HOURS * 3600
    events = auditlog_source.read_audit_log(AUDIT_LOG, since=since)
    web_events = nginx_access.parse_access_log(ACCESS_LOG, since=since)
    events = events + web_events
    n_audit, n_web = len(events) - len(web_events), len(web_events)

    inc = forensic.correlate(residues, events, incident_id=args.incident_id)

    if inc is None:
        print("=" * 68)
        print("  NO CORRELATED EVIDENCE")
        print("=" * 68)
        print(f"  {len(residues)} residue item(s), but none reached the promotion rule")
        return 0

    report = forensic.render(inc)
    print(report)
    print(f"\n[forensic] evidence sources: {n_audit} auditd events, {n_web} web requests")

    path_json = _save(f"incident-{inc.incident_id}-{_stamp()}.json",
                      json.dumps(inc.to_dict(), indent=2, sort_keys=True, default=str))
    path_txt = _save(f"incident-{inc.incident_id}-{_stamp()}.txt", report)
    return 0


def cmd_response(args: argparse.Namespace) -> int:
    doc = baseline_mod.load(args.name)
    residues = detector.scan(doc)

    if args.response_cmd == "contain":
        res = containment.contain_incident(residues, apply=args.apply)
        print("=" * 68)
        print(f"  INCIDENT RESPONSE CONTAINMENT ({res['mode']})")
        print("=" * 68)
        print(f"  Status: {res['status']}")
        for act in res["actions"]:
            print(f"  • {act}")
        if not res["actions"]:
            print("  • No active residue items require containment.")
        print()
        return 0

    if args.response_cmd == "verify":
        new_residues = [r for r in detector.scan(doc) if not r.authorized]
        print("=" * 68)
        print("  POST-CONTAINMENT RE-OBSERVATION VERIFICATION")
        print("=" * 68)
        if not new_residues:
            print("  STATUS: CONTAINED (Verified: 0 uncontained residue items remain)")
        else:
            print(f"  STATUS: UNCONTAINED ({len(new_residues)} uncontained items remain)")
        print()
        return 0

    return 1


def cmd_dashboard(args: argparse.Namespace) -> int:
    doc = baseline_mod.load(args.name)
    residues = detector.scan(doc)
    since = time.time() - Spec.LOOKBACK_HOURS * 3600
    events = auditlog_source.read_audit_log(AUDIT_LOG, since=since) if os.path.exists(AUDIT_LOG) else []
    web_events = nginx_access.parse_access_log(ACCESS_LOG, since=since)
    inc = forensic.correlate(residues, events + web_events)

    html = web_dashboard.generate_html_report(doc, residues, inc)
    target_path = args.output or "/var/www/college/dashboard.html"
    saved_path = web_dashboard.save_dashboard(html, target_path)

    print("=" * 68)
    print("  PRESENTATION WEB DASHBOARD GENERATED")
    print("=" * 68)
    print(f"  Dashboard File : {saved_path}")
    print(f"  Nginx URL      : http://127.0.0.1:8081/dashboard.html")
    print()
    return 0


def cmd_state(args: argparse.Namespace) -> int:
    print(collectors.dump_state(collectors.collect_all()))
    return 0


# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--name", default="local", help="baseline name (default: local)")

    p = argparse.ArgumentParser(
        prog="residue-system",
        description="Attack residue detection and forensic reconstruction")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("baseline", help="record/inspect trusted state", parents=[common])
    bsub = b.add_subparsers(dest="baseline_cmd", required=True)
    bc = bsub.add_parser("create"); bc.add_argument("--note", default="")
    bsub.add_parser("show")
    bsub.add_parser("verify")
    b.set_defaults(func=cmd_baseline)

    r = sub.add_parser("residue", help="detect attack residue", parents=[common])
    rsub = r.add_subparsers(dest="residue_cmd", required=True)
    rs = rsub.add_parser("scan"); rs.add_argument("--json", action="store_true")
    r.set_defaults(func=cmd_residue)

    f = sub.add_parser("forensic", help="reconstruct a past incident", parents=[common])
    fsub = f.add_subparsers(dest="forensic_cmd", required=True)
    fc = fsub.add_parser("correlate")
    fc.add_argument("--incident-id", default="INC-0001")
    fc.add_argument("--json", action="store_true")
    f.set_defaults(func=cmd_forensic)

    resp = sub.add_parser("response", help="incident response and containment", parents=[common])
    respsub = resp.add_subparsers(dest="response_cmd", required=True)
    rc = respsub.add_parser("contain")
    rc.add_argument("--apply", action="store_true", help="Apply containment actions")
    respsub.add_parser("verify")
    resp.set_defaults(func=cmd_response)

    dash = sub.add_parser("dashboard", help="generate presentation web dashboard", parents=[common])
    dash.add_argument("--output", default="", help="custom dashboard output path")
    dash.set_defaults(func=cmd_dashboard)

    s = sub.add_parser("state", help="dump current collected state (debug)")
    s.set_defaults(func=cmd_state)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
