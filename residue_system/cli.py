#!/usr/bin/env python3
"""Command line entry point for the residue detection system.

    python3 -m residue_system.cli baseline create
    python3 -m residue_system.cli baseline show
    python3 -m residue_system.cli residue scan
    python3 -m residue_system.cli forensic correlate
    python3 -m residue_system.cli forensic report

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
from residue_system.forensic import correlator as forensic
from residue_system.residue import detector

AUDIT_LOG = os.environ.get("RESIDUE_AUDIT_LOG", "/var/log/audit/audit.log")

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
    unauthorized = [r for r in residues if not r.authorized]

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

    print(f"  {len(residues)} residue item(s) vs baseline "
          f"'{args.name}' v{doc.get('version')}:\n")
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

    inc = forensic.correlate(residues, events, incident_id=args.incident_id)

    if inc is None:
        print("=" * 68)
        print("  NO CORRELATED EVIDENCE")
        print("=" * 68)
        print(f"  {len(residues)} residue item(s), but none reached the "
              f"promotion rule")
        print(f"  (>= {Spec.MIN_RELATED_EVENTS} related auditd events within "
              f"{Spec.CORRELATION_WINDOW_MINUTES} minutes, "
              f"lookback {Spec.LOOKBACK_HOURS}h)")
        return 0

    report = forensic.render(inc)
    print(report)

    path_json = _save(f"incident-{inc.incident_id}-{_stamp()}.json",
                      json.dumps(inc.to_dict(), indent=2, sort_keys=True,
                                 default=str))
    path_txt = _save(f"incident-{inc.incident_id}-{_stamp()}.txt", report)

    # Save the exact raw audit lines the report cites, so every claim in the
    # incident can be checked against the log independently.
    cited: list[str] = []
    for ev in inc.evidence:
        cited.extend(auditlog_source.events_for_serial(AUDIT_LOG, ev.event_id))
    cited_path = _save(f"incident-{inc.incident_id}-{_stamp()}-auditd-evidence.txt",
                       "\n".join(cited) + "\n")

    for p in (path_txt, path_json, cited_path):
        if p:
            print(f"[forensic] artifact: {p}")
    return 0


def cmd_state(args: argparse.Namespace) -> int:
    print(collectors.dump_state(collectors.collect_all()))
    return 0


# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="residue-system",
        description="Attack residue detection and forensic reconstruction")
    p.add_argument("--baseline-name", default="local",
                   help="baseline name (default: local)")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("baseline", help="record/inspect the trusted state")
    bsub = b.add_subparsers(dest="baseline_cmd", required=True)
    bc = bsub.add_parser("create"); bc.add_argument("--note", default="")
    bsub.add_parser("show")
    bsub.add_parser("verify")
    b.set_defaults(func=cmd_baseline)

    r = sub.add_parser("residue", help="detect attack residue")
    rsub = r.add_subparsers(dest="residue_cmd", required=True)
    rs = rsub.add_parser("scan"); rs.add_argument("--json", action="store_true")
    r.set_defaults(func=cmd_residue)

    f = sub.add_parser("forensic", help="reconstruct a past incident")
    fsub = f.add_subparsers(dest="forensic_cmd", required=True)
    fc = fsub.add_parser("correlate")
    fc.add_argument("--incident-id", default="INC-0001")
    fc.add_argument("--json", action="store_true")
    f.set_defaults(func=cmd_forensic)

    s = sub.add_parser("state", help="dump current collected state (debug)")
    s.set_defaults(func=cmd_state)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
