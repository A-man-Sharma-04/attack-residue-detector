"""Forensic reconstruction: correlate present-day residue with past evidence.

Implements the promotion rule fixed by the project definition:

    A past incident is raised when an unexplained residue has at least
    MIN_RELATED_EVENTS (2) related historical security events within a
    CORRELATION_WINDOW_MINUTES (10) minute window, looked back over
    LOOKBACK_HOURS (24) hours.

Evidence comes from the raw audit log parsed by evidence.auditlog_source.
"""

from __future__ import annotations

import datetime as _dt
import time
from typing import Any, Iterable

from ..core.statemodel import (
    AttackStage,
    EvidenceEvent,
    Incident,
    IncidentState,
    Residue,
    ResidueType,
    Spec,
)

# Which audit keys are relevant to which residue type.
RESIDUE_AUDIT_KEYS: dict[ResidueType, tuple[str, ...]] = {
    ResidueType.NEW_SERVICE: ("service_changes",),
    ResidueType.NEW_CONTAINER: ("service_changes",),
    ResidueType.FILE_MODIFIED: ("web_changes",),
    ResidueType.FILE_CREATED: ("web_changes",),
    ResidueType.NEW_EXECUTABLE: ("opt_changes",),
    ResidueType.NEW_USER: ("identity_changes",),
    ResidueType.PERMISSION_CHANGE: ("identity_changes", "web_changes",
                                    "service_changes", "opt_changes"),
    ResidueType.NEW_SSH_KEY: ("ssh_keys",),
    ResidueType.NEW_SCHEDULED_TASK: ("cron_changes",),
    ResidueType.LOG_TAMPERING: ("log_changes",),
    ResidueType.NEW_PORT: (),          # no direct key; rely on process lineage
}

# Audit key -> attack stage, for building the ordered attack path.
KEY_TO_STAGE: dict[str, AttackStage] = {
    "web_changes": AttackStage.WEB_REQUEST,
    "opt_changes": AttackStage.PROCESS_EXECUTION,
    "process_execution": AttackStage.PROCESS_EXECUTION,
    "service_changes": AttackStage.PERSISTENCE,
    "ssh_keys": AttackStage.PERSISTENCE,
    "cron_changes": AttackStage.PERSISTENCE,
    "identity_changes": AttackStage.PRIVILEGE_ESCALATION,
    "authentication_changes": AttackStage.CREDENTIAL_ACCESS,
    "privilege_changes": AttackStage.PRIVILEGE_ESCALATION,
    "log_changes": AttackStage.DEFENSE_EVASION,
}


def _within_window(events: list[EvidenceEvent],
                   window_sec: int) -> list[list[EvidenceEvent]]:
    """Group events into clusters whose span is <= window_sec."""
    if not events:
        return []
    ordered = sorted(events, key=lambda e: e.timestamp)
    clusters: list[list[EvidenceEvent]] = [[ordered[0]]]
    for ev in ordered[1:]:
        if ev.timestamp - clusters[-1][0].timestamp <= window_sec:
            clusters[-1].append(ev)
        else:
            clusters.append([ev])
    return clusters


def related_events(residue: Residue,
                   events: Iterable[EvidenceEvent]) -> list[EvidenceEvent]:
    """Evidence plausibly responsible for a residue.

    Two independent ways to match, because either alone is weak:
      1. the audit key mapped to this residue type, and
      2. the event actually touched a path related to the residue target.
    """
    keys = RESIDUE_AUDIT_KEYS.get(residue.residue_type, ())
    target = residue.target
    parent = os.path.dirname(target) if "/" in target else ""
    stem = os.path.basename(target) if target else ""

    hits: list[EvidenceEvent] = []
    for ev in events:
        by_key = bool(keys) and ev.audit_key in keys
        by_path = False
        for name in ev.path_names():
            if not name:
                continue
            if name == target:
                by_path = True
                break
            if stem and stem in name and parent and parent in name:
                by_path = True
                break
            if parent and (name.startswith(parent.rstrip("/") + "/")):
                by_path = True
                break
        if by_key or by_path:
            hits.append(ev)
    return hits


def build_attack_path(events: list[EvidenceEvent]) -> list[AttackStage]:
    """Ordered, de-duplicated stage sequence for the demo's attack path."""
    stages: list[AttackStage] = []
    for ev in sorted(events, key=lambda e: e.timestamp):
        stage = KEY_TO_STAGE.get(ev.audit_key, AttackStage.UNKNOWN)
        if stage is AttackStage.UNKNOWN:
            continue
        if not stages or stages[-1] is not stage:
            stages.append(stage)
    return stages


def _classify(residue_count: int, max_window: int,
              evidence: list[EvidenceEvent]) -> IncidentState:
    """final_plan section 21: no evidence / possible / corroborated."""
    if not residue_count:
        return IncidentState.NONE
    # A residue with a tight, multi-event burst across more than one audit key
    # is stronger than a single unexplained change.
    distinct_keys = {e.audit_key for e in evidence if e.audit_key}
    if len(evidence) >= Spec.MIN_RELATED_EVENTS and len(distinct_keys) >= 2:
        return IncidentState.CORROBORATED
    return IncidentState.POSSIBLE


def correlate(residues: list[Residue],
              events: list[EvidenceEvent],
              incident_id: str = "INC-0001",
              now: float | None = None) -> Incident | None:
    """Build an Incident from residues + lookback evidence, or return None.

    Residues inside a maintenance window are not evidence of attack and are
    skipped entirely.
    """
    now = now or time.time()
    since = now - Spec.LOOKBACK_HOURS * 3600
    window_sec = Spec.CORRELATION_WINDOW_MINUTES * 60

    window_events = [e for e in events if e.timestamp >= since]
    actionable = [r for r in residues if not r.authorized]

    # --- per-residue: does it clear the promotion rule? ---
    promoted: list[tuple[Residue, list[EvidenceEvent]]] = []
    for r in actionable:
        rel = related_events(r, window_events)
        best: list[EvidenceEvent] = []
        for cluster in _within_window(rel, window_sec):
            if len(cluster) >= Spec.MIN_RELATED_EVENTS:
                best = cluster if len(cluster) > len(best) else best
        if best:
            promoted.append((r, best))

    if not promoted:
        return None

    # --- merge all promoted evidence into one incident ---
    all_rel: dict[str, EvidenceEvent] = {}
    for _r, cluster in promoted:
        for ev in cluster:
            all_rel[ev.event_id] = ev
    evidence = sorted(all_rel.values(), key=lambda e: e.timestamp)

    first = evidence[0].timestamp
    last = evidence[-1].timestamp
    residue_ts = min(r.detected_at for r, _ in promoted)

    state = _classify(len(promoted), window_sec, evidence)
    types = sorted({r.residue_type.value for r, _ in promoted})

    inc = Incident(
        incident_id=incident_id,
        state=state,
        title="Possible past compromise: " + ", ".join(types),
        residues=[r for r, _ in promoted],
        evidence=evidence,
        attack_path=build_attack_path(evidence),
        first_evidence_at=first,
        last_evidence_at=last,
        residue_detected_at=residue_ts,
        created_at=now,
    )
    return inc


def render(inc: Incident) -> str:
    """The report the demo prints."""
    lines: list[str] = []
    add = lines.append
    add("=" * 68)
    add(f"  PAST INCIDENT DETECTED  {inc.incident_id}")
    add("=" * 68)
    add(f"  Type                : {inc.title}")
    add(f"  State               : {inc.state.value.upper()}")
    add(f"  First evidence      : {_hm(inc.first_evidence_at)}")
    add(f"  Last evidence       : {_hm(inc.last_evidence_at)}")
    add(f"  Residue detected    : {_hm(inc.residue_detected_at)}")
    add(f"  Residues found      : {len(inc.residues)}")
    add(f"  Historical evidence : {len(inc.evidence)} events")
    add(f"  Attacker active now : "
        f"{'NO EVIDENCE OF LIVE ACTIVITY' if inc.last_evidence_at < inc.residue_detected_at else 'POSSIBLE'}")
    add("")
    add("  Residue artifacts:")
    for r in inc.residues:
        add(f"    [{r.residue_type.value:<20}] {r.target}")
        if r.sha256_before and r.sha256_after:
            add(f"        sha256 {r.sha256_before[:12]}… -> {r.sha256_after[:12]}…")
        add(f"        {r.detail}")
    add("")
    add("  Reconstructed attack path:")
    for i, stage in enumerate(inc.attack_path):
        arrow = "  v" if i < len(inc.attack_path) - 1 else ""
        add(f"    {i + 1}. {stage.value.replace('_', ' ').title()} {arrow}")
    add("")
    add("  Timeline (correlated evidence then residue):")
    for ts, kind, desc in inc.timeline():
        add(f"    {_hm(ts)}  [{kind:<8}] {desc}")
    add("")
    add("=" * 68)
    return "\n".join(lines)


def _hm(ts: float | None) -> str:
    if not ts:
        return "-"
    return _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc).strftime(
        "%H:%M:%S")


import os  # noqa: E402
