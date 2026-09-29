"""Core data model for the residue detection system.

Stdlib only, by design: the target runs Python 3.14 and we install no wheels.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import enum
from dataclasses import dataclass, field
from typing import Any


# --------------------------------------------------------------------------
# Residue taxonomy - final_plan section 17
# --------------------------------------------------------------------------

class ResidueType(str, enum.Enum):
    NEW_USER = "new_user"
    NEW_SSH_KEY = "new_ssh_key"
    NEW_SERVICE = "new_service"
    NEW_SCHEDULED_TASK = "new_scheduled_task"
    NEW_PORT = "new_port"
    NEW_PROCESS = "new_process"
    FILE_MODIFIED = "file_modified"
    FILE_CREATED = "file_created"
    PERMISSION_CHANGE = "permission_change"
    NEW_EXECUTABLE = "new_executable"
    NEW_CONTAINER = "new_container"
    CONTAINER_CHANGE = "container_change"
    PACKAGE_ADDED = "package_added"
    LOG_TAMPERING = "log_tampering"


class IncidentState(str, enum.Enum):
    """final_plan sections 21 and 34."""

    NONE = "none"
    POSSIBLE = "possible"
    CORROBORATED = "corroborated"
    CONTAINED = "contained"
    RESOLVED = "resolved"

    @classmethod
    def order(cls) -> list["IncidentState"]:
        return [
            cls.NONE,
            cls.POSSIBLE,
            cls.CORROBORATED,
            cls.CONTAINED,
            cls.RESOLVED,
        ]


class AttackStage(str, enum.Enum):
    """Stages used to build the attack path shown in the demo."""

    RECONNAISSANCE = "reconnaissance"
    WEB_REQUEST = "web_request"
    PROCESS_EXECUTION = "process_execution"
    FILE_MODIFICATION = "file_modification"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CREDENTIAL_ACCESS = "credential_access"
    DEFENSE_EVASION = "defense_evasion"
    LATERAL_MOVEMENT = "lateral_movement"
    EXFILTRATION = "exfiltration"
    UNKNOWN = "unknown"


# --------------------------------------------------------------------------
# Records
# --------------------------------------------------------------------------

@dataclass
class EvidenceEvent:
    """One audit/security event, normalised from a raw record.

    ``event_id`` is the audit serial (e.g. "1790662283.599:699"). It is the join
    key that stitches SYSCALL + PATH + EXECVE records of the same syscall into
    one event, which is what lets the correlator assert
    "process X created file Y at time T".
    """

    event_id: str
    timestamp: float
    event_type: str                       # SYSCALL / PATH / EXECVE / ...
    audit_key: str = ""                   # e.g. "web_changes"
    uid: int | None = None
    gid: int | None = None
    pid: int | None = None
    ppid: int | None = None
    comm: str = ""                        # process name
    exe: str = ""                         # full executable path
    syscall: str = ""
    success: bool = True
    paths: list[dict[str, Any]] = field(default_factory=list)
    argv: list[str] = field(default_factory=list)
    session: str = ""
    tty: str = ""
    raw: str = ""

    # -- classification helpers -------------------------------------------

    @property
    def dt(self) -> _dt.datetime:
        return _dt.datetime.fromtimestamp(self.timestamp, tz=_dt.timezone.utc)

    @property
    def primary_path(self) -> str:
        """The most meaningful path this event touched."""
        if not self.paths:
            return ""
        preferred = ("CREATE", "DELETE")
        for want in preferred:
            for p in self.paths:
                if p.get("nametype") == want:
                    return str(p.get("name", ""))
        return str(self.paths[0].get("name", ""))

    def path_names(self) -> list[str]:
        return [str(p.get("name", "")) for p in self.paths if p.get("name")]

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["dt"] = self.dt.isoformat()
        return d


@dataclass
class Residue:
    """An unexplained difference between current state and the trusted baseline.

    A residue is NOT proof of compromise (final_plan section 17). It only
    becomes meaningful once correlated with historical security events.
    """

    residue_id: str
    residue_type: ResidueType
    target: str                           # path, unit name, username, port...
    detail: str = ""
    severity: int = 5                     # 1..10
    detected_at: float = 0.0
    baseline_value: Any = None
    current_value: Any = None
    sha256_before: str = ""
    sha256_after: str = ""
    owner: str = ""
    mode: str = ""
    mtime: float | None = None
    authorized: bool = False              # inside a maintenance window?
    detector_version: str = "1.0.0"

    @property
    def dt(self) -> _dt.datetime:
        return _dt.datetime.fromtimestamp(self.detected_at, tz=_dt.timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["detected_at_iso"] = self.dt.isoformat()
        return d


@dataclass
class Incident:
    """A correlated past-incident hypothesis built from residue + history."""

    incident_id: str
    state: IncidentState = IncidentState.POSSIBLE
    title: str = ""
    residues: list[Residue] = field(default_factory=list)
    evidence: list[EvidenceEvent] = field(default_factory=list)
    attack_path: list[AttackStage] = field(default_factory=list)
    first_evidence_at: float | None = None
    last_evidence_at: float | None = None
    residue_detected_at: float | None = None
    created_at: float = 0.0
    actions_taken: list[str] = field(default_factory=list)
    verification: str = ""

    # -- timeline ----------------------------------------------------------

    @property
    def first_evidence_iso(self) -> str:
        return _iso(self.first_evidence_at)

    @property
    def last_evidence_iso(self) -> str:
        return _iso(self.last_evidence_at)

    @property
    def residue_detected_iso(self) -> str:
        return _iso(self.residue_detected_at)

    def timeline(self) -> list[tuple[float, str, str]]:
        """(timestamp, kind, description) sorted chronologically."""
        rows: list[tuple[float, str, str]] = []
        for e in self.evidence:
            rows.append((e.timestamp, "evidence", self._describe_evidence(e)))
        for r in self.residues:
            rows.append((r.detected_at, "residue",
                         f"{r.residue_type.value}: {r.target}"))
        for a in self.actions_taken:
            rows.append((self.created_at, "response", a))
        return sorted(rows, key=lambda r: r[0])

    @staticmethod
    def _describe_evidence(e: EvidenceEvent) -> str:
        bits = [e.audit_key or e.event_type]
        if e.comm:
            bits.append(f"comm={e.comm}")
        p = e.primary_path
        if p:
            bits.append(f"path={p}")
        return " ".join(bits)

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "state": self.state.value,
            "title": self.title,
            "created_at": self.created_at,
            "residues": [r.to_dict() for r in self.residues],
            "evidence": [e.to_dict() for e in self.evidence],
            "attack_path": [s.value for s in self.attack_path],
            "first_evidence_at": self.first_evidence_at,
            "last_evidence_at": self.last_evidence_at,
            "first_evidence_iso": self.first_evidence_iso,
            "last_evidence_iso": self.last_evidence_iso,
            "residue_detected_at": self.residue_detected_at,
            "residue_detected_iso": self.residue_detected_iso,
            "actions_taken": self.actions_taken,
            "verification": self.verification,
        }


def _iso(ts: float | None) -> str:
    if not ts:
        return "-"
    return _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc).isoformat()


# --------------------------------------------------------------------------
# Tunables - the numbers the project spec fixes
# --------------------------------------------------------------------------

class Spec:
    """Constants fixed by the project definition document."""

    SCAN_INTERVAL_SECONDS = 60
    LOOKBACK_HOURS = 24
    CORRELATION_WINDOW_MINUTES = 10
    MIN_RELATED_EVENTS = 2          # incident promotion rule
