"""
Alert output schema for CyberTrace Detection Engine.

Defines the contract for all generated alerts, guaranteeing that every alert
is backed by concrete log evidence references (event_id, raw_file, byte_offset, record_length).

Phase 2.2 enhancements:
  - Added structured process metadata fields (process_name, process_id, parent_process_name, parent_process_id)
    to facilitate Phase 3 attack-path correlation.
  - Granular EvidenceReference schema retaining distinct actor, PID, and command-line per supporting event.
"""

from dataclasses import asdict, dataclass, field
import datetime
import json
from typing import Any, Optional
import uuid


ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "informational"}
ALLOWED_CONFIDENCES = {"high", "medium", "low"}
ALLOWED_STATUSES = {"new", "in_progress", "resolved", "false_positive"}


@dataclass
class EvidenceReference:
    """Provenance pointer to a raw log record with granular event-level attribution."""
    event_id: str
    raw_file: str
    byte_offset: int
    record_length: int
    timestamp: Optional[str] = None
    username: Optional[str] = None
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process_name: Optional[str] = None
    parent_process_id: Optional[int] = None
    process_command_line: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "event_id": self.event_id,
            "raw_file": self.raw_file,
            "byte_offset": int(self.byte_offset),
            "record_length": int(self.record_length),
        }
        if self.timestamp:
            d["timestamp"] = self.timestamp
        if self.username:
            d["username"] = self.username
        if self.process_name:
            d["process_name"] = self.process_name
        if self.process_id is not None:
            d["process_id"] = int(self.process_id)
        if self.parent_process_name:
            d["parent_process_name"] = self.parent_process_name
        if self.parent_process_id is not None:
            d["parent_process_id"] = int(self.parent_process_id)
        if self.process_command_line:
            d["process_command_line"] = self.process_command_line
        if self.source_ip:
            d["source_ip"] = self.source_ip
        if self.destination_ip:
            d["destination_ip"] = self.destination_ip
        if self.extra:
            d["extra"] = self.extra
        return d


@dataclass
class Alert:
    """
    Structured alert produced by the CyberTrace detection engine.
    Retains host, actor, network, and process telemetry for downstream correlation.
    """
    rule_id: str
    title: str
    description: str
    severity: str
    confidence: str
    mitre_technique_id: str
    mitre_technique_name: str
    mitre_tactic: str
    kill_chain_stage: str
    first_seen: str
    last_seen: str
    supporting_event_ids: list[str]
    evidence_references: list[dict[str, Any]]
    reasoning: str
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    host: Optional[str] = None
    username: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process_name: Optional[str] = None
    parent_process_id: Optional[int] = None
    status: str = "new"

    def __post_init__(self):
        # Validate severity
        self.severity = self.severity.lower()
        if self.severity not in ALLOWED_SEVERITIES:
            raise ValueError(
                f"Invalid severity '{self.severity}'. Must be one of {sorted(ALLOWED_SEVERITIES)}"
            )

        # Validate confidence
        self.confidence = self.confidence.lower()
        if self.confidence not in ALLOWED_CONFIDENCES:
            raise ValueError(
                f"Invalid confidence '{self.confidence}'. Must be one of {sorted(ALLOWED_CONFIDENCES)}"
            )

        # Validate status
        self.status = self.status.lower()
        if self.status not in ALLOWED_STATUSES:
            raise ValueError(
                f"Invalid status '{self.status}'. Must be one of {sorted(ALLOWED_STATUSES)}"
            )

        # Evidence guarantee: every alert must link to supporting events
        if not self.supporting_event_ids:
            raise ValueError("Alert must include at least one supporting event ID.")
        if not self.evidence_references:
            raise ValueError("Alert must include at least one evidence reference.")

        # Ensure evidence references have required provenance fields
        for ref in self.evidence_references:
            if not isinstance(ref, dict):
                raise TypeError(f"Evidence reference must be a dict, got {type(ref)}")
            for req_key in ("event_id", "raw_file", "byte_offset", "record_length"):
                if req_key not in ref:
                    raise ValueError(f"Evidence reference missing required key '{req_key}': {ref}")

    def to_dict(self) -> dict[str, Any]:
        """Convert alert to a pure JSON-serializable dictionary."""
        return asdict(self)

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serialize alert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Alert":
        """Deserialize an alert from dictionary."""
        d = dict(data)
        return cls(**d)
