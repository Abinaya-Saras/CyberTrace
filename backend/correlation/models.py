"""
Data models for CyberTrace Incident Correlation and Attack Graph (FR-4, FR-5, FR-6).

Guiding principles:
  - Every relationship and timeline step retains concrete log evidence provenance.
  - Distinguishes observed facts from inferred relationships.
  - Distinguishes observed network connectivity from confirmed access rights.
  - Purely JSON-serializable for simple API consumption.
"""

from dataclasses import asdict, dataclass, field
import json
from typing import Any, Optional


@dataclass
class TimelineEvent:
    """A chronologically ordered step in an incident's attack progression."""
    timestamp: str
    host: str
    action: str
    event_id: str
    raw_file: str
    byte_offset: int
    record_length: int
    user: Optional[str] = None
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process_name: Optional[str] = None
    parent_process_id: Optional[int] = None
    process_command_line: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_domain: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    kill_chain_stage: Optional[str] = None
    rule_id: Optional[str] = None
    description: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class ReachNextAsset:
    """
    Evidence-based next reachable asset reasoning (FR-6).

    Strict verification status values:
      - 'unverified_connectivity': Observed network traffic to destination, but authentication
        and administrative permissions are unverified.
      - 'authenticated_only': Confirmed successful authentication observed, but administrative
        privileges or access rights are unverified.
      - 'confirmed_access': Confirmed administrative execution or verified group membership.
    """
    target: str
    target_type: str  # 'ip', 'host', 'domain'
    from_host: str
    relationship: str  # 'observed_network_connection', 'successful_authentication', etc.
    verification_status: str  # 'unverified_connectivity', 'authenticated_only', 'confirmed_access'
    confidence: str  # 'high', 'medium', 'low'
    reasoning: str
    evidence_event_ids: list[str] = field(default_factory=list)
    evidence_references: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class GraphNode:
    """Node in the Evidence-Weighted Directed Attack Graph."""
    id: str
    node_type: str  # 'host', 'user', 'process', 'registry', 'file', 'network_dest', 'alert'
    label: str
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class GraphEdge:
    """
    Evidence-weighted directed edge in the attack graph.
    Every relationship retains full evidence provenance and inference status.
    """
    source: str
    target: str
    relationship_type: str
    weight: float  # 0.0 to 1.0 (evidence strength)
    is_observed: bool
    is_inferred: bool
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    supporting_event_ids: list[str] = field(default_factory=list)
    evidence_references: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Incident:
    """
    Correlated security incident (FR-4, FR-5, FR-6).
    Represents an evidence-backed cluster of detections and events.
    """
    incident_id: str
    title: str
    severity: str
    confidence: str
    first_seen: str
    last_seen: str
    hosts: list[str]
    users: list[str]
    alert_ids: list[str]
    alerts: list[dict[str, Any]]
    timeline: list[TimelineEvent] = field(default_factory=list)
    graph: dict[str, Any] = field(default_factory=lambda: {"nodes": [], "edges": []})
    reach_next: list[ReachNextAsset] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "hosts": self.hosts,
            "users": self.users,
            "alert_ids": self.alert_ids,
            "alerts": self.alerts,
            "timeline": [t.to_dict() for t in self.timeline],
            "graph": self.graph,
            "reach_next": [r.to_dict() for r in self.reach_next],
            "summary": self.summary,
        }

    def to_json(self, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)
