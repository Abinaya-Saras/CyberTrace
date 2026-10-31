"""
Relationship and Graph Schema for CyberTrace Correlation Engine.

Defines the explicit data contract for:
  - Multi-dimensional correlation relationships between security observations.
  - Typed graph nodes and edges for evidence graph construction.
  - Clear separation between observed factual overlap and inferred/hypothesized links.
"""

from dataclasses import asdict, dataclass, field
import json
from typing import Any, Optional
import uuid


# -----------------------------------------------------------------------------
# Canonical Constants and Enums
# -----------------------------------------------------------------------------

class RelationshipType:
    SAME_HOST = "SAME_HOST"
    SAME_USER = "SAME_USER"
    SAME_SOURCE_IP = "SAME_SOURCE_IP"
    SAME_DESTINATION_IP = "SAME_DESTINATION_IP"
    SAME_PROCESS = "SAME_PROCESS"
    SAME_PROCESS_IMAGE = "SAME_PROCESS_IMAGE"
    SAME_PROCESS_NAME = "SAME_PROCESS_IMAGE"  # Alias
    PARENT_CHILD_PROCESS = "PARENT_CHILD_PROCESS"
    TEMPORALLY_NEAR = "TEMPORALLY_NEAR"
    CROSS_SOURCE_NETWORK_MATCH = "CROSS_SOURCE_NETWORK_MATCH"
    POTENTIAL_BEHAVIORAL_SEQUENCE = "POTENTIAL_BEHAVIORAL_SEQUENCE"


class CorrelationDimension:
    HOST = "host"
    USER = "user"
    NETWORK = "network"
    PROCESS = "process"
    TEMPORAL = "temporal"
    CROSS_SOURCE = "cross_source"
    BEHAVIORAL = "behavioral"


class ConfidenceLevel:
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INSUFFICIENT = "INSUFFICIENT"


class ObservationStatus:
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    HYPOTHESIZED = "HYPOTHESIZED"


class NodeType:
    HOST = "host"
    USER = "user"
    IP_ADDRESS = "ip_address"
    PROCESS = "process"
    ALERT = "alert"
    EVENT = "event"


ALLOWED_RELATIONSHIP_TYPES = {
    RelationshipType.SAME_HOST,
    RelationshipType.SAME_USER,
    RelationshipType.SAME_SOURCE_IP,
    RelationshipType.SAME_DESTINATION_IP,
    RelationshipType.SAME_PROCESS,
    RelationshipType.SAME_PROCESS_IMAGE,
    RelationshipType.PARENT_CHILD_PROCESS,
    RelationshipType.TEMPORALLY_NEAR,
    RelationshipType.CROSS_SOURCE_NETWORK_MATCH,
    RelationshipType.POTENTIAL_BEHAVIORAL_SEQUENCE,
}

ALLOWED_CONFIDENCE_LEVELS = {
    ConfidenceLevel.HIGH,
    ConfidenceLevel.MEDIUM,
    ConfidenceLevel.LOW,
    ConfidenceLevel.INSUFFICIENT,
}

ALLOWED_OBSERVATION_STATUSES = {
    ObservationStatus.OBSERVED,
    ObservationStatus.INFERRED,
    ObservationStatus.HYPOTHESIZED,
}


# -----------------------------------------------------------------------------
# Relationship Model
# -----------------------------------------------------------------------------

@dataclass
class Relationship:
    """
    Explicit relationship between two security observations (alerts or events).
    Maintains full evidence, confidence rationale, provenance references,
    and investigation clustering eligibility.
    """
    source_observation_id: str
    target_observation_id: str
    relationship_type: str
    correlation_dimension: str
    evidence: dict[str, Any]
    confidence: str
    explanation: str
    observed_or_inferred: str
    timestamp_context: dict[str, Any]
    supporting_event_ids: list[str] = field(default_factory=list)
    provenance_references: list[dict[str, Any]] = field(default_factory=list)
    relationship_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    is_investigation_eligible: bool = True

    def __post_init__(self):
        # Validate relationship type
        if self.relationship_type not in ALLOWED_RELATIONSHIP_TYPES:
            raise ValueError(
                f"Invalid relationship_type '{self.relationship_type}'. Must be one of {sorted(ALLOWED_RELATIONSHIP_TYPES)}"
            )

        # Validate confidence level
        self.confidence = self.confidence.upper()
        if self.confidence not in ALLOWED_CONFIDENCE_LEVELS:
            raise ValueError(
                f"Invalid confidence '{self.confidence}'. Must be one of {sorted(ALLOWED_CONFIDENCE_LEVELS)}"
            )

        # Validate observation status
        self.observed_or_inferred = self.observed_or_inferred.upper()
        if self.observed_or_inferred not in ALLOWED_OBSERVATION_STATUSES:
            raise ValueError(
                f"Invalid observed_or_inferred '{self.observed_or_inferred}'. Must be one of {sorted(ALLOWED_OBSERVATION_STATUSES)}"
            )

        # Ensure evidence is a dictionary
        if not isinstance(self.evidence, dict):
            raise TypeError(f"evidence must be a dict, got {type(self.evidence)}")

        # Ensure explanation is present
        if not self.explanation or not self.explanation.strip():
            raise ValueError("Relationship explanation cannot be empty.")

    def to_dict(self) -> dict[str, Any]:
        """Convert relationship to serializable dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Relationship":
        """Deserialize relationship from dictionary."""
        d = dict(data)
        return cls(**d)


# -----------------------------------------------------------------------------
# Graph Node and Edge Models
# -----------------------------------------------------------------------------

@dataclass
class EntityNode:
    """A node in the evidence graph representing an entity or detection."""
    node_id: str
    node_type: str
    label: str
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RelationshipEdge:
    """A directed or undirected relationship edge between two nodes."""
    edge_id: str
    source_node_id: str
    target_node_id: str
    relationship_type: str
    confidence: str
    observed_or_inferred: str
    relationship_id: Optional[str] = None
    is_investigation_eligible: bool = True
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
