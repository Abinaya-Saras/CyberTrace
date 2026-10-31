"""
CyberTrace Correlation Engine Package.

Provides evidence-based cross-entity correlation across hosts, users,
network addresses, processes, timestamps, and log sources.
"""

from backend.correlation.confidence import (
    IPClassification,
    classify_ip,
    evaluate_confidence,
    is_test_net_ip,
)
from backend.correlation.correlation_engine import CorrelationEngine
from backend.correlation.correlation_rules import (
    BehavioralSequenceCorrelator,
    CrossSourceCorrelator,
    HostCorrelator,
    NetworkCorrelator,
    ProcessCorrelator,
    TemporalCorrelator,
    UserCorrelator,
)
from backend.correlation.entity_extractor import EntityExtractor
from backend.correlation.graph_builder import EvidenceGraph, GraphBuilder
from backend.correlation.relationship_schema import (
    ConfidenceLevel,
    CorrelationDimension,
    EntityNode,
    NodeType,
    ObservationStatus,
    Relationship,
    RelationshipEdge,
    RelationshipType,
)

__all__ = [
    "CorrelationEngine",
    "EntityExtractor",
    "GraphBuilder",
    "EvidenceGraph",
    "Relationship",
    "EntityNode",
    "RelationshipEdge",
    "RelationshipType",
    "CorrelationDimension",
    "ConfidenceLevel",
    "ObservationStatus",
    "NodeType",
    "classify_ip",
    "is_test_net_ip",
    "evaluate_confidence",
    "IPClassification",
    "HostCorrelator",
    "UserCorrelator",
    "NetworkCorrelator",
    "ProcessCorrelator",
    "TemporalCorrelator",
    "BehavioralSequenceCorrelator",
    "CrossSourceCorrelator",
]
