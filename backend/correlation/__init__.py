"""
CyberTrace Incident Correlation & Attack Graph Package (FR-4, FR-5, FR-6).
"""

from backend.correlation.attack_graph import (
    build_evidence_attack_graph,
    build_incident_timeline,
    evaluate_reach_next,
)
from backend.correlation.incident_correlator import (
    IncidentCorrelator,
    normalize_host,
    normalize_ip,
    normalize_user,
)
from backend.correlation.models import (
    GraphEdge,
    GraphNode,
    Incident,
    ReachNextAsset,
    TimelineEvent,
)

__all__ = [
    "Incident",
    "TimelineEvent",
    "ReachNextAsset",
    "GraphNode",
    "GraphEdge",
    "IncidentCorrelator",
    "build_evidence_attack_graph",
    "build_incident_timeline",
    "evaluate_reach_next",
    "normalize_host",
    "normalize_user",
    "normalize_ip",
]
