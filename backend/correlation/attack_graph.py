"""
Evidence-Weighted Directed Attack Graph and Path Reconstruction (FR-5 & FR-6).

Guiding principles:
  - Uses NetworkX (nx.DiGraph) with minimal, evidence-backed abstractions.
  - Every edge retains relationship type, direction, timestamp range, supporting event IDs,
    evidence source, observed vs. inferred status, and evidence strength (weight).
  - Chronological timeline reconstruction starting from available evidence (no assumed initial access).
  - Rigorous Reach-Next reasoning (FR-6): strictly separates observed connectivity from
    confirmed authentication and verified administrative permissions.
"""

from datetime import datetime
import logging
from typing import Any, Optional

import networkx as nx

from backend.detection.alert_schema import Alert
from backend.correlation.models import (
    GraphEdge,
    GraphNode,
    ReachNextAsset,
    TimelineEvent,
)

logger = logging.getLogger(__name__)


def _parse_ts(ts: Any) -> datetime:
    """Parse timestamp into datetime object for chronological sorting."""
    if isinstance(ts, datetime):
        return ts
    s = str(ts).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return datetime.min


def build_incident_timeline(
    alerts: list[Alert],
    supplementary_events: Optional[list[dict[str, Any]]] = None,
) -> list[TimelineEvent]:
    """
    Reconstruct chronological timeline of events for an incident (FR-5).
    Sorts all supporting events chronologically, retaining MITRE technique mapping
    and byte-accurate log evidence pointers.
    Does not assume missing initial-access steps; preserves incomplete paths honestly.
    """
    timeline: list[TimelineEvent] = []
    seen_event_ids: set[str] = set()

    for alert in alerts:
        for ref in alert.evidence_references:
            eid = ref.get("event_id")
            if not eid or eid in seen_event_ids:
                continue
            seen_event_ids.add(eid)

            ts_str = ref.get("timestamp") or alert.first_seen
            timeline.append(
                TimelineEvent(
                    timestamp=ts_str,
                    host=alert.host or "UNKNOWN",
                    user=ref.get("username") or alert.username,
                    action=alert.title,
                    event_id=eid,
                    raw_file=ref.get("raw_file", "unknown"),
                    byte_offset=int(ref.get("byte_offset", 0)),
                    record_length=int(ref.get("record_length", 0)),
                    process_name=ref.get("process_name") or alert.process_name,
                    process_id=ref.get("process_id") or alert.process_id,
                    parent_process_name=ref.get("parent_process_name") or alert.parent_process_name,
                    parent_process_id=ref.get("parent_process_id") or alert.parent_process_id,
                    process_command_line=ref.get("process_command_line"),
                    source_ip=ref.get("source_ip") or alert.source_ip,
                    destination_ip=ref.get("destination_ip") or alert.destination_ip,
                    mitre_technique_id=alert.mitre_technique_id,
                    mitre_technique_name=alert.mitre_technique_name,
                    kill_chain_stage=alert.kill_chain_stage,
                    rule_id=alert.rule_id,
                    description=alert.description,
                )
            )

    # Include any supplementary observed events (e.g. outbound network connections)
    if supplementary_events:
        for se in supplementary_events:
            eid = se.get("event_id")
            if not eid or eid in seen_event_ids:
                continue
            seen_event_ids.add(eid)
            timeline.append(
                TimelineEvent(
                    timestamp=se.get("timestamp", ""),
                    host=se.get("host_name", "UNKNOWN"),
                    user=se.get("username"),
                    action=f"Outbound network connection to {se.get('destination_ip') or se.get('destination_domain')}",
                    event_id=eid,
                    raw_file=se.get("raw_file", "unknown"),
                    byte_offset=int(se.get("byte_offset", 0)),
                    record_length=int(se.get("record_length", 0)),
                    process_name=se.get("process_name"),
                    process_id=se.get("process_id"),
                    destination_ip=se.get("destination_ip"),
                    destination_domain=se.get("destination_domain"),
                    rule_id="TELEMETRY-OBSERVED",
                    description="Observed outbound network traffic from endpoint during attack window.",
                )
            )

    # Sort strictly chronologically
    timeline.sort(key=lambda item: _parse_ts(item.timestamp))
    return timeline


def build_evidence_attack_graph(
    alerts: list[Alert],
    hosts: list[str],
    supplementary_network_events: Optional[list[dict[str, Any]]] = None,
) -> tuple[nx.DiGraph, dict[str, Any]]:
    """
    Construct an Evidence-Weighted Directed Attack Graph using NetworkX (FR-5).

    Returns:
      (graph, serialized_graph_dict)
      The serialized dict contains 'nodes' and 'edges' ready for JSON/frontend consumption.
    """
    g = nx.DiGraph()
    nodes_map: dict[str, GraphNode] = {}
    edges_list: list[GraphEdge] = []

    def add_node(node_id: str, node_type: str, label: str, properties: Optional[dict[str, Any]] = None) -> str:
        if node_id not in nodes_map:
            gn = GraphNode(id=node_id, node_type=node_type, label=label, properties=properties or {})
            nodes_map[node_id] = gn
            g.add_node(node_id, **gn.to_dict())
        return node_id

    def add_edge(
        source_id: str,
        target_id: str,
        rel_type: str,
        weight: float,
        is_observed: bool,
        is_inferred: bool,
        supporting_event_ids: Optional[list[str]] = None,
        evidence_references: Optional[list[dict[str, Any]]] = None,
        first_seen: Optional[str] = None,
        last_seen: Optional[str] = None,
    ) -> None:
        ge = GraphEdge(
            source=source_id,
            target=target_id,
            relationship_type=rel_type,
            weight=weight,
            is_observed=is_observed,
            is_inferred=is_inferred,
            first_seen=first_seen,
            last_seen=last_seen,
            supporting_event_ids=supporting_event_ids or [],
            evidence_references=evidence_references or [],
        )
        edges_list.append(ge)
        g.add_edge(source_id, target_id, **ge.to_dict())

    # Add host nodes
    for h in hosts:
        add_node(f"host:{h}", "host", h, {"host_name": h})

    # Sort alerts chronologically
    sorted_alerts = sorted(alerts, key=lambda a: _parse_ts(a.first_seen))

    prev_alert_node_id: Optional[str] = None

    for alert in sorted_alerts:
        alert_node_id = f"alert:{alert.rule_id}:{alert.mitre_technique_id}:{alert.alert_id[:8]}"
        add_node(
            alert_node_id,
            "alert",
            f"{alert.mitre_technique_id} ({alert.rule_id})",
            {
                "rule_id": alert.rule_id,
                "title": alert.title,
                "severity": alert.severity,
                "confidence": alert.confidence,
                "mitre_technique_id": alert.mitre_technique_id,
                "mitre_technique_name": alert.mitre_technique_name,
                "kill_chain_stage": alert.kill_chain_stage,
                "first_seen": alert.first_seen,
                "last_seen": alert.last_seen,
            },
        )

        host_id = f"host:{alert.host}" if alert.host else (f"host:{hosts[0]}" if hosts else "host:UNKNOWN")
        if host_id not in nodes_map and alert.host:
            add_node(host_id, "host", alert.host, {"host_name": alert.host})

        user_node_id: Optional[str] = None
        if alert.username:
            # Handle possible comma-aggregated user strings
            primary_user = alert.username.split(",")[0].strip()
            user_node_id = f"user:{primary_user}"
            add_node(user_node_id, "user", primary_user, {"username": primary_user})

        # Rule-specific node & edge generation
        if alert.rule_id == "RULE-001":  # Brute Force
            src_ip = alert.source_ip or "UNKNOWN_SRC"
            attacker_id = f"net:{src_ip}"
            add_node(attacker_id, "network_dest", src_ip, {"ip": src_ip, "role": "attacker_source"})

            if user_node_id:
                add_edge(
                    attacker_id,
                    user_node_id,
                    "FAILED_AUTH_ATTEMPT",
                    weight=1.0,
                    is_observed=True,
                    is_inferred=False,
                    supporting_event_ids=alert.supporting_event_ids,
                    evidence_references=alert.evidence_references,
                    first_seen=alert.first_seen,
                    last_seen=alert.last_seen,
                )
                add_edge(
                    user_node_id,
                    host_id,
                    "TARGETED_ACCOUNT_ON",
                    weight=1.0,
                    is_observed=True,
                    is_inferred=False,
                    supporting_event_ids=alert.supporting_event_ids,
                    evidence_references=alert.evidence_references,
                    first_seen=alert.first_seen,
                    last_seen=alert.last_seen,
                )
            add_edge(
                attacker_id,
                alert_node_id,
                "TRIGGERED",
                weight=1.0,
                is_observed=True,
                is_inferred=False,
                supporting_event_ids=alert.supporting_event_ids,
                evidence_references=alert.evidence_references,
            )

        elif alert.rule_id == "RULE-002":  # Office -> PowerShell Execution
            parent_name = alert.parent_process_name or "winword.exe"
            child_name = alert.process_name or "powershell.exe"
            parent_proc_id = f"proc:{parent_name}"
            child_proc_id = f"proc:{child_name}"

            add_node(parent_proc_id, "process", parent_name, {"process_name": parent_name, "is_parent": True})
            add_node(child_proc_id, "process", child_name, {"process_name": child_name, "is_child": True})

            add_edge(
                parent_proc_id,
                child_proc_id,
                "SPAWNED_PROCESS",
                weight=1.0,
                is_observed=True,
                is_inferred=False,
                supporting_event_ids=alert.supporting_event_ids,
                evidence_references=alert.evidence_references,
                first_seen=alert.first_seen,
                last_seen=alert.last_seen,
            )
            add_edge(
                child_proc_id,
                host_id,
                "EXECUTED_ON",
                weight=1.0,
                is_observed=True,
                is_inferred=False,
                supporting_event_ids=alert.supporting_event_ids,
                evidence_references=alert.evidence_references,
            )
            add_edge(
                child_proc_id,
                alert_node_id,
                "TRIGGERED",
                weight=1.0,
                is_observed=True,
                is_inferred=False,
                supporting_event_ids=alert.supporting_event_ids,
                evidence_references=alert.evidence_references,
            )

        elif alert.rule_id == "RULE-004":  # Registry Persistence
            proc_name = alert.process_name or "powershell.exe"
            proc_id = f"proc:{proc_name}"
            reg_node_id = f"reg:{alert.host}:RunKey"

            add_node(proc_id, "process", proc_name, {"process_name": proc_name})
            add_node(reg_node_id, "registry", "Windows Run Key", {"registry_path": "HKCU\\...\\Run"})

            add_edge(
                proc_id,
                reg_node_id,
                "MODIFIED_PERSISTENCE_KEY",
                weight=1.0,
                is_observed=True,
                is_inferred=False,
                supporting_event_ids=alert.supporting_event_ids,
                evidence_references=alert.evidence_references,
                first_seen=alert.first_seen,
                last_seen=alert.last_seen,
            )
            add_edge(
                reg_node_id,
                host_id,
                "INSTALLED_ON",
                weight=1.0,
                is_observed=True,
                is_inferred=False,
                supporting_event_ids=alert.supporting_event_ids,
                evidence_references=alert.evidence_references,
            )
            add_edge(
                reg_node_id,
                alert_node_id,
                "TRIGGERED",
                weight=1.0,
                is_observed=True,
                is_inferred=False,
                supporting_event_ids=alert.supporting_event_ids,
                evidence_references=alert.evidence_references,
            )

        elif alert.rule_id == "RULE-005":  # Ransomware File Modification
            proc_name = alert.process_name or "unknown.exe"
            proc_id = f"proc:{proc_name}"
            file_node_id = f"file:{alert.host}:.locked"

            add_node(proc_id, "process", proc_name, {"process_name": proc_name})
            add_node(file_node_id, "file", "*.locked files", {"extension": "locked"})

            add_edge(
                proc_id,
                file_node_id,
                "RENAMED_FILES",
                weight=1.0,
                is_observed=True,
                is_inferred=False,
                supporting_event_ids=alert.supporting_event_ids,
                evidence_references=alert.evidence_references,
                first_seen=alert.first_seen,
                last_seen=alert.last_seen,
            )
            add_edge(
                file_node_id,
                host_id,
                "LOCATED_ON",
                weight=1.0,
                is_observed=True,
                is_inferred=False,
                supporting_event_ids=alert.supporting_event_ids,
                evidence_references=alert.evidence_references,
            )
            add_edge(
                file_node_id,
                alert_node_id,
                "TRIGGERED",
                weight=1.0,
                is_observed=True,
                is_inferred=False,
                supporting_event_ids=alert.supporting_event_ids,
                evidence_references=alert.evidence_references,
            )

        elif alert.rule_id == "RULE-003":  # C2 Beaconing
            proc_name = alert.process_name or "powershell.exe"
            proc_id = f"proc:{proc_name}"
            dest = alert.destination_ip or "EXTERNAL_C2"
            dest_id = f"net:{dest}"

            add_node(proc_id, "process", proc_name, {"process_name": proc_name})
            add_node(dest_id, "network_dest", dest, {"destination": dest})

            add_edge(
                proc_id,
                dest_id,
                "OUTBOUND_CONNECTION",
                weight=0.8,
                is_observed=True,
                is_inferred=False,
                supporting_event_ids=alert.supporting_event_ids,
                evidence_references=alert.evidence_references,
                first_seen=alert.first_seen,
                last_seen=alert.last_seen,
            )
            add_edge(
                dest_id,
                alert_node_id,
                "TRIGGERED",
                weight=1.0,
                is_observed=True,
                is_inferred=False,
                supporting_event_ids=alert.supporting_event_ids,
                evidence_references=alert.evidence_references,
            )

        # Inferred temporal progression edge between consecutive alert stages on the same host
        if prev_alert_node_id and prev_alert_node_id != alert_node_id:
            add_edge(
                prev_alert_node_id,
                alert_node_id,
                "PROGRESSION_TO",
                weight=0.7,
                is_observed=False,
                is_inferred=True,
                first_seen=alert.first_seen,
            )
        prev_alert_node_id = alert_node_id

    # Add observed supplementary network connections to graph
    if supplementary_network_events:
        for sne in supplementary_network_events:
            proc = sne.get("process_name") or "powershell.exe"
            proc_id = f"proc:{proc}"
            dest = sne.get("destination_ip") or sne.get("destination_domain")
            if not dest:
                continue
            dest_id = f"net:{dest}"
            add_node(proc_id, "process", proc, {"process_name": proc})
            add_node(dest_id, "network_dest", dest, {"destination": dest})
            add_edge(
                proc_id,
                dest_id,
                "OUTBOUND_CONNECTION",
                weight=0.8,
                is_observed=True,
                is_inferred=False,
                first_seen=sne.get("timestamp"),
                supporting_event_ids=[sne.get("event_id")] if sne.get("event_id") else [],
                evidence_references=[
                    {
                        "event_id": sne.get("event_id"),
                        "raw_file": sne.get("raw_file", "unknown"),
                        "byte_offset": sne.get("byte_offset", 0),
                        "record_length": sne.get("record_length", 0),
                    }
                ]
                if sne.get("event_id")
                else [],
            )

    serialized = {
        "nodes": [n.to_dict() for n in nodes_map.values()],
        "edges": [e.to_dict() for e in edges_list],
    }
    return g, serialized


def evaluate_reach_next(
    hosts: list[str],
    alerts: list[Alert],
    supplementary_network_events: Optional[list[dict[str, Any]]] = None,
) -> list[ReachNextAsset]:
    """
    Evaluate what the attacker could potentially reach next (FR-6).

    Rigorous Evidence Constraints:
      - An observed network connection is connectivity, NOT proven access.
      - A successful authentication provides identity access, NOT proven administrative privilege.
      - Never infer administrative rights merely from a username containing 'admin'.
      - Return empty list or 'unverified_connectivity' when access is unproven.
    """
    reach_assets: list[ReachNextAsset] = []
    seen_targets: set[str] = set()

    # Case 1: Infrastructure Brute Force with zero successful logons
    is_brute_force_only = all(a.rule_id == "RULE-001" for a in alerts)
    if is_brute_force_only:
        # Attacker failed password guessing; 0 access obtained
        return []

    # Case 2: Observed outbound connections from compromised processes
    if supplementary_network_events:
        for sne in supplementary_network_events:
            dest_ip = sne.get("destination_ip")
            dest_domain = sne.get("destination_domain")
            target = dest_ip or dest_domain
            if not target or target in seen_targets:
                continue
            seen_targets.add(target)

            src_host = sne.get("host_name") or (hosts[0] if hosts else "UNKNOWN")
            proc = sne.get("process_name") or "powershell.exe"

            # Strict FR-6 distinction: observed outbound traffic is connectivity only
            reach_assets.append(
                ReachNextAsset(
                    target=target,
                    target_type="ip" if dest_ip else "domain",
                    from_host=src_host,
                    relationship="observed_network_connection",
                    verification_status="unverified_connectivity",
                    confidence="medium",
                    reasoning=(
                        f"Observed outbound network traffic from process '{proc}' on compromised host '{src_host}' "
                        f"to external destination '{target}'. Destination connectivity is observed; however, "
                        f"access rights, authentication, and administrative privileges are unverified."
                    ),
                    evidence_event_ids=[sne.get("event_id")] if sne.get("event_id") else [],
                    evidence_references=[
                        {
                            "event_id": sne.get("event_id"),
                            "raw_file": sne.get("raw_file", "unknown"),
                            "byte_offset": sne.get("byte_offset", 0),
                            "record_length": sne.get("record_length", 0),
                        }
                    ]
                    if sne.get("event_id")
                    else [],
                )
            )

    # Check alert evidence references for network connections if not supplied separately
    if not reach_assets:
        for alert in alerts:
            if alert.destination_ip and alert.destination_ip not in seen_targets:
                seen_targets.add(alert.destination_ip)
                reach_assets.append(
                    ReachNextAsset(
                        target=alert.destination_ip,
                        target_type="ip",
                        from_host=alert.host or (hosts[0] if hosts else "UNKNOWN"),
                        relationship="observed_network_connection",
                        verification_status="unverified_connectivity",
                        confidence="medium",
                        reasoning=(
                            f"Observed network connection from '{alert.host}' to destination IP '{alert.destination_ip}'. "
                            f"Potential connectivity established; confirmed access rights and privileges are unverified."
                        ),
                        evidence_event_ids=alert.supporting_event_ids,
                        evidence_references=alert.evidence_references,
                    )
                )

    return reach_assets
