"""
Evidence-Weighted Directed Attack Graph and Path Reconstruction (FR-5 & FR-6).

Guiding principles:
  - Uses NetworkX (nx.DiGraph) enforcing strict Directed Acyclic Graph (DAG) topology.
  - Process Node Identity: process instances are uniquely identified by (host, process_name, PID).
    Distinct process executions with different PIDs are never falsely merged.
  - Granular Evidence Integrity: every edge retains relationship type, direction, timestamp range,
    supporting event IDs, evidence references, observed vs. inferred status, and weight.
  - Strict Reach-Next Semantics (FR-6): separates observed external outbound destinations from
    internal target reachability and verified administrative permissions.
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


def _get_process_node_id(host: str, proc_name: str, pid: Optional[Any], event_id: Optional[str] = None) -> str:
    """
    Construct unique process node ID incorporating host, executable name, and PID.
    Different process executions with different PIDs never merge into one node.
    If PID is missing, event_id is used to isolate the process execution instance.
    """
    h_str = host or "UNKNOWN"
    p_str = (proc_name or "unknown.exe").lower()
    if pid is not None and str(pid).isdigit():
        return f"proc:{h_str}:{p_str}:{pid}"
    elif event_id:
        return f"proc:{h_str}:{p_str}:evt_{event_id[:8]}"
    else:
        return f"proc:{h_str}:{p_str}:unspecified"


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

    # Sort strictly chronologically and cap to prevent browser DOM exhaustion
    timeline.sort(key=lambda item: _parse_ts(item.timestamp))
    return timeline[:500]


def build_evidence_attack_graph(
    alerts: list[Alert],
    hosts: list[str],
    supplementary_network_events: Optional[list[dict[str, Any]]] = None,
) -> tuple[nx.DiGraph, dict[str, Any]]:
    """
    Construct an Evidence-Weighted Directed Attack Graph using NetworkX (FR-5).
    Guarantees Directed Acyclic Graph (DAG) topology.
    Distinguishes observed facts from inferred temporal stage progression.
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
        if source_id == target_id:
            return  # Prevent self-loops
        # Avoid duplicate edges
        if g.has_edge(source_id, target_id):
            return

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

    # Sort alerts chronologically and cap to top 20 for graph clarity and performance
    sorted_alerts = sorted(alerts, key=lambda a: _parse_ts(a.first_seen))
    if len(sorted_alerts) > 20:
        sorted_alerts = sorted_alerts[:20]
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

        host_str = alert.host or (hosts[0] if hosts else "UNKNOWN")
        host_id = f"host:{host_str}"
        if host_id not in nodes_map and alert.host:
            add_node(host_id, "host", alert.host, {"host_name": alert.host})

        user_node_id: Optional[str] = None
        if alert.username:
            primary_user = alert.username.split(",")[0].strip()
            user_node_id = f"user:{primary_user}"
            add_node(user_node_id, "user", primary_user, {"username": primary_user})

        # Process-level node and edge building preserving PID instances
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
                "TRIGGERED_DETECTION",
                weight=1.0,
                is_observed=True,
                is_inferred=False,
                supporting_event_ids=alert.supporting_event_ids,
                evidence_references=alert.evidence_references,
            )

        elif alert.rule_id == "RULE-002":  # Office -> PowerShell Execution
            # Process each individual execution in evidence_references to preserve distinct PIDs
            for ref in alert.evidence_references:
                parent_name = ref.get("parent_process_name") or alert.parent_process_name or "winword.exe"
                child_name = ref.get("process_name") or alert.process_name or "powershell.exe"
                pid = ref.get("process_id")
                ppid = ref.get("parent_process_id")
                eid = ref.get("event_id")

                parent_proc_id = _get_process_node_id(host_str, parent_name, ppid, eid)
                child_proc_id = _get_process_node_id(host_str, child_name, pid, eid)

                p_label = f"{parent_name} (PID: {ppid})" if ppid is not None else parent_name
                c_label = f"{child_name} (PID: {pid})" if pid is not None else child_name

                add_node(parent_proc_id, "process", p_label, {"process_name": parent_name, "process_id": ppid, "is_parent": True})
                add_node(child_proc_id, "process", c_label, {"process_name": child_name, "process_id": pid, "is_child": True})

                add_edge(
                    parent_proc_id,
                    child_proc_id,
                    "SPAWNED_PROCESS",
                    weight=1.0,
                    is_observed=True,
                    is_inferred=False,
                    supporting_event_ids=[eid] if eid else alert.supporting_event_ids,
                    evidence_references=[ref],
                    first_seen=ref.get("timestamp") or alert.first_seen,
                    last_seen=ref.get("timestamp") or alert.last_seen,
                )
                add_edge(
                    child_proc_id,
                    host_id,
                    "EXECUTED_ON",
                    weight=1.0,
                    is_observed=True,
                    is_inferred=False,
                    supporting_event_ids=[eid] if eid else alert.supporting_event_ids,
                    evidence_references=[ref],
                )
                add_edge(
                    child_proc_id,
                    alert_node_id,
                    "TRIGGERED_DETECTION",
                    weight=1.0,
                    is_observed=True,
                    is_inferred=False,
                    supporting_event_ids=[eid] if eid else alert.supporting_event_ids,
                    evidence_references=[ref],
                )

        elif alert.rule_id == "RULE-004":  # Registry Persistence
            for ref in alert.evidence_references:
                proc_name = ref.get("process_name") or alert.process_name or "powershell.exe"
                pid = ref.get("process_id")
                eid = ref.get("event_id")

                proc_id = _get_process_node_id(host_str, proc_name, pid, eid)
                p_label = f"{proc_name} (PID: {pid})" if pid is not None else proc_name
                reg_node_id = f"reg:{host_str}:RunKey"

                add_node(proc_id, "process", p_label, {"process_name": proc_name, "process_id": pid})
                add_node(reg_node_id, "registry", "Windows Run Key", {"registry_path": "HKCU\\...\\Run"})

                add_edge(
                    proc_id,
                    reg_node_id,
                    "MODIFIED_PERSISTENCE_KEY",
                    weight=1.0,
                    is_observed=True,
                    is_inferred=False,
                    supporting_event_ids=[eid] if eid else alert.supporting_event_ids,
                    evidence_references=[ref],
                    first_seen=ref.get("timestamp") or alert.first_seen,
                )
                add_edge(
                    reg_node_id,
                    host_id,
                    "INSTALLED_ON",
                    weight=1.0,
                    is_observed=True,
                    is_inferred=False,
                    supporting_event_ids=[eid] if eid else alert.supporting_event_ids,
                    evidence_references=[ref],
                )
                add_edge(
                    reg_node_id,
                    alert_node_id,
                    "TRIGGERED_DETECTION",
                    weight=1.0,
                    is_observed=True,
                    is_inferred=False,
                    supporting_event_ids=[eid] if eid else alert.supporting_event_ids,
                    evidence_references=[ref],
                )

        elif alert.rule_id == "RULE-005":  # Ransomware File Modification
            for ref in alert.evidence_references:
                proc_name = ref.get("process_name") or alert.process_name or "unknown.exe"
                pid = ref.get("process_id")
                eid = ref.get("event_id")

                proc_id = _get_process_node_id(host_str, proc_name, pid, eid)
                p_label = f"{proc_name} (PID: {pid})" if pid is not None else proc_name
                file_node_id = f"file:{host_str}:.locked"

                add_node(proc_id, "process", p_label, {"process_name": proc_name, "process_id": pid})
                add_node(file_node_id, "file", "*.locked files", {"extension": "locked"})

                add_edge(
                    proc_id,
                    file_node_id,
                    "RENAMED_FILES",
                    weight=1.0,
                    is_observed=True,
                    is_inferred=False,
                    supporting_event_ids=[eid] if eid else alert.supporting_event_ids,
                    evidence_references=[ref],
                    first_seen=ref.get("timestamp") or alert.first_seen,
                )
                add_edge(
                    file_node_id,
                    host_id,
                    "LOCATED_ON",
                    weight=1.0,
                    is_observed=True,
                    is_inferred=False,
                    supporting_event_ids=[eid] if eid else alert.supporting_event_ids,
                    evidence_references=[ref],
                )
                add_edge(
                    file_node_id,
                    alert_node_id,
                    "TRIGGERED_DETECTION",
                    weight=1.0,
                    is_observed=True,
                    is_inferred=False,
                    supporting_event_ids=[eid] if eid else alert.supporting_event_ids,
                    evidence_references=[ref],
                )

        # Inferred temporal progression edge between consecutive alert stages
        if prev_alert_node_id and prev_alert_node_id != alert_node_id:
            add_edge(
                prev_alert_node_id,
                alert_node_id,
                "INFERRED_STAGE_PROGRESSION",
                weight=0.7,
                is_observed=False,
                is_inferred=True,
                first_seen=alert.first_seen,
                supporting_event_ids=alert.supporting_event_ids,
            )
        prev_alert_node_id = alert_node_id

    # Add observed supplementary network connections to graph
    if supplementary_network_events:
        for sne in supplementary_network_events:
            proc = sne.get("process_name") or "powershell.exe"
            pid = sne.get("process_id")
            eid = sne.get("event_id")
            host_str = sne.get("host_name") or (hosts[0] if hosts else "UNKNOWN")

            proc_id = _get_process_node_id(host_str, proc, pid, eid)
            p_label = f"{proc} (PID: {pid})" if pid is not None else proc

            dest = sne.get("destination_ip") or sne.get("destination_domain")
import ipaddress

def _is_documentation_ip_or_domain(target: str) -> bool:
    """Check if target IP or domain is in RFC 5737 / documentation / example range."""
    if not target:
        return False
    t_lower = target.lower().strip()
    if any(t_lower.endswith(tld) for tld in (".test", ".example", ".invalid", ".localhost")):
        return True
    try:
        ip = ipaddress.ip_address(target.strip())
        test_net_1 = ipaddress.ip_network("192.0.2.0/24")
        test_net_2 = ipaddress.ip_network("198.51.100.0/24")
        test_net_3 = ipaddress.ip_network("203.0.113.0/24")
        bench_net = ipaddress.ip_network("198.18.0.0/15")
        if ip in test_net_1 or ip in test_net_2 or ip in test_net_3 or ip in bench_net or ip.is_reserved or ip.is_loopback:
            return True
    except ValueError:
        pass
    return False


def _is_private_ip(target: str) -> bool:
    """Check if target IP is RFC 1918 private."""
    if not target:
        return False
    try:
        ip = ipaddress.ip_address(target.strip())
        return ip.is_private and not _is_documentation_ip_or_domain(target)
    except ValueError:
        return False


def build_evidence_attack_graph(
    alerts: list[Alert],
    hosts: list[str],
    supplementary_network_events: Optional[list[dict[str, Any]]] = None,
) -> tuple[nx.DiGraph, dict[str, Any]]:
    """
    Construct an Evidence-Weighted Directed Attack Graph using NetworkX (FR-5).
    Guarantees Directed Acyclic Graph (DAG) topology.
    Distinguishes observed facts from inferred temporal stage progression.
    Preserves process instances by PID; never creates false causal edges across unlinked processes.
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
        if source_id == target_id:
            return  # Prevent self-loops
        if g.has_edge(source_id, target_id):
            return

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

    sorted_alerts = sorted(alerts, key=lambda a: _parse_ts(a.first_seen))
    if len(sorted_alerts) > 50:
        sorted_alerts = sorted_alerts[:50]

    prev_alert_node_id: Optional[str] = None
    prev_rule_id: Optional[str] = None

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

        host_str = alert.host or (hosts[0] if hosts else "UNKNOWN")
        host_id = f"host:{host_str}"
        if host_id not in nodes_map and alert.host:
            add_node(host_id, "host", alert.host, {"host_name": alert.host})

        user_node_id: Optional[str] = None
        if alert.username:
            primary_user = alert.username.split(",")[0].strip()
            user_node_id = f"user:{primary_user}"
            add_node(user_node_id, "user", primary_user, {"username": primary_user})

        # Process-level node and edge building preserving PID instances
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
                "TRIGGERED_DETECTION",
                weight=1.0,
                is_observed=True,
                is_inferred=False,
                supporting_event_ids=alert.supporting_event_ids,
                evidence_references=alert.evidence_references,
            )

        elif alert.rule_id == "RULE-002":  # Office -> PowerShell Execution
            for ref in alert.evidence_references:
                parent_name = ref.get("parent_process_name") or alert.parent_process_name or "winword.exe"
                child_name = ref.get("process_name") or alert.process_name or "powershell.exe"
                pid = ref.get("process_id") if ref.get("process_id") is not None else alert.process_id
                ppid = ref.get("parent_process_id") if ref.get("parent_process_id") is not None else alert.parent_process_id
                eid = ref.get("event_id")

                parent_proc_id = _get_process_node_id(host_str, parent_name, ppid, eid)
                child_proc_id = _get_process_node_id(host_str, child_name, pid, eid)

                p_label = f"{parent_name} (PID: {ppid})" if ppid is not None else parent_name
                c_label = f"{child_name} (PID: {pid})" if pid is not None else child_name

                add_node(parent_proc_id, "process", p_label, {"process_name": parent_name, "process_id": ppid, "is_parent": True})
                add_node(child_proc_id, "process", c_label, {"process_name": child_name, "process_id": pid, "parent_process_id": ppid, "is_child": True})

                add_edge(
                    parent_proc_id,
                    child_proc_id,
                    "SPAWNED_PROCESS",
                    weight=1.0,
                    is_observed=True,
                    is_inferred=False,
                    supporting_event_ids=[eid] if eid else alert.supporting_event_ids,
                    evidence_references=[ref],
                    first_seen=ref.get("timestamp") or alert.first_seen,
                    last_seen=ref.get("timestamp") or alert.last_seen,
                )
                add_edge(
                    child_proc_id,
                    host_id,
                    "EXECUTED_ON",
                    weight=1.0,
                    is_observed=True,
                    is_inferred=False,
                    supporting_event_ids=[eid] if eid else alert.supporting_event_ids,
                    evidence_references=[ref],
                )
                add_edge(
                    child_proc_id,
                    alert_node_id,
                    "TRIGGERED_DETECTION",
                    weight=1.0,
                    is_observed=True,
                    is_inferred=False,
                    supporting_event_ids=[eid] if eid else alert.supporting_event_ids,
                    evidence_references=[ref],
                )

        elif alert.rule_id == "RULE-003":  # Outbound Network Connection
            for ref in alert.evidence_references:
                proc_name = ref.get("process_name") or alert.process_name or "powershell.exe"
                pid = ref.get("process_id") if ref.get("process_id") is not None else alert.process_id
                eid = ref.get("event_id")
                dest_ip = ref.get("destination_ip") or alert.destination_ip
                dest = dest_ip or "unknown_destination"

                proc_id = _get_process_node_id(host_str, proc_name, pid, eid)
                p_label = f"{proc_name} (PID: {pid})" if pid is not None else proc_name
                dest_id = f"net:{dest}"

                is_doc_ip = _is_documentation_ip_or_domain(dest)
                add_node(proc_id, "process", p_label, {"process_name": proc_name, "process_id": pid})
                add_node(dest_id, "network_dest", dest, {
                    "destination": dest,
                    "is_reserved_documentation": is_doc_ip,
                    "role": "reserved_documentation_ip" if is_doc_ip else "observed_outbound_destination",
                })

                add_edge(
                    proc_id,
                    dest_id,
                    "OUTBOUND_NETWORK_TRAFFIC",
                    weight=0.8,
                    is_observed=True,
                    is_inferred=False,
                    supporting_event_ids=[eid] if eid else alert.supporting_event_ids,
                    evidence_references=[ref],
                    first_seen=ref.get("timestamp") or alert.first_seen,
                )
                add_edge(
                    dest_id,
                    alert_node_id,
                    "TRIGGERED_DETECTION",
                    weight=1.0,
                    is_observed=True,
                    is_inferred=False,
                    supporting_event_ids=[eid] if eid else alert.supporting_event_ids,
                    evidence_references=[ref],
                )

        elif alert.rule_id == "RULE-004":  # Registry Persistence
            for ref in alert.evidence_references:
                proc_name = ref.get("process_name") or alert.process_name or "powershell.exe"
                pid = ref.get("process_id") if ref.get("process_id") is not None else alert.process_id
                eid = ref.get("event_id")

                proc_id = _get_process_node_id(host_str, proc_name, pid, eid)
                p_label = f"{proc_name} (PID: {pid})" if pid is not None else proc_name
                reg_node_id = f"reg:{host_str}:RunKey"

                add_node(proc_id, "process", p_label, {"process_name": proc_name, "process_id": pid})
                add_node(reg_node_id, "registry", "Windows Run Key", {"registry_path": "HKCU\\...\\Run"})

                add_edge(
                    proc_id,
                    reg_node_id,
                    "MODIFIED_PERSISTENCE_KEY",
                    weight=1.0,
                    is_observed=True,
                    is_inferred=False,
                    supporting_event_ids=[eid] if eid else alert.supporting_event_ids,
                    evidence_references=[ref],
                    first_seen=ref.get("timestamp") or alert.first_seen,
                )
                add_edge(
                    reg_node_id,
                    host_id,
                    "INSTALLED_ON",
                    weight=1.0,
                    is_observed=True,
                    is_inferred=False,
                    supporting_event_ids=[eid] if eid else alert.supporting_event_ids,
                    evidence_references=[ref],
                )
                add_edge(
                    reg_node_id,
                    alert_node_id,
                    "TRIGGERED_DETECTION",
                    weight=1.0,
                    is_observed=True,
                    is_inferred=False,
                    supporting_event_ids=[eid] if eid else alert.supporting_event_ids,
                    evidence_references=[ref],
                )

        elif alert.rule_id == "RULE-005":  # Ransomware File Modification
            for ref in alert.evidence_references:
                proc_name = ref.get("process_name") or alert.process_name or "unknown.exe"
                pid = ref.get("process_id") if ref.get("process_id") is not None else alert.process_id
                eid = ref.get("event_id")

                # unknown.exe has unobserved parent PID; isolated on its own branch
                proc_id = _get_process_node_id(host_str, proc_name, pid, eid)
                p_label = f"{proc_name} (PID: {pid})" if pid is not None else proc_name
                file_node_id = f"file:{host_str}:.locked"

                add_node(proc_id, "process", p_label, {
                    "process_name": proc_name,
                    "process_id": pid,
                    "parent_process_id": None,
                    "parent_process_name": None,
                    "unobserved_parent": True,
                })
                add_node(file_node_id, "file", "*.locked files", {"extension": "locked"})

                add_edge(
                    proc_id,
                    file_node_id,
                    "RENAMED_FILES",
                    weight=1.0,
                    is_observed=True,
                    is_inferred=False,
                    supporting_event_ids=[eid] if eid else alert.supporting_event_ids,
                    evidence_references=[ref],
                    first_seen=ref.get("timestamp") or alert.first_seen,
                )
                add_edge(
                    file_node_id,
                    host_id,
                    "LOCATED_ON",
                    weight=1.0,
                    is_observed=True,
                    is_inferred=False,
                    supporting_event_ids=[eid] if eid else alert.supporting_event_ids,
                    evidence_references=[ref],
                )
                add_edge(
                    file_node_id,
                    alert_node_id,
                    "TRIGGERED_DETECTION",
                    weight=1.0,
                    is_observed=True,
                    is_inferred=False,
                    supporting_event_ids=[eid] if eid else alert.supporting_event_ids,
                    evidence_references=[ref],
                )

        # Inferred temporal progression edge across distinct attack stages (not between repeated alerts of same rule)
        if prev_alert_node_id and prev_rule_id and prev_rule_id != alert.rule_id:
            add_edge(
                prev_alert_node_id,
                alert_node_id,
                "INFERRED_STAGE_PROGRESSION",
                weight=0.7,
                is_observed=False,
                is_inferred=True,
                first_seen=alert.first_seen,
                supporting_event_ids=alert.supporting_event_ids,
            )
        prev_alert_node_id = alert_node_id
        prev_rule_id = alert.rule_id

    # Add observed supplementary network connections to graph if any
    if supplementary_network_events:
        for sne in supplementary_network_events:
            proc = sne.get("process_name") or "powershell.exe"
            pid = sne.get("process_id")
            eid = sne.get("event_id")
            host_str = sne.get("host_name") or (hosts[0] if hosts else "UNKNOWN")

            proc_id = _get_process_node_id(host_str, proc, pid, eid)
            p_label = f"{proc} (PID: {pid})" if pid is not None else proc

            dest = sne.get("destination_ip") or sne.get("destination_domain")
            if not dest:
                continue
            dest_id = f"net:{dest}"

            is_doc_ip = _is_documentation_ip_or_domain(dest)
            add_node(proc_id, "process", p_label, {"process_name": proc, "process_id": pid})
            add_node(dest_id, "network_dest", dest, {
                "destination": dest,
                "is_reserved_documentation": is_doc_ip,
                "role": "reserved_documentation_ip" if is_doc_ip else "observed_outbound_destination",
            })
            add_edge(
                proc_id,
                dest_id,
                "OUTBOUND_NETWORK_TRAFFIC",
                weight=0.8,
                is_observed=True,
                is_inferred=False,
                first_seen=sne.get("timestamp"),
                supporting_event_ids=[eid] if eid else [],
                evidence_references=[
                    {
                        "event_id": eid,
                        "raw_file": sne.get("raw_file", "unknown"),
                        "byte_offset": sne.get("byte_offset", 0),
                        "record_length": sne.get("record_length", 0),
                    }
                ]
                if eid
                else [],
            )

    # Topological verification: ensure graph is strictly a Directed Acyclic Graph (DAG)
    if not nx.is_directed_acyclic_graph(g):
        logger.warning("Graph contains cycles; removing back-edges to preserve DAG topology.")
        cycles = list(nx.simple_cycles(g))
        for cycle in cycles:
            if len(cycle) >= 2:
                g.remove_edge(cycle[-1], cycle[0])

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

    Rigorous Semantics:
      - Destinations in reserved documentation IP ranges (RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
        are explicitly classified as reserved documentation ranges, not real attacker infrastructure.
      - Distinguish:
          * Outbound connection observed.
          * Internal network connectivity observed.
          * Successful authentication observed.
          * Access or compromise confirmed.
          * Insufficient evidence.
      - Never infer successful access from a network connection alone.
    """
    reach_assets: list[ReachNextAsset] = []
    seen_targets: set[str] = set()

    # Case 1: Infrastructure Brute Force with zero successful logons
    is_brute_force_only = all(a.rule_id == "RULE-001" for a in alerts)
    if is_brute_force_only:
        return []

    # Gather candidate network connections from RULE-003 alerts and supplementary events
    candidates: list[dict[str, Any]] = []

    for alert in alerts:
        if alert.rule_id == "RULE-003" or alert.destination_ip:
            for ref in alert.evidence_references:
                dest = ref.get("destination_ip") or alert.destination_ip
                if dest:
                    candidates.append({
                        "destination_ip": dest,
                        "destination_domain": ref.get("destination_domain") or getattr(alert, "destination_domain", None),
                        "host_name": alert.host,
                        "process_name": ref.get("process_name") or alert.process_name or "powershell.exe",
                        "process_id": ref.get("process_id") or alert.process_id,
                        "event_id": ref.get("event_id"),
                        "raw_file": ref.get("raw_file", "unknown"),
                        "byte_offset": ref.get("byte_offset", 0),
                        "record_length": ref.get("record_length", 0),
                    })

    if supplementary_network_events:
        candidates.extend(supplementary_network_events)

    for item in candidates:
        dest_ip = item.get("destination_ip")
        dest_domain = item.get("destination_domain")
        target = dest_ip or dest_domain
        if not target or target in seen_targets:
            continue
        seen_targets.add(target)

        src_host = item.get("host_name") or (hosts[0] if hosts else "UNKNOWN")
        proc = item.get("process_name") or "powershell.exe"
        pid = item.get("process_id")
        pid_str = f" (PID: {pid})" if pid is not None else ""

        eid = item.get("event_id")
        ev_refs = [
            {
                "event_id": eid,
                "raw_file": item.get("raw_file", "unknown"),
                "byte_offset": item.get("byte_offset", 0),
                "record_length": item.get("record_length", 0),
            }
        ] if eid else []

        if _is_documentation_ip_or_domain(target):
            # Reserved Documentation IP Range (RFC 5737 TEST-NET)
            reach_assets.append(
                ReachNextAsset(
                    target=target,
                    target_type="reserved_documentation_ip",
                    from_host=src_host,
                    relationship="observed_outbound_destination",
                    verification_status="outbound_connection_observed",
                    confidence="medium",
                    reasoning=(
                        f"Destination '{target}' is within a reserved documentation IP address range (RFC 5737 / documentation domain). "
                        f"Outbound network connection was observed from host '{src_host}' by process '{proc}'{pid_str}, but this represents "
                        f"documentation / test range telemetry and NOT real external attacker infrastructure. "
                        f"Successful access, authentication, or compromise is NOT confirmed and cannot be inferred from network connectivity alone."
                    ),
                    evidence_event_ids=[eid] if eid else [],
                    evidence_references=ev_refs,
                )
            )
        elif _is_private_ip(target):
            # Internal RFC 1918 Private Network
            reach_assets.append(
                ReachNextAsset(
                    target=target,
                    target_type="internal_ip",
                    from_host=src_host,
                    relationship="internal_network_connectivity_observed",
                    verification_status="internal_network_connectivity_observed",
                    confidence="medium",
                    reasoning=(
                        f"Observed internal network connection from host '{src_host}' to internal destination '{target}'. "
                        f"Internal network connectivity observed; successful authentication and access or compromise remain unverified."
                    ),
                    evidence_event_ids=[eid] if eid else [],
                    evidence_references=ev_refs,
                )
            )
        else:
            # Public External IP
            reach_assets.append(
                ReachNextAsset(
                    target=target,
                    target_type="external_destination",
                    from_host=src_host,
                    relationship="observed_outbound_destination",
                    verification_status="outbound_connection_observed",
                    confidence="medium",
                    reasoning=(
                        f"Observed outbound network traffic from process '{proc}'{pid_str} on host '{src_host}' "
                        f"to external destination '{target}'. Outbound connection observed; this represents observed network activity, "
                        f"NOT confirmed internal pivot reachability or target access."
                    ),
                    evidence_event_ids=[eid] if eid else [],
                    evidence_references=ev_refs,
                )
            )

    return reach_assets
