"""
Evidence Graph Construction and Component Analysis for CyberTrace.

Builds an in-memory graph containing:
  - Typed Entity Nodes (Host, User, IP Address, Process, Alert)
  - Typed Relationship Edges (Entity Associations and Inter-Observation Correlations)
  - Explicit evidence backing for every edge.
  - Dual Graph Analysis:
      1. Raw Association Graph: Contains all observable links (showing global entity co-occurrence).
      2. Investigation Graph: Applies strict relationship-strength and edge-eligibility policies,
         disqualifying cross-host random usernames and synthetic TEST-NET addresses from merging
         unrelated endpoints into artificial campaigns.
"""

from collections import defaultdict, deque
from typing import Any, Optional
import uuid

from backend.correlation.confidence import is_test_net_ip
from backend.correlation.entity_extractor import EntityExtractor
from backend.correlation.relationship_schema import (
    EntityNode,
    NodeType,
    Relationship,
    RelationshipEdge,
)
from backend.detection.alert_schema import Alert


class EvidenceGraph:
    """
    In-memory multi-entity evidence graph representing security observations,
    entities, and their verified correlation relationships.
    Supports both raw association analysis and defensible investigation clustering.
    """

    def __init__(self):
        self.nodes: dict[str, EntityNode] = {}
        self.edges: dict[str, RelationshipEdge] = {}
        self.relationships: dict[str, Relationship] = {}

        # Dual adjacency structures
        self.adj_all: dict[str, set[str]] = defaultdict(set)
        self.adj_investigation: dict[str, set[str]] = defaultdict(set)
        self.edge_by_nodes: dict[tuple[str, str, str], str] = {}

    def add_node(self, node: EntityNode) -> None:
        """Add a typed entity node if not already present."""
        if node.node_id not in self.nodes:
            self.nodes[node.node_id] = node

    def add_relationship(self, rel: Relationship) -> Optional[RelationshipEdge]:
        """
        Add a correlation relationship edge between two alert nodes.
        Enforces deduplication of identical relationships and records investigation eligibility.
        """
        self.relationships[rel.relationship_id] = rel

        src_node_id = f"alert:{rel.source_observation_id}"
        tgt_node_id = f"alert:{rel.target_observation_id}"

        # Deduplication key
        edge_key = (
            min(src_node_id, tgt_node_id),
            max(src_node_id, tgt_node_id),
            rel.relationship_type,
        )
        if edge_key in self.edge_by_nodes:
            return None

        edge_id = str(uuid.uuid4())
        edge = RelationshipEdge(
            edge_id=edge_id,
            source_node_id=src_node_id,
            target_node_id=tgt_node_id,
            relationship_type=rel.relationship_type,
            confidence=rel.confidence,
            observed_or_inferred=rel.observed_or_inferred,
            relationship_id=rel.relationship_id,
            is_investigation_eligible=rel.is_investigation_eligible,
            properties={
                "correlation_dimension": rel.correlation_dimension,
                "explanation": rel.explanation,
                "evidence": rel.evidence,
                "timestamp_context": rel.timestamp_context,
            },
        )
        self.edges[edge_id] = edge
        self.edge_by_nodes[edge_key] = edge_id

        # Update raw adjacency
        self.adj_all[src_node_id].add(tgt_node_id)
        self.adj_all[tgt_node_id].add(src_node_id)

        # Update investigation adjacency if eligible
        if rel.is_investigation_eligible:
            self.adj_investigation[src_node_id].add(tgt_node_id)
            self.adj_investigation[tgt_node_id].add(src_node_id)

        return edge

    def add_entity_association(
        self,
        alert_node_id: str,
        entity_node_id: str,
        assoc_type: str,
        confidence: str = "HIGH",
        is_investigation_eligible: bool = True,
    ) -> Optional[RelationshipEdge]:
        """Add a factual association edge between an Alert and an Entity node."""
        edge_key = (alert_node_id, entity_node_id, assoc_type)
        if edge_key in self.edge_by_nodes:
            return None

        edge_id = str(uuid.uuid4())
        edge = RelationshipEdge(
            edge_id=edge_id,
            source_node_id=alert_node_id,
            target_node_id=entity_node_id,
            relationship_type=assoc_type,
            confidence=confidence,
            observed_or_inferred="OBSERVED",
            is_investigation_eligible=is_investigation_eligible,
            properties={"is_entity_association": True},
        )
        self.edges[edge_id] = edge
        self.edge_by_nodes[edge_key] = edge_id

        self.adj_all[alert_node_id].add(entity_node_id)
        self.adj_all[entity_node_id].add(alert_node_id)

        if is_investigation_eligible:
            self.adj_investigation[alert_node_id].add(entity_node_id)
            self.adj_investigation[entity_node_id].add(alert_node_id)

        return edge

    def get_connected_components(self, investigation_only: bool = False) -> list[dict[str, Any]]:
        """
        Compute connected components using Breadth-First Search (BFS).
        If investigation_only=True, uses only investigation-eligible edges to prevent
        cross-host random usernames or TEST-NET addresses from collapsing the graph.
        """
        adj_map = self.adj_investigation if investigation_only else self.adj_all
        visited = set()
        components = []

        for node_id in self.nodes:
            if node_id in visited:
                continue

            comp_nodes = []
            queue = deque([node_id])
            visited.add(node_id)

            while queue:
                curr = queue.popleft()
                comp_nodes.append(curr)
                for neighbor in adj_map.get(curr, set()):
                    if neighbor not in visited and neighbor in self.nodes:
                        visited.add(neighbor)
                        queue.append(neighbor)

            # Analyze component
            node_types_count = defaultdict(int)
            hosts_in_comp = set()
            alerts_in_comp = set()

            for nid in comp_nodes:
                nobj = self.nodes[nid]
                node_types_count[nobj.node_type] += 1
                if nobj.node_type == NodeType.HOST:
                    hosts_in_comp.add(nobj.label)
                elif nobj.node_type == NodeType.ALERT:
                    alerts_in_comp.add(nid)

            # Count edges strictly within component
            comp_nodes_set = set(comp_nodes)
            comp_edges = [
                e for e in self.edges.values()
                if e.source_node_id in comp_nodes_set and e.target_node_id in comp_nodes_set
                and (not investigation_only or e.is_investigation_eligible)
            ]

            components.append({
                "component_id": len(components) + 1,
                "node_count": len(comp_nodes),
                "edge_count": len(comp_edges),
                "node_types": dict(node_types_count),
                "hosts": sorted(list(hosts_in_comp)),
                "alert_count": len(alerts_in_comp),
                "node_ids": comp_nodes,
                "is_isolated": len(comp_nodes) == 1,
                "has_alerts": len(alerts_in_comp) > 0,
            })

        components.sort(key=lambda c: c["node_count"], reverse=True)
        return components

    def summary(self) -> dict[str, Any]:
        """Generate high-level graph metrics and distributions."""
        node_counts_by_type = defaultdict(int)
        for n in self.nodes.values():
            node_counts_by_type[n.node_type] += 1

        edge_counts_by_type = defaultdict(int)
        edge_counts_by_confidence = defaultdict(int)
        edge_counts_by_status = defaultdict(int)
        investigation_eligible_edges = 0

        for e in self.edges.values():
            edge_counts_by_type[e.relationship_type] += 1
            edge_counts_by_confidence[e.confidence] += 1
            edge_counts_by_status[e.observed_or_inferred] += 1
            if e.is_investigation_eligible:
                investigation_eligible_edges += 1

        raw_components = self.get_connected_components(investigation_only=False)
        inv_components = self.get_connected_components(investigation_only=True)

        raw_alert_comps = [c for c in raw_components if c["has_alerts"]]
        inv_alert_comps = [c for c in inv_components if c["has_alerts"]]

        # Find top hub nodes by degree in investigation graph
        node_degrees = {nid: len(self.adj_investigation.get(nid, set())) for nid in self.nodes}
        top_hubs = sorted(node_degrees.items(), key=lambda x: x[1], reverse=True)[:5]
        hubs_summary = [
            {
                "node_id": nid,
                "node_type": self.nodes[nid].node_type,
                "label": self.nodes[nid].label,
                "investigation_degree": deg,
            }
            for nid, deg in top_hubs if deg > 0
        ]

        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "investigation_eligible_edges": investigation_eligible_edges,
            "total_relationships": len(self.relationships),
            "nodes_by_type": dict(node_counts_by_type),
            "edges_by_type": dict(edge_counts_by_type),
            "edges_by_confidence": dict(edge_counts_by_confidence),
            "edges_by_status": dict(edge_counts_by_status),
            "total_connected_components": len(raw_components),
            "components_with_alerts": len(raw_alert_comps),
            "largest_component_nodes": raw_components[0]["node_count"] if raw_components else 0,
            "raw_connected_components": len(raw_components),
            "raw_components_with_alerts": len(raw_alert_comps),
            "largest_raw_component_nodes": raw_components[0]["node_count"] if raw_components else 0,
            "investigation_connected_components": len(inv_components),
            "investigation_components_with_alerts": len(inv_alert_comps),
            "largest_investigation_component_nodes": inv_components[0]["node_count"] if inv_components else 0,
            "investigation_clustering_policy": (
                "Cross-host SAME_USER relationships, sub-second temporal proximity, and synthetic "
                "RFC 5737 TEST-NET addresses are preserved as observable associations, but strictly "
                "disqualified from merging investigation clusters without independent lateral movement or C2 telemetry."
            ),
            "top_hub_nodes": hubs_summary,
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize entire graph to dictionary."""
        return {
            "summary": self.summary(),
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges.values()],
            "relationships": [r.to_dict() for r in self.relationships.values()],
            "components": self.get_connected_components(investigation_only=False),
            "investigation_components": self.get_connected_components(investigation_only=True),
        }


class GraphBuilder:
    """
    Constructs the EvidenceGraph from extracted entities and evaluated relationships.
    """

    def build_graph(
        self,
        extractor: EntityExtractor,
        relationships: list[Relationship],
        include_entity_associations: bool = True,
    ) -> EvidenceGraph:
        """
        Assemble the complete evidence graph with dual-mode adjacency.
        """
        graph = EvidenceGraph()

        # 1. Add Alert Nodes
        for alert in extractor.alerts:
            anode = EntityNode(
                node_id=f"alert:{alert.alert_id}",
                node_type=NodeType.ALERT,
                label=f"[{alert.rule_id}] {alert.title}",
                properties={
                    "alert_id": alert.alert_id,
                    "rule_id": alert.rule_id,
                    "title": alert.title,
                    "severity": alert.severity,
                    "confidence": alert.confidence,
                    "mitre_technique_id": alert.mitre_technique_id,
                    "mitre_tactic": alert.mitre_tactic,
                    "kill_chain_stage": alert.kill_chain_stage,
                    "host": alert.host,
                    "first_seen": alert.first_seen,
                    "last_seen": alert.last_seen,
                    "supporting_event_count": len(alert.supporting_event_ids),
                },
            )
            graph.add_node(anode)

        # 2. Add Entity Nodes
        for hname, hent in extractor.hosts.items():
            graph.add_node(
                EntityNode(
                    node_id=f"host:{hname}",
                    node_type=NodeType.HOST,
                    label=hname,
                    properties=hent.to_dict(),
                )
            )

        for uname, uent in extractor.users.items():
            graph.add_node(
                EntityNode(
                    node_id=f"user:{uname}",
                    node_type=NodeType.USER,
                    label=uname,
                    properties=uent.to_dict(),
                )
            )

        for ip_addr, ipent in extractor.ips.items():
            graph.add_node(
                EntityNode(
                    node_id=f"ip:{ip_addr}",
                    node_type=NodeType.IP_ADDRESS,
                    label=ip_addr,
                    properties=ipent.to_dict(),
                )
            )

        for pkey, pent in extractor.processes.items():
            graph.add_node(
                EntityNode(
                    node_id=f"proc:{pent.entity_id}",
                    node_type=NodeType.PROCESS,
                    label=f"{pent.process_name} (PID: {pent.process_id or '?'})",
                    properties=pent.to_dict(),
                )
            )

        # 3. Add Entity Association Edges
        # Policy: Host and Process associations are investigation-eligible.
        # User associations are NOT investigation-eligible (prevents global user bridging).
        # IP associations are investigation-eligible ONLY if public (not TEST-NET).
        if include_entity_associations:
            for alert in extractor.alerts:
                aid = f"alert:{alert.alert_id}"

                if alert.host:
                    graph.add_entity_association(
                        aid, f"host:{alert.host.strip()}", "OBSERVED_ON", is_investigation_eligible=True
                    )

                if alert.source_ip:
                    is_test_net = is_test_net_ip(alert.source_ip)
                    graph.add_entity_association(
                        aid, f"ip:{alert.source_ip.strip()}", "OBSERVED_SOURCE_IP",
                        is_investigation_eligible=not is_test_net
                    )

                if alert.destination_ip:
                    is_test_net = is_test_net_ip(alert.destination_ip)
                    graph.add_entity_association(
                        aid, f"ip:{alert.destination_ip.strip()}", "OBSERVED_DESTINATION_IP",
                        is_investigation_eligible=not is_test_net
                    )

                if alert.username:
                    for u in alert.username.split(","):
                        cu = u.strip()
                        if cu and f"user:{cu}" in graph.nodes:
                            # User associations are preserved as observable facts, but disqualified from bridging hosts
                            graph.add_entity_association(
                                aid, f"user:{cu}", "ASSOCIATED_USER", is_investigation_eligible=False
                            )

                if alert.process_name and alert.host:
                    pkey = f"{alert.host.strip()}:{alert.process_name.lower().strip()}:{alert.process_id if alert.process_id is not None else 'unknown'}"
                    if f"proc:{pkey}" in graph.nodes:
                        graph.add_entity_association(
                            aid, f"proc:{pkey}", "EXECUTED_PROCESS", is_investigation_eligible=True
                        )

        # 4. Add Inter-Observation Relationship Edges
        for rel in relationships:
            graph.add_relationship(rel)

        return graph
