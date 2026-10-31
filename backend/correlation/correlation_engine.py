"""
CyberTrace Phase 3 Correlation Engine.

Orchestrates multi-dimensional evidence-based correlation across:
  - Host co-occurrence
  - User identity matching
  - Network IP matching and RFC 5737 classification
  - Process parent-child PID validation
  - Temporal proximity with synthetic compression handling
  - Behavioral sequence hypothesis
  - Cross-source firewall integration

Preserves complete evidence provenance without inventing attack paths.
"""

import json
import logging
import os
from typing import Any, Optional

from backend.correlation.confidence import classify_ip
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
from backend.correlation.relationship_schema import Relationship
from backend.detection.alert_schema import Alert

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """
    Main orchestrator for evidence-based cross-entity correlation.
    """

    def __init__(
        self,
        alerts: Optional[list[Alert]] = None,
        alerts_file: Optional[str] = None,
        fortigate_records: Optional[list[dict[str, Any]]] = None,
        temporal_window_ms: float = 50.0,
    ):
        self.alerts: list[Alert] = alerts or []
        self.alerts_file = alerts_file
        self.fortigate_records = fortigate_records or []
        self.temporal_window_ms = temporal_window_ms

        if not self.alerts and self.alerts_file and os.path.isfile(self.alerts_file):
            self.load_alerts_from_json(self.alerts_file)

        # Output state
        self.extractor: Optional[EntityExtractor] = None
        self.relationships: list[Relationship] = []
        self.graph: Optional[EvidenceGraph] = None
        self.correlator_limitation_notes: list[str] = []

    def load_alerts_from_json(self, filepath: str) -> None:
        """Load alerts from a Phase 2 JSON alert export."""
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        raw_alerts = data.get("alerts", data) if isinstance(data, dict) else data
        self.alerts = [Alert.from_dict(a) for a in raw_alerts]
        logger.info(f"Loaded {len(self.alerts)} alerts from {filepath}")

    def run(self) -> dict[str, Any]:
        """
        Execute full cross-entity correlation pipeline.
        Returns complete correlation results dictionary.
        """
        if not self.alerts:
            logger.warning("No alerts loaded for correlation.")
            return {"status": "empty", "message": "No alerts provided to correlate."}

        # 1. Entity Extraction
        self.extractor = EntityExtractor(self.alerts)
        entity_summary = self.extractor.summary()

        # 2. Execute Correlation Rules
        raw_relationships: list[Relationship] = []

        host_correlator = HostCorrelator()
        raw_relationships.extend(host_correlator.correlate(self.extractor))

        user_correlator = UserCorrelator()
        raw_relationships.extend(user_correlator.correlate(self.extractor))

        network_correlator = NetworkCorrelator()
        raw_relationships.extend(network_correlator.correlate(self.extractor))

        process_correlator = ProcessCorrelator()
        raw_relationships.extend(process_correlator.correlate(self.extractor))

        temporal_correlator = TemporalCorrelator(time_window_ms=self.temporal_window_ms)
        raw_relationships.extend(temporal_correlator.correlate(self.extractor))

        behavioral_correlator = BehavioralSequenceCorrelator()
        raw_relationships.extend(behavioral_correlator.correlate(self.extractor))

        cross_source_correlator = CrossSourceCorrelator(self.fortigate_records)
        raw_relationships.extend(cross_source_correlator.correlate(self.extractor))
        if cross_source_correlator.data_limitation_reported:
            self.correlator_limitation_notes.append(
                "FortiGate telemetry limitation: Workspace 'firex-10G.log' contains an HTML error/login page from an incomplete download. Cross-source correlation operates in architecture-ready mode without fabricating firewall events."
            )

        # 3. Deduplicate Relationships
        deduped: list[Relationship] = []
        seen_pairs = set()

        for rel in raw_relationships:
            # Canonicalize pair for symmetric types
            if rel.relationship_type in ("SAME_HOST", "SAME_USER", "SAME_SOURCE_IP", "SAME_DESTINATION_IP", "TEMPORALLY_NEAR"):
                pair_key = (
                    min(rel.source_observation_id, rel.target_observation_id),
                    max(rel.source_observation_id, rel.target_observation_id),
                    rel.relationship_type,
                )
            else:
                pair_key = (
                    rel.source_observation_id,
                    rel.target_observation_id,
                    rel.relationship_type,
                )

            if pair_key not in seen_pairs:
                seen_pairs.add(pair_key)
                deduped.append(rel)

        self.relationships = deduped

        # 4. Construct Evidence Graph
        builder = GraphBuilder()
        self.graph = builder.build_graph(
            extractor=self.extractor,
            relationships=self.relationships,
            include_entity_associations=True,
        )

        # 5. Compile Results
        graph_summary = self.graph.summary()

        # Breakdown by dimension and type
        rel_by_dimension = {}
        rel_by_type = {}
        rel_by_confidence = {}
        rel_by_status = {}

        for r in self.relationships:
            rel_by_dimension[r.correlation_dimension] = rel_by_dimension.get(r.correlation_dimension, 0) + 1
            rel_by_type[r.relationship_type] = rel_by_type.get(r.relationship_type, 0) + 1
            rel_by_confidence[r.confidence] = rel_by_confidence.get(r.confidence, 0) + 1
            rel_by_status[r.observed_or_inferred] = rel_by_status.get(r.observed_or_inferred, 0) + 1

        # Provenance verification check
        total_supporting_events = sum(len(r.supporting_event_ids) for r in self.relationships)
        total_provenance_refs = sum(len(r.provenance_references) for r in self.relationships)

        # Run exhaustive provenance verification against raw EDR file if available
        raw_edr_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "edr_events.json")
        provenance_audit = self.verify_all_provenance(raw_edr_path) if os.path.isfile(raw_edr_path) else None

        results = {
            "metadata": {
                "engine": "CyberTrace Correlation Engine",
                "phase": "Phase 3.1: Evidence-Based Cross-Entity Correlation & Quality Audit",
                "total_alerts_evaluated": len(self.alerts),
                "total_relationships_identified": len(self.relationships),
                "temporal_window_ms": self.temporal_window_ms,
                "limitation_notes": self.correlator_limitation_notes,
                "provenance_audit": provenance_audit,
            },
            "entity_summary": entity_summary,
            "relationship_metrics": {
                "by_dimension": rel_by_dimension,
                "by_type": rel_by_type,
                "by_confidence": rel_by_confidence,
                "by_observation_status": rel_by_status,
                "total_supporting_events_linked": total_supporting_events,
                "total_provenance_refs_linked": total_provenance_refs,
            },
            "graph_metrics": graph_summary,
            "relationships": [r.to_dict() for r in self.relationships],
            "graph": self.graph.to_dict(),
        }

        return results

    def verify_all_provenance(self, raw_file_path: str = "edr_events.json") -> dict[str, Any]:
        """
        Exhaustively verify every single underlying evidence reference across all alerts
        against the raw JSON file on disk by seeking to byte_offset and reading record_length.
        """
        if not os.path.isfile(raw_file_path):
            return {
                "verified": False,
                "error": f"Raw file '{raw_file_path}' not found",
                "total_references": 0,
                "verified_count": 0,
                "failed_count": 0,
            }

        all_refs = []
        for alert in self.alerts:
            for ref in alert.evidence_references:
                all_refs.append({
                    "alert_id": alert.alert_id,
                    "rule_id": alert.rule_id,
                    "event_id": ref.get("event_id"),
                    "byte_offset": int(ref.get("byte_offset", 0)),
                    "record_length": int(ref.get("record_length", 0)),
                    "raw_file": ref.get("raw_file"),
                })

        verified_count = 0
        failed_count = 0
        duplicate_count = 0
        seen_offsets = set()
        failures = []

        file_size = os.path.getsize(raw_file_path)

        with open(raw_file_path, "rb") as rf:
            for item in all_refs:
                offset = item["byte_offset"]
                length = item["record_length"]
                expected_eid = item["event_id"]

                key = (offset, length)
                if key in seen_offsets:
                    duplicate_count += 1
                seen_offsets.add(key)

                if offset < 0 or offset + length > file_size:
                    failed_count += 1
                    failures.append({
                        "expected_event_id": expected_eid,
                        "byte_offset": offset,
                        "record_length": length,
                        "reason": f"seek error: offset {offset} + length {length} exceeds file size {file_size}",
                    })
                    continue

                rf.seek(offset)
                chunk = rf.read(length)

                try:
                    line_str = chunk.decode("utf-8")
                    rec = json.loads(line_str)
                    actual_eid = rec.get("event", {}).get("id") or rec.get("event_id")
                    if actual_eid == expected_eid:
                        verified_count += 1
                    else:
                        failed_count += 1
                        failures.append({
                            "expected_event_id": expected_eid,
                            "actual_event_id": actual_eid,
                            "byte_offset": offset,
                            "record_length": length,
                            "reason": "event_id mismatch",
                        })
                except Exception as e:
                    failed_count += 1
                    failures.append({
                        "expected_event_id": expected_eid,
                        "byte_offset": offset,
                        "record_length": length,
                        "reason": f"json decode error: {str(e)}",
                    })

        rate_pct = (verified_count / len(all_refs) * 100.0) if all_refs else 100.0
        return {
            "total_references_tested": len(all_refs),
            "total_references": len(all_refs),
            "total_unique_references": len(seen_offsets),
            "verified_count": verified_count,
            "verified": verified_count,
            "failed_count": failed_count,
            "failed": failed_count,
            "unresolvable": failed_count,
            "duplicate_count": duplicate_count,
            "verification_rate_pct": rate_pct,
            "success_rate_pct": rate_pct,
            "is_exhaustively_verified": (failed_count == 0 and len(all_refs) > 0),
            "failures": failures,
            "failure_details": failures,
        }

    def export_results(self, output_filepath: str) -> None:
        """Export full correlation results to JSON."""
        results = self.run()
        os.makedirs(os.path.dirname(output_filepath), exist_ok=True)
        with open(output_filepath, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str)
        logger.info(f"Exported correlation results to {output_filepath}")
