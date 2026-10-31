"""
Unit and Integration Tests for CyberTrace Phase 3 Correlation Engine.

Tests cover:
  1. Reserved IP and TEST-NET classification (RFC 5737, RFC 1918, etc.)
  2. Exact host matching (positive and negative)
  3. Different users on the same host (actor separation)
  4. Shared user on same host vs across distinct hosts
  5. Shared IP correlation and TEST-NET infrastructure handling
  6. Valid and invalid PID parent-child relationships
  7. Timestamp compression and sub-second proximity handling
  8. Out-of-order event ordering handling
  9. Weak vs strong relationship confidence rules
  10. Missing evidence and validation error handling
  11. Disconnected graph components and isolated node identification
  12. Duplicate relationship deduplication
  13. Evidence provenance preservation
  14. Critical check: 22 shared hosts (RULE-002 & RULE-004) are NOT labeled confirmed campaign
  15. Cross-source FortiGate integration (positive with mock and negative with real incomplete log)
  16. End-to-end integration test against 90 Phase 2 alerts
"""

import os
import pytest

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
    ObservationStatus,
    Relationship,
    RelationshipType,
)
from backend.detection.alert_schema import Alert


# -----------------------------------------------------------------------------
# Fixtures & Mock Helpers
# -----------------------------------------------------------------------------

def make_alert(
    rule_id: str,
    host: str,
    username: str,
    alert_id: str,
    first_seen: str = "2026-10-31T12:39:55.000000+05:30",
    last_seen: str = "2026-10-31T12:39:55.010000+05:30",
    source_ip: str = None,
    destination_ip: str = None,
    process_name: str = None,
    process_id: int = None,
    parent_process_name: str = None,
    parent_process_id: int = None,
    kill_chain_stage: str = "Execution",
    supporting_event_ids: list[str] = None,
    evidence_references: list[dict] = None,
) -> Alert:
    """Helper to construct valid Alert instances for testing."""
    eids = supporting_event_ids or [f"ev-{alert_id}-1"]
    refs = evidence_references or [
        {
            "event_id": eids[0],
            "raw_file": "edr_events.json",
            "byte_offset": 1000,
            "record_length": 500,
            "timestamp": first_seen,
            "username": username,
            "process_name": process_name,
            "process_id": process_id,
            "parent_process_name": parent_process_name,
            "parent_process_id": parent_process_id,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
        }
    ]
    return Alert(
        rule_id=rule_id,
        title=f"Test Alert {rule_id} on {host}",
        description="Test alert description",
        severity="high",
        confidence="high",
        mitre_technique_id="T1059.001",
        mitre_technique_name="PowerShell",
        mitre_tactic="Execution",
        kill_chain_stage=kill_chain_stage,
        first_seen=first_seen,
        last_seen=last_seen,
        host=host,
        username=username,
        source_ip=source_ip,
        destination_ip=destination_ip,
        process_name=process_name,
        process_id=process_id,
        parent_process_name=parent_process_name,
        parent_process_id=parent_process_id,
        supporting_event_ids=eids,
        evidence_references=refs,
        reasoning="Test alert reasoning",
        alert_id=alert_id,
    )


# -----------------------------------------------------------------------------
# 1. Reserved IP and TEST-NET Classification Tests
# -----------------------------------------------------------------------------

def test_reserved_ip_classification():
    """Verify IP classification accurately identifies RFC 5737 TEST-NET blocks, RFC 1918, etc."""
    # RFC 5737 TEST-NET-1, 2, 3
    test_nets = ["192.0.2.88", "198.51.100.23", "203.0.113.57"]
    for ip in test_nets:
        res = classify_ip(ip)
        assert res["classification"] == IPClassification.TEST_NET_DOCUMENTATION
        assert res["is_test_net"] is True
        assert res["is_public"] is False
        assert is_test_net_ip(ip) is True

    # RFC 1918 Private
    privates = ["10.0.1.5", "172.16.5.10", "192.168.1.1"]
    for ip in privates:
        res = classify_ip(ip)
        assert res["classification"] == IPClassification.RFC1918_PRIVATE
        assert res["is_private"] is True
        assert res["is_test_net"] is False

    # Loopback
    res = classify_ip("127.0.0.1")
    assert res["classification"] == IPClassification.LOOPBACK

    # Public Routable
    res = classify_ip("8.8.8.8")
    assert res["classification"] == IPClassification.PUBLIC_ROUTABLE
    assert res["is_public"] is True
    assert res["is_test_net"] is False

    # Invalid / Null
    assert classify_ip(None)["classification"] == IPClassification.INVALID
    assert classify_ip("not-an-ip")["classification"] == IPClassification.INVALID


# -----------------------------------------------------------------------------
# 2. Host Matching Tests (Positive and Negative)
# -----------------------------------------------------------------------------

def test_exact_host_matching_positive_and_negative():
    """Verify SAME_HOST connects alerts on the same host across rules, but ignores different hosts."""
    a1 = make_alert("RULE-002", "WS-HR-01", "alice", "a1")
    a2 = make_alert("RULE-004", "WS-HR-01", "alice", "a2")
    a3 = make_alert("RULE-002", "WS-FIN-02", "bob", "a3")

    extractor = EntityExtractor([a1, a2, a3])
    correlator = HostCorrelator()
    rels = correlator.correlate(extractor)

    # a1 and a2 share host WS-HR-01
    assert len(rels) == 1
    rel = rels[0]
    assert rel.relationship_type == RelationshipType.SAME_HOST
    assert rel.evidence["host"] == "WS-HR-01"
    assert rel.source_observation_id == "a1"
    assert rel.target_observation_id == "a2"

    # a3 on WS-FIN-02 has no partners on that host
    assert not any(r.evidence["host"] == "WS-FIN-02" for r in rels)


# -----------------------------------------------------------------------------
# 3. User Separation Tests
# -----------------------------------------------------------------------------

def test_different_users_on_same_host():
    """Verify different users on the same host produce SAME_HOST with low confidence and NO SAME_USER."""
    a1 = make_alert("RULE-002", "WS-HR-01", "alice", "a1")
    a2 = make_alert("RULE-004", "WS-HR-01", "bob", "a2")

    extractor = EntityExtractor([a1, a2])
    host_corr = HostCorrelator()
    user_corr = UserCorrelator()

    host_rels = host_corr.correlate(extractor)
    user_rels = user_corr.correlate(extractor)

    assert len(host_rels) == 1
    assert host_rels[0].confidence == ConfidenceLevel.LOW
    assert host_rels[0].evidence["shared_user"] is False
    assert "disjoint user accounts" in host_rels[0].explanation

    # No SAME_USER relationship because users differ
    assert len(user_rels) == 0


# -----------------------------------------------------------------------------
# 4. User Correlation Tests (Same Host vs Cross-Host)
# -----------------------------------------------------------------------------

def test_shared_user_same_host_vs_different_hosts():
    """Verify shared user on same host has medium confidence; across distinct hosts has low confidence."""
    a1 = make_alert("RULE-002", "WS-01", "charlie", "a1")
    a2 = make_alert("RULE-004", "WS-01", "charlie", "a2")
    a3 = make_alert("RULE-002", "WS-02", "charlie", "a3")

    extractor = EntityExtractor([a1, a2, a3])
    correlator = UserCorrelator()
    rels = correlator.correlate(extractor)

    # 3 pairs: (a1, a2), (a1, a3), (a2, a3)
    assert len(rels) == 3

    same_host_rel = next(r for r in rels if r.evidence["same_host"])
    diff_host_rel = next(r for r in rels if not r.evidence["same_host"])

    assert same_host_rel.confidence == ConfidenceLevel.MEDIUM
    assert diff_host_rel.confidence == ConfidenceLevel.LOW
    assert "no network lateral movement" in diff_host_rel.explanation


# -----------------------------------------------------------------------------
# 5. Shared IP and TEST-NET Correlation Tests
# -----------------------------------------------------------------------------

def test_shared_ip_correlation_and_test_net_handling():
    """Verify shared IP across alerts generates SAME_SOURCE_IP with RFC 5737 documentation note."""
    a1 = make_alert("RULE-001", "SRV-DC-01", "user1", "a1", source_ip="203.0.113.57")
    a2 = make_alert("RULE-001", "SRV-DC-01", "user2", "a2", source_ip="203.0.113.57")

    extractor = EntityExtractor([a1, a2])
    correlator = NetworkCorrelator()
    rels = correlator.correlate(extractor)

    assert len(rels) == 1
    rel = rels[0]
    assert rel.relationship_type == RelationshipType.SAME_SOURCE_IP
    assert rel.evidence["is_test_net"] is True
    assert rel.confidence == ConfidenceLevel.LOW
    assert rel.is_investigation_eligible is False
    assert "TEST-NET" in rel.explanation


# -----------------------------------------------------------------------------
# 6. Process Parent-Child and Process Identity Tests
# -----------------------------------------------------------------------------

def test_process_valid_and_invalid_pid_relationships():
    """Verify valid PID/PPID match generates PARENT_CHILD_PROCESS (HIGH); mismatched PIDs do not."""
    # Positive: Parent has PID 5000, Child has parent_process_id 5000 on same host
    p1 = make_alert("RULE-002", "WS-01", "user", "p1", process_name="winword.exe", process_id=5000)
    c1 = make_alert("RULE-002", "WS-01", "user", "c1", process_name="powershell.exe", process_id=6000, parent_process_id=5000)

    # Negative: Child has parent_process_id 9999 (no match)
    c2 = make_alert("RULE-004", "WS-01", "user", "c2", process_name="powershell.exe", process_id=7000, parent_process_id=9999)

    extractor = EntityExtractor([p1, c1, c2])
    correlator = ProcessCorrelator()
    rels = correlator.correlate(extractor)

    parent_child_rels = [r for r in rels if r.relationship_type == RelationshipType.PARENT_CHILD_PROCESS]
    assert len(parent_child_rels) == 1
    rel = parent_child_rels[0]
    assert rel.confidence == ConfidenceLevel.HIGH
    assert rel.source_observation_id == "p1"
    assert rel.target_observation_id == "c1"
    assert rel.evidence["pid_match"] is True

    # Check SAME_PROCESS_IMAGE for c1 and c2 (both powershell.exe on WS-01, but PIDs differ)
    same_img_rels = [r for r in rels if r.relationship_type == RelationshipType.SAME_PROCESS_IMAGE]
    assert len(same_img_rels) == 1
    sp_rel = same_img_rels[0]
    assert sp_rel.confidence == ConfidenceLevel.MEDIUM
    assert sp_rel.evidence["same_pid"] is False
    assert "separate execution instances" in sp_rel.explanation

    # Negative check: Must NOT be SAME_PROCESS because PIDs are different
    assert not any(r.relationship_type == RelationshipType.SAME_PROCESS for r in rels)


# -----------------------------------------------------------------------------
# 7. Timestamp Compression Tests
# -----------------------------------------------------------------------------

def test_timestamp_compression_handling():
    """Verify sub-second temporal proximity produces TEMPORALLY_NEAR with LOW confidence and synthetic caveat."""
    t1 = "2026-10-31T12:39:55.000000+05:30"
    t2 = "2026-10-31T12:39:55.005000+05:30"  # 5 ms later
    a1 = make_alert("RULE-002", "WS-01", "user", "a1", first_seen=t1)
    a2 = make_alert("RULE-004", "WS-01", "user", "a2", first_seen=t2)

    extractor = EntityExtractor([a1, a2])
    correlator = TemporalCorrelator(time_window_ms=50.0)
    rels = correlator.correlate(extractor)

    assert len(rels) == 1
    rel = rels[0]
    assert rel.relationship_type == RelationshipType.TEMPORALLY_NEAR
    assert rel.confidence == ConfidenceLevel.LOW
    assert rel.evidence["delta_ms"] == pytest.approx(5.0, 0.1)
    assert "synthetic dataset" in rel.explanation


# -----------------------------------------------------------------------------
# 8. Out-of-Order Timestamp Handling Tests
# -----------------------------------------------------------------------------

def test_out_of_order_events():
    """Verify engine handles out-of-order / inverted timestamps safely without crashing or negative deltas."""
    t_later = "2026-10-31T12:39:55.050000+05:30"
    t_earlier = "2026-10-31T12:39:55.010000+05:30"
    a1 = make_alert("RULE-002", "WS-01", "user", "a1", first_seen=t_later)
    a2 = make_alert("RULE-004", "WS-01", "user", "a2", first_seen=t_earlier)

    extractor = EntityExtractor([a1, a2])
    correlator = HostCorrelator()
    rels = correlator.correlate(extractor)

    assert len(rels) == 1
    delta = rels[0].evidence["delta_ms"]
    assert delta >= 0.0
    assert delta == pytest.approx(40.0, 0.1)


# -----------------------------------------------------------------------------
# 9. Confidence Rules Validation Tests
# -----------------------------------------------------------------------------

def test_weak_versus_strong_relationship_confidence():
    """Verify confidence rules adhere to guidelines and never upgrade weak associations."""
    # Process parent-child with PID match -> HIGH
    conf, _ = evaluate_confidence(
        rel_type=RelationshipType.PARENT_CHILD_PROCESS,
        dimension=CorrelationDimension.PROCESS,
        evidence={"pid_match": True, "same_host": True},
    )
    assert conf == ConfidenceLevel.HIGH

    # Process parent-child without PID match -> INSUFFICIENT
    conf, _ = evaluate_confidence(
        rel_type=RelationshipType.PARENT_CHILD_PROCESS,
        dimension=CorrelationDimension.PROCESS,
        evidence={"pid_match": False, "same_host": True},
    )
    assert conf == ConfidenceLevel.INSUFFICIENT

    # Host co-occurrence without shared user -> LOW
    conf, _ = evaluate_confidence(
        rel_type=RelationshipType.SAME_HOST,
        dimension=CorrelationDimension.HOST,
        evidence={"shared_user": False, "host": "WS-01"},
    )
    assert conf == ConfidenceLevel.LOW


# -----------------------------------------------------------------------------
# 10. Schema Validation Tests
# -----------------------------------------------------------------------------

def test_missing_evidence_references_validation():
    """Verify Relationship dataclass rejects invalid confidence or empty explanations."""
    with pytest.raises(ValueError):
        Relationship(
            source_observation_id="a1",
            target_observation_id="a2",
            relationship_type=RelationshipType.SAME_HOST,
            correlation_dimension=CorrelationDimension.HOST,
            evidence={},
            confidence="INVALID_CONFIDENCE",
            explanation="explanation",
            observed_or_inferred=ObservationStatus.OBSERVED,
            timestamp_context={},
        )

    with pytest.raises(ValueError):
        Relationship(
            source_observation_id="a1",
            target_observation_id="a2",
            relationship_type=RelationshipType.SAME_HOST,
            correlation_dimension=CorrelationDimension.HOST,
            evidence={},
            confidence=ConfidenceLevel.LOW,
            explanation="",  # Empty explanation rejected
            observed_or_inferred=ObservationStatus.OBSERVED,
            timestamp_context={},
        )


# -----------------------------------------------------------------------------
# 11. Disconnected Graph Components Tests
# -----------------------------------------------------------------------------

def test_disconnected_graph_components():
    """Verify graph builder correctly identifies disconnected components and isolated subgraphs."""
    # Cluster A on WS-01
    a1 = make_alert("RULE-002", "WS-01", "alice", "a1")
    a2 = make_alert("RULE-004", "WS-01", "alice", "a2")

    # Cluster B on WS-02
    b1 = make_alert("RULE-002", "WS-02", "bob", "b1")
    b2 = make_alert("RULE-004", "WS-02", "bob", "b2")

    # Isolated C on WS-03
    c1 = make_alert("RULE-005", "WS-03", "charlie", "c1")

    engine = CorrelationEngine(alerts=[a1, a2, b1, b2, c1])
    results = engine.run()

    graph_metrics = results["graph_metrics"]
    # There must be multiple components
    assert graph_metrics["total_connected_components"] >= 2
    # c1 has no cross-rule or cross-alert partners on WS-03
    components = results["graph"]["components"]
    c1_comp = next((c for c in components if f"alert:c1" in c["node_ids"]), None)
    assert c1_comp is not None


# -----------------------------------------------------------------------------
# 12. Duplicate Relationship Deduplication Tests
# -----------------------------------------------------------------------------

def test_duplicate_relationship_prevention():
    """Verify symmetric relationships (A, B) and (B, A) are canonicalized without duplicates."""
    a1 = make_alert("RULE-002", "WS-01", "alice", "a1")
    a2 = make_alert("RULE-004", "WS-01", "alice", "a2")

    engine = CorrelationEngine(alerts=[a1, a2])
    results = engine.run()

    same_host_rels = [r for r in results["relationships"] if r["relationship_type"] == RelationshipType.SAME_HOST]
    assert len(same_host_rels) == 1, "Exactly one SAME_HOST relationship should exist between a1 and a2"


# -----------------------------------------------------------------------------
# 13. Evidence Provenance Preservation Tests
# -----------------------------------------------------------------------------

def test_evidence_provenance_preservation():
    """Verify all relationships retain complete provenance references with byte offsets."""
    a1 = make_alert("RULE-002", "WS-01", "alice", "a1", evidence_references=[
        {"event_id": "ev-1", "raw_file": "edr.json", "byte_offset": 500, "record_length": 120}
    ])
    a2 = make_alert("RULE-004", "WS-01", "alice", "a2", evidence_references=[
        {"event_id": "ev-2", "raw_file": "edr.json", "byte_offset": 800, "record_length": 140}
    ])

    engine = CorrelationEngine(alerts=[a1, a2])
    results = engine.run()

    for rel in results["relationships"]:
        assert len(rel["supporting_event_ids"]) > 0
        assert len(rel["provenance_references"]) > 0
        for ref in rel["provenance_references"]:
            assert "byte_offset" in ref
            assert ref["byte_offset"] >= 0
            assert "raw_file" in ref
            assert ref["record_length"] > 0


# -----------------------------------------------------------------------------
# 14. Critical Overlap Audit Test (RULE-002 & RULE-004 Campaign Guard)
# -----------------------------------------------------------------------------

def test_r2_r4_shared_hosts_not_classified_as_confirmed_campaign():
    """
    CRITICAL AUDIT INVARIANT:
    The 22 hosts sharing RULE-002 and RULE-004 must NOT be classified as a confirmed campaign.
    All behavioral sequence relationships must be INFERRED and LOW confidence.
    """
    alerts = []
    for i in range(22):
        hname = f"WS-TEST-{i:02d}"
        alerts.append(make_alert("RULE-002", hname, f"user{i}", f"r2-{i}", kill_chain_stage="Execution"))
        alerts.append(make_alert("RULE-004", hname, f"user{i}", f"r4-{i}", kill_chain_stage="Persistence"))

    engine = CorrelationEngine(alerts=alerts)
    results = engine.run()

    for rel in results["relationships"]:
        # Assert no relationship claims confirmed campaign or confirmed compromise
        assert "confirmed campaign" not in rel["explanation"].lower()
        assert "confirmed compromise" not in rel["explanation"].lower()

        # If behavioral sequence, must be INFERRED and LOW
        if rel["relationship_type"] == RelationshipType.POTENTIAL_BEHAVIORAL_SEQUENCE:
            assert rel["observed_or_inferred"] == ObservationStatus.INFERRED
            assert rel["confidence"] == ConfidenceLevel.LOW


# -----------------------------------------------------------------------------
# 15. Cross-Source FortiGate Integration Tests
# -----------------------------------------------------------------------------

def test_cross_source_fortigate_integration():
    """Verify cross-source correlation matches EDR and FortiGate on IP, and reports limitation if missing."""
    # Positive: Valid mock FortiGate log record matching EDR alert source IP
    edr_alert = make_alert("RULE-001", "SRV-DC-01", "admin", "edr-1", source_ip="198.51.100.23")
    mock_fg = [
        {
            "event_id": "fg-traffic-101",
            "source_ip": "198.51.100.23",
            "destination_ip": "10.0.1.10",
            "timestamp": "2026-10-31T12:39:55.000000+05:30",
            "raw_file": "firex-10G.log",
            "byte_offset": 4500,
            "record_length": 180,
        }
    ]

    engine = CorrelationEngine(alerts=[edr_alert], fortigate_records=mock_fg)
    results = engine.run()

    cross_rels = [r for r in results["relationships"] if r["relationship_type"] == RelationshipType.CROSS_SOURCE_NETWORK_MATCH]
    assert len(cross_rels) == 1
    rel = cross_rels[0]
    assert rel["correlation_dimension"] == CorrelationDimension.CROSS_SOURCE
    assert rel["evidence"]["matched_ip"] == "198.51.100.23"
    assert "fg-traffic-101" in rel["supporting_event_ids"]

    # Negative: Without FortiGate records, cleanly reports limitation without crashing
    engine_empty = CorrelationEngine(alerts=[edr_alert])
    results_empty = engine_empty.run()
    cross_empty = [r for r in results_empty["relationships"] if r["relationship_type"] == RelationshipType.CROSS_SOURCE_NETWORK_MATCH]
    assert len(cross_empty) == 0


# -----------------------------------------------------------------------------
# 16. End-to-End Integration Test against Real Phase 2 Alerts
# -----------------------------------------------------------------------------

def test_full_phase3_pipeline_on_real_alerts():
    """Run full correlation engine against the actual reports/phase2_alerts.json export."""
    alerts_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports", "phase2_alerts.json")
    if not os.path.isfile(alerts_file):
        pytest.skip("reports/phase2_alerts.json not found")

    engine = CorrelationEngine(alerts_file=alerts_file)
    results = engine.run()

    assert results["metadata"]["total_alerts_evaluated"] == 90
    assert results["entity_summary"]["unique_hosts"] == 28
    assert results["entity_summary"]["unique_users"] == 12

    # Check dimension presence
    by_dim = results["relationship_metrics"]["by_dimension"]
    assert "host" in by_dim
    assert "user" in by_dim
    assert "network" in by_dim
    assert "process" in by_dim
    assert "temporal" in by_dim
    assert "behavioral" in by_dim

    # Check confidence breakdown
    by_conf = results["relationship_metrics"]["by_confidence"]
    assert "LOW" in by_conf
    assert "MEDIUM" in by_conf

    # Check that NO relationship overclaims confirmed compromise
    for rel in results["relationships"]:
        assert "confirmed compromise" not in rel["explanation"].lower()
        assert "confirmed campaign" not in rel["explanation"].lower()


# -----------------------------------------------------------------------------
# 17. Phase 3.1 Audit Negative Tests & Integrity Invariants
# -----------------------------------------------------------------------------

def test_cross_host_same_user_does_not_merge_investigation_clusters():
    """
    NEGATIVE TEST: Prove randomly shared usernames do not merge unrelated investigation clusters.
    Two alerts on different hosts sharing a username must be marked ineligible for investigation clustering.
    """
    a1 = make_alert("RULE-002", "WS-HR-01", "common_user", "a1")
    a2 = make_alert("RULE-004", "WS-FIN-02", "common_user", "a2")

    engine = CorrelationEngine(alerts=[a1, a2])
    results = engine.run()

    user_rels = [r for r in results["relationships"] if r["relationship_type"] == RelationshipType.SAME_USER]
    assert len(user_rels) == 1
    rel = user_rels[0]
    assert rel["is_investigation_eligible"] is False
    assert rel["evidence"]["same_host"] is False

    # In raw components, they are connected via user
    raw_comps = [c for c in results["graph"]["components"] if c["has_alerts"]]
    assert len(raw_comps) == 1

    # In investigation components, they MUST remain strictly disconnected
    inv_comps = [c for c in results["graph"]["investigation_components"] if c["has_alerts"]]
    assert len(inv_comps) == 2, "Cross-host username match must NOT merge distinct host investigation clusters"


def test_same_process_image_with_different_pids_is_not_same_process():
    """
    NEGATIVE TEST: Prove same process image with different PIDs is NOT classified as SAME_PROCESS.
    Only matching PIDs may be classified as SAME_PROCESS.
    """
    # a1 and a2 have same image, different PIDs
    a1 = make_alert("RULE-002", "WS-01", "alice", "a1", process_name="powershell.exe", process_id=1001)
    a2 = make_alert("RULE-004", "WS-01", "alice", "a2", process_name="powershell.exe", process_id=2002)
    # a3 has same image AND same PID as a1
    a3 = make_alert("RULE-004", "WS-01", "alice", "a3", process_name="powershell.exe", process_id=1001)

    extractor = EntityExtractor([a1, a2, a3])
    correlator = ProcessCorrelator()
    rels = correlator.correlate(extractor)

    # Check pair (a1, a2)
    a1_a2 = [r for r in rels if {r.source_observation_id, r.target_observation_id} == {"a1", "a2"}]
    assert len(a1_a2) == 1
    assert a1_a2[0].relationship_type == RelationshipType.SAME_PROCESS_IMAGE
    assert a1_a2[0].confidence == ConfidenceLevel.MEDIUM
    assert a1_a2[0].evidence["same_pid"] is False

    # Check pair (a1, a3)
    a1_a3 = [r for r in rels if {r.source_observation_id, r.target_observation_id} == {"a1", "a3"}]
    assert len(a1_a3) == 1
    assert a1_a3[0].relationship_type == RelationshipType.SAME_PROCESS
    assert a1_a3[0].confidence == ConfidenceLevel.HIGH
    assert a1_a3[0].evidence["same_pid"] is True


def test_same_host_temporal_proximity_does_not_establish_attack_sequence():
    """
    NEGATIVE TEST: Prove same-host temporal proximity alone does NOT establish a behavioral attack sequence.
    RULE-001 (failed logon) and RULE-005 (ransomware file rename) on SRV-DC-01 5ms apart without process
    or credential link must produce 0 behavioral sequences.
    """
    t1 = "2026-10-31T12:39:55.000000+05:30"
    t2 = "2026-10-31T12:39:55.005000+05:30"
    a1 = make_alert("RULE-001", "SRV-DC-01", "johndoe", "a1", first_seen=t1, process_name="lsass.exe", process_id=500, kill_chain_stage="Credential Access")
    a2 = make_alert("RULE-005", "SRV-DC-01", "administrator", "a2", first_seen=t2, process_name="unknown.exe", process_id=900, kill_chain_stage="Actions on Objectives")

    engine = CorrelationEngine(alerts=[a1, a2])
    results = engine.run()

    # Behavioral sequence must be rejected
    seq_rels = [r for r in results["relationships"] if r["relationship_type"] == RelationshipType.POTENTIAL_BEHAVIORAL_SEQUENCE]
    assert len(seq_rels) == 0, "Unevidenced failed logon to file rename must NOT be synthesized into an attack sequence"

    # Temporal co-occurrence is recorded but marked ineligible for investigation clustering
    temp_rels = [r for r in results["relationships"] if r["relationship_type"] == RelationshipType.TEMPORALLY_NEAR]
    assert len(temp_rels) == 1
    assert temp_rels[0]["confidence"] == ConfidenceLevel.LOW
    assert temp_rels[0]["is_investigation_eligible"] is False


def test_test_net_addresses_are_not_real_attacker_infrastructure():
    """
    NEGATIVE TEST: Prove TEST-NET documentation addresses are NOT classified as real attacker infrastructure.
    Multiple hosts targeting a TEST-NET IP must receive LOW confidence and be ineligible for investigation clustering.
    """
    a1 = make_alert("RULE-001", "SRV-01", "u1", "a1", source_ip="198.51.100.23")
    a2 = make_alert("RULE-001", "SRV-02", "u2", "a2", source_ip="198.51.100.23")
    a3 = make_alert("RULE-001", "SRV-03", "u3", "a3", source_ip="198.51.100.23")

    engine = CorrelationEngine(alerts=[a1, a2, a3])
    results = engine.run()

    ip_rels = [r for r in results["relationships"] if r["relationship_type"] == RelationshipType.SAME_SOURCE_IP]
    assert len(ip_rels) == 3
    for r in ip_rels:
        assert r["confidence"] == ConfidenceLevel.LOW
        assert r["is_investigation_eligible"] is False
        assert "TEST-NET" in r["explanation"]

    # In investigation components, the 3 servers must NOT be merged
    inv_comps = [c for c in results["graph"]["investigation_components"] if c["has_alerts"]]
    assert len(inv_comps) == 3


def test_missing_pid_ppid_linkage_does_not_produce_process_ancestry():
    """
    NEGATIVE TEST: Prove missing or mismatched PID-to-PPID linkage does NOT produce process ancestry.
    """
    p1 = make_alert("RULE-002", "WS-01", "user", "p1", process_name="winword.exe", process_id=1234)
    c1 = make_alert("RULE-002", "WS-01", "user", "c1", process_name="cmd.exe", process_id=5678, parent_process_id=9999)

    extractor = EntityExtractor([p1, c1])
    correlator = ProcessCorrelator()
    rels = correlator.correlate(extractor)

    pc_rels = [r for r in rels if r.relationship_type == RelationshipType.PARENT_CHILD_PROCESS]
    assert len(pc_rels) == 0, "Mismatched PPID must not produce PARENT_CHILD_PROCESS"


def test_public_ip_multi_target_does_not_receive_high_confidence():
    """
    NEGATIVE TEST: A public IP targeting >= 3 hosts must NOT receive HIGH confidence solely due to target count.
    Shared IP alone without authenticated C2 telemetry remains at most MEDIUM confidence.
    """
    conf, exp = evaluate_confidence(
        rel_type=RelationshipType.SAME_SOURCE_IP,
        dimension=CorrelationDimension.NETWORK,
        evidence={"ip": "8.8.8.8", "is_test_net": False, "is_public": True, "target_count": 5},
    )
    assert conf == ConfidenceLevel.MEDIUM, f"Expected MEDIUM, got {conf}"
    assert "do not independently establish malicious intent" in exp


def test_provenance_verification_detects_corrupted_offsets_and_records(tmp_path):
    """
    NEGATIVE TEST: Prove provenance verification actively detects corrupted offsets, truncated lengths,
    and mismatched event IDs rather than silently succeeding.
    """
    raw_content = b'{"event_id": "test-uuid-001", "event_type": "process_creation"}\n'
    test_file = tmp_path / "test_events.json"
    test_file.write_bytes(raw_content)

    # 1. Valid reference should pass
    valid_alert = make_alert("RULE-002", "WS-01", "user", "a1", evidence_references=[
        {"event_id": "test-uuid-001", "raw_file": str(test_file), "byte_offset": 0, "record_length": len(raw_content)}
    ])
    engine_valid = CorrelationEngine(alerts=[valid_alert])
    engine_valid.run()
    res_valid = engine_valid.verify_all_provenance(str(test_file))
    assert res_valid["verified"] == 1
    assert res_valid["failed"] == 0

    # 2. Corrupted byte offset should fail
    corrupt_offset_alert = make_alert("RULE-002", "WS-01", "user", "a2", evidence_references=[
        {"event_id": "test-uuid-001", "raw_file": str(test_file), "byte_offset": 99999, "record_length": len(raw_content)}
    ])
    engine_bad_offset = CorrelationEngine(alerts=[corrupt_offset_alert])
    engine_bad_offset.run()
    res_bad_offset = engine_bad_offset.verify_all_provenance(str(test_file))
    assert res_bad_offset["failed"] == 1
    assert "seek error" in res_bad_offset["failure_details"][0]["reason"]

    # 3. Mismatched event ID should fail
    mismatched_id_alert = make_alert("RULE-002", "WS-01", "user", "a3", evidence_references=[
        {"event_id": "different-uuid-999", "raw_file": str(test_file), "byte_offset": 0, "record_length": len(raw_content)}
    ])
    engine_bad_id = CorrelationEngine(alerts=[mismatched_id_alert])
    engine_bad_id.run()
    res_bad_id = engine_bad_id.verify_all_provenance(str(test_file))
    assert res_bad_id["failed"] == 1
    assert "event_id mismatch" in res_bad_id["failure_details"][0]["reason"]


def test_exhaustive_provenance_verification_on_actual_dataset():
    """
    EXHAUSTIVE PROVENANCE TEST: Verify all 364 underlying evidence references against edr_events.json.
    Must achieve 100% resolution with 0 failures and 0 duplicates.
    """
    alerts_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports", "phase2_alerts.json")
    raw_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), "edr_events.json")

    if not os.path.isfile(alerts_file) or not os.path.isfile(raw_file):
        pytest.skip("Dataset files not found")

    engine = CorrelationEngine(alerts_file=alerts_file)
    engine.run()
    prov_result = engine.verify_all_provenance(raw_file)

    assert prov_result["total_unique_references"] == 364
    assert prov_result["verified"] == 364
    assert prov_result["failed"] == 0
    assert prov_result["unresolvable"] == 0
    assert prov_result["success_rate_pct"] == 100.0

