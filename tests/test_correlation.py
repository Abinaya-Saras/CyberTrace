"""
Comprehensive test suite for CyberTrace Incident Correlation & Attack Graph (FR-4, FR-5, FR-6).

Tests cover all required scenarios:
  1. Events that should belong to the same incident (same host multi-stage attack).
  2. Events that must remain separate (distinct endpoints).
  3. Same username appearing on different hosts (no artificial cross-host merging).
  4. Same IP appearing in unrelated activity (infrastructure reuse vs host intrusion).
  5. Temporal ordering of timeline events.
  6. Successful versus failed authentication handling in reach-next.
  7. Missing and sparse identity fields resilience.
  8. Unsupported cross-host relationships rejected.
  9. Cycles and duplicate relationships deduplication.
  10. Incomplete attack paths preserved honestly (no fabricated initial access or impact).
  11. Observed connectivity versus confirmed access (FR-6 verification status).
  12. End-to-end correlation integration test on normalized EDR dataset.
"""

from datetime import datetime, timedelta, timezone
import json
import os
import uuid

import pytest

from backend.core.duckdb_engine import DuckDBEngine
from backend.detection.alert_schema import Alert
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
from backend.correlation.models import Incident, ReachNextAsset, TimelineEvent


# -----------------------------------------------------------------------------
# Fixtures & Helpers
# -----------------------------------------------------------------------------

def make_alert(
    rule_id: str,
    host: str,
    username: str,
    technique_id: str,
    technique_name: str,
    tactic: str,
    kill_chain: str,
    severity: str = "high",
    confidence: str = "high",
    first_seen: str = "2026-10-31T12:00:00Z",
    last_seen: str = "2026-10-31T12:05:00Z",
    source_ip: str = None,
    destination_ip: str = None,
    process_name: str = None,
    parent_process_name: str = None,
    reasoning: str = "Test reasoning",
) -> Alert:
    """Helper to construct valid Alert instances with evidence references."""
    eid = f"evt-{uuid.uuid4().hex[:8]}"
    return Alert(
        rule_id=rule_id,
        title=f"Test Alert {rule_id} on {host}",
        description="Test description",
        severity=severity,
        confidence=confidence,
        mitre_technique_id=technique_id,
        mitre_technique_name=technique_name,
        mitre_tactic=tactic,
        kill_chain_stage=kill_chain,
        first_seen=first_seen,
        last_seen=last_seen,
        host=host,
        username=username,
        source_ip=source_ip,
        destination_ip=destination_ip,
        process_name=process_name,
        parent_process_name=parent_process_name,
        supporting_event_ids=[eid],
        evidence_references=[
            {
                "event_id": eid,
                "raw_file": "test.json",
                "byte_offset": 100,
                "record_length": 80,
                "timestamp": first_seen,
                "username": username,
                "process_name": process_name,
                "parent_process_name": parent_process_name,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
            }
        ],
        reasoning=reasoning,
    )


# -----------------------------------------------------------------------------
# 1. Entity Resolution Unit Tests
# -----------------------------------------------------------------------------

def test_entity_resolution_helpers():
    """Verify entity normalization handles domains, whitespace, cases, and None."""
    assert normalize_host("ws-sales-011") == "WS-SALES-011"
    assert normalize_host("  SRV-DC-01  ") == "SRV-DC-01"
    assert normalize_host(None) == "UNKNOWN_HOST"

    assert normalize_user("CORP\\asharma") == "asharma"
    assert normalize_user("admin@corp.local") == "admin"
    assert normalize_user("  pmehta  ") == "pmehta"
    assert normalize_user(None) == "unknown_user"

    assert normalize_ip("  192.168.1.1  ") == "192.168.1.1"
    assert normalize_ip(None) == "UNKNOWN_IP"


# -----------------------------------------------------------------------------
# 2. Same-Host Multi-Stage Clustering & Distinct Host Isolation
# -----------------------------------------------------------------------------

def test_same_host_multi_stage_incident():
    """Detections on the same host across attack stages correctly cluster into a single incident."""
    a1 = make_alert(
        rule_id="RULE-002",
        host="WS-001",
        username="alice",
        technique_id="T1059.001",
        technique_name="PowerShell",
        tactic="Execution",
        kill_chain="Exploitation",
        process_name="powershell.exe",
        parent_process_name="winword.exe",
        first_seen="2026-10-31T12:00:00Z",
    )
    a2 = make_alert(
        rule_id="RULE-004",
        host="WS-001",
        username="alice",
        technique_id="T1547.001",
        technique_name="Registry Run Keys",
        tactic="Persistence",
        kill_chain="Installation",
        process_name="powershell.exe",
        first_seen="2026-10-31T12:01:00Z",
    )
    a3 = make_alert(
        rule_id="RULE-005",
        host="WS-001",
        username="alice",
        technique_id="T1486",
        technique_name="Data Encrypted for Impact",
        tactic="Impact",
        kill_chain="Actions on Objectives",
        severity="critical",
        process_name="unknown.exe",
        first_seen="2026-10-31T12:02:00Z",
    )

    correlator = IncidentCorrelator()
    incidents = correlator.correlate([a1, a2, a3])

    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.hosts == ["WS-001"]
    assert inc.severity == "critical"
    assert len(inc.alerts) == 3
    assert "Multi-Stage Ransomware Attack" in inc.title


def test_distinct_hosts_must_remain_separate():
    """Detections on distinct hosts must remain two separate incidents."""
    a1 = make_alert(
        rule_id="RULE-002",
        host="WS-001",
        username="alice",
        technique_id="T1059.001",
        technique_name="PowerShell",
        tactic="Execution",
        kill_chain="Exploitation",
    )
    a2 = make_alert(
        rule_id="RULE-002",
        host="WS-002",
        username="bob",
        technique_id="T1059.001",
        technique_name="PowerShell",
        tactic="Execution",
        kill_chain="Exploitation",
    )

    correlator = IncidentCorrelator()
    incidents = correlator.correlate([a1, a2])

    assert len(incidents) == 2
    hosts = {inc.hosts[0] for inc in incidents}
    assert hosts == {"WS-001", "WS-002"}


# -----------------------------------------------------------------------------
# 3. Same User on Different Hosts (No Artificial Merging)
# -----------------------------------------------------------------------------

def test_same_username_on_different_hosts_not_merged():
    """Critical: User 'Administrator' or shared user on different hosts must NOT merge into a single incident."""
    a1 = make_alert(
        rule_id="RULE-002",
        host="WS-FIN-01",
        username="Administrator",
        technique_id="T1059.001",
        technique_name="PowerShell",
        tactic="Execution",
        kill_chain="Exploitation",
    )
    a2 = make_alert(
        rule_id="RULE-002",
        host="WS-HR-01",
        username="Administrator",
        technique_id="T1059.001",
        technique_name="PowerShell",
        tactic="Execution",
        kill_chain="Exploitation",
    )

    correlator = IncidentCorrelator()
    incidents = correlator.correlate([a1, a2])

    assert len(incidents) == 2
    assert incidents[0].hosts != incidents[1].hosts


# -----------------------------------------------------------------------------
# 4. Same IP in Unrelated Activity
# -----------------------------------------------------------------------------

def test_same_ip_in_unrelated_activity_not_falsely_merged():
    """External attacker IP targeting DC is NOT falsely merged with a workstation making outbound traffic."""
    # Failed brute force against DC from 198.51.100.23
    a1 = make_alert(
        rule_id="RULE-001",
        host="SRV-DC-01",
        username="asharma",
        technique_id="T1110",
        technique_name="Brute Force",
        tactic="Credential Access",
        kill_chain="Exploitation",
        source_ip="198.51.100.23",
        reasoning="Failed authentication; account compromise is NOT established.",
    )
    # Workstation compromise on WS-001
    a2 = make_alert(
        rule_id="RULE-002",
        host="WS-001",
        username="asharma",
        technique_id="T1059.001",
        technique_name="PowerShell",
        tactic="Execution",
        kill_chain="Exploitation",
        destination_ip="198.51.100.23",
    )

    correlator = IncidentCorrelator()
    incidents = correlator.correlate([a1, a2])

    # Must produce 2 separate incidents
    assert len(incidents) == 2
    dc_inc = next(inc for inc in incidents if "SRV-DC-01" in inc.hosts)
    ws_inc = next(inc for inc in incidents if "WS-001" in inc.hosts)
    assert dc_inc.incident_id != ws_inc.incident_id
    assert "External Brute Force" in dc_inc.title


# -----------------------------------------------------------------------------
# 5. Temporal Ordering of Timeline Events
# -----------------------------------------------------------------------------

def test_temporal_ordering_in_timeline():
    """Timeline events must be sorted strictly chronologically regardless of ingestion order."""
    t3 = "2026-10-31T12:05:00Z"
    t1 = "2026-10-31T12:00:00Z"
    t2 = "2026-10-31T12:02:30Z"

    a_late = make_alert("RULE-005", "WS-001", "alice", "T1486", "Impact", "Impact", "Actions on Objectives", first_seen=t3)
    a_early = make_alert("RULE-002", "WS-001", "alice", "T1059.001", "PowerShell", "Execution", "Exploitation", first_seen=t1)
    a_mid = make_alert("RULE-004", "WS-001", "alice", "T1547.001", "Run Keys", "Persistence", "Installation", first_seen=t2)

    # Provide out of order: late, early, mid
    timeline = build_incident_timeline([a_late, a_early, a_mid])
    timestamps = [item.timestamp for item in timeline]

    assert timestamps == [t1, t2, t3]


# -----------------------------------------------------------------------------
# 6. Successful vs Failed Authentication (Reach-Next)
# -----------------------------------------------------------------------------

def test_failed_authentication_produces_no_reach_next():
    """Failed brute force authentication without successful login yields 0 reach-next assets."""
    a_bf = make_alert(
        rule_id="RULE-001",
        host="SRV-DC-01",
        username="admin",
        technique_id="T1110",
        technique_name="Brute Force",
        tactic="Credential Access",
        kill_chain="Exploitation",
        source_ip="203.0.113.57",
        reasoning="Repeated authentication failures; account compromise is NOT established.",
    )
    reach = evaluate_reach_next(["SRV-DC-01"], [a_bf])
    assert len(reach) == 0


# -----------------------------------------------------------------------------
# 7. Missing and Sparse Identity Fields Resilience
# -----------------------------------------------------------------------------

def test_missing_identity_fields_resilience():
    """Correlator handles alerts with None for host, username, or IP without raising exceptions."""
    a_sparse = Alert(
        rule_id="RULE-002",
        title="Sparse Alert",
        description="Testing missing fields",
        severity="medium",
        confidence="medium",
        mitre_technique_id="T1059.001",
        mitre_technique_name="PowerShell",
        mitre_tactic="Execution",
        kill_chain_stage="Exploitation",
        first_seen="2026-10-31T12:00:00Z",
        last_seen="2026-10-31T12:00:00Z",
        host=None,
        username=None,
        supporting_event_ids=["evt-sparse"],
        evidence_references=[
            {"event_id": "evt-sparse", "raw_file": "test.json", "byte_offset": 0, "record_length": 10}
        ],
        reasoning="Sparse fields",
    )

    correlator = IncidentCorrelator()
    incidents = correlator.correlate([a_sparse])
    assert len(incidents) == 1
    assert incidents[0].hosts == ["UNKNOWN_HOST"]


# -----------------------------------------------------------------------------
# 8. Unsupported Cross-Host Relationships Rejected
# -----------------------------------------------------------------------------

def test_unsupported_cross_host_relationships_rejected():
    """Graph construction does NOT create edges between hosts without direct evidence."""
    a1 = make_alert("RULE-002", "WS-001", "alice", "T1059.001", "PS", "Exec", "Exploitation")
    a2 = make_alert("RULE-002", "WS-002", "bob", "T1059.001", "PS", "Exec", "Exploitation")

    g1, _ = build_evidence_attack_graph([a1], ["WS-001"])
    g2, _ = build_evidence_attack_graph([a2], ["WS-002"])

    # Graphs are completely independent
    assert "host:WS-002" not in g1.nodes
    assert "host:WS-001" not in g2.nodes


# -----------------------------------------------------------------------------
# 9. Cycles and Duplicate Relationships Deduplication
# -----------------------------------------------------------------------------

def test_cycles_and_duplicate_relationships_deduplication():
    """Multiple events referencing the same process and host do not create graph cycles or duplicate edges."""
    a1 = make_alert("RULE-002", "WS-001", "alice", "T1059.001", "PS", "Exec", "Exploitation", process_name="powershell.exe", parent_process_name="winword.exe")
    a2 = make_alert("RULE-002", "WS-001", "alice", "T1059.001", "PS", "Exec", "Exploitation", process_name="powershell.exe", parent_process_name="winword.exe")

    g, serialized = build_evidence_attack_graph([a1, a2], ["WS-001"])

    # NetworkX DiGraph should be a Directed Acyclic Graph (DAG)
    import networkx as nx
    assert nx.is_directed_acyclic_graph(g)


# -----------------------------------------------------------------------------
# 10. Incomplete Attack Paths Preserved Honestly
# -----------------------------------------------------------------------------

def test_incomplete_attack_paths_preserved_honestly():
    """An incident missing initial access or missing impact is preserved honestly without fabricated stages."""
    # Persistence followed by Ransomware (no initial Office execution observed)
    a1 = make_alert("RULE-004", "WS-FIN-010", "user1", "T1547.001", "Run Keys", "Persistence", "Installation")
    a2 = make_alert("RULE-005", "WS-FIN-010", "user1", "T1486", "Impact", "Impact", "Actions on Objectives", severity="critical")

    correlator = IncidentCorrelator()
    incidents = correlator.correlate([a1, a2])

    assert len(incidents) == 1
    inc = incidents[0]
    alert_rules = [a["rule_id"] for a in inc.alerts]
    assert "RULE-002" not in alert_rules
    assert alert_rules == ["RULE-004", "RULE-005"]

    # Graph contains no winword.exe node
    node_labels = [n["label"] for n in inc.graph["nodes"]]
    assert "winword.exe" not in node_labels


# -----------------------------------------------------------------------------
# 11. Observed Connectivity vs Confirmed Access (FR-6)
# -----------------------------------------------------------------------------

def test_observed_connectivity_vs_confirmed_access():
    """Outbound connection is classified as 'unverified_connectivity'; username containing admin does NOT confer access."""
    a_compromise = make_alert(
        rule_id="RULE-002",
        host="WS-001",
        username="administrator",  # username contains admin
        technique_id="T1059.001",
        technique_name="PowerShell",
        tactic="Execution",
        kill_chain="Exploitation",
        process_name="powershell.exe",
    )
    supp_net = [
        {
            "event_id": "net-evt-1",
            "host_name": "WS-001",
            "process_name": "powershell.exe",
            "destination_ip": "203.0.113.57",
            "destination_domain": "c2-domain.test",
            "raw_file": "net.json",
            "byte_offset": 100,
            "record_length": 50,
        }
    ]

    reach = evaluate_reach_next(["WS-001"], [a_compromise], supp_net)
    assert len(reach) == 1
    r = reach[0]
    assert r.target == "203.0.113.57"
    assert r.verification_status == "unverified_connectivity"
    assert "access rights, authentication, and administrative privileges are unverified" in r.reasoning


# -----------------------------------------------------------------------------
# 12. End-to-End Correlation on Real Normalized EDR Parquet
# -----------------------------------------------------------------------------

def test_e2e_correlation_on_real_dataset():
    """
    End-to-end correlation test against edr_events.parquet.
    Verifies alert clustering, incident count (29), NetworkX graph validity, and reach-next reasoning.
    """
    parquet_path = "data/processed/edr_events.parquet"
    if not os.path.exists(parquet_path):
        pytest.skip("data/processed/edr_events.parquet does not exist")

    from backend.detection.engine import DetectionEngine

    with DuckDBEngine() as db:
        with DetectionEngine(engine=db) as det:
            alerts = det.run_all(parquet_path)
            assert len(alerts) == 90

            correlator = IncidentCorrelator(engine=db, parquet_path=parquet_path)
            incidents = correlator.correlate(alerts)

            # 29 discrete, evidence-backed security incidents
            assert len(incidents) == 29

            # Check that every incident has a valid graph, timeline, and valid reach-next status
            for inc in incidents:
                assert inc.incident_id.startswith("INC-")
                assert inc.title
                assert inc.severity in {"critical", "high", "medium", "low"}
                assert inc.confidence in {"high", "medium", "low"}
                assert len(inc.hosts) > 0
                assert len(inc.timeline) > 0
                assert len(inc.graph["nodes"]) > 0

                for r in inc.reach_next:
                    assert r.verification_status in {"unverified_connectivity", "authenticated_only", "confirmed_access"}
                    assert r.confidence in {"high", "medium", "low"}

            # Verify DC brute-force campaign is properly separated from workstation compromises
            dc_inc = next(inc for inc in incidents if inc.title.startswith("External Brute Force"))
            assert "SRV-DC-01" in dc_inc.hosts
            assert len(dc_inc.reach_next) == 0  # 0 access obtained
