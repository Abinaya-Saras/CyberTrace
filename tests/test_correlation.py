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
  9. Cycles and duplicate relationships deduplication with DAG enforcement.
  10. Incomplete attack paths preserved honestly (no fabricated initial access or impact).
  11. Process node identity by PID: two PowerShell instances with different PIDs remain distinct nodes.
  12. Genuine parent-child process ancestry preservation (WinWord -> PowerShell).
  13. Observed external network activity versus internal reachable assets (FR-6 semantics).
  14. Complete end-to-end correlation and exact alert accounting on normalized EDR dataset.
"""

from datetime import datetime, timedelta, timezone
import json
import os
import uuid

import networkx as nx
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
    process_id: int = None,
    parent_process_name: str = None,
    parent_process_id: int = None,
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
        process_id=process_id,
        parent_process_name=parent_process_name,
        parent_process_id=parent_process_id,
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
                "process_id": process_id,
                "parent_process_name": parent_process_name,
                "parent_process_id": parent_process_id,
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
        process_id=1001,
        parent_process_name="winword.exe",
        parent_process_id=500,
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
        process_id=1001,
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
        process_id=2001,
        first_seen="2026-10-31T12:02:00Z",
    )

    correlator = IncidentCorrelator()
    incidents = correlator.correlate([a1, a2, a3])

    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.hosts == ["WS-001"]
    assert inc.severity == "critical"
    assert len(inc.alerts) == 3
    assert "Multi-Stage Suspicious Activity Cluster" in inc.title


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

    assert "host:WS-002" not in g1.nodes
    assert "host:WS-001" not in g2.nodes


# -----------------------------------------------------------------------------
# 9. Cycles and Duplicate Relationships Deduplication with DAG Enforcement
# -----------------------------------------------------------------------------

def test_cycles_and_duplicate_relationships_dag_enforcement():
    """Multiple events referencing the same process and host do not create graph cycles; DAG is enforced."""
    a1 = make_alert("RULE-002", "WS-001", "alice", "T1059.001", "PS", "Exec", "Exploitation", process_name="powershell.exe", process_id=1001, parent_process_name="winword.exe", parent_process_id=500)
    a2 = make_alert("RULE-002", "WS-001", "alice", "T1059.001", "PS", "Exec", "Exploitation", process_name="powershell.exe", process_id=1001, parent_process_name="winword.exe", parent_process_id=500)

    g, serialized = build_evidence_attack_graph([a1, a2], ["WS-001"])
    assert nx.is_directed_acyclic_graph(g)


# -----------------------------------------------------------------------------
# 10. Incomplete Attack Paths Preserved Honestly
# -----------------------------------------------------------------------------

def test_incomplete_attack_paths_preserved_honestly():
    """An incident missing initial access or missing impact is preserved honestly without fabricated stages."""
    a1 = make_alert("RULE-004", "WS-FIN-010", "user1", "T1547.001", "Run Keys", "Persistence", "Installation")
    a2 = make_alert("RULE-005", "WS-FIN-010", "user1", "T1486", "Impact", "Impact", "Actions on Objectives", severity="critical")

    correlator = IncidentCorrelator()
    incidents = correlator.correlate([a1, a2])

    assert len(incidents) == 1
    inc = incidents[0]
    alert_rules = [a["rule_id"] for a in inc.alerts]
    assert "RULE-002" not in alert_rules
    assert alert_rules == ["RULE-004", "RULE-005"]

    node_labels = [n["label"] for n in inc.graph["nodes"]]
    assert not any("winword" in l.lower() for l in node_labels)


# -----------------------------------------------------------------------------
# 11. Process Node Identity by PID & Genuine Ancestry
# -----------------------------------------------------------------------------

def test_process_node_identity_distinct_pids():
    """Two PowerShell executions with different PIDs (PID 1001 vs PID 2002) remain distinct nodes in the graph."""
    # Construct an alert with two distinct PowerShell executions under different PIDs
    ref1 = {
        "event_id": "evt-ps-1",
        "raw_file": "proc.json",
        "byte_offset": 100,
        "record_length": 50,
        "timestamp": "2026-10-31T12:00:00Z",
        "process_name": "powershell.exe",
        "process_id": 1001,
        "parent_process_name": "winword.exe",
        "parent_process_id": 500,
    }
    ref2 = {
        "event_id": "evt-ps-2",
        "raw_file": "proc.json",
        "byte_offset": 200,
        "record_length": 50,
        "timestamp": "2026-10-31T12:00:05Z",
        "process_name": "powershell.exe",
        "process_id": 2002,
        "parent_process_name": "excel.exe",
        "parent_process_id": 600,
    }
    alert = Alert(
        rule_id="RULE-002",
        title="Multiple Office Script Executions",
        description="Testing PID isolation",
        severity="high",
        confidence="high",
        mitre_technique_id="T1059.001",
        mitre_technique_name="PowerShell",
        mitre_tactic="Execution",
        kill_chain_stage="Exploitation",
        first_seen="2026-10-31T12:00:00Z",
        last_seen="2026-10-31T12:00:05Z",
        host="WS-001",
        username="alice",
        supporting_event_ids=["evt-ps-1", "evt-ps-2"],
        evidence_references=[ref1, ref2],
        reasoning="Multiple executions",
    )

    g, serialized = build_evidence_attack_graph([alert], ["WS-001"])

    # Must contain both distinct process nodes
    node_ids = set(g.nodes)
    assert "proc:WS-001:powershell.exe:1001" in node_ids
    assert "proc:WS-001:powershell.exe:2002" in node_ids

    # Must preserve genuine parent-child process relationships
    assert g.has_edge("proc:WS-001:winword.exe:500", "proc:WS-001:powershell.exe:1001")
    assert g.has_edge("proc:WS-001:excel.exe:600", "proc:WS-001:powershell.exe:2002")
    assert g.edges["proc:WS-001:winword.exe:500", "proc:WS-001:powershell.exe:1001"]["relationship_type"] == "SPAWNED_PROCESS"
    assert g.edges["proc:WS-001:winword.exe:500", "proc:WS-001:powershell.exe:1001"]["is_observed"] is True

    # Graph remains a strict DAG
    assert nx.is_directed_acyclic_graph(g)


# -----------------------------------------------------------------------------
# 12. Reach-Next Semantics: External Outbound vs Internal Pivot
# -----------------------------------------------------------------------------

def test_reach_next_semantics_external_vs_internal():
    """External destination is classified as 'observed_outbound_activity', NOT reachable next asset."""
    a_comp = make_alert(
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
        # Observed outbound destination (RFC 5737 test address)
        {
            "event_id": "net-ext-1",
            "host_name": "WS-001",
            "process_name": "powershell.exe",
            "destination_ip": "203.0.113.57",
            "destination_domain": "external-example.test",
            "raw_file": "net.json",
            "byte_offset": 100,
            "record_length": 50,
        },
        # Internal lateral IP
        {
            "event_id": "net-int-1",
            "host_name": "WS-001",
            "process_name": "powershell.exe",
            "destination_ip": "10.10.4.15",
            "destination_domain": None,
            "raw_file": "net.json",
            "byte_offset": 200,
            "record_length": 50,
        },
    ]

    reach = evaluate_reach_next(["WS-001"], [a_comp], supp_net)
    assert len(reach) == 2

    ext_r = next(r for r in reach if r.target == "203.0.113.57")
    assert ext_r.target_type == "reserved_documentation_ip"
    assert ext_r.relationship == "observed_outbound_destination"
    assert ext_r.verification_status == "outbound_connection_observed"
    assert "reserved documentation IP address range (RFC 5737" in ext_r.reasoning

    int_r = next(r for r in reach if r.target == "10.10.4.15")
    assert int_r.target_type == "internal_ip"
    assert int_r.relationship == "internal_network_connectivity_observed"
    assert int_r.verification_status == "internal_network_connectivity_observed"


# -----------------------------------------------------------------------------
# 13. End-to-End Correlation and Exact Accounting on Real Dataset
# -----------------------------------------------------------------------------

def test_e2e_correlation_and_exact_accounting():
    """
    End-to-end integration and accounting test against edr_events.parquet.
    Strictly verifies:
      - Total detected alerts = 571 (per-instance process separation)
      - Total incidents = 29
      - Total assigned alerts = 571 (0 unassigned)
      - All graphs are DAGs (Directed Acyclic Graphs)
      - Every edge has valid supporting evidence references
      - INC-002 on WS-SALES-013 regression requirements:
          * 18 alert records, 4 detection rules, 9 distinct users, 4 MITRE techniques
          * Process identity separation (8 PS, 3 registry, 5 file rename, 2 network PIDs)
          * Missing parent PID handling (unknown.exe file renames unparented, separate branch)
          * Observed vs inferred edges explicitly labeled
          * RFC 5737 reserved documentation IP classification (192.0.2.88, 203.0.113.57)
          * Plain-English report and executive story consistency
    """
    parquet_path = "data/processed/edr_events.parquet"
    if not os.path.exists(parquet_path):
        pytest.skip("data/processed/edr_events.parquet does not exist")

    from backend.detection.engine import DetectionEngine
    from backend.correlation.report_generator import generate_incident_report, generate_one_minute_story

    with DuckDBEngine() as db:
        with DetectionEngine(engine=db) as det:
            alerts = det.run_all(parquet_path)
            assert len(alerts) == 571

            correlator = IncidentCorrelator(engine=db, parquet_path=parquet_path)
            incidents = correlator.correlate(alerts)

            assert len(incidents) == 29

            # Reconcile alert accounting
            assigned_alert_ids = set()
            for inc in incidents:
                assigned_alert_ids.update(inc.alert_ids)
            assert len(assigned_alert_ids) == 571

            # Verify DAG topology and edge evidence on every incident
            for inc in incidents:
                g = nx.DiGraph()
                for n in inc.graph["nodes"]:
                    g.add_node(n["id"])
                for e in inc.graph["edges"]:
                    g.add_edge(e["source"], e["target"])
                    assert "relationship_type" in e
                    assert "weight" in e
                    assert "is_observed" in e
                    assert "is_inferred" in e
                    assert "evidence_references" in e

                assert nx.is_directed_acyclic_graph(g), f"Incident {inc.incident_id} graph is not a DAG!"

            # -----------------------------------------------------------------
            # Comprehensive Regression Suite for INC-002 on WS-SALES-013
            # -----------------------------------------------------------------
            inc_002 = next((i for i in incidents if i.incident_id == "INC-002"), None)
            assert inc_002 is not None, "INC-002 not found in correlated incidents!"
            assert inc_002.hosts == ["WS-SALES-013"]

            # 1. Evidence Accuracy & Counts
            assert len(inc_002.alerts) == 18, f"Expected 18 alerts, got {len(inc_002.alerts)}"
            assert len(inc_002.detection_rules) == 4
            assert set(inc_002.detection_rules) == {"RULE-002", "RULE-003", "RULE-004", "RULE-005"}
            assert len(inc_002.mitre_techniques) == 4
            assert set(inc_002.mitre_techniques) == {"T1059.001", "T1071.001", "T1486", "T1547.001"}
            assert len(inc_002.users) == 9
            expected_users = {"asharma", "dnair", "kiyer", "mkhan", "nverma", "pmehta", "rkumar", "sgupta", "vreddy"}
            assert set(inc_002.users) == expected_users

            # 2. Process-Level Separation
            ps_alerts = [a for a in inc_002.alerts if a["rule_id"] == "RULE-002"]
            reg_alerts = [a for a in inc_002.alerts if a["rule_id"] == "RULE-004"]
            file_alerts = [a for a in inc_002.alerts if a["rule_id"] == "RULE-005"]
            net_alerts = [a for a in inc_002.alerts if a["rule_id"] == "RULE-003"]

            assert len(ps_alerts) == 8, f"Expected 8 PS alerts, got {len(ps_alerts)}"
            assert len(reg_alerts) == 3, f"Expected 3 registry alerts, got {len(reg_alerts)}"
            assert len(file_alerts) == 5, f"Expected 5 file alerts, got {len(file_alerts)}"
            assert len(net_alerts) == 2, f"Expected 2 net alerts, got {len(net_alerts)}"

            ps_pids = {a.get("process_id") for a in ps_alerts}
            reg_pids = {a.get("process_id") for a in reg_alerts}
            file_pids = {a.get("process_id") for a in file_alerts}
            net_pids = {a.get("process_id") for a in net_alerts}

            assert len(ps_pids) == 8, f"Expected 8 distinct PS PIDs, got {len(ps_pids)}"
            assert len(reg_pids) == 3, f"Expected 3 distinct registry PIDs, got {len(reg_pids)}"
            assert len(file_pids) == 5, f"Expected 5 distinct file PIDs, got {len(file_pids)}"
            assert len(net_pids) == 2, f"Expected 2 distinct net PIDs, got {len(net_pids)}"

            # 3. Missing Parent PID Handling
            for fa in file_alerts:
                assert fa.get("parent_process_id") is None
                assert fa.get("parent_process_name") is None

            # Verify graph branches: unknown.exe has NO causal edge from powershell.exe
            for edge in inc_002.graph["edges"]:
                if edge["relationship_type"] == "SPAWNED_PROCESS":
                    assert not ("powershell" in edge["source"] and "unknown" in edge["target"])

            # 4. Observed vs Inferred Edges
            observed_edges = [e for e in inc_002.graph["edges"] if e.get("is_observed")]
            inferred_edges = [e for e in inc_002.graph["edges"] if e.get("is_inferred")]
            assert len(observed_edges) > 0
            assert len(inferred_edges) > 0

            # 5. Potential Next Access - RFC 5737 Classification
            assert len(inc_002.reach_next) == 2
            reach_targets = {r.target: r for r in inc_002.reach_next}
            assert "192.0.2.88" in reach_targets
            assert "203.0.113.57" in reach_targets
            for tgt in ["192.0.2.88", "203.0.113.57"]:
                r = reach_targets[tgt]
                assert r.target_type == "reserved_documentation_ip"
                assert r.verification_status == "outbound_connection_observed"
                assert "reserved documentation IP address range" in r.reasoning
                assert "NOT real external attacker infrastructure" in r.reasoning

            # 6. Report and Story Consistency
            report = generate_incident_report(inc_002)
            assert "markdown_report" in report
            md = report["markdown_report"]
            assert "RULE-002" in md
            assert "RULE-003" in md
            assert "RULE-004" in md
            assert "RULE-005" in md
            for u in expected_users:
                assert u in md
            assert "18 alert records" in md
            assert "**Risk Score:** 100/100" in md

            story = generate_one_minute_story(inc_002)
            assert story["risk_score"] == 100
            story_dets = story["question_answers"].get("triggered_detections", [])
            assert len(story_dets) == 18
            distinct_rules = {d["rule_id"] for d in story_dets}
            assert len(distinct_rules) == 4
            assert distinct_rules == {"RULE-002", "RULE-003", "RULE-004", "RULE-005"}
