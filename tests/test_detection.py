"""
Comprehensive test suite for CyberTrace Detection Engine (FR-2 & FR-3).

Tests:
  1. MITRE ATT&CK & Cyber Kill Chain Mapping Validity (FR-3)
  2. Alert Schema & Granular Provenance Integrity
  3. Positive, Negative, and Boundary Unit Tests for all 5 Detection Rules (FR-2):
     - RULE-001 (T1110: Brute Force)
     - RULE-002 (T1059.001: Suspicious Process Execution)
     - RULE-003 (T1071.001: C2 Beaconing)
     - RULE-004 (T1547.001: Registry Persistence)
     - RULE-005 (T1486: Mass File Modification / Ransomware)
  4. Robustness & Edge Cases (NULL fields, multi-host isolation, empty Parquet)
  5. End-to-End Integration Benchmark against normalized Parquet dataset
"""

from datetime import datetime, timedelta, timezone
import json
import os
import tempfile
import uuid

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from backend.core.duckdb_engine import DuckDBEngine
from backend.core.schema import NORMALIZED_SCHEMA, empty_row
from backend.detection.alert_schema import Alert, EvidenceReference
from backend.detection.engine import (
    DetectionEngine,
    detect_brute_force,
    detect_c2_beaconing,
    detect_mass_file_modification,
    detect_registry_persistence,
    detect_suspicious_process,
)
from backend.mitre.mappings import (
    TECHNIQUE_CATALOG,
    get_mapping,
    validate_mitre_mapping,
)


# -----------------------------------------------------------------------------
# Fixtures & Synthetic Parquet Helpers
# -----------------------------------------------------------------------------

def write_parquet(rows: list[dict], path: str) -> None:
    """Helper to write a list of event dicts to a Parquet file matching NORMALIZED_SCHEMA."""
    columns: dict[str, list] = {field.name: [] for field in NORMALIZED_SCHEMA}
    for r in rows:
        base = empty_row()
        base.update(r)
        for k, v in base.items():
            columns[k].append(v)
    table = pa.Table.from_pydict(columns, schema=NORMALIZED_SCHEMA)
    pq.write_table(table, path, compression="zstd")


@pytest.fixture
def temp_parquet(tmp_path):
    """Provides a temporary parquet file path."""
    return str(tmp_path / "test_events.parquet")


@pytest.fixture
def duckdb_engine():
    """Provides an isolated DuckDBEngine instance for testing."""
    engine = DuckDBEngine(memory_limit="512MB", threads=1)
    yield engine
    engine.close()


# -----------------------------------------------------------------------------
# 1. MITRE ATT&CK & Cyber Kill Chain Mapping Tests (FR-3)
# -----------------------------------------------------------------------------

def test_mitre_catalog_authoritative_definitions():
    """Verify all 5 core techniques are mapped to valid tactics and kill chain stages."""
    assert len(TECHNIQUE_CATALOG) == 5
    expected_techniques = {"T1110", "T1059.001", "T1071.001", "T1547.001", "T1486"}
    assert set(TECHNIQUE_CATALOG.keys()) == expected_techniques

    for tid, mapping in TECHNIQUE_CATALOG.items():
        assert mapping.technique_id == tid
        assert mapping.technique_name
        assert mapping.mitre_tactic
        assert mapping.kill_chain_stage
        assert mapping.rationale
        is_valid, err = validate_mitre_mapping(
            tid, mapping.technique_name, mapping.mitre_tactic, mapping.kill_chain_stage
        )
        assert is_valid, f"Validation failed for {tid}: {err}"


def test_mitre_validation_rejects_invalid_mappings():
    """Verify validate_mitre_mapping rejects unknown IDs and mismatched tactics."""
    is_valid, err = validate_mitre_mapping("T9999")
    assert not is_valid
    assert "Unknown MITRE technique ID" in err

    is_valid, err = validate_mitre_mapping("T1110", mitre_tactic="Execution")
    assert not is_valid
    assert "tactic mismatch" in err

    is_valid, err = validate_mitre_mapping("T1110", kill_chain_stage="Installation")
    assert not is_valid
    assert "stage mismatch" in err


# -----------------------------------------------------------------------------
# 2. Alert Schema & Provenance Contract Tests
# -----------------------------------------------------------------------------

def test_alert_schema_validation():
    """Verify Alert class enforces severity, confidence, and evidence reference requirements."""
    # Valid alert
    alert = Alert(
        rule_id="RULE-001",
        title="Test Alert",
        description="Testing schema validation",
        severity="high",
        confidence="high",
        mitre_technique_id="T1110",
        mitre_technique_name="Brute Force",
        mitre_tactic="Credential Access",
        kill_chain_stage="Exploitation",
        first_seen="2026-10-31T12:00:00Z",
        last_seen="2026-10-31T12:05:00Z",
        supporting_event_ids=["evt-1"],
        evidence_references=[
            {"event_id": "evt-1", "raw_file": "test.json", "byte_offset": 100, "record_length": 50}
        ],
        reasoning="Valid test reasoning",
    )
    assert alert.severity == "high"
    assert alert.confidence == "high"
    assert alert.to_dict()["rule_id"] == "RULE-001"

    # Missing evidence references must raise ValueError
    with pytest.raises(ValueError, match="at least one evidence reference"):
        Alert(
            rule_id="RULE-001",
            title="Test Alert",
            description="Testing",
            severity="high",
            confidence="high",
            mitre_technique_id="T1110",
            mitre_technique_name="Brute Force",
            mitre_tactic="Credential Access",
            kill_chain_stage="Exploitation",
            first_seen="2026-10-31T12:00:00Z",
            last_seen="2026-10-31T12:05:00Z",
            supporting_event_ids=["evt-1"],
            evidence_references=[],
            reasoning="Missing refs",
        )

    # Incomplete evidence reference (missing byte_offset)
    with pytest.raises(ValueError, match="missing required key 'byte_offset'"):
        Alert(
            rule_id="RULE-001",
            title="Test Alert",
            description="Testing",
            severity="high",
            confidence="high",
            mitre_technique_id="T1110",
            mitre_technique_name="Brute Force",
            mitre_tactic="Credential Access",
            kill_chain_stage="Exploitation",
            first_seen="2026-10-31T12:00:00Z",
            last_seen="2026-10-31T12:05:00Z",
            supporting_event_ids=["evt-1"],
            evidence_references=[{"event_id": "evt-1", "raw_file": "test.json", "record_length": 50}],
            reasoning="Missing byte_offset",
        )


# -----------------------------------------------------------------------------
# 3. Rule-by-Rule Detection Tests (Positive, Negative, Boundary, Audit)
# -----------------------------------------------------------------------------

def test_detect_brute_force_positive_and_subsequent_success(temp_parquet, duckdb_engine):
    """RULE-001: 3 failed authentications followed by success from SAME source IP escalates to HIGH confidence."""
    t0 = datetime(2026, 10, 31, 10, 0, 0, tzinfo=timezone.utc)
    rows = [
        # 3 failures from 198.51.100.23 targeting user 'admin' on SRV-01
        {
            "event_id": f"auth-fail-{i}",
            "raw_file": "auth.json",
            "byte_offset": i * 100,
            "record_length": 80,
            "timestamp": t0 + timedelta(seconds=i),
            "event_category": "authentication",
            "event_outcome": "failure",
            "winlog_event_id": 4625,
            "host_name": "SRV-01",
            "username": "admin",
            "source_ip": "198.51.100.23",
        }
        for i in range(3)
    ]
    # Subsequent success from SAME attacker source IP
    rows.append({
        "event_id": "auth-succ-1",
        "raw_file": "auth.json",
        "byte_offset": 300,
        "record_length": 80,
        "timestamp": t0 + timedelta(seconds=10),
        "event_category": "authentication",
        "event_outcome": "success",
        "winlog_event_id": 4624,
        "host_name": "SRV-01",
        "username": "admin",
        "source_ip": "198.51.100.23",
    })

    write_parquet(rows, temp_parquet)
    duckdb_engine.create_parquet_view("v_bf", temp_parquet)
    alerts = detect_brute_force(duckdb_engine, "v_bf", min_failures=3)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "RULE-001"
    assert alert.mitre_technique_id == "T1110"
    assert alert.kill_chain_stage == "Exploitation"
    assert alert.confidence == "high"
    assert alert.host == "SRV-01"
    assert alert.username == "admin"
    assert alert.source_ip == "198.51.100.23"
    assert len(alert.supporting_event_ids) == 3
    assert len(alert.evidence_references) == 3
    assert "confirmed successful authentication from the SAME source IP" in alert.reasoning


def test_detect_brute_force_unrelated_internal_success_not_conflated(temp_parquet, duckdb_engine):
    """RULE-001 Audit: Subsequent success from an internal IP must NOT claim account compromise by attacker IP."""
    t0 = datetime(2026, 10, 31, 10, 0, 0, tzinfo=timezone.utc)
    rows = [
        # 4 failures from external IP 203.0.113.57
        {
            "event_id": f"auth-fail-{i}",
            "raw_file": "auth.json",
            "byte_offset": i * 100,
            "record_length": 80,
            "timestamp": t0 + timedelta(seconds=i),
            "event_category": "authentication",
            "event_outcome": "failure",
            "winlog_event_id": 4625,
            "host_name": "SRV-DC-01",
            "username": "pmehta",
            "source_ip": "203.0.113.57",
        }
        for i in range(4)
    ]
    # Legitimate internal workstation login from 10.10.3.11 (DIFFERENT source IP)
    rows.append({
        "event_id": "auth-succ-internal",
        "raw_file": "auth.json",
        "byte_offset": 500,
        "record_length": 80,
        "timestamp": t0 + timedelta(seconds=15),
        "event_category": "authentication",
        "event_outcome": "success",
        "winlog_event_id": 4624,
        "host_name": "SRV-DC-01",
        "username": "pmehta",
        "source_ip": "10.10.3.11",
    })

    write_parquet(rows, temp_parquet)
    duckdb_engine.create_parquet_view("v_bf_audit", temp_parquet)
    alerts = detect_brute_force(duckdb_engine, "v_bf_audit", min_failures=3)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.confidence == "medium"
    assert "account compromise is NOT established" in alert.reasoning


def test_detect_brute_force_boundary_and_negative(temp_parquet, duckdb_engine):
    """RULE-001 Boundary: Exactly 2 failures (threshold 3) produces 0 alerts. Benign logins produce 0 alerts."""
    t0 = datetime(2026, 10, 31, 10, 0, 0, tzinfo=timezone.utc)
    rows = [
        # 2 failures (below threshold)
        {
            "event_id": f"auth-fail-{i}",
            "raw_file": "auth.json",
            "byte_offset": i * 100,
            "record_length": 80,
            "timestamp": t0 + timedelta(seconds=i),
            "event_category": "authentication",
            "event_outcome": "failure",
            "winlog_event_id": 4625,
            "host_name": "SRV-01",
            "username": "user1",
            "source_ip": "10.0.0.1",
        }
        for i in range(2)
    ] + [
        # 10 successful logins (benign)
        {
            "event_id": f"auth-succ-{i}",
            "raw_file": "auth.json",
            "byte_offset": (i + 10) * 100,
            "record_length": 80,
            "timestamp": t0 + timedelta(seconds=i),
            "event_category": "authentication",
            "event_outcome": "success",
            "winlog_event_id": 4624,
            "host_name": "SRV-01",
            "username": "user2",
            "source_ip": "10.0.0.2",
        }
        for i in range(10)
    ]

    write_parquet(rows, temp_parquet)
    duckdb_engine.create_parquet_view("v_bf_neg", temp_parquet)
    alerts = detect_brute_force(duckdb_engine, "v_bf_neg", min_failures=3)
    assert len(alerts) == 0


def test_detect_suspicious_process_positive_and_evasive_flags(temp_parquet, duckdb_engine):
    """RULE-002: Word spawning PowerShell with encoded command flags triggers HIGH confidence alert."""
    t0 = datetime(2026, 10, 31, 11, 0, 0, tzinfo=timezone.utc)
    rows = [
        {
            "event_id": "proc-word-ps",
            "raw_file": "proc.json",
            "byte_offset": 1000,
            "record_length": 150,
            "timestamp": t0,
            "event_category": "process",
            "host_name": "WS-001",
            "username": "alice",
            "parent_process_name": "winword.exe",
            "parent_process_id": 1204,
            "process_name": "powershell.exe",
            "process_id": 4500,
            "process_command_line": "powershell.exe -nop -w hidden -enc JABzACAAPQAgAE4AZQB3...",
        }
    ]
    write_parquet(rows, temp_parquet)
    duckdb_engine.create_parquet_view("v_proc", temp_parquet)
    alerts = detect_suspicious_process(duckdb_engine, "v_proc")

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "RULE-002"
    assert alert.mitre_technique_id == "T1059.001"
    assert alert.kill_chain_stage == "Exploitation"
    assert alert.confidence == "high"
    assert alert.host == "WS-001"
    assert alert.process_name == "powershell.exe"
    assert alert.parent_process_name == "winword.exe"
    assert alert.process_id == 4500
    assert alert.parent_process_id == 1204
    assert len(alert.evidence_references) == 1
    assert alert.evidence_references[0]["process_command_line"] == rows[0]["process_command_line"]


def test_detect_suspicious_process_negative_cases(temp_parquet, duckdb_engine):
    """RULE-002 Negative: Benign process creation (explorer spawning notepad, services spawning svchost) produces 0 alerts."""
    t0 = datetime(2026, 10, 31, 11, 0, 0, tzinfo=timezone.utc)
    rows = [
        {
            "event_id": "proc-benign-1",
            "raw_file": "proc.json",
            "byte_offset": 100,
            "record_length": 100,
            "timestamp": t0,
            "event_category": "process",
            "host_name": "WS-001",
            "username": "alice",
            "parent_process_name": "explorer.exe",
            "parent_process_id": 1000,
            "process_name": "notepad.exe",
            "process_id": 2000,
            "process_command_line": "notepad.exe test.txt",
        },
        {
            "event_id": "proc-benign-2",
            "raw_file": "proc.json",
            "byte_offset": 200,
            "record_length": 100,
            "timestamp": t0,
            "event_category": "process",
            "host_name": "WS-001",
            "username": "SYSTEM",
            "parent_process_name": "services.exe",
            "parent_process_id": 500,
            "process_name": "svchost.exe",
            "process_id": 700,
            "process_command_line": "svchost.exe -k netsvcs",
        },
    ]
    write_parquet(rows, temp_parquet)
    duckdb_engine.create_parquet_view("v_proc_neg", temp_parquet)
    alerts = detect_suspicious_process(duckdb_engine, "v_proc_neg")
    assert len(alerts) == 0


def test_detect_c2_beaconing_positive(temp_parquet, duckdb_engine):
    """RULE-003: Script engine making >= 3 outbound connections across non-zero interval triggers alert."""
    t0 = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)
    rows = [
        {
            "event_id": f"net-c2-{i}",
            "raw_file": "net.json",
            "byte_offset": i * 150,
            "record_length": 120,
            "timestamp": t0 + timedelta(seconds=i * 30),  # 30-second interval
            "event_category": "network",
            "host_name": "WS-002",
            "username": "bob",
            "process_name": "powershell.exe",
            "destination_ip": "104.244.42.1",
            "destination_domain": "c2-domain.com",
            "destination_port": 443,
        }
        for i in range(5)
    ]
    write_parquet(rows, temp_parquet)
    duckdb_engine.create_parquet_view("v_c2", temp_parquet)
    alerts = detect_c2_beaconing(duckdb_engine, "v_c2", min_connections=3, min_interval_seconds=1.0)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "RULE-003"
    assert alert.mitre_technique_id == "T1071.001"
    assert alert.kill_chain_stage == "Command and Control"
    assert alert.confidence == "high"
    assert alert.host == "WS-002"
    assert alert.destination_ip == "104.244.42.1"
    assert len(alert.supporting_event_ids) == 5


def test_detect_c2_beaconing_suppresses_subsecond_bursts(temp_parquet, duckdb_engine):
    """RULE-003 Audit: 3 connections within 50ms are suppressed as unproven periodic beaconing."""
    t0 = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)
    rows = [
        {
            "event_id": f"net-burst-{i}",
            "raw_file": "net.json",
            "byte_offset": i * 100,
            "record_length": 90,
            "timestamp": t0 + timedelta(milliseconds=i * 15),  # total span: 30ms
            "event_category": "network",
            "host_name": "WS-002",
            "username": "bob",
            "process_name": "powershell.exe",
            "destination_ip": "198.51.100.23",
            "destination_domain": "demo.invalid",
            "destination_port": 443,
        }
        for i in range(3)
    ]
    write_parquet(rows, temp_parquet)
    duckdb_engine.create_parquet_view("v_c2_subsec", temp_parquet)
    alerts = detect_c2_beaconing(duckdb_engine, "v_c2_subsec", min_connections=3, min_interval_seconds=1.0)
    assert len(alerts) == 0


def test_detect_registry_persistence_positive_and_negative(temp_parquet, duckdb_engine):
    """RULE-004: Autorun key modification detected; registry reads or unrelated keys produce 0 alerts."""
    t0 = datetime(2026, 10, 31, 13, 0, 0, tzinfo=timezone.utc)
    rows = [
        # Suspicious Run key value set
        {
            "event_id": "reg-run-1",
            "raw_file": "reg.json",
            "byte_offset": 100,
            "record_length": 110,
            "timestamp": t0,
            "event_category": "registry",
            "event_action": "registry_value_set",
            "host_name": "WS-003",
            "username": "carol",
            "process_name": "powershell.exe",
            "registry_path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
            "registry_data": "C:\\Users\\carol\\AppData\\Local\\Temp\\updater.exe",
        },
        # Benign registry read on Run key (should NOT alert)
        {
            "event_id": "reg-read-1",
            "raw_file": "reg.json",
            "byte_offset": 250,
            "record_length": 100,
            "timestamp": t0 + timedelta(seconds=1),
            "event_category": "registry",
            "event_action": "registry_key_read",
            "host_name": "WS-003",
            "username": "carol",
            "process_name": "explorer.exe",
            "registry_path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "registry_data": None,
        },
        # Non-run key modification (should NOT alert)
        {
            "event_id": "reg-unrelated-1",
            "raw_file": "reg.json",
            "byte_offset": 400,
            "record_length": 100,
            "timestamp": t0 + timedelta(seconds=2),
            "event_category": "registry",
            "event_action": "registry_value_set",
            "host_name": "WS-003",
            "username": "SYSTEM",
            "process_name": "svchost.exe",
            "registry_path": "HKLM\\System\\CurrentControlSet\\Control\\TimeZoneInformation",
            "registry_data": "UTC",
        },
    ]
    write_parquet(rows, temp_parquet)
    duckdb_engine.create_parquet_view("v_reg", temp_parquet)
    alerts = detect_registry_persistence(duckdb_engine, "v_reg")

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "RULE-004"
    assert alert.mitre_technique_id == "T1547.001"
    assert alert.kill_chain_stage == "Installation"
    assert alert.confidence == "high"
    assert alert.host == "WS-003"
    assert "AppData" in alert.reasoning


def test_detect_mass_file_modification_burst_vs_isolated(temp_parquet, duckdb_engine):
    """RULE-005: Multi-file rename burst triggers alert; isolated single file rename produces 0 alerts."""
    t0 = datetime(2026, 10, 31, 14, 0, 0, tzinfo=timezone.utc)
    rows = [
        # Workstation 1: Burst of 3 files renamed to .locked
        {
            "event_id": f"file-burst-{i}",
            "raw_file": "file.json",
            "byte_offset": i * 120,
            "record_length": 100,
            "timestamp": t0 + timedelta(milliseconds=i * 10),
            "event_category": "file",
            "event_action": "file_rename",
            "host_name": "WS-BURST",
            "username": "dave",
            "process_name": "unknown.exe",
            "file_path": f"C:\\Users\\dave\\doc_{i}.locked",
            "file_extension": "locked",
        }
        for i in range(3)
    ] + [
        # Workstation 2: Isolated single file rename (below threshold of 2)
        {
            "event_id": "file-single-1",
            "raw_file": "file.json",
            "byte_offset": 500,
            "record_length": 100,
            "timestamp": t0,
            "event_category": "file",
            "event_action": "file_rename",
            "host_name": "WS-ISOLATED",
            "username": "eve",
            "process_name": "unknown.exe",
            "file_path": "C:\\Users\\eve\\single.locked",
            "file_extension": "locked",
        }
    ]
    write_parquet(rows, temp_parquet)
    duckdb_engine.create_parquet_view("v_ransom", temp_parquet)
    alerts = detect_mass_file_modification(duckdb_engine, "v_ransom", min_files=2)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "RULE-005"
    assert alert.mitre_technique_id == "T1486"
    assert alert.kill_chain_stage == "Actions on Objectives"
    assert alert.severity == "critical"
    assert alert.host == "WS-BURST"
    assert len(alert.supporting_event_ids) == 3


# -----------------------------------------------------------------------------
# 4. Resilience & Edge Case Tests
# -----------------------------------------------------------------------------

def test_null_fields_resilience(temp_parquet, duckdb_engine):
    """Detection functions handle NULL and empty fields across telemetry without crashing."""
    t0 = datetime(2026, 10, 31, 15, 0, 0, tzinfo=timezone.utc)
    sparse_rows = [
        {
            "event_id": f"sparse-{i}",
            "raw_file": "sparse.json",
            "byte_offset": i * 50,
            "record_length": 40,
            "timestamp": t0,
            "event_category": cat,
            "event_action": None,
            "event_outcome": None,
            "winlog_event_id": None,
            "host_name": "WS-SPARSE",
            "username": None,
            "process_name": None,
            "destination_ip": None,
            "registry_path": None,
            "file_path": None,
        }
        for i, cat in enumerate(["authentication", "process", "network", "registry", "file"])
    ]
    write_parquet(sparse_rows, temp_parquet)

    with DetectionEngine(engine=duckdb_engine) as engine:
        alerts = engine.run_all(temp_parquet)
        assert len(alerts) == 0


def test_empty_parquet_handling(temp_parquet, duckdb_engine):
    """DetectionEngine handles empty Parquet files cleanly."""
    write_parquet([], temp_parquet)
    with DetectionEngine(engine=duckdb_engine) as engine:
        alerts = engine.run_all(temp_parquet)
        assert len(alerts) == 0


def test_multi_host_isolation(temp_parquet, duckdb_engine):
    """Detections on separate hosts are never combined into a single host alert."""
    t0 = datetime(2026, 10, 31, 16, 0, 0, tzinfo=timezone.utc)
    rows = []
    for h in ["HOST-A", "HOST-B"]:
        for i in range(3):
            rows.append({
                "event_id": f"bf-{h}-{i}",
                "raw_file": "auth.json",
                "byte_offset": i * 100,
                "record_length": 80,
                "timestamp": t0 + timedelta(seconds=i),
                "event_category": "authentication",
                "event_outcome": "failure",
                "winlog_event_id": 4625,
                "host_name": h,
                "username": "target_user",
                "source_ip": "192.168.1.100",
            })
    write_parquet(rows, temp_parquet)

    with DetectionEngine(engine=duckdb_engine) as engine:
        alerts = engine.detect_brute_force(temp_parquet, min_failures=3)
        assert len(alerts) == 2
        hosts = {a.host for a in alerts}
        assert hosts == {"HOST-A", "HOST-B"}


# -----------------------------------------------------------------------------
# 5. Integration Benchmark Against Normalized EDR Parquet
# -----------------------------------------------------------------------------

def test_e2e_edr_parquet_benchmark():
    """
    End-to-end integration test executing all 5 detection rules against edr_events.parquet.
    Verifies alert count, 100% MITRE mapping, and byte-offset provenance against raw JSON.
    """
    parquet_path = "data/processed/edr_events.parquet"
    if not os.path.exists(parquet_path):
        pytest.skip("data/processed/edr_events.parquet does not exist")

    with DetectionEngine() as engine:
        alerts = engine.run_all(parquet_path)

        # Verified alert count on 10,000-event synthetic dataset
        assert len(alerts) == 90

        rule_counts = {}
        for a in alerts:
            rule_counts[a.rule_id] = rule_counts.get(a.rule_id, 0) + 1

        assert rule_counts.get("RULE-001") == 18
        assert rule_counts.get("RULE-002") == 23
        assert rule_counts.get("RULE-004") == 23
        assert rule_counts.get("RULE-005") == 26

        # 100% of generated alerts must have valid MITRE ATT&CK & Kill Chain mappings
        for a in alerts:
            is_valid, err = validate_mitre_mapping(
                a.mitre_technique_id, a.mitre_technique_name, a.mitre_tactic, a.kill_chain_stage
            )
            assert is_valid, f"Alert {a.alert_id} mapping invalid: {err}"

        # Byte-offset provenance check against raw edr_events.json
        raw_json_path = "edr_events.json"
        if os.path.exists(raw_json_path):
            with open(raw_json_path, "rb") as f:
                checked = 0
                for a in alerts[:10]:  # check first 10 alerts
                    for ref in a.evidence_references[:3]:
                        f.seek(ref["byte_offset"])
                        chunk = f.read(ref["record_length"])
                        raw_data = json.loads(chunk.decode("utf-8"))
                        assert raw_data["event"]["id"] == ref["event_id"]
                        checked += 1
                assert checked > 0
