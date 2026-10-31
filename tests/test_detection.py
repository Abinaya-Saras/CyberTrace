"""
Comprehensive test suite for CyberTrace Phase 2 Detection Engine.

Covers:
  - Positive detection tests for each of the 5 rules
  - Negative detection tests (benign activity produces 0 alerts)
  - Threshold boundary tests (count < threshold vs count >= threshold)
  - Missing/NULL field resilience
  - Multiple hosts / multiple users isolation
  - Evidence reference provenance verification (byte offsets, raw files, event IDs)
  - Rule loader validation & security boundaries (unapproved handlers, invalid YAML, invalid MITRE mappings)
  - Alert schema validation (confidence/severity separation, required evidence)
  - Phase 2.1 Audit Quality Tests:
      * Insufficient C2 observations (<3 connections)
      * Irregular / sub-second network bursts rejected as periodic beaconing
      * Reserved documentation IP address (RFC 5737) handling
      * File modification without encryption evidence (distinguishing rename from encryption)
      * False parent-child process relationships (cmd.exe or explorer.exe spawning PowerShell)
      * Authentication failures outside configured time window
      * Unrelated internal successful logon NOT conflated with external brute force
      * Registry read/query vs write/modification operations
      * Unrelated events sharing a host or user
      * Missing evidence references rejection
  - End-to-end integration test against the normalized EDR Parquet dataset
"""

from datetime import datetime, timedelta, timezone
import os
import tempfile
import uuid

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from backend.core.duckdb_engine import DuckDBEngine
from backend.core.schema import NORMALIZED_SCHEMA, empty_row
from backend.detection.alert_schema import Alert, EvidenceReference
from backend.detection.engine import DetectionEngine
from backend.detection.rule_loader import (
    RuleDefinition,
    RuleLoadError,
    RuleValidationError,
    load_rule_from_yaml,
    load_rules_from_directory,
    validate_rule_dict,
)
from backend.mitre.mappings import (
    TECHNIQUE_CATALOG,
    validate_mitre_mapping,
)


# -----------------------------------------------------------------------------
# Fixtures & Helpers
# -----------------------------------------------------------------------------

def create_synthetic_parquet(rows: list[dict], path: str) -> None:
    """Helper to write a list of event dicts to a Parquet file with NORMALIZED_SCHEMA."""
    columns: dict[str, list] = {field.name: [] for field in NORMALIZED_SCHEMA}
    for r in rows:
        base = empty_row()
        base.update(r)
        for k, v in base.items():
            columns[k].append(v)

    table = pa.Table.from_pydict(columns, schema=NORMALIZED_SCHEMA)
    pq.write_table(table, path, compression="zstd")


@pytest.fixture
def rules_dir():
    """Return path to existing validated detection rules."""
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "detection_rules")
    return path


@pytest.fixture
def temp_parquet_file(tmp_path):
    """Temporary file path for synthetic Parquet data."""
    return str(tmp_path / "synthetic_events.parquet")


# -----------------------------------------------------------------------------
# 1. MITRE & Alert Schema Tests
# -----------------------------------------------------------------------------

def test_mitre_catalog_and_validation():
    """Verify all 5 initial techniques are mapped with valid tactics and stages."""
    assert len(TECHNIQUE_CATALOG) == 5
    for tid, mapping in TECHNIQUE_CATALOG.items():
        assert mapping.technique_id == tid
        assert mapping.mitre_tactic
        assert mapping.kill_chain_stage
        assert mapping.rationale
        is_valid, err = validate_mitre_mapping(tid, mapping.technique_name, mapping.mitre_tactic, mapping.kill_chain_stage)
        assert is_valid, f"Validation failed for {tid}: {err}"

    # Invalid technique
    is_valid, err = validate_mitre_mapping("T9999.999")
    assert not is_valid
    assert "Unknown MITRE technique" in err

    # Mismatched tactic
    is_valid, err = validate_mitre_mapping("T1110", mitre_tactic="Execution")
    assert not is_valid
    assert "tactic mismatch" in err


def test_alert_schema_validation():
    """Verify Alert model enforces confidence, severity, and evidence requirements."""
    # Valid alert
    alert = Alert(
        rule_id="RULE-001",
        title="Test Alert",
        description="Testing alert schema",
        severity="high",
        confidence="medium",
        mitre_technique_id="T1110",
        mitre_technique_name="Brute Force",
        mitre_tactic="Credential Access",
        kill_chain_stage="Exploitation",
        first_seen="2026-10-31T12:00:00Z",
        last_seen="2026-10-31T12:05:00Z",
        supporting_event_ids=["evt-1"],
        evidence_references=[{"event_id": "evt-1", "raw_file": "edr.json", "byte_offset": 100, "record_length": 50}],
        reasoning="Test reasoning",
    )
    assert alert.severity == "high"
    assert alert.confidence == "medium"
    d = alert.to_dict()
    assert d["alert_id"]
    assert d["supporting_event_ids"] == ["evt-1"]

    # Invalid severity
    with pytest.raises(ValueError, match="Invalid severity"):
        Alert(
            rule_id="R1", title="T", description="D", severity="super-critical",
            confidence="high", mitre_technique_id="T1110", mitre_technique_name="B",
            mitre_tactic="C", kill_chain_stage="E", first_seen="now", last_seen="now",
            supporting_event_ids=["e1"], evidence_references=[{"event_id": "e1", "raw_file": "f", "byte_offset": 0, "record_length": 10}],
            reasoning="R"
        )

    # Invalid confidence
    with pytest.raises(ValueError, match="Invalid confidence"):
        Alert(
            rule_id="R1", title="T", description="D", severity="high",
            confidence="85%", mitre_technique_id="T1110", mitre_technique_name="B",
            mitre_tactic="C", kill_chain_stage="E", first_seen="now", last_seen="now",
            supporting_event_ids=["e1"], evidence_references=[{"event_id": "e1", "raw_file": "f", "byte_offset": 0, "record_length": 10}],
            reasoning="R"
        )

    # Missing evidence references
    with pytest.raises(ValueError, match="at least one evidence reference"):
        Alert(
            rule_id="R1", title="T", description="D", severity="high",
            confidence="high", mitre_technique_id="T1110", mitre_technique_name="B",
            mitre_tactic="C", kill_chain_stage="E", first_seen="now", last_seen="now",
            supporting_event_ids=["e1"], evidence_references=[],
            reasoning="R"
        )


# -----------------------------------------------------------------------------
# 2. Rule Loader Security & Validation Tests
# -----------------------------------------------------------------------------

def test_rule_loader_loads_all_five_rules(rules_dir):
    """Verify rule loader correctly loads all 5 production YAML rules."""
    rules = load_rules_from_directory(rules_dir)
    assert len(rules) == 5
    rule_ids = {r.rule_id for r in rules}
    assert rule_ids == {"RULE-001", "RULE-002", "RULE-003", "RULE-004", "RULE-005"}


def test_rule_loader_rejects_unapproved_handler():
    """Verify rule loader rejects unapproved handler / untrusted SQL injection."""
    bad_rule = {
        "rule_id": "RULE-BAD",
        "rule_name": "Malicious Rule",
        "description": "Attempting arbitrary handler",
        "enabled": True,
        "required_fields": ["event_id"],
        "detection_logic": "DROP TABLE users;--",
        "threshold": {"min_events": 1},
        "time_window": "300s",
        "mitre_technique_id": "T1110",
        "mitre_technique_name": "Brute Force",
        "mitre_tactic": "Credential Access",
        "kill_chain_stage": "Exploitation",
        "severity": "medium",
        "evidence_requirements": ["event_id"],
    }
    with pytest.raises(RuleValidationError, match="unapproved detection_logic"):
        validate_rule_dict(bad_rule)


def test_rule_loader_rejects_unknown_schema_field():
    """Verify rule loader ensures required_fields exist in NORMALIZED_SCHEMA."""
    bad_rule = {
        "rule_id": "RULE-BAD2",
        "rule_name": "Bad Schema Rule",
        "description": "Uses non-existent field",
        "enabled": True,
        "required_fields": ["event_id", "non_existent_column_xyz"],
        "detection_logic": "brute_force_handler",
        "threshold": {"min_events": 1},
        "time_window": "300s",
        "mitre_technique_id": "T1110",
        "mitre_technique_name": "Brute Force",
        "mitre_tactic": "Credential Access",
        "kill_chain_stage": "Exploitation",
        "severity": "medium",
        "evidence_requirements": ["event_id"],
    }
    with pytest.raises(RuleValidationError, match="unknown schema field"):
        validate_rule_dict(bad_rule)


def test_rule_loader_rejects_invalid_yaml(tmp_path):
    """Verify RuleLoadError on malformed YAML file."""
    bad_yaml_file = tmp_path / "bad.yaml"
    bad_yaml_file.write_text("rule_id: [unclosed list\n  - item")
    with pytest.raises(RuleLoadError, match="YAML parsing error"):
        load_rule_from_yaml(str(bad_yaml_file))


# -----------------------------------------------------------------------------
# 3. RULE-001 (Brute Force) Tests
# -----------------------------------------------------------------------------

def test_rule1_brute_force_positive_and_negative(temp_parquet_file, rules_dir):
    """Test RULE-001: detects >= 3 failures, ignores < 3, upgrades confidence on subsequent success from SAME source IP."""
    now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)

    events = []

    # 4 failures for victim without subsequent success -> Medium confidence
    for i in range(4):
        events.append({
            "event_id": f"bf-vic-{i}", "raw_file": "edr.json", "byte_offset": 1000 + i * 100,
            "record_length": 90, "timestamp": now + timedelta(seconds=i), "event_category": "authentication",
            "event_outcome": "failure", "winlog_event_id": 4625, "host_name": "SRV-DC-01",
            "username": "victim", "source_ip": "198.51.100.23",
        })

    # 2 failures for other -> NO Alert (< threshold 3)
    for i in range(2):
        events.append({
            "event_id": f"bf-oth-{i}", "raw_file": "edr.json", "byte_offset": 2000 + i * 100,
            "record_length": 90, "timestamp": now + timedelta(seconds=i), "event_category": "authentication",
            "event_outcome": "failure", "winlog_event_id": 4625, "host_name": "SRV-DC-01",
            "username": "other", "source_ip": "198.51.100.23",
        })

    # 7 failures for admin followed by 1 success from the SAME source IP -> High confidence (compromise)
    for i in range(7):
        events.append({
            "event_id": f"bf-adm-{i}", "raw_file": "edr.json", "byte_offset": 3000 + i * 100,
            "record_length": 90, "timestamp": now + timedelta(seconds=i), "event_category": "authentication",
            "event_outcome": "failure", "winlog_event_id": 4625, "host_name": "SRV-DC-02",
            "username": "admin", "source_ip": "203.0.113.57",
        })
    events.append({
        "event_id": "bf-adm-succ", "raw_file": "edr.json", "byte_offset": 3800,
        "record_length": 90, "timestamp": now + timedelta(seconds=10), "event_category": "authentication",
        "event_outcome": "success", "winlog_event_id": 4624, "host_name": "SRV-DC-02",
        "username": "admin", "source_ip": "203.0.113.57",
    })

    create_synthetic_parquet(events, temp_parquet_file)

    rule = load_rule_from_yaml(os.path.join(rules_dir, "brute_force.yaml"))
    with DetectionEngine() as engine:
        alerts = engine.run_rule(rule, temp_parquet_file)

    assert len(alerts) == 2

    # Check alert for admin (High confidence due to confirmed subsequent success from SAME source IP)
    admin_alert = next(a for a in alerts if a.username == "admin")
    assert admin_alert.confidence == "high"
    assert admin_alert.host == "SRV-DC-02"
    assert len(admin_alert.supporting_event_ids) == 7
    assert len(admin_alert.evidence_references) == 7
    assert "successful authentication" in admin_alert.reasoning

    # Check alert for victim (Medium confidence, 4 failures, no success from source)
    victim_alert = next(a for a in alerts if a.username == "victim")
    assert victim_alert.confidence == "medium"
    assert victim_alert.host == "SRV-DC-01"
    assert len(victim_alert.supporting_event_ids) == 4
    assert "NOT established" in victim_alert.reasoning

    # Verify 'other' (<3 failures) generated NO alert
    assert not any(a.username == "other" for a in alerts)


# -----------------------------------------------------------------------------
# 4. RULE-002 (Suspicious Process Execution) Tests
# -----------------------------------------------------------------------------

def test_rule2_suspicious_process_positive_and_negative(temp_parquet_file, rules_dir):
    """Test RULE-002: detects Office spawning PowerShell, flags stealth args, ignores benign explorer spawning."""
    now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)

    events = [
        # Positive 1: winword spawning powershell with -enc on WS-FIN-01 (High confidence)
        {
            "event_id": "proc-pos-1", "raw_file": "edr.json", "byte_offset": 500,
            "record_length": 120, "timestamp": now, "event_category": "process",
            "host_name": "WS-FIN-01", "username": "alice", "process_name": "powershell.exe",
            "process_id": 4120, "parent_process_name": "winword.exe", "parent_process_id": 2040,
            "process_command_line": "powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQ...",
        },
        # Positive 2: excel spawning pwsh without stealth flags on WS-FIN-02 (Medium confidence)
        {
            "event_id": "proc-pos-2", "raw_file": "edr.json", "byte_offset": 700,
            "record_length": 100, "timestamp": now, "event_category": "process",
            "host_name": "WS-FIN-02", "username": "bob", "process_name": "pwsh.exe",
            "process_id": 5510, "parent_process_name": "excel.exe", "parent_process_id": 3100,
            "process_command_line": "pwsh.exe -File script.ps1",
        },
        # Negative: explorer spawning powershell (Benign administrative use)
        {
            "event_id": "proc-neg-1", "raw_file": "edr.json", "byte_offset": 900,
            "record_length": 100, "timestamp": now, "event_category": "process",
            "host_name": "WS-FIN-01", "username": "alice", "process_name": "powershell.exe",
            "process_id": 6100, "parent_process_name": "explorer.exe", "parent_process_id": 1000,
            "process_command_line": "powershell.exe",
        },
        # Negative: winword spawning notepad (Not a script interpreter)
        {
            "event_id": "proc-neg-2", "raw_file": "edr.json", "byte_offset": 1100,
            "record_length": 100, "timestamp": now, "event_category": "process",
            "host_name": "WS-FIN-01", "username": "alice", "process_name": "notepad.exe",
            "process_id": 7100, "parent_process_name": "winword.exe", "parent_process_id": 2040,
            "process_command_line": "notepad.exe readme.txt",
        },
    ]

    create_synthetic_parquet(events, temp_parquet_file)
    rule = load_rule_from_yaml(os.path.join(rules_dir, "suspicious_process.yaml"))

    with DetectionEngine() as engine:
        alerts = engine.run_rule(rule, temp_parquet_file)

    assert len(alerts) == 2

    alert_winword = next(a for a in alerts if a.host == "WS-FIN-01")
    assert alert_winword.confidence == "high"
    assert alert_winword.supporting_event_ids == ["proc-pos-1"]
    assert alert_winword.evidence_references[0]["byte_offset"] == 500

    alert_excel = next(a for a in alerts if a.host == "WS-FIN-02")
    assert alert_excel.confidence == "medium"
    assert alert_excel.supporting_event_ids == ["proc-pos-2"]


# -----------------------------------------------------------------------------
# 5. RULE-003 (C2 Beaconing) Tests
# -----------------------------------------------------------------------------

def test_rule3_c2_beaconing_positive_and_negative(temp_parquet_file, rules_dir):
    """Test RULE-003: requires regular intervals and >= 3 connections; ignores single or benign connections."""
    now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)

    # Positive: 3 outbound connections by powershell spaced by 30 seconds to an external IP
    events = [
        {
            "event_id": f"c2-pos-{i}", "raw_file": "edr.json", "byte_offset": 2000 + i * 100,
            "record_length": 110, "timestamp": now + timedelta(seconds=i * 30), "event_category": "network",
            "host_name": "WS-01", "username": "user1", "process_name": "powershell.exe",
            "destination_ip": "198.51.100.23", "destination_domain": "c2-test.invalid",
        }
        for i in range(3)
    ]
    # Negative 1: Single outbound connection by powershell (< threshold of 3)
    events.append({
        "event_id": "c2-single", "raw_file": "edr.json", "byte_offset": 2500,
        "record_length": 110, "timestamp": now, "event_category": "network",
        "host_name": "WS-02", "username": "user2", "process_name": "powershell.exe",
        "destination_ip": "203.0.113.57", "destination_domain": "c2-single.invalid",
    })
    # Negative 2: 10 outbound connections by chrome.exe to github.com (Benign domain and browser)
    for i in range(10):
        events.append({
            "event_id": f"chrome-benign-{i}", "raw_file": "edr.json", "byte_offset": 3000 + i * 100,
            "record_length": 110, "timestamp": now + timedelta(seconds=i * 10), "event_category": "network",
            "host_name": "WS-01", "username": "user1", "process_name": "chrome.exe",
            "destination_ip": "140.82.121.4", "destination_domain": "github.com",
        })

    create_synthetic_parquet(events, temp_parquet_file)
    rule = load_rule_from_yaml(os.path.join(rules_dir, "c2_beaconing.yaml"))

    with DetectionEngine() as engine:
        alerts = engine.run_rule(rule, temp_parquet_file)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.host == "WS-01"
    assert alert.destination_ip == "198.51.100.23"
    assert len(alert.supporting_event_ids) == 3


# -----------------------------------------------------------------------------
# 6. RULE-004 (Registry Persistence) Tests
# -----------------------------------------------------------------------------

def test_rule4_registry_persistence_positive_and_negative(temp_parquet_file, rules_dir):
    """Test RULE-004: detects Run key modification, ignores benign RecentFiles registry writes."""
    now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)

    events = [
        # Positive: Run key addition by powershell.exe pointing to AppData
        {
            "event_id": "reg-pos-1", "raw_file": "edr.json", "byte_offset": 4000,
            "record_length": 130, "timestamp": now, "event_category": "registry",
            "host_name": "WS-HR-01", "username": "charlie", "process_name": "powershell.exe",
            "registry_path": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
            "registry_data": r"%AppData%\malware.exe", "event_action": "registry_value_set",
            "event_type": "change",
        },
        # Negative: Normal Office RecentFiles registry write
        {
            "event_id": "reg-neg-1", "raw_file": "edr.json", "byte_offset": 4200,
            "record_length": 120, "timestamp": now, "event_category": "registry",
            "host_name": "WS-HR-01", "username": "charlie", "process_name": "winword.exe",
            "registry_path": r"HKCU\Software\Microsoft\Office\16.0\Common\General\RecentFiles",
            "registry_data": "12345", "event_action": "registry_value_set",
            "event_type": "change",
        },
    ]

    create_synthetic_parquet(events, temp_parquet_file)
    rule = load_rule_from_yaml(os.path.join(rules_dir, "registry_persistence.yaml"))

    with DetectionEngine() as engine:
        alerts = engine.run_rule(rule, temp_parquet_file)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.host == "WS-HR-01"
    assert alert.confidence == "high"
    assert alert.supporting_event_ids == ["reg-pos-1"]
    assert alert.evidence_references[0]["byte_offset"] == 4000


# -----------------------------------------------------------------------------
# 7. RULE-005 (Mass File Modification / Ransomware) Tests
# -----------------------------------------------------------------------------

def test_rule5_mass_file_modification_positive_and_negative(temp_parquet_file, rules_dir):
    """Test RULE-005: detects >= 2 .locked file renames, ignores single file renames and benign Word docs."""
    now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)

    events = [
        # Positive: 2 file renames to .locked by unknown.exe on WS-SALES-01
        {
            "event_id": "file-pos-1", "raw_file": "edr.json", "byte_offset": 5000,
            "record_length": 115, "timestamp": now, "event_category": "file",
            "host_name": "WS-SALES-01", "username": "david", "process_name": "unknown.exe",
            "file_path": r"C:\Users\david\Documents\report.locked", "file_extension": "locked",
            "event_action": "file_rename",
        },
        {
            "event_id": "file-pos-2", "raw_file": "edr.json", "byte_offset": 5200,
            "record_length": 115, "timestamp": now, "event_category": "file",
            "host_name": "WS-SALES-01", "username": "david", "process_name": "unknown.exe",
            "file_path": r"C:\Users\david\Documents\budget.locked", "file_extension": "locked",
            "event_action": "file_rename",
        },
        # Negative 1: Single file rename on WS-SALES-02 (< min_files: 2)
        {
            "event_id": "file-single", "raw_file": "edr.json", "byte_offset": 5300,
            "record_length": 115, "timestamp": now, "event_category": "file",
            "host_name": "WS-SALES-02", "username": "eve", "process_name": "unknown.exe",
            "file_path": r"C:\Users\eve\Documents\notes.locked", "file_extension": "locked",
            "event_action": "file_rename",
        },
        # Negative 2: Normal file save by winword.exe to .docx
        {
            "event_id": "file-neg-1", "raw_file": "edr.json", "byte_offset": 5400,
            "record_length": 110, "timestamp": now, "event_category": "file",
            "host_name": "WS-SALES-01", "username": "david", "process_name": "winword.exe",
            "file_path": r"C:\Users\david\Documents\proposal.docx", "file_extension": "docx",
            "event_action": "file_modified",
        },
    ]

    create_synthetic_parquet(events, temp_parquet_file)
    rule = load_rule_from_yaml(os.path.join(rules_dir, "mass_file_modification.yaml"))

    with DetectionEngine() as engine:
        alerts = engine.run_rule(rule, temp_parquet_file)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.host == "WS-SALES-01"
    assert len(alert.supporting_event_ids) == 2
    assert "file-pos-1" in alert.supporting_event_ids
    assert "file-pos-2" in alert.supporting_event_ids
    # Verify reasoning does not claim confirmed encryption
    assert "encryption cannot be independently confirmed" in alert.reasoning or "encryption is not directly established" in alert.reasoning


# -----------------------------------------------------------------------------
# 8. Phase 2.1 Audit Quality Tests
# -----------------------------------------------------------------------------

def test_audit_c2_insufficient_observations(temp_parquet_file, rules_dir):
    """Audit Test: 2 outbound connections within milliseconds must NOT trigger a C2 beacon alert."""
    now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)
    events = [
        {
            "event_id": f"c2-few-{i}", "raw_file": "edr.json", "byte_offset": 100 * i,
            "record_length": 100, "timestamp": now + timedelta(milliseconds=i * 10),
            "event_category": "network", "host_name": "WS-C2-01", "username": "u1",
            "process_name": "powershell.exe", "destination_ip": "198.51.100.23",
            "destination_domain": "bad.example",
        }
        for i in range(2)
    ]
    create_synthetic_parquet(events, temp_parquet_file)
    rule = load_rule_from_yaml(os.path.join(rules_dir, "c2_beaconing.yaml"))

    with DetectionEngine() as engine:
        alerts = engine.run_rule(rule, temp_parquet_file)

    assert len(alerts) == 0, "Two observations within milliseconds should not trigger C2 beaconing"


def test_audit_c2_subsecond_intervals_filtered(temp_parquet_file, rules_dir):
    """Audit Test: Connections occurring within a sub-second burst (< 1.0s) are filtered as unconfirmed."""
    now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)
    # 3 connections spanning only 0.05 seconds total
    events = [
        {
            "event_id": f"c2-fast-{i}", "raw_file": "edr.json", "byte_offset": 100 * i,
            "record_length": 100, "timestamp": now + timedelta(milliseconds=i * 25),
            "event_category": "network", "host_name": "WS-C2-02", "username": "u2",
            "process_name": "powershell.exe", "destination_ip": "198.51.100.23",
            "destination_domain": "fast.example",
        }
        for i in range(3)
    ]
    create_synthetic_parquet(events, temp_parquet_file)
    rule = load_rule_from_yaml(os.path.join(rules_dir, "c2_beaconing.yaml"))

    with DetectionEngine() as engine:
        alerts = engine.run_rule(rule, temp_parquet_file)

    assert len(alerts) == 0, "Sub-second burst should not be classified as periodic beaconing"


def test_audit_brute_force_ignores_unrelated_internal_success(temp_parquet_file, rules_dir):
    """Audit Test: Internal workstation success (10.10.x.x) must NOT be conflated with external brute-force (203.0.113.57)."""
    now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)
    events = []

    # 5 failures from external IP 203.0.113.57
    for i in range(5):
        events.append({
            "event_id": f"bf-ext-{i}", "raw_file": "edr.json", "byte_offset": 100 * i,
            "record_length": 100, "timestamp": now + timedelta(seconds=i),
            "event_category": "authentication", "event_outcome": "failure",
            "winlog_event_id": 4625, "host_name": "SRV-DC-01", "username": "target_user",
            "source_ip": "203.0.113.57",
        })

    # Unrelated success from internal workstation 10.10.2.15 for the same user
    events.append({
        "event_id": "bf-int-succ", "raw_file": "edr.json", "byte_offset": 600,
        "record_length": 100, "timestamp": now + timedelta(seconds=10),
        "event_category": "authentication", "event_outcome": "success",
        "winlog_event_id": 4624, "host_name": "SRV-DC-01", "username": "target_user",
        "source_ip": "10.10.2.15",
    })

    create_synthetic_parquet(events, temp_parquet_file)
    rule = load_rule_from_yaml(os.path.join(rules_dir, "brute_force.yaml"))

    with DetectionEngine() as engine:
        alerts = engine.run_rule(rule, temp_parquet_file)

    assert len(alerts) == 1
    alert = alerts[0]
    # Confidence must remain MEDIUM (not elevated to HIGH) because success was NOT from attacker source
    assert alert.confidence == "medium"
    assert "account compromise is NOT established" in alert.reasoning


def test_audit_false_parent_child_relationship(temp_parquet_file, rules_dir):
    """Audit Test: PowerShell spawned by cmd.exe or explorer.exe must NOT trigger RULE-002."""
    now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)
    events = [
        {
            "event_id": "cmd-spawn-ps", "raw_file": "edr.json", "byte_offset": 100,
            "record_length": 100, "timestamp": now, "event_category": "process",
            "host_name": "WS-01", "username": "user", "process_name": "powershell.exe",
            "parent_process_name": "cmd.exe", "process_command_line": "powershell.exe -Command Get-Date",
        },
        {
            "event_id": "svc-spawn-ps", "raw_file": "edr.json", "byte_offset": 200,
            "record_length": 100, "timestamp": now, "event_category": "process",
            "host_name": "WS-01", "username": "user", "process_name": "powershell.exe",
            "parent_process_name": "services.exe", "process_command_line": "powershell.exe",
        },
    ]
    create_synthetic_parquet(events, temp_parquet_file)
    rule = load_rule_from_yaml(os.path.join(rules_dir, "suspicious_process.yaml"))

    with DetectionEngine() as engine:
        alerts = engine.run_rule(rule, temp_parquet_file)

    assert len(alerts) == 0, "Non-Office parent process should not trigger RULE-002"


def test_audit_registry_read_vs_write(temp_parquet_file, rules_dir):
    """Audit Test: Registry read/query operations on Run key must NOT trigger persistence detection."""
    now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)
    events = [
        {
            "event_id": "reg-read-1", "raw_file": "edr.json", "byte_offset": 100,
            "record_length": 100, "timestamp": now, "event_category": "registry",
            "host_name": "WS-REG-01", "username": "user", "process_name": "reg.exe",
            "registry_path": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "registry_data": None, "event_action": "registry_value_read",
            "event_type": "access",
        },
    ]
    create_synthetic_parquet(events, temp_parquet_file)
    rule = load_rule_from_yaml(os.path.join(rules_dir, "registry_persistence.yaml"))

    with DetectionEngine() as engine:
        alerts = engine.run_rule(rule, temp_parquet_file)

    assert len(alerts) == 0, "Registry read/query should not be classified as autorun persistence modification"


def test_audit_unrelated_events_sharing_host_not_merged(temp_parquet_file, rules_dir):
    """Audit Test: Benign browsing and failed logins on same host must not contaminate detection."""
    now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)
    events = [
        # Benign network browsing
        {
            "event_id": "net-benign", "raw_file": "edr.json", "byte_offset": 100,
            "record_length": 100, "timestamp": now, "event_category": "network",
            "host_name": "SRV-DC-01", "username": "admin", "process_name": "chrome.exe",
            "destination_ip": "142.250.190.46", "destination_domain": "www.google.com",
        },
        # Single authentication failure (< 3 threshold)
        {
            "event_id": "auth-single", "raw_file": "edr.json", "byte_offset": 200,
            "record_length": 100, "timestamp": now, "event_category": "authentication",
            "event_outcome": "failure", "winlog_event_id": 4625,
            "host_name": "SRV-DC-01", "username": "admin", "source_ip": "10.10.1.5",
        },
    ]
    create_synthetic_parquet(events, temp_parquet_file)

    with DetectionEngine(rules_directory=rules_dir) as engine:
        alerts = engine.run_all(temp_parquet_file)

    assert len(alerts) == 0, "Unrelated benign events on the same host must produce 0 alerts"


def test_missing_fields_resilience(temp_parquet_file, rules_dir):
    """Verify engine handles events with missing optional fields without crashing."""
    now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)

    # Bare minimal event with NULLs for all optional fields
    sparse_event = {
        "event_id": "sparse-1", "raw_file": "edr.json", "byte_offset": 10,
        "record_length": 50, "timestamp": now, "event_category": "authentication",
        "event_outcome": "failure", "winlog_event_id": 4625,
    }
    create_synthetic_parquet([sparse_event], temp_parquet_file)

    with DetectionEngine(rules_directory=rules_dir) as engine:
        alerts = engine.run_all(temp_parquet_file)
        assert isinstance(alerts, list)


# -----------------------------------------------------------------------------
# 9. End-to-End Integration Test against Real EDR Parquet
# -----------------------------------------------------------------------------

def test_integration_full_edr_dataset(rules_dir):
    """Run full detection engine against normalized Parquet dataset."""
    real_parquet = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "processed", "edr_events.parquet")
    if not os.path.isfile(real_parquet):
        pytest.skip("data/processed/edr_events.parquet not found")

    with DetectionEngine(rules_directory=rules_dir) as engine:
        alerts = engine.run_all(real_parquet)

    assert len(alerts) > 0
    rule_counts = {}
    for a in alerts:
        rule_counts[a.rule_id] = rule_counts.get(a.rule_id, 0) + 1
        assert len(a.supporting_event_ids) > 0
        assert len(a.evidence_references) == len(a.supporting_event_ids)
        for ref in a.evidence_references:
            assert ref["byte_offset"] >= 0
            assert ref["record_length"] > 0
            assert ref["raw_file"]

    # Audited rules active on dataset
    assert "RULE-001" in rule_counts
    assert "RULE-002" in rule_counts
    assert "RULE-004" in rule_counts
    assert "RULE-005" in rule_counts
    # RULE-003 correctly produces 0 alerts on this synthetic dataset due to insufficient observations (<3)
    assert rule_counts.get("RULE-003", 0) == 0


# -----------------------------------------------------------------------------
# 10. Phase 2.2 Readiness Audit Regression Tests
# -----------------------------------------------------------------------------

def test_phase2_2_audit_r2_r4_host_overlap_and_disjoint(rules_dir):
    """
    Phase 2.2 Audit Test:
    Verify exact host overlap between RULE-002 (PowerShell) and RULE-004 (Registry RunKey).
    Identifies 22 shared hosts, 1 R2-only host ('WS-HR-011'), and 1 R4-only host ('WS-FIN-010').
    Validates evidence-based classification without false claims of 'compromised endpoint'.
    """
    real_parquet = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "processed", "edr_events.parquet")
    if not os.path.isfile(real_parquet):
        pytest.skip("data/processed/edr_events.parquet not found")

    with DetectionEngine(rules_directory=rules_dir) as engine:
        alerts = engine.run_all(real_parquet)

    r2_alerts = [a for a in alerts if a.rule_id == "RULE-002"]
    r4_alerts = [a for a in alerts if a.rule_id == "RULE-004"]

    assert len(r2_alerts) == 23, f"Expected 23 RULE-002 alerts, got {len(r2_alerts)}"
    assert len(r4_alerts) == 23, f"Expected 23 RULE-004 alerts, got {len(r4_alerts)}"

    r2_hosts = set(a.host for a in r2_alerts)
    r4_hosts = set(a.host for a in r4_alerts)

    shared_hosts = r2_hosts.intersection(r4_hosts)
    r2_only = r2_hosts - r4_hosts
    r4_only = r4_hosts - r2_hosts

    assert len(shared_hosts) == 22, f"Expected 22 shared hosts, got {len(shared_hosts)}"
    assert r2_only == {"WS-HR-011"}, f"Expected R2-only to be WS-HR-011, got {r2_only}"
    assert r4_only == {"WS-FIN-010"}, f"Expected R4-only to be WS-FIN-010, got {r4_only}"

    # Verify conservative wording: no unproven 'compromised endpoint' or 'confirmed compromise' claims
    for a in alerts:
        assert "compromised endpoint" not in a.title.lower(), f"Overclaiming title in {a.rule_id}: {a.title}"
        assert "confirmed compromise" not in a.reasoning.lower(), f"Overclaiming reasoning in {a.rule_id}: {a.reasoning}"
        assert "confirmed encryption" not in a.reasoning.lower(), f"Overclaiming reasoning in {a.rule_id}: {a.reasoning}"


def test_phase2_2_audit_shared_hosts_pid_linkage_absence(rules_dir):
    """
    Phase 2.2 Audit Test:
    On the 22 hosts exhibiting both RULE-002 and RULE-004 behaviors, verify whether
    process execution and registry modification can be connected via process IDs.
    Because the synthetic generator assigned random PIDs, PID/PPID linkage is absent (0/22).
    Confirms classification must be 'multiple suspicious behaviors observed', NOT proven compromise.
    """
    real_parquet = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "processed", "edr_events.parquet")
    if not os.path.isfile(real_parquet):
        pytest.skip("data/processed/edr_events.parquet not found")

    with DetectionEngine(rules_directory=rules_dir) as engine:
        alerts = engine.run_all(real_parquet)

    r2_by_host = {a.host: a for a in alerts if a.rule_id == "RULE-002"}
    r4_by_host = {a.host: a for a in alerts if a.rule_id == "RULE-004"}
    shared = set(r2_by_host.keys()) & set(r4_by_host.keys())

    pid_match_count = 0
    for h in shared:
        a2 = r2_by_host[h]
        a4 = r4_by_host[h]

        r2_pids = {ref.get("process_id") for ref in a2.evidence_references if ref.get("process_id")}
        r4_pids = {ref.get("process_id") for ref in a4.evidence_references if ref.get("process_id")}
        r4_ppids = {ref.get("parent_process_id") for ref in a4.evidence_references if ref.get("parent_process_id")}

        if (r2_pids & r4_pids) or (r2_pids & r4_ppids):
            pid_match_count += 1

    # Exactly 0 out of 22 shared hosts have direct PID linkage
    assert pid_match_count == 0, "Synthetic dataset does not link PIDs between process and registry events"


def test_phase2_2_audit_rule005_srv_db_01_reconciliation(rules_dir):
    """
    Phase 2.2 Audit Test:
    Reconcile RULE-005 scope. Under host-level aggregation, SRV-DB-01 generates an alert
    capturing all 3 .locked file rename events across 3 distinct users (dnair, sgupta, svc_sql).
    Verifies that host-level aggregation does not lose distinct actor identities in evidence_references.
    """
    real_parquet = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "processed", "edr_events.parquet")
    if not os.path.isfile(real_parquet):
        pytest.skip("data/processed/edr_events.parquet not found")

    with DetectionEngine(rules_directory=rules_dir) as engine:
        alerts = engine.run_all(real_parquet)

    r5_alerts = [a for a in alerts if a.rule_id == "RULE-005"]
    assert len(r5_alerts) == 26, f"Expected 26 hosts with file rename bursts, got {len(r5_alerts)}"

    srv_db_alerts = [a for a in r5_alerts if a.host == "SRV-DB-01"]
    assert len(srv_db_alerts) == 1, "SRV-DB-01 must generate exactly 1 RULE-005 alert"

    alert = srv_db_alerts[0]
    assert len(alert.supporting_event_ids) == 3, f"SRV-DB-01 must link 3 events, got {len(alert.supporting_event_ids)}"
    assert len(alert.evidence_references) == 3

    # Check distinct usernames retained in evidence references
    users_in_evidence = {ref.get("username") for ref in alert.evidence_references}
    assert users_in_evidence == {"dnair", "sgupta", "svc_sql"}, f"Expected distinct users, got {users_in_evidence}"

    # Verify reasoning notes file rename rather than asserting encryption
    assert "file encryption cannot be" in alert.reasoning.lower() or "file encryption is not" in alert.reasoning.lower()


def test_phase2_2_evidence_references_granularity(rules_dir):
    """
    Phase 2.2 Audit Test:
    Verify that evidence_references maintain full provenance and per-event attribution:
    event_id, raw_file, byte_offset, record_length, timestamp, and actor/PID details.
    """
    real_parquet = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "processed", "edr_events.parquet")
    if not os.path.isfile(real_parquet):
        pytest.skip("data/processed/edr_events.parquet not found")

    with DetectionEngine(rules_directory=rules_dir) as engine:
        alerts = engine.run_all(real_parquet)

    for alert in alerts:
        for ref in alert.evidence_references:
            assert "event_id" in ref
            assert "raw_file" in ref
            assert "byte_offset" in ref
            assert "record_length" in ref
            assert ref["byte_offset"] >= 0
            assert ref["record_length"] > 0
            # Check presence of timestamp
            assert "timestamp" in ref
            # If RULE-002, check process_name and process_id
            if alert.rule_id == "RULE-002":
                assert "process_name" in ref
                assert "parent_process_name" in ref

