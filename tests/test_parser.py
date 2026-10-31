"""
CyberTrace Phase 1 tests: parsing, normalisation, byte-offsets, malformed handling.

Run with:  python -m pytest tests/test_parser.py -v
"""

import json
import os
import sys
import tempfile

import pyarrow.parquet as pq
import pytest

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.core.schema import NORMALIZED_SCHEMA, empty_row, SCHEMA_COLUMNS
from backend.parsers.ndjson_parser import NDJSONParser, _parse_timestamp
from backend.parsers.fortigate_parser import FortiGateParser, _parse_kv_line, _parse_fg_timestamp
from backend.parsers.writer import ParquetWriter


# ---------------------------------------------------------------
# Fixtures: sample data
# ---------------------------------------------------------------

SAMPLE_EDR_AUTH = json.dumps({
    "@timestamp": "2026-10-31T07:09:54.910Z",
    "event": {"id": "test-auth-001", "kind": "event", "category": ["authentication"],
              "type": ["start"], "action": "user_logon", "severity": 0,
              "module": "edr", "dataset": "edr.authentication", "outcome": "success"},
    "agent": {"id": "abc123", "type": "edr", "name": "SimEDR", "version": "1.0"},
    "observer": {"vendor": "Mitigata", "product": "SimEDR", "version": "1.0"},
    "host": {"name": "SRV-DC-01", "hostname": "SRV-DC-01", "ip": ["10.10.0.10"],
             "os": {"type": "windows", "full": "Windows Server 2022"}},
    "user": {"name": "rkumar", "domain": "CORP"},
    "winlog": {"event_id": 4624, "logon": {"type": "Interactive"}},
    "source": {"ip": "10.10.1.13"},
})

SAMPLE_EDR_PROCESS = json.dumps({
    "@timestamp": "2026-10-31T07:10:00.000Z",
    "event": {"id": "test-proc-001", "kind": "event", "category": ["process"],
              "type": ["start"], "action": "process_created", "severity": 0,
              "module": "edr", "dataset": "edr.process"},
    "host": {"name": "WS-ENG-012", "ip": ["10.10.3.12"],
             "os": {"type": "windows", "full": "Windows 11 Enterprise 23H2"}},
    "user": {"name": "pmehta", "domain": "CORP"},
    "process": {"pid": 1234, "name": "powershell.exe",
                "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "command_line": "powershell.exe -nop -enc AAAA",
                "hash": {"md5": "abc123", "sha256": "def456"},
                "parent": {"pid": 5678, "name": "winword.exe"},
                "entity_id": "ent-999"},
})

SAMPLE_EDR_NETWORK = json.dumps({
    "@timestamp": "2026-10-31T07:11:00.000Z",
    "event": {"id": "test-net-001", "kind": "event", "category": ["network"],
              "type": ["connection"], "action": "network_connection", "severity": 0,
              "module": "edr", "dataset": "edr.network"},
    "host": {"name": "WS-FIN-010", "ip": ["10.10.1.10"],
             "os": {"type": "windows", "full": "Windows 11 Enterprise 23H2"}},
    "user": {"name": "sgupta", "domain": "CORP"},
    "process": {"pid": 9999, "name": "chrome.exe"},
    "source": {"ip": "10.10.1.10", "port": 50000},
    "destination": {"ip": "198.51.100.23", "port": 443, "domain": "evil.test"},
    "network": {"transport": "tcp", "direction": "outbound",
                "protocol": "https", "bytes": 5000},
})

SAMPLE_EDR_ALERT = json.dumps({
    "@timestamp": "2026-10-31T07:12:00.000Z",
    "event": {"id": "test-alert-001", "kind": "alert", "category": ["process"],
              "type": ["start"], "action": "process_created", "severity": 8,
              "module": "edr", "dataset": "edr.process"},
    "host": {"name": "WS-HR-011", "ip": ["10.10.2.11"],
             "os": {"type": "windows", "full": "Windows 11 Enterprise 23H2"}},
    "user": {"name": "asharma", "domain": "CORP"},
    "process": {"pid": 4444, "name": "powershell.exe",
                "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "command_line": "powershell.exe -nop -w hidden -enc <REDACTED>",
                "parent": {"pid": 3333, "name": "winword.exe"},
                "entity_id": "ent-alert-1"},
    "threat": {"framework": "MITRE ATT&CK",
               "technique": {"id": ["T1059.001"], "name": ["PowerShell"]},
               "tactic": {"name": ["Execution"]}},
    "rule": {"id": "rule123", "name": "Office spawned scripting engine", "severity": "high"},
    "labels": {"synthetic": "true"},
})

SAMPLE_FG_DNS = 'date=2026-10-23 time=08:48:26 eventtime=1792745306000000000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="1501054600" type="utm" subtype="dns" level="information" vd="root" srcip=10.10.40.156 srcport=37918 srcintf="internal4" srcintfrole="lan" dstip=11.113.232.73 dstport=53 dstintf="wan1" dstintfrole="wan" sessionid=235524450 proto=17 action="pass" policyid=20 service="DNS" srccountry="Reserved" dstcountry="Ireland" hostname="nytimes.com"'

SAMPLE_FG_TRAFFIC = 'date=2026-10-23 time=08:48:26 eventtime=1792745306423348000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.10.40.225 srcport=50951 srcintf="internal4" srcintfrole="lan" dstip=71.38.6.121 dstport=443 dstintf="wan1" dstintfrole="wan" sessionid=1309353623 proto=6 action="accept" policyid=4 service="RDP" srccountry="Reserved" dstcountry="Brazil" app="Discord" appcat="Email" apprisk="elevated" duration=274 sentbyte=17865 rcvdbyte=35730 sentpkt=14 rcvdpkt=26'

SAMPLE_FG_LOGIN_FAIL = 'date=2026-10-23 time=08:48:26 eventtime=1792745306564464000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032002" type="event" subtype="system" level="alert" vd="root" logdesc="Admin login failed" user="admin" ui="https(209.50.167.232)" method="https" srcip=209.50.167.232 srcintf="wan1" srcintfrole="wan" dstip=10.10.99.1 dstintf="mgmt" dstintfrole="lan" proto=6 action="login" srccountry="India" dstcountry="Reserved" status="failed" reason="name_invalid" msg="Administrator admin login failed from https(209.50.167.232) because of invalid user name"'


# ===============================================================
# Test: Schema
# ===============================================================

class TestSchema:
    def test_empty_row_has_all_columns(self):
        row = empty_row()
        assert set(row.keys()) == SCHEMA_COLUMNS

    def test_empty_row_all_none(self):
        row = empty_row()
        for k, v in row.items():
            assert v is None, f"{k} should be None"

    def test_schema_column_count(self):
        assert len(NORMALIZED_SCHEMA) >= 60  # We have ~70 columns


# ===============================================================
# Test: NDJSON Parser
# ===============================================================

class TestNDJSONParser:
    def test_parse_auth_event(self):
        parser = NDJSONParser()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(SAMPLE_EDR_AUTH + "\n")
            f.flush()
            rows = list(parser.parse(f.name))
        os.unlink(f.name)

        assert len(rows) == 1
        row = rows[0]
        assert row["event_id"] == "test-auth-001"
        assert row["event_category"] == "authentication"
        assert row["event_action"] == "user_logon"
        assert row["event_outcome"] == "success"
        assert row["host_name"] == "SRV-DC-01"
        assert row["host_ip"] == "10.10.0.10"
        assert row["username"] == "rkumar"
        assert row["user_domain"] == "CORP"
        assert row["source_ip"] == "10.10.1.13"
        assert row["winlog_event_id"] == 4624
        assert row["winlog_logon_type"] == "Interactive"
        assert row["log_source"] == "edr"

    def test_parse_process_event(self):
        parser = NDJSONParser()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(SAMPLE_EDR_PROCESS + "\n")
            f.flush()
            rows = list(parser.parse(f.name))
        os.unlink(f.name)

        row = rows[0]
        assert row["process_name"] == "powershell.exe"
        assert row["process_id"] == 1234
        assert row["parent_process_name"] == "winword.exe"
        assert row["parent_process_id"] == 5678
        assert row["process_command_line"] == "powershell.exe -nop -enc AAAA"
        assert row["process_entity_id"] == "ent-999"
        assert row["process_hash_md5"] == "abc123"
        assert row["process_hash_sha256"] == "def456"

    def test_parse_network_event(self):
        parser = NDJSONParser()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(SAMPLE_EDR_NETWORK + "\n")
            f.flush()
            rows = list(parser.parse(f.name))
        os.unlink(f.name)

        row = rows[0]
        assert row["source_ip"] == "10.10.1.10"
        assert row["source_port"] == 50000
        assert row["destination_ip"] == "198.51.100.23"
        assert row["destination_port"] == 443
        assert row["destination_domain"] == "evil.test"
        assert row["network_transport"] == "tcp"
        assert row["network_direction"] == "outbound"
        assert row["network_bytes_total"] == 5000

    def test_alert_threat_labels_not_in_output(self):
        """Ensure threat/rule/labels are NOT carried into normalized output."""
        parser = NDJSONParser()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(SAMPLE_EDR_ALERT + "\n")
            f.flush()
            rows = list(parser.parse(f.name))
        os.unlink(f.name)

        row = rows[0]
        # The row should NOT have threat/rule/labels columns
        assert "threat" not in row
        assert "rule" not in row
        assert "labels" not in row
        # But event_kind=alert should be preserved
        assert row["event_kind"] == "alert"
        assert row["event_severity"] == 8

    def test_timestamp_parsing(self):
        ts = _parse_timestamp("2026-10-31T07:09:54.910Z")
        assert ts is not None
        assert ts.year == 2026
        assert ts.month == 10
        assert ts.day == 31
        assert ts.hour == 7
        assert ts.minute == 9

    def test_timestamp_none(self):
        assert _parse_timestamp(None) is None
        assert _parse_timestamp("") is None

    def test_malformed_json(self):
        parser = NDJSONParser()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write('{"valid": "line"}\n')
            f.write('NOT JSON AT ALL\n')
            f.write('{"another": "valid"}\n')
            f.flush()
            rows = list(parser.parse(f.name))
        os.unlink(f.name)

        assert parser.stats["parsed_ok"] == 2
        assert parser.stats["malformed"] == 1
        assert len(parser.malformed_records) == 1
        assert "JSON decode error" in parser.malformed_records[0]["error"]

    def test_empty_lines_skipped(self):
        parser = NDJSONParser()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(SAMPLE_EDR_AUTH + "\n")
            f.write("\n")
            f.write("  \n")
            f.write(SAMPLE_EDR_PROCESS + "\n")
            f.flush()
            rows = list(parser.parse(f.name))
        os.unlink(f.name)

        assert len(rows) == 2
        assert parser.stats["empty_lines"] == 2

    def test_byte_offsets_accurate(self):
        """Verify byte offsets allow re-reading the original record."""
        parser = NDJSONParser()
        lines = [SAMPLE_EDR_AUTH, SAMPLE_EDR_PROCESS, SAMPLE_EDR_NETWORK]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            for line in lines:
                f.write(line + "\n")
            fpath = f.name

        rows = list(parser.parse(fpath))
        assert len(rows) == 3

        # Verify each offset + length recovers the original line
        with open(fpath, "rb") as fh:
            for i, row in enumerate(rows):
                fh.seek(row["byte_offset"])
                raw = fh.read(row["record_length"])
                decoded = raw.decode("utf-8").strip()
                original = json.loads(decoded)
                assert original["event"]["id"] == row["event_id"], \
                    f"Byte offset mismatch at row {i}"

        os.unlink(fpath)

    def test_missing_fields_are_none(self):
        """Events missing optional fields should have None, not invented values."""
        minimal = json.dumps({
            "@timestamp": "2026-01-01T00:00:00Z",
            "event": {"id": "min-001", "kind": "event", "category": ["process"],
                      "type": ["start"], "action": "test", "severity": 0,
                      "module": "edr", "dataset": "edr.test"},
            "host": {"name": "TEST-HOST", "ip": ["1.2.3.4"]},
            "user": {"name": "tester"},
        })
        parser = NDJSONParser()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(minimal + "\n")
            fpath = f.name

        rows = list(parser.parse(fpath))
        os.unlink(fpath)

        row = rows[0]
        # These should be None, not invented
        assert row["process_name"] is None
        assert row["source_ip"] is None
        assert row["destination_ip"] is None
        assert row["file_path"] is None
        assert row["registry_path"] is None
        assert row["dns_query_name"] is None
        assert row["network_transport"] is None


# ===============================================================
# Test: FortiGate Parser
# ===============================================================

class TestFortiGateParser:
    def test_kv_parse_basic(self):
        kv = _parse_kv_line(SAMPLE_FG_DNS)
        assert kv["type"] == "utm"
        assert kv["subtype"] == "dns"
        assert kv["srcip"] == "10.10.40.156"
        assert kv["hostname"] == "nytimes.com"

    def test_kv_parse_quoted(self):
        kv = _parse_kv_line(SAMPLE_FG_LOGIN_FAIL)
        assert kv["user"] == "admin"
        assert "login failed" in kv["msg"]
        assert kv["status"] == "failed"

    def test_parse_dns_event(self):
        parser = FortiGateParser()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(SAMPLE_FG_DNS + "\n")
            fpath = f.name

        rows = list(parser.parse(fpath))
        os.unlink(fpath)

        assert len(rows) == 1
        row = rows[0]
        assert row["log_source"] == "fortigate"
        assert row["event_category"] == "network"
        assert row["event_action"] == "dns_query"
        assert row["source_ip"] == "10.10.40.156"
        assert row["destination_ip"] == "11.113.232.73"
        assert row["dns_query_name"] == "nytimes.com"
        assert row["fg_subtype"] == "dns"
        assert row["timestamp"] is not None

    def test_parse_traffic_event(self):
        parser = FortiGateParser()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(SAMPLE_FG_TRAFFIC + "\n")
            fpath = f.name

        rows = list(parser.parse(fpath))
        os.unlink(fpath)

        row = rows[0]
        assert row["source_ip"] == "10.10.40.225"
        assert row["destination_port"] == 443
        assert row["network_transport"] == "tcp"
        assert row["network_direction"] == "outbound"
        assert row["network_bytes_sent"] == 17865
        assert row["network_bytes_recv"] == 35730
        assert row["fg_app"] == "Discord"
        assert row["fg_duration"] == 274

    def test_parse_login_failure(self):
        parser = FortiGateParser()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(SAMPLE_FG_LOGIN_FAIL + "\n")
            fpath = f.name

        rows = list(parser.parse(fpath))
        os.unlink(fpath)

        row = rows[0]
        assert row["event_kind"] == "alert"
        assert row["event_category"] == "authentication"
        assert row["username"] == "admin"
        assert row["fg_status"] == "failed"
        assert row["fg_reason"] == "name_invalid"
        assert row["event_severity"] == 8  # alert level

    def test_fg_timestamp_nanosecond(self):
        kv = _parse_kv_line(SAMPLE_FG_DNS)
        ts = _parse_fg_timestamp(kv)
        assert ts is not None
        assert ts.year == 2026

    def test_byte_offsets_fortigate(self):
        parser = FortiGateParser()
        lines = [SAMPLE_FG_DNS, SAMPLE_FG_TRAFFIC, SAMPLE_FG_LOGIN_FAIL]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            for line in lines:
                f.write(line + "\n")
            fpath = f.name

        rows = list(parser.parse(fpath))
        assert len(rows) == 3

        with open(fpath, "rb") as fh:
            for i, row in enumerate(rows):
                fh.seek(row["byte_offset"])
                raw = fh.read(row["record_length"]).decode("utf-8").strip()
                # Verify the raw content contains expected key
                assert "devname=" in raw, f"Byte offset mismatch at FG row {i}"

        os.unlink(fpath)


# ===============================================================
# Test: Parquet Writer
# ===============================================================

class TestParquetWriter:
    def test_write_and_read(self):
        with tempfile.NamedTemporaryFile(suffix=".parquet", delete=False) as f:
            fpath = f.name

        row = empty_row()
        row["event_id"] = "write-test-001"
        row["log_source"] = "test"
        row["event_severity"] = 5

        with ParquetWriter(fpath, flush_size=100) as writer:
            writer.add_row(row)
            total = writer.total_written

        assert total == 1

        # Read back
        table = pq.read_table(fpath)
        assert table.num_rows == 1
        assert table.column("event_id").to_pylist() == ["write-test-001"]
        assert table.column("event_severity").to_pylist() == [5]

        os.unlink(fpath)

    def test_flush_at_threshold(self):
        with tempfile.NamedTemporaryFile(suffix=".parquet", delete=False) as f:
            fpath = f.name

        with ParquetWriter(fpath, flush_size=5) as writer:
            for i in range(12):
                row = empty_row()
                row["event_id"] = f"flush-{i}"
                writer.add_row(row)

        # Should have written 12 rows across multiple flushes
        table = pq.read_table(fpath)
        assert table.num_rows == 12

        os.unlink(fpath)

    def test_zstd_compression(self):
        with tempfile.NamedTemporaryFile(suffix=".parquet", delete=False) as f:
            fpath = f.name

        with ParquetWriter(fpath, flush_size=100, compression="zstd") as writer:
            for i in range(100):
                row = empty_row()
                row["event_id"] = f"comp-{i}"
                row["log_source"] = "test"
                writer.add_row(row)

        meta = pq.read_metadata(fpath)
        # Verify ZSTD compression is used
        col_meta = meta.row_group(0).column(0)
        assert "ZSTD" in str(col_meta.compression).upper()

        os.unlink(fpath)


# ===============================================================
# Test: Full round-trip (parse -> write -> read back)
# ===============================================================

class TestRoundTrip:
    def test_edr_roundtrip(self):
        """Parse EDR JSON -> write Parquet -> read back and verify."""
        lines = [SAMPLE_EDR_AUTH, SAMPLE_EDR_PROCESS, SAMPLE_EDR_NETWORK, SAMPLE_EDR_ALERT]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as src:
            for line in lines:
                src.write(line + "\n")
            src_path = src.name

        with tempfile.NamedTemporaryFile(suffix=".parquet", delete=False) as dst:
            dst_path = dst.name

        parser = NDJSONParser()
        with ParquetWriter(dst_path, flush_size=100) as writer:
            for row in parser.parse(src_path):
                writer.add_row(row)

        assert parser.stats["parsed_ok"] == 4

        table = pq.read_table(dst_path)
        assert table.num_rows == 4

        ids = table.column("event_id").to_pylist()
        assert "test-auth-001" in ids
        assert "test-proc-001" in ids
        assert "test-net-001" in ids
        assert "test-alert-001" in ids

        os.unlink(src_path)
        os.unlink(dst_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
