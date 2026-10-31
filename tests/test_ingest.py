"""
Unit and Integration Tests for CyberTrace Ingestion Pipeline (FR-1).

Tests cover:
  1. Exact 28-column schema structure and types.
  2. Streaming NDJSON parsing with byte-offset tracking.
  3. Streaming FortiGate key-value parsing and category/action mapping.
  4. Exhaustive byte-offset recovery (seek -> read -> verify event_id).
  5. Malformed record resilience (invalid JSON, HTML files, empty lines).
  6. Memory-bounded Parquet chunking with Zstandard compression.
  7. DuckDB querying over normalized Parquet tables.
"""

import json
import os
import sys
import tempfile
import pyarrow.parquet as pq
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.core.schema import NORMALIZED_SCHEMA, NUM_COLUMNS, empty_row, SCHEMA_COLUMNS
from backend.parsers.ndjson_parser import NDJSONParser, _parse_timestamp
from backend.parsers.fortigate_parser import FortiGateParser, _parse_kv_line, _parse_fg_timestamp
from backend.parsers.writer import ParquetWriter
from backend.core.pipeline import ingest_file, detect_format
from backend.core.duckdb_engine import DuckDBEngine


# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------

SAMPLE_EDR_AUTH = json.dumps({
    "@timestamp": "2026-10-31T07:09:54.910Z",
    "event": {"id": "test-auth-001", "kind": "event", "category": ["authentication"],
              "type": ["start"], "action": "user_logon", "severity": 0,
              "module": "edr", "dataset": "edr.authentication", "outcome": "success"},
    "host": {"name": "SRV-DC-01", "ip": ["10.10.0.10"]},
    "user": {"name": "rkumar", "domain": "CORP"},
    "winlog": {"event_id": 4624, "logon": {"type": "Interactive"}},
    "source": {"ip": "10.10.1.13", "port": 50442},
})

SAMPLE_EDR_PROCESS = json.dumps({
    "@timestamp": "2026-10-31T07:10:00.000Z",
    "event": {"id": "test-proc-001", "kind": "event", "category": ["process"],
              "action": "process_created"},
    "host": {"name": "WS-ENG-012", "ip": ["10.10.3.12"]},
    "user": {"name": "pmehta", "domain": "CORP"},
    "process": {
        "pid": 1234,
        "name": "powershell.exe",
        "command_line": "powershell.exe -nop -enc AAAA",
        "parent": {"pid": 5678, "name": "winword.exe"},
    },
})

SAMPLE_EDR_FILE = json.dumps({
    "@timestamp": "2026-10-31T07:12:00.000Z",
    "event": {"id": "test-file-001", "category": ["file"], "action": "file_rename"},
    "host": {"name": "WS-HR-01"},
    "user": {"name": "alex.smith"},
    "file": {"path": "C:\\Users\\alex\\document.docx.locked", "name": "document.docx.locked", "extension": "locked"},
})

SAMPLE_FG_TRAFFIC = (
    'date=2026-10-23 time=08:48:26 eventtime=1792745306000000000 devname="FGT60FTK00000000" '
    'logid="0000000013" type="traffic" subtype="forward" level="notice" action="accept" '
    'srcip=10.10.40.225 srcport=54321 dstip=142.250.190.46 dstport=443 proto=6 service="HTTPS" '
    'user="nverma" hostname="google.com"'
)


# -----------------------------------------------------------------------------
# 1. Schema Validation Tests
# -----------------------------------------------------------------------------

def test_schema_exact_field_count():
    """Verify NORMALIZED_SCHEMA has exactly 28 fields."""
    assert len(NORMALIZED_SCHEMA) == 28
    assert NUM_COLUMNS == 28
    assert len(SCHEMA_COLUMNS) == 28


def test_empty_row_keys():
    """Verify empty_row produces all 28 schema keys set to None."""
    row = empty_row()
    assert len(row) == 28
    for col in SCHEMA_COLUMNS:
        assert col in row
        assert row[col] is None


# -----------------------------------------------------------------------------
# 2. NDJSON Parsing & Byte-Offset Tests
# -----------------------------------------------------------------------------

def test_ndjson_parser_streaming():
    """Verify NDJSON parser streams records and extracts normalized fields."""
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write(SAMPLE_EDR_AUTH + "\n" + SAMPLE_EDR_PROCESS + "\n" + SAMPLE_EDR_FILE + "\n")
        fpath = f.name

    try:
        parser = NDJSONParser()
        rows = list(parser.parse(fpath))
        assert len(rows) == 3
        assert parser.stats["parsed_ok"] == 3
        assert parser.stats["malformed"] == 0

        # Row 1: Auth
        assert rows[0]["event_id"] == "test-auth-001"
        assert rows[0]["event_category"] == "authentication"
        assert rows[0]["winlog_event_id"] == 4624
        assert rows[0]["host_name"] == "SRV-DC-01"
        assert rows[0]["username"] == "rkumar"

        # Row 2: Process
        assert rows[1]["event_id"] == "test-proc-001"
        assert rows[1]["process_name"] == "powershell.exe"
        assert rows[1]["process_id"] == 1234
        assert rows[1]["parent_process_name"] == "winword.exe"
        assert rows[1]["parent_process_id"] == 5678

        # Row 3: File
        assert rows[2]["file_extension"] == "locked"
        assert rows[2]["file_path"].endswith(".locked")

    finally:
        os.unlink(fpath)


def test_byte_offset_exact_recovery():
    """Verify byte_offset and record_length precisely recover raw source lines."""
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write(SAMPLE_EDR_AUTH + "\n" + SAMPLE_EDR_PROCESS + "\n")
        fpath = f.name

    try:
        parser = NDJSONParser()
        rows = list(parser.parse(fpath))

        with open(fpath, "rb") as fh:
            for row in rows:
                fh.seek(row["byte_offset"])
                chunk = fh.read(row["record_length"])
                parsed_json = json.loads(chunk.decode("utf-8").strip())
                assert parsed_json["event"]["id"] == row["event_id"]
    finally:
        os.unlink(fpath)


# -----------------------------------------------------------------------------
# 3. FortiGate Parser Tests
# -----------------------------------------------------------------------------

def test_fortigate_parser_normalization():
    """Verify FortiGate key-value parsing maps into 28-field schema."""
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
        f.write(SAMPLE_FG_TRAFFIC + "\n")
        fpath = f.name

    try:
        parser = FortiGateParser()
        rows = list(parser.parse(fpath))
        assert len(rows) == 1
        r = rows[0]
        assert r["log_source"] == "fortigate"
        assert r["source_ip"] == "10.10.40.225"
        assert r["source_port"] == 54321
        assert r["destination_ip"] == "142.250.190.46"
        assert r["destination_port"] == 443
        assert r["destination_domain"] == "google.com"
        assert r["host_name"] == "FGT60FTK00000000"
        assert r["username"] == "nverma"
        assert r["event_outcome"] == "success"
    finally:
        os.unlink(fpath)


# -----------------------------------------------------------------------------
# 4. Malformed Records Resilience Tests
# -----------------------------------------------------------------------------

def test_malformed_records_handled_gracefully():
    """Verify invalid JSON lines and HTML snippets are logged as malformed without crashing."""
    lines = [
        "<!DOCTYPE html>",
        SAMPLE_EDR_AUTH,
        "{bad json line",
        "",
        SAMPLE_EDR_PROCESS,
    ]
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write("\n".join(lines) + "\n")
        fpath = f.name

    try:
        parser = NDJSONParser()
        rows = list(parser.parse(fpath))
        assert len(rows) == 2
        assert parser.stats["parsed_ok"] == 2
        assert parser.stats["malformed"] == 2
        assert parser.stats["empty_lines"] == 1
        assert len(parser.malformed_records) == 2
    finally:
        os.unlink(fpath)


# -----------------------------------------------------------------------------
# 5. Parquet Ingestion & Bounded Memory Tests
# -----------------------------------------------------------------------------

def test_pipeline_ingest_and_duckdb_query(tmp_path):
    """Verify full end-to-end pipeline writes Parquet and DuckDB queries it with 28 columns."""
    sample_file = tmp_path / "sample.json"
    sample_file.write_text(SAMPLE_EDR_AUTH + "\n" + SAMPLE_EDR_PROCESS + "\n" + SAMPLE_EDR_FILE + "\n")

    out_dir = str(tmp_path / "processed")
    stats = ingest_file(str(sample_file), output_dir=out_dir, flush_size=2)

    assert stats.parsed_ok == 3
    assert stats.parquet_rows_written == 3
    assert os.path.isfile(stats.output_file)

    # Verify Parquet Schema
    table = pq.read_table(stats.output_file)
    assert table.num_columns == 28
    assert table.num_rows == 3

    # Query with DuckDB
    with DuckDBEngine(memory_limit="512MB", threads=1) as db:
        res = db.query(f"SELECT host_name, event_category, count(*) FROM read_parquet('{stats.output_file}') GROUP BY host_name, event_category")
        assert len(res) == 3


def test_real_dataset_ingestion_and_provenance():
    """Integration test against actual edr_events.json."""
    if not os.path.isfile("edr_events.json"):
        pytest.skip("edr_events.json not present")

    stats = ingest_file("edr_events.json", output_dir="data/processed", flush_size=5000)
    assert stats.parsed_ok == 10000
    assert stats.malformed == 0
    assert stats.parquet_rows_written == 10000
    assert stats.peak_ram_mb < 200.0  # Well below 16 GB PRD target
