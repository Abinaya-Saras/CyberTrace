#!/usr/bin/env python3
"""
Phase 1 benchmark: ingest edr_events.json, write Parquet, verify with DuckDB.

Run:  source .venv/bin/activate && python run_phase1_benchmark.py
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.core.pipeline import ingest_file, save_malformed
from backend.core.duckdb_engine import DuckDBEngine
from backend.core.schema import NORMALIZED_SCHEMA


def main():
    input_file = "edr_events.json"
    output_dir = "data/processed"
    malformed_file = "data/processed/malformed_edr.json"

    if not os.path.exists(input_file):
        print(f"ERROR: {input_file} not found")
        sys.exit(1)

    # ---- Step 1: Ingest ----
    print("=" * 60)
    print("  Phase 1 Benchmark: EDR Events Ingestion")
    print("=" * 60)
    print(f"\nIngesting {input_file} ...")

    stats = ingest_file(input_file, output_dir=output_dir, flush_size=5000)

    # Save malformed records
    if stats.malformed_records:
        save_malformed(stats.malformed_records, malformed_file)
        print(f"\nMalformed records saved to: {malformed_file}")

    # Print ingestion report
    stats.print_report()

    # ---- Step 2: Byte-offset verification (sample) ----
    print("\n--- Byte-Offset Verification ---")
    import pyarrow.parquet as pq
    table = pq.read_table(stats.output_file)

    offsets = table.column("byte_offset").to_pylist()
    lengths = table.column("record_length").to_pylist()
    event_ids = table.column("event_id").to_pylist()

    verified = 0
    failed = 0
    sample_size = min(100, len(offsets))  # Verify first 100 records

    with open(input_file, "rb") as fh:
        for i in range(sample_size):
            fh.seek(offsets[i])
            raw = fh.read(lengths[i])
            try:
                decoded = raw.decode("utf-8").strip()
                obj = json.loads(decoded)
                if obj["event"]["id"] == event_ids[i]:
                    verified += 1
                else:
                    failed += 1
                    print(f"  MISMATCH at row {i}: expected {event_ids[i]}, got {obj['event']['id']}")
            except Exception as e:
                failed += 1
                print(f"  ERROR at row {i}: {e}")

    print(f"  Verified: {verified}/{sample_size}")
    print(f"  Failed:   {failed}/{sample_size}")

    # ---- Step 3: Missing-field statistics ----
    print("\n--- Missing-Field Statistics ---")
    total_rows = table.num_rows
    for field in NORMALIZED_SCHEMA:
        col = table.column(field.name)
        null_count = col.null_count
        present = total_rows - null_count
        pct = present / total_rows * 100
        if pct < 100:
            print(f"  {field.name:.<40} {present:>6}/{total_rows}  ({pct:5.1f}%)")

    # ---- Step 4: DuckDB queries ----
    print("\n--- DuckDB Query Tests ---")
    parquet_glob = os.path.join(output_dir, "*.parquet")

    with DuckDBEngine(memory_limit="1GB", threads=2) as db:
        # Test 1: Row count
        t0 = time.monotonic()
        row_count = db.query_one(f"SELECT count(*) FROM read_parquet('{parquet_glob}')")[0]
        t1 = time.monotonic()
        print(f"  Row count:          {row_count}  ({(t1-t0)*1000:.1f} ms)")

        # Test 2: Category distribution
        t0 = time.monotonic()
        cats = db.query(
            f"SELECT event_category, count(*) as cnt "
            f"FROM read_parquet('{parquet_glob}') "
            f"GROUP BY event_category ORDER BY cnt DESC"
        )
        t1 = time.monotonic()
        print(f"  Category query:     {(t1-t0)*1000:.1f} ms")
        for cat, cnt in cats:
            print(f"    {cat or 'NULL':.<30} {cnt}")

        # Test 3: Host distribution
        t0 = time.monotonic()
        hosts = db.query(
            f"SELECT count(DISTINCT host_name) FROM read_parquet('{parquet_glob}')"
        )[0][0]
        t1 = time.monotonic()
        print(f"  Distinct hosts:     {hosts}  ({(t1-t0)*1000:.1f} ms)")

        # Test 4: User distribution
        t0 = time.monotonic()
        users = db.query(
            f"SELECT count(DISTINCT username) FROM read_parquet('{parquet_glob}')"
        )[0][0]
        t1 = time.monotonic()
        print(f"  Distinct users:     {users}  ({(t1-t0)*1000:.1f} ms)")

        # Test 5: Timestamp range
        t0 = time.monotonic()
        ts_range = db.query_one(
            f"SELECT min(timestamp), max(timestamp) FROM read_parquet('{parquet_glob}')"
        )
        t1 = time.monotonic()
        print(f"  Timestamp range:    {ts_range[0]} -> {ts_range[1]}  ({(t1-t0)*1000:.1f} ms)")

        # Test 6: Severity distribution
        t0 = time.monotonic()
        sevs = db.query(
            f"SELECT event_severity, count(*) as cnt "
            f"FROM read_parquet('{parquet_glob}') "
            f"GROUP BY event_severity ORDER BY event_severity"
        )
        t1 = time.monotonic()
        print(f"  Severity query:     {(t1-t0)*1000:.1f} ms")
        for sev, cnt in sevs:
            print(f"    severity={sev}:  {cnt}")

        # Test 7: Events with process info
        t0 = time.monotonic()
        proc_cnt = db.query_one(
            f"SELECT count(*) FROM read_parquet('{parquet_glob}') "
            f"WHERE process_name IS NOT NULL"
        )[0]
        t1 = time.monotonic()
        print(f"  Events with process:{proc_cnt}  ({(t1-t0)*1000:.1f} ms)")

        # Test 8: Alert events (kind='alert')
        t0 = time.monotonic()
        alert_cnt = db.query_one(
            f"SELECT count(*) FROM read_parquet('{parquet_glob}') "
            f"WHERE event_kind = 'alert'"
        )[0]
        t1 = time.monotonic()
        print(f"  Alert events:       {alert_cnt}  ({(t1-t0)*1000:.1f} ms)")

        # Test 9: Auth failures
        t0 = time.monotonic()
        auth_fail = db.query_one(
            f"SELECT count(*) FROM read_parquet('{parquet_glob}') "
            f"WHERE event_category = 'authentication' AND event_outcome = 'failure'"
        )[0]
        t1 = time.monotonic()
        print(f"  Auth failures:      {auth_fail}  ({(t1-t0)*1000:.1f} ms)")

        # Test 10: Create view and query
        db.create_parquet_view("events", parquet_glob)
        t0 = time.monotonic()
        top_hosts = db.query(
            "SELECT host_name, count(*) as cnt FROM events "
            "GROUP BY host_name ORDER BY cnt DESC LIMIT 5"
        )
        t1 = time.monotonic()
        print(f"  Top 5 hosts (view): {(t1-t0)*1000:.1f} ms")
        for host, cnt in top_hosts:
            print(f"    {host:.<30} {cnt}")

    print("\n" + "=" * 60)
    print("  Phase 1 Benchmark Complete")
    print("=" * 60)


if __name__ == "__main__":
    main()
