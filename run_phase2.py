#!/usr/bin/env python3
"""
CyberTrace Phase 2 CLI Runner.

Runs the independent detection engine against normalized Parquet telemetry,
evaluates all YAML detection rules, prints formatted summaries, and exports
structured alerts with evidence provenance.

Usage:
  source .venv/bin/activate
  python run_phase2.py
  python run_phase2.py --output reports/phase2_alerts.json
  python run_phase2.py --rule-id RULE-001
"""

import argparse
import json
import os
import sys
import time

# Ensure project root is in python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.core.duckdb_engine import DuckDBEngine
from backend.detection.engine import DetectionEngine
from backend.detection.rule_loader import load_rules_from_directory


def main():
    parser = argparse.ArgumentParser(description="CyberTrace Phase 2 Detection Engine Runner")
    parser.add_argument(
        "--parquet",
        default="data/processed/edr_events.parquet",
        help="Path to normalized Parquet dataset (default: data/processed/edr_events.parquet)",
    )
    parser.add_argument(
        "--rules",
        default="config/detection_rules",
        help="Directory containing YAML detection rules (default: config/detection_rules)",
    )
    parser.add_argument(
        "--output",
        default="reports/phase2_alerts.json",
        help="Output path for JSON alert export (default: reports/phase2_alerts.json)",
    )
    parser.add_argument(
        "--rule-id",
        default=None,
        help="Execute only a specific rule ID (e.g. RULE-001)",
    )
    args = parser.parse_args()

    print("=" * 70)
    print("CYBERTRACE - PHASE 2: INDEPENDENT SECURITY DETECTION ENGINE")
    print("=" * 70)

    if not os.path.isfile(args.parquet):
        print(f"[-] ERROR: Parquet file not found: {args.parquet}")
        sys.exit(1)

    if not os.path.isdir(args.rules):
        print(f"[-] ERROR: Rules directory not found: {args.rules}")
        sys.exit(1)

    # 1. Load rules
    print(f"\n[+] Loading detection rules from '{args.rules}'...")
    all_rules = load_rules_from_directory(args.rules)
    if args.rule_id:
        rules = [r for r in all_rules if r.rule_id == args.rule_id]
        if not rules:
            print(f"[-] ERROR: Rule '{args.rule_id}' not found among loaded rules.")
            sys.exit(1)
    else:
        rules = all_rules

    print(f"[+] Loaded {len(rules)} active rule(s):")
    for r in rules:
        print(f"    - [{r.rule_id}] {r.rule_name} (MITRE: {r.mitre_technique_id}, Severity: {r.severity.upper()})")

    # 2. Inspect Parquet dataset
    duck = DuckDBEngine(memory_limit="1GB", threads=2)
    info = duck.table_info(args.parquet)
    print(f"\n[+] Dataset information:")
    print(f"    - Target Parquet: {args.parquet}")
    print(f"    - Total records: {info['row_count']:,}")
    print(f"    - Time span: {info['timestamp_min']} to {info['timestamp_max']}")

    # 3. Execute Detection Engine
    print(f"\n[+] Executing detection engine...")
    t0 = time.perf_counter()
    with DetectionEngine(engine=duck) as engine:
        alerts = []
        for rule in rules:
            rule_t0 = time.perf_counter()
            rule_alerts = engine.run_rule(rule, args.parquet)
            rule_t = time.perf_counter() - rule_t0
            alerts.extend(rule_alerts)
            print(f"    ✓ {rule.rule_id} ({rule.mitre_technique_id}): {len(rule_alerts)} alerts ({rule_t*1000:.1f}ms)")

    total_time = time.perf_counter() - t0

    # 4. Analyze results
    print("\n" + "=" * 70)
    print("DETECTION SUMMARY & METRICS")
    print("=" * 70)
    row_count = info.get("row_count", 10000)
    print(f"Detection engine time:   {total_time * 1000:.2f} ms ({row_count / total_time:,.0f} records/sec)")

    # Groupings
    by_rule = {}
    by_severity = {}
    by_confidence = {}
    unique_hosts = set()
    unique_users = set()
    total_evidence_refs = 0

    for a in alerts:
        by_rule[a.rule_id] = by_rule.get(a.rule_id, 0) + 1
        by_severity[a.severity] = by_severity.get(a.severity, 0) + 1
        by_confidence[a.confidence] = by_confidence.get(a.confidence, 0) + 1
        if a.host:
            unique_hosts.add(a.host)
        if a.username:
            for u in a.username.split(", "):
                unique_users.add(u.strip())
        total_evidence_refs += len(a.evidence_references)

    print("\nAlerts by Rule:")
    for rid, count in sorted(by_rule.items()):
        rule_obj = next((r for r in rules if r.rule_id == rid), None)
        tech = rule_obj.mitre_technique_id if rule_obj else "N/A"
        print(f"  {rid:<10} | {tech:<10} | {count:>4} alerts | {rule_obj.rule_name if rule_obj else ''}")

    print("\nSeverity Breakdown:")
    for sev in ["critical", "high", "medium", "low", "informational"]:
        if sev in by_severity:
            print(f"  {sev.upper():<12}: {by_severity[sev]:>4} alerts")

    print("\nConfidence Breakdown (Evidence Strength):")
    for conf in ["high", "medium", "low"]:
        if conf in by_confidence:
            print(f"  {conf.upper():<12}: {by_confidence[conf]:>4} alerts")

    print("\nScope of Impact:")
    print(f"  Unique hosts affected: {len(unique_hosts)}")
    print(f"  Unique users affected: {len(unique_users)}")
    print(f"  Total evidence links:  {total_evidence_refs}")

    # 5. Export JSON
    if args.output:
        os.makedirs(os.path.dirname(args.output), exist_ok=True)
        export_data = {
            "metadata": {
                "engine": "CyberTrace Phase 2 Detection Engine",
                "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "parquet_source": args.parquet,
                "total_records_evaluated": info["row_count"],
                "total_alerts": len(alerts),
                "execution_time_seconds": round(total_time, 4),
            },
            "alerts": [a.to_dict() for a in alerts],
        }
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, default=str)
        print(f"\n[+] Exported {len(alerts)} alerts to '{args.output}'")

    # 6. Sample Alert
    if alerts:
        print("\n" + "=" * 70)
        print(f"SAMPLE ALERT (1 of {len(alerts)}):")
        print("=" * 70)
        sample = alerts[0]
        print(f"Alert ID:       {sample.alert_id}")
        print(f"Rule:           {sample.rule_id} ({sample.title})")
        print(f"MITRE:          {sample.mitre_technique_id} - {sample.mitre_technique_name} (Tactic: {sample.mitre_tactic})")
        print(f"Kill Chain:     {sample.kill_chain_stage}")
        print(f"Severity:       {sample.severity.upper()} | Confidence: {sample.confidence.upper()}")
        print(f"Host:           {sample.host} | User: {sample.username}")
        print(f"First/Last:     {sample.first_seen} -> {sample.last_seen}")
        print(f"Evidence Links: {len(sample.evidence_references)} records (e.g. offset {sample.evidence_references[0]['byte_offset']} in {sample.evidence_references[0]['raw_file']})")
        print(f"Reasoning:      {sample.reasoning}")

    print("\n[+] Phase 2 execution complete.")


if __name__ == "__main__":
    main()
