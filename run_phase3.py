#!/usr/bin/env python3
"""
CyberTrace Phase 3 CLI Runner.

Executes evidence-based cross-entity correlation across hosts, users,
network addresses, processes, timestamps, and behavioral stages.
Constructs an evidence graph and exports structured correlation reports.

Usage:
  source .venv/bin/activate
  python run_phase3.py
  python run_phase3.py --alerts reports/phase2_alerts.json --output reports/phase3_correlations.json
"""

import argparse
import json
import os
import sys
import time

# Ensure project root is in python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.correlation.correlation_engine import CorrelationEngine
from backend.correlation.relationship_schema import RelationshipType


def main():
    parser = argparse.ArgumentParser(description="CyberTrace Phase 3 Cross-Entity Correlation Runner")
    parser.add_argument(
        "--alerts",
        default="reports/phase2_alerts.json",
        help="Path to Phase 2 JSON alert export (default: reports/phase2_alerts.json)",
    )
    parser.add_argument(
        "--output",
        default="reports/phase3_correlations.json",
        help="Output path for JSON correlation report (default: reports/phase3_correlations.json)",
    )
    parser.add_argument(
        "--temporal-window-ms",
        type=float,
        default=50.0,
        help="Temporal correlation window in milliseconds (default: 50.0)",
    )
    args = parser.parse_args()

    print("=" * 70)
    print("CYBERTRACE - PHASE 3: CROSS-ENTITY CORRELATION ENGINE")
    print("=" * 70)

    if not os.path.isfile(args.alerts):
        print(f"[-] ERROR: Alerts file not found: {args.alerts}")
        print("    Please run 'python run_phase2.py' first to generate alerts.")
        sys.exit(1)

    print(f"[+] Loading alerts from '{args.alerts}'...")
    start_time = time.perf_counter()

    engine = CorrelationEngine(
        alerts_file=args.alerts,
        temporal_window_ms=args.temporal_window_ms,
    )
    results = engine.run()
    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    meta = results["metadata"]
    ent = results["entity_summary"]
    metrics = results["relationship_metrics"]
    graph = results["graph_metrics"]

    print(f"[+] Correlation execution complete in {elapsed_ms:.2f} ms")
    print(f"    - Evaluated alerts:     {meta['total_alerts_evaluated']}")
    print(f"    - Extracted entities:   {ent['unique_hosts']} hosts, {ent['unique_users']} users, {ent['unique_ips']} IPs, {ent['unique_processes']} processes")
    print(f"    - Total relationships:  {meta['total_relationships_identified']}")

    print("\n" + "=" * 70)
    print("CORRELATION METRICS & DISTRIBUTIONS")
    print("=" * 70)

    print("\nRelationships by Dimension:")
    for dim, count in sorted(metrics["by_dimension"].items(), key=lambda x: x[1], reverse=True):
        print(f"  {dim:<15} : {count:>5} relationships")

    print("\nRelationships by Type:")
    for rtype, count in sorted(metrics["by_type"].items(), key=lambda x: x[1], reverse=True):
        print(f"  {rtype:<30} : {count:>5}")

    print("\nConfidence Distribution:")
    for conf, count in sorted(metrics["by_confidence"].items(), key=lambda x: x[1], reverse=True):
        print(f"  {conf:<15} : {count:>5}")

    print("\nObservation Status:")
    for status, count in sorted(metrics["by_observation_status"].items(), key=lambda x: x[1], reverse=True):
        print(f"  {status:<15} : {count:>5}")

    print(f"\n" + "=" * 70)
    print("EVIDENCE GRAPH METRICS & CLUSTERING AUDIT")
    print("=" * 70)
    print(f"Total Graph Nodes:               {graph['total_nodes']}")
    for ntype, count in graph["nodes_by_type"].items():
        print(f"  - {ntype:<15} nodes : {count}")
    print(f"Total Graph Edges:               {graph['total_edges']}")
    print(f"Investigation-Eligible Edges:    {graph.get('investigation_eligible_edges', 'N/A')}")
    print(f"\nConnected Components Audit:")
    print(f"  - Raw Association Components:  {graph.get('raw_connected_components', graph.get('total_connected_components'))} (Largest component: {graph.get('largest_raw_component_nodes', graph.get('largest_component_nodes'))} nodes)")
    print(f"  - Investigation Components:    {graph.get('investigation_connected_components', 'N/A')} (Largest component: {graph.get('largest_investigation_component_nodes', 'N/A')} nodes)")
    print(f"  - Investigation Alert Comps:   {graph.get('investigation_components_with_alerts', 'N/A')}")

    print("\nTop Investigation Hub Nodes:")
    for hub in graph.get("top_hub_nodes", []):
        deg = hub.get("investigation_degree", hub.get("degree", 0))
        print(f"  - [{hub['node_type']}] {hub['label']} (Investigation Degree: {deg})")

    # Sample relationship inspection
    if results["relationships"]:
        print("\n" + "=" * 70)
        print("SAMPLE RELATIONSHIPS")
        print("=" * 70)

        # Sample SAME_HOST
        sample_sh = next((r for r in results["relationships"] if r["relationship_type"] == RelationshipType.SAME_HOST), None)
        if sample_sh:
            print("\n[Sample 1: SAME_HOST]")
            print(f"  ID:          {sample_sh['relationship_id']}")
            print(f"  Endpoints:   {sample_sh['source_observation_id']} <--> {sample_sh['target_observation_id']}")
            print(f"  Dimension:   {sample_sh['correlation_dimension']} | Confidence: {sample_sh['confidence']}")
            print(f"  Eligible:    {sample_sh.get('is_investigation_eligible')}")
            print(f"  Explanation: {sample_sh['explanation']}")

        # Sample SAME_SOURCE_IP
        sample_ip = next((r for r in results["relationships"] if r["relationship_type"] == RelationshipType.SAME_SOURCE_IP), None)
        if sample_ip:
            print("\n[Sample 2: SAME_SOURCE_IP (Network)]")
            print(f"  ID:          {sample_ip['relationship_id']}")
            print(f"  Dimension:   {sample_ip['correlation_dimension']} | Confidence: {sample_ip['confidence']}")
            print(f"  Eligible:    {sample_ip.get('is_investigation_eligible')}")
            print(f"  Explanation: {sample_ip['explanation']}")

        # Sample SAME_PROCESS_IMAGE
        sample_proc = next((r for r in results["relationships"] if r["relationship_type"] == RelationshipType.SAME_PROCESS_IMAGE), None)
        if not sample_proc:
            sample_proc = next((r for r in results["relationships"] if r["relationship_type"] == RelationshipType.SAME_PROCESS), None)
        if sample_proc:
            print(f"\n[Sample 3: {sample_proc['relationship_type']} (Process)]")
            print(f"  ID:          {sample_proc['relationship_id']}")
            print(f"  Dimension:   {sample_proc['correlation_dimension']} | Confidence: {sample_proc['confidence']}")
            print(f"  Eligible:    {sample_proc.get('is_investigation_eligible')}")
            print(f"  Explanation: {sample_proc['explanation']}")

        # Sample POTENTIAL_BEHAVIORAL_SEQUENCE
        sample_seq = next((r for r in results["relationships"] if r["relationship_type"] == RelationshipType.POTENTIAL_BEHAVIORAL_SEQUENCE), None)
        if sample_seq:
            print("\n[Sample 4: POTENTIAL_BEHAVIORAL_SEQUENCE (Behavioral)]")
            print(f"  ID:          {sample_seq['relationship_id']}")
            print(f"  Dimension:   {sample_seq['correlation_dimension']} | Confidence: {sample_seq['confidence']}")
            print(f"  Eligible:    {sample_seq.get('is_investigation_eligible')}")
            print(f"  Status:      {sample_seq['observed_or_inferred']}")
            print(f"  Explanation: {sample_seq['explanation']}")

    # Provenance Exhaustive Verification
    print("\n" + "=" * 70)
    print("EXHAUSTIVE PROVENANCE VERIFICATION AUDIT")
    print("=" * 70)
    raw_edr = "edr_events.json"
    if os.path.isfile(raw_edr):
        prov = engine.verify_all_provenance(raw_edr)
        print(f"  Underlying references tested: {prov['total_references_tested']}")
        print(f"  Unique references:            {prov['total_unique_references']}")
        print(f"  Verified exact byte match:    {prov['verified_count']} ({prov['verification_rate_pct']:.2f}%)")
        print(f"  Failed references:            {prov['failed_count']}")
        print(f"  Duplicate references:         {prov['duplicate_count']}")
        print(f"  Exhaustively verified:        {prov['is_exhaustively_verified']}")
    else:
        print(f"  [!] Raw EDR file '{raw_edr}' not found; skipped disk verification.")

    # Export
    engine.export_results(args.output)
    print(f"\n[+] Successfully exported correlation report and evidence graph to '{args.output}'")
    print("=" * 70)


if __name__ == "__main__":
    main()
