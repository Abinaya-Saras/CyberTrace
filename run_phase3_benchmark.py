#!/usr/bin/env python3
"""
CyberTrace Phase 3 Correlation Engine Benchmark Suite.

Rigorously benchmarks:
  - Alerts evaluated (90)
  - Multi-iteration correlation latency and throughput (iterations=5)
  - Peak RAM consumption via psutil
  - Component-by-component execution time breakdown
  - Relationship counts by dimension, type, confidence, and observation status
  - Evidence Graph complexity (nodes, edges, connected components, hub centrality)
  - Evidence provenance verification (verifying raw byte offsets against edr_events.json)

Usage:
  source .venv/bin/activate
  python run_phase3_benchmark.py
"""

import json
import os
import random
import sys
import time
import psutil

# Ensure project root is in python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.correlation.confidence import classify_ip
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
from backend.correlation.graph_builder import GraphBuilder
from backend.detection.alert_schema import Alert


def get_process_memory_mb() -> float:
    """Return resident set size (RSS) memory in megabytes for the current process."""
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / (1024 * 1024)


def benchmark_phase3(
    alerts_file: str = "reports/phase2_alerts.json",
    raw_edr_file: str = "edr_events.json",
    iterations: int = 5,
    sample_offsets_count: int = 50,
):
    print("=" * 75)
    print("CYBERTRACE - PHASE 3 CORRELATION ENGINE BENCHMARK")
    print("=" * 75)

    if not os.path.isfile(alerts_file):
        print(f"[-] Alerts file not found: {alerts_file}")
        print("    Please run 'python run_phase2.py' first.")
        sys.exit(1)

    initial_ram = get_process_memory_mb()
    print(f"[*] Initial process RAM: {initial_ram:.2f} MB")

    with open(alerts_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    raw_alerts = data.get("alerts", data) if isinstance(data, dict) else data
    alerts = [Alert.from_dict(a) for a in raw_alerts]
    print(f"[*] Loaded alerts:       {len(alerts)} alerts from '{alerts_file}'")

    # 1. Component-by-Component Timing Breakdown
    print("\n" + "-" * 75)
    print("CORRELATION PIPELINE TIMING BREAKDOWN (Single Run)")
    print("-" * 75)

    # A. Entity Extractor
    t0 = time.perf_counter()
    extractor = EntityExtractor(alerts)
    t_extract = (time.perf_counter() - t0) * 1000.0
    print(f"  Entity Extraction              | {len(extractor.hosts)} hosts, {len(extractor.users)} users, {len(extractor.ips)} IPs | {t_extract:>6.2f} ms")

    # B. Host Correlator
    t0 = time.perf_counter()
    host_corr = HostCorrelator()
    host_rels = host_corr.correlate(extractor)
    t_host = (time.perf_counter() - t0) * 1000.0
    print(f"  Host Correlator                | {len(host_rels):>4} SAME_HOST relationships             | {t_host:>6.2f} ms")

    # C. User Correlator
    t0 = time.perf_counter()
    user_corr = UserCorrelator()
    user_rels = user_corr.correlate(extractor)
    t_user = (time.perf_counter() - t0) * 1000.0
    print(f"  User Correlator                | {len(user_rels):>4} SAME_USER relationships             | {t_user:>6.2f} ms")

    # D. Network Correlator
    t0 = time.perf_counter()
    net_corr = NetworkCorrelator()
    net_rels = net_corr.correlate(extractor)
    t_net = (time.perf_counter() - t0) * 1000.0
    print(f"  Network Correlator             | {len(net_rels):>4} SAME_IP relationships               | {t_net:>6.2f} ms")

    # E. Process Correlator
    t0 = time.perf_counter()
    proc_corr = ProcessCorrelator()
    proc_rels = proc_corr.correlate(extractor)
    t_proc = (time.perf_counter() - t0) * 1000.0
    print(f"  Process Correlator             | {len(proc_rels):>4} SAME/CHILD_PROC relationships      | {t_proc:>6.2f} ms")

    # F. Temporal Correlator
    t0 = time.perf_counter()
    temp_corr = TemporalCorrelator(time_window_ms=50.0)
    temp_rels = temp_corr.correlate(extractor)
    t_temp = (time.perf_counter() - t0) * 1000.0
    print(f"  Temporal Correlator            | {len(temp_rels):>4} TEMPORALLY_NEAR relationships      | {t_temp:>6.2f} ms")

    # G. Behavioral Correlator
    t0 = time.perf_counter()
    beh_corr = BehavioralSequenceCorrelator()
    beh_rels = beh_corr.correlate(extractor)
    t_beh = (time.perf_counter() - t0) * 1000.0
    print(f"  Behavioral Sequence Correlator | {len(beh_rels):>4} BEHAVIORAL_SEQ relationships       | {t_beh:>6.2f} ms")

    # H. Graph Builder
    all_rels = host_rels + user_rels + net_rels + proc_rels + temp_rels + beh_rels
    t0 = time.perf_counter()
    builder = GraphBuilder()
    graph = builder.build_graph(extractor, all_rels)
    t_graph = (time.perf_counter() - t0) * 1000.0
    print(f"  Evidence Graph Assembly        | {len(graph.nodes):>4} nodes, {len(graph.edges):>4} edges               | {t_graph:>6.2f} ms")

    # 2. Multi-Iteration Full Engine Benchmark
    print("\n" + "-" * 75)
    print(f"MULTI-ITERATION BENCHMARK ({iterations} runs)")
    print("-" * 75)

    latencies = []
    peak_ram = initial_ram

    for i in range(1, iterations + 1):
        engine = CorrelationEngine(alerts=alerts, temporal_window_ms=50.0)
        t_start = time.perf_counter()
        res = engine.run()
        elapsed_ms = (time.perf_counter() - t_start) * 1000.0
        latencies.append(elapsed_ms)

        current_ram = get_process_memory_mb()
        peak_ram = max(peak_ram, current_ram)
        throughput = (len(alerts) / (elapsed_ms / 1000.0))

        print(f"  Run {i}: {elapsed_ms:>6.2f} ms ({throughput:>8,.0f} alerts/sec) | RAM: {current_ram:.2f} MB")

    avg_latency = sum(latencies) / len(latencies)
    avg_throughput = len(alerts) / (avg_latency / 1000.0)

    print(f"\n  Average latency:    {avg_latency:.2f} ms")
    print(f"  Min latency:        {min(latencies):.2f} ms")
    print(f"  Max latency:        {max(latencies):.2f} ms")
    print(f"  Average Throughput: {avg_throughput:,.0f} alerts/sec")
    print(f"  Peak RAM:           {peak_ram:.2f} MB (Delta: +{peak_ram - initial_ram:.2f} MB)")

    # 3. Correlation Metrics & Breakdown
    print("\n" + "-" * 75)
    print("CORRELATION RELATIONSHIPS & DISTRIBUTIONS")
    print("-" * 75)

    last_res = res
    metrics = last_res["relationship_metrics"]
    print(f"Total relationships:     {last_res['metadata']['total_relationships_identified']}")
    print(f"Dimension distribution:  {metrics['by_dimension']}")
    print(f"Type distribution:       {metrics['by_type']}")
    print(f"Confidence distribution: {metrics['by_confidence']}")
    print(f"Status distribution:     {metrics['by_observation_status']}")

    # 4. Graph Metrics & Connected Components
    print("\n" + "-" * 75)
    print("EVIDENCE GRAPH TOPOLOGY & HUB ANALYSIS")
    print("-" * 75)
    gmeta = last_res["graph_metrics"]
    print(f"Total Graph Nodes:               {gmeta['total_nodes']} {gmeta['nodes_by_type']}")
    print(f"Total Graph Edges:               {gmeta['total_edges']}")
    print(f"Investigation-Eligible Edges:    {gmeta.get('investigation_eligible_edges', 'N/A')}")
    print(f"Raw Connected Components:        {gmeta.get('raw_connected_components', gmeta.get('total_connected_components'))} (Largest: {gmeta.get('largest_raw_component_nodes', gmeta.get('largest_component_nodes'))} nodes)")
    print(f"Investigation Components:        {gmeta.get('investigation_connected_components', 'N/A')} (Largest: {gmeta.get('largest_investigation_component_nodes', 'N/A')} nodes)")
    print(f"Investigation Alert Comps:       {gmeta.get('investigation_components_with_alerts', 'N/A')}")

    print("\nTop 5 Investigation Hub Nodes by Degree:")
    for hub in gmeta.get("top_hub_nodes", []):
        deg = hub.get("investigation_degree", hub.get("degree", 0))
        print(f"  - [{hub['node_type']}] {hub['label']} -> Investigation Degree: {deg}")

    # 5. Provenance Verification
    print("\n" + "-" * 75)
    print("EXHAUSTIVE EVIDENCE PROVENANCE VERIFICATION (All References)")
    print("-" * 75)

    if not os.path.isfile(raw_edr_file):
        print(f"[-] Raw EDR log not found: {raw_edr_file}. Skipping raw byte verification.")
        verified_pct = 0.0
        verified_count = 0
        total_refs = 0
        failed_count = 0
    else:
        prov = engine.verify_all_provenance(raw_edr_file)
        total_refs = prov["total_references_tested"]
        verified_count = prov["verified_count"]
        failed_count = prov["failed_count"]
        verified_pct = prov["verification_rate_pct"]
        duplicate_count = prov["duplicate_count"]

        print(f"  Underlying references tested: {total_refs}")
        print(f"  Unique references:            {prov['total_unique_references']}")
        print(f"  Verified exact byte match:    {verified_count}/{total_refs} ({verified_pct:.2f}%)")
        print(f"  Failed references:            {failed_count}")
        print(f"  Duplicate references:         {duplicate_count}")
        print(f"  Exhaustively verified:        {prov['is_exhaustively_verified']}")

    # 6. Benchmark Summary Table
    print("\n" + "=" * 75)
    print("PHASE 3.1 AUDIT BENCHMARK SUMMARY TABLE")
    print("=" * 75)
    print("| Metric                                | Result                        |")
    print("|---------------------------------------|-------------------------------|")
    print(f"| Alerts evaluated                      | {len(alerts):<30}|")
    print(f"| Unique entities extracted             | {len(extractor.hosts)} hosts, {len(extractor.users)} users, {len(extractor.ips)} IPs  |")
    print(f"| Correlation relationships             | {last_res['metadata']['total_relationships_identified']:<30}|")
    print(f"| Evidence Graph Nodes / Edges          | {gmeta['total_nodes']} nodes / {gmeta['total_edges']} edges           |")
    print(f"| Investigation Eligible Edges          | {gmeta.get('investigation_eligible_edges', 'N/A'):<30}|")
    print(f"| Raw Connected Components              | {gmeta.get('raw_connected_components', gmeta.get('total_connected_components'))} (Largest: {gmeta.get('largest_raw_component_nodes', gmeta.get('largest_component_nodes'))} nodes)  |")
    print(f"| Investigation Components              | {gmeta.get('investigation_connected_components', 'N/A')} (Largest: {gmeta.get('largest_investigation_component_nodes', 'N/A')} nodes)  |")
    print(f"| Investigation Alert Clusters          | {gmeta.get('investigation_components_with_alerts', 'N/A')} distinct endpoint clusters |")
    print(f"| Average execution latency             | {avg_latency:.2f} ms                     |")
    print(f"| Throughput                            | {avg_throughput:,.0f} alerts/sec             |")
    print(f"| Peak RAM usage                        | {peak_ram:.2f} MB                      |")
    print(f"| Net RAM delta                         | +{peak_ram - initial_ram:.2f} MB                      |")
    print(f"| Exhaustive Provenance Verification    | {verified_count}/{total_refs} ({verified_pct:.2f}%)             |")
    print("=" * 75)
    print("=" * 75)


if __name__ == "__main__":
    benchmark_phase3()
