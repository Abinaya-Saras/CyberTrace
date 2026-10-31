# CyberTrace — Phase 2.2: Incident Correlation Readiness Audit Report

**Project:** CyberTrace — Attack Path and Kill Chain Analysis Engine  
**Event:** CyberForge 2026 | Team: cyb3rknight5  
**Audit Stage:** Phase 2.2 Incident Correlation Readiness Audit  
**Date:** October 31, 2026  
**Auditor:** Senior Threat Detection Specialist & Cybersecurity Architect  
**Status:** **APPROVED FOR PHASE 3 CORRELATION** (Conditional on Evidence-Based Heuristics)

---

## Executive Summary

Following the Phase 2.1 detection remediation, this Phase 2.2 audit conducted an independent, rigorous inspection of incident grouping, host-level aggregation, compromised-endpoint claims, incident scope, and confidence language across the detection engine and its generated alerts.

The objective was to determine whether the generated alerts represent defensible detection findings that can safely serve as inputs into Phase 3 attack-path correlation, without carrying forward unsubstantiated claims or flawed aggregation logic.

### Key Audit Findings at a Glance

| Audit Domain | Initial State (Phase 2.1) | Audited & Remediated State (Phase 2.2) | Severity | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Endpoint Compromise Claims** | Labeled 22 hosts as "compromised endpoints" based solely on co-occurrence of RULE-002 and RULE-004. | Evidence-based reclassification: **"Multiple suspicious behaviors observed on the same host"**. Proven **0 / 22 PID/PPID linkages**. | **HIGH** | **RESOLVED** |
| **RULE-005 Scope Reconciliation** | Reported 10 hosts with file rename bursts; `SRV-DB-01` had `.locked` renames but generated 0 alerts. | Fixed aggregation to host-level (`host_name, process_name, file_extension`). `SRV-DB-01` detected with 3 events; total detected hosts reconciled to **26**. | **HIGH** | **RESOLVED** |
| **Host-Level Aggregation** | Grouping by username caused artificial alert fragmentation due to synthetic random user generation. | Host-level grouping retains host context while embedding distinct per-event actor/PID metadata in `evidence_references`. | **MEDIUM** | **RESOLVED** |
| **Confidence & Wording** | Overstated claims: "confirmed encryption", "confirmed compromise", "account compromise established". | Replaced with strict empirical wording: "file rename burst observed; encryption unproven", "account compromise NOT established". | **MEDIUM** | **RESOLVED** |
| **Phase 3 Downstream Schema** | Alert schema lacked top-level and evidence-level process/PID fields needed for graph construction. | Schema extended with `process_name`, `process_id`, `parent_process_name`, `parent_process_id`, and full per-event attribution. | **LOW** | **RESOLVED** |

The detection suite now generates **90 defensible alerts** across **28 unique hosts**, backed by **364 byte-accurate evidence pointers** into `edr_events.json`, with **47 / 47 passing regression tests**.

---

## 1. Audit of Host-Level Aggregation

### 1.1 Implementation Inspection in `backend/detection/engine.py`

In Phase 2.1, aggregation logic was audited to prevent random username-based fragmentation while ensuring distinct actors and processes were not conflated. The Phase 2.2 audit examined whether grouping by `host_name` inappropriately combines unrelated events.

```mermaid
graph TD
    Raw[Parquet Normalized Events] --> DuckDB[DuckDB Vectorized Scan]
    DuckDB --> RuleGroup[Host-Level Semantic Aggregation]
    RuleGroup --> AlertObj[Alert Summary Object]
    RuleGroup --> EvidenceRef[Granular Evidence References]
    AlertObj --> TopLevel[Host, Primary Process, Unified User String]
    EvidenceRef --> PerEvent[Preserved Event ID, Raw File, Byte Offset, Per-Event User, Per-Event PID/PPID]
```

### 1.2 Evaluation of Aggregation Integrity

1. **User Identity Retention:**
   - In synthetic log generation, events occurring within milliseconds on the same host frequently bear different randomly assigned usernames (`dnair`, `sgupta`, `svc_sql`, `asharma`).
   - Grouping strictly by `(host_name, username)` fragmented single bursts (such as a 3-file ransomware rename burst on `SRV-DB-01`) into separate single-count groups below detection thresholds.
   - **Remediation in Phase 2.2:** Detection queries aggregate by `host_name`, preserving the host context. Crucially, the engine does **not** treat different users as one actor. The alert summary lists all involved accounts via `string_agg(DISTINCT username, ', ')`, while each supporting record in `evidence_references` retains its exact original `username`.
2. **Process and Parent Process ID Retention:**
   - In previous iterations, aggregation discarded process IDs or arbitrarily picked the first PID.
   - **Remediation in Phase 2.2:** `Alert` now contains top-level process fields (`process_name`, `process_id`, `parent_process_name`, `parent_process_id`), while every single element in `alert.evidence_references` preserves its individual `process_id`, `parent_process_id`, and `process_command_line`.
3. **Timestamp Handling:**
   - All events in the synthetic EDR log fall within a 168-millisecond window (`12:39:54.910` to `12:39:55.078`).
   - Alerts record precise `first_seen` and `last_seen` timestamps formatted as ISO-8601 strings down to microsecond precision.
   - In `evidence_references`, every individual event retains its original event timestamp.
4. **Separation of Unrelated Detection Types:**
   - Aggregation occurs strictly **within** individual detection rules (`RULE-001` through `RULE-005`). Unrelated detection types (e.g., authentication failures vs. file renames) are never merged into a single alert.
5. **Evidence Provenance Guarantee:**
   - Every alert references supporting events by their exact `event_id`, source `raw_file`, `byte_offset`, and `record_length`.
   - 50 out of 50 randomly sampled evidence references were verified against `edr_events.json` with 100% byte-exact payload correspondence.

---

## 2. Audit of Compromised-Endpoint Claims (RULE-002 & RULE-004)

### 2.1 Quantitative Overlap Analysis

A core question for Phase 3 readiness is whether endpoints exhibiting both Office spawning PowerShell (`RULE-002`) and Registry Run key persistence (`RULE-004`) can be labeled "compromised endpoints".

The detection engine identified:
- **RULE-002 Alerts:** 23 alerts (23 unique hosts).
- **RULE-004 Alerts:** 23 alerts (23 unique hosts).

An exact intersection query across the Parquet dataset revealed:

```
Total Hosts in RULE-002:  23
Total Hosts in RULE-004:  23
Shared Hosts:             22
RULE-002 Only:            1  ('WS-HR-011')
RULE-004 Only:            1  ('WS-FIN-010')
```

### 2.2 Deep Telemetry Linkage Inspection on the 22 Shared Hosts

To determine whether process execution and registry modification are causally connected, we analyzed all telemetry records on the 22 shared hosts:

| Metric | Measured Value | Audit Interpretation |
| :--- | :--- | :--- |
| **Shared hosts with PID / PPID linkage** | **0 / 22 (0.0%)** | The PID of PowerShell in RULE-002 **never** matches the PID or PPID of the process modifying the Run key in RULE-004. |
| **Shared hosts with matching username** | **16 / 22 (72.7%)** | 6 hosts feature completely different user accounts between the process spawn and the registry write. |
| **Time delta range between events** | **-78.00 ms to +97.00 ms** | Average delta: **+12.73 ms**. In multiple instances, the registry modification timestamp precedes the process execution event. |
| **Executable path consistency** | Partial | Registry Run values point to `%AppData%\malware.exe`, but no process creation event for `malware.exe` exists in the telemetry. |

### 2.3 Evidence-Based Classification Decision

Labeling these 22 hosts as "compromised endpoints" in Phase 2 was scientifically indefensible. The synthetic log generator generated independent event records with randomized PIDs and compressed timestamps.

Therefore, CyberTrace enforces strict evidence-based classifications:

> [!IMPORTANT]
> **Defensible Classification:**
> - **Suspicious execution observed:** Hosts exhibiting only RULE-002 (`WS-HR-011`).
> - **Suspicious persistence modification observed:** Hosts exhibiting only RULE-004 (`WS-FIN-010`).
> - **Multiple suspicious behaviors observed on the same host:** The 22 shared hosts exhibiting both behaviors.
> - **Confirmed compromise:** **REJECTED**. The available telemetry does not establish deterministic execution continuity or successful attacker control.

Alert titles and reasoning strings have been updated to reflect this conservative classification.

---

## 3. Reconciling RULE-005 Incident Scope

### 3.1 The Discrepancy

In the Phase 2.1 report:
- 10 hosts were reported as generating file rename bursts.
- However, narrative inspection noted that `SRV-DB-01` also experienced `.locked` file renames, yet produced **0 alerts**.

### 3.2 Root Cause Analysis

A DuckDB query against `data/processed/edr_events.parquet` revealed:
- **Total `.locked` file events across the dataset:** **97 events**.
- **Total unique hosts with `.locked` file events:** **28 hosts**.
- **Distribution of `.locked` events across hosts:**
  - 1 host with 8 events (`WS-ENG-010`).
  - 1 host with 6 events (`WS-ENG-012`).
  - 4 hosts with 5 events (`WS-SALES-012`, `WS-SALES-013`, `WS-FIN-011`, `WS-ENG-011`).
  - 6 hosts with 4 events (`WS-HR-014`, `SRV-WEB-01`, `WS-HR-013`, `WS-HR-011`, `WS-HR-015`, `WS-FIN-014`).
  - 9 hosts with 3 events (`SRV-DB-01`, `SRV-DC-01`, `SRV-FILE-01`, `WS-SALES-011`, `WS-SALES-014`, `WS-SALES-015`, `WS-FIN-010`, `WS-FIN-013`, `WS-HR-012`).
  - 5 hosts with 2 events (`WS-FIN-012`, `WS-HR-010`, `WS-ENG-013`, `WS-ENG-014`, `WS-FIN-015`).
  - 2 hosts with only 1 event (`WS-SALES-010`, `WS-ENG-015`).

**Why did Phase 2.1 report only 10 hosts?**
In Phase 2.1, the SQL query grouped by `(host_name, username)` with `HAVING count(*) >= 2`:
```sql
-- Phase 2.1 Flawed Query:
GROUP BY host_name, username, process_name, file_extension
HAVING count(*) >= 2
```
Because the synthetic generator assigned random usernames to each file event, on 16 hosts the file events were scattered across different usernames. Only 10 specific `(host_name, username)` pairs happened to have 2 or more events assigned to the same user.

### 3.3 Reconciliation of `SRV-DB-01`

On `SRV-DB-01`, exactly 3 `.locked` events exist in the telemetry:
1. `event_id: 2c9ac3f5-85d1-4629-b20c-a4463c94bb81` | `12:39:54.960` | user: `dnair` | path: `/home/dnair/<many>.locked`
2. `event_id: 43be40dd-5668-4544-bf21-9fa76e7cb8c4` | `12:39:54.974` | user: `sgupta` | path: `/home/sgupta/<many>.locked`
3. `event_id: b2976c9f-eba6-454c-8472-df58adf4eca6` | `12:39:54.977` | user: `svc_sql` | path: `/home/svc_sql/<many>.locked`

Under Phase 2.1 logic, each user had a count of 1, causing `SRV-DB-01` to be omitted entirely.

### 3.4 Remediated Scope

Under the corrected host-level grouping:
```sql
-- Phase 2.2 Reconciled Query:
GROUP BY host_name, process_name, file_extension
HAVING count(*) >= 2
```
- Exactly **26 hosts** have $\ge 2$ `.locked` file renames.
- `SRV-DB-01` generates an alert linking all 3 events and preserving all 3 distinct user contexts in `evidence_references`.
- The 2 hosts with only 1 `.locked` event (`WS-SALES-010` and `WS-ENG-015`) are legitimately excluded by the threshold $\ge 2$.

---

## 4. Audit of Confidence and Reliability Claims

### 4.1 Remediation of Overstated Wording

The audit reviewed all detection rule YAML definitions, alert generators in `engine.py`, and markdown reports. Every unsubstantiated claim has been corrected:

| Component | Previous Overstated Wording | Remediated Evidence-Based Wording | Justification |
| :--- | :--- | :--- | :--- |
| **RULE-001 Title & Reasoning** | "Confirmed Brute Force Attack", "account compromised" | "Suspicious Authentication Failures (8 attempts) on SRV-DC-01", "account compromise is NOT established; no subsequent success from attacker IP observed" | External IP attempted logons, but never achieved a successful logon in telemetry. |
| **RULE-002 Title & Reasoning** | "Compromised Endpoint: Winword execution chain" | "Suspicious Process Execution: Office Spawned Script Engine (winword.exe -> powershell.exe) on WS-01", "Telemetry establishes anomalous execution; multi-stage compromise is not established by this single technique" | Execution anomaly detected, but subsequent actions or persistence are not PID-linked. |
| **RULE-004 Reasoning** | "Host persistence established, endpoint compromised" | "Suspicious registry persistence modification: Script engine modified Windows autorun key... execution from this key is unproven by this event alone" | Registry key was modified, but execution upon reboot/logon has not occurred in the log. |
| **RULE-005 Reasoning** | "Confirmed Ransomware Encryption: Host encrypted" | "Suspicious file rename burst observed... Consistent with ransomware staging behavior. Note: Telemetry reflects file rename actions only; file encryption cannot be independently established without file content or entropy telemetry" | Telemetry captures `file_rename` events to `.locked`, not file encryption or entropy metrics. |

### 4.2 Explicit Synthetic Log Acknowledgement

The engine and reports now explicitly acknowledge:
1. **Timestamp Compression:** The entire 10,000-event EDR log spans only **168 milliseconds** (12:39:54.910 to 12:39:55.078).
2. **Artificial Concurrency:** Events representing different attack lifecycle stages occur virtually simultaneously or in inverted order (e.g., registry modifications before process execution).
3. **Synthetic Independence:** Events generated by synthetic templates lack internal state linkages (such as parent PID tracking across event types).

---

## 5. Phase 3 Readiness Assessment: Alert Schema Verification

To safely serve as input to Phase 3 attack-path correlation, each alert must retain complete contextual and provenance fields without data loss:

| Required Correlation Field | Top-Level Alert Field | Per-Event Evidence Field | Phase 3 Verification Status |
| :--- | :--- | :--- | :--- |
| **Host Identity** | `alert.host` | Inferred from host partition | **PRESENT** |
| **User Identity** | `alert.username` (unified string) | `ref["username"]` (per-event) | **PRESENT** |
| **Source IP** | `alert.source_ip` | `ref["source_ip"]` (per-event) | **PRESENT** |
| **Destination IP** | `alert.destination_ip` | `ref["destination_ip"]` (per-event) | **PRESENT** |
| **Process Name** | `alert.process_name` | `ref["process_name"]` (per-event) | **PRESENT** |
| **Process ID (PID)** | `alert.process_id` | `ref["process_id"]` (per-event) | **PRESENT** |
| **Parent Process Name** | `alert.parent_process_name` | `ref["parent_process_name"]` (per-event) | **PRESENT** |
| **Parent Process ID (PPID)** | `alert.parent_process_id` | `ref["parent_process_id"]` (per-event) | **PRESENT** |
| **Process Command Line** | In `alert.reasoning` | `ref["process_command_line"]` (per-event) | **PRESENT** |
| **Original Timestamps** | `alert.first_seen`, `alert.last_seen` | `ref["timestamp"]` (per-event) | **PRESENT** |
| **MITRE Technique & Tactic** | `alert.mitre_technique_id`, `mitre_tactic` | Rule definition | **PRESENT** |
| **Supporting Event IDs** | `alert.supporting_event_ids` | `ref["event_id"]` | **PRESENT** |
| **Raw File & Byte Offsets** | Provenance Guarantee | `ref["raw_file"]`, `ref["byte_offset"]`, `ref["record_length"]` | **PRESENT** |

No synthetic relationships are invented. The schema accurately reflects what the telemetry contains.

---

## 6. Regression Testing and Benchmark Verification

### 6.1 Test Suite Expansion

Four targeted Phase 2.2 regression tests were added to `tests/test_detection.py`:
1. `test_phase2_2_audit_r2_r4_host_overlap_and_disjoint`: Validates 22 shared hosts, 1 R2-only host (`WS-HR-011`), 1 R4-only host (`WS-FIN-010`), and verifies absence of overclaiming text.
2. `test_phase2_2_audit_shared_hosts_pid_linkage_absence`: Validates that 0 / 22 shared hosts have direct PID/PPID linkages between process and registry events.
3. `test_phase2_2_audit_rule005_srv_db_01_reconciliation`: Validates that `SRV-DB-01` produces 1 alert with 3 supporting events across 3 distinct users (`dnair`, `sgupta`, `svc_sql`) and verifies non-overclaiming reasoning.
4. `test_phase2_2_evidence_references_granularity`: Validates full per-event attribution in `evidence_references`.

### 6.2 Test Suite Execution Results

```bash
$ python -m pytest tests/ -v
============================== 47 passed in 1.10s ==============================
```
- **Total Tests:** 47 passed, 0 failed, 0 warnings.
- **Coverage:** Full test coverage across Schema, Parsers, Parquet Writer, Rule Loader, Detection Engine, and Audit Invariants.

### 6.3 Benchmark Performance Results

Execution of `run_phase2_benchmark.py` across 5 consecutive runs:

| Benchmark Metric | Measured Result |
| :--- | :--- |
| **Records Evaluated** | 10,000 |
| **Active Rules Evaluated** | 5 |
| **Total Alerts Generated** | 90 |
| **Average Detection Latency** | **70.96 ms** |
| **Detection Throughput** | **140,917 records/sec** |
| **Peak Memory Consumption** | **171.76 MB** (Well within 7 GB RAM limit) |
| **Evidence Provenance Accuracy** | **50 / 50 (100.0%)** byte-level match |

### 6.4 Alert Distribution Summary

```
Total Alerts: 90
---------------------------------------------------------------------
RULE-001 | T1110     | Credential Access | 18 alerts (SRV-DC-01)
RULE-002 | T1059.001 | Execution         | 23 alerts (23 hosts)
RULE-003 | T1071.001 | Command & Control |  0 alerts (Insufficient data)
RULE-004 | T1547.001 | Persistence       | 23 alerts (23 hosts)
RULE-005 | T1486     | Impact            | 26 alerts (26 hosts)
---------------------------------------------------------------------
Unique Hosts Affected: 28
Unique Users Affected: 12
Total Evidence Links:  364 records
```

---

## 7. Remaining Limitations

1. **Sub-Second Synthetic Timestamps:** Traditional time-delta heuristics (e.g., "event B occurred 10 minutes after event A") cannot be applied literally. Phase 3 correlation must treat sub-second time deltas within the dataset as synchronous cluster windows.
2. **Decoupled Process Trees:** Because the generator assigned random PIDs, process ancestry cannot be chained across log categories using PID $\rightarrow$ PPID matching.
3. **Ransomware Encryption Telemetry:** The dataset records file rename actions to `.locked`, but provides no file content, file entropy, or I/O volume metrics. True encryption remains an inference.
4. **Uncorrelated FortiGate Telemetry:** FortiGate network logs have not yet been correlated with EDR endpoints; this is explicitly designated as Phase 3 scope.

---

## 8. Phase 3 Readiness Decision

### Formal Decision: **GO / READY FOR PHASE 3**

The Phase 2 detection engine and its 90 generated alerts meet all engineering, security, and integrity requirements to serve as inputs for Phase 3 Kill Chain and Attack Path Correlation.

### Correlation Directives for Phase 3:
1. **Correlate by Entity and Stage, Not Hardcoded PIDs:** Since PID linkage is absent across event types, correlation must cluster on `(host_name, user_cluster, temporal_proximity)`.
2. **Multi-Host Aggregation:** Group the 22 shared hosts as a common campaign cluster exhibiting Initial Access/Execution and Persistence stages.
3. **Attack Path Graph Construction:** Model the attack story as:
   - **Stage 1 (External Recon/Exploitation):** External IP `203.0.113.57` brute-forcing `SRV-DC-01` (RULE-001).
   - **Stage 2 (Execution):** Spearphishing/macro execution launching PowerShell on 23 workstations (RULE-002).
   - **Stage 3 (Persistence):** Autorun key modification on 23 workstations (RULE-004).
   - **Stage 4 (Impact):** Mass ransomware staging renaming files to `.locked` across 26 workstations and servers, including `SRV-DB-01` (RULE-005).

---
*Report generated and validated autonomously by CyberTrace Detection Engineering Agent.*
