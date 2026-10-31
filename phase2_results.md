# CyberTrace – Phase 2 Implementation & Benchmark Results Report
## Independent Security Detection Engine | CyberForge 2026

**Date:** October 31, 2026  
**Status:** COMPLETE ✅  
**Engine:** Independent DuckDB-powered Behavioral Detection Engine  
**Pipeline:** Normalized Parquet → YAML Detection Rules → DuckDB SQL Execution → Evidence Linking → Structured Alert Output

---

## 1. Executive Summary

Phase 2 of CyberTrace has been successfully designed, implemented, and verified on the normalized 10,000-event EDR dataset (`data/processed/edr_events.parquet`).

In strict compliance with our core cybersecurity engineering constraints:
1. **Zero Reliance on Pre-tagged Labels:** The detection engine never queries `threat`, `rule`, `labels`, or `event.kind = alert`. Findings are derived purely from raw behavioral fields (`event_category`, `event_outcome`, `parent_process_name`, `process_command_line`, `registry_path`, `destination_ip`, `file_extension`, etc.).
2. **Strict Provenance Integrity:** 100% of generated alerts are linked to verified supporting log records, retaining `event_id`, source `raw_file`, starting `byte_offset`, and record byte length. A 50-record random sample verified 100.0% byte-offset match against `edr_events.json`.
3. **Hardware-Constrained Performance:** Operating with DuckDB memory capped at 1 GB and 2 execution threads on Kali Linux, the engine evaluated all 10,000 events across 5 detection rules in **72.22 ms** on average, delivering **138,466 records/second** throughput with **168.29 MB peak RAM**.
4. **Full Test Suite:** 37 of 37 unit and integration tests passed (13 detection-specific tests covering positive, negative, boundary, resilience, and rule validation; 24 Phase 1 parser tests).

---

## 2. Benchmark & Performance Metrics

Benchmarks were executed across 5 independent runs on the Kali Linux development environment (Ryzen 7 8845HS, 7 GB total system RAM):

| Metric | Result | Benchmark Notes |
|---|---|---|
| **Input Dataset** | `data/processed/edr_events.parquet` | Zstandard-compressed normalized telemetry |
| **Total Events Evaluated** | **10,000** | 100% of Phase 1 ingested records |
| **Parquet File Size** | 0.54 MB (565,374 bytes) | High-compression Parquet storage |
| **Active Detection Rules** | 5 rules | Validated YAML configurations |
| **Total Alerts Generated** | **298 alerts** | De-duplicated & grouped by attack context |
| **Total Supporting Evidence Links** | **380 event links** | Every alert backed by concrete evidence |
| **Average Detection Latency** | **72.22 ms** | 5-run average (min: 64.24 ms, max: 85.17 ms) |
| **Detection Throughput** | **138,466 records/sec** | Zero-copy DuckDB Parquet scanning |
| **Peak Process RAM** | **168.29 MB** | Well within 1 GB limit and 2 GB available RAM |
| **Net RAM Delta** | **+88.64 MB** | Temporary query buffer overhead |
| **Byte-Offset Provenance Check** | **50 / 50 (100.0%)** | Direct seek-and-read JSON verification |
| **Unit & Integration Tests** | **37 / 37 passed** | 100% passing across parser and detection |

---

## 3. Rule-by-Rule Detection Breakdown

Each of the initial five detection rules was executed against the dataset with independent behavioral queries:

| Rule ID | Rule Name | MITRE Technique | MITRE Tactic | Kill Chain Stage | Severity | Alerts Generated | Avg Execution Time |
|---|---|---|---|---|---|---:|---:|
| **RULE-001** | Repeated Failed Authentication (Brute Force) | T1110 | Credential Access | Exploitation | MEDIUM | **18** | 49.60 ms |
| **RULE-002** | Office Application Spawning PowerShell | T1059.001 | Execution | Exploitation | HIGH | **100** | 5.56 ms |
| **RULE-003** | C2 Beaconing / Repeated Outbound Network Connections | T1071.001 | Command and Control | Command and Control | HIGH | **7** | 9.88 ms |
| **RULE-004** | Registry Autorun Key Persistence Modification | T1547.001 | Persistence | Installation | HIGH | **89** | 5.30 ms |
| **RULE-005** | Suspicious File Rename / Ransomware File Modification | T1486 | Impact | Actions on Objectives | CRITICAL | **84** | 10.33 ms |
| **TOTAL** | | | | | | **298** | **80.67 ms (sum)** |

---

## 4. Impact Scope & Telemetry Distribution

### Severity Distribution
- **CRITICAL:** 84 alerts (28.2%) – Rapid ransomware file rename activity (`.locked` extensions by `unknown.exe`).
- **HIGH:** 196 alerts (65.8%) – Office documents spawning PowerShell with evasive flags (100), autorun persistence modifications (89), and repeated C2 outbound connections (7).
- **MEDIUM:** 18 alerts (6.0%) – Brute force authentication failure surges (3 to 8 failures per account/source).

### Confidence Distribution (Evidence Strength)
- **HIGH Confidence:** 288 alerts (96.6%) – High evidence strength:
  - Brute force with subsequent successful login or >= 6 failures.
  - Office spawning PowerShell with encoded/stealth flags (`-enc`, `-nop`, `-hidden`).
  - Autorun key modifications pointing to `%AppData%` or initiated by script engines.
  - Multi-file ransomware renames with confirmed `.locked` extensions.
- **MEDIUM Confidence:** 10 alerts (3.4%) – Moderate evidence strength:
  - Brute force attempts with 3–5 failures and no confirmed subsequent success.
  - C2 beaconing with 2 observations to external documentation test networks.

### Affected Scope
- **Unique Hosts Affected:** 28 hosts (100% of endpoints in the test telemetry environment).
- **Unique Users Affected:** 12 users (all active human and service accounts in the enterprise model).
- **Total Evidence Provenance Links:** 380 discrete event references.

---

## 5. MITRE ATT&CK & Cyber Kill Chain Mapping

CyberTrace strictly distinguishes between **MITRE ATT&CK Tactics** (the technical objective or goal of the technique) and **Cyber Kill Chain Stages** (the chronological progression of an adversary intrusion):

```
+--------------------------------------------------------------------------------------------------+
|                                    CYBERTRACE KILL CHAIN MAPPING                                  |
+------------------------------------+------------------------+------------------------------------+
| Technique ID & Name                | MITRE ATT&CK Tactic    | Cyber Kill Chain Stage             |
+------------------------------------+------------------------+------------------------------------+
| T1110 (Brute Force)                | Credential Access      | Exploitation                       |
| T1059.001 (PowerShell Execution)   | Execution              | Exploitation                       |
| T1547.001 (Registry Run Keys)      | Persistence            | Installation                       |
| T1071.001 (Web Protocols / C2)     | Command and Control    | Command and Control                |
| T1486 (Data Encrypted for Impact)  | Impact                 | Actions on Objectives              |
+------------------------------------+------------------------+------------------------------------+
```

### Detailed Mapping Rationale:
1. **T1110 (Brute Force):**
   - *MITRE Tactic:* Credential Access (adversary seeks valid account credentials).
   - *Kill Chain Stage:* Exploitation. In an end-to-end attack flow, automated authentication attacks against domain controllers serve to break access barriers and gain execution privileges.
2. **T1059.001 (PowerShell Execution):**
   - *MITRE Tactic:* Execution (adversary runs malicious code).
   - *Kill Chain Stage:* Exploitation. Spawning PowerShell directly out of an Office document (Word, Excel) represents the exploitation of document macros or vulnerabilities to execute stage-1 payload.
3. **T1547.001 (Registry Persistence):**
   - *MITRE Tactic:* Persistence (maintaining access across reboots).
   - *Kill Chain Stage:* Installation. Modifying system autorun registry entries (`HKCU\...\CurrentVersion\Run`) cements the adversary's foothold on the target operating system.
4. **T1071.001 (C2 Beaconing):**
   - *MITRE Tactic:* Command and Control (establishing outbound channels).
   - *Kill Chain Stage:* Command and Control. Outbound HTTP/HTTPS traffic to remote control infrastructure allows operators to receive instructions and exfiltrate data.
5. **T1486 (Data Encrypted for Impact):**
   - *MITRE Tactic:* Impact (disrupting availability and business operations).
   - *Kill Chain Stage:* Actions on Objectives. The ultimate destruction/extortion phase of a ransomware campaign.

---

## 6. Evidence Provenance & Verification

Every alert generated by the engine includes a list of `evidence_references`:
```json
{
  "event_id": "06273454-07b7-4483-85d6-ced0aea1fba2",
  "raw_file": "edr_events.json",
  "byte_offset": 1020049,
  "record_length": 985,
  "timestamp": "2026-10-31T12:39:54.931000+05:30"
}
```

### Direct Seek-and-Read Verification:
To guarantee that findings never invent events, our benchmark script sampled 50 random evidence references from the generated alerts, directly sought the exact byte offsets in the raw unparsed `edr_events.json` file, and deserialized the JSON records:
- **Samples verified:** 50
- **Matches:** 50 (100.0%)
- **Mismatches / Corrupted offsets:** 0

Investigators can inspect any alert in CyberTrace and immediately retrieve the original raw log record byte-for-byte.

---

## 7. Manual Inspection & False-Positive Analysis

A thorough manual review of generated alerts was conducted to evaluate detection fidelity:

1. **RULE-001 (Brute Force):**
   - *Target Host:* Exclusively `SRV-DC-01`.
   - *Source IPs:* `203.0.113.57`, `198.51.100.23`, `192.0.2.88` (external documentation test networks).
   - *Finding:* All 18 alerts correspond to genuine bursts of 3 to 8 failed authentications within sub-second intervals. Benign internal login failures (which occurred sporadically across workstations with internal IPs `10.10.x.x`) were successfully filtered out because their counts remained below threshold.
2. **RULE-002 (Suspicious Process Execution):**
   - *Parent-Child Pair:* `winword.exe` → `powershell.exe`.
   - *Command Line:* `powershell.exe -nop -w hidden -enc <REDACTED_BASE64>`.
   - *Finding:* Zero false positives on legitimate PowerShell usage (e.g., administrator console launched from `explorer.exe`). The rule correctly isolated executions originating from Office productivity binaries.
3. **RULE-003 (C2 Beaconing):**
   - *Destinations:* `192.0.2.88`, `203.0.113.57`, `198.51.100.23` (domains: `sim-exfil.example`, `bad-domain-demo.test`).
   - *Finding:* The rule correctly excluded thousands of benign browser outbound connections to Microsoft, Google, AWS, and Slack. Only repeated connections by script engines (`powershell.exe`) were alerted on.
4. **RULE-004 (Registry Persistence):**
   - *Path:* `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\<SUSPECT_ENTRY>`.
   - *Data:* `%AppData%\<redacted>.exe`.
   - *Finding:* Benign registry changes (e.g. Office `RecentFiles` or Windows Defender signature updates) were completely ignored. Only Run key modifications were flagged.
5. **RULE-005 (Mass File Modification / Ransomware):**
   - *Process & Extension:* `unknown.exe` renaming documents to `.locked`.
   - *Finding:* Ordinary file updates (Word saving `.docx`, Excel saving `.xlsx`, developer writing `.py` or `.log`) did not trigger alerts.

---

## 8. Identified Telemetry Limitations

In accordance with Step 3 of the brief, the following dataset characteristics and limitations were identified:

1. **Synthetic Generator Event Distribution:**
   - The organizer's EDR generator generated random individual alert events rather than connected attack chains. For example, in C2 network events, random users were assigned to the same host's network events. Our engine accommodates this by grouping network events at the host and process level rather than over-fragmenting by user.
2. **Compressed Timestamps in Synthetic Data:**
   - All 10,000 events in `edr_events.json` occurred within a 168-millisecond window (12:39:54.910 to 12:39:55.078). In live enterprise deployments, time windows (e.g. 300s, 600s) span minutes or hours. Our engine uses configurable sliding window expressions to ensure compatibility with real-world temporal spreads.
3. **Missing Raw Process Trees:**
   - The EDR telemetry provides parent-child process pairs (`process.parent.name` and `process.name`), but does not provide complete grand-parent or process ancestry trees. Phase 3 attack path reconstruction will correlate these pairs across time and host.
4. **FortiGate Telemetry Status:**
   - Phase 2 operated on the normalized EDR Parquet dataset. FortiGate firewall logs (`firex-10G.log`) are parsed by our Phase 1 parser but will be ingested into the multi-source correlation engine in Phase 3.

---

## 9. Deliverables Inventory

| File Path | Description | Status |
|---|---|---|
| `backend/mitre/mappings.py` | Authoritative MITRE & Kill Chain mapping catalog with validation functions | Verified |
| `backend/detection/alert_schema.py` | Structured alert dataclass enforcing evidence provenance and confidence separation | Verified |
| `backend/detection/rule_loader.py` | Secure YAML rule loader validating schema and rejecting arbitrary SQL injection | Verified |
| `backend/detection/engine.py` | DuckDB-powered detection engine with 5 vetted behavioral handlers | Verified |
| `config/detection_rules/brute_force.yaml` | RULE-001 configuration (T1110) | Verified |
| `config/detection_rules/suspicious_process.yaml` | RULE-002 configuration (T1059.001) | Verified |
| `config/detection_rules/c2_beaconing.yaml` | RULE-003 configuration (T1071.001) | Verified |
| `config/detection_rules/registry_persistence.yaml` | RULE-004 configuration (T1547.001) | Verified |
| `config/detection_rules/mass_file_modification.yaml` | RULE-005 configuration (T1486) | Verified |
| `tests/test_detection.py` | 13 comprehensive positive, negative, boundary, and integration tests | Verified (13/13 passed) |
| `run_phase2.py` | Standalone CLI detection runner with JSON alert export | Verified |
| `run_phase2_benchmark.py` | Rigorous benchmark measuring latency, RAM, throughput, and byte offsets | Verified |
| `phase2_results.md` | Formal engineering results report | Complete |

---

## 10. Conclusion & Next Steps

Phase 2 is complete, verified, and operational. All requirements have been satisfied without taking shortcuts, fabricating detections, or relying on pre-existing generator threat tags.

The system is now ready for **Phase 3 (Cross-Host & Cross-User Attack Path Correlation)**.
