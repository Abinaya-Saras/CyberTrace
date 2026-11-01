# CyberTrace: Kill Chain & Attack Path Analysis

CyberTrace is an enterprise incident correlation and evidence-weighted attack graph engine. It ingests massive multi-gigabyte security event telemetry (EDR NDJSON and FortiGate Key-Value), maps detections to MITRE ATT&CK techniques, and reconstructs chronological attack paths with verifiable raw log byte provenance.

---

## 📺 Project Demo Video

[![CyberTrace Demo Video](https://img.youtube.com/vi/7AXHslqxJkE/0.jpg)](https://youtu.be/7AXHslqxJkE)

> 🎥 **Watch the Full Demonstration on YouTube:** [https://youtu.be/7AXHslqxJkE](https://youtu.be/7AXHslqxJkE)
>
> *Walkthrough covering streaming ingestion & bounded RAM parsing, 5 MITRE ATT&CK detection rules, incident correlation, 1-Minute Executive Attack Stories, 5-stage interactive attack graphs, and raw byte provenance seeking.*

---

## 1. System Requirements & Architecture

- **Operating System:** Linux, macOS, or Windows (via WSL2 recommended).
- **Python:** Python 3.10, 3.11, 3.12, 3.13, or 3.14.
- **RAM:** Minimum 2 GB RAM (bounded streaming pipeline runs within 200 MB RSS for multi-gigabyte datasets).
- **Storage:** Persistent directory storage for `data/uploads/`, `data/processed/`, and `data/dataset_registry.json`.

### Core Architecture Components:
- **Parser Tier (`backend/parsers/`):** Streaming chunked parsers for FortiGate KV logs and NDJSON EDR logs with live byte offset tracking and bounded malformed error buffers.
- **Normalization & Schema (`backend/models/event.py`):** Unified internal security event schema matching PRD Table 1 with strict provenance (`raw_file`, `byte_offset`, `record_length`).
- **Detection Engine (`backend/detection/`):** Streaming DuckDB SQL evaluation of 5 MITRE ATT&CK rules (Brute Force T1110, Office Spawning Script Engine T1059.001, Firewall Inbound Scan T1046, Autorun Registry Persistence T1547.001, Ransomware File Renames T1486). Two-stage aggregation limits brute force candidate groups to prevent RAM bloat.
- **Correlation & Attack Graph (`backend/correlation/`):** Evidence-weighted temporal graph clustering with strict host isolation, distinct observed vs. inferred edges, and reachability validation.
- **Dataset Registry (`backend/core/dataset_registry.py`):** Persistent dataset catalog tracking file size, fast SHA-256, format, parser version, active selection, and instant Parquet reuse (zero re-parsing).
- **Executive Reporting (`backend/correlation/report_generator.py`):** 1-Minute Attack Story (8 mandatory PRD questions + Risk Score) and complete 11-section plain-English incident investigation reports.
- **Frontend Console (`frontend/index.html`):** Minimal light-theme enterprise UI with 5-stage left-to-right DAG layout, zoom/pan navigation, inspector drawer, and exportable markdown reports.

---

## 2. Quick Start: One-Step Launch (Recommended for Evaluators)

Run everything (virtualenv setup, dependency check, test suite, and web server) with a single command:

```bash
# 1. Run all 62 automated unit and regression tests, then start server:
./run.sh --test

# 2. Or start the server directly:
./run.sh
```
Open **`http://localhost:8000`** in any web browser.

---

## 3. Quick Start: Native Python Installation (Step-by-Step)

### Step 1: Clone or Open Directory
```bash
cd CyberTrace
```

### Step 2: Create and Activate Virtual Environment
**Linux / macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows (PowerShell):**
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### Step 3: Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4: Run Automated Test Suite
```bash
PYTHONPATH=. pytest tests/ -v
```
*(All 62 automated tests will execute and pass in < 3 seconds)*

### Step 5: Start CyberTrace Server
```bash
PYTHONPATH=. uvicorn backend.api.main:app --host 0.0.0.0 --port 8000 --reload
```
Open **`http://localhost:8000`** in any modern web browser.

---

## 4. Key Usability Features

### A. Persistent Dataset Management & Zero Re-Parsing
- Every uploaded dataset is registered persistently in `data/dataset_registry.json`.
- The active dataset selection survives browser refreshes and backend restarts.
- If no dataset is active, CyberTrace presents a clean empty state with a dataset picker (it never silently defaults to `edr_events.json`).
- When an existing dataset is selected or uploaded again, CyberTrace instantly reuses the processed Parquet output—bypassing raw file re-parsing completely.

### B. 1-Minute Executive Attack Story (PRD Mandatory Requirement)
For every incident, an executive card at the top answers:
1. **What happened?**
2. **Which host or user was involved?**
3. **What happened first?**
4. **What happened next?**
5. **Which detections were triggered?**
6. **What evidence connects the events?**
7. **What is confirmed and what is inferred?**
8. **What is the current impact or known outcome?**

Includes an evidence-weighted **Risk Score** (0–100) combining severity, multi-stage kill chain progression, and high-frequency alert density.

### C. 5-Stage Left-to-Right Attack Graph
- Structured progression across 5 visual stages:
  1. `Affected Host`
  2. `Execution` (winword.exe, powershell.exe, etc.)
  3. `Persistence` (Registry Run Keys)
  4. `File & Supporting Network` (*.locked, outbound traffic destinations)
  5. `Detections` (MITRE ATT&CK techniques)
- Clear distinction between **Observed Actions** (solid blue edges) and **Inferred Progression** (dashed lines).
- Supporting network traffic is clearly identified as outbound connectivity, not assumed target compromise.
- Repeated process instances (e.g. multiple `powershell.exe` calls) are cleanly grouped into expandable cards showing all distinct PIDs.
- Smooth navigation: `Zoom In (+)` , `Zoom Out (−)`, `Fit View (⛶)`, `Reset View (↺)`, and drag pan.
- Slide-out Inspector Drawer displaying raw telemetry attributes and direct "Seek Byte Offset" buttons.

### D. Strict Potential Next Access
- Distinguishes observed outbound network connections, internal network traffic, remote authentication, and confirmed execution.
- If evidence is insufficient, displays: *"Insufficient evidence to determine whether the attacker could access another system."*
- Reserved documentation IP addresses (RFC 5737: `192.0.2.88`, `203.0.113.57`) are explicitly labeled as test ranges, not attacker infrastructure.

### E. Plain-English Incident Reports (PRD Bonus B-2)
- Automatically writes a complete 11-section markdown investigation report grounded directly in incident evidence.
- Includes severity, confidence, timeline, observed vs. inferred boundaries, uncertainties, and MITRE mapping.
- Reconciles alert counts, supporting log events, and individual process PIDs in a structured table.
- One-click "Copy Markdown" and "Download (.md)" export buttons.

---

## 5. Ground-Truth Verification: Incident INC-002 on WS-SALES-013

Evaluators can immediately verify that incident `INC-002` correctly correlates:
- **18 Alert Records** across **18 Supporting Events**
- **4 Detection Rules:** `RULE-002` (T1059.001), `RULE-003` (T1071.001), `RULE-004` (T1547.001), `RULE-005` (T1486)
- **9 Distinct Users:** `asharma`, `dnair`, `kiyer`, `mkhan`, `nverma`, `pmehta`, `rkumar`, `sgupta`, `vreddy`
- **18 Distinct Process Instances:**
  - 8 PowerShell execution PIDs: `13257`, `15667`, `21414`, `22435`, `28797`, `29942`, `31231`, `52604`
  - 3 Registry persistence PIDs: `15244`, `23136`, `58399`
  - 5 File rename PIDs: `14484`, `1749`, `27951`, `40344`, `62614` (`parent_process_id = None`)
  - 2 Outbound network PIDs: `49557`, `53871` (Destinations: `192.0.2.88`, `203.0.113.57`)

Run the automated verification script:
```bash
python3 -c "
import json
offsets = [
    (60462, 1303), (1040066, 1304), (1424951, 1304), (1939188, 1304),
    (2643466, 1304), (2976427, 1305), (3981392, 1304), (7108890, 1304),
    (2183602, 1084), (5857560, 1084),
    (1203455, 1055), (2134292, 1054), (2511767, 1055),
    (17165, 1006), (655193, 1007), (4335326, 1009), (4957611, 1006), (6698029, 1009)
]
with open('edr_events.json', 'rb') as f:
    events = [json.loads(f.seek(o) or f.read(l)) for o, l in offsets]
print(f'Verified {len(events)} events | {len(set(e[\"user\"][\"name\"] for e in events))} users | {len(set(e[\"threat\"][\"technique\"][\"id\"][0] for e in events))} MITRE techniques')
"
```

---

## 6. API Reference

| Endpoint | Method | Description |
|---|---|---|
| `GET /api/health` | GET | Healthcheck endpoint reporting RAM, active dataset, and incident count |
| `GET /api/datasets` | GET | List all registered datasets with metadata, size, format, status |
| `GET /api/datasets/active` | GET | Retrieve currently active dataset |
| `POST /api/datasets/select` | POST | Activate a dataset and switch Parquet instantly |
| `POST /api/datasets/reprocess` | POST | Force re-parse a dataset from original log file |
| `DELETE /api/datasets/{id}` | DELETE | Remove dataset and delete cached Parquet file |
| `POST /api/upload/init` | POST | Initialize resumable 32MB chunked file upload |
| `POST /api/upload/chunk` | POST | Upload sequential chunk to disk offset |
| `POST /api/upload/finalize` | POST | Assemble upload, check Parquet reuse, and trigger pipeline |
| `GET /api/jobs/{job_id}` | GET | Poll background pipeline progress percentage and throughput |
| `GET /api/incidents` | GET | List correlated incidents for active dataset |
| `GET /incidents/{id}/path` | GET | Retrieve graph DAG, chronological timeline, and reachability |
| `GET /api/incidents/{id}/story` | GET | Retrieve 1-minute attack story answering the 8 PRD questions |
| `GET /api/incidents/{id}/report` | GET | Generate and retrieve 11-section plain-English incident report |
| `GET /api/evidence/{event_id}` | GET | Seek and return raw disk log record by byte offset |

---

## 7. PRD Requirement Coverage Matrix

| PRD Section | Requirement | Status | Implementation |
|---|---|---|---|
| **FR-1** | Ingestion & Telemetry Handling | **COMPLETE** | Streaming DuckDB + PyArrow Parquet with byte offset tracking |
| **FR-2** | Log Parsers & Normalization | **COMPLETE** | FortiGate KV + NDJSON parsers with unified internal schema |
| **FR-3** | Detection Engine | **COMPLETE** | 5 MITRE rules with bounded two-stage brute force queries |
| **FR-4** | Incident Correlation | **COMPLETE** | Evidence-weighted temporal correlation; separate observed/inferred |
| **FR-5** | Attack Path Visualization | **COMPLETE** | 5-stage L-to-R DAG layout; fit/zoom controls; inspector drawer |
| **FR-6** | Potential Next Access | **COMPLETE** | Strict 4-level verification; outbound traffic distinction |
| **FR-7** | API & Web Console | **COMPLETE** | Light-theme console; persistent dataset manager; zero re-parsing |
| **Bonus B-1** | Risk Scoring | **COMPLETE** | 0–100 composite risk scoring based on kill chain depth & alerts |
| **Bonus B-2** | Plain-English Incident Reports | **COMPLETE** | 11-section automated report generation with markdown download |
| **Bonus B-3** | Merged Raw Alert Count | **COMPLETE** | Alert counts preserved on incidents, timelines, and reports |
| **Bonus B-5** | Multi-Source Telemetry | **COMPLETE** | Supports both endpoint EDR and firewall network telemetry |
