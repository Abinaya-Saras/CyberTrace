# CyberTrace: Kill Chain & Attack Path Analysis

CyberTrace is an enterprise incident correlation and evidence-weighted attack graph engine. It ingests massive multi-gigabyte security event telemetry (EDR NDJSON and FortiGate Key-Value), maps detections to MITRE ATT&CK techniques, and reconstructs chronological attack paths with verifiable raw log byte provenance.

---

## 1. System Requirements & Architecture

- **Operating System:** Linux, macOS, or Windows (via WSL2 recommended).
- **Python:** Python 3.10, 3.11, 3.12, 3.13, or 3.14.
- **Docker (Optional):** Docker 20.10+ and Docker Compose v2.
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

## 2. Quick Start: Docker Compose (Production Deployment)

Run the entire containerized application with persistent volume mounts and automated health checks:

```bash
docker compose up --build -d
```

Verify health check status:
```bash
docker compose ps
curl http://localhost:8000/api/health
```

Access the UI at:
```
http://localhost:8000
```

To stop:
```bash
docker compose down
```

---

## 3. Quick Start: Native Python Installation

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

### Step 4: Run Test Suite
```bash
PYTHONPATH=. pytest tests/ -v
```
*(All 61 automated tests will execute and pass)*

### Step 5: Start CyberTrace Server
```bash
PYTHONPATH=. uvicorn backend.api.main:app --host 0.0.0.0 --port 8000
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

### E. Plain-English Incident Reports (PRD Bonus B-2)
- Automatically writes a complete 11-section markdown investigation report grounded directly in incident evidence.
- Includes severity, confidence, timeline, observed vs. inferred boundaries, uncertainties, and MITRE mapping.
- One-click "Copy Markdown" and "Download (.md)" export buttons.

---

## 5. API Reference

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

## 6. PRD Requirement Coverage Matrix

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
