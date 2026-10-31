# CyberTrace: Kill Chain & Attack Path Analysis

CyberTrace is a high-performance incident correlation and evidence-weighted attack graph engine. It ingests massive multi-gigabyte security event logs (EDR NDJSON and FortiGate Key-Value), maps detections to MITRE ATT&CK techniques, and reconstructs chronological attack paths with verifiable raw log byte provenance.

---

## 1. System Requirements

- **Operating System:** Linux (Ubuntu/Debian/Fedora), macOS, or Windows (via WSL2 recommended).
- **Python:** Python 3.10, 3.11, 3.12, 3.13, or 3.14.
- **RAM:** Minimum 2 GB RAM (runs within 200 MB RSS for multi-gigabyte datasets).
- **Disk Space:** ~500 MB for core application & dependencies (additional space for datasets).

---

## 2. Moving CyberTrace to a New Laptop

### Option A: Transfer via Git (Recommended)
Push your repository to GitHub / GitLab / USB drive, then clone:
```bash
git clone <your-repo-url> CyberTrace
cd CyberTrace
```

### Option B: Transfer via ZIP / External Drive
Copy the `CyberTrace` folder to your new laptop.
*You do NOT need to copy `.venv/` or `__pycache__/` (they will be freshly created).*

---

## 3. Installation Steps

### Step 1: Open a Terminal in the Project Directory
```bash
cd CyberTrace
```

### Step 2: Create and Activate a Python Virtual Environment

**On Linux / macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**On Windows (PowerShell):**
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**On Windows (Command Prompt):**
```cmd
python -m venv .venv
.venv\Scripts\activate.bat
```

### Step 3: Upgrade pip and Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 4. Verify Installation (Run Test Suite)

Run the 56 automated unit and integration tests:

**On Linux / macOS:**
```bash
PYTHONPATH=. pytest tests/ -v
```

**On Windows (PowerShell):**
```powershell
$env:PYTHONPATH="."
pytest tests/ -v
```

*Expected output:*
```
======================== 56 passed in ~2.5s ========================
```

---

## 5. Running the Application

### Start the CyberTrace API & Web Console
```bash
uvicorn backend.api.main:app --host 127.0.0.1 --port 8000
```

### Access the Web Dashboard
Open your browser and navigate to:
```
http://127.0.0.1:8000/
```

---

## 6. Working with Datasets

### A. Pre-Loaded EDR Intrusion Dataset
On startup, if `data/processed/edr_events.parquet` is present, CyberTrace automatically loads **29 correlated security incidents** covering brute force, suspicious PowerShell spawns, registry persistence, mass ransomware file encryption, and potential next access assessments.

To re-ingest `edr_events.json` from the UI:
1. Click **Choose Log File** $\rightarrow$ select `edr_events.json`.
2. Click **Upload & Analyse**.
3. The dashboard will populate the 29 incidents, interactive Cytoscape attack graphs, chronological timeline cards, and raw log byte-offset evidence inspector.

### B. High-Volume FortiGate Firewall Telemetry (`firex-10G.log`)
For multi-gigabyte logs (e.g. 6.1 GB `firex-10G.log` with 12.4M records):
- Use the web UI file picker (automatically streams via chunked 32MB multipart uploads directly to disk without memory bloat).
- Or run the streaming pipeline directly via CLI:
  ```bash
  python3 scratch/test_e2e_firex.py
  ```
- Or load the generated Parquet table via API:
  ```bash
  curl -X POST http://127.0.0.1:8000/api/ingest \
       -H "Content-Type: application/json" \
       -d '{"file_path": "data/processed/firex-10G.parquet"}'
  ```

---

## 7. Project Architecture Overview

- `backend/core/`: Common 28-field normalized schema, pipeline orchestrator, and DuckDB analytical query engine.
- `backend/parsers/`: Zero-copy binary streaming parsers for EDR NDJSON and FortiGate Key-Value with exact byte-offset tracking.
- `backend/detection/`: SQL-based detection engine mapping 100% of alerts to MITRE ATT&CK techniques and Cyber Kill Chain stages.
- `backend/correlation/`: Entity resolution, temporal clustering, directed acyclic attack graphs (NetworkX), and Reach-Next lateral asset prediction.
- `backend/api/`: FastAPI REST endpoints (`/api/status`, `/api/incidents`, `/api/upload/chunk`, etc.).
- `frontend/`: Single-page web dashboard (Vanilla HTML5/CSS3/JavaScript, Cytoscape.js layered graph rendering).
