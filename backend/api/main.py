"""
CyberTrace REST API (FR-7).

Provides minimal, high-performance HTTP endpoints for:
  - Ingestion orchestration (POST /api/ingest)
  - Processing status and statistics (GET /api/status)
  - Incident catalog listing (GET /api/incidents)
  - Detailed incident retrieval (GET /api/incidents/{incident_id})
  - PRD Attack path & graph endpoint (GET /incidents/{incident_id}/path and GET /api/incidents/{incident_id}/path)
  - Chronological timeline events (GET /api/incidents/{incident_id}/timeline)
  - Granular raw log evidence retrieval via byte offsets (GET /api/evidence/{event_id})
  - Single-page web console static delivery (GET /)
"""

from contextlib import asynccontextmanager
import json
import logging
import os
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend.core.duckdb_engine import DuckDBEngine
from backend.core.pipeline import ingest_file
from backend.correlation.incident_correlator import IncidentCorrelator
from backend.correlation.models import Incident
from backend.detection.engine import DetectionEngine

logger = logging.getLogger(__name__)

# State cache for active incident catalog and evidence index
state: dict[str, Any] = {
    "incidents": {},  # incident_id -> Incident
    "evidence_index": {},  # event_id -> dict(raw_file, byte_offset, record_length, metadata)
    "last_ingestion": None,
    "active_parquet": None,
}


def _index_incident_evidence(incidents: list[Incident]) -> None:
    """Index all supporting event evidence pointers for fast seeking."""
    for inc in incidents:
        for t in inc.timeline:
            if t.event_id and t.byte_offset is not None:
                state["evidence_index"][t.event_id] = {
                    "raw_file": t.raw_file,
                    "byte_offset": t.byte_offset,
                    "record_length": t.record_length,
                    "host": t.host,
                    "user": t.user,
                    "action": t.action,
                    "timestamp": t.timestamp,
                    "rule_id": t.rule_id,
                    "mitre_technique_id": t.mitre_technique_id,
                }


def load_pipeline_data(parquet_path: str = "data/processed/edr_events.parquet") -> bool:
    """Run detection and correlation on parquet to populate in-memory incident cache."""
    if not os.path.exists(parquet_path):
        return False
    try:
        with DuckDBEngine() as db:
            with DetectionEngine(engine=db) as det:
                alerts = det.run_all(parquet_path)
                correlator = IncidentCorrelator(engine=db, parquet_path=parquet_path)
                incidents_list = correlator.correlate(alerts)

                state["incidents"] = {inc.incident_id: inc for inc in incidents_list}
                state["active_parquet"] = parquet_path
                _index_incident_evidence(incidents_list)
                logger.info(f"Loaded {len(incidents_list)} incidents from {parquet_path}")
                return True
    except Exception as e:
        logger.error(f"Failed to load pipeline data from {parquet_path}: {e}")
        return False


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup initialization: load existing Parquet telemetry if available."""
    default_parquet = "data/processed/edr_events.parquet"
    if os.path.exists(default_parquet):
        load_pipeline_data(default_parquet)
    yield


app = FastAPI(
    title="CyberTrace API",
    description="Kill Chain and Attack Path Analysis REST API (FR-7)",
    version="1.0.0",
    lifespan=lifespan,
)

# Enable CORS for local web development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------------------------------------------------------------
# Request & Response Schemas
# -----------------------------------------------------------------------------

class IngestionRequest(BaseModel):
    file_path: str = Field(default="edr_events.json", description="Path to raw EDR or FortiGate log file")
    flush_size: int = Field(default=5000, description="Streaming chunk row count for Parquet writing")


# -----------------------------------------------------------------------------
# Ingestion & System Status Endpoints
# -----------------------------------------------------------------------------

@app.post("/api/ingest")
def start_ingestion(req: IngestionRequest):
    """
    Ingest a raw log dataset, detect suspicious events, and correlate incidents.
    Returns streaming throughput, RAM consumption, and detection counts.
    """
    if not os.path.isfile(req.file_path):
        raise HTTPException(status_code=400, detail=f"File not found: '{req.file_path}'")

    try:
        # Step 1: Stream-parse to Parquet
        stats = ingest_file(req.file_path, output_dir="data/processed", flush_size=req.flush_size)
        state["last_ingestion"] = stats.to_dict()

        # Step 2: Run Detection and Incident Correlation
        load_pipeline_data(stats.output_file)

        return {
            "status": "success",
            "ingestion": stats.to_dict(),
            "incidents_count": len(state["incidents"]),
            "message": f"Successfully processed {stats.parsed_ok:,} records into {len(state['incidents'])} correlated incidents.",
        }
    except Exception as e:
        logger.exception("Ingestion failed")
        raise HTTPException(status_code=500, detail=f"Ingestion failed: {str(e)}")


@app.get("/api/status")
def get_status():
    """Retrieve current system status, active telemetry source, and incident count."""
    return {
        "status": "online",
        "active_parquet": state["active_parquet"],
        "total_incidents": len(state["incidents"]),
        "last_ingestion": state["last_ingestion"],
    }


# -----------------------------------------------------------------------------
# Incident Catalog Endpoints (FR-4 & FR-7)
# -----------------------------------------------------------------------------

@app.get("/api/incidents")
@app.get("/incidents")
def list_incidents(
    severity: Optional[str] = Query(None, description="Filter by severity: critical, high, medium, low"),
    host: Optional[str] = Query(None, description="Filter by hostname"),
):
    """
    List all correlated security incidents with summary metadata.
    Supports filtering by severity and host.
    """
    results = []
    for inc in state["incidents"].values():
        if severity and inc.severity.lower() != severity.lower():
            continue
        if host and not any(host.lower() in h.lower() for h in inc.hosts):
            continue

        results.append({
            "incident_id": inc.incident_id,
            "title": inc.title,
            "severity": inc.severity,
            "confidence": inc.confidence,
            "first_seen": inc.first_seen,
            "last_seen": inc.last_seen,
            "hosts": inc.hosts,
            "users": inc.users,
            "alert_count": len(inc.alerts),
            "timeline_steps": len(inc.timeline),
            "reach_next_count": len(inc.reach_next),
            "summary": inc.summary,
        })

    # Sort: Critical first, then by earliest timestamp
    sev_weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    results.sort(key=lambda x: (-sev_weights.get(x["severity"].lower(), 0), x["first_seen"]))
    return results


@app.get("/api/incidents/{incident_id}")
@app.get("/incidents/{incident_id}")
def get_incident_details(incident_id: str):
    """Retrieve full details of a specific incident including graph, timeline, and reach-next assets."""
    inc = state["incidents"].get(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    return inc.to_dict()


# -----------------------------------------------------------------------------
# Attack Path & Graph Endpoint (FR-5, FR-6 & PRD Specification)
# -----------------------------------------------------------------------------

@app.get("/incidents/{incident_id}/path")
@app.get("/api/incidents/{incident_id}/path")
def get_incident_path(incident_id: str):
    """
    PRD-specified endpoint: returns the incident's attack path, NetworkX graph,
    chronological timeline, and reach-next reasoning.
    """
    inc = state["incidents"].get(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")

    return {
        "incident_id": inc.incident_id,
        "title": inc.title,
        "severity": inc.severity,
        "confidence": inc.confidence,
        "first_seen": inc.first_seen,
        "last_seen": inc.last_seen,
        "hosts": inc.hosts,
        "users": inc.users,
        "summary": inc.summary,
        "graph": inc.graph,
        "timeline": [t.to_dict() for t in inc.timeline],
        "reach_next": [r.to_dict() for r in inc.reach_next],
    }


@app.get("/api/incidents/{incident_id}/timeline")
def get_incident_timeline(incident_id: str):
    """Retrieve only the chronological timeline steps for a specific incident."""
    inc = state["incidents"].get(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    return [t.to_dict() for t in inc.timeline]


# -----------------------------------------------------------------------------
# Evidence Provenance Seeking Endpoint (FR-1 & FR-5)
# -----------------------------------------------------------------------------

@app.get("/api/evidence/{event_id}")
def get_raw_evidence(event_id: str):
    """
    Retrieve exact raw log record directly from disk via byte offset.
    Proves byte-level log provenance without loading entire log files into memory.
    """
    meta = state["evidence_index"].get(event_id)
    if not meta:
        raise HTTPException(status_code=404, detail=f"Event ID '{event_id}' not found in active evidence index")

    raw_file = meta["raw_file"]
    byte_offset = meta["byte_offset"]
    record_length = meta["record_length"]

    if not os.path.isfile(raw_file):
        raise HTTPException(status_code=404, detail=f"Source raw file '{raw_file}' is missing from disk")

    try:
        with open(raw_file, "rb") as f:
            f.seek(byte_offset)
            chunk = f.read(record_length)
            raw_text = chunk.decode("utf-8", errors="replace")

        # Attempt JSON decoding if NDJSON format
        raw_json = None
        try:
            raw_json = json.loads(raw_text)
        except Exception:
            pass

        return {
            "event_id": event_id,
            "raw_file": raw_file,
            "byte_offset": byte_offset,
            "record_length": record_length,
            "metadata": meta,
            "raw_text": raw_text.strip(),
            "raw_json": raw_json,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read raw evidence at byte offset {byte_offset}: {e}")


# -----------------------------------------------------------------------------
# Frontend Static File Serving (FR-7)
# -----------------------------------------------------------------------------

frontend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "frontend")

if os.path.isdir(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

    @app.get("/", include_in_schema=False)
    def serve_frontend_index():
        index_path = os.path.join(frontend_dir, "index.html")
        if os.path.exists(index_path):
            return FileResponse(index_path)
        return JSONResponse({"status": "CyberTrace API online", "frontend": "index.html not found"})
