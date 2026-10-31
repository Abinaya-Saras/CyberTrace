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
import math
import os
import shutil
import uuid
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend.core.duckdb_engine import DuckDBEngine
from backend.core.pipeline import ingest_file, detect_format
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


class InitUploadRequest(BaseModel):
    filename: str = Field(..., description="Original name of the log file")
    total_size: int = Field(..., description="Total file size in bytes")
    chunk_size: int = Field(default=33554432, description="Chunk size in bytes (default: 32MB)")


class FinalizeUploadRequest(BaseModel):
    upload_id: str = Field(..., description="Unique upload session identifier")
    trigger_pipeline: bool = Field(default=True, description="Whether to start parsing and correlation immediately")


# Active chunked upload sessions
upload_sessions: dict[str, dict] = {}


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


@app.post("/api/upload")
async def upload_and_process_log(file: UploadFile = File(...)):
    """
    Multipart file upload endpoint.
    Streams log file directly to disk in 1MB chunks to prevent memory bloat,
    validates log format (NDJSON / FortiGate), and triggers the pipeline.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    upload_dir = "data/uploads"
    os.makedirs(upload_dir, exist_ok=True)
    dest_path = os.path.join(upload_dir, file.filename)

    try:
        # Stream file to disk in chunks (O(1) RAM)
        with open(dest_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer, length=1024 * 1024)
    except Exception as e:
        logger.exception("File save failed")
        raise HTTPException(status_code=500, detail=f"Failed to save uploaded file: {str(e)}")

    # Format validation
    fmt = detect_format(dest_path)
    if fmt == "unknown":
        if os.path.exists(dest_path):
            os.remove(dest_path)
        raise HTTPException(
            status_code=400,
            detail="Unsupported log format. Only NDJSON/JSON (e.g. EDR events) and FortiGate key-value logs are supported.",
        )

    try:
        # Stream-parse into Parquet
        stats = ingest_file(dest_path, output_dir="data/processed")
        state["last_ingestion"] = stats.to_dict()

        # Run Detection & Incident Correlation
        load_pipeline_data(stats.output_file)

        return {
            "status": "success",
            "filename": file.filename,
            "format": fmt,
            "ingestion": stats.to_dict(),
            "incidents_count": len(state["incidents"]),
            "message": f"Uploaded and processed {stats.parsed_ok:,} records into {len(state['incidents'])} correlated incidents.",
        }
    except Exception as e:
        logger.exception("Processing uploaded file failed")
        raise HTTPException(status_code=500, detail=f"Pipeline processing failed: {str(e)}")


# -----------------------------------------------------------------------------
# Resumable Chunked Large-File Upload Endpoints
# -----------------------------------------------------------------------------

@app.post("/api/upload/init")
def init_chunked_upload(req: InitUploadRequest):
    """
    Initialize a chunked upload session for large files (e.g. 6.5GB firex-10G.log).
    Allocates a temporary file on disk, validates parameters, and returns an upload_id.
    """
    if req.total_size <= 0:
        raise HTTPException(status_code=400, detail="Invalid total_size: must be positive")
    if req.chunk_size <= 0:
        raise HTTPException(status_code=400, detail="Invalid chunk_size: must be positive")

    upload_id = uuid.uuid4().hex[:12]
    total_chunks = math.ceil(req.total_size / req.chunk_size)

    upload_dir = "data/uploads"
    os.makedirs(upload_dir, exist_ok=True)

    safe_filename = os.path.basename(req.filename)
    temp_file = os.path.join(upload_dir, f".tmp_{upload_id}_{safe_filename}")

    # Initialize empty temp file
    with open(temp_file, "wb") as f:
        pass

    upload_sessions[upload_id] = {
        "upload_id": upload_id,
        "filename": safe_filename,
        "total_size": req.total_size,
        "chunk_size": req.chunk_size,
        "total_chunks": total_chunks,
        "temp_file": temp_file,
        "received_chunks": set(),
        "bytes_written": 0,
        "status": "in_progress",
    }

    return {
        "upload_id": upload_id,
        "filename": safe_filename,
        "total_size": req.total_size,
        "chunk_size": req.chunk_size,
        "total_chunks": total_chunks,
    }


@app.post("/api/upload/chunk")
async def upload_chunk(
    upload_id: str = Form(...),
    chunk_index: int = Form(...),
    file: UploadFile = File(...),
):
    """
    Write a single chunk directly to the temporary file on disk at its exact byte offset.
    Never holds more than the single chunk size in memory (O(1) RAM).
    """
    session = upload_sessions.get(upload_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Upload session '{upload_id}' not found or expired")

    if chunk_index < 0 or chunk_index >= session["total_chunks"]:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid chunk_index {chunk_index}: must be 0 <= idx < {session['total_chunks']}",
        )

    temp_file = session["temp_file"]
    offset = chunk_index * session["chunk_size"]

    try:
        chunk_data = await file.read()
        chunk_len = len(chunk_data)

        # Write chunk directly at offset
        with open(temp_file, "r+b") as f:
            f.seek(offset)
            f.write(chunk_data)

        session["received_chunks"].add(chunk_index)
        received_count = len(session["received_chunks"])
        progress_pct = round((received_count / session["total_chunks"]) * 100, 1)

        return {
            "status": "chunk_received",
            "upload_id": upload_id,
            "chunk_index": chunk_index,
            "chunk_bytes": chunk_len,
            "received_count": received_count,
            "total_chunks": session["total_chunks"],
            "progress_pct": progress_pct,
        }
    except Exception as e:
        logger.exception(f"Failed to write chunk {chunk_index} for upload {upload_id}")
        raise HTTPException(status_code=500, detail=f"Failed to write chunk: {str(e)}")


@app.get("/api/upload/status/{upload_id}")
def get_upload_status(upload_id: str):
    """
    Return current progress and list of received chunks for resumability.
    Allows clients to resume interrupted uploads without re-uploading existing chunks.
    """
    session = upload_sessions.get(upload_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Upload session '{upload_id}' not found")

    return {
        "upload_id": upload_id,
        "filename": session["filename"],
        "total_size": session["total_size"],
        "total_chunks": session["total_chunks"],
        "received_count": len(session["received_chunks"]),
        "received_chunks": sorted(list(session["received_chunks"])),
        "is_complete": len(session["received_chunks"]) == session["total_chunks"],
    }


@app.post("/api/upload/finalize")
def finalize_chunked_upload(req: FinalizeUploadRequest):
    """
    Validate all chunks have been received and file size matches total_size.
    Atomically renames the temporary file to its final destination (zero copy).
    Optionally triggers the parsing, detection, and correlation pipeline.
    """
    session = upload_sessions.get(req.upload_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Upload session '{req.upload_id}' not found")

    if len(session["received_chunks"]) != session["total_chunks"]:
        missing = set(range(session["total_chunks"])) - session["received_chunks"]
        raise HTTPException(
            status_code=400,
            detail=f"Upload incomplete: {len(missing)} chunks missing (e.g. {sorted(list(missing))[:5]})",
        )

    temp_file = session["temp_file"]
    if not os.path.isfile(temp_file):
        raise HTTPException(status_code=500, detail="Temporary upload file missing from disk")

    actual_size = os.path.getsize(temp_file)
    if actual_size != session["total_size"]:
        raise HTTPException(
            status_code=400,
            detail=f"Size mismatch: expected {session['total_size']} bytes, found {actual_size} bytes on disk",
        )

    # Atomic rename to final path (zero-copy)
    final_path = os.path.join("data/uploads", session["filename"])
    try:
        os.replace(temp_file, final_path)
    except Exception as e:
        logger.exception("Atomic file rename failed")
        raise HTTPException(status_code=500, detail=f"Failed to finalize file: {str(e)}")

    # Clean up session
    del upload_sessions[req.upload_id]

    # Validate format
    fmt = detect_format(final_path)
    if fmt == "unknown":
        if os.path.exists(final_path):
            os.remove(final_path)
        raise HTTPException(
            status_code=400,
            detail="Unsupported log format. Only NDJSON/JSON and FortiGate key-value logs are supported.",
        )

    pipeline_result = None
    if req.trigger_pipeline:
        try:
            stats = ingest_file(final_path, output_dir="data/processed")
            state["last_ingestion"] = stats.to_dict()
            load_pipeline_data(stats.output_file)
            pipeline_result = stats.to_dict()
        except Exception as e:
            logger.exception("Pipeline execution after finalize failed")
            raise HTTPException(status_code=500, detail=f"Pipeline processing failed: {str(e)}")

    return {
        "status": "success",
        "filename": os.path.basename(final_path),
        "file_path": final_path,
        "file_size": actual_size,
        "format": fmt,
        "pipeline": pipeline_result,
        "incidents_count": len(state["incidents"]),
    }


@app.delete("/api/upload/{upload_id}")
def abort_chunked_upload(upload_id: str):
    """Abort an upload session and remove its temporary file."""
    session = upload_sessions.pop(upload_id, None)
    if not session:
        return {"status": "not_found", "upload_id": upload_id}

    temp_file = session["temp_file"]
    if os.path.exists(temp_file):
        try:
            os.remove(temp_file)
        except Exception:
            pass

    return {"status": "aborted", "upload_id": upload_id}


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
