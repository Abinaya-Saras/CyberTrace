"""
Integration and Unit Tests for CyberTrace REST API and Frontend (FR-7).

Tests covered:
  - Log ingestion orchestration (/api/ingest)
  - Invalid/missing file error handling (400)
  - System status and processing telemetry (/api/status)
  - Incident catalog listing (/api/incidents and /incidents)
  - Incident filtering by severity and host
  - Empty incident query handling
  - Individual incident details retrieval (/api/incidents/{id})
  - PRD-specified attack path endpoint (GET /incidents/{id}/path)
  - Invalid incident ID handling (404)
  - Timeline step retrieval (/api/incidents/{id}/timeline)
  - Byte-offset raw evidence seeking (/api/evidence/{event_id})
  - Invalid event ID evidence seeking (404)
  - Frontend static asset and HTML serving (GET /)
"""

import os
import pytest
from starlette.testclient import TestClient

from backend.api.main import app, state, load_pipeline_data


@pytest.fixture(scope="module")
def client():
    """Create test client with pipeline data loaded."""
    default_parquet = "data/processed/edr_events.parquet"
    if os.path.exists(default_parquet):
        load_pipeline_data(default_parquet)
    with TestClient(app) as c:
        yield c


class TestAPIEndpoints:

    def test_status_endpoint(self, client):
        """GET /api/status returns online status and active parquet."""
        resp = client.get("/api/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "online"
        assert "total_incidents" in data
        assert data["total_incidents"] >= 29

    def test_list_incidents(self, client):
        """GET /api/incidents and GET /incidents list correlated incidents."""
        for endpoint in ["/api/incidents", "/incidents"]:
            resp = client.get(endpoint)
            assert resp.status_code == 200
            incidents = resp.json()
            assert isinstance(incidents, list)
            assert len(incidents) >= 29
            # Verify fields present
            first = incidents[0]
            assert "incident_id" in first
            assert "title" in first
            assert "severity" in first
            assert "hosts" in first
            assert "alert_count" in first

    def test_list_incidents_filter_by_severity(self, client):
        """GET /api/incidents?severity=critical filters appropriately."""
        resp = client.get("/api/incidents?severity=critical")
        assert resp.status_code == 200
        incidents = resp.json()
        assert len(incidents) > 0
        for inc in incidents:
            assert inc["severity"].lower() == "critical"

    def test_list_incidents_filter_by_host(self, client):
        """GET /api/incidents?host=SRV-DC-01 filters appropriately."""
        resp = client.get("/api/incidents?host=SRV-DC-01")
        assert resp.status_code == 200
        incidents = resp.json()
        assert len(incidents) >= 1
        for inc in incidents:
            assert any("srv-dc-01" in h.lower() for h in inc["hosts"])

    def test_list_incidents_empty_filter(self, client):
        """GET /api/incidents with non-matching filter returns empty list."""
        resp = client.get("/api/incidents?host=NONEXISTENT-HOST-999")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_get_incident_details(self, client):
        """GET /api/incidents/{id} returns complete incident object."""
        resp = client.get("/api/incidents")
        incidents = resp.json()
        inc_id = incidents[0]["incident_id"]

        resp_detail = client.get(f"/api/incidents/{inc_id}")
        assert resp_detail.status_code == 200
        detail = resp_detail.json()
        assert detail["incident_id"] == inc_id
        assert "graph" in detail
        assert "nodes" in detail["graph"]
        assert "edges" in detail["graph"]
        assert "timeline" in detail
        assert "reach_next" in detail

    def test_get_incident_details_invalid_id(self, client):
        """GET /api/incidents/INVALID-ID returns 404."""
        resp = client.get("/api/incidents/INC-DOES-NOT-EXIST")
        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"].lower()

    def test_prd_endpoint_path(self, client):
        """
        GET /incidents/{id}/path (Official PRD Example Endpoint).
        Must return incident metadata, NetworkX graph, chronological timeline,
        and reach-next intelligence.
        """
        resp = client.get("/api/incidents")
        incidents = resp.json()
        inc_id = incidents[0]["incident_id"]

        resp_path = client.get(f"/incidents/{inc_id}/path")
        assert resp_path.status_code == 200
        data = resp_path.json()
        assert data["incident_id"] == inc_id
        assert "graph" in data
        assert "timeline" in data
        assert "reach_next" in data
        assert isinstance(data["graph"]["nodes"], list)
        assert isinstance(data["graph"]["edges"], list)

        # Also verify alias /api/incidents/{id}/path
        resp_alias = client.get(f"/api/incidents/{inc_id}/path")
        assert resp_alias.status_code == 200
        assert resp_alias.json()["incident_id"] == inc_id

    def test_get_timeline_endpoint(self, client):
        """GET /api/incidents/{id}/timeline returns ordered timeline steps."""
        resp = client.get("/api/incidents")
        inc_id = resp.json()[0]["incident_id"]

        resp_tl = client.get(f"/api/incidents/{inc_id}/timeline")
        assert resp_tl.status_code == 200
        tl = resp_tl.json()
        assert isinstance(tl, list)
        assert len(tl) > 0
        assert "timestamp" in tl[0]
        assert "action" in tl[0]

    def test_evidence_provenance_seeking(self, client):
        """
        GET /api/evidence/{event_id} seeks byte offset on disk and returns raw log chunk.
        Proves byte-level log provenance without full-file RAM loading.
        """
        # Find an incident with timeline events that have event_id
        incidents = client.get("/api/incidents").json()
        target_event_id = None
        for inc in incidents:
            tl = client.get(f"/api/incidents/{inc['incident_id']}/timeline").json()
            for step in tl:
                if step.get("event_id") and step.get("byte_offset") is not None:
                    target_event_id = step["event_id"]
                    break
            if target_event_id:
                break

        assert target_event_id is not None, "Could not find any timeline event with byte offset"

        resp_ev = client.get(f"/api/evidence/{target_event_id}")
        assert resp_ev.status_code == 200
        ev_data = resp_ev.json()
        assert ev_data["event_id"] == target_event_id
        assert "byte_offset" in ev_data
        assert "record_length" in ev_data
        assert "raw_text" in ev_data
        assert len(ev_data["raw_text"]) > 0
        # If NDJSON, raw_json should be parsed
        assert ev_data.get("raw_json") is not None

    def test_evidence_provenance_invalid_id(self, client):
        """GET /api/evidence/INVALID-EVENT-ID returns 404."""
        resp = client.get("/api/evidence/EVT-NONEXISTENT-999999")
        assert resp.status_code == 404

    def test_ingest_missing_file_error(self, client):
        """POST /api/ingest with nonexistent file returns 400 Bad Request."""
        resp = client.post("/api/ingest", json={"file_path": "nonexistent_file.json"})
        assert resp.status_code == 400
        assert "file not found" in resp.json()["detail"].lower()

    def test_ingest_valid_file(self, client):
        """POST /api/ingest executes streaming parse, detection, and correlation."""
        resp = client.post("/api/ingest", json={"file_path": "edr_events.json", "flush_size": 5000})
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert "ingestion" in data
        assert data["ingestion"]["parsed_ok"] == 10000
        assert data["incidents_count"] >= 29

    def test_frontend_serving(self, client):
        """GET / serves the responsive single-page frontend console."""
        resp = client.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "CyberTrace" in resp.text

    def test_multipart_upload_unsupported_format(self, client):
        """POST /api/upload rejects unsupported plain text format with 400."""
        files = {"file": ("unsupported.txt", b"plain text with no structure\nanother line\n", "text/plain")}
        resp = client.post("/api/upload", files=files)
        assert resp.status_code == 400
        assert "unsupported log format" in resp.json()["detail"].lower()

    def test_multipart_upload_valid_file(self, client):
        """POST /api/upload streams NDJSON file to disk in chunks, parses, and correlates."""
        with open("edr_events.json", "rb") as f:
            content = f.read()
        files = {"file": ("uploaded_edr.json", content, "application/json")}
        resp = client.post("/api/upload", files=files)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert data["filename"] == "uploaded_edr.json"
        assert data["format"] == "ndjson"
        assert data["ingestion"]["parsed_ok"] == 10000
        assert data["incidents_count"] >= 29

    def test_chunked_upload_lifecycle_and_checksum_match(self, client):
        """Test complete chunked upload protocol: init -> chunk -> status -> finalize -> checksum."""
        import hashlib

        with open("edr_events.json", "rb") as f:
            original_data = f.read(50000)  # 50KB test payload
        original_hash = hashlib.sha256(original_data).hexdigest()
        chunk_size = 15000
        total_size = len(original_data)
        total_chunks = (total_size + chunk_size - 1) // chunk_size

        # 1. Init
        init_resp = client.post("/api/upload/init", json={
            "filename": "chunked_test.json",
            "total_size": total_size,
            "chunk_size": chunk_size
        })
        assert init_resp.status_code == 200
        upload_id = init_resp.json()["upload_id"]
        assert init_resp.json()["total_chunks"] == total_chunks

        # 2. Upload chunks in non-sequential order to verify seek-based placement
        chunk_indices = list(range(total_chunks))
        chunk_indices.reverse()  # upload reverse order: 3, 2, 1, 0

        for idx in chunk_indices:
            start = idx * chunk_size
            end = min(start + chunk_size, total_size)
            chunk_slice = original_data[start:end]

            c_resp = client.post(
                "/api/upload/chunk",
                data={"upload_id": upload_id, "chunk_index": idx},
                files={"file": ("blob", chunk_slice, "application/octet-stream")}
            )
            assert c_resp.status_code == 200
            assert c_resp.json()["status"] == "chunk_received"

        # 3. Check status
        st_resp = client.get(f"/api/upload/status/{upload_id}")
        assert st_resp.status_code == 200
        assert st_resp.json()["is_complete"] is True
        assert st_resp.json()["received_count"] == total_chunks

        # 4. Finalize
        fin_resp = client.post("/api/upload/finalize", json={
            "upload_id": upload_id,
            "trigger_pipeline": False
        })
        assert fin_resp.status_code == 200
        file_path = fin_resp.json()["file_path"]
        assert os.path.isfile(file_path)

        # 5. Verify Checksum
        with open(file_path, "rb") as f:
            uploaded_hash = hashlib.sha256(f.read()).hexdigest()
        assert uploaded_hash == original_hash, "Uploaded file checksum does not match original!"

        # Cleanup test file
        if os.path.exists(file_path):
            os.remove(file_path)

    def test_chunked_upload_abort(self, client):
        """Test aborting an in-progress chunked upload session and cleaning up temporary files."""
        init_resp = client.post("/api/upload/init", json={
            "filename": "aborted_test.log",
            "total_size": 100000,
            "chunk_size": 20000
        })
        upload_id = init_resp.json()["upload_id"]

        del_resp = client.delete(f"/api/upload/{upload_id}")
        assert del_resp.status_code == 200
        assert del_resp.json()["status"] == "aborted"

        # Verify status now returns 404
        st_resp = client.get(f"/api/upload/status/{upload_id}")
        assert st_resp.status_code == 404


