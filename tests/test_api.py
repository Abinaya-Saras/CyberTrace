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
        assert "graphCanvas" in resp.text
        assert "timelineContainer" in resp.text
        assert "reachGridContainer" in resp.text
