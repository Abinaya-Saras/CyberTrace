"""
Streaming NDJSON parser for ECS-format EDR events.

Reads a file line-by-line, flattens nested ECS JSON into the
normalized schema, and tracks byte offsets for evidence provenance.

Important:
  - Does NOT use pre-existing threat/rule/labels metadata as detection
    inputs.  Those fields are intentionally ignored during normalization.
  - Missing fields are stored as None/NULL, never invented.
  - Malformed lines are captured separately with error reasons.
"""

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Generator

from backend.core.schema import empty_row


# ---------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------

def _parse_timestamp(raw: str | None) -> datetime | None:
    """Parse an ISO-8601 timestamp string to datetime UTC.

    Handles formats like:
      2026-10-31T07:09:54.910Z
      2026-10-31T07:09:54Z
      2026-10-31T07:09:54.910+00:00
    """
    if not raw:
        return None
    try:
        # Strip trailing Z and replace with +00:00 for fromisoformat
        s = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        # Ensure UTC
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------
# Safe nested access
# ---------------------------------------------------------------

def _get(obj: dict, *keys, default=None):
    """Safely traverse nested dicts.  _get(d, 'a', 'b') == d['a']['b']."""
    cur = obj
    for k in keys:
        if isinstance(cur, dict):
            cur = cur.get(k)
        else:
            return default
    return cur if cur is not None else default


def _get_int(obj: dict, *keys, default=None) -> int | None:
    """Like _get but coerce to int."""
    val = _get(obj, *keys)
    if val is None:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def _get_first(obj: dict, *keys, default=None):
    """Get first element if value is a list, otherwise return value."""
    val = _get(obj, *keys)
    if isinstance(val, list):
        return val[0] if val else default
    return val if val is not None else default


# ---------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------

class NDJSONParser:
    """
    Streaming parser for NDJSON files with ECS-format EDR events.

    Usage:
        parser = NDJSONParser()
        for row in parser.parse("edr_events.json"):
            writer.add_row(row)
        print(parser.stats)
    """

    def __init__(self):
        self.stats = {
            "total_lines": 0,
            "parsed_ok": 0,
            "malformed": 0,
            "empty_lines": 0,
        }
        self.malformed_records: list[dict] = []

    def parse(
        self, filepath: str, source_label: str | None = None
    ) -> Generator[dict, None, None]:
        """
        Yield normalized row dicts from an NDJSON file.

        Each yielded dict matches the NORMALIZED_SCHEMA columns.
        """
        filename = os.path.basename(filepath)
        source = source_label or filename
        byte_offset = 0
        self.current_byte_offset = 0

        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            for line_no, raw_line in enumerate(fh, start=1):
                line_bytes = len(raw_line.encode("utf-8"))
                current_offset = byte_offset
                byte_offset += line_bytes
                self.current_byte_offset = byte_offset

                self.stats["total_lines"] += 1

                stripped = raw_line.strip()
                if not stripped:
                    self.stats["empty_lines"] += 1
                    continue

                try:
                    obj = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    self.stats["malformed"] += 1
                    if len(self.malformed_records) < 1000:
                        self.malformed_records.append({
                            "file": filename,
                            "line": line_no,
                            "byte_offset": current_offset,
                            "error": f"JSON decode error: {exc}",
                            "raw": stripped[:500],
                        })
                    continue

                if not isinstance(obj, dict):
                    self.stats["malformed"] += 1
                    if len(self.malformed_records) < 1000:
                        self.malformed_records.append({
                            "file": filename,
                            "line": line_no,
                            "byte_offset": current_offset,
                            "error": "Top-level value is not a JSON object",
                            "raw": stripped[:500],
                        })
                    continue

                try:
                    row = self._normalize(obj, filename, current_offset, line_bytes)
                    self.stats["parsed_ok"] += 1
                    yield row
                except Exception as exc:
                    self.stats["malformed"] += 1
                    if len(self.malformed_records) < 1000:
                        self.malformed_records.append({
                            "file": filename,
                            "line": line_no,
                            "byte_offset": current_offset,
                            "error": f"Normalization error: {exc}",
                            "raw": stripped[:500],
                        })

    # ------------------------------------------------------------------
    # Normalization: flatten ECS JSON -> flat dict
    # ------------------------------------------------------------------

    def _normalize(self, ev: dict, raw_file: str, offset: int, length: int) -> dict:
        """Flatten one ECS JSON event into a normalized 28-field row dict."""
        row = empty_row()

        # --- 1. Provenance (FR-1) ---
        row["event_id"]       = _get(ev, "event", "id") or str(uuid.uuid4())
        row["raw_file"]       = raw_file
        row["byte_offset"]    = offset
        row["record_length"]  = length
        row["log_source"]     = "edr"

        # --- 2. Temporal Context ---
        row["timestamp"]      = _parse_timestamp(ev.get("@timestamp"))

        # --- 3. Classification & Outcome ---
        row["event_category"] = _get_first(ev, "event", "category")
        row["event_action"]   = _get(ev, "event", "action")
        row["event_outcome"]  = _get(ev, "event", "outcome")
        row["winlog_event_id"] = _get_int(ev, "winlog", "event_id")

        # --- 4. Host & Identity ---
        row["host_name"]      = _get(ev, "host", "name")
        host_ips = _get(ev, "host", "ip")
        row["host_ip"]        = host_ips[0] if isinstance(host_ips, list) and host_ips else None
        row["username"]       = _get(ev, "user", "name")
        row["user_domain"]    = _get(ev, "user", "domain")

        # --- 5. Process Lineage & Command Context ---
        row["process_name"]         = _get(ev, "process", "name")
        row["process_id"]           = _get_int(ev, "process", "pid")
        row["process_command_line"]  = _get(ev, "process", "command_line")
        row["parent_process_name"]  = _get(ev, "process", "parent", "name")
        row["parent_process_id"]    = _get_int(ev, "process", "parent", "pid")

        # --- 6. Network Communications ---
        row["source_ip"]            = _get(ev, "source", "ip")
        row["source_port"]          = _get_int(ev, "source", "port")
        row["destination_ip"]       = _get(ev, "destination", "ip")
        row["destination_port"]     = _get_int(ev, "destination", "port")
        row["destination_domain"]   = _get(ev, "destination", "domain")

        # --- 7. Persistence & Impact Artifacts ---
        row["registry_path"]  = _get(ev, "registry", "path")
        reg_data = _get(ev, "registry", "data")
        if isinstance(reg_data, dict):
            strings = reg_data.get("strings")
            row["registry_data"] = "; ".join(strings) if isinstance(strings, list) else str(reg_data)
        elif reg_data is not None:
            row["registry_data"] = str(reg_data)

        row["file_path"]      = _get(ev, "file", "path")
        file_ext = _get(ev, "file", "extension")
        if file_ext is None and _get(ev, "file", "name"):
            parts = str(_get(ev, "file", "name")).rsplit(".", 1)
            file_ext = parts[1] if len(parts) == 2 else None
        row["file_extension"] = file_ext

        return row
