"""
CyberTrace Normalized Event Schema.

One streamlined schema for all log sources (EDR, FortiGate, etc.).
Contains exactly 28 essential fields required for:
  - Ingestion & Source Provenance (FR-1)
  - Detection Queries (FR-2)
  - MITRE ATT&CK & Kill Chain Mapping (FR-3)
  - Incident Correlation & Entity Resolution (FR-4)
  - Chronological Attack Timelines & Host/User Graphs (FR-5)
  - Evidence-Supported Reach-Next Reasoning (FR-6)

Fields not present in a given source record are stored as NULL.
"""

import pyarrow as pa

# ---------------------------------------------------------------
# Streamlined 28-Column Normalized Schema
# ---------------------------------------------------------------

NORMALIZED_SCHEMA = pa.schema([
    # --- 1. Evidence Provenance (FR-1: Exact Raw Byte-Level Traceability) ---
    pa.field("event_id",               pa.string()),   # Original event.id or generated UUID
    pa.field("raw_file",               pa.string()),   # Source raw filename
    pa.field("byte_offset",            pa.int64()),    # Start byte offset in raw file
    pa.field("record_length",          pa.int32()),    # Byte length of raw record
    pa.field("log_source",             pa.string()),   # "edr" | "fortigate"

    # --- 2. Temporal Context (FR-1, FR-4, FR-5) ---
    pa.field("timestamp",              pa.timestamp("us", tz="UTC")),  # Microsecond UTC timestamp

    # --- 3. Event Classification & Outcome (FR-2) ---
    pa.field("event_category",         pa.string()),   # authentication | process | network | file | registry
    pa.field("event_action",           pa.string()),   # user_logon | process_created | file_rename | ...
    pa.field("event_outcome",          pa.string()),   # success | failure
    pa.field("winlog_event_id",        pa.int32()),    # 4624 (logon success), 4625 (logon fail), etc.

    # --- 4. Host & Identity (FR-4, FR-5) ---
    pa.field("host_name",              pa.string()),   # Target/observer host name
    pa.field("host_ip",                pa.string()),   # Primary host IP
    pa.field("username",               pa.string()),   # Acting/target user account
    pa.field("user_domain",            pa.string()),   # User domain (e.g., CORP)

    # --- 5. Process Lineage & Command Context (FR-2, FR-4, FR-5) ---
    pa.field("process_name",           pa.string()),   # Executable name (e.g., powershell.exe)
    pa.field("process_id",             pa.int32()),    # OS PID
    pa.field("process_command_line",    pa.string()),   # Full execution command line
    pa.field("parent_process_name",    pa.string()),   # Spawning process name
    pa.field("parent_process_id",      pa.int32()),    # Spawning process PID

    # --- 6. Network Communications & Lateral Movement (FR-2, FR-4, FR-6) ---
    pa.field("source_ip",              pa.string()),   # Inbound/initiating IP
    pa.field("source_port",            pa.int32()),    # Source port
    pa.field("destination_ip",         pa.string()),   # Outbound target IP
    pa.field("destination_port",       pa.int32()),    # Outbound target port (e.g., 445, 80, 443)
    pa.field("destination_domain",     pa.string()),   # DNS query or destination hostname

    # --- 7. Persistence & Impact Artifacts (FR-2) ---
    pa.field("registry_path",          pa.string()),   # Windows registry key path
    pa.field("registry_data",          pa.string()),   # Registry value payload
    pa.field("file_path",              pa.string()),   # File system path
    pa.field("file_extension",         pa.string()),   # File extension (e.g., locked, crypto)
])

# Column names set for O(1) membership checks
SCHEMA_COLUMNS = frozenset(f.name for f in NORMALIZED_SCHEMA)

# Strict field count verification
NUM_COLUMNS = len(NORMALIZED_SCHEMA)
assert NUM_COLUMNS == 28, f"Expected 28 fields in schema, got {NUM_COLUMNS}"


_EMPTY_ROW_TEMPLATE = {f.name: None for f in NORMALIZED_SCHEMA}


def empty_row() -> dict:
    """Return a fresh dictionary with all 28 schema keys initialized to None."""
    return _EMPTY_ROW_TEMPLATE.copy()

