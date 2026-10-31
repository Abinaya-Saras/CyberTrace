"""
CyberTrace normalized event schema.

One flat schema for all log sources (EDR, FortiGate, etc.).
Fields not present in a given source are stored as NULL.
This schema is the single contract between parsers, the Parquet
writer, and every downstream module (detection, correlation, graph).
"""

import pyarrow as pa

# ---------------------------------------------------------------
# Schema definition
# ---------------------------------------------------------------

NORMALIZED_SCHEMA = pa.schema([
    # --- Evidence provenance (NEVER drop these) ---
    pa.field("event_id",        pa.string()),   # Original event.id or generated UUID
    pa.field("raw_file",        pa.string()),   # Source filename
    pa.field("byte_offset",     pa.int64()),    # Start byte in raw file
    pa.field("record_length",   pa.int32()),    # Byte length of raw record
    pa.field("log_source",      pa.string()),   # "edr" | "fortigate"

    # --- Time ---
    pa.field("timestamp",       pa.timestamp("us", tz="UTC")),  # Microsecond UTC

    # --- Event classification ---
    pa.field("event_kind",      pa.string()),   # event | alert | signal
    pa.field("event_category",  pa.string()),   # authentication | process | network | file | registry
    pa.field("event_type",      pa.string()),   # start | connection | change | creation | protocol
    pa.field("event_action",    pa.string()),   # user_logon | process_created | ...
    pa.field("event_outcome",   pa.string()),   # success | failure
    pa.field("event_severity",  pa.int16()),    # 0-10
    pa.field("event_module",    pa.string()),   # edr | fortigate
    pa.field("event_dataset",   pa.string()),   # edr.authentication | utm.dns | ...

    # --- Host ---
    pa.field("host_name",       pa.string()),
    pa.field("host_ip",         pa.string()),   # Primary IP as string
    pa.field("host_os_type",    pa.string()),   # windows | linux
    pa.field("host_os_full",    pa.string()),   # "Windows 11 Enterprise 23H2"

    # --- User ---
    pa.field("username",        pa.string()),
    pa.field("user_domain",     pa.string()),

    # --- Source / Destination (network + auth) ---
    pa.field("source_ip",       pa.string()),
    pa.field("source_port",     pa.int32()),
    pa.field("destination_ip",  pa.string()),
    pa.field("destination_port", pa.int32()),
    pa.field("destination_domain", pa.string()),

    # --- Process ---
    pa.field("process_name",    pa.string()),
    pa.field("process_id",      pa.int32()),
    pa.field("process_executable", pa.string()),
    pa.field("process_command_line", pa.string()),
    pa.field("process_entity_id", pa.string()),
    pa.field("parent_process_name", pa.string()),
    pa.field("parent_process_id", pa.int32()),
    pa.field("process_hash_md5", pa.string()),
    pa.field("process_hash_sha256", pa.string()),

    # --- File ---
    pa.field("file_path",       pa.string()),
    pa.field("file_name",       pa.string()),
    pa.field("file_size",       pa.int64()),
    pa.field("file_extension",  pa.string()),

    # --- Registry ---
    pa.field("registry_path",   pa.string()),
    pa.field("registry_data",   pa.string()),

    # --- DNS ---
    pa.field("dns_query_name",  pa.string()),
    pa.field("dns_response_code", pa.string()),

    # --- Network ---
    pa.field("network_transport", pa.string()),  # tcp | udp
    pa.field("network_direction", pa.string()),  # inbound | outbound
    pa.field("network_protocol", pa.string()),   # https | dns | ...
    pa.field("network_bytes_total", pa.int64()), # Total bytes
    pa.field("network_bytes_sent", pa.int64()),
    pa.field("network_bytes_recv", pa.int64()),

    # --- Windows event log ---
    pa.field("winlog_event_id", pa.int32()),
    pa.field("winlog_logon_type", pa.string()),

    # --- FortiGate-specific (detection-relevant) ---
    pa.field("fg_type",         pa.string()),   # traffic | utm | event
    pa.field("fg_subtype",      pa.string()),   # forward | dns | system | ips | ...
    pa.field("fg_level",        pa.string()),   # information | notice | alert | ...
    pa.field("fg_logid",        pa.string()),
    pa.field("fg_session_id",   pa.string()),
    pa.field("fg_service",      pa.string()),   # DNS | HTTPS | SSH | ...
    pa.field("fg_app",          pa.string()),   # Application name
    pa.field("fg_app_category", pa.string()),
    pa.field("fg_app_risk",     pa.string()),
    pa.field("fg_policy_id",    pa.int32()),
    pa.field("fg_src_country",  pa.string()),
    pa.field("fg_dst_country",  pa.string()),
    pa.field("fg_src_intf",     pa.string()),
    pa.field("fg_dst_intf",     pa.string()),
    pa.field("fg_attack_name",  pa.string()),   # IPS attack name
    pa.field("fg_virus_name",   pa.string()),   # AV detection
    pa.field("fg_url",          pa.string()),
    pa.field("fg_hostname",     pa.string()),   # Destination hostname (DNS/web)
    pa.field("fg_cat_desc",     pa.string()),   # Web filter category
    pa.field("fg_msg",          pa.string()),   # Human-readable message
    pa.field("fg_duration",     pa.int32()),    # Session duration in seconds
    pa.field("fg_status",       pa.string()),   # failed | success etc.
    pa.field("fg_reason",       pa.string()),   # Failure reason
])

# Column names as a frozen set for fast membership checks
SCHEMA_COLUMNS = frozenset(f.name for f in NORMALIZED_SCHEMA)

# Number of columns
NUM_COLUMNS = len(NORMALIZED_SCHEMA)


def empty_row() -> dict:
    """Return a dict with all schema keys set to None."""
    return {f.name: None for f in NORMALIZED_SCHEMA}
