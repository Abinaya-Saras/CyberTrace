"""
Streaming parser for FortiGate key-value log format.

FortiGate logs use a flat key=value format with optional quoting:
  date=2026-10-23 time=08:48:26 eventtime=1792745306000000000 ...
  srcip=10.10.40.156 hostname="nytimes.com" msg="Admin login failed ..."

This parser:
  - Reads line by line (streaming).
  - Tracks byte offsets for evidence provenance.
  - Normalizes into the common CyberTrace schema.
  - Handles malformed records without crashing.
  - Does NOT load the entire file into memory.
"""

import os
import re
import uuid
from datetime import datetime, timezone
from typing import Generator

from backend.core.schema import empty_row


# ---------------------------------------------------------------
# FortiGate KV tokeniser
# ---------------------------------------------------------------

# Regex: match key=value or key="quoted value"
_KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|((?:[^ ]|(?<=\\) )*))')


def _parse_kv_line(line: str) -> dict[str, str]:
    """Parse a FortiGate key=value line into a flat dict of strings."""
    pairs: dict[str, str] = {}
    for m in _KV_RE.finditer(line):
        key = m.group(1)
        val = m.group(2) if m.group(2) is not None else m.group(3)
        pairs[key] = val
    return pairs


# ---------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------

def _parse_fg_timestamp(kv: dict) -> datetime | None:
    """
    Build a UTC datetime from FortiGate fields.

    Priority:
      1. eventtime (nanosecond epoch) – most precise
      2. date + time + tz
    """
    # Try nanosecond eventtime first
    et = kv.get("eventtime")
    if et:
        try:
            ns = int(et)
            return datetime.fromtimestamp(ns / 1_000_000_000, tz=timezone.utc)
        except (ValueError, OSError, OverflowError):
            pass

    # Fall back to date + time + tz
    date_str = kv.get("date")
    time_str = kv.get("time")
    if date_str and time_str:
        tz_str = kv.get("tz", "+0000")
        try:
            combined = f"{date_str}T{time_str}{tz_str}"
            dt = datetime.fromisoformat(combined)
            return dt.astimezone(timezone.utc)
        except (ValueError, TypeError):
            pass

    return None


def _safe_int(val: str | None) -> int | None:
    """Convert string to int, returning None on failure."""
    if val is None:
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------

_FG_SEVERITY = {
    "emergency": 10,
    "critical": 10,
    "alert": 8,
    "error": 6,
    "warning": 5,
    "notice": 3,
    "information": 0,
}


# ---------------------------------------------------------------
# Category / action mapping
# ---------------------------------------------------------------

def _map_category(kv: dict) -> str:
    """Map FortiGate type+subtype to a normalized event category."""
    fg_type = kv.get("type", "")
    fg_sub = kv.get("subtype", "")

    if fg_sub == "dns":
        return "network"
    if fg_sub in ("ips", "virus"):
        return "network"
    if fg_sub == "webfilter":
        return "network"
    if fg_sub == "system":
        action = kv.get("action", "")
        if action in ("login", "logout"):
            return "authentication"
        return "configuration"
    if fg_sub in ("vpn", "ha", "dhcp", "sdwan", "connector"):
        return "network"
    if fg_type == "traffic":
        return "network"
    if fg_type == "utm":
        return "network"
    return "network"


def _map_action(kv: dict) -> str:
    """Map FortiGate fields to a normalised event action."""
    fg_sub = kv.get("subtype", "")
    action = kv.get("action", "")

    if fg_sub == "dns":
        return "dns_query"
    if fg_sub == "system" and action in ("login", "logout"):
        return f"admin_{action}"
    if fg_sub == "ips":
        return "ips_detection"
    if fg_sub == "virus":
        return "virus_detection"
    if fg_sub == "webfilter":
        return f"web_{action}"
    if fg_sub == "forward":
        return f"traffic_{action}"
    return action or "unknown"


# ---------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------

class FortiGateParser:
    """
    Streaming parser for FortiGate KV log files.

    Usage:
        parser = FortiGateParser()
        for row in parser.parse("/path/to/firex.log"):
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
        Yield normalized row dicts from a FortiGate KV log file.
        """
        filename = os.path.basename(filepath)
        source = source_label or filename
        byte_offset = 0

        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            for line_no, raw_line in enumerate(fh, start=1):
                line_bytes = len(raw_line.encode("utf-8"))
                current_offset = byte_offset
                byte_offset += line_bytes

                self.stats["total_lines"] += 1

                stripped = raw_line.strip()
                if not stripped:
                    self.stats["empty_lines"] += 1
                    continue

                try:
                    kv = _parse_kv_line(stripped)
                    if not kv:
                        raise ValueError("No key-value pairs extracted")

                    row = self._normalize(kv, filename, current_offset, line_bytes)
                    self.stats["parsed_ok"] += 1
                    yield row

                except Exception as exc:
                    self.stats["malformed"] += 1
                    self.malformed_records.append({
                        "file": filename,
                        "line": line_no,
                        "byte_offset": current_offset,
                        "error": str(exc),
                        "raw": stripped[:500],
                    })

    # ------------------------------------------------------------------
    # Normalisation
    # ------------------------------------------------------------------

    def _normalize(
        self, kv: dict, raw_file: str, offset: int, length: int
    ) -> dict:
        """Flatten one FortiGate KV record into a normalized row dict."""
        row = empty_row()

        # --- Provenance ---
        row["event_id"]      = kv.get("logid", "") + "-" + kv.get("sessionid", str(uuid.uuid4()))
        row["raw_file"]      = raw_file
        row["byte_offset"]   = offset
        row["record_length"] = length
        row["log_source"]    = "fortigate"

        # --- Timestamp ---
        row["timestamp"] = _parse_fg_timestamp(kv)

        # --- Event classification ---
        fg_type = kv.get("type", "")
        fg_sub = kv.get("subtype", "")
        fg_level = kv.get("level", "")
        fg_action = kv.get("action", "")

        row["event_kind"]     = "alert" if fg_level in ("alert", "emergency", "critical") else "event"
        row["event_category"] = _map_category(kv)
        row["event_type"]     = fg_sub
        row["event_action"]   = _map_action(kv)
        row["event_outcome"]  = kv.get("status") or ("success" if fg_action == "accept" else (
            "failure" if fg_action in ("deny", "blocked", "dropped") else None))
        row["event_severity"] = _FG_SEVERITY.get(fg_level, 0)
        row["event_module"]   = "fortigate"
        row["event_dataset"]  = f"{fg_type}.{fg_sub}" if fg_sub else fg_type

        # --- Host (the FortiGate device itself) ---
        row["host_name"]    = kv.get("devname")
        row["host_ip"]      = None  # FortiGate is the observer, not the host
        row["host_os_type"] = None
        row["host_os_full"] = None

        # --- User ---
        row["username"]     = kv.get("user")
        row["user_domain"]  = None

        # --- Source / Destination ---
        row["source_ip"]          = kv.get("srcip")
        row["source_port"]        = _safe_int(kv.get("srcport"))
        row["destination_ip"]     = kv.get("dstip")
        row["destination_port"]   = _safe_int(kv.get("dstport"))
        row["destination_domain"] = kv.get("hostname")  # DNS/web destination hostname

        # --- Process: N/A for firewall logs ---

        # --- File: N/A ---

        # --- Registry: N/A ---

        # --- DNS ---
        if fg_sub == "dns":
            row["dns_query_name"]    = kv.get("hostname")
            row["dns_response_code"] = None  # Not in FortiGate KV

        # --- Network ---
        proto_num = kv.get("proto")
        transport = None
        if proto_num == "6":
            transport = "tcp"
        elif proto_num == "17":
            transport = "udp"
        elif proto_num == "1":
            transport = "icmp"

        row["network_transport"]   = transport
        # Determine direction from interface roles
        src_role = kv.get("srcintfrole", "")
        dst_role = kv.get("dstintfrole", "")
        if src_role == "lan" and dst_role == "wan":
            row["network_direction"] = "outbound"
        elif src_role == "wan" and dst_role == "lan":
            row["network_direction"] = "inbound"
        elif src_role == "dmz" and dst_role == "wan":
            row["network_direction"] = "outbound"
        elif src_role == "wan" and dst_role == "dmz":
            row["network_direction"] = "inbound"
        else:
            row["network_direction"] = None

        row["network_protocol"]    = kv.get("service")
        sent = _safe_int(kv.get("sentbyte"))
        recv = _safe_int(kv.get("rcvdbyte"))
        row["network_bytes_sent"]  = sent
        row["network_bytes_recv"]  = recv
        row["network_bytes_total"] = (sent or 0) + (recv or 0) if (sent is not None or recv is not None) else None

        # --- Windows event log: N/A ---

        # --- FortiGate-specific fields ---
        row["fg_type"]         = fg_type
        row["fg_subtype"]      = fg_sub
        row["fg_level"]        = fg_level
        row["fg_logid"]        = kv.get("logid")
        row["fg_session_id"]   = kv.get("sessionid")
        row["fg_service"]      = kv.get("service")
        row["fg_app"]          = kv.get("app")
        row["fg_app_category"] = kv.get("appcat")
        row["fg_app_risk"]     = kv.get("apprisk")
        row["fg_policy_id"]    = _safe_int(kv.get("policyid"))
        row["fg_src_country"]  = kv.get("srccountry")
        row["fg_dst_country"]  = kv.get("dstcountry")
        row["fg_src_intf"]     = kv.get("srcintf")
        row["fg_dst_intf"]     = kv.get("dstintf")
        row["fg_attack_name"]  = kv.get("attack")
        row["fg_virus_name"]   = kv.get("virus")
        row["fg_url"]          = kv.get("url")
        row["fg_hostname"]     = kv.get("hostname")
        row["fg_cat_desc"]     = kv.get("catdesc")
        row["fg_msg"]          = kv.get("msg")
        row["fg_duration"]     = _safe_int(kv.get("duration"))
        row["fg_status"]       = kv.get("status")
        row["fg_reason"]       = kv.get("reason")

        return row
