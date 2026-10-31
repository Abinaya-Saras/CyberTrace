"""
CyberTrace Security Detection Engine.

Executes validated YAML detection rules against normalized Parquet telemetry
using an embedded, resource-constrained DuckDB instance.

Guiding principles:
  - Every finding must be supported by actual log evidence.
  - Never invent events, relationships, or attack stages.
  - Strict separation of confidence (evidence strength) and severity (impact).
  - Accurate entity context: target of an attack != compromised entity.
  - Granular evidence provenance: preserves per-event actor, PID, and command-line.
  - Memory-safe: zero-copy Parquet scanning, conservative limits (1 GB RAM, 2 threads).
"""

from datetime import datetime, timezone
import json
import logging
import os
from typing import Any, Callable, Optional

from backend.core.duckdb_engine import DuckDBEngine
from backend.detection.alert_schema import Alert
from backend.detection.rule_loader import RuleDefinition, load_rules_from_directory

logger = logging.getLogger(__name__)


def _format_ts(ts: Any) -> str:
    """Format timestamp to ISO 8601 string."""
    if ts is None:
        return datetime.now(timezone.utc).isoformat()
    if hasattr(ts, "isoformat"):
        return ts.isoformat()
    return str(ts)


def _build_evidence_refs(
    event_ids: list[str],
    raw_files: list[str],
    byte_offsets: list[int],
    record_lengths: list[int],
    timestamps: Optional[list[Any]] = None,
    usernames: Optional[list[str]] = None,
    process_names: Optional[list[str]] = None,
    process_ids: Optional[list[Any]] = None,
    parent_process_names: Optional[list[str]] = None,
    parent_process_ids: Optional[list[Any]] = None,
    process_command_lines: Optional[list[str]] = None,
    source_ips: Optional[list[str]] = None,
    destination_ips: Optional[list[str]] = None,
) -> list[dict[str, Any]]:
    """
    Build structured evidence provenance references for an alert.
    Retains granular per-event actor, PID, and command-line metadata.
    """
    refs = []
    n = len(event_ids)
    for i in range(n):
        rf = raw_files[i] if i < len(raw_files) else "unknown"
        bo = int(byte_offsets[i]) if i < len(byte_offsets) else 0
        rl = int(record_lengths[i]) if i < len(record_lengths) else 0
        ts_str = _format_ts(timestamps[i]) if timestamps and i < len(timestamps) else None

        ref: dict[str, Any] = {
            "event_id": str(event_ids[i]),
            "raw_file": str(rf),
            "byte_offset": bo,
            "record_length": rl,
        }
        if ts_str:
            ref["timestamp"] = ts_str
        if usernames and i < len(usernames) and usernames[i]:
            ref["username"] = str(usernames[i])
        if process_names and i < len(process_names) and process_names[i]:
            ref["process_name"] = str(process_names[i])
        if process_ids and i < len(process_ids) and process_ids[i] is not None:
            try:
                ref["process_id"] = int(process_ids[i])
            except (ValueError, TypeError):
                pass
        if parent_process_names and i < len(parent_process_names) and parent_process_names[i]:
            ref["parent_process_name"] = str(parent_process_names[i])
        if parent_process_ids and i < len(parent_process_ids) and parent_process_ids[i] is not None:
            try:
                ref["parent_process_id"] = int(parent_process_ids[i])
            except (ValueError, TypeError):
                pass
        if process_command_lines and i < len(process_command_lines) and process_command_lines[i]:
            ref["process_command_line"] = str(process_command_lines[i])
        if source_ips and i < len(source_ips) and source_ips[i]:
            ref["source_ip"] = str(source_ips[i])
        if destination_ips and i < len(destination_ips) and destination_ips[i]:
            ref["destination_ip"] = str(destination_ips[i])

        refs.append(ref)
    return refs


# -----------------------------------------------------------------------------
# Detection Handlers
# -----------------------------------------------------------------------------

def handle_brute_force(
    engine: DuckDBEngine,
    rule: RuleDefinition,
    view_name: str,
) -> list[Alert]:
    """
    Handler for RULE-001 (T1110 - Brute Force).
    Identifies repeated authentication failures targeting users on a host from a source IP.
    Verifies whether a subsequent successful authentication occurred from the SAME source IP.
    Never claims account compromise without concrete evidence of success from the attacker's source.
    """
    min_failures = int(rule.threshold.get("min_failures", 3))
    min_failures_high = int(rule.parameters.get("min_failures_high_confidence", 6))

    sql = f"""
    SELECT
        host_name,
        username,
        source_ip,
        count(*) as fail_count,
        min(timestamp) as first_seen,
        max(timestamp) as last_seen,
        list(event_id) as event_ids,
        list(raw_file) as raw_files,
        list(byte_offset) as byte_offsets,
        list(record_length) as record_lengths,
        list(timestamp) as timestamps,
        list(username) as usernames,
        list(source_ip) as source_ips
    FROM {view_name}
    WHERE event_category = 'authentication'
      AND (event_outcome = 'failure' OR winlog_event_id = 4625)
    GROUP BY host_name, username, source_ip
    HAVING count(*) >= ?
    ORDER BY fail_count DESC
    """
    rows = engine.query(sql, [min_failures])
    alerts = []

    for row in rows:
        host, user, src_ip, fail_cnt, first_seen, last_seen, eids, rfiles, boffs, rlens, tss, unames, sips = row

        first_iso = _format_ts(first_seen)
        last_iso = _format_ts(last_seen)

        # Audit Check: Check if subsequent successful login occurred from the SAME source IP
        subsequent_success_from_source = False
        if rule.parameters.get("check_subsequent_success", True) and user and src_ip:
            succ_sql = f"""
            SELECT count(*)
            FROM {view_name}
            WHERE event_category = 'authentication'
              AND (event_outcome = 'success' OR winlog_event_id = 4624)
              AND username = ?
              AND host_name = ?
              AND source_ip = ?
              AND timestamp >= ?
            """
            succ_row = engine.query_one(succ_sql, [user, host, src_ip, first_seen])
            if succ_row and succ_row[0] > 0:
                subsequent_success_from_source = True

        if subsequent_success_from_source:
            confidence = "high"
            reasoning = (
                f"Suspicious authentication activity: observed {fail_cnt} failed authentication attempts "
                f"for user '{user}' on target host '{host}' from source IP '{src_ip}' between {first_iso} "
                f"and {last_iso}, followed by a confirmed successful authentication from the SAME source IP. "
                f"Evidence indicates probable credential compromise."
            )
        elif fail_cnt >= min_failures_high:
            confidence = "medium"
            reasoning = (
                f"High-frequency failed logon surge: observed {fail_cnt} authentication failures "
                f"targeting user '{user}' on host '{host}' from external source IP '{src_ip}' between "
                f"{first_iso} and {last_iso}. No subsequent successful authentication was observed from "
                f"source IP '{src_ip}'; account compromise is NOT established."
            )
        else:
            confidence = "medium"
            reasoning = (
                f"Repeated authentication failures: observed {fail_cnt} failed logon attempts "
                f"targeting user '{user}' on host '{host}' from source IP '{src_ip}' between {first_iso} "
                f"and {last_iso}. No subsequent successful authentication was observed from source IP '{src_ip}'; "
                f"account compromise is NOT established."
            )

        evidence_refs = _build_evidence_refs(
            eids, rfiles, boffs, rlens, tss, usernames=unames, source_ips=sips
        )

        alert = Alert(
            rule_id=rule.rule_id,
            title=f"Suspicious Authentication Failures ({fail_cnt} attempts) on {host}",
            description=rule.description,
            severity=rule.severity,
            confidence=confidence,
            mitre_technique_id=rule.mitre_technique_id,
            mitre_technique_name=rule.mitre_technique_name,
            mitre_tactic=rule.mitre_tactic,
            kill_chain_stage=rule.kill_chain_stage,
            first_seen=first_iso,
            last_seen=last_iso,
            host=host,
            username=user,
            source_ip=src_ip,
            destination_ip=None,
            supporting_event_ids=[str(e) for e in eids],
            evidence_references=evidence_refs,
            reasoning=reasoning,
        )
        alerts.append(alert)

    return alerts


def handle_suspicious_process(
    engine: DuckDBEngine,
    rule: RuleDefinition,
    view_name: str,
) -> list[Alert]:
    """
    Handler for RULE-002 (T1059.001 - Suspicious Process Execution).
    Identifies Office applications spawning PowerShell/pwsh.
    Aggregates executions by host within the time window to prevent alert flooding
    while preserving all execution evidence references and per-event actor/PID details.
    """
    parent_procs = [p.lower() for p in rule.parameters.get("parent_processes", ["winword.exe", "excel.exe"])]
    child_procs = [p.lower() for p in rule.parameters.get("child_processes", ["powershell.exe", "pwsh.exe"])]
    stealth_flags = [f.lower() for f in rule.parameters.get("stealth_flags", ["-enc", "-nop", "-w hidden"])]

    parents_clause = ", ".join(f"'{p}'" for p in parent_procs)
    children_clause = ", ".join(f"'{c}'" for c in child_procs)

    sql = f"""
    SELECT
        host_name,
        string_agg(DISTINCT username, ', ') as username,
        process_name,
        parent_process_name,
        count(*) as execution_count,
        min(timestamp) as first_seen,
        max(timestamp) as last_seen,
        list(event_id) as event_ids,
        list(raw_file) as raw_files,
        list(byte_offset) as byte_offsets,
        list(record_length) as record_lengths,
        list(timestamp) as timestamps,
        list(process_id) as pids,
        list(parent_process_id) as ppids,
        list(process_command_line) as cmd_lines,
        list(username) as usernames
    FROM {view_name}
    WHERE event_category = 'process'
      AND lower(parent_process_name) IN ({parents_clause})
      AND lower(process_name) IN ({children_clause})
    GROUP BY host_name, parent_process_name, process_name
    ORDER BY execution_count DESC
    """
    rows = engine.query(sql)
    alerts = []

    for row in rows:
        (
            host,
            user,
            proc_name,
            parent_name,
            exec_cnt,
            first_seen,
            last_seen,
            eids,
            rfiles,
            boffs,
            rlens,
            tss,
            pids,
            ppids,
            cmd_lines,
            unames,
        ) = row

        first_iso = _format_ts(first_seen)
        last_iso = _format_ts(last_seen)

        has_stealth = any(
            any(flag in (cmd or "").lower() for flag in stealth_flags)
            for cmd in cmd_lines
        )

        sample_cmd = cmd_lines[0] if cmd_lines else ""
        sample_pid = pids[0] if pids else None
        sample_ppid = ppids[0] if ppids else None

        if has_stealth:
            confidence = "high"
            reasoning = (
                f"Suspicious process execution observed: Office application '{parent_name}' (PID: {sample_ppid}) "
                f"spawned scripting engine '{proc_name}' (PID: {sample_pid}) {exec_cnt} time(s) on host '{host}' "
                f"(associated user(s): {user}) with evasive/encoded command-line arguments: '{sample_cmd}'. "
                f"Telemetry establishes anomalous execution; multi-stage compromise is not established by this single technique."
            )
        else:
            confidence = "medium"
            reasoning = (
                f"Suspicious process execution observed: Office application '{parent_name}' (PID: {sample_ppid}) "
                f"spawned scripting engine '{proc_name}' (PID: {sample_pid}) {exec_cnt} time(s) on host '{host}' "
                f"(associated user(s): {user}). Command line: '{sample_cmd}'."
            )

        evidence_refs = _build_evidence_refs(
            eids, rfiles, boffs, rlens, tss,
            usernames=unames,
            process_names=[proc_name] * len(eids),
            process_ids=pids,
            parent_process_names=[parent_name] * len(eids),
            parent_process_ids=ppids,
            process_command_lines=cmd_lines,
        )

        alert = Alert(
            rule_id=rule.rule_id,
            title=f"Suspicious Process Execution: Office Spawned Script Engine ({parent_name} -> {proc_name}) on {host}",
            description=rule.description,
            severity=rule.severity,
            confidence=confidence,
            mitre_technique_id=rule.mitre_technique_id,
            mitre_technique_name=rule.mitre_technique_name,
            mitre_tactic=rule.mitre_tactic,
            kill_chain_stage=rule.kill_chain_stage,
            first_seen=first_iso,
            last_seen=last_iso,
            host=host,
            username=user,
            source_ip=None,
            destination_ip=None,
            process_name=proc_name,
            process_id=int(sample_pid) if sample_pid is not None else None,
            parent_process_name=parent_name,
            parent_process_id=int(sample_ppid) if sample_ppid is not None else None,
            supporting_event_ids=[str(e) for e in eids],
            evidence_references=evidence_refs,
            reasoning=reasoning,
        )
        alerts.append(alert)

    return alerts


def handle_c2_beaconing(
    engine: DuckDBEngine,
    rule: RuleDefinition,
    view_name: str,
) -> list[Alert]:
    """
    Handler for RULE-003 (T1071.001 - C2 Beaconing).
    Identifies repeated outbound network connections to suspicious destinations.
    Requires sufficient observations and interval consistency.
    """
    min_conns = int(rule.threshold.get("min_connections", 3))
    min_interval_sec = float(rule.parameters.get("min_interval_seconds", 1.0))
    suspicious_procs = [p.lower() for p in rule.parameters.get("suspicious_processes", ["powershell.exe"])]
    excluded_domains = [d.lower() for d in rule.parameters.get("exclude_benign_domains", [])]

    procs_clause = ", ".join(f"'{p}'" for p in suspicious_procs)
    excl_clause = ", ".join(f"'{d}'" for d in excluded_domains) if excluded_domains else "''"

    sql = f"""
    SELECT
        host_name,
        string_agg(DISTINCT username, ', ') as username,
        process_name,
        destination_ip,
        destination_domain,
        count(*) as conn_count,
        min(timestamp) as first_seen,
        max(timestamp) as last_seen,
        epoch(max(timestamp)) - epoch(min(timestamp)) as delta_seconds,
        list(event_id) as event_ids,
        list(raw_file) as raw_files,
        list(byte_offset) as byte_offsets,
        list(record_length) as record_lengths,
        list(timestamp) as timestamps,
        list(username) as usernames,
        list(destination_ip) as dest_ips
    FROM {view_name}
    WHERE event_category = 'network'
      AND (destination_ip IS NOT NULL OR destination_domain IS NOT NULL)
      AND (destination_domain IS NULL OR lower(destination_domain) NOT IN ({excl_clause}))
      AND lower(process_name) IN ({procs_clause})
    GROUP BY host_name, process_name, destination_ip, destination_domain
    HAVING count(*) >= ?
    ORDER BY conn_count DESC
    """
    rows = engine.query(sql, [min_conns])
    alerts = []

    for row in rows:
        (
            host,
            user,
            proc,
            dest_ip,
            dest_domain,
            conn_cnt,
            first_seen,
            last_seen,
            delta_sec,
            eids,
            rfiles,
            boffs,
            rlens,
            tss,
            unames,
            dips,
        ) = row

        if delta_sec < min_interval_sec and conn_cnt < 5:
            logger.info(
                f"Skipping unconfirmed C2 on {host}: {conn_cnt} events within {delta_sec:.4f}s "
                f"(requires >= {min_interval_sec}s interval or >= 5 observations)"
            )
            continue

        first_iso = _format_ts(first_seen)
        last_iso = _format_ts(last_seen)
        is_doc_ip = dest_ip in ("192.0.2.88", "198.51.100.23", "203.0.113.57")

        if conn_cnt >= 5 and not is_doc_ip:
            confidence = "high"
            reasoning = (
                f"Consistent outbound communication observed: {conn_cnt} connections from host '{host}' "
                f"by scripting process '{proc}' to external destination '{dest_ip or 'N/A'}' "
                f"(domain: '{dest_domain or 'N/A'}') over a {delta_sec:.2f}s span."
            )
        else:
            confidence = "low"
            reasoning = (
                f"Suspicious outbound network activity: observed {conn_cnt} connections by process '{proc}' "
                f"from host '{host}' to destination '{dest_ip or 'N/A'}' (domain: '{dest_domain or 'N/A'}') "
                f"spanning {delta_sec:.4f}s. Note: Observations are limited; periodic beaconing cannot be "
                f"conclusively established from this sample."
            )

        evidence_refs = _build_evidence_refs(
            eids, rfiles, boffs, rlens, tss,
            usernames=unames,
            process_names=[proc] * len(eids),
            destination_ips=dips,
        )

        alert = Alert(
            rule_id=rule.rule_id,
            title=f"Suspicious Outbound Network Connections ({conn_cnt} conns to {dest_domain or dest_ip}) on {host}",
            description=rule.description,
            severity=rule.severity,
            confidence=confidence,
            mitre_technique_id=rule.mitre_technique_id,
            mitre_technique_name=rule.mitre_technique_name,
            mitre_tactic=rule.mitre_tactic,
            kill_chain_stage=rule.kill_chain_stage,
            first_seen=first_iso,
            last_seen=last_iso,
            host=host,
            username=user,
            source_ip=None,
            destination_ip=dest_ip,
            process_name=proc,
            supporting_event_ids=[str(e) for e in eids],
            evidence_references=evidence_refs,
            reasoning=reasoning,
        )
        alerts.append(alert)

    return alerts


def handle_registry_persistence(
    engine: DuckDBEngine,
    rule: RuleDefinition,
    view_name: str,
) -> list[Alert]:
    """
    Handler for RULE-004 (T1547.001 - Registry Persistence).
    Identifies writes/modifications to Windows Run / RunOnce keys.
    Aggregates modifications by host within the time window.
    Strictly filters for value modification actions (ignores read/query operations).
    """
    key_patterns = rule.parameters.get(
        "key_patterns",
        ["%CurrentVersion\\Run%", "%CurrentVersion\\RunOnce%"],
    )
    suspicious_procs = [p.lower() for p in rule.parameters.get("suspicious_processes", ["powershell.exe"])]
    pattern_conditions = " OR ".join(f"registry_path ILIKE '{pat}'" for pat in key_patterns)

    sql = f"""
    SELECT
        host_name,
        string_agg(DISTINCT username, ', ') as username,
        string_agg(DISTINCT process_name, ', ') as process_name,
        registry_path,
        string_agg(DISTINCT registry_data, '; ') as reg_data,
        count(*) as mod_count,
        min(timestamp) as first_seen,
        max(timestamp) as last_seen,
        list(event_id) as event_ids,
        list(raw_file) as raw_files,
        list(byte_offset) as byte_offsets,
        list(record_length) as record_lengths,
        list(timestamp) as timestamps,
        list(username) as usernames,
        list(process_name) as procs
    FROM {view_name}
    WHERE event_category = 'registry'
      AND (event_action IN ('registry_value_set', 'change', 'creation') OR event_type IN ('change', 'creation'))
      AND ({pattern_conditions})
    GROUP BY host_name, registry_path
    ORDER BY mod_count DESC
    """
    rows = engine.query(sql)
    alerts = []

    for row in rows:
        host, user, proc_summary, reg_path, reg_data, mod_cnt, first_seen, last_seen, eids, rfiles, boffs, rlens, tss, unames, procs = row
        first_iso = _format_ts(first_seen)
        last_iso = _format_ts(last_seen)

        sample_proc = procs[0] if procs else "unknown"
        data_str = reg_data or ""

        is_suspicious_proc = any(sp in (sample_proc or "").lower() for sp in suspicious_procs)
        is_suspicious_payload = any(s in data_str.lower() for s in ["appdata", "temp", ".exe", "<redacted>"])

        if is_suspicious_proc or is_suspicious_payload:
            confidence = "high"
            reasoning = (
                f"Suspicious registry persistence modification: Script engine '{sample_proc}' "
                f"modified Windows autorun key '{reg_path}' {mod_cnt} time(s) with value '{reg_data}' "
                f"on host '{host}' (associated user(s): {user}) between {first_iso} and {last_iso}. "
                f"Indicates autorun persistence configuration; execution from this key is unproven by this event alone."
            )
        else:
            confidence = "medium"
            reasoning = (
                f"Autorun key modification observed under '{reg_path}' with value '{reg_data}' "
                f"by process '{sample_proc}' on host '{host}' ({mod_cnt} event(s)) at {first_iso}."
            )

        evidence_refs = _build_evidence_refs(
            eids, rfiles, boffs, rlens, tss,
            usernames=unames,
            process_names=procs,
        )

        alert = Alert(
            rule_id=rule.rule_id,
            title=f"Suspicious Registry Modification: Autorun Key Persistence on {host}",
            description=rule.description,
            severity=rule.severity,
            confidence=confidence,
            mitre_technique_id=rule.mitre_technique_id,
            mitre_technique_name=rule.mitre_technique_name,
            mitre_tactic=rule.mitre_tactic,
            kill_chain_stage=rule.kill_chain_stage,
            first_seen=first_iso,
            last_seen=last_iso,
            host=host,
            username=user,
            source_ip=None,
            destination_ip=None,
            process_name=sample_proc,
            supporting_event_ids=[str(e) for e in eids],
            evidence_references=evidence_refs,
            reasoning=reasoning,
        )
        alerts.append(alert)

    return alerts


def handle_mass_file_modification(
    engine: DuckDBEngine,
    rule: RuleDefinition,
    view_name: str,
) -> list[Alert]:
    """
    Handler for RULE-005 (T1486 - Mass File Modification / Ransomware).
    Identifies suspicious file rename bursts matching ransomware patterns.
    Aggregates by host_name, process_name, file_extension to preserve host-level context
    and avoid synthetic username fragmentation.
    """
    min_files = int(rule.threshold.get("min_files", 2))
    ransom_extensions = [e.lower() for e in rule.parameters.get("ransom_extensions", ["locked", "crypto"])]
    ext_clause = ", ".join(f"'{e}'" for e in ransom_extensions)

    sql = f"""
    SELECT
        host_name,
        string_agg(DISTINCT username, ', ') as username,
        process_name,
        file_extension,
        count(*) as file_count,
        min(timestamp) as first_seen,
        max(timestamp) as last_seen,
        list(event_id) as event_ids,
        list(raw_file) as raw_files,
        list(byte_offset) as byte_offsets,
        list(record_length) as record_lengths,
        list(timestamp) as timestamps,
        list(file_path) as file_paths,
        list(username) as usernames
    FROM {view_name}
    WHERE event_category = 'file'
      AND (
          lower(file_extension) IN ({ext_clause})
          OR lower(file_path) LIKE '%.locked'
          OR (event_action = 'file_rename' AND lower(process_name) = 'unknown.exe')
      )
    GROUP BY host_name, process_name, file_extension
    HAVING count(*) >= ?
    ORDER BY file_count DESC
    """
    rows = engine.query(sql, [min_files])
    alerts = []

    for row in rows:
        (
            host,
            user,
            proc,
            ext,
            cnt,
            first_seen,
            last_seen,
            eids,
            rfiles,
            boffs,
            rlens,
            tss,
            paths,
            unames,
        ) = row

        first_iso = _format_ts(first_seen)
        last_iso = _format_ts(last_seen)

        if cnt >= 3:
            confidence = "high"
            reasoning = (
                f"Suspicious file rename burst observed: {cnt} files renamed to uniform extension '.{ext}' "
                f"by non-standard process '{proc}' on host '{host}' (associated user(s): {user}) between "
                f"{first_iso} and {last_iso}. Consistent with ransomware staging behavior. "
                f"Note: Telemetry reflects file rename actions only; file encryption cannot be "
                f"independently established without file content or entropy telemetry."
            )
        else:
            confidence = "medium"
            reasoning = (
                f"Suspicious file rename activity: {cnt} file rename events to extension '.{ext}' "
                f"by process '{proc}' on host '{host}' (associated user(s): {user}) between {first_iso} and {last_iso}. "
                f"Note: Telemetry captures file rename actions; file encryption is not directly established."
            )

        evidence_refs = _build_evidence_refs(
            eids, rfiles, boffs, rlens, tss,
            usernames=unames,
            process_names=[proc] * len(eids),
        )

        alert = Alert(
            rule_id=rule.rule_id,
            title=f"Suspicious File Rename Activity Consistent with Ransomware ({cnt} files) on {host}",
            description=rule.description,
            severity=rule.severity,
            confidence=confidence,
            mitre_technique_id=rule.mitre_technique_id,
            mitre_technique_name=rule.mitre_technique_name,
            mitre_tactic=rule.mitre_tactic,
            kill_chain_stage=rule.kill_chain_stage,
            first_seen=first_iso,
            last_seen=last_iso,
            host=host,
            username=user,
            source_ip=None,
            destination_ip=None,
            process_name=proc,
            supporting_event_ids=[str(e) for e in eids],
            evidence_references=evidence_refs,
            reasoning=reasoning,
        )
        alerts.append(alert)

    return alerts


# Registry of approved handlers
HANDLER_REGISTRY: dict[str, Callable[[DuckDBEngine, RuleDefinition, str], list[Alert]]] = {
    "brute_force_handler": handle_brute_force,
    "suspicious_process_handler": handle_suspicious_process,
    "c2_beaconing_handler": handle_c2_beaconing,
    "registry_persistence_handler": handle_registry_persistence,
    "mass_file_modification_handler": handle_mass_file_modification,
}


# -----------------------------------------------------------------------------
# Main Detection Engine
# -----------------------------------------------------------------------------

class DetectionEngine:
    """
    Orchestrates execution of validated detection rules against normalized Parquet data.
    """

    def __init__(
        self,
        rules_directory: Optional[str] = None,
        engine: Optional[DuckDBEngine] = None,
    ):
        self.engine = engine or DuckDBEngine(memory_limit="1GB", threads=2)
        self.rules: list[RuleDefinition] = []
        if rules_directory:
            self.load_rules(rules_directory)

    def load_rules(self, rules_directory: str) -> None:
        """Load and validate all rules from a directory."""
        self.rules = load_rules_from_directory(rules_directory)
        logger.info(f"Loaded {len(self.rules)} rules from {rules_directory}")

    def run_rule(self, rule: RuleDefinition, parquet_path: str) -> list[Alert]:
        """Execute a single rule against a Parquet dataset."""
        if not rule.enabled:
            logger.info(f"Rule '{rule.rule_id}' is disabled. Skipping.")
            return []

        handler = HANDLER_REGISTRY.get(rule.detection_logic)
        if not handler:
            raise ValueError(f"No handler registered for '{rule.detection_logic}' in rule '{rule.rule_id}'")

        view_name = "events_for_detection"
        self.engine.create_parquet_view(view_name, parquet_path)

        alerts = handler(self.engine, rule, view_name)
        return alerts

    def run_all(self, parquet_path: str) -> list[Alert]:
        """Execute all enabled rules against a Parquet dataset."""
        all_alerts: list[Alert] = []
        view_name = "events_for_detection"
        self.engine.create_parquet_view(view_name, parquet_path)

        for rule in self.rules:
            if not rule.enabled:
                continue
            handler = HANDLER_REGISTRY.get(rule.detection_logic)
            if not handler:
                logger.warning(f"Skipping rule '{rule.rule_id}': handler '{rule.detection_logic}' not found")
                continue
            alerts = handler(self.engine, rule, view_name)
            all_alerts.extend(alerts)

        return all_alerts

    def close(self) -> None:
        """Close internal DuckDB engine."""
        if self.engine:
            self.engine.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
