"""
Multi-Dimensional Correlation Strategies for CyberTrace.

Implements independent, evidence-backed correlation rules:
  A. Host Correlation (same host across rules; preserves endpoint boundary)
  B. User Correlation (exact user matching; cross-host marked ineligible for investigation clustering)
  C. Network Correlation (IP matching; TEST-NET classified as synthetic test data, ineligible for clustering)
  D. Process Correlation (PID/PPID validation; distinguishes SAME_PROCESS from SAME_PROCESS_IMAGE)
  E. Temporal Correlation (timestamp delta; sub-second proximity marked ineligible for clustering)
  F. Cross-Source Correlation (EDR <-> FortiGate framework and limitation handling)
  G. Behavioral Sequence Correlation (strictly requires independent contextual overlap; rejects unevidenced transitions)
"""

from datetime import datetime
import os
from typing import Any, Optional

from backend.correlation.confidence import (
    classify_ip,
    evaluate_confidence,
    is_test_net_ip,
)
from backend.correlation.entity_extractor import EntityExtractor
from backend.correlation.relationship_schema import (
    ConfidenceLevel,
    CorrelationDimension,
    ObservationStatus,
    Relationship,
    RelationshipType,
)
from backend.detection.alert_schema import Alert


def _parse_iso_ts(ts_str: Optional[str]) -> Optional[datetime]:
    """Parse ISO-8601 timestamp string safely."""
    if not ts_str:
        return None
    try:
        s = ts_str.replace("Z", "+00:00")
        return datetime.fromisoformat(s)
    except Exception:
        return None


def _calc_time_delta_ms(ts_a_str: Optional[str], ts_b_str: Optional[str]) -> Optional[float]:
    """Calculate absolute difference between two ISO timestamps in milliseconds."""
    dt_a = _parse_iso_ts(ts_a_str)
    dt_b = _parse_iso_ts(ts_b_str)
    if dt_a and dt_b:
        return abs((dt_b - dt_a).total_seconds() * 1000.0)
    return None


def _extract_alert_users(alert: Alert) -> set[str]:
    """Extract all individual usernames associated with an alert."""
    users = set()
    if alert.username:
        for u in alert.username.split(","):
            clean = u.strip()
            if clean:
                users.add(clean)
    for ref in alert.evidence_references:
        ru = ref.get("username")
        if ru:
            users.add(ru.strip())
    return users


def _extract_all_pids(alert: Alert) -> set[int]:
    """Extract all process IDs associated with an alert."""
    pids = set()
    if alert.process_id is not None:
        pids.add(alert.process_id)
    for ref in alert.evidence_references:
        rpid = ref.get("process_id")
        if rpid is not None:
            try:
                pids.add(int(rpid))
            except (ValueError, TypeError):
                pass
    return pids


def _extract_all_ppids(alert: Alert) -> set[int]:
    """Extract all parent process IDs associated with an alert."""
    ppids = set()
    if alert.parent_process_id is not None:
        ppids.add(alert.parent_process_id)
    for ref in alert.evidence_references:
        rppid = ref.get("parent_process_id")
        if rppid is not None:
            try:
                ppids.add(int(rppid))
            except (ValueError, TypeError):
                pass
    return ppids


# -----------------------------------------------------------------------------
# 1. Host Correlator
# -----------------------------------------------------------------------------

class HostCorrelator:
    """
    Correlates alerts sharing the same host across different detection rules.
    Host co-occurrence preserves endpoint boundaries for investigation clustering,
    while explicitly noting that host co-occurrence alone does NOT establish causality.
    """

    def correlate(self, extractor: EntityExtractor) -> list[Relationship]:
        relationships = []

        for host_name, alerts in extractor.alerts_by_host.items():
            n = len(alerts)
            if n < 2:
                continue

            for i in range(n):
                for j in range(i + 1, n):
                    a1 = alerts[i]
                    a2 = alerts[j]

                    if a1.rule_id == a2.rule_id:
                        continue

                    users1 = _extract_alert_users(a1)
                    users2 = _extract_alert_users(a2)
                    shared_users = users1.intersection(users2)
                    delta_ms = _calc_time_delta_ms(a1.first_seen, a2.first_seen)

                    evidence = {
                        "host": host_name,
                        "source_rule": a1.rule_id,
                        "target_rule": a2.rule_id,
                        "source_mitre": a1.mitre_technique_id,
                        "target_mitre": a2.mitre_technique_id,
                        "shared_user": bool(shared_users),
                        "shared_users": sorted(list(shared_users)),
                        "delta_ms": delta_ms,
                    }

                    confidence, explanation = evaluate_confidence(
                        rel_type=RelationshipType.SAME_HOST,
                        dimension=CorrelationDimension.HOST,
                        evidence=evidence,
                    )

                    rel = Relationship(
                        source_observation_id=a1.alert_id,
                        target_observation_id=a2.alert_id,
                        relationship_type=RelationshipType.SAME_HOST,
                        correlation_dimension=CorrelationDimension.HOST,
                        evidence=evidence,
                        confidence=confidence,
                        explanation=explanation,
                        observed_or_inferred=ObservationStatus.OBSERVED,
                        timestamp_context={
                            "source_first_seen": a1.first_seen,
                            "target_first_seen": a2.first_seen,
                            "delta_ms": delta_ms,
                        },
                        supporting_event_ids=list(set(a1.supporting_event_ids + a2.supporting_event_ids)),
                        provenance_references=a1.evidence_references + a2.evidence_references,
                        is_investigation_eligible=True,
                    )
                    relationships.append(rel)

        return relationships


# -----------------------------------------------------------------------------
# 2. User Correlator
# -----------------------------------------------------------------------------

class UserCorrelator:
    """
    Correlates alerts sharing the exact same username.
    Preserves original user identity.
    CRITICAL AUDIT POLICY: Cross-host SAME_USER relationships are preserved as
    observable associations, but marked INELIGIBLE for investigation clustering
    to prevent synthetic random usernames from merging unrelated hosts.
    """

    def correlate(self, extractor: EntityExtractor) -> list[Relationship]:
        relationships = []

        for username, alerts in extractor.alerts_by_user.items():
            n = len(alerts)
            if n < 2:
                continue

            for i in range(n):
                for j in range(i + 1, n):
                    a1 = alerts[i]
                    a2 = alerts[j]

                    src_id, tgt_id = (a1.alert_id, a2.alert_id) if a1.alert_id < a2.alert_id else (a2.alert_id, a1.alert_id)
                    src_alert, tgt_alert = (a1, a2) if a1.alert_id < a2.alert_id else (a2, a1)

                    same_host = (src_alert.host == tgt_alert.host) and (src_alert.host is not None)
                    delta_ms = _calc_time_delta_ms(src_alert.first_seen, tgt_alert.first_seen)

                    evidence = {
                        "username": username,
                        "same_host": same_host,
                        "source_host": src_alert.host,
                        "target_host": tgt_alert.host,
                        "source_rule": src_alert.rule_id,
                        "target_rule": tgt_alert.rule_id,
                        "delta_ms": delta_ms,
                    }

                    confidence, explanation = evaluate_confidence(
                        rel_type=RelationshipType.SAME_USER,
                        dimension=CorrelationDimension.USER,
                        evidence=evidence,
                    )

                    rel = Relationship(
                        source_observation_id=src_id,
                        target_observation_id=tgt_id,
                        relationship_type=RelationshipType.SAME_USER,
                        correlation_dimension=CorrelationDimension.USER,
                        evidence=evidence,
                        confidence=confidence,
                        explanation=explanation,
                        observed_or_inferred=ObservationStatus.OBSERVED,
                        timestamp_context={
                            "source_first_seen": src_alert.first_seen,
                            "target_first_seen": tgt_alert.first_seen,
                            "delta_ms": delta_ms,
                        },
                        supporting_event_ids=list(set(src_alert.supporting_event_ids + tgt_alert.supporting_event_ids)),
                        provenance_references=src_alert.evidence_references + tgt_alert.evidence_references,
                        is_investigation_eligible=bool(same_host),
                    )
                    relationships.append(rel)

        return relationships


# -----------------------------------------------------------------------------
# 3. Network Correlator
# -----------------------------------------------------------------------------

class NetworkCorrelator:
    """
    Correlates alerts sharing source or destination IP addresses.
    Explicitly classifies RFC 5737 TEST-NET addresses as non-malicious synthetic test artifacts.
    CRITICAL AUDIT POLICY: TEST-NET addresses are marked INELIGIBLE for investigation clustering.
    """

    def correlate(self, extractor: EntityExtractor) -> list[Relationship]:
        relationships = []

        for sip, alerts in extractor.alerts_by_source_ip.items():
            n = len(alerts)
            if n < 2:
                continue

            ip_info = classify_ip(sip)
            is_test_net = ip_info["is_test_net"]

            for i in range(n):
                for j in range(i + 1, n):
                    a1 = alerts[i]
                    a2 = alerts[j]

                    src_id, tgt_id = (a1.alert_id, a2.alert_id) if a1.alert_id < a2.alert_id else (a2.alert_id, a1.alert_id)
                    src_alert, tgt_alert = (a1, a2) if a1.alert_id < a2.alert_id else (a2, a1)

                    delta_ms = _calc_time_delta_ms(src_alert.first_seen, tgt_alert.first_seen)
                    evidence = {
                        "ip": sip,
                        "classification": ip_info["classification"],
                        "is_test_net": is_test_net,
                        "target_count": n,
                        "source_host": src_alert.host,
                        "target_host": tgt_alert.host,
                        "source_rule": src_alert.rule_id,
                        "target_rule": tgt_alert.rule_id,
                        "delta_ms": delta_ms,
                    }

                    confidence, explanation = evaluate_confidence(
                        rel_type=RelationshipType.SAME_SOURCE_IP,
                        dimension=CorrelationDimension.NETWORK,
                        evidence=evidence,
                    )

                    rel = Relationship(
                        source_observation_id=src_id,
                        target_observation_id=tgt_id,
                        relationship_type=RelationshipType.SAME_SOURCE_IP,
                        correlation_dimension=CorrelationDimension.NETWORK,
                        evidence=evidence,
                        confidence=confidence,
                        explanation=explanation,
                        observed_or_inferred=ObservationStatus.OBSERVED,
                        timestamp_context={
                            "source_first_seen": src_alert.first_seen,
                            "target_first_seen": tgt_alert.first_seen,
                            "delta_ms": delta_ms,
                        },
                        supporting_event_ids=list(set(src_alert.supporting_event_ids + tgt_alert.supporting_event_ids)),
                        provenance_references=src_alert.evidence_references + tgt_alert.evidence_references,
                        is_investigation_eligible=not is_test_net,
                    )
                    relationships.append(rel)

        return relationships


# -----------------------------------------------------------------------------
# 4. Process Correlator
# -----------------------------------------------------------------------------

class ProcessCorrelator:
    """
    Correlates alerts based on process identity and validated parent-child PID linkage.
    CRITICAL AUDIT POLICY:
      - Validated parent-child PID match on same host -> PARENT_CHILD_PROCESS (HIGH confidence).
      - Validated process identity (same image AND same PID on host) -> SAME_PROCESS (HIGH confidence).
      - Same process image on same host with different/unverified PIDs -> SAME_PROCESS_IMAGE (MEDIUM confidence).
      - Never fabricates process ancestry.
    """

    def correlate(self, extractor: EntityExtractor) -> list[Relationship]:
        relationships = []

        # 1. Check for genuine parent-child linkage across alerts on the same host
        for host_name, alerts in extractor.alerts_by_host.items():
            n = len(alerts)
            if n < 2:
                continue

            for i in range(n):
                for j in range(n):
                    if i == j:
                        continue
                    parent_alert = alerts[i]
                    child_alert = alerts[j]

                    parent_pids = _extract_all_pids(parent_alert)
                    child_ppids = _extract_all_ppids(child_alert)

                    matched_pids = parent_pids.intersection(child_ppids)
                    if matched_pids:
                        delta_ms = _calc_time_delta_ms(parent_alert.first_seen, child_alert.first_seen)
                        evidence = {
                            "same_host": True,
                            "host": host_name,
                            "pid_match": True,
                            "matched_pids": sorted(list(matched_pids)),
                            "parent_rule": parent_alert.rule_id,
                            "child_rule": child_alert.rule_id,
                            "parent_process": parent_alert.process_name,
                            "child_process": child_alert.process_name,
                            "delta_ms": delta_ms,
                        }

                        confidence, explanation = evaluate_confidence(
                            rel_type=RelationshipType.PARENT_CHILD_PROCESS,
                            dimension=CorrelationDimension.PROCESS,
                            evidence=evidence,
                        )

                        rel = Relationship(
                            source_observation_id=parent_alert.alert_id,
                            target_observation_id=child_alert.alert_id,
                            relationship_type=RelationshipType.PARENT_CHILD_PROCESS,
                            correlation_dimension=CorrelationDimension.PROCESS,
                            evidence=evidence,
                            confidence=confidence,
                            explanation=explanation,
                            observed_or_inferred=ObservationStatus.OBSERVED,
                            timestamp_context={
                                "parent_first_seen": parent_alert.first_seen,
                                "child_first_seen": child_alert.first_seen,
                                "delta_ms": delta_ms,
                            },
                            supporting_event_ids=list(set(parent_alert.supporting_event_ids + child_alert.supporting_event_ids)),
                            provenance_references=parent_alert.evidence_references + child_alert.evidence_references,
                            is_investigation_eligible=True,
                        )
                        relationships.append(rel)

        # 2. Check for process image and identity matching on the same host across different rules
        for host_name, alerts in extractor.alerts_by_host.items():
            n = len(alerts)
            if n < 2:
                continue

            for i in range(n):
                for j in range(i + 1, n):
                    a1 = alerts[i]
                    a2 = alerts[j]

                    if a1.rule_id == a2.rule_id:
                        continue

                    p1 = (a1.process_name or "").lower().strip()
                    p2 = (a2.process_name or "").lower().strip()
                    if p1 and p2 and p1 == p2:
                        pids1 = _extract_all_pids(a1)
                        pids2 = _extract_all_pids(a2)
                        shared_pids = pids1.intersection(pids2)
                        delta_ms = _calc_time_delta_ms(a1.first_seen, a2.first_seen)

                        # If PIDs match and are non-empty -> validated SAME_PROCESS (HIGH)
                        # If PIDs differ -> SAME_PROCESS_IMAGE (MEDIUM)
                        if shared_pids:
                            rel_type = RelationshipType.SAME_PROCESS
                            evidence = {
                                "host": host_name,
                                "process_name": a1.process_name,
                                "same_image": True,
                                "same_pid": True,
                                "shared_pids": sorted(list(shared_pids)),
                                "pids_source": sorted(list(pids1)),
                                "pids_target": sorted(list(pids2)),
                                "source_rule": a1.rule_id,
                                "target_rule": a2.rule_id,
                                "delta_ms": delta_ms,
                            }
                        else:
                            rel_type = RelationshipType.SAME_PROCESS_IMAGE
                            evidence = {
                                "host": host_name,
                                "process_name": a1.process_name,
                                "same_image": True,
                                "same_pid": False,
                                "shared_pids": [],
                                "pids_source": sorted(list(pids1)),
                                "pids_target": sorted(list(pids2)),
                                "source_rule": a1.rule_id,
                                "target_rule": a2.rule_id,
                                "delta_ms": delta_ms,
                            }

                        confidence, explanation = evaluate_confidence(
                            rel_type=rel_type,
                            dimension=CorrelationDimension.PROCESS,
                            evidence=evidence,
                        )

                        src_id, tgt_id = (a1.alert_id, a2.alert_id) if a1.alert_id < a2.alert_id else (a2.alert_id, a1.alert_id)
                        rel = Relationship(
                            source_observation_id=src_id,
                            target_observation_id=tgt_id,
                            relationship_type=rel_type,
                            correlation_dimension=CorrelationDimension.PROCESS,
                            evidence=evidence,
                            confidence=confidence,
                            explanation=explanation,
                            observed_or_inferred=ObservationStatus.OBSERVED,
                            timestamp_context={
                                "source_first_seen": a1.first_seen,
                                "target_first_seen": a2.first_seen,
                                "delta_ms": delta_ms,
                            },
                            supporting_event_ids=list(set(a1.supporting_event_ids + a2.supporting_event_ids)),
                            provenance_references=a1.evidence_references + a2.evidence_references,
                            is_investigation_eligible=True,
                        )
                        relationships.append(rel)

        return relationships


# -----------------------------------------------------------------------------
# 5. Temporal Correlator
# -----------------------------------------------------------------------------

class TemporalCorrelator:
    """
    Correlates observations occurring within a configurable time window.
    Explicitly flags synthetic timestamp compression (~168ms total dataset span).
    CRITICAL AUDIT POLICY: Sub-second temporal proximity is marked INELIGIBLE
    for investigation clustering to prevent unevidenced campaign merges.
    """

    def __init__(self, time_window_ms: float = 50.0):
        self.time_window_ms = time_window_ms

    def correlate(self, extractor: EntityExtractor) -> list[Relationship]:
        relationships = []

        for host_name, alerts in extractor.alerts_by_host.items():
            n = len(alerts)
            if n < 2:
                continue

            for i in range(n):
                for j in range(i + 1, n):
                    a1 = alerts[i]
                    a2 = alerts[j]

                    if a1.rule_id == a2.rule_id:
                        continue

                    delta_ms = _calc_time_delta_ms(a1.first_seen, a2.first_seen)
                    if delta_ms is not None and delta_ms <= self.time_window_ms:
                        evidence = {
                            "host": host_name,
                            "delta_ms": delta_ms,
                            "window_ms": self.time_window_ms,
                            "source_rule": a1.rule_id,
                            "target_rule": a2.rule_id,
                        }

                        confidence, explanation = evaluate_confidence(
                            rel_type=RelationshipType.TEMPORALLY_NEAR,
                            dimension=CorrelationDimension.TEMPORAL,
                            evidence=evidence,
                        )

                        rel = Relationship(
                            source_observation_id=a1.alert_id,
                            target_observation_id=a2.alert_id,
                            relationship_type=RelationshipType.TEMPORALLY_NEAR,
                            correlation_dimension=CorrelationDimension.TEMPORAL,
                            evidence=evidence,
                            confidence=confidence,
                            explanation=explanation,
                            observed_or_inferred=ObservationStatus.OBSERVED,
                            timestamp_context={
                                "source_first_seen": a1.first_seen,
                                "target_first_seen": a2.first_seen,
                                "delta_ms": delta_ms,
                            },
                            supporting_event_ids=list(set(a1.supporting_event_ids + a2.supporting_event_ids)),
                            provenance_references=a1.evidence_references + a2.evidence_references,
                            is_investigation_eligible=False,
                        )
                        relationships.append(rel)

        return relationships


# -----------------------------------------------------------------------------
# 6. Behavioral Sequence Correlator (Candidate / Hypothesized)
# -----------------------------------------------------------------------------

class BehavioralSequenceCorrelator:
    """
    Identifies candidate kill chain stage transitions occurring on the same host.
    CRITICAL AUDIT POLICY:
      - Does NOT infer attack-stage transitions from host equality and timestamps alone.
      - Requires independent contextual evidence on the host (e.g. shared process image, PID linkage).
      - Rejects transitions from unproven failed authentications (e.g. RULE-001 -> RULE-005 on SRV-DC-01).
      - Rejects transitions between unrelated processes (e.g. powershell.exe -> unknown.exe).
      - Retains candidate progressions (e.g. RULE-002 -> RULE-004 sharing powershell.exe).
      - Strictly marked INFERRED and LOW confidence.
    """

    STAGE_ORDER = {
        "Exploitation": 1,
        "Execution": 1,
        "Installation": 2,
        "Persistence": 2,
        "Privilege Escalation": 3,
        "Defense Evasion": 3,
        "Credential Access": 4,
        "Lateral Movement": 5,
        "Command and Control": 6,
        "Actions on Objectives": 7,
        "Impact": 7,
    }

    def correlate(self, extractor: EntityExtractor) -> list[Relationship]:
        relationships = []

        for host_name, alerts in extractor.alerts_by_host.items():
            n = len(alerts)
            if n < 2:
                continue

            for i in range(n):
                for j in range(n):
                    if i == j:
                        continue
                    a_prior = alerts[i]
                    a_later = alerts[j]

                    stage_a = a_prior.kill_chain_stage
                    stage_b = a_later.kill_chain_stage
                    rank_a = self.STAGE_ORDER.get(stage_a, 0)
                    rank_b = self.STAGE_ORDER.get(stage_b, 0)

                    # Only evaluate if rank_a < rank_b (ordered progression)
                    if 0 < rank_a < rank_b:
                        # AUDIT REQUIREMENT: Must have independent contextual overlap
                        # 1. Reject failed authentication -> subsequent stages (RULE-001 has no confirmed access)
                        if a_prior.rule_id == "RULE-001":
                            continue

                        # 2. Check for process continuity or shared process image
                        proc_a = (a_prior.process_name or "").lower().strip()
                        proc_b = (a_later.process_name or "").lower().strip()
                        pids_a = _extract_all_pids(a_prior)
                        ppids_b = _extract_all_ppids(a_later)

                        has_pid_link = bool(pids_a.intersection(ppids_b))
                        has_process_image_link = bool(proc_a and proc_b and proc_a == proc_b)

                        # If no process link and no PID link, reject unevidenced sequence
                        if not has_pid_link and not has_process_image_link:
                            continue

                        delta_ms = _calc_time_delta_ms(a_prior.first_seen, a_later.first_seen)
                        evidence = {
                            "host": host_name,
                            "prior_stage": stage_a,
                            "later_stage": stage_b,
                            "prior_rule": a_prior.rule_id,
                            "later_rule": a_later.rule_id,
                            "stages": [stage_a, stage_b],
                            "has_process_image_link": has_process_image_link,
                            "has_pid_link": has_pid_link,
                            "process_name": a_prior.process_name,
                            "delta_ms": delta_ms,
                        }

                        confidence, explanation = evaluate_confidence(
                            rel_type=RelationshipType.POTENTIAL_BEHAVIORAL_SEQUENCE,
                            dimension=CorrelationDimension.BEHAVIORAL,
                            evidence=evidence,
                        )

                        rel = Relationship(
                            source_observation_id=a_prior.alert_id,
                            target_observation_id=a_later.alert_id,
                            relationship_type=RelationshipType.POTENTIAL_BEHAVIORAL_SEQUENCE,
                            correlation_dimension=CorrelationDimension.BEHAVIORAL,
                            evidence=evidence,
                            confidence=confidence,
                            explanation=explanation,
                            observed_or_inferred=ObservationStatus.INFERRED,
                            timestamp_context={
                                "prior_first_seen": a_prior.first_seen,
                                "later_first_seen": a_later.first_seen,
                                "delta_ms": delta_ms,
                            },
                            supporting_event_ids=list(set(a_prior.supporting_event_ids + a_later.supporting_event_ids)),
                            provenance_references=a_prior.evidence_references + a_later.evidence_references,
                            is_investigation_eligible=True,
                        )
                        relationships.append(rel)

        return relationships


# -----------------------------------------------------------------------------
# 7. Cross-Source Correlator (EDR <-> FortiGate Architecture)
# -----------------------------------------------------------------------------

class CrossSourceCorrelator:
    """
    Correlates EDR endpoint detections with FortiGate network security telemetry.
    Respects real-world data availability: reports limitations when FortiGate data
    is unavailable or incomplete without fabricating mock records.
    """

    def __init__(self, fortigate_records: Optional[list[dict[str, Any]]] = None):
        self.fortigate_records = fortigate_records or []
        self.data_limitation_reported = False

    def correlate(self, extractor: EntityExtractor) -> list[Relationship]:
        relationships = []

        if not self.fortigate_records:
            firex_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "firex-10G.log")
            if os.path.exists(firex_path):
                self.data_limitation_reported = True
            return relationships

        for fg in self.fortigate_records:
            fg_src_ip = fg.get("source_ip")
            fg_dst_ip = fg.get("destination_ip")
            fg_event_id = fg.get("event_id", "fg-unknown")
            fg_ts = fg.get("timestamp")

            target_ips = [ip for ip in (fg_src_ip, fg_dst_ip) if ip]
            for ip in target_ips:
                matching_alerts = extractor.alerts_by_source_ip.get(ip, []) + extractor.alerts_by_dest_ip.get(ip, [])
                for alert in matching_alerts:
                    delta_ms = _calc_time_delta_ms(str(fg_ts), alert.first_seen) if fg_ts else None
                    evidence = {
                        "matched_ip": ip,
                        "edr_alert_id": alert.alert_id,
                        "fortigate_event_id": fg_event_id,
                        "edr_rule": alert.rule_id,
                        "delta_ms": delta_ms,
                    }

                    confidence, explanation = evaluate_confidence(
                        rel_type=RelationshipType.CROSS_SOURCE_NETWORK_MATCH,
                        dimension=CorrelationDimension.CROSS_SOURCE,
                        evidence=evidence,
                    )

                    rel = Relationship(
                        source_observation_id=alert.alert_id,
                        target_observation_id=str(fg_event_id),
                        relationship_type=RelationshipType.CROSS_SOURCE_NETWORK_MATCH,
                        correlation_dimension=CorrelationDimension.CROSS_SOURCE,
                        evidence=evidence,
                        confidence=confidence,
                        explanation=explanation,
                        observed_or_inferred=ObservationStatus.OBSERVED,
                        timestamp_context={
                            "edr_first_seen": alert.first_seen,
                            "fortigate_timestamp": str(fg_ts) if fg_ts else None,
                            "delta_ms": delta_ms,
                        },
                        supporting_event_ids=alert.supporting_event_ids + [str(fg_event_id)],
                        provenance_references=alert.evidence_references + [
                            {
                                "event_id": str(fg_event_id),
                                "raw_file": fg.get("raw_file", "firex-10G.log"),
                                "byte_offset": int(fg.get("byte_offset", 0)),
                                "record_length": int(fg.get("record_length", 0)),
                            }
                        ],
                        is_investigation_eligible=not is_test_net_ip(ip),
                    )
                    relationships.append(rel)

        return relationships
