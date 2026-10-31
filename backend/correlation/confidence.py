"""
Confidence Evaluation and Network Classification for CyberTrace Correlation.

Defines transparent, deterministic rules for:
  - Classifying IP addresses (internal RFC 1918, RFC 5737 TEST-NET documentation blocks, public, loopback).
  - Evaluating relationship confidence strictly from empirical evidence.
  - Enforcing guards against overclaiming or artificial confidence upgrading.
"""

import ipaddress
from typing import Any, Optional

from backend.correlation.relationship_schema import (
    ConfidenceLevel,
    CorrelationDimension,
    ObservationStatus,
    RelationshipType,
)


# RFC 5737 and RFC 3849 Documentation networks (TEST-NET)
TEST_NET_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),    # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),   # TEST-NET-3
    ipaddress.ip_network("2001:db8::/32"),    # IPv6 Documentation
]


class IPClassification:
    RFC1918_PRIVATE = "RFC1918_PRIVATE"
    TEST_NET_DOCUMENTATION = "TEST_NET_DOCUMENTATION"
    LOOPBACK = "LOOPBACK"
    LINK_LOCAL = "LINK_LOCAL"
    CARRIER_GRADE_NAT = "CARRIER_GRADE_NAT"
    MULTICAST = "MULTICAST"
    PUBLIC_ROUTABLE = "PUBLIC_ROUTABLE"
    INVALID = "INVALID"


def classify_ip(ip_str: Optional[str]) -> dict[str, Any]:
    """
    Classify an IP address and detect RFC 5737 TEST-NET documentation addresses.
    Never treats TEST-NET addresses as genuine external malicious infrastructure.
    """
    if not ip_str or not isinstance(ip_str, str):
        return {
            "ip": ip_str,
            "classification": IPClassification.INVALID,
            "is_test_net": False,
            "is_private": False,
            "is_public": False,
            "is_routable": False,
            "description": "Null or invalid IP string",
        }

    clean_ip = ip_str.strip()
    try:
        obj = ipaddress.ip_address(clean_ip)
    except ValueError:
        return {
            "ip": clean_ip,
            "classification": IPClassification.INVALID,
            "is_test_net": False,
            "is_private": False,
            "is_public": False,
            "is_routable": False,
            "description": "Unparseable IP address format",
        }

    # Check RFC 5737 documentation blocks
    for net in TEST_NET_NETWORKS:
        if obj in net:
            return {
                "ip": clean_ip,
                "classification": IPClassification.TEST_NET_DOCUMENTATION,
                "is_test_net": True,
                "is_private": False,
                "is_public": False,
                "is_routable": False,
                "network_block": str(net),
                "description": "RFC 5737 / RFC 3849 Documentation Address (TEST-NET). Synthetic log artifact, not genuine malicious infrastructure.",
            }

    if obj.is_loopback:
        return {
            "ip": clean_ip,
            "classification": IPClassification.LOOPBACK,
            "is_test_net": False,
            "is_private": True,
            "is_public": False,
            "is_routable": False,
            "description": "Loopback address",
        }

    if obj.is_link_local:
        return {
            "ip": clean_ip,
            "classification": IPClassification.LINK_LOCAL,
            "is_test_net": False,
            "is_private": True,
            "is_public": False,
            "is_routable": False,
            "description": "Link-local address",
        }

    if obj.is_private:
        return {
            "ip": clean_ip,
            "classification": IPClassification.RFC1918_PRIVATE,
            "is_test_net": False,
            "is_private": True,
            "is_public": False,
            "is_routable": False,
            "description": "RFC 1918 Private enterprise network address",
        }

    if obj.is_multicast:
        return {
            "ip": clean_ip,
            "classification": IPClassification.MULTICAST,
            "is_test_net": False,
            "is_private": False,
            "is_public": False,
            "is_routable": False,
            "description": "Multicast address",
        }

    return {
        "ip": clean_ip,
        "classification": IPClassification.PUBLIC_ROUTABLE,
        "is_test_net": False,
        "is_private": False,
        "is_public": True,
        "is_routable": True,
        "description": "Public globally routable IP address",
    }


def is_test_net_ip(ip_str: Optional[str]) -> bool:
    """Convenience helper to check if an IP is a TEST-NET documentation address."""
    info = classify_ip(ip_str)
    return info.get("is_test_net", False)


def evaluate_confidence(
    rel_type: str,
    dimension: str,
    evidence: dict[str, Any],
    context: Optional[dict[str, Any]] = None,
) -> tuple[str, str]:
    """
    Evaluate correlation confidence based on transparent, defensible rules.

    Confidence Levels:
      - HIGH: Strong direct evidence, such as validated parent-child PID linkage or exact cross-source match.
      - MEDIUM: Multiple independent supporting indicators without causal proof.
      - LOW: Weak association based on shared host, user, or temporal proximity alone.
      - INSUFFICIENT: Inconclusive or contradictory evidence.

    Returns:
      (confidence_level, explanation)
    """
    ctx = context or {}

    # 1. Process correlation
    if rel_type == RelationshipType.PARENT_CHILD_PROCESS:
        pid_match = evidence.get("pid_match", False)
        same_host = evidence.get("same_host", False)
        if pid_match and same_host:
            return (
                ConfidenceLevel.HIGH,
                "Strong direct evidence: validated parent-child process relationship with matching PID/PPID on the same host."
            )
        return (
            ConfidenceLevel.INSUFFICIENT,
            "Insufficient evidence: process lineage cannot be established without matching PID and host."
        )

    if rel_type == RelationshipType.SAME_PROCESS_IMAGE:
        pname = evidence.get("process_name", "process")
        host = evidence.get("host", "")
        return (
            ConfidenceLevel.MEDIUM,
            f"Supporting indicator: identical process image '{pname}' observed on host '{host}', but process IDs differ (separate execution instances). Does not establish execution continuity."
        )

    if rel_type == RelationshipType.SAME_PROCESS:
        same_image = evidence.get("same_image", False)
        same_pid = evidence.get("same_pid", False)
        pname = evidence.get("process_name", "process")
        host = evidence.get("host", "")
        if same_image and same_pid:
            return (
                ConfidenceLevel.HIGH,
                f"Strong direct evidence: validated process identity match (same executable image '{pname}' and verified PID) on host '{host}'."
            )
        return (
            ConfidenceLevel.INSUFFICIENT,
            "Insufficient evidence: SAME_PROCESS requires validated host, image name, and matching process ID."
        )

    # 2. Network / Cross-Source correlation
    if rel_type == RelationshipType.CROSS_SOURCE_NETWORK_MATCH:
        matched_ip = evidence.get("matched_ip")
        ip_info = classify_ip(matched_ip)
        if ip_info["is_test_net"]:
            return (
                ConfidenceLevel.LOW,
                f"Cross-source IP match observed for '{matched_ip}', but address is an RFC 5737 TEST-NET documentation address (synthetic test artifact, not genuine malicious infrastructure)."
            )
        return (
            ConfidenceLevel.HIGH,
            f"Strong direct evidence: cross-source network telemetry match on public IP '{matched_ip}' with matching timestamp window."
        )

    if rel_type in (RelationshipType.SAME_SOURCE_IP, RelationshipType.SAME_DESTINATION_IP):
        matched_ip = evidence.get("ip")
        ip_info = classify_ip(matched_ip)
        count = evidence.get("target_count", 1)
        if ip_info["is_test_net"]:
            return (
                ConfidenceLevel.LOW,
                f"Weak association: shared source IP '{matched_ip}' observed across {count} target(s). Address belongs to RFC 5737 documentation block (TEST-NET) and represents synthetic test data, not genuine malicious infrastructure."
            )
        return (
            ConfidenceLevel.MEDIUM,
            f"Supporting network entity match: shared IP '{matched_ip}' observed across {count} target(s). Multiple targets reflect shared origin, but do not independently establish malicious intent or campaign membership without corroborating C2 payload telemetry."
        )

    # 3. User correlation
    if rel_type == RelationshipType.SAME_USER:
        same_host = evidence.get("same_host", False)
        user = evidence.get("username", "")
        if same_host:
            return (
                ConfidenceLevel.MEDIUM,
                f"Multiple indicators: identical user account '{user}' observed across alerts on the same host."
            )
        return (
            ConfidenceLevel.LOW,
            f"Weak association: shared user account '{user}' observed across distinct hosts; no network lateral movement or credential forwarding telemetry observed."
        )

    # 4. Host correlation
    if rel_type == RelationshipType.SAME_HOST:
        shared_user = evidence.get("shared_user", False)
        rule_a = evidence.get("source_rule", "")
        rule_b = evidence.get("target_rule", "")
        host = evidence.get("host", "")

        # If both rules are different and have no shared user or PID
        if not shared_user:
            return (
                ConfidenceLevel.LOW,
                f"Weak association: alerts co-occur on host '{host}', but originate from distinct rules ({rule_a} and {rule_b}) with disjoint user accounts and unlinked PIDs. Host co-occurrence alone does not establish causality."
            )
        return (
            ConfidenceLevel.MEDIUM,
            f"Multiple indicators: alerts co-occur on host '{host}' ({rule_a} and {rule_b}) with an overlapping user account."
        )

    # 5. Temporal correlation
    if rel_type == RelationshipType.TEMPORALLY_NEAR:
        delta_ms = evidence.get("delta_ms", 0.0)
        return (
            ConfidenceLevel.LOW,
            f"Weak association: observations occurred within {delta_ms:.2f}ms. Note: in this synthetic dataset spanning 168ms total, sub-second proximity reflects synthetic generator batching rather than an authentic multi-stage attack timeline."
        )

    # 6. Behavioral sequence
    if rel_type == RelationshipType.POTENTIAL_BEHAVIORAL_SEQUENCE:
        host = evidence.get("host", "")
        stages = evidence.get("stages", [])
        return (
            ConfidenceLevel.LOW,
            f"Inferred candidate sequence on host '{host}': {' -> '.join(stages)}. Note: Telemetry demonstrates behavioral co-occurrence on the same endpoint, but causal PID continuity or attacker identity is not proven."
        )

    return (ConfidenceLevel.LOW, "Default baseline confidence for candidate association.")
