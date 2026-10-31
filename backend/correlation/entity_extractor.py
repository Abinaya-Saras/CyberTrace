"""
Entity Extraction and Indexing for CyberTrace Correlation Engine.

Extracts normalized, typed entities (Hosts, Users, IP Addresses, Processes, Alerts)
from detection alerts and evidence references to establish the foundation
for multi-dimensional cross-entity correlation.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional

from backend.correlation.confidence import classify_ip
from backend.detection.alert_schema import Alert


@dataclass
class HostEntity:
    host_name: str
    alert_ids: list[str] = field(default_factory=list)
    rules_present: set[str] = field(default_factory=set)
    associated_users: set[str] = field(default_factory=set)
    associated_ips: set[str] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host_name": self.host_name,
            "alert_count": len(self.alert_ids),
            "alert_ids": self.alert_ids,
            "rules_present": sorted(list(self.rules_present)),
            "associated_users": sorted(list(self.associated_users)),
            "associated_ips": sorted(list(self.associated_ips)),
        }


@dataclass
class UserEntity:
    username: str
    alert_ids: list[str] = field(default_factory=list)
    associated_hosts: set[str] = field(default_factory=set)
    rules_present: set[str] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "alert_count": len(self.alert_ids),
            "alert_ids": self.alert_ids,
            "associated_hosts": sorted(list(self.associated_hosts)),
            "rules_present": sorted(list(self.rules_present)),
        }


@dataclass
class IPEntity:
    ip_address: str
    classification: str
    is_test_net: bool
    role: str  # source, destination, or both
    alert_ids: list[str] = field(default_factory=list)
    targeted_hosts: set[str] = field(default_factory=set)
    targeted_users: set[str] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip_address": self.ip_address,
            "classification": self.classification,
            "is_test_net": self.is_test_net,
            "role": self.role,
            "alert_count": len(self.alert_ids),
            "alert_ids": self.alert_ids,
            "targeted_hosts": sorted(list(self.targeted_hosts)),
            "targeted_users": sorted(list(self.targeted_users)),
        }


@dataclass
class ProcessEntity:
    host_name: str
    process_name: str
    process_id: Optional[int]
    parent_process_name: Optional[str] = None
    parent_process_id: Optional[int] = None
    command_lines: set[str] = field(default_factory=set)
    alert_ids: list[str] = field(default_factory=list)

    @property
    def entity_id(self) -> str:
        pid_str = str(self.process_id) if self.process_id is not None else "unknown"
        return f"{self.host_name}:{self.process_name}:{pid_str}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "host_name": self.host_name,
            "process_name": self.process_name,
            "process_id": self.process_id,
            "parent_process_name": self.parent_process_name,
            "parent_process_id": self.parent_process_id,
            "command_lines": sorted(list(self.command_lines)),
            "alert_ids": self.alert_ids,
        }


class EntityExtractor:
    """
    Extracts entities from alerts and constructs lookup indices for correlation.
    """

    def __init__(self, alerts: list[Alert]):
        self.alerts = alerts

        # Extracted entities
        self.hosts: dict[str, HostEntity] = {}
        self.users: dict[str, UserEntity] = {}
        self.ips: dict[str, IPEntity] = {}
        self.processes: dict[str, ProcessEntity] = {}

        # Inverted index mappings: entity_key -> list of Alert objects
        self.alerts_by_host: dict[str, list[Alert]] = defaultdict(list)
        self.alerts_by_user: dict[str, list[Alert]] = defaultdict(list)
        self.alerts_by_source_ip: dict[str, list[Alert]] = defaultdict(list)
        self.alerts_by_dest_ip: dict[str, list[Alert]] = defaultdict(list)
        self.alerts_by_process_name: dict[str, list[Alert]] = defaultdict(list)
        self.alerts_by_host_pid: dict[tuple[str, int], list[Alert]] = defaultdict(list)

        self._extract()

    def _extract(self) -> None:
        """Run extraction across all alerts."""
        for alert in self.alerts:
            aid = alert.alert_id

            # 1. Host Extraction
            if alert.host:
                host_name = alert.host.strip()
                self.alerts_by_host[host_name].append(alert)
                if host_name not in self.hosts:
                    self.hosts[host_name] = HostEntity(host_name=host_name)
                host_ent = self.hosts[host_name]
                host_ent.alert_ids.append(aid)
                host_ent.rules_present.add(alert.rule_id)
                if alert.source_ip:
                    host_ent.associated_ips.add(alert.source_ip)
                if alert.destination_ip:
                    host_ent.associated_ips.add(alert.destination_ip)

            # 2. User Extraction (Top-level + Evidence-level)
            alert_users = set()
            if alert.username:
                for u in alert.username.split(","):
                    clean_u = u.strip()
                    if clean_u:
                        alert_users.add(clean_u)
            for ref in alert.evidence_references:
                ref_u = ref.get("username")
                if ref_u:
                    alert_users.add(ref_u.strip())

            for username in alert_users:
                self.alerts_by_user[username].append(alert)
                if username not in self.users:
                    self.users[username] = UserEntity(username=username)
                user_ent = self.users[username]
                user_ent.alert_ids.append(aid)
                user_ent.rules_present.add(alert.rule_id)
                if alert.host:
                    user_ent.associated_hosts.add(alert.host.strip())
                    if alert.host.strip() in self.hosts:
                        self.hosts[alert.host.strip()].associated_users.add(username)

            # 3. IP Extraction
            if alert.source_ip:
                sip = alert.source_ip.strip()
                self.alerts_by_source_ip[sip].append(alert)
                if sip not in self.ips:
                    ip_info = classify_ip(sip)
                    self.ips[sip] = IPEntity(
                        ip_address=sip,
                        classification=ip_info["classification"],
                        is_test_net=ip_info["is_test_net"],
                        role="source",
                    )
                ip_ent = self.ips[sip]
                ip_ent.alert_ids.append(aid)
                if alert.host:
                    ip_ent.targeted_hosts.add(alert.host.strip())
                for u in alert_users:
                    ip_ent.targeted_users.add(u)

            if alert.destination_ip:
                dip = alert.destination_ip.strip()
                self.alerts_by_dest_ip[dip].append(alert)
                if dip not in self.ips:
                    ip_info = classify_ip(dip)
                    self.ips[dip] = IPEntity(
                        ip_address=dip,
                        classification=ip_info["classification"],
                        is_test_net=ip_info["is_test_net"],
                        role="destination",
                    )
                else:
                    if self.ips[dip].role == "source":
                        self.ips[dip].role = "both"
                ip_ent = self.ips[dip]
                ip_ent.alert_ids.append(aid)
                if alert.host:
                    ip_ent.targeted_hosts.add(alert.host.strip())

            # 4. Process Extraction
            if alert.process_name and alert.host:
                pname = alert.process_name.lower().strip()
                self.alerts_by_process_name[pname].append(alert)
                if alert.process_id is not None:
                    self.alerts_by_host_pid[(alert.host.strip(), alert.process_id)].append(alert)

                proc_key = f"{alert.host.strip()}:{pname}:{alert.process_id if alert.process_id is not None else 'unknown'}"
                if proc_key not in self.processes:
                    self.processes[proc_key] = ProcessEntity(
                        host_name=alert.host.strip(),
                        process_name=alert.process_name,
                        process_id=alert.process_id,
                        parent_process_name=alert.parent_process_name,
                        parent_process_id=alert.parent_process_id,
                    )
                self.processes[proc_key].alert_ids.append(aid)

            # Also check evidence references for additional process instances
            for ref in alert.evidence_references:
                ref_pname = ref.get("process_name")
                ref_pid = ref.get("process_id")
                ref_cmd = ref.get("process_command_line")
                if ref_pname and alert.host:
                    proc_key = f"{alert.host.strip()}:{ref_pname.lower().strip()}:{ref_pid if ref_pid is not None else 'unknown'}"
                    if proc_key in self.processes:
                        if ref_cmd:
                            self.processes[proc_key].command_lines.add(ref_cmd)
                    else:
                        pe = ProcessEntity(
                            host_name=alert.host.strip(),
                            process_name=ref_pname,
                            process_id=ref_pid,
                            parent_process_name=ref.get("parent_process_name"),
                            parent_process_id=ref.get("parent_process_id"),
                        )
                        if ref_cmd:
                            pe.command_lines.add(ref_cmd)
                        pe.alert_ids.append(aid)
                        self.processes[proc_key] = pe

    def summary(self) -> dict[str, int]:
        """Return counts of unique entities."""
        return {
            "total_alerts": len(self.alerts),
            "unique_hosts": len(self.hosts),
            "unique_users": len(self.users),
            "unique_ips": len(self.ips),
            "unique_processes": len(self.processes),
        }
