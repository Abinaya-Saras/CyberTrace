"""
MITRE ATT&CK and Cyber Kill Chain authoritative mappings for CyberTrace.

Maintains strict separation between:
  - MITRE ATT&CK Tactics (attacker goals from matrix)
  - Cyber Kill Chain Stages (chronological phases of an intrusion)

Guiding Principle:
  Every mapping must be technically justified. Tactics and Kill Chain stages
  are related concepts but operate at different conceptual levels.
"""

from dataclasses import dataclass
from typing import Optional


# Lockheed Martin Cyber Kill Chain (7 sequential stages)
CYBER_KILL_CHAIN_STAGES = [
    "Reconnaissance",
    "Weaponization",
    "Delivery",
    "Exploitation",
    "Installation",
    "Command and Control",
    "Actions on Objectives",
]

# MITRE Enterprise ATT&CK Tactics
MITRE_TACTICS = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


@dataclass(frozen=True)
class TechniqueMapping:
    technique_id: str
    technique_name: str
    mitre_tactic: str
    kill_chain_stage: str
    description: str
    rationale: str


# Authoritative mapping catalog for CyberTrace initial techniques
TECHNIQUE_CATALOG: dict[str, TechniqueMapping] = {
    "T1110": TechniqueMapping(
        technique_id="T1110",
        technique_name="Brute Force",
        mitre_tactic="Credential Access",
        kill_chain_stage="Exploitation",
        description="Adversaries may use brute force techniques to attempt authentication.",
        rationale=(
            "In MITRE ATT&CK, brute force is categorized under Credential Access as the goal "
            "is obtaining credentials. In the Cyber Kill Chain, external or internal automated "
            "credential guessing serves as the Exploitation stage to penetrate systems or escalate privileges."
        ),
    ),
    "T1059.001": TechniqueMapping(
        technique_id="T1059.001",
        technique_name="Command and Scripting Interpreter: PowerShell",
        mitre_tactic="Execution",
        kill_chain_stage="Exploitation",
        description="Adversaries may abuse PowerShell commands and scripts for execution.",
        rationale=(
            "In MITRE ATT&CK, PowerShell execution is categorized under the Execution tactic. "
            "When spawned by Office applications, it represents initial post-delivery payload "
            "execution, bridging the Delivery and Exploitation phases of the Cyber Kill Chain."
        ),
    ),
    "T1071.001": TechniqueMapping(
        technique_id="T1071.001",
        technique_name="Application Layer Protocol: Web Protocols",
        mitre_tactic="Command and Control",
        kill_chain_stage="Command and Control",
        description="Adversaries may communicate using application layer protocols (HTTP/HTTPS) to bypass defenses.",
        rationale=(
            "Both MITRE ATT&CK and the Cyber Kill Chain recognize outbound application layer "
            "communication to adversary-controlled servers as the Command and Control stage."
        ),
    ),
    "T1547.001": TechniqueMapping(
        technique_id="T1547.001",
        technique_name="Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        mitre_tactic="Persistence",
        kill_chain_stage="Installation",
        description="Adversaries may achieve persistence by adding programs to autorun registry keys.",
        rationale=(
            "In MITRE ATT&CK, Run key modification falls under Persistence. In the Cyber Kill Chain, "
            "establishing persistent presence so malware survives system reboots corresponds to "
            "the Installation phase."
        ),
    ),
    "T1486": TechniqueMapping(
        technique_id="T1486",
        technique_name="Data Encrypted for Impact",
        mitre_tactic="Impact",
        kill_chain_stage="Actions on Objectives",
        description="Adversaries may encrypt data on target systems to interrupt availability.",
        rationale=(
            "In MITRE ATT&CK, ransomware encryption is categorized under Impact. In the Cyber "
            "Kill Chain, this represents the final phase—Actions on Objectives—where the attacker "
            "executes their destructive end goal."
        ),
    ),
}


def validate_mitre_mapping(
    technique_id: str,
    technique_name: Optional[str] = None,
    mitre_tactic: Optional[str] = None,
    kill_chain_stage: Optional[str] = None,
) -> tuple[bool, Optional[str]]:
    """
    Validate that a given technique ID exists in our catalog and that the specified
    technique name, tactic, and kill chain stage match authoritative standards.

    Returns:
        (is_valid, error_message)
    """
    mapping = TECHNIQUE_CATALOG.get(technique_id)
    if not mapping:
        return False, f"Unknown MITRE technique ID: {technique_id}"

    if technique_name and technique_name.lower() != mapping.technique_name.lower():
        return False, (
            f"Technique name mismatch for {technique_id}: "
            f"expected '{mapping.technique_name}', got '{technique_name}'"
        )

    if mitre_tactic and mitre_tactic.lower() != mapping.mitre_tactic.lower():
        return False, (
            f"MITRE tactic mismatch for {technique_id}: "
            f"expected '{mapping.mitre_tactic}', got '{mitre_tactic}'"
        )

    if kill_chain_stage and kill_chain_stage.lower() != mapping.kill_chain_stage.lower():
        return False, (
            f"Kill Chain stage mismatch for {technique_id}: "
            f"expected '{mapping.kill_chain_stage}', got '{kill_chain_stage}'"
        )

    return True, None


def get_mapping(technique_id: str) -> Optional[TechniqueMapping]:
    """Retrieve the authoritative mapping for a technique ID."""
    return TECHNIQUE_CATALOG.get(technique_id)
