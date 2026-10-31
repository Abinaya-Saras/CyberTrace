"""
Detection rule loader and validator for CyberTrace.

Loads YAML detection rules, validates their schema and MITRE mappings,
and enforces security boundaries:
  - Rejects arbitrary untrusted SQL from rules.
  - Dispatches exclusively to vetted, approved detection handlers.
  - Validates required fields against the normalized schema.
"""

from dataclasses import dataclass, field
import os
import re
from typing import Any, Optional
import yaml

from backend.core.schema import SCHEMA_COLUMNS
from backend.detection.alert_schema import ALLOWED_SEVERITIES
from backend.mitre.mappings import validate_mitre_mapping


# Approved detection handlers in engine registry
ALLOWED_HANDLERS = {
    "brute_force_handler",
    "suspicious_process_handler",
    "c2_beaconing_handler",
    "registry_persistence_handler",
    "mass_file_modification_handler",
}

# Required top-level fields in each rule YAML
REQUIRED_RULE_FIELDS = [
    "rule_id",
    "rule_name",
    "description",
    "enabled",
    "required_fields",
    "detection_logic",
    "threshold",
    "time_window",
    "mitre_technique_id",
    "mitre_technique_name",
    "mitre_tactic",
    "kill_chain_stage",
    "severity",
    "evidence_requirements",
]


class RuleValidationError(Exception):
    """Raised when a rule configuration is invalid."""
    pass


class RuleLoadError(Exception):
    """Raised when a rule file cannot be loaded or parsed."""
    pass


@dataclass
class RuleDefinition:
    """Validated in-memory detection rule configuration."""
    rule_id: str
    rule_name: str
    description: str
    enabled: bool
    required_fields: list[str]
    detection_logic: str
    threshold: dict[str, Any]
    time_window: str | int
    time_window_seconds: int
    mitre_technique_id: str
    mitre_technique_name: str
    mitre_tactic: str
    kill_chain_stage: str
    severity: str
    evidence_requirements: list[str]
    parameters: dict[str, Any] = field(default_factory=dict)
    source_file: Optional[str] = None


def parse_time_window_to_seconds(time_window: str | int) -> int:
    """Parse time window (e.g., 300, '300s', '5m', '1h') to integer seconds."""
    if isinstance(time_window, (int, float)):
        return int(time_window)
    if isinstance(time_window, str):
        tw = time_window.strip().lower()
        if tw.isdigit():
            return int(tw)
        match = re.match(r"^(\d+)\s*([smhdw])$", tw)
        if match:
            val, unit = int(match.group(1)), match.group(2)
            multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
            return val * multipliers[unit]
    raise RuleValidationError(f"Invalid time_window format: '{time_window}'")


def validate_rule_dict(data: dict[str, Any], source_file: Optional[str] = None) -> RuleDefinition:
    """Validate raw dictionary from YAML against rule specifications."""
    if not isinstance(data, dict):
        raise RuleValidationError(f"Rule content must be a YAML mapping (dict), got {type(data)}")

    # Check for missing required fields
    missing = [f for f in REQUIRED_RULE_FIELDS if f not in data]
    if missing:
        raise RuleValidationError(f"Rule missing required fields: {missing} (file: {source_file})")

    # Validate rule_id
    rule_id = str(data["rule_id"]).strip()
    if not rule_id:
        raise RuleValidationError("Rule 'rule_id' cannot be empty")

    # Validate rule_name
    rule_name = str(data["rule_name"]).strip()
    if not rule_name:
        raise RuleValidationError(f"Rule '{rule_id}' has an empty 'rule_name'")

    # Validate enabled
    enabled = bool(data["enabled"])

    # Validate severity
    severity = str(data["severity"]).strip().lower()
    if severity not in ALLOWED_SEVERITIES:
        raise RuleValidationError(
            f"Rule '{rule_id}' has invalid severity '{severity}'. Allowed: {sorted(ALLOWED_SEVERITIES)}"
        )

    # Validate detection logic / handler against approved registry
    handler = str(data["detection_logic"]).strip()
    if handler not in ALLOWED_HANDLERS:
        raise RuleValidationError(
            f"Rule '{rule_id}' specifies unapproved detection_logic '{handler}'. "
            f"Allowed vetted handlers: {sorted(ALLOWED_HANDLERS)}"
        )

    # Validate required fields against NORMALIZED_SCHEMA
    req_fields = data["required_fields"]
    if not isinstance(req_fields, list) or not req_fields:
        raise RuleValidationError(f"Rule '{rule_id}' 'required_fields' must be a non-empty list")
    for f in req_fields:
        if f not in SCHEMA_COLUMNS:
            raise RuleValidationError(
                f"Rule '{rule_id}' requires unknown schema field '{f}' not in normalized schema"
            )

    # Validate threshold
    threshold = data["threshold"]
    if isinstance(threshold, (int, float)):
        threshold = {"value": threshold}
    elif not isinstance(threshold, dict):
        raise RuleValidationError(f"Rule '{rule_id}' threshold must be a dict or number")

    # Validate time_window
    time_window = data["time_window"]
    time_window_seconds = parse_time_window_to_seconds(time_window)

    # Validate MITRE and Kill Chain mapping
    tid = str(data["mitre_technique_id"]).strip()
    tname = str(data["mitre_technique_name"]).strip()
    tactic = str(data["mitre_tactic"]).strip()
    kc = str(data["kill_chain_stage"]).strip()

    is_valid, err_msg = validate_mitre_mapping(tid, tname, tactic, kc)
    if not is_valid:
        raise RuleValidationError(f"Rule '{rule_id}' MITRE/Kill-Chain validation failed: {err_msg}")

    # Validate evidence requirements
    ev_reqs = data["evidence_requirements"]
    if not isinstance(ev_reqs, list) or not ev_reqs:
        raise RuleValidationError(f"Rule '{rule_id}' 'evidence_requirements' must be a non-empty list")

    parameters = data.get("parameters", {})
    if not isinstance(parameters, dict):
        raise RuleValidationError(f"Rule '{rule_id}' 'parameters' must be a dict")

    return RuleDefinition(
        rule_id=rule_id,
        rule_name=rule_name,
        description=str(data["description"]).strip(),
        enabled=enabled,
        required_fields=req_fields,
        detection_logic=handler,
        threshold=threshold,
        time_window=time_window,
        time_window_seconds=time_window_seconds,
        mitre_technique_id=tid,
        mitre_technique_name=tname,
        mitre_tactic=tactic,
        kill_chain_stage=kc,
        severity=severity,
        evidence_requirements=ev_reqs,
        parameters=parameters,
        source_file=source_file,
    )


def load_rule_from_yaml(path: str) -> RuleDefinition:
    """Load and validate a single detection rule from a YAML file."""
    if not os.path.isfile(path):
        raise RuleLoadError(f"Rule file not found: {path}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise RuleLoadError(f"YAML parsing error in {path}: {e}") from e
    except Exception as e:
        raise RuleLoadError(f"Error reading {path}: {e}") from e

    return validate_rule_dict(data, source_file=path)


def load_rules_from_directory(dir_path: str) -> list[RuleDefinition]:
    """
    Load and validate all .yaml / .yml detection rules from a directory.
    Sorts rules deterministically by rule_id.
    """
    if not os.path.isdir(dir_path):
        raise RuleLoadError(f"Rules directory not found: {dir_path}")

    rules = []
    for fname in sorted(os.listdir(dir_path)):
        if fname.endswith((".yaml", ".yml")):
            fpath = os.path.join(dir_path, fname)
            rule = load_rule_from_yaml(fpath)
            rules.append(rule)

    return rules
