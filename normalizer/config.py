import logging
from pathlib import Path

import yaml

log = logging.getLogger(__name__)

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def load(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    with p.open() as f:
        cfg = yaml.safe_load(f) or {}
    log.debug("Config loaded from %s", path)
    return cfg


def get_integration(config: dict, name: str) -> dict:
    return config.get("integrations", {}).get(name, {})


def is_enabled(config: dict, integration: str) -> bool:
    return get_integration(config, integration).get("enabled", False)


def source_meta(config: dict) -> dict:
    """Return source metadata fields injected into every normalised event."""
    org = config.get("organization", {})
    return {
        "environment": org.get("environment"),
        "cloud_provider": None,
        "region": None,
        "account_id": None,
    }


def drop_below(config: dict) -> str:
    return config.get("normalizer", {}).get("drop_below_severity", "info")


def severity_passes(severity: str, min_severity: str) -> bool:
    """Return True if severity is at or above min_severity."""
    try:
        return SEVERITY_ORDER.index(severity) <= SEVERITY_ORDER.index(min_severity)
    except ValueError:
        return True


def evidence_dir(config: dict) -> str:
    return config.get("evidence", {}).get("output_dir", "evidence/")
