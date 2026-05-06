"""
Live ingestor CLI — pulls events from cloud providers and identity systems,
normalises them, routes to integrations, and writes evidence artifacts.

Usage:
    python3 scripts/ingest.py --source cloudtrail --since 24h
    python3 scripts/ingest.py --source okta --since 1h
    python3 scripts/ingest.py --source gcp-audit --since 12h
    python3 scripts/ingest.py --source azure-monitor --since 6h
    python3 scripts/ingest.py --source azure-ad --since 4h
    python3 scripts/ingest.py --source aws-iam --since 24h

    # Dry run (normalise and log, do not route or write evidence):
    python3 scripts/ingest.py --source cloudtrail --since 24h --dry-run

    # Custom config:
    python3 scripts/ingest.py --source okta --since 6h --config config/config.yaml
"""

import argparse
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Ensure the project root is on the path when run as a script
sys.path.insert(0, str(Path(__file__).parent.parent))

from normalizer import config as cfg
from normalizer import evidence, validator
from normalizer.router import route

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger(__name__)

_INGESTORS = {
    "cloudtrail":    ("normalizer.sources.cloud.cloudtrail",    "fetch", "ingestors.cloudtrail"),
    "gcp-audit":     ("normalizer.sources.cloud.gcp_audit",     "fetch", "ingestors.gcp_audit"),
    "azure-monitor": ("normalizer.sources.cloud.azure_monitor", "fetch", "ingestors.azure_monitor"),
    "okta":          ("normalizer.sources.identity.okta",       "fetch", "ingestors.okta"),
    "azure-ad":      ("normalizer.sources.identity.azure_ad",   "fetch", "ingestors.azure_ad"),
    "aws-iam":       ("normalizer.sources.identity.aws_iam",    "fetch", "ingestors.aws_iam"),
}


def _parse_since(since_str: str) -> datetime:
    """Parse '24h', '30m', '7d' into a UTC datetime."""
    since_str = since_str.strip().lower()
    if since_str.endswith("h"):
        delta = timedelta(hours=float(since_str[:-1]))
    elif since_str.endswith("m"):
        delta = timedelta(minutes=float(since_str[:-1]))
    elif since_str.endswith("d"):
        delta = timedelta(days=float(since_str[:-1]))
    else:
        raise ValueError(f"Cannot parse --since value '{since_str}'. Use '24h', '30m', or '7d'.")
    return datetime.now(timezone.utc) - delta


def _get_ingestor_config(config: dict, config_key: str) -> dict:
    """Drill into config using a dot-separated key, e.g. 'ingestors.okta'."""
    parts = config_key.split(".")
    node = config
    for part in parts:
        node = node.get(part, {})
    # Merge in top-level org fields for convenience
    org = config.get("organization", {})
    return {**node, "environment": org.get("environment")}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SecureOps live ingestor — pull events from cloud/identity sources"
    )
    parser.add_argument(
        "--source",
        required=True,
        choices=list(_INGESTORS),
        help="Source to ingest from",
    )
    parser.add_argument(
        "--since",
        default="24h",
        help="How far back to fetch (e.g. 24h, 1h, 30m, 7d). Default: 24h",
    )
    parser.add_argument(
        "--config",
        default="config/config.yaml",
        help="Path to SecureOps config file",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch and normalise but do not route to integrations or write evidence",
    )
    args = parser.parse_args()

    try:
        config = cfg.load(args.config)
    except FileNotFoundError as e:
        log.warning("%s — running with empty config", e)
        config = {}

    drop_sev = cfg.drop_below(config)
    ev_dir = cfg.evidence_dir(config)

    since = _parse_since(args.since)
    until = datetime.now(timezone.utc)
    log.info("Fetching %s events from %s to %s", args.source, since.isoformat(), until.isoformat())

    module_path, fn_name, config_key = _INGESTORS[args.source]
    ingestor_config = _get_ingestor_config(config, config_key)

    import importlib
    try:
        module = importlib.import_module(module_path)
        fetch_fn = getattr(module, fn_name)
    except ImportError as e:
        log.error("Import failed for %s: %s", module_path, e)
        sys.exit(1)

    try:
        events = fetch_fn(ingestor_config, since, until)
    except (RuntimeError, ValueError) as e:
        log.error("Ingestor error: %s", e)
        sys.exit(1)

    log.info("Fetched %d raw event(s)", len(events))

    events = [e for e in events if cfg.severity_passes(e.get("severity", "info"), drop_sev)]
    log.info("%d event(s) meet the minimum severity (%s)", len(events), drop_sev)

    events = validator.validate_batch(events)
    log.info("%d event(s) passed schema validation", len(events))

    if not events:
        log.info("No events to process. Done.")
        return

    if args.dry_run:
        log.info("Dry run — skipping routing and evidence writing")
        for e in events:
            log.info("  [%s] %s — %s", e["severity"].upper(), e["source"]["tool"], e["title"])
        return

    route(events, config)
    evidence.write_batch(events, ev_dir)
    log.info("Done. Processed %d event(s).", len(events))


if __name__ == "__main__":
    main()
