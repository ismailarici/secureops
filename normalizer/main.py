"""
Entry point for the SecureOps normaliser.

Usage:
    python -m normalizer.main --input <path-to-tool-output.json> [--source <tool-name>]

The normaliser:
1. Reads raw tool output from --input
2. Detects or accepts the source tool via --source
3. Runs the appropriate normaliser to produce SecurityEvent objects
4. Validates each event against the JSON schema
5. Routes each event to enabled integrations
6. Writes each event to evidence/
"""

import argparse
import json
import logging
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger(__name__)


def load_config(config_path: str) -> dict:
    # TODO (Phase 2): parse config/config.yaml and return a validated config dict
    log.info("Loading config from %s", config_path)
    return {}


def load_raw_input(input_path: str) -> dict:
    path = Path(input_path)
    if not path.exists():
        log.error("Input file not found: %s", input_path)
        sys.exit(1)
    with path.open() as f:
        return json.load(f)


def detect_source(raw: dict) -> str:
    # TODO (Phase 2): inspect raw output structure to auto-detect which tool produced it
    # e.g. check for semgrep's "results" key, trivy's "Results" key, etc.
    raise NotImplementedError("Auto-detection not yet implemented. Pass --source explicitly.")


def normalise(raw: dict, source: str) -> list[dict]:
    # TODO (Phase 2): route to the correct per-source normaliser
    # e.g. from normalizer.sources.securepipe import semgrep, trivy
    #      return semgrep.normalise(raw)
    raise NotImplementedError(f"Normaliser for source '{source}' not yet implemented.")


def validate_event(event: dict) -> bool:
    # TODO (Phase 2): validate event against normalizer/schemas/event.schema.json
    # Use jsonschema.validate() — fail fast on schema violations
    return True


def route_events(events: list[dict], config: dict) -> None:
    # TODO (Phase 2): for each event, call each enabled integration client
    # from integrations.wazuh.client import WazuhClient
    # from integrations.defectdojo.client import DefectDojoClient
    # from integrations.slack.client import SlackClient
    for event in events:
        log.info("Routing event: %s  severity=%s", event.get("event_id"), event.get("severity"))


def write_evidence(events: list[dict], config: dict) -> None:
    # TODO (Phase 2): write each event as a timestamped JSON file under evidence/
    # Use config["evidence"]["output_dir"] for the path
    pass


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SecureOps normaliser — convert tool output to SecurityEvents"
    )
    parser.add_argument("--input", required=True, help="Path to raw tool output (JSON)")
    parser.add_argument("--source", default=None, help="Source tool name (e.g. semgrep, trivy)")
    parser.add_argument(
        "--config", default="config/config.yaml", help="Path to SecureOps config file"
    )
    args = parser.parse_args()

    config = load_config(args.config)
    raw = load_raw_input(args.input)

    source = args.source or detect_source(raw)
    log.info("Source: %s", source)

    events = normalise(raw, source)
    log.info("Produced %d events", len(events))

    valid_events = [e for e in events if validate_event(e)]
    log.info("%d events passed schema validation", len(valid_events))

    route_events(valid_events, config)
    write_evidence(valid_events, config)

    log.info("Done.")


if __name__ == "__main__":
    main()
