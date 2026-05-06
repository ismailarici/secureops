"""
Entry point for the SecureOps normaliser.

Usage:
    # Consume a full SecurePipe raw/ directory:
    python -m normalizer.main --input /path/to/reports/raw

    # Consume a single JSON file (source tool must be specified):
    python -m normalizer.main --input semgrep.json --source semgrep

    # Use a non-default config:
    python -m normalizer.main --input /path/to/raw --config /path/to/config.yaml
"""

import argparse
import logging
import sys
from pathlib import Path

from normalizer import config as cfg
from normalizer import evidence, validator
from normalizer.router import route
from normalizer.sources.securepipe import loader as securepipe_loader

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger(__name__)

_SINGLE_FILE_SOURCES = {"semgrep", "sca", "trivy", "zap"}


def _load_single_file(input_path: Path, source: str, source_meta: dict) -> list[dict]:
    from normalizer.sources.securepipe import semgrep, sca, trivy, zap
    parsers = {
        "semgrep": semgrep.normalise,
        "sca": sca.normalise,
        "trivy": trivy.normalise,
        "zap": zap.normalise,
    }
    if source not in parsers:
        log.error(
            "Unknown source '%s'. Supported values: %s",
            source,
            ", ".join(parsers),
        )
        sys.exit(1)
    return parsers[source](input_path, source_meta)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SecureOps normaliser — convert tool output to SecurityEvents and route to integrations"
    )
    parser.add_argument(
        "--input",
        required=True,
        help=(
            "Path to a SecurePipe reports/raw/ directory, "
            "or to a single tool JSON file (requires --source)"
        ),
    )
    parser.add_argument(
        "--source",
        default=None,
        help="Source tool when --input is a single file: semgrep | sca | trivy | zap",
    )
    parser.add_argument(
        "--config",
        default="config/config.yaml",
        help="Path to SecureOps config file (default: config/config.yaml)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Normalise and validate events but do not send to integrations or write evidence",
    )
    args = parser.parse_args()

    # ── Config ────────────────────────────────────────────────────────────────
    try:
        config = cfg.load(args.config)
    except FileNotFoundError as e:
        log.warning("%s — running with empty config (no integrations will be active)", e)
        config = {}

    meta = cfg.source_meta(config)
    drop_sev = cfg.drop_below(config)
    ev_dir = cfg.evidence_dir(config)

    # ── Load and normalise ────────────────────────────────────────────────────
    input_path = Path(args.input)

    if input_path.is_dir():
        log.info("Mode: SecurePipe raw directory (%s)", input_path)
        events = securepipe_loader.load(str(input_path), meta)
    elif input_path.is_file():
        if not args.source:
            log.error("--source is required when --input is a single file")
            sys.exit(1)
        log.info("Mode: single file (%s, source=%s)", input_path, args.source)
        events = _load_single_file(input_path, args.source, meta)
    else:
        log.error("Input not found: %s", args.input)
        sys.exit(1)

    log.info("Produced %d raw event(s)", len(events))

    # ── Filter by minimum severity ────────────────────────────────────────────
    events = [
        e for e in events
        if cfg.severity_passes(e.get("severity", "info"), drop_sev)
    ]
    log.info("%d event(s) meet the minimum severity (%s)", len(events), drop_sev)

    # ── Validate ──────────────────────────────────────────────────────────────
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

    # ── Route to integrations ─────────────────────────────────────────────────
    route(events, config)

    # ── Write evidence ────────────────────────────────────────────────────────
    evidence.write_batch(events, ev_dir)

    log.info("Done. Processed %d event(s).", len(events))


if __name__ == "__main__":
    main()
