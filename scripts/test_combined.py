#!/usr/bin/env python3
"""
Combined end-to-end test: SecurePipe + SecureInfra → SecureOps.

Loads example data from both SecurePipe and SecureInfra, runs the full
normalizer pipeline (validate → route → evidence) for each source, and
prints a unified summary.

Usage:
    python3 scripts/test_combined.py [--dry-run]
"""

import argparse
import json
import logging
import sys
from pathlib import Path

# Run from secureops/ project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from normalizer import config as cfg, evidence, validator
from normalizer.router import route
from normalizer.sources.securepipe import loader as securepipe_loader
from normalizer.sources.secureinfra import loader as secureinfra_loader

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger(__name__)

SECUREPIPE_EXAMPLES = Path("examples/securepipe-raw")
SECUREINFRA_EXAMPLES = Path("examples/secureinfra-raw")
CONFIG_PATH = "config/config.yaml"


def _severity_summary(events: list[dict]) -> dict:
    counts = {}
    for e in events:
        s = e.get("severity", "unknown")
        counts[s] = counts.get(s, 0) + 1
    return counts


def _print_banner(title: str) -> None:
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}")


def run(dry_run: bool) -> None:
    # ── Config ────────────────────────────────────────────────────────────────
    try:
        config = cfg.load(CONFIG_PATH)
        log.info("Config loaded from %s", CONFIG_PATH)
    except FileNotFoundError:
        log.warning("config/config.yaml not found — running with no integrations")
        config = {}

    meta = cfg.source_meta(config)
    drop_sev = cfg.drop_below(config)
    ev_dir = cfg.evidence_dir(config)

    all_events: list[dict] = []

    # ── SecurePipe ────────────────────────────────────────────────────────────
    _print_banner("SOURCE 1: SecurePipe (SAST / SCA / Container / DAST)")
    if SECUREPIPE_EXAMPLES.is_dir():
        sp_events = securepipe_loader.load(str(SECUREPIPE_EXAMPLES), meta)
        sp_events = [e for e in sp_events if cfg.severity_passes(e.get("severity", "info"), drop_sev)]
        sp_events = validator.validate_batch(sp_events)
        log.info("SecurePipe: %d valid event(s)", len(sp_events))
        for e in sp_events:
            log.info("  [%-8s] %-10s %s", e["severity"].upper(), e["source"]["tool"], e["title"][:60])
        all_events += sp_events
    else:
        log.warning("SecurePipe examples not found at %s", SECUREPIPE_EXAMPLES)

    # ── SecureInfra ───────────────────────────────────────────────────────────
    _print_banner("SOURCE 2: SecureInfra (AWS CSPM / Prowler)")
    if SECUREINFRA_EXAMPLES.is_dir():
        si_events = secureinfra_loader.load(str(SECUREINFRA_EXAMPLES))
        si_events = [e for e in si_events if cfg.severity_passes(e.get("severity", "info"), drop_sev)]
        si_events = validator.validate_batch(si_events)
        log.info("SecureInfra: %d valid event(s)", len(si_events))
        for e in si_events:
            log.info("  [%-8s] %-10s %s", e["severity"].upper(), e["source"]["tool"], e["title"][:60])
        all_events += si_events
    else:
        log.warning("SecureInfra examples not found at %s", SECUREINFRA_EXAMPLES)

    # ── Combined summary ──────────────────────────────────────────────────────
    _print_banner(f"COMBINED: {len(all_events)} events total")
    sev_counts = _severity_summary(all_events)
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = sev_counts.get(sev, 0)
        if count:
            log.info("  %-10s %d event(s)", sev.upper(), count)

    by_source = {}
    for e in all_events:
        comp = e["source"]["component"]
        by_source[comp] = by_source.get(comp, 0) + 1
    for comp, count in sorted(by_source.items()):
        log.info("  %-14s %d event(s)", comp, count)

    if not all_events:
        log.info("No events to process.")
        return

    if dry_run:
        _print_banner("DRY RUN — routing and evidence skipped")
        return

    # ── Route to integrations ─────────────────────────────────────────────────
    _print_banner("ROUTING → Wazuh + DefectDojo")
    route(all_events, config)

    # ── Write evidence ────────────────────────────────────────────────────────
    _print_banner("EVIDENCE")
    written = evidence.write_batch(all_events, ev_dir)
    log.info("Evidence written: %d files to %s/", len(written) if written else len(all_events), ev_dir)

    _print_banner("DONE")
    log.info(
        "Processed %d events from 2 sources (SecurePipe + SecureInfra) → Wazuh + DefectDojo",
        len(all_events),
    )


def main():
    parser = argparse.ArgumentParser(description="Combined SecurePipe + SecureInfra → SecureOps test")
    parser.add_argument("--dry-run", action="store_true", help="Skip routing and evidence writing")
    args = parser.parse_args()
    run(args.dry_run)


if __name__ == "__main__":
    main()
