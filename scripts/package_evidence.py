"""
Evidence packaging CLI — reads all artifacts from the evidence/ directory
and produces a self-contained ZIP bundle ready for auditor submission.

Usage:
    python3 scripts/package_evidence.py
    python3 scripts/package_evidence.py --output audit-bundle-2026-05-05.zip
    python3 scripts/package_evidence.py --evidence-dir /path/to/evidence
    python3 scripts/package_evidence.py --config config/config.yaml
"""

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from normalizer import config as cfg
from audit.bundler import create_bundle

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SecureOps evidence packager — create audit-ready ZIP bundle"
    )
    parser.add_argument(
        "--evidence-dir",
        default=None,
        help="Path to the evidence directory (default: from config or evidence/)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output ZIP path (default: evidence-bundle-YYYYMMDD.zip in current directory)",
    )
    parser.add_argument(
        "--config",
        default="config/config.yaml",
        help="Path to SecureOps config file",
    )
    args = parser.parse_args()

    try:
        config = cfg.load(args.config)
    except FileNotFoundError as e:
        log.warning("%s — running with empty config", e)
        config = {}

    evidence_dir = args.evidence_dir or cfg.evidence_dir(config)
    if not Path(evidence_dir).is_dir():
        log.error("Evidence directory not found: %s", evidence_dir)
        sys.exit(1)

    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    output_path = args.output or f"evidence-bundle-{date_str}.zip"

    log.info("Packaging evidence from %s → %s", evidence_dir, output_path)

    try:
        create_bundle(evidence_dir, output_path, config)
    except Exception as e:
        log.error("Bundling failed: %s", e)
        sys.exit(1)

    size_kb = Path(output_path).stat().st_size // 1024
    log.info("Bundle ready: %s (%d KB)", output_path, size_kb)
    log.info("Submit %s to your auditor along with your config/config.yaml (redacted).", output_path)


if __name__ == "__main__":
    main()
