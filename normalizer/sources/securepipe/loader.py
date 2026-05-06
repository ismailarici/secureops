"""
Loads a SecurePipe reports/raw/ directory and returns a flat list of SecurityEvents.

Supported files:
    semgrep.json  — SAST findings
    sca.json      — SCA findings (pip-audit, npm audit, or OWASP Dependency-Check)
    trivy.json    — Container / filesystem scan findings
    zap.json      — DAST findings

Files that are missing or empty are silently skipped.
"""

import logging
from pathlib import Path

from . import semgrep, sca, trivy, zap

log = logging.getLogger(__name__)


def load(raw_dir: str, source_meta: dict) -> list[dict]:
    """
    raw_dir:     path to SecurePipe's reports/raw/ directory
    source_meta: {environment, cloud_provider, region, account_id}
    """
    raw = Path(raw_dir)
    if not raw.is_dir():
        raise NotADirectoryError(f"Not a directory: {raw_dir}")

    events: list[dict] = []

    for filename, parser in [
        ("semgrep.json", semgrep.normalise),
        ("sca.json", sca.normalise),
        ("trivy.json", trivy.normalise),
        ("zap.json", zap.normalise),
    ]:
        path = raw / filename
        if not path.exists():
            log.debug("Skipping %s — file not found", filename)
            continue
        try:
            found = parser(path, source_meta)
            log.info("%-12s → %d event(s)", filename, len(found))
            events += found
        except Exception as e:
            log.error("Failed to parse %s: %s", filename, e)

    return events
