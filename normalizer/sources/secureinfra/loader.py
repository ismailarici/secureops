"""
Loads SecureInfra normalized output into SecureOps.

SecureInfra events are already in SecureOps event schema format — this loader
reads the JSONL bundles SecureInfra writes and passes them through as-is.
Schema validation happens downstream in the normalizer pipeline.
"""

import json
import logging
from pathlib import Path

log = logging.getLogger(__name__)


def load(input_dir: str) -> list[dict]:
    """
    Reads all *.jsonl files from a SecureInfra output directory.
    Each line is a pre-normalized SecurityEvent conforming to schema v1.0.
    Returns the full event list — no further mapping needed.
    """
    path = Path(input_dir)
    if not path.is_dir():
        raise NotADirectoryError(f"Not a directory: {input_dir}")

    events: list[dict] = []

    jsonl_files = sorted(path.glob("*.jsonl"))
    if not jsonl_files:
        log.warning("No *.jsonl files found in %s", input_dir)
        return events

    for jsonl_file in jsonl_files:
        file_events = 0
        with open(jsonl_file) as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    events.append(event)
                    file_events += 1
                except json.JSONDecodeError as e:
                    log.error("JSON parse error in %s line %d: %s", jsonl_file.name, lineno, e)
        log.info("%-40s → %d event(s)", jsonl_file.name, file_events)

    return events
