import json
import logging
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)


def write(event: dict, output_dir: str) -> Path:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"{ts}_{event['event_id']}.json"
    path = out / filename
    with path.open("w") as f:
        json.dump(event, f, indent=2)
    log.debug("Evidence written: %s", path)
    return path


def write_batch(events: list[dict], output_dir: str) -> list[Path]:
    paths = [write(e, output_dir) for e in events]
    log.info("Wrote %d evidence file(s) to %s", len(paths), output_dir)
    return paths
