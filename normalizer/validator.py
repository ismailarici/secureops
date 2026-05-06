import json
import logging
from pathlib import Path

import jsonschema

log = logging.getLogger(__name__)

_SCHEMA_PATH = Path(__file__).parent / "schemas" / "event.schema.json"
_schema: dict | None = None


def _get_schema() -> dict:
    global _schema
    if _schema is None:
        with _SCHEMA_PATH.open() as f:
            _schema = json.load(f)
    return _schema


def validate(event: dict) -> tuple[bool, str]:
    try:
        jsonschema.validate(instance=event, schema=_get_schema())
        return True, ""
    except jsonschema.ValidationError as e:
        return False, e.message
    except jsonschema.SchemaError as e:
        log.error("Schema itself is invalid: %s", e.message)
        return False, f"Schema error: {e.message}"


def validate_batch(events: list[dict]) -> list[dict]:
    """Return only the events that pass schema validation, logging failures."""
    valid = []
    for event in events:
        ok, reason = validate(event)
        if ok:
            valid.append(event)
        else:
            log.warning(
                "Event %s failed validation: %s",
                event.get("event_id", "unknown"),
                reason,
            )
    return valid
