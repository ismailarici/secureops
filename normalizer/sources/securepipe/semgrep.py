"""Converts a SecurePipe semgrep.json into SecurityEvent objects."""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

# SecurePipe maps semgrep severities to ERROR/WARNING/INFO
_SEV_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "info"}


def normalise(path: Path, source_meta: dict) -> list[dict]:
    with open(path) as f:
        data = json.load(f)

    now = datetime.now(timezone.utc).isoformat()
    events = []

    for r in data.get("results", []):
        extra = r.get("extra", {})
        raw_sev = extra.get("severity", "INFO").upper()
        severity = _SEV_MAP.get(raw_sev, "info")
        rule_id = r.get("check_id", "unknown")
        file_path = r.get("path", "")
        line = r.get("start", {}).get("line")
        message = (extra.get("message") or "").strip()
        refs = (extra.get("metadata") or {}).get("references", [])
        cwe = next((ref for ref in refs if "cwe.mitre.org" in str(ref)), None)
        cwe_id = None
        if cwe:
            # Extract CWE-NNN from URL like https://cwe.mitre.org/data/definitions/89.html
            import re
            m = re.search(r"definitions/(\d+)", str(cwe))
            if m:
                cwe_id = f"CWE-{m.group(1)}"

        short_rule = rule_id.split(".")[-1].replace("-", " ").title()
        title = f"{short_rule} in {file_path}:{line}" if file_path else short_rule

        events.append({
            "event_id": str(uuid.uuid4()),
            "timestamp": now,
            "ingested_at": now,
            "schema_version": "1.0",
            "source": {
                "component": "securepipe",
                "tool": "semgrep",
                "environment": source_meta.get("environment"),
                "cloud_provider": source_meta.get("cloud_provider"),
                "region": source_meta.get("region"),
                "account_id": source_meta.get("account_id"),
            },
            "event_type": "vulnerability",
            "severity": severity,
            "title": title,
            "description": message or None,
            "tags": ["sast", "semgrep"],
            "payload": {
                "cve_id": None,
                "cwe_id": cwe_id,
                "affected_file": file_path or None,
                "affected_line": line,
                "affected_package": None,
                "affected_version": None,
                "fixed_version": None,
                "remediation": None,
                "references": [ref for ref in refs if isinstance(ref, str)][:3],
            },
            "raw": r,
        })

    return events
