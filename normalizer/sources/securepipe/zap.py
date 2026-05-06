"""Converts a SecurePipe zap.json into SecurityEvent objects."""

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

_ZAP_SEV = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
    "INFORMATIONAL": "info",
}


def _map_sev(riskdesc: str) -> str:
    word = riskdesc.split(" ")[0].upper() if riskdesc else "INFO"
    return _ZAP_SEV.get(word, "info")


def normalise(path: Path, source_meta: dict) -> list[dict]:
    with open(path) as f:
        data = json.load(f)

    now = datetime.now(timezone.utc).isoformat()
    events = []

    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            severity = _map_sev(alert.get("riskdesc", ""))
            cwe_raw = alert.get("cweid", "")
            cwe_id = f"CWE-{cwe_raw}" if cwe_raw else None
            solution = (alert.get("solution") or "").strip()
            refs = []
            if cwe_raw:
                refs.append(f"https://cwe.mitre.org/data/definitions/{cwe_raw}.html")
            for url in re.findall(r"https?://\S+", alert.get("reference", "")):
                refs.append(url.rstrip(">,.)"))
            endpoint = alert.get("uri", "")
            method = (alert.get("method") or "").upper()
            title = alert.get("alert", "")

            events.append({
                "event_id": str(uuid.uuid4()),
                "timestamp": now,
                "ingested_at": now,
                "schema_version": "1.0",
                "source": {
                    "component": "securepipe",
                    "tool": "zap",
                    "environment": source_meta.get("environment"),
                    "cloud_provider": source_meta.get("cloud_provider"),
                    "region": source_meta.get("region"),
                    "account_id": source_meta.get("account_id"),
                },
                "event_type": "vulnerability",
                "severity": severity,
                "title": f"{title} — {method} {endpoint}" if endpoint else title,
                "description": (alert.get("desc") or "").strip() or None,
                "tags": ["dast", "zap"],
                "payload": {
                    "cve_id": None,
                    "cwe_id": cwe_id,
                    "affected_file": endpoint or None,
                    "affected_line": None,
                    "affected_package": None,
                    "affected_version": None,
                    "fixed_version": None,
                    "remediation": solution or None,
                    "references": refs[:3],
                },
                "raw": alert,
            })

    return events
