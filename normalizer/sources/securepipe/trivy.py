"""Converts a SecurePipe trivy.json into SecurityEvent objects."""

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

_SEV_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
}


def normalise(path: Path, source_meta: dict) -> list[dict]:
    with open(path) as f:
        data = json.load(f)

    now = datetime.now(timezone.utc).isoformat()
    events = []

    for result in data.get("Results", []):
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities") or []:
            cve = vuln.get("VulnerabilityID", "")
            pkg = vuln.get("PkgName", "")
            installed = vuln.get("InstalledVersion", "")
            fixed = vuln.get("FixedVersion") or None
            severity = _SEV_MAP.get(vuln.get("Severity", "UNKNOWN").upper(), "info")
            cve_title = (vuln.get("Title") or "").strip()
            desc = (vuln.get("Description") or cve_title or "")[:400].strip()
            refs = [
                r for r in vuln.get("References", [])
                if "cve.mitre" in r or "nvd.nist" in r or "github.com/advisories" in r
            ][:2]
            remediation = (
                f"Upgrade {pkg} to {fixed}"
                if fixed
                else f"No fix released yet for {pkg}@{installed} — monitor the upstream advisory"
            )

            events.append({
                "event_id": str(uuid.uuid4()),
                "timestamp": now,
                "ingested_at": now,
                "schema_version": "1.0",
                "source": {
                    "component": "securepipe",
                    "tool": "trivy",
                    "environment": source_meta.get("environment"),
                    "cloud_provider": source_meta.get("cloud_provider"),
                    "region": source_meta.get("region"),
                    "account_id": source_meta.get("account_id"),
                },
                "event_type": "vulnerability",
                "severity": severity,
                "title": f"{cve} in {pkg}@{installed}" if cve else f"Vulnerability in {pkg}@{installed}",
                "description": cve_title or desc or None,
                "tags": ["container", "trivy"],
                "payload": {
                    "cve_id": cve or None,
                    "cwe_id": None,
                    "affected_file": target or None,
                    "affected_line": None,
                    "affected_package": pkg or None,
                    "affected_version": installed or None,
                    "fixed_version": fixed,
                    "remediation": remediation,
                    "references": refs,
                },
                "raw": vuln,
            })

    return events
