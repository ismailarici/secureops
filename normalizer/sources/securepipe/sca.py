"""
Converts a SecurePipe sca.json into SecurityEvent objects.

SecurePipe writes one of three formats to sca.json depending on the language:
  pip-audit   → {"dependencies": [{name, version, vulns: [{id, fix_versions, description}]}]}
  npm audit   → {"vulnerabilities": {name: {severity, via, range, fixAvailable, title}}}
  OWASP DC    → {"dependencies": [{fileName, vulnerabilities: [{name, severity, description}]}]}

Detection mirrors SecurePipe's own normalize.py logic.
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

_SEV_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
    "INFORMATIONAL": "info",
    "UNKNOWN": "info",
}


def _norm_sev(s: str) -> str:
    return _SEV_MAP.get((s or "UNKNOWN").upper().strip(), "info")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _base_event(source_meta: dict, tool: str) -> dict:
    now = _now()
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": now,
        "ingested_at": now,
        "schema_version": "1.0",
        "source": {
            "component": "securepipe",
            "tool": tool,
            "environment": source_meta.get("environment"),
            "cloud_provider": source_meta.get("cloud_provider"),
            "region": source_meta.get("region"),
            "account_id": source_meta.get("account_id"),
        },
        "event_type": "vulnerability",
        "tags": ["sca", tool],
    }


def _from_pip_audit(data: dict, source_meta: dict) -> list[dict]:
    events = []
    for dep in data.get("dependencies", []):
        pkg = dep.get("name", "")
        ver = dep.get("version", "")
        for vuln in dep.get("vulns", []):
            cve = vuln.get("id", "")
            fix_versions = vuln.get("fix_versions", [])
            fixed = fix_versions[0] if fix_versions else None
            desc = (vuln.get("description") or "").strip()
            remediation = (
                f"Upgrade {pkg} to {fixed}" if fixed
                else f"Upgrade {pkg} — check PyPI for the latest safe version"
            )
            event = _base_event(source_meta, "pip-audit")
            event.update({
                "severity": "high",
                "title": f"{cve} in {pkg} {ver}" if cve else f"Vulnerability in {pkg} {ver}",
                "description": desc or None,
                "payload": {
                    "cve_id": cve or None,
                    "cwe_id": None,
                    "affected_file": "requirements.txt",
                    "affected_line": None,
                    "affected_package": pkg,
                    "affected_version": ver,
                    "fixed_version": fixed,
                    "remediation": remediation,
                    "references": (
                        [f"https://osv.dev/vulnerability/{cve}"]
                        if cve and (cve.startswith("CVE") or cve.startswith("PYSEC"))
                        else []
                    ),
                },
                "raw": vuln,
            })
            events.append(event)
    return events


def _from_npm_audit(data: dict, source_meta: dict) -> list[dict]:
    events = []
    for name, vuln in data.get("vulnerabilities", {}).items():
        severity = _norm_sev(vuln.get("severity", "UNKNOWN"))
        via = vuln.get("via", [])
        cve = None
        title_str = vuln.get("title") or name
        desc = ""
        for v in via:
            if isinstance(v, dict):
                cve = v.get("cve") or v.get("name") or ""
                title_str = v.get("title") or title_str
                desc = title_str
                break
        fix_available = vuln.get("fixAvailable")
        if isinstance(fix_available, dict):
            fn = fix_available.get("name", name)
            fv = fix_available.get("version", "")
            remediation = f"Run `npm install {fn}@{fv}` or `npm audit fix --force`"
        elif fix_available is True:
            remediation = "Run `npm audit fix` to apply available patches"
        else:
            remediation = "No automatic fix available — review manually or pin to a safe version"
        event = _base_event(source_meta, "npm-audit")
        event.update({
            "severity": severity,
            "title": f"{cve or title_str} in {name}" if cve else f"{title_str} in {name}",
            "description": desc or None,
            "payload": {
                "cve_id": cve or None,
                "cwe_id": None,
                "affected_file": "package.json",
                "affected_line": None,
                "affected_package": name,
                "affected_version": vuln.get("range") or None,
                "fixed_version": None,
                "remediation": remediation,
                "references": (
                    [f"https://osv.dev/vulnerability/{cve}"]
                    if cve and cve.startswith("CVE") else []
                ),
            },
            "raw": vuln,
        })
        events.append(event)
    return events


def _from_owasp_dc(data: dict, source_meta: dict) -> list[dict]:
    events = []
    for dep in data.get("dependencies", []):
        file_name = dep.get("fileName", "")
        pkg_name = file_name.split("/")[-1].split("\\")[-1]
        for vuln in dep.get("vulnerabilities", []):
            severity = _norm_sev(vuln.get("severity", "UNKNOWN"))
            cve = vuln.get("name", "")
            desc = (vuln.get("description") or "")[:400].strip()
            event = _base_event(source_meta, "owasp-dc")
            event.update({
                "severity": severity,
                "title": f"{cve} in {pkg_name}" if cve else f"Vulnerability in {pkg_name}",
                "description": desc or None,
                "payload": {
                    "cve_id": cve or None,
                    "cwe_id": None,
                    "affected_file": file_name or None,
                    "affected_line": None,
                    "affected_package": pkg_name or None,
                    "affected_version": None,
                    "fixed_version": None,
                    "remediation": (
                        f"Upgrade {pkg_name} to a patched version. Check the vendor advisory for {cve}."
                        if cve else f"Upgrade {pkg_name} to a patched version."
                    ),
                    "references": (
                        [f"https://nvd.nist.gov/vuln/detail/{cve}"]
                        if cve.startswith("CVE") else []
                    ),
                },
                "raw": vuln,
            })
            events.append(event)
    return events


def normalise(path: Path, source_meta: dict) -> list[dict]:
    with open(path) as f:
        data = json.load(f)

    deps = data.get("dependencies", [])
    first = deps[0] if deps else {}

    if deps and "vulns" in first:
        return _from_pip_audit(data, source_meta)
    if deps and "vulnerabilities" in first:
        return _from_owasp_dc(data, source_meta)
    if "vulnerabilities" in data:
        return _from_npm_audit(data, source_meta)

    return []
