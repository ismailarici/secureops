"""
Evidence bundle generator.

Reads all SecurityEvent JSON files from the evidence/ directory, packages
them into a self-contained ZIP archive that can be handed to an auditor:

    evidence-bundle-YYYYMMDD.zip
    ├── README.txt
    ├── summary.csv
    ├── by-severity/
    │   ├── critical.json
    │   ├── high.json
    │   ├── medium.json
    │   └── low.json
    ├── by-source/
    │   ├── securepipe.json
    │   ├── cloud.json
    │   └── identity.json
    └── compliance-report.html
"""

import csv
import io
import json
import logging
import zipfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from audit.report import generate_html

log = logging.getLogger(__name__)

_SEVERITIES = ["critical", "high", "medium", "low", "info"]
_COMPONENTS = ["securepipe", "secureinfra", "cloud", "identity", "system"]


def _load_events(evidence_dir: str) -> list[dict]:
    out = []
    for path in sorted(Path(evidence_dir).glob("*.json")):
        try:
            with path.open() as f:
                out.append(json.load(f))
        except Exception as e:
            log.warning("Skipping %s: %s", path.name, e)
    log.info("Loaded %d events from %s", len(out), evidence_dir)
    return out


def _summary_csv(events: list[dict]) -> str:
    buf = io.StringIO()
    fields = ["event_id", "timestamp", "severity", "event_type", "source_tool",
              "source_component", "title", "affected_file", "cve_id"]
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for e in events:
        payload = e.get("payload", {})
        writer.writerow({
            "event_id": e.get("event_id", ""),
            "timestamp": e.get("timestamp", ""),
            "severity": e.get("severity", ""),
            "event_type": e.get("event_type", ""),
            "source_tool": e.get("source", {}).get("tool", ""),
            "source_component": e.get("source", {}).get("component", ""),
            "title": e.get("title", ""),
            "affected_file": payload.get("affected_file", ""),
            "cve_id": payload.get("cve_id", ""),
        })
    return buf.getvalue()


def _group_by(events: list[dict], key_fn) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        groups[key_fn(e)].append(e)
    return dict(groups)


def _readme(events: list[dict], org: str, env: str) -> str:
    sev_counts = defaultdict(int)
    for e in events:
        sev_counts[e.get("severity", "info")] += 1
    lines = [
        "SecureOps Audit Evidence Bundle",
        "=" * 40,
        f"Generated:    {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"Organization: {org}",
        f"Environment:  {env}",
        f"Total events: {len(events)}",
        "",
        "Severity breakdown:",
    ]
    for sev in _SEVERITIES:
        if sev_counts[sev]:
            lines.append(f"  {sev.upper():<10} {sev_counts[sev]}")
    lines += [
        "",
        "Files:",
        "  summary.csv              All events in tabular form",
        "  by-severity/             Events grouped by severity",
        "  by-source/               Events grouped by source component",
        "  compliance-report.html   SOC 2 / ISO 27001 coverage mapping",
        "",
        "For auditors:",
        "  Open compliance-report.html for the executive summary.",
        "  summary.csv contains the complete machine-readable event log.",
        "  Raw event JSON files (evidence/*.json) are referenced by event_id.",
    ]
    return "\n".join(lines)


def create_bundle(
    evidence_dir: str,
    output_path: str,
    config: dict,
) -> str:
    """
    Package all events from evidence_dir into a ZIP at output_path.
    Returns the path to the created ZIP.
    """
    org = config.get("organization", {}).get("name", "unknown")
    env = config.get("organization", {}).get("environment", "unknown")
    frameworks = config.get("evidence", {}).get("frameworks", ["SOC2", "ISO27001"])

    events = _load_events(evidence_dir)
    if not events:
        log.warning("No events found in %s — bundle will be empty", evidence_dir)

    by_sev = _group_by(events, lambda e: e.get("severity", "info"))
    by_src = _group_by(events, lambda e: e.get("source", {}).get("component", "unknown"))

    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("README.txt", _readme(events, org, env))
        zf.writestr("summary.csv", _summary_csv(events))
        for sev in _SEVERITIES:
            if sev in by_sev:
                zf.writestr(
                    f"by-severity/{sev}.json",
                    json.dumps(by_sev[sev], indent=2),
                )
        for comp in _COMPONENTS:
            if comp in by_src:
                zf.writestr(
                    f"by-source/{comp}.json",
                    json.dumps(by_src[comp], indent=2),
                )
        zf.writestr(
            "compliance-report.html",
            generate_html(events, org=org, env=env, frameworks=frameworks),
        )

    log.info("Bundle created: %s (%d events)", output_path, len(events))
    return output_path
