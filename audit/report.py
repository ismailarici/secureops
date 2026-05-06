"""
Compliance report generator.

Produces a self-contained HTML report that maps SecureOps evidence to
SOC 2 and ISO 27001 controls. Designed to be handed directly to an auditor.
"""

from collections import defaultdict
from datetime import datetime, timezone

_SEVERITIES = ["critical", "high", "medium", "low", "info"]

_SEV_COLOUR = {
    "critical": "#CC0000",
    "high": "#E05C00",
    "medium": "#E0A000",
    "low": "#888888",
    "info": "#4A90D9",
}

# Compliance control definitions.
# Each entry: (framework, control_id, title, description, satisfied_by_components, satisfied_by_event_types)
_CONTROLS = [
    (
        "SOC 2", "CC6.6",
        "Logical and Physical Access Controls",
        "The entity implements logical access security software, infrastructure, and architectures "
        "over protected information assets.",
        {"securepipe", "identity"},
        {"vulnerability", "identity_event"},
    ),
    (
        "SOC 2", "CC7.1",
        "Detection and Monitoring of Security Threats",
        "The entity uses detection and monitoring procedures to identify changes to configurations "
        "and potential threats.",
        {"securepipe", "cloud", "system"},
        {"vulnerability", "cloud_event", "system_event"},
    ),
    (
        "SOC 2", "CC7.2",
        "Monitoring of System Components",
        "The entity monitors system components and uses the monitoring to detect anomalies.",
        {"cloud", "identity", "system"},
        {"cloud_event", "identity_event", "system_event"},
    ),
    (
        "SOC 2", "CC7.3",
        "Evaluation and Monitoring of Internal Controls",
        "The entity evaluates and communicates internal control deficiencies in a timely manner.",
        {"securepipe", "secureinfra"},
        {"vulnerability"},
    ),
    (
        "ISO 27001", "A.12.6.1",
        "Management of Technical Vulnerabilities",
        "Information about technical vulnerabilities shall be obtained and the organisation's "
        "exposure to such vulnerabilities evaluated.",
        {"securepipe"},
        {"vulnerability"},
    ),
    (
        "ISO 27001", "A.14.2.3",
        "Technical Review of Applications",
        "Business critical applications shall be reviewed and tested when operating platforms "
        "are changed.",
        {"securepipe"},
        {"vulnerability"},
    ),
    (
        "ISO 27001", "A.16.1.4",
        "Assessment of and Decision on Information Security Events",
        "Information security events shall be assessed and it shall be decided if they are "
        "to be classified as information security incidents.",
        {"cloud", "identity", "system"},
        {"cloud_event", "identity_event", "system_event"},
    ),
    (
        "ISO 27001", "A.9.4.2",
        "Secure Log-on Procedures",
        "Where required by the access control policy, access to systems and applications "
        "shall be controlled by a secure log-on procedure.",
        {"identity"},
        {"identity_event"},
    ),
]


def _count_by_severity(events: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for e in events:
        counts[e.get("severity", "info")] += 1
    return dict(counts)


def _count_by_source(events: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for e in events:
        counts[e.get("source", {}).get("component", "unknown")] += 1
    return dict(counts)


def _control_status(events: list[dict], components: set, event_types: set) -> tuple[str, int]:
    """Return (status_label, matching_event_count) for a control."""
    matching = [
        e for e in events
        if e.get("source", {}).get("component") in components
        or e.get("event_type") in event_types
    ]
    if matching:
        return "COVERED", len(matching)
    return "NO EVIDENCE", 0


def generate_html(
    events: list[dict],
    org: str = "",
    env: str = "",
    frameworks: list[str] | None = None,
) -> str:
    frameworks = frameworks or ["SOC2", "ISO27001"]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sev_counts = _count_by_severity(events)
    src_counts = _count_by_source(events)
    total = len(events)

    # ── Severity summary table ─────────────────────────────────────────────
    sev_rows = "".join(
        f"<tr><td style='padding:6px 14px'><span style='color:{_SEV_COLOUR[s]};font-weight:bold'>"
        f"{s.upper()}</span></td><td style='padding:6px 14px'>{sev_counts.get(s, 0)}</td></tr>"
        for s in _SEVERITIES
    )

    # ── Source coverage table ──────────────────────────────────────────────
    all_sources = ["securepipe", "secureinfra", "cloud", "identity", "system"]
    src_rows = "".join(
        f"<tr><td style='padding:6px 14px'>{s}</td>"
        f"<td style='padding:6px 14px'>{src_counts.get(s, 0)}</td>"
        f"<td style='padding:6px 14px'>{'✓' if src_counts.get(s, 0) > 0 else '—'}</td></tr>"
        for s in all_sources
    )

    # ── Compliance controls table ──────────────────────────────────────────
    applicable = [c for c in _CONTROLS if c[0].replace(" ", "") in [f.replace(" ", "") for f in frameworks]]
    control_rows = ""
    for framework, control_id, title, description, components, event_types in applicable:
        status, count = _control_status(events, components, event_types)
        status_colour = "#2d8a4e" if status == "COVERED" else "#CC0000"
        control_rows += (
            f"<tr>"
            f"<td style='padding:8px 14px;white-space:nowrap'><strong>{framework}</strong></td>"
            f"<td style='padding:8px 14px;white-space:nowrap'>{control_id}</td>"
            f"<td style='padding:8px 14px'>{title}</td>"
            f"<td style='padding:8px 14px;font-size:13px;color:#555'>{description}</td>"
            f"<td style='padding:8px 14px'>{count} event(s)</td>"
            f"<td style='padding:8px 14px;font-weight:bold;color:{status_colour}'>{status}</td>"
            f"</tr>"
        )

    # ── Recent events table (latest 50) ───────────────────────────────────
    recent = sorted(events, key=lambda e: e.get("timestamp", ""), reverse=True)[:50]
    event_rows = ""
    for e in recent:
        sev = e.get("severity", "info")
        colour = _SEV_COLOUR.get(sev, "#888")
        event_rows += (
            f"<tr>"
            f"<td style='padding:6px 10px;white-space:nowrap'>{e.get('timestamp', '')[:19]}</td>"
            f"<td style='padding:6px 10px;color:{colour};font-weight:bold'>{sev.upper()}</td>"
            f"<td style='padding:6px 10px'>{e.get('source', {}).get('tool', '')}</td>"
            f"<td style='padding:6px 10px'>{e.get('event_type', '')}</td>"
            f"<td style='padding:6px 10px'>{e.get('title', '')[:100]}</td>"
            f"</tr>"
        )

    covered = sum(1 for c in applicable if _control_status(events, c[4], c[5])[0] == "COVERED")
    coverage_pct = int(covered / len(applicable) * 100) if applicable else 0

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SecureOps Compliance Evidence Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         max-width: 1100px; margin: 0 auto; padding: 24px; color: #222; }}
  h1 {{ border-left: 5px solid #1a56a0; padding-left: 14px; }}
  h2 {{ margin-top: 36px; color: #1a56a0; border-bottom: 1px solid #ddd; padding-bottom: 6px; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 12px; font-size: 14px; }}
  th {{ background: #f4f6f8; text-align: left; padding: 8px 14px; border-bottom: 2px solid #ccc; }}
  tr:nth-child(even) {{ background: #fafbfc; }}
  .badge {{ display: inline-block; padding: 3px 10px; border-radius: 4px;
            font-weight: bold; font-size: 12px; }}
  .meta {{ color: #666; font-size: 14px; margin-top: -10px; }}
  .coverage {{ font-size: 18px; font-weight: bold; color: {'#2d8a4e' if coverage_pct >= 75 else '#E05C00'}; }}
</style>
</head>
<body>

<h1>SecureOps — Audit Evidence Report</h1>
<p class="meta">
  Generated: {now} &nbsp;|&nbsp;
  Organization: <strong>{org or '—'}</strong> &nbsp;|&nbsp;
  Environment: <strong>{env or '—'}</strong> &nbsp;|&nbsp;
  Total events: <strong>{total}</strong>
</p>

<h2>Event Summary</h2>
<table style="width:auto">
  <tr><th>Severity</th><th>Count</th></tr>
  {sev_rows}
  <tr style="border-top:2px solid #ccc"><td style="padding:6px 14px"><strong>Total</strong></td>
      <td style="padding:6px 14px"><strong>{total}</strong></td></tr>
</table>

<h2>Source Coverage</h2>
<table style="width:auto">
  <tr><th>Source</th><th>Events</th><th>Active</th></tr>
  {src_rows}
</table>

<h2>Compliance Coverage</h2>
<p>
  <span class="coverage">{coverage_pct}%</span> of applicable controls have evidence
  ({covered}/{len(applicable)} controls covered).
  Frameworks: {', '.join(frameworks)}.
</p>
<table>
  <tr>
    <th>Framework</th><th>Control</th><th>Title</th>
    <th>Description</th><th>Evidence</th><th>Status</th>
  </tr>
  {control_rows}
</table>

<h2>Event Log (latest 50)</h2>
<table>
  <tr><th>Timestamp</th><th>Severity</th><th>Tool</th><th>Type</th><th>Title</th></tr>
  {event_rows if event_rows else '<tr><td colspan="5" style="padding:12px;color:#888">No events recorded.</td></tr>'}
</table>

<hr style="margin-top:40px">
<p style="color:#888;font-size:12px">
  Generated by SecureOps &nbsp;|&nbsp;
  This report is based on events collected by SecureOps and should be
  supplemented with raw evidence files (evidence/*.json) for detailed review.
</p>
</body>
</html>"""
