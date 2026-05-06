"""
Email integration — sends security alert emails via SMTP with STARTTLS.

Configuration keys (from config.yaml):
    integrations.email.smtp_host
    integrations.email.smtp_port
    integrations.email.smtp_username
    integrations.email.smtp_password
    integrations.email.from_address
    integrations.email.to_addresses
    integrations.email.min_severity
"""

import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

log = logging.getLogger(__name__)

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


class EmailClient:
    def __init__(self, config: dict) -> None:
        self._host = config.get("smtp_host", "")
        self._port = config.get("smtp_port", 587)
        self._username = config.get("smtp_username", "")
        self._password = config.get("smtp_password", "")
        self._from = config.get("from_address", "")
        self._to = config.get("to_addresses", [])
        self._min_severity = config.get("min_severity", "critical")

    def send_alert(self, event: dict) -> None:
        if not self._should_send(event):
            return
        msg = self._build_message(event)
        try:
            with smtplib.SMTP(self._host, self._port, timeout=15) as smtp:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()
                smtp.login(self._username, self._password)
                smtp.sendmail(self._from, self._to, msg.as_string())
            log.debug("Email: sent alert for event %s", event.get("event_id"))
        except smtplib.SMTPException as e:
            log.error("Email: SMTP error: %s", e)
        except OSError as e:
            log.error("Email: connection error to %s:%s — %s", self._host, self._port, e)

    def send_events(self, events: list[dict]) -> None:
        for event in events:
            self.send_alert(event)

    def _should_send(self, event: dict) -> bool:
        try:
            return SEVERITY_ORDER.index(event.get("severity", "info")) <= SEVERITY_ORDER.index(self._min_severity)
        except ValueError:
            return True

    def _build_message(self, event: dict) -> MIMEMultipart:
        severity = event.get("severity", "info").upper()
        title = event.get("title", "Security event")
        source = event.get("source", {})
        payload = event.get("payload", {})

        subject = f"[SecureOps] {severity} — {title}"
        plain = self._plain_body(event, severity, source, payload)
        html = self._html_body(event, severity, source, payload)

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self._from
        msg["To"] = ", ".join(self._to)
        msg.attach(MIMEText(plain, "plain"))
        msg.attach(MIMEText(html, "html"))
        return msg

    def _plain_body(self, event: dict, severity: str, source: dict, payload: dict) -> str:
        lines = [
            f"SecureOps Security Alert",
            f"{'=' * 40}",
            f"Severity:    {severity}",
            f"Title:       {event.get('title', '')}",
            f"Tool:        {source.get('tool', '—')}",
            f"Environment: {source.get('environment') or '—'}",
            f"Affected:    {payload.get('affected_file') or payload.get('affected_package') or '—'}",
            f"Event ID:    {event.get('event_id', '—')}",
            f"Timestamp:   {event.get('timestamp', '—')}",
        ]
        if event.get("description"):
            lines += ["", "Description:", event["description"]]
        if payload.get("remediation"):
            lines += ["", "Remediation:", payload["remediation"]]
        if payload.get("references"):
            lines += ["", "References:"] + payload["references"]
        return "\n".join(lines)

    def _html_body(self, event: dict, severity: str, source: dict, payload: dict) -> str:
        colour = {
            "CRITICAL": "#CC0000", "HIGH": "#E05C00",
            "MEDIUM": "#E0A000", "LOW": "#888888", "INFO": "#4A90D9",
        }.get(severity, "#888888")

        rows = [
            ("Severity", f'<span style="color:{colour};font-weight:bold">{severity}</span>'),
            ("Title", event.get("title", "")),
            ("Tool", source.get("tool", "—")),
            ("Environment", source.get("environment") or "—"),
            ("Affected", payload.get("affected_file") or payload.get("affected_package") or "—"),
            ("Event ID", f'<code>{event.get("event_id", "—")}</code>'),
            ("Timestamp", event.get("timestamp", "—")),
        ]
        if payload.get("cve_id"):
            rows.append(("CVE", payload["cve_id"]))
        if payload.get("fixed_version"):
            rows.append(("Fix version", payload["fixed_version"]))

        table_rows = "".join(
            f"<tr><td style='padding:6px 12px;font-weight:bold;white-space:nowrap'>{k}</td>"
            f"<td style='padding:6px 12px'>{v}</td></tr>"
            for k, v in rows
        )

        desc_block = ""
        if event.get("description"):
            desc_block = f"<p><strong>Description</strong><br>{event['description']}</p>"

        rem_block = ""
        if payload.get("remediation"):
            rem_block = f"<p><strong>Remediation</strong><br>{payload['remediation']}</p>"

        refs_block = ""
        if payload.get("references"):
            links = " ".join(f'<a href="{r}">{r}</a>' for r in payload["references"])
            refs_block = f"<p><strong>References</strong><br>{links}</p>"

        return f"""<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:700px;margin:0 auto">
<h2 style="border-left:4px solid {colour};padding-left:12px">SecureOps Security Alert</h2>
<table style="border-collapse:collapse;width:100%">{table_rows}</table>
{desc_block}{rem_block}{refs_block}
<hr><p style="color:#888;font-size:12px">Generated by SecureOps</p>
</body></html>"""
