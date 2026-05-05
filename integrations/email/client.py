"""
Email integration — sends security alert emails via SMTP.

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

log = logging.getLogger(__name__)

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


class EmailClient:
    def __init__(self, config: dict) -> None:
        self.smtp_host = config.get("smtp_host", "")
        self.smtp_port = config.get("smtp_port", 587)
        self.smtp_username = config.get("smtp_username", "")
        self.smtp_password = config.get("smtp_password", "")
        self.from_address = config.get("from_address", "")
        self.to_addresses = config.get("to_addresses", [])
        self.min_severity = config.get("min_severity", "critical")

    def send_alert(self, event: dict) -> None:
        """Send a single normalised SecurityEvent as an email alert."""
        if not self._should_send(event):
            return
        subject, body = self._build_email(event)
        # TODO (Phase 2): open an SMTP connection, authenticate, and send
        # Use smtplib with STARTTLS; never log smtp_password
        log.debug("Would send email alert for event %s", event.get("event_id"))

    def send_alerts(self, events: list[dict]) -> None:
        for event in events:
            self.send_alert(event)

    def _should_send(self, event: dict) -> bool:
        event_idx = SEVERITY_ORDER.index(event.get("severity", "info"))
        min_idx = SEVERITY_ORDER.index(self.min_severity)
        return event_idx <= min_idx

    def _build_email(self, event: dict) -> tuple[str, str]:
        # TODO (Phase 2): build a plain-text (and optionally HTML) email body
        # Include: severity, title, description, source, affected resource,
        #          event_id, timestamp, evidence file path
        severity = event.get("severity", "info").upper()
        title = event.get("title", "Security event")
        subject = f"[SecureOps] {severity} — {title}"
        body = f"Severity: {severity}\nTitle: {title}\nEvent ID: {event.get('event_id')}\n"
        return subject, body
