"""
Slack integration — posts structured security alert messages to a Slack
channel via an incoming webhook.

Configuration keys (from config.yaml):
    integrations.slack.webhook_url
    integrations.slack.channel
    integrations.slack.min_severity
    integrations.slack.mention_on_critical
"""

import logging

log = logging.getLogger(__name__)

SEVERITY_EMOJI = {
    "critical": ":red_circle:",
    "high": ":large_orange_circle:",
    "medium": ":large_yellow_circle:",
    "low": ":white_circle:",
    "info": ":information_source:",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


class SlackClient:
    def __init__(self, config: dict) -> None:
        self.webhook_url = config.get("webhook_url", "")
        self.channel = config.get("channel", "#security-alerts")
        self.min_severity = config.get("min_severity", "high")
        self.mention_on_critical = config.get("mention_on_critical", "")

    def send_alert(self, event: dict) -> None:
        """Send a single normalised SecurityEvent as a Slack message."""
        if not self._should_send(event):
            return
        payload = self._build_message(event)
        # TODO (Phase 2): POST payload to self.webhook_url using requests
        # Do not log the webhook URL (treat it as a credential)
        log.debug("Would post Slack alert for event %s", event.get("event_id"))

    def send_alerts(self, events: list[dict]) -> None:
        for event in events:
            self.send_alert(event)

    def _should_send(self, event: dict) -> bool:
        event_idx = SEVERITY_ORDER.index(event.get("severity", "info"))
        min_idx = SEVERITY_ORDER.index(self.min_severity)
        return event_idx <= min_idx

    def _build_message(self, event: dict) -> dict:
        # TODO (Phase 2): build a Slack Block Kit payload
        # Include: severity emoji, title, source tool, environment, affected file/resource,
        #          link to evidence artifact, @mention if critical
        severity = event.get("severity", "info")
        emoji = SEVERITY_EMOJI.get(severity, "")
        title = event.get("title", "Security event")
        mention = ""
        if severity == "critical" and self.mention_on_critical:
            mention = f"{self.mention_on_critical} "
        return {
            "channel": self.channel,
            "text": f"{mention}{emoji} *{severity.upper()}* — {title}",
        }
