"""
Slack integration — posts Block Kit alert messages via an incoming webhook.

Configuration keys (from config.yaml):
    integrations.slack.webhook_url
    integrations.slack.channel
    integrations.slack.min_severity
    integrations.slack.mention_on_critical
"""

import logging

import requests

log = logging.getLogger(__name__)

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

_EMOJI = {
    "critical": ":red_circle:",
    "high": ":large_orange_circle:",
    "medium": ":large_yellow_circle:",
    "low": ":white_circle:",
    "info": ":information_source:",
}

_COLOUR = {
    "critical": "#CC0000",
    "high": "#E05C00",
    "medium": "#E0A000",
    "low": "#888888",
    "info": "#4A90D9",
}


class SlackClient:
    def __init__(self, config: dict) -> None:
        self._webhook = config.get("webhook_url", "")
        self._channel = config.get("channel", "#security-alerts")
        self._min_severity = config.get("min_severity", "high")
        self._mention = config.get("mention_on_critical", "")

    def send_alert(self, event: dict) -> None:
        if not self._should_send(event):
            return
        payload = self._build_message(event)
        try:
            resp = requests.post(self._webhook, json=payload, timeout=10)
            resp.raise_for_status()
            log.debug("Slack: sent alert for event %s", event.get("event_id"))
        except requests.exceptions.RequestException as e:
            log.error("Slack: failed to send alert: %s", e)

    def send_events(self, events: list[dict]) -> None:
        for event in events:
            self.send_alert(event)

    def _should_send(self, event: dict) -> bool:
        try:
            return SEVERITY_ORDER.index(event.get("severity", "info")) <= SEVERITY_ORDER.index(self._min_severity)
        except ValueError:
            return True

    def _build_message(self, event: dict) -> dict:
        severity = event.get("severity", "info")
        emoji = _EMOJI.get(severity, "")
        colour = _COLOUR.get(severity, "#888888")
        source = event.get("source", {})
        payload = event.get("payload", {})
        tool = source.get("tool", "unknown")
        env = source.get("environment") or "—"
        affected = payload.get("affected_file") or payload.get("affected_package") or "—"
        title = event.get("title", "Security event")
        desc = (event.get("description") or "")[:300]
        mention = f"{self._mention} " if severity == "critical" and self._mention else ""

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} {severity.upper()} — {title}"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Tool:* {tool}"},
                    {"type": "mrkdwn", "text": f"*Environment:* {env}"},
                    {"type": "mrkdwn", "text": f"*Affected:* {affected}"},
                    {"type": "mrkdwn", "text": f"*Event ID:* `{event.get('event_id', '—')}`"},
                ],
            },
        ]

        if desc:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": desc},
            })

        if mention:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": mention},
            })

        return {
            "channel": self._channel,
            "attachments": [{"color": colour, "blocks": blocks}],
        }
