"""
Wazuh integration — forwards normalised SecurityEvents to a Wazuh manager
via the Wazuh REST API.

Each event is mapped to a Wazuh alert with an appropriate rule level.

Configuration keys (from config.yaml):
    integrations.wazuh.url
    integrations.wazuh.port
    integrations.wazuh.username
    integrations.wazuh.password
    integrations.wazuh.min_severity
"""

import logging

log = logging.getLogger(__name__)

# Wazuh rule levels mapped from SecureOps severity.
# Wazuh uses 0–15; we use a conservative mapping that avoids
# collisions with built-in Wazuh rules (which use 0–12).
SEVERITY_TO_LEVEL = {
    "critical": 15,
    "high": 12,
    "medium": 9,
    "low": 6,
    "info": 3,
}


class WazuhClient:
    def __init__(self, config: dict) -> None:
        self.url = config.get("url", "")
        self.port = config.get("port", 55000)
        self.username = config.get("username", "")
        self.password = config.get("password", "")
        self.min_severity = config.get("min_severity", "medium")
        # TODO (Phase 2): initialise authenticated HTTP session against the Wazuh API
        self._session = None

    def _authenticate(self) -> None:
        # TODO (Phase 2): POST /security/user/authenticate to obtain a JWT token
        # Store token in self._session headers for subsequent requests
        raise NotImplementedError

    def send_event(self, event: dict) -> None:
        """Send a single normalised SecurityEvent to Wazuh."""
        if not self._should_send(event):
            return
        # TODO (Phase 2): map event to Wazuh alert payload and POST to the API
        # Endpoint: POST /events
        # Payload: { "events": [ <wazuh-alert-format> ] }
        log.debug("Would send event %s to Wazuh", event.get("event_id"))

    def send_events(self, events: list[dict]) -> None:
        """Send a batch of normalised SecurityEvents to Wazuh."""
        for event in events:
            self.send_event(event)

    def _should_send(self, event: dict) -> bool:
        """Return True if the event meets the configured minimum severity."""
        levels = list(SEVERITY_TO_LEVEL.keys())
        event_level = levels.index(event.get("severity", "info"))
        min_level = levels.index(self.min_severity)
        return event_level <= min_level

    def _build_wazuh_payload(self, event: dict) -> dict:
        # TODO (Phase 2): translate a SecurityEvent into the Wazuh API event format
        # Include: rule level, description, source tool, affected resource
        raise NotImplementedError
