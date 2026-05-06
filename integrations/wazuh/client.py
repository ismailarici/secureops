"""
Wazuh integration — forwards normalised SecurityEvents to a Wazuh manager
via the Wazuh REST API (v4.2+).

Auth:  POST /security/user/authenticate  (Basic auth) → JWT token
Send:  POST /events                      (Bearer token) → log ingestion

Configuration keys (from config.yaml):
    integrations.wazuh.url
    integrations.wazuh.port
    integrations.wazuh.username
    integrations.wazuh.password
    integrations.wazuh.min_severity
"""

import json
import logging

import requests
from requests.auth import HTTPBasicAuth

log = logging.getLogger(__name__)

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


class WazuhClient:
    def __init__(self, config: dict) -> None:
        base = config.get("url", "").rstrip("/")
        port = config.get("port", 55000)
        self._base_url = f"{base}:{port}"
        self._username = config.get("username", "")
        self._password = config.get("password", "")
        self._min_severity = config.get("min_severity", "medium")
        self._token: str | None = None

    def _authenticate(self) -> None:
        url = f"{self._base_url}/security/user/authenticate"
        try:
            resp = requests.post(
                url,
                auth=HTTPBasicAuth(self._username, self._password),
                verify=True,
                timeout=10,
            )
            resp.raise_for_status()
            self._token = resp.json()["data"]["token"]
            log.debug("Wazuh: authenticated successfully")
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Wazuh authentication failed: {e}") from e

    def _headers(self) -> dict:
        if not self._token:
            self._authenticate()
        return {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}

    def _post_events(self, payload: dict) -> None:
        url = f"{self._base_url}/events"
        try:
            resp = requests.post(url, json=payload, headers=self._headers(), timeout=10)
            if resp.status_code == 401:
                # Token expired — re-auth once and retry
                self._token = None
                resp = requests.post(url, json=payload, headers=self._headers(), timeout=10)
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Wazuh event POST failed: {e}") from e

    def send_event(self, event: dict) -> None:
        if not self._should_send(event):
            return
        # Wazuh /events expects a list of plain strings — we send the event as a JSON string
        log_line = json.dumps({
            "secureops": True,
            "event_id": event.get("event_id"),
            "source": event.get("source", {}),
            "event_type": event.get("event_type"),
            "severity": event.get("severity"),
            "title": event.get("title"),
        }, separators=(",", ":"))
        self._post_events({"events": [log_line]})
        log.debug("Wazuh: sent event %s", event.get("event_id"))

    def send_events(self, events: list[dict]) -> None:
        for event in events:
            self.send_event(event)

    def _should_send(self, event: dict) -> bool:
        try:
            return SEVERITY_ORDER.index(event.get("severity", "info")) <= SEVERITY_ORDER.index(self._min_severity)
        except ValueError:
            return True
