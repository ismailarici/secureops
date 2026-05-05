"""
DefectDojo integration — pushes vulnerability findings to DefectDojo
via its REST API.

Only processes events with event_type == "vulnerability".
Other event types are silently ignored.

Configuration keys (from config.yaml):
    integrations.defectdojo.url
    integrations.defectdojo.api_token
    integrations.defectdojo.default_product_name
    integrations.defectdojo.auto_close_resolved
"""

import logging

log = logging.getLogger(__name__)


class DefectDojoClient:
    def __init__(self, config: dict) -> None:
        self.url = config.get("url", "").rstrip("/")
        self.api_token = config.get("api_token", "")
        self.default_product_name = config.get("default_product_name", "")
        self.auto_close_resolved = config.get("auto_close_resolved", True)
        # TODO (Phase 2): initialise HTTP session with Authorization header
        self._session = None

    def _get_or_create_engagement(self, product_name: str, scan_label: str) -> int:
        # TODO (Phase 2): look up the product ID by name, then create or reuse an engagement
        # Endpoint: GET /api/v2/products/?name=<product_name>
        #           POST /api/v2/engagements/
        raise NotImplementedError

    def push_finding(self, event: dict) -> None:
        """Push a single vulnerability event to DefectDojo as a finding."""
        if event.get("event_type") != "vulnerability":
            return
        # TODO (Phase 2): map SecurityEvent to DefectDojo finding payload
        # POST /api/v2/findings/
        # Fields: title, severity, description, file_path, line, cve, mitigation
        log.debug("Would push finding %s to DefectDojo", event.get("event_id"))

    def push_findings(self, events: list[dict]) -> None:
        """Push all vulnerability events from a list to DefectDojo."""
        for event in events:
            self.push_finding(event)

    def _severity_to_defectdojo(self, severity: str) -> str:
        # DefectDojo uses: Critical, High, Medium, Low, Info (title case)
        return severity.capitalize()

    def _build_finding_payload(self, event: dict) -> dict:
        # TODO (Phase 2): construct the full DefectDojo finding dict from a SecurityEvent
        raise NotImplementedError
