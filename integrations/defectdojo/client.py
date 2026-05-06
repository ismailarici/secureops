"""
DefectDojo integration — pushes vulnerability findings via the DefectDojo REST API.

Flow per finding:
  1. Look up or create the configured product
  2. Look up or create a "SecureOps Import" engagement on that product
  3. Look up or create a "SecureOps" test inside the engagement
  4. POST the finding

Only events with event_type == "vulnerability" are processed.

Configuration keys (from config.yaml):
    integrations.defectdojo.url
    integrations.defectdojo.api_token
    integrations.defectdojo.default_product_name
    integrations.defectdojo.auto_close_resolved
"""

import logging

import requests

log = logging.getLogger(__name__)

_ENGAGEMENT_NAME = "SecureOps Import"
_TEST_TITLE = "SecureOps"
_TEST_TYPE_NAME = "Manual Code Review"  # nearest built-in type for custom findings


_SEVERITY_MAP = {
    "critical": "S0",
    "high": "S1",
    "medium": "S2",
    "low": "S3",
    "info": "S4",
    "informational": "S4",
}


class DefectDojoClient:
    def __init__(self, config: dict) -> None:
        self._base = config.get("url", "").rstrip("/")
        self._token = config.get("api_token", "")
        self._product_name = config.get("default_product_name", "")
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Token {self._token}",
            "Content-Type": "application/json",
        })
        self._product_id: int | None = None
        self._engagement_id: int | None = None
        self._test_id: int | None = None
        self._test_type_id: int | None = None

    # ── API helpers ──────────────────────────────────────────────────────────

    def _get(self, path: str, params: dict | None = None) -> dict:
        resp = self._session.get(f"{self._base}{path}", params=params, timeout=15)
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, payload: dict) -> dict:
        resp = self._session.post(f"{self._base}{path}", json=payload, timeout=15)
        resp.raise_for_status()
        return resp.json()

    # ── Setup ────────────────────────────────────────────────────────────────

    def _get_or_create_product_type(self) -> int:
        type_name = "SecureOps"
        results = self._get("/api/v2/product_types/", {"name": type_name}).get("results", [])
        if results:
            return results[0]["id"]
        data = self._post("/api/v2/product_types/", {"name": type_name})
        log.info("DefectDojo: created product type '%s' (id=%s)", type_name, data["id"])
        return data["id"]

    def _get_or_create_product(self) -> int:
        results = self._get("/api/v2/products/", {"name": self._product_name}).get("results", [])
        if results:
            return results[0]["id"]
        prod_type_id = self._get_or_create_product_type()
        data = self._post("/api/v2/products/", {
            "name": self._product_name,
            "description": "Managed by SecureOps",
            "prod_type": prod_type_id,
        })
        log.info("DefectDojo: created product '%s' (id=%s)", self._product_name, data["id"])
        return data["id"]

    def _get_or_create_engagement(self, product_id: int) -> int:
        results = self._get("/api/v2/engagements/", {
            "product": product_id,
            "name": _ENGAGEMENT_NAME,
            "status": "In Progress",
        }).get("results", [])
        if results:
            return results[0]["id"]
        from datetime import date
        data = self._post("/api/v2/engagements/", {
            "name": _ENGAGEMENT_NAME,
            "product": product_id,
            "status": "In Progress",
            "engagement_type": "CI/CD",
            "target_start": str(date.today()),
            "target_end": str(date.today()),
        })
        log.info("DefectDojo: created engagement (id=%s)", data["id"])
        return data["id"]

    def _get_or_create_test(self, engagement_id: int) -> int:
        results = self._get("/api/v2/tests/", {
            "engagement": engagement_id,
            "title": _TEST_TITLE,
        }).get("results", [])
        if results:
            self._test_type_id = results[0]["test_type"]
            return results[0]["id"]
        type_results = self._get("/api/v2/test_types/", {"name": _TEST_TYPE_NAME}).get("results", [])
        self._test_type_id = type_results[0]["id"] if type_results else 1
        from datetime import date
        data = self._post("/api/v2/tests/", {
            "engagement": engagement_id,
            "title": _TEST_TITLE,
            "test_type": self._test_type_id,
            "target_start": f"{date.today()}T00:00:00Z",
            "target_end": f"{date.today()}T23:59:59Z",
        })
        log.info("DefectDojo: created test (id=%s)", data["id"])
        return data["id"]

    def _ensure_ids(self) -> None:
        if self._test_id:
            return
        self._product_id = self._get_or_create_product()
        self._engagement_id = self._get_or_create_engagement(self._product_id)
        self._test_id = self._get_or_create_test(self._engagement_id)

    # ── Finding creation ─────────────────────────────────────────────────────

    def push_finding(self, event: dict) -> None:
        if event.get("event_type") != "vulnerability":
            return
        try:
            self._ensure_ids()
            payload = self._build_finding(event)
            self._post("/api/v2/findings/", payload)
            log.debug("DefectDojo: pushed finding for event %s", event.get("event_id"))
        except requests.exceptions.RequestException as e:
            log.error("DefectDojo: failed to push finding: %s", e)

    def send_events(self, events: list[dict]) -> None:
        for event in events:
            self.push_finding(event)

    def _build_finding(self, event: dict) -> dict:
        payload = event.get("payload", {})
        sev = event.get("severity", "info").lower()
        return {
            "test": self._test_id,
            "found_by": [self._test_type_id],
            "title": event.get("title", "")[:500],
            "severity": sev.capitalize(),
            "numerical_severity": _SEVERITY_MAP.get(sev, "S4"),
            "description": event.get("description") or event.get("title", ""),
            "mitigation": payload.get("remediation") or "See finding description.",
            "references": "\n".join(payload.get("references") or []),
            "file_path": payload.get("affected_file") or "",
            "line": payload.get("affected_line"),
            "component_name": payload.get("affected_package") or "",
            "component_version": payload.get("affected_version") or "",
            "cve": payload.get("cve_id") or "",
            "cwe": int((payload.get("cwe_id") or "CWE-0").replace("CWE-", "") or 0) or None,
            "active": True,
            "verified": False,
            "false_p": False,
            "duplicate": False,
            "out_of_scope": False,
        }
