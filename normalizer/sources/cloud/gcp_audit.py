"""
GCP Audit Logs ingestor — fetches Admin Activity and Data Access audit log
entries from Cloud Logging and normalises them into SecurityEvent objects.

Requires: google-cloud-logging (pip install google-cloud-logging)
Credentials: GOOGLE_APPLICATION_CREDENTIALS env var pointing to a service
  account JSON key, or Application Default Credentials (gcloud auth application-default login).

Configuration keys (from config.yaml):
    ingestors.gcp_audit.project_id
    ingestors.gcp_audit.max_results   (default: 100)
"""

import logging
import uuid
from datetime import datetime, timezone

log = logging.getLogger(__name__)

# Method names that carry HIGH severity
_HIGH_METHODS = {
    "delete", "remove", "revoke", "detach", "disable",
    "createServiceAccount", "deleteServiceAccount",
    "setIamPolicy", "bindRole",
}


def _classify_severity(method_name: str, status_code: int) -> str:
    method_lower = method_name.lower()
    if any(kw in method_lower for kw in _HIGH_METHODS):
        return "high"
    if status_code not in (0, 200, 201, 204):
        return "medium"
    return "info"


def _parse_timestamp(ts) -> str:
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts.isoformat()
    return str(ts)


def fetch(config: dict, since: datetime, until: datetime) -> list[dict]:
    """
    Fetch GCP audit log entries for the configured project between since and until.
    Returns a list of normalised SecurityEvents.
    """
    try:
        from google.cloud import logging_v2
    except ImportError:
        raise ImportError(
            "google-cloud-logging is required for the GCP Audit Logs ingestor: "
            "pip install google-cloud-logging"
        )

    project_id = config.get("project_id", "")
    max_results = int(config.get("max_results", 100))
    environment = config.get("environment")

    if not project_id:
        raise ValueError("ingestors.gcp_audit.project_id is required")

    client = logging_v2.Client(project=project_id)
    since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")
    until_str = until.strftime("%Y-%m-%dT%H:%M:%SZ")
    filter_str = (
        'protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog" '
        f'AND timestamp>="{since_str}" AND timestamp<="{until_str}"'
    )

    log.info("GCP Audit Logs: fetching from project %s since %s", project_id, since_str)

    try:
        entries = list(client.list_entries(
            filter_=filter_str,
            page_size=max_results,
            order_by=logging_v2.DESCENDING,
            max_results=max_results,
        ))
    except Exception as e:
        raise RuntimeError(f"GCP list_entries failed: {e}") from e

    events = []
    now = datetime.now(timezone.utc).isoformat()

    for entry in entries:
        payload = entry.payload if hasattr(entry, "payload") else {}
        if not isinstance(payload, dict):
            payload = {}

        auth_info = payload.get("authenticationInfo", {})
        request_meta = payload.get("requestMetadata", {})
        status = payload.get("status", {})

        method_name = payload.get("methodName", "")
        service_name = payload.get("serviceName", "")
        resource_name = payload.get("resourceName", "")
        principal = auth_info.get("principalEmail", "")
        source_ip = request_meta.get("callerIp", "")
        user_agent = request_meta.get("callerSuppliedUserAgent", "")
        status_code = status.get("code", 0)
        outcome = "failure" if status_code not in (0, 200) else "success"
        severity = _classify_severity(method_name, status_code)

        events.append({
            "event_id": str(uuid.uuid4()),
            "timestamp": _parse_timestamp(entry.timestamp),
            "ingested_at": now,
            "schema_version": "1.0",
            "source": {
                "component": "cloud",
                "tool": "gcp-audit",
                "environment": environment,
                "cloud_provider": "gcp",
                "region": None,
                "account_id": project_id,
            },
            "event_type": "cloud_event",
            "severity": severity,
            "title": f"{method_name} by {principal}" if principal else method_name,
            "description": status.get("message") or None,
            "tags": ["gcp-audit", "gcp"],
            "payload": {
                "action": f"{service_name}/{method_name}" if service_name else method_name,
                "actor": principal or None,
                "resource": resource_name or None,
                "source_ip": source_ip or None,
                "user_agent": user_agent or None,
                "outcome": outcome,
            },
            "raw": payload,
        })

    log.info("GCP Audit Logs: normalised %d events", len(events))
    return events
