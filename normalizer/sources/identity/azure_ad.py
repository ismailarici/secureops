"""
Azure AD audit log ingestor — fetches sign-in and audit events from the
Microsoft Graph API and normalises them into SecurityEvent objects.

Requires: requests (already a core dependency)
Auth: client credentials flow using:
    AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID environment variables
  or via config.

Configuration keys (from config.yaml):
    ingestors.azure_ad.tenant_id
    ingestors.azure_ad.client_id
    ingestors.azure_ad.client_secret   (prefer AZURE_CLIENT_SECRET env var)
    ingestors.azure_ad.max_results     (default: 100)

Graph API: https://learn.microsoft.com/en-us/graph/api/signin-list
"""

import logging
import os
import uuid
from datetime import datetime, timezone

import requests

log = logging.getLogger(__name__)

_TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
_GRAPH_SIGNINS_URL = "https://graph.microsoft.com/v1.0/auditLogs/signIns"
_GRAPH_AUDIT_URL = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits"

# Error codes that indicate suspicious/failed authentication
_HIGH_ERROR_CODES = {50053, 50126, 53003, 50097}  # account locked, invalid creds, CA block, MFA required but not done
_MEDIUM_ERROR_CODES = {50055, 50056, 50058, 50059, 50074, 50076, 50079}  # various auth failures


def _classify_severity(error_code: int, conditional_access: str) -> str:
    if error_code in _HIGH_ERROR_CODES:
        return "high"
    if error_code in _MEDIUM_ERROR_CODES:
        return "medium"
    if conditional_access == "failure":
        return "medium"
    if error_code != 0:
        return "medium"
    return "info"


def _get_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    resp = requests.post(
        _TOKEN_URL.format(tenant_id=tenant_id),
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://graph.microsoft.com/.default",
        },
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def fetch(config: dict, since: datetime, until: datetime) -> list[dict]:
    """
    Fetch Azure AD sign-in log events between since and until.
    Returns a list of normalised SecurityEvents.
    """
    tenant_id = config.get("tenant_id") or os.environ.get("AZURE_TENANT_ID", "")
    client_id = config.get("client_id") or os.environ.get("AZURE_CLIENT_ID", "")
    client_secret = config.get("client_secret") or os.environ.get("AZURE_CLIENT_SECRET", "")
    max_results = int(config.get("max_results", 100))
    environment = config.get("environment")

    for name, val in [("tenant_id", tenant_id), ("client_id", client_id), ("client_secret", client_secret)]:
        if not val:
            raise ValueError(
                f"Azure AD ingestor: {name} is required — set ingestors.azure_ad.{name} "
                f"or AZURE_{name.upper()} env var"
            )

    log.info("Azure AD: fetching sign-in logs for tenant %s since %s", tenant_id, since.isoformat())

    try:
        token = _get_token(tenant_id, client_id, client_secret)
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Azure AD token acquisition failed: {e}") from e

    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")
    params = {
        "$filter": f"createdDateTime ge {since_str}",
        "$top": min(max_results, 1000),
        "$orderby": "createdDateTime desc",
    }

    try:
        resp = requests.get(_GRAPH_SIGNINS_URL, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        raw_events = resp.json().get("value", [])
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Azure AD sign-ins API request failed: {e}") from e

    events = []
    now = datetime.now(timezone.utc).isoformat()

    for raw in raw_events[:max_results]:
        status = raw.get("status", {})
        error_code = status.get("errorCode", 0)
        failure_reason = status.get("failureReason")
        ca_status = raw.get("conditionalAccessStatus", "notApplied")
        upn = raw.get("userPrincipalName", "")
        app = raw.get("appDisplayName", "")
        ip = raw.get("ipAddress", "")
        mfa_detail = raw.get("mfaDetail") or {}
        mfa_used = bool(mfa_detail.get("authMethod"))
        severity = _classify_severity(error_code, ca_status)
        outcome = "success" if error_code == 0 else "failure"

        events.append({
            "event_id": str(uuid.uuid4()),
            "timestamp": raw.get("createdDateTime", now),
            "ingested_at": now,
            "schema_version": "1.0",
            "source": {
                "component": "identity",
                "tool": "azure-ad",
                "environment": environment,
                "cloud_provider": "azure",
                "region": None,
                "account_id": tenant_id,
            },
            "event_type": "identity_event",
            "severity": severity,
            "title": f"Sign-in by {upn} to {app}" if app else f"Sign-in by {upn}",
            "description": failure_reason or None,
            "tags": ["azure-ad", "identity", "signin"],
            "payload": {
                "action": "login",
                "actor": upn or None,
                "target": app or None,
                "outcome": outcome,
                "source_ip": ip or None,
                "mfa_used": mfa_used,
            },
            "raw": {k: v for k, v in raw.items()},
        })

    log.info("Azure AD: normalised %d events", len(events))
    return events
