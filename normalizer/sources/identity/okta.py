"""
Okta System Log ingestor — fetches events from the Okta System Log API
and normalises them into SecurityEvent objects (event_type: identity_event).

Requires: requests (already a core dependency)
Auth: OKTA_API_TOKEN environment variable, or api_token in config.

Configuration keys (from config.yaml):
    ingestors.okta.domain          e.g. your-org.okta.com
    ingestors.okta.api_token       (prefer OKTA_API_TOKEN env var)
    ingestors.okta.max_results     (default: 100)

Okta API reference: https://developer.okta.com/docs/reference/api/system-log/
"""

import logging
import os
import uuid
from datetime import datetime, timezone

import requests

log = logging.getLogger(__name__)

# Event types that carry HIGH severity
_HIGH_EVENT_TYPES = {
    "user.mfa.factor.deactivate",
    "user.account.privilege.grant",
    "user.account.privilege.revoke",
    "policy.lifecycle.update",
    "policy.lifecycle.delete",
    "policy.rule.update",
    "policy.rule.delete",
    "application.lifecycle.delete",
    "user.session.impersonation.initiate",
    "security.attack.start",
    "user.account.lock_out",
}

# Event types that carry MEDIUM severity
_MEDIUM_EVENT_TYPES = {
    "user.authentication.auth_via_mfa",  # only on FAILURE, handled below
    "app.generic.unauth_app_access_attempt",
    "user.authentication.sso",           # only on FAILURE
    "security.request.blocked",
}

# Event types that are definitely just INFO
_INFO_EVENT_TYPES = {
    "user.session.start",
    "user.session.end",
    "user.authentication.auth_via_mfa",
    "user.lifecycle.create",
}


def _classify_severity(event_type: str, outcome: str) -> str:
    if event_type in _HIGH_EVENT_TYPES:
        return "high"
    if outcome == "FAILURE":
        if "mfa" in event_type or "auth" in event_type or "session" in event_type:
            return "medium"
    if "attack" in event_type or "block" in event_type or "unauth" in event_type:
        return "medium"
    return "info"


def fetch(config: dict, since: datetime, until: datetime) -> list[dict]:
    """
    Fetch Okta System Log events between since and until.
    Returns a list of normalised SecurityEvents.
    """
    domain = config.get("domain", "")
    api_token = config.get("api_token") or os.environ.get("OKTA_API_TOKEN", "")
    max_results = int(config.get("max_results", 100))
    environment = config.get("environment")

    if not domain:
        raise ValueError("ingestors.okta.domain is required (e.g. your-org.okta.com)")
    if not api_token:
        raise ValueError("Okta API token required: set ingestors.okta.api_token or OKTA_API_TOKEN env var")

    since_str = since.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    until_str = until.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    url = f"https://{domain}/api/v1/logs"
    headers = {"Authorization": f"SSWS {api_token}", "Accept": "application/json"}
    params = {"since": since_str, "until": until_str, "limit": min(max_results, 1000)}

    log.info("Okta: fetching system log from %s since %s", domain, since_str)

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        raw_events = resp.json()
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Okta System Log API request failed: {e}") from e

    events = []
    now = datetime.now(timezone.utc).isoformat()

    for raw in raw_events[:max_results]:
        event_type = raw.get("eventType", "")
        actor = raw.get("actor", {})
        actor_id = actor.get("alternateId") or actor.get("displayName", "")
        outcome_obj = raw.get("outcome", {})
        outcome = outcome_obj.get("result", "UNKNOWN").upper()
        targets = raw.get("target", [])
        target_id = targets[0].get("alternateId") if targets else None
        ip_chain = (raw.get("request") or {}).get("ipChain", [])
        source_ip = ip_chain[0].get("ip") if ip_chain else None
        auth_context = raw.get("authenticationContext", {})
        mfa_used = auth_context.get("credentialType") in ("PASSWORD_IWA", "FIDO2", "OTP", "SIGNED_NONCE")
        severity = _classify_severity(event_type, outcome)

        events.append({
            "event_id": str(uuid.uuid4()),
            "timestamp": raw.get("published", now),
            "ingested_at": now,
            "schema_version": "1.0",
            "source": {
                "component": "identity",
                "tool": "okta",
                "environment": environment,
                "cloud_provider": None,
                "region": None,
                "account_id": domain,
            },
            "event_type": "identity_event",
            "severity": severity,
            "title": f"{event_type} — {actor_id}" if actor_id else event_type,
            "description": outcome_obj.get("reason") or None,
            "tags": ["okta", "identity", event_type.split(".")[0]],
            "payload": {
                "action": event_type,
                "actor": actor_id or None,
                "target": target_id or None,
                "outcome": "success" if outcome == "SUCCESS" else "failure",
                "source_ip": source_ip,
                "mfa_used": mfa_used,
            },
            "raw": {k: v for k, v in raw.items() if k != "debugContext"},
        })

    log.info("Okta: normalised %d events", len(events))
    return events
