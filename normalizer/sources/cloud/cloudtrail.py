"""
AWS CloudTrail ingestor — fetches management events from CloudTrail
and normalises them into SecurityEvent objects (event_type: cloud_event).

Requires: boto3 (pip install boto3)
Credentials: standard AWS credential chain
  (env vars AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY, IAM role, ~/.aws/credentials)

Configuration keys (from config.yaml):
    ingestors.cloudtrail.region
    ingestors.cloudtrail.account_id
    ingestors.cloudtrail.max_results   (default: 50)
    ingestors.cloudtrail.high_severity_actions  (optional list of action prefixes)
"""

import json
import logging
import uuid
from datetime import datetime, timezone

log = logging.getLogger(__name__)

# Actions that warrant HIGH severity regardless of outcome.
# Destructive, privilege-escalating, or security-relevant.
_HIGH_ACTIONS = {
    "DeleteBucket", "DeleteObject", "DeleteTable", "DeleteCluster",
    "TerminateInstances", "StopInstances", "DeleteSecurityGroup",
    "CreateUser", "DeleteUser", "AttachUserPolicy", "DetachUserPolicy",
    "AttachRolePolicy", "DetachRolePolicy", "PutUserPolicy", "PutRolePolicy",
    "CreateAccessKey", "DeleteAccessKey",
    "AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress",
    "RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress",
    "ModifyInstanceAttribute", "PutBucketPolicy", "DeleteBucketPolicy",
    "UpdateAssumeRolePolicy", "CreateLoginProfile",
}

_MEDIUM_ACTIONS = {"ConsoleLogin"}


def _classify_severity(event_name: str, error_code: str | None) -> str:
    if event_name in _HIGH_ACTIONS:
        return "high"
    if event_name in _MEDIUM_ACTIONS:
        return "high" if error_code else "info"
    if error_code:
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
    Fetch CloudTrail management events between since and until.
    Returns a list of normalised SecurityEvents.
    """
    try:
        import boto3
    except ImportError:
        raise ImportError("boto3 is required for the CloudTrail ingestor: pip install boto3")

    region = config.get("region", "us-east-1")
    account_id = config.get("account_id")
    max_results = int(config.get("max_results", 50))
    environment = config.get("environment")

    client = boto3.client("cloudtrail", region_name=region)
    log.info("CloudTrail: fetching up to %d events from %s (%s)", max_results, region, since.isoformat())

    try:
        response = client.lookup_events(
            StartTime=since,
            EndTime=until,
            MaxResults=max_results,
        )
    except Exception as e:
        raise RuntimeError(f"CloudTrail lookup_events failed: {e}") from e

    events = []
    now = datetime.now(timezone.utc).isoformat()

    for raw_event in response.get("Events", []):
        ct = json.loads(raw_event.get("CloudTrailEvent", "{}"))
        event_name = raw_event.get("EventName", "")
        username = raw_event.get("Username") or ct.get("userIdentity", {}).get("arn", "")
        source_ip = ct.get("sourceIPAddress", "")
        user_agent = ct.get("userAgent", "")
        error_code = ct.get("errorCode")
        resources = raw_event.get("Resources") or []
        resource = resources[0].get("ResourceName", "") if resources else ct.get("requestParameters", {})
        if isinstance(resource, dict):
            resource = json.dumps(resource)[:200]

        outcome = "failure" if error_code else "success"
        severity = _classify_severity(event_name, error_code)

        events.append({
            "event_id": str(uuid.uuid4()),
            "timestamp": _parse_timestamp(raw_event.get("EventTime")),
            "ingested_at": now,
            "schema_version": "1.0",
            "source": {
                "component": "cloud",
                "tool": "cloudtrail",
                "environment": environment,
                "cloud_provider": "aws",
                "region": region,
                "account_id": account_id,
            },
            "event_type": "cloud_event",
            "severity": severity,
            "title": f"{event_name} by {username}" if username else event_name,
            "description": f"Error: {error_code}" if error_code else None,
            "tags": ["cloudtrail", "aws"],
            "payload": {
                "action": event_name,
                "actor": username or None,
                "resource": str(resource) or None,
                "source_ip": source_ip or None,
                "user_agent": user_agent or None,
                "outcome": outcome,
            },
            "raw": ct,
        })

    log.info("CloudTrail: normalised %d events", len(events))
    return events
