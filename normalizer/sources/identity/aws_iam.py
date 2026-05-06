"""
AWS IAM event ingestor — fetches IAM-specific events from CloudTrail
(service: iam.amazonaws.com) and normalises them into SecurityEvent objects
with event_type: identity_event.

Requires: boto3 (pip install boto3)
Credentials: standard AWS credential chain.

Configuration keys (from config.yaml):
    ingestors.aws_iam.region
    ingestors.aws_iam.account_id
    ingestors.aws_iam.max_results   (default: 50)

This is a specialised view of CloudTrail focused on IAM changes.
For broad CloudTrail coverage, use the cloudtrail ingestor instead.
"""

import json
import logging
import uuid
from datetime import datetime, timezone

log = logging.getLogger(__name__)

# IAM actions that carry HIGH severity — privilege changes, credential creation
_HIGH_IAM_ACTIONS = {
    "CreateUser", "DeleteUser",
    "CreateAccessKey", "DeleteAccessKey", "UpdateAccessKey",
    "AttachUserPolicy", "DetachUserPolicy",
    "AttachRolePolicy", "DetachRolePolicy",
    "PutUserPolicy", "DeleteUserPolicy",
    "PutRolePolicy", "DeleteRolePolicy",
    "CreateLoginProfile", "UpdateLoginProfile", "DeleteLoginProfile",
    "AddUserToGroup", "RemoveUserFromGroup",
    "CreateRole", "DeleteRole",
    "AssumeRole", "AssumeRoleWithWebIdentity",
    "UpdateAssumeRolePolicy",
    "EnableMFADevice", "DeactivateMFADevice",
    "CreateVirtualMFADevice", "DeleteVirtualMFADevice",
}


def _classify_severity(action: str, error_code: str | None) -> str:
    if action in _HIGH_IAM_ACTIONS:
        return "high"
    if error_code:
        return "medium"
    return "info"


def fetch(config: dict, since: datetime, until: datetime) -> list[dict]:
    """
    Fetch IAM-scoped CloudTrail events between since and until.
    Returns a list of normalised SecurityEvents (event_type: identity_event).
    """
    try:
        import boto3
    except ImportError:
        raise ImportError("boto3 is required for the AWS IAM ingestor: pip install boto3")

    region = config.get("region", "us-east-1")
    account_id = config.get("account_id")
    max_results = int(config.get("max_results", 50))
    environment = config.get("environment")

    client = boto3.client("cloudtrail", region_name=region)
    log.info("AWS IAM: fetching CloudTrail IAM events from %s since %s", region, since.isoformat())

    try:
        response = client.lookup_events(
            StartTime=since,
            EndTime=until,
            MaxResults=max_results,
            LookupAttributes=[{"AttributeKey": "EventSource", "AttributeValue": "iam.amazonaws.com"}],
        )
    except Exception as e:
        raise RuntimeError(f"CloudTrail lookup_events (IAM) failed: {e}") from e

    events = []
    now = datetime.now(timezone.utc).isoformat()

    for raw_event in response.get("Events", []):
        ct = json.loads(raw_event.get("CloudTrailEvent", "{}"))
        action = raw_event.get("EventName", "")
        username = raw_event.get("Username") or ct.get("userIdentity", {}).get("arn", "")
        error_code = ct.get("errorCode")
        request_params = ct.get("requestParameters") or {}
        # Determine the affected IAM principal (the target of the action)
        target = (
            request_params.get("userName")
            or request_params.get("roleName")
            or request_params.get("groupName")
            or None
        )
        source_ip = ct.get("sourceIPAddress", "")
        ts = raw_event.get("EventTime")
        if isinstance(ts, datetime):
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            timestamp = ts.isoformat()
        else:
            timestamp = now
        severity = _classify_severity(action, error_code)
        outcome = "failure" if error_code else "success"

        events.append({
            "event_id": str(uuid.uuid4()),
            "timestamp": timestamp,
            "ingested_at": now,
            "schema_version": "1.0",
            "source": {
                "component": "identity",
                "tool": "aws-iam",
                "environment": environment,
                "cloud_provider": "aws",
                "region": region,
                "account_id": account_id,
            },
            "event_type": "identity_event",
            "severity": severity,
            "title": f"{action} by {username}" if username else action,
            "description": f"Error: {error_code}" if error_code else None,
            "tags": ["aws-iam", "identity", "cloudtrail"],
            "payload": {
                "action": action,
                "actor": username or None,
                "target": target,
                "outcome": outcome,
                "source_ip": source_ip or None,
                "mfa_used": ct.get("userIdentity", {}).get("sessionContext", {})
                               .get("mfaAuthenticated") == "true",
            },
            "raw": ct,
        })

    log.info("AWS IAM: normalised %d events", len(events))
    return events
