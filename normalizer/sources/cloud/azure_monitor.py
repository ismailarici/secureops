"""
Azure Monitor Activity Log ingestor — fetches subscription-level activity
log events and normalises them into SecurityEvent objects.

Requires:
    pip install azure-mgmt-monitor azure-identity

Credentials: DefaultAzureCredential reads from environment variables:
    AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID
  or from az CLI login (az login).

Configuration keys (from config.yaml):
    ingestors.azure_monitor.subscription_id
    ingestors.azure_monitor.max_results   (default: 100)
"""

import logging
import uuid
from datetime import datetime, timezone

log = logging.getLogger(__name__)

# ARM operation name prefixes that carry HIGH severity
_HIGH_OPERATIONS = {
    "delete", "remove", "revoke", "disable",
    "Microsoft.Authorization/roleAssignments/write",
    "Microsoft.Authorization/roleAssignments/delete",
    "Microsoft.Network/networkSecurityGroups/securityRules/write",
    "Microsoft.KeyVault/vaults/delete",
    "Microsoft.Compute/virtualMachines/deallocate",
    "Microsoft.Compute/virtualMachines/delete",
}


def _classify_severity(operation: str, status: str) -> str:
    op_lower = operation.lower()
    if any(kw in op_lower for kw in ("delete", "remove", "revoke", "disable")):
        return "high"
    if "roleassignment" in op_lower or "authorization" in op_lower:
        return "high"
    if status.lower() == "failed":
        return "medium"
    return "info"


def _safe_str(val) -> str | None:
    if val is None:
        return None
    if hasattr(val, "value"):
        return str(val.value)
    return str(val)


def fetch(config: dict, since: datetime, until: datetime) -> list[dict]:
    """
    Fetch Azure Monitor Activity Log events for the configured subscription.
    Returns a list of normalised SecurityEvents.
    """
    try:
        from azure.mgmt.monitor import MonitorManagementClient
        from azure.identity import DefaultAzureCredential
    except ImportError:
        raise ImportError(
            "azure-mgmt-monitor and azure-identity are required for the Azure Monitor ingestor: "
            "pip install azure-mgmt-monitor azure-identity"
        )

    subscription_id = config.get("subscription_id", "")
    max_results = int(config.get("max_results", 100))
    environment = config.get("environment")

    if not subscription_id:
        raise ValueError("ingestors.azure_monitor.subscription_id is required")

    credential = DefaultAzureCredential()
    client = MonitorManagementClient(credential, subscription_id)

    since_str = since.strftime("%Y-%m-%dT%H:%M:%S")
    until_str = until.strftime("%Y-%m-%dT%H:%M:%S")
    filter_str = f"eventTimestamp ge '{since_str}' and eventTimestamp le '{until_str}'"

    log.info("Azure Monitor: fetching activity log for subscription %s since %s", subscription_id, since_str)

    try:
        raw_events = list(client.activity_logs.list(filter=filter_str, select=None))
    except Exception as e:
        raise RuntimeError(f"Azure Monitor activity_logs.list failed: {e}") from e

    events = []
    now = datetime.now(timezone.utc).isoformat()

    for evt in raw_events[:max_results]:
        operation = _safe_str(evt.operation_name) or ""
        status = _safe_str(evt.status) or "Unknown"
        caller = getattr(evt, "caller", None) or ""
        resource_id = getattr(evt, "resource_id", None) or ""
        ts = getattr(evt, "event_timestamp", None)
        if ts:
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            timestamp = ts.isoformat()
        else:
            timestamp = now
        description = _safe_str(getattr(evt, "description", None))
        outcome = "failure" if status.lower() == "failed" else "success"
        severity = _classify_severity(operation, status)

        events.append({
            "event_id": str(uuid.uuid4()),
            "timestamp": timestamp,
            "ingested_at": now,
            "schema_version": "1.0",
            "source": {
                "component": "cloud",
                "tool": "azure-monitor",
                "environment": environment,
                "cloud_provider": "azure",
                "region": _safe_str(getattr(evt, "resource_group_name", None)),
                "account_id": subscription_id,
            },
            "event_type": "cloud_event",
            "severity": severity,
            "title": f"{operation} by {caller}" if caller else operation,
            "description": description or None,
            "tags": ["azure-monitor", "azure"],
            "payload": {
                "action": operation or None,
                "actor": caller or None,
                "resource": str(resource_id)[:300] if resource_id else None,
                "source_ip": None,
                "user_agent": None,
                "outcome": outcome,
            },
            "raw": {"operation": operation, "status": status, "caller": caller},
        })

    log.info("Azure Monitor: normalised %d events", len(events))
    return events
