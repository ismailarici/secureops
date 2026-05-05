# Security Event Schema — v1

All inputs to SecureOps — regardless of source — are normalised into this schema before any routing, alerting, or storage takes place. This is the single contract between the normaliser and every downstream integration.

The JSON Schema definition lives at [`normalizer/schemas/event.schema.json`](../normalizer/schemas/event.schema.json).

---

## Top-level fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `event_id` | string (UUID) | Yes | Globally unique identifier for this event |
| `timestamp` | string (ISO 8601) | Yes | When the event occurred (UTC) |
| `ingested_at` | string (ISO 8601) | Yes | When SecureOps received the event |
| `schema_version` | string | Yes | Schema version — currently `"1.0"` |
| `source` | object | Yes | Where this event came from |
| `event_type` | string (enum) | Yes | Top-level event category |
| `severity` | string (enum) | Yes | `critical` \| `high` \| `medium` \| `low` \| `info` |
| `title` | string | Yes | Short human-readable summary |
| `description` | string | No | Full detail |
| `tags` | array of strings | No | Free-form labels for filtering and grouping |
| `payload` | object | Yes | Event-type-specific fields (see below) |
| `raw` | object | No | Original unmodified input — preserved for audit purposes |

---

## Source object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `component` | string (enum) | Yes | `securepipe` \| `secureinfra` \| `cloud` \| `identity` \| `system` |
| `tool` | string | Yes | The specific tool that produced the finding (e.g. `semgrep`, `trivy`, `cloudtrail`) |
| `environment` | string | No | Environment name from config (e.g. `production`, `staging`) |
| `cloud_provider` | string (enum) | No | `aws` \| `gcp` \| `azure` \| `on-prem` — null if not applicable |
| `region` | string | No | Cloud region, if applicable |
| `account_id` | string | No | Cloud account or project ID, if applicable |

---

## Event types and payloads

### `vulnerability`

Produced by SecurePipe (SAST, SCA, container scan) or SecureInfra (host scan).

| Field | Type | Description |
|-------|------|-------------|
| `cve_id` | string | CVE identifier, if applicable |
| `cwe_id` | string | CWE identifier, if applicable |
| `affected_file` | string | Source file or package where the issue was found |
| `affected_line` | integer | Line number, if applicable |
| `affected_package` | string | Package name, if a dependency issue |
| `affected_version` | string | Installed version of the affected package |
| `fixed_version` | string | Version that resolves the issue, if known |
| `remediation` | string | Short remediation guidance |
| `references` | array of strings | Links to advisories, CVE entries, etc. |

### `cloud_event`

Produced by cloud provider audit logs (CloudTrail, GCP Audit Logs, Azure Monitor).

| Field | Type | Description |
|-------|------|-------------|
| `action` | string | API call or action name (e.g. `s3:GetObject`, `compute.instances.create`) |
| `actor` | string | IAM user, service account, or principal |
| `resource` | string | Affected resource ARN, name, or ID |
| `source_ip` | string | IP address of the caller |
| `user_agent` | string | User agent string from the API call |
| `outcome` | string | `success` \| `failure` |

### `identity_event`

Produced by identity providers (Okta, Azure AD, AWS IAM).

| Field | Type | Description |
|-------|------|-------------|
| `action` | string | e.g. `login`, `mfa_bypass`, `role_assigned`, `password_reset` |
| `actor` | string | User or service that performed the action |
| `target` | string | User, group, or resource the action was applied to |
| `outcome` | string | `success` \| `failure` |
| `source_ip` | string | IP address of the actor |
| `mfa_used` | boolean | Whether MFA was used |

### `system_event`

Produced by host and OS-level sources (Wazuh agent, syslog, auditd).

| Field | Type | Description |
|-------|------|-------------|
| `hostname` | string | Host where the event occurred |
| `process` | string | Process name or PID |
| `action` | string | e.g. `file_modified`, `process_created`, `network_connection` |
| `target_path` | string | File path, if applicable |
| `destination_ip` | string | Remote IP, for network events |
| `destination_port` | integer | Remote port, for network events |
| `rule_id` | string | Detection rule that triggered this event |

---

## Example: vulnerability event

```json
{
  "event_id": "a3f1c2d4-0001-4b5e-9f3a-1234abcd5678",
  "timestamp": "2026-05-05T10:30:00Z",
  "ingested_at": "2026-05-05T10:30:05Z",
  "schema_version": "1.0",
  "source": {
    "component": "securepipe",
    "tool": "semgrep",
    "environment": "production",
    "cloud_provider": "aws",
    "region": "us-east-1",
    "account_id": "123456789012"
  },
  "event_type": "vulnerability",
  "severity": "high",
  "title": "SQL injection in users.py:42",
  "description": "User-controlled input passed directly to a SQL query without parameterisation.",
  "tags": ["sast", "injection", "owasp-a03"],
  "payload": {
    "cwe_id": "CWE-89",
    "affected_file": "app/users.py",
    "affected_line": 42,
    "remediation": "Use parameterised queries or an ORM.",
    "references": ["https://cwe.mitre.org/data/definitions/89.html"]
  },
  "raw": {}
}
```

---

## Versioning

The schema version is tracked in the `schema_version` field. Breaking changes increment the major version. Additive changes (new optional fields) increment the minor version. Downstream integrations must handle unknown fields gracefully.
