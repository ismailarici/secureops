"""
normalizer — converts raw tool outputs into normalised SecurityEvent objects.

Each supported source has its own normaliser function that maps the tool's
native output format to the canonical event schema defined in
normalizer/schemas/event.schema.json.

Supported sources (Phase 2):
    - securepipe: semgrep, trivy, pip-audit, npm-audit, zap
    - secureinfra: (planned)
    - cloud: cloudtrail, gcp-audit-logs, azure-monitor (planned)
    - identity: okta, azure-ad, aws-iam (planned)
    - system: wazuh-agent, syslog (planned)
"""
