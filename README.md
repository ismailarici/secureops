# SecureOps

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A portable, low-cost, audit-ready security operations layer. SecureOps ingests security findings and events from across your stack, normalises them into a common schema, routes them to the right systems, and produces evidence you can hand to an auditor.

---

## Where SecureOps fits

SecureOps is one component of a three-part modular security platform:

| Component | Scope | What it does |
|-----------|-------|-------------|
| **SecurePipe** | Application security | SAST, SCA, DAST, CI/CD scanning |
| **SecureInfra** | Cloud & infrastructure | Host scanning, cloud posture, network exposure |
| **SecureOps** | Operations & audit | Ingests outputs from the above, normalises events, routes to SIEM/XDR, triggers alerts, produces audit evidence |

SecureOps does **not** run any scans. It only consumes outputs.

```
SecurePipe ──┐
             ├──► SecureOps ──► Wazuh (SIEM/XDR)
SecureInfra ─┤             ──► DefectDojo (vuln tracking)
             │             ──► Slack / Email (alerts)
Cloud logs ──┘             ──► evidence/ (audit artifacts)
Identity logs
System logs
```

---

## What SecureOps does

1. **Ingests** findings and events from SecurePipe, SecureInfra, cloud providers, identity systems, and host logs
2. **Normalises** every input into a single [Security Event Schema](docs/event-schema.md)
3. **Routes** normalised events to Wazuh, DefectDojo, Slack, and email
4. **Stores** audit-ready evidence artifacts in the `evidence/` directory

---

## Design principles

**Portable** — works on AWS, GCP, Azure, and on-premises. No cloud-specific dependencies in core logic.

**Config-driven** — every integration, credential, and behaviour is controlled via `config/`. Nothing is hardcoded.

**Schema-first** — all inputs are normalised to a single schema before any routing or alerting. Adding a new source means writing a normaliser, not touching downstream systems.

**Low-cost** — no Kafka, no heavy pipelines. Python, Docker Compose, and standard open-source tools.

**Loosely coupled** — each integration (`wazuh`, `defectdojo`, `slack`, `email`) is an independent module. Disabling one has no effect on the others.

**Audit-ready** — every event processed produces a timestamped artifact in `evidence/`. Reports are self-contained and can be handed directly to an auditor.

---

## What is implemented

| Area | Status |
|------|--------|
| Project structure and folder layout | ✅ Done |
| Security Event Schema (v1) | ✅ Done |
| Example config file | ✅ Done |
| Normalizer module skeleton | ✅ Done |
| Wazuh integration skeleton | ✅ Done |
| DefectDojo integration skeleton | ✅ Done |
| Slack integration skeleton | ✅ Done |
| Email integration skeleton | ✅ Done |

## What is planned

| Phase | Area | Description |
|-------|------|-------------|
| Phase 2 | Normalizer | Full normalisation logic for SecurePipe and SecureInfra outputs |
| Phase 2 | Wazuh client | HTTP API client — send normalised events as Wazuh alerts |
| Phase 2 | DefectDojo client | Create/update findings via the DefectDojo REST API |
| Phase 2 | Slack client | Post structured alert messages to a configured channel |
| Phase 2 | Email client | Send alert emails via SMTP |
| Phase 3 | Cloud log ingestors | AWS CloudTrail, GCP Audit Logs, Azure Monitor connectors |
| Phase 3 | Identity log ingestors | Okta, Azure AD, AWS IAM event connectors |
| Phase 3 | Evidence packaging | Automated evidence bundle generation for SOC 2 / ISO 27001 |
| Phase 3 | Rules engine | Configurable alert rules (severity thresholds, suppression, dedup) |
| Phase 4 | Deploy | Docker Compose stack for Wazuh + DefectDojo |
| Phase 4 | GitHub Actions | Trigger SecureOps as a step in CI after SecurePipe runs |

---

## Quick start

**Prerequisites:** Python 3.10+, Docker (for integrations).

```bash
git clone https://github.com/your-org/secureops.git
cd secureops
cp config/example.yaml config/config.yaml
# edit config/config.yaml with your credentials
python -m normalizer.main --input examples/securepipe-output.json
```

---

## Repository structure

```
secureops/
├── normalizer/
│   ├── schemas/
│   │   └── event.schema.json       # canonical security event schema
│   ├── __init__.py
│   └── main.py                     # normaliser entry point
├── integrations/
│   ├── wazuh/
│   │   └── client.py               # send events to Wazuh
│   ├── defectdojo/
│   │   └── client.py               # push findings to DefectDojo
│   ├── slack/
│   │   └── client.py               # post Slack alerts
│   └── email/
│       └── client.py               # send alert emails
├── rules/
│   └── wazuh/                      # custom Wazuh detection rules
├── config/
│   └── example.yaml                # reference configuration
├── deploy/
│   └── docker-compose/             # Wazuh + DefectDojo stack
├── evidence/                       # audit artifacts (gitignored)
├── examples/                       # sample inputs for local testing
├── scripts/                        # operational helpers
└── docs/
    └── event-schema.md             # schema documentation
```

---

## License

MIT — see [LICENSE](LICENSE).
