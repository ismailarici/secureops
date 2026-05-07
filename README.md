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
Cloud logs ──┤             ──► evidence/ (audit artifacts)
Identity logs
System logs
```

---

## What SecureOps does

1. **Ingests** findings and events from SecurePipe, cloud providers (AWS CloudTrail, GCP Audit Logs, Azure Monitor), and identity systems (Okta, Azure AD, AWS IAM)
2. **Normalises** every input into a single [Security Event Schema](docs/event-schema.md)
3. **Routes** normalised events to Wazuh, DefectDojo, Slack, and email
4. **Packages** timestamped audit evidence into a ZIP bundle with an SOC 2 / ISO 27001 compliance report

---

## Design principles

**Portable** — works on AWS, GCP, Azure, and on-premises. No cloud-specific dependencies in core logic.

**Config-driven** — every integration, credential, and behaviour is controlled via `config/`. Nothing is hardcoded.

**Schema-first** — all inputs are normalised to a single schema before any routing or alerting. Adding a new source means writing a normaliser, not touching downstream systems.

**Low-cost** — no Kafka, no heavy pipelines. Python, Docker Compose, and standard open-source tools.

**Loosely coupled** — each integration (`wazuh`, `defectdojo`, `slack`, `email`) is an independent module. Disabling one has no effect on the others.

**Audit-ready** — every event processed produces a timestamped artifact in `evidence/`. The evidence packager generates a self-contained ZIP with an HTML compliance report ready for auditor submission.

---

## Quick start

**Prerequisites:** Python 3.10+, Docker (for deploy stack).

```bash
git clone https://github.com/ismailarici/secureops.git
cd secureops
pip install -r requirements.txt
cp config/example.yaml config/config.yaml
# edit config/config.yaml with your credentials

# Scan with SecurePipe first, then normalise its raw output:
python3 -m normalizer.main --input /path/to/securepipe/reports/raw

# Pull live events from a cloud or identity source:
python3 scripts/ingest.py --source cloudtrail --since 24h
python3 scripts/ingest.py --source okta --since 6h

# Package all evidence into an auditor-ready ZIP:
python3 scripts/package_evidence.py
```

---

## What is implemented

All four phases are complete.

### Phase 1 — Foundation
| Area | Status |
|------|--------|
| Project structure and folder layout | ✅ |
| Security Event Schema v1 | ✅ |
| Reference config file | ✅ |
| Module skeletons for all integrations | ✅ |

### Phase 2 — Normaliser and integration clients
| Area | Status |
|------|--------|
| SecurePipe source parsers (semgrep, trivy, pip-audit, npm-audit, owasp-dc, zap) | ✅ |
| Config loader with severity helpers | ✅ |
| JSON schema validation | ✅ |
| Evidence file writer | ✅ |
| Integration router | ✅ |
| Wazuh client — JWT auth + `/events` API | ✅ |
| DefectDojo client — product / engagement / test / finding flow | ✅ |
| Slack client — Block Kit messages with severity colours | ✅ |
| Email client — SMTP with STARTTLS, plain text + HTML | ✅ |

### Phase 3 — Cloud and identity ingestors + evidence packaging
| Area | Status |
|------|--------|
| AWS CloudTrail ingestor | ✅ |
| GCP Audit Logs ingestor | ✅ |
| Azure Monitor Activity Log ingestor | ✅ |
| Okta System Log ingestor | ✅ |
| Azure AD sign-in log ingestor (Microsoft Graph) | ✅ |
| AWS IAM event ingestor | ✅ |
| Live ingestor CLI (`scripts/ingest.py`) | ✅ |
| Evidence bundle generator (`audit/bundler.py`) | ✅ |
| SOC 2 / ISO 27001 compliance report (`audit/report.py`) | ✅ |
| Evidence packaging CLI (`scripts/package_evidence.py`) | ✅ |

### Phase 4 — Deploy and CI
| Area | Status |
|------|--------|
| Wazuh single-node Docker Compose (manager + indexer + dashboard) | ✅ |
| DefectDojo Docker Compose (postgres + celery + nginx) | ✅ |
| Makefile for both stacks | ✅ |
| Deploy README with setup and port guide | ✅ |
| Reusable GitHub Actions workflow (`secureops-pipeline.yml`) | ✅ |
| Example caller workflow for app repos | ✅ |

---

## Deploy

See [`deploy/docker-compose/README.md`](deploy/docker-compose/README.md) for full setup instructions.

```bash
cd deploy/docker-compose
cp .env.example .env
# edit .env with secure passwords

make wazuh-up      # start Wazuh stack
make wazuh-init    # first time only — initialises OpenSearch security and patches filebeat
make defectdojo-up # http://localhost:8080
make defectdojo-token
```

---

## CI integration

Add SecureOps as a step after SecurePipe in your app's pipeline.
Copy [`examples/caller-workflow.yml`](examples/caller-workflow.yml) to `.github/workflows/security.yml` in your app repo, then set the `SECUREOPS_CONFIG` secret to the full content of your `config/config.yaml`.

```yaml
secureops:
  needs: securepipe-cli
  uses: ismailarici/secureops/.github/workflows/secureops-pipeline.yml@main
  with:
    raw-artifact-name: securepipe-raw-reports
  secrets:
    SECUREOPS_CONFIG: ${{ secrets.SECUREOPS_CONFIG }}
```

---

## Repository structure

```
secureops/
├── normalizer/
│   ├── schemas/event.schema.json       # canonical security event schema
│   ├── sources/
│   │   ├── securepipe/                 # semgrep, sca, trivy, zap parsers
│   │   ├── cloud/                      # cloudtrail, gcp_audit, azure_monitor
│   │   └── identity/                   # okta, azure_ad, aws_iam
│   ├── config.py                       # config loader
│   ├── validator.py                    # jsonschema validation
│   ├── evidence.py                     # timestamped artifact writer
│   ├── router.py                       # dispatches to integrations
│   └── main.py                         # CLI entry point
├── integrations/
│   ├── wazuh/client.py                 # Wazuh REST API client
│   ├── defectdojo/client.py            # DefectDojo REST API client
│   ├── slack/client.py                 # Slack webhook client
│   └── email/client.py                 # SMTP client
├── audit/
│   ├── bundler.py                      # evidence ZIP generator
│   └── report.py                       # SOC 2 / ISO 27001 HTML report
├── rules/wazuh/secureops.xml           # custom Wazuh detection rules
├── scripts/
│   ├── ingest.py                       # live cloud/identity ingestor CLI
│   └── package_evidence.py             # evidence packaging CLI
├── deploy/docker-compose/
│   ├── wazuh.yml                       # Wazuh single-node stack
│   ├── defectdojo.yml                  # DefectDojo stack
│   ├── .env.example                    # credential template
│   ├── Makefile                        # convenience targets
│   └── README.md                       # setup guide
├── .github/workflows/
│   └── secureops-pipeline.yml          # reusable CI workflow
├── config/example.yaml                 # reference configuration
├── examples/
│   ├── securepipe-raw/                 # sample SecurePipe JSON inputs
│   └── caller-workflow.yml             # example CI caller
├── evidence/                           # audit artifacts (gitignored)
└── docs/event-schema.md                # schema documentation
```

---

## License

MIT — see [LICENSE](LICENSE).
