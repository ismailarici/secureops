# SecureOps — Deploy

Docker Compose stacks for Wazuh (SIEM/XDR) and DefectDojo (vulnerability tracking).
Run these locally or on a dedicated server. SecureOps routes events to both.

---

## Prerequisites

- Docker 24+ and Docker Compose v2
- 8 GB RAM minimum (Wazuh alone needs ~4 GB)
- Ports 443, 55000, 1514, 1515 (Wazuh) and 8080 (DefectDojo) available

---

## Quick start

```bash
cd deploy/docker-compose
cp .env.example .env
# edit .env with secure passwords
```

### Wazuh

```bash
# Start the stack
make wazuh-up

# First time only — initialises OpenSearch security, starts manager, patches filebeat config
make wazuh-init

# Tail logs
make wazuh-logs
```

`wazuh-init` runs four steps automatically: waits for OpenSearch, runs `securityadmin`, starts the manager and dashboard, then patches the filebeat TLS config so the manager stays running. Run it once after every `make wazuh-down -v` (fresh volume) or after the first `make wazuh-up`.

Wazuh is ready when the dashboard loads at **https://localhost**.
Login: `admin` / `admin` (demo stack — change `WAZUH_API_PASSWORD` in `.env` for the API user).

**Connect SecureOps to Wazuh** — update `config/config.yaml`:
```yaml
integrations:
  wazuh:
    enabled: true
    url: "https://localhost"
    port: 55000
    username: "wazuh-wui"
    password: "<WAZUH_API_PASSWORD from .env>"
    min_severity: "medium"
    verify_ssl: false   # demo stack uses self-signed certs
```

Deploy the custom SecureOps rules to the Wazuh manager:
```bash
docker cp ../../rules/wazuh/secureops.xml \
  $(docker ps -qf name=wazuh.manager):/var/ossec/etc/rules/secureops.xml
docker exec $(docker ps -qf name=wazuh.manager) /var/ossec/bin/wazuh-control restart
```

---

### DefectDojo

```bash
make defectdojo-up

# Wait ~2 minutes for the database migration, then get your API token:
make defectdojo-token
```

DefectDojo is ready at **http://localhost:8080**.
Login: `admin` / value of `DD_ADMIN_PASSWORD` in `.env`.

**Connect SecureOps to DefectDojo** — update `config/config.yaml`:
```yaml
integrations:
  defectdojo:
    enabled: true
    url: "http://localhost:8080"
    api_token: "<token from make defectdojo-token>"
    default_product_name: "your-product"
```

---

## Ports

| Service | Port | Protocol | Purpose |
|---------|------|----------|---------|
| Wazuh dashboard | 443 | HTTPS | Web UI |
| Wazuh API | 55000 | HTTPS | SecureOps connects here |
| Wazuh agent log | 1514 | TCP | Agent log ingestion |
| Wazuh agent enroll | 1515 | TCP | Agent enrollment |
| Wazuh syslog | 514 | UDP | Syslog input |
| DefectDojo | 8080 | HTTP | Web UI + API |
| OpenSearch | 9200 | HTTPS | Internal (Wazuh indexer) |

---

## Production notes

- Change all default passwords in `.env` before exposing any port externally
- Replace self-signed Wazuh certificates with CA-signed certs for production
- Put DefectDojo behind a reverse proxy with HTTPS for production
- Set `DD_ALLOWED_HOSTS` in `defectdojo.yml` to your actual hostname
- Back up Docker volumes regularly: `wazuh_indexer_data`, `defectdojo_db`, `defectdojo_media`

---

## Teardown

```bash
make wazuh-down
make defectdojo-down

# To also remove all data volumes (destructive):
docker volume rm $(docker volume ls -q | grep -E 'wazuh_|defectdojo_')
```
