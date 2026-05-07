.PHONY: wazuh-up wazuh-init wazuh-down wazuh-logs \
        defectdojo-up defectdojo-down defectdojo-logs defectdojo-token \
        help

help:
	@echo "Wazuh:"
	@echo "  make wazuh-up          Start the Wazuh stack"
	@echo "  make wazuh-init        Initialise OpenSearch security (run once after first start)"
	@echo "  make wazuh-down        Stop and remove Wazuh containers"
	@echo "  make wazuh-logs        Tail Wazuh manager logs"
	@echo ""
	@echo "DefectDojo:"
	@echo "  make defectdojo-up     Start DefectDojo (first start takes ~2 min)"
	@echo "  make defectdojo-down   Stop and remove DefectDojo containers"
	@echo "  make defectdojo-logs   Tail DefectDojo app logs"
	@echo "  make defectdojo-token  Print the admin API token"

# ─── Wazuh ───────────────────────────────────────────────────────────────────

wazuh-up:
	@[ -f .env ] || ( echo "Copy .env.example to .env and configure it first."; exit 1 )
	docker compose -f wazuh.yml --env-file .env up -d
	@echo ""
	@echo "Wazuh starting (uses built-in demo TLS certificates)."
	@echo "Once the indexer is healthy, run: make wazuh-init"
	@echo ""
	@echo "Dashboard: https://localhost"
	@echo "API:       https://localhost:55000  (wazuh-wui / see .env WAZUH_API_PASSWORD)"

wazuh-init:
	@echo "Initialising OpenSearch security index..."
	@docker exec docker-compose-wazuh.indexer-1 bash -c "\
	  export JAVA_HOME=/usr/share/wazuh-indexer/jdk && \
	  export PATH=\$$JAVA_HOME/bin:\$$PATH && \
	  bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
	    -cd /usr/share/wazuh-indexer/opensearch-security \
	    -nhnv \
	    -cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
	    -cert /usr/share/wazuh-indexer/certs/admin.pem \
	    -key /usr/share/wazuh-indexer/certs/admin-key.pem \
	    -p 9200 -h 127.0.0.1"
	@echo "Security index initialised. Wazuh should become healthy shortly."

wazuh-down:
	docker compose -f wazuh.yml down

wazuh-logs:
	docker compose -f wazuh.yml logs -f wazuh.manager

# ─── DefectDojo ──────────────────────────────────────────────────────────────

defectdojo-up:
	@[ -f .env ] || ( echo "Copy .env.example to .env and configure it first."; exit 1 )
	docker compose -f defectdojo.yml --env-file .env up -d
	@echo ""
	@echo "DefectDojo starting (first run takes ~2 minutes for DB migration)."
	@echo "Dashboard: http://localhost:8080"
	@echo "Login:     admin / (see .env DD_ADMIN_PASSWORD)"
	@echo "API token: run 'make defectdojo-token' once the app is ready."

defectdojo-down:
	docker compose -f defectdojo.yml down

defectdojo-logs:
	docker compose -f defectdojo.yml logs -f django

defectdojo-token:
	@docker compose -f defectdojo.yml --env-file .env exec django \
	  python manage.py shell -c \
	  "from rest_framework.authtoken.models import Token; from django.contrib.auth import get_user_model; u=get_user_model().objects.get(username='admin'); t,_=Token.objects.get_or_create(user=u); print('Admin API token:', t.key)"
