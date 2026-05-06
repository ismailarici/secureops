.PHONY: wazuh-certs wazuh-up wazuh-down wazuh-logs \
        defectdojo-up defectdojo-down defectdojo-logs defectdojo-token \
        help

help:
	@echo "Wazuh:"
	@echo "  make wazuh-certs       Generate SSL certificates (first time only)"
	@echo "  make wazuh-up          Start the Wazuh stack"
	@echo "  make wazuh-down        Stop and remove Wazuh containers"
	@echo "  make wazuh-logs        Tail Wazuh manager logs"
	@echo ""
	@echo "DefectDojo:"
	@echo "  make defectdojo-up     Start DefectDojo (first start takes ~2 min)"
	@echo "  make defectdojo-down   Stop and remove DefectDojo containers"
	@echo "  make defectdojo-logs   Tail DefectDojo app logs"
	@echo "  make defectdojo-token  Print the admin API token"

# ─── Wazuh ───────────────────────────────────────────────────────────────────

wazuh-certs:
	@echo "Generating Wazuh SSL certificates..."
	@mkdir -p config/certs
	docker run --rm \
	  -v $$(pwd)/config/certs:/certs \
	  wazuh/wazuh-certs-generator:0.0.1 \
	  --certs-tool /certs \
	  --config /certs/config.yml 2>/dev/null || \
	  ( \
	    echo "Falling back to openssl self-signed cert generation..."; \
	    openssl req -x509 -nodes -days 3650 -newkey rsa:4096 \
	      -keyout config/certs/root-ca.key \
	      -out config/certs/root-ca.pem \
	      -subj "/C=US/ST=State/L=City/O=SecureOps/CN=wazuh-root-ca"; \
	    for node in wazuh.manager wazuh.indexer wazuh.dashboard; do \
	      openssl req -new -nodes -newkey rsa:2048 \
	        -keyout config/certs/$$node-key.pem \
	        -out config/certs/$$node.csr \
	        -subj "/C=US/ST=State/L=City/O=SecureOps/CN=$$node"; \
	      openssl x509 -req -days 3650 \
	        -in config/certs/$$node.csr \
	        -CA config/certs/root-ca.pem \
	        -CAkey config/certs/root-ca.key \
	        -CAcreateserial \
	        -out config/certs/$$node.pem; \
	    done; \
	    cp config/certs/root-ca.pem config/certs/root-ca-manager.pem; \
	    echo "Certificates generated in config/certs/"; \
	  )

wazuh-up:
	@[ -f .env ] || ( echo "Copy .env.example to .env and configure it first."; exit 1 )
	@[ -f config/certs/root-ca.pem ] || ( echo "Run 'make wazuh-certs' first."; exit 1 )
	docker compose -f wazuh.yml --env-file .env up -d
	@echo ""
	@echo "Wazuh starting. Dashboard will be available at https://localhost"
	@echo "API available at https://localhost:55000"
	@echo "SecureOps config:"
	@echo "  url: https://localhost"
	@echo "  port: 55000"
	@echo "  username: wazuh-wui"
	@echo "  password: (see .env WAZUH_API_PASSWORD)"

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
