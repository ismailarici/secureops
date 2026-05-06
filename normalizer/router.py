import logging

from normalizer import config as cfg
from integrations.wazuh.client import WazuhClient
from integrations.defectdojo.client import DefectDojoClient
from integrations.slack.client import SlackClient
from integrations.email.client import EmailClient

log = logging.getLogger(__name__)

_INTEGRATIONS = {
    "wazuh": WazuhClient,
    "defectdojo": DefectDojoClient,
    "slack": SlackClient,
    "email": EmailClient,
}


def route(events: list[dict], config: dict) -> None:
    """Send events to every enabled integration. Errors in one do not stop others."""
    for name, client_cls in _INTEGRATIONS.items():
        if not cfg.is_enabled(config, name):
            log.debug("Integration %s is disabled — skipping", name)
            continue
        integration_cfg = cfg.get_integration(config, name)
        try:
            client = client_cls(integration_cfg)
            client.send_events(events)
            log.info("Routed %d event(s) to %s", len(events), name)
        except Exception as e:
            log.error("Integration %s failed: %s", name, e)
