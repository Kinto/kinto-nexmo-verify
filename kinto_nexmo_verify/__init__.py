import logging

import pkg_resources
from pyramid.exceptions import ConfigurationError

from .authentication import nexmo_ping

logger = logging.getLogger(__name__)

#: Module version, as defined in PEP-0396.
__version__ = pkg_resources.get_distribution(__package__).version


DEFAULT_SETTINGS = {
    "nexmo.header_type": "Bearer",
    "nexmo.api_endpoint": "https://api.nexmo.com/",
    "nexmo.api_key": None,
    "nexmo.api_secret": None,
    "nexmo.brand": "ACME Inc.",
    "nexmo.sender_id": "verify",
    "nexmo.code_length": 4,
    "nexmo.jwt_secret": None,
    "nexmo.cache_ttl_seconds": 1 * 30 * 24 * 3600,  # 1 month
    "nexmo.heartbeat_timeout_seconds": 3,
    "nexmo.state_ttl_seconds": 300,  # 5 minutes (default nexmo request timeout)
}


def includeme(config):
    if not hasattr(config.registry, "heartbeats"):
        message = (
            "kinto-nexmo-verify should be included once Kinto is initialized. "
            "Use setting ``kinto.includes`` instead of ``pyramid.includes`` "
            "or include it manually."
        )
        raise ConfigurationError(message)

    settings = config.get_settings()

    defaults = {k: v for k, v in DEFAULT_SETTINGS.items() if k not in settings}
    config.add_settings(defaults)

    # Register heartbeat to ping related services.
    config.registry.heartbeats["nexmo"] = nexmo_ping

    config.add_api_capability(
        "nexmo-verify",
        version=__version__,
        description="You can authenticate to that server using "
        "Nexmo Passwordless Auth.",
        url="https://github.com/kinto/kinto-nexmo-verify",
    )

    config.scan("kinto_nexmo_verify.views")
