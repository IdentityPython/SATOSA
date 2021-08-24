import logging
import os

from oidcop.configure import OPConfiguration
from oidcop.server import Server
from oidcop.util import importer


folder = os.path.dirname(os.path.realpath(__file__))
logger = logging.getLogger(__name__)


def oidc_provider_init_app(config, name="oidc_op", **kwargs):
    name = name or __name__
    app = type("OidcOpApp", (object,), {"srv_config": config})
    app.server = Server(config, cwd=folder)
    return app


def oidcop_application(conf: dict):
    domain = getattr(conf, "domain", None)
    config = OPConfiguration(conf=conf["op"]["server_info"], domain=domain)
    app = oidc_provider_init_app(config)

    # app customs
    app.default_target_backend = conf.get("default_target_backend")
    app.salt_size = conf.get("salt_size", 8)

    _strg = conf["storage"]
    app.storage = importer(_strg["class"])(_strg, **_strg["kwargs"])
    return app
