import logging
from vopaas_proxy.backends.social.oauth import OAuth

logger = logging.getLogger(__name__)


class Twitter(OAuth):
    def __init__(self, client_id, client_secret, **kwargs):
        OAuth.__init__(self, client_id, client_secret, **kwargs)
