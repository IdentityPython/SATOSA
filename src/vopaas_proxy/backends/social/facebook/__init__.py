from urllib.parse import urlparse
from vopaas_proxy.backends.social.oauth2 import OAuth2

from oic.oauth2.message import Message
from oic.oauth2.message import SINGLE_REQUIRED_STRING
from oic.oauth2.message import SINGLE_OPTIONAL_INT

import logging

LOGGER = logging.getLogger(__name__)


# Facebook version
class FacebookAccessTokenResponse(Message):
    c_param = {
        "access_token": SINGLE_REQUIRED_STRING,
        "expires": SINGLE_OPTIONAL_INT,
    }


class FacebookOAuth2(OAuth2):
    def __init__(self, client_id, client_secret, **kwargs):
        OAuth2.__init__(self, client_id, client_secret, **kwargs)
        self.access_token_response = FacebookAccessTokenResponse

    def eppn_from_link(self, link):
        result = urlparse.urlparse(link)

        return "%s@facebook.%s" % (result.path[1:], self.extra["DOMAIN"])
