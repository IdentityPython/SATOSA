from vopaas_proxy.backends.social.oauth2 import OAuth2

# from oic.oauth2.message import Message, AccessTokenResponse
# from oic.oauth2.message import SINGLE_REQUIRED_STRING
# from oic.oauth2.message import SINGLE_OPTIONAL_INT

import logging

logger = logging.getLogger(__name__)


class LiveIDOAuth2(OAuth2):
    def __init__(self, client_id, client_secret, **kwargs):
        OAuth2.__init__(self, client_id, client_secret, **kwargs)
        self.token_response_body_type = "json"
        # self.access_token_response = AccessTokenResponse

# def userinfo_endpoint(self, tokenresp):
#        # A JWT
#        auth_token = tokenresp["authentication_token"]
#        # don't mind the signature
#        claims = json.loads(unpack(auth_token)[1])
#        uid = claims["uid"]
#        return self.extra["userinfo_endpoint"].replace("me", uid)
