import json
from idpproxy.social.oauth import OAuth
import oauth2 as oauth
#from xml.etree import ElementTree as ET
import logging
logger = logging.getLogger(__name__)

__author__ = 'rohe0002'

class LinkedIn(OAuth):
    def __init__(self, client_id, client_secret, **kwargs):
        OAuth.__init__(self, client_id, client_secret, **kwargs)

    def get_profile(self, info_set):
        token = oauth.Token(key=info_set["oauth_token"][0],
                            secret=info_set["oauth_token_secret"][0])

        client = oauth.Client(self.consumer, token)

        resp, content = client.request(self.extra["userinfo_endpoint"], "GET")
#        # content in XML :-(
#        logger.debug("UserInfo XML: %s" % content)
#        res = {}
#        root = ET.fromstring(content)
#        for child in root:
#            res[child.tag] = child.text

        res = json.loads(content)
        logger.debug("userinfo: %s" % res)
        res["user_id"] = info_set["oauth_token"]
        return resp, res