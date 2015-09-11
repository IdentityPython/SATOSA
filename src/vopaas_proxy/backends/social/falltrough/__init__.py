import urllib
from idpproxy.social import Social

__author__ = 'rohe0002'

import logging

logger = logging.getLogger(__name__)

class FallTrough(Social):
    def __init__(self, consumer_key=None, consumer_secret=None, **kwargs):
        Social.__init__(self, **kwargs)

        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        self.authn_service_name = "Fall"
        self.authenticating_authority = "Foo"
        self.authorize_url = "http://localhost:8088/falltrough"

    #noinspection PyUnusedLocal
    def begin(self, environ, session, server_env, start_response, cookie,
              state, query):

        # attribute name *must* coincide with 'variable' in idp_proxy_conf
        args = {"session_id": session.sid_digest}
        url = "%s?%s" % (self.authorize_url, urllib.urlencode(args))
        start_response("302 Found", [("Location", url), cookie])
        return [url]


    #noinspection PyUnusedLocal
    def do(self, environ, session, server_env, start_response, cookie, state,
           query):

        user_info = {
            "uid": "user1",
            "name": "Foo Bar"
        }

        session["permanent_id"] = user_info["uid"]
        session["service"] = self.authn_service_name
        session["service_info"] = user_info
        session["authn_auth"] = self.authenticating_authority
        session["authentication"] = "OK"

        return True, user_info, session
