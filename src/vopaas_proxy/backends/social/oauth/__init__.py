import urllib
import vopaas_proxy.backends.social.oauth2 as oauth

from urllib.parse import parse_qs
from vopaas_proxy.backends.social import Social

import logging

logger = logging.getLogger(__name__)


class OAuth(Social):
    def __init__(self, client_id, client_secret, **kwargs):
        Social.__init__(self, client_id, client_secret, **kwargs)
        self.consumer = oauth.Consumer(client_id, client_secret)

    def token_secret_key(sid):
        return "token_secret_%s" % sid

    # noinspection PyUnusedLocal
    def begin(self, environ, server_env, start_response, cookie, sid, info):
        """Step 1: Get a request token. This is a temporary token that is used for
        having the user authorize an access token and to sign the request to obtain
        said access token."""

        session = server_env["CACHE"][sid]

        client = oauth.Client(self.consumer)
        try:
            url = "%s?scope=%s" % (self.extra["request_token_url"],
                                   "+".join(self.extra["scope"]))
        except KeyError:
            url = self.extra["request_token_url"]

        logger.debug("Request_token url: %s" % url)
        resp, content = client.request(url, "GET")
        if server_env["DEBUG"]:
            logger.info("Client resp: %s" % resp)
            logger.info("Client content: %s" % content)

        if resp['status'] != '200':
            raise Exception("Invalid response %s." % resp['status'])

        request_token = dict(parse_qs(content))

        token = oauth.Token(request_token['oauth_token'][0],
                            request_token['oauth_token_secret'][0])

        session['oauth_token'] = request_token['oauth_token'][0]
        session[request_token['oauth_token'][0]] = token
        try:
            dig = session["sid_digest"]
        except KeyError:
            dig = server_env["CACHE"].digest(sid)
            session["sid_digest"] = dig

        callback_url = "%s%s/%s" % (server_env["base_url"],
                                    self.social_endpoint,
                                    session["sid_digest"])
        logger.debug("callback_url: %s" % callback_url)
        # Step 2: Redirect to the provider.

        args = {
            "oauth_token": request_token['oauth_token'][0],
            "oauth_callback": callback_url,
        }

        server_env["CACHE"][sid] = session

        url = "%s?%s" % (self.extra["authorization_endpoint"],
                         urllib.urlencode(args))
        logger.debug("redirect to: %s" % url)
        start_response("302 Found", [("Location", url), cookie])
        return []

    def get_profile(self, info_set):
        """
        default is you're not going to get anymore
        :param info_set:
        :return:
        """
        return {"status": "200"}, info_set

    # noinspection PyUnusedLocal
    def phase_n(self, environ, info, server_env, sid):
        """Step 2: Once the consumer has redirected the user back to the
        oauth_callback URL you can request the access token the user has
        approved. You use the request token to sign this request. After this is
        done you throw away the request token and use the access token returned.
        You should store this access token somewhere safe, like a database, for
        future use."""

        logger.debug("[phaseN] info: %s" % info)
        session = server_env["CACHE"][sid]

        try:
            response_oauth_token = info["oauth_token"][0]
        except KeyError:
            session["authentication"] = "FAILED"
            return False, "Access denied", session

        logger.info("response_oauth_token: %s" % response_oauth_token)

        token = session[response_oauth_token]

        # token.set_verifier(oauth_verifier)
        client = oauth.Client(self.consumer, token)

        if "oauth_verifier" in info:
            _body = "oauth_verifier=%s" % info["oauth_verifier"][0]
        else:
            _body = ""

        resp, content = client.request(self.extra["token_endpoint"], "POST",
                                       body=_body)
        if resp['status'] != '200':
            logger.error("<token_endpoint> response: %s, content: %s" % (resp,
                                                                         content))
            return False, "Invalid response %s." % resp['status'], session

        if server_env["DEBUG"]:
            logger.info("[%s phase2] content: %s" % (self.name, content))

        info_set = dict(parse_qs(content))

        resp, profile = self.get_profile(info_set)

        if resp['status'] != '200':
            logger.error("<token_endpoint> response: %s, content: %s" % (resp,
                                                                         content))
            return False, "Invalid response %s." % resp['status'], session

        if server_env["DEBUG"]:
            logger.info("[%s phase2] profile: %s" % (self.name, profile))

        session["permanent_id"] = profile["user_id"][0]
        session["service"] = self.name
        session["service_info"] = profile
        session["authn_auth"] = self.authenticating_authority
        session["authentication"] = "OK"
        session["status"] = "SUCCESS"

        return True, self.convert(profile), session
