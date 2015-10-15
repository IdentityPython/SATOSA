from oic.oauth2.consumer import Consumer
from satosa.backends.base import BackendModule
from satosa.service import response

__author__ = 'haho0032'


class OAuthBackend(BackendModule):

    def __init__(self, outgoing, config):
        super(OAuthBackend, self).__init__(outgoing)
        self.config = config


    def get_consumer(self):
        consumer = Consumer(
            session_db=None,
            client_config=self.config["client_config"],
            server_info=self.config["server_info"],
            authz_page=self.config["authz_page"],
            response_type=self.config["response_type"])
        consumer.client_secret = self.config["client_secret"]
        return consumer

    def _start_auth(self, consumer):
        return consumer.begin(self.config["response_type"]["base_url"], "")

    def start_auth(self, context, internal_request, state):
        oauth_state, url = self._start_auth()
        #return redirect(url)
        #TODO RETURN REDIRECT

    def register_endpoints(self):
        url_map = []
        url_map.append(
            ("^%s?(.*)$" % self.consumer.authz_page, (self.authn_response, "redirect")))
        url_map.append(
            ("^%s$" % self.consumer.authz_page, (self.authn_response, "redirect")))

    def authn_response(self, context, binding):
        consumer = self.get_consumer()
        self._start_auth(consumer)
        request = context.request
        self.consumer.sdb = {}
        state = None #GET STATE FROM COOKIE
        self.consumer.sdb["state"] = state
        aresp = self.consumer.handle_authorization_response(request)
        rargs = {"code": aresp["code"]}
        atresp = self.consumer.do_access_token_request(request_args=rargs, state=aresp["state"])
        #c.do_any(state=aresp["state"],scope="code",access_token=atresp['access_token'])
        #resp = c.fetch_protected_resource(uri,state=aresp["state"],token=atresp['access_token'])
        payload = {'access_token': atresp["access_token"]}
        url = "https://graph.facebook.com/v2.5/me?fields="
        fields_str = ""
        first = True
        for field in fields:
            if not first:
                url += ","
                fields_str += ","
            else:
                first = False
            url += field
            fields_str += field
        r = requests.get(url, params=payload)

    def user_information(self):
        raise NotImplementedError("Method user_information must be implemented!")


class FacebookBackend(OAuthBackend):

    def __init__(self, outgoing, config):
        super(FacebookBackend, self).__init__(outgoing, config)

    def user_information(self):
