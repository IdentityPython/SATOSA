from oic.oauth2.consumer import Consumer
from satosa.backends.base import BackendModule

__author__ = 'haho0032'


class OAuthBackend(BackendModule):

    def __init__(self, outgoing, config):
        super(OAuthBackend, self).__init__(outgoing)

        c_conf = {"client_id": "414989058592359"}
        self.consumer = Consumer(
            session_db=None,
            client_config=config["client_config"],
            server_info=config["server_info"],
            authz_page=config["authz_page"],
            response_type=config["response_type"])
        self.consumer.client_secret = config["client_secret"]

    def start_auth(self, context, internal_request, state):
        sid, url = self.consumer.begin(context., path)

    def register_endpoints(self):


    def user_information(self):
        raise NotImplementedError("Method user_information must be implemented!")


class FacebookBackend(OAuthBackend):

    def __init__(self, outgoing, config):
        super(FacebookBackend, self).__init__(outgoing, config)

    def user_information(self):
