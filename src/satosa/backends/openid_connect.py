from datetime import datetime
from urllib.parse import urlparse

from jwkest.jws import alg2keytype
from oic.oauth2 import rndstr
from oic.oic.message import RegistrationResponse, ProviderConfigurationResponse
from oic.utils.authn.authn_context import UNSPECIFIED
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

from oic.utils.http_util import Redirect

from oic.utils.keyio import KeyJar

from satosa.backends.base import BackendModule
from satosa.backends.oidc import OIDCClients
from satosa.internal_data import InternalResponse, AuthenticationInformation, UserIdHashType
from satosa.state import State

__author__ = 'danielevertsson'


def get_id_token(client, state):
    return client.grant[state].get_id_token()


# Produce a JWS, a signed JWT, containing a previously received ID token
def id_token_as_signed_jwt(client, id_token, alg="RS256"):
    ckey = client.keyjar.get_signing_key(alg2keytype(alg), "")
    _signed_jwt = id_token.to_jwt(key=ckey, algorithm=alg)
    return _signed_jwt


class MissingUrlPath(Exception):
    pass


class OpenIdBackend(BackendModule):
    def __init__(self, auth_callback_func, config):
        super(OpenIdBackend, self).__init__(auth_callback_func)
        self.auth_callback_func = auth_callback_func
        self.config = config
        self.oidc_clients = OIDCClients(self.config)

    def start_auth(self, context, request_info, state):
        client = self.oidc_clients.dynamic_client(self.config.OP_URL)

        nonce = rndstr()
        state_data = {
            "op": client.provider_info["issuer"],
            "nonce": nonce
        }

        state.add(self.config.STATE_ID, state_data)
        try:
            resp = client.create_authn_request(
                state.urlstate(self.config.STATE_ENCRYPTION_KEY),
                nonce,
                self.config.ACR_VALUES
            )
        except Exception:
            raise
        else:
            return resp

    def register_endpoints(self):
        url_map = []

        redirect_uris = self.config.CLIENTS[""]["client_info"]["redirect_uris"]
        for uri in redirect_uris:
            url_map = self._add_endpoint_to_url_map(uri, url_map, self.redirect_endpoint)

        return url_map

    def _add_endpoint_to_url_map(self, endpoint, url_map, function, binding=None):
        url = urlparse(endpoint)
        if not url.path:
            raise MissingUrlPath()
        url_map.append(("%s?(.+?)" % url.path[1:], (function, binding)))
        url_map.append(("%s" % url.path[1:], (function, binding)))
        return url_map

    def redirect_endpoint(self, context, *args):
        state = State(context.request['state'], self.config.STATE_ENCRYPTION_KEY)
        backend_state = state.get(self.config.STATE_ID)
        try:
            client = self.oidc_clients.client[backend_state["op"]]
        except KeyError:
            val = {
                "srv_discovery_url": self.config.OP_URL,
                "client_registration": {
                    "client_id": "client_1",
                    "client_secret": "2222222222",
                    "redirect_uris": ["%sauthz_cb" %
                                      self.config.CLIENTS[""]["client_info"]["redirect_uris"][0]]
                },
                "behaviour": {
                    "response_type": "code",
                }
            }
            client = self.oidc_clients.client_cls(client_authn_method=CLIENT_AUTHN_METHOD,
                                                  behaviour=val["behaviour"],
                                                  verify_ssl=self.config.VERIFY_SSL)
            client.token_endpoint = self.config.OP_URL + "token"
            client.keyjar = KeyJar(verify_ssl=self.config.VERIFY_SSL)
            pcr = ProviderConfigurationResponse()
            pcr['jwks_uri'] = self.config.OP_URL + "static/jwks.json"
            # client.keyjar.load_keys(pcr, self.config.OP_URL)
            client.handle_provider_config(pcr, self.config.OP_URL)
            for issuer, keybundle_list in client.keyjar.issuer_keys.items():
                for kb in keybundle_list:
                    if kb.remote:
                        kb.do_remote()
            client.store_registration_info(RegistrationResponse(
                **val["client_registration"]))
            client.userinfo_endpoint = self.config.OP_URL + "userinfo_endpoint"


        result = client.callback(context.request)
        if isinstance(result, Redirect):
            # TODO this should be handled in a correct way
            print("Hello")

        return self.auth_callback_func(context,
                                       self._translate_response(
                                           result,
                                           backend_state["op"]
                                       ),
                                       state)

    def _translate_response(self, response, issuer):

        subject_type = self.oidc_clients.config.CLIENTS[""]["client_info"]["subject_type"]
        auth_info = AuthenticationInformation(UNSPECIFIED, str(datetime.now()), issuer)

        internal_resp = InternalResponse(
            self.name_format_to_hash_type(subject_type),
            auth_info=auth_info
        )
        internal_resp.add_oidc_attributes(response)
        internal_resp.user_id = response["sub"]
        return internal_resp

    def name_format_to_hash_type(self, name_format):
        if name_format == "public":
            return UserIdHashType.public
        elif name_format == "pairwise":
            return UserIdHashType.pairwise
        return None
