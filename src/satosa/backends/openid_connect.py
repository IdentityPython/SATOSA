from datetime import datetime
import json

from urllib.parse import urlparse

from jwkest.jws import alg2keytype

from oic.utils.authn.authn_context import UNSPECIFIED

from oic.utils.http_util import Redirect

from satosa.backends.base import BackendModule
from satosa.backends.oidc import OIDCClients
from satosa.internal_data import InternalResponse, AuthenticationInformation, UserIdHashType

__author__ = 'danielevertsson'


def get_id_token(client, state):
    return client.grant[state].get_id_token()


# Produce a JWS, a signed JWT, containing a previously received ID token
def id_token_as_signed_jwt(client, id_token, alg="RS256"):
    ckey = client.keyjar.get_signing_key(alg2keytype(alg), "")
    _signed_jwt = id_token.to_jwt(key=ckey, algorithm=alg)
    return _signed_jwt


class OpenidRP(BackendModule):
    def __init__(self, auth_callback_func, config):
        super(OpenidRP, self).__init__(auth_callback_func)
        self.auth_callback_func = auth_callback_func
        self.config = config
        self.clients = OIDCClients(self.config)

    def start_auth(self, context, request_info, original_state):
        # entity_id = b64decode(entity_id).decode("utf-8")
        client = self.clients.dynamic_client(self.config.OP_URL)
        state = {
            "op": client.provider_info["issuer"],
            "original_state": original_state
        }

        try:
            resp = client.create_authn_request(state, self.config.ACR_VALUES)
        except Exception:
            raise
        else:
            return resp

    def register_endpoints(self):
        url_map = []

        # post_logout_redirect_uris = self.config.CLIENTS[""]["client_info"][
        #     "post_logout_redirect_uris"]
        # for uri in post_logout_redirect_uris:
        #     url_map = self._add_endpoint_to_url_map(uri, url_map, self.logout_endpoint)

        redirect_uris = self.config.CLIENTS[""]["client_info"]["redirect_uris"]
        for uri in redirect_uris:
            url_map = self._add_endpoint_to_url_map(uri, url_map, self.redirect_endpoint)

        return url_map

    def _add_endpoint_to_url_map(self, endpoint, url_map, function, binding=None):
        url = urlparse(endpoint)
        url_map.append(("^%s?(.+?)$" % url.path[1:], (function, binding)))
        url_map.append(("^%s$" % url.path[1:], (function, binding)))
        return url_map

    # def logout_endpoint(self, context):
    #     # session = environ['beaker.session']
    #     state = context.request['state']
    #
    #     client = self.clients[state['op']]
    #     logout_url = client.end_session_endpoint
    #     try:
    #         # Specify to which URL the OP should return the user after
    #         # log out. That URL must be registered with the OP at client
    #         # registration.
    #         logout_url += "?" + urlencode(
    #             {"post_logout_redirect_uri": client.registration_response[
    #                 "post_logout_redirect_uris"][0]})
    #     except KeyError:
    #         pass
    #     else:
    #         # If there is an ID token send it along as a id_token_hint
    #         _idtoken = get_id_token(client, state)
    #         if _idtoken:
    #             logout_url += "&" + urlencode({
    #                 "id_token_hint": id_token_as_signed_jwt(client, _idtoken,
    #                                                         "HS256")})
    #         # Also append the ACR values
    #         logout_url += "&" + urlencode({"acr_values": self.config.ACR_VALUES},
    #                                                True)
    #     resp = Redirect(str(logout_url))
    #     return resp

    def redirect_endpoint(self, context, *args):
        state = json.loads(context.request['state'])
        client = self.clients[state["op"]]
        result = client.callback(context.request)
        if isinstance(result, Redirect):
            # TODO this should be handled in a correct way
            print("Hello")

        return self.auth_callback_func(context,
                                       self._translate_response(
                                           result,
                                           state["op"]
                                       ),
                                       state['original_state'])

    def _translate_response(self, response, issuer):

        subject_type = self.clients.config.CLIENTS[""]["client_info"]["subject_type"]
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

        # def get_metadata_desc(self):
        #     metadata_desciption = []
        #     desc = {}
        #     desc["entityid"] = b64encode(self.config.OP_URL.encode("utf-8")).decode("utf-8")
        #     metadata_desciption.append(desc)
        #     return metadata_desciption
