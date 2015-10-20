import json
from oic.utils.authn.authn_context import UNSPECIFIED
import requests
from oic.oauth2.consumer import Consumer, stateID
from oic.oauth2.message import AuthorizationRequest, AuthorizationResponse
from satosa.backends.base import BackendModule
from satosa.exception import AuthenticationError, SATOSAError
from satosa.internal_data import InternalResponse, AuthenticationInformation, UserIdHashType
from satosa.response import Redirect
from satosa.service import response, rndstr
from satosa.state import state_to_cookie, cookie_to_state, StateError

__author__ = 'haho0032'


class OIDCBackend(BackendModule):

    def __init__(self, outgoing, config, get_consumer=get_consumer):
        super(OAuthBackend, self).__init__(outgoing)
        self.config = config
        self.redirect_url = "%s/%s" % (self.config["base_url"], self.config["authz_page"])
        self.get_consumer = get_consumer

    def start_auth(self, context, internal_request, state):
        consumer = self.get_consumer(internal_request.user_id_hash_type, self.config)
        request_args = {}
        request_args["redirect_uri"] = self.redirect_url
        request_args["state"] = stateID(self.config["base_url"], rndstr().encode())
        state_data = {
            "state": request_args["state"],
            "user_id_hash_type": internal_request.user_id_hash_type.name
        }
        state.add(self.config["state_key"], state_data)
        cis = consumer.construct_AuthorizationRequest(request_args=request_args)
        url, body, ht_args, cis = consumer.uri_and_body(AuthorizationRequest, cis,
                                                        method="GET",
                                                        request_args=request_args)
        state_cookie = state_to_cookie(state, self.config["state_cookie_name"], "/",
                                       self.config["state_encryption_key"])
        return Redirect(url, state_cookie)

    def register_endpoints(self):
        url_map = []
        url_map.append(("^%s?(.*)$" % self.config["authz_page"], (self.authn_response, "redirect")))
        url_map.append(("^%s$" % self.config["authz_page"], (self.authn_response, "redirect")))
        return url_map

    def verify_state(self, resp, state_data, state):
        if not ("state" in resp and "state" in state_data and resp["state"] == state_data["state"]):
            tmp_state = ""
            if "state" in resp:
                tmp_state = resp["state"]

            raise AuthenticationError(state,
                                      "Missing or invalid state [%s] in response!" % tmp_state)

    def authn_response(self, context, binding):
        try:
            state = cookie_to_state(context.cookie,
                                    self.config["state_cookie_name"],
                                    self.config["state_encryption_key"])
            state_data = state.get(self.config["state_key"])
            if "user_id_hash_type" in state_data:
                enum_value = UserIdHashType[state_data["user_id_hash_type"]]
                state_data["user_id_hash_type"] = enum_value
            consumer = self.get_consumer(state_data["user_id_hash_type"], self.config)
            request = context.request
            aresp = consumer.parse_response(AuthorizationResponse, info=json.dumps(request))
            self.verify_state(aresp, state_data, state)
            rargs = {"code": aresp["code"]}
            rargs["redirect_uri"] = self.redirect_url
            rargs["state"] = state_data["state"]
            atresp = consumer.do_access_token_request(request_args=rargs, state=aresp["state"])
            if ("verify_accesstoken_state" not in self.config or
                    self.config["verify_accesstoken_state"]):
                self.verify_state(atresp, state_data, state)
            user_info = self.user_information(atresp["access_token"])
            internal_response = InternalResponse(state_data["user_id_hash_type"],
                                                 auth_info=self.auth_info(request))
            if "oauth_to_internal" not in self.config:
                internal_response.add_oidc_attributes(user_info)
            else:
                internal_response.add_attributes(self.config["oauth_to_internal"],
                                                 user_info)
            return self.auth_callback_func(context, internal_response, state)
        except Exception as error:
            if isinstance(error, SATOSAError):
                raise error
            # TODO LOG
            raise AuthenticationError(None, "Missing state in authn_response")

    def auth_info(self, request):
        raise NotImplementedError("Method user_information must be implemented!")

    def user_information(self, access_token):
        raise NotImplementedError("Method user_information must be implemented!")