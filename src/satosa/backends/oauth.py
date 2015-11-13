"""
This module contains classes to create OAuth 2 backends for SATOSA.
"""
import json
import logging
from oic.utils.authn.authn_context import UNSPECIFIED
import requests
from oic.oauth2.consumer import Consumer, stateID
from oic.oauth2.message import AuthorizationRequest, AuthorizationResponse
from satosa.backends.base import BackendModule
from satosa.exception import SATOSAAuthenticationError, SATOSAError
from satosa.internal_data import InternalResponse, AuthenticationInformation, UserIdHashType, \
    DataConverter
from satosa.logging import satosaLogging
from satosa.response import Redirect
from satosa.service import rndstr

__author__ = 'haho0032'

LOGGER = logging.getLogger(__name__)

class OAuthBackend(BackendModule):

    def __init__(self, outgoing, internal_attributes, config, type):
        super(OAuthBackend, self).__init__(outgoing, internal_attributes)
        self.config = config
        self.redirect_url = "%s/%s" % (self.config["base_url"], self.config["authz_page"])
        self.converter = DataConverter(internal_attributes)
        self.type = type

    def get_consumer(self, user_id_hash_type):
        """
        Creates a OAuth 2.0 consumer from a given configuration.

        :param user_id_hash_type: Tells the OAuth consumer how to ask for user id. I oidc can pairwise
        and public be used.
        :param config: Contains all the configurations for a consumer. See OAuthBacken#__init__ for more
        information.

        :type user_id_hash_type: UserIdHashType
        :type config: dict[str, str | dict[str, str]]
        :rtype: Consumer
        :return: An OAuth 2.0 consumer.
        """
        consumer = Consumer(
            session_db=None,
            client_config=self.config["client_config"],
            server_info=self.config["server_info"],
            authz_page=self.config["authz_page"],
            response_type=self.config["response_type"])
        consumer.client_secret = self.config["client_secret"]
        return consumer

    def start_auth(self, context, internal_request, get_state=stateID):
        consumer = self.get_consumer(internal_request.user_id_hash_type)
        request_args = {}
        request_args["redirect_uri"] = self.redirect_url
        request_args["state"] = get_state(self.config["base_url"], rndstr().encode())
        state_data = {
            "state": request_args["state"],
            "user_id_hash_type": internal_request.user_id_hash_type.name
        }
        state = context.state
        state.add(self.config["state_key"], state_data)
        cis = consumer.construct_AuthorizationRequest(request_args=request_args)
        url, body, ht_args, cis = consumer.uri_and_body(AuthorizationRequest, cis,
                                                        method="GET",
                                                        request_args=request_args)
        return Redirect(url)

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
            satosaLogging(LOGGER, logging.DEBUG, "Missing or invalid state [%s] in response!" % tmp_state, state,
                          exc_info=True)
            raise SATOSAAuthenticationError(state, "Missing or invalid state [%s] in response!" % tmp_state)

    def authn_response(self, context, binding):
        state = context.state
        try:
            state_data = state.get(self.config["state_key"])
            user_id_hash_type = UserIdHashType.pairwise
            if "user_id_hash_type" in state_data:
                enum_value = UserIdHashType[state_data["user_id_hash_type"]]
                user_id_hash_type = enum_value
            consumer = self.get_consumer(state_data["user_id_hash_type"])
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
            internal_response = InternalResponse(user_id_hash_type,
                                                 auth_info=self.auth_info(request))
            internal_response.add_attributes(self.converter.to_internal(self.type, user_info))
            return self.auth_callback_func(context, internal_response, state)
        except Exception as error:
            satosaLogging(LOGGER, logging.DEBUG, "Not a valid authentication", state, exc_info=True)
            if isinstance(error, SATOSAError):
                raise error
            if state is not None:
                raise SATOSAAuthenticationError(state, "Not a valid authentication") from error
            raise

    def auth_info(self, request):
        raise NotImplementedError("Method user_information must be implemented!")

    def user_information(self, access_token):
        raise NotImplementedError("Method user_information must be implemented!")


class FacebookBackend(OAuthBackend):
    STATE_KEY = "facebook_backend"

    def __init__(self, outgoing, internal_attributes, config):
        super(FacebookBackend, self).__init__(outgoing, internal_attributes, config, "facebook")
        self.fields = None
        self.convert_dict = None
        if "state_key" not in self.config:
            self.config["state_key"] = FacebookBackend.STATE_KEY
        if "verify_accesstoken_state" not in self.config:
            self.config["verify_accesstoken_state"] = False
        if "response_type" not in self.config:
            self.config["response_type"] = "code"
        if "fields" in self.config:
            self.fields = self.config["fields"]

    def auth_info(self, request):
        auth_info = AuthenticationInformation(UNSPECIFIED,
                                              None,
                                              self.config["server_info"]["authorization_endpoint"])
        return auth_info

    def request_fb(self, url, payload):
        r = requests.get(url, params=payload)
        return r

    def user_information(self, access_token):
        payload = {'access_token': access_token}
        url = "https://graph.facebook.com/v2.5/me"
        if self.fields is not None:
            #url += "?fields="
            fields_str = ""
            first = True
            for field in self.fields:
                if not first:
                    #url += ","
                    fields_str += ","
                else:
                    first = False
                #url += field
                fields_str += field
            payload["fields"] = fields_str
        r = self.request_fb(url, payload)
        data = json.loads(r.text)
        if "picture" in data and "data" in data["picture"] and "url" in data["picture"]["data"]:
            picture_url = data["picture"]["data"]["url"]
            data["picture"] = picture_url
        return data
