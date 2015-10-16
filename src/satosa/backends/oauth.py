import json
from oic.utils.authn.authn_context import UNSPECIFIED
import requests
from oic.oauth2.consumer import Consumer, stateID
from oic.oauth2.message import AuthorizationRequest, AuthorizationResponse
from satosa.backends.base import BackendModule
from satosa.exception import AuthenticationError, SATOSAError
from satosa.internal_data import InternalResponse, AuthenticationInformation
from satosa.response import Redirect
from satosa.service import response, rndstr
from satosa.state import state_to_cookie, cookie_to_state, StateError

__author__ = 'haho0032'


def get_consumer(self, user_id_hash_type):
    """
        :rtype: UserIdHashType
    :return:
    """
    consumer = Consumer(
        session_db=None,
        client_config=self.config["client_config"],
        server_info=self.config["server_info"],
        authz_page=self.config["authz_page"],
        response_type=self.config["response_type"])
    consumer.client_secret = self.config["client_secret"]
    return consumer


class OAuthBackend(BackendModule):

    def __init__(self, outgoing, config, get_consumer=get_consumer):
        super(OAuthBackend, self).__init__(outgoing)
        self.config = config
        self.redirect_url = "%s/%s" % (self.config["base_url"], self.config["authz_page"])
        self.get_consumer = get_consumer

    def start_auth(self, context, internal_request, state):
        consumer = self.get_consumer(internal_request.user_id_hash_type)
        request_args = {}
        request_args["redirect_uri"] = self.redirect_url
        request_args["state"] = stateID(self.config["base_url"], rndstr())
        state_data = {
            "state": request_args["state"],
            "user_id_hash_type": internal_request.user_id_hash_type
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
        url_map.append(("^%s?(.*)$" % self.redirect_url, (self.authn_response, "redirect")))
        url_map.append(("^%s$" % self.redirect_url, (self.authn_response, "redirect")))
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
            consumer = self.get_consumer()
            request = context.request
            aresp = consumer.parse_response(AuthorizationResponse, info=request, sformat="urlencoded")
            self.verify_state(aresp, state_data, state)
            rargs = {"code": aresp["code"]}
            rargs["redirect_uri"] = self.redirect_url
            rargs["state"] = state_data["state"]
            atresp = consumer.do_access_token_request(request_args=rargs, state=aresp["state"])
            self.verify_state(atresp, state_data, state)
            user_info = self.user_information(atresp["access_token"])
            internal_response = InternalResponse(state_data["user_id_hash_type"],
                                                 auth_info=self.auth_info())
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


class FacebookBackend(OAuthBackend):

    def __init__(self, outgoing, config, fields, convert_dict):
        super(FacebookBackend, self).__init__(outgoing, config)
        self.fields = fields
        self.convert_dict = convert_dict

    def auth_info(self, request):
        auth_info = AuthenticationInformation(UNSPECIFIED,
                                              None,
                                              self.config["server_info"]["authorization_endpoint"])

    def user_information(self, access_token):
        payload = {'access_token': "access_token"}
        url = "https://graph.facebook.com/v2.5/me?fields="
        fields_str = ""
        first = True
        for field in self.fields:
            if not first:
                url += ","
                fields_str += ","
            else:
                first = False
            url += field
            fields_str += field
        r = requests.get(url, params=payload)
        data = json.loads(r.text.encode('UTF-8'))
        if "picture" in data and "data" in data["picture"] and "url" in data["picture"]["data"]:
            picture_url = data["picture"]["data"]["url"]
            data["picture"] = picture_url
        ["picture"]["data"]["url"].encode('UTF-8')
        return json.loads(r.text)
