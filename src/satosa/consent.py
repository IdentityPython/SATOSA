"""
A consent module for the satosa proxy
"""
import hashlib
from http.cookies import SimpleCookie
import json
from jwkest.jws import JWS
import requests
from base64 import urlsafe_b64encode
from saml2.httputil import Redirect, Response
from satosa.internal_data import InternalResponse, AuthenticationInformation, UserIdHashType
from satosa.state import State
from jwkest.jwk import rsa_load
from jwkest.jwk import RSAKey

__author__ = 'mathiashedstrom'


class ConsentModule(object):
    """
    Module for handling consent. Uses an external consent service
    """

    STATE_KEY = "CONSENT"

    def __init__(self, config, callback_func):
        self.callback_func = callback_func
        self.enabled = "CONSENT" in config and ("enable" not in config.CONSENT or config.CONSENT["enable"])
        if self.enabled:
            self.proxy_base = config.BASE
            self.state_enc_key = config.CONSENT["state_enc_key"]
            self.consent_uri = config.CONSENT["service.rest_uri"]
            self.consent_redirect_url = config.CONSENT["service.consent_redirect"]
            self.endpoint = config.CONSENT["endpoint"]
            self.cookie_max_age = config.CONSENT["cookie_max-age"]

            _bkey = rsa_load(config.CONSENT["sign_key"])
            self.sign_key = RSAKey().load_key(_bkey)
            self.sign_key.use = "sig"

    def save_state(self, internal_request, state):
        """
        Save stuff needed by the consent module when getting an internal response

        :type internal_request: satosa.internal_data.InternalRequest
        :type state: satosa.state.State
        :rtype: None

        :param internal_request: The current request
        :param state: the current state
        :return: None
        """
        if self.enabled:
            state.add(ConsentModule.STATE_KEY, {"fr": internal_request._attribute_filter,
                                                "reqor": internal_request.requestor})

    def _handle_consent_response(self, context):
        """
        Endpoint for handling consent service response
        :type context: satosa.context.Context
        :rtype context: Any

        :param context: response context
        :return: response
        """
        # Handle answer from consent service
        # load state
        state = State(SimpleCookie(context.cookie)["consent_state"].value, self.state_enc_key)
        consent_state = state.get(ConsentModule.STATE_KEY)
        saved_resp = consent_state["internal_resp"]

        # rebuild internal_response from state
        auth_info = AuthenticationInformation(saved_resp["auth_info"]["auth_class_ref"], saved_resp["auth_info"]["timestamp"],
                                              saved_resp["auth_info"]["issuer"])
        internal_response = InternalResponse(getattr(UserIdHashType, saved_resp["hash_type"]), auth_info=auth_info)
        internal_response._attributes = saved_resp["attr"]
        internal_response.user_id = saved_resp["usr_id"]

        requestor = consent_state["reqor"]
        filtered_attr = []
        for attr in internal_response._attributes:
            filtered_attr.append(attr)

        hash_id = self._get_consent_id(requestor, internal_response.user_id, filtered_attr)

        if self._verify_consent(hash_id):
            return self.callback_func(context, internal_response, state)
        else:
            # TODO What to send back?
            return Response(message="consent was NOT given")

    def manage_consent(self, context, internal_response, state):
        """
        Manage consent and attribute filtering

        :type context: satosa.context.Context
        :type internal_response: satosa.internal_data.InternalResponse
        :type state: satosa.state.State
        :rtype: Any

        :param context: response context
        :param internal_response: the response
        :param state: the current state
        :return: response
        """

        if not self.enabled:
            return self.callback_func(context, internal_response, state)

        consent_state = state.get(ConsentModule.STATE_KEY)
        filter = consent_state["fr"]
        requestor = consent_state["reqor"]

        # filter attributes
        filtered_attributes = []
        for attr in filter:
            if attr in internal_response._attributes:
                filtered_attributes.append(attr)

        # update internal response
        filtered_data = {}
        for attr in filtered_attributes:
            filtered_data[attr] = internal_response._attributes[attr]
        internal_response._attributes = filtered_data

        id_hash = self._get_consent_id(requestor, internal_response.user_id, filtered_attributes)

        # Check if consent is already given
        if self._verify_consent(id_hash):
            return self.callback_func(context, internal_response, state)

        consent_state["internal_resp"] = self._internal_resp_to_dict(internal_response)
        state.add(ConsentModule.STATE_KEY, consent_state)

        # Save state in cookie
        cookie = SimpleCookie()
        cookie["consent_state"] = state.urlstate(self.state_enc_key)
        cookie["consent_state"]["secure"] = True
        cookie["consent_state"]["path"] = "/consent/%s" % self.endpoint
        cookie["consent_state"]["max-age"] = self.cookie_max_age

        consent_args = {"attr": filtered_attributes,
                        "id": id_hash,
                        "redirect_endpoint": "%s/consent/%s" % (self.proxy_base, self.endpoint)}
        consent_args_json = self._to_jws(consent_args)

        consent_redirect = "%s?jwt=%s" % (self.consent_redirect_url, consent_args_json)
        return Redirect(consent_redirect, headers=[tuple(cookie.output().split(": ", 1))], content="text/html")

    def _get_consent_id(self, requestor, user_id, filtered_attr):
        """
        Get a hashed id based on requestor, user id and filtered attributes

        :type requestor: str
        :type user_id: str
        :type filtered_attr: list[str]

        :param requestor: The calling requestor
        :param user_id: The authorized user id
        :param filtered_attr: a list containing all attributes to be sent
        :return: an id
        """
        filtered_attr.sort()
        id_string = "%s%s%s" % (requestor, user_id, json.dumps(filtered_attr))
        return urlsafe_b64encode(hashlib.sha224(id_string.encode("utf-8")).hexdigest().encode("utf-8")).decode("utf-8")

    def _verify_consent(self, id):
        """
        Connects to the consent service using the REST api and checks if the user has given consent

        :type id: str
        :rtype: bool

        :param id: An id associated to the authenticated user, the calling requestor and attributes to be sent.
        :return: True if given consent, else False
        """
        try:
            request = "{}/verify/{}".format(self.consent_uri, id)
            res = requests.get(request, verify=False)
        except ConnectionError as con_exc:
            raise ConnectionError(
                "Could not connect to consent service: {}".format(str(con_exc)))
        return res.status_code == 200

    def _internal_resp_to_dict(self, internal_response):
        """
        Converts an InternalResponse object to a dict

        :type internal_response: satosa.internal_data.InternalResponse

        :param internal_response: The incoming response
        :return: A dict representation of internal_response
        """
        # TODO move to InternalResponse?
        auth_info = internal_response.auth_info
        response_state = {"usr_id": internal_response.user_id,
                          "attr": internal_response._attributes,
                          "hash_type": internal_response.user_id_hash_type.name,
                          "auth_info": {"issuer": auth_info.issuer,
                                        "timestamp": auth_info.timestamp,
                                        "auth_class_ref": auth_info.auth_class_ref, }}
        return response_state

    def _to_jws(self, data):
        """
        Converts data to a jws

        :type data: Any
        :rtype: str

        :param data: Data to be converted to jws
        :return: a jws
        """
        algorithm = "RS256"
        _jws = JWS(json.dumps(data), alg=algorithm)
        return _jws.sign_compact([self.sign_key])

    def register_endpoints(self):
        """
        Register consent module endpoints

        :rtype: list[(srt, (satosa.context.Context) -> Any)]

        :return: A list of endpoints bound to a function
        """
        return [("^consent/%s?(.*)$" % self.endpoint, self._handle_consent_response)]
