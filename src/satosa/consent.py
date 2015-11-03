"""
A consent module for the satosa proxy
"""
import hashlib
import json
from jwkest.jws import JWS
import requests
from requests.exceptions import ConnectionError
from base64 import urlsafe_b64encode
from satosa.internal_data import InternalResponse, AuthenticationInformation, UserIdHashType
from satosa.response import Redirect
from satosa.state import state_to_cookie, cookie_to_state
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
            self.verify_ssl = config.CONSENT["verify_ssl"]

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
        # TODO What if no cookie?
        state = cookie_to_state(context.cookie, "consent_state", self.state_enc_key)

        consent_state = state.get(ConsentModule.STATE_KEY)
        saved_resp = consent_state["internal_resp"]

        # rebuild internal_response from state
        auth_info = AuthenticationInformation(saved_resp["auth_info"]["auth_class_ref"],
                                              saved_resp["auth_info"]["timestamp"],
                                              saved_resp["auth_info"]["issuer"])
        internal_response = InternalResponse(getattr(UserIdHashType, saved_resp["hash_type"]),
                                             auth_info=auth_info)
        internal_response._attributes = saved_resp["attr"]
        internal_response.user_id = saved_resp["usr_id"]

        requestor = consent_state["reqor"]

        hash_id = self._get_consent_id(requestor, internal_response.user_id, list(internal_response._attributes.keys()))

        try:
            consent_given = self._verify_consent(hash_id)
        except ConnectionError as error:
            # TODO LOG
            # Send an internal_response without any attributes
            consent_given = False

        if not consent_given:
            # If consent was not given, then don't send any attributes
            internal_response._attributes = {}

        return self.callback_func(context, internal_response, state)

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

        #filter attributes
        filtered_data = {}
        for attr in filter:
           if attr in internal_response._attributes:
               data = internal_response._attributes[attr]
               if not isinstance(data, list):
                   data = [data]
               filtered_data[attr] = data
        #Update intenal response
        internal_response._attributes = filtered_data
        #filtered_data = internal_response._attributes

        id_hash = self._get_consent_id(requestor, internal_response.user_id, list(filtered_data.keys()))

        try:
            # Check if consent is already given
            if self._verify_consent(id_hash):
                return self.callback_func(context, internal_response, state)
        except ConnectionError as error:
            # TODO LOG
            # Send an internal_response without any attributes
            internal_response._attributes = {}
            return self.callback_func(context, internal_response, state)

        consent_state["internal_resp"] = self._internal_resp_to_dict(internal_response)
        state.add(ConsentModule.STATE_KEY, consent_state)

        # Save state in cookie
        state_cookie = state_to_cookie(state, "consent_state", "/consent/%s" % self.endpoint, self.state_enc_key)

        consent_args = {"attr": filtered_data,
                        "id": id_hash,
                        "redirect_endpoint": "%s/consent/%s" % (self.proxy_base, self.endpoint)}
        consent_args_jws = self._to_jws(consent_args)

        try:
            ticket = self._consent_registration(consent_args_jws)
        except (ConnectionError, AssertionError) as error:
            # TODO LOG
            # Send an internal_response without any attributes
            internal_response._attributes = {}
            return self.callback_func(context, internal_response, state)

        consent_redirect = "%s?ticket=%s" % (self.consent_redirect_url, ticket)
        return Redirect(consent_redirect, state_cookie)

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

    def _consent_registration(self, jws):
        """
        Register a request at the consent service

        :type jws: str
        :type state: satosa.state.State
        :rtype: str

        :param jws: A jws containing id, redirect_endpoint and attr
        :param state: The current state
        :return: Ticket received from the consent service
        """
        try:
            request = "{}/creq/{}".format(self.consent_uri, jws)
            res = requests.get(request, verify=self.verify_ssl)
        except ConnectionError as con_exc:
            raise ConnectionError("Could not connect to consent service: {}".format(str(con_exc)))

        assert res.status_code == 200, "Consent service: {}".format(res.status_code)

        ticket = res.text
        return ticket

    def _verify_consent(self, id):
        """
        Connects to the consent service using the REST api and checks if the user has given consent

        :type id: str
        :type state: satosa.state.State
        :rtype: bool

        :param id: An id associated to the authenticated user, the calling requestor and attributes to be sent.
        :param state: The current state
        :return: True if given consent, else False
        """
        try:
            request = "{}/verify/{}".format(self.consent_uri, id)
            res = requests.get(request, verify=self.verify_ssl)
        except ConnectionError as con_exc:
            raise ConnectionError("Could not connect to consent service: {}".format(str(con_exc)))

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
