"""
A consent module for the satosa proxy
"""
import hashlib
import json
import logging
from base64 import urlsafe_b64encode

import requests
from requests.exceptions import ConnectionError
from jwkest.jws import JWS

from jwkest.jwk import rsa_load

from jwkest.jwk import RSAKey

from satosa.logging_util import satosa_logging
from satosa.internal_data import InternalResponse
from satosa.response import Redirect

LOGGER = logging.getLogger(__name__)


class ConsentModule(object):
    """
    Module for handling consent. Uses an external consent service
    """

    STATE_KEY = "CONSENT"

    def __init__(self, config, callback_func):
        self.callback_func = callback_func
        self.enabled = \
            "CONSENT" in config and ("enable" not in config.CONSENT or config.CONSENT["enable"])
        if self.enabled:
            self.proxy_base = config.BASE
            self.consent_uri = config.CONSENT["rest_uri"]
            self.consent_redirect_url = config.CONSENT["redirect"]
            self.endpoint = config.CONSENT["endpoint"]
            self.verify_ssl = config.CONSENT["verify_ssl"]
            self.locked_attr = None
            if "user_id_to_attr" in config.INTERNAL_ATTRIBUTES:
                self.locked_attr = config.INTERNAL_ATTRIBUTES["user_id_to_attr"]

            _bkey = rsa_load(config.CONSENT["sign_key"])
            self.sign_key = RSAKey().load_key(_bkey)
            self.sign_key.use = "sig"
            LOGGER.info("Consent flow is active")
        else:
            LOGGER.info("Consent flow is not active")

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
            state.add(ConsentModule.STATE_KEY, {"filter": internal_request.get_filter(),
                                                "requester_name": internal_request.requester_name})

    def _handle_consent_response(self, context):
        """
        Endpoint for handling consent service response
        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: response context
        :return: response
        """
        # Handle answer from consent service
        state = context.state
        consent_state = state.get(ConsentModule.STATE_KEY)
        saved_resp = consent_state["internal_resp"]

        # rebuild internal_response from state
        internal_response = InternalResponse.from_dict(saved_resp)

        requestor = internal_response.to_requestor

        hash_id = self._get_consent_id(requestor, internal_response.get_user_id(),
                                       internal_response.get_attributes())

        try:
            consent_attributes = self._verify_consent(hash_id)
        except ConnectionError:
            satosa_logging(LOGGER, logging.ERROR,
                           "Consent service is not reachable, no consent given.", state)
            # Send an internal_response without any attributes
            consent_attributes = None

        if consent_attributes is None:
            satosa_logging(LOGGER, logging.INFO, "Consent was NOT given", state)
            # If consent was not given, then don't send any attributes
            consent_attributes = []
        else:
            satosa_logging(LOGGER, logging.INFO, "Consent was given", state)

        internal_response = self._filter_attributes(internal_response, consent_attributes)
        return self._end_consent(context, internal_response)

    def manage_consent(self, context, internal_response):
        """
        Manage consent and attribute filtering

        :type context: satosa.context.Context
        :type internal_response: satosa.internal_data.InternalResponse
        :rtype: satosa.response.Response

        :param context: response context
        :param internal_response: the response
        :return: response
        """
        state = context.state
        if not self.enabled:
            satosa_logging(LOGGER, logging.INFO, "Consent flow not activated", state)
            return self._end_consent(context, internal_response)

        consent_state = state.get(ConsentModule.STATE_KEY)
        filter = consent_state["filter"]
        requestor = internal_response.to_requestor
        requester_name = consent_state["requester_name"]

        internal_response = self._filter_attributes(internal_response, filter)
        filtered_data = internal_response.get_attributes()

        id_hash = self._get_consent_id(requestor, internal_response.get_user_id(), filtered_data)

        try:
            # Check if consent is already given
            consent_attributes = self._verify_consent(id_hash)
            if consent_attributes:
                internal_response = self._filter_attributes(internal_response, consent_attributes)
                return self._end_consent(context, internal_response)
        except ConnectionError:
            satosa_logging(LOGGER, logging.ERROR,
                           "Consent service is not reachable, no consent given.", state)
            # Send an internal_response without any attributes
            internal_response._attributes = {}
            return self._end_consent(context, internal_response)

        consent_state["internal_resp"] = internal_response.to_dict()
        state.add(ConsentModule.STATE_KEY, consent_state)

        consent_args = {"attr": filtered_data,
                        "locked_attr": self.locked_attr,
                        "id": id_hash,
                        "redirect_endpoint": "%s/consent/%s" % (self.proxy_base, self.endpoint),
                        "requestor": requestor,
                        "requester_name": requester_name}
        consent_args_jws = self._to_jws(consent_args)

        try:
            ticket = self._consent_registration(consent_args_jws)
        except (ConnectionError, AssertionError):
            satosa_logging(LOGGER, logging.ERROR,
                           "Consent service is not reachable, no consent given.", state)
            # Send an internal_response without any attributes
            internal_response._attributes = {}
            return self._end_consent(context, internal_response)

        consent_redirect = "%s?ticket=%s" % (self.consent_redirect_url, ticket)
        return Redirect(consent_redirect)

    def _filter_attributes(self, internal_response, attr_filter):
        # filter attributes
        filtered_data = {}
        for attr in attr_filter:
            if attr in internal_response.get_attributes():
                data = internal_response.get_attributes()[attr]
                if not isinstance(data, list):
                    data = [data]
                filtered_data[attr] = data
        # Update internal response
        internal_response._attributes = filtered_data
        return internal_response

    def _get_consent_id(self, requestor, user_id, filtered_attr):
        """
        Get a hashed id based on requestor, user id and filtered attributes

        :type requestor: str
        :type user_id: str
        :type filtered_attr: dict[str, str]

        :param requestor: The calling requestor
        :param user_id: The authorized user id
        :param filtered_attr: a list containing all attributes to be sent
        :return: an id
        """

        filtered_attr_key_list = list(filtered_attr.keys())
        filtered_attr_key_list.sort()
        hash_str = ""
        for key in filtered_attr_key_list:
            _value = filtered_attr[key]
            _hash_value = ""
            if isinstance(_value, list):
                _value.sort()
                for val in _value:
                    _hash_value += val
            else:
                _hash_value = val
            hash_str += key + _hash_value
        id_string = "%s%s%s" % (requestor, user_id, hash_str)
        return urlsafe_b64encode(
            hashlib.sha512(id_string.encode("utf-8")).hexdigest().encode("utf-8")).decode("utf-8")

    def _consent_registration(self, jws):
        """
        Register a request at the consent service

        :type jws: str
        :rtype: str

        :param jws: A jws containing id, redirect_endpoint and attr
        :return: Ticket received from the consent service
        """
        try:
            request = "{}/creq/{}".format(self.consent_uri, jws)
            res = requests.get(request, verify=self.verify_ssl)
        except ConnectionError as con_exc:
            raise ConnectionError("Could not connect to consent service") from con_exc

        assert res.status_code == 200, "Consent service: {}".format(res.status_code)

        ticket = res.text
        return ticket

    def _verify_consent(self, consent_id):
        """
        Connects to the consent service using the REST api and checks if the user has given consent

        :type consent_id: str
        :rtype: bool

        :param consent_id: An id associated to the authenticated user, the calling requestor and
        attributes to be sent.
        :return: True if given consent, else False
        """
        try:
            request = "{}/verify/{}".format(self.consent_uri, consent_id)
            res = requests.get(request, verify=self.verify_ssl)
        except ConnectionError as con_exc:
            raise ConnectionError("Could not connect to consent service") from con_exc

        if res.status_code == 200:
            return json.loads(res.text)
        return None

    def _end_consent(self, context, internal_response):
        """
        Clear the state for consent and end the consent step

        :type context: satosa.context.Context
        :type internal_response: satosa.internal_data.InternalResponse
        :rtype: satosa.response.Response

        :param context: response context
        :param internal_response: the response
        :return: response
        """
        try:
            context.state.remove(ConsentModule.STATE_KEY)
        except KeyError:
            pass
        return self.callback_func(context, internal_response)

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
