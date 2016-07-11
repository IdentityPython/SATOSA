"""
A consent module for the satosa proxy
"""
import hashlib
import json
import logging
from base64 import urlsafe_b64encode

import requests
from jwkest.jwk import RSAKey
from jwkest.jwk import rsa_load
from jwkest.jws import JWS
from requests.exceptions import ConnectionError

from .internal_data import InternalResponse
from .logging_util import satosa_logging
from .response import Redirect

logger = logging.getLogger(__name__)

STATE_KEY = "CONSENT"


class UnexpectedResponseError(Exception):
    pass


class ConsentModule(object):
    """
    Module for handling consent. Uses an external consent service
    """

    def __init__(self, config, callback_func):
        self.callback_func = callback_func
        self.enabled = "CONSENT" in config and \
                       ("enable" not in config["CONSENT"] or config["CONSENT"]["enable"])
        if self.enabled:
            self.proxy_base = config["BASE"]
            self.api_url = config["CONSENT"]["api_url"]
            self.redirect_url = config["CONSENT"]["redirect_url"]
            self.locked_attr = None
            if "user_id_to_attr" in config["INTERNAL_ATTRIBUTES"]:
                self.locked_attr = config["INTERNAL_ATTRIBUTES"]["user_id_to_attr"]

            self.signing_key = RSAKey(key=rsa_load(config["CONSENT"]["sign_key"]), use="sig", alg="RS256")
            self.endpoint = "/handle_consent"
            logger.info("Consent flow is active")
        else:
            logger.info("Consent flow is not active")

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
            state[STATE_KEY] = {"filter": internal_request.approved_attributes or [],
                                "requester_name": internal_request.requester_name}

    def _handle_consent_response(self, context):
        """
        Endpoint for handling consent service response
        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: response context
        :return: response
        """
        consent_state = context.state[STATE_KEY]
        saved_resp = consent_state["internal_resp"]
        internal_response = InternalResponse.from_dict(saved_resp)

        hash_id = self._get_consent_id(internal_response.requester, internal_response.user_id,
                                       internal_response.attributes)

        try:
            consent_attributes = self._verify_consent(hash_id)
        except ConnectionError as e:
            satosa_logging(logger, logging.ERROR,
                           "Consent service is not reachable, no consent given.", context.state)
            # Send an internal_response without any attributes
            consent_attributes = None

        if consent_attributes is None:
            satosa_logging(logger, logging.INFO, "Consent was NOT given", context.state)
            # If consent was not given, then don't send any attributes
            consent_attributes = []
        else:
            satosa_logging(logger, logging.INFO, "Consent was given", context.state)

        internal_response.attributes = self._filter_attributes(internal_response.attributes, consent_attributes)
        return self._end_consent(context, internal_response)

    def _approve_new_consent(self, context, internal_response, id_hash):
        consent_state = context.state[STATE_KEY]
        consent_state["internal_resp"] = internal_response.to_dict()
        context.state[STATE_KEY] = consent_state

        consent_args = {
            "attr": internal_response.attributes,
            "id": id_hash,
            "redirect_endpoint": "%s/consent%s" % (self.proxy_base, self.endpoint),
            "requester_name": internal_response.requester
        }
        if self.locked_attr:
            consent_args["locked_attrs"] = [self.locked_attr]

        try:
            ticket = self._consent_registration(consent_args)
        except (ConnectionError, UnexpectedResponseError) as e:
            satosa_logging(logger, logging.ERROR, "Consent request failed, no consent given: {}".format(str(e)),
                           context.state)
            # Send an internal_response without any attributes
            internal_response.attributes = {}
            return self._end_consent(context, internal_response)

        consent_redirect = "%s?ticket=%s" % (self.redirect_url, ticket)
        return Redirect(consent_redirect)

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
        if not self.enabled:
            return self.callback_func(context, internal_response)

        consent_state = context.state[STATE_KEY]

        internal_response.attributes = self._filter_attributes(internal_response.attributes, consent_state["filter"])
        id_hash = self._get_consent_id(internal_response.requester, internal_response.user_id,
                                       internal_response.attributes)

        try:
            # Check if consent is already given
            consent_attributes = self._verify_consent(id_hash)
        except ConnectionError:
            satosa_logging(logger, logging.ERROR,
                           "Consent service is not reachable, no consent given.", context.state)
            # Send an internal_response without any attributes
            internal_response.attributes = {}
            return self._end_consent(context, internal_response)

        # Previous consent was given
        if consent_attributes is not None:
            satosa_logging(logger, logging.DEBUG, "Previous consent was given", context.state)
            internal_response.attributes = self._filter_attributes(internal_response.attributes, consent_attributes)
            return self._end_consent(context, internal_response)

        # No previous consent, request consent by user
        return self._approve_new_consent(context, internal_response, id_hash)

    def _filter_attributes(self, attributes, filter):
        return {k: v for k, v in attributes.items() if k in filter}

    def _get_consent_id(self, requester, user_id, filtered_attr):
        """
        Get a hashed id based on requester, user id and filtered attributes

        :type requester: str
        :type user_id: str
        :type filtered_attr: dict[str, str]

        :param requester: The calling requester
        :param user_id: The authorized user id
        :param filtered_attr: a list containing all attributes to be sent
        :return: an id
        """

        filtered_attr_key_list = sorted(filtered_attr.keys())
        hash_str = ""
        for key in filtered_attr_key_list:
            _hash_value = "".join(sorted(filtered_attr[key]))
            hash_str += key + _hash_value
        id_string = "%s%s%s" % (requester, user_id, hash_str)
        return urlsafe_b64encode(hashlib.sha512(id_string.encode("utf-8")).hexdigest().encode("utf-8")).decode("utf-8")

    def _consent_registration(self, consent_args):
        """
        Register a request at the consent service

        :type consent_args: dict
        :rtype: str

        :param consent_args: All necessary parameters for the consent request
        :return: Ticket received from the consent service
        """
        jws = JWS(json.dumps(consent_args), alg=self.signing_key.alg).sign_compact([self.signing_key])
        request = "{}/creq/{}".format(self.api_url, jws)
        res = requests.get(request)

        if res.status_code != 200:
            raise UnexpectedResponseError("Consent service error: %s %s", res.status_code, res.text)

        return res.text

    def _verify_consent(self, consent_id):
        """
        Connects to the consent service using the REST api and checks if the user has given consent

        :type consent_id: str
        :rtype: Optional[List[str]]

        :param consent_id: An id associated to the authenticated user, the calling requester and
        attributes to be sent.
        :return: list attributes given which have been approved by user consent
        """
        request = "{}/verify/{}".format(self.api_url, consent_id)
        res = requests.get(request)

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
        del context.state[STATE_KEY]
        return self.callback_func(context, internal_response)

    def register_endpoints(self):
        """
        Register consent module endpoints

        :rtype: list[(srt, (satosa.context.Context) -> Any)]

        :return: A list of endpoints bound to a function
        """
        return [("^consent%s$" % self.endpoint, self._handle_consent_response)]
