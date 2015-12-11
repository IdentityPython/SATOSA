"""
An account linking module for the satosa proxy
"""
import json
import logging

import requests
from jwkest.jwk import rsa_load, RSAKey
from jwkest.jws import JWS

from satosa.exception import SATOSAAuthenticationError
from satosa.internal_data import InternalResponse
from satosa.logging_util import satosa_logging
from satosa.response import Redirect

LOGGER = logging.getLogger(__name__)


class AccountLinkingModule(object):
    """
    Module for handling account linking and recovery. Uses an external account linking service
    """
    STATE_KEY = "ACCOUNT_LINKING"

    def __init__(self, config, callback_func):
        """
        :type config: satosa.satosa_config.SATOSAConfig
        :type callback_func:
        (satosa.context.Context, satosa.internal_data.InternalResponse) -> satosa.response.Response

        :param config: The SATOSA proxy config
        :param callback_func: Callback function when the linking is done
        """
        self.config = config
        self.callback_func = callback_func
        self.enabled = \
            "ACCOUNT_LINKING" in config and ("enable" not in config.ACCOUNT_LINKING or
                                             config.ACCOUNT_LINKING["enable"])
        if self.enabled:
            self.proxy_base = config.BASE
            self.al_rest_uri = config.ACCOUNT_LINKING["rest_uri"]
            self.al_redirect = config.ACCOUNT_LINKING["redirect"]
            self.endpoint = config.ACCOUNT_LINKING["endpoint"]
            self.verify_ssl = True if "verify_ssl" not in config.ACCOUNT_LINKING else \
                config.ACCOUNT_LINKING["verify_ssl"]
            _bkey = rsa_load(config.ACCOUNT_LINKING["sign_key"])
            self.sign_key = RSAKey().load_key(_bkey)
            self.sign_key.use = "sig"
            LOGGER.info("Account linking is active")
        else:
            LOGGER.info("Account linking is not active")

    def _handle_al_response(self, context):
        """
        Endpoint for handling account linking service response

        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: The current context
        :return: response
        """
        saved_state = context.state.get(AccountLinkingModule.STATE_KEY)
        internal_response = InternalResponse.from_dict(saved_state)
        return self.manage_al(context, internal_response)

    def manage_al(self, context, internal_response):
        """
        Manage account linking and recovery

        :type context: satosa.context.Context
        :type internal_response: satosa.internal_data.InternalResponse
        :rtype: satosa.response.Response

        :param context:
        :param internal_response:
        :return: response
        """

        if not self.enabled:
            return self.callback_func(context, internal_response)

        issuer = internal_response.auth_info.issuer
        id = internal_response.get_user_id()
        status_code, message = self._get_uuid(context, issuer, id)

        if status_code == 200:
            satosa_logging(LOGGER, logging.INFO, "issuer/id pair is linked in AL service",
                           context.state)
            internal_response.set_user_id(message)
            try:
                context.state.remove(AccountLinkingModule.STATE_KEY)
            except KeyError:
                pass
            return self.callback_func(context, internal_response)

        return self._approve_new_id(context, internal_response, message)

    def _approve_new_id(self, context, internal_response, ticket):
        """
        Redirect the user to approve the new id

        :type context: satosa.context.Context
        :type internal_response: satosa.internal_data.InternalResponse
        :type ticket: str
        :rtype: satosa.response.Redirect

        :param context: The current context
        :param internal_response: The internal response
        :param ticket: The ticket given by the al service
        :return: A redirect to approve the new id linking
        """
        satosa_logging(LOGGER, logging.INFO, "A new ID must be linked by the AL service",
                       context.state)
        context.state.add(AccountLinkingModule.STATE_KEY, internal_response.to_dict())
        return Redirect("%s/%s" % (self.al_redirect, ticket))

    def _get_uuid(self, context, issuer, id):
        """
        Ask the account linking service for a uuid.
        If the given issuer/id pair is not linked, then the function will return a ticket.
        This ticket should be used for linking the issuer/id pair to the user account

        :type context: satosa.context.Context
        :type issuer: str
        :type id: str
        :rtype: (int, str)

        :param context: The current context
        :param issuer: the issuer used for authentication
        :param id: the given id
        :return: response status code and message
            (200, uuid) or (400, ticket)
        """
        data = {"idp": issuer, "id": id,
                "redirect_endpoint": "%s/account_linking/%s" % (self.proxy_base,
                                                                self.endpoint)}
        jws = self._to_jws(data)

        try:
            request = "{}/get_id?jwt={}".format(self.al_rest_uri, jws)
            response = requests.get(request, verify=self.verify_ssl)
        except ConnectionError as con_exc:
            msg = "Could not connect to account linking service"
            satosa_logging(LOGGER, logging.CRITICAL, msg, context.state, exc_info=True)
            raise SATOSAAuthenticationError(context.state, msg) from con_exc

        if response.status_code != 200 and response.status_code != 404:
            msg = "Got status code '%s' from account linking service" % (response.status_code)
            satosa_logging(LOGGER, logging.CRITICAL, msg, context.state)
            raise SATOSAAuthenticationError(context.state, msg)

        return response.status_code, response.text

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
        return [("^account_linking/%s?(.*)$" % self.endpoint, self._handle_al_response)]
