"""
An account linking module for the satosa proxy
"""
import json
import logging

import requests
from jwkest.jwk import rsa_load, RSAKey
from jwkest.jws import JWS

from ..exception import SATOSAAuthenticationError
from ..internal_data import InternalResponse
from ..logging_util import satosa_logging
from ..micro_services.base import ResponseMicroService
from ..response import Redirect

logger = logging.getLogger(__name__)


class AccountLinking(ResponseMicroService):
    """
    Module for handling account linking and recovery. Uses an external account linking service
    """

    def __init__(self, config, *args, **kwargs):
        """
        :type config: satosa.satosa_config.SATOSAConfig
        :param config: The SATOSA proxy config
        """
        super().__init__(*args, **kwargs)
        self.api_url = config["api_url"]
        self.redirect_url = config["redirect_url"]
        self.signing_key = RSAKey(key=rsa_load(config["sign_key"]), use="sig", alg="RS256")
        self.endpoint = "/handle_account_linking"
        logger.info("Account linking is active")

    def _handle_al_response(self, context):
        """
        Endpoint for handling account linking service response

        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: The current context
        :return: response
        """
        saved_state = context.state[self.name]
        internal_response = InternalResponse.from_dict(saved_state)
        status_code, message = self._get_uuid(context, internal_response.auth_info.issuer, internal_response.user_id)

        if status_code == 200:
            satosa_logging(logger, logging.INFO, "issuer/id pair is linked in AL service",
                           context.state)
            internal_response.user_id = message
            del context.state[self.name]
            return super().process(context, internal_response)
        else:
            raise SATOSAAuthenticationError(context.state, "Could not link account for user")

    def process(self, context, internal_response):
        """
        Manage account linking and recovery

        :type context: satosa.context.Context
        :type internal_response: satosa.internal_data.InternalResponse
        :rtype: satosa.response.Response

        :param context:
        :param internal_response:
        :return: response
        """

        status_code, message = self._get_uuid(context, internal_response.auth_info.issuer, internal_response.user_id)

        if status_code == 200:
            satosa_logging(logger, logging.INFO, "issuer/id pair is linked in AL service",
                           context.state)
            internal_response.user_id = message
            try:
                del context.state[self.name]
            except KeyError:
                pass
            return super().process(context, internal_response)

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
        satosa_logging(logger, logging.INFO, "A new ID must be linked by the AL service",
                       context.state)
        context.state[self.name] = internal_response.to_dict()
        return Redirect("%s/%s" % (self.redirect_url, ticket))

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
            (200, uuid) or (404, ticket)
        """
        data = {
            "idp": issuer,
            "id": id,
            "redirect_endpoint": "%s/account_linking%s" % (self.base_url, self.endpoint)
        }
        jws = JWS(json.dumps(data), alg=self.signing_key.alg).sign_compact([self.signing_key])

        try:
            request = "{}/get_id?jwt={}".format(self.api_url, jws)
            response = requests.get(request)
        except requests.ConnectionError as con_exc:
            msg = "Could not connect to account linking service"
            satosa_logging(logger, logging.CRITICAL, msg, context.state, exc_info=True)
            raise SATOSAAuthenticationError(context.state, msg) from con_exc

        if response.status_code not in [200, 404]:
            msg = "Got status code '%s' from account linking service" % (response.status_code)
            satosa_logging(logger, logging.CRITICAL, msg, context.state)
            raise SATOSAAuthenticationError(context.state, msg)

        return response.status_code, response.text

    def register_endpoints(self):
        """
        Register consent module endpoints

        :rtype: list[(srt, (satosa.context.Context) -> Any)]

        :return: A list of endpoints bound to a function
        """
        return [("^account_linking%s$" % self.endpoint, self._handle_al_response)]
