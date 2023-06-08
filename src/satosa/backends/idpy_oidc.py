"""
OIDC backend module.
"""
import logging
from datetime import datetime

from idpyoidc.server.user_authn.authn_context import UNSPECIFIED

import satosa.logging_util as lu
from satosa.backends.base import BackendModule
from satosa.exception import SATOSAAuthenticationError
from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData

logger = logging.getLogger(__name__)

"""
OIDC/OAuth2 backend module.
"""
from idpyoidc.client.oauth2.stand_alone_client import StandAloneClient


class IdpyOIDCBackend(BackendModule):
    """
    Backend module for OIDC and OAuth 2.0, can be directly used.
    """

    def __init__(self, outgoing, internal_attributes, config, base_url, name):
        """
        :type outgoing:
        (satosa.context.Context, satosa.internal.InternalData) -> satosa.response.Response
        :type internal_attributes: dict[str, dict[str, list[str] | str]]
        :type config: dict[str, Any]
        :type base_url: str
        :type name: str

        :param outgoing: Callback should be called by the module after
                                   the authorization in the backend is done.
        :param internal_attributes: Internal attribute map
        :param config: The module config
        :param base_url: base url of the service
        :param name: name of the plugin
        """
        super().__init__(outgoing, internal_attributes, base_url, name)

        self.client = StandAloneClient(config=config["client_config"],
                                       client_type=config["client_config"]['client_type'])
        # Deal with provider discovery and client registration
        self.client.do_provider_info()
        self.client.do_client_registration()

    def start_auth(self, context, internal_request):
        """
        See super class method satosa.backends.base#start_auth

        :type context: satosa.context.Context
        :type internal_request: satosa.internal.InternalData
        :rtype satosa.response.Redirect
        """
        return self.client.init_authorization()

    def register_endpoints(self):
        """
        Creates a list of all the endpoints this backend module needs to listen to. In this case
        it's the authentication response from the underlying OP that is redirected from the OP to
        the proxy.
        :rtype: Sequence[(str, Callable[[satosa.context.Context], satosa.response.Response]]
        :return: A list that can be used to map the request to SATOSA to this endpoint.
        """

        return self.client.context.claims.get_usage('authorization_endpoint')

    def _check_error_response(self, response, context):
        """
        Check if the response is an error response.
        :param response: the response from finalize()
        :type response: oic.oic.message
        :raise SATOSAAuthenticationError: if the response is an OAuth error response
        """
        if "error" in response:
            msg = "{name} error: {error} {description}".format(
                name=type(response).__name__,
                error=response["error"],
                description=response.get("error_description", ""),
            )
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.debug(logline)
            raise SATOSAAuthenticationError(context.state, "Access denied")

    def _authn_response(self, context):
        """
        Handles the authentication response from the AS.

        :type context: satosa.context.Context
        :rtype: satosa.response.Response
        :param context: The context in SATOSA
        :return: A SATOSA response. This method is only responsible to call the callback function
        which generates the Response object.
        """

        _info = self.client.finalize(context.request)
        self._check_error_response(_info, context)

        try:
            auth_info = self.auth_info(context.request)
        except NotImplementedError:
            auth_info = AuthenticationInformation(auth_class_ref=UNSPECIFIED,
                                                  timestamp=str(datetime.now()),
                                                  issuer=_info["issuer"])

        attributes = self.converter.to_internal(
            self.client.client_type, _info['userinfo'],
        )

        internal_response = InternalData(
            auth_info=auth_info,
            attributes=attributes,
            subject_id=_info['userinfo']['sub']
        )
        return internal_response

    def auth_info(self, request):
        """
        Creates the SATOSA authentication information object.
        :type request: dict[str, str]
        :rtype: AuthenticationInformation

        :param request: The request parameters in the authentication response sent by the AS.
        :return: How, who and when the authentication took place.
        """
        raise NotImplementedError("Method 'auth_info' must be implemented in the subclass!")
