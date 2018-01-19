import satosa.micro_services.base
from satosa.logging_util import satosa_logging

from satosa.response import Response

import logging

logger = logging.getLogger(__name__)

class PingFrontend(satosa.frontends.base.FrontendModule):
    """
    SATOSA frontend that responds to a query with a simple
    200 OK, intended to be used as a simple heartbeat monitor.
    """
    logprefix = "PING:"

    def __init__(self, auth_req_callback_func, internal_attributes, config, base_url, name):
        super().__init__(auth_req_callback_func, internal_attributes, base_url, name)

        self.config = config

    def handle_authn_response(self, context, internal_resp, extra_id_token_claims=None):
        """
        See super class method satosa.frontends.base.FrontendModule#handle_authn_response
        :type context: satosa.context.Context
        :type internal_response: satosa.internal_data.InternalResponse
        :rtype oic.utils.http_util.Response
        """
        raise NotImplementedError()

    def handle_backend_error(self, exception):
        """
        See super class satosa.frontends.base.FrontendModule
        :type exception: satosa.exception.SATOSAError
        :rtype: oic.utils.http_util.Response
        """
        raise NotImplementedError()

    def register_endpoints(self, backend_names):
        """
        See super class satosa.frontends.base.FrontendModule
        :type backend_names: list[str]
        :rtype: list[(str, ((satosa.context.Context, Any) -> satosa.response.Response, Any))]
        :raise ValueError: if more than one backend is configured
        """
        url_map = [("^{}".format(self.name), self.ping_endpoint)]

        return url_map

    def ping_endpoint(self, context):
        """
        """
        logprefix = PingFrontend.logprefix
        satosa_logging(logger, logging.DEBUG, "{} ping returning 200 OK".format(logprefix), context.state)

        msg = " "

        return Response(msg)
