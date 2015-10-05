"""
The SATOSA main module
"""
from satosa.plugin_loader import load_backends, load_frontends, load_micro_services
from satosa.routing import ModuleRouter

__author__ = 'mathiashedstrom'


class SATOSABase(object):
    """
    Base class for a satosa proxy server.
    Does not contain any server parts.
    """

    def __init__(self, config):
        """
        Creates a satosa proxy base

        :type config: satosa.satosa_config.SATOSAConfig

        :param config: satosa proxy config
        """
        if config is None:
            raise ValueError("Missing configuration")

        self.config = config
        backends = load_backends(self.config, self._auth_resp_callback_func)
        frontends = load_frontends(self.config, self._auth_req_callback_func)

        if "MICRO_SERVICES" in self.config:
            self.request_micro_services, self.response_micro_services = load_micro_services(self.config.PLUGIN_PATH,
                                                                                            self.config.MICRO_SERVICES)
        self.module_router = ModuleRouter(frontends, backends)

    def _auth_req_callback_func(self, context, internal_request, state):
        """
        This function is called by a frontend module when an authorization request has been processed.

        :type context: satosa.context.Context
        :type internal_request: satosa.internal_data.InternalRequest
        :type state: str

        :param context: The request context
        :param internal_request: request processed by the frontend
        :param state: the current state

        :return: response
        """
        backend, state = self.module_router.backend_routing(context, state)
        context.request = None
        if self.request_micro_services:
            internal_request = self.request_micro_services.process_service_queue(context, internal_request)
        return backend.start_auth(context, internal_request, state)

    def _auth_resp_callback_func(self, context, internal_response, state):
        """
        This function is called by a backend module when the authorization is complete.

        :type context: satosa.context.Context
        :type internal_response: satosa.internal_data.InternalResponse
        :type state: str

        :param context: The request context
        :param internal_response: The authentication response
        :param state: The current state
        :return: response
        """

        frontend, state = self.module_router.frontend_routing(state)
        context.request = None
        if self.response_micro_services:
            internal_response = self.response_micro_services.process_service_queue(context, internal_response)
        return frontend.handle_authn_response(context, internal_response, state)

    def _run_bound_endpoint(self, context, spec):
        """

        :type context: satosa.context.Context
        :type spec: ((satosa.context.Context, Any) -> Any, Any) | (satosa.context.Context, Any) -> Any

        :param context: The request context
        :param spec: bound endpoint function
        :return: response
        """
        if isinstance(spec, tuple):
            return spec[0](context, *spec[1:])
        else:
            return spec(context)

    def run(self, context):
        """
        Runs the satosa proxy with the given context.

        :type context: satosa.context.Context

        :param context: The request context
        :return: response
        """
        spec = self.module_router.endpoint_routing(context)
        return self._run_bound_endpoint(context, spec)
