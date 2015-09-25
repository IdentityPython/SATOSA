from satosa.plugin_loader import load_backends, load_frontends
from satosa.routing import ModuleRouter

__author__ = 'mathiashedstrom'


class SATOSABase():
    def __init__(self, config):
        self.config = config
        backends = load_backends(self.config, self._auth_resp_callback_func)
        frontends = load_frontends(self.config, self._auth_req_callback_func)

        self.module_router = ModuleRouter(frontends, backends)

    def _auth_req_callback_func(self, context, internal_request, state):
        """
        This function is called by a frontend module when an authorization request has been processed.

        :type context: satosa.request_context.RequestContext
        :type internal_request: dict
        :type state: str

        :param context: The request context
        :param internal_request: request processed by the frontend
        :param state: the current state

        :return: response
        """
        backend, state = self.module_router.backend_routing(context, state)
        return backend.start_auth(context, internal_request, state)

    def _auth_resp_callback_func(self, context, internal_response, state):
        """
        This function is called by a backend module when the authorization is complete.

        :type context: satosa.request_context.RequestContext
        :type internal_response: dict
        :type state: str

        :param context: The request context
        :param internal_response: The authentication response
        :param state: The current state
        :return: response
        """

        frontend, state = self.module_router.frontend_routing(state)
        return frontend.handle_authn_response(context, internal_response, state)

    def _run_bound_endpoint(self, context, spec):
        """

        :type context: satosa.request_context.RequestContext
        :type spec: (satosa.request_context.RequestContext) -> object

        :param context: The request context
        :param spec: bound endpoint function
        :return: response
        """
        if isinstance(spec, tuple):
            return spec[0](context, *spec[1:])
        else:
            return spec()

    def run(self, context):
        """
        Runs the satosa proxy with the given context.

        :type context: satosa.request_context.RequestContext

        :param context: The request context
        :return: response
        """
        spec = self.module_router.endpoint_routing(context)
        return self._run_bound_endpoint(context, spec)
