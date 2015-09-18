from vopaas_proxy.plugin_loader import load_backends, load_frontends
from vopaas_proxy.routing import ModuleRouter

__author__ = 'mathiashedstrom'


class SATOSABase():
    def __init__(self, config):
        self.config = config
        backends = load_backends(self.config, self._auth_resp_callback_func)
        frontends = load_frontends(self.config, self._auth_req_callback_func)

        self.module_router = ModuleRouter(frontends, backends)

    def _auth_req_callback_func(self, context, internal_request, state):
        """
        An Authentication request has been requested, this is the second step
        in the sequence

        :param info: Information about the authentication request
        :param environ: WSGI environment
        :param start_response: WSGI start_response
        :param state_key:

        :return: response
        """
        backend, state = self.module_router.incoming(context, state)
        return backend.start_auth(context, internal_request, state)

    def _auth_resp_callback_func(self, context, internal_response, state):
        """
        An authentication response has been received and now an authentication
        response from this server should be constructed.

        :param internal_response: The Authentication response
        :param instance: SP instance that received the authentication response
        :return: response
        """
        frontend, state = self.module_router.outgoing(state)
        return frontend.handle_authn_response(context, internal_response, state)

    def _run_bound_endpoint(self, context, spec):
        if isinstance(spec, tuple):
            return spec[0](context, *spec[1:])
        else:
            return spec()

    def run(self, context):
        spec = self.module_router.url_routing(context)
        return self._run_bound_endpoint(context, spec)
