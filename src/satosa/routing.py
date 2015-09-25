"""
Holds satosa routing logic
"""
from base64 import urlsafe_b64decode, urlsafe_b64encode
import json
import re
from satosa.request_context import BadContextError

__author__ = 'mathiashedstrom'


class NoBoundEndpointError(Exception):
    """
    Raised when a given url path is not bound to any endpoint function
    """
    pass


class UnknownTargetBackend(Exception):
    """
    Raised when targeting an unknown backend
    """
    pass


class ModuleRouter():
    """
    Routes url paths to their bound functions
    and handles the internal routing between frontends and backends.
    """
    def __init__(self, frontends, backends):
        """
        :type frontends: dict[str, satosa.frontends.base.FrontendModule]
        :type backends: dict[str, satosa.backends.base.BackendModule]

        :param frontends: All available frontends used by the proxy. Key as frontend name, value as module
        :param backends: All available backends used by the proxy. Key as backend name, value as module
        """

        if not (frontends and backends):
            raise ValueError("Need at least one frontend and backend")

        self.frontends = {}
        self.backends = {}

        for backend in backends:
            self.backends[backend] = {"instance": backends[backend],
                                      "endpoints": backends[backend].register_endpoints()}

        providers = list(backends.keys())
        for frontend in frontends:
            self.frontends[frontend] = {"instance": frontends[frontend],
                                        "endpoints": frontends[frontend].register_endpoints(
                                            providers)}

    def backend_routing(self, context, state):
        """
        Returns the targeted backend and an updated state

        :type context: satosa.request_context.RequestContext
        :type state: str
        :rtype (satosa.backends.base.BackendModule, str)

        :param context: The request context
        :param state: The current state
        :return: (backend, state)
        """

        backend = self.backends[context._target_backend]["instance"]
        satosa_state = {"state_key": state, "frontend": context._target_frontend}
        satosa_state = urlsafe_b64encode(json.dumps(satosa_state).encode("UTF-8")).decode("UTF-8")
        return backend, satosa_state

    def frontend_routing(self, state):
        """
        Returns the targeted frontend and original state

        :type state: str
        :rtype (satosa.frontends.base.FrontendModule, str)

        :param state: The state created in the incoming function
        :return: (frontend, state)
        """

        unpacked_state = json.loads(urlsafe_b64decode(state.encode("UTF-8")).decode("UTF-8"))
        frontend = self.frontends[unpacked_state["frontend"]]["instance"]
        request_state = unpacked_state["state_key"]
        return frontend, request_state

    def _validate_context(self, context):
        """
        Validates values in the context needed by the ModuleRouter.
        Raises BadContextError if any error.

        :type context: satosa.request_context.RequestContext
        :rtype: None

        :param context: The request context
        :return: None
        """
        if not context:
            raise BadContextError("Context is None")
        if context.path is None:
            raise BadContextError("Context did not contain any path")

    def endpoint_routing(self, context):
        """
        Finds and returns the endpoint function bound to the path

        :type context: satosa.request_context.RequestContext
        :rtype: (function, *args)

        :param context: The request context
        :return: registered endpoint and bound parameters
        """
        self._validate_context(context)

        path_split = context.path.split('/')
        backend = path_split[0]

        if backend not in self.backends:
            raise UnknownTargetBackend("Unknown backend {}".format(backend))

        context._target_backend = backend

        # Search for frontend endpoint
        for frontend in self.frontends.keys():
            for regex, spec in self.frontends[frontend]["endpoints"]:
                match = re.search(regex, context.path)
                if match is not None:
                    context._target_frontend = frontend
                    return spec

        # Search for backend endpoint
        for regex, spec in self.backends[backend]["endpoints"]:
            match = re.search(regex, context.path)
            if match is not None:
                return spec

        raise NoBoundEndpointError("{} not bound to anny function".format(context.path))
