"""
Holds satosa routing logic
"""
import logging
import re

from satosa.context import BadContextError

__author__ = 'mathiashedstrom'

LOGGER = logging.getLogger(__name__)

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

    STATE_KEY = "ROUTER"

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

        LOGGER.debug("Loaded backends with endpoints: %s" % backends)
        LOGGER.debug("Loaded frontends with endpoints: %s" % frontends)

    def backend_routing(self, context, state):
        """
        Returns the targeted backend and an updated state

        :type context: satosa.context.Context
        :type state: satosa.state.State
        :rtype satosa.backends.base.BackendModule

        :param context: The request context
        :param state: The current state
        :return: backend
        """
        LOGGER.debug("Routing to backend: %s " % context._target_backend)
        backend = self.backends[context._target_backend]["instance"]
        state.add(ModuleRouter.STATE_KEY, context._target_frontend)
        return backend

    def frontend_routing(self, context, state):
        """
        Returns the targeted frontend and original state

        :type context: satosa.context.Context
        :type state: satosa.state.State
        :rtype satosa.frontends.base.FrontendModule

        :param context: The response context
        :param state: The state created in the incoming function
        :return: frontend
        """

        target_frontend = state.get(ModuleRouter.STATE_KEY)
        LOGGER.debug("Routing to backend: %s " % target_frontend)
        context._target_frontend = target_frontend
        frontend = self.frontends[context._target_frontend]["instance"]
        return frontend

    def _validate_context(self, context):
        """
        Validates values in the context needed by the ModuleRouter.
        Raises BadContextError if any error.

        :type context: satosa.context.Context
        :rtype: None

        :param context: The request context
        :return: None
        """
        if not context:
            LOGGER.error("Context was None!")
            raise BadContextError("Context is None")
        if context.path is None:
            LOGGER.error("Context did not contain a path!")
            raise BadContextError("Context did not contain any path")

    def endpoint_routing(self, context):
        """
        Finds and returns the endpoint function bound to the path

        :type context: satosa.context.Context
        :rtype: ((satosa.context.Context, Any) -> Any, Any)

        :param context: The request context
        :return: registered endpoint and bound parameters
        """
        LOGGER.debug("Routing path: %s" % context.path)
        self._validate_context(context)

        path_split = context.path.split('/')
        backend = path_split[0]

        if backend not in self.backends:
            LOGGER.warn("Unknown backend %s" % backend)
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
        LOGGER.warn("%s not bound to any function" % context.path)
        raise NoBoundEndpointError("{} not bound to any function".format(context.path))
