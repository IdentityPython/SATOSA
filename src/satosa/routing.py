"""
Holds satosa routing logic
"""
import logging
import re

from .context import SATOSABadContextError
from .exception import SATOSAError
from .logging_util import satosa_logging

logger = logging.getLogger(__name__)

STATE_KEY = "ROUTER"


class SATOSANoBoundEndpointError(SATOSAError):
    """
    Raised when a given url path is not bound to any endpoint function
    """
    pass


class SATOSAUnknownTargetBackend(SATOSAError):
    """
    Raised when targeting an unknown backend
    """
    pass


class ModuleRouter(object):
    """
    Routes url paths to their bound functions
    and handles the internal routing between frontends and backends.
    """

    def __init__(self, frontends, backends):
        """
        :type frontends: dict[str, satosa.frontends.base.FrontendModule]
        :type backends: dict[str, satosa.backends.base.BackendModule]

        :param frontends: All available frontends used by the proxy. Key as frontend name, value as
        module
        :param backends: All available backends used by the proxy. Key as backend name, value as
        module
        """

        if not frontends and not backends:
            raise ValueError("Need at least one frontend and one backend")

        self.frontends = {name: {"instance": instance, "endpoints": instance.register_endpoints(list(backends.keys()))}
                          for name, instance in frontends.items()}
        self.backends = {name: {"instance": instance, "endpoints": instance.register_endpoints()}
                         for name, instance in backends.items()}

        logger.debug("Loaded backends with endpoints: %s" % backends)
        logger.debug("Loaded frontends with endpoints: %s" % frontends)

    def backend_routing(self, context):
        """
        Returns the targeted backend and an updated state

        :type context: satosa.context.Context
        :rtype satosa.backends.base.BackendModule

        :param context: The request context
        :return: backend
        """
        satosa_logging(logger, logging.DEBUG, "Routing to backend: %s " % context.target_backend, context.state)
        backend = self.backends[context.target_backend]["instance"]
        context.state[STATE_KEY] = context.target_frontend
        return backend

    def frontend_routing(self, context):
        """
        Returns the targeted frontend and original state

        :type context: satosa.context.Context
        :rtype satosa.frontends.base.FrontendModule

        :param context: The response context
        :return: frontend
        """

        target_frontend = context.state[STATE_KEY]
        satosa_logging(logger, logging.DEBUG, "Routing to frontend: %s " % target_frontend, context.state)
        context.target_frontend = target_frontend
        frontend = self.frontends[context.target_frontend]["instance"]
        return frontend

    def _find_registered_frontend_endpoint(self, context):
        # Search for frontend endpoint
        for frontend in self.frontends.keys():
            for regex, spec in self.frontends[frontend]["endpoints"]:
                match = re.search(regex, context.path)
                if match is not None:
                    context.target_frontend = frontend
                    msg = "Frontend request. Module name:'{name}', endpoint: {endpoint}".format(
                        name=frontend,
                        endpoint=context.path)
                    satosa_logging(logger, logging.DEBUG, msg, context.state)
                    return spec

        return None

    def _find_registered_backend_endpoint(self, context):
        # Search for backend endpoint
        for regex, spec in self.backends[context.target_backend]["endpoints"]:
            match = re.search(regex, context.path)
            if match is not None:
                msg = "Backend request. Module name:'{name}', endpoint: {endpoint}".format(
                    name=context.target_backend,
                    endpoint=context.path)
                satosa_logging(logger, logging.DEBUG, msg, context.state)
                return spec

        satosa_logging(logger, logging.DEBUG, "%s not bound to any function" % context.path,
                       context.state)
        return None

    def endpoint_routing(self, context):
        """
        Finds and returns the endpoint function bound to the path

        :type context: satosa.context.Context
        :rtype: ((satosa.context.Context, Any) -> Any, Any)

        :param context: The request context
        :return: registered endpoint and bound parameters
        """
        if context.path is None:
            satosa_logging(logger, logging.DEBUG, "Context did not contain a path!", context.state)
            raise SATOSABadContextError("Context did not contain any path")

        satosa_logging(logger, logging.DEBUG, "Routing path: %s" % context.path, context.state)
        path_split = context.path.split("/")
        backend = path_split[0]

        if backend in self.backends:
            context.target_backend = backend
        else:
            satosa_logging(logger, logging.DEBUG, "Unknown backend %s" % backend, context.state)

        frontend_endpoint = self._find_registered_frontend_endpoint(context)
        if frontend_endpoint:
            return frontend_endpoint

        if backend in self.backends:
            backend_endpoint = self._find_registered_backend_endpoint(context)
            if backend_endpoint:
                return backend_endpoint

        raise SATOSANoBoundEndpointError("'{}' not bound to any function".format(context.path))
