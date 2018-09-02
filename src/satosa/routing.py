"""
Holds satosa routing logic
"""
import logging
import re
import time

from .context import SATOSABadContextError
from .exception import SATOSAError
from .logging_util import satosa_logging
from threading import Timer

logger = logging.getLogger(__name__)

STATE_KEY = "ROUTER"
TIMER_KEY = "TIMER"

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

#def _timeout(context):
    #logger.debug("Timeout %s" % context.state['SESSION_ID'])

class ModuleRouter(object):
    class UnknownEndpoint(ValueError):
        pass

    """
    Routes url paths to their bound functions
    and handles the internal routing between frontends and backends.
    """

    def __init__(self, frontends, backends, micro_services):
        """
        :type frontends: dict[str, satosa.frontends.base.FrontendModule]
        :type backends: dict[str, satosa.backends.base.BackendModule]
        :type micro_services: Sequence[satosa.micro_services.base.MicroService]

        :param frontends: All available frontends used by the proxy. Key as frontend name, value as
        module
        :param backends: All available backends used by the proxy. Key as backend name, value as
        module
        :param micro_services: All available micro services used by the proxy. Key as micro service name, value as
        module
        """

        if not frontends and not backends:
            raise ValueError("Need at least one frontend and one backend")

        backend_names = [backend.name for backend in backends]
        self.frontends = {instance.name: {"instance": instance,
                                          "endpoints": instance.register_endpoints(backend_names)}
                          for instance in frontends}
        self.backends = {instance.name: {"instance": instance, "endpoints": instance.register_endpoints()}
                         for instance in backends}

        if micro_services:
            self.micro_services = {instance.name: {"instance": instance, "endpoints": instance.register_endpoints()}
                                   for instance in micro_services}
        else:
            self.micro_services = {}

        logger.debug("Loaded backends with endpoints: %s" % backends)
        logger.debug("Loaded frontends with endpoints: %s" % frontends)
        logger.debug("Loaded micro services with endpoints: %s" % micro_services)
        self.timer = {}
        Timer(1, self._cleanup).start()

    def _cleanup(self):
        while True:
            #logger.debug("Timout cleanup thread")
            for k, v in list(self.timer.items()):
                if not v.is_alive():
                    del self.timer[k]
                    logger.debug("Cleanup timer %s" % k)
            time.sleep(1)

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
        #self.timer[context.state['SESSION_ID']] = Timer(3, lambda context: logger.debug("Timeout %s" % context.state['SESSION_ID']))
        self.timer[context.state['SESSION_ID']] = Timer(3, lambda: satosa_logging(logger, logging.DEBUG, "Timeout timer", context.state))
        self.timer[context.state['SESSION_ID']].start()
        satosa_logging(logger, logging.DEBUG, "Started timer", context.state)
        #logger.debug("Started timer: %s" % context.state['SESSION_ID'])
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
        satosa_logging(logger, logging.DEBUG, "Stopped timer", context.state)
        #self.timer[context.state['SESSION_ID']].cancel()
        logger.debug("Stopped timer: %s" % context.state['SESSION_ID'])
        return frontend

    def _find_registered_endpoint_for_module(self, module, context):
        for regex, spec in module["endpoints"]:
            match = re.search(regex, context.path)
            if match is not None:
                msg = "Found registered endpoint: module name:'{name}', endpoint: {endpoint}".format(
                    name=module["instance"].name,
                    endpoint=context.path)
                satosa_logging(logger, logging.DEBUG, msg, context.state)
                return spec

        return None

    def _find_registered_backend_endpoint(self, context):
        return self._find_registered_endpoint_for_module(self.backends[context.target_backend], context)

    def _find_registered_endpoint(self, context, modules):
        for module in modules.values():
            matched = self._find_registered_endpoint_for_module(module, context)
            if matched:
                return module["instance"].name, matched

        raise ModuleRouter.UnknownEndpoint(context.path)

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

        try:
            name, frontend_endpoint = self._find_registered_endpoint(context, self.frontends)
        except ModuleRouter.UnknownEndpoint as e:
            pass
        else:
            context.target_frontend = name
            return frontend_endpoint

        try:
            name, micro_service_endpoint = self._find_registered_endpoint(context, self.micro_services)
        except ModuleRouter.UnknownEndpoint as e:
            pass
        else:
            context.target_micro_service = name
            return micro_service_endpoint

        if backend in self.backends:
            backend_endpoint = self._find_registered_backend_endpoint(context)
            if backend_endpoint:
                return backend_endpoint

        raise SATOSANoBoundEndpointError("'{}' not bound to any function".format(context.path))
