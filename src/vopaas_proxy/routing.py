from base64 import b64encode, b64decode
import json
import re

__author__ = 'mathiashedstrom'

ENVIRON_BACKEND_ATTR_NAME = "satosa.backend"
ENVIRON_FRONTEND_ATTR_NAME = "satosa.frontend"


class ModuleRouter():
    def __init__(self, frontends, backends):
        """
        :param frontends: All available frontends
        :param backends: All available backends
        """

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

    def incoming(self, context, state):
        """
        Returns the targeted backend and an updated state
        :param context: The request context
        :param state: The state of a frontend
        :return: (backend, state)
        """

        backend = self.backends[context.target_backend]["instance"]
        satosa_state = {"state_key": state, "frontend": context.target_frontend}
        satosa_state = b64encode(json.dumps(satosa_state).encode("UTF-8")).decode("UTF-8")
        return backend, satosa_state

    def outgoing(self, state):
        """
        Returns the targeted frontend and original state
        :param state: The state created in the incoming function
        :return: (frontend, state)
        """

        unpacked_state = json.loads(b64decode(state.encode("UTF-8")).decode("UTF-8"))
        frontend = self.frontends[unpacked_state["frontend"]]["instance"]
        request_state = unpacked_state["state_key"]
        return frontend, request_state

    def url_routing(self, context):
        """
        Finds and returns the endpoint function bound to the path
        :param context: The request context
        :param path: url path
        :return: registered endpoint
        """

        path_split = context.path.split('/')
        backend = path_split[0]

        context.target_backend = backend

        # Search for frontend endpoint
        for frontend in self.frontends.keys():
            for regex, spec in self.frontends[frontend]["endpoints"]:
                match = re.search(regex, context.path)
                if match is not None:
                    context.target_frontend = frontend
                    return spec

        # Search for backend endpoint
        for regex, spec in self.backends[backend]["endpoints"]:
            match = re.search(regex, context.path)
            if match is not None:
                return spec
