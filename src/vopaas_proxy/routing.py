from base64 import b64encode, b64decode
import json
import re

__author__ = 'mathiashedstrom'

ENVIRON_BACKEND_ATTR_NAME = "satosa.backend"
ENVIRON_FRONTEND_ATTR_NAME = "satosa.frontend"


class ModuleRouter():
    def __init__(self, frontends, backends):
        """
        :param frontends: All available frontends and their endpoints
        :param backends: All available backends and their endpoints
        """

        self.frontends = frontends
        self.backends = backends

    def incoming(self, environ, state):
        """
        Returns the targeted backend and an updated state
        :param environ: The HTTP application environment
        :param state: The state of a frontend
        :return: (backend, state)
        """

        backend = self.backends[environ[ENVIRON_BACKEND_ATTR_NAME]]["instance"]
        satosa_state = {"state_key": state, "frontend": environ[ENVIRON_FRONTEND_ATTR_NAME]}
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

    def url_routing(self, environ, path):
        """
        Finds and returns the endpoint function bound to the path
        :param environ: The HTTP application environment
        :param path: url path
        :return: registered endpoint
        """

        path_split = path.split('/')
        backend = path_split[0]

        environ[ENVIRON_BACKEND_ATTR_NAME] = backend
        environ[ENVIRON_FRONTEND_ATTR_NAME] = None

        # Search for frontend endpoint
        for frontend in self.frontends.keys():
            for regex, spec in self.frontends[frontend]["endpoints"]:
                match = re.search(regex, path)
                if match is not None:
                    environ[ENVIRON_FRONTEND_ATTR_NAME] = frontend
                    return spec

        # Search for backend endpoint
        for regex, spec in self.backends[backend]["endpoints"]:
            match = re.search(regex, path)
            if match is not None:
                return spec
