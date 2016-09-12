"""
Holds methods for sending internal data through the satosa proxy
"""
from .exception import SATOSAError


class SATOSABadContextError(SATOSAError):
    """
    Raise this exception if validating the Context and failing.
    """
    pass


class Context(object):
    """
    Holds information about the current request.
    """

    def __init__(self):
        self._path = None
        self.request = None
        self.target_backend = None
        self.target_frontend = None
        self.target_micro_service = None
        # This dict is a data carrier between frontend and backend modules.
        self.internal_data = {}
        self.cookie = None
        self.state = None

    @property
    def path(self):
        """
        Get the path

        :rtype: str

        :return: context path
        """
        return self._path

    @path.setter
    def path(self, p):
        """
        Inserts a path to the context.
        This path is striped by the base_url, so for example:
            A path BASE_URL/ENDPOINT_URL, would be inserted as only ENDPOINT_URL
            https://localhost:8092/sso/redirect -> sso/redirect

        :type p: str

        :param p: A path to an endpoint.
        :return: None
        """
        if not p:
            raise ValueError("path can't be set to None")
        elif p.startswith('/'):
            raise ValueError("path can't start with '/'")
        self._path = p
