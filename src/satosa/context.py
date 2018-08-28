from .exception import SATOSAError


class SATOSABadContextError(SATOSAError):
    """
    Raise this exception if validating the Context and failing.
    """
    pass


"""
Holds methods for sending internal data through the satosa proxy
"""
class Context(object):
    """
    Holds information about the current request.
    """
    KEY_BACKEND_METADATA_STORE = 'metadata_store'
    KEY_TARGET_ENTITYID = 'target_entity_id'

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

    def __repr__(self):
        from pprint import pformat
        return pformat(vars(self))

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

    def target_entity_id_from_path(self):
        target_entity_id = self.path.split("/")[1]
        return target_entity_id

    def decorate(self, key, value):
        """
        Add information to the context
        """

        self.internal_data[key] = value
        return self

    def get_decoration(self, key):
        """
        Retrieve information from the context
        """

        value = self.internal_data.get(key)
        return value
