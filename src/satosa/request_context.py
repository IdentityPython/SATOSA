__author__ = 'mathiashedstrom'


class BadContextError(Exception):
    pass


class RequestContext():
    def __init__(self):
        self._path = None
        self.request = None
        self.target_backend = None
        self.target_frontend = None
        self.internal_data = {}

    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, p):
        if not p:
            raise ValueError("path can't be set to None")
        elif p.startswith('/'):
            raise ValueError("path can't start with '/'")
        self._path = p
