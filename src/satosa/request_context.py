__author__ = 'mathiashedstrom'


class RequestContext():
    def __init__(self):
        self.path = None
        self.request = None
        self.target_backend = None
        self.target_frontend = None
        self.internal_data = {}
