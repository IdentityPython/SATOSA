__author__ = 'mathiashedstrom'


class BackendBase(object):
    def __init__(self, auth_callback_func):
        self.auth_callback_func = auth_callback_func

    def start_auth(self, context, request_info, state):
        raise NotImplementedError()

    def register_endpoints(self):
        raise NotImplementedError()
