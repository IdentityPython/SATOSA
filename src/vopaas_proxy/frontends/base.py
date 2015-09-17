__author__ = 'mathiashedstrom'


class FrontendBase():
    def __init__(self, auth_req_callback_func):
        self.auth_req_callback_func = auth_req_callback_func

    def handle_authn_request(self, context, binding_in):
        raise NotImplementedError()

    def handle_authn_response(self, context, internal_response, state):
        raise NotImplementedError()

    def register_endpoints(self, providers):
        raise NotImplementedError()
