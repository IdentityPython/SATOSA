"""
Holds a base class for frontend modules used in the SATOSA proxy.
"""
__author__ = 'mathiashedstrom'


class FrontendModule(object):
    """
    Base class for a frontend module.
    """

    def __init__(self, auth_req_callback_func):
        """
        :type auth_req_callback_func: (satosa.context.Context, dict, str) -> Any

        :param auth_req_callback_func: Callback should be called by the module after the authorization response
                                       has been processed.
        """
        self.auth_req_callback_func = auth_req_callback_func

    def handle_authn_response(self, context, internal_response, state):
        """
        If an authorization has been successful in a backend, this function is called and is supposed to send an
        authorization response to the client.

        :type context: satosa.context.Context
        :type internal_response: dict
        :type state: str
        :rtype Any

        :param context: The request context
        :param internal_response: Attributes from the authorization
        :param state: the saved frontend state
        :return response
        """
        raise NotImplementedError()

    def register_endpoints(self, providers):
        """
        Register frontend functions to endpoint urls.

        Example of registering an endpoint:
            providers = ["Saml2IDP", "OIDCOP"]
            reg_endp = [
                ("^Saml2IDP/sso/redirect$", (endpoint_function, arguments)),
                ("^OIDCOP/sso/redirect$", (endpoint_function, arguments)),
            ]


        :type providers: list[str]
        :rtype list[(str, ((satosa.context.Context, Any) -> Any, Any))]

        :param providers: A list of all possible endpoints.
        :return: A list with functions and args bound to a specific endpoint url,
                 [(regexp, (function, arguments)), ...]
        """
        raise NotImplementedError()
