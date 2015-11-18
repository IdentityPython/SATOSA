"""
Holds a base class for frontend modules used in the SATOSA proxy.
"""
__author__ = 'mathiashedstrom'


class FrontendModule(object):
    """
    Base class for a frontend module.
    """

    def __init__(self, auth_req_callback_func, internal_attrbitues):
        """
        :type auth_req_callback_func:
        (satosa.context.Context, satosa.internal_data.InternalData) -> satosa.response.Response
        :type internal_attrbitues: dict[str, dict[str, str | list[str]]]

        :param auth_req_callback_func: Callback should be called by the module after the
        authorization response has been processed.
        """
        self.auth_req_callback_func = auth_req_callback_func
        self.internal_attrbitues = internal_attrbitues

    def handle_authn_response(self, context, internal_resp):
        """
        If an authorization has been successful in a backend, this function is called and is
        supposed to send an authorization response to the client.

        :type context: satosa.context.Context
        :type internal_resp: satosa.internal_data.InternalResponse
        :rtype satosa.response.Response

        :param context: The request context
        :param internal_resp: Attributes from the authorization
        :return response
        """
        raise NotImplementedError()

    def handle_backend_error(self, exception):
        """
        IF the backend gets an unexpected error, a suitable notice about the failure should be sent
        to the requestor. This function is supposed to send a suitable error message to the
        requestor.

        :type exception: satosa.exception.SATOSAError
        :rtype: satosa.response.Response

        :param exception: The raised exception
        :return: response
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
        :rtype list[(str, ((satosa.context.Context, Any) -> satosa.response.Response, Any))] |
               list[(str, (satosa.context.Context) -> satosa.response.Response)]

        :param providers: A list of all possible endpoints.
        :return: A list with functions and args bound to a specific endpoint url,
                 [(regexp, (function, arguments)), ...]
        """
        raise NotImplementedError()
