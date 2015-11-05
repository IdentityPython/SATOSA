"""
Holds a base class for backend modules used in the SATOSA proxy.
"""
__author__ = 'mathiashedstrom'


class BackendModule(object):
    """
    Base class for a backend module.
    """

    def __init__(self, auth_callback_func, internal_attributes):
        """
        :type auth_callback_func: (satosa.context.Context, satosa.internal_data.InternalResponse, satosa.state.State) -> Any

        :param auth_callback_func: Callback should be called by the module after
                                   the authorization in the backend is done.
        """
        self.auth_callback_func = auth_callback_func
        self.internal_attributes = internal_attributes

    def start_auth(self, context, internal_request, state):
        """
        This is the start up function of the backend authorization.

        :type context: satosa.context.Context
        :type internal_request: satosa.internal_data.InternalRequest
        :type state: satosa.state.State
        :rtype Any

        :param context: the request context
        :param internal_request: Information about the authorization request
        :param state: current state
        :return: response
        """
        raise NotImplementedError()

    def register_endpoints(self):
        """
        Register backend functions to endpoint urls.

        Example of registering an endpoint:
            reg_endp = [
                ("^Saml2IDP/acs/redirect", (endpoint_function, arguments)),
            ]


        :rtype list[(str, ((satosa.context.Context, Any) -> Any, Any))]

        :return: A list with functions and args bound to a specific endpoint url,
                 [(regexp, (function, arguments)), ...]
        """
        raise NotImplementedError()
