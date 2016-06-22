"""
Holds a base class for backend modules used in the SATOSA proxy.
"""

from ..internal_data import DataConverter


class BackendModule(object):
    """
    Base class for a backend module.
    """

    def __init__(self, auth_callback_func, internal_attributes, name):
        """
        :type auth_callback_func:
        (satosa.context.Context, satosa.internal_data.InternalResponse) -> satosa.response.Response
        :type internal_attributes: dict[string, dict[str, str | list[str]]]

        :param auth_callback_func: Callback should be called by the module after
                                   the authorization in the backend is done.
        :param internal_attributes: Mapping dictionary between SATOSA internal attribute names and
        the names returned by underlying IdP's/OP's as well as what attributes the calling SP's and
        RP's expects namevice.
        """
        self.auth_callback_func = auth_callback_func
        self.internal_attributes = internal_attributes
        self.converter = DataConverter(internal_attributes)
        self.name = name

    def start_auth(self, context, internal_request):
        """
        This is the start up function of the backend authorization.

        :type context: satosa.context.Context
        :type internal_request: satosa.internal_data.InternalRequest
        :rtype satosa.response.Response

        :param context: the request context
        :param internal_request: Information about the authorization request
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


        :rtype List[Tuple[str, Tuple[Callable[[satosa.context.Context, Any], satosa.response.Response], Any]]]

        :return: A list with functions and args bound to a specific endpoint url,
                 [(regexp, (function, arguments)), ...]
        """
        raise NotImplementedError()

    def get_metadata_desc(self):
        """
        Returns a description of the backend module.
        This is used when creating SAML metadata for the frontend of the proxy
        :rtype: satosa.metadata_creation.description.MetadataDescription
        :return: A description of the backend
        """
        raise NotImplementedError()
