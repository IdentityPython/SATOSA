from saml2 import BINDING_HTTP_REDIRECT, BINDING_SOAP

from .response import SeeOther, Response


def make_saml_response(binding, http_args):
    """
    Creates a SAML response.
    :param binding: SAML response binding
    :param http_args: http arguments
    :return: response.Response
    """
    if binding == BINDING_HTTP_REDIRECT:
        headers = dict(http_args["headers"])
        return SeeOther(str(headers["Location"]))
    elif binding == BINDING_SOAP:
        return Response(
            http_args["data"],
            headers=http_args["headers"],
            content="application/soap+xml"
        )

    return Response(http_args["data"], headers=http_args["headers"])
