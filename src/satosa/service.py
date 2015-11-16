#!/usr/bin/env python
import logging
import random
import string
from urllib.parse import parse_qs

from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_SOAP
from saml2 import BINDING_HTTP_POST
from saml2.extension.idpdisc import BINDING_DISCO
from saml2.httputil import get_post
from saml2.httputil import SeeOther
from saml2.httputil import ServiceError
from saml2.httputil import Response

LOGGER = logging.getLogger(__name__)

BINDING_MAP = {
    BINDING_HTTP_POST: "post",
    BINDING_HTTP_REDIRECT: "redirect",
    # BINDING_HTTP_ARTIFACT: "artifact",
    BINDING_SOAP: "soap",
    BINDING_DISCO: "disco"
}

INV_BINDING_MAP = {v: k for k, v in BINDING_MAP.items()}


def unpack(environ, binding):
    if binding == "redirect":
        return unpack_redirect(environ)
    elif binding == "post":
        return unpack_post(environ)
    elif binding == "soap":
        return unpack_soap(environ)
    else:
        return unpack_either(environ)


def unpack_redirect(environ):
    if "QUERY_STRING" in environ:
        _qs = environ["QUERY_STRING"]
        return dict([(k, v[0]) for k, v in parse_qs(_qs).items()])
    else:
        return None


def unpack_post(environ):
    post_body = get_post(environ).decode("utf-8")
    _dict = parse_qs(post_body)
    LOGGER.debug("unpack_post:: %s", _dict)
    try:
        return dict([(k, v[0]) for k, v in _dict.items()])
    except IOError:
        return None


def unpack_soap(environ):
    try:
        query = get_post(environ)
        return {"SAMLResponse": query, "RelayState": ""}
    except IOError:
        return None


def unpack_either(environ):
    if environ["REQUEST_METHOD"] == "GET":
        _dict = unpack_redirect(environ)
    elif environ["REQUEST_METHOD"] == "POST":
        _dict = unpack_post(environ)
    else:
        _dict = None
    LOGGER.debug("_dict: %s", _dict)
    return _dict


def response(binding, http_args):
    if binding == BINDING_HTTP_REDIRECT:
        for param, value in http_args["headers"]:
            if param == "Location":
                resp = SeeOther(str(value))
                break
        else:
            resp = ServiceError("Parameter error")
    else:
        resp = Response(http_args["data"], headers=http_args["headers"])

    return resp


def rndstr(size=16, alphabet=""):
    """
    Returns a string of random ascii characters or digits

    :param size: The length of the string
    :return: string
    """
    rng = random.SystemRandom()
    if not alphabet:
        alphabet = string.ascii_letters[0:52] + string.digits
    return type(alphabet)().join(rng.choice(alphabet) for _ in range(size))
