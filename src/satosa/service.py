#!/usr/bin/env python
import logging
import random
import string
from urllib.parse import parse_qs
from saml2 import BINDING_HTTP_REDIRECT
from saml2.httputil import get_post
from saml2.httputil import SeeOther
from saml2.httputil import ServiceError
from saml2.httputil import Response
from saml2.saml import NAMEID_FORMAT_TRANSIENT, NAMEID_FORMAT_PERSISTENT
from satosa.internal_data import UserIdHashType

LOGGER = logging.getLogger(__name__)


def saml_name_format_to_hash_type(name_format):
    """
    Translate pySAML2 name format to statosa format

    :type name_format: str
    :rtype: satosa.internal_data.UserIdHashType
    :param name_format: SAML2 name format
    :return: satosa format
    """
    if name_format == NAMEID_FORMAT_TRANSIENT:
        return UserIdHashType.transient
    elif name_format == NAMEID_FORMAT_PERSISTENT:
        return UserIdHashType.persistent
    return None


def get_saml_name_id_format(hash_type):
    """
    Translate satosa format to pySAML2 name format

    :type hash_type: satosa.internal_data.UserIdHashType
    :rtype: str
    :param hash_type: satosa format
    :return: pySAML2 name format
    """
    if hash_type == UserIdHashType.transient:
        return NAMEID_FORMAT_TRANSIENT
    elif hash_type == UserIdHashType.persistent:
        return NAMEID_FORMAT_PERSISTENT
    return None


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
