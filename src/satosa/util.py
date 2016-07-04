"""
Python package file for util functions.
"""
import json
import logging
import random
import string
from urllib.parse import parse_qsl

from saml2 import BINDING_HTTP_REDIRECT
from saml2.httputil import Response
from saml2.httputil import SeeOther
from saml2.httputil import ServiceError
from saml2.httputil import get_post
from saml2.saml import NAMEID_FORMAT_TRANSIENT, NAMEID_FORMAT_PERSISTENT

from .internal_data import UserIdHashType

logger = logging.getLogger(__name__)


def hash_type_to_saml_name_id_format(hash_type):
    """
    Translate satosa format to pySAML2 name format

    :type hash_type: satosa.internal_data.UserIdHashType
    :rtype: str
    :param hash_type: satosa format
    :return: pySAML2 name format
    """
    if hash_type == UserIdHashType.transient.name:
        return NAMEID_FORMAT_TRANSIENT
    elif hash_type == UserIdHashType.persistent.name:
        return NAMEID_FORMAT_PERSISTENT
    return NAMEID_FORMAT_PERSISTENT


def unpack_redirect(environ):
    """
    Unpacks a redirect request query string.
    :param environ: whiskey application environment.
    :return: A dictionary with parameters.
    """
    if "QUERY_STRING" in environ:
        return dict(parse_qsl(environ["QUERY_STRING"]))

    return None


def unpack_post(environ):
    """
    Unpacks a post request query string.
    :param environ: whiskey application environment.
    :return: A dictionary with parameters.
    """
    post_body = get_post(environ).decode("utf-8")
    data = None
    if environ["CONTENT_TYPE"] == "application/x-www-form-urlencoded":
        data = dict(parse_qsl(post_body))
    elif environ["CONTENT_TYPE"] == "application/json":
        data = json.loads(post_body)

    logger.debug("unpack_post:: %s", data)
    return data


def unpack_either(environ):
    """
    Unpacks a get or post request query string.
    :param environ: whiskey application environment.
    :return: A dictionary with parameters.
    """
    data = None
    if environ["REQUEST_METHOD"] == "GET":
        data = unpack_redirect(environ)
    elif environ["REQUEST_METHOD"] == "POST":
        data = unpack_post(environ)

    logger.debug("read request data: %s", data)
    return data


def rndstr(size=16, alphabet=""):
    """
    Returns a string of random ascii characters or digits
    :type size: int
    :type alphabet: str
    :param size: The length of the string
    :param alphabet: A string with characters.
    :return: string
    """
    rng = random.SystemRandom()
    if not alphabet:
        alphabet = string.ascii_letters[0:52] + string.digits
    return type(alphabet)().join(rng.choice(alphabet) for _ in range(size))


def scope(s):
    if not '@' in s:
        raise ValueError("Unscoped string")
    (local_part, _, domain_part) = s.partition('@')
    return domain_part
