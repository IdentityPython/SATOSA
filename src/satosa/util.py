"""
Python package file for util functions.
"""
import logging
import random
import string

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
