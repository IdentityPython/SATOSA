"""
Python package file for util functions.
"""
import base64
import hashlib
import logging
import random
import string
import xml.dom.minidom
import zlib

from satosa.logging_util import satosa_logging
from xml.parsers.expat import ExpatError


logger = logging.getLogger(__name__)



def repr_saml(saml_str, b64=False):
    """
    Decode SAML from b64 and b64 deflated and
    return a pretty printed representation.

    If b64 is True saml_str must be encoded

    :type saml_str: str
    :type b64: bool
    """
    # needed for '' string
    if not saml_str: return saml_str

    try:
        msg = base64.b64decode(saml_str).decode() if b64 else saml_str
        dom = xml.dom.minidom.parseString(msg)
    except (UnicodeDecodeError, ExpatError):
        # in HTTP-REDIRECT the base64 must be inflated
        msg = base64.b64decode(saml_str)
        inflated = zlib.decompress(msg, -15)
        dom = xml.dom.minidom.parseString(inflated.decode())
    return dom.toprettyxml()

def hash_data(salt, value, hash_alg=None):
    """
    Hashes a value together with a salt with the given hash algorithm.

    :type salt: str
    :type hash_alg: str
    :type value: str
    :param salt: hash salt
    :param hash_alg: the hash algorithm to use (default: SHA512)
    :param value: value to hash together with the salt
    :return: hashed value
    """
    hash_alg = hash_alg or 'sha512'
    hasher = hashlib.new(hash_alg)
    hasher.update(value.encode('utf-8'))
    hasher.update(salt.encode('utf-8'))
    value_hashed = hasher.hexdigest()
    return value_hashed


def check_set_dict_defaults(dic, spec):
    for path, value in spec.items():
        keys = path.split('.')
        try:
            _val = dict_get_nested(dic, keys)
        except KeyError:
            if type(value) is list:
                value_default = value[0]
            else:
                value_default = value
            dict_set_nested(dic, keys, value_default)
        else:
            if type(value) is list:
                is_value_valid = _val in value
            elif type(value) is dict:
                # do not validate dict
                is_value_valid = bool(_val)
            else:
                is_value_valid = _val == value
            if not is_value_valid:
                satosa_logging(
                    logger, logging.WARNING,
                    "Incompatible configuration value '{}' for '{}'."
                    " Value shoud be: {}".format(_val, path, value),
                    {})
    return dic


def dict_set_nested(dic, keys, value):
    for key in keys[:-1]:
        dic = dic.setdefault(key, {})
    dic[keys[-1]] = value


def dict_get_nested(dic, keys):
    for key in keys[:-1]:
        dic = dic.setdefault(key, {})
    return dic[keys[-1]]


def get_dict_defaults(d, *keys):
    for key in keys:
        d = d.get(key, d.get("", d.get("default", {})))
    return d


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
