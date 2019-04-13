"""
Python package file for util functions.
"""
import hashlib
import logging
import random
import string
import saml2.xmldsig

from satosa.logging_util import satosa_logging


logger = logging.getLogger(__name__)


def xmldsig_validate_w3c_format(alg_value):
    """
    Map a w3c alg format to a xmldsig attribute name
    this function could be also used to implement other validations
    on matching

    :type value: str
    :type allowed_alg_list: list
    """
    for allowed_list in (saml2.xmldsig.SIG_ALLOWED_ALG,
                         saml2.xmldsig.DIGEST_ALLOWED_ALG):
        for alg_tuple in allowed_list:
            if alg_value == alg_tuple[1]:
                return alg_tuple[0]
    return alg_value


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
