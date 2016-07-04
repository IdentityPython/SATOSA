"""
This module contains all needed to keep a request state, without saving any information on the
server.
"""
import base64
import copy
import hashlib
import json
import logging
from http.cookies import SimpleCookie
from lzma import LZMADecompressor, LZMACompressor

from Crypto import Random
from Crypto.Cipher import AES

from .exception import SATOSAStateError
from .logging_util import satosa_logging

logger = logging.getLogger(__name__)

# TODO MOVE TO CONFIG
STATE_COOKIE_MAX_AGE = 1200
STATE_COOKIE_SECURE = True


def state_to_cookie(state, name, path, encryption_key):
    """
    Saves a state to a cookie

    :type state: satosa.state.State
    :type name: str
    :type path: str
    :type encryption_key: str
    :rtype: http.cookies.SimpleCookie

    :param state: The state to save
    :param name: Name identifier of the cookie
    :param path: Endpoint path the cookie will be associated to
    :param encryption_key: Key to encrypt the state information
    :return: A cookie
    """

    cookie_data = "" if state.delete else state.urlstate(encryption_key)
    max_age = 0 if state.delete else STATE_COOKIE_MAX_AGE

    satosa_logging(logger, logging.DEBUG,
                   "Saving state as cookie, secure: %s, max-age: %s, path: %s" %
                   (STATE_COOKIE_SECURE, STATE_COOKIE_MAX_AGE, path), state)
    cookie = SimpleCookie()
    cookie[name] = cookie_data
    cookie[name]["secure"] = STATE_COOKIE_SECURE
    cookie[name]["path"] = path
    cookie[name]["max-age"] = max_age
    return cookie


def cookie_to_state(cookie_str, name, encryption_key):
    """
    Loads a state from a cookie

    :type cookie_str: str
    :type name: str
    :type encryption_key: str
    :rtype: satosa.state.State

    :param cookie_str: string representation of cookie/s
    :param name: Name identifier of the cookie
    :param encryption_key: Key to encrypt the state information
    :return: A state
    """
    try:
        state = State(SimpleCookie(cookie_str)[name].value, encryption_key)
        satosa_logging(logger, logging.DEBUG, "Loading state from cookie: %s" % cookie_str, state)
        return state
    except KeyError:
        logger.debug("Did not find cookie named '%s' in cookie string '%s'" % (name, cookie_str))
        raise SATOSAStateError(
            "No cookie named '{}' in cookie string '{}'".format(name, cookie_str))


class _AESCipher(object):
    """
    This class will perform AES encryption/decryption with a keylength of 256.

    @see: http://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
    """

    def __init__(self, key):
        """
        Constructor

        :type key: str

        :param key: The key used for encryption and decryption. The longer key the better.
        """
        self.bs = 32
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        """
        Encryptes the parameter raw.

        :type raw: bytes
        :rtype: str

        :param: bytes to be encrypted.

        :return: A base 64 encoded string.
        """
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.urlsafe_b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        """
        Decryptes the parameter enc.

        :type enc: bytes
        :rtype: bytes

        :param: The value to be decrypted.
        :return: The decrypted value.
        """
        enc = base64.urlsafe_b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:]))

    def _pad(self, b):
        """
        Will padd the param to be of the correct length for the encryption alg.

        :type b: bytes
        :rtype: bytes
        """
        return b + (self.bs - len(b) % self.bs) * chr(self.bs - len(b) % self.bs).encode("UTF-8")

    @staticmethod
    def _unpad(b):
        """
        Removes the padding performed by the method _pad.

        :type b: bytes
        :rtype: bytes
        """
        return b[:-ord(b[len(b) - 1:])]


class State(object):
    """
    This class holds a state attribute object. A state object must be able to be converted to
    a json string, otherwise will an exception be raised.
    """

    def __init__(self, urlstate_data=None, encryption_key=None):
        """
        If urlstate is empty a new empty state instance will be returned.

        If urlstate is not empty the constructor will rebuild the state attribute objects
        from the urlstate string.
        :type urlstate_data: str
        :type encryption_key: str
        :rtype: State

        :param encryption_key: The key to be used for encryption.
        :param urlstate_data: A string created by the method urlstate in this class.
        :return: An instance of this class.
        """
        self._state_dict = {}
        self.delete = False

        if urlstate_data and not encryption_key:
            raise ValueError("If an 'urlstate_data' is supplied 'encrypt_key' must be specified.")

        if urlstate_data is not None:
            urlstate_data = urlstate_data.encode("utf-8")
            urlstate_data = base64.urlsafe_b64decode(urlstate_data)
            lzma = LZMADecompressor()
            urlstate_data = lzma.decompress(urlstate_data)
            urlstate_data = _AESCipher(encryption_key).decrypt(urlstate_data)
            lzma = LZMADecompressor()
            urlstate_data = lzma.decompress(urlstate_data)
            urlstate_data = urlstate_data.decode("UTF-8")
            self._state_dict = json.loads(urlstate_data)

    def __setitem__(self, key, data):
        """
        Will set session data (which must be JSON serializable) associated with a unique key.

        :type key: str
        :type data: Mapping[str, Any]

        :param key: unique key to associate the data with
        :param data: state data to keep
        :raise ValueError: if the data is not JSON serializable
        """
        json.dumps(data)  # verify the data is JSON serializable by trying to serialize it
        self._state_dict[key] = data

    def __delitem__(self, key):
        """
        Removes state value
        :type key: str
        :param key: Key for value
        """
        del self._state_dict[key]

    def __getitem__(self, key):
        """
        Will retrieve the state data for a specific key.


        :type key: str
        :rtype: Mapping[str, Any]

        :param key: the unique for which the data is associated
        :return: the state data associated with the key
        """
        return self._state_dict[key]

    def __contains__(self, key):
        return key in self._state_dict

    def urlstate(self, encryption_key):
        """
        Will return a url safe representation of the state.

        :type encryption_key: Key used for encryption.
        :rtype: str

        :return: Url representation av of the state.
        """
        lzma = LZMACompressor()
        urlstate_data = json.dumps(self._state_dict)
        urlstate_data = lzma.compress(urlstate_data.encode("UTF-8"))
        urlstate_data += lzma.flush()
        urlstate_data = _AESCipher(encryption_key).encrypt(urlstate_data)
        lzma = LZMACompressor()
        urlstate_data = lzma.compress(urlstate_data)
        urlstate_data += lzma.flush()
        urlstate_data = base64.urlsafe_b64encode(urlstate_data)
        return urlstate_data.decode("utf-8")

    def copy(self):
        """
        Returns a deepcopy of the state

        :rtype: satosa.state.State

        :return: A copy of the state
        """
        state_copy = State()
        state_copy._state_dict = copy.deepcopy(self._state_dict)
        return state_copy

    def __str__(self):
        return str(self._state_dict)

    @property
    def state_dict(self):
        """
        :rtype: dict[str, any]
        :return: A copy of the state as dictionary.
        """
        return copy.deepcopy(self._state_dict)
