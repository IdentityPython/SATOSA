"""
This module contains all needed to keep a request state, without saving any information on the
server.
"""
import base64
from collections import UserDict
import copy
import json
import logging
from lzma import LZMACompressor
from lzma import LZMADecompressor
from uuid import uuid4

# from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptojwt.jwe.aes import AES_GCMEncrypter

from satosa.cookies import SimpleCookie
from satosa.exception import SATOSAStateError
import satosa.logging_util as lu

logger = logging.getLogger(__name__)

_SESSION_ID_KEY = "SESSION_ID"


class State(UserDict):
    """
    This class holds a state attribute object. A state object must be possible to convert to
    a json string, otherwise an exception will be raised.
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
        self.delete = False

        urlstate_data = {} if urlstate_data is None else urlstate_data
        if urlstate_data and not encryption_key:
            raise ValueError("If an 'urlstate_data' is supplied 'encrypt_key' must be specified.")

        if urlstate_data:
            urlstate_data_obj = self.unpack(urlstate_data, encryption_key=encryption_key)
            if urlstate_data_obj is None:
                urlstate_data = {}

        session_id = (
            urlstate_data[_SESSION_ID_KEY]
            if urlstate_data and _SESSION_ID_KEY in urlstate_data
            else uuid4().urn
        )
        urlstate_data[_SESSION_ID_KEY] = session_id

        super().__init__(urlstate_data)

    @property
    def session_id(self):
        return self.data.get(_SESSION_ID_KEY)

    def unpack(self, data: str, encryption_key):
        """

        :param data: A string created by the method pack in this class.
        """
        try:
            data_bytes = data.encode("utf-8")
            data_b64decoded = base64.urlsafe_b64decode(data_bytes)
            lzma = LZMADecompressor()
            data_decompressed = lzma.decompress(data_b64decoded)
            data_decrypted = AES_GCMEncrypter(key=encryption_key).decrypt(
                data_decompressed
            )
            lzma = LZMADecompressor()
            data_decrypted_decompressed = lzma.decompress(data_decrypted)
            data_obj = json.loads(data_decrypted_decompressed)
        except Exception as e:
            error_context = {
                "message": "Failed to load state data. Reinitializing empty state.",
                "reason": str(e),
                "urlstate_data": data,
            }
            logger.warning(error_context)
            data_obj = None

        return data_obj

    def pack(self, encryption_key):
        """
        Will return an url safe representation of the state.

        :type encryption_key: Key used for encryption.
        :rtype: str

        :return: Url representation av of the state.
        """

        lzma = LZMACompressor()
        _data = json.dumps(self.data)
        _data = lzma.compress(_data.encode("UTF-8"))
        _data += lzma.flush()
        _data = AES_GCMEncrypter(encryption_key).encrypt(_data)
        lzma = LZMACompressor()
        _data = lzma.compress(_data)
        _data += lzma.flush()
        _data = base64.urlsafe_b64encode(_data)
        return _data.decode("utf-8")

    def copy(self):
        """
        Returns a deepcopy of the state

        :rtype: satosa.state.State

        :return: A copy of the state
        """
        state_copy = State()
        state_copy.data = copy.deepcopy(self.data)
        return state_copy

    @property
    def state_dict(self):
        """
        :rtype: dict[str, any]
        :return: A copy of the state as dictionary.
        """
        return copy.deepcopy(self.data)


def state_to_cookie(
        state: State,
        *,
        name: str,
        path: str,
        encryption_key: str,
        secure: bool = None,
        httponly: bool = None,
        samesite: str = None,
        max_age: str = None,
) -> SimpleCookie:
    """
    Saves a state to a cookie

    :param state: the data to save
    :param name: identifier of the cookie
    :param path: path the cookie will be associated to
    :param encryption_key: the key to use to encrypt the state information
    :param secure: whether to include the cookie only when the request is transmitted
                   over a secure channel
    :param httponly: whether the cookie should only be accessed only by the server
    :param samesite: whether the cookie should only be sent with requests
                     initiated from the same registrable domain
    :param max_age: indicates the maximum lifetime of the cookie,
                    represented as the number of seconds until the cookie expires
    :return: A cookie object
    """
    cookie = SimpleCookie()
    cookie[name] = "" if state.delete else state.urlstate(encryption_key)
    cookie[name]["path"] = path
    cookie[name]["secure"] = secure if secure is not None else True
    cookie[name]["httponly"] = httponly if httponly is not None else ""
    cookie[name]["samesite"] = samesite if samesite is not None else "None"
    cookie[name]["max-age"] = (
        0
        if state.delete
        else max_age
        if max_age is not None
        else ""
    )

    msg = "Saved state in cookie {name} with properties {props}".format(
        name=name, props=list(cookie[name].items())
    )
    logline = lu.LOG_FMT.format(id=lu.get_session_id(state), message=msg)
    logger.debug(logline)

    return cookie


def cookie_to_state(cookie_str: str, name: str, encryption_key: str) -> State:
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
        cookie = SimpleCookie(cookie_str)
        state = State(cookie[name].value, encryption_key)
    except KeyError as e:
        msg = f'No cookie named {name} in {cookie_str}'
        raise SATOSAStateError(msg) from e
    except ValueError as e:
        msg_tmpl = 'Failed to process {name} from {data}'
        msg = msg_tmpl.format(name=name, data=cookie_str)
        raise SATOSAStateError(msg) from e
    else:
        return state

#
# class _AESCipher(object):
#     """
#     This class will perform AES encryption/decryption with a keylength of 256.
#
#     @see: http://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
#     """
#
#     def __init__(self, key):
#         """
#         Constructor
#
#         :type key: str
#
#         :param key: The key used for encryption and decryption. The longer key the better.
#         """
#         self.bs = 32
#         self.key = hashlib.sha256(key.encode()).digest()
#
#     def encrypt(self, raw):
#         """
#         Encryptes the parameter raw.
#
#         :type raw: bytes
#         :rtype: str
#
#         :param: bytes to be encrypted.
#
#         :return: A base 64 encoded string.
#         """
#         raw = self._pad(raw)
#         iv = rndstr(AES.block_size)
#         cipher = AES.new(self.key, AES.MODE_CBC, iv)
#         return base64.urlsafe_b64encode(iv + cipher.encrypt(raw))
#
#     def decrypt(self, enc):
#         """
#         Decryptes the parameter enc.
#
#         :type enc: bytes
#         :rtype: bytes
#
#         :param: The value to be decrypted.
#         :return: The decrypted value.
#         """
#         enc = base64.urlsafe_b64decode(enc)
#         iv = enc[:AES.block_size]
#         cipher = AES.new(self.key, AES.MODE_CBC, iv)
#         return self._unpad(cipher.decrypt(enc[AES.block_size:]))
#
#     def _pad(self, b):
#         """
#         Will padd the param to be of the correct length for the encryption alg.
#
#         :type b: bytes
#         :rtype: bytes
#         """
#         return b + (self.bs - len(b) % self.bs) * chr(self.bs - len(b) % self.bs).encode("UTF-8")
#
#     @staticmethod
#     def _unpad(b):
#         """
#         Removes the padding performed by the method _pad.
#
#         :type b: bytes
#         :rtype: bytes
#         """
#         return b[:-ord(b[len(b) - 1:])]
