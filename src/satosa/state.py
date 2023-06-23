"""
This module contains all needed to keep a request state, without saving any information on the
server.
"""
import base64
import copy
import json
import logging
import os
from collections import UserDict
import lzma
from uuid import uuid4

from cryptojwt.jwe.aes import AES_CBCEncrypter

import satosa.logging_util as lu
from satosa.cookies import SimpleCookie
from satosa.exception import SATOSAStateError

logger = logging.getLogger(__name__)

_SESSION_ID_KEY = "SESSION_ID"


def state_to_cookie(state, name, path, encryption_key):
    """
    Saves a state to a cookie

    :type state: satosa.state.State
    :type name: str
    :type path: str
    :type encryption_key: str
    :rtype: satosa.cookies.SimpleCookie

    :param state: The state to save
    :param name: Name identifier of the cookie
    :param path: Endpoint path the cookie will be associated to
    :param encryption_key: Key to encrypt the state information
    :return: A cookie
    """

    cookie_data = "" if state.delete else state.urlstate(encryption_key)

    cookie = SimpleCookie()
    cookie[name] = cookie_data
    cookie[name]["samesite"] = "None"
    cookie[name]["secure"] = True
    cookie[name]["path"] = path
    cookie[name]["max-age"] = 0 if state.delete else ""

    msg = "Saved state in cookie {name} with properties {props}".format(
        name=name, props=list(cookie[name].items())
    )
    logline = lu.LOG_FMT.format(id=lu.get_session_id(state), message=msg)
    logger.debug(logline)

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
        cookie = SimpleCookie(cookie_str)
        state = State(cookie[name].value, encryption_key)
    except KeyError as e:
        msg_tmpl = 'No cookie named {name} in {data}'
        msg = msg_tmpl.format(name=name, data=cookie_str)
        raise SATOSAStateError(msg) from e
    except ValueError as e:
        msg_tmpl = 'Failed to process {name} from {data}'
        msg = msg_tmpl.format(name=name, data=cookie_str)
        raise SATOSAStateError(msg) from e
    else:
        return state


def len_val_construct(*args):
    _p = []
    for arg in args:
        _p.append(f'{len(arg):05d}'.encode())
        _p.append(arg)

    return b''.join(_p)


def len_val_parse(arg):
    _p = []
    while arg:
        _len = int(arg[:5])
        _p.append(arg[5:_len + 5])
        arg = arg[_len + 5:]
    return _p


class State(UserDict):
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
        self.delete = False

        urlstate_data = {} if urlstate_data is None else urlstate_data
        if urlstate_data and not encryption_key:
            raise ValueError("If an 'urlstate_data' is supplied 'encrypt_key' must be specified.")

        if urlstate_data:
            try:
                urlstate_data_bytes = urlstate_data.encode("utf-8")
                urlstate_data_b64decoded = base64.urlsafe_b64decode(urlstate_data_bytes)
                urlstate_data_decompressed = lzma.decompress(urlstate_data_b64decoded)
                ct, iv, tag = len_val_parse(urlstate_data_decompressed)
                urlstate_data_decrypted = AES_CBCEncrypter(key=encryption_key).decrypt(
                    msg=ct, iv=iv, tag=tag
                )
                urlstate_data_decrypted_decompressed = lzma.decompress(urlstate_data_decrypted)
                urlstate_data_obj = json.loads(urlstate_data_decrypted_decompressed)
            except Exception as e:
                error_context = {
                    "message": "Failed to load state data. Reinitializing empty state.",
                    "reason": str(e),
                    "urlstate_data": urlstate_data,
                }
                logger.warning(error_context)
                urlstate_data = {}
            else:
                urlstate_data = urlstate_data_obj

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

    def urlstate(self, encryption_key):
        """
        Will return an url safe representation of the state.

        :type encryption_key: Key used for encryption.
        :rtype: str

        :return: Url representation of the state.
        """
        urlstate_data = json.dumps(self.data)
        urlstate_data = lzma.compress(urlstate_data.encode("UTF-8"))
        iv = os.urandom(16)
        ct, tag = AES_CBCEncrypter(key=encryption_key).encrypt(urlstate_data, iv=iv)
        _data = len_val_construct(ct, iv, tag)
        urlstate_data = lzma.compress(_data)
        urlstate_data = base64.urlsafe_b64encode(urlstate_data)
        return urlstate_data.decode("utf-8")

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
