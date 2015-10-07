"""
This class contains all needed to keep a request state, without saving any information on the
server.
"""
import base64
import json
from zipfile import LZMACompressor, LZMADecompressor
import hashlib
from Crypto import Random
from Crypto.Cipher import AES


class AESCipher(object):

    def __init__(self, key):
        self.bs = 32
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


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
        if urlstate_data is not None:
            urlstate_data = base64.b64decode(urlstate_data)
            lzma = LZMADecompressor()
            urlstate_data = lzma.decompress(urlstate_data)
            urlstate_data = AESCipher(encryption_key).decrypt(urlstate_data)
            self._state_dict = json.loads(urlstate_data)

    def add(self, key, data):
        """
        Will add data connected to a specific key.

        Beware to use unqiue keys, so different parts of the proxy do not overwrite state data.

        The method will convert the data object to a json string. If it cannot be converted an
        exception will be raised.

        :type key: str
        :type data: object

        :param key: A unque key for this data section in the state.
        :param data: Any kind of object, as long as it can be converted to json. So a good principle
        is to only use dictionaries, lists and strings.
        """
        json.dumps(data)
        self._state_dict[key] = data

    def get(self, key):
        """
        Will retrieve the state data for a specific key.


        :type key: str
        :rtype: object

        :param key:
        :return: A python object generated from a json string. So dictionary/list containing
        strings.
        """
        return self._state_dict[key]

    def urlstate(self, encryption_key):
        """
        Will return a url safe representation of the state.

        :rtype: str

        :return: Url representation av of the state.
        """
        urlstate_data = json.dumps(self._state_dict)
        urlstate_data = AESCipher(encryption_key).encrypt(urlstate_data.encode('utf-8'))
        lzma = LZMACompressor()
        urlstate_data = lzma.compress(urlstate_data)
        urlstate_data = base64.b64encode(urlstate_data)
        return urlstate_data
