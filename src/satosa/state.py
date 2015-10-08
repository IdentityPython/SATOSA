"""
This class contains all needed to keep a request state, without saving any information on the
server.
"""
import base64
import json
import hashlib
from lzma import LZMADecompressor, LZMACompressor

from Crypto import Random
from Crypto.Cipher import AES


class AESCipher(object):
    """
    This class will perform AES encryption/decryption with a keylength of 256.
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
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        """
        Decryptes the parameter enc.

        :type enc: bytes
        :rtype: bytes

        :param: The value to be decrypted.
        :return: The decrypted value.
        """
        enc = base64.b64decode(enc)
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
        if urlstate_data is not None:
            urlstate_data = base64.b64decode(urlstate_data)
            lzma = LZMADecompressor()
            urlstate_data = lzma.decompress(urlstate_data)
            urlstate_data = AESCipher(encryption_key).decrypt(urlstate_data)
            lzma = LZMADecompressor()
            urlstate_data = lzma.decompress(urlstate_data)
            urlstate_data = urlstate_data.decode("UTF-8")
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

        :type encryption_key: Key used for encryption.
        :rtype: str

        :return: Url representation av of the state.
        """
        lzma = LZMACompressor()
        urlstate_data = json.dumps(self._state_dict)
        urlstate_data = lzma.compress(urlstate_data.encode("UTF-8"))
        urlstate_data += lzma.flush()
        urlstate_data = AESCipher(encryption_key).encrypt(urlstate_data)
        lzma = LZMACompressor()
        urlstate_data = lzma.compress(urlstate_data)
        urlstate_data += lzma.flush()
        urlstate_data = base64.b64encode(urlstate_data)
        return urlstate_data
