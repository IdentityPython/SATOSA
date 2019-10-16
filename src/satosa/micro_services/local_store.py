""" implement key/valuer store """
import pickle
import redis
from satosa.state import _AESCipher

class LocalStore():
    """ Store context objects in Redis.
        Create a new key when a new value is set.
        Delete key/value after reading it
    """
    def __init__(self, encryption_key: str, redishost: str):
        self.redis = redis.Redis(host=redishost, port=6379)
        self.aes_cipher = _AESCipher(encryption_key)

    def set(self, context: object) -> int:
        context_serlzd = pickle.dumps(context, pickle.HIGHEST_PROTOCOL)
        context_enc = self.aes_cipher.encrypt(context_serlzd)
        key = self.redis.incr('REDIRURL_sequence', 1)
        self.redis.set(key, context_serlzd, 1800) # generous 30 min timeout to complete SSO transaction
        return key

    def get(self, key: int) -> object:
        context_serlzd = self.redis.get(key)
        self.redis.expire(key, 600)  # delay deletion in case request is repeated due to network issues
        return pickle.loads(context_serlzd)

