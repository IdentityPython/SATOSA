from ..attribute_processor import AttributeProcessorError
from .base_processor import BaseProcessor

import hashlib


CONFIG_KEY_SALT = 'salt'
CONFIG_DEFAULT_SALT = ''
CONFIG_KEY_HASHALGO = 'hash_algo'
CONFIG_DEFAULT_HASHALGO = 'sha256'


class HashProcessor(BaseProcessor):
    def process(self, internal_data, attribute, **kwargs):
        salt = kwargs.get(CONFIG_KEY_HASHALGO, CONFIG_DEFAULT_SALT)
        hash_algo = kwargs.get(CONFIG_KEY_HASHALGO, CONFIG_DEFAULT_HASHALGO)
        if hash_algo not in hashlib.algorithms_available:
            raise AttributeProcessorError(
                "Hash algorithm not supported: {}".format(hash_algo))

        attributes = internal_data.attributes
        value = attributes.get(attribute, [None])[0]
        if value is None:
            raise AttributeProcessorError(
                "No value for attribute: {}".format(attribute))

        hasher = hashlib.new(hash_algo)
        hasher.update(value.encode('utf-8'))
        hasher.update(salt.encode('utf-8'))
        value_hashed = hasher.hexdigest()
        attributes[attribute][0] = value_hashed
