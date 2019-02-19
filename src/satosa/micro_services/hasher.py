import satosa.util as util
from satosa.micro_services.base import ResponseMicroService


CONFIG_KEY_SALT = "salt"
CONFIG_KEY_ALG = "alg"
CONFIG_KEY_SUBJID = "subject_id"
CONFIG_KEY_ATTRS = "attributes"


class Hasher(ResponseMicroService):
    """Hash subject_id and attributes.

    This is a micro-service that allows hashing of the subject_id and different
    attributes, with the selected hash algorithm and salt, as specified in the
    configuration.

    Supported hash algorithms are listed through hashlib:

      import hashlib
      print(hashlib.algorithms_available)

    An example configuration:

      module: satosa.micro_services.hasher.Hasher
      name: Hasher
      config:

        # default settings that apply to every requester
        "":
          # default salt configuration is required
          salt: abcdef0123456789

          # the hash algorithm to use (default: sha512)
          alg: sha256

          # whether subject_id should be hashed (default: yes)
          subject_id: yes

          # a list of attributes to hash (default: [])
          attributes:
          - edupersontargetedid

        # specific settings for requester 'some_entityid'
        some_entityid:
          # for this requester use sha1
          alg: sha1

          # do not hash any attributes
          # if this is missing the defaults will be used
          attributes: []

        # specific settings for requester 'some_other_entityid'
        some_other_entityid:
          # for this requester only use this salt
          salt: abcd1234

          # do not hash subject_id
          subject_id: no

          # only hash the following attributes
          attributes:
          - gender
          - identifier
    """

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = self._init_config(config)

    def _init_config(self, config):
        defaults = {
            CONFIG_KEY_ALG: "sha512",
            CONFIG_KEY_SUBJID: True,
            CONFIG_KEY_ATTRS: [],
        }

        defaults.update(config.get("", {}))
        if not defaults.get(CONFIG_KEY_SALT, None):
            raise Exception(
                "Required config key missing: {}".format(CONFIG_KEY_SALT)
            )

        for requester, conf in config.items():
            defs = defaults.copy()
            defs.update(conf)
            config[requester] = defs
        return config

    def process(self, context, internal_data):
        requester = internal_data.requester
        config = self.config.get(requester, self.config[""])
        if config[CONFIG_KEY_SUBJID]:
            self.hash_subject_id(config, internal_data)
        if config[CONFIG_KEY_ATTRS]:
            self.hash_attributes(config, internal_data)
        return super().process(context, internal_data)

    def hash_subject_id(self, config, internal_data):
        internal_data.subject_id = util.hash_data(
            config[CONFIG_KEY_SALT],
            internal_data.subject_id,
            hash_alg=config[CONFIG_KEY_ALG],
        )

    def hash_attributes(self, config, internal_data):
        for attribute in config[CONFIG_KEY_ATTRS]:
            internal_data.attributes[attribute] = [
                util.hash_data(
                    config[CONFIG_KEY_SALT],
                    value,
                    hash_alg=config[CONFIG_KEY_ALG],
                )
                for value in internal_data.attributes.get(attribute, [])
            ]
