"""
This module contains methods to load, verify and build configurations for the satosa proxy.
"""
import json
import logging
import os

import yaml

__author__ = 'mathiashedstrom'

LOGGER = logging.getLogger(__name__)


class SATOSAConfig(object):
    """
    A configuration class for the satosa proxy. Verifies that the given config holds all the
    necessary parameters.
    """
    sensitive_dict_keys = ["STATE_ENCRYPTION_KEY", "USER_ID_HASH_SALT"]
    mandatory_dict_keys = ["BASE", "PLUGIN_PATH", "BACKEND_MODULES", "FRONTEND_MODULES",
                           "INTERNAL_ATTRIBUTES", "COOKIE_STATE_NAME"] + sensitive_dict_keys

    def __init__(self, config):
        """
        Reads a given config and builds the SATOSAConfig.

        :type config: str | dict
        :rtype: satosa.satosa_config.SATOSAConfig

        :param config: Can be a file path, a string (ex. json/yaml), or a dict
        :return: A verified SATOSAConfig
        """
        dict_parsers = [SATOSAConfig._load_dict, SATOSAConfig._load_json, SATOSAConfig._load_yaml]
        for parser in dict_parsers:
            self.__dict__["_config"] = parser(config)
            if self._config is not None:
                break

        # Load sensitive config
        for key in SATOSAConfig.sensitive_dict_keys:
            val = os.environ.get("SATOSA_{key}".format(key=key))
            if val:
                self._config[key] = val

        self._verify_dict(self._config)

        for parser in dict_parsers:
            _internal_attributes = parser(self._config["INTERNAL_ATTRIBUTES"])
            if _internal_attributes is not None:
                break
        self._config["INTERNAL_ATTRIBUTES"] = _internal_attributes

    @staticmethod
    def _verify_dict(conf):
        """
        Raises assertion error if any of the mandatory keys are missing in the conf.

        :type conf: dict
        :rtype: None
        :exception AssertionError

        :param conf: config to verify
        :return: None
        """
        if not (conf is not None and isinstance(conf, dict)):
            msg = "Missing configuration or unknown format"
            LOGGER.critical(msg)
            raise AssertionError(msg)
        for mand_key in SATOSAConfig.mandatory_dict_keys:
            if mand_key not in conf:
                msg = "Missing key '%s' in config" % mand_key
                LOGGER.critical(msg)
                raise AssertionError(msg)

    def __getattr__(self, item):
        """
        Returns data bound to the key 'item'.

        :type item: str
        :rtype object

        :param item: key to data
        :return: data bound to key 'item'
        """
        if self._config is not None and item in self._config:
            return self._config[item]
        raise AttributeError("'module' object has no attribute '%s'" % item)

    def __setattr__(self, key, value):
        """
        Inserts value into internal dict

        :type key: str
        :type value: object

        :param key: key
        :param value: data
        :return: None
        """
        if key != "_config":
            if self._config is not None:
                self._config[key] = value

    def __iter__(self):
        return self._config.__iter__()

    @staticmethod
    def _load_dict(config):
        """
        Load config from dict

        :type config: dict
        :rtype: dict

        :param config: config to load
        :return: Loaded config
        """
        if isinstance(config, dict):
            return config

    @staticmethod
    def _load_json(config):
        """
        Load config from json file or string

        :type config: str
        :rtype: dict

        :param config: config to load. Can be file path or json string
        :return: Loaded config
        """
        try:
            config = SATOSAConfig._readfile(config)
            return json.loads(config)
        except ValueError as error:  # not a json config
            LOGGER.debug("Could not parse config as json: {}", str(error))

    @staticmethod
    def _load_yaml(config):
        """
        Load config from yaml file or string

        :type config: str
        :rtype: dict

        :param config: config to load. Can be file path or yaml string
        :return: Loaded config
        """
        try:
            config = SATOSAConfig._readfile(config)
            return yaml.safe_load(config)
        except yaml.YAMLError as error:
            LOGGER.debug("Could not parse config as YAML: {}", str(error))

    @staticmethod
    def _readfile(config):
        """
        Reads a file path and return the data.
        If the path doesn't point to a file, the input will be used as return data.

        :type config: str
        :rtype: str

        :param config: Path to file or config string
        :return: File data
        """
        with open(config) as f:
            return f.read()
