"""
This module contains methods to load, verify and build configurations for the satosa proxy.
"""
import logging
import os

import yaml

from .exception import SATOSAConfigurationError

logger = logging.getLogger(__name__)


class SATOSAConfig(object):
    """
    A configuration class for the satosa proxy. Verifies that the given config holds all the
    necessary parameters.
    """
    sensitive_dict_keys = ["STATE_ENCRYPTION_KEY", "USER_ID_HASH_SALT"]
    mandatory_dict_keys = ["BASE", "BACKEND_MODULES", "FRONTEND_MODULES",
                           "INTERNAL_ATTRIBUTES", "COOKIE_STATE_NAME"] + sensitive_dict_keys

    def __init__(self, config):
        """
        Reads a given config and builds the SATOSAConfig.

        :type config: str | dict
        :rtype: satosa.satosa_config.SATOSAConfig

        :param config: Can be a file path or a dictionary
        :return: A verified SATOSAConfig
        """
        parsers = [self._load_dict, self._load_yaml]
        for parser in parsers:
            self._config = parser(config)
            if self._config is not None:
                break

        # Load sensitive config from environment variables
        for key in SATOSAConfig.sensitive_dict_keys:
            val = os.environ.get("SATOSA_{key}".format(key=key))
            if val:
                self._config[key] = val

        self._verify_dict(self._config)

        # Read plugin configs from dict or file path
        for key in ["BACKEND_MODULES", "FRONTEND_MODULES", "MICRO_SERVICES"]:
            plugin_configs = []
            for config in self._config.get(key, []):
                for parser in parsers:
                    plugin_config = parser(config)
                    if plugin_config:
                        plugin_configs.append(plugin_config)
                        break
                else:
                    raise SATOSAConfigurationError('Failed to load plugin config \'{}\''.format(config))
            self._config[key] = plugin_configs

        for parser in parsers:
            _internal_attributes = parser(self._config["INTERNAL_ATTRIBUTES"])
            if _internal_attributes is not None:
                self._config["INTERNAL_ATTRIBUTES"] = _internal_attributes
                break
        if not self._config["INTERNAL_ATTRIBUTES"]:
            raise SATOSAConfigurationError("Could not load attribute mapping from 'INTERNAL_ATTRIBUTES.")

    def _verify_dict(self, conf):
        """
        Check that the configuration contains all necessary keys.

        :type conf: dict
        :rtype: None
        :raise SATOSAConfigurationError: if the configuration is incorrect

        :param conf: config to verify
        :return: None
        """
        if not conf:
            raise SATOSAConfigurationError("Missing configuration or unknown format")

        for key in SATOSAConfig.mandatory_dict_keys:
            if key not in conf:
                raise SATOSAConfigurationError("Missing key '%s' in config" % key)

    def __getitem__(self, item):
        """
        Returns data bound to the key 'item'.

        :type item: str
        :rtype object

        :param item: key to data
        :return: data bound to key 'item'
        """
        return self._config[item]

    def __setitem__(self, key, value):
        """
        Inserts value into internal dict

        :type key: str
        :type value: object

        :param key: key
        :param value: data
        :return: None
        """
        self._config[key] = value

    def __contains__(self, key):
        return key in self._config

    def get(self, item, default=None):
        return self._config.get(item, default)

    def _load_dict(self, config):
        """
        Load config from dict

        :type config: dict
        :rtype: dict

        :param config: config to load
        :return: Loaded config
        """
        if isinstance(config, dict):
            return config

        return None

    def _load_yaml(self, config_file):
        """
        Load config from yaml file or string

        :type config_file: str
        :rtype: dict

        :param config_file: config to load. Can be file path or yaml string
        :return: Loaded config
        """
        try:
            with open(config_file) as f:
                return yaml.safe_load(f.read())
        except yaml.YAMLError as exc:
            logger.error("Could not parse config as YAML: {}", str(exc))
            if hasattr(exc, 'problem_mark'):
                mark = exc.problem_mark
                logger.error("Error position: (%s:%s)" % (mark.line + 1, mark.column + 1))
        except IOError as e:
            logger.debug("Could not open config file: {}", str(e))

        return None
