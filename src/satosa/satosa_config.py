import os

__author__ = 'mathiashedstrom'


class SATOSAConfig(object):
    mandatory_dict_keys = ["HOST", "PORT", "HTTPS", "PLUGIN_PATH", "BACKEND_MODULES",
                           "FRONTEND_MODULES"]

    def __init__(self, config):

        self.__dict__["_config"] = None
        dict_parsers = [SATOSAConfig._load_dict, SATOSAConfig._load_json, SATOSAConfig._load_yaml]
        for parser in dict_parsers:
            self.__dict__["_config"] = parser(config)
            if self._config:
                break

        self._verify_dict(self._config)
        https = ""
        if self._config["HTTPS"]:
            https = "s"
        self.BASE = "http%s://%s:%s" % (https, self.HOST, self.PORT)

    def _verify_dict(self, conf):
        assert conf is not None, "Missing configuration or unknown format"
        for mand_key in SATOSAConfig.mandatory_dict_keys:
            assert mand_key in conf, "Missing key '%s' in config" % mand_key

    def __getattr__(self, item):
        if self._config is not None and item in self._config:
            return self._config[item]
        raise AttributeError("'module' object has no attribute '%s'" % item)

    def __setattr__(self, key, value):
        if key != "_config":
            if self._config is not None:
                self._config[key] = value

    @staticmethod
    def _load_dict(config):
        if isinstance(config, dict):
            return config

    @staticmethod
    def _load_json(config):
        try:
            config = SATOSAConfig._readfile(config)
            import json
            return json.loads(config)
        except Exception:
            pass

    @staticmethod
    def _load_yaml(config):
        try:
            config = SATOSAConfig._readfile(config)
            import yaml
            return yaml.load(config)
        except Exception:
            pass

    @staticmethod
    def _readfile(config):
        try:
            if os.path.isfile(config):
                fd = open(config, "r")
                config = fd.read()
                fd.close()
        except Exception:
            pass
        return config
