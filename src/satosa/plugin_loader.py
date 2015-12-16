"""
Some help functions to load satosa backend and frontend modules
"""
import inspect
import json
import os
from pydoc import locate
import logging
import sys

from pluginbase import PluginBase

from satosa.exception import SATOSAConfigurationError
from satosa.micro_service.service_base import MicroService, RequestMicroService, \
    ResponseMicroService, \
    build_micro_service_queue
from satosa.plugin_base.endpoint import InterfaceModulePlugin, BackendModulePlugin, \
    FrontendModulePlugin

__author__ = 'mathiashedstrom'

LOGGER = logging.getLogger(__name__)


def load_backends(config, callback, internal_attributes):
    """
    Load all backend modules specified in the config

    :type config: satosa.satosa_config.SATOSAConfig
    :type callback:
    (satosa.context.Context, satosa.internal_data.InternalResponse) -> satosa.response.Response
    :type internal_attributes: dict[string, dict[str, str | list[str]]]
    :rtype: dict[str, satosa.backends.base.BackendModule]

    :param config: The configuration of the satosa proxy
    :param callback: Function that will be called by the backend after the authentication is done.
    :return: A list of backend modules
    """
    return _load_endpoint_modules(
        _load_plugins(config.PLUGIN_PATH, config.BACKEND_MODULES, backend_filter,
                      BackendModulePlugin.__name__,
                      config.BASE),
        callback, internal_attributes)


def load_frontends(config, callback, internal_attributes):
    """
    Load all frontend modules specified in the config

    :type config: satosa.satosa_config.SATOSAConfig
    :type callback:
    (satosa.context.Context, satosa.internal_data.InternalRequest) -> satosa.response.Response
    :type internal_attributes: dict[string, dict[str, str | list[str]]]
    :rtype: dict[str, satosa.frontends.base.FrontendModule]

    :param config: The configuration of the satosa proxy
    :param callback: Function that will be called by the frontend after the authentication request
    has been processed.
    :return: A dict of frontend modules
    """
    return _load_endpoint_modules(
        _load_plugins(config.PLUGIN_PATH, config.FRONTEND_MODULES, frontend_filter,
                      FrontendModulePlugin.__name__,
                      config.BASE),
        callback, internal_attributes)


def _member_filter(member):
    """
    Will only give a find on classes that is a subclass of InterfaceModulePlugin, with the exception
    that the class is not allowed to be a direct BackendModulePlugin or FrontendModulePlugin.

    :type member: type | str
    :rtype: bool

    :param member: A class object
    :return: True if match, else false
    """
    return (inspect.isclass(member) and issubclass(member, InterfaceModulePlugin) and
            member is not BackendModulePlugin and member is not FrontendModulePlugin)


def backend_filter(member):
    """
    Will only give a find on classes that is a subclass of BackendModulePlugin.
    Use this filter to only find backend plugins

    :type member: type | str
    :rtype: bool

    :param member: A class object
    :return: True if match, else false
    """
    return _member_filter(member) and issubclass(member, BackendModulePlugin)


def frontend_filter(member):
    """
    Will only give a find on classes that is a subclass of FrontendModulePlugin.
    Use this filter to only find frontend plugins

    :type member: type | str
    :rtype: bool

    :param member: A class object
    :return: True if match, else false
    """
    return _member_filter(member) and issubclass(member, FrontendModulePlugin)


def _micro_service_filter(member):
    """
    Will only give a find on classes that is a subclass of MicroService, with the exception that
    the class is not allowed to be a direct ResponseMicroService or RequestMicroService.

    :type member: type | str
    :rtype: bool

    :param member: A class object
    :return: True if match, else false
    """
    return (inspect.isclass(member) and
            issubclass(member, MicroService) and
            member is not ResponseMicroService and
            member is not RequestMicroService)


def _request_micro_service_filter(member):
    """
    Will only give a find on classes that is a subclass of RequestMicroService.
    Use this filter to only find frontend plugins

    :type member: type | str
    :rtype: bool

    :param member: A class object
    :return: True if match, else false
    """
    return _micro_service_filter(member) and issubclass(member, RequestMicroService)


def _response_micro_service_filter(member):
    """
    Will only give a find on classes that is a subclass of ResponseMicroService.
    Use this filter to only find frontend plugins

    :type member: type | str
    :rtype: bool

    :param member: A class object
    :return: True if match, else false
    """
    return _micro_service_filter(member) and issubclass(member, ResponseMicroService)


def _load_endpoint_modules(plugins, callback, internal_attributes=None):
    """
    Loads endpoint modules from plugins

    :type plugins: list[satosa.plugins_base.endpoint.InterfaceModulePlugin]
    :type callback: (satosa.context.Context, dict, str) -> T
    :rtype dict[str, satosa.frontends.base.FrontendModule | satosa.backends.base.BackendModule]

    :param plugins: A list of plugins
    :param callback: A function that will be called by the loaded endpoint module
    :return: a dict with the laoded modules. Key as module name and value as module instance
    """
    endpoint_modules = {}
    for plugin in plugins:
        module_inst = plugin.module(callback, internal_attributes, plugin.config)
        endpoint_modules[plugin.name] = module_inst
    LOGGER.info("Loaded modules: %s" % list(endpoint_modules.keys()))
    return endpoint_modules


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


def _load_json(config):
    """
    Load config from json file or string

    :type config: str
    :rtype: dict

    :param config: config to load. Can be file path or json string
    :return: Loaded config
    """
    file_config = None
    try:
        if not config.endswith('.json'):
            file_config = config + ".json"
        else:
            file_config = config
        config = _readfile(file_config)
        if config is not None:
            import json

            _dict = json.loads(config)
            if isinstance(_dict, dict):
                return _dict
            if file_config is not None and os.path.isfile(file_config):
                LOGGER.exception("The configuration file %s is corrupt." % file_config)
                raise SATOSAConfigurationError(
                    "The configuration file %s is corrupt." % file_config)
            return None
    except ValueError as error:
        if file_config is not None and os.path.isfile(file_config):
            LOGGER.exception("The configuration file %s is corrupt." % file_config)
            raise SATOSAConfigurationError("The configuration file %s is corrupt." % file_config)


def _load_yaml(config):
    """
    Load config from yaml file or string

    :type config: str
    :rtype: dict

    :param config: config to load. Can be file path or yaml string
    :return: Loaded config
    """
    file_config = None
    try:
        if not (config.endswith('.yaml') or config.endswith('.yml')):
            if os.path.isfile(config + ".yaml"):
                file_config = config + ".yaml"
            elif os.path.isfile(config + ".yml"):
                file_config = config + ".yml"
        else:
            file_config = config
        if config is not None:
            config = _readfile(file_config)
            import yaml

            _dict = yaml.load(config)
            if isinstance(_dict, dict):
                return _dict
            if file_config is not None and os.path.isfile(file_config):
                LOGGER.exception("The configuration file %s is corrupt." % file_config)
                raise SATOSAConfigurationError(
                    "The configuration file %s is corrupt." % file_config)
            return None
    except Exception as error:
        if file_config is not None and os.path.isfile(file_config):
            LOGGER.exception("The configuration file %s is corrupt." % file_config)
            raise SATOSAConfigurationError("The configuration file %s is corrupt." % file_config)


def _readfile(config):
    """
    Reads a file path and return the data.
    If the path doesn't point to a file, the input will be used as return data.

    :type config: str
    :rtype: str

    :param config: Path to file or config string
    :return: File data
    """
    try:
        if os.path.isfile(config):
            config_file = open(config, "r")
            config = config_file.read()
            config_file.close()
            return config
    except Exception:
        pass
    return None


def _load_plugins(plugin_path, plugins, plugin_filter, filter_class, *args):
    """
    Loads endpoint plugins

    :type plugin_path: list[str]
    :type plugins: list[str]
    :type plugin_filter: (type | str) -> bool
    :type args: Any
    :rtype list[satosa.plugin_base.endpoint.InterfaceModulePlugin]

    :param plugin_path: Path to the plugin directory
    :param plugins: A list with the name of the plugin files
    :param plugin_filter: Filter what to load from the module file
    :param args: Arguments to the plugin
    :return: A list with all the loaded plugins
    """
    plugin_base = PluginBase(package='satosa_plugins')
    plugin_source = plugin_base.make_plugin_source(searchpath=plugin_path)
    loaded_plugins = []
    loaded_plugin_names = []
    for module_file_name in plugins:
        try:
            module = plugin_source.load_plugin(module_file_name)
            for name, obj in inspect.getmembers(module, plugin_filter):
                loaded_plugins.append(obj(*args))
                loaded_plugin_names.append(module_file_name)
        except ImportError as error:
            LOGGER.debug("Not a py file or import error '%s': %s", module_file_name, error)
            dict_parsers = [_load_dict,
                            _load_json,
                            _load_yaml]
            _config = None
            for path in plugin_path:
                done = False
                for parser in dict_parsers:
                    _config = parser("%s/%s" % (path, module_file_name))
                    if _config and "plugin" in _config:
                            if _config["plugin"] == filter_class:
                                done = True
                                break
                            else:
                                _config = None
                if done:
                    break
            if _config is not None:
                try:

                    if "plugin" in _config and "MicroService" in _config["plugin"]:
                        # Load micro service
                        if all(k in _config for k in ("plugin", "module")):
                            module_class = locate(_config["module"])
                            instance = None
                            if "config" in _config:
                                instance = module_class(_config["config"])
                            else:
                                instance = module_class()
                            loaded_plugins.append(instance)
                        else:
                            LOGGER.warn("Missing mandatory configuration parameters in "
                                        "the micro service plugin %s ('plugin', 'module')."
                                        % module_file_name)
                    else:
                        if all(k in _config for k in ("name", "plugin", "module", "config")):

                            plugin_class = getattr(sys.modules[__name__], _config["plugin"])
                            module_class = locate(_config["module"])
                            if not module_class:
                                raise ValueError("Can't find module '%s'" % _config["module"])
                            name = _config["name"]
                            config = json.dumps(_config["config"])
                            replace = [
                                ("<base_url>", args[0]),
                                ("<name>", _config["name"])
                            ]
                            for _replace in replace:
                                config = config.replace(_replace[0], _replace[1])
                            config = json.loads(config)
                            module = plugin_class(module_class, name, config)
                            loaded_plugins.append(module)
                            loaded_plugin_names.append(module_file_name)
                        else:

                            LOGGER.warn("Missing mandatory configuration parameters in "
                                        "the plugin %s (plugin, module, receiver and/or config)."
                                        % module_file_name)
                except:
                    LOGGER.exception("Cannot create the module %s." % module_file_name)
        except Exception as error:
            LOGGER.exception("The configuration file %s is corrupt." % module_file_name)
            raise SATOSAConfigurationError(
                "The configuration file %s is corrupt." % module_file_name) from error
    LOGGER.debug("Loaded plugins: {}".format(loaded_plugin_names))
    return loaded_plugins


def load_micro_services(plugin_path, plugins):
    """
    Loads micro services

    :type plugin_path: list[str]
    :type plugins: list[str]
    :rtype (satosa.micro_service.service_base.RequestMicroService,
    satosa.micro_service.service_base.ResponseMicroService)

    :param plugin_path: Path to the plugin directory
    :param plugins: A list with the name of the plugin files
    :return: (Request micro service, response micro service)
    """
    request_services = _load_plugins(plugin_path, plugins, _request_micro_service_filter,
                                     RequestMicroService.__name__)
    response_services = _load_plugins(plugin_path, plugins, _response_micro_service_filter,
                                      ResponseMicroService.__name__)

    LOGGER.info(
        "Loaded request micro services: %s" % [k.__class__.__name__ for k in request_services])
    LOGGER.info(
        "Loaded response micro services: %s" % [k.__class__.__name__ for k in response_services])

    return (
        build_micro_service_queue(request_services), build_micro_service_queue(response_services))
