"""
Some help functions to load satosa backend and frontend modules
"""
import inspect
import json
import logging
import sys
from pydoc import locate

import yaml
from yaml.error import YAMLError

from .backends.base import BackendModule
from .exception import SATOSAConfigurationError
from .frontends.base import FrontendModule
from .micro_service.service_base import (MicroService, RequestMicroService,
                                         ResponseMicroService, build_micro_service_queue)

logger = logging.getLogger(__name__)


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
    backend_modules = _load_plugins(config.PLUGIN_PATH, config.BACKEND_MODULES, backend_filter,
                                    config.BASE, internal_attributes, callback)
    endpoint_modules = {module.name: module for module in backend_modules}
    logger.info("Setup backends: %s" % list(endpoint_modules.keys()))
    return endpoint_modules


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
    frontend_modules = _load_plugins(config.PLUGIN_PATH, config.FRONTEND_MODULES, frontend_filter,
                                     config.BASE, internal_attributes, callback)
    endpoint_modules = {module.name: module for module in frontend_modules}
    logger.info("Setup frontends: %s" % list(endpoint_modules.keys()))
    return endpoint_modules


def backend_filter(cls):
    """
    Verify that the type proper subclass of BackendModule.

    :type cls: type
    :rtype: bool

    :param cls: A class object
    :return: True if match, else false
    """
    return issubclass(cls, BackendModule) and cls != BackendModule


def frontend_filter(cls):
    """
    Verify that the type proper subclass of FrontendModule.

    :type cls: type
    :rtype: bool

    :param cls: A class object
    :return: True if match, else false
    """
    return issubclass(cls, FrontendModule) and cls != FrontendModule


def _micro_service_filter(member):
    """
    Will only give a find on classes that is a subclass of MicroService, with the exception that
    the class is not allowed to be a direct ResponseMicroService or RequestMicroService.

    :type member: type | str
    :rtype: bool

    :param member: A class object
    :return: True if match, else false
    """
    is_module = inspect.isclass(member) and issubclass(member, MicroService)
    is_correct_subclass = member != MicroService and member != ResponseMicroService and member != RequestMicroService
    return is_module and is_correct_subclass


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


def _load_plugin_config(config):
    try:
        return yaml.safe_load(config)
    except YAMLError as exc:
        if hasattr(exc, 'problem_mark'):
            mark = exc.problem_mark
            logger.error("Error position: (%s:%s)" % (mark.line + 1, mark.column + 1))
            raise SATOSAConfigurationError("The configuration is corrupt.") from exc


def _load_plugins(plugin_paths, plugins, plugin_filter, base_url, internal_attributes, callback):
    """
    Loads endpoint plugins

    :type plugin_paths: list[str]
    :type plugins: list[str]
    :type plugin_filter: (type | str) -> bool
    :type internal_attributes: dict[string, dict[str, str | list[str]]]
    :rtype list[satosa.plugin_base.endpoint.InterfaceModulePlugin]

    :param plugin_paths: Path to the plugin directory
    :param plugins: A list with the name of the plugin files
    :param plugin_filter: Filter what to load from the module file
    :param args: Arguments to the plugin
    :return: A list with all the loaded plugins
    """
    for p in reversed(plugin_paths):  # insert the specified plugin paths in the same order
        sys.path.insert(0, p)

    loaded_plugin_modules = []
    for module_file_name in plugins:
        with open(module_file_name) as f:
            _config = _load_plugin_config(f.read())

        if "plugin" in _config and "MicroService" in _config["plugin"]:
            # Load micro service
            if all(k in _config for k in ("plugin", "module")):
                module_class = locate(_config["module"])
                if not plugin_filter(module_class):
                    continue
                if "config" in _config:
                    instance = module_class(internal_attributes, _config["config"])
                else:
                    instance = module_class(internal_attributes)
                loaded_plugin_modules.append(instance)
            else:
                logger.warn("Missing mandatory configuration parameters in "
                            "the micro service plugin %s ('plugin', 'module')."
                            % module_file_name)
        else:
            try:
                plugin_module = _load_plugin_module(_config, plugin_filter, internal_attributes, callback, base_url)
                if plugin_module:
                    loaded_plugin_modules.append(plugin_module)
                    logger.debug("Loaded plugin from %s", module_file_name)
            except SATOSAConfigurationError as e:
                raise SATOSAConfigurationError("Configuration error in {}".format(module_file_name)) from e

    del sys.path[0:len(plugin_paths)]  # restore sys.path
    return loaded_plugin_modules


def _load_plugin_module(plugin_config, plugin_filter, internal_attributes, callback, base_url):
    _mandatory_params = ("name", "module", "config")
    if not all(k in plugin_config for k in _mandatory_params):
        raise SATOSAConfigurationError("Missing mandatory plugin configuration parameter: {}".format(_mandatory_params))

    module_class = locate(plugin_config["module"])
    if not module_class:
        raise ValueError("Can't find module '%s'" % plugin_filter["module"])
    if not plugin_filter(module_class):
        return None

    module_config = _replace_variables_in_plugin_module_config(plugin_config["config"], base_url, plugin_config["name"])
    return module_class(callback, internal_attributes, module_config, base_url, plugin_config["name"])


def _replace_variables_in_plugin_module_config(module_config, base_url, name):
    config = json.dumps(module_config)
    replace = [
        ("<base_url>", base_url),
        ("<name>", name)
    ]
    for _replace in replace:
        config = config.replace(_replace[0], _replace[1])
    return json.loads(config)


def load_micro_services(plugin_path, plugins, internal_attributes):
    """
    Loads micro services

    :type plugin_path: list[str]
    :type plugins: list[str]
    :type internal_attributes: dict[string, dict[str, str | list[str]]]
    :rtype (satosa.micro_service.service_base.RequestMicroService,
    satosa.micro_service.service_base.ResponseMicroService)

    :param plugin_path: Path to the plugin directory
    :param plugins: A list with the name of the plugin files
    :return: (Request micro service, response micro service)
    """
    request_services = _load_plugins(plugin_path, plugins, _request_micro_service_filter, "")
    response_services = _load_plugins(plugin_path, plugins, _response_micro_service_filter, "",
                                      internal_attributes=internal_attributes)

    logger.info(
        "Loaded request micro services: %s" % [k.__class__.__name__ for k in request_services])
    logger.info(
        "Loaded response micro services: %s" % [k.__class__.__name__ for k in
                                                response_services])

    return (
        build_micro_service_queue(request_services), build_micro_service_queue(response_services))
