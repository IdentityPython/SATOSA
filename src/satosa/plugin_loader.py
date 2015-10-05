"""
Some help functions to load satosa backend and frontend modules
"""
import inspect
from pluginbase import PluginBase
from satosa.micro_service.service_base import MicroService, RequestMicroService, ResponseMicroService, \
    buld_micro_service_queue
from satosa.plugin_base.endpoint import InterfaceModulePlugin, BackendModulePlugin, FrontendModulePlugin

__author__ = 'mathiashedstrom'


def load_backends(config, callback):
    """
    Load all backend modules specified in the config

    :type config: satosa.satosa_config.SATOSAConfig
    :type callback: (satosa.context.Context, satosa.internal_data.InternalResponse, str) -> Any
    :rtype: dict[str, satosa.backends.base.BackendModule]

    :param config: The configuration of the satosa proxy
    :param callback: Function that will be called by the backend after the authentication is done.
    :return: A list of backend modules
    """
    return _load_endpoint_modules(
        _load_plugins(config.PLUGIN_PATH, config.BACKEND_MODULES, backend_filter, config.BASE),
        callback)


def load_frontends(config, callback):
    """
    Load all frontend modules specified in the config

    :type config: satosa.satosa_config.SATOSAConfig
    :type callback: (satosa.context.Context, satosa.internal_data.InternalRequest, str) -> Any
    :rtype: dict[str, satosa.frontends.base.FrontendModule]
    :rtype: dict[str, satosa.frontends.base.FrontendModule]

    :param config: The configuration of the satosa proxy
    :param callback: Function that will be called by the frontend after the authentication request has been processed.
    :return: A dict of frontend modules
    """
    return _load_endpoint_modules(
        _load_plugins(config.PLUGIN_PATH, config.FRONTEND_MODULES, frontend_filter, config.BASE),
        callback)


def _member_filter(member):
    """
    Will only give a find on classes that is a subclass of InterfaceModulePlugin, with the exception that the class
    is not allowed to be a direct BackendModulePlugin or FrontendModulePlugin.

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
    return (inspect.isclass(member) and issubclass(member, MicroService) and member is not ResponseMicroService and
            member is not RequestMicroService)

def _request_micro_service_filter(member):
    return _micro_service_filter(member) and issubclass(member, RequestMicroService)

def _response_micro_service_filter(member):
    return _micro_service_filter(member) and issubclass(member, ResponseMicroService)


def _load_endpoint_modules(plugins, callback):
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
        module_inst = plugin.module(callback, plugin.config)
        endpoint_modules[plugin.name] = module_inst

    return endpoint_modules


def _load_plugins(plugin_path, plugins, filter, *args):
    """
    Loads endpoint plugins

    :type plugin_path: list[str]
    :type plugins: list[str]
    :type filter: (type | str) -> bool
    :type args: Any
    :rtype list[satosa.plugin_base.endpoint.InterfaceModulePlugin]

    :param plugin_path: Path to the plugin directory
    :param plugins: A list with the name of the plugin files
    :param filter: Filter what to load from the module file
    :param args: Arguments to the plugin
    :return: A list with all the loaded plugins
    """
    plugin_base = PluginBase(package='satosa_plugins')
    plugin_source = plugin_base.make_plugin_source(searchpath=plugin_path)
    loaded_plugins = []
    for module_file_name in plugins:
        module = plugin_source.load_plugin(module_file_name)
        for name, obj in inspect.getmembers(module, filter):
            loaded_plugins.append(obj(*args))
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
    request_services = _load_plugins(plugin_path, plugins, _request_micro_service_filter)
    response_services = _load_plugins(plugin_path, plugins, _response_micro_service_filter)
    return (buld_micro_service_queue(request_services), buld_micro_service_queue(response_services))
