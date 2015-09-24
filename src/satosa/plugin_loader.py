import inspect
from pluginbase import PluginBase
from satosa.plugin_base.endpoint import InterfaceModule, BackendModulePlugin, FrontendModulePlugin

__author__ = 'mathiashedstrom'


def load_backends(config, callback):
    return _load_endpoint_modules(config.PLUGIN_PATH, config.BACKEND_MODULES, config.BASE,
                                  callback, backend_filter)


def load_frontends(config, callback):
    return _load_endpoint_modules(config.PLUGIN_PATH, config.FRONTEND_MODULES, config.BASE,
                                  callback, frontend_filter)


def member_filter(member):
    return (inspect.isclass(member) and issubclass(member, InterfaceModule) and
            member is not BackendModulePlugin and member is not FrontendModulePlugin)


def backend_filter(member):
    return member_filter(member) and issubclass(member, BackendModulePlugin)


def frontend_filter(member):
    return member_filter(member) and issubclass(member, FrontendModulePlugin)


def _load_endpoint_modules(plugin_path, modules, base, callback, filter):
    endpoint_modules = {}
    plugins = _load_plugins(plugin_path, modules, base, filter)
    for plugin in plugins:
        module_inst = plugin.module(callback, plugin.config)
        endpoint_modules[plugin.name] = module_inst

    return endpoint_modules


def _load_plugins(plugin_path, modules, base, filter):
    plugin_base = PluginBase(package='satosa_plugins')
    plugin_source = plugin_base.make_plugin_source(searchpath=plugin_path)
    plugins = []
    for module_file_name in modules:
        module = plugin_source.load_plugin(module_file_name)
        for name, obj in inspect.getmembers(module, filter):
            plugins.append(obj.get_instance(base))
    return plugins
