import inspect
from pluginbase import PluginBase
from satosa.plugin_base.endpoint import InterfaceModule, BackendModule, FrontendModule

__author__ = 'mathiashedstrom'


def load_backends(config, callback):
    return _load_endpoint_modules(config.PLUGIN_PATH, config.BACKEND_MODULES, config.BASE,
                                  callback)


def load_frontends(config, callback):
    return _load_endpoint_modules(config.PLUGIN_PATH, config.FRONTEND_MODULES, config.BASE,
                                  callback)


def member_filter(member):
    try:
        return (inspect.isclass(member) and issubclass(member, InterfaceModule) and
                member is not BackendModule and member is not FrontendModule)
    except Exception:
        pass
    return False


def _load_endpoint_modules(plugin_path, modules, base, callback):
    plugin_base = PluginBase(package='satosa_plugins')
    plugin_source = plugin_base.make_plugin_source(searchpath=plugin_path)
    endpoint_modules = {}
    for module_file_name in modules:
        module = plugin_source.load_plugin(module_file_name)
        for name, obj in inspect.getmembers(module, member_filter):
            endpoint_plugin = obj.get_instance(base)
            module_inst = endpoint_plugin.module(callback, endpoint_plugin.config)
            endpoint_modules[endpoint_plugin.name] = module_inst

    return endpoint_modules
