from pluginbase import PluginBase

__author__ = 'mathiashedstrom'


def load_backends(config, callback):
    return _load_endpoint_modules(config.PLUGIN_PATH, config.BACKEND_MODULES, config.BASE,
                                  callback, "provider")


def load_frontends(config, callback):
    return _load_endpoint_modules(config.PLUGIN_PATH, config.FRONTEND_MODULES, config.BASE,
                                  callback, "receiver")


def _load_endpoint_modules(plugin_path, modules, base, callback, name_attr):
    plugin_base = PluginBase(package='satosa_plugins')
    plugin_source = plugin_base.make_plugin_source(searchpath=plugin_path)
    endpoint_modules = {}
    for frontend in modules:
        endpoint_plugin = plugin_source.load_plugin(frontend).setup(base)
        module_inst = endpoint_plugin.module(callback, endpoint_plugin.config)
        endpoint_modules[getattr(endpoint_plugin, name_attr)] = module_inst
    return endpoint_modules
