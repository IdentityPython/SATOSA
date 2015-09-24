from satosa.backends.base import BackendModule
from satosa.frontends.base import FrontendModule

__author__ = 'mathiashedstrom'


class InterfaceModule(object):
    def __init__(self, module, name, config):
        self.module = module
        self.name = name
        self.config = config

    @staticmethod
    def get_instance(base_url):
        raise NotImplementedError()


class FrontendModulePlugin(InterfaceModule):
    def __init__(self, module, receiver, config):
        if not issubclass(module, FrontendModule):
            raise AttributeError("module is not instance of {}".format(FrontendModule.__name__))
        super(FrontendModulePlugin, self).__init__(module, receiver, config)


class BackendModulePlugin(InterfaceModule):
    def __init__(self, module, receiver, config):
        if not issubclass(module, BackendModule):
            raise AttributeError("module is not instance of {}".format(FrontendModule.__name__))
        super(BackendModulePlugin, self).__init__(module, receiver, config)
