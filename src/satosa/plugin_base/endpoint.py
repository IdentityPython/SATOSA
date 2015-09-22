from satosa.backends.base import BackendBase
from satosa.frontends.base import FrontendBase

__author__ = 'mathiashedstrom'


class InterfaceModule(object):
    def __init__(self, module, name, config):
        self.module = module
        self.name = name
        self.config = config

    @staticmethod
    def get_instance(base_url):
        raise NotImplementedError()


class FrontendModule(InterfaceModule):
    def __init__(self, module, receiver, config):
        if not issubclass(module, FrontendBase):
            raise AttributeError("module is not instance of {}".format(FrontendBase.__name__))
        super(FrontendModule, self).__init__(module, receiver, config)


class BackendModule(InterfaceModule):
    def __init__(self, module, receiver, config):
        if not issubclass(module, BackendBase):
            raise AttributeError("module is not instance of {}".format(FrontendBase.__name__))
        super(BackendModule, self).__init__(module, receiver, config)
