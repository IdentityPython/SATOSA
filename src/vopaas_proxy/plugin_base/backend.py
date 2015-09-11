from vopaas_proxy.backends.base import BackendBase

__author__ = 'mathiashedstrom'


class BackendPlugin(object):
    def __init__(self, module, provider, config):
        if not issubclass(module, BackendBase):
            raise AttributeError("module is not instance of {}".format(BackendBase.__name__))
        self.module = module
        self.provider = provider
        self.config = config
