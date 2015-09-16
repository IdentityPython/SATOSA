from vopaas_proxy.frontends.base import FrontendBase

__author__ = 'mathiashedstrom'


class FrontendPlugin(object):
    def __init__(self, module, receiver, config):
        if not issubclass(module, FrontendBase):
            raise AttributeError("module is not instance of {}".format(FrontendBase.__name__))
        self.module = module
        self.receiver = receiver
        self.config = config
