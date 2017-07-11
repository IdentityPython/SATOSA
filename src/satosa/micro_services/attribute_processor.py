import importlib
import json
import logging

from satosa.exception import SATOSAError
from satosa.logging_util import satosa_logging
from satosa.micro_services.base import ResponseMicroService


logger = logging.getLogger(__name__)

CONFIG_KEY_ROOT = 'process'
CONFIG_KEY_MODULE = 'module'
CONFIG_KEY_CLASSNAME = 'name'
CONFIG_KEY_ATTRIBUTE = 'attribute'
CONFIG_KEY_PROCESSORS = 'processors'


class AttributeProcessor(ResponseMicroService):
    """
    This microservice enables users to define modules that process internal
    attributes and their values.

    Example configuration:

      # file: attribute_processor.yaml
      module: satosa.micro_services.attribute_processor.AttributeProcessor
        process:
        - attribute: gender
          - name: GenderToSchacProcessor
            module: satosa.micro_services.processors.gender_processor
        - attribute: identifier
          processors:
          - name: HashProcessor
            module: satosa.micro_services.processors.hash_processor
            hash_alg: sha256
            salt: abcdef0123456789
          - name: ScopeProcessor
            module: satosa.micro_services.processors.scope_processor
            scope: example
    """
    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = config
        self.processes = config[CONFIG_KEY_ROOT]

    def process(self, context, data):
        for process in self.processes:
            attribute = process[CONFIG_KEY_ATTRIBUTE]
            processors = process[CONFIG_KEY_PROCESSORS]
            for processor in processors:
                module = importlib.import_module(processor[CONFIG_KEY_MODULE])
                module_cls = getattr(module, processor[CONFIG_KEY_CLASSNAME])
                instance = module_cls()

                kwargs = processor.copy()
                kwargs.pop(CONFIG_KEY_MODULE)
                kwargs.pop(CONFIG_KEY_CLASSNAME)

                try:
                    instance.process(data, attribute, **kwargs)
                except AttributeProcessorWarning as w:
                    satosa_logging(logger, logging.WARNING, w, context.state)

        return super().process(context, data)


class AttributeProcessorWarning(SATOSAError):
    pass


class AttributeProcessorError(SATOSAError):
    pass
