from ..attribute_processor import AttributeProcessorError
from .base_processor import BaseProcessor


CONFIG_KEY_MAPPEDATTRIBUTE = 'mapped_attribute'
CONFIG_DEFAULT_MAPPEDATTRIBUTE = ''


class ScopeExtractorProcessor(BaseProcessor):
    """
    Extracts the scope from a scoped attribute and maps that to 
    another attribute
    
    Example configuration:
    module: satosa.micro_services.attribute_processor.AttributeProcessor
    name: AttributeProcessor
    config:
      process:
      - attribute: scoped_affiliation
        processors:
        - name: ScopeExtractorProcessor
          module: satosa.micro_services.processors.scope_extractor_processor
          mapped_attribute: domain
    """
    def process(self, internal_data, attribute, **kwargs):
        mapped_attribute = kwargs.get(CONFIG_KEY_MAPPEDATTRIBUTE, CONFIG_DEFAULT_MAPPEDATTRIBUTE)
        if mapped_attribute is None or mapped_attribute == '':
            raise AttributeProcessorError("The mapped_attribute needs to be set")

        attributes = internal_data.attributes
        for value in attributes.get(attribute, [None]):
            if '@' in value:
                scope = value.split('@')[1]
                attributes[mapped_attribute] = [scope]

