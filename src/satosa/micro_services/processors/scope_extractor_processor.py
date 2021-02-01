from ..attribute_processor import AttributeProcessorError, AttributeProcessorWarning
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
        values = attributes.get(attribute, [])
        if not values:
            raise AttributeProcessorWarning("Cannot apply scope_extractor to {}, it has no values".format(attribute))
        if not isinstance(values, list):
            values = [values]
        if not any('@' in val for val in values):
            raise AttributeProcessorWarning("Cannot apply scope_extractor to {}, it's values are not scoped".format(attribute))
        for value in values:
            if '@' in value:
                scope = value.split('@')[1]
                attributes[mapped_attribute] = [scope]
                break
