from ..attribute_processor import AttributeProcessorError, AttributeProcessorWarning
from .base_processor import BaseProcessor

class ScopeRemoverProcessor(BaseProcessor):
    """
    Removes the scope from all values of a given attribute 
    
    """
    def process(self, internal_data, attribute, **kwargs):
        attributes = internal_data.attributes
        new_values = []
        values = attributes.get(attribute, [None])
        if values:
            for value in attributes.get(attribute, [None]):
                unscoped_value = value.split('@')[0]
                new_values.append(unscoped_value)
            attributes[attribute] = new_values
        else:
            raise AttributeProcessorWarning("Attribute {} is not available".format(attribute))
