from ..attribute_processor import AttributeProcessorError
from .base_processor import BaseProcessor

class ScopeRemoverProcessor(BaseProcessor):
    """
    Removes the scope from a given attribute 
    
    """
    def process(self, internal_data, attribute, **kwargs):
        attributes = internal_data.attributes
        new_values = []
        for value in attributes.get(attribute, [None]):
            if '@' in value:
                new_values.append(value.split('@')[0])
        attributes[attribute] = new_values
