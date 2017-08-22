from ..attribute_processor import AttributeProcessorError
from .base_processor import BaseProcessor


CONFIG_KEY_SCOPE = 'scope'
CONFIG_DEFAULT_SCOPE = ''


class ScopeProcessor(BaseProcessor):
    def process(self, internal_data, attribute, **kwargs):
        scope = kwargs.get(CONFIG_KEY_SCOPE, CONFIG_DEFAULT_SCOPE)
        if scope is None or scope == '':
            raise AttributeProcessorError("No scope set.")

        attributes = internal_data.attributes
        values = attributes.get(attribute, [])
        if not isinstance(values, list):
            values = [values]
        if values:
            attributes[attribute] = list(v + '@' + scope for v in values)
