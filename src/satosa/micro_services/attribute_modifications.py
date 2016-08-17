import os

import yaml

from .base import ResponseMicroService
from ..attribute_mapping import AttributeMapper


class AddStaticAttributes(ResponseMicroService):
    """
    Add static attributes to the responses.

    The path to the file describing the mapping (as YAML) of static attributes must be specified
    with the environment variable 'SATOSA_STATIC_ATTRIBUTES'.
    """

    def __init__(self, internal_attributes, **kwargs):
        super().__init__()
        self.data_converter = AttributeMapper(internal_attributes)

        mapping_file = os.environ.get("SATOSA_STATIC_ATTRIBUTES")
        if not mapping_file:
            raise ValueError("Could not find file containing mapping of static attributes.")

        with open(mapping_file) as f:
            self.static_attributes = yaml.safe_load(f)

    def process(self, context, data):
        data.attributes.update(self.static_attributes)
        return data
