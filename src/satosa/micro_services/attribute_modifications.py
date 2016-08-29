import os
import re

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


class FilterAttributeValues(ResponseMicroService):
    """
    Filter attribute values, only preserving those matching the given regex.

    The path to the file describing the filters (as YAML) must be specified
    with the environment variable 'SATOSA_ATTRIBUTE_VALUES_FILTER'.
    """

    def __init__(self, *args, **kwargs):
        filter_file = os.environ.get("SATOSA_ATTRIBUTE_FILTER")
        if not filter_file:
            raise ValueError("Environment variable 'SATOSA_ATTRIBUTE_FILTER' not set to path of filter file.")

        with open(filter_file) as f:
            self.attribute_filters = yaml.safe_load(f)

    def process(self, context, data):
        # apply default filters
        provider_filters = self.attribute_filters.get("", {})
        self._apply_requester_filters(data.attributes, provider_filters, data.requester)

        # apply target provider specific filters
        target_provider = data.auth_info.issuer
        provider_filters = self.attribute_filters.get(target_provider, {})
        self._apply_requester_filters(data.attributes, provider_filters, data.requester)
        return data

    def _apply_requester_filters(self, attributes, provider_filters, requester):
        # apply default requester filters
        default_requester_filters = provider_filters.get("", {})
        self._apply_filter(attributes, default_requester_filters)

        # apply requester specific filters
        requester_filters = provider_filters.get(requester, {})
        self._apply_filter(attributes, requester_filters)

    def _apply_filter(self, attributes, attribute_filters):
        for attribute_name, attribute_filter in attribute_filters.items():
            regex = re.compile(attribute_filter)
            if attribute_name == "":  # default filter for all attributes
                for attribute, values in attributes.items():
                    attributes[attribute] = list(filter(regex.search, attributes[attribute]))
            elif attribute_name in attributes:
                attributes[attribute_name] = list(filter(regex.search, attributes[attribute_name]))
