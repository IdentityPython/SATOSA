import re

from .base import ResponseMicroService
from ..exception import SATOSAError


class AddStaticAttributes(ResponseMicroService):
    """
    Add static attributes to the responses.
    """

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.static_attributes = config["static_attributes"]

    def process(self, context, data):
        data.attributes.update(self.static_attributes)
        return super().process(context, data)


class FilterAttributeValues(ResponseMicroService):
    """
    Filter attribute values, only preserving those matching the given regex.
    """

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.attribute_filters = config["attribute_filters"]

    def process(self, context, data):
        # apply default filters
        provider_filters = self.attribute_filters.get("", {})
        self._apply_requester_filters(data.attributes, provider_filters, data.requester)

        # apply target provider specific filters
        target_provider = data.auth_info.issuer
        provider_filters = self.attribute_filters.get(target_provider, {})
        self._apply_requester_filters(data.attributes, provider_filters, data.requester)
        return super().process(context, data)

    def _apply_requester_filters(self, attributes, provider_filters, requester):
        # apply default requester filters
        default_requester_filters = provider_filters.get("", {})
        self._apply_filters(attributes, default_requester_filters)

        # apply requester specific filters
        requester_filters = provider_filters.get(requester, {})
        self._apply_filters(attributes, requester_filters)

    def _apply_filters(self, attributes, attribute_filters):
        for attribute_name, attribute_filters in attribute_filters.items():
            if type(attribute_filters) == str:
                # convert simple notation to filter list
                attribute_filters = {'regexp': attribute_filters}

            for filter_type, filter_value in attribute_filters.items():

                if filter_type == "regexp":
                    filter_func = re.compile(filter_value).search
                else:
                    raise SATOSAError("Unknown filter type")

                if attribute_name == "":  # default filter for all attributes
                    for attribute, values in attributes.items():
                        attributes[attribute] = list(filter(filter_func, attributes[attribute]))
                elif attribute_name in attributes:
                    attributes[attribute_name] = list(filter(filter_func, attributes[attribute_name]))
