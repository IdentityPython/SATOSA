import re
import logging

from .base import ResponseMicroService
from ..context import Context
from ..exception import SATOSAError

logger = logging.getLogger(__name__)

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
        target_provider = data.auth_info.issuer
        self._apply_requester_filters(data.attributes, provider_filters, data.requester, context, target_provider)

        # apply target provider specific filters
        provider_filters = self.attribute_filters.get(target_provider, {})
        self._apply_requester_filters(data.attributes, provider_filters, data.requester, context, target_provider)
        return super().process(context, data)

    def _apply_requester_filters(self, attributes, provider_filters, requester, context, target_provider):
        # apply default requester filters
        default_requester_filters = provider_filters.get("", {})
        self._apply_filters(attributes, default_requester_filters, context, target_provider)

        # apply requester specific filters
        requester_filters = provider_filters.get(requester, {})
        self._apply_filters(attributes, requester_filters, context, target_provider)

    def _apply_filters(self, attributes, attribute_filters, context, target_provider):
        for attribute_name, attribute_filters in attribute_filters.items():
            if type(attribute_filters) == str:
                # convert simple notation to filter list
                attribute_filters = {'regexp': attribute_filters}

            for filter_type, filter_value in attribute_filters.items():

                if filter_type == "regexp":
                    filter_func = re.compile(filter_value).search
                elif filter_type == "shibmdscope_match_scope":
                    mdstore = context.get_decoration(Context.KEY_METADATA_STORE)
                    md_scopes = list(mdstore.shibmd_scopes(target_provider,"idpsso_descriptor")) if mdstore else []
                    filter_func = lambda v: self._shibmdscope_match_scope(v, md_scopes)
                elif filter_type == "shibmdscope_match_value":
                    mdstore = context.get_decoration(Context.KEY_METADATA_STORE)
                    md_scopes = list(mdstore.shibmd_scopes(target_provider,"idpsso_descriptor")) if mdstore else []
                    filter_func = lambda v: self._shibmdscope_match_value(v, md_scopes)
                else:
                    raise SATOSAError("Unknown filter type")

                if attribute_name == "":  # default filter for all attributes
                    for attribute, values in attributes.items():
                        attributes[attribute] = list(filter(filter_func, attributes[attribute]))
                elif attribute_name in attributes:
                    attributes[attribute_name] = list(filter(filter_func, attributes[attribute_name]))

    def _shibmdscope_match_value(self, value, md_scopes):
        for md_scope in md_scopes:
            if not md_scope['regexp'] and md_scope['text'] == value:
                return True
            elif md_scope['regexp'] and re.fullmatch(md_scope['text'], value):
                return True
        return False

    def _shibmdscope_match_scope(self, value, md_scopes):
        split_value = value.split('@')
        if len(split_value) != 2:
            logger.info(f"Discarding invalid scoped value {value}")
            return False
        value_scope = split_value[1]
        return self._shibmdscope_match_value(value_scope, md_scopes)
