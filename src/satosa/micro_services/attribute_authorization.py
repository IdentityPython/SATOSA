import re

from .base import ResponseMicroService
from ..exception import SATOSAAuthenticationError

def _filters(f, requester, provider):
    pf = f.get(provider, f.get("", f.get("default", {})))
    rf = pf.get(requester, pf.get("", pf.get("default", {})))
    return rf.items()

class AttributeAuthorization(ResponseMicroService):

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.attribute_allow = config.get("attribute_allow", {})
        self.attribute_deny = config.get("attribute_deny", {})

    def _check_authz(self, context, attributes, requester, provider):
        for attribute_name, attribute_filter in _filters(self.attribute_allow, requester, provider):
            regex = re.compile(attribute_filter)
            if attribute_name in attributes:
                print(repr(regex))
                print(list(filter(regex.search, attributes[attribute_name])))
                if not list(filter(regex.search, attributes[attribute_name])):
                    raise SATOSAAuthenticationError(context.state, "Permission denied")

        for attribute_name, attribute_filter in _filters(self.attribute_deny, requester, provider):
            regex = re.compile(attribute_filter)
            if attribute_name in attributes:
                if len(list(filter(regex.search, attributes[attribute_name]))) != len(attributes[attribute_name]):
                    raise SATOSAAuthenticationError(context.state, "Permission denied")

    def process(self, context, data):
        self._check_authz(context, data.attributes, data.requester, data.auth_info.issuer)
        return super().process(context, data)
