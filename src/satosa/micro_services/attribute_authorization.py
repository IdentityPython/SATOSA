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
        for attribute_name, attribute_filters in _filters(self.attribute_allow, requester, provider):
            if attribute_name in attributes:
                if not any([any(filter(re.compile(af).search, attributes[attribute_name])) for af in attribute_filters]):
                    raise SATOSAAuthenticationError(context.state, "Permission denied")

        for attribute_name, attribute_filters in _filters(self.attribute_deny, requester, provider):
            if attribute_name in attributes:
                if any([any(filter(re.compile(af).search, attributes[attribute_name])) for af in attribute_filters]):
                    raise SATOSAAuthenticationError(context.state, "Permission denied")

    def process(self, context, data):
        self._check_authz(context, data.attributes, data.requester, data.auth_info.issuer)
        return super().process(context, data)
