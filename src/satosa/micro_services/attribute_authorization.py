import re

from .base import ResponseMicroService
from ..exception import SATOSAAuthenticationError
from ..util import get_dict_defaults

class AttributeAuthorization(ResponseMicroService):

    """
A microservice that performs simple regexp-based authorization based on response
attributes. The configuration assumes a dict with two keys: attributes_allow
and attributes_deny. An examples speaks volumes:

```yaml
config:
    attribute_allow:
        target_provider1:
            requester1:
                attr1:
                   - "^foo:bar$"
                   - "^kaka$"
            default:
                attr1:
                   - "plupp@.+$"
        "":
            "":
                attr2:
                   - "^knytte:.*$"
    attribute_deny:
        default:
            default:
                eppn:
                   - "^[^@]+$"

```

The use of "" and 'default' is synonymous. Attribute rules are not overloaded
or inherited. For instance a response from "provider2" would only be allowed
through if the eppn attribute had all values containing an '@' (something
perhaps best implemented via an allow rule in practice). Responses from
target_provider1 bound for requester1 would be allowed through only if attr1
contained foo:bar or kaka. Note that attribute filters (the leaves of the
structure above) are ORed together - i.e any attribute match is sufficient.
    """

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.attribute_allow = config.get("attribute_allow", {})
        self.attribute_deny = config.get("attribute_deny", {})

    def _check_authz(self, context, attributes, requester, provider):
        for attribute_name, attribute_filters in get_dict_defaults(self.attribute_allow, requester, provider).items():
            if attribute_name in attributes:
                if not any([any(filter(re.compile(af).search, attributes[attribute_name])) for af in attribute_filters]):
                    raise SATOSAAuthenticationError(context.state, "Permission denied")

        for attribute_name, attribute_filters in get_dict_defaults(self.attribute_deny, requester, provider).items():
            if attribute_name in attributes:
                if any([any(filter(re.compile(af).search, attributes[attribute_name])) for af in attribute_filters]):
                    raise SATOSAAuthenticationError(context.state, "Permission denied")

    def process(self, context, data):
        self._check_authz(context, data.attributes, data.requester, data.auth_info.issuer)
        return super().process(context, data)
