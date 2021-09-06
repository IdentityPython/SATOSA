import re
from chevron import render as render_mustache

from .base import ResponseMicroService
from ..util import get_dict_defaults


class MustachAttrValue(object):
    def __init__(self, attr_name, values):
        self._attr_name = attr_name
        self._values = values
        if any(['@' in v for v in values]):
            local_parts = []
            domain_parts = []
            scopes = dict()
            for v in values:
                (local_part, sep, domain_part) = v.partition('@')
                # probably not needed now...
                local_parts.append(local_part)
                domain_parts.append(domain_part)
                scopes[domain_part] = True
            self._scopes = list(scopes.keys())
        else:
            self._scopes = None

    def __str__(self):
        return ";".join(self._values)

    @property
    def values(self):
        return [{self._attr_name: v} for v in self._values]

    @property
    def value(self):
        if len(self._values) == 1:
            return self._values[0]
        else:
            return self._values

    @property
    def first(self):
        if len(self._values) > 0:
            return self._values[0]
        else:
            return ""

    @property
    def scope(self):
        if self._scopes is not None:
            return self._scopes[0]
        return ""


class AddSyntheticAttributes(ResponseMicroService):
    """
A class that add generated or synthetic attributes to a response set. Attribute
generation is done using mustach (http://mustache.github.io) templates. The
following example configuration illustrates most common features:

```yaml
module: satosa.micro_services.attribute_generation.AddSyntheticAttributes
name: AddSyntheticAttributes
config:
    synthetic_attributes:
        requester1:
            target_provider1:
                eduPersonAffiliation: member;employee
        default:
            default:
                schacHomeOrganization: {{eduPersonPrincipalName.scope}}
                schacHomeOrganizationType: tomfoolery provider

```

The use of "" and 'default' is synonymous. Attribute rules are not
overloaded or inherited. For instance a response for "requester1"
from target_provider1 in the above config will generate a (static) attribute
set of 'member' and 'employee' for the eduPersonAffiliation attribute
and nothing else. Note that synthetic attributes override existing
attributes if present.

*Evaluating and interpreting templates*

Attribute values are split on combinations of ';' and newline so that
a template resulting in the following text:
```
a;
b;c
```
results in three attribute values: 'a','b' and 'c'. Templates are
evaluated with a single context that represents the response attributes
before the microservice is processed. De-referencing the attribute
name as in '{{name}}' results in a ';'-separated list of all attribute
values. This notation is useful when you know there is only a single
attribute value in the set.

*Special contexts*

For treating the values as a list - eg for interating using mustach,
use the .values sub-context For instance to synthesize all first-last
name combinations do this:

```
{{#givenName.values}}
   {{#sn.values}}{{givenName}} {{sn}}{{/sn.values}}
{{/givenName.values}}
```

Note that the .values sub-context behaves as if it is an iterator
over single-value context with the same key name as the original
attribute name.

The .scope sub-context evalues to the right-hand part of any @
sign. This is assumed to be single valued.

The .first sub-context evalues to the first value of a context
which may be safer to use if the attribute is multivalued but
you don't care which value is used in a template.
    """

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.synthetic_attributes = config["synthetic_attributes"]

    def _synthesize(self, attributes, requester, provider):
        syn_attributes = dict()
        context = dict()

        for attr_name, values in attributes.items():
            context[attr_name] = MustachAttrValue(
                attr_name,
                values if values is not None else []
            )

        recipes = get_dict_defaults(self.synthetic_attributes, requester, provider)
        for attr_name, fmt in recipes.items():
            syn_attributes[attr_name] = [
                value
                for token in re.split("[;\n]+", render_mustache(fmt, context))
                for value in [token.strip().strip(';')]
                if value
            ]
        return syn_attributes

    def process(self, context, data):
        data.attributes.update(self._synthesize(data.attributes, data.requester, data.auth_info.issuer))
        return super().process(context, data)
