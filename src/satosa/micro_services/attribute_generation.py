import re
import pystache

from .base import ResponseMicroService

def _config(f, requester, provider):
    pf = f.get(provider, f.get("", f.get("default", {})))
    rf = pf.get(requester, pf.get("", pf.get("default", {})))
    return rf.items()

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
        [{self._attr_name: v} for v in self._values]
   
    @property 
    def value(self):
        if 1 == len(self._values):
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
    Add synthetic attributes to the responses.
    """

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.synthetic_attributes = config["synthetic_attributes"]

    def _synthesize(self, attributes, requester, provider):
        syn_attributes = dict()
        context = dict()
        
        for attr_name,values in attributes.items():
           context[attr_name] = MustachAttrValue(attr_name, values)

        recipes = _config(self.synthetic_attributes, requester, provider)
        print(context)
        for attr_name, fmt in recipes:
           print(fmt)
           syn_attributes[attr_name] = [v.strip().strip(';') for v in re.split("[;\n]+", pystache.render(fmt, context))]
        print(syn_attributes)
        return syn_attributes

    def process(self, context, data):
        data.attributes.update(self._synthesize(data.attributes, data.requester, data.auth_info.issuer))
        return super().process(context, data)
