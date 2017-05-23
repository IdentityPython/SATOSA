import re
import pystache

from .base import ResponseMicroService

def _config(f, requester, provider):
    pf = f.get(provider, f.get("", f.get("default", {})))
    rf = pf.get(requester, pf.get("", pf.get("default", {})))
    return rf.items()

class MustachAttrValue(object):
    def __init__(self,values):
       self.values = values
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
        return ";".join(self.values)
   
    @property 
    def value(self):
        if 1 == len(self.values): 
           return self.values[0]
        else:
           return self.values

    @property
    def first(self):
        if len(self.values) > 0:
           return self.values[0]
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
           context[attr_name] = MustachAttrValue(values)

        recipes = _config(self.synthetic_attributes, requester, provider)
        print(context)
        for attr_name, fmt in recipes:
           print(fmt)
           syn_attributes[attr_name] = re.split("[;\n]+", pystache.render(fmt, context))
        print(syn_attributes)
        return syn_attributes

    def process(self, context, data):
        data.attributes.update(self._synthesize(data.attributes, data.requester, data.auth_info.issuer))
        return super().process(context, data)
