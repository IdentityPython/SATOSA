from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData
from satosa.micro_services.attribute_generation import AddSyntheticAttributes
from satosa.context import Context

class TestAddSyntheticAttributes:
    def create_syn_service(self, synthetic_attributes):
        authz_service = AddSyntheticAttributes(config=dict(synthetic_attributes=synthetic_attributes),
                                               name="test_gen",
                                               base_url="https://satosa.example.com")
        authz_service.next = lambda ctx, data: data
        return authz_service

    def test_generate_static(self):
        synthetic_attributes = {
           "": { "default": {"a0": "value1;value2" }}
        }
        authz_service = self.create_syn_service(synthetic_attributes)
        resp = InternalData(auth_info=AuthenticationInformation())
        resp.attributes = {
            "a1": ["test@example.com"],
        }
        ctx = Context()
        ctx.state = dict()
        authz_service.process(ctx, resp)
        assert("value1" in resp.attributes['a0'])
        assert("value2" in resp.attributes['a0'])
        assert("test@example.com" in resp.attributes['a1'])

    def test_generate_mustache1(self):
        synthetic_attributes = {
           "": { "default": {"a0": "{{kaka}}#{{eppn.scope}}" }}
        }
        authz_service = self.create_syn_service(synthetic_attributes)
        resp = InternalData(auth_info=AuthenticationInformation())
        resp.attributes = {
            "kaka": ["kaka1"],
            "eppn": ["a@example.com","b@example.com"]
        }
        ctx = Context()
        ctx.state = dict()
        authz_service.process(ctx, resp)
        assert("kaka1#example.com" in resp.attributes['a0'])
        assert("kaka1" in resp.attributes['kaka'])
        assert("a@example.com" in resp.attributes['eppn'])
        assert("b@example.com" in resp.attributes['eppn'])

    def test_generate_mustache2(self):
        synthetic_attributes = {
           "": { "default": {"a0": "{{kaka.first}}#{{eppn.scope}}" }}
        }
        authz_service = self.create_syn_service(synthetic_attributes)
        resp = InternalData(auth_info=AuthenticationInformation())
        resp.attributes = {
            "kaka": ["kaka1","kaka2"],
            "eppn": ["a@example.com","b@example.com"]
        }
        ctx = Context()
        ctx.state = dict()
        authz_service.process(ctx, resp)
        assert("kaka1#example.com" in resp.attributes['a0'])
        assert("kaka1" in resp.attributes['kaka'])
        assert("a@example.com" in resp.attributes['eppn'])
        assert("b@example.com" in resp.attributes['eppn'])

    def test_generate_mustache_empty_attribute(self):
        synthetic_attributes = {
           "": {"default": {"a0": "{{kaka.first}}#{{eppn.scope}}"}}
        }
        authz_service = self.create_syn_service(synthetic_attributes)
        resp = InternalData(auth_info=AuthenticationInformation())
        resp.attributes = {
            "kaka": ["kaka1", "kaka2"],
            "eppn": None,
        }
        ctx = Context()
        ctx.state = dict()
        authz_service.process(ctx, resp)
        assert("kaka1#" in resp.attributes['a0'])
        assert("kaka1" in resp.attributes['kaka'])
        assert("kaka2" in resp.attributes['kaka'])
