from satosa.internal_data import InternalResponse, AuthenticationInformation
from satosa.micro_services.attribute_authorization import AttributeAuthorization
from satosa.exception import SATOSAAuthenticationError
from satosa.context import Context

class TestAttributeAuthorization:
    def create_authz_service(self, attribute_allow, attribute_deny):
        authz_service = AttributeAuthorization(config=dict(attribute_allow=attribute_allow,attribute_deny=attribute_deny), name="test_authz",
                                               base_url="https://satosa.example.com")
        authz_service.next = lambda ctx, data: data
        return authz_service

    def test_authz_allow_success(self):
        attribute_allow = {
           "": { "default": {"a0": ['.+@.+']} }
        }
        attribute_deny = {}
        authz_service = self.create_authz_service(attribute_allow, attribute_deny)
        resp = InternalResponse(AuthenticationInformation(None, None, None))
        resp.attributes = {
            "a0": ["test@example.com"],
        }
        try:
           ctx = Context()
           ctx.state = dict()
           authz_service.process(ctx, resp)
        except SATOSAAuthenticationError as ex:
           assert False

    def test_authz_allow_fail(self):
        attribute_allow = {
           "": { "default": {"a0": ['foo1','foo2']} }
        }
        attribute_deny = {}
        authz_service = self.create_authz_service(attribute_allow, attribute_deny)
        resp = InternalResponse(AuthenticationInformation(None, None, None))
        resp.attributes = {
            "a0": ["bar"],
        }
        try:
           ctx = Context()
           ctx.state = dict()
           authz_service.process(ctx, resp)
           assert False
        except SATOSAAuthenticationError as ex:
           assert True

    def test_authz_allow_second(self):
        attribute_allow = {
           "": { "default": {"a0": ['foo1','foo2']} }
        }
        attribute_deny = {}
        authz_service = self.create_authz_service(attribute_allow, attribute_deny)
        resp = InternalResponse(AuthenticationInformation(None, None, None))
        resp.attributes = {
            "a0": ["foo2","kaka"],
        }
        try:
           ctx = Context()
           ctx.state = dict()
           authz_service.process(ctx, resp)
        except SATOSAAuthenticationError as ex:
           assert False

    def test_authz_deny_success(self):
        attribute_deny = {
           "": { "default": {"a0": ['foo1','foo2']} }
        }
        attribute_allow = {}
        authz_service = self.create_authz_service(attribute_allow, attribute_deny)
        resp = InternalResponse(AuthenticationInformation(None, None, None))
        resp.attributes = {
            "a0": ["foo2"],
        }
        try:
           ctx = Context()
           ctx.state = dict()
           authz_service.process(ctx, resp)
           assert False
        except SATOSAAuthenticationError as ex:
           assert True

    def test_authz_deny_fail(self):
        attribute_deny = {
           "": { "default": {"a0": ['foo1','foo2']} }
        }
        attribute_allow = {}
        authz_service = self.create_authz_service(attribute_allow, attribute_deny)
        resp = InternalResponse(AuthenticationInformation(None, None, None))
        resp.attributes = {
            "a0": ["foo3"],
        }
        try:
           ctx = Context()
           ctx.state = dict()
           authz_service.process(ctx, resp)
        except SATOSAAuthenticationError as ex:
           assert False
