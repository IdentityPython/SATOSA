import pytest
from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData
from satosa.micro_services.attribute_authorization import AttributeAuthorization
from satosa.exception import SATOSAAuthenticationError
from satosa.context import Context

class TestAttributeAuthorization:
    def create_authz_service(
        self,
        attribute_allow,
        attribute_deny,
        force_attributes_presence_on_allow=False,
        force_attributes_presence_on_deny=False,
    ):
        authz_service = AttributeAuthorization(
            config=dict(
                force_attributes_presence_on_allow=force_attributes_presence_on_allow,
                force_attributes_presence_on_deny=force_attributes_presence_on_deny,
                attribute_allow=attribute_allow,
                attribute_deny=attribute_deny,
            ),
            name="test_authz",
            base_url="https://satosa.example.com",
        )
        authz_service.next = lambda ctx, data: data
        return authz_service

    def test_authz_allow_success(self):
        attribute_allow = {
           "": { "default": {"a0": ['.+@.+']} }
        }
        attribute_deny = {}
        authz_service = self.create_authz_service(attribute_allow, attribute_deny)
        resp = InternalData(auth_info=AuthenticationInformation())
        resp.attributes = {
            "a0": ["test@example.com"],
        }
        try:
           ctx = Context()
           ctx.state = dict()
           authz_service.process(ctx, resp)
        except SATOSAAuthenticationError:
           assert False

    def test_authz_allow_fail(self):
        attribute_allow = {
           "": { "default": {"a0": ['foo1','foo2']} }
        }
        attribute_deny = {}
        authz_service = self.create_authz_service(attribute_allow, attribute_deny)
        resp = InternalData(auth_info=AuthenticationInformation())
        resp.attributes = {
            "a0": ["bar"],
        }
        with pytest.raises(SATOSAAuthenticationError):
           ctx = Context()
           ctx.state = dict()
           authz_service.process(ctx, resp)

    def test_authz_allow_missing(self):
        attribute_allow = {
           "": { "default": {"a0": ['foo1','foo2']} }
        }
        attribute_deny = {}
        authz_service = self.create_authz_service(attribute_allow, attribute_deny, force_attributes_presence_on_allow=True)
        resp = InternalData(auth_info=AuthenticationInformation())
        resp.attributes = {
        }
        with pytest.raises(SATOSAAuthenticationError):
           ctx = Context()
           ctx.state = dict()
           authz_service.process(ctx, resp)

    def test_authz_allow_second(self):
        attribute_allow = {
           "": { "default": {"a0": ['foo1','foo2']} }
        }
        attribute_deny = {}
        authz_service = self.create_authz_service(attribute_allow, attribute_deny)
        resp = InternalData(auth_info=AuthenticationInformation())
        resp.attributes = {
            "a0": ["foo2","kaka"],
        }
        try:
           ctx = Context()
           ctx.state = dict()
           authz_service.process(ctx, resp)
        except SATOSAAuthenticationError:
           assert False

    def test_authz_deny_success(self):
        attribute_deny = {
           "": { "default": {"a0": ['foo1','foo2']} }
        }
        attribute_allow = {}
        authz_service = self.create_authz_service(attribute_allow, attribute_deny)
        resp = InternalData(auth_info=AuthenticationInformation())
        resp.attributes = {
            "a0": ["foo2"],
        }
        with pytest.raises(SATOSAAuthenticationError):
           ctx = Context()
           ctx.state = dict()
           authz_service.process(ctx, resp)

    def test_authz_deny_fail(self):
        attribute_deny = {
           "": { "default": {"a0": ['foo1','foo2']} }
        }
        attribute_allow = {}
        authz_service = self.create_authz_service(attribute_allow, attribute_deny)
        resp = InternalData(auth_info=AuthenticationInformation())
        resp.attributes = {
            "a0": ["foo3"],
        }
        try:
           ctx = Context()
           ctx.state = dict()
           authz_service.process(ctx, resp)
        except SATOSAAuthenticationError:
           assert False
