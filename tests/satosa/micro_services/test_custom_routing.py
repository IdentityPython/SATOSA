from base64 import urlsafe_b64encode
from unittest import TestCase

import pytest

from satosa.context import Context
from satosa.state import State
from satosa.exception import SATOSAError, SATOSAConfigurationError
from satosa.internal import InternalData
from satosa.micro_services.custom_routing import DecideIfRequesterIsAllowed
from satosa.micro_services.custom_routing import DecideBackendByTargetIssuer
from satosa.micro_services.custom_routing import DecideBackendByRequester


TARGET_ENTITY = "entity1"


@pytest.fixture
def target_context(context):
    entityid_bytes = TARGET_ENTITY.encode("utf-8")
    entityid_b64_str = urlsafe_b64encode(entityid_bytes).decode("utf-8")
    context.decorate(Context.KEY_TARGET_ENTITYID, entityid_b64_str)
    return context


class TestDecideIfRequesterIsAllowed:
    def create_decide_service(self, rules):
        decide_service = DecideIfRequesterIsAllowed(config=dict(rules=rules), name="test_decide_service",
                                                    base_url="https://satosa.example.com")
        decide_service.next = lambda ctx, data: data
        return decide_service

    def test_allow_one_requester(self, target_context):
        rules = {
            TARGET_ENTITY: {
                "allow": ["test_requester"],
            }
        }
        decide_service = self.create_decide_service(rules)

        req = InternalData(requester="test_requester")
        assert decide_service.process(target_context, req)

        req.requester = "somebody else"
        with pytest.raises(SATOSAError):
            decide_service.process(target_context, req)

    @pytest.mark.parametrize("requester", [
        "test_requester",
        "somebody else"
    ])
    def test_allow_all_requesters(self, target_context, requester):
        rules = {
            TARGET_ENTITY: {
                "allow": ["*"],
            }
        }
        decide_service = self.create_decide_service(rules)

        req = InternalData(requester=requester)
        assert decide_service.process(target_context, req)

    def test_deny_one_requester(self, target_context):
        rules = {
            TARGET_ENTITY: {
                "deny": ["test_requester"],
            }
        }
        decide_service = self.create_decide_service(rules)

        req = InternalData(requester="test_requester")
        with pytest.raises(SATOSAError):
            assert decide_service.process(target_context, req)

    @pytest.mark.parametrize("requester", [
        "test_requester",
        "somebody else"
    ])
    def test_deny_all_requesters(self, target_context, requester):
        rules = {
            TARGET_ENTITY: {
                "deny": ["*"],
            }
        }
        decide_service = self.create_decide_service(rules)

        req = InternalData(requester=requester)
        with pytest.raises(SATOSAError):
            decide_service.process(target_context, req)

    def test_allow_takes_precedence_over_deny_all(self, target_context):
        requester = "test_requester"
        rules = {
            TARGET_ENTITY: {
                "allow": requester,
                "deny": ["*"],
            }
        }
        decide_service = self.create_decide_service(rules)

        req = InternalData(requester=requester)

        assert decide_service.process(target_context, req)

        req.requester = "somebody else"
        with pytest.raises(SATOSAError):
            decide_service.process(target_context, req)

    def test_deny_takes_precedence_over_allow_all(self, target_context):
        requester = "test_requester"
        rules = {
            TARGET_ENTITY: {
                "allow": ["*"],
                "deny": [requester],
            }
        }
        decide_service = self.create_decide_service(rules)

        req = InternalData(requester=requester)

        with pytest.raises(SATOSAError):
            decide_service.process(target_context, req)

        req = InternalData(requester="somebody else")
        decide_service.process(target_context, req)

    @pytest.mark.parametrize("requester", [
        "*",
        "test_requester"
    ])
    def test_deny_all_and_allow_all_should_raise_exception(self, requester):
        rules = {
            TARGET_ENTITY: {
                "allow": [requester],
                "deny": [requester],
            }
        }
        with pytest.raises(SATOSAConfigurationError):
            self.create_decide_service(rules)

    def test_defaults_to_allow_all_requesters_for_target_entity_without_specific_rules(self, target_context):
        rules = {
            "some other entity": {
                "allow": ["foobar"]
            }
        }
        decide_service = self.create_decide_service(rules)

        req = InternalData(requester="test_requester")
        assert decide_service.process(target_context, req)

    def test_missing_target_entity_id_from_context(self, context):
        target_entity = "entity1"
        rules = {
            target_entity: {
                "deny": ["*"],
            }
        }
        decide_service = self.create_decide_service(rules)

        req = InternalData(requester="test_requester")
        with pytest.raises(SATOSAError):
            decide_service.process(context, req)


class TestDecideBackendByTargetIssuer(TestCase):
    def setUp(self):
        context = Context()
        context.state = State()

        config = {
            'default_backend': 'default_backend',
            'target_mapping': {
                'mapped_idp.example.org': 'mapped_backend',
            },
        }

        plugin = DecideBackendByTargetIssuer(
            config=config,
            name='test_decide_service',
            base_url='https://satosa.example.org',
        )
        plugin.next = lambda ctx, data: (ctx, data)

        self.config = config
        self.context = context
        self.plugin = plugin

    def test_when_target_is_not_set_do_skip(self):
        data = InternalData(requester='test_requester')
        newctx, newdata = self.plugin.process(self.context, data)
        assert not newctx.target_backend

    def test_when_target_is_not_mapped_choose_default_backend(self):
        self.context.decorate(Context.KEY_TARGET_ENTITYID, 'idp.example.org')
        data = InternalData(requester='test_requester')
        newctx, newdata = self.plugin.process(self.context, data)
        assert newctx.target_backend == 'default_backend'

    def test_when_target_is_mapped_choose_mapping_backend(self):
        self.context.decorate(Context.KEY_TARGET_ENTITYID, 'mapped_idp.example.org')
        data = InternalData(requester='test_requester')
        data.requester = 'somebody else'
        newctx, newdata = self.plugin.process(self.context, data)
        assert newctx.target_backend == 'mapped_backend'


class TestDecideBackendByRequester(TestCase):
    def setUp(self):
        context = Context()
        context.state = State()

        config = {
            'requester_mapping': {
                'test_requester': 'mapped_backend',
            },
        }

        plugin = DecideBackendByRequester(
            config=config,
            name='test_decide_service',
            base_url='https://satosa.example.org',
        )
        plugin.next = lambda ctx, data: (ctx, data)

        self.config = config
        self.context = context
        self.plugin = plugin

    def test_when_requester_is_not_mapped_and_no_default_backend_skip(self):
        data = InternalData(requester='other_test_requester')
        newctx, newdata = self.plugin.process(self.context, data)
        assert not newctx.target_backend

    def test_when_requester_is_not_mapped_choose_default_backend(self):
        # override config to set default backend
        self.config['default_backend'] = 'default_backend'
        self.plugin = DecideBackendByRequester(
            config=self.config,
            name='test_decide_service',
            base_url='https://satosa.example.org',
        )
        self.plugin.next = lambda ctx, data: (ctx, data)

        data = InternalData(requester='other_test_requester')
        newctx, newdata = self.plugin.process(self.context, data)
        assert newctx.target_backend == 'default_backend'

    def test_when_requester_is_mapped_choose_mapping_backend(self):
        data = InternalData(requester='test_requester')
        data.requester = 'test_requester'
        newctx, newdata = self.plugin.process(self.context, data)
        assert newctx.target_backend == 'mapped_backend'
