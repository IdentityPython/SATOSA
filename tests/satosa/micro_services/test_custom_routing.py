from base64 import urlsafe_b64encode

import pytest

from satosa.context import Context
from satosa.exception import SATOSAError, SATOSAConfigurationError
from satosa.internal_data import InternalRequest
from satosa.micro_services.custom_routing import DecideIfRequesterIsAllowed

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

        req = InternalRequest(None, "test_requester", None)
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

        req = InternalRequest(None, requester, None)
        assert decide_service.process(target_context, req)

    def test_deny_one_requester(self, target_context):
        rules = {
            TARGET_ENTITY: {
                "deny": ["test_requester"],
            }
        }
        decide_service = self.create_decide_service(rules)

        req = InternalRequest(None, "test_requester", None)
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

        req = InternalRequest(None, requester, None)
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

        req = InternalRequest(None, requester, None)

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

        req = InternalRequest(None, requester, None)

        with pytest.raises(SATOSAError):
            decide_service.process(target_context, req)

        req = InternalRequest(None, "somebody else", None)
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

        req = InternalRequest(None, "test_requester", None)
        assert decide_service.process(target_context, req)

    def test_missing_target_entity_id_from_context(self, context):
        target_entity = "entity1"
        rules = {
            target_entity: {
                "deny": ["*"],
            }
        }
        decide_service = self.create_decide_service(rules)

        req = InternalRequest(None, "test_requester", None)
        with pytest.raises(SATOSAError):
            decide_service.process(context, req)
