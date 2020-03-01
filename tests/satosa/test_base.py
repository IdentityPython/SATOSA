from unittest.mock import Mock

import pytest

import satosa
from satosa.base import SATOSABase
from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData
from satosa.satosa_config import SATOSAConfig


class TestSATOSABase:
    @pytest.fixture
    def satosa_config(self, satosa_config_dict):
        return SATOSAConfig(satosa_config_dict)

    def test_full_initialisation(self, satosa_config):
        base = SATOSABase(satosa_config)
        assert base.config == satosa_config
        assert len(base.module_router.frontends) == 1
        assert len(base.module_router.backends) == 1
        assert len(base.request_micro_services) == 1
        assert len(base.response_micro_services) == 1

    def test_auth_resp_callback_func_user_id_from_attrs_is_used_to_override_user_id(self, context, satosa_config):
        satosa_config["INTERNAL_ATTRIBUTES"]["user_id_from_attrs"] = ["user_id", "domain"]
        base = SATOSABase(satosa_config)

        internal_resp = InternalData(auth_info=AuthenticationInformation("", "", ""))
        internal_resp.attributes = {"user_id": ["user"], "domain": ["@example.com"]}
        internal_resp.requester = "test_requester"
        context.state[satosa.base.STATE_KEY] = {"requester": "test_requester"}
        context.state[satosa.routing.STATE_KEY] = satosa_config["FRONTEND_MODULES"][0]["name"]

        base._auth_resp_callback_func(context, internal_resp)

        expected_user_id = "user@example.com"
        assert internal_resp.subject_id == expected_user_id

    def test_auth_resp_callback_func_respects_user_id_to_attr(self, context, satosa_config):
        satosa_config["INTERNAL_ATTRIBUTES"]["user_id_to_attr"] = "user_id"
        base = SATOSABase(satosa_config)

        internal_resp = InternalData(auth_info=AuthenticationInformation("", "", ""))
        internal_resp.subject_id = "user1234"
        context.state[satosa.base.STATE_KEY] = {"requester": "test_requester"}
        context.state[satosa.routing.STATE_KEY] = satosa_config["FRONTEND_MODULES"][0]["name"]

        base._auth_resp_callback_func(context, internal_resp)
        assert internal_resp.attributes["user_id"] == [internal_resp.subject_id]

    @pytest.mark.parametrize("micro_services", [
        [Mock()],
        [Mock(), Mock()],
        [Mock(), Mock(), Mock()],
    ])
    def test_link_micro_services(self, satosa_config, micro_services):
        base = SATOSABase(satosa_config)
        finish_callable = Mock()
        base._link_micro_services(micro_services, finish_callable)

        for i in range(len(micro_services) - 1):
            assert micro_services[i].next == micro_services[i + 1].process
        assert micro_services[-1].next == finish_callable

    @pytest.mark.parametrize("micro_services", [
        [],
        None
    ])
    def test_link_micro_services_with_invalid_input(self, satosa_config, micro_services):
        base = SATOSABase(satosa_config)
        finish_callable = Mock()
        # should not raise exception
        base._link_micro_services(micro_services, finish_callable)
