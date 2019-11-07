import copy
from unittest.mock import Mock

import pytest

from saml2.saml import NAMEID_FORMAT_TRANSIENT
from saml2.saml import NAMEID_FORMAT_PERSISTENT

import satosa
from satosa import util
from satosa.base import SATOSABase
from satosa.exception import SATOSAConfigurationError
from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData
from satosa.micro_services import consent
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

    def test_constuctor_should_raise_exception_if_account_linking_is_not_first_in_micro_service_list(
            self, satosa_config, account_linking_module_config):
        satosa_config["MICRO_SERVICES"].append(account_linking_module_config)
        with pytest.raises(SATOSAConfigurationError):
            SATOSABase(satosa_config)

    def test_constuctor_should_raise_exception_if_consent_is_not_last_in_micro_service_list(
            self, satosa_config, consent_module_config):
        satosa_config["MICRO_SERVICES"].insert(0, consent_module_config)
        with pytest.raises(SATOSAConfigurationError):
            SATOSABase(satosa_config)

    def test_auth_resp_callback_func_user_id_from_attrs_is_used_to_override_user_id(self, context, satosa_config):
        satosa_config["INTERNAL_ATTRIBUTES"]["user_id_from_attrs"] = ["user_id", "domain"]
        base = SATOSABase(satosa_config)

        internal_resp = InternalData(
            auth_info=AuthenticationInformation("", "", ""),
            attributes={"user_id": ["user"], "domain": ["@example.com"]},
            requester="test_requester",
        )
        context.state[satosa.base.STATE_KEY] = {"requester": "test_requester"}
        context.state[satosa.routing.STATE_KEY] = satosa_config["FRONTEND_MODULES"][0]["name"]

        base._auth_resp_callback_func(context, internal_resp)

        expected_user_id = "user@example.com"
        assert internal_resp["subject_id"] == expected_user_id

    def test_auth_req_callback_stores_state_for_consent(self, context, satosa_config):
        base = SATOSABase(satosa_config)

        context.target_backend = satosa_config["BACKEND_MODULES"][0]["name"]
        requester_name = [{"lang": "en", "text": "Test EN"}, {"lang": "sv", "text": "Test SV"}]
        internal_req = InternalData(
            subject_type=NAMEID_FORMAT_TRANSIENT,
            requester_name=requester_name,
            attributes=["attr1", "attr2"],
        )
        base._auth_req_callback_func(context, internal_req)

        assert context.state[consent.STATE_KEY]["requester_name"] == internal_req["requester_name"]
        assert context.state[consent.STATE_KEY]["filter"] == internal_req["attributes"]

    def test_auth_resp_callback_func_hashes_all_specified_attributes(self, context, satosa_config):
        satosa_config["INTERNAL_ATTRIBUTES"]["hash"] = ["user_id", "mail"]
        base = SATOSABase(satosa_config)

        attributes = {"user_id": ["user"], "mail": ["user@example.com", "user@otherdomain.com"]}
        internal_resp = InternalData(
            auth_info=AuthenticationInformation("", "", ""),
            attributes=copy.copy(attributes),
            subject_id="test_user",
        )
        context.state[satosa.base.STATE_KEY] = {"requester": "test_requester"}
        context.state[satosa.routing.STATE_KEY] = satosa_config["FRONTEND_MODULES"][0]["name"]

        base._auth_resp_callback_func(context, internal_resp)
        for attr in satosa_config["INTERNAL_ATTRIBUTES"]["hash"]:
            assert internal_resp["attributes"][attr] == [
                util.hash_data(satosa_config.get("USER_ID_HASH_SALT", ""), v)
                for v in attributes[attr]
            ]

    def test_auth_resp_callback_func_respects_user_id_to_attr(self, context, satosa_config):
        satosa_config["INTERNAL_ATTRIBUTES"]["user_id_to_attr"] = "user_id"
        base = SATOSABase(satosa_config)

        internal_resp = InternalData(
            auth_info=AuthenticationInformation("", "", ""),
            subject_id="user1234",
        )
        context.state[satosa.base.STATE_KEY] = {"requester": "test_requester"}
        context.state[satosa.routing.STATE_KEY] = satosa_config["FRONTEND_MODULES"][0]["name"]

        base._auth_resp_callback_func(context, internal_resp)
        assert internal_resp["attributes"]["user_id"] == [internal_resp["subject_id"]]

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
