import copy
from unittest.mock import Mock

import pytest

import satosa
from satosa.base import SATOSABase
from satosa.internal_data import InternalResponse, AuthenticationInformation, UserIdHasher, InternalRequest, \
    UserIdHashType
from satosa.satosa_config import SATOSAConfig


class TestSATOSABase:
    @pytest.fixture
    def consent_module_config(self, signing_key_path):
        consent_config = {
            "api_url": "http://consent.example.com/api",
            "redirect_url": "http://consent.example.com/redirect",
            "sign_key": signing_key_path,
            "state_enc_key": "foo123",
        }
        return consent_config

    @pytest.fixture
    def accoung_linking_module_config(self, signing_key_path):
        account_linking_config = {
            "api_url": "http://account.example.com/api",
            "redirect_url": "http://account.example.com/redirect",
            "sign_key": signing_key_path,
            "state_enc_key": "abc123",
        }
        return account_linking_config

    @pytest.fixture
    def satosa_config(self, satosa_config_dict):
        return SATOSAConfig(satosa_config_dict)

    def test_full_initialisation(self, satosa_config, consent_module_config, accoung_linking_module_config):
        satosa_config["CONSENT"] = consent_module_config
        satosa_config["ACCOUNT_LINKING"] = accoung_linking_module_config

        base = SATOSABase(satosa_config)
        assert base.config == satosa_config
        assert base.consent_module
        assert base.account_linking_module
        assert len(base.module_router.frontends) == 1
        assert len(base.module_router.backends) == 3
        assert len(base.request_micro_services) == 1
        assert len(base.response_micro_services) == 1

    def test_auth_resp_callback_func_user_id_from_attrs_is_used_to_override_user_id(self, context, satosa_config):
        satosa_config["INTERNAL_ATTRIBUTES"]["user_id_from_attrs"] = ["user_id", "domain"]
        base = SATOSABase(satosa_config)

        internal_resp = InternalResponse(AuthenticationInformation("", "", ""))
        internal_resp.attributes = {"user_id": ["user"], "domain": ["@example.com"]}
        context.state[satosa.base.STATE_KEY] = {"requester": "test_requester"}
        base.account_linking_module = Mock()

        base._auth_resp_callback_func(context, internal_resp)
        assert internal_resp.user_id == UserIdHasher.hash_data(satosa_config["USER_ID_HASH_SALT"], "user@example.com")

    def test_account_linking_callback_func_hashes_all_specified_attributes(self, context, satosa_config):
        satosa_config["INTERNAL_ATTRIBUTES"]["hash"] = ["user_id", "mail"]
        base = SATOSABase(satosa_config)

        attributes = {"user_id": ["user"], "mail": ["user@example.com", "user@otherdomain.com"]}
        internal_resp = InternalResponse(AuthenticationInformation("", "", ""))
        internal_resp.attributes = copy.copy(attributes)
        UserIdHasher.save_state(InternalRequest(UserIdHashType.transient, ""), context.state)

        base.consent_module = Mock()
        base._account_linking_callback_func(context, internal_resp)
        for attr in satosa_config["INTERNAL_ATTRIBUTES"]["hash"]:
            assert internal_resp.attributes[attr] == [UserIdHasher.hash_data(satosa_config["USER_ID_HASH_SALT"], v)
                                                      for v in attributes[attr]]

    def test_account_linking_callback_func_respects_user_id_to_attr(self, context, satosa_config):
        satosa_config["INTERNAL_ATTRIBUTES"]["user_id_to_attr"] = "user_id"
        base = SATOSABase(satosa_config)

        internal_resp = InternalResponse(AuthenticationInformation("", "", ""))
        internal_resp.user_id = "user1234"
        UserIdHasher.save_state(InternalRequest(UserIdHashType.transient, ""), context.state)

        base.consent_module = Mock()
        base._account_linking_callback_func(context, internal_resp)
        assert internal_resp.attributes["user_id"] == internal_resp.user_id
