import os
from unittest.mock import Mock

import pytest

import satosa
from satosa.base import SATOSABase
from satosa.internal_data import InternalResponse, AuthenticationInformation, UserIdHasher
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
    def satosa_config(self, backend_plugin_config, frontend_plugin_config, request_microservice_config,
                      response_microservice_config):
        satosa_config = {
            "BASE": "https://proxy.example.com",
            "USER_ID_HASH_SALT": "qwerty",
            "COOKIE_STATE_NAME": "SATOSA_SATE",
            "STATE_ENCRYPTION_KEY": "ASDasd123",
            "CUSTOM_PLUGIN_MODULE_PATHS": [os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))],
            "BACKEND_MODULES": [backend_plugin_config],
            "FRONTEND_MODULES": [frontend_plugin_config],
            "MICRO_SERVICES": [request_microservice_config, response_microservice_config],
            "INTERNAL_ATTRIBUTES": {"attributes": {}},
        }

        return SATOSAConfig(satosa_config)

    def test_full_initialisation(self, satosa_config, consent_module_config, accoung_linking_module_config):
        satosa_config["CONSENT"] = consent_module_config
        satosa_config["ACCOUNT_LINKING"] = accoung_linking_module_config

        base = SATOSABase(satosa_config)
        assert base.config == satosa_config
        assert base.consent_module
        assert base.account_linking_module
        assert len(base.module_router.frontends) == 1
        assert len(base.module_router.backends) == 1
        assert len(base.request_micro_services) == 1
        assert len(base.response_micro_services) == 1

    def test_auth_resp_callback_func_user_id_from_attrs_is_used_to_override_user_id(self, context, satosa_config):
        satosa_config["INTERNAL_ATTRIBUTES"]["user_id_from_attrs"] = ["user_id", "domain"]
        internal_resp = InternalResponse(AuthenticationInformation("", "", ""))
        internal_resp.attributes = {"user_id": ["user"], "domain": ["@example.com"]}
        base = SATOSABase(satosa_config)

        context.state[satosa.base.STATE_KEY] = {"requester": "test_requester"}
        base.account_linking_module = Mock()
        base._auth_resp_callback_func(context, internal_resp)
        assert internal_resp.user_id == UserIdHasher.hash_data(satosa_config["USER_ID_HASH_SALT"], "user@example.com")
