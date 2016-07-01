import os

import pytest

from satosa.base import SATOSABase
from satosa.satosa_config import SATOSAConfig


class TestSATOSABase:
    @pytest.fixture
    def satosa_config(self, signing_key_path, backend_plugin_config, frontend_plugin_config,
                      request_microservice_config, response_microservice_config):
        consent_config = {
            "api_url": "http://consent.example.com/api",
            "redirect_url": "http://consent.example.com/redirect",
            "sign_key": signing_key_path,
            "state_enc_key": "foo123",
        }
        account_linking_config = {
            "api_url": "http://account.example.com/api",
            "redirect_url": "http://account.example.com/redirect",
            "sign_key": signing_key_path,
            "state_enc_key": "abc123",
        }
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
            "CONSENT": consent_config,
            "ACCOUNT_LINKING": account_linking_config
        }

        return SATOSAConfig(satosa_config)

    def test_constructor(self, satosa_config):
        base = SATOSABase(satosa_config)
        assert base.config == satosa_config
        assert base.consent_module
        assert base.account_linking_module
        assert len(base.module_router.frontends) == 1
        assert len(base.module_router.backends) == 1
        assert len(base.request_micro_services) == 1
        assert len(base.response_micro_services) == 1

