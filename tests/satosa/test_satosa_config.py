import json
from unittest.mock import mock_open, patch

import pytest

from satosa.exception import SATOSAConfigurationError
from satosa.satosa_config import SATOSAConfig


class TestSATOSAConfig:
    @pytest.fixture
    def non_sensitive_config_dict(self):
        """Returns config without sensitive data (secret keys)."""
        config = {
            "BASE": "https://example.com",
            "COOKIE_STATE_NAME": "TEST_STATE",
            "BACKEND_MODULES": [{"foo": "bar"}],
            "FRONTEND_MODULES": [{"foo": "bar"}],
            "INTERNAL_ATTRIBUTES": {"attributes": {}}
        }
        return config

    def test_read_senstive_config_data_from_env_var(self, monkeypatch, non_sensitive_config_dict):
        monkeypatch.setenv("SATOSA_STATE_ENCRYPTION_KEY", "state_encryption_key")
        config = SATOSAConfig(non_sensitive_config_dict)
        assert config["STATE_ENCRYPTION_KEY"] == "state_encryption_key"

    def test_senstive_config_data_from_env_var_overrides_config(self, monkeypatch, non_sensitive_config_dict):
        non_sensitive_config_dict["STATE_ENCRYPTION_KEY"] = "bar"
        monkeypatch.setenv("SATOSA_STATE_ENCRYPTION_KEY", "state_encryption_key")

        config = SATOSAConfig(non_sensitive_config_dict)
        assert config["STATE_ENCRYPTION_KEY"] == "state_encryption_key"

    def test_constructor_should_raise_exception_if_sensitive_keys_are_missing(self, non_sensitive_config_dict):
        with pytest.raises(SATOSAConfigurationError):
            SATOSAConfig(non_sensitive_config_dict)

    @pytest.mark.parametrize("modules_key", [
        "BACKEND_MODULES",
        "FRONTEND_MODULES",
        "MICRO_SERVICES"
    ])
    def test_can_read_endpoint_configs_from_dict(self, satosa_config_dict, modules_key):
        expected_config = [{"foo": "bar"}, {"abc": "xyz"}]
        satosa_config_dict[modules_key] = expected_config

        config = SATOSAConfig(satosa_config_dict)
        assert config[modules_key] == expected_config

    @pytest.mark.parametrize("modules_key", [
        "BACKEND_MODULES",
        "FRONTEND_MODULES",
        "MICRO_SERVICES"
    ])
    def test_can_read_endpoint_configs_from_file(self, satosa_config_dict, modules_key):
        satosa_config_dict[modules_key] = ["/fake_file_path"]
        expected_config = {"foo": "bar"}

        with patch("builtins.open", mock_open(read_data=json.dumps(expected_config))):
            config = SATOSAConfig(satosa_config_dict)

        assert config[modules_key] == [expected_config]

    @pytest.mark.parametrize("modules_key", [
        "BACKEND_MODULES",
        "FRONTEND_MODULES",
        "MICRO_SERVICES"
    ])
    def test_can_read_endpoint_configs_from_file(self, satosa_config_dict, modules_key):
        satosa_config_dict[modules_key] = ["/fake_file_path"]

        with pytest.raises(SATOSAConfigurationError):
            SATOSAConfig(satosa_config_dict)

    def test_missing_mandatory_dict_keys_raises_exception(self, satosa_config_dict):
        for key in SATOSAConfig.mandatory_dict_keys:
            patched_dict = satosa_config_dict
            del patched_dict[key]
            with pytest.raises(SATOSAConfigurationError):
                SATOSAConfig(satosa_config_dict)

    def test_empty_mandatory_dict_key_vals_raises_exception(self, satosa_config_dict):
        for key in SATOSAConfig.mandatory_dict_keys:
            patched_dict = satosa_config_dict
            patched_dict[key] = None
            with pytest.raises(SATOSAConfigurationError):
                SATOSAConfig(satosa_config_dict)

    def test_can_skip_unset_microservices(self, satosa_config_dict):
        satosa_config_dict["MICRO_SERVICES"] = None
        config = SATOSAConfig(satosa_config_dict)
        assert config["MICRO_SERVICES"] == []

    def test_invalid_internal_attributes_raises_exception(self, satosa_config_dict):
        satosa_config_dict["INTERNAL_ATTRIBUTES"] = ["dummy.yaml"]
        expected_config = {}

        with patch("builtins.open", mock_open(read_data=json.dumps(expected_config))), \
             pytest.raises(SATOSAConfigurationError):
            SATOSAConfig(satosa_config_dict)

    def test_invalid_conf_raises_exception(self):
        with pytest.raises(SATOSAConfigurationError) as e:
            SATOSAConfig({})
