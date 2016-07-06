import pytest
import yaml

from satosa.satosa_config import SATOSAConfig


class TestSATOSAConfig:
    @pytest.fixture
    def non_sensitive_config_dict(self):
        """Returns config without sensitive data (secret keys)."""
        config = {
            "BASE": "https://example.com",
            "COOKIE_STATE_NAME": "TEST_STATE",
            "BACKEND_MODULES": ["foo"],
            "FRONTEND_MODULES": ["bar"],
            "INTERNAL_ATTRIBUTES": {"attributes": {}}
        }
        return config

    @pytest.fixture
    def sensitive_config_dict(self, non_sensitive_config_dict):
        non_sensitive_config_dict["STATE_ENCRYPTION_KEY"] = "state_encryption_key"
        non_sensitive_config_dict["USER_ID_HASH_SALT"] = "user_id_hash_salt"
        return non_sensitive_config_dict

    def test_read_senstive_config_data_from_env_var(self, monkeypatch, non_sensitive_config_dict):
        monkeypatch.setenv("SATOSA_USER_ID_HASH_SALT", "user_id_hash_salt")
        monkeypatch.setenv("SATOSA_STATE_ENCRYPTION_KEY", "state_encryption_key")
        config = SATOSAConfig(non_sensitive_config_dict)
        assert config["USER_ID_HASH_SALT"] == "user_id_hash_salt"
        assert config["STATE_ENCRYPTION_KEY"] == "state_encryption_key"

    def test_senstive_config_data_from_env_var_overrides_config(self, monkeypatch, non_sensitive_config_dict):
        non_sensitive_config_dict["USER_ID_HASH_SALT"] = "foo"
        non_sensitive_config_dict["STATE_ENCRYPTION_KEY"] = "bar"
        monkeypatch.setenv("SATOSA_USER_ID_HASH_SALT", "user_id_hash_salt")
        monkeypatch.setenv("SATOSA_STATE_ENCRYPTION_KEY", "state_encryption_key")

        config = SATOSAConfig(non_sensitive_config_dict)
        assert config["USER_ID_HASH_SALT"] == "user_id_hash_salt"
        assert config["STATE_ENCRYPTION_KEY"] == "state_encryption_key"

    @pytest.mark.parametrize("modules_key", [
        "BACKEND_MODULES",
        "FRONTEND_MODULES",
        "MICRO_SERVICES"
    ])
    def test_can_read_endpoint_configs_from_dict(self, sensitive_config_dict, modules_key):
        expected_config = [{"foo": "bar"}, {"abc": "xyz"}]
        sensitive_config_dict[modules_key] = expected_config

        config = SATOSAConfig(sensitive_config_dict)
        assert config[modules_key] == expected_config

    @pytest.mark.parametrize("modules_key", [
        "BACKEND_MODULES",
        "FRONTEND_MODULES",
        "MICRO_SERVICES"
    ])
    def test_can_read_endpoint_configs_from_file(self, backend_plugin_config, sensitive_config_dict, modules_key):
        sensitive_config_dict[modules_key] = [backend_plugin_config]
        with open(backend_plugin_config) as f:
            expected_config = yaml.load(f)

        config = SATOSAConfig(sensitive_config_dict)
        assert config[modules_key] == [expected_config]
