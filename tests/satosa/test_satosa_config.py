import pytest

from satosa.satosa_config import SATOSAConfig

DEFAULT_CONFIG_DICT = {
    "BASE": "https://example.com",
    "COOKIE_STATE_NAME": "TEST_STATE",
    "PLUGIN_PATH": ["."],
    "BACKEND_MODULES": ["foo"],
    "FRONTEND_MODULES": ["bar"],
    "INTERNAL_ATTRIBUTES": {}
}


class TestSATOSAConfig:
    def test_read_senstive_config_data_from_env_var(self, monkeypatch):
        monkeypatch.setenv("SATOSA_USER_ID_HASH_SALT", "user_id_hash_salt")
        monkeypatch.setenv("SATOSA_STATE_ENCRYPTION_KEY", "state_encryption_key")
        config = SATOSAConfig(DEFAULT_CONFIG_DICT)
        assert config.USER_ID_HASH_SALT == "user_id_hash_salt"
        assert config.STATE_ENCRYPTION_KEY == "state_encryption_key"

    def test_senstive_config_data_from_env_var_overrides_config(self, monkeypatch):
        monkeypatch.setitem(DEFAULT_CONFIG_DICT, "USER_ID_HASH_SALT", "foo")
        monkeypatch.setitem(DEFAULT_CONFIG_DICT, "STATE_ENCRYPTION_KEY", "bar")
        monkeypatch.setenv("SATOSA_USER_ID_HASH_SALT", "user_id_hash_salt")
        monkeypatch.setenv("SATOSA_STATE_ENCRYPTION_KEY", "state_encryption_key")

        config = SATOSAConfig(DEFAULT_CONFIG_DICT)
        assert config.USER_ID_HASH_SALT == "user_id_hash_salt"
        assert config.STATE_ENCRYPTION_KEY == "state_encryption_key"

    def test_raise_exception_if_file_dont_exist(self):
        with pytest.raises(IOError):
            SATOSAConfig._readfile("no_exist")
