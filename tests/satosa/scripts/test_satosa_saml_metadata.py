import glob
import os

import mongomock
import pytest
from saml2.config import Config
from saml2.mdstore import MetaDataFile
from saml2.sigver import security_context

from satosa.scripts.satosa_saml_metadata import create_and_write_saml_metadata


@pytest.fixture
def oidc_frontend_config(signing_key_path):
    data = {
        "module": "satosa.frontends.openid_connect.OpenIDConnectFrontend",
        "name": "OIDCFrontend",
        "config": {
            "issuer": "https://proxy-op.example.com",
            "signing_key_path": signing_key_path,
            "provider": {"response_types_supported": ["id_token"]},
        }
    }
    return data


@mongomock.patch(servers=(('localhost', 27017),))
class TestConstructSAMLMetadata:
    def test_saml_saml(self, tmpdir, cert_and_key, satosa_config_dict, saml_frontend_config,
                       saml_backend_config):
        satosa_config_dict["FRONTEND_MODULES"] = [saml_frontend_config]
        satosa_config_dict["BACKEND_MODULES"] = [saml_backend_config]

        create_and_write_saml_metadata(satosa_config_dict, cert_and_key[1], cert_and_key[0], str(tmpdir), None)

        conf = Config()
        conf.cert_file = cert_and_key[0]
        security_ctx = security_context(conf)
        metadata_files = ["frontend.xml", "backend.xml"]
        for file in metadata_files:
            md = MetaDataFile(None, os.path.join(str(tmpdir), file), security=security_ctx)
            assert md.load()

    def test_saml_oidc(self, tmpdir, cert_and_key, satosa_config_dict, saml_frontend_config,
                       oidc_backend_config):
        satosa_config_dict["FRONTEND_MODULES"] = [saml_frontend_config]
        satosa_config_dict["BACKEND_MODULES"] = [oidc_backend_config]

        create_and_write_saml_metadata(satosa_config_dict, cert_and_key[1], cert_and_key[0], str(tmpdir), None)

        conf = Config()
        conf.cert_file = cert_and_key[0]
        security_ctx = security_context(conf)
        md = MetaDataFile(None, os.path.join(str(tmpdir), "frontend.xml"), security=security_ctx)
        assert md.load()

        assert not os.path.isfile(os.path.join(str(tmpdir), "backend.xml"))

    def test_oidc_saml(self, tmpdir, cert_and_key, satosa_config_dict, oidc_frontend_config,
                       saml_backend_config):
        satosa_config_dict["FRONTEND_MODULES"] = [oidc_frontend_config]
        satosa_config_dict["BACKEND_MODULES"] = [saml_backend_config]

        create_and_write_saml_metadata(satosa_config_dict, cert_and_key[1], cert_and_key[0], str(tmpdir), None)

        conf = Config()
        conf.cert_file = cert_and_key[0]
        security_ctx = security_context(conf)
        md = MetaDataFile(None, os.path.join(str(tmpdir), "backend.xml"), security=security_ctx)
        assert md.load()

        assert not os.path.isfile(os.path.join(str(tmpdir), "frontend.xml"))

    def test_split_frontend_metadata_to_separate_files(self, tmpdir, cert_and_key, satosa_config_dict,
                                                       saml_mirror_frontend_config, saml_backend_config,
                                                       oidc_backend_config):

        satosa_config_dict["FRONTEND_MODULES"] = [saml_mirror_frontend_config]
        satosa_config_dict["BACKEND_MODULES"] = [oidc_backend_config, saml_backend_config]

        create_and_write_saml_metadata(satosa_config_dict, cert_and_key[1], cert_and_key[0], str(tmpdir), None,
                                       split_frontend_metadata=True)

        conf = Config()
        conf.cert_file = cert_and_key[0]
        security_ctx = security_context(conf)

        file_pattern = "{}*.xml".format(saml_mirror_frontend_config["name"])
        written_metadata_files = glob.glob(os.path.join(str(tmpdir), file_pattern))
        assert len(written_metadata_files) == 2
        for file in written_metadata_files:
            md = MetaDataFile(None, file, security=security_ctx)
            assert md.load()

    def test_split_backend_metadata_to_separate_files(self, tmpdir, cert_and_key, satosa_config_dict,
                                                      saml_frontend_config, saml_backend_config):

        satosa_config_dict["FRONTEND_MODULES"] = [saml_frontend_config]
        satosa_config_dict["BACKEND_MODULES"] = [saml_backend_config, saml_backend_config]

        create_and_write_saml_metadata(satosa_config_dict, cert_and_key[1], cert_and_key[0], str(tmpdir), None,
                                       split_backend_metadata=True)

        conf = Config()
        conf.cert_file = cert_and_key[0]
        security_ctx = security_context(conf)

        written_metadata_files = [saml_backend_config["name"], saml_backend_config["name"]]
        for file in written_metadata_files:
            md = MetaDataFile(None, os.path.join(str(tmpdir), "{}_0.xml".format(file)), security=security_ctx)
            assert md.load()
