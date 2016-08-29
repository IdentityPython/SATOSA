import os

from saml2.config import Config
from saml2.mdstore import MetaDataFile
from saml2.sigver import security_context

from satosa.scripts.satosa_saml_metadata import create_and_write_saml_metadata


class TestConstructSAMLMetadata:
    def test_saml_saml(self, tmpdir, cert_and_key, satosa_config_dict, saml_frontend_config,
                       saml_backend_config):
        satosa_config_dict["FRONTEND_MODULES"] = [saml_frontend_config]
        satosa_config_dict["BACKEND_MODULES"] = [saml_backend_config]

        create_and_write_saml_metadata(satosa_config_dict, cert_and_key[1], cert_and_key[0], str(tmpdir), None)

        conf = Config()
        conf.cert_file = cert_and_key[0]
        security_ctx = security_context(conf)
        metadata_files = [os.path.join(str(tmpdir), "frontend.xml"), os.path.join(str(tmpdir), "backend.xml")]
        for file in metadata_files:
            md = MetaDataFile(None, file, security=security_ctx)
            assert md.load()

    def test_saml_oidc(self, tmpdir, cert_and_key, satosa_config_dict, saml_frontend_config,
                       oidc_backend_config):
        satosa_config_dict["FRONTEND_MODULES"] = [saml_frontend_config]
        satosa_config_dict["BACKEND_MODULES"] = [oidc_backend_config]

        create_and_write_saml_metadata(satosa_config_dict, cert_and_key[1], cert_and_key[0], str(tmpdir), None)

        conf = Config()
        conf.cert_file = cert_and_key[0]
        security_ctx = security_context(conf)
        metadata_files = [os.path.join(str(tmpdir), "frontend.xml")]
        for file in metadata_files:
            md = MetaDataFile(None, file, security=security_ctx)
            assert md.load()

        assert not os.path.isfile(os.path.join(str(tmpdir), "backend.xml"))
