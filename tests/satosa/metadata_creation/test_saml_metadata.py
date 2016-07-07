import copy
from base64 import urlsafe_b64encode

import pytest
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.config import SPConfig, Config
from saml2.extension.idpdisc import BINDING_DISCO
from saml2.mdstore import InMemoryMetaData
from saml2.metadata import entity_descriptor
from saml2.saml import NAMEID_FORMAT_TRANSIENT, NAME_FORMAT_URI
from saml2.sigver import security_context
from saml2.time_util import in_a_while

from satosa.metadata_creation.saml_metadata import create_saml_metadata, sign_entity_descriptors
from satosa.satosa_config import SATOSAConfig
from tests.util import create_metadata_from_config_dict

BASE_URL = "https://example.com"


class TestCreateSAMLMetadata:
    @pytest.fixture
    def saml_backend_config(self):
        data = {
            "module": "satosa.backends.saml2.SAMLBackend",
            "name": "SAML2Backend",
            "config": {
                "config": {
                    "entityid": "backend-entity_id",
                    "organization": {"display_name": "Example Identities", "name": "Test Identities Org.",
                                     "url": "http://www.example.com"},
                    "contact_person": [
                        {"contact_type": "technical", "email_address": "technical@example.com",
                         "given_name": "Technical"},
                        {"contact_type": "support", "email_address": "support@example.com", "given_name": "Support"}
                    ],
                    "service": {
                        "sp": {
                            "allow_unsolicited": True,
                            "endpoints": {
                                "assertion_consumer_service": [
                                    ("{}/acs/post".format(BASE_URL), BINDING_HTTP_POST),
                                    ("{}/acs/redirect", BINDING_HTTP_REDIRECT)],
                                "discovery_response": [("{}/disco", BINDING_DISCO)]

                            }
                        }
                    }
                }
            }
        }
        return data

    @pytest.fixture
    def saml_frontend_config(self):
        data = {
            "module": "satosa.frontends.saml2.SAMLFrontend",
            "name": "SAML2Frontend",
            "config": {
                "idp_config": {
                    "entityid": "frontend-entity_id",
                    "organization": {"display_name": "Test Identities", "name": "Test Identities Org.",
                                     "url": "http://www.example.com"},
                    "contact_person": [{"contact_type": "technical", "email_address": "technical@example.com",
                                        "given_name": "Technical"},
                                       {"contact_type": "support", "email_address": "support@example.com",
                                        "given_name": "Support"}],
                    "service": {
                        "idp": {
                            "endpoints": {
                                "single_sign_on_service": []
                            },
                            "name": "Frontend IdP",
                            "name_id_format": NAMEID_FORMAT_TRANSIENT,
                            "policy": {
                                "default": {
                                    "attribute_restrictions": None,
                                    "fail_on_missing_requested": False,
                                    "lifetime": {"minutes": 15},
                                    "name_form": NAME_FORMAT_URI
                                }
                            }}}},
                "endpoints": {
                    "single_sign_on_service": {BINDING_HTTP_POST: "sso/post",
                                               BINDING_HTTP_REDIRECT: "sso/redirect"}
                }
            }
        }
        return data

    @pytest.fixture
    def saml_mirror_frontend_config(self, saml_frontend_config):
        data = copy.deepcopy(saml_frontend_config)
        data["module"] = "satosa.frontends.saml2.SAMLMirrorFrontend"
        data["name"] = "SAMLMirrorFrontend"
        return data

    @pytest.fixture
    def oidc_backend_config(self):
        data = {
            "module": "satosa.backends.openid_connect.OpenIDConnectBackend",
            "name": "OIDCBackend",
            "config": {
                "provider_metadata": {
                    "issuer": "https://op.example.com",
                    "authorization_endpoint": "https://example.com/authorization"
                },
                "client": {
                    "auth_req_params": {
                        "response_type": "code",
                        "scope": "openid, profile, email, address, phone"
                    },
                    "client_metadata": {
                        "client_id": "backend_client",
                        "application_name": "SATOSA",
                        "application_type": "web",
                        "contacts": ["suppert@example.com"],
                        "redirect_uris": ["{}/OIDCBackend"],
                        "subject_type": "public",
                    }
                },
                "entity_info": {
                    "contact_person": [{
                        "contact_type": "technical",
                        "email_address": ["technical_test@example.com", "support_test@example.com"],
                        "given_name": "Test",
                        "sur_name": "OP"
                    }, {
                        "contact_type": "support",
                        "email_address": ["support_test@example.com"],
                        "given_name": "Support_test"
                    }],
                    "organization": {
                        "display_name": ["OP Identities", "en"],
                        "name": [["En test-OP", "se"], ["A test OP", "en"]],
                        "url": [["http://www.example.com", "en"], ["http://www.example.se", "se"]],
                        "ui_info": {
                            "description": [["This is a test OP", "en"]],
                            "display_name": [["OP - TEST", "en"]]
                        }
                    }
                }
            }
        }

        return data

    def assert_single_sign_on_endpoints_for_saml_frontend(self, entity_descriptor, saml_frontend_config, backend_names):
        metadata = InMemoryMetaData(None, str(entity_descriptor))
        metadata.load()
        sso = metadata.service(saml_frontend_config["config"]["idp_config"]["entityid"], "idpsso_descriptor",
                               "single_sign_on_service")

        for backend_name in backend_names:
            for binding, path in saml_frontend_config["config"]["endpoints"]["single_sign_on_service"].items():
                sso_urls_for_binding = [endpoint["location"] for endpoint in sso[binding]]
                expected_url = "{}/{}/{}".format(BASE_URL, backend_name, path)
                assert expected_url in sso_urls_for_binding

    def assert_single_sign_on_endpoints_for_saml_mirror_frontend(self, entity_descriptors, encoded_target_entity_id,
                                                                 saml_mirror_frontend_config, backend_names):
        expected_entity_id = saml_mirror_frontend_config["config"]["idp_config"][
                                 "entityid"] + "/" + encoded_target_entity_id
        metadata = InMemoryMetaData(None, None)
        for ed in entity_descriptors:
            metadata.parse(str(ed))
        sso = metadata.service(expected_entity_id, "idpsso_descriptor", "single_sign_on_service")

        for backend_name in backend_names:
            for binding, path in saml_mirror_frontend_config["config"]["endpoints"]["single_sign_on_service"].items():
                sso_urls_for_binding = [endpoint["location"] for endpoint in sso[binding]]
                expected_url = "{}/{}/{}/{}".format(BASE_URL, backend_name, encoded_target_entity_id, path)
                assert expected_url in sso_urls_for_binding

    def assert_assertion_consumer_service_endpoints_for_saml_backend(self, entity_descriptor, saml_backend_config):
        metadata = InMemoryMetaData(None, str(entity_descriptor))
        metadata.load()
        acs = metadata.service(saml_backend_config["config"]["config"]["entityid"], "spsso_descriptor",
                               "assertion_consumer_service")
        for url, binding in saml_backend_config["config"]["config"]["service"]["sp"]["endpoints"][
            "assertion_consumer_service"]:
            assert acs[binding][0]["location"] == url

    def test_saml_frontend_with_saml_backend(self, satosa_config_dict, saml_frontend_config, saml_backend_config):
        satosa_config_dict["FRONTEND_MODULES"] = [saml_frontend_config]
        satosa_config_dict["BACKEND_MODULES"] = [saml_backend_config]
        satosa_config = SATOSAConfig(satosa_config_dict)
        frontend_metadata, backend_metadata = create_saml_metadata(satosa_config)

        assert len(frontend_metadata) == 1
        assert len(frontend_metadata[saml_frontend_config["name"]]) == 1
        entity_descriptor = frontend_metadata[saml_frontend_config["name"]][0]
        self.assert_single_sign_on_endpoints_for_saml_frontend(entity_descriptor, saml_frontend_config,
                                                               [saml_backend_config["name"]])
        assert len(backend_metadata) == 1
        self.assert_assertion_consumer_service_endpoints_for_saml_backend(backend_metadata[saml_backend_config["name"]],
                                                                          saml_backend_config)

    def test_saml_frontend_with_oidc_backend(self, satosa_config_dict, saml_frontend_config, oidc_backend_config):
        satosa_config_dict["FRONTEND_MODULES"] = [saml_frontend_config]
        satosa_config_dict["BACKEND_MODULES"] = [oidc_backend_config]
        satosa_config = SATOSAConfig(satosa_config_dict)
        frontend_metadata, backend_metadata = create_saml_metadata(satosa_config)

        assert len(frontend_metadata) == 1
        assert len(frontend_metadata[saml_frontend_config["name"]]) == 1
        entity_descriptor = frontend_metadata[saml_frontend_config["name"]][0]
        self.assert_single_sign_on_endpoints_for_saml_frontend(entity_descriptor, saml_frontend_config,
                                                               [oidc_backend_config["name"]])
        # OIDC backend does not produce any SAML metadata
        assert not backend_metadata

    def test_saml_frontend_with_multiple_backends(self, satosa_config_dict, saml_frontend_config, saml_backend_config,
                                                  oidc_backend_config):
        satosa_config_dict["FRONTEND_MODULES"] = [saml_frontend_config]
        satosa_config_dict["BACKEND_MODULES"] = [saml_backend_config, oidc_backend_config]
        satosa_config = SATOSAConfig(satosa_config_dict)
        frontend_metadata, backend_metadata = create_saml_metadata(satosa_config)

        assert len(frontend_metadata) == 1
        assert len(frontend_metadata[saml_frontend_config["name"]]) == 1
        entity_descriptor = frontend_metadata[saml_frontend_config["name"]][0]
        self.assert_single_sign_on_endpoints_for_saml_frontend(entity_descriptor, saml_frontend_config,
                                                               [saml_backend_config["name"],
                                                                oidc_backend_config["name"]])
        # only the SAML backend produces SAML metadata
        assert len(backend_metadata) == 1
        self.assert_assertion_consumer_service_endpoints_for_saml_backend(backend_metadata[saml_backend_config["name"]],
                                                                          saml_backend_config)

    def test_saml_mirror_frontend_with_saml_backend_with_multiple_target_providers(self, satosa_config_dict, idp_conf,
                                                                                   saml_mirror_frontend_config,
                                                                                   saml_backend_config):
        idp_conf2 = copy.deepcopy(idp_conf)
        idp_conf2["entityid"] = "https://idp2.example.com"
        satosa_config_dict["FRONTEND_MODULES"] = [saml_mirror_frontend_config]
        saml_backend_config["config"]["config"]["metadata"] = {"inline": [create_metadata_from_config_dict(idp_conf),
                                                                          create_metadata_from_config_dict(idp_conf2)]}
        satosa_config_dict["BACKEND_MODULES"] = [saml_backend_config]
        satosa_config = SATOSAConfig(satosa_config_dict)
        frontend_metadata, backend_metadata = create_saml_metadata(satosa_config)

        assert len(frontend_metadata) == 1
        assert len(frontend_metadata[saml_mirror_frontend_config["name"]]) == 2

        # TODO connect order of frontend_metadata[saml_mirror_frontend_config["name"]] with expected idp entity id's
        entity_descriptors = frontend_metadata[saml_mirror_frontend_config["name"]]
        for target_entity_id in [idp_conf["entityid"], idp_conf2["entityid"]]:
            encoded_target_entity_id = urlsafe_b64encode(target_entity_id.encode("utf-8")).decode("utf-8")
            self.assert_single_sign_on_endpoints_for_saml_mirror_frontend(entity_descriptors, encoded_target_entity_id,
                                                                          saml_mirror_frontend_config,
                                                                          [saml_backend_config["name"]])
        assert len(backend_metadata) == 1
        self.assert_assertion_consumer_service_endpoints_for_saml_backend(backend_metadata[saml_backend_config["name"]],
                                                                          saml_backend_config)

    def test_saml_mirror_frontend_with_oidc_backend(self, satosa_config_dict, saml_mirror_frontend_config,
                                                    oidc_backend_config):
        satosa_config_dict["FRONTEND_MODULES"] = [saml_mirror_frontend_config]
        satosa_config_dict["BACKEND_MODULES"] = [oidc_backend_config]
        satosa_config = SATOSAConfig(satosa_config_dict)
        frontend_metadata, backend_metadata = create_saml_metadata(satosa_config)

        assert len(frontend_metadata) == 1
        assert len(frontend_metadata[saml_mirror_frontend_config["name"]]) == 1
        entity_descriptors = frontend_metadata[saml_mirror_frontend_config["name"]]
        target_entity_id = oidc_backend_config["config"]["provider_metadata"]["issuer"]
        encoded_target_entity_id = urlsafe_b64encode(target_entity_id.encode("utf-8")).decode("utf-8")
        self.assert_single_sign_on_endpoints_for_saml_mirror_frontend(entity_descriptors, encoded_target_entity_id,
                                                                      saml_mirror_frontend_config,
                                                                      [oidc_backend_config["name"]])

        # OIDC backend does not produce any SAML metadata
        assert not backend_metadata

    def test_saml_mirror_frontend_with_multiple_backends(self, satosa_config_dict, idp_conf,
                                                         saml_mirror_frontend_config,
                                                         saml_backend_config, oidc_backend_config):
        satosa_config_dict["FRONTEND_MODULES"] = [saml_mirror_frontend_config]
        saml_backend_config["config"]["config"]["metadata"] = {"inline": [create_metadata_from_config_dict(idp_conf)]}
        satosa_config_dict["BACKEND_MODULES"] = [saml_backend_config, oidc_backend_config]
        satosa_config = SATOSAConfig(satosa_config_dict)
        frontend_metadata, backend_metadata = create_saml_metadata(satosa_config)

        assert len(frontend_metadata) == 1
        assert len(frontend_metadata[saml_mirror_frontend_config["name"]]) == 2
        params = zip([idp_conf["entityid"], oidc_backend_config["config"]["provider_metadata"]["issuer"]],
                     [saml_backend_config["name"], oidc_backend_config["name"]])
        entity_descriptors = frontend_metadata[saml_mirror_frontend_config["name"]]
        for target_entity_id, backend_name in params:
            encoded_target_entity_id = urlsafe_b64encode(target_entity_id.encode("utf-8")).decode("utf-8")
            self.assert_single_sign_on_endpoints_for_saml_mirror_frontend(entity_descriptors, encoded_target_entity_id,
                                                                          saml_mirror_frontend_config,
                                                                          [backend_name])

        # only the SAML backend produces SAML metadata
        assert len(backend_metadata)
        self.assert_assertion_consumer_service_endpoints_for_saml_backend(backend_metadata[saml_backend_config["name"]],
                                                                          saml_backend_config)

    def test_two_saml_frontends(self, satosa_config_dict, saml_frontend_config, saml_mirror_frontend_config,
                                oidc_backend_config):

        satosa_config_dict["FRONTEND_MODULES"] = [saml_frontend_config, saml_mirror_frontend_config]
        satosa_config_dict["BACKEND_MODULES"] = [oidc_backend_config]
        satosa_config = SATOSAConfig(satosa_config_dict)
        frontend_metadata, backend_metadata = create_saml_metadata(satosa_config)

        assert len(frontend_metadata) == 2

        saml_entities = frontend_metadata[saml_frontend_config["name"]]
        assert len(saml_entities) == 1
        entity_descriptor = saml_entities[0]
        self.assert_single_sign_on_endpoints_for_saml_frontend(entity_descriptor, saml_frontend_config,
                                                               [oidc_backend_config["name"]])

        mirrored_saml_entities = frontend_metadata[saml_mirror_frontend_config["name"]]
        assert len(mirrored_saml_entities) == 1
        target_entity_id = oidc_backend_config["config"]["provider_metadata"]["issuer"]
        encoded_target_entity_id = urlsafe_b64encode(target_entity_id.encode("utf-8")).decode("utf-8")
        self.assert_single_sign_on_endpoints_for_saml_mirror_frontend(mirrored_saml_entities, encoded_target_entity_id,
                                                                      saml_mirror_frontend_config,
                                                                      [oidc_backend_config["name"]])

        # OIDC backend does not produce any SAML metadata
        assert not backend_metadata


class TestSignSAMLMetadata:
    @pytest.fixture
    def saml_security_context(self, cert_and_key):
        conf = Config()
        conf.cert_file = cert_and_key[0]
        conf.key_file = cert_and_key[1]
        return security_context(conf)

    def test_sign_metadata(self, sp_conf, saml_security_context):
        ed = entity_descriptor(SPConfig().load(sp_conf, metadata_construction=True))
        signed_metadata = sign_entity_descriptors([ed], saml_security_context)

        md = InMemoryMetaData(None, security=saml_security_context)
        md.parse(signed_metadata)
        assert md.signed() is True
        assert md.parse_and_check_signature(signed_metadata) is True
        assert not md.entities_descr.valid_until

    def test_valid_for(self, sp_conf, saml_security_context):
        ed = entity_descriptor(SPConfig().load(sp_conf, metadata_construction=True))
        valid_for = 4  # metadata valid for 4 hours
        signed_metadata = sign_entity_descriptors([ed], saml_security_context, valid_for=valid_for)

        md = InMemoryMetaData(None, security=saml_security_context)
        md.parse(signed_metadata)
        assert md.signed() is True
        assert md.parse_and_check_signature(signed_metadata) is True
        assert md.entities_descr.valid_until == in_a_while(hours=valid_for)
