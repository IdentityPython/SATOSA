import copy
from urllib.parse import parse_qsl, urlparse, urlencode

import pytest
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.config import SPConfig, IdPConfig
from saml2.extension.idpdisc import BINDING_DISCO
from saml2.saml import NAMEID_FORMAT_TRANSIENT, NAME_FORMAT_URI
from werkzeug.test import Client
from werkzeug.wrappers import BaseResponse

from satosa.metadata_creation.saml_metadata import create_entity_descriptors
from satosa.proxy_server import WsgiApplication
from satosa.satosa_config import SATOSAConfig
from tests.users import USERS
from tests.util import FakeSP, FakeIdP, create_metadata_from_config_dict

BASE_URL = "https://test-proxy.com"


@pytest.fixture
def saml_frontend_config(cert_and_key, sp_conf):
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
                        }
                    }
                },
                "cert_file": cert_and_key[0],
                "key_file": cert_and_key[1],
                "metadata": {"inline": [create_metadata_from_config_dict(sp_conf)]}
            },

            "endpoints": {
                "single_sign_on_service": {BINDING_HTTP_POST: "sso/post",
                                           BINDING_HTTP_REDIRECT: "sso/redirect"}
            }
        }
    }

    return data


@pytest.fixture
def saml_backend_config(idp_conf):
    name = "SAML2Backend"
    data = {
        "module": "satosa.backends.saml2.SAMLBackend",
        "name": name,
        "config": {
            "sp_config": {
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
                                ("{}/{}/acs/redirect".format(BASE_URL, name), BINDING_HTTP_REDIRECT)],
                            "discovery_response": [("{}/disco", BINDING_DISCO)]

                        }
                    }
                },
                "metadata": {"inline": [create_metadata_from_config_dict(idp_conf)]}
            }
        }
    }
    return data


@pytest.fixture
def saml_mirror_frontend_config(saml_frontend_config):
    data = copy.deepcopy(saml_frontend_config)
    data["module"] = "satosa.frontends.saml2.SAMLMirrorFrontend"
    data["name"] = "SAMLMirrorFrontend"
    return data


class TestSAMLToSAML:
    def run_test(self, satosa_config_dict, sp_conf, idp_conf, saml_backend_config, frontend_config):
        user_id = "testuser1"
        # proxy config
        satosa_config_dict["FRONTEND_MODULES"] = [frontend_config]
        satosa_config_dict["BACKEND_MODULES"] = [saml_backend_config]
        satosa_config_dict["INTERNAL_ATTRIBUTES"]["attributes"] = {attr_name: {"saml": [attr_name]} for attr_name in
                                                                   USERS[user_id]}
        frontend_metadata, backend_metadata = create_entity_descriptors(SATOSAConfig(satosa_config_dict))

        # application
        app = WsgiApplication(config=SATOSAConfig(satosa_config_dict))
        test_client = Client(app, BaseResponse)

        # test SP config
        frontend_metadata_str = str(frontend_metadata[frontend_config["name"]][0])
        sp_conf["metadata"]["inline"].append(frontend_metadata_str)
        fakesp = FakeSP(SPConfig().load(sp_conf, metadata_construction=False))

        # create auth req
        req = urlparse(fakesp.make_auth_req(frontend_metadata[frontend_config["name"]][0].entity_id))
        auth_req = req.path + "?" + req.query

        # make auth req to proxy
        proxied_auth_req = test_client.get(auth_req)
        assert proxied_auth_req.status == "303 See Other"

        # test IdP config
        backend_metadata_str = str(backend_metadata[saml_backend_config["name"]][0])
        idp_conf["metadata"]["inline"].append(backend_metadata_str)
        fakeidp = FakeIdP(USERS, config=IdPConfig().load(idp_conf, metadata_construction=False))

        # create auth resp
        req_params = dict(parse_qsl(urlparse(proxied_auth_req.data.decode("utf-8")).query))
        url, authn_resp = fakeidp.handle_auth_req(
            req_params["SAMLRequest"],
            req_params["RelayState"],
            BINDING_HTTP_REDIRECT,
            user_id,
            response_binding=BINDING_HTTP_REDIRECT)

        # make auth resp to proxy
        authn_resp_req = urlparse(url).path + "?" + urlencode(authn_resp)
        authn_resp = test_client.get("/" + authn_resp_req)
        assert authn_resp.status == "303 See Other"

        # verify auth resp from proxy
        resp_dict = dict(parse_qsl(urlparse(authn_resp.data.decode("utf-8")).query))
        auth_resp = fakesp.parse_authn_request_response(resp_dict["SAMLResponse"], BINDING_HTTP_REDIRECT)
        assert auth_resp.ava == USERS[user_id]

    def test_full_flow(self, satosa_config_dict, sp_conf, idp_conf, saml_backend_config,
                       saml_frontend_config, saml_mirror_frontend_config):
        for conf in [saml_frontend_config, saml_mirror_frontend_config]:
            self.run_test(satosa_config_dict, sp_conf, idp_conf, saml_backend_config, conf)
