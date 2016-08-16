import copy

import pytest
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.extension.idpdisc import BINDING_DISCO
from saml2.saml import NAMEID_FORMAT_TRANSIENT, NAME_FORMAT_URI

from tests.util import create_metadata_from_config_dict

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
