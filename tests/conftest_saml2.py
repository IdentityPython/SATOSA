import copy

import pytest
from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
from saml2.extension.idpdisc import BINDING_DISCO
from saml2.saml import NAME_FORMAT_URI, NAMEID_FORMAT_TRANSIENT

from .util import create_metadata_from_config_dict

BASE_URL = "https://test-proxy.com"


@pytest.fixture
def sp_conf(cert_and_key):
    sp_base = "http://example.com"
    spconfig = {
        "entityid": "{}/unittest_sp.xml".format(sp_base),
        "service": {
            "sp": {
                "endpoints": {
                    "assertion_consumer_service": [
                        ("%s/acs/redirect" % sp_base, BINDING_HTTP_REDIRECT)
                    ],
                    "discovery_response": [("%s/disco" % sp_base, BINDING_DISCO)]
                },
                "want_response_signed": False,
                "allow_unsolicited": True,
                "name_id_format": [NAMEID_FORMAT_PERSISTENT]
            },
        },
        "cert_file": cert_and_key[0],
        "key_file": cert_and_key[1],
        "metadata": {"inline": []},
    }

    return spconfig


@pytest.fixture
def idp_conf(cert_and_key):
    idp_base = "http://idp.example.com"

    idpconfig = {
        "entityid": "{}/{}/proxy.xml".format(idp_base, "Saml2IDP"),
        "description": "A SAML2SAML proxy",
        "service": {
            "idp": {
                "name": "Proxy IdP",
                "endpoints": {
                    "single_sign_on_service": [
                        ("%s/sso/redirect" % idp_base, BINDING_HTTP_REDIRECT),
                    ],
                },
                "policy": {
                    "default": {
                        "lifetime": {"minutes": 15},
                        "attribute_restrictions": None,  # means all I have
                        "name_form": NAME_FORMAT_URI,
                        "fail_on_missing_requested": False
                    },
                },
                "subject_data": {},
                "name_id_format": [NAMEID_FORMAT_TRANSIENT,
                                   NAMEID_FORMAT_PERSISTENT],
                "want_authn_requests_signed": False,
                "ui_info": {
                    "display_name": [{"text": "SATOSA Test IdP", "lang": "en"}],
                    "description": [{"text": "Test IdP for SATOSA unit tests.", "lang": "en"}],
                    "logo": [{"text": "https://idp.example.com/static/logo.png", "width": "120", "height": "60",
                              "lang": "en"}],
                },
            },
        },
        "cert_file": cert_and_key[0],
        "key_file": cert_and_key[1],
        "metadata": {"inline": []},
        "organization": {
            "name": [["Test IdP Org.", "en"]],
            "display_name": [["Test IdP", "en"]],
            "url": [["https://idp.example.com/about", "en"]]
        },
        "contact_person": [
            {"given_name": "Test IdP", "sur_name": "Support", "email_address": ["help@idp.example.com"],
             "contact_type": "support"
             },
            {"given_name": "Test IdP", "sur_name": "Tech support",
             "email_address": ["tech@idp.example.com"], "contact_type": "technical"}
        ]
    }

    return idpconfig


@pytest.fixture
def context():
    context = Context()
    context.state = State()
    return context


@pytest.fixture
def satosa_config_dict(backend_plugin_config, frontend_plugin_config, request_microservice_config,
                       response_microservice_config):
    config = {
        "BASE": BASE_URL,
        "COOKIE_STATE_NAME": "TEST_STATE",
        "INTERNAL_ATTRIBUTES": {"attributes": {}},
        "STATE_ENCRYPTION_KEY": "state_encryption_key",
        "CUSTOM_PLUGIN_MODULE_PATHS": [os.path.dirname(__file__)],
        "BACKEND_MODULES": [backend_plugin_config],
        "FRONTEND_MODULES": [frontend_plugin_config],
        "MICRO_SERVICES": [request_microservice_config, response_microservice_config],
        "LOGGING": {"version": 1}
    }
    return config


@pytest.fixture
def backend_plugin_config():
    data = {
        "module": "util.TestBackend",
        "name": "backend",
        "config": {"foo": "bar"}
    }
    return data


@pytest.fixture
def frontend_plugin_config():
    data = {
        "module": "util.TestFrontend",
        "name": "frontend",
        "config": {"abc": "xyz"}
    }
    return data


@pytest.fixture
def request_microservice_config():
    data = {
        "module": "util.TestRequestMicroservice",
        "name": "request-microservice",
    }
    return data


@pytest.fixture
def response_microservice_config():
    data = {
        "module": "util.TestResponseMicroservice",
        "name": "response-microservice",
        "config": {"qwe": "rty"}
    }
    return data


@pytest.fixture
def saml_frontend_config(cert_and_key, sp_conf):
    data = {
        "module": "satosa.frontends.saml2.SAMLFrontend",
        "name": "SAML2Frontend",
        "config": {
            "idp_config": {
                "entityid": "frontend-entity_id",
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
                "metadata": {"inline": [create_metadata_from_config_dict(sp_conf)]},
                "organization": {
                    "name": [["SATOSA Org.", "en"]],
                    "display_name": [["SATOSA", "en"]],
                    "url": [["https://satosa.example.com/about", "en"]]
                },
                "contact_person": [
                    {"given_name": "SATOSA", "sur_name": "Support",
                     "email_address": ["help@satosa.example.com"],
                     "contact_type": "support"
                     },
                    {"given_name": "SATOSA", "sur_name": "Tech Support",
                     "email_address": ["tech@satosa.example.com"],
                     "contact_type": "technical"
                     }
                ]
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
                "organization": {"display_name": "Example Identities",
                                 "name": "Test Identities Org.",
                                 "url": "http://www.example.com"},
                "contact_person": [
                    {"contact_type": "technical", "email_address": "technical@example.com",
                     "given_name": "Technical"},
                    {"contact_type": "support", "email_address": "support@example.com",
                     "given_name": "Support"}
                ],
                "service": {
                    "sp": {
                        "want_response_signed": False,
                        "allow_unsolicited": True,
                        "endpoints": {
                            "assertion_consumer_service": [
                                ("{}/{}/acs/redirect".format(BASE_URL, name),
                                 BINDING_HTTP_REDIRECT)],
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
