import os

import pytest
from saml2 import BINDING_HTTP_REDIRECT
from saml2.extension.idpdisc import BINDING_DISCO
from saml2.saml import NAME_FORMAT_URI, NAMEID_FORMAT_TRANSIENT, NAMEID_FORMAT_PERSISTENT

from satosa.context import Context
from satosa.state import State
from .util import generate_cert, write_cert


@pytest.fixture(scope="session")
def signing_key_path(tmpdir_factory):
    tmpdir = str(tmpdir_factory.getbasetemp())
    path = os.path.join(tmpdir, "sign_key.pem")
    _, private_key = generate_cert()

    with open(path, "wb") as f:
        f.write(private_key)

    return path


@pytest.fixture
def cert_and_key(tmpdir):
    dir_path = str(tmpdir)
    cert_path = os.path.join(dir_path, "cert.pem")
    key_path = os.path.join(dir_path, "key.pem")
    write_cert(cert_path, key_path)

    return cert_path, key_path


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
                "allow_unsolicited": "true",
                "name_id_format": [NAMEID_FORMAT_TRANSIENT]
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
            "name": [["SaToSa org.", "en"]],
            "display_name": [["SATOSA", "en"]],
            "url": [["https://satosa.example.com/about", "en"]]
        },
        "contact_person": [
            {"given_name": "Satosa", "sur_name": "Support", "email_address": ["help@example.com"],
             "contact_type": "support"
             },
            {"given_name": "Satosa", "sur_name": "Tech support",
             "email_address": ["tech@example.com"], "contact_type": "technical"}]
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
        "BASE": "https://example.com",
        "COOKIE_STATE_NAME": "TEST_STATE",
        "BACKEND_MODULES": ["foo"],
        "FRONTEND_MODULES": ["bar"],
        "INTERNAL_ATTRIBUTES": {"attributes": {}},
        "STATE_ENCRYPTION_KEY": "state_encryption_key",
        "USER_ID_HASH_SALT": "user_id_hash_salt",
        "CUSTOM_PLUGIN_MODULE_PATHS": [os.path.dirname(__file__)],
        "BACKEND_MODULES": [backend_plugin_config],
        "FRONTEND_MODULES": [frontend_plugin_config],
        "MICRO_SERVICES": [request_microservice_config, response_microservice_config],
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
        "conf": {"qwe": "rty"}
    }
    return data
