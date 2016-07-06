import os

import pytest
import yaml
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
def cert(tmpdir):
    dir_path = str(tmpdir)
    cert_path = os.path.join(dir_path, "cert.pem")
    key_path = os.path.join(dir_path, "key.pem")
    write_cert(cert_path, key_path)

    return cert_path, key_path


@pytest.fixture
def sp_conf(cert):
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
        "cert_file": cert[0],
        "key_file": cert[1],
        "metadata": {"inline": []},
    }

    return spconfig


@pytest.fixture
def idp_conf(cert):
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
        "cert_file": cert[0],
        "key_file": cert[1],
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


@pytest.fixture(scope="session")
def plugin_directory(tmpdir_factory):
    return str(tmpdir_factory.mktemp("plugins"))


@pytest.fixture(scope="session")
def backend_plugin_config(plugin_directory):
    data = {
        "module": "util.TestBackend",
        "name": "backend",
        "config": {"foo": "bar"}
    }

    backend_file = os.path.join(plugin_directory, "backend_conf.yaml")
    with open(backend_file, "w") as f:
        yaml.dump(data, f)
    return backend_file


@pytest.fixture(scope="session")
def frontend_plugin_config(plugin_directory):
    data = {
        "module": "util.TestFrontend",
        "name": "frontend",
        "config": {"abc": "xyz"}
    }

    frontend_filename = os.path.join(plugin_directory, "frontend_conf.yaml")
    with open(frontend_filename, "w") as f:
        yaml.dump(data, f)
    return frontend_filename


@pytest.fixture(scope="session")
def request_microservice_config(plugin_directory):
    data = {
        "module": "util.TestRequestMicroservice",
        "name": "request-microservice",
    }

    request_file = os.path.join(plugin_directory, "request_conf.yaml")
    with open(request_file, "w") as f:
        yaml.dump(data, f)
    return request_file


@pytest.fixture(scope="session")
def response_microservice_config(plugin_directory):
    data = {
        "module": "util.TestResponseMicroservice",
        "name": "response-microservice",
        "conf": {"qwe": "rty"}
    }

    response_file = os.path.join(plugin_directory, "response_conf.yaml")
    with open(response_file, "w") as f:
        yaml.dump(data, f)
    return response_file
