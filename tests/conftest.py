import os

import pytest
from saml2 import BINDING_HTTP_REDIRECT
from saml2.extension.idpdisc import BINDING_DISCO
from saml2.saml import NAME_FORMAT_URI, NAMEID_FORMAT_TRANSIENT, NAMEID_FORMAT_PERSISTENT

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
                "want_authn_requests_signed": False
            },
        },
        "cert_file": cert[0],
        "key_file": cert[1],
        "metadata": {"inline": []}
    }

    return idpconfig
