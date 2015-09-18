import os

import pytest
from werkzeug.utils import ArgumentValidationError
from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
from saml2.entity_category.edugain import COC
from saml2.entity_category.swamid import RESEARCH_AND_EDUCATION, HEI, \
    SFS_1993_1153, NREN, EU
from saml2.saml import NAME_FORMAT_URI
from saml2.saml import NAMEID_FORMAT_TRANSIENT
from saml2.saml import NAMEID_FORMAT_PERSISTENT

from satosa.frontends.saml2 import SamlFrontend


def auth_req_callback_func(context, _dict, state):
    pass


def full_path(local_file):
    basedir = os.path.abspath(os.path.dirname(__file__))
    return os.path.join(basedir, local_file)


XMLSEC_PATH = '/usr/local/bin/xmlsec1'
BASE = "http://test.tester.se"
MODULE = SamlFrontend
RECEIVER = "Saml2IDP"
ENDPOINTS = {"single_sign_on_service": {BINDING_HTTP_REDIRECT: "sso/redirect",
                                        BINDING_HTTP_POST: "sso/post"}}

IDPCONFIG = {
    "entityid": "%s/%s/proxy.xml" % (BASE, RECEIVER),
    "description": "A SAML2SAML proxy",
    "entity_category": [COC, RESEARCH_AND_EDUCATION, HEI, SFS_1993_1153, NREN,
                        EU],
    # "valid_for": 168,
    "service": {
        "idp": {
            "name": "Proxy IdP",
            "endpoints": {
                "single_sign_on_service": [
                    # The endpoints will be added later when registering endpoints in the
                    # module.
                ],
            },
            "policy": {
                "default": {
                    "lifetime": {"minutes": 15},
                    "attribute_restrictions": None,  # means all I have
                    "name_form": NAME_FORMAT_URI,
                    "entity_categories": ["edugain"],
                    "fail_on_missing_requested": False
                },
            },
            "subject_data": "./idp.subject",
            "name_id_format": [NAMEID_FORMAT_TRANSIENT,
                               NAMEID_FORMAT_PERSISTENT],
            "want_authn_requests_signed": False
        },
    },
    "debug": 1,
    "key_file": full_path("pki/new_server.key"),
    "cert_file": full_path("pki/new_server.crt"),
    "metadata": {
        "local": ["/Users/mathiashedstrom/work/DIRG/pysaml2/example/sp-wsgi/sp.xml"],
    },
    # This database holds the map between a subjects local identifier and
    # the identifier returned to a SP
    "xmlsec_binary": XMLSEC_PATH,
    "logger": {
        "rotating": {
            "filename": "idp.log",
            "maxBytes": 500000,
            "backupCount": 5,
        },
        "loglevel": "debug",
    }
}

CONFIG_ERR1 = {"idp_config_notok": IDPCONFIG, "endpoints": ENDPOINTS, "base": BASE, }

CONFIG_ERR2 = {"idp_config": IDPCONFIG, "endpoints_notok": ENDPOINTS, "base": BASE, }

CONFIG_ERR3 = {"idp_config": IDPCONFIG, "endpoints": ENDPOINTS, "base_notok": BASE, }

CONFIG = {"idp_config": IDPCONFIG, "endpoints": ENDPOINTS, "base": BASE}

TESTDATA_HANDLE_AUTHN_REQUEST = \
    [({"auth_req_callback_func": None, "conf": None, "error": ArgumentValidationError},
      None, None),
     ({"auth_req_callback_func": None, "conf": CONFIG_ERR1, "error": ArgumentValidationError},
      None, None),
     ({"auth_req_callback_func": None, "conf": CONFIG_ERR2, "error": ArgumentValidationError},
      None, None),
     ({"auth_req_callback_func": None, "conf": CONFIG_ERR3, "error": ArgumentValidationError},
      None, None),
     ({"auth_req_callback_func": None, "conf": CONFIG, "error": ArgumentValidationError},
      None, None),
     ({"auth_req_callback_func": auth_req_callback_func, "conf": CONFIG, "error": None},
      {"context": None, "binding_in": None, "error": ArgumentValidationError},
      {"providers": None, "error": ArgumentValidationError}),
     ({"auth_req_callback_func": auth_req_callback_func, "conf": CONFIG, "error": None},
      {"context": None, "binding_in": None, "error": ArgumentValidationError},
      {"providers": ["qwerty", "ytrewq"], "error": ArgumentValidationError})]


@pytest.mark.parametrize(
    "samlfrontend_params, handle_authn_request_params, register_endpoints_params",
    TESTDATA_HANDLE_AUTHN_REQUEST)
def test_handle_authn_request(samlfrontend_params, handle_authn_request_params,
                              register_endpoints_params):
    samlfrontend = None
    try:
        samlfrontend = SamlFrontend(samlfrontend_params["auth_req_callback_func"],
                                    samlfrontend_params["conf"])
    except samlfrontend_params["error"]:
        assert True
    assert samlfrontend_params["conf"] is not None, \
        "conf cannot be None. Argument validation missing."
    assert samlfrontend_params["auth_req_callback_func"] is not None, \
        "auth_req_callback_func cannot be None. Argument validation missing."
    try:
        samlfrontend.register_endpoints(register_endpoints_params["providers"])
    except register_endpoints_params["error"]:
        assert True
    try:
        samlfrontend.handle_authn_request(handle_authn_request_params["context"],
                                          handle_authn_request_params["binding_in"])
    except handle_authn_request_params["error"]:
        assert True
    assert True
