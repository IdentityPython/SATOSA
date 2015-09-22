"""
Tests for the SAML frontend module src/frontends/saml2.py.
"""
import re
import pytest
from urllib import parse
from saml2.authn_context import PASSWORD
from saml2.config import SPConfig
from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
from saml2.entity_category.edugain import COC
from saml2.entity_category.swamid import RESEARCH_AND_EDUCATION, HEI, \
    SFS_1993_1153, NREN, EU
from saml2.saml import NAME_FORMAT_URI, NAMEID_FORMAT_PERSISTENT
from saml2.saml import NAMEID_FORMAT_TRANSIENT
from satosa.frontends.saml2 import SamlFrontend
from satosa.request_context import RequestContext
from tests.test_users import USERS
from tests.test_util import FakeSP, create_metadata, generate_cert, create_name_id

IDP_CERT_FILE, IDP_KEY_FILE = generate_cert()
XMLSEC_PATH = '/usr/local/bin/xmlsec1'
IDP_BASE = "http://test.tester.se"
RECEIVER = "Saml2IDP"
ENDPOINTS = {"single_sign_on_service": {BINDING_HTTP_REDIRECT: "sso/redirect",
                                        BINDING_HTTP_POST: "sso/post"}}
IDPCONFIG = {
    "entityid": "%s/%s/proxy.xml" % (IDP_BASE, RECEIVER),
    "description": "A SAML2SAML proxy",
    "entity_category": [COC, RESEARCH_AND_EDUCATION, HEI, SFS_1993_1153, NREN,
                        EU],
    "valid_for": 0,
    "service": {
        "idp": {
            "name": "Proxy IdP",
            "endpoints": {
                "single_sign_on_service": [
                    ("%s/sso/post" % IDP_BASE, BINDING_HTTP_POST),
                    ("%s/sso/redirect" % IDP_BASE, BINDING_HTTP_REDIRECT)
                ],
            },
            "policy": {
                "default": {
                    "lifetime": {"minutes": 15},
                    "attribute_restrictions": None,  # means all I have
                    "name_form": NAME_FORMAT_URI,
                    # "entity_categories": ["edugain"],
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
    "key_file": IDP_KEY_FILE.name,
    "cert_file": IDP_CERT_FILE.name,
    "metadata": {
    },
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

SP_CERT_FILE, SP_KEY_FILE = generate_cert()
SP_BASE = "http://example.com"
SPCONFIG = {
    "entityid": "{}/unittest_sp.xml".format(SP_BASE),
    "service": {
        "sp": {
            "endpoints": {
                "assertion_consumer_service": [
                    ("%s/acs/redirect" % SP_BASE, BINDING_HTTP_REDIRECT),
                    ("%s/acs/post" % SP_BASE, BINDING_HTTP_POST)
                ],
            },
            "allow_unsolicited": "true",
        },
    },
    "key_file": SP_KEY_FILE.name,
    "cert_file": SP_CERT_FILE.name,
    "metadata": {
    },
    "xmlsec_binary": XMLSEC_PATH,
}
CONFIG_ERR1 = {"idp_config_notok": IDPCONFIG, "endpoints": ENDPOINTS, "base": IDP_BASE, }
CONFIG_ERR2 = {"idp_config": IDPCONFIG, "endpoints_notok": ENDPOINTS, "base": IDP_BASE, }
CONFIG_ERR3 = {"idp_config": IDPCONFIG, "endpoints": ENDPOINTS, "base_notok": IDP_BASE, }
CONFIG = {"idp_config": IDPCONFIG, "endpoints": ENDPOINTS, "base": IDP_BASE}

TESTDATA_HANDLE_AUTHN_REQUEST = \
    [  # (None, None, None, ArgumentValidationError),
       # (CONFIG_ERR1, None, None, ArgumentValidationError),
       # (CONFIG_ERR2, None, None, ArgumentValidationError),
       # (CONFIG_ERR3, None, None, ArgumentValidationError),
       # (CONFIG, None, None, ArgumentValidationError),
       # (CONFIG, "whatever", None, ArgumentValidationError),
       (CONFIG, "redirect", ["qwerty", "ytrewq"], None)]


@pytest.mark.parametrize("conf, binding_in, providers, error", TESTDATA_HANDLE_AUTHN_REQUEST)
def test_handle_authn_request(conf, binding_in, providers, error):
    """
    Performs a complete test for the module. The flow should be accepted.
    :param conf:
    :param binding_in:
    :param providers:
    :param error:
    :return:
    """
    samlfrontend = None
    fakesp = None
    try:
        def auth_req_callback_func(context, _dict, state):
            internal_response = {}
            internal_response["ava"] = USERS["testuser1"]
            internal_response["name_id"] = create_name_id()
            internal_response["auth_info"] = {"class_ref": PASSWORD,
                                              "authn_auth": "http://www.example.com/login"}
            resp = samlfrontend.handle_authn_response(context, internal_response, state)
            resp_dict = parse.parse_qs(resp.message.split("?")[1])
            resp = fakesp.parse_authn_request_response(resp_dict['SAMLResponse'][0],
                                                       BINDING_HTTP_REDIRECT)
            for key in resp.ava:
                assert key in resp.ava
                assert USERS["testuser1"][key] == resp.ava[key]

        samlfrontend = SamlFrontend(auth_req_callback_func, conf)
    except Exception as exception:
        if error is None or not isinstance(exception, error):
            raise exception
    assert conf is not None, \
        "conf cannot be None. Argument validation missing."
    try:
        sp_metadata_file = create_metadata(SPCONFIG)
        IDPCONFIG["metadata"]["local"] = [sp_metadata_file.name]
        url_map = samlfrontend.register_endpoints(providers)
        for regex in url_map:
            p = re.compile(regex[0])
            match = False
            for provider in providers:
                for s_key in conf["endpoints"]:
                    for b_key in conf["endpoints"][s_key]:
                        if p.match(provider + "/" + conf["endpoints"][s_key][b_key]):
                            match = True
                            break
            assert match, "All regular expressions must match!"
    except Exception as exception:
        if error is None or not isinstance(exception, error):
            raise exception
    try:
        idp_metadata_file = create_metadata(samlfrontend.config)
        SPCONFIG["metadata"]["local"] = [idp_metadata_file.name]
        fakesp = FakeSP(None, config=SPConfig().load(SPCONFIG, metadata_construction=False))
        context = RequestContext()
        context.request = parse.parse_qs(
            fakesp.make_auth_req(samlfrontend.config["entityid"]).split("?")[1])
        tmp_dict = {}
        for val in context.request:
            if isinstance(context.request[val], list):
                tmp_dict[val] = context.request[val][0]
            else:
                tmp_dict[val] = context.request[val]
        context.request = tmp_dict
        samlfrontend.handle_authn_request(context, binding_in)
    except Exception as exception:
        if error is None or not isinstance(exception, error):
            raise exception
    assert True
