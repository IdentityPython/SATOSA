"""
Tests for the SAML frontend module src/frontends/saml2.py.
"""
import os.path
import re
from urllib import parse
from urllib.parse import urlparse

import pytest
from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
from saml2.authn_context import PASSWORD
from saml2.config import SPConfig
from saml2.entity_category.edugain import COC
from saml2.entity_category.swamid import RESEARCH_AND_EDUCATION, HEI, \
    SFS_1993_1153, NREN, EU
from saml2.saml import NAMEID_FORMAT_TRANSIENT
from saml2.saml import NAME_FORMAT_URI, NAMEID_FORMAT_PERSISTENT

from satosa.context import Context
from satosa.frontends.saml2 import SamlFrontend
from satosa.internal_data import InternalResponse, AuthenticationInformation, InternalRequest
from satosa.state import State
from satosa.util import saml_name_format_to_hash_type
from tests.users import USERS
from tests.util import FakeSP, FileGenerator, create_metadata_from_config_dict

INTERNAL_ATTRIBUTES = {
    'attributes': {'displayname': {'openid': ['nickname'], 'saml': ['displayName']},
                   'givenname': {'saml': ['givenName'], 'openid': ['given_name'],
                                 'facebook': ['first_name']},
                   'mail': {'saml': ['email', 'emailAdress', 'mail'], 'openid': ['email'],
                            'facebook': ['email']},
                   'edupersontargetedid': {'saml': ['eduPersonTargetedID'], 'openid': ['sub'],
                                           'facebook': ['id']},
                   'name': {'saml': ['cn'], 'openid': ['name'], 'facebook': ['name']},
                   'surname': {'saml': ['sn', 'surname'], 'openid': ['family_name'],
                               'facebook': ['last_name']}}}

IDP_CERT_FILE, IDP_KEY_FILE = FileGenerator.get_instance().generate_cert()

if os.path.isfile("/usr/bin/xmlsec1"):
    XMLSEC_PATH = "/usr/bin/xmlsec1"
elif os.path.isfile("/usr/local/bin/xmlsec1"):
    XMLSEC_PATH = "/usr/local/bin/xmlsec1"

IDP_STATE_ID = "frontend_id"
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
            "subject_data": {},
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
}

SP_CERT_FILE, SP_KEY_FILE = FileGenerator.get_instance().generate_cert()
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


@pytest.mark.parametrize("conf", [
    None,
    {"idp_config_notok": IDPCONFIG, "endpoints": ENDPOINTS, "base": IDP_BASE,
     "state_id": IDP_STATE_ID},
    {"idp_config": IDPCONFIG, "endpoints_notok": ENDPOINTS, "base": IDP_BASE,
     "state_id": IDP_STATE_ID},
    {"idp_config": IDPCONFIG, "endpoints": ENDPOINTS, "base_notok": IDP_BASE,
     "state_id": IDP_STATE_ID}
])
def test_config_error_handling(conf):
    with pytest.raises(AssertionError):
        SamlFrontend(lambda ctx, req: None, INTERNAL_ATTRIBUTES, conf)


def test_handle_authn_request():
    """
    Performs a complete test for the module. The flow should be accepted.
    """

    CONFIG = {"idp_config": IDPCONFIG, "endpoints": ENDPOINTS, "base": IDP_BASE,
              "state_id": IDP_STATE_ID}
    providers = ["foo", "bar"]

    samlfrontend = SamlFrontend(lambda context, internal_req: (context, internal_req),
                                INTERNAL_ATTRIBUTES, CONFIG)

    sp_metadata_file = FileGenerator.get_instance().create_metadata(SPCONFIG)
    IDPCONFIG["metadata"]["local"] = [sp_metadata_file.name]
    url_map = samlfrontend.register_endpoints(providers)
    for regex in url_map:
        p = re.compile(regex[0])
        match = False
        for provider in providers:
            for s_key in CONFIG["endpoints"]:
                for b_key in CONFIG["endpoints"][s_key]:
                    if p.match(provider + "/" + CONFIG["endpoints"][s_key][b_key]) or \
                            p.match(provider + "/" + CONFIG["endpoints"][s_key][b_key] + "/test"):
                        match = True
                        break
        assert match, "All regular expressions must match!"

    idp_metadata_file = FileGenerator.get_instance().create_metadata(samlfrontend.config)
    SPCONFIG["metadata"]["local"] = [idp_metadata_file.name]
    fakesp = FakeSP(None, config=SPConfig().load(SPCONFIG, metadata_construction=False))
    context = Context()
    context.state = State()
    context.request = parse.parse_qs(
            urlparse(fakesp.make_auth_req(samlfrontend.config["entityid"])).query)
    tmp_dict = {}
    for val in context.request:
        if isinstance(context.request[val], list):
            tmp_dict[val] = context.request[val][0]
        else:
            tmp_dict[val] = context.request[val]
    context.request = tmp_dict

    _, internal_req = samlfrontend.handle_authn_request(context, BINDING_HTTP_REDIRECT)
    assert internal_req.requestor == SPCONFIG["entityid"]

    auth_info = AuthenticationInformation(PASSWORD, "2015-09-30T12:21:37Z", "unittest_idp.xml")
    internal_response = InternalResponse(auth_info=auth_info)
    internal_response.set_user_id_hash_type(internal_req.user_id_hash_type)
    internal_response.add_attributes(USERS["testuser1"])

    resp = samlfrontend.handle_authn_response(context, internal_response)
    resp_dict = parse.parse_qs(urlparse(resp.message).query)
    resp = fakesp.parse_authn_request_response(resp_dict['SAMLResponse'][0],
                                               BINDING_HTTP_REDIRECT)
    for key in resp.ava:
        assert USERS["testuser1"][key] == resp.ava[key]


def test_get_filter_attributes_with_sp_requested_attributes_without_friendlyname():
    idp_config = IDPCONFIG.copy()
    sp_metadata_str = """<?xml version="1.0"?>
    <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://sp.example.com">
      <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:1.1:protocol urn:oasis:names:tc:SAML:2.0:protocol">
        <md:AttributeConsumingService>
          <md:RequestedAttribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.10" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
          <md:RequestedAttribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
          <md:RequestedAttribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"/>
          <md:RequestedAttribute Name="urn:oid:0.9.2342.19200300.100.1.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
          <md:RequestedAttribute Name="urn:oid:2.16.840.1.113730.3.1.241" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"/>
          <md:RequestedAttribute Name="urn:oid:2.5.4.4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"/>
          <md:RequestedAttribute Name="urn:oid:2.5.4.42" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"/>
        </md:AttributeConsumingService>
      </md:SPSSODescriptor>
    </md:EntityDescriptor>
    """

    idp_config["metadata"] = {"inline": [sp_metadata_str]}

    conf = {"idp_config": idp_config, "endpoints": ENDPOINTS, "base": IDP_BASE,
            "state_id": IDP_STATE_ID}

    internal_attributes = {"attributes": {attr_name: {"saml": [attr_name]} for attr_name in
                                          ["edupersontargetedid", "edupersonprincipalname",
                                           "edupersonaffiliation", "mail", "displayname", "sn",
                                           "givenname"]}}  # no op mapping for saml attribute names

    samlfrontend = SamlFrontend(None, internal_attributes, conf)
    samlfrontend.register_endpoints(["testprovider"])

    internal_req = InternalRequest(saml_name_format_to_hash_type(NAMEID_FORMAT_PERSISTENT),
                                   "http://sp.example.com",
                                   "Example SP")
    filtered_attributes = samlfrontend.get_filter_attributes(samlfrontend.idp,
                                                             samlfrontend.idp.config.getattr(
                                                                     "policy", "idp"),
                                                             internal_req.requestor, None)

    assert set(filtered_attributes) == set(
            ["edupersontargetedid", "edupersonprincipalname", "edupersonaffiliation", "mail",
             "displayname", "sn", "givenname"])
