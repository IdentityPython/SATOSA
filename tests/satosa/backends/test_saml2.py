"""
Tests for the SAML frontend module src/backends/saml2.py.
"""
from urllib import parse
import re
import os.path

from saml2 import BINDING_HTTP_POST
from saml2.authn_context import PASSWORD
from saml2.config import IdPConfig
from saml2.entity_category.edugain import COC
from saml2.entity_category.swamid import RESEARCH_AND_EDUCATION, HEI, SFS_1993_1153, NREN, EU

from saml2.extension.idpdisc import BINDING_DISCO

from saml2.saml import NAME_FORMAT_URI, NAMEID_FORMAT_TRANSIENT, NAMEID_FORMAT_PERSISTENT

from satosa.backends.saml2 import SamlBackend
from satosa.context import Context
from satosa.internal_data import UserIdHashType, InternalRequest
from satosa.state import State
from tests.users import USERS
from tests.util import FileGenerator, FakeIdP

__author__ = 'haho0032'

INTERNAL_ATTRIBUTES = {
    'attributes': {'displayname': {'openid': ['nickname'], 'saml': ['displayName']},
                   'givenname': {'saml': ['givenName'], 'openid': ['given_name'],
                                 'facebook': ['first_name']},
                   'mail': {'saml': ['email', 'emailAdress', 'mail'], 'openid': ['email'],
                            'facebook': ['email']},
                   'edupersontargetedid': {'saml': ['eduPersonTargetedID'], 'openid': ['sub'],
                                           'facebook': ['id']},
                   'name': {'saml': ['cn'], 'openid': ['name'], 'facebook': ['name']},
                   'address': {'openid': ['address->street_address'], 'saml': ['postaladdress']},
                   'surname': {'saml': ['sn', 'surname'], 'openid': ['family_name'],
                               'facebook': ['last_name']}}, 'separator': '->'}


class TestConfiguration(object):
    """
    Testdata.

    The IdP and SP configuration is relying on endpoints with POST to simply the testing.
    """
    _instance = None

    def __init__(self):
        idp_cert_file, idp_key_file = FileGenerator.get_instance().generate_cert("idp")
        if os.path.isfile("/usr/bin/xmlsec1"):
            xmlsec_path = "/usr/bin/xmlsec1"
        elif os.path.isfile("/usr/local/bin/xmlsec1"):
            xmlsec_path = "/usr/local/bin/xmlsec1"
        idp_base = "http://test.tester.se"

        self.idpconfig = {
            "entityid": "%s/%s/proxy.xml" % (idp_base, "Saml2IDP"),
            "description": "A SAML2SAML proxy",
            "entity_category": [COC, RESEARCH_AND_EDUCATION, HEI, SFS_1993_1153, NREN,
                                EU],
            "valid_for": 0,
            "service": {
                "idp": {
                    "name": "Proxy IdP",
                    "endpoints": {
                        "single_sign_on_service": [
                            ("%s/sso/post" % idp_base, BINDING_HTTP_POST),
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
            "key_file": idp_key_file.name,
            "cert_file": idp_cert_file.name,
            "metadata": {
                "local": []
            },
            "xmlsec_binary": xmlsec_path,
        }

        sp_cert_file, sp_key_file = FileGenerator.get_instance().generate_cert("sp")
        self.sp_base = "http://example.com"
        self.spconfig = {
            "config": {
                "entityid": "{}/unittest_sp.xml".format(self.sp_base),
                "service": {
                    "sp": {
                        "endpoints": {
                            "assertion_consumer_service": [
                                ("%s/acs/post" % self.sp_base, BINDING_HTTP_POST)
                            ],
                            "discovery_response": [("%s/disco" % self.sp_base, BINDING_DISCO)]
                        },
                        "allow_unsolicited": "true",
                    },
                },
                "key_file": sp_key_file.name,
                "cert_file": sp_cert_file.name,
                "metadata": {
                    "local": []
                },
                "xmlsec_binary": xmlsec_path,
            },
            "encryption_key": "asduy234879dyisahkd2",
            "disco_srv": "https://my.dicso.com/role/idp.ds",
        }
        sp_metadata = FileGenerator.get_instance().create_metadata(self.spconfig["config"],
                                                                   "sp_metadata")
        idp_metadata = FileGenerator.get_instance().create_metadata(self.idpconfig, "idp_metadata")
        self.spconfig["config"]["metadata"]["local"].append(idp_metadata.name)
        self.idpconfig["metadata"]["local"].append(sp_metadata.name)

    @staticmethod
    def get_instance():
        """
        Returns an instance of the singleton class.
        """
        if not TestConfiguration._instance:
            TestConfiguration._instance = TestConfiguration()
        return TestConfiguration._instance


def test_register_endpoints():
    """
    Tests the method register_endpoints
    """
    samlbackend = SamlBackend(
        None,
        INTERNAL_ATTRIBUTES,
        TestConfiguration.get_instance().spconfig)
    url_map = samlbackend.register_endpoints()
    for k, v in TestConfiguration.get_instance().spconfig["config"]["service"]["sp"][
        "endpoints"].items():
        for e in v:
            match = False
            for regex in url_map:
                p = re.compile(regex[0])
                if p.match(e[0].replace(TestConfiguration.get_instance().sp_base + "/", "")):
                    match = True
                    break
            assert match, "Not correct regular expression for endpoint: %s" % e[0]


def test_start_auth_no_request_info():
    """
    Performs a complete test for the module satosa.backends.saml2. The flow should be accepted.
    """
    samlbackend = SamlBackend(
        None,
        INTERNAL_ATTRIBUTES,
        TestConfiguration.get_instance().spconfig)

    internal_data = InternalRequest(None, None)

    state = State()
    context = Context()
    context.state = state
    resp = samlbackend.start_auth(context, internal_data)
    assert resp.status == "303 See Other", "Must be a redirect to the discovery server."
    assert resp.message.startswith(TestConfiguration.get_instance().spconfig["disco_srv"]), \
        "Redirect to wrong URL."

    # create_name_id_policy_transient()
    state = State()
    context = Context()
    context.state = state
    user_id_hash_type = UserIdHashType.transient
    internal_data = InternalRequest(user_id_hash_type, None)
    resp = samlbackend.start_auth(context, internal_data)
    assert resp.status == "303 See Other", "Must be a redirect to the discovery server."


def test_start_auth_name_id_policy():
    """
    Performs a complete test for the module satosa.backends.saml2. The flow should be accepted.
    """
    samlbackend = SamlBackend(
        None,
        INTERNAL_ATTRIBUTES,
        TestConfiguration.get_instance().spconfig)

    test_state_key = "sauyghj34589fdh"

    state = State()
    state.add(test_state_key, "my_state")
    context = Context()
    context.state = state

    internal_req = InternalRequest(UserIdHashType.transient, None)
    resp = samlbackend.start_auth(context, internal_req)

    assert resp.status == "303 See Other", "Must be a redirect to the discovery server."

    disco_resp = parse.parse_qs(resp.message.replace(
        TestConfiguration.get_instance().spconfig["disco_srv"] + "?", ""))
    sp_config = TestConfiguration.get_instance().spconfig["config"]
    sp_disco_resp = sp_config["service"]["sp"]["endpoints"]["discovery_response"][0][0]
    assert "return" in disco_resp and disco_resp["return"][0].startswith(sp_disco_resp), \
        "Not a valid return url in the call to the discovery server"
    assert "entityID" in disco_resp and disco_resp["entityID"][0] == sp_config["entityid"], \
        "Not a valid entity id in the call to the discovery server"

    request_info_tmp = context.state
    assert request_info_tmp.get(test_state_key) == "my_state", "Wrong state!"


def test_start_auth_disco():
    """
    Performs a complete test for the module satosa.backends.saml2. The flow should be accepted.
    """
    test_state_key = "test_state_key_456afgrh"
    spconfig = TestConfiguration.get_instance().spconfig
    idpconfig = TestConfiguration.get_instance().idpconfig
    fakeidp = FakeIdP(USERS, config=IdPConfig().load(
        TestConfiguration.get_instance().idpconfig,
        metadata_construction=False))

    def auth_req_callback_func(context, internal_resp):
        """
        Callback function.
        :type context:
        :type: internal_resp: satosa.internal_data.InternalResponse
        :type: state: str

        :param context: Contains the request context from the module.
        :param internal_resp:
        :param state: The current state for the module.
        :return:
        """
        assert isinstance(context, Context), "Not correct instance!"
        assert context.state.get(test_state_key) == "my_state", "Not correct state!"
        assert internal_resp.auth_info.auth_class_ref == PASSWORD, "Not correct authentication!"
        _dict = internal_resp._attributes
        verify_dict = {'surname': ['Testsson 1'], 'mail': ['test@example.com'],
                       'displayname': ['Test Testsson'], 'givenname': ['Test 1'],
                       'edupersontargetedid': ['one!for!all']}
        for key in _dict:
            assert verify_dict[key] == _dict[key]

    samlbackend = SamlBackend(
        auth_req_callback_func,
        INTERNAL_ATTRIBUTES,
        spconfig)

    internal_req = InternalRequest(UserIdHashType.persistent, "example.se/sp.xml")

    state = State()
    state.add(test_state_key, "my_state")
    context = Context()
    context.state = state

    resp = samlbackend.start_auth(context, internal_req)
    assert resp.status == "303 See Other", "Must be a redirect to the discovery server."

    sp_disco_resp = spconfig["config"]["service"]["sp"]["endpoints"]["discovery_response"][0][0]
    disco_resp = parse.parse_qs(resp.message.replace(spconfig["disco_srv"] + "?", ""))
    info = parse.parse_qs(disco_resp["return"][0].replace(sp_disco_resp + "?", ""))
    info[samlbackend.idp_disco_query_param] = idpconfig["entityid"]
    context = Context()
    context.request = info
    context.state = state
    resp = samlbackend.disco_response(context)
    assert resp.status == "200 OK", "A post must be 200 OK."
    sp_url, req_params = fakeidp.get_post_action_body(resp.message)
    url, fake_idp_resp = fakeidp.handle_auth_req(
        req_params["SAMLRequest"],
        req_params["RelayState"],
        BINDING_HTTP_POST,
        "testuser1")
    context = Context()
    context.request = fake_idp_resp
    context.state = state
    samlbackend.authn_response(context, BINDING_HTTP_POST)
