"""
Tests for the SAML frontend module src/backends/saml2.py.
"""
import os.path
import re
from urllib.parse import urlparse, parse_qs, parse_qsl

import pytest
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.authn_context import PASSWORD
from saml2.config import IdPConfig
from saml2.extension.idpdisc import BINDING_DISCO
from saml2.saml import NAME_FORMAT_URI, NAMEID_FORMAT_TRANSIENT, NAMEID_FORMAT_PERSISTENT

from satosa.backends.saml2 import SamlBackend
from satosa.context import Context
from satosa.internal_data import UserIdHashType, InternalRequest
from satosa.state import State
from tests.users import USERS
from tests.util import FakeIdP, generate_cert, create_metadata_from_config_dict

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
                   'surname': {'saml': ['sn', 'surname'], 'openid': ['family_name'],
                               'facebook': ['last_name']}}}


def write_cert(cert_path, key_path):
    cert, key = generate_cert()
    with open(cert_path, "wb") as cert_file:
        cert_file.write(cert)
    with open(key_path, "wb") as key_file:
        key_file.write(key)


@pytest.fixture(scope="session")
def sp_conf(tmpdir_factory):
    tmpdir = str(tmpdir_factory.getbasetemp())
    sp_cert_path = os.path.join(tmpdir, "sp_cert.pem")
    sp_key_path = os.path.join(tmpdir, "sp_key.pem")
    write_cert(sp_cert_path, sp_key_path)

    sp_base = "http://example.com"
    spconfig = {
        "config": {
            "entityid": "{}/unittest_sp.xml".format(sp_base),
            "service": {
                "sp": {
                    "endpoints": {
                        "assertion_consumer_service": [
                            ("%s/acs/post" % sp_base, BINDING_HTTP_POST)
                        ],
                        "discovery_response": [("%s/disco" % sp_base, BINDING_DISCO)]
                    },
                    "allow_unsolicited": "true",
                },
            },
            "key_file": sp_key_path,
            "cert_file": sp_cert_path,
            "metadata": {"inline": []},
        },
        "disco_srv": "https://my.dicso.com/role/idp.ds",
        "state_id": "saml_bakend_test_id"
    }

    return spconfig


@pytest.fixture(scope="session")
def idp_conf(tmpdir_factory):
    tmpdir = tmpdir_factory.getbasetemp()
    idp_cert_path = os.path.join(str(tmpdir), "idp_cert.pem")
    idp_key_path = os.path.join(str(tmpdir), "idp_key.pem")
    write_cert(idp_cert_path, idp_key_path)
    idp_base = "http://test.tester.se"

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
        "key_file": idp_key_path,
        "cert_file": idp_cert_path,
        "metadata": {"inline": []}
    }

    return idpconfig


@pytest.fixture(scope="session")
def setup_test_config(sp_conf, idp_conf):
    idp_metadata_str = create_metadata_from_config_dict(idp_conf)
    sp_conf["config"]["metadata"]["inline"].append(idp_metadata_str)
    idp2_config = idp_conf.copy()
    idp2_config["entityid"] = "just_an_extra_idp"
    idp_metadata_str2 = create_metadata_from_config_dict(idp2_config)
    sp_conf["config"]["metadata"]["inline"].append(idp_metadata_str2)

    sp_metadata_str = create_metadata_from_config_dict(sp_conf["config"])
    idp_conf["metadata"]["inline"] = [sp_metadata_str]


@pytest.mark.usefixtures("setup_test_config")
class TestSamlBackend:
    @pytest.fixture(autouse=True)
    def setup_backend(self, sp_conf):
        self.samlbackend = SamlBackend(None, INTERNAL_ATTRIBUTES, sp_conf)

    def test_register_endpoints(self, sp_conf):
        """
        Tests the method register_endpoints
        """
        url_map = self.samlbackend.register_endpoints()
        for k, v in sp_conf["config"]["service"]["sp"]["endpoints"].items():
            for endp in v:
                match = False
                for regex in url_map:
                    p = re.compile(regex[0])
                    if p.match(urlparse(endp[0]).path.lstrip("/")):
                        match = True
                        break
                assert match, "Not correct regular expression for endpoint: %s" % endp[0]

    def test_start_auth_no_request_info(self, sp_conf):
        """
        Performs a complete test for the module satosa.backends.saml2. The flow should be accepted.
        """
        internal_data = InternalRequest(None, None)

        state = State()
        context = Context()
        context.state = state
        resp = self.samlbackend.start_auth(context, internal_data)
        assert resp.status == "303 See Other", "Must be a redirect to the discovery server."
        assert resp.message.startswith(sp_conf["disco_srv"]), \
            "Redirect to wrong URL."

        # create_name_id_policy_transient()
        state = State()
        context = Context()
        context.state = state
        user_id_hash_type = UserIdHashType.transient
        internal_data = InternalRequest(user_id_hash_type, None)
        resp = self.samlbackend.start_auth(context, internal_data)
        assert resp.status == "303 See Other", "Must be a redirect to the discovery server."

    def test_start_auth_name_id_policy(self, sp_conf):
        """
        Performs a complete test for the module satosa.backends.saml2. The flow should be accepted.
        """
        test_state_key = "sauyghj34589fdh"

        state = State()
        state.add(test_state_key, "my_state")
        context = Context()
        context.state = state

        internal_req = InternalRequest(UserIdHashType.transient, None)
        resp = self.samlbackend.start_auth(context, internal_req)

        assert resp.status == "303 See Other", "Must be a redirect to the discovery server."

        disco_resp = parse_qs(urlparse(resp.message).query)
        sp_config = sp_conf["config"]
        sp_disco_resp = sp_config["service"]["sp"]["endpoints"]["discovery_response"][0][0]
        assert "return" in disco_resp and disco_resp["return"][0].startswith(sp_disco_resp), \
            "Not a valid return url in the call to the discovery server"
        assert "entityID" in disco_resp and disco_resp["entityID"][0] == sp_config["entityid"], \
            "Not a valid entity id in the call to the discovery server"

        request_info_tmp = context.state
        assert request_info_tmp.get(test_state_key) == "my_state", "Wrong state!"

    def test_start_auth_disco(self, sp_conf, idp_conf):
        """
        Performs a complete test for the module satosa.backends.saml2. The flow should be accepted.
        """
        test_state_key = "test_state_key_456afgrh"
        fakeidp = FakeIdP(USERS, config=IdPConfig().load(idp_conf, metadata_construction=False))

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
                sp_conf)

        internal_req = InternalRequest(UserIdHashType.persistent, "example.se/sp.xml")

        state = State()
        state.add(test_state_key, "my_state")
        context = Context()
        context.state = state

        resp = samlbackend.start_auth(context, internal_req)
        assert resp.status == "303 See Other", "Must be a redirect to the discovery server."

        disco_resp = parse_qs(urlparse(resp.message).query)

        info = parse_qs(urlparse(disco_resp["return"][0]).query)
        info[samlbackend.idp_disco_query_param] = idp_conf["entityid"]
        context = Context()
        context.request = info
        context.state = state
        resp = samlbackend.disco_response(context)
        assert resp.status == "303 See Other"
        req_params = dict(parse_qsl(urlparse(resp.message).query))
        url, fake_idp_resp = fakeidp.handle_auth_req(
                req_params["SAMLRequest"],
                req_params["RelayState"],
                BINDING_HTTP_REDIRECT,
                "testuser1")
        context = Context()
        context.request = fake_idp_resp
        context.state = state
        samlbackend.authn_response(context, BINDING_HTTP_POST)

    def test_redirect_to_idp_if_only_one_idp_in_metadata(self, monkeypatch, sp_conf, idp_conf):
        monkeypatch.delitem(sp_conf, "disco_srv")
        monkeypatch.setitem(sp_conf["config"]["metadata"], "inline",
                            [create_metadata_from_config_dict(idp_conf)])

        state = State()
        state.add("test", "state")
        context = Context()
        context.state = state
        internal_req = InternalRequest(UserIdHashType.transient, None)
        samlbackend = SamlBackend(None, INTERNAL_ATTRIBUTES, sp_conf)
        resp = samlbackend.start_auth(context, internal_req)

        assert resp.status == "303 See Other"
        assert resp.message.split("?")[0] == "http://test.tester.se/sso/redirect"
