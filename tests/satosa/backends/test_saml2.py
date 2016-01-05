"""
Tests for the SAML frontend module src/backends/saml2.py.
"""
import re
from urllib.parse import urlparse, parse_qs, parse_qsl

import pytest
from saml2 import BINDING_HTTP_REDIRECT
from saml2.authn_context import PASSWORD
from saml2.config import IdPConfig

from satosa.backends.saml2 import SamlBackend
from satosa.context import Context
from satosa.internal_data import UserIdHashType, InternalRequest
from satosa.state import State
from tests.users import USERS
from tests.util import FakeIdP, create_metadata_from_config_dict

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


@pytest.fixture
def setup_test_config(sp_conf, idp_conf):
    idp_metadata_str = create_metadata_from_config_dict(idp_conf)
    sp_conf["metadata"]["inline"].append(idp_metadata_str)
    idp2_config = idp_conf.copy()
    idp2_config["entityid"] = "just_an_extra_idp"
    idp_metadata_str2 = create_metadata_from_config_dict(idp2_config)
    sp_conf["metadata"]["inline"].append(idp_metadata_str2)

    sp_metadata_str = create_metadata_from_config_dict(sp_conf)
    idp_conf["metadata"]["inline"] = [sp_metadata_str]


@pytest.mark.usefixtures("setup_test_config")
class TestSamlBackend:
    def test_register_endpoints(self, sp_conf):
        """
        Tests the method register_endpoints
        """
        samlbackend = SamlBackend(None, INTERNAL_ATTRIBUTES, {"config": sp_conf,
                                                              "disco_srv": "https://my.dicso.com/role/idp.ds",
                                                              "state_id": "saml_backend_test_id"})

        url_map = samlbackend.register_endpoints()
        for k, v in sp_conf["service"]["sp"]["endpoints"].items():
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
        disco_srv = "https://my.dicso.com/role/idp.ds"
        samlbackend = SamlBackend(None, INTERNAL_ATTRIBUTES, {"config": sp_conf,
                                                              "disco_srv": disco_srv,
                                                              "state_id": "saml_backend_test_id"})
        internal_data = InternalRequest(None, None)

        state = State()
        context = Context()
        context.state = state
        resp = samlbackend.start_auth(context, internal_data)
        assert resp.status == "303 See Other", "Must be a redirect to the discovery server."
        assert resp.message.startswith("https://my.dicso.com/role/idp.ds"), \
            "Redirect to wrong URL."

        # create_name_id_policy_transient()
        state = State()
        context = Context()
        context.state = state
        user_id_hash_type = UserIdHashType.transient
        internal_data = InternalRequest(user_id_hash_type, None)
        resp = samlbackend.start_auth(context, internal_data)
        assert resp.status == "303 See Other", "Must be a redirect to the discovery server."

    def test_start_auth_name_id_policy(self, sp_conf):
        """
        Performs a complete test for the module satosa.backends.saml2. The flow should be accepted.
        """
        samlbackend = SamlBackend(None, INTERNAL_ATTRIBUTES, {"config": sp_conf,
                                                              "disco_srv": "https://my.dicso.com/role/idp.ds",
                                                              "state_id": "saml_backend_test_id"})
        test_state_key = "sauyghj34589fdh"

        state = State()
        state.add(test_state_key, "my_state")
        context = Context()
        context.state = state

        internal_req = InternalRequest(UserIdHashType.transient, None)
        resp = samlbackend.start_auth(context, internal_req)

        assert resp.status == "303 See Other", "Must be a redirect to the discovery server."

        disco_resp = parse_qs(urlparse(resp.message).query)
        sp_disco_resp = \
            sp_conf["service"]["sp"]["endpoints"]["discovery_response"][0][0]
        assert "return" in disco_resp and disco_resp["return"][0].startswith(sp_disco_resp), \
            "Not a valid return url in the call to the discovery server"
        assert "entityID" in disco_resp and disco_resp["entityID"][0] == sp_conf["entityid"], \
            "Not a valid entity id in the call to the discovery server"

        request_info_tmp = context.state
        assert request_info_tmp.get(test_state_key) == "my_state", "Wrong state!"

    def test_start_auth_disco(self, sp_conf, idp_conf):
        """
        Performs a complete test for the module satosa.backends.saml2. The flow should be accepted.
        """
        samlbackend = SamlBackend(lambda context, internal_resp: (context, internal_resp),
                                  INTERNAL_ATTRIBUTES, {"config": sp_conf,
                                                        "disco_srv": "https://my.dicso.com/role/idp.ds",
                                                        "state_id": "saml_backend_test_id"})
        test_state_key = "test_state_key_456afgrh"
        response_binding = BINDING_HTTP_REDIRECT
        fakeidp = FakeIdP(USERS, config=IdPConfig().load(idp_conf, metadata_construction=False))

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
                "testuser1",
                response_binding=response_binding)
        context = Context()
        context.request = fake_idp_resp
        context.state = state
        context, internal_resp = samlbackend.authn_response(context, response_binding)
        assert isinstance(context, Context), "Not correct instance!"
        assert context.state.get(test_state_key) == "my_state", "Not correct state!"
        assert internal_resp.auth_info.auth_class_ref == PASSWORD, "Not correct authentication!"
        _dict = internal_resp.get_attributes()
        expected_data = {'surname': ['Testsson 1'], 'mail': ['test@example.com'],
                         'displayname': ['Test Testsson'], 'givenname': ['Test 1'],
                         'edupersontargetedid': ['one!for!all']}
        for key in _dict:
            assert expected_data[key] == _dict[key]

    def test_redirect_to_idp_if_only_one_idp_in_metadata(self, sp_conf, idp_conf):
        sp_conf["metadata"]["inline"] = [create_metadata_from_config_dict(idp_conf)]
        samlbackend = SamlBackend(None, INTERNAL_ATTRIBUTES,
                                  {"config": sp_conf, "state_id": "saml_backend_test_id"})

        state = State()
        state.add("test", "state")
        context = Context()
        context.state = state
        internal_req = InternalRequest(UserIdHashType.transient, None)

        resp = samlbackend.start_auth(context, internal_req)

        assert resp.status == "303 See Other"
        parsed = urlparse(resp.message)
        assert "{parsed.scheme}://{parsed.netloc}{parsed.path}".format(
                parsed=parsed) == \
               idp_conf["service"]["idp"]["endpoints"]["single_sign_on_service"][0][0]
        assert "SAMLRequest" in parse_qs(parsed.query)
