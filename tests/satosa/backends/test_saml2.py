"""
Tests for the SAML frontend module src/backends/saml2.py.
"""
import os
import re
from base64 import urlsafe_b64encode
from collections import Counter
from datetime import datetime
from unittest.mock import Mock, patch
from urllib.parse import urlparse, parse_qs, parse_qsl

import pytest
from saml2 import BINDING_HTTP_REDIRECT
from saml2.authn_context import PASSWORD
from saml2.config import IdPConfig, SPConfig
from saml2.s_utils import deflate_and_base64_encode

from satosa.backends.saml2 import SAMLBackend, SAMLMirrorBackend
from satosa.context import Context
from satosa.internal_data import InternalRequest
from tests.users import USERS
from tests.util import FakeIdP, create_metadata_from_config_dict, FakeSP

TEST_RESOURCE_BASE_PATH = os.path.join(os.path.dirname(__file__), "../../test_resources")

INTERNAL_ATTRIBUTES = {
    'attributes': {
        'displayname': {'saml': ['displayName']},
        'givenname': {'saml': ['givenName']},
        'mail': {'saml': ['email', 'emailAdress', 'mail']},
        'edupersontargetedid': {'saml': ['eduPersonTargetedID']},
        'name': {'saml': ['cn']},
        'surname': {'saml': ['sn', 'surname']}
    }
}

DISCOSRV_URL = "https://my.dicso.com/role/idp.ds"


class TestSAMLBackend:
    def assert_redirect_to_idp(self, redirect_response, idp_conf):
        assert redirect_response.status == "303 See Other"
        parsed = urlparse(redirect_response.message)
        redirect_location = "{parsed.scheme}://{parsed.netloc}{parsed.path}".format(parsed=parsed)
        assert redirect_location == idp_conf["service"]["idp"]["endpoints"]["single_sign_on_service"][0][0]
        assert "SAMLRequest" in parse_qs(parsed.query)

    def assert_redirect_to_discovery_server(self, redirect_response, sp_conf):
        assert redirect_response.status == "303 See Other"
        parsed = urlparse(redirect_response.message)
        redirect_location = "{parsed.scheme}://{parsed.netloc}{parsed.path}".format(parsed=parsed)
        assert redirect_location == DISCOSRV_URL

        request_params = dict(parse_qsl(parsed.query))
        assert request_params["return"] == sp_conf["service"]["sp"]["endpoints"]["discovery_response"][0][0]
        assert request_params["entityID"] == sp_conf["entityid"]

    def assert_authn_response(self, internal_resp):
        assert internal_resp.auth_info.auth_class_ref == PASSWORD
        expected_data = {'surname': ['Testsson 1'], 'mail': ['test@example.com'],
                         'displayname': ['Test Testsson'], 'givenname': ['Test 1'],
                         'edupersontargetedid': ['one!for!all']}
        assert expected_data == internal_resp.attributes

    def setup_test_config(self, sp_conf, idp_conf):
        idp_metadata_str = create_metadata_from_config_dict(idp_conf)
        sp_conf["metadata"]["inline"].append(idp_metadata_str)
        idp2_config = idp_conf.copy()
        idp2_config["entityid"] = "just_an_extra_idp"
        idp_metadata_str2 = create_metadata_from_config_dict(idp2_config)
        sp_conf["metadata"]["inline"].append(idp_metadata_str2)

        sp_metadata_str = create_metadata_from_config_dict(sp_conf)
        idp_conf["metadata"]["inline"] = [sp_metadata_str]

    @pytest.fixture(autouse=True)
    def create_backend(self, sp_conf, idp_conf):
        self.setup_test_config(sp_conf, idp_conf)
        self.samlbackend = SAMLBackend(Mock(), INTERNAL_ATTRIBUTES, {"sp_config": sp_conf,
                                                                     "disco_srv": DISCOSRV_URL},
                                       "base_url",
                                       "samlbackend")

    def test_register_endpoints(self, sp_conf):
        """
        Tests the method register_endpoints
        """

        def get_path_from_url(url):
            return urlparse(url).path.lstrip("/")

        url_map = self.samlbackend.register_endpoints()
        all_sp_endpoints = [get_path_from_url(v[0][0]) for v in sp_conf["service"]["sp"]["endpoints"].values()]
        compiled_regex = [re.compile(regex) for regex, _ in url_map]
        for endp in all_sp_endpoints:
            assert any(p.match(endp) for p in compiled_regex)

    def test_start_auth_defaults_to_redirecting_to_discovery_server(self, context, sp_conf):
        resp = self.samlbackend.start_auth(context, InternalRequest(None, None))
        self.assert_redirect_to_discovery_server(resp, sp_conf)

    def test_full_flow(self, context, idp_conf, sp_conf):
        test_state_key = "test_state_key_456afgrh"
        response_binding = BINDING_HTTP_REDIRECT
        fakeidp = FakeIdP(USERS, config=IdPConfig().load(idp_conf, metadata_construction=False))

        context.state[test_state_key] = "my_state"

        # start auth flow (redirecting to discovery server)
        resp = self.samlbackend.start_auth(context, InternalRequest(None, None))
        self.assert_redirect_to_discovery_server(resp, sp_conf)

        # fake response from discovery server
        disco_resp = parse_qs(urlparse(resp.message).query)
        info = parse_qs(urlparse(disco_resp["return"][0]).query)
        info["entityID"] = idp_conf["entityid"]
        request_context = Context()
        request_context.request = info
        request_context.state = context.state

        # pass discovery response to backend and check that it redirects to the selected IdP
        resp = self.samlbackend.disco_response(request_context)
        self.assert_redirect_to_idp(resp, idp_conf)

        # fake auth response to the auth request
        req_params = dict(parse_qsl(urlparse(resp.message).query))
        url, fake_idp_resp = fakeidp.handle_auth_req(
            req_params["SAMLRequest"],
            req_params["RelayState"],
            BINDING_HTTP_REDIRECT,
            "testuser1",
            response_binding=response_binding)
        response_context = Context()
        response_context.request = fake_idp_resp
        response_context.state = request_context.state

        # pass auth response to backend and verify behavior
        self.samlbackend.authn_response(response_context, response_binding)
        context, internal_resp = self.samlbackend.auth_callback_func.call_args[0]
        assert self.samlbackend.name not in context.state
        assert context.state[test_state_key] == "my_state"
        self.assert_authn_response(internal_resp)

    def test_start_auth_redirects_directly_to_mirrored_idp(
            self, context, idp_conf):
        entityid = idp_conf["entityid"]
        entityid_bytes = entityid.encode("utf-8")
        entityid_b64_str = urlsafe_b64encode(entityid_bytes).decode("utf-8")
        context.decorate(Context.KEY_MIRROR_TARGET_ENTITYID, entityid_b64_str)

        resp = self.samlbackend.start_auth(context, InternalRequest(None, None))
        self.assert_redirect_to_idp(resp, idp_conf)

    def test_redirect_to_idp_if_only_one_idp_in_metadata(self, context, sp_conf, idp_conf):
        sp_conf["metadata"]["inline"] = [create_metadata_from_config_dict(idp_conf)]
        # instantiate new backend, without any discovery service configured
        samlbackend = SAMLBackend(None, INTERNAL_ATTRIBUTES, {"sp_config": sp_conf}, "base_url", "saml_backend")

        resp = samlbackend.start_auth(context, InternalRequest(None, None))
        self.assert_redirect_to_idp(resp, idp_conf)

    def test_always_redirect_to_discovery_service_if_using_mdq(self, context, sp_conf, idp_conf):
        # one IdP in the metadata, but MDQ also configured so should always redirect to the discovery service
        sp_conf["metadata"]["inline"] = [create_metadata_from_config_dict(idp_conf)]
        sp_conf["metadata"]["mdq"] = ["https://mdq.example.com"]
        samlbackend = SAMLBackend(None, INTERNAL_ATTRIBUTES, {"sp_config": sp_conf, "disco_srv": DISCOSRV_URL,},
                                  "base_url", "saml_backend")
        resp = samlbackend.start_auth(context, InternalRequest(None, None))
        self.assert_redirect_to_discovery_server(resp, sp_conf)

    def test_authn_request(self, context, idp_conf):
        resp = self.samlbackend.authn_request(context, idp_conf["entityid"])
        self.assert_redirect_to_idp(resp, idp_conf)
        req_params = dict(parse_qsl(urlparse(resp.message).query))
        assert context.state[self.samlbackend.name]["relay_state"] == req_params["RelayState"]

    def test_authn_response(self, context, idp_conf, sp_conf):
        response_binding = BINDING_HTTP_REDIRECT
        fakesp = FakeSP(SPConfig().load(sp_conf, metadata_construction=False))
        fakeidp = FakeIdP(USERS, config=IdPConfig().load(idp_conf, metadata_construction=False))
        destination, request_params = fakesp.make_auth_req(idp_conf["entityid"])
        url, auth_resp = fakeidp.handle_auth_req(request_params["SAMLRequest"], request_params["RelayState"],
                                                 BINDING_HTTP_REDIRECT,
                                                 "testuser1", response_binding=response_binding)

        context.request = auth_resp
        context.state[self.samlbackend.name] = {"relay_state": request_params["RelayState"]}
        self.samlbackend.authn_response(context, response_binding)

        context, internal_resp = self.samlbackend.auth_callback_func.call_args[0]
        self.assert_authn_response(internal_resp)
        assert self.samlbackend.name not in context.state

    def test_authn_response_with_encrypted_assertion(self, sp_conf, context):
        with open(os.path.join(TEST_RESOURCE_BASE_PATH,
                               "idp_metadata_for_encrypted_signed_auth_response.xml")) as idp_metadata_file:
            sp_conf["metadata"]["inline"] = [idp_metadata_file.read()]
        samlbackend = SAMLBackend(Mock(), INTERNAL_ATTRIBUTES, {"sp_config": sp_conf,
                                                                "disco_srv": DISCOSRV_URL},
                                  "base_url", "samlbackend")
        response_binding = BINDING_HTTP_REDIRECT
        relay_state = "test relay state"

        with open(os.path.join(TEST_RESOURCE_BASE_PATH,
                               "auth_response_with_encrypted_signed_assertion.xml")) as auth_response_file:
            auth_response = auth_response_file.read()
        context.request = {"SAMLResponse": deflate_and_base64_encode(auth_response), "RelayState": relay_state}

        context.state[self.samlbackend.name] = {"relay_state": relay_state}
        with open(os.path.join(TEST_RESOURCE_BASE_PATH, "encryption_key.pem")) as encryption_key_file:
            samlbackend.encryption_keys = [encryption_key_file.read()]

        assertion_issued_at = 1479315212
        with patch('saml2.validate.time_util.shift_time') as mock_shift_time, \
                patch('saml2.validate.time_util.utc_now') as mock_utc_now:
            mock_utc_now.return_value = assertion_issued_at + 1
            mock_shift_time.side_effect = [datetime.utcfromtimestamp(assertion_issued_at + 1),
                                     datetime.utcfromtimestamp(assertion_issued_at - 1)]
            samlbackend.authn_response(context, response_binding)

        context, internal_resp = samlbackend.auth_callback_func.call_args[0]
        assert Counter(internal_resp.attributes.keys()) == Counter({"mail", "givenname", "displayname", "surname"})

    def test_backend_reads_encryption_key_from_key_file(self, sp_conf):
        sp_conf["key_file"] = os.path.join(TEST_RESOURCE_BASE_PATH, "encryption_key.pem")
        samlbackend = SAMLBackend(Mock(), INTERNAL_ATTRIBUTES, {"sp_config": sp_conf,
                                                                "disco_srv": DISCOSRV_URL},
                                  "base_url", "samlbackend")
        assert samlbackend.encryption_keys

    def test_backend_reads_encryption_key_from_encryption_keypair(self, sp_conf):
        del sp_conf["key_file"]
        sp_conf["encryption_keypairs"] = [{"key_file": os.path.join(TEST_RESOURCE_BASE_PATH, "encryption_key.pem")}]
        samlbackend = SAMLBackend(Mock(), INTERNAL_ATTRIBUTES, {"sp_config": sp_conf,
                                                                "disco_srv": DISCOSRV_URL},
                                  "base_url", "samlbackend")
        assert samlbackend.encryption_keys

    def test_metadata_endpoint(self, context, sp_conf):
        resp = self.samlbackend._metadata_endpoint(context)
        headers = dict(resp.headers)
        assert headers["Content-Type"] == "text/xml"
        assert sp_conf["entityid"] in resp.message

    def test_get_metadata_desc(self, sp_conf, idp_conf):
        sp_conf["metadata"]["inline"] = [create_metadata_from_config_dict(idp_conf)]
        # instantiate new backend, with a single backing IdP
        samlbackend = SAMLBackend(None, INTERNAL_ATTRIBUTES, {"sp_config": sp_conf}, "base_url", "saml_backend")
        entity_descriptions = samlbackend.get_metadata_desc()

        assert len(entity_descriptions) == 1

        idp_desc = entity_descriptions[0].to_dict()

        assert idp_desc["entityid"] == urlsafe_b64encode(idp_conf["entityid"].encode("utf-8")).decode("utf-8")
        assert idp_desc["contact_person"] == idp_conf["contact_person"]

        assert idp_desc["organization"]["name"][0] == tuple(idp_conf["organization"]["name"][0])
        assert idp_desc["organization"]["display_name"][0] == tuple(idp_conf["organization"]["display_name"][0])
        assert idp_desc["organization"]["url"][0] == tuple(idp_conf["organization"]["url"][0])

        expected_ui_info = idp_conf["service"]["idp"]["ui_info"]
        ui_info = idp_desc["service"]["ui_info"]
        assert ui_info["display_name"] == expected_ui_info["display_name"]
        assert ui_info["description"] == expected_ui_info["description"]
        assert ui_info["logo"] == expected_ui_info["logo"]

    def test_get_metadata_desc_with_logo_without_lang(self, sp_conf, idp_conf):
        # add logo without 'lang'
        idp_conf["service"]["idp"]["ui_info"]["logo"] = [{"text": "https://idp.example.com/static/logo.png",
                                                          "width": "120", "height": "60"}]

        sp_conf["metadata"]["inline"] = [create_metadata_from_config_dict(idp_conf)]
        # instantiate new backend, with a single backing IdP
        samlbackend = SAMLBackend(None, INTERNAL_ATTRIBUTES, {"sp_config": sp_conf}, "base_url", "saml_backend")
        entity_descriptions = samlbackend.get_metadata_desc()

        assert len(entity_descriptions) == 1

        idp_desc = entity_descriptions[0].to_dict()

        assert idp_desc["entityid"] == urlsafe_b64encode(idp_conf["entityid"].encode("utf-8")).decode("utf-8")
        assert idp_desc["contact_person"] == idp_conf["contact_person"]

        assert idp_desc["organization"]["name"][0] == tuple(idp_conf["organization"]["name"][0])
        assert idp_desc["organization"]["display_name"][0] == tuple(idp_conf["organization"]["display_name"][0])
        assert idp_desc["organization"]["url"][0] == tuple(idp_conf["organization"]["url"][0])

        expected_ui_info = idp_conf["service"]["idp"]["ui_info"]
        ui_info = idp_desc["service"]["ui_info"]
        assert ui_info["display_name"] == expected_ui_info["display_name"]
        assert ui_info["description"] == expected_ui_info["description"]
        assert ui_info["logo"] == expected_ui_info["logo"]

class TestSAMLMirrorBackend:
    def setup_test_config(self, sp_conf, idp_conf):
        idp_metadata_str = create_metadata_from_config_dict(idp_conf)
        sp_conf["metadata"]["inline"].append(idp_metadata_str)
        idp2_config = idp_conf.copy()
        idp2_config["entityid"] = "just_an_extra_idp"
        idp_metadata_str2 = create_metadata_from_config_dict(idp2_config)
        sp_conf["metadata"]["inline"].append(idp_metadata_str2)

        sp_metadata_str = create_metadata_from_config_dict(sp_conf)
        idp_conf["metadata"]["inline"] = [sp_metadata_str]

    @pytest.fixture(autouse=True)
    def create_backend(self, sp_conf, idp_conf):
        self.setup_test_config(sp_conf, idp_conf)
        self.samlbackend = SAMLMirrorBackend(Mock(), INTERNAL_ATTRIBUTES, {"sp_config": sp_conf,
                                                                           "disco_srv": DISCOSRV_URL},
                                       "base_url",
                                       "samlbackend")

    def test_dynamic_entityid(self, context, sp_conf, idp_conf):
        test_state_key = "test_state_key_456afgrh"
        context.state[test_state_key] = "my_state"
        context.target_frontend = "target_frontend"
        requester = "requester_id"

        self.samlbackend.start_auth(context, InternalRequest(None, requester))
        assert self.samlbackend.sp.config.entityid == sp_conf['entityid'] + '/' + context.target_frontend + '/' +  urlsafe_b64encode(requester.encode('utf-8')).decode('utf-8')

