"""
Tests for the SAML frontend module src/backends/saml2.py.
"""
import re
from unittest.mock import Mock
from urllib.parse import urlparse, parse_qs, parse_qsl

import pytest
from saml2 import BINDING_HTTP_REDIRECT
from saml2.authn_context import PASSWORD
from saml2.config import IdPConfig

from satosa.backends.saml2 import SamlBackend
from satosa.context import Context
from satosa.internal_data import UserIdHashType, InternalRequest
from tests.users import USERS
from tests.util import FakeIdP, create_metadata_from_config_dict

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

METADATA_URL = "http://example.com/SAML2IDP/metadata"


class TestSamlBackend:
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
        self.samlbackend = SamlBackend(Mock(), INTERNAL_ATTRIBUTES, {"config": sp_conf,
                                                                     "disco_srv": "https://my.dicso.com/role/idp.ds",
                                                                     "publish_metadata": METADATA_URL},
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

        assert any(p.match(get_path_from_url(METADATA_URL)) for p in compiled_regex)

    def test_start_auth_no_request_info(self, context):
        """
        Performs a complete test for the module satosa.backends.saml2. The flow should be accepted.
        """
        internal_data = InternalRequest(None, None)
        resp = self.samlbackend.start_auth(context, internal_data)
        assert resp.status == "303 See Other", "Must be a redirect to the discovery server."
        assert resp.message.startswith("https://my.dicso.com/role/idp.ds"), \
            "Redirect to wrong URL."

    def test_start_auth_name_id_policy(self, context, sp_conf):
        """
        Performs a complete test for the module satosa.backends.saml2. The flow should be accepted.
        """
        test_state_key = "sauyghj34589fdh"
        context.state[test_state_key] = "my_state"

        internal_req = InternalRequest(UserIdHashType.transient, None)
        resp = self.samlbackend.start_auth(context, internal_req)

        assert resp.status == "303 See Other", "Must be a redirect to the discovery server."

        disco_resp = parse_qs(urlparse(resp.message).query)
        sp_disco_resp = \
            sp_conf["service"]["sp"]["endpoints"]["discovery_response"][0][0]
        assert "return" in disco_resp and disco_resp["return"][0].startswith(sp_disco_resp), \
            "Not a valid return url in the call to the discovery server"
        assert "entityID" in disco_resp and disco_resp["entityID"][0] == sp_conf["entityid"], \
            "Not a valid entity id in the call to the discovery server"

        request_info_tmp = context.state
        assert request_info_tmp[test_state_key] == "my_state", "Wrong state!"

    def test_start_auth_disco(self, context, idp_conf):
        """
        Performs a complete test for the module satosa.backends.saml2. The flow should be accepted.
        """
        test_state_key = "test_state_key_456afgrh"
        response_binding = BINDING_HTTP_REDIRECT
        fakeidp = FakeIdP(USERS, config=IdPConfig().load(idp_conf, metadata_construction=False))

        internal_req = InternalRequest(UserIdHashType.persistent, "example.se/sp.xml")
        context.state[test_state_key] = "my_state"

        resp = self.samlbackend.start_auth(context, internal_req)
        assert resp.status == "303 See Other", "Must be a redirect to the discovery server."

        disco_resp = parse_qs(urlparse(resp.message).query)

        info = parse_qs(urlparse(disco_resp["return"][0]).query)
        info["entityID"] = idp_conf["entityid"]
        request_context = Context()
        request_context.request = info
        request_context.state = context.state
        resp = self.samlbackend.disco_response(request_context)
        assert resp.status == "303 See Other"
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
        self.samlbackend.authn_response(response_context, response_binding)
        context, internal_resp = self.samlbackend.auth_callback_func.call_args[0]
        assert isinstance(context, Context), "Not correct instance!"
        assert context.state[test_state_key] == "my_state", "Not correct state!"
        assert internal_resp.auth_info.auth_class_ref == PASSWORD, "Not correct authentication!"
        expected_data = {'surname': ['Testsson 1'], 'mail': ['test@example.com'],
                         'displayname': ['Test Testsson'], 'givenname': ['Test 1'],
                         'edupersontargetedid': ['one!for!all']}
        assert expected_data == internal_resp.attributes

    def test_redirect_to_idp_if_only_one_idp_in_metadata(self, context, sp_conf, idp_conf):
        sp_conf["metadata"]["inline"] = [create_metadata_from_config_dict(idp_conf)]
        # instantiate new backend, without any discovery service configured
        samlbackend = SamlBackend(None, INTERNAL_ATTRIBUTES, {"config": sp_conf}, "base_url", "saml_backend")

        context.state["test"] = "state"
        internal_req = InternalRequest(UserIdHashType.transient, None)

        resp = samlbackend.start_auth(context, internal_req)

        assert resp.status == "303 See Other"
        parsed = urlparse(resp.message)
        assert "{parsed.scheme}://{parsed.netloc}{parsed.path}".format(
            parsed=parsed) == \
               idp_conf["service"]["idp"]["endpoints"]["single_sign_on_service"][0][0]
        assert "SAMLRequest" in parse_qs(parsed.query)
