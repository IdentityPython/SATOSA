import re

import pytest
import responses
from oic.utils.http_util import Redirect

from mock import MagicMock

from satosa.backends.openid_connect import OpenIdBackend
from satosa.context import Context
from satosa.internal_data import InternalResponse
from satosa.state import State
from tests.satosa.backends.FakeOp import FakeOP, CLIENT_ID, TestConfiguration, USERDB, USERNAME

__author__ = 'danielevertsson'


def verify_object_types_callback(context, response, state):
    assert isinstance(context, Context)
    assert isinstance(response, InternalResponse)
    assert isinstance(state, State)


def verify_userinfo_callback(context, response, state):
    assert isinstance(response, InternalResponse)
    for attribute in ["name", "email"]:
        assert response._attributes[attribute] == USERDB[USERNAME][attribute]

class TestOpenIdBackend:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.openid_backend = OpenIdBackend(MagicMock, TestConfiguration.get_instance().rp_config)
        self.fake_op = FakeOP()

    def test_registered_endpoints(self):
        url_map = self.openid_backend.register_endpoints()
        for endpoint in self.fake_op.redirect_urls:
            match = False
            for regex in url_map:
                if re.search(regex[0], endpoint):
                    match = True
                    break
            assert match, "Not correct regular expression for endpoint: %s" % endpoint[0]

    def test_translate_response_to_internal_response(self):
        sub = "123qweasd"
        response = {"given_name": "Bob", "family_name": "Devsson", "sub": sub}
        internal_response = self.openid_backend._translate_response(
            response,
            TestConfiguration.get_instance().rp_config.OP_URL
        )
        assert internal_response.user_id == sub
        attributes_keys = internal_response._attributes.keys()
        assert sorted(attributes_keys) == sorted(['surname', 'edupersontargetedid', 'givenname'])

    @responses.activate
    def test_redirect_endpoint_returned_correct_object_types(self):
        openid_backend = OpenIdBackend(
            verify_object_types_callback,
            TestConfiguration.get_instance().rp_config
        )
        context = self.setup_fake_op_endpoints()
        openid_backend.redirect_endpoint(context)

    @responses.activate
    def test_redirect_endpoint_returned_correct_user_info(self):
        openid_backend = OpenIdBackend(
            verify_userinfo_callback,
            TestConfiguration.get_instance().rp_config
        )
        context = self.setup_fake_op_endpoints()
        openid_backend.redirect_endpoint(context)

    def setup_fake_op_endpoints(self, state_as_url=None):
        context = self.fake_op.setup_authentication_response(state_as_url)
        self.fake_op.provider.client_authn = MagicMock(return_value=CLIENT_ID)
        self.fake_op.publish_jwks()
        self.fake_op.setup_token_endpoint()
        self.fake_op.setup_userinfo_endpoint()
        return context

    @responses.activate
    def test_redirect_to_login_at_auth_endpoint(self):
        self.fake_op.setup_webfinger_endpoint()
        self.fake_op.setup_opienid_config_endpoint()
        self.fake_op.setup_client_registration_endpoint()
        auth_response = self.openid_backend.start_auth(None, None, State())
        assert auth_response._status == Redirect._status

    @responses.activate
    def test_set_state_in_start_auth_and_use_in_redirect_endpoint(self):
        self.fake_op.setup_webfinger_endpoint()
        self.fake_op.setup_opienid_config_endpoint()
        self.fake_op.setup_client_registration_endpoint()
        state = State()
        self.openid_backend.start_auth(None, None, state)
        state_as_ulr = state.urlstate(
            TestConfiguration.get_instance().rp_config.STATE_ENCRYPTION_KEY
        )
        context = self.setup_fake_op_endpoints(state_as_ulr)
        self.openid_backend.redirect_endpoint(context)
