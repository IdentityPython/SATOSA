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


def verify_object_types_callback(context, response):
    assert isinstance(context, Context)
    assert isinstance(response, InternalResponse)


def verify_userinfo_callback(context, response):
    assert isinstance(response, InternalResponse)
    for attribute in [("name", "name"), ("mail", "email")]:
        assert response._attributes[attribute[0]][0] == USERDB[USERNAME][attribute[1]]

class TestOpenIdBackend:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.openid_backend = OpenIdBackend(MagicMock, INTERNAL_ATTRIBUTES, TestConfiguration.get_instance().config)
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

    @responses.activate
    def test_translate_response_to_internal_response(self):
        self.fake_op.setup_webfinger_endpoint()
        self.fake_op.setup_opienid_config_endpoint()
        self.fake_op.setup_client_registration_endpoint()
        sub = "123qweasd"
        response = {"given_name": "Bob", "family_name": "Devsson", "sub": sub}
        internal_response = self.openid_backend._translate_response(
            response,
            TestConfiguration.get_instance().rp_config.OP_URL,
            "public"
        )
        assert internal_response.get_user_id() == sub
        attributes_keys = internal_response._attributes.keys()
        assert sorted(attributes_keys) == sorted(['surname', 'edupersontargetedid', 'givenname'])

    @responses.activate
    def test_redirect_endpoint_returned_correct_object_types(self):
        self.fake_op.setup_webfinger_endpoint()
        self.fake_op.setup_opienid_config_endpoint()
        self.fake_op.setup_client_registration_endpoint()
        openid_backend = OpenIdBackend(
            verify_object_types_callback,
            INTERNAL_ATTRIBUTES,
            TestConfiguration.get_instance().config
        )
        context = self.setup_fake_op_endpoints(FakeOP.STATE)
        openid_backend.redirect_endpoint(context)

    @responses.activate
    def test_redirect_endpoint_returned_correct_user_info(self):
        self.fake_op.setup_webfinger_endpoint()
        self.fake_op.setup_opienid_config_endpoint()
        self.fake_op.setup_client_registration_endpoint()
        openid_backend = OpenIdBackend(
            verify_userinfo_callback,
            INTERNAL_ATTRIBUTES,
            TestConfiguration.get_instance().config
        )
        context = self.setup_fake_op_endpoints(FakeOP.STATE)
        openid_backend.redirect_endpoint(context)

    def setup_fake_op_endpoints(self, state=None):
        context = self.fake_op.setup_authentication_response(state)
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
        context = Context()
        context.state = State()
        auth_response = self.openid_backend.start_auth(context, None)
        assert auth_response._status == Redirect._status

    @responses.activate
    def test_set_state_in_start_auth_and_use_in_redirect_endpoint(self):
        self.fake_op.setup_webfinger_endpoint()
        self.fake_op.setup_opienid_config_endpoint()
        self.fake_op.setup_client_registration_endpoint()
        context = Context()
        context.state = State()
        self.openid_backend.start_auth(context, None)
        context = self.setup_fake_op_endpoints(FakeOP.STATE)
        self.openid_backend.redirect_endpoint(context)

    @responses.activate
    def test_test_restore_state_with_separate_backends(self):
        openid_backend_1 = OpenIdBackend(MagicMock, INTERNAL_ATTRIBUTES, TestConfiguration.get_instance().config)
        openid_backend_2 = OpenIdBackend(MagicMock, INTERNAL_ATTRIBUTES, TestConfiguration.get_instance().config)
        self.fake_op.setup_webfinger_endpoint()
        self.fake_op.setup_opienid_config_endpoint()
        self.fake_op.setup_client_registration_endpoint()
        context = Context()
        context.state = State()
        openid_backend_1.start_auth(context, None)
        context = self.setup_fake_op_endpoints(FakeOP.STATE)
        openid_backend_2.redirect_endpoint(context)
