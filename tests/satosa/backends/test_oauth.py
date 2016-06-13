import json
from unittest.mock import Mock
from urllib.parse import urlparse, parse_qsl

import pytest
import responses

from satosa.backends.oauth import FacebookBackend
from satosa.context import Context
from satosa.internal_data import UserIdHashType, InternalRequest
from satosa.state import State

FB_RESPONSE = {
    "id": "fb_id",
    "name": "fb_name",
    "first_name": "fb_first_name",
    "last_name": "fb_last_name",
    "picture": {
        "data": {
            "is_silhouette": False,
            "url": "fb_picture"}},
    "email": "fb_email",
    "verified": True,
    "gender": "fb_gender",
    "timezone": 2,
    "locale": "sv_SE",
    "updated_time": "2015-10-15T07:04:10+0000"
}
BASE_URL = "https://client.example.com"
AUTHZ_PAGE = 'facebook'
CLIENT_ID = "facebook_client_id"
FB_AUTH_ENDPOINT = "https://www.facebook.com/dialog/oauth"
FB_CONFIG = {
    'server_info': {
        'authorization_endpoint': FB_AUTH_ENDPOINT,
        'token_endpoint': 'https://graph.facebook.com/v2.5/oauth/access_token'
    },
    'client_secret': 'facebook_secret',
    'base_url': BASE_URL,
    'state_encryption_key': 'state_encryption_key',
    'encryption_key': 'encryption_key',
    'fields': ['id', 'name', 'first_name', 'last_name', 'middle_name', 'picture', 'email',
               'verified', 'gender', 'timezone', 'locale', 'updated_time'],
    'authz_page': AUTHZ_PAGE,
    'client_config': {'client_id': CLIENT_ID}
}
FB_RESPONSE_CODE = "the_fb_code"

INTERNAL_ATTRIBUTES = {
    'attributes': {
        'givenname': {'facebook': ['first_name']},
        'mail': {'facebook': ['email']},
        'edupersontargetedid': {'facebook': ['id']},
        'name': {'facebook': ['name']},
        'surname': {'facebook': ['last_name']},
        'gender': {'facebook': ['gender']}
    }
}

mock_get_state = Mock(return_value="abcdef")


class TestFacebookBackend(object):
    @pytest.fixture(autouse=True)
    def setup(self):
        self.fb_backend = FacebookBackend(None, INTERNAL_ATTRIBUTES, FB_CONFIG)

    def test_register_endpoints(self):
        url_map = self.fb_backend.register_endpoints()
        test_map = [('^facebook?(.*)$', self.fb_backend.authn_response),
                    ('^facebook$', self.fb_backend.authn_response)]
        assert url_map == test_map

    def test_start_auth(self):
        context = Context()
        context.path = 'facebook/sso/redirect'
        context.state = State()
        internal_request = InternalRequest(UserIdHashType.transient, 'test_requestor')

        resp = self.fb_backend.start_auth(context, internal_request, mock_get_state)
        login_url = resp.message
        assert login_url.startswith(FB_AUTH_ENDPOINT)
        expected_params = {
            "client_id": CLIENT_ID,
            "state": mock_get_state.return_value,
            "response_type": "code",
            "redirect_uri": "%s/%s" % (BASE_URL, AUTHZ_PAGE)
        }
        actual_params = dict(parse_qsl(urlparse(login_url).query))
        assert actual_params == expected_params

    def verify_callback(self, context, internal_response):
        expected_attributes = {
            "edupersontargetedid": [FB_RESPONSE["id"]],
            "surname": [FB_RESPONSE["last_name"]],
            "name": [FB_RESPONSE["name"]],
            "mail": [FB_RESPONSE["email"]],
            "givenname": [FB_RESPONSE["first_name"]],
            "gender": [FB_RESPONSE["gender"]],
        }

        assert internal_response.get_attributes() == expected_attributes

    def verify_do_access_token_request(self, request_args, state, **kwargs):
        assert request_args["code"] == FB_RESPONSE_CODE
        assert request_args["redirect_uri"] == "%s/%s" % (BASE_URL, AUTHZ_PAGE)
        assert request_args["state"] == mock_get_state.return_value
        assert state == mock_get_state.return_value
        return {"access_token": "fb access token"}

    @responses.activate
    def test_authn_response(self):
        responses.add(responses.GET,
                      "https://graph.facebook.com/v2.5/me",
                      body=json.dumps(FB_RESPONSE),
                      status=200,
                      content_type='application/json')

        context = Context()
        context.path = 'facebook/sso/redirect'
        context.state = State()
        internal_request = InternalRequest(UserIdHashType.transient, 'test_requestor')
        self.fb_backend.start_auth(context, internal_request, mock_get_state)
        context.request = {
            "code": FB_RESPONSE_CODE,
            "state": mock_get_state.return_value
        }

        self.fb_backend.auth_callback_func = self.verify_callback
        consumer = self.fb_backend.get_consumer()
        consumer.do_access_token_request = self.verify_do_access_token_request
        self.fb_backend.get_consumer = Mock(return_value=consumer)
        self.fb_backend.authn_response(context)

    @responses.activate
    def test_entire_flow(self):
        """Tests start of authentication (incoming auth req) and receiving auth response."""
        responses.add(responses.POST,
                      "https://graph.facebook.com/v2.5/oauth/access_token",
                      body=json.dumps({"access_token": "qwerty",
                                       "token_type": "bearer",
                                       "expires_in": 9999999999999}),
                      status=200,
                      content_type='application/json')
        responses.add(responses.GET,
                      "https://graph.facebook.com/v2.5/me",
                      body=json.dumps(FB_RESPONSE),
                      status=200,
                      content_type='application/json')

        context = Context()
        context.path = 'facebook/sso/redirect'
        context.state = State()
        internal_request = InternalRequest(UserIdHashType.transient, 'test_requestor')

        self.fb_backend.start_auth(context, internal_request, mock_get_state)
        context.request = {
            "code": FB_RESPONSE_CODE,
            "state": mock_get_state.return_value
        }
        self.fb_backend.auth_callback_func = self.verify_callback
        self.fb_backend.authn_response(context)
