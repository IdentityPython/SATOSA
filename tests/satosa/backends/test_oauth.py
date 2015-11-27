import json
from urllib.parse import quote_plus, parse_qs

import responses

from mock.mock import Mock
import pytest

from satosa.backends.oauth import FacebookBackend
from satosa.context import Context
from satosa.internal_data import UserIdHashType, InternalRequest
from satosa.state import State

__author__ = 'haho0032'

FB_RESPONSE_CHECK = {'edupersontargetedid': ['fb_id'], 'surname': ['fb_last_name'],
                     'name': ['fb_name'], 'mail': ['fb_email'], 'givenname': ['fb_first_name']}
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
    "updated_time": "2015-10-15T07:04:10+0000"}
FB_RESPONSE_CODE = "the_fb_code"
STATE = "mystate"
CLIENT_ID = "facebook_client_id"
BASE_URL = "https://hashog.umdc.umu.se:8091"
AUTHZ_PAGE = 'facebook'
CODE = "code"
FB_AUTH_ENDPOINT = "https://www.facebook.com/dialog/oauth"
FB_REDIRECT_URL = "%s?client_id=%s&state=%s" \
                  "&response_type=%s&redirect_uri=%s/%s" \
                  % (
                      FB_AUTH_ENDPOINT,
                      quote_plus(CLIENT_ID),
                      quote_plus(STATE),
                      quote_plus(CODE),
                      quote_plus(BASE_URL),
                      quote_plus(AUTHZ_PAGE)
                  )
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


class TestFacebook:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.config = {
            'server_info':
                {'authorization_endpoint': FB_AUTH_ENDPOINT,
                 'token_endpoint': 'https://graph.facebook.com/v2.5/oauth/access_token'},
            'client_secret': 'facebook_secret',
            'base_url': BASE_URL,
            'state_encryption_key': 'state_encryption_key',
            'encryption_key': 'encryption_key',
            'fields': ['id', 'name', 'first_name', 'last_name', 'middle_name', 'picture', 'email',
                       'verified', 'gender', 'timezone', 'locale', 'updated_time'],
            'authz_page': AUTHZ_PAGE,
            'client_config': {'client_id': CLIENT_ID}
        }
        self.fb_backend = FacebookBackend(None, INTERNAL_ATTRIBUTES, self.config)

    def test_register_endpoints(self):
        resp_map = self.fb_backend.register_endpoints()
        test_map = [('^facebook?(.*)$', self.fb_backend.authn_response),
                    ('^facebook$', self.fb_backend.authn_response)]
        assert len(resp_map) == len(test_map), "The endpoint registration is not working!"
        for idx, val in enumerate(resp_map):
            assert val == test_map[idx], "The endpoint registration is not working!"

    def test_start_auth(self):
        context = Context()
        context.path = 'facebook/sso/redirect'
        context.state = State()
        internal_request = InternalRequest(UserIdHashType.transient, 'http://localhost:8087/sp.xml')
        get_state = Mock()
        get_state.return_value = STATE
        resp = self.fb_backend.start_auth(context, internal_request, get_state)
        # assert resp.headers[0][0] == "Set-Cookie", "Not the correct return cookie"
        # assert len(resp.headers[0][1]) > 1, "Not the correct return cookie"
        resp_url = resp.message.split("?")
        test_url = FB_REDIRECT_URL.split("?")
        resp_attr = parse_qs(resp_url[1])
        test_attr = parse_qs(test_url[1])
        assert resp_url[0] == test_url[0]
        assert len(resp_attr) == len(test_attr), "Redirect url is not correct!"
        for key in test_attr:
            assert key in resp_attr, "Redirect url is not correct!"
            assert test_attr[key] == resp_attr[key], "Redirect url is not correct!"

    def verify_callback(self, context, internal_response):
        assert len(FB_RESPONSE_CHECK) == len(
            internal_response._attributes), "Not a correct callback!"
        for key in internal_response._attributes:
            assert key in FB_RESPONSE_CHECK, "Not a correct callback!"
            assert FB_RESPONSE_CHECK[key] == internal_response._attributes[key], \
                "Not a correct callback!"

    def verify_do_access_token_request(self, request_args, state, **kwargs):
        assert request_args["code"] == FB_RESPONSE_CODE, "Not a correct at request!"
        assert request_args["redirect_uri"] == "%s/%s" % (BASE_URL, AUTHZ_PAGE), \
            "Not a correct at request!"
        assert request_args["state"] == STATE, "Not a correct at request!"
        assert state == STATE, "Not a correnct state!"
        return {"access_token": "fb access token"}

    def verify_request_fb(self, url, payload):
        resp = Mock()
        resp.text = json.dumps(FB_RESPONSE)
        return resp

    def test_authn_response(self):
        context = Context()
        context.path = 'facebook/sso/redirect'
        context.state = State()
        internal_request = InternalRequest(UserIdHashType.transient, 'http://localhost:8087/sp.xml')
        get_state = Mock()
        get_state.return_value = STATE
        resp = self.fb_backend.start_auth(context, internal_request, get_state)
        context.cookie = resp.headers[0][1]
        context.request = {
            "code": FB_RESPONSE_CODE,
            "state": STATE
        }
        # context.request = json.dumps(context.request)
        self.fb_backend.auth_callback_func = self.verify_callback
        tmp_consumer = self.fb_backend.get_consumer()
        tmp_consumer.do_access_token_request = self.verify_do_access_token_request
        self.fb_backend.get_consumer = Mock()
        self.fb_backend.get_consumer.return_value = tmp_consumer
        self.fb_backend.request_fb = self.verify_request_fb
        self.fb_backend.authn_response(context)

    @responses.activate
    def test_with_pyoidc(self):
        responses.add(responses.POST,
                      "https://graph.facebook.com/v2.5/oauth/access_token",
                      body=json.dumps({"access_token": "qwerty",
                                       "token_type": "bearer",
                                       "expires_in": 9999999999999}),
                      adding_headers={"set-cookie": "TEST=testing; path=/"},
                      status=200,
                      content_type='application/json')
        responses.add(responses.GET,
                      "https://graph.facebook.com/v2.5/me",
                      match_querystring=False,
                      body=json.dumps(FB_RESPONSE),
                      status=200,
                      content_type='application/json')

        context = Context()
        context.path = 'facebook/sso/redirect'
        context.state = State()
        internal_request = InternalRequest(UserIdHashType.transient, 'http://localhost:8087/sp.xml')
        get_state = Mock()
        get_state.return_value = STATE
        resp = self.fb_backend.start_auth(context, internal_request, get_state)
        context.cookie = resp.headers[0][1]
        context.request = {
            "code": FB_RESPONSE_CODE,
            "state": STATE
        }
        self.fb_backend.auth_callback_func = self.verify_callback
        self.fb_backend.authn_response(context)
