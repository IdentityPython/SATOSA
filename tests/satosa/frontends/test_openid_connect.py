"""
Tests for the SAML frontend module src/frontends/saml2.py.
"""
import json
from base64 import urlsafe_b64encode
from unittest.mock import Mock
from urllib.parse import urlparse, parse_qsl

import pytest
from oic.oic.message import AuthorizationResponse, AuthorizationRequest, IdToken, ClaimsRequest, \
    Claims, AuthorizationErrorResponse, RegistrationResponse, RegistrationRequest, \
    ClientRegistrationErrorResponse, ProviderConfigurationResponse, AccessTokenRequest, AccessTokenResponse, \
    TokenErrorResponse, OpenIDSchema
from oic.oic.provider import TokenEndpoint, UserinfoEndpoint, RegistrationEndpoint
from saml2.authn_context import PASSWORD

from satosa.attribute_mapping import AttributeMapper
from satosa.exception import SATOSAAuthenticationError
from satosa.frontends.openid_connect import OpenIDConnectFrontend, oidc_subject_type_to_hash_type
from satosa.internal_data import InternalResponse, AuthenticationInformation, UserIdHashType
from tests.users import USERS

INTERNAL_ATTRIBUTES = {
    'attributes': {"mail": {"saml": ["email"], "openid": ["email"]}}
}
BASE_URL = "https://op.example.com"
CLIENT_ID = "client1"
CLIENT_SECRET = "client_secret"


class TestOpenIDConnectFrontend(object):
    @pytest.fixture
    def frontend(self, signing_key_path):
        config = {
            "signing_key_path": signing_key_path,
            "provider": {
                "response_types_supported": ["code", "id_token", "code id_token token"],
                "scopes_supported": ["openid", "email"]
            }
        }
        # will use in-memory storage
        instance = OpenIDConnectFrontend(lambda ctx, req: None, INTERNAL_ATTRIBUTES,
                                         config, BASE_URL, "oidc_frontend")
        instance.register_endpoints(["foo_backend"])
        return instance

    @pytest.fixture
    def authn_req(self):
        state = "my_state"
        nonce = "nonce"
        redirect_uri = "https://client.example.com"
        claims_req = ClaimsRequest(id_token=Claims(email=None))
        req = AuthorizationRequest(client_id=CLIENT_ID, state=state, scope="openid",
                                   response_type="id_token", redirect_uri=redirect_uri,
                                   nonce=nonce, claims=claims_req)
        return req

    def insert_client_in_client_db(self, frontend, redirect_uri):
        frontend.provider.clients = {
            CLIENT_ID: {"response_types": ["code", "id_token"],
                        "redirect_uris": [redirect_uri],
                        "client_secret": CLIENT_SECRET}}

    def insert_user_in_user_db(self, frontend, user_id):
        frontend.user_db[user_id] = {"email": "tester@example.com"}

    def create_access_token(self, frontend, user_id, auth_req):
        sub = frontend.provider.authz_state.get_subject_identifier('pairwise', user_id, 'client1.example.com')
        auth_req = AuthorizationRequest().from_dict(auth_req)
        access_token = frontend.provider.authz_state.create_access_token(auth_req, sub)
        return access_token.value

    def setup_for_authn_response(self, context, frontend, auth_req):
        context.state[frontend.name] = {"oidc_request": auth_req.to_urlencoded()}

        auth_info = AuthenticationInformation(PASSWORD, "2015-09-30T12:21:37Z", "unittest_idp.xml")
        internal_response = InternalResponse(auth_info=auth_info)
        internal_response.attributes = AttributeMapper(INTERNAL_ATTRIBUTES).to_internal("saml", USERS["testuser1"])
        internal_response.user_id = USERS["testuser1"]["eduPersonTargetedID"][0]

        return internal_response

    def test_handle_authn_response(self, context, frontend, authn_req):
        self.insert_client_in_client_db(frontend, authn_req["redirect_uri"])
        internal_response = self.setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        assert http_resp.message.startswith(authn_req["redirect_uri"])

        resp = AuthorizationResponse().deserialize(urlparse(http_resp.message).fragment)
        assert resp["state"] == authn_req["state"]
        id_token = IdToken().from_jwt(resp["id_token"], key=[frontend.signing_key])
        assert id_token["iss"] == BASE_URL
        assert id_token["nonce"] == authn_req["nonce"]
        assert id_token["aud"] == [authn_req["client_id"]]
        assert "sub" in id_token
        assert id_token["email"] == USERS["testuser1"]["email"][0]
        assert frontend.name not in context.state

    def test_handle_authn_request(self, context, frontend, authn_req):
        mock_callback = Mock()
        frontend.auth_req_callback_func = mock_callback
        self.insert_client_in_client_db(frontend, authn_req["redirect_uri"])

        context.request = dict(parse_qsl(authn_req.to_urlencoded()))
        frontend.handle_authn_request(context)

        assert mock_callback.call_count == 1
        context, internal_req = mock_callback.call_args[0]
        assert internal_req.requester == authn_req["client_id"]
        assert internal_req.user_id_hash_type == UserIdHashType.pairwise

    def test_handle_backend_error(self, context, frontend):
        redirect_uri = "https://client.example.com"
        areq = AuthorizationRequest(client_id=CLIENT_ID, scope="openid", response_type="id_token",
                                    redirect_uri=redirect_uri)
        context.state[frontend.name] = {"oidc_request": areq.to_urlencoded()}

        # fake an error
        message = "test error"
        error = SATOSAAuthenticationError(context.state, message)
        resp = frontend.handle_backend_error(error)

        assert resp.message.startswith(redirect_uri)
        error_response = AuthorizationErrorResponse().deserialize(urlparse(resp.message).fragment)
        error_response["error"] = "access_denied"
        error_response["error_description"] == message

    def test_register_client(self, context, frontend):
        redirect_uri = "https://client.example.com"
        registration_request = RegistrationRequest(redirect_uris=[redirect_uri],
                                                   response_types=["id_token"])
        context.request = registration_request.to_dict()
        registration_response = frontend.client_registration(context)
        assert registration_response.status == "201 Created"

        reg_resp = RegistrationResponse().deserialize(registration_response.message, "json")
        assert "client_id" in reg_resp
        assert reg_resp["redirect_uris"] == [redirect_uri]
        assert reg_resp["response_types"] == ["id_token"]

    def test_register_client_with_wrong_response_type(self, context, frontend):
        redirect_uri = "https://client.example.com"
        registration_request = RegistrationRequest(redirect_uris=[redirect_uri],
                                                   response_types=["id_token token"])
        context.request = registration_request.to_dict()
        registration_response = frontend.client_registration(context)
        assert registration_response.status == "400 Bad Request"
        error_response = ClientRegistrationErrorResponse().deserialize(
            registration_response.message, "json")
        assert error_response["error"] == "invalid_request"
        assert "response_type" in error_response["error_description"]

    def test_provider_configuration_endpoint(self, context, frontend):
        expected_capabilities = {
            "response_types_supported": ["code", "id_token", "code id_token token"],
            "token_endpoint": BASE_URL + "/foo_backend/token",
            "id_token_signing_alg_values_supported": ["RS256"],
            "response_modes_supported": ["fragment", "query"],
            "subject_types_supported": ["pairwise"],
            "claim_types_supported": ["normal"],
            "claims_parameter_supported": True,
            "request_parameter_supported": False,
            "request_uri_parameter_supported": False,
            "authorization_endpoint": "{}/foo_backend/authorization".format(BASE_URL),
            "scopes_supported": ["openid", "email"],
            "claims_supported": ["email"],
            "grant_types_supported": ["authorization_code", "implicit"],
            "issuer": BASE_URL,
            "require_request_uri_registration": True,
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
            "userinfo_endpoint": "{}/foo_backend/userinfo".format(BASE_URL),
            "version": "3.0"
        }

        http_response = frontend.provider_config(context)
        provider_config = ProviderConfigurationResponse().deserialize(http_response.message, "json")

        assert provider_config.to_dict() == expected_capabilities

    def test_jwks(self, context, frontend):
        http_response = frontend.jwks(context)
        jwks = json.loads(http_response.message)
        assert jwks == {"keys": [frontend.signing_key.serialize()]}

    def test_register_endpoints_token_and_userinfo_endpoint_is_published_if_necessary(self, frontend):
        urls = frontend.register_endpoints(["test"])
        assert ("^{}/{}".format("test", TokenEndpoint.url), frontend.token_endpoint) in urls
        assert ("^{}/{}".format("test", UserinfoEndpoint.url), frontend.userinfo_endpoint) in urls

    def test_register_endpoints_token_and_userinfo_endpoint_is_not_published_if_only_implicit_flow(self,
                                                                                                   signing_key_path,
                                                                                                   context):
        config = {
            "signing_key_path": signing_key_path,
            "provider": {"response_types_supported": ["id_token", "id_token token"]}
        }
        frontend = OpenIDConnectFrontend(lambda ctx, req: None, INTERNAL_ATTRIBUTES,
                                         config, BASE_URL,
                                         "oidc_frontend")

        urls = frontend.register_endpoints(["test"])
        assert ("^{}/{}".format("test", TokenEndpoint.url), frontend.token_endpoint) not in urls
        assert ("^{}/{}".format("test", UserinfoEndpoint.url), frontend.userinfo_endpoint) not in urls

        http_response = frontend.provider_config(context)
        provider_config = ProviderConfigurationResponse().deserialize(http_response.message, "json")
        assert "token_endpoint" not in provider_config

    @pytest.mark.parametrize("client_registration_enabled", [
        True,
        False
    ])
    def test_register_endpoints_dynamic_client_registration_is_configurable(self, signing_key_path,
                                                                            client_registration_enabled):
        config = {"signing_key_path": signing_key_path,
                  "provider": {"client_registration_supported": client_registration_enabled}}
        frontend = OpenIDConnectFrontend(lambda ctx, req: None, INTERNAL_ATTRIBUTES,
                                         config, BASE_URL, "oidc_frontend")

        urls = frontend.register_endpoints(["test"])
        assert (("^{}/{}".format("test", RegistrationEndpoint.url),
                 frontend.client_registration) in urls) == client_registration_enabled
        provider_info = ProviderConfigurationResponse().deserialize(frontend.provider_config(None).message, "json")
        assert ("registration_endpoint" in provider_info) == client_registration_enabled

    def test_token_endpoint(self, context, frontend, authn_req):
        user_id = "test_user"
        self.insert_client_in_client_db(frontend, authn_req["redirect_uri"])
        self.insert_user_in_user_db(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_resp = frontend.provider.authorize(authn_req, user_id)

        context.request = AccessTokenRequest(redirect_uri=authn_req["redirect_uri"], code=authn_resp["code"]).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.token_endpoint(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        assert "access_token" in parsed
        assert "id_token" in parsed

    def test_token_endpoint_with_invalid_client_authentication(self, context, frontend, authn_req):
        context.request = AccessTokenRequest(redirect_uri=authn_req["redirect_uri"], code="code").to_dict()
        credentials = "{}:{}".format("unknown", "unknown")
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.token_endpoint(context)
        parsed_message = TokenErrorResponse().deserialize(response.message, "json")
        assert response.status == "401 Unauthorized"
        assert parsed_message["error"] == "invalid_client"

    def test_token_endpoint_with_invalid_code(self, context, frontend, authn_req):
        self.insert_client_in_client_db(frontend, authn_req["redirect_uri"])
        context.request = AccessTokenRequest(redirect_uri=authn_req["redirect_uri"], code="invalid").to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.token_endpoint(context)
        parsed_message = TokenErrorResponse().deserialize(response.message, "json")
        assert response.status == "400 Bad Request"
        assert parsed_message["error"] == "invalid_grant"

    def test_userinfo_endpoint(self, context, frontend, authn_req):
        user_id = "user1"
        self.insert_client_in_client_db(frontend, authn_req["redirect_uri"])
        self.insert_user_in_user_db(frontend, user_id)

        authn_req["scope"] = "openid email"
        token = self.create_access_token(frontend, user_id, authn_req)
        context.request = {}
        context.request_authorization = "Bearer {}".format(token)
        response = frontend.userinfo_endpoint(context)
        parsed = OpenIDSchema().deserialize(response.message, "json")
        assert parsed["email"] == "tester@example.com"

    def test_userinfo_without_token(self, context, frontend):
        context.request = {}
        context.request_authorization = ""

        response = frontend.userinfo_endpoint(context)
        assert response.status == "401 Unauthorized"

    def test_userinfo_with_invalid_token(self, context, frontend):
        context.request = {}
        context.request_authorization = "Bearer invalid"

        response = frontend.userinfo_endpoint(context)
        assert response.status == "401 Unauthorized"

    def test_full_flow(self, context, frontend):
        redirect_uri = "https://client.example.com/redirect"
        response_type = "code id_token token"
        mock_callback = Mock()
        frontend.auth_req_callback_func = mock_callback
        # discovery
        http_response = frontend.provider_config(context)
        provider_config = ProviderConfigurationResponse().deserialize(http_response.message, "json")

        # client registration
        registration_request = RegistrationRequest(redirect_uris=[redirect_uri], response_types=[response_type])
        context.request = registration_request.to_dict()
        http_response = frontend.client_registration(context)
        registration_response = RegistrationResponse().deserialize(http_response.message, "json")

        # authentication request
        authn_req = AuthorizationRequest(redirect_uri=redirect_uri, client_id=registration_response["client_id"],
                                         response_type=response_type, scope="openid email", state="state",
                                         nonce="nonce")
        context.request = dict(parse_qsl(authn_req.to_urlencoded()))
        frontend.handle_authn_request(context)
        assert mock_callback.call_count == 1

        # fake authentication response from backend
        internal_response = self.setup_for_authn_response(context, frontend, authn_req)
        http_response = frontend.handle_authn_response(context, internal_response)
        authn_resp = AuthorizationResponse().deserialize(urlparse(http_response.message).fragment, "urlencoded")
        assert "code" in authn_resp
        assert "access_token" in authn_resp
        assert "id_token" in authn_resp

        # token request
        context.request = AccessTokenRequest(redirect_uri=authn_req["redirect_uri"], code=authn_resp["code"]).to_dict()
        credentials = "{}:{}".format(registration_response["client_id"], registration_response["client_secret"])
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        http_response = frontend.token_endpoint(context)
        parsed = AccessTokenResponse().deserialize(http_response.message, "json")
        assert "access_token" in parsed
        assert "id_token" in parsed

        # userinfo request
        context.request = {}
        context.request_authorization = "Bearer {}".format(parsed["access_token"])
        http_response = frontend.userinfo_endpoint(context)
        parsed = OpenIDSchema().deserialize(http_response.message, "json")
        assert "email" in parsed


class TestOidcSubjectTypeToHashType:
    def test_should_default_to_pairwise(self):
        assert oidc_subject_type_to_hash_type("foobar") == UserIdHashType.pairwise

    def test_should_map_pairwise(self):
        assert oidc_subject_type_to_hash_type("pairwise") == UserIdHashType.pairwise

    def test_should_map_pairwise(self):
        assert oidc_subject_type_to_hash_type("public") == UserIdHashType.public
