"""
Tests for the SAML frontend module src/frontends/saml2.py.
"""
from urllib.parse import urlparse

import pytest
from oic.oic.message import AuthorizationResponse, AuthorizationRequest, IdToken, ClaimsRequest, \
    Claims, AuthorizationErrorResponse, RegistrationResponse, RegistrationRequest, \
    ClientRegistrationErrorResponse, ProviderConfigurationResponse
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


class TestOpenIDConnectFrontend(object):
    @pytest.fixture(autouse=True)
    def setup(self, signing_key_path):
        self.instance = OpenIDConnectFrontend(lambda ctx, req: None, INTERNAL_ATTRIBUTES,
                                              dict(signing_key_path=signing_key_path), BASE_URL,
                                              "oidc_frontend")
        self.instance.register_endpoints(["foo_backend"])

    @pytest.fixture
    def authn_req(self):
        client_id = "client1"
        state = "my_state"
        nonce = "nonce"
        redirect_uri = "https://client.example.com"
        claims_req = ClaimsRequest(id_token=Claims(email=None))
        req = AuthorizationRequest(client_id=client_id, state=state, scope="openid",
                                   response_type="id_token", redirect_uri=redirect_uri,
                                   nonce=nonce, claims=claims_req)
        return req

    def setup_for_authn_response(self, context, auth_req):
        context.state[self.instance.name] = {"oidc_request": auth_req.to_urlencoded()}

        auth_info = AuthenticationInformation(PASSWORD, "2015-09-30T12:21:37Z", "unittest_idp.xml")
        internal_response = InternalResponse(auth_info=auth_info)
        internal_response.attributes = AttributeMapper(INTERNAL_ATTRIBUTES).to_internal("saml", USERS["testuser1"])
        internal_response.user_id = USERS["testuser1"]["eduPersonTargetedID"][0]

        self.instance.cdb = {
            "client1": {"response_types": ["id_token"],
                        "redirect_uris": [(auth_req["redirect_uri"], None)],
                        "client_salt": "salt"}}

        return internal_response

    def test_handle_authn_response(self, context, authn_req):
        internal_response = self.setup_for_authn_response(context, authn_req)
        http_resp = self.instance.handle_authn_response(context, internal_response)
        assert http_resp.message.startswith(authn_req["redirect_uri"])

        resp = AuthorizationResponse().deserialize(urlparse(http_resp.message).fragment)
        assert resp["state"] == authn_req["state"]
        id_token = IdToken().from_jwt(resp["id_token"], key=[self.instance.signing_key])
        assert id_token["iss"] == BASE_URL
        assert id_token["nonce"] == authn_req["nonce"]
        assert id_token["aud"] == [authn_req["client_id"]]
        assert id_token["sub"] == USERS["testuser1"]["eduPersonTargetedID"][0]
        assert id_token["email"] == USERS["testuser1"]["email"][0]
        assert self.instance.name not in context.state

    def test_get_authn_response_query_encoded(self, context):
        client_id = "client1"
        state = "my_state"
        nonce = "nonce"
        redirect_uri = "https://client.example.com"
        claims_req = ClaimsRequest(id_token=Claims(email=None))
        req = AuthorizationRequest(client_id=client_id, state=state, scope="openid",
                                   response_type="id_token",
                                   redirect_uri=redirect_uri,
                                   nonce=nonce,
                                   claims=claims_req,
                                   response_mode="query")
        internal_response = self.setup_for_authn_response(context, req)
        http_resp = self.instance.handle_authn_response(context, internal_response)
        assert http_resp.message.startswith(redirect_uri)

        resp = AuthorizationResponse().deserialize(urlparse(http_resp.message).query)
        assert resp["state"] == state
        id_token = IdToken().from_jwt(resp["id_token"], key=[self.instance.signing_key])
        assert id_token["iss"] == BASE_URL
        assert id_token["nonce"] == nonce
        assert id_token["sub"] == USERS["testuser1"]["eduPersonTargetedID"][0]
        assert id_token["email"] == USERS["testuser1"]["email"][0]

    def test_handle_backend_error(self, context):
        client_id = "client1"
        redirect_uri = "https://client.example.com"
        areq = AuthorizationRequest(client_id=client_id, scope="openid", response_type="id_token",
                                    redirect_uri=redirect_uri)
        context.state[self.instance.name] = {"oidc_request": areq.to_urlencoded()}

        # fake an error
        message = "test error"
        error = SATOSAAuthenticationError(context.state, message)
        resp = self.instance.handle_backend_error(error)

        assert resp.message.startswith(redirect_uri)
        error_response = AuthorizationErrorResponse().deserialize(urlparse(resp.message).fragment)
        error_response["error"] = "access_denied"
        error_response["error_description"] == message

    def test_register_client(self, context):
        redirect_uri = "https://client.example.com"
        registration_request = RegistrationRequest(redirect_uris=[redirect_uri],
                                                   response_types=["id_token"])
        context.request = registration_request.to_dict()
        registration_response = self.instance._register_client(context)
        assert registration_response.status == "201 Created"

        reg_resp = RegistrationResponse().deserialize(registration_response.message, "json")
        assert "client_id" in reg_resp
        assert reg_resp["client_id"] in self.instance.provider.cdb
        # no need to issue client secret since to token endpoint is published
        assert "client_secret" not in reg_resp
        assert reg_resp["redirect_uris"] == [redirect_uri]
        assert reg_resp["response_types"] == ["id_token"]
        assert reg_resp["id_token_signed_response_alg"] == "RS256"

    def test_register_client_with_wrong_response_type(self, context):
        redirect_uri = "https://client.example.com"
        registration_request = RegistrationRequest(redirect_uris=[redirect_uri],
                                                   response_types=["code"])
        context.request = registration_request.to_dict()
        registration_response = self.instance._register_client(context)
        assert registration_response.status == "400 Bad Request"
        error_response = ClientRegistrationErrorResponse().deserialize(
            registration_response.message, "json")
        assert error_response["error"] == "invalid_request"
        assert "response_type" in error_response["error_description"]

    def test_provider_configuration_endpoint(self, context):
        expected_capabilities = {
            "response_types_supported": ["id_token"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "response_modes_supported": ["fragment", "query"],
            "subject_types_supported": ["public", "pairwise"],
            "grant_types_supported": ["implicit"],
            "claim_types_supported": ["normal"],
            "claims_parameter_supported": True,
            "request_parameter_supported": False,
            "request_uri_parameter_supported": False,
        }

        http_response = self.instance._provider_config(context)
        provider_config = ProviderConfigurationResponse().deserialize(http_response.message, "json")
        assert all(
            item in provider_config.to_dict().items() for item in expected_capabilities.items())
        assert provider_config["authorization_endpoint"] == "{}/foo_backend/authorization".format(BASE_URL)


class TestOidcSubjectTypeToHashType:
    def test_should_default_to_pairwise(self):
        assert oidc_subject_type_to_hash_type("foobar") == UserIdHashType.pairwise

    def test_should_map_pairwise(self):
        assert oidc_subject_type_to_hash_type("pairwise") == UserIdHashType.pairwise

    def test_should_map_pairwise(self):
        assert oidc_subject_type_to_hash_type("public") == UserIdHashType.public
