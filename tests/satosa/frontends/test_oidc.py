"""
Tests for the SAML frontend module src/frontends/saml2.py.
"""
import os
from urllib.parse import urlparse

import pytest
from oic.oic.message import AuthorizationResponse, AuthorizationRequest, IdToken, ClaimsRequest, \
    Claims, AuthorizationErrorResponse, RegistrationResponse, RegistrationRequest, \
    ClientRegistrationErrorResponse, ProviderConfigurationResponse
from oic.utils.keyio import create_and_store_rsa_key_pair
from saml2.authn_context import PASSWORD

from satosa.context import Context
from satosa.exception import SATOSAAuthenticationError
from satosa.frontends.oidc import OIDCFrontend
from satosa.internal_data import InternalResponse, AuthenticationInformation, DataConverter
from satosa.state import State
from tests.users import USERS

INTERNAL_ATTRIBUTES = {
    'attributes': {'mail': {'saml': ['email'], 'openid': ['email']}}
}


@pytest.fixture
def signing_key(tmpdir):
    filename = "key"
    create_and_store_rsa_key_pair(filename, str(tmpdir), 1024)
    return os.path.join(str(tmpdir), filename)


class TestOIDCFrontend(object):
    ISSUER = "https://op.example.com"

    @pytest.fixture(autouse=True)
    def setup(self, signing_key):
        self.instance = OIDCFrontend(lambda ctx, req: None, INTERNAL_ATTRIBUTES,
                                     dict(issuer=self.ISSUER, signing_key_path=signing_key))
        self.instance.register_endpoints(["foo_backend"])

    def create_state(self, auth_req):
        state = State()
        state.add(type(self.instance).__name__, {"oidc_request": auth_req.to_urlencoded()})
        return state

    def setup_for_authn_response(self, auth_req):
        context = Context()
        context.state = self.create_state(auth_req)

        auth_info = AuthenticationInformation(PASSWORD, "2015-09-30T12:21:37Z", "unittest_idp.xml")
        internal_response = InternalResponse(auth_info=auth_info)
        internal_response.add_attributes(
            DataConverter(INTERNAL_ATTRIBUTES).to_internal("saml", USERS["testuser1"]))
        internal_response.set_user_id(USERS["testuser1"]["eduPersonTargetedID"][0])

        self.instance.provider.cdb = {
            "client1": {"response_types": ["id_token"],
                        "redirect_uris": [(auth_req["redirect_uri"], None)],
                        "client_salt": "salt"}}

        return context, internal_response

    def test_handle_authn_response(self):
        client_id = "client1"
        state = "my_state"
        nonce = "nonce"
        redirect_uri = "https://client.example.com"
        claims_req = ClaimsRequest(id_token=Claims(email=None))
        req = AuthorizationRequest(client_id=client_id, state=state, scope="openid",
                                   response_type="id_token",
                                   redirect_uri=redirect_uri,
                                   nonce=nonce,
                                   claims=claims_req)
        context, internal_response = self.setup_for_authn_response(req)
        http_resp = self.instance.handle_authn_response(context, internal_response)
        assert http_resp.message.startswith(redirect_uri)

        resp = AuthorizationResponse().deserialize(urlparse(http_resp.message).fragment)
        assert resp["state"] == state
        id_token = IdToken().from_jwt(resp["id_token"], keyjar=self.instance.provider.keyjar)
        assert id_token["iss"] == self.ISSUER
        assert id_token["nonce"] == nonce
        assert id_token["sub"] == USERS["testuser1"]["eduPersonTargetedID"][0]
        assert id_token["email"] == USERS["testuser1"]["email"][0]

    def test_get_authn_response_query_encoded(self):
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
        context, internal_response = self.setup_for_authn_response(req)
        http_resp = self.instance.handle_authn_response(context, internal_response)
        assert http_resp.message.startswith(redirect_uri)

        resp = AuthorizationResponse().deserialize(urlparse(http_resp.message).query)
        assert resp["state"] == state
        id_token = IdToken().from_jwt(resp["id_token"], keyjar=self.instance.provider.keyjar)
        assert id_token["iss"] == self.ISSUER
        assert id_token["nonce"] == nonce
        assert id_token["sub"] == USERS["testuser1"]["eduPersonTargetedID"][0]
        assert id_token["email"] == USERS["testuser1"]["email"][0]

    def test_handle_backend_error(self):
        client_id = "client1"
        redirect_uri = "https://client.example.com"
        areq = AuthorizationRequest(client_id=client_id, scope="openid", response_type="id_token",
                                    redirect_uri=redirect_uri)

        message = "test error"
        error = SATOSAAuthenticationError(self.create_state(areq), message)
        resp = self.instance.handle_backend_error(error)
        assert resp.message.startswith(redirect_uri)
        error_response = AuthorizationErrorResponse().deserialize(urlparse(resp.message).fragment)
        error_response["error"] = "access_denied"
        error_response["error_description"] == message

    def test_register_client(self):
        redirect_uri = "https://client.example.com"
        registration_request = RegistrationRequest(redirect_uris=[redirect_uri],
                                                   response_types=["id_token"])
        context = Context()
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

    def test_register_client_with_wrong_response_type(self):
        redirect_uri = "https://client.example.com"
        registration_request = RegistrationRequest(redirect_uris=[redirect_uri],
                                                   response_types=["code"])
        context = Context()
        context.request = registration_request.to_dict()
        registration_response = self.instance._register_client(context)
        assert registration_response.status == "400 Bad Request"
        error_response = ClientRegistrationErrorResponse().deserialize(
            registration_response.message, "json")
        assert error_response["error"] == "invalid_request"
        assert "response_type" in error_response["error_description"]

    def test_provider_configuration_endpoint(self):
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

        http_response = self.instance._provider_config(Context())
        provider_config = ProviderConfigurationResponse().deserialize(http_response.message, "json")
        assert all(
            item in provider_config.to_dict().items() for item in expected_capabilities.items())
        assert provider_config["authorization_endpoint"] == "{}/foo_backend/authorization".format(self.ISSUER)
