import json
import re
import time
from unittest.mock import Mock
from urllib.parse import parse_qsl
from urllib.parse import urlparse

import pytest
import responses
from cryptojwt.key_jar import build_keyjar

idpyoidc = pytest.importorskip('idpyoidc')

from idpyoidc.client.oauth2.stand_alone_client import StandAloneClient
from idpyoidc.message.oidc import IdToken

from satosa.backends.idpy_oidc import create_client
from satosa.backends.idpy_oidc import IdpyOIDCBackend
from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Response

ISSUER = "https://provider.example.com"
CLIENT_ID = "test_client"
NONCE = "the nonce"

NONCE_KEY = "oidc_nonce"
STATE_KEY = "oidc_state"

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]


class TestOpenIDConnectBackend(object):

    @pytest.fixture(autouse=True)
    def create_backend(self, internal_attributes, backend_config):
        self.oidc_backend = IdpyOIDCBackend(Mock(), internal_attributes, backend_config,
                                            "base_url", "idpy_oidc")
        self.issuer_keyjar = build_keyjar(KEYDEFS, issuer_id=ISSUER)
        self.oidc_backend.client.keyjar.import_jwks(
            self.issuer_keyjar.export_jwks(issuer_id=ISSUER),
            ISSUER
        )

    @pytest.fixture
    def internal_attributes(self):
        return {
            "attributes": {
                "givenname": {"openid": ["given_name"]},
                "mail": {"openid": ["email"]},
                "edupersontargetedid": {"openid": ["sub"]},
                "surname": {"openid": ["family_name"]}
            }
        }

    @pytest.fixture
    def backend_config(self):
        return {
            "client": {
                "client_id": CLIENT_ID,
                "client_secret": "ZJYCqe3GGRvdrudKyZS0XhGv_Z45DuKhCUk0gBR1vZk",
                "application_type": "web",
                "application_name": "SATOSA Test",
                "contacts": ["ops@example.com"],
                "redirect_uris": ["https://client.test.com/authz_cb"],
                "response_types_supported": ["code"],
                "subject_types_supported": "pairwise",
                # "response_type": "code id_token token",
                "scopes_supported": ["openid", "foo"],
                "provider_info": {
                    "issuer": ISSUER,
                    "authorization_endpoint": ISSUER + "/authorization",
                    "token_endpoint": ISSUER + "/token",
                    "userinfo_endpoint": ISSUER + "/userinfo",
                    "registration_endpoint": ISSUER + "/registration",
                    "jwks_uri": ISSUER + "/static/jwks"
                }
            }
        }

    @pytest.fixture
    def userinfo(self):
        return {
            "given_name": "Test",
            "family_name": "Devsson",
            "email": "test_dev@example.com",
            "sub": "username"
        }

    @pytest.fixture
    def signing_key(self):
        return self.issuer_keyjar.get_signing_key("rsa", issuer_id=ISSUER)[0]

    def assert_expected_attributes(self, attr_map, user_claims, actual_attributes):
        expected_attributes = {}
        for out_attr, in_mapping in attr_map["attributes"].items():
            expected_attributes[out_attr] = [user_claims[in_mapping["openid"][0]]]

        assert actual_attributes == expected_attributes

    def setup_token_endpoint(self, token_endpoint_url, userinfo, signing_key):
        id_token_claims = {
            "iss": ISSUER,
            "sub": userinfo["sub"],
            "aud": CLIENT_ID,
            "nonce": NONCE,
            "exp": time.time() + 3600,
            "iat": time.time()
        }
        id_token = IdToken(**id_token_claims).to_jwt(key=[signing_key], algorithm="RS256")
        token_response = {
            "access_token": "SlAV32hkKG",
            "token_type": "Bearer",
            "refresh_token": "8xLOxBtZp8",
            "expires_in": 3600,
            "id_token": id_token
        }
        responses.add(responses.POST,
                      token_endpoint_url,
                      body=json.dumps(token_response),
                      status=200,
                      content_type="application/json")

    def setup_userinfo_endpoint(self, userinfo_endpoint_url, userinfo):
        responses.add(responses.GET,
                      userinfo_endpoint_url,
                      body=json.dumps(userinfo),
                      status=200,
                      content_type="application/json")

    def get_redirect_uri_path(self, backend_config):
        return urlparse(
            backend_config["client"]["redirect_uris"][0]).path.lstrip("/")

    @pytest.fixture
    def incoming_authn_response(self, context, backend_config):
        oidc_state = "my state"
        context.path = self.get_redirect_uri_path(backend_config)
        context.request = {
            "code": "F+R4uWbN46U+Bq9moQPC4lEvRd2De4o=",
            "state": oidc_state
        }

        # Set state
        _client_context = self.oidc_backend.client.get_context()
        _client_context.cstate.set(
            'my state',
            {
                'iss': ISSUER,
                "response_type": "code",
                "redirect_uri": backend_config["client"]["redirect_uris"][0],
                "nonce": NONCE
            }
        )
        _client_context.cstate.bind_key(NONCE, "my state")
        return context

    def test_register_endpoints(self, backend_config):
        redirect_uri_path = self.get_redirect_uri_path(backend_config)
        url_map = self.oidc_backend.register_endpoints()
        regex, callback = url_map[0]
        assert re.search(regex, redirect_uri_path)
        assert callback == self.oidc_backend.response_endpoint

    def test_translate_response_to_internal_response(self, internal_attributes, userinfo):
        internal_response = self.oidc_backend._translate_response(userinfo, ISSUER)
        assert internal_response.subject_id == userinfo["sub"]
        self.assert_expected_attributes(internal_attributes, userinfo,
                                        internal_response.attributes)

    @responses.activate
    def test_response_endpoint(self, backend_config, internal_attributes, userinfo, signing_key,
                               incoming_authn_response):
        self.setup_token_endpoint(backend_config["client"]["provider_info"]["token_endpoint"],
                                  userinfo,
                                  signing_key)
        self.setup_userinfo_endpoint(backend_config["client"]["provider_info"]["userinfo_endpoint"],
                                     userinfo)

        self.oidc_backend.response_endpoint(incoming_authn_response)
        assert self.oidc_backend.name not in incoming_authn_response.state

        args = self.oidc_backend.auth_callback_func.call_args[0]
        assert isinstance(args[0], Context)
        assert isinstance(args[1], InternalData)
        self.assert_expected_attributes(internal_attributes, userinfo, args[1].attributes)

    def test_start_auth_redirects_to_provider_authorization_endpoint(self, context,
                                                                     backend_config):
        auth_response = self.oidc_backend.start_auth(context, None)
        assert isinstance(auth_response, Response)

        login_url = auth_response.message
        parsed = urlparse(login_url)
        _client_config = backend_config["client"]
        assert login_url.startswith(_client_config["provider_info"]["authorization_endpoint"])
        auth_params = dict(parse_qsl(parsed.query))
        assert auth_params["scope"] == " ".join(_client_config["scopes_supported"])
        assert auth_params["response_type"] in _client_config["response_types_supported"]
        assert auth_params["client_id"] == _client_config["client_id"]
        assert auth_params["redirect_uri"] == _client_config["redirect_uris"][0]
        assert "state" in auth_params
        assert "nonce" in auth_params


class TestBackendConfiguration(object):

    def create_config(self, client_metadata, provider_metadata=None):
        _config = client_metadata.copy()
        if provider_metadata:
            _config['provider_info'] = provider_metadata
        return _config

    @pytest.fixture
    def internal_attributes(self):
        return {
            "attributes": {
                "givenname": {"openid": ["given_name"]},
                "mail": {"openid": ["email"]},
                "edupersontargetedid": {"openid": ["sub"]},
                "surname": {"openid": ["family_name"]}
            }
        }

    @pytest.fixture
    def provider_metadata(self):
        return {
            "issuer": ISSUER,
            "authorization_endpoint": ISSUER + "/authorization",
            "token_endpoint": ISSUER + "/token",
            "registration_endpoint": ISSUER + "/registration",
            "jwks_uri": ISSUER + "/jwks.json",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public", "pairwise"],
            "id_token_signing_alg_values_supported": ["RS256"]
        }

    @pytest.fixture
    def client_metadata(self):
        return {
            "client_id": "s6BhdRkqt3",
            "client_secret": "ZJYCqe3GGRvdrudKyZS0XhGv_Z45DuKhCUk0gBR1vZk",
            "application_type": "web",
            "redirect_uris":
                ["https://client.example.org/callback",
                 "https://client.example.org/callback2"],
            "client_name": "SATOSA Test",
            "logo_uri": "https://client.example.org/logo.png",
            "subject_types_supported": ["pairwise"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
            "jwks_uri": "https://client.example.org/my_public_keys.jwks",
            "contacts": ["ve7jtb@example.org", "mary@example.org"],
        }

    def assert_provider_metadata(self, provider_metadata, client):
        _provider_info = client.get_context().provider_info
        assert _provider_info["authorization_endpoint"] == provider_metadata[
            "authorization_endpoint"]
        assert _provider_info["token_endpoint"] == provider_metadata["token_endpoint"]
        assert _provider_info["registration_endpoint"] == provider_metadata["registration_endpoint"]
        assert all(x in _provider_info for x in provider_metadata.keys())

    def assert_client_metadata(self, client_metadata, client):
        _use = client.get_context().claims.use
        for key in ["client_id", "client_secret", "client_name", "application_type", "logo_uri",
                    "contacts"]:
            assert _use[key] == client_metadata[key]

    def test_init(self, client_metadata, provider_metadata):
        client = create_client(self.create_config(client_metadata, provider_metadata))
        assert isinstance(client, StandAloneClient)

    def test_supports_static_provider_discovery(self, client_metadata, provider_metadata):
        client = create_client(self.create_config(client_metadata, provider_metadata))
        self.assert_provider_metadata(provider_metadata, client)

    @responses.activate
    def test_supports_dynamic_discovery(self, client_metadata, provider_metadata):
        responses.add(
            responses.GET,
            ISSUER + "/.well-known/openid-configuration",
            body=json.dumps(provider_metadata),
            status=200,
            content_type='application/json'
        )
        _client_config = client_metadata
        _client_config["issuer"] = provider_metadata['issuer']
        client = create_client(self.create_config(client_metadata))
        self.assert_provider_metadata(provider_metadata, client)

    def test_supports_static_client_registration(self, client_metadata, provider_metadata):
        client = create_client(self.create_config(client_metadata, provider_metadata))
        self.assert_client_metadata(client_metadata, client)

    def test_supports_dynamic_client_registration(self, client_metadata, provider_metadata):
        with responses.RequestsMock(assert_all_requests_are_fired=True) as rsps:
            rsps.add(
                responses.POST,
                provider_metadata["registration_endpoint"],
                body=json.dumps(client_metadata),
                status=200,
                content_type='application/json'
            )
            _client_metadata = {
                "redirect_uris": client_metadata["redirect_uris"]}
            client = create_client(self.create_config(_client_metadata, provider_metadata))

        self.assert_client_metadata(client_metadata, client)
