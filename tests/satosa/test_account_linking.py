import json
from unittest.mock import Mock

import pytest
import requests
import responses
from jwkest.jwk import rsa_load, RSAKey
from jwkest.jws import JWS

from satosa.account_linking import AccountLinkingModule
from satosa.exception import SATOSAAuthenticationError
from satosa.internal_data import InternalResponse, AuthenticationInformation
from satosa.response import Redirect
from satosa.satosa_config import SATOSAConfig


class TestAccountLinking():
    @pytest.fixture
    def internal_response(self):
        auth_info = AuthenticationInformation("auth_class_ref", "timestamp", "issuer")
        internal_response = InternalResponse(auth_info=auth_info)
        internal_response.user_id = "user1"
        return internal_response

    @pytest.fixture
    def satosa_config(self, signing_key_path):
        account_linking_config = {
            "enable": True,
            "api_url": "https://localhost:8167",
            "redirect_url": "https://localhost:8167/approve",
            "sign_key": signing_key_path,
        }
        satosa_config = {
            "BASE": "https://proxy.example.com",
            "USER_ID_HASH_SALT": "qwerty",
            "COOKIE_STATE_NAME": "SATOSA_SATE",
            "STATE_ENCRYPTION_KEY": "ASDasd123",
            "BACKEND_MODULES": "",
            "FRONTEND_MODULES": "",
            "INTERNAL_ATTRIBUTES": {"attributes": {}},
            "ACCOUNT_LINKING": account_linking_config
        }

        return SATOSAConfig(satosa_config)

    @pytest.fixture(autouse=True)
    def create_account_linking(self, satosa_config):
        self.mock_callback = Mock(side_effect=lambda context, internal_resp: (context, internal_resp))
        self.account_linking = AccountLinkingModule(satosa_config, self.mock_callback)

    def test_disable_account_linking(self, satosa_config):
        satosa_config["ACCOUNT_LINKING"]["enable"] = False
        account_linking = AccountLinkingModule(satosa_config, self.mock_callback)
        assert account_linking.enabled == False
        assert not hasattr(account_linking, "proxy_base")
        account_linking.manage_al(None, None)
        assert self.mock_callback.called

    @responses.activate
    def test_existing_account_linking_with_known_known_uuid(self, satosa_config, internal_response, context):
        uuid = "uuid"
        data = {
            "idp": internal_response.auth_info.issuer,
            "id": internal_response.user_id,
            "redirect_endpoint": satosa_config["BASE"] + "/account_linking/handle_account_linking"
        }
        key = RSAKey(key=rsa_load(satosa_config["ACCOUNT_LINKING"]["sign_key"]), use="sig", alg="RS256")
        jws = JWS(json.dumps(data), alg=key.alg).sign_compact([key])
        responses.add(
            responses.GET,
            "%s/get_id?jwt=%s" % (satosa_config["ACCOUNT_LINKING"]["api_url"], jws),
            status=200,
            body=uuid,
            content_type="text/html",
            match_querystring=True
        )

        self.account_linking.manage_al(context, internal_response)
        assert internal_response.user_id == uuid

    def test_full_flow(self, satosa_config, internal_response, context):
        ticket = "ticket"
        with responses.RequestsMock() as rsps:
            rsps.add(
                responses.GET,
                "%s/get_id" % satosa_config["ACCOUNT_LINKING"]["api_url"],
                status=404,
                body=ticket,
                content_type="text/html"
            )
            result = self.account_linking.manage_al(context, internal_response)
        assert isinstance(result, Redirect)
        assert result.message.startswith(satosa_config["ACCOUNT_LINKING"]["redirect_url"])

        data = {
            "idp": internal_response.auth_info.issuer,
            "id": internal_response.user_id,
            "redirect_endpoint": satosa_config["BASE"] + "/account_linking/handle_account_linking"
        }
        key = RSAKey(key=rsa_load(satosa_config["ACCOUNT_LINKING"]["sign_key"]), use="sig", alg="RS256")
        jws = JWS(json.dumps(data), alg=key.alg).sign_compact([key])
        uuid = "uuid"
        with responses.RequestsMock() as rsps:
            # account is linked, 200 OK
            rsps.add(
                responses.GET,
                "%s/get_id?jwt=%s" % (satosa_config["ACCOUNT_LINKING"]["api_url"], jws),
                status=200,
                body=uuid,
                content_type="text/html",
                match_querystring=True
            )
            context, internal_response = self.account_linking._handle_al_response(context)
        assert internal_response.user_id == uuid

    @responses.activate
    def test_handle_failed_connection(self, satosa_config, internal_response, context):
        exception = requests.ConnectionError("No connection")
        responses.add(responses.GET, "%s/get_id" % satosa_config["ACCOUNT_LINKING"]["api_url"],
                      body=exception)

        with pytest.raises(SATOSAAuthenticationError):
            self.account_linking.manage_al(context, internal_response)
