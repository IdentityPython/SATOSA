import json
from unittest.mock import Mock

import pytest
import requests
import responses
from jwkest.jwk import rsa_load, RSAKey
from jwkest.jws import JWS

from satosa.account_linking import AccountLinkingModule
from satosa.context import Context
from satosa.exception import SATOSAAuthenticationError
from satosa.internal_data import InternalResponse, AuthenticationInformation
from satosa.response import Redirect
from satosa.satosa_config import SATOSAConfig
from satosa.state import State


class TestAccountLinking():
    @pytest.fixture(autouse=True)
    def setup(self, signing_key_path):
        self.account_linking_config = {
            "enable": True,
            "api_url": "https://localhost:8167",
            "redirect_url": "https://localhost:8167/approve",
            "sign_key": signing_key_path,
        }
        self.satosa_config = {
            "BASE": "https://proxy.example.com",
            "USER_ID_HASH_SALT": "qwerty",
            "COOKIE_STATE_NAME": "SATOSA_SATE",
            "STATE_ENCRYPTION_KEY": "ASDasd123",
            "BACKEND_MODULES": "",
            "FRONTEND_MODULES": "",
            "INTERNAL_ATTRIBUTES": {"attributes": {}},
            "ACCOUNT_LINKING": self.account_linking_config
        }
        self.callback_func = Mock()
        self.context = Context()
        state = State()
        self.context.state = state
        auth_info = AuthenticationInformation("auth_class_ref", "timestamp", "issuer")
        self.internal_response = InternalResponse(auth_info=auth_info)

    def test_disable_account_linking(self):
        self.account_linking_config['enable'] = False
        account_linking = AccountLinkingModule(SATOSAConfig(self.satosa_config), self.callback_func)
        account_linking.manage_al(None, None)
        assert self.callback_func.called

    @responses.activate
    def test_existing_account_linking_with_known_known_uuid(self):
        uuid = "uuid"
        data = {
            "idp": self.internal_response.auth_info.issuer,
            "id": self.internal_response.get_user_id(),
            "redirect_endpoint": self.satosa_config["BASE"] + "/account_linking/handle_account_linking"
        }
        key = RSAKey(key=rsa_load(self.satosa_config["ACCOUNT_LINKING"]["sign_key"]), use="sig", alg="RS256")
        jws = JWS(json.dumps(data), alg=key.alg).sign_compact([key])
        responses.add(
            responses.GET,
            "%s/get_id?jwt=%s" % (self.account_linking_config['api_url'], jws),
            status=200,
            body=uuid,
            content_type='text/html',
            match_querystring=True
        )

        account_linking = AccountLinkingModule(SATOSAConfig(self.satosa_config), self.callback_func)
        account_linking.manage_al(self.context, self.internal_response)
        assert self.internal_response.get_user_id() == uuid

    @responses.activate
    def test_unknown_uuid_requiring_new_account_linking(self):
        ticket = "ticket"
        responses.add(
            responses.GET,
            "%s/get_id" % self.account_linking_config['api_url'],
            status=404,
            body=ticket,
            content_type='text/html'
        )
        account_linking = AccountLinkingModule(SATOSAConfig(self.satosa_config), self.callback_func)
        result = account_linking.manage_al(self.context, self.internal_response)
        assert isinstance(result, Redirect)
        assert result.message.startswith(self.account_linking_config["redirect_url"])

    @responses.activate
    def test_handle_failed_connection(self):
        exception = requests.ConnectionError("No connection")
        responses.add(responses.GET, "%s/get_id" % self.account_linking_config['api_url'],
                      body=exception)
        account_linking = AccountLinkingModule(SATOSAConfig(self.satosa_config), self.callback_func)

        with pytest.raises(SATOSAAuthenticationError):
            account_linking.manage_al(self.context, self.internal_response)
