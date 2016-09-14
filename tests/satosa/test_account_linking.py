import json
import re
from unittest.mock import Mock

import pytest
import requests
import responses
from jwkest.jwk import rsa_load, RSAKey
from jwkest.jws import JWS

from satosa.exception import SATOSAAuthenticationError
from satosa.internal_data import InternalResponse, AuthenticationInformation
from satosa.micro_services.account_linking import AccountLinking
from satosa.response import Redirect


class TestAccountLinking():
    @pytest.fixture
    def internal_response(self):
        auth_info = AuthenticationInformation("auth_class_ref", "timestamp", "issuer")
        internal_response = InternalResponse(auth_info=auth_info)
        internal_response.user_id = "user1"
        return internal_response

    @pytest.fixture
    def account_linking_config(self, signing_key_path):
        return {
            "api_url": "http://account.example.com/api",
            "redirect_url": "http://account.example.com/redirect",
            "sign_key": signing_key_path,
        }

    @pytest.fixture(autouse=True)
    def create_account_linking(self, account_linking_config):
        self.account_linking = AccountLinking(account_linking_config, name="AccountLinking",
                                              base_url="https://satosa.example.com")
        self.account_linking.next = lambda ctx, data: data

    def test_disable_account_linking(self, account_linking_config):
        account_linking_config["enable"] = False
        account_linking = AccountLinking(account_linking_config, name="AccountLinking",
                                         base_url="https://satosa.example.com")
        mock_next_callback = Mock()
        account_linking.next = mock_next_callback
        assert account_linking.enabled is False
        account_linking.process(None, None)
        assert mock_next_callback.called

    @responses.activate
    def test_existing_account_linking_with_known_known_uuid(self, account_linking_config, internal_response, context):
        uuid = "uuid"
        data = {
            "idp": internal_response.auth_info.issuer,
            "id": internal_response.user_id,
            "redirect_endpoint": self.account_linking.base_url + "/account_linking/handle_account_linking"
        }
        key = RSAKey(key=rsa_load(account_linking_config["sign_key"]), use="sig", alg="RS256")
        jws = JWS(json.dumps(data), alg=key.alg).sign_compact([key])
        responses.add(
            responses.GET,
            "%s/get_id?jwt=%s" % (account_linking_config["api_url"], jws),
            status=200,
            body=uuid,
            content_type="text/html",
            match_querystring=True
        )

        self.account_linking.process(context, internal_response)
        assert internal_response.user_id == uuid

    def test_full_flow(self, account_linking_config, internal_response, context):
        ticket = "ticket"
        with responses.RequestsMock() as rsps:
            rsps.add(
                responses.GET,
                "%s/get_id" % account_linking_config["api_url"],
                status=404,
                body=ticket,
                content_type="text/html"
            )
            result = self.account_linking.process(context, internal_response)
        assert isinstance(result, Redirect)
        assert result.message.startswith(account_linking_config["redirect_url"])

        data = {
            "idp": internal_response.auth_info.issuer,
            "id": internal_response.user_id,
            "redirect_endpoint": self.account_linking.base_url + "/account_linking/handle_account_linking"
        }
        key = RSAKey(key=rsa_load(account_linking_config["sign_key"]), use="sig", alg="RS256")
        jws = JWS(json.dumps(data), alg=key.alg).sign_compact([key])
        uuid = "uuid"
        with responses.RequestsMock() as rsps:
            # account is linked, 200 OK
            rsps.add(
                responses.GET,
                "%s/get_id?jwt=%s" % (account_linking_config["api_url"], jws),
                status=200,
                body=uuid,
                content_type="text/html",
                match_querystring=True
            )
            internal_response = self.account_linking._handle_al_response(context)
        assert internal_response.user_id == uuid

    @responses.activate
    def test_account_linking_failed(self, account_linking_config, internal_response, context):
        ticket = "ticket"
        responses.add(
            responses.GET,
            "%s/get_id" % account_linking_config["api_url"],
            status=404,
            body=ticket,
            content_type="text/html"
        )

        result = self.account_linking.process(context, internal_response)
        assert isinstance(result, Redirect)
        assert result.message.startswith(account_linking_config["redirect_url"])

        # account linking endpoint still does not return an id
        with pytest.raises(SATOSAAuthenticationError):
            self.account_linking._handle_al_response(context)

    @responses.activate
    def test_manage_al_handle_failed_connection(self, account_linking_config, internal_response, context):
        exception = requests.ConnectionError("No connection")
        responses.add(responses.GET, "%s/get_id" % account_linking_config["api_url"],
                      body=exception)

        with pytest.raises(SATOSAAuthenticationError):
            self.account_linking.process(context, internal_response)

    @pytest.mark.parametrize("http_status", [
        400, 401, 500
    ])
    @responses.activate
    def test_manage_al_handle_bad_response_status(self, http_status, account_linking_config, internal_response,
                                                  context):
        responses.add(responses.GET, "%s/get_id" % account_linking_config["api_url"],
                      status=http_status)

        with pytest.raises(SATOSAAuthenticationError):
            self.account_linking.process(context, internal_response)

    def test_register_endpoints(self):
        url_map = self.account_linking.register_endpoints()
        assert len(url_map) == 1

        regex, func = url_map[0]
        assert re.compile(regex).match("account_linking/handle_account_linking")
        assert func == self.account_linking._handle_al_response
