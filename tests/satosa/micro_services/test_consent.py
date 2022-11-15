import json
import re
from collections import Counter
from urllib.parse import urlparse

import pytest
import requests
import responses
from jwkest.jwk import RSAKey, rsa_load
from jwkest.jws import JWS

from saml2.saml import NAMEID_FORMAT_PERSISTENT

from satosa.context import Context
from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData
from satosa.micro_services import consent
from satosa.micro_services.consent import Consent, UnexpectedResponseError
from satosa.response import Redirect

FILTER = ["displayName", "co"]
CONSENT_SERVICE_URL = "https://consent.example.com"
ATTRIBUTES = {"displayName": ["Test"], "co": ["example"], "sn": ["should be removed by consent filter"]}
USER_ID_ATTR = "user_id"


class TestConsent:
    @pytest.fixture
    def consent_config(self, signing_key_path):
        consent_config = {
            "api_url": CONSENT_SERVICE_URL,
            "redirect_url": "{}/consent".format(CONSENT_SERVICE_URL),
            "sign_key": signing_key_path,
        }
        return consent_config

    @pytest.fixture(autouse=True)
    def create_module(self, consent_config):
        self.consent_module = Consent(consent_config,
                                      internal_attributes={"attributes": {}, "user_id_to_attr": USER_ID_ATTR},
                                      name="Consent", base_url="https://satosa.example.com")
        self.consent_module.next = lambda ctx, data: (ctx, data)

    @pytest.fixture
    def internal_response(self):
        auth_info = AuthenticationInformation("auth_class_ref", "timestamp", "issuer")
        internal_response = InternalData(auth_info=auth_info)
        internal_response.requester = "client"
        internal_response.attributes = ATTRIBUTES
        return internal_response

    @pytest.fixture
    def internal_request(self):
        req = InternalData(
            subject_type=NAMEID_FORMAT_PERSISTENT,
            requester="example_requester",
        )
        req.attributes = FILTER + ["sn"]
        return req

    @pytest.fixture(scope="session")
    def consent_verify_endpoint_regex(self):
        return re.compile(r"{}/verify/.*".format(CONSENT_SERVICE_URL))

    @pytest.fixture(scope="session")
    def consent_registration_endpoint_regex(self):
        return re.compile(r"{}/creq/.*".format(CONSENT_SERVICE_URL))

    def assert_redirect(self, redirect_resp, expected_ticket):
        assert isinstance(redirect_resp, Redirect)

        path = urlparse(redirect_resp.message).path
        assert path == "/consent/" + expected_ticket

    def assert_registration_req(self, request, internal_response, sign_key_path, base_url, requester_name):
        split_path = request.path_url.lstrip("/").split("/")
        assert len(split_path) == 2
        jwks = split_path[1]

        # Verify signature
        sign_key = RSAKey(key=rsa_load(sign_key_path), use="sig")
        jws = JWS()
        jws.verify_compact(jwks, [sign_key])

        consent_args = jws.msg
        assert consent_args["attr"] == internal_response.attributes
        assert consent_args["redirect_endpoint"] == base_url + "/consent/handle_consent"
        assert consent_args["requester_name"] == requester_name
        assert consent_args["locked_attrs"] == [USER_ID_ATTR]
        assert "id" in consent_args

    @responses.activate
    def test_verify_consent_false_on_http_400(self, consent_config):
        consent_id = "1234"
        responses.add(responses.GET,
                      "{}/verify/{}".format(consent_config["api_url"], consent_id),
                      status=400)
        assert not self.consent_module._verify_consent(consent_id)

    @responses.activate
    def test_verify_consent(self, consent_config):
        consent_id = "1234"
        responses.add(responses.GET,
                      "{}/verify/{}".format(consent_config["api_url"], consent_id),
                      status=200, body=json.dumps(FILTER))
        assert self.consent_module._verify_consent(consent_id) == FILTER

    @pytest.mark.parametrize('status', [
        401, 404, 418, 500
    ])
    @responses.activate
    def test_consent_registration_raises_on_unexpected_status_code(self, status, consent_config):
        responses.add(responses.GET, re.compile(r"{}/creq/.*".format(consent_config["api_url"])),
                      status=status)
        with pytest.raises(UnexpectedResponseError):
            self.consent_module._consent_registration({})

    @responses.activate
    def test_consent_registration(self, consent_config):
        responses.add(responses.GET, re.compile(r"{}/creq/.*".format(consent_config["api_url"])),
                      status=200, body="ticket")
        assert self.consent_module._consent_registration({}) == "ticket"

    @responses.activate
    def test_consent_handles_connection_error(self, context, internal_response, internal_request,
                                              consent_verify_endpoint_regex):
        responses.add(responses.GET,
                      consent_verify_endpoint_regex,
                      body=requests.ConnectionError("No connection"))
        context.state[consent.STATE_KEY] = {"filter": []}
        with responses.RequestsMock(assert_all_requests_are_fired=True) as rsps:
            rsps.add(responses.GET,
                     consent_verify_endpoint_regex,
                     body=requests.ConnectionError("No connection"))
            context, internal_response = self.consent_module.process(context, internal_response)

        assert context
        assert not internal_response.attributes

    @responses.activate
    def test_consent_prev_given(self, context, internal_response, internal_request,
                                consent_verify_endpoint_regex):
        responses.add(responses.GET, consent_verify_endpoint_regex, status=200,
                      body=json.dumps(FILTER))

        context.state[consent.STATE_KEY] = {"filter": internal_request.attributes}
        context, internal_response = self.consent_module.process(context, internal_response)
        assert context
        assert "displayName" in internal_response.attributes

    def test_consent_full_flow(self, context, consent_config, internal_response, internal_request,
                               consent_verify_endpoint_regex, consent_registration_endpoint_regex):
        expected_ticket = "my_ticket"

        requester_name = internal_response.requester_name
        context.state[consent.STATE_KEY] = {"filter": internal_request.attributes,
                                            "requester_name": requester_name}

        with responses.RequestsMock() as rsps:
            rsps.add(responses.GET, consent_verify_endpoint_regex, status=401)
            rsps.add(responses.GET, consent_registration_endpoint_regex, status=200,
                     body=expected_ticket)
            resp = self.consent_module.process(context, internal_response)

            self.assert_redirect(resp, expected_ticket)
            self.assert_registration_req(rsps.calls[1].request,
                                         internal_response,
                                         consent_config["sign_key"],
                                         self.consent_module.base_url,
                                         requester_name)

        with responses.RequestsMock() as rsps:
            # Now consent has been given, consent service returns 200 OK
            rsps.add(responses.GET, consent_verify_endpoint_regex, status=200,
                     body=json.dumps(FILTER))

            context, internal_response = self.consent_module._handle_consent_response(context)

        assert internal_response.attributes["displayName"] == ["Test"]
        assert internal_response.attributes["co"] == ["example"]
        assert "sn" not in internal_response.attributes  # 'sn' should be filtered

    @responses.activate
    def test_consent_not_given(self, context, consent_config, internal_response, internal_request,
                               consent_verify_endpoint_regex, consent_registration_endpoint_regex):
        expected_ticket = "my_ticket"

        responses.add(responses.GET, consent_verify_endpoint_regex, status=401)
        responses.add(responses.GET, consent_registration_endpoint_regex, status=200,
                      body=expected_ticket)

        requester_name = internal_response.requester_name
        context.state[consent.STATE_KEY] = {}

        resp = self.consent_module.process(context, internal_response)

        self.assert_redirect(resp, expected_ticket)
        self.assert_registration_req(responses.calls[1].request,
                                     internal_response,
                                     consent_config["sign_key"],
                                     self.consent_module.base_url,
                                     requester_name)

        new_context = Context()
        new_context.state = context.state
        # Verify endpoint of consent service still gives 401 (no consent given)
        context, internal_response = self.consent_module._handle_consent_response(context)
        assert not internal_response.attributes

    def test_get_consent_id(self):
        attributes = {"foo": ["bar", "123"], "abc": ["xyz", "456"]}

        id = self.consent_module._get_consent_id("test-requester", "user1", attributes)
        assert id == "ZTRhMTJmNWQ2Yjk2YWE0YzgyMzU4NTlmNjM3YjlhNmQ4ZjZiODMzOTQ0ZjNiMTVmODEwMDhmMDg5N2JlMDg0Y2ZkZGFkOTkzMDZiNDZiNjMxNzBkYzExOTcxN2RkMzJjMmY5NzRhZDA2NjYxMTg0NjkyYzdjN2IxNTRiZDkwNmM="

    def test_filter_attributes(self):
        filtered_attributes = self.consent_module._filter_attributes(ATTRIBUTES, FILTER)
        assert Counter(filtered_attributes.keys()) == Counter(FILTER)

    @responses.activate
    def test_manage_consent_without_filter_passes_through_all_attributes(self, context, internal_response,
                                                                         consent_verify_endpoint_regex):
        # fake previous consent
        responses.add(responses.GET, consent_verify_endpoint_regex, status=200,
                      body=json.dumps(list(internal_response.attributes.keys())))

        context.state[consent.STATE_KEY] = {"filter": []} # No filter
        self.consent_module.process(context, internal_response)

        consent_hash = urlparse(responses.calls[0].request.url).path.split("/")[2]
        expected_hash = self.consent_module._get_consent_id(internal_response.requester, internal_response.subject_id,
                                                            internal_response.attributes)
        assert consent_hash == expected_hash
