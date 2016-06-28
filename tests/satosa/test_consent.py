import json
import re
from urllib.parse import urlparse, parse_qs

import pytest
import requests
import responses
from jwkest import jws
from jwkest.jwk import RSAKey, import_rsa_key
from jwkest.jwt import JWT

from satosa.consent import ConsentModule, UnexpectedResponseError
from satosa.context import Context
from satosa.internal_data import InternalResponse, UserIdHashType, InternalRequest, \
    AuthenticationInformation
from satosa.response import Redirect
from satosa.satosa_config import SATOSAConfig
from satosa.state import State
from tests.util import private_to_public_key

FILTER = ["displayName", "co"]
CONSENT_SERVICE_URL = "https://consent.example.com"


def identity_callback(*args):
    return args


@pytest.fixture
def internal_response():
    auth_info = AuthenticationInformation("auth_class_ref", "timestamp", "issuer")
    internal_response = InternalResponse(auth_info=auth_info)
    internal_response.set_user_id_hash_type(UserIdHashType.persistent)
    internal_response.add_attributes(
        {"displayName": "Test", "co": "example", "sn": "removed_by_filter"})
    internal_response.user_id = "usrID"
    return internal_response


@pytest.fixture
def internal_request():
    req = InternalRequest(UserIdHashType.persistent, "example_requestor")
    req.add_filter(FILTER)
    return req


@pytest.fixture(scope="session")
def consent_verify_endpoint_regex():
    return re.compile(r"{}/verify/.*".format(CONSENT_SERVICE_URL))


@pytest.fixture(scope="session")
def consent_registration_endpoint_regex():
    return re.compile(r"{}/creq/.*".format(CONSENT_SERVICE_URL))


class TestConsent:
    def assert_redirect(self, redirect_resp, expected_ticket):
        assert isinstance(redirect_resp, Redirect)

        parsed_url = parse_qs(urlparse(redirect_resp.message).query)
        assert len(parsed_url["ticket"]) == 1
        ticket = parsed_url["ticket"][0]
        assert ticket == expected_ticket

    def assert_registstration_req(self, request, sign_key_str):
        split_path = request.path_url.lstrip("/").split("/")
        assert len(split_path) == 2

        jwks = split_path[1]

        # Verify signature
        public_key = import_rsa_key(private_to_public_key(sign_key_str))
        sign_key = RSAKey().load_key(public_key)
        sign_key.use = "sig"
        _jw = jws.factory(jwks)
        _jw.verify_compact(jwks, [sign_key])

        # Verify JWT
        _jwt = JWT().unpack(jwks)
        consent_args = _jwt.payload()

        assert "attr" in consent_args
        assert "redirect_endpoint" in consent_args
        assert "id" in consent_args

    @pytest.fixture(autouse=True)
    def setup(self, signing_key_path):
        self.consent_config = {
            "api_url": CONSENT_SERVICE_URL,
            "redirect_url": "{}/consent".format(CONSENT_SERVICE_URL),
            "sign_key": signing_key_path,
            "state_enc_key": "fsghajf90984jkflds",
        }
        self.satosa_config = {
            "BASE": "https://proxy.example.com",
            "USER_ID_HASH_SALT": "qwerty",
            "COOKIE_STATE_NAME": "SATOSA_SATE",
            "STATE_ENCRYPTION_KEY": "ASDasd123",
            "BACKEND_MODULES": "",
            "FRONTEND_MODULES": "",
            "INTERNAL_ATTRIBUTES": {"attributes": {}},
            "CONSENT": self.consent_config
        }

    def test_disabled_consent(self, internal_response):
        self.consent_config["enable"] = False
        consent_config = SATOSAConfig(self.satosa_config)
        consent_module = ConsentModule(consent_config, identity_callback)
        assert not consent_module.enabled

    @responses.activate
    def test_verify_consent_false_on_http_400(self):
        consent_config = SATOSAConfig(self.satosa_config)
        consent_module = ConsentModule(consent_config, lambda: None)

        consent_id = "1234"
        responses.add(responses.GET,
                      "{}/verify/{}".format(consent_config["CONSENT"]["api_url"], consent_id),
                      status=400)
        assert not consent_module._verify_consent(consent_id)

    @responses.activate
    def test_verify_consent(self):
        consent_config = SATOSAConfig(self.satosa_config)
        consent_module = ConsentModule(consent_config, lambda: None)
        consent_id = "1234"
        responses.add(responses.GET,
                      "{}/verify/{}".format(consent_config["CONSENT"]["api_url"], consent_id),
                      status=200, body=json.dumps(FILTER))
        assert consent_module._verify_consent(consent_id) == FILTER

    @responses.activate
    def test_consent_registration_raises_on_http401(self):
        consent_config = SATOSAConfig(self.satosa_config)
        consent_module = ConsentModule(consent_config, lambda: None)
        jws = "A_JWS"

        responses.add(responses.GET, "{}/creq/{}".format(consent_config["CONSENT"]["api_url"], jws),
                      status=401)
        with pytest.raises(UnexpectedResponseError):
            consent_module._consent_registration(jws)

    @responses.activate
    def test_consent_registration(self):
        consent_config = SATOSAConfig(self.satosa_config)
        consent_module = ConsentModule(consent_config, lambda: None)
        jws = "A_JWS"
        responses.add(responses.GET, "{}/creq/{}".format(consent_config["CONSENT"]["api_url"], jws),
                      status=200, body="ticket")
        assert consent_module._consent_registration(jws) == "ticket"

    @responses.activate
    def test_consent_handles_connection_error(self, internal_response, internal_request,
                                              consent_verify_endpoint_regex):
        consent_config = SATOSAConfig(self.satosa_config)
        consent_module = ConsentModule(consent_config, identity_callback)

        state = State()
        context = Context()
        context.state = state
        consent_module.save_state(internal_request, state)
        with responses.RequestsMock(assert_all_requests_are_fired=True) as rsps:
            rsps.add(responses.GET,
                     consent_verify_endpoint_regex,
                     body=requests.ConnectionError("No connection"))
            context, internal_response = consent_module.manage_consent(context, internal_response)

        assert context
        assert not internal_response.get_attributes()

    @responses.activate
    def test_consent_prev_given(self, internal_response, internal_request,
                                consent_verify_endpoint_regex):
        consent_config = SATOSAConfig(self.satosa_config)
        consent_module = ConsentModule(consent_config, identity_callback)

        responses.add(responses.GET, consent_verify_endpoint_regex, status=200,
                      body=json.dumps(FILTER))

        context = Context()
        state = State()
        context.state = state
        consent_module.save_state(internal_request, state)
        context, internal_response = consent_module.manage_consent(context, internal_response)
        assert context
        assert "displayName" in internal_response.get_attributes()

    @responses.activate
    def test_consent_full_flow(self, internal_response, internal_request,
                               consent_verify_endpoint_regex, consent_registration_endpoint_regex):
        consent_config = SATOSAConfig(self.satosa_config)
        consent_module = ConsentModule(consent_config, identity_callback)
        expected_ticket = "my_ticket"

        context = Context()
        state = State()
        context.state = state
        consent_module.save_state(internal_request, state)

        with responses.RequestsMock() as rsps:
            rsps.add(responses.GET, consent_verify_endpoint_regex, status=401)
            rsps.add(responses.GET, consent_registration_endpoint_regex, status=200,
                     body=expected_ticket)
            resp = consent_module.manage_consent(context, internal_response)

            self.assert_redirect(resp, expected_ticket)
            self.assert_registstration_req(rsps.calls[1].request,
                                           consent_config["CONSENT"]["sign_key"])

        with responses.RequestsMock() as rsps:
            # Now consent has been given, consent service returns 200 OK
            rsps.add(responses.GET, consent_verify_endpoint_regex, status=200,
                     body=json.dumps(FILTER))

            context = Context()
            context.state = state
            context, internal_response = consent_module._handle_consent_response(context)

        assert internal_response.get_attributes()["displayName"] == ["Test"]
        assert internal_response.get_attributes()["co"] == ["example"]
        assert "sn" not in internal_response.get_attributes()  # 'sn' should be filtered

    @responses.activate
    def test_consent_not_given(self, internal_response, internal_request,
                               consent_verify_endpoint_regex, consent_registration_endpoint_regex):
        consent_config = SATOSAConfig(self.satosa_config)
        consent_module = ConsentModule(consent_config, identity_callback)
        expected_ticket = "my_ticket"

        responses.add(responses.GET, consent_verify_endpoint_regex, status=401)
        responses.add(responses.GET, consent_registration_endpoint_regex, status=200,
                      body=expected_ticket)

        context = Context()
        state = State()
        context.state = state
        consent_module.save_state(internal_request, state)

        resp = consent_module.manage_consent(context, internal_response)

        self.assert_redirect(resp, expected_ticket)
        self.assert_registstration_req(responses.calls[1].request,
                                       consent_config["CONSENT"]["sign_key"])

        context = Context()
        context.state = state
        # Verify endpoint of consent service still gives 401 (no consent given)
        context, internal_response = consent_module._handle_consent_response(context)
        assert not internal_response.get_attributes()
