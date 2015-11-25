import re
from urllib.parse import urlparse, parse_qs
from jwkest import jws
from jwkest.jwk import RSAKey, import_rsa_key
from jwkest.jwt import JWT
import pytest
from requests.exceptions import ConnectionError
import responses
from satosa.response import Redirect
from satosa.consent import ConsentModule
from satosa.context import Context
from satosa.internal_data import InternalResponse, UserIdHashType, InternalRequest, AuthenticationInformation
from satosa.satosa_config import SATOSAConfig
from satosa.state import State
from tests.util import FileGenerator, private_to_public_key

__author__ = 'mathiashedstrom'

SATOSA_CONFIG = {"HOST": 'localhost',
                 "PORT": 8090,
                 "HTTPS": True,
                 "PLUGIN_PATH": "",
                 "BACKEND_MODULES": "",
                 "FRONTEND_MODULES": "",
                 "USER_ID_HASH_SALT": "qwerty"}

CONSENT_CERT, CONSENT_KEY = FileGenerator.get_instance().generate_cert("consent")

CONSENT_PUB_KEY_STR = private_to_public_key(CONSENT_KEY.name)

CONSENT_CONFIG = {"CONSENT":
                      {"rest_uri": "https://localhost:8055",
                       "consent_redirect": "https://localhost:8055/consent",
                       "endpoint": "handle_consent",
                       "sign_key": CONSENT_KEY.name,
                       "state_enc_key": "fsghajf90984jkflds",
                       "verify_ssl": False}
                  }

CONSENT_CONFIG.update(SATOSA_CONFIG)

FILTER = ["displayName", "co"]


class ConsentService():
    def __init__(self):
        self.clear()

    def verify(self, request):
        split_path = request.path_url.lstrip("/").split("/")
        assert len(split_path) == 2

        if self.consent_given is not None:
            if self.consent_given:
                return (200, {}, "")
            else:
                return (401, {}, "")

        id_hash = split_path[1]

        if id_hash in self.database:
            return (200, {}, "")
        return (401, {}, "")

    def registration(self, request):
        split_path = request.path_url.lstrip("/").split("/")
        assert len(split_path) == 2

        jwks = split_path[1]

        # # Assert signature
        _bkey = import_rsa_key(CONSENT_PUB_KEY_STR)
        sign_key = RSAKey().load_key(_bkey)
        sign_key.use = "sig"

        _jw = jws.factory(jwks)
        _jw.verify_compact(jwks, [sign_key])

        # unpack jwt
        _jwt = JWT().unpack(jwks)
        consent_args = _jwt.payload()

        assert "attr" in consent_args
        assert "redirect_endpoint" in consent_args
        assert "id" in consent_args

        self.database.append(consent_args["id"])

        return (200, {}, self.ticket)

    def redirect(self, url):
        parsed_url = parse_qs(urlparse(url).query)
        assert "ticket" in parsed_url
        assert len(parsed_url["ticket"]) == 1

        ticket = parsed_url["ticket"][0]
        assert ticket == self.ticket

    def clear(self):
        self.database = []
        self.ticket = "my_ticket"
        self.consent_given = None


def _join_dict(dict_a, dict_b):
    for key, value in dict_b.items():
        if key not in dict_a:
            dict_a[key] = value
        elif not isinstance(value, dict):
            dict_a[key] = value
        else:
            dict_a[key] = _join_dict(dict_a[key], dict_b[key])
    return dict_a


@pytest.mark.parametrize("config", [
    (SATOSA_CONFIG),
    (_join_dict({"CONSENT": {"enable": False}}, SATOSA_CONFIG)),
])
def test_disable_consent(config):
    def callback(_, internal_response, state):
        assert internal_response._attributes["displayname"] == "test"
        assert internal_response._attributes["co"] == "test_co"

    consent_config = SATOSAConfig(config)
    consent_module = ConsentModule(consent_config, callback)
    assert not consent_module.enabled

    attributes = {"displayName": "test",
                  "co": "test_co"}

    context = Context()
    internal_response = InternalResponse(UserIdHashType.persistent)
    internal_response.add_pysaml_attributes(attributes)
    state = State()
    consent_module.manage_consent(context, internal_response, state)


@responses.activate
def test_verify_consent():
    def callback(context, internal_response, state):
        pass

    def consent_service_verify_callback(request):
        split_path = request.path_url.lstrip("/").split("/")
        assert len(split_path) == 2
        id_hash = split_path[1]
        assert id_hash == "test_id"
        return (200, {}, "")

    consent_config = SATOSAConfig(CONSENT_CONFIG)
    consent_module = ConsentModule(consent_config, callback)

    with pytest.raises(ConnectionError):
        consent_module._verify_consent("test_id")

    url_re = re.compile(r'%s/verify/.*' % consent_config.CONSENT["rest_uri"])
    responses.add(responses.GET, url_re, status=400)
    assert not consent_module._verify_consent("test_id")

    responses.reset()
    responses.add_callback(responses.GET, url_re, consent_service_verify_callback)
    assert consent_module._verify_consent("test_id")


@responses.activate
def test_consent_registration():
    def callback(context, internal_response, state):
        pass

    def consent_service_registration_callback(request):
        split_path = request.path_url.lstrip("/").split("/")
        assert len(split_path) == 2
        jws = split_path[1]
        assert jws == "A_JWS"
        return (200, {}, "ticket")

    consent_config = SATOSAConfig(CONSENT_CONFIG)
    consent_module = ConsentModule(consent_config, callback)

    jws = "A_JWS"

    with pytest.raises(ConnectionError):
        consent_module._consent_registration(jws)

    url_re = re.compile(r'%s/creq/.*' % consent_config.CONSENT["rest_uri"])
    responses.add(responses.GET, url_re, status=401)
    with pytest.raises(AssertionError):
        consent_module._consent_registration(jws)

    responses.reset()
    responses.add_callback(responses.GET, url_re, consent_service_registration_callback)
    assert consent_module._consent_registration(jws) == "ticket"


def callback(context, internal_response, state):
    assert state, "state was None"
    assert context, "context was None"
    saml_attr = internal_response.get_pysaml_attributes()
    #TODO FIX THE FILTER!!!
    #for attr in saml_attr:
    #    assert attr in FILTER, "Consent module did not filter the attributes"
    return "response"


def empty_callback(context, internal_response, state):
    assert state, "state was None"
    assert context, "context was None"
    assert not internal_response._attributes
    return "no_attr_response"


def create_internal_response():
    auth_info = AuthenticationInformation("auth_class_ref", "timestamp", "issuer")
    internal_response = InternalResponse(UserIdHashType.persistent, auth_info=auth_info)
    internal_response.add_pysaml_attributes({"displayName": "Test", "co": "example", "sn": "removed_by_filter"})
    internal_response.user_id = "usrID"
    return internal_response


@pytest.fixture
def consent_items():
    consent_config = SATOSAConfig(CONSENT_CONFIG)
    consent_module = ConsentModule(consent_config, callback)
    assert consent_module.enabled
    internal_request = InternalRequest(UserIdHashType.persistent, "example_requestor")
    internal_request.add_pysaml_attr_filter(FILTER)

    return consent_module, internal_request, consent_config, ConsentService()


@responses.activate
def test_consent_verify_down(consent_items):
    consent_module, internal_request, _, _ = consent_items

    state = State()
    context = Context()
    internal_response = create_internal_response()
    consent_module.callback_func = empty_callback
    resp = consent_module.manage_consent(context, internal_response, state)
    assert resp == "no_attr_response"


@responses.activate
def test_consent_verify_down(consent_items):
    consent_module, internal_request, _, _ = consent_items

    state = State()
    context = Context()
    consent_module.save_state(internal_request, state)
    internal_response = create_internal_response()
    consent_module.callback_func = empty_callback
    resp = consent_module.manage_consent(context, internal_response, state)
    assert resp == "no_attr_response"


@responses.activate
def test_consent_creq_down(consent_items):
    consent_module, internal_request, consent_config, consent_service = consent_items

    url_re = re.compile(r'%s/verify/.*' % consent_config.CONSENT["rest_uri"])
    responses.add_callback(responses.GET, url_re, consent_service.verify)

    context = Context()
    state = State()
    internal_response = create_internal_response()
    consent_module.save_state(internal_request, state)
    consent_module.callback_func = empty_callback
    resp = consent_module.manage_consent(context, internal_response, state)
    assert resp == "no_attr_response"


@responses.activate
def test_consent_prev_given(consent_items):
    consent_module, internal_request, consent_config, consent_service = consent_items

    url_re = re.compile(r'%s/verify/.*' % consent_config.CONSENT["rest_uri"])
    responses.add_callback(responses.GET, url_re, consent_service.verify)

    consent_service.clear()
    context = Context()
    state = State()
    consent_service.consent_given = True
    internal_response = create_internal_response()
    consent_module.save_state(internal_request, state)
    consent_module.callback_func = callback
    resp = consent_module.manage_consent(context, internal_response, state)
    assert resp == "response"


@responses.activate
def test_consent_full_flow(consent_items):
    consent_module, internal_request, consent_config, consent_service = consent_items

    url_re = re.compile(r'%s/verify/.*' % consent_config.CONSENT["rest_uri"])
    responses.add_callback(responses.GET, url_re, consent_service.verify)
    url_re = re.compile(r'%s/creq/.*' % consent_config.CONSENT["rest_uri"])
    responses.add_callback(responses.GET, url_re, consent_service.registration)

    consent_service.clear()
    context = Context()
    state = State()
    internal_response = create_internal_response()
    consent_module.save_state(internal_request, state)
    consent_module.callback_func = callback
    resp = consent_module.manage_consent(context, internal_response, state)
    assert isinstance(resp, Redirect)
    cookie_header = None
    for header in resp.headers:
        if header[0] == 'Set-Cookie':
            cookie_header = header[1]
            break
    assert cookie_header, "Did not save state!"
    consent_service.redirect(resp.message)
    consent_service.consent_given = True
    context = Context()
    context.cookie = cookie_header
    resp = consent_module._handle_consent_response(context)
    assert resp == "response"


@responses.activate
def test_consent_not_given(consent_items):
    consent_module, internal_request, consent_config, consent_service = consent_items

    url_re = re.compile(r'%s/verify/.*' % consent_config.CONSENT["rest_uri"])
    responses.add_callback(responses.GET, url_re, consent_service.verify)
    url_re = re.compile(r'%s/creq/.*' % consent_config.CONSENT["rest_uri"])
    responses.add_callback(responses.GET, url_re, consent_service.registration)

    consent_service.clear()
    context = Context()
    state = State()
    internal_response = create_internal_response()
    consent_module.save_state(internal_request, state)
    consent_module.callback_func = empty_callback
    resp = consent_module.manage_consent(context, internal_response, state)
    assert isinstance(resp, Redirect)
    cookie_header = None
    for header in resp.headers:
        if header[0] == 'Set-Cookie':
            cookie_header = header[1]
            break
    assert cookie_header, "Did not save state!"
    consent_service.redirect(resp.message)
    consent_service.consent_given = False
    context = Context()
    context.cookie = cookie_header
    resp = consent_module._handle_consent_response(context)
    assert resp == "no_attr_response"
