import re
from urllib.parse import urlparse, parse_qs

from jwkest import jws
from jwkest.jwk import RSAKey, import_rsa_key
from jwkest.jwt import JWT
import pytest
import responses

from saml2.httputil import Redirect

from satosa.consent import ConsentModule
from satosa.context import Context
from satosa.internal_data import InternalResponse, UserIdHashType, InternalRequest, \
    AuthenticationInformation
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
                      {"service.rest_uri": "https://localhost:8055",
                       "service.consent_redirect": "https://localhost:8055/consent",
                       "endpoint": "handle_consent",
                       "sign_key": CONSENT_KEY.name,
                       "state_enc_key": "fsghajf90984jkflds",
                       "cookie_max-age": 60}
                  }

CONSENT_CONFIG.update(SATOSA_CONFIG)


class ConsentService():
    def __init__(self):
        self.database = []
        self.number_called = 0

    def callback(self, request):
        self.number_called += 1
        split_path = request.path_url.lstrip("/").split("/")
        assert len(split_path) == 2

        id_hash = split_path[1]

        if id_hash in self.database:
            return (200, {}, "")
        return (401, {}, "")

    def redirect(self, url):
        parsed_url = parse_qs(urlparse(url).query)
        assert "jwt" in parsed_url
        assert len(parsed_url["jwt"]) == 1

        # # Assert signature
        _bkey = import_rsa_key(CONSENT_PUB_KEY_STR)
        sign_key = RSAKey().load_key(_bkey)
        sign_key.use = "sig"

        _jw = jws.factory(parsed_url["jwt"][0])
        _jw.verify_compact(parsed_url["jwt"][0], [sign_key])

        # unpack jwt
        _jwt = JWT().unpack(parsed_url["jwt"][0])
        consent_args = _jwt.payload()

        assert "attr" in consent_args
        assert "redirect_endpoint" in consent_args
        assert "id" in consent_args

        self.database.append(consent_args["id"])

        return consent_args["redirect_endpoint"], consent_args["attr"]


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
def test_consent_flow():
    filter = ["displayName", "co"]

    def callback(context, internal_response, state):
        assert state, "state was None"
        assert context, "context was None"
        saml_attr = internal_response.get_pysaml_attributes()
        for attr in saml_attr:
            assert attr in filter, "Consent module did not filter the attributes"

    consent_service = ConsentService()

    consent_config = SATOSAConfig(CONSENT_CONFIG)
    consent_module = ConsentModule(consent_config, callback)

    assert consent_module.enabled

    internal_request = InternalRequest(UserIdHashType.persistent, "example_requestor")
    internal_request.add_pysaml_attr_filter(filter)

    state = State()
    consent_module.save_state(internal_request, state)

    auth_info = AuthenticationInformation("auth_class_ref", "timestamp", "issuer")
    internal_response = InternalResponse(UserIdHashType.persistent, auth_info=auth_info)
    internal_response.add_pysaml_attributes(
        {"displayName": "Test", "co": "example", "sn": "removed_by_filter"})
    internal_response.user_id = "usrID"

    url_re = re.compile(r'%s/verify/.*' % consent_config.CONSENT["service.rest_uri"])
    responses.add_callback(responses.GET, url_re, consent_service.callback)
    context = Context()
    resp = consent_module.manage_consent(context, internal_response, state)

    assert isinstance(resp, Redirect)

    consent_redirect, consent_attr = consent_service.redirect(resp.message)

    internal_filter = ["displayname", "co"]
    for attr in consent_attr:
        assert attr in internal_filter, "%s should not have been sent to the consent service!" % attr

    # Call the endpoint
    consent_context = Context()
    consent_context.cookie = resp.headers[0][1]
    consent_module._handle_consent_response(consent_context)

    # Assert uses the same id when interacting with consent service
    assert len(consent_service.database) == 1, "Does not use the same hashed ID!"
    # Assert number of calls to consent_verify
    assert consent_service.number_called == 2, "Does not check consent verification properly"
