import json
import os
import re
import time

from jwkest.jwk import RSAKey
from oic.oauth2 import rndstr
from oic.oic import DEF_SIGN_ALG
from oic.oic.consumer import Consumer
from oic.oic.message import RegistrationResponse, RegistrationRequest, AccessTokenRequest, \
    AuthorizationRequest, AuthorizationResponse, UserInfoRequest
from oic.oic.provider import Provider
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.client import verify_client
from oic.utils.authn.user import UserAuthnMethod
from oic.utils.authz import AuthzHandling
from oic.utils.http_util import Response
from oic.utils.keyio import KeyJar, KeyBundle, UnknownKeyType
from oic.utils.sdb import SessionDB, AuthnEvent
from oic.utils.userinfo import UserInfo
from oic.utils.webfinger import WebFinger
import pytest
import responses

from oic.utils.http_util import Redirect

from mock import MagicMock

from satosa.backends.openid_connect import OpenIdBackend
from satosa.context import Context
from tests.util import FileGenerator
from six.moves.urllib.parse import urlparse

__author__ = 'danielevertsson'


class RpConfig(object):
    def __init__(self, module_base):
        self.CLIENTS = {
            "": {
                "client_info": {
                    "application_type": "web",
                    "application_name": "SATOSA",
                    "contacts": ["ops@example.com"],
                    "redirect_uris": ["%sauthz_cb" % module_base],
                    "response_types": ["code"],
                    "subject_type": "pairwise"
                },
                "behaviour": {
                    "response_type": "code",
                    "scope": ["openid", "profile", "email", "address", "phone"],
                }
            }
        }
        self.ACR_VALUES = ["PASSWORD"]
        self.VERIFY_SSL = False
        self.OP_URL = "https://op.tester.se/"


class TestConfiguration(object):
    """
    Testdata.

    The IdP and SP configuration is relying on endpoints with POST to simply the testing.
    """
    _instance = None

    def __init__(self):
        idp_cert_file, idp_key_file = FileGenerator.get_instance().generate_cert("idp")
        xmlsec_path = '/usr/local/bin/xmlsec1'
        self.op_config = {}

        sp_cert_file, sp_key_file = FileGenerator.get_instance().generate_cert("sp")
        self.rp_base = "https://rp.example.com/openid/"
        self.rp_config = RpConfig(self.rp_base)

        # sp_metadata = FileGenerator.get_instance().create_metadata(self.rp_config, "sp_metadata")
        # idp_metadata = FileGenerator.get_instance().create_metadata(self.op_config, "idp_metadata")
        # self.rp_config["metadata"]["local"].append(idp_metadata.name)
        # self.op_config["metadata"]["local"].append(sp_metadata.name)

    @staticmethod
    def get_instance():
        """
        Returns an instance of the singleton class.
        """
        if not TestConfiguration._instance:
            TestConfiguration._instance = TestConfiguration()
        return TestConfiguration._instance


CLIENT_ID = "client_1"
SIGNING_KEY_FILE = "private.key"


def keybundle_from_local_file(filename, typ, usage, kid):
    if typ.upper() == "RSA":
        kb = KeyBundle()
        k = RSAKey(kid=kid)
        k.load(filename)
        k.use = usage[0]
        kb.append(k)
        for use in usage[1:]:
            _k = RSAKey(kid=kid + "1")
            _k.use = use
            _k.load_key(k.key)
            kb.append(_k)
    elif typ.lower() == "jwk":
        kb = KeyBundle(source=filename, fileformat="jwk", keyusage=usage)
    else:
        raise UnknownKeyType("Unsupported key type")

    return kb


BASE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../keys"))
KC_RSA = keybundle_from_local_file(os.path.join(BASE_PATH, SIGNING_KEY_FILE),
                                   "RSA", ["ver", "sig"], "op_sign")

KEYJAR = KeyJar()
KEYJAR[CLIENT_ID] = [KC_RSA]
KEYJAR[""] = KC_RSA

JWKS = KEYJAR.export_jwks()

CDB = {
    CLIENT_ID: {
        "client_secret": "client_secret",
        "redirect_uris": [("http://localhost:8087/authz", None)],
        "client_salt": "salted"
    }
}

op_url = TestConfiguration.get_instance().rp_config.OP_URL
SERVER_INFO = {
    "version": "3.0",
    "issuer": op_url,
    "authorization_endpoint": "%sauthorization" % op_url,
    "token_endpoint": "%stoken" % op_url,
    "flows_supported": ["code", "token", "code token"],
}

CONSUMER_CONFIG = {
    "authz_page": "/authz",
    "scope": ["openid"],
    "response_type": ["code"],
    "user_info": {
        "name": None,
        "email": None,
        "nickname": None
    },
    "request_method": "param"
}
USERDB = {
    "user": {
        "name": "Hans Granberg",
        "nickname": "Hasse",
        "email": "hans@example.org",
        "verified": False,
        "sub": "user"
    },
    "username": {
        "name": "Linda Lindgren",
        "nickname": "Linda",
        "email": "linda@example.com",
        "verified": True,
        "sub": "username"
    }
}

USERINFO = UserInfo(USERDB)


class DummyAuthn(UserAuthnMethod):
    def __init__(self, srv, user):
        UserAuthnMethod.__init__(self, srv)
        self.user = user

    def authenticated_as(self, cookie=None, **kwargs):
        if cookie == "FAIL":
            return None, 0
        else:
            return {"uid": self.user}, time.time()


# AUTHN = UsernamePasswordMako(None, "login.mako", tl, PASSWD, "authenticated")
AUTHN_BROKER = AuthnBroker()
AUTHN_BROKER.add("UNDEFINED", DummyAuthn(None, "username"))

# dealing with authorization
AUTHZ = AuthzHandling()
SYMKEY = rndstr(16)  # symmetric key used to encrypt cookie info


class TestOpenIdBackend:
    @pytest.fixture(autouse=True)
    def port_db_editor(self):
        self.openid_backend = OpenIdBackend(None, TestConfiguration.get_instance().rp_config)
        self.op_base = TestConfiguration.get_instance().rp_config.OP_URL
        self.redirect_urls = TestConfiguration.get_instance().rp_config.CLIENTS[""]["client_info"][
            "redirect_uris"]
        self.provider = Provider(
            "pyoicserv",
            SessionDB(self.op_base),
            CDB,
            AUTHN_BROKER,
            USERINFO,
            AUTHZ,
            verify_client,
            SYMKEY,
            urlmap=None,
            keyjar=KEYJAR
        )
        self.provider.baseurl = TestConfiguration.get_instance().rp_config.OP_URL

    def test_register_endpoints(self):
        """
        Tests the method register_endpoints
        """
        url_map = self.openid_backend.register_endpoints()
        for endpoint in self.redirect_urls:
            match = False
            for regex in url_map:
                if re.search(regex[0], endpoint):
                    match = True
                    break
            assert match, "Not correct regular expression for endpoint: %s" % endpoint[0]

    def test_translate_response_to_internal_response(self):
        sub = "123qweasd"
        response = {"given_name": "Bob", "family_name": "Devsson", "sub": sub}
        internal_response = self.openid_backend._translate_response(response,
                                                                    "https://localhost:8090")
        assert internal_response.user_id == sub
        attributes_keys = internal_response._attributes.keys()
        assert sorted(attributes_keys) == sorted(['surname', 'eduPersonTargetedID', 'givenName'])

    @responses.activate
    def test_redirect_end_point(self, ):
        context = self.fake_authentication_response()
        self.provider.client_authn = MagicMock(return_value=CLIENT_ID)

        responses.add(
            responses.GET,
            self.op_base + "static/jwks.json",
            body=json.dumps(JWKS),
            status=200,
            content_type='application/json')

        self.fake_token_endpoint()
        self.fake_userinfo_endpoint()
        self.openid_backend.redirect_endpoint(context)

    def fake_userinfo_endpoint(self):
        cons = Consumer({}, CONSUMER_CONFIG, {"client_id": CLIENT_ID},
                        server_info=SERVER_INFO, )
        cons.behaviour = {
            "request_object_signing_alg": DEF_SIGN_ALG["openid_request_object"]}
        cons.keyjar[""] = KC_RSA

        cons.client_secret = "drickyoughurt"
        cons.config["response_type"] = ["token"]
        cons.config["request_method"] = "parameter"
        state, location = cons.begin("openid", "token",
                                     path="http://localhost:8087")

        resp = self.provider.authorization_endpoint(
            request=urlparse(location).query)

        # redirect
        atr = AuthorizationResponse().deserialize(
            urlparse(resp.message).fragment, "urlencoded")

        uir = UserInfoRequest(access_token=atr["access_token"], schema="openid")
        resp = self.provider.userinfo_endpoint(request=uir.to_urlencoded())
        responses.add(
            responses.POST,
            self.op_base + "userinfo_endpoint",
            body=resp.message,
            status=200,
            content_type='application/json')

    def fake_token_endpoint(self):
        authreq = AuthorizationRequest(state="state",
                                       redirect_uri=self.redirect_urls[0],
                                       client_id=CLIENT_ID,
                                       response_type="code",
                                       scope=["openid"])
        _sdb = self.provider.sdb
        sid = _sdb.token.key(user="sub", areq=authreq)
        access_grant = _sdb.token(sid=sid)
        ae = AuthnEvent("user", "salt")
        _sdb[sid] = {
            "oauth_state": "authz",
            "authn_event": ae,
            "authzreq": authreq.to_json(),
            "client_id": CLIENT_ID,
            "code": access_grant,
            "code_used": False,
            "scope": ["openid"],
            "redirect_uri": self.redirect_urls[0],
        }
        _sdb.do_sub(sid, "client_salt")
        # Construct Access token request
        areq = AccessTokenRequest(code=access_grant, client_id=CLIENT_ID,
                                  redirect_uri=self.redirect_urls[0],
                                  client_secret="client_secret_1")
        txt = areq.to_urlencoded()
        resp = self.provider.token_endpoint(request=txt)
        responses.add(
            responses.POST,
            self.op_base + "token",
            body=resp.message,
            status=200,
            content_type='application/json')

    def fake_authentication_response(self):
        context = Context()
        context.path = 'openid_connect/authz_cb'
        op_base = TestConfiguration.get_instance().rp_config.OP_URL
        state = json.dumps({
            "state": "Y3hjMkp1VFRaaWJrMTNVRlozYVdSWVNuVlBiVGxvWXpKc2VrOXROV2hpVjFaNlQyNVNhazlzVGtKVVZYYzJUV2swZDA5dVFubGlNMUoyV1RJNWMxaERTV2RsUnpGelltNU5ObUp1VFhoUVZuZHBaRmhLZFU5dE9XaGpNbXg2VDIwMWFHSlhWbnBQYmxKcVQyeE9RbFJWZHpaTmFUUjNUMjFHZW1NeVZubGtSMngyWW14M2FVbElhSFJpUnpWNlQyMDFlazFxTVdOSmJXZ3daRWhCTmt4NU9UTmtNMk4xWkhwTmRXSXpTbTVNZWtsM1RVUkJkazFFYTNabFJ6RnpXa2hPY0ZwNVRtTkphVUpDWXpOT2JHTnVVbkJpTWpWRVlqSTFlbVJYTVd4amJFNXNZMjVhY0ZreVZsWlZhM2M1V0VOS2IyUklVbmRQYVRoMllrYzVhbGxYZUc5aU0wNHdUMnBuZDA5RVkzWlpWMDU2VEROQ2RtTXpVbU5KYVVKRldsaE9NR0ZYTldoa1IyeDJZbW94WTBsdGFEQmtTRUo2VDJrNGRrMVVTVE5NYWtGMVRVTTBlRTlxWjNkUFZFRjJZak5DYkdKdGJHdFlNazUyWW0wMWJGa3pVWFpqTTA1MlRETktiRnBIYkhsYVYwNHdXRU5KWjFOVlVUbFlRMHB3V2tNeE5GTllTVFJPTW14V1ZqQmFVbU50TVhCVFJWa3hXakYzYVVsRmJIcGpNMVpzVTFjMWVtUkhSblZrUkRGalNXcEpkMDFVVlhSTlZFRjBUVlJLVlUxVVNUWk5hbGsyVFhwT1lWaERTV2RWU0VwMlpFYzVhbUl5ZUVOaFZ6VnJZVmMxYmxCV2QybGtXRXAxVDIwNWFHTXliSHBQYlRWb1lsZFdlazl1VW1wUGJFNUNWRlYzTmsxcE5IZFBiVXB3WW0xU2NHSnRaSHBQYTJoVlZrWkJkRlZGT1ZSV1JuZHBTVVphYkdOdVRuQmlNalE1V0VOSmVVeHFRbU5KYWpRNFltNU5lRTlyYkhwak0xWnNZMmxDUjJJelNuUlpXRkU1V0VOS01XTnRORFppTWtaNllWaE5ObUp0Um5SYVdFMDJaRWROTmxVd1JrNVVSRzk1VEdwQk5tSnRSblJhVjJ4clRGZGFkbU50TVdoa1JIQnNZbTVTY0dSSWJHTkphalZ2WkVoU2QwOXBPSFppUnpscVdWZDRiMkl6VGpCUGFtZDNUMFJqZG1NelFtWmpNa1pvWTNrMU5HSlhkemhNTWpWNlRWUndTbU16VGpGYVdFa3RVRWMxZWsxcWNGUmhWMlIxV1ZoU01XTnRWV2RUVjFFNVdFTktWR0ZYWkhWWldGSXhZMjFWZUZoRFNTMVFSelY2VFdwd1ZHRlhaSFZhVjFKS1ltMWFkbEJxZUhWamVrazJVVEpHZFdJeU5YQlpNa1p6WVZod2FHUkhiSFppYXpGc1pFZG9kbHBEUWtKaVIyUjJZMjFzTUdGSE1EbFlRMHB2WkVoU2QwOXBPSFprTTJRelRHNWpla3h0T1hsYWVUaDVUVVJCZUV4NlJYZE1NMmgwWWtNeGJHVkhUWFJaZWtVd1ltbE9ZMGxwUVhaUWFuaDFZM3BKTmxVeWJHNWliVVl3WkZoS2JGUlhWakJoUnpsclNVVkdjMW95T1hsaFdGSnZZbFF4WTBsdGFEQmtTRUUyVEhrNU0yUXpZM1ZrZWsxMVlqTktia3g2U1hkTlJFRjJUVVJyZG1WSE1YTmFTRTV3V25sT2VXTXlSWFJqTW1ob1RWWjNhVWxET0MxUVJ6VjZUV3B3VTFwWFdteGpiVloxV1RKVloxWldTa3BRVm5kcFNUSnNhMHhZYUVwamFtY3pZVlpXV0ZKc1JubGlWMnhKVW1wV2JsaERTUzFRUnpWNlRXcHdWV050Um5Wak1scDJZMjB4ZWxCcWVIVmpla2syVmtoS2FHSnVUbTFpTTBwMFNVVkdjMW95T1hsaFdGSnZZbFF4WTBsdGFEQmtTRUUyVEhrNU0yUXpZM1ZrZWsxMVlqTktia3g2U1hkTlJFRjJUVVJyZG1WSE1YTmFTRTV3V25sT2JHSnVXbXhpUnpsM1dsZFJkR015Ykc1aWJVWXdaRmhLYkZoRFNXZE1lalE0WW01TmVVOXNVbmxaVnpWNldtMDVlV0pUUWtKaVIyUjJZMjFzTUdGSE1EbFlRMHB2WkVoU2QwOXBPSFprTTJRelRHNWpla3h0T1hsYWVUaDVUVVJCZUV4NlJYZE1NMmgwWWtNeGJHVkhUWFJaZWtVd1ltbE9ZMGxwUVhaUWFuZDJZbTVOZVU5c1VubFpWelY2V20wNWVXSllUUzFRUnpWNlRXcHdSV0ZYWkd4ak0xSk9XbGhTYjJJeVVXZFJWM2h1WWpOS2NHUkhhSFJRVm5kcFlVaFNNR05FYjNaTU0yUXpaSGsxTTAxNU5YWmpiV04yVFdwQmQwMURPSGRQVXprMFlsZDRhMk15Ykc1Sk0wNXZXVlJHWTBscFFYWlFhbmgxWTNwSk5sSkhiRzVhV0U0d1ZtMUdjMlJYVlMxU01XdDNaVk01YTA0d2RGQldhbEpXVGxob2VHRnFUbXBoTTFwcVZGaEJkMUpGYUZKUVZIZDJZbTVOZVU5clVuQmFNbFo2WkVaYWFHSklWbXhRYW5kMlltNU5lVTlzU214YWJWWjVXbGMxYWxwVU5EaE1NalY2VFdwd1ZHRlhaSFZhVjFKS1ltMWFkbEJxZUhWamVrazJWVEpzYm1KdFJqQmtXRXBzVm0xR2MyUlhWUzFUYW1oelZsZGtUa3g1ZERSbFIzUjNZak5HZG1KR1VsUk5NMUZ5VjFjeGRWZEZUbmhVYkZZMVkzcENSRlZZVWxOU1ZrRjVWa1U1YUUxNmFIRmFNSEJ4VlZoS2VrMHdUbTlXU0VKeFV6RmFVazlFUWt0WFJuaDFWRWhzZUdKWWFIVmpNVnA1VWtSR00xWjZSbFZPUjNoRFpGVmtWVnByYkZsVWEyTjVUVmRWZVZWSVNucGlSVm8wVWxWYWVGUllhRkZYUlhkM1kyNWtWV1ZZU2tWVlZWcHFZMWhTVldOSGRGRlVWbFZ5WXpGNGRVNXJWbXBPUnpGWlpXdFJjbVJWZUhoTlJVWXdWVE53Y2s1V2JIZGllbXhVWVVkU2NHTldWblpTVlVwVFdtdFZkMlZxYURCaGVtaHRZbm93T0V3eU5YcE5hbkJVWVZka2RWbFlVakZqYlZaWFdWZDRNVnBVTkRoaWJrMTVUMnQwYkdWVmJIVmFiVGd0VUVjMWVrMXFjRmxPVkVFMVVrZEdNRmxVTkRoaWJrMTVUMnhuTVUxRWJFUmFXRW93WVZkYWNGa3lSakJhVkRWT1UxVnNSRTlIY0VSUk1FWnpaRmRrUW1Rd2JFTlJWMlJLVTJ0R1MxTkhZM2xXYWxaTFRYcEdTazlGTVVKTlJXUkVWVE5HU0ZVd2JHbE5NRkpTVWxWS1ExVldWa0pVVlZwMlpVVk9ObEZWY0VOYU1EVlhVV3RHV2xaRlJuTlVhMXBPVlZSQ00xRXpaRnBTUmxwU1ZWVm9SbVF4U2xkWmJHUlhZVVV4VTFvelpFZGFNV3hGVm14R1VsTXdWak5QVmxwcFZqRmFiMU5WV2xka1YwWlpWMjE0YW1Kck5YZGFSV2h5WlVWV1JWRlZPVU5hTURWWFVXdEdlbFpGU1hkaVJsWktVbXhhTVZsV2FGSmxSVlpGVVZVNVExb3dOVmRSYTBaT1ZrVkplRlZ0ZUdwTk1VWnVWbFJHUW1Rd2FHOVpNRFZPVWtkME5GUlZVa3BOYXpGVlZGaHdUbFpGVlhoV01taHFWR3N4VlZGWWFFNVNSV3Q1VkZaU1RtVnJNVlZTVkVaWVlXdEthRlJXUm5wa01FNVNWMVZTVjFWV1JraFNXR1JMVmtaS1ZWSlZOVTVSV0U1SVVWUkdWbEpWU2pSVVZWWlhWbnBHYzFkV1VrWlhWVEZEVjFWa1FrMVdWa1pSTW1oT1ZVWmFXRTFYZUZwVk1FcFhXVzB4YzAxc2NGbFRibkJvVjBaSk1WUldTa0prTUZKdVYxVlNWMVZXUmsxU1dHUnJVMnhhUkZGc1dtbGlWM2QzVkZaS1FtUXdVbTVYVlZKWFZWWkdSVkpZWkd0V1ZuQlpWR3BDU2xKck5WSlVWV3hJV21zeFFrMUZaRVJWTTBaSVZUQnNhVTB3VWxKU1ZVcENWVlpXUWxGVVVraFVhMFpGVVRCS2NGVlZkRU5hTVVaRllUQndXRlZFWkdsa01EazBaRVZuY2xKVVJURldiRkpvWkZkNFQyVnNXbEpNZWtKcVZUSktUazVWWXpOWlYwcDRXbGhHVkZSc1RucE5SM2QzWkcxV1NXTnFXWFpWYXpsdVZucHJNbGR0VmxKT1ZHUnRaV3hhTlUxck1VUlNiV3hTVlc1amVWcHVjRU5qZWtKMVRqSjRiRkpYTVVWVGJteFhWbTVTUTFaSFJqSlhWM2h2VVZaYVdWSkZOV2hOTTA0d1dqTmFiMDVFVG5oUk1scE5aVU4wYW1KR1ZuTlVNMW93WW01T2RsUlhiSEJWYlRGMlRqTkdiVTFGU25aVlJYUlZZV3BrYWsxSVZrMVRNMEpGWTBWV2FWRlZhRkpXUkZKUVVtcEdTVlZzYkZkbFJURXpVMVZTUWxWVlJrTmllbEpJVERBeFNsSjZhRTVSYWtKSVVWUkdWbHBGVW01VlZtUkRVV3hGTTFWdFpHbFVWWEJIVWtWa1UxRnVWVFZpZWs0d1VrWkdSV1JXVG5aUmJtc3pVMjF3UkZGdGNFSlhWVkpYVldwQ2NWRnJiRWhTVlRGS1VqQktibEZzUlROVmJXUnBWRlZ3UjFKRlpGTlJibFUxWW5wT01GSkdSa1ZrVms1MlVXNXJNMU51UmtkYVdFSkhaRE5rV0dGclZrMVVWVVp5VWpCRmVGWlZWa05oUlRGRVZsUkNWbVZGVWxWUlZYaERXakExVjFGclJtcFdSVXBIVm01U1lWWXdWalJTTUZKQ1ZqQktibFJzV2tOUlZ6bFZVa1JHVjJSR2NGaFNWMlJYVm5wV2QxcEhNVmRsVjAxNVlrUkNiRlpGVmxKVVZVVXdVakJGZUZaVlZrUmxSVEZKVlRGYVVsb3hXbGhPV0VKclVrVldVbFJWUlRCU01FVjRWbFZXUW1WRk1VbFdhMlJYWlcxU1JGRnNVbFpUVld4TFVWVndTVnA2U2xkT1ZXOTZUVlZyTkZSVlJqTlNNRVY0VmxkU1JtUXhSa2RVVlVaT1VXdEdiVTlJWkVWVlZteExVekk1WVZOWGFESlpNRFZDVlZWV1IxRnNSa0pTUjJSYVVsVkdUbVJXU2pOa01XaFRZbTVPY0dWV1pEWmlWa3B3WVROQ00yRlhOWFZoUmxKMFdXMDVkbE15TURGV1JXeFBWVVZWTTFGVVpHNVZNVVV6VFZSQ1UyVkhiSFpWVjFaUlZVZG9ZVlF6Y0hKVVZFa3pWRzAxU1ZaSVNrUmFWRXA1VVd4YWJrMUZWa2hsYW1SU1ZrZFJlRk5yYkROVVJrSXlXakk1Y1U1R1dsVmhVemx0VlRKb2FFd3pVbGxqYkd4V1dWaEdhazlWUm5oV1ZFWnlWakJyTUZZd05ISmtiVnB0VVd0a1VrMUViSFJpZVhNeVVUSmFiV1JWV2xWWGJHeHNWREpvTmxWRE9IbGpNMUpDVlVoa1JGWkdWVEJoTTJoR1lqSnNOVTFGZEhkWGF6RkNWR3RyT1ZCRE9YVmpla2syVjBSVmQwOVZUbXhqYmxKd1dtMXNhbGxZVW14UWFuZDJZbTVOZVU5c1p6Rk5SR3hGV1ZoU2FGQnFkM1ppYmsxNVQydDBiR1ZWYkhWYWJUZ3RVRU01ZFdONlNUWlZNbXh1WW0xR01HUllTbXhRYW5oMVkzcEJObFJ0Um5SYVZXeEZWVWM1YzJGWFRqVkpSVVp6WWtjNU0xRXpTbXhaV0ZKc1VGWjNhVnB0Um5Oak1sWmpTV2xDUjJJelNuUlpXRkU1V0VOS01XTnRORFppTWtaNllWaE5ObUp0Um5SYVdFMDJaRWROTmxVd1JrNVVSRzk1VEdwQk5tSnRSblJhVjJ4clRGZGFkbU50TVdoa1JIQXdZMjFHZFdNeWJHeGlibEpqU1dsQmRsQnFkM1ppYmsxM1QydEdNV1JIYUhWVmJWWjRaRmRXZW1SRU5HbG1VVDA5SWl3Z0luSmxjWFZsYzNSdmNpSTZJQ0pvZEhSd09pOHZiRzlqWVd4b2IzTjBPamd3T0RjdmMzQmZjMkZoY3k1NGJXd2lmUT09In0=",
            "op": op_base, "nonce": "9YraWpJAmVp4L3NJ"}
        )
        context.request = {
            'code': 'j7FxMTjd8kptU6RC34+C3HVR32sGF78+vye+rjXxAO4zSGI4oPieziwxObztCznAjmyV20d5EYe/F+R4uWbN46U+Bq9moQPC4lEvRd2De4o=',
            'scope': 'openid profile email address phone', 'state': state}
        return context

    @responses.activate
    def test_send_authn_request(self):
        self.fake_webfinger_endpoint()
        self.fake_opienid_config_endpoint()
        self.fake_client_registration_endpoint()
        auth_response = self.openid_backend.start_auth(None, None, "my_state")
        assert auth_response._status == Redirect._status

    def fake_client_registration_endpoint(self):
        client_info = TestConfiguration.get_instance().rp_config.CLIENTS[""]["client_info"]
        request = RegistrationRequest().deserialize(json.dumps(client_info), "json")
        _cinfo = self.provider.do_client_registration(request, CLIENT_ID)
        args = dict([(k, v) for k, v in _cinfo.items()
                     if k in RegistrationResponse.c_param])
        args['client_id'] = CLIENT_ID
        self.provider.comb_uri(args)
        registration_response = RegistrationResponse(**args)
        responses.add(
            responses.POST,
            self.op_base + "registration",
            body=registration_response.to_json(),
            status=200,
            content_type='application/json')

    def fake_opienid_config_endpoint(self):
        self.provider.baseurl = self.op_base
        provider_info = self.provider.create_providerinfo()
        responses.add(
            responses.GET,
            self.op_base + ".well-known/openid-configuration",
            body=provider_info.to_json(),
            status=200,
            content_type='application/json'
        )

    def fake_webfinger_endpoint(self):
        wf = WebFinger()
        resp = Response(wf.response(subject=self.op_base, base=self.op_base))
        responses.add(responses.GET,
                      self.op_base + ".well-known/webfinger",
                      body=resp.message,
                      status=200,
                      content_type='application/json')
