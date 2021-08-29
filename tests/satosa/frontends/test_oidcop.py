import copy
import datetime
import json
import pytest

from base64 import urlsafe_b64encode
from cryptojwt.key_jar import KeyJar
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.tools import keyconv

from oidcmsg.oidc import AccessTokenRequest
from oidcmsg.oidc import AuthnToken
from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.oidc import AuthorizationResponse
from oidcmsg.oidc import RegistrationRequest
from oidcop.exception import UnAuthorizedClient

from saml2.authn_context import PASSWORD
from satosa.attribute_mapping import AttributeMapper
from satosa.context import Context
from satosa.frontends.idpy_oidcop import OidcOpFrontend
from satosa.frontends.oidcop.storage.mongo import Mongodb
from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData
from tests.users import USERS
from tests.users import OIDC_USERS

from urllib.parse import urlparse, parse_qsl


CLIENT_1_ID = 'jbxedfmfyc'
CLIENT_1_PASSWD = '19cc69b70d0108f630e52f72f7a3bd37ba4e11678ad1a7434e9818e1'
CLIENT_1_RAT = 'z3PCMmC1HZ1QmXeXGOQMJpWQNQynM4xY'
CLIENT_RED_URL = 'https://127.0.0.1:8090/authz_cb/satosa'
CLIENT_1_SESLOGOUT = 'https://127.0.0.1:8090/session_logout/satosa'

# unused because actually we can't have private_key_jwt/RFC7523 in satosa
CLIENT_JWK_DICT = {'keys': [{'kty': 'RSA',
   'use': 'sig',
   'kid': 'OWIzN25HNmY0d0VTNWtMeEstTFU3endZbm9ucjhwTVhfLUdwajU1QS1NMA',
   'n': 'ytqcNOfMII7NT1n4AhG8nWBvNuJ7gfBXdOjde-iPIy0OiXj6CeuXZXdaUsWeUElG3yw03IRyGs6Q1sh1_b3kFTjrfMhj7nX50ZWucZJCO0MLtsPqOfjKCiyOJjb4rSDhDrM2PxNJ_eXEuFzUVB5CPCK2GvKzPBZJvtYmGDnaf0CDH2XcWfUeyrFip2zvJ4wrrb4l-hqngPLhAyNaV3QtzbbXJtQTNPlHYghC_prVj18onHsC68fxQg7OfHmPQq9DVZs24rAb6rqxI0PJwSVbUA89gGjuytQAQEFKzR4AR9bfhZBj6H3X5sOcFg8xg-iOBmQxx7vM_5Dxu1sTIvykFQ',
   'e': 'AQAB',
   'd': 'cQeQhHYoKngHdFCYPWbupu5F6doWoZdu08ixKMqzfxErCXSsNfzc1f_EB1zv0qKR5-Z06e6uubshv1vhSuqU_TJDHLt32zZHZf22PrgVSXoZO9Q8XeL_iN28sxRsSeOJI6y97DVuRBfUHjozYU-e7m0U9T0Im9F7c-dVQKhz0_T6JNr_swwatlL4lrIIc-sAWbTZp30ef8QNze48twxtrhf-NcNIft0GF_jLN3PdQrSe7DmEv6BxSHDG2IKOT-KjmoehkKtc0UTP-465GXFKDQZiMjf7nHh7zdqRCJXPDoS9YFpQFGWvH89p5thBACVMpTOgM3t3eXwUODhwTuXB_Q',
   'p': '-7RuaUjObNfd3iKppj5oSbecRpAa_x_vq5zM6Q0qs0PLyJz6wZRGAvg4pmQFwvGskqOBFXcOPWH4WmmvM6YzuPajIoCMLEojQltmBVaoc-IIo9B7Wry6PXrLjmc-2aFOyECYt8QMkVMC7zcswfA1xy-_gNlXCrA40MLSa6MXv5c',
   'q': 'zlDGTW163TMtXvkah1MvDi9w8qfDHZ9L3iQYhZjvooXIyaRCwQP24EwfYdOeXt1PpKdLbI3ZdeWcjAaqpqJCb-X9BXS_H2KNQkMKqhrKYwrlLEyYkGKsgFTB8Kx1-dgzszV2awR4NJImhl4WdhudUbnD9HDhkOouCICYPeYpbzM'},
  {'kty': 'EC',
   'use': 'sig',
   'kid': 'TjNnM3libWFDMjBpeU5WWmZjVkFqdUFCc0dWd3h2eFNGOW1MSk5VYTVUYw',
   'crv': 'P-256',
   'x': 'AWSp7rX1Obb_D7HZhkjAjND721VZaYp5OuJvc0kxSVE',
   'y': 'X1l4LMpq8dI4idQXUPScuarbyz_a0gq0DjHZhdWWiAw',
   'd': 'd2SBLs_LZIxt2U_sdcjTCLLoMYWli_HYkZ0YIDe2SvE'}]
}
# unused because actually we can't have private_key_jwt/RFC7523 in satosa
CLIENT_RSA_KEY = key_from_jwk_dict(CLIENT_JWK_DICT['keys'][0])


CLIENT_CONF = {
        'client_id': CLIENT_1_ID,
        'client_name': "ciro",
        'client_salt': '6flfsj0Z',
        'registration_access_token': CLIENT_1_RAT,
        'registration_client_uri': f'https://127.0.0.1:8000/registration_api?client_id={CLIENT_1_ID}',
        'client_id_issued_at': datetime.datetime.utcnow().timestamp(),
        'client_secret': CLIENT_1_PASSWD,
        'client_secret_expires_at': (datetime.datetime.utcnow() + datetime.timedelta(days=1)).timestamp(),
        'application_type': 'web',
        'contacts': ['ops@example.com'],
        'token_endpoint_auth_method': 'client_secret_basic',
        # TODO for jwe and rfc7523
        # 'jwks_uri': 'https://127.0.0.1:8099/static/jwks.json',
        #'jwks': CLIENT_RSA_KEY.serialize(),
        'redirect_uris': [(CLIENT_RED_URL, {})],
        'post_logout_redirect_uris': [(CLIENT_1_SESLOGOUT, None)],
        'response_types': ['code'],
        'grant_types': ['authorization_code'],
        'allowed_scopes': ['openid', 'profile', 'email', 'offline_access']
}

BASE_URL = "https://idpy.oidc.provid.er"
OIDCOP_CONF = {
  "domain": "localhost",
  "server_name": "localhost",
  "base_url": BASE_URL,
  "storage": {
    "class": "satosa.frontends.oidcop.storage.mongo.Mongodb",
    "kwargs": {
      "url": "mongodb://127.0.0.1:27017/oidcop",
      "connection_params": {
        # "username": "satosa",
        # "password": "thatpassword",
        "connectTimeoutMS": 2000,
        "socketTimeoutMS": 2000,
        "serverSelectionTimeoutMS": 2000
      }
    },
    "db_name": "oidcop",
    "collections": {
      "session": "session_test",
      "client": "client_test"
    }
  },
  "default_target_backend": "spidSaml2",
  "salt_size": 8,
  "op": {
    "server_info": {
      "add_on": {
        "claims": {
          "function": "oidcop.oidc.add_on.custom_scopes.add_custom_scopes",
          "kwargs": {
            "research_and_scholarship": [
              "name",
              "given_name",
              "family_name",
              "email",
              "email_verified",
              "sub",
              "iss",
              "eduperson_scoped_affiliation"
            ]
          }
        },
        "pkce": {
          "function": "oidcop.oidc.add_on.pkce.add_pkce_support",
          "kwargs": {
            "code_challenge_method": "S256 S384 S512",
            "essential": False
          }
        }
      },
      "authentication": {
        "user": {
          "acr": "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword",
          "class": "satosa.frontends.oidcop.user_authn.SatosaAuthnMethod"
        }
      },
      "authz": {
        "class": "oidcop.authz.AuthzHandling",
        "kwargs": {
          "grant_config": {
            "expires_in": 43200,
            "usage_rules": {
              "access_token": {},
              "authorization_code": {
                "max_usage": 1,
                "supports_minting": [
                  "access_token",
                  "refresh_token",
                  "id_token"
                ]
              },
              "refresh_token": {
                "supports_minting": [
                  "access_token",
                  "refresh_token"
                ]
              }
            }
          }
        }
      },
      "capabilities": {
        "grant_types_supported": [
          "authorization_code",
          "urn:ietf:params:oauth:grant-type:jwt-bearer",
          "refresh_token"
        ],
        "subject_types_supported": [
          "public",
          "pairwise"
        ]
      },
      "endpoint": {
        "provider_info": {
          "class": "oidcop.oidc.provider_config.ProviderConfiguration",
          "kwargs": {
            "client_authn_method": None
          },
          "path": ".well-known/openid-configuration"
        },
        "authorization": {
          "class": "oidcop.oidc.authorization.Authorization",
          "kwargs": {
            "claims_parameter_supported": True,
            "client_authn_method": None,
            "request_object_encryption_alg_values_supported": [
              "RSA-OAEP",
              "RSA-OAEP-256",
              "A192KW",
              "A256KW",
              "ECDH-ES",
              "ECDH-ES+A128KW",
              "ECDH-ES+A192KW",
              "ECDH-ES+A256KW"
            ],
            "request_parameter_supported": True,
            "request_uri_parameter_supported": True,
            "response_modes_supported": [
              "query",
              "fragment",
              "form_post"
            ],
            "response_types_supported": [
              "code"
            ]
          },
          "path": "OIDC/authorization"
        },
        "token": {
          "class": "oidcop.oidc.token.Token",
          "kwargs": {
            "client_authn_method": [
              "client_secret_post",
              "client_secret_basic",
              "client_secret_jwt",
              "private_key_jwt"
            ]
          },
          "path": "OIDC/token"
        },
        "userinfo": {
          "class": "oidcop.oidc.userinfo.UserInfo",
          "kwargs": {
            "claim_types_supported": [
              "normal",
              "aggregated",
              "distributed"
            ],
            "userinfo_encryption_alg_values_supported": [
              "RSA-OAEP",
              "RSA-OAEP-256",
              "A192KW",
              "A256KW",
              "ECDH-ES",
              "ECDH-ES+A128KW",
              "ECDH-ES+A192KW",
              "ECDH-ES+A256KW"
            ],
            "userinfo_signing_alg_values_supported": [
              "RS256",
              "RS512",
              "ES256",
              "ES512",
              "PS256",
              "PS512"
            ]
          },
          "path": "OIDC/userinfo"
        },
        "introspection": {
          "class": "oidcop.oauth2.introspection.Introspection",
          "kwargs": {
            "client_authn_method": [
              "client_secret_post",
              "client_secret_basic",
              "client_secret_jwt",
              "private_key_jwt"
            ],
            "release": [
              "username"
            ]
          },
          "path": "OIDC/introspection"
        },
        "registration": {
            "class": "oidcop.oidc.registration.Registration",
            "kwargs": {
              "client_authn_method": None,
              "client_id_generator": {
                "class": "oidcop.oidc.registration.random_client_id",
                "kwargs": {}
               },
              "client_secret_expiration_time": 432000
            },
            "path": "OIDC/registration"
        },
        "registration_read": {
            "class": "oidcop.oidc.read_registration.RegistrationRead",
            "kwargs": {
              "client_authn_method": [
               "bearer_header"
               ]},
            "path": "OIDC/registration_read"
        },
      },
      "httpc_params": {
        "verify": False
      },
      "issuer": "https://localhost:10000",
      "keys": {
        "key_defs": [
          {
            "type": "RSA",
            "use": [
              "sig"
            ]
          },
          {
            "crv": "P-256",
            "type": "EC",
            "use": [
              "sig"
            ]
          }
        ],
        "private_path": "data/oidc_op/private/jwks.json",
        "public_path": "data/static/jwks.json",
        "read_only": False,
        "uri_path": "OIDC/jwks.json"
      },
      "login_hint2acrs": {
        "class": "oidcop.login_hint.LoginHint2Acrs",
        "kwargs": {
          "scheme_map": {
            "email": [
              "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword"
            ]
          }
        }
      },
      "session_params": {
        "password": "__password_used_to_encrypt_access_token_sid_value",
        "salt": "salt involved in session sub hash ",
        "sub_func": {
          "pairwise": {
            "class": "oidcop.session.manager.PairWiseID",
            "kwargs": {
              "salt": "CHANGE_ME_OR_LET_IT_BE_RANDOMIC"
            }
          },
          "public": {
            "class": "oidcop.session.manager.PublicID",
            "kwargs": {
              "salt": "CHANGE_ME_OR_LET_IT_BE_RANDOMIC"
            }
          }
        }
      },
      "template_dir": "templates",
      "token_handler_args": {
        "code": {
          "kwargs": {
            "lifetime": 600
          }
        },
        "id_token": {
          "class": "oidcop.token.id_token.IDToken",
          "kwargs": {
            "id_token_encryption_alg_values_supported": [
              "RSA-OAEP",
              "RSA-OAEP-256",
              "A192KW",
              "A256KW",
              "ECDH-ES",
              "ECDH-ES+A128KW",
              "ECDH-ES+A192KW",
              "ECDH-ES+A256KW"
            ],
            "id_token_encryption_enc_values_supported": [
              "A128CBC-HS256",
              "A192CBC-HS384",
              "A256CBC-HS512",
              "A128GCM",
              "A192GCM",
              "A256GCM"
            ],
            "id_token_signing_alg_values_supported": [
              "RS256",
              "RS512",
              "ES256",
              "ES512",
              "PS256",
              "PS512"
            ]
          }
        },
        "jwks_file": "data/oidc_op/private/token_jwks.json",
        "refresh": {
          "kwargs": {
            "lifetime": 86400
          }
        },
        "token": {
          "class": "oidcop.token.jwt_token.JWTToken",
          "kwargs": {
            "lifetime": 3600
          }
        }
      },
      "userinfo": {
        "class": "satosa.frontends.oidcop.user_info.SatosaOidcUserInfo"
      }
    }
  }
}

INTERNAL_ATTRIBUTES = {
    "attributes": {"mail": {"saml": ["email"], "openid": ["email"]}}
}

CLIENT_AUTHN_REQUEST = {
    'redirect_uri': CLIENT_RED_URL,
    'scope': 'openid profile email address phone',
    'response_type': 'code',
    'nonce': 'my_nonce',
    'state': 'my_state',
    # TODO
    # 'code_challenge': 'W-Wr0SA2lQgTEKrJm_t-RFzQtaY_-wXxrCp5PnanTe0',
    # 'code_challenge_method': 'S256',
    'client_id': CLIENT_1_ID
}

msg = {
    "application_type": "web",
    "redirect_uris": [
        "https://client.example.org/callback",
        "https://client.example.org/callback2",
    ],
    "client_name": "My Example",
    "client_name#ja-Jpan-JP": "クライアント名",
    "subject_type": "pairwise",
    "token_endpoint_auth_method": "client_secret_basic",
    "jwks_uri": "https://client.example.org/my_public_keys.jwks",
    "userinfo_encrypted_response_alg": "RSA-OAEP",
    "userinfo_encrypted_response_enc": "A128CBC-HS256",
    "contacts": ["ve7jtb@example.org", "mary@example.org"],
    "request_uris": [
        "https://client.example.org/rf.txt#qpXaRLh_n93TT",
        "https://client.example.org/rf.txt",
    ],
    "post_logout_redirect_uris": [
        "https://rp.example.com/pl?foo=bar",
        "https://rp.example.com/pl",
    ],
}

CLI_REQ = RegistrationRequest(**msg)


class TestOidcOpFrontend(object):

    def create_frontend(self, mongodb_instance, frontend_config=OIDCOP_CONF):
        # monkey patch
        def monkey_mongo(obj):
            obj.client = mongodb_instance

        # will use in-memory storage
        frontend = OidcOpFrontend(lambda ctx, req: None, INTERNAL_ATTRIBUTES,
                                  frontend_config, BASE_URL, "oidc_frontend")
        frontend.register_endpoints(["foo_backend"])
        return frontend

    @pytest.fixture
    def frontend(self, mongodb_instance):
        return self.create_frontend(mongodb_instance, OIDCOP_CONF)

    def test_jwks_endpoint(self, context, frontend):
        res = frontend.jwks_endpoint(context)
        assert res._status == "200 OK"
        msg = json.loads(res.message)
        assert msg.get('keys')

    def test_provider_info_endpoint(self, context, frontend):
        res = frontend.provider_info_endpoint(context)
        assert res._status == "200 OK"
        msg = json.loads(res.message)
        assert msg.get('token_endpoint_auth_methods_supported')

    def get_authn_req(self, **kwargs):
        """ produces default or customized oidc autz requests """
        data = copy.deepcopy(CLIENT_AUTHN_REQUEST)
        if kwargs:
            data.update(kwargs)

        req = AuthorizationRequest(**data)
        return req

    @pytest.fixture
    def authn_req(self):
        return self.get_authn_req()

    def insert_client_in_client_db(self, frontend, **kwargs):
        client_conf = copy.deepcopy(CLIENT_CONF)
        client_conf.update(kwargs)

        frontend.app.storage.insert_client(client_conf)
        client = frontend.app.storage.get_client_by_id(
                    client_conf['client_id'])
        return client

    def prepare_call(self, context, frontend, authn_req):
        frontend.auth_req_callback_func = lambda x, y: x
        client = self.insert_client_in_client_db(frontend)
        context.request = authn_req.to_dict()
        return client

    def test_authorization_endpoint(self, context, frontend, authn_req):
        client = self.prepare_call(context, frontend, authn_req)
        assert client['client_id'] == authn_req['client_id']
        res = frontend.authorization_endpoint(context)
        assert isinstance(res, Context)

    def test_handle_authn_request(self, context, frontend, authn_req):
        client = self.prepare_call(context, frontend, authn_req)
        res = frontend.handle_authn_request(context)
        assert isinstance(res, Context)

    def test_handle_authn_request_faulty(self, context, frontend, authn_req):
        client = self.prepare_call(context, frontend, authn_req)

        context.request = {'scope': 'email', 'response_type': 'code', 'client_id': CLIENT_1_ID}
        res = frontend.handle_authn_request(context)
        assert res['error_description'] == "Missing required attribute 'redirect_uri'"

        context.request['redirect_uri'] = CLIENT_RED_URL
        res = frontend.handle_authn_request(context)
        assert res['error_description'] == 'openid not in scope'

        context.request['scope'] = 'openid'
        res = frontend.handle_authn_request(context)
        # now's good :)

    def setup_for_authn_response(self, context, frontend, auth_req):
        context.state[frontend.name] = {"oidc_request": auth_req.to_dict()}
        auth_info = AuthenticationInformation(
            PASSWORD, "2021-09-30T12:21:37Z", "unittest_idp.xml"
        )
        internal_response = InternalData(auth_info=auth_info)
        internal_response.attributes = AttributeMapper(
            frontend.internal_attributes
        ).to_internal("saml", USERS["testuser1"])
        internal_response.subject_id = USERS["testuser1"]["eduPersonTargetedID"][0]

        return internal_response

    def test_handle_authn_response_authcode_flow(self, context, frontend, authn_req):
        self.insert_client_in_client_db(frontend, redirect_uri = authn_req["redirect_uri"])
        internal_response = self.setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        assert http_resp.message.startswith(authn_req["redirect_uri"])
        assert http_resp.status == '303 See Other'
        _res = urlparse(http_resp.message).query
        resp = AuthorizationResponse().from_urlencoded(_res)

        assert resp["scope"] == authn_req["scope"]
        assert resp["code"]
        assert frontend.name not in context.state
        # Test Token endpoint
        context.request = {
            'grant_type': 'authorization_code',
            'redirect_uri': CLIENT_RED_URL,
            'client_id': CLIENT_AUTHN_REQUEST['client_id'],
            'state': CLIENT_AUTHN_REQUEST['state'],
            'code': resp["code"],
            # TODO
            # 'code_verifier': 'ySfTlMpTEZPYU7H0XQZ75b3B568R5kkMkGRuRpQHOr1KNC9oimGnWygexLJuTyyT'
        }

        credentials = f"{CLIENT_1_ID}:{CLIENT_1_PASSWD}"
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        _basic_auth = f"Basic {basic_auth}"
        context.request_authorization = _basic_auth

        token_resp = frontend.token_endpoint(context)

        _token_resp = json.loads(token_resp.message)
        assert _token_resp.get('access_token')
        assert _token_resp.get('id_token')

        # Test UserInfo endpoint
        context.request = {}
        _access_token = _token_resp['access_token']
        context.request_authorization = f"{_token_resp['token_type']} {_access_token}"
        userinfo_resp = frontend.userinfo_endpoint(context)

        _userinfo_resp = json.loads(userinfo_resp.message)
        assert _userinfo_resp.get("sub")

        # Test token introspection endpoint
        context.request = {
         'token': _access_token,
         'token_type_hint': 'access_token'
        }
        context.request_authorization = _basic_auth
        introspection_resp = frontend.introspection_endpoint(context)
        assert json.loads(introspection_resp.message).get('sub')

    def test_fault_token_endpoint(self, context, frontend):
        # Test Token endpoint
        context.request = {
            'grant_type': 'authorization_code',
            'redirect_uri': CLIENT_RED_URL,
            'client_id': CLIENT_AUTHN_REQUEST['client_id'],
            'state': CLIENT_AUTHN_REQUEST['state'],
            'code': "FAKE-CODE",
            # TODO
            # 'code_verifier': 'ySfTlMpTEZPYU7H0XQZ75b3B568R5kkMkGRuRpQHOr1KNC9oimGnWygexLJuTyyT'
        }
        # and missing credentials ... just to test the exception in satosa
        # for security checks see oidcop tests

        # here fails client auth
        token_resp = frontend.token_endpoint(context)
        assert 'error' in token_resp.message

        # insert the client and miss client auth Basic
        self.insert_client_in_client_db(frontend)
        token_resp = frontend.token_endpoint(context)
        assert 'error' in token_resp.message

        # put also auth basic
        credentials = f"{CLIENT_1_ID}:{CLIENT_1_PASSWD}"
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = f"Basic {basic_auth}"
        token_resp = frontend.token_endpoint(context)
        assert token_resp.status == '403'
        assert json.loads(token_resp.message)['error'] == 'unauthorized_client'

    def test_load_cdb_basicauth(self, context, frontend):
        self.insert_client_in_client_db(frontend)
        credentials = f"{CLIENT_1_ID}:{CLIENT_1_PASSWD}"
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = f"Basic {basic_auth}"
        client = frontend._load_cdb(context)
        assert client

    def test_handle_authn_response_hibrid_flow(self, context, frontend, authn_req):
        response_type = "code id_token token".split(' ')
        self.insert_client_in_client_db(
            frontend,
            response_types = response_type,
            redirect_uri = authn_req["redirect_uri"],
        )
        authn_req['response_type'] = response_type
        internal_response = self.setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)

        res = dict(parse_qsl(urlparse(http_resp.message).query))
        assert res.get('access_token')
        assert res.get('id_token')
        assert res.get('code')

    def test_handle_authn_response_implicit_flow(self, context, frontend, authn_req):
        response_type = "id_token token".split(' ')
        self.insert_client_in_client_db(
            frontend,
            response_types = response_type,
            redirect_uri = authn_req["redirect_uri"],
        )
        authn_req['response_type'] = response_type
        internal_response = self.setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)

        res = dict(parse_qsl(urlparse(http_resp.message).query))
        assert res.get('access_token')
        assert res.get('id_token')


    def test_refresh_token(self, context, frontend, authn_req):
        response_type = "code".split(' ')
        scope = ["openid", "offline_access"]
        self.insert_client_in_client_db(
            frontend,
            response_types = response_type,
            redirect_uri = authn_req["redirect_uri"],
            scope = scope
        )

        authn_req['response_type'] = response_type
        authn_req['scope'] = ["openid", "offline_access"]
        internal_response = self.setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        assert http_resp.message.startswith(authn_req["redirect_uri"])

        assert http_resp.status == '303 See Other'
        _res = urlparse(http_resp.message).query
        resp = AuthorizationResponse().from_urlencoded(_res)

        assert resp["scope"] == authn_req["scope"]
        assert resp["code"]
        assert frontend.name not in context.state

        context.request = {
            'grant_type': 'authorization_code',
            'redirect_uri': CLIENT_RED_URL,
            'client_id': CLIENT_AUTHN_REQUEST['client_id'],
            'state': CLIENT_AUTHN_REQUEST['state'],
            'code': resp["code"],
            # TODO
            # 'code_verifier': 'ySfTlMpTEZPYU7H0XQZ75b3B568R5kkMkGRuRpQHOr1KNC9oimGnWygexLJuTyyT'
        }

        credentials = f"{CLIENT_1_ID}:{CLIENT_1_PASSWD}"
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        _basic_auth = f"Basic {basic_auth}"
        context.request_authorization = _basic_auth

        token_resp = frontend.token_endpoint(context)
        res = json.loads(token_resp.message)
        assert res.get('refresh_token')

        # test refresh token
        context.request = {
            "grant_type" : "refresh_token",
            "client_id" : CLIENT_1_ID,
            "client_secret" : CLIENT_1_PASSWD,
            "refresh_token" : res.get('refresh_token')
        }
        refresh_resp = frontend.token_endpoint(context)
        _res = json.loads(refresh_resp.message)
        assert _res.get('refresh_token')
        assert _res.get('access_token')

    # def test_private_key_jwt_token_endpoint(self, context, frontend):
        # """
        # Unused because we cannot have private_key_jwt/RFC7523 in satosa
        # client/rp is a machine, while auth code flow needs an human user

        # in satosa the user MUST call the authorization endpoint
        # """
        # client_assertion_data = {
            # "iss": CLIENT_1_ID,
            # "sub": CLIENT_1_ID,
            # "aud": [f"{BASE_URL}/OIDC/token"],
            # "jti": "my-opaque-jti-value",
            # "exp": (datetime.datetime.now() + datetime.timedelta(days=1)).timestamp(),
            # "iat": datetime.datetime.now().timestamp()

        # }
        # _private_key_jwt = AuthnToken(**client_assertion_data)
        # client_assertion = _private_key_jwt.to_jwt(key=[CLIENT_RSA_KEY], algorithm='RS256')

        # ## Test Token endpoint
        # context.request = {
            # 'grant_type': 'authorization_code',
            # 'redirect_uri': CLIENT_RED_URL,
            # 'state': CLIENT_AUTHN_REQUEST['state'],
            # 'code': "FAKE-CODE",
            # "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            # "client_assertion": client_assertion
        # }
        # self.insert_client_in_client_db(frontend)
        # token_resp = frontend.token_endpoint(context)
        # breakpoint()

    def test_client_registration_endpoint(self, context, frontend, authn_req):
        # just to test reserved client_id
        self.insert_client_in_client_db(frontend)

        context.request = CLI_REQ.to_dict()
        http_resp = frontend.registration_endpoint(context)
        _resp = json.loads(http_resp.message)
        assert _resp['client_id']

    def test_client_registration_read_endpoint(self, context, frontend, authn_req):
        self.insert_client_in_client_db(frontend)
        _bearer_auth = f"Bearer {CLIENT_1_RAT}"
        context.request_authorization = _bearer_auth
        context.request = {'client_id': CLIENT_1_ID}
        http_resp = frontend.registration_read_endpoint(context)
        _resp = json.loads(http_resp.message)
        assert _resp['client_id'] == CLIENT_1_ID
        assert _resp['client_secret'] == CLIENT_1_PASSWD

    def teardown(self):
        """ Clean up mongo """
        frontend = self.create_frontend(OIDCOP_CONF)
        frontend.app.storage.client_db.drop()
        frontend.app.storage.session_db.drop()
