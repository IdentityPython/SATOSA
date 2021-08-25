import copy
import datetime
import pytest

from oidcmsg.oidc import AccessTokenRequest
from oidcmsg.oidc import AuthorizationRequest
from satosa.context import Context
from satosa.frontends.idpy_oidcop import OidcOpFrontend
from unittest.mock import Mock
from urllib.parse import urlparse, parse_qsl

CLIENT_1_ID = 'jbxedfmfyc'
CLIENT_1_PASSWD = '19cc69b70d0108f630e52f72f7a3bd37ba4e11678ad1a7434e9818e1'
CLIENT_1_RAT = 'z3PCMmC1HZ1QmXeXGOQMJpWQNQynM4xY'
CLIENT_RED_URL = 'https://127.0.0.1:8090/authz_cb/satosa'
CLIENT_1_SESLOGOUT = 'https://127.0.0.1:8090/session_logout/satosa'
CLIENT_CONF = {
        'client_id': CLIENT_1_ID,
        'client_salt': '6flfsj0Z',
        'registration_access_token': CLIENT_1_RAT,
        'registration_client_uri': f'https://127.0.0.1:8000/registration_api?client_id={CLIENT_1_ID}',
        'client_id_issued_at': datetime.datetime.utcnow(),
        'client_secret': CLIENT_1_PASSWD,
        'client_secret_expires_at': (datetime.datetime.utcnow() + datetime.timedelta(days=1)).timestamp(),
        'application_type': 'web',
        'contacts': ['ops@example.com'],
        'token_endpoint_auth_method': 'client_secret_basic',
        # 'jwks_uri': 'https://127.0.0.1:8099/static/jwks.json',
        'redirect_uris': [(CLIENT_RED_URL, {})],
        'post_logout_redirect_uris': [(CLIENT_1_SESLOGOUT, None)],
        'response_types': ['code'],
        'grant_types': ['authorization_code'],
        'allowed_scopes': ['openid', 'profile', 'email', 'offline_access']
}

BASE_URL = "https://localhost:10000"
OIDCOP_CONF = {
  "domain": "localhost",
  "server_name": "localhost",
  "base_url": BASE_URL,
  "storage": {
    "class": "satosa.frontends.oidcop.storage.mongo.Mongodb",
    "kwargs": {
      "url": "mongodb://172.21.0.3:27017/oidcop",
      "connection_params": {
        "username": "satosa",
        "password": "thatpassword",
        "connectTimeoutMS": 5000,
        "socketTimeoutMS": 5000,
        "serverSelectionTimeoutMS": 5000
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
        }
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
    'redirect_uri': 'https://127.0.0.1:8090/authz_cb/satosa',
    'scope': 'openid profile email address phone',
    'response_type': 'code',
    'nonce': '8FBvLJrlNlp64BR9BAUcP48P',
    'state': 'TBE6uB954uMeFYb7Iw2MAgE1FfWkgvWO',
    'code_challenge': 'W-Wr0SA2lQgTEKrJm_t-RFzQtaY_-wXxrCp5PnanTe0',
    'code_challenge_method': 'S256',
    'client_id': 'jbxedfmfyc'
}


class TestOidcOpFrontend(object):

    def create_frontend(self, frontend_config=OIDCOP_CONF):
        # will use in-memory storage
        frontend = OidcOpFrontend(lambda ctx, req: None, INTERNAL_ATTRIBUTES,
                                  frontend_config, BASE_URL, "oidc_frontend")
        frontend.register_endpoints(["foo_backend"])
        return frontend

    @pytest.fixture
    def frontend(self):
        return self.create_frontend(OIDCOP_CONF)

    def get_authn_req(self, **kwargs):
        """ produces default or customized oidc autz requests """
        if not kwargs:
            kwargs = dict(
                client_id=CLIENT_1_ID, state="my_state", scope="openid",
                response_type="code", redirect_uri=CLIENT_RED_URL,
                nonce="nonce"
            )
        req = AuthorizationRequest(**kwargs)
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
