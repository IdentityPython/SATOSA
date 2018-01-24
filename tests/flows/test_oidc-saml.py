import json
from urllib.parse import urlparse, urlencode, parse_qsl

import pytest
from jwkest.jwk import rsa_load, RSAKey
from jwkest.jws import JWS
from oic.oic.message import ClaimsRequest, Claims
from pyop.storage import MongoWrapper
from saml2 import BINDING_HTTP_REDIRECT
from saml2.config import IdPConfig
from werkzeug.test import Client
from werkzeug.wrappers import BaseResponse

from satosa.metadata_creation.saml_metadata import create_entity_descriptors
from satosa.proxy_server import make_app
from satosa.satosa_config import SATOSAConfig
from tests.users import USERS
from tests.util import FakeIdP

CLIENT_ID = "client1"
REDIRECT_URI = "https://client.example.com/cb"


@pytest.fixture
def oidc_frontend_config(signing_key_path, mongodb_instance):
    data = {
        "module": "satosa.frontends.openid_connect.OpenIDConnectFrontend",
        "name": "OIDCFrontend",
        "config": {
            "issuer": "https://proxy-op.example.com",
            "signing_key_path": signing_key_path,
            "provider": {"response_types_supported": ["id_token"]},
            "db_uri": mongodb_instance.get_uri()  # use mongodb for integration testing
        }
    }

    # insert client in mongodb
    cdb = MongoWrapper(mongodb_instance.get_uri(), "satosa", "clients")
    cdb[CLIENT_ID] = {
        "redirect_uris": [REDIRECT_URI],
        "response_types": ["id_token"]
    }

    return data


class TestOIDCToSAML:
    def test_full_flow(self, satosa_config_dict, oidc_frontend_config, saml_backend_config, idp_conf):
        user_id = "testuser1"

        # proxy config
        satosa_config_dict["FRONTEND_MODULES"] = [oidc_frontend_config]
        satosa_config_dict["BACKEND_MODULES"] = [saml_backend_config]
        satosa_config_dict["INTERNAL_ATTRIBUTES"]["attributes"] = {attr_name: {"openid": [attr_name],
                                                                               "saml": [attr_name]}
                                                                   for attr_name in USERS[user_id]}
        _, backend_metadata = create_entity_descriptors(SATOSAConfig(satosa_config_dict))

        # application
        test_client = Client(make_app(SATOSAConfig(satosa_config_dict)), BaseResponse)

        # get frontend OP config info
        provider_config = json.loads(test_client.get("/.well-known/openid-configuration").data.decode("utf-8"))

        # create auth req
        claims_request = ClaimsRequest(id_token=Claims(**{k: None for k in USERS[user_id]}))
        req_args = {"scope": "openid", "response_type": "id_token", "client_id": CLIENT_ID,
                    "redirect_uri": REDIRECT_URI, "nonce": "nonce",
                    "claims": claims_request.to_json()}
        auth_req = urlparse(provider_config["authorization_endpoint"]).path + "?" + urlencode(req_args)

        # make auth req to proxy
        proxied_auth_req = test_client.get(auth_req)
        assert proxied_auth_req.status == "303 See Other"

        # config test IdP
        backend_metadata_str = str(backend_metadata[saml_backend_config["name"]][0])
        idp_conf["metadata"]["inline"].append(backend_metadata_str)
        fakeidp = FakeIdP(USERS, config=IdPConfig().load(idp_conf, metadata_construction=False))

        # create auth resp
        req_params = dict(parse_qsl(urlparse(proxied_auth_req.data.decode("utf-8")).query))
        url, authn_resp = fakeidp.handle_auth_req(
            req_params["SAMLRequest"],
            req_params["RelayState"],
            BINDING_HTTP_REDIRECT,
            user_id,
            response_binding=BINDING_HTTP_REDIRECT)

        # make auth resp to proxy
        authn_resp_req = urlparse(url).path + "?" + urlencode(authn_resp)
        authn_resp = test_client.get("/" + authn_resp_req)
        assert authn_resp.status == "303 See Other"

        # verify auth resp from proxy
        resp_dict = dict(parse_qsl(urlparse(authn_resp.data.decode("utf-8")).fragment))
        signing_key = RSAKey(key=rsa_load(oidc_frontend_config["config"]["signing_key_path"]),
                             use="sig", alg="RS256")
        id_token_claims = JWS().verify_compact(resp_dict["id_token"], keys=[signing_key])
        assert all((k, v) in {ck:cv if isinstance(cv,list) else [cv] for ck, cv in id_token_claims.items()}.items() for k, v in USERS[user_id].items())
