from urllib.parse import parse_qsl, urlparse, urlencode

from saml2 import BINDING_HTTP_REDIRECT
from saml2.config import SPConfig, IdPConfig
from werkzeug.test import Client
from werkzeug.wrappers import Response

from satosa.metadata_creation.saml_metadata import create_entity_descriptors
from satosa.proxy_server import make_app
from satosa.satosa_config import SATOSAConfig
from tests.users import USERS
from tests.util import FakeSP, FakeIdP


class TestSAMLToSAML:
    def run_test(self, satosa_config_dict, sp_conf, idp_conf, saml_backend_config, frontend_config):
        subject_id = "testuser1"
        # proxy config
        satosa_config_dict["FRONTEND_MODULES"] = [frontend_config]
        satosa_config_dict["BACKEND_MODULES"] = [saml_backend_config]
        satosa_config_dict["INTERNAL_ATTRIBUTES"]["attributes"] = {attr_name: {"saml": [attr_name]} for attr_name in
                                                                   USERS[subject_id]}
        frontend_metadata, backend_metadata = create_entity_descriptors(SATOSAConfig(satosa_config_dict))

        # application
        test_client = Client(make_app(SATOSAConfig(satosa_config_dict)), Response)

        # config test SP
        frontend_metadata_str = str(frontend_metadata[frontend_config["name"]][0])
        sp_conf["metadata"]["inline"].append(frontend_metadata_str)
        fakesp = FakeSP(SPConfig().load(sp_conf))

        # create auth req
        destination, req_args = fakesp.make_auth_req(frontend_metadata[frontend_config["name"]][0].entity_id)
        auth_req = urlparse(destination).path + "?" + urlencode(req_args)

        # make auth req to proxy
        proxied_auth_req = test_client.get(auth_req)
        assert proxied_auth_req.status == "303 See Other"

        # config test IdP
        backend_metadata_str = str(backend_metadata[saml_backend_config["name"]][0])
        idp_conf["metadata"]["inline"].append(backend_metadata_str)
        fakeidp = FakeIdP(USERS, config=IdPConfig().load(idp_conf))

        # create auth resp
        req_params = dict(parse_qsl(urlparse(proxied_auth_req.data.decode("utf-8")).query))
        url, authn_resp = fakeidp.handle_auth_req(
            req_params["SAMLRequest"],
            req_params["RelayState"],
            BINDING_HTTP_REDIRECT,
            subject_id,
            response_binding=BINDING_HTTP_REDIRECT)

        # make auth resp to proxy
        authn_resp_req = urlparse(url).path + "?" + urlencode(authn_resp)
        authn_resp = test_client.get(authn_resp_req)
        assert authn_resp.status == "303 See Other"

        # verify auth resp from proxy
        resp_dict = dict(parse_qsl(urlparse(authn_resp.data.decode("utf-8")).query))
        auth_resp = fakesp.parse_authn_request_response(resp_dict["SAMLResponse"], BINDING_HTTP_REDIRECT)
        assert auth_resp.ava == USERS[subject_id]

    def test_full_flow(self, satosa_config_dict, sp_conf, idp_conf, saml_backend_config,
                       saml_frontend_config, saml_mirror_frontend_config):
        for conf in [saml_frontend_config, saml_mirror_frontend_config]:
            self.run_test(satosa_config_dict, sp_conf, idp_conf, saml_backend_config, conf)
