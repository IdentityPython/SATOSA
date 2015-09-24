# pylint: disable = missing-docstring
import os
import inspect
from urllib.parse import urlsplit, parse_qs, urlencode, quote
import sys

from cherrypy.test import helper

from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
import cherrypy

from saml2.config import SPConfig, IdPConfig

from satosa.backends.saml2 import SamlBackend
from satosa.frontends.saml2 import SamlFrontend
from satosa.plugin_base.endpoint import BackendModulePlugin, FrontendModulePlugin
from satosa.satosa_config import SATOSAConfig
from tests.wsgi_server import WsgiApplication
from tests.util import FakeSP, FakeIdP, generate_cert, create_metadata
from tests.users import USERS





# Add test directory to path to be able to import configurations
sys.path.append(os.path.dirname(__file__))

xmlsec_path = "/usr/local/bin/xmlsec1"

PROXY_CONFIG_DICT = {"HOST": 'localhost',
                     "PORT": 8090,
                     "HTTPS": True,
                     "PLUGIN_PATH": [os.path.dirname(__file__)],
                     "BACKEND_MODULES": [inspect.getmodulename(__file__)],
                     "FRONTEND_MODULES": [inspect.getmodulename(__file__)]}

PROXY_CONFIG = SATOSAConfig(PROXY_CONFIG_DICT)

FRONTEND_METADATA = []
BACKEND_METADATA = []
FAKE_IDP_METADATA = []
FAKE_SP_METADATA = []

BACKEND_CERT, BACKEND_KEY = generate_cert("Saml2Backend")

class Saml2BackendPlugin(BackendModulePlugin):
    provider = "Saml2"

    @staticmethod
    def get_instance(base_url):
        module_base = "%s/%s" % (base_url, Saml2BackendPlugin.provider)
        config = {
            "idp_entity_id": "https://example.com/unittest_idp.xml",
            "entityid": "%s/proxy_sp.xml" % module_base,
            "service": {
                "sp": {
                    "allow_unsolicited": True,
                    "endpoints": {
                        "assertion_consumer_service": [
                            ("%s/acs/post" % module_base, BINDING_HTTP_POST),
                            ("%s/acs/redirect" % module_base, BINDING_HTTP_REDIRECT)
                        ],
                    }
                }
            },
            "key_file": BACKEND_KEY.name,
            "cert_file": BACKEND_CERT.name,
            "metadata": {
                "local": FAKE_IDP_METADATA,
            },

            "xmlsec_binary": xmlsec_path,
        }

        return Saml2BackendPlugin(SamlBackend, Saml2BackendPlugin.provider, config)


FRONTEND_CERT, FRONTEND_KEY = generate_cert("Saml2Frontend")


class Saml2FrontendPlugin(FrontendModulePlugin):
    endpoints = {"single_sign_on_service": {BINDING_HTTP_REDIRECT: "sso/redirect",
                                            BINDING_HTTP_POST: "sso/post"}}

    @staticmethod
    def get_instance(base_url):
        idpConfig = {
            "entityid": "{}/proxy.xml".format(base_url),
            "service": {
                "idp": {
                    "endpoints": {
                        "single_sign_on_service": [("%s/%s/sso/redirect" % (
                            base_url, Saml2BackendPlugin.provider), BINDING_HTTP_REDIRECT),
                                                   ("%s/%s/sso/post" % (
                                                       base_url, Saml2BackendPlugin.provider),
                                                    BINDING_HTTP_POST)],
                    },
                },
            },
            "key_file": FRONTEND_KEY.name,
            "cert_file": FRONTEND_CERT.name,
            "metadata": {
                "local": FAKE_SP_METADATA,
            },
            "xmlsec_binary": xmlsec_path,
        }

        config = {"idp_config": idpConfig,
                  "endpoints": Saml2FrontendPlugin.endpoints,
                  "base": base_url}

        return Saml2FrontendPlugin(SamlFrontend, "Saml2IDP", config)


FAKE_IDP_BASE = "https://example.com"
FAKE_IDP_CERT, FAKE_IDP_KEY = generate_cert()
FAKE_IDP_CONFIG = {
    "entityid": "{}/unittest_idp.xml".format(FAKE_IDP_BASE),
    "service": {
        "idp": {
            "endpoints": {
                "single_sign_on_service": [
                    ("%s/sso/post" % FAKE_IDP_BASE, BINDING_HTTP_POST),
                    ("%s/sso/redirect" % FAKE_IDP_BASE, BINDING_HTTP_REDIRECT),
                ],
            },
        },
    },
    "key_file": FAKE_IDP_KEY.name,
    "cert_file": FAKE_IDP_CERT.name,
    "metadata": {
        "local": BACKEND_METADATA,
    },
    "xmlsec_binary": xmlsec_path,
}

FAKE_SP_BASE = "http://example.com"
FAKE_SP_CERT, FAKE_SP_KEY = generate_cert()
FAKE_SP_CONFIG = {
    "entityid": "{}/unittest_sp.xml".format(FAKE_SP_BASE),
    "service": {
        "sp": {
            "endpoints": {
                "assertion_consumer_service": [
                    ("%s/acs/redirect" % FAKE_SP_BASE, BINDING_HTTP_REDIRECT),
                    ("%s/acs/post" % FAKE_SP_BASE, BINDING_HTTP_POST)
                ],
            },
            "allow_unsolicited": "true",
        },
    },
    "key_file": FAKE_SP_KEY.name,
    "cert_file": FAKE_SP_CERT.name,
    "metadata": {
        "local": FRONTEND_METADATA,
    },
    "xmlsec_binary": xmlsec_path,
}

FAKE_IDP_METADATA_FILE = create_metadata(FAKE_IDP_CONFIG)
FAKE_SP_METADATA_FILE = create_metadata(FAKE_SP_CONFIG)
FRONTEND_METADATA_FILE = create_metadata(
    Saml2FrontendPlugin.get_instance(PROXY_CONFIG.BASE).config["idp_config"])
BACKEND_METADATA_FILE = create_metadata(Saml2BackendPlugin.get_instance(PROXY_CONFIG.BASE).config)

FAKE_IDP_METADATA.append(FAKE_IDP_METADATA_FILE.name)
FAKE_SP_METADATA.append(FAKE_SP_METADATA_FILE.name)
FRONTEND_METADATA.append(FRONTEND_METADATA_FILE.name)
BACKEND_METADATA.append(BACKEND_METADATA_FILE.name)


class ProxyTest(helper.CPWebCase):
    def setUp(self):
        self.sp = FakeSP(None, config=SPConfig().load(FAKE_SP_CONFIG, metadata_construction=False))
        self.idp = FakeIdP(USERS, IdPConfig().load(FAKE_IDP_CONFIG, metadata_construction=False))

    @staticmethod
    def setup_server():
        app = WsgiApplication(config=PROXY_CONFIG)

        cherrypy.tree.graft(app.run_server, '/')

    def test_flow(self):
        e_id = 'https://localhost:8090/proxy.xml'
        target_id = 'https://example.com/unittest_idp.xml'

        url = self.sp.make_auth_req(e_id)
        url = "%s&entityID=%s" % (url, quote(target_id))
        status, headers, _ = self.getPage(url)
        assert status == '303 See Other'

        url = self.get_redirect_location(headers)
        req = parse_qs(urlsplit(url).query)
        assert 'SAMLRequest' in req
        assert 'RelayState' in req

        action, body = self.idp.handle_auth_req(req['SAMLRequest'][0],
                                                req['RelayState'][0],
                                                BINDING_HTTP_REDIRECT,
                                                'testuser1')
        status, headers, body = self.getPage(action, method='POST',
                                             body=urlencode(body))
        assert status == '302 Found'

        url = self.get_redirect_location(headers)
        req = parse_qs(urlsplit(url).query)
        assert 'SAMLResponse' in req
        assert 'RelayState' in req
        resp = self.sp.parse_authn_request_response(req['SAMLResponse'][0],
                                                    BINDING_HTTP_REDIRECT)

        identity = resp.ava
        assert identity["displayName"][0] == "Test Testsson"

    def get_redirect_location(self, headers):
        for header, value in headers:
            if header.lower() == 'location':
                return value
