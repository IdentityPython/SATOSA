"""
Complete test for a SAML to SAML proxy.
"""
import inspect
import os
import os.path
import sys
from urllib.parse import urlsplit, parse_qs, urlencode, quote, urlparse

import pytest
from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
from saml2.config import SPConfig, IdPConfig
from werkzeug.test import Client
from werkzeug.wrappers import BaseResponse

from satosa.backends.saml2 import SamlBackend
from satosa.frontends.saml2 import SamlFrontend
from satosa.plugin_base.endpoint import BackendModulePlugin, FrontendModulePlugin
from satosa.proxy_server import WsgiApplication
from satosa.satosa_config import SATOSAConfig
from tests.users import USERS
from tests.util import FakeSP, FakeIdP, FileGenerator

INTERNAL_ATTRIBUTES = {
    'attributes': {'displayname': {'openid': ['nickname'], 'saml': ['displayName']},
                   'givenname': {'saml': ['givenName'], 'openid': ['given_name'],
                                 'facebook': ['first_name']},
                   'mail': {'saml': ['email', 'emailAdress', 'mail'], 'openid': ['email'],
                            'facebook': ['email']},
                   'edupersontargetedid': {'saml': ['eduPersonTargetedID'], 'openid': ['sub'],
                                           'facebook': ['id']},
                   'name': {'saml': ['cn'], 'openid': ['name'], 'facebook': ['name']},
                   'address': {'openid': ['address.street_address'], 'saml': ['postaladdress']},
                   'surname': {'saml': ['sn', 'surname'], 'openid': ['family_name'],
                               'facebook': ['last_name']}}}


class TestConfiguration(object):
    """
    Contains all metadata, cert and key configurations.
    """
    _instance = None

    def __init__(self):
        if TestConfiguration._instance:
            raise TypeError('Singletons must be accessed through `get_instance()`.')
        else:
            TestConfiguration._instance = self
        # Add test directory to path to be able to import configurations
        sys.path.append(os.path.dirname(__file__))

        if os.path.isfile("/usr/bin/xmlsec1"):
            self.xmlsec_path = "/usr/bin/xmlsec1"
        elif os.path.isfile("/usr/local/bin/xmlsec1"):
            self.xmlsec_path = "/usr/local/bin/xmlsec1"

        proxy_config_dict = {"BASE": "https://localhost:8090",
                             "COOKIE_STATE_NAME": "TEST_STATE",
                             "STATE_ENCRYPTION_KEY": "ASDasd123",
                             "PLUGIN_PATH": [os.path.dirname(__file__)],
                             "BACKEND_MODULES": [inspect.getmodulename(__file__)],
                             "FRONTEND_MODULES": [inspect.getmodulename(__file__)],
                             "USER_ID_HASH_SALT": "qwerty",
                             "INTERNAL_ATTRIBUTES": INTERNAL_ATTRIBUTES}

        self.proxy_config = SATOSAConfig(proxy_config_dict)

        frontend_metadata = []
        backend_metadata = []
        self.fake_idp_metadata = []
        self.fake_sp_metadata = []

        self.backend_cert, self.backend_key = \
            FileGenerator.get_instance().generate_cert("Saml2Backend")
        self.frontend_cert, self.frontend_key = \
            FileGenerator.get_instance().generate_cert("Saml2Frontend")

        fake_idp_base = "https://example.com"
        fake_idp_cert, fake_idp_key = FileGenerator.get_instance().generate_cert("fake_idp")
        self.fake_idp_config = {
            "entityid": "{}/unittest_idp.xml".format(fake_idp_base),
            "service": {
                "idp": {
                    "endpoints": {
                        "single_sign_on_service": [
                            ("%s/sso/post" % fake_idp_base, BINDING_HTTP_POST),
                            ("%s/sso/redirect" % fake_idp_base, BINDING_HTTP_REDIRECT),
                        ],
                    },
                },
            },
            "key_file": fake_idp_key.name,
            "cert_file": fake_idp_cert.name,
            "metadata": {
                "local": backend_metadata,
            },
            "xmlsec_binary": self.xmlsec_path,
        }

        fake_sp_base = "http://example.com"
        fake_sp_cert, fake_sp_key = FileGenerator.get_instance().generate_cert("fake_sp")
        self.fake_sp_config = {
            "entityid": "{}/unittest_sp.xml".format(fake_sp_base),
            "service": {
                "sp": {
                    "endpoints": {
                        "assertion_consumer_service": [
                            ("%s/acs/redirect" % fake_sp_base, BINDING_HTTP_REDIRECT),
                            ("%s/acs/post" % fake_sp_base, BINDING_HTTP_POST)
                        ],
                    },
                    "allow_unsolicited": "true",
                },
            },
            "key_file": fake_sp_key.name,
            "cert_file": fake_sp_cert.name,
            "metadata": {
                "local": frontend_metadata,
            },
            "xmlsec_binary": self.xmlsec_path,
        }

        fake_idp_metadata_file = FileGenerator.get_instance().create_metadata(
            self.fake_idp_config,
            "fake_idp")
        fake_sp_metadata_file = FileGenerator.get_instance().create_metadata(
            self.fake_sp_config,
            "fake_sp")
        frontend_metadata_file = FileGenerator.get_instance().create_metadata(
            Saml2FrontendPlugin(self.proxy_config.BASE).config["idp_config"],
            "frontend")
        backend_metadata_file = FileGenerator.get_instance().create_metadata(
            Saml2BackendPlugin(self.proxy_config.BASE).config["config"], "backend")

        self.fake_idp_metadata.append(fake_idp_metadata_file.name)
        self.fake_sp_metadata.append(fake_sp_metadata_file.name)
        frontend_metadata.append(frontend_metadata_file.name)
        backend_metadata.append(backend_metadata_file.name)

    @staticmethod
    def get_instance():
        """
        Returns an instance of the singleton class.
        """
        if not TestConfiguration._instance:
            TestConfiguration._instance = TestConfiguration()
        return TestConfiguration._instance


class Saml2BackendPlugin(BackendModulePlugin):
    """
    Plugin containing the configuration for the module SamlBackend.
    """
    provider = "Saml2"

    def __init__(self, base_url):
        """
        Creates an instance of the class with defined configuration.

        :type base_url: str
        :rtype: Saml2BackendPlugin

        :param base_url: Base url for the proxy server.
        :return: Object instance for this class.
        """
        module_base = "%s/%s" % (base_url, Saml2BackendPlugin.provider)
        sp_config = {
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
            "key_file": TestConfiguration.get_instance().backend_key.name,
            "cert_file": TestConfiguration.get_instance().backend_cert.name,
            "metadata": {
                "local": TestConfiguration.get_instance().fake_idp_metadata,
            },

            "xmlsec_binary": TestConfiguration.get_instance().xmlsec_path,
        }
        config = {"config": sp_config,
                  "idp_entity_id": "https://example.com/unittest_idp.xml",
                  "state_id": "saml_backend_test_id"
                  }

        super(Saml2BackendPlugin, self).__init__(SamlBackend, Saml2BackendPlugin.provider, config)


class Saml2FrontendPlugin(FrontendModulePlugin):
    """
    Plugin containing the configuration for the module SamlFrontend.
    """
    endpoints = {"single_sign_on_service": {BINDING_HTTP_REDIRECT: "sso/redirect",
                                            BINDING_HTTP_POST: "sso/post"}}

    def __init__(self, base_url):
        """
        Creates an instance of the class with defined configuration.

        :type base_url: str
        :rtype: Saml2FrontendPlugin

        :param base_url: Base url for the proxy server.
        :return: Object instance for this class.
        """
        idpconfig = {
            "entityid": "{}/proxy.xml".format(base_url),
            "service": {
                "idp": {
                    "endpoints": {
                        "single_sign_on_service": [("%s/%s/sso/redirect" %
                                                    (base_url, Saml2BackendPlugin.provider),
                                                    BINDING_HTTP_REDIRECT),
                                                   ("%s/%s/sso/post" %
                                                    (base_url, Saml2BackendPlugin.provider),
                                                    BINDING_HTTP_POST)]
                    },
                },
            },
            "key_file": TestConfiguration.get_instance().frontend_key.name,
            "cert_file": TestConfiguration.get_instance().frontend_cert.name,
            "metadata": {
                "local": TestConfiguration.get_instance().fake_sp_metadata,
            },
            "xmlsec_binary": TestConfiguration.get_instance().xmlsec_path,
        }

        config = {"idp_config": idpconfig,
                  "endpoints": Saml2FrontendPlugin.endpoints,
                  "base": base_url,
                  "state_id": "saml_frontend_state_id"}

        super(Saml2FrontendPlugin, self).__init__(SamlFrontend, "Saml2IDP", config)


class TestProxy:
    """
    Performs a complete flow test for the proxy.
    Verifies SAML -> PROXY -> SAML.
    """

    @pytest.fixture(autouse=True)
    def setup(self):
        """
        Initiates the test.
        :return: None
        """
        self.sp = FakeSP(None, config=SPConfig().load(TestConfiguration.get_instance().
                                                      fake_sp_config,
                                                      metadata_construction=False))
        self.idp = FakeIdP(USERS, IdPConfig().load(TestConfiguration.get_instance().fake_idp_config,
                                                   metadata_construction=False))

    def test_flow(self):
        """
        Performs the test.
        """
        e_id = 'https://localhost:8090/proxy.xml'
        target_id = 'https://example.com/unittest_idp.xml'
        url = "{}&entityID={}".format(self.sp.make_auth_req(e_id), quote(target_id))

        app = WsgiApplication(config=TestConfiguration.get_instance().proxy_config)
        test_client = Client(app.run_server, BaseResponse)

        parsed = urlparse(url)
        request = "{}?{}".format(parsed.path, parsed.query)

        resp = test_client.get(request)
        assert resp.status == '303 See Other'
        headers = dict(resp.headers)
        assert headers["Set-Cookie"], "Did not save state in cookie!"

        url = headers["location"]
        req = parse_qs(urlsplit(url).query)
        assert 'SAMLRequest' in req
        assert 'RelayState' in req

        action, body = self.idp.handle_auth_req(req['SAMLRequest'][0],
                                                req['RelayState'][0],
                                                BINDING_HTTP_REDIRECT,
                                                'testuser1')

        parsed = urlparse(action)
        request = "{}?{}".format(parsed.path, parsed.query)
        resp = test_client.post(request, data=urlencode(body),
                                headers=[("Cookie", headers["Set-Cookie"]),
                                         ("Content-Type", "application/x-www-form-urlencoded")])
        assert resp.status == '302 Found'

        headers = dict(resp.headers)
        url = headers["location"]
        req = parse_qs(urlsplit(url).query)
        assert 'SAMLResponse' in req
        assert 'RelayState' in req
        resp = self.sp.parse_authn_request_response(req['SAMLResponse'][0], BINDING_HTTP_REDIRECT)

        identity = resp.ava
        assert identity["displayName"][0] == "Test Testsson"
