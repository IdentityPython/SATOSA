"""
Complete test for a SAML to SAML proxy.
"""
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
from tests.util import FakeSP, FakeIdP, FileGenerator
from tests.users import USERS

INTERNAL_ATTRIBUTES = {
    'attributes': {'displayname': {'openid': ['nickname'], 'saml': ['displayName']},
                   'givenname': {'saml': ['givenName'], 'openid': ['given_name'],
                                 'facebook': ['first_name']},
                   'mail': {'saml': ['email', 'emailAdress', 'mail'], 'openid': ['email'],
                            'facebook': ['email']},
                   'edupersontargetedid': {'saml': ['eduPersonTargetedID'], 'openid': ['sub'],
                                           'facebook': ['id']},
                   'name': {'saml': ['cn'], 'openid': ['name'], 'facebook': ['name']},
                   'address': {'openid': ['address->street_address'], 'saml': ['postaladdress']},
                   'surname': {'saml': ['sn', 'surname'], 'openid': ['family_name'],
                               'facebook': ['last_name']}}, 'separator': '->'}

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

        self.xmlsec_path = "/usr/bin/xmlsec1"

        proxy_config_dict = {"HOST": 'localhost',
                             "PORT": 8090,
                             "HTTPS": True,
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
                  "encryption_key": "asd89673oeirds90",
                  "idp_entity_id": "https://example.com/unittest_idp.xml",
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
                  "base": base_url}

        super(Saml2FrontendPlugin, self).__init__(SamlFrontend, "Saml2IDP", config)


class ProxyTest(helper.CPWebCase):
    """
    Performs a complete flow test for the proxy.
    Verifies SAML -> PROXY -> SAML in a cherrypy server.
    """
    def setUp(self):
        """
        Initiates the test.
        :return: None
        """
        self.sp = FakeSP(None, config=SPConfig().load(TestConfiguration.get_instance().
                                                      fake_sp_config,
                                                      metadata_construction=False))
        self.idp = FakeIdP(USERS, IdPConfig().load(TestConfiguration.get_instance().fake_idp_config,
                                                   metadata_construction=False))

    @staticmethod
    def setup_server():
        """
        Creates a new server.

        :return: None
        """
        app = WsgiApplication(config=TestConfiguration.get_instance().proxy_config)

        cherrypy.tree.graft(app.run_server, '/')

    def test_flow(self):
        """
        Performs the test.
        """
        e_id = 'https://localhost:8090/proxy.xml'
        target_id = 'https://example.com/unittest_idp.xml'

        url = self.sp.make_auth_req(e_id)
        url = "%s&entityID=%s" % (url, quote(target_id))
        status, headers, _ = self.getPage(url)
        assert status == '303 See Other'
        cookie_header = None
        for header in headers:
            if header[0] == "Set-Cookie":
                cookie_header = header[1]
                break
        assert cookie_header, "Did not save state in cookie!"

        url = self.get_redirect_location(headers)
        req = parse_qs(urlsplit(url).query)
        assert 'SAMLRequest' in req
        assert 'RelayState' in req

        action, body = self.idp.handle_auth_req(req['SAMLRequest'][0],
                                                req['RelayState'][0],
                                                BINDING_HTTP_REDIRECT,
                                                'testuser1')
        status, headers, body = self.getPage(action, method='POST', body=urlencode(body), headers=[("Cookie", cookie_header)])
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
        """
        Gets the redirect location from the header.
        :type headers: {list}
        :rtype: str

        :param headers: A list of (str, str) tuples.
        :return: An URL for the redirect.
        """
        for header, value in headers:
            if header.lower() == 'location':
                return value
