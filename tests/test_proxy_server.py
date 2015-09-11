# pylint: disable = missing-docstring
import os
from urllib.parse import urlsplit, parse_qs, urlencode

from cherrypy.test import helper

from saml2 import BINDING_HTTP_REDIRECT
import cherrypy
import sys

from vopaas_proxy.server import WsgiApplication
from tests.test_util import FakeSP, FakeIdP

USERS = {
    'test1': {
        'c': 'SE',
        'displayName': 'Test1',
        'eduPersonPrincipalName': 'test1@example.com',
        'eduPersonScopedAffiliation': 'staff@example.com',
        'eduPersonTargetedID': 'one!for!all',
        'email': 'test1@example.com',
        'givenName': 'Test1',
        'initials': 'T1.T',
        'labeledURL': 'http://www.example.com/test1 My homepage',
        'norEduPersonNIN': 'SE199012315555',
        'o': 'Example Co.',
        'ou': 'IT',
        'schacHomeOrganization': 'example.com',
        'sn': 'Testsson',
        'uid': 'test1',
    },
}

# Add test directory to path to be able to import configurations
sys.path.append(os.path.dirname(__file__))


class ProxyTest(helper.CPWebCase):
    def setUp(self):
        self.sp = FakeSP('tests.configurations.sp_conf')
        self.idp = FakeIdP(USERS)

    @staticmethod
    def setup_server():
        app = WsgiApplication('tests.configurations.proxy_conf',
                              'http://example.com/unittest_idp.xml')

        cherrypy.tree.graft(app.run_server, '/')

    def test_flow(self):
        e_id = 'https://localhost:8090/proxy.xml/aHR0cHM6Ly9leGFtcGxlLmNvbS91bml0dGVzdF9pZHAueG1s'

        url = self.sp.make_auth_req(e_id)
        status, headers, _ = self.getPage(url)
        assert status == '303 See Other'

        url = self.get_redirect_location(headers)
        req = parse_qs(urlsplit(url).query)
        assert 'SAMLRequest' in req
        assert 'RelayState' in req

        action, body = self.idp.handle_auth_req(req['SAMLRequest'][0],
                                                req['RelayState'][0],
                                                BINDING_HTTP_REDIRECT,
                                                'test1')
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
        assert identity["displayName"][0] == "Test1"

    def get_redirect_location(self, headers):
        for header, value in headers:
            if header.lower() == 'location':
                return value
