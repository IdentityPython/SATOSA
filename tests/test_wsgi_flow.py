"""
Complete test for a SAML to SAML proxy.
"""
import inspect
import json
import os
import os.path

import pytest
from saml2.httputil import NotFound
from werkzeug.test import Client
from werkzeug.wrappers import BaseResponse

from satosa.plugin_base.endpoint import BackendModulePlugin, FrontendModulePlugin
from satosa.proxy_server import WsgiApplication
from satosa.satosa_config import SATOSAConfig
from tests.util import TestBackend, TestFrontend


class TestBackendPlugin(BackendModulePlugin):
    def __init__(self, base_url):
        super().__init__(TestBackend, TestBackend.provider, {})


class TestFrontendPlugin(FrontendModulePlugin):
    def __init__(self, base_url):
        super().__init__(TestFrontend, "TestFrontend", {})


class TestProxy:
    """
    Performs a complete flow test for the proxy.
    Verifies client <-> PROXY.
    """

    @pytest.fixture(autouse=True)
    def setup(self):
        proxy_config_dict = {"BASE": "https://localhost:8090",
                             "COOKIE_STATE_NAME": "TEST_STATE",
                             "STATE_ENCRYPTION_KEY": "ASDasd123",
                             "PLUGIN_PATH": [os.path.dirname(__file__)],
                             "BACKEND_MODULES": [inspect.getmodulename(__file__)],
                             "FRONTEND_MODULES": [inspect.getmodulename(__file__)],
                             "USER_ID_HASH_SALT": "qwerty",
                             "INTERNAL_ATTRIBUTES": {"attributes": {}}}

        self.proxy_config = SATOSAConfig(proxy_config_dict)

    def test_flow(self):
        """
        Performs the test.
        """
        app = WsgiApplication(config=self.proxy_config)
        test_client = Client(app.run_server, BaseResponse)

        # Make request to frontend
        resp = test_client.get('/{}/request'.format(TestBackend.provider))
        assert resp.status == '200 OK'
        headers = dict(resp.headers)
        assert headers["Set-Cookie"], "Did not save state in cookie!"

        # Fake response coming in to backend
        resp = test_client.get('/{}/response'.format(TestBackend.provider), headers=[("Cookie", headers["Set-Cookie"])])
        assert resp.status == '200 OK'
        assert json.loads(resp.data.decode('utf-8'))["foo"] == "bar"

    def test_unknown_request_path(self):
        app = WsgiApplication(config=self.proxy_config)
        test_client = Client(app.run_server, BaseResponse)

        resp = test_client.get('/unknown')
        assert resp.status == NotFound._status
