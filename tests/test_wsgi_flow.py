"""
Complete test for a SAML to SAML proxy.
"""
import json
import os
import os.path

import pytest
import yaml
from saml2.httputil import NotFound
from werkzeug.test import Client
from werkzeug.wrappers import BaseResponse

from satosa.proxy_server import WsgiApplication
from satosa.satosa_config import SATOSAConfig
from tests.util import TestBackend, TestFrontend


@pytest.fixture(scope="session")
def plugin_directory(tmpdir_factory):
    return str(tmpdir_factory.mktemp("plugins"))


@pytest.fixture(scope="session")
def backend_plugin_config(plugin_directory):
    data = {
        "module": "util.TestBackend",
        "name": TestBackend.NAME,
        "config": {"foo": "bar"}
    }

    backend_file = os.path.join(plugin_directory, "backend_conf.yaml")
    with open(backend_file, "w") as f:
        yaml.dump(data, f)
    return backend_file


@pytest.fixture(scope="session")
def frontend_plugin_config(plugin_directory):
    data = {
        "module": "util.TestFrontend",
        "name": TestFrontend.NAME,
        "config": {"abc": "xyz"}
    }

    frontend_filename = os.path.join(plugin_directory, "frontend_conf.yaml")
    with open(frontend_filename, "w") as f:
        yaml.dump(data, f)
    return frontend_filename

@pytest.fixture(scope="session")
def request_microservice_config(plugin_directory):
    data = {
        "module": "util.TestRequestMicroservice",
        "name": "request-microservice",
    }

    request_file = os.path.join(plugin_directory, "request_conf.yaml")
    with open(request_file, "w") as f:
        yaml.dump(data, f)
    return request_file

@pytest.fixture(scope="session")
def response_microservice_config(plugin_directory):
    data = {
        "module": "util.TestResponseMicroservice",
        "name": "response-microservice",
        "conf": {"qwe": "rty"}
    }

    response_file = os.path.join(plugin_directory, "response_conf.yaml")
    with open(response_file, "w") as f:
        yaml.dump(data, f)
    return response_file


class TestProxy:
    """
    Performs a complete flow test for the proxy.
    Verifies client <-> PROXY.
    """

    @pytest.fixture(autouse=True)
    def setup(self, backend_plugin_config, frontend_plugin_config, request_microservice_config, response_microservice_config):
        proxy_config_dict = {"BASE": "https://localhost:8090",
                             "COOKIE_STATE_NAME": "TEST_STATE",
                             "STATE_ENCRYPTION_KEY": "ASDasd123",
                             "CUSTOM_PLUGIN_MODULE_PATHS": [os.path.dirname(__file__)],
                             "BACKEND_MODULES": [backend_plugin_config],
                             "FRONTEND_MODULES": [frontend_plugin_config],
                             "MICRO_SERVICES": [request_microservice_config, response_microservice_config],
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
        resp = test_client.get('/{}/request'.format(TestBackend.NAME))
        assert resp.status == '200 OK'
        headers = dict(resp.headers)
        assert headers["Set-Cookie"], "Did not save state in cookie!"

        # Fake response coming in to backend
        resp = test_client.get('/{}/response'.format(TestBackend.NAME), headers=[("Cookie", headers["Set-Cookie"])])
        assert resp.status == '200 OK'
        assert json.loads(resp.data.decode('utf-8'))["foo"] == "bar"

    def test_unknown_request_path(self):
        app = WsgiApplication(config=self.proxy_config)
        test_client = Client(app.run_server, BaseResponse)

        resp = test_client.get('/unknown')
        assert resp.status == NotFound._status
