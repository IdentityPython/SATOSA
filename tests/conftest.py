import os

import pytest

from satosa.context import Context
from satosa.state import State
from .util import generate_cert
from .util import write_cert

BASE_URL = "https://test-proxy.com"


@pytest.fixture(scope="session")
def signing_key_path(tmpdir_factory):
    tmpdir = str(tmpdir_factory.getbasetemp())
    path = os.path.join(tmpdir, "sign_key.pem")
    _, private_key = generate_cert()

    with open(path, "wb") as f:
        f.write(private_key)

    return path


@pytest.fixture
def cert_and_key(tmpdir):
    dir_path = str(tmpdir)
    cert_path = os.path.join(dir_path, "cert.pem")
    key_path = os.path.join(dir_path, "key.pem")
    write_cert(cert_path, key_path)

    return cert_path, key_path


@pytest.fixture
def context():
    context = Context()
    context.state = State()
    return context


@pytest.fixture
def satosa_config_dict(backend_plugin_config, frontend_plugin_config, request_microservice_config,
                       response_microservice_config):
    config = {
        "BASE": BASE_URL,
        "COOKIE_STATE_NAME": "TEST_STATE",
        "INTERNAL_ATTRIBUTES": {"attributes": {}},
        "STATE_ENCRYPTION_KEY": "state_encryption_key",
        "CUSTOM_PLUGIN_MODULE_PATHS": [os.path.dirname(__file__)],
        "BACKEND_MODULES": [backend_plugin_config],
        "FRONTEND_MODULES": [frontend_plugin_config],
        "MICRO_SERVICES": [request_microservice_config, response_microservice_config],
        "LOGGING": {"version": 1}
    }
    return config


@pytest.fixture
def backend_plugin_config():
    data = {
        "module": "util.TestBackend",
        "name": "backend",
        "config": {"foo": "bar"}
    }
    return data


@pytest.fixture
def frontend_plugin_config():
    data = {
        "module": "util.TestFrontend",
        "name": "frontend",
        "config": {"abc": "xyz"}
    }
    return data


@pytest.fixture
def request_microservice_config():
    data = {
        "module": "util.TestRequestMicroservice",
        "name": "request-microservice",
    }
    return data


@pytest.fixture
def response_microservice_config():
    data = {
        "module": "util.TestResponseMicroservice",
        "name": "response-microservice",
        "config": {"qwe": "rty"}
    }
    return data


@pytest.fixture
def account_linking_module_config(signing_key_path):
    account_linking_config = {
        "module": "satosa.micro_services.account_linking.AccountLinking",
        "name": "AccountLinking",
        "config": {
            "api_url": "http://account.example.com/api",
            "redirect_url": "http://account.example.com/redirect",
            "sign_key": signing_key_path,
        }
    }
    return account_linking_config


@pytest.fixture
def consent_module_config(signing_key_path):
    consent_config = {
        "module": "satosa.micro_services.consent.Consent",
        "name": "Consent",
        "config": {
            "api_url": "http://consent.example.com/api",
            "redirect_url": "http://consent.example.com/redirect",
            "sign_key": signing_key_path,
        }
    }
    return consent_config
