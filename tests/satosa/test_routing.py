import pytest

from satosa.context import Context
from satosa.routing import ModuleRouter
from tests.util import TestBackend, TestFrontend

FRONTEND_NAMES = ["Saml2IDP", "VOPaaSSaml2IDP"]
BACKEND_NAMES = ["Saml2SP", "VOPaaSSaml2SP"]


class TestModuleRouter:
    @pytest.fixture(autouse=True)
    def create_router(self):
        backends = {}
        for provider in BACKEND_NAMES:
            backends[provider] = TestBackend(None, {"attributes": {}}, None, None, provider)

        frontends = {}
        for receiver in FRONTEND_NAMES:
            frontends[receiver] = TestFrontend(None, {"attributes": {}}, None, None, receiver)

        self.router = ModuleRouter(frontends, backends)

    @pytest.mark.parametrize('url_path, expected_frontend, expected_backend', [
        ("%s/%s/request" % (provider, receiver), receiver, provider)
        for receiver in FRONTEND_NAMES
        for provider in BACKEND_NAMES
        ])
    def test_url_routing_frontend(self, url_path, expected_frontend, expected_backend):
        context = Context()
        context.path = url_path
        self.router.endpoint_routing(context)
        assert context.target_frontend == expected_frontend
        assert context.target_backend == expected_backend

    @pytest.mark.parametrize('url_path, expected_backend', [
        ("%s/response" % (provider,), provider) for provider in BACKEND_NAMES
        ])
    def test_url_routing_backend(self, url_path, expected_backend):
        context = Context()
        context.path = url_path
        self.router.endpoint_routing(context)
        assert context.target_backend == expected_backend
        assert context.target_frontend is None

    @pytest.mark.parametrize('url_path, expected_frontend, expected_backend', [
        ("%s/%s/request" % (provider, receiver), receiver, provider)
        for receiver in FRONTEND_NAMES
        for provider in BACKEND_NAMES
        ])
    def test_module_routing(self, url_path, expected_frontend, expected_backend, context):
        context.path = url_path

        self.router.endpoint_routing(context)
        assert context.target_backend == expected_backend
        assert context.target_frontend == expected_frontend

        backend = self.router.backend_routing(context)
        assert backend == self.router.backends[expected_backend]["instance"]
        frontend = self.router.frontend_routing(context)
        assert frontend == self.router.frontends[expected_frontend]["instance"]

    @pytest.mark.parametrize(("frontends", "backends"), [
        (None, None),
        ({}, {})
    ])
    def test_bad_init(self, frontends, backends):
        with pytest.raises(ValueError):
            ModuleRouter(frontends, backends)
