import pytest

from satosa.context import Context
from satosa.routing import ModuleRouter
from tests.util import TestBackend, TestFrontend

FRONTEND_NAMES = ["Saml2IDP", "VOPaaSSaml2IDP"]
BACKEND_NAMES = ["Saml2SP", "VOPaaSSaml2SP"]


@pytest.fixture
def router():
    backends = {}
    for provider in BACKEND_NAMES:
        backends[provider] = TestBackend(None, {"attributes": {}}, None, None, provider)

    frontends = {}
    for receiver in FRONTEND_NAMES:
        frontends[receiver] = TestFrontend(None, {"attributes": {}}, None, None, receiver)

    return ModuleRouter(frontends, backends)


def foreach_frontend_endpoint(callback):
    for receiver in FRONTEND_NAMES:
        for provider in BACKEND_NAMES:
            path = "%s/%s/request" % (provider, receiver)
            callback(path, provider, receiver)


def foreach_backend_endpoint(callback):
    for provider in BACKEND_NAMES:
        path = "%s/response" % provider
        callback(path, provider)


def test_url_routing(router):
    def test_frontend(path, provider, receiver):
        context = Context()
        context.path = path
        router.endpoint_routing(context)
        assert context.target_frontend == receiver
        assert context.target_backend == provider

    def test_backend(path, provider):
        context = Context()
        context.path = path
        router.endpoint_routing(context)
        assert context.target_backend == provider
        assert context.target_frontend is None

    foreach_frontend_endpoint(test_frontend)
    foreach_backend_endpoint(test_backend)


def test_module_routing(context, router):
    def test_routing(path, provider, receiver):
        context.path = path
        router.endpoint_routing(context)

        backend = router.backend_routing(context)
        assert backend == router.backends[provider]["instance"]

        frontend = router.frontend_routing(context)
        assert frontend == router.frontends[receiver]["instance"]
        assert context.target_frontend == receiver

    foreach_frontend_endpoint(test_routing)


@pytest.mark.parametrize(("frontends", "backends"), [
    (None, None),
    ({}, {})])
def test_bad_init(frontends, backends):
    with pytest.raises(ValueError):
        ModuleRouter(frontends, backends)
