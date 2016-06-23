import pytest

from satosa.context import Context
from satosa.routing import ModuleRouter
from satosa.state import State
from tests.util import FakeFrontend, FakeBackend

RECEIVERS = ["Saml2IDP", "VOPaaSSaml2IDP"]
PROVIDERS = ["Saml2SP", "VOPaaSSaml2SP"]
FRONTEND_ENDPOINTS = ["sso/redirect", "sso/post"]
BACKEND_ENDPOINTS = ["disco", "auth"]


def create_frontend_endpoint_func(receiver):
    def register_frontend_url(providers):
        endpoints = []
        for endp in FRONTEND_ENDPOINTS:
            frontend_endp = "%s/%s" % (receiver, endp)
            for provider in providers:
                endpoints.append(("^%s/%s$" % (provider, frontend_endp), (receiver, endp)))
        return endpoints

    return register_frontend_url


def create_backend_endpoint_func(provider):
    def register_backend_url():
        endpoints = []
        for endp in BACKEND_ENDPOINTS:
            backend_endp = "%s/%s" % (provider, endp)
            endpoints.append(("^%s$" % backend_endp, (provider, endp)))
        return endpoints

    return register_backend_url


@pytest.fixture
def router_fixture():
    frontends = {}
    backends = {}

    for provider in PROVIDERS:
        backends[provider] = FakeBackend(internal_attributes={"attributes": {}})
        backends[provider].register_endpoints_func = create_backend_endpoint_func(provider)

    for receiver in RECEIVERS:
        frontends[receiver] = FakeFrontend(internal_attributes={"attributes": {}})
        frontends[receiver].register_endpoints_func = create_frontend_endpoint_func(receiver)

    return ModuleRouter(frontends, backends), frontends, backends


def foreach_frontend_endpoint(callback):
    for receiver in RECEIVERS:
        for provider in PROVIDERS:
            for endp in FRONTEND_ENDPOINTS:
                path = "%s/%s/%s" % (provider, receiver, endp)
                callback(path, provider, receiver, endp)


def foreach_backend_endpoint(callback):
    for provider in PROVIDERS:
        for endp in BACKEND_ENDPOINTS:
            path = "%s/%s" % (provider, endp)
            callback(path, provider, endp)


def test_url_routing(router_fixture):
    router, _, _ = router_fixture

    def test_frontend(path, provider, receiver, endpoint):
        context = Context()
        context.state = State()
        context.path = path
        spec = router.endpoint_routing(context)
        assert spec[0] == receiver
        assert spec[1] == endpoint
        assert context.target_frontend == receiver
        assert context.target_backend == provider

    def test_backend(path, provider, endpoint):
        context = Context()
        context.path = path
        spec = router.endpoint_routing(context)
        assert spec[0] == provider
        assert spec[1] == endpoint
        assert context.target_backend == provider
        assert context.target_frontend is None

    foreach_frontend_endpoint(test_frontend)
    foreach_backend_endpoint(test_backend)


def test_module_routing(router_fixture):
    router, frontends, backends = router_fixture
    state = State()

    def test_routing(path, provider, receiver, _):
        context = Context()
        context.path = path
        context.state = state
        router.endpoint_routing(context)

        backend = router.backend_routing(context)
        assert backend == backends[provider]

        frontend = router.frontend_routing(context)
        assert frontend == frontends[receiver]
        assert context.target_frontend == receiver

    foreach_frontend_endpoint(test_routing)


@pytest.mark.parametrize(("frontends", "backends"), [
    (None, None),
    ({}, {})])
def test_bad_init(frontends, backends):
    with pytest.raises(ValueError):
        ModuleRouter(frontends, backends)
