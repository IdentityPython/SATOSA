import pytest

from satosa.context import Context


def test_path():
    context = Context()
    with pytest.raises(ValueError):
        context.path = None

    with pytest.raises(ValueError):
        context.path = "/babal"

    valid_path = "Saml2/sso/redirect"
    context.path = valid_path
    assert context.path == valid_path
