import pytest

from satosa.response import Response


class TestResponse:
    def test_constructor_adding_content_type_header(self):
        resp = Response("foo", content="bar")
        headers = dict(resp.headers)
        assert headers["Content-Type"] == "bar"

    @pytest.mark.parametrize("data, expected", [
        ("foobar", ["foobar"]),
        (["foobar"], ["foobar"])
    ])
    def test_call_should_always_return_flat_list_to_comply_with_wsgi(self, data, expected):
        resp = Response(data)
        assert resp({}, lambda x, y: None) == expected
