from satosa.response import Response


class TestResponse:
    def test_constructor_adding_content_type_header(self):
        resp = Response("foo", content="bar")
        headers = dict(resp.headers)
        assert headers["Content-Type"] == "bar"